use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use tokio::io::AsyncReadExt;

use async_trait::async_trait;
use russh_sftp::protocol::Attrs;
use russh_sftp::protocol::File;
use russh_sftp::protocol::FileAttributes;
use russh_sftp::protocol::Handle;
use russh_sftp::protocol::Name;
use russh_sftp::protocol::OpenFlags;
use russh_sftp::protocol::Status;
use russh_sftp::protocol::StatusCode;
use russh_sftp::protocol::Version;
use tokio::fs::OpenOptions;
use tokio::io::AsyncSeekExt;
use tokio::io::AsyncWriteExt;
use tracing::debug;
use tracing::error;
use tracing::info;

struct InternalHandle {
    path: PathBuf,
    file: Option<tokio::fs::File>,
}

impl InternalHandle {
    fn file(&mut self) -> Result<&mut tokio::fs::File, StatusCode> {
        self.file.as_mut().ok_or(StatusCode::Failure)
    }
}

#[derive(Default)]
pub(crate) struct SftpSession {
    version: Option<u32>,
    root_dir_read_done: bool,
    handles: HashMap<String, InternalHandle>,
    cur_dir: Option<PathBuf>,
}

fn canonizalize_unix_path_name(path: &PathBuf) -> PathBuf {
    let mut parts = vec![];
    for part in path {
        match part.to_str() {
            Some(".") => continue,
            Some("\\") => continue,
            Some("..") => _ = parts.pop(),
            Some(val) => parts.push(val),
            None => {}
        }
    }

    let res = String::from("/") + parts.join("/").as_str();
    PathBuf::from(&res)
}


fn unix_like_path_to_windows_path(unix_path: &str) -> Option<PathBuf> {
    let parsed_path = Path::new(&unix_path);

    // Only accept full paths
    if !parsed_path.has_root() {
        debug!("returning None");
        return None;
    }

    // Grab the drive letter. We assume the first dir is the drive
    let mut split = unix_path.split('/').skip(1);
    if let Some(mount) = split.next() {
        // They're statting something under a drive letter
        let mut translated_path = PathBuf::from(format!("{}:\\", mount));
        for component in split {
            translated_path.push(component);
        }

        translated_path = translated_path.canonicalize().unwrap_or(translated_path);
        debug!("returning translated path: {:?}", translated_path);

        Some(translated_path)
    } else {
        Some(PathBuf::from("/"))
    }
}

#[async_trait]
impl russh_sftp::server::Handler for SftpSession {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    async fn init(
        &mut self,
        version: u32,
        extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        if self.version.is_some() {
            error!("duplicate SSH_FXP_VERSION packet");
            return Err(StatusCode::ConnectionLost);
        }

        self.version = Some(version);
        info!("version: {:?}, extensions: {:?}", self.version, extensions);
        Ok(Version::new())
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        let _ = self.handles.remove(&handle);

        Ok(Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        info!("opendir: {}", path);
        self.cur_dir = unix_like_path_to_windows_path(path.as_str());
        Ok(Handle { id, handle: path })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        info!("readdir handle: {}", handle);
        debug!("self.root_dir_read_done = {}", self.root_dir_read_done);

        if !self.root_dir_read_done {
            self.root_dir_read_done = true;

            if handle == "/" {
                let mut drives = Vec::with_capacity(26);
                let assigned_letters =
                    unsafe { windows::Win32::Storage::FileSystem::GetLogicalDrives() };

                for i in 0..27 {
                    if assigned_letters & (1 << i) != 0 {
                        let mount = ('A' as u8 + i) as char;
                        let mut attrs = FileAttributes::default();
                        attrs.set_dir(true);

                        drives.push(File {
                            filename: String::from(mount),
                            longname: format!("/{}", mount),
                            attrs,
                        });
                    }
                }

                info!("returning: {:?}", drives);
                return Ok(Name { id, files: drives });
            }

            match unix_like_path_to_windows_path(&handle) {
                Some(path) if path.exists() => {
                    let files = path
                        .read_dir()
                        .context("read_dir")
                        .map_err(|e| {
                            error!("{:?}", e);
                            // TODO: Proper error code
                            StatusCode::PermissionDenied
                        })?
                        .map(|file| {
                            let file = file.context("file dir_entry").map_err(|e| {
                                error!("{:?}", e);
                                StatusCode::PermissionDenied
                            })?;
                            let name = file.file_name().to_string_lossy().into_owned();

                            if let Ok(metadata) = file
                                .metadata()
                                .context("readdir metadata")
                                .map_err(|e| error!("{:?}", e))
                            {
                                Ok(File {
                                    filename: name.clone(),
                                    longname: name,
                                    attrs: (&metadata).into(),
                                })
                            } else {
                                // TODO
                                Ok(File {
                                    filename: name.clone(),
                                    longname: name,
                                    attrs: FileAttributes::default(),
                                })
                            }
                        })
                        .collect::<Result<Vec<_>, _>>()?;

                    return Ok(Name { id, files });
                }
                _ => return Err(StatusCode::NoSuchFile),
            }
        }

        self.root_dir_read_done = false;

        Ok(Name { id, files: vec![] })
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        info!("realpath: {}", path);
        if path == "." {
            let attrs = FileAttributes::default();
            return Ok(Name {
                id,
                files: vec![File {
                    filename: "/".to_string(),
                    longname: "/".to_string(),
                    attrs,
                }],
            });
        }
        let mut attrs = FileAttributes::default();
        attrs.set_dir(true);
        Ok(Name {
            id,
            files: vec![File {
                filename: path.to_string(),
                longname: path.to_string(),
                attrs: attrs,
            }],
        })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: russh_sftp::protocol::OpenFlags,
        attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        debug!("open: {id} {filename} {pflags:?} {attrs:?}");
        if let Some(path) = unix_like_path_to_windows_path(&filename) {
            if !path.exists() {
                return Err(StatusCode::NoSuchFile);
            }

            let file = OpenOptions::new()
                .read(pflags.contains(OpenFlags::READ))
                .write(pflags.contains(OpenFlags::WRITE))
                .truncate(pflags.contains(OpenFlags::TRUNCATE))
                .create(pflags.contains(OpenFlags::CREATE))
                .append(pflags.contains(OpenFlags::APPEND))
                .open(&path)
                .await
                .map_err(|_e| StatusCode::NoSuchFile)?;

            self.handles.insert(
                filename.clone(),
                InternalHandle {
                    path,
                    file: Some(file),
                },
            );

            Ok(Handle {
                id,
                handle: filename,
            })
        } else {
            Err(StatusCode::NoSuchFile)
        }
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<russh_sftp::protocol::Data, Self::Error> {
        debug!("read: {id} {handle} {offset:#X} {len:#X}");

        let file = self
            .handles
            .get_mut(&handle)
            .ok_or(StatusCode::BadMessage)
            .map(InternalHandle::file)??;

        let eof = file
            .seek(SeekFrom::End(0))
            .await
            .context("EOF seek")
            .map_err(|e| {
                error!("{:?}", e);
                StatusCode::Failure
            })?;

        if offset >= eof {
            return Err(StatusCode::Eof);
        }

        match file.seek(SeekFrom::Start(offset)).await {
            Ok(_) => {
                let mut data = vec![0u8; len as usize];
                match file.read(data.as_mut_slice()).await.context("reading file") {
                    Ok(read) => {
                        data.truncate(read);
                        Ok(russh_sftp::protocol::Data { id, data })
                    }
                    Err(e) => {
                        error!("{:?}", e);
                        Err(StatusCode::Failure)
                    }
                }
            }
            Err(_) => Err(StatusCode::Failure),
        }
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let file = self
            .handles
            .get_mut(&handle)
            .ok_or(StatusCode::BadMessage)
            .map(InternalHandle::file)??;

        match file.seek(SeekFrom::Start(offset)).await {
            Ok(_) => {
                match file
                    .write_all(data.as_slice())
                    .await
                    .context("writing file")
                {
                    Ok(_) => Err(StatusCode::Ok),
                    Err(e) => {
                        error!("{:?}", e);
                        Err(StatusCode::Failure)
                    }
                }
            }
            Err(_) => Err(StatusCode::Failure),
        }
    }

    async fn lstat(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        debug!("lstat: {id} {path}");

        let win_path = unix_like_path_to_windows_path(&path);
        // Only accept full paths
        if win_path.is_none() {
            dbg!("lstat returning no such file");
            return Err(StatusCode::NoSuchFile);
        }

        if path == "/" {
            debug!("returning root");
            // They're statting the virtual root dir
            return Ok(Attrs {
                id,
                attrs: FileAttributes::default(),
            });
        }

        let win_path = win_path.unwrap();
        match win_path.metadata().context("lstat metadata") {
            Ok(meta) => Ok(Attrs {
                id,
                attrs: (&meta).into(),
            }),
            Err(e) => {
                error!("{:?}", e);
                Err(StatusCode::NoSuchFile)
            }
        }
    }

    async fn fstat(
        &mut self,
        id: u32,
        handle: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        debug!("fstat: {id} {handle}");
        let file = self
            .handles
            .get_mut(&handle)
            .ok_or(StatusCode::BadMessage)
            .map(InternalHandle::file)??;

        match file.metadata().await.context("fstat metadata") {
            Ok(meta) => Ok(Attrs {
                id,
                attrs: (&meta).into(),
            }),
            Err(e) => {
                error!("{:?}", e);
                Err(StatusCode::NoSuchFile)
            }
        }
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        debug!("setstat: {id} {path} {attrs:?}");
        Err(self.unimplemented())
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        debug!("fsetstat: {id} {handle} {attrs:?}");
        Err(self.unimplemented())
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        debug!("remove: {id} {filename}");

        if let Some(path) = unix_like_path_to_windows_path(&filename) {
            match path.parent() {
                Some(path)
                    if path
                        .file_name()
                        .expect("path has no filename?")
                        .to_string_lossy()
                        == "/" =>
                {
                    Err(StatusCode::PermissionDenied)
                }
                Some(path) if path.is_dir() => {
                    if let Err(e) = tokio::fs::remove_dir_all(path)
                        .await
                        .context("removing dir")
                    {
                        error!("{:?}", e);
                        Err(StatusCode::Failure)
                    } else {
                        Err(StatusCode::Ok)
                    }
                }
                Some(path) => {
                    if let Err(e) = tokio::fs::remove_file(path).await.context("removing file") {
                        error!("{:?}", e);
                        Err(StatusCode::Failure)
                    } else {
                        Err(StatusCode::Ok)
                    }
                }
                None => Err(StatusCode::NoSuchFile),
            }
        } else {
            Err(StatusCode::NoSuchFile)
        }
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        debug!("mkdir: {id} {path}");
        if let Some(path) = unix_like_path_to_windows_path(&path) {
            match path.parent() {
                Some(parent)
                    if parent
                        .file_name()
                        .expect("path has no filename?")
                        .to_string_lossy()
                        == "/" =>
                {
                    Err(StatusCode::PermissionDenied)
                }
                Some(parent) if parent.is_dir() => {
                    if let Err(e) = tokio::fs::create_dir(path)
                        .await
                        .context("creating dir")
                    {
                        error!("creating dir: {:?}", e);
                        Err(StatusCode::Failure)
                    } else {
                        Ok(Status {
                            id,
                            status_code: StatusCode::Ok,
                            error_message: "Ok".to_string(),
                            language_tag: "en-US".to_string(),
                        })
                    }
                },
                _ => Err(StatusCode::NoSuchFile),
            }
        } else {
            Err(StatusCode::NoSuchFile)
        }
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        debug!("rmdir: {id} {path}");
        if let Some(path) = unix_like_path_to_windows_path(&path) {
            if !path.exists() || !path.is_dir() {
                return Err(StatusCode::NoSuchFile);
            }

            if let Err(e) = tokio::fs::remove_dir(&path)
                .await
                .context("deleting dir")
            {
                error!("deleting dir: {:?}", e);
                Err(StatusCode::Failure)
            } else {
                Ok(Status {
                    id,
                    status_code: StatusCode::Ok,
                    error_message: "Ok".to_string(),
                    language_tag: "en-US".to_string(),
                })
            }
        } else {
            Err(StatusCode::NoSuchFile)
        }
    }

    async fn stat(
        &mut self,
        id: u32,
        path: String,
    ) -> Result<russh_sftp::protocol::Attrs, Self::Error> {
        debug!("stat: {id} {path}");
        let win_path = unix_like_path_to_windows_path(&path);
        // Only accept full paths
        if win_path.is_none() {
            return Err(StatusCode::NoSuchFile);
        }

        if path == "/" {
            // They're statting the virtual root dir
            return Ok(Attrs {
                id,
                attrs: FileAttributes::default(),
            });
        }

        let win_path = win_path.unwrap();
        match win_path.metadata() {
            Ok(meta) => Ok(Attrs {
                id,
                attrs: (&meta).into(),
            }),
            Err(_) => Err(StatusCode::NoSuchFile),
        }
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        debug!("rename: {id} from= {oldpath} to= {newpath}");
        if let Some(oldpath_win) = unix_like_path_to_windows_path(&oldpath) {
            if !oldpath_win.exists() {
                return Err(StatusCode::NoSuchFile);
            }

            if let Some(newpath_win) = unix_like_path_to_windows_path(&newpath) {
                if newpath_win.exists() {
                    // Newpath already exists
                    return Err(StatusCode::OpUnsupported);
                }

                if let Err(e) = tokio::fs::rename(&oldpath_win, &newpath_win)
                    .await
                    .context("renaming file/dir")
                {
                    error!("renaming dir/file: {:?}", e);
                    Err(StatusCode::OpUnsupported)
                } else {
                    Ok(Status {
                        id,
                        status_code: StatusCode::Ok,
                        error_message: "Ok".to_string(),
                        language_tag: "en-US".to_string(),
                    })
                }
            }
            else {
                Err(StatusCode::NoSuchFile)
            }
        } else {
            Err(StatusCode::NoSuchFile)
        }
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        debug!("readlink: {id} {path}");
        if let Some(path) = unix_like_path_to_windows_path(&path) {
            if !path.exists() {
                return Err(StatusCode::NoSuchFile);
            }
            else if !path.is_symlink() {
                return Err(StatusCode::OpUnsupported);
            }

            match tokio::fs::read_link(&path)
                .await
                .context("reading link")
            {
                Ok(file) => {
                    let metadata = &file.metadata().unwrap();
                    let filename = file.to_string_lossy().to_owned();
                    Ok(Name {
                        id,
                        files: vec![File {
                            filename: filename.to_string(),
                            longname: filename.to_string(),
                            attrs: metadata.into()
                        }]
                    })
                },
                Err(e) => {
                    error!("reading link: {e:?}");
                    Err(StatusCode::Failure)
                }
            }
        } else {
            Err(StatusCode::NoSuchFile)
        }
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        debug!("symlink: {id} {linkpath} {targetpath}");
        if let Some(targetpath_win) = unix_like_path_to_windows_path(&targetpath) {
            if !targetpath_win.exists() {
                return Err(StatusCode::NoSuchFile);
            }

            if let Some(linkpath_win) = unix_like_path_to_windows_path(&linkpath) {
                match tokio::fs::hard_link(&linkpath_win, &targetpath_win)
                    .await
                    .context("creating link")
                {
                    Ok(_) => return Ok(Status {
                        id,
                        status_code: StatusCode::Ok,
                        error_message: "Ok".to_string(),
                        language_tag: "en-US".to_string(),
                    }),
                    Err(e) => {
                        error!("reading link: {e:?}");
                        return Err(StatusCode::Failure);
                    }
                }
            }
        }

        Err(StatusCode::Failure)
    }

    async fn extended(
        &mut self,
        id: u32,
        request: String,
        data: Vec<u8>,
    ) -> Result<russh_sftp::protocol::Packet, Self::Error> {
        debug!("extended: {id} {request}");
        Err(self.unimplemented())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn test_canonicalize_path_name() {
            assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/")), PathBuf::from("/"));
            assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/..")), PathBuf::from("/"));
            assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/../..")), PathBuf::from("/"));
            assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C")), PathBuf::from("/C"));
            assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/")), PathBuf::from("/C"));
            assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/users/../..")), PathBuf::from("/"));
            assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/users")), PathBuf::from("/C/users"));
            assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/users/")), PathBuf::from("/C/users"));
            assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/users/appdata/local/")), PathBuf::from("/C/users/appdata/local"));
            assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/users/appdata/local/../")), PathBuf::from("/C/users/appdata"));
            assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/users/..")), PathBuf::from("/C"));
            assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/users/../.")), PathBuf::from("/C"));
            assert_eq!(canonizalize_unix_path_name(&PathBuf::from("/C/../C/users/.././.")), PathBuf::from("/C"));
        }
    }
}
