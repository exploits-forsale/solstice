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
use tracing::warn;

struct FileEx {
    filename: String,
    attrs: FileAttributes,
}

impl Into<File> for FileEx {
    fn into(self) -> File {
        let mut f = File {
            filename: self.filename,
            longname: String::new(),
            attrs: self.attrs
        };
        f.longname = f.longname();
        f
    }
}

enum OurHandle {
    File(tokio::fs::File),
    // Bool marks whether the dir has been read yet
    // false if not read, true if EOF was returned to consumer
    Dir(bool),
}

struct InternalHandle {
    pub path: PathBuf,
    pub handle: OurHandle,
}

impl InternalHandle {
    pub fn new_dir(path: &PathBuf) -> Self {
        Self {
            path: path.to_owned(),
            handle: OurHandle::Dir(false),
        }
    }

    fn file(&mut self) -> Result<&mut tokio::fs::File, StatusCode> {
        match &mut self.handle {
            OurHandle::File(f) => Ok(f),
            _ => Err(StatusCode::NoSuchFile),
        }
    }

    fn directory(&mut self) -> Result<&mut bool, StatusCode> {
        match &mut self.handle {
            OurHandle::Dir(status) => Ok(status),
            _ => Err(StatusCode::NoSuchFile),
        }
    }
}

#[derive(Default)]
pub(crate) struct SftpSession {
    version: Option<u32>,
    handles: HashMap<String, InternalHandle>,
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
    debug!("unix to windows path: {unix_path}");
    // Only accept full paths
    if !parsed_path.has_root() {
        debug!("returning None");
        return None;
    } else if unix_path == "/" {
        debug!("unix->windows: returning root path: /");
        return Some(PathBuf::from("/"));
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

impl SftpSession {
    fn success(&self, id: u32) -> Status {
        Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".to_string(),
            language_tag: "en-US".to_string(),
        }
    }
}

#[async_trait]
impl russh_sftp::server::Handler for SftpSession {
    type Error = StatusCode;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported
    }

    /// The default is to send an SSH_FXP_VERSION response with
    /// the protocol version and ignore any extensions.
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

    /// Called on SSH_FXP_CLOSE.
    /// The status can be returned as Ok or as Err
    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        info!("close: {} {}", id, handle);
        let _ = self.handles.remove(&handle);

        Ok(self.success(id))
    }

    /// Called on SSH_FXP_OPENDIR
    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        info!("opendir: {}", &path);
        let pathbuf = PathBuf::from(&path);
        self.handles.insert(path.clone(), InternalHandle::new_dir(&pathbuf));
        Ok(Handle { id, handle: path })
    }

    /// Called on SSH_FXP_READDIR.
    /// EOF error should be returned at the end of reading the directory
    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        info!("readdir handle: {}", handle);

        let dir_read_done = self.handles
            .get_mut(&handle)
            .ok_or(StatusCode::NoSuchFile)?
            .directory()?;

        if *dir_read_done {
            debug!("Dir {} read already - returning EOF", handle);
            return Err(StatusCode::Eof);
        }

        // Mark dir as read
        *dir_read_done = true;

        if handle == "/" {
            let mut drives = Vec::with_capacity(26);
            let assigned_letters =
                unsafe { windows::Win32::Storage::FileSystem::GetLogicalDrives() };

            for i in 0..27 {
                if assigned_letters & (1 << i) != 0 {
                    let mount = ('A' as u8 + i) as char;
                    let mut attrs = FileAttributes::default();
                    attrs.set_dir(true);

                    drives.push(FileEx {
                        filename: String::from(mount),
                        attrs,
                    }.into());
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
                            Ok(FileEx {
                                filename: name.clone(),
                                attrs: (&metadata).into(),
                            }.into())
                        } else {
                            // TODO
                            Ok(FileEx {
                                filename: name.clone(),
                                attrs: FileAttributes::default(),
                            }.into())
                        }
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                return Ok(Name { id, files });
            }
            _ => {
                error!("readdir: File not found");
                return Err(StatusCode::NoSuchFile)
            },
        }
    }

    /// Called on SSH_FXP_REALPATH.
    /// Must contain only one name and a dummy attributes
    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        info!("realpath: {}", path);
        let normalized = canonizalize_unix_path_name(&PathBuf::from(&path));
        let mut attrs = FileAttributes::default();

        if let Some(winpath) = unix_like_path_to_windows_path(&path) {
            if let Ok(metadata) = winpath.metadata() {
                attrs = (&metadata).into();
            }
        }
        debug!("realpath: returning: {normalized:?}");

        Ok(Name {
            id,
            files: vec![FileEx {
                filename: normalized.to_string_lossy().to_string(),
                attrs: attrs,
            }.into()],
        })
    }

    /// Called on SSH_FXP_OPEN
    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: russh_sftp::protocol::OpenFlags,
        attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        debug!("open: {id} {filename} {pflags:?} {attrs:?}");
        if let Some(path) = unix_like_path_to_windows_path(&filename) {
            if !path.exists() && !pflags.contains(OpenFlags::CREATE) {
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
                    handle: OurHandle::File(file),
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

    /// Called on SSH_FXP_READ
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

    /// Called on SSH_FXP_WRITE
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

    /// Called on SSH_FXP_LSTAT
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

    /// Called on SSH_FXP_FSTAT
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

    /// Called on SSH_FXP_SETSTAT
    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        debug!("setstat: {id} {path} {attrs:?}");
        Err(self.unimplemented())
    }

    /// Called on SSH_FXP_FSETSTAT
    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        debug!("fsetstat: {id} {handle} {attrs:?}");
        Err(self.unimplemented())
    }

    /// Called on SSH_FXP_REMOVE.
    /// The status can be returned as Ok or as Err
    async fn remove(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        debug!("remove: {id} {path}");
        match unix_like_path_to_windows_path(&path) {
            Some(path) if path.is_file() => {
                debug!("remove: file {path:?}");
                if let Err(e) = tokio::fs::remove_file(path).await.context("removing file") {
                    error!("{:?}", e);
                    Err(StatusCode::Failure)
                } else {
                    Err(StatusCode::Ok)
                }
            },
            Some(path) => {
                debug!("remove: permission denied {path:?}");
                Err(StatusCode::PermissionDenied)
            }
            None => Err(StatusCode::NoSuchFile),
        }
    }

    /// Called on SSH_FXP_MKDIR
    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        debug!("mkdir: {id} {path}");
        if let Some(path) = unix_like_path_to_windows_path(&path) {
            match path.parent() {
                Some(parent) if parent.is_dir() => {
                    if let Err(e) = tokio::fs::create_dir(path)
                        .await
                        .context("creating dir")
                    {
                        error!("creating dir: {:?}", e);
                        Err(StatusCode::Failure)
                    } else {
                        Ok(self.success(id))
                    }
                },
                _ => Err(StatusCode::PermissionDenied),
            }
        } else {
            Err(StatusCode::NoSuchFile)
        }
    }

    /// Called on SSH_FXP_RMDIR.
    /// The status can be returned as Ok or as Err
    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        debug!("rmdir: {id} {path}");
        if let Some(path) = unix_like_path_to_windows_path(&path) {
            if !path.exists() || !path.is_dir() {
                return Err(StatusCode::NoSuchFile);
            }

            if path.components().count() <= 2 {
                return Err(StatusCode::PermissionDenied);
            }

            if let Err(e) = tokio::fs::remove_dir(&path)
                .await
                .context("deleting dir")
            {
                error!("deleting dir: {:?}", e);
                Err(StatusCode::Failure)
            } else {
                Ok(self.success(id))
            }
        } else {
            Err(StatusCode::NoSuchFile)
        }
    }

    /// Called on SSH_FXP_STAT
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

    /// Called on SSH_FXP_RENAME.
    /// The status can be returned as Ok or as Err
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
                    Ok(self.success(id))
                }
            }
            else {
                Err(StatusCode::NoSuchFile)
            }
        } else {
            Err(StatusCode::NoSuchFile)
        }
    }

    /// Called on SSH_FXP_READLINK
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
                    let filename = file.file_name().unwrap_or(std::ffi::OsStr::new("/")).to_string_lossy().to_owned();
                    Ok(Name {
                        id,
                        files: vec![FileEx {
                            filename: filename.to_string(),
                            attrs: metadata.into()
                        }.into()]
                    })
                },
                Err(e) => {
                    error!("failed reading link, path={path:?} error={e:?}");
                    Err(StatusCode::Failure)
                }
            }
        } else {
            Err(StatusCode::NoSuchFile)
        }
    }

    /// Called on SSH_FXP_SYMLINK.
    /// The status can be returned as Ok or as Err
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
                    Ok(_) => return Ok(self.success(id)),
                    Err(e) => {
                        error!("reading link: {e:?}");
                        return Err(StatusCode::Failure);
                    }
                }
            }
        }

        Err(StatusCode::Failure)
    }

    /// Called on SSH_FXP_EXTENDED.
    /// The extension can return any packet, so it's not specific.
    /// If the server does not recognize the `request' name
    /// the server must respond with an SSH_FX_OP_UNSUPPORTED error
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
            assert_eq!(canonizalize_unix_path_name(&PathBuf::from(".")), PathBuf::from("/"));
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
