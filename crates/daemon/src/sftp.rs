use std::collections::HashMap;
use std::io::SeekFrom;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncSeek;

use async_trait::async_trait;
use russh::server::Auth;
use russh::server::Msg;
use russh::server::Server as _;
use russh::server::Session;
use russh::Channel;
use russh::ChannelId;
use russh_keys::key::KeyPair;
use russh_sftp::protocol::Attrs;
use russh_sftp::protocol::File;
use russh_sftp::protocol::FileAttributes;
use russh_sftp::protocol::FileMode;
use russh_sftp::protocol::Handle;
use russh_sftp::protocol::Name;
use russh_sftp::protocol::OpenFlags;
use russh_sftp::protocol::Status;
use russh_sftp::protocol::StatusCode;
use russh_sftp::protocol::Version;
use tokio::fs::OpenOptions;
use tokio::io::AsyncSeekExt;
use tokio::sync::Mutex;
use tracing::debug;
use tracing::error;
use tracing::info;

#[derive(Clone)]
struct Server;

impl russh::server::Server for Server {
    type Handler = SshSession;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        SshSession::default()
    }
}

struct SshSession {
    clients: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

impl Default for SshSession {
    fn default() -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl SshSession {
    pub async fn get_channel(&mut self, channel_id: ChannelId) -> Channel<Msg> {
        let mut clients = self.clients.lock().await;
        clients.remove(&channel_id).unwrap()
    }
}

#[async_trait]
impl russh::server::Handler for SshSession {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        info!("credentials: {}, {}", user, password);
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &russh_keys::key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        info!("credentials: {}, {:?}", user, public_key);
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut Session,
    ) -> Result<bool, Self::Error> {
        {
            let mut clients = self.clients.lock().await;
            clients.insert(channel.id(), channel);
        }
        Ok(true)
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("subsystem: {}", name);

        if name == "sftp" {
            let channel = self.get_channel(channel_id).await;
            let sftp = SftpSession::default();
            session.channel_success(channel_id);
            russh_sftp::server::run(channel.into_stream(), sftp).await;
        } else {
            session.channel_failure(channel_id);
        }

        Ok(())
    }
}

#[derive(Default)]
struct SftpSession {
    version: Option<u32>,
    root_dir_read_done: bool,
    handles: HashMap<String, tokio::fs::File>,
    cur_dir: Option<PathBuf>,
}

fn unix_like_path_to_windows_path(unix_path: &str) -> Option<PathBuf> {
    let parsed_path = Path::new(&unix_path);

    // Only accept full paths
    if !parsed_path.has_root() {
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

    async fn close(&mut self, id: u32, _handle: String) -> Result<Status, Self::Error> {
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
                        .map_err(|_e| {
                            // TODO: Proper error code
                            StatusCode::PermissionDenied
                        })?
                        .map(|file| {
                            let file = file.map_err(|_e| StatusCode::PermissionDenied)?;
                            let name = file.file_name().to_string_lossy().into_owned();
                            let metadata =
                                file.metadata().map_err(|_e| StatusCode::PermissionDenied)?;

                            Ok(File {
                                filename: name.clone(),
                                longname: name,
                                attrs: (&metadata).into(),
                            })
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

            self.handles.insert(filename.clone(), file);

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

        match self.handles.get_mut(&handle) {
            Some(file) => match file.seek(SeekFrom::Start(offset)).await {
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
            },
            None => Err(StatusCode::BadMessage),
        }
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        Err(self.unimplemented())
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
        Err(self.unimplemented())
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        Err(self.unimplemented())
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        Err(self.unimplemented())
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        Err(self.unimplemented())
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        Err(self.unimplemented())
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        Err(self.unimplemented())
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
        Err(self.unimplemented())
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        Err(self.unimplemented())
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        Err(self.unimplemented())
    }

    async fn extended(
        &mut self,
        id: u32,
        request: String,
        data: Vec<u8>,
    ) -> Result<russh_sftp::protocol::Packet, Self::Error> {
        Err(self.unimplemented())
    }
}

pub(crate) const SFTP_LISTEN_PORT: u16 = 22;

pub async fn start_sftp_server() -> std::io::Result<()> {
    debug!("in start_sftp_server");

    let config = russh::server::Config {
        auth_rejection_time: Duration::from_secs(3),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![KeyPair::generate_ed25519().unwrap()],
        ..Default::default()
    };

    let mut server = Server;

    let host = "0.0.0.0";
    debug!("about to listen on {host}:{SFTP_LISTEN_PORT}");

    server
        .run_on_address(Arc::new(config), (host, SFTP_LISTEN_PORT))
        .await?;

    Ok(())
}
