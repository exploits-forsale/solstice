use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::io::Seek;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use russh::server::Auth;
use russh::server::Msg;
use russh::server::Server as _;
use russh::server::Session;
use russh::Channel;
use russh::ChannelId;
use russh::CryptoVec;
use russh::Pty;
use russh_keys::key::KeyPair;
use tokio::sync::Mutex;
use tracing::debug;
use tracing::error;
use tracing::info;
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtyPair, PtySize, PtySystem, SlavePty};

use crate::sftp::SftpSession;

struct PtyStream{
    reader: Mutex<Box<dyn Read + Send>>,
    writer: Mutex<Box<dyn Write + Send>>,
    slave: Mutex<Box<dyn SlavePty + Send>>
}

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
    ptys: Arc<Mutex<HashMap<ChannelId, Arc<PtyStream>>>>,
}

impl Default for SshSession {
    fn default() -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
            ptys: Arc::new(Mutex::new(HashMap::new()))
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

    async fn shell_request(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {

        let handle_reader = session.handle();
        let handle_waiter = session.handle();


        let ptys = self.ptys.clone();

        tokio::spawn(async move {
            let pty_cloned = ptys.clone();
            let shell = "cmd.exe";
            let reader_handle = tokio::spawn(async move {
                loop {
                    let mut buffer = vec![0; 1024];
                    let pty_cloned = ptys.clone();
                    match tokio::task::spawn_blocking(move || {
                        let stream = pty_cloned.blocking_lock().get(&channel_id).unwrap().clone();
                        let mut reader = stream.reader.blocking_lock();
                        reader.read(&mut buffer).map(|n| (n, buffer))

                    }).await {
                        Ok(Ok((n, buffer))) if n == 0 => {
                            debug!("PTY: No more data to read.");
                            break;
                        }
                        Ok(Ok((n,buffer))) => {
                            if let Err(e) = handle_reader.data(channel_id, CryptoVec::from_slice(&buffer[0..n])).await {
                                error!("Error sending PTY data to client: {:?}", e);
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            error!("PTY read error: {:?}", e);
                            break;
                        }
                        Err(e) => {
                            error!("Join error: {:?}", e);
                            break;
                        }
                    }
                }
            });

            let child_status = tokio::task::spawn_blocking(move || {
                let stream = pty_cloned.blocking_lock().get(&channel_id).unwrap().clone();

                let mut child = stream.slave.blocking_lock().spawn_command(CommandBuilder::new(shell)).expect("Failed to spawn child process");
                child.wait().expect("Failed to wait on child process")
            }).await;

            match child_status {
                Ok(status) => {
                    if status.success() {
                        info!("Child process exited successfully.");
                        //reader_handle.abort();
                        let _ = handle_waiter.exit_status_request(channel_id, status.exit_code()).await;
                        let _ = handle_waiter.close(channel_id).await;
                    } else {
                        error!("Child process exited with status: {:?}", status);
                        //reader_handle.abort();
                        let _ = handle_waiter.exit_status_request(channel_id, status.exit_code()).await;
                        let _ = handle_waiter.close(channel_id).await;
                    }
                }
                Err(e) => {
                    error!("Failed to wait on child process: {:?}", e);
                }
            }
        });
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel_id: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        info!("Requesting PTY!");

        info!("PTY request received: term={}, col_width={}, row_height={}", term, col_width, row_height);

        let pty_system = native_pty_system();
        let pty_pair = pty_system.openpty(PtySize {
            rows: row_height as u16,
            cols: col_width as u16,
            pixel_width: pix_width as u16,
            pixel_height: pix_height as u16,
        })?;

        let pair = pty_pair;
        let slave = pair.slave;
        let mut master = pair.master;

        let master_reader = Mutex::new(master.try_clone_reader().unwrap());
        let mut master_writer = Mutex::new(master.take_writer().unwrap());

        let p = Mutex::new(master);
        

        self.ptys
        .lock()
        .await
            .insert(channel_id, Arc::new(PtyStream {
                reader: master_reader,
                writer: master_writer,
                slave: Mutex::new(slave)
            }));
        
        session.request_success();
        Ok(())
    }


    async fn data(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {

        if let Some(pty_stream) = self.ptys.lock().await.get_mut(&channel_id) {
            let mut pty_writer = pty_stream.writer.lock().await;

            pty_writer
                .write_all(data)
                .map_err(anyhow::Error::new)?;

            pty_writer.flush().map_err(anyhow::Error::new)?;    
        }
        Ok(())
    }
}

pub fn load_host_key(config_dir: &PathBuf) -> std::io::Result<KeyPair> {
    let ed25519_key_path = config_dir.join("ssh_host_ed25519_key");
    if let Ok(secret_key) = russh_keys::load_secret_key(&ed25519_key_path, None)
    {
        return Ok(secret_key);
    }

    let generated = KeyPair::generate_ed25519().unwrap();
    let priv_key_writer = fs::File::create(&ed25519_key_path)?;
    russh_keys::encode_pkcs8_pem(&generated, priv_key_writer)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    let pub_key_writer = fs::File::create(ed25519_key_path.to_str().unwrap().to_string() + ".pub")?;
    russh_keys::write_public_key_base64(pub_key_writer, &generated.clone_public_key().unwrap())
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    Ok(generated)
}

pub async fn start_ssh_server(port: u16, config_dir: &PathBuf) -> std::io::Result<()> {
    debug!("in start_ssh_server");

    debug!("Loading or generating hostkey(s)");
    let ed25519_host_key = load_host_key(config_dir)?;

    let config = russh::server::Config {
        auth_rejection_time: Duration::from_secs(3),
        auth_rejection_time_initial: Some(Duration::from_secs(0)),
        keys: vec![ed25519_host_key],
        ..Default::default()
    };

    let mut server = Server;

    let host = "0.0.0.0";
    debug!("about to listen on {host}:{port}");

    server
        .run_on_address(Arc::new(config), (host, port))
        .await?;

    Ok(())
}