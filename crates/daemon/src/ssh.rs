use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use async_trait::async_trait;
use portable_pty::native_pty_system;
use portable_pty::CommandBuilder;
use portable_pty::MasterPty;
use portable_pty::PtySize;
use portable_pty::PtySystem;
use portable_pty::SlavePty;
use russh::server::Auth;
use russh::server::Msg;
use russh::server::Server as _;
use russh::server::Session;
use russh::Channel;
use russh::ChannelId;
use russh::CryptoVec;
use russh::Pty;
use russh_keys::key::KeyPair;
use russh_keys::key::PublicKey;
use tokio::sync::Mutex;
use tracing::debug;
use tracing::error;
use tracing::info;

use crate::sftp::SftpSession;

struct PtyStream {
    reader: Mutex<Box<dyn Read + Send>>,
    writer: Mutex<Box<dyn Write + Send>>,
    slave: Mutex<Box<dyn SlavePty + Send>>,
}

#[derive(Clone)]
struct Server {
    config_dir: PathBuf,
}

impl russh::server::Server for Server {
    type Handler = SshSession;

    fn new_client(&mut self, _: Option<SocketAddr>) -> Self::Handler {
        SshSession {
            config_dir: self.config_dir.clone(),
            ..Default::default()
        }
    }
}

fn authorized_keys_path(config_dir: &PathBuf) -> PathBuf {
    config_dir.join("authorized_keys")
}

fn deserialize_authorized_keys(
    keydata: &str,
) -> Result<Vec<russh_keys::key::PublicKey>, std::io::Error> {
    let mut keys = Vec::new();

    for line in keydata.lines() {
        let line_trimmed = line.trim();

        if line_trimmed.is_empty() {
            continue;
        }

        let mut split = line_trimmed.split_whitespace();

        // Skip over pubkey prefix
        split.next();

        if let Some(pubkey) = split.next() {
            if let Ok(parsed_key) = russh_keys::parse_public_key_base64(pubkey) {
                keys.push(parsed_key);
            } else {
                info!("Ignoring authorized_key line: {line}");
            }
        }
    }

    Ok(keys)
}

fn read_authorized_keys(
    config_dir: &PathBuf,
) -> Result<Vec<russh_keys::key::PublicKey>, std::io::Error> {
    let authorized_keys_path = authorized_keys_path(config_dir);

    if !authorized_keys_path.exists() {
        debug!("Creating authorized keys file");

        // Create the file and its parent directories if they don't exist
        if let Some(parent) = authorized_keys_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::File::create(&authorized_keys_path)?;
    }

    debug!("Reading authorized keys");

    let contents = std::fs::read_to_string(&authorized_keys_path)?;

    deserialize_authorized_keys(&contents)
}

struct SshSession {
    config_dir: PathBuf,
    clients: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
    ptys: Arc<Mutex<HashMap<ChannelId, Arc<PtyStream>>>>,
}

impl Default for SshSession {
    fn default() -> Self {
        Self {
            // FIXME: What would be a good default here?
            config_dir: "".into(),
            clients: Arc::new(Mutex::new(HashMap::new())),
            ptys: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl SshSession {
    pub async fn get_channel(&mut self, channel_id: ChannelId) -> Channel<Msg> {
        let mut clients = self.clients.lock().await;
        clients.remove(&channel_id).unwrap()
    }

    fn add_authorized_key(&mut self, key: &PublicKey) -> anyhow::Result<()> {
        let mut keys_file = OpenOptions::new()
            .append(true)
            .open(authorized_keys_path(&self.config_dir))?;
        russh_keys::write_public_key_base64(&mut keys_file, key)?;

        Ok(())
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
        let keys = read_authorized_keys(&self.config_dir)?;

        if keys.is_empty() {
            info!("No authorized keys have been added yet -- adding this key to the keystore");

            if let Err(e) = self
                .add_authorized_key(public_key)
                .context("Could not add authorized key")
            {
                error!("{:?}", e);
            } else {
                // We presumably added the key fine, allow this person in
                return Ok(Auth::Accept);
            }
        }

        if keys.contains(public_key) {
            info!("User {user} accepted via pubkey auth");
            return Ok(Auth::Accept);
        }

        info!("Rejecting {user}");

        Ok(Auth::Reject {
            proceed_with_methods: (None),
        })
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
        info!("Requesting PTY");

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
                    })
                    .await
                    {
                        Ok(Ok((n, buffer))) if n == 0 => {
                            debug!("PTY: No more data to read.");
                            break;
                        }
                        Ok(Ok((n, buffer))) => {
                            if let Err(e) = handle_reader
                                .data(channel_id, CryptoVec::from_slice(&buffer[0..n]))
                                .await
                            {
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

                let mut child = stream
                    .slave
                    .blocking_lock()
                    .spawn_command(CommandBuilder::new(shell))
                    .expect("Failed to spawn child process");
                child.wait().expect("Failed to wait on child process")
            })
            .await;

            match child_status {
                Ok(status) => {
                    if status.success() {
                        info!("Child process exited successfully.");
                        //reader_handle.abort();
                        let _ = handle_waiter
                            .exit_status_request(channel_id, status.exit_code())
                            .await;
                        let _ = handle_waiter.close(channel_id).await;
                    } else {
                        error!("Child process exited with status: {:?}", status);
                        //reader_handle.abort();
                        let _ = handle_waiter
                            .exit_status_request(channel_id, status.exit_code())
                            .await;
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

        info!(
            "PTY request received: term={}, col_width={}, row_height={}",
            term, col_width, row_height
        );

        let pty_system = native_pty_system();
        let pty_pair = pty_system.openpty(PtySize {
            rows: row_height as u16,
            cols: col_width as u16,
            pixel_width: pix_width as u16,
            pixel_height: pix_height as u16,
        })?;

        let pair = pty_pair;
        let slave = pair.slave;
        let master = pair.master;

        let master_reader = Mutex::new(master.try_clone_reader().unwrap());
        let master_writer = Mutex::new(master.take_writer().unwrap());

        let p = Mutex::new(master);

        self.ptys.lock().await.insert(
            channel_id,
            Arc::new(PtyStream {
                reader: master_reader,
                writer: master_writer,
                slave: Mutex::new(slave),
            }),
        );

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

            pty_writer.write_all(data).map_err(anyhow::Error::new)?;

            pty_writer.flush().map_err(anyhow::Error::new)?;
        }
        Ok(())
    }
}

pub fn load_host_key(config_dir: &PathBuf) -> std::io::Result<KeyPair> {
    let ed25519_key_path = config_dir.join("ssh_host_ed25519_key");
    if let Ok(secret_key) = russh_keys::load_secret_key(&ed25519_key_path, None) {
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

    let mut server = Server {
        config_dir: config_dir.to_path_buf(),
    };

    let host = "0.0.0.0";
    debug!("about to listen on {host}:{port}");

    server
        .run_on_address(Arc::new(config), (host, port))
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_authorized_keys() {
        let keydata = r#"
        ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLHQEZWhL+IUEDghyVkDy81piOgZ8bQ7+Jso+gigCHmq0Qq4Liv8LqNxvk/qBS8PdHfyZVIaLhJb2bsXzm5qQaA=
        ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLHQEZWhL+IUEDghyVkDy81piOgZ8bQ7+Jso+gigCHmq0Qq4Liv8LqNxvk/qBS8PdHfyZVIaLhJb2bsXzm5qQaA= othername
        ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEaIg9xwd9czg0A8Tar2iL71X4WWN0oermPA1PO49kqY
        ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEaIg9xwd9czg0A8Tar2iL71X4WWN0oermPA1PO49kqY user@host.com
        ssh-dss AAAAB3NzaC1kc3MAAACBANyhZYCr5UGcg70AMbFhdtVBdRfE3Q1NuJC2uWGPYSywFnirux0B/l6BEepGYH2x7+nJ6B4wioRFB92I7KVD6XlCGvtAg5hydoG01ZOdLSeszmjLXqJ7rgof0Q7x87c9fFBf94Z2GUM5PSAENMpp9eThhNfZw2jUobfCZuUrFtojAAAAFQDG5HzFLq1tfosxZ968XuCRZl5l4QAAAIBT+YCdF2l8Fqeodl6pWmmeVaMXRrw4oWFEty/t2JwmaCR1zaJAx56uUTb0SrRMjZmCr8qflBIK4ji25ixxa6MTLvfTxu3YMFWGq/CVai+vh+x/2UbSP/e65fQOH/pximML+AbY1y5Mnw5tZbcUiTsWWu5BtEZzbQDprsAbTpTU/AAAAIBfiQ5zUtvHqOdpCkdTEmn0J5jPukaCfpWqRBWttKrkVS2Qx0LKoX3/iNR2b4e0U5UTkihYAQ5taQDg96hdYMW16Hnoal0v/puL+WRN58UWdFLR0jkzToLyfuCdarhE4xUAl5y4KaldPC69Bl6X53wGKf/joEmvNPZ6ZvucBpyBDw==
        ssh-dss AAAAB3NzaC1kc3MAAACBANyhZYCr5UGcg70AMbFhdtVBdRfE3Q1NuJC2uWGPYSywFnirux0B/l6BEepGYH2x7+nJ6B4wioRFB92I7KVD6XlCGvtAg5hydoG01ZOdLSeszmjLXqJ7rgof0Q7x87c9fFBf94Z2GUM5PSAENMpp9eThhNfZw2jUobfCZuUrFtojAAAAFQDG5HzFLq1tfosxZ968XuCRZl5l4QAAAIBT+YCdF2l8Fqeodl6pWmmeVaMXRrw4oWFEty/t2JwmaCR1zaJAx56uUTb0SrRMjZmCr8qflBIK4ji25ixxa6MTLvfTxu3YMFWGq/CVai+vh+x/2UbSP/e65fQOH/pximML+AbY1y5Mnw5tZbcUiTsWWu5BtEZzbQDprsAbTpTU/AAAAIBfiQ5zUtvHqOdpCkdTEmn0J5jPukaCfpWqRBWttKrkVS2Qx0LKoX3/iNR2b4e0U5UTkihYAQ5taQDg96hdYMW16Hnoal0v/puL+WRN58UWdFLR0jkzToLyfuCdarhE4xUAl5y4KaldPC69Bl6X53wGKf/joEmvNPZ6ZvucBpyBDw== user@host.com
        ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCqjfB7ULpstUGnwIz0L6Tywf1jlfOVW0F4wOsZW7QoF4co6HXrcMTAUPN2KxspMJmTb4vYZHoEwA/OXGM5VxJ6dFW5JGTuxam3Ee+XnO/jtEWgAMIffu6ATeuqnqyODucgM6srvQBItSLUK8hLqnYgURA7dtnvSAorHlQbKzUpNVdr+nfx7bSTFltOahk8CBPV8CdNP6jpQW0RQJu92XRCd9ncB/vUr3+Ho64G++OFLUuNjB4dAEUoopYYbTc1g/6v5oHjkLjQ2I+kP/fzkcLgarucB7pnO3vva+L0s2lOJG0AZh+rIdD+N06lGkx8D8Bpjxx65wWDJDUeEL6ubjjrAzcwE7l11wGquJ8H1arPNbPcKgbQF8AJ920potBSvGUXXKi+K9KGL4VihH6Sv1fDcSU12H12JRd5N5p0e0fWZFCED1OoQJQc0PfWSsHhdJET6swP6ce8XHi8lyGF7QYMG51e8oNiGEHGQcicpqJNBev0w/BHl1E2QMUExeaEI6k=
        ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCqjfB7ULpstUGnwIz0L6Tywf1jlfOVW0F4wOsZW7QoF4co6HXrcMTAUPN2KxspMJmTb4vYZHoEwA/OXGM5VxJ6dFW5JGTuxam3Ee+XnO/jtEWgAMIffu6ATeuqnqyODucgM6srvQBItSLUK8hLqnYgURA7dtnvSAorHlQbKzUpNVdr+nfx7bSTFltOahk8CBPV8CdNP6jpQW0RQJu92XRCd9ncB/vUr3+Ho64G++OFLUuNjB4dAEUoopYYbTc1g/6v5oHjkLjQ2I+kP/fzkcLgarucB7pnO3vva+L0s2lOJG0AZh+rIdD+N06lGkx8D8Bpjxx65wWDJDUeEL6ubjjrAzcwE7l11wGquJ8H1arPNbPcKgbQF8AJ920potBSvGUXXKi+K9KGL4VihH6Sv1fDcSU12H12JRd5N5p0e0fWZFCED1OoQJQc0PfWSsHhdJET6swP6ce8XHi8lyGF7QYMG51e8oNiGEHGQcicpqJNBev0w/BHl1E2QMUExeaEI6k= solstice@host.us
        "#;
        // Only supporting ED25519 and ECDSA-SHA2-NISTP256
        // DSS or RSA is not parsed successfully in this case
        assert_eq!(4, deserialize_authorized_keys(keydata).unwrap().len());
    }
}
