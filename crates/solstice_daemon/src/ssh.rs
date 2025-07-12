use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow};

use pbkdf2::password_hash::PasswordHash;
use pbkdf2::password_hash::PasswordHasher;
use pbkdf2::password_hash::PasswordVerifier;
use pbkdf2::password_hash::SaltString;
use pbkdf2::Pbkdf2;
use portable_pty::native_pty_system;
use portable_pty::CommandBuilder;
use portable_pty::MasterPty;
use portable_pty::PtySize;
use portable_pty::SlavePty;
use rand_core::OsRng;
use russh::server::Auth;
use russh::server::Msg;
use russh::server::Server as _;
use russh::server::Session;
use russh::Channel;
use russh::ChannelId;
use russh::CryptoVec;
use russh::Pty;
use russh::MethodSet;
use russh::MethodKind;
use russh::keys;
//use russh::keys::ssh_key;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::debug;
use tracing::error;
use tracing::info;
use tracing::trace;
use tracing::warn;

use crate::directory::wildcard_path_to_filedir_list;
use crate::impersonate::get_token;
use crate::sftp::SftpSession;

const DEFAULT_PASSWORD: &str = "xbox";

struct PtyStream {
    reader: Mutex<Box<dyn Read + Send>>,
    writer: Mutex<Box<dyn Write + Send>>,
    slave: Mutex<Box<dyn SlavePty + Send>>,
    master: Mutex<Box<dyn MasterPty + Send>>,
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

    fn handle_session_error(&mut self, error: <Self::Handler as russh::server::Handler>::Error) {
        error!("Session error: {error:?}");
    }
}

fn authorized_keys_path(config_dir: &PathBuf) -> PathBuf {
    config_dir.join("authorized_keys")
}

fn passwd_path(config_dir: &PathBuf) -> PathBuf {
    config_dir.join("passwd")
}

fn deserialize_authorized_keys(
    keydata: &str,
) -> Result<Vec<keys::PublicKey>, std::io::Error> {
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
            if let Ok(parsed_key) = keys::parse_public_key_base64(pubkey) {
                keys.push(parsed_key);
            } else {
                warn!("Ignoring authorized_key line: {line}");
            }
        }
    }

    Ok(keys)
}

fn read_authorized_keys(
    config_dir: &PathBuf,
) -> Result<Vec<keys::PublicKey>, std::io::Error> {
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

fn hash_password(password: &str) -> Result<String, pbkdf2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let hash = Pbkdf2
        .hash_password(password.as_bytes(), &salt)?
        .to_string();
    Ok(hash)
}

fn verify_password(
    password: &str,
    expected_hash: &str,
) -> Result<(), pbkdf2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(expected_hash)?;
    Pbkdf2.verify_password(password.as_bytes(), &parsed_hash)
}

fn read_passwd(config_dir: &PathBuf) -> Result<String, anyhow::Error> {
    let passwd_path = passwd_path(config_dir);

    if !passwd_path.exists() {
        debug!("Creating passwd file");

        // Create the file and its parent directories if they don't exist
        if let Some(parent) = passwd_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Hash the default pw and write it to the newly created file
        let pw_hash = hash_password(DEFAULT_PASSWORD)
            .map_err(|e| anyhow::anyhow!("Failed hashing default pw, err: {e:?}"))?;
        std::fs::write(&passwd_path, pw_hash)?;
    }

    trace!("Reading passwd");
    std::fs::read_to_string(&passwd_path)
        .map_err(|e| anyhow::anyhow!("Failed reading passwd from file, err: {e:?}"))
}

async fn spawn_command_and_get_output(cmd: &str, raw_args: &str) -> Result<(ExitStatus, Vec<u8>), anyhow::Error> {
    let (mut reader, writer) = std::pipe::pipe().unwrap();
    let child_stdout = writer.try_clone()?;
    let child_stderr = writer;

    // some command that outputs to its stdout and stderr
    let mut command = Command::new(cmd)
        .raw_arg(raw_args)
        .stdout(child_stdout)
        .stderr(child_stderr)
        .spawn()?;

    let exit_status = command.wait().await?;
    let mut buf = vec![];
    reader.read_to_end(&mut buf)?;

    Ok((exit_status, buf))
}

fn spawn_channel_msg_reader(mut channel: Channel<Msg>) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            if let Some(msg) = channel.wait().await {
                trace!("Received channel msg: {msg:?}");
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
}

struct SshSession {
    config_dir: PathBuf,
    clients: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
    ptys: Arc<Mutex<HashMap<ChannelId, Arc<PtyStream>>>>,
    username: Arc<Mutex<Option<String>>>,
}

impl Default for SshSession {
    fn default() -> Self {
        Self {
            // FIXME: What would be a good default here?
            config_dir: "".into(),
            clients: Arc::new(Mutex::new(HashMap::new())),
            ptys: Arc::new(Mutex::new(HashMap::new())),
            username: Arc::new(Mutex::new(None)),
        }
    }
}

impl SshSession {
    pub async fn get_channel(&mut self, channel_id: ChannelId) -> Channel<Msg> {
        let mut clients = self.clients.lock().await;
        clients.remove(&channel_id).unwrap()
    }

    fn add_authorized_key(&mut self, key: &keys::PublicKey) -> anyhow::Result<()> {
        let mut keys_file = OpenOptions::new()
            .append(true)
            .open(authorized_keys_path(&self.config_dir))?;

        let encoded_key = "\n".to_string() + &key.to_openssh()?;
        keys_file.write(encoded_key.as_bytes())?;
        Ok(())
    }

    fn set_new_password(&mut self, password: &str) -> anyhow::Result<()> {
        let hash = hash_password(password)
            .map_err(|e| anyhow::anyhow!("Failed to hash password, err: {e:?}"))?;

        std::fs::write(passwd_path(&self.config_dir), hash.into_bytes())?;
        Ok(())
    }
}

impl russh::server::Handler for SshSession {
    type Error = anyhow::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        trace!("credentials: {}, {}", user, password);
        let expected_hash = read_passwd(&self.config_dir)?;

        if verify_password(password, &expected_hash).is_ok() {
            let _ = self.username.lock().await.insert(user.to_owned());
            Ok(Auth::Accept)
        } else {
            warn!("Rejected user: {user} with password-auth");
            let mut methodset = MethodSet::empty();
            methodset.push(MethodKind::PublicKey);

            Ok(Auth::Reject {
                proceed_with_methods: Some(methodset),
                partial_success: false,
            })
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &keys::PublicKey,
    ) -> Result<Auth, Self::Error> {
        trace!("credentials: {}, {:?}", user, public_key);
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
                let _ = self.username.lock().await.insert(user.to_owned());
                return Ok(Auth::Accept);
            }
        }

        if keys.contains(public_key) {
            let _ = self.username.lock().await.insert(user.to_owned());
            debug!("User {user} accepted via pubkey auth");
            return Ok(Auth::Accept);
        }

        warn!("Rejecting {user}");

        Ok(Auth::Reject {
            proceed_with_methods: (None),
            partial_success: false,
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

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.close(channel)?;
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.close(channel)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        trace!("subsystem: {}", name);

        if name == "sftp" {
            let channel = self.get_channel(channel_id).await;
            let sftp = SftpSession::default();
            session.channel_success(channel_id)?;
            russh_sftp::server::run(channel.into_stream(), sftp).await;
        } else {
            session.channel_failure(channel_id)?;
        }

        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        trace!("Requesting shell");

        let handle_reader = session.handle();
        let handle_waiter = session.handle();

        let ptys = self.ptys.clone();
        let username = self.username.lock().await.clone();

        let channel = self.get_channel(channel_id).await;

        tokio::spawn(async move {
            let pty_cloned = ptys.clone();
            let shell = "cmd.exe";

            let _channel_reader = spawn_channel_msg_reader(channel);

            let _reader_handle = tokio::spawn(async move {
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
                        Ok(Ok((0, _buffer))) => {
                            debug!("PTY: No more data to read.");
                            break;
                        }
                        Ok(Ok((n, buffer))) => {
                            if let Err(e) = handle_reader
                                .data(channel_id, CryptoVec::from_slice(&buffer[0..n]))
                                .await
                            {
                                warn!("Error sending PTY data to client: {:?}", e);
                                break;
                            }
                        }
                        Ok(Err(e)) => {
                            warn!("PTY read error: {:?}", e);
                            break;
                        }
                        Err(e) => {
                            warn!("Join error: {:?}", e);
                            break;
                        }
                    }
                }
            });

            let child_status = tokio::task::spawn_blocking(move || {
                let stream = pty_cloned.blocking_lock().get(&channel_id).unwrap().clone();

                let maybe_token = match (username.as_deref(), get_token()) {
                    (Some("DefaultAccount"), Ok(token_handle)) => {
                        debug!("DefaultAccount context was requested...");
                        Some(token_handle)
                    },
                    _ => {
                        // Default context
                        None
                    },
                };

                let mut child = stream
                    .slave
                    .blocking_lock()
                    .spawn_command(CommandBuilder::new(shell), maybe_token)
                    .expect("Failed to spawn child process");
                child.wait().expect("Failed to wait on child process")
            })
            .await;

            match child_status {
                Ok(status) => {
                    if status.success() {
                        debug!("Child process exited successfully.");
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

    async fn window_change_request(
        &mut self,
        channel_id: ChannelId,
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        trace!("Requesting window change {channel_id} {col_width}x{row_height}, {pix_width}x{pix_height}");

        let clone = self.ptys.clone();
        let ptys_guard = clone.lock().await;
        let _pty = ptys_guard.get(&channel_id).unwrap();

        let _ = ptys_guard.get(&channel_id).unwrap().master.lock().await.resize(PtySize {
            rows: row_height as u16,
            cols: col_width as u16,
            pixel_width: pix_width as u16,
            pixel_height: pix_height as u16,
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
        _modes: &[(Pty, u32)],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        trace!("Requesting PTY!");

        debug!(
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

        let master_lock = Mutex::new(master);

        self.ptys.lock().await.insert(
            channel_id,
            Arc::new(PtyStream {
                reader: master_reader,
                writer: master_writer,
                master: master_lock,
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
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(pty_stream) = self.ptys.lock().await.get_mut(&channel_id) {
            let mut pty_writer = pty_stream.writer.lock().await;

            pty_writer.write_all(data).map_err(anyhow::Error::new)?;

            pty_writer.flush().map_err(anyhow::Error::new)?;
        }
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        debug!("exec_request: '{}'", std::str::from_utf8(data)?);

        if let Ok(command_line) = String::from_utf8(data.to_vec()) {
            let mut parts = command_line.split(" ");

            match parts.next() {
                Some("passwd") => {
                    let expected_pw_hash = read_passwd(&self.config_dir)?;
                    let old_pw = parts.next();
                    let new_pw = parts.next();

                    match (old_pw, new_pw) {
                        (Some(old_pw), Some(new_pw)) => {
                            if verify_password(old_pw, &expected_pw_hash).is_ok() {
                                // All checks passed, setting new password
                                self.set_new_password(new_pw)?;
                                session.data(
                                    channel_id,
                                    CryptoVec::from_slice(b"New password set successfully!\n"),
                                )?;
                            } else {
                                session.data(channel_id, CryptoVec::from_slice(b"Invalid password\n"))?;
                            }
                        }
                        (_, _) => {
                            session.data(channel_id, CryptoVec::from_slice(b"Invalid argument count\n"))?;
                        }
                    }
                },
                Some("command") => {
                    // Shell command is requested
                    if let Some("ls") = parts.next() {
                        // f.e for unix scp path completion: `command ls -aF1dL pwd*` (for empty remote path) or `command ls -aF1dL /D/somepath*`
                        //
                        // Request:
                        // command ls -aF1dL b*
                        //
                        // Response:
                        // bin/
                        // folder/
                        // script.ps1*
                        let mut peekable = parts.clone().peekable();

                        if let Some(&next) = peekable.peek() {
                            if next.starts_with("-") {
                                // skip over command line switches
                                parts.next();
                            }
                        }

                        let path = parts.collect::<Vec<&str>>().join(" ");
                        let res = wildcard_path_to_filedir_list(&path)
                            .map_err(|e|anyhow!("Failed to convert wildcard path to filedir list {e:?}"))?;

                        session.data(channel_id, CryptoVec::from_slice(res.as_bytes()))?;

                    }
                },
                Some(_) => {
                    let args = format!("/c {}", std::str::from_utf8(data)?);

                    let channel = self.get_channel(channel_id).await;
                    let _channel_reader = spawn_channel_msg_reader(channel);

                    let res = spawn_command_and_get_output("cmd", &args).await;

                    match res {
                        Ok((exit_status, output)) => {
                            session.data(channel_id, CryptoVec::from(output))?;
                            let msg = format!("Command exited, {exit_status}");
                            debug!("{}", msg);
                            session.data(channel_id, CryptoVec::from(msg.as_bytes().to_vec()))?;
                        },
                        Err(err) => {
                            session.data(channel_id, CryptoVec::from(err.to_string().as_bytes().to_vec()))?;
                        },
                    }
                },
                None => {
                    session.data(channel_id, CryptoVec::from_slice(b"Invalid command\n"))?;
                },
            }
        }

        session.channel_success(channel_id)?;
        session.close(channel_id)?;
        Ok(())
    }
}

pub fn load_host_key(config_dir: &PathBuf) -> std::io::Result<keys::PrivateKey> {
    let ed25519_key_path = config_dir.join("ssh_host_ed25519_key");
    let ed25519_pubkey_path = config_dir.join("ssh_host_ed25519_key.pub");

    if let Ok(secret_key) = keys::load_secret_key(&ed25519_key_path, None) {
        return Ok(secret_key);
    }

    let generated = keys::PrivateKey::random(&mut OsRng, keys::Algorithm::Ed25519).unwrap();
    generated.write_openssh_file(&ed25519_key_path, keys::ssh_key::LineEnding::LF)
        .context("Failed to write OpenSSH private hostkey ")
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    generated.public_key().write_openssh_file(&ed25519_pubkey_path)
        .context("Failed to write OpenSSH public hostkey")
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    Ok(generated)
}

pub async fn start_ssh_server(port: u16, config_dir: &PathBuf) -> std::io::Result<()> {
    trace!("in start_ssh_server");

    debug!("Loading or generating hostkey(s)");
    let ed25519_host_key = load_host_key(config_dir)?;

    let config = russh::server::Config {
        inactivity_timeout: None,
        auth_rejection_time: Duration::from_secs(0),
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
        // Only supporting ED25519, ECDSA-SHA2-NISTP256 and RSA
        // DSS is not parsed successfully in this case
        assert_eq!(8, deserialize_authorized_keys(keydata).unwrap().len());
    }
}
