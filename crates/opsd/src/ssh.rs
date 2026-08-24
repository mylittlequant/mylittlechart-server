//! Minimal SSH client wrapper around `russh` — trimmed port of
//! mirage2operator's `operator-box/src/ssh.rs`, keeping only what this crate
//! needs: key-auth `exec` and atomic SFTP `upload` against our own box.
//!
//! Hostkey handler accepts any key: this is a single known box reached by IP.
//! Key pinning against a stored fingerprint is a deliberate v1.1 option.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use russh::client;
use russh::keys::key::PrivateKeyWithHashAlg;
use russh_sftp::client::SftpSession;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const EXEC_TIMEOUT: Duration = Duration::from_secs(120);

pub struct SshOptions<'a> {
    pub host: &'a str,
    pub port: u16,
    pub user: &'a str,
    pub key_pem: &'a [u8],
}

pub struct ExecOutput {
    pub exit_code: Option<u32>,
    pub stdout: String,
    pub stderr: String,
}

pub struct AcceptAnyHostKey;

#[async_trait::async_trait]
impl client::Handler for AcceptAnyHostKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A live ssh session; serves many `exec`/`upload` calls over one dial.
pub struct SshSession {
    handle: client::Handle<AcceptAnyHostKey>,
}

impl SshSession {
    pub async fn exec(&self, cmd: &str) -> Result<ExecOutput, SshError> {
        run_exec(&self.handle, cmd).await
    }

    pub async fn upload(
        &self,
        local_bytes: &[u8],
        remote_path: &str,
        mode: u32,
    ) -> Result<(), SshError> {
        upload_via_handle(&self.handle, local_bytes, remote_path, mode).await
    }

    /// Download a remote file over the SFTP subsystem.
    pub async fn download(&self, remote_path: &str) -> Result<Vec<u8>, SshError> {
        let channel = self.handle.channel_open_session().await.map_err(SshError::Russh)?;
        channel.request_subsystem(true, "sftp").await.map_err(SshError::Russh)?;
        let sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| SshError::Sftp(e.to_string()))?;
        let mut file = sftp
            .open(remote_path)
            .await
            .map_err(|e| SshError::Sftp(format!("open {remote_path}: {e}")))?;
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .await
            .map_err(|e| SshError::Sftp(format!("read {remote_path}: {e}")))?;
        Ok(buf)
    }
}

pub async fn open_session(opts: &SshOptions<'_>) -> Result<SshSession, SshError> {
    let cfg = Arc::new(client::Config {
        inactivity_timeout: Some(EXEC_TIMEOUT),
        ..Default::default()
    });
    let key_pem = std::str::from_utf8(opts.key_pem).map_err(|_| SshError::BadKeyEncoding)?;
    let key = russh::keys::decode_secret_key(key_pem, None).map_err(SshError::Key)?;
    let addr = format!("{}:{}", opts.host, opts.port);
    let mut handle = tokio::time::timeout(
        CONNECT_TIMEOUT,
        client::connect(cfg, addr.clone(), AcceptAnyHostKey),
    )
    .await
    .map_err(|_| SshError::Timeout(addr))?
    .map_err(SshError::Russh)?;
    let key_with_alg =
        PrivateKeyWithHashAlg::new(Arc::new(key), None).map_err(SshError::Key)?;
    let auth_ok = handle
        .authenticate_publickey(opts.user, key_with_alg)
        .await
        .map_err(SshError::Russh)?;
    if !auth_ok {
        return Err(SshError::AuthFailed(opts.user.to_string()));
    }
    Ok(SshSession { handle })
}

/// Drain until the channel CLOSES — never on `Eof`: OpenSSH can send
/// `exit-status` after EOF, and breaking early loses the exit code of a
/// command that already ran (mirage incident 2026-08-02).
async fn run_exec(
    handle: &client::Handle<AcceptAnyHostKey>,
    cmd: &str,
) -> Result<ExecOutput, SshError> {
    let fut = async {
        let mut channel = handle.channel_open_session().await.map_err(SshError::Russh)?;
        channel.exec(true, cmd).await.map_err(SshError::Russh)?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code = None;
        while let Some(msg) = channel.wait().await {
            use russh::ChannelMsg;
            match msg {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext } => {
                    if ext == 1 {
                        stderr.extend_from_slice(&data);
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => exit_code = Some(exit_status),
                ChannelMsg::Close => break,
                _ => {}
            }
        }
        Ok(ExecOutput {
            exit_code,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        })
    };
    match tokio::time::timeout(EXEC_TIMEOUT, fut).await {
        Ok(res) => res,
        Err(_) => Err(SshError::ExecTimeout(cmd.chars().take(80).collect())),
    }
}

/// Atomic SFTP upload: write `<remote>.new`, verify on-disk size, chmod,
/// rename over the target. Chunked at 32KB — sftp servers cap packet size
/// and russh-sftp's write_all silently zero-fills on overflow.
async fn upload_via_handle(
    handle: &client::Handle<AcceptAnyHostKey>,
    local_bytes: &[u8],
    remote_path: &str,
    mode: u32,
) -> Result<(), SshError> {
    let channel = handle.channel_open_session().await.map_err(SshError::Russh)?;
    channel.request_subsystem(true, "sftp").await.map_err(SshError::Russh)?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| SshError::Sftp(e.to_string()))?;

    let tmp_path = format!("{remote_path}.new");
    {
        let mut file = sftp
            .create(&tmp_path)
            .await
            .map_err(|e| SshError::Sftp(format!("create {tmp_path}: {e}")))?;
        use tokio::io::AsyncWriteExt;
        const CHUNK: usize = 32 * 1024;
        let mut offset = 0;
        while offset < local_bytes.len() {
            let end = (offset + CHUNK).min(local_bytes.len());
            file.write_all(&local_bytes[offset..end])
                .await
                .map_err(|e| SshError::Sftp(format!("write {tmp_path} @ {offset}: {e}")))?;
            offset = end;
        }
        file.flush()
            .await
            .map_err(|e| SshError::Sftp(format!("flush {tmp_path}: {e}")))?;
        file.shutdown()
            .await
            .map_err(|e| SshError::Sftp(format!("close {tmp_path}: {e}")))?;
    }

    let metadata = sftp
        .metadata(&tmp_path)
        .await
        .map_err(|e| SshError::Sftp(format!("stat {tmp_path}: {e}")))?;
    let want = local_bytes.len() as u64;
    let got = metadata.size.unwrap_or(0);
    if got != want {
        let _ = sftp.remove_file(&tmp_path).await;
        return Err(SshError::Sftp(format!(
            "upload size mismatch for {tmp_path}: wrote {want} bytes, remote reports {got}"
        )));
    }

    // Build SETSTAT field-by-field — `FileAttributes::default()` pre-fills
    // `size: Some(0)` and OpenSSH's sftp-server would truncate the file on
    // chmod (mirage field incident 2026-05-23).
    let attrs = russh_sftp::protocol::FileAttributes {
        size: None,
        uid: None,
        user: None,
        gid: None,
        group: None,
        permissions: Some(mode),
        atime: None,
        mtime: None,
    };
    sftp.set_metadata(&tmp_path, attrs)
        .await
        .map_err(|e| SshError::Sftp(format!("chmod {tmp_path}: {e}")))?;
    let _ = sftp.remove_file(remote_path).await;
    sftp.rename(&tmp_path, remote_path)
        .await
        .map_err(|e| SshError::Sftp(format!("rename {tmp_path}->{remote_path}: {e}")))?;
    Ok(())
}

#[derive(Debug)]
pub enum SshError {
    BadKeyEncoding,
    Key(russh::keys::Error),
    Timeout(String),
    ExecTimeout(String),
    Russh(russh::Error),
    AuthFailed(String),
    Sftp(String),
}

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SshError::BadKeyEncoding => write!(f, "ssh key is not utf-8"),
            SshError::Key(e) => write!(f, "ssh key parse: {e}"),
            SshError::Timeout(addr) => write!(f, "ssh connect timeout to {addr}"),
            SshError::ExecTimeout(cmd) => write!(f, "ssh exec timeout: {cmd}"),
            SshError::Russh(e) => write!(f, "ssh: {e}"),
            SshError::AuthFailed(u) => write!(f, "ssh auth failed for user {u}"),
            SshError::Sftp(m) => write!(f, "sftp: {m}"),
        }
    }
}

impl std::error::Error for SshError {}
