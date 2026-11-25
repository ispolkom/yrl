//! The local channel between the gatekeeper (network side, no privileges) and the executor (does things on the machine).
//! A Unix socket, Noise IK on top, then the same frames the client speaks. See src/executor.rs for the four checks on who may connect.
use crate::keys::{self, KeyPair};
use crate::wire::{Frame, WireError};
use anyhow::{bail, Context, Result};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// gatekeeper -> executor: `[key public 32][account_len u8][account][rights_len u16][rights, comma separated]`, exact
pub const IPC_OPEN: u8 = 60;
/// executor -> gatekeeper: the session exists; the frames of the session follow in both directions
pub const IPC_OK: u8 = 61;
/// executor -> gatekeeper: no (the reason is deliberately not told)
pub const IPC_REFUSED: u8 = 62;
/// Open an opaque byte tunnel. On the executor door this is the only session-opening request:
/// client identity, login, rights, SEQ and ACK remain inside the tunneled Client <-> Executor Noise channel.
pub const IPC_TUNNEL: u8 = 63;
pub const IPC_TUNNEL_OK: u8 = 64;
pub const IPC_TUNNEL_DATA: u8 = 65;

pub const MAX_ACCOUNT: usize = 64;
pub const MAX_RIGHTS: usize = 1024;
const TUNNEL_CHUNK: usize = 32 * 1024;
const TUNNEL_BUFFER: usize = 256 * 1024;

/// Turns an authenticated Noise connection into a bounded opaque byte stream. The framing is visible
/// to the carrier, but the bytes are the independent Client <-> Executor Noise protocol.
pub fn secure_tunnel<R, W>(mut rd: R, mut wr: W, sec: std::sync::Arc<crate::session::Secure>) -> tokio::io::DuplexStream
where
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (user, pump) = tokio::io::duplex(TUNNEL_BUFFER);
    let (mut from_user, mut to_user) = tokio::io::split(pump);
    let sec_out = sec.clone();
    tokio::spawn(async move {
        let outgoing = async {
            let mut buf = vec![0u8; TUNNEL_CHUNK];
            loop {
                let n = from_user.read(&mut buf).await?;
                if n == 0 { return Ok::<(), std::io::Error>(()) }
                let frame = Frame::new(IPC_TUNNEL_DATA, 0, buf[..n].to_vec());
                let msg = sec_out.seal(&frame).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "cannot seal tunnel data"))?;
                crate::session::write_msg(&mut wr, &msg).await?;
            }
        };
        let incoming = async {
            loop {
                let msg = crate::session::read_msg(&mut rd).await?;
                let frame = sec.open(&msg).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad tunnel data"))?;
                if frame.kind != IPC_TUNNEL_DATA { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "unexpected tunnel frame")) }
                to_user.write_all(&frame.payload).await?;
            }
        };
        let _ = tokio::select! { r = outgoing => r, r = incoming => r };
    });
    user
}

pub fn encode_open(key: &[u8], account: &str, rights: &[String]) -> Result<Vec<u8>, WireError> {
    let r = rights.join(",");
    if key.len() != 32 || account.is_empty() || account.len() > MAX_ACCOUNT || r.len() > MAX_RIGHTS {
        return Err(WireError::TooLarge);
    }
    let mut v = key.to_vec();
    v.push(account.len() as u8);
    v.extend_from_slice(account.as_bytes());
    v.extend_from_slice(&(r.len() as u16).to_be_bytes());
    v.extend_from_slice(r.as_bytes());
    Ok(v)
}

pub fn decode_open(b: &[u8]) -> Result<(Vec<u8>, String, Vec<String>), WireError> {
    if b.len() < 36 {
        return Err(WireError::Short);
    }
    let n = b[32] as usize;
    if n == 0 || n > MAX_ACCOUNT {
        return Err(WireError::TooLarge);
    }
    if b.len() < 33 + n + 2 {
        return Err(WireError::Short);
    }
    let account = std::str::from_utf8(&b[33..33 + n]).map_err(|_| WireError::Malformed)?.to_string();
    let m = u16::from_be_bytes([b[33 + n], b[34 + n]]) as usize;
    if m > MAX_RIGHTS {
        return Err(WireError::TooLarge);
    }
    if b.len() != 35 + n + m {
        return Err(WireError::Malformed);
    }
    let rights = std::str::from_utf8(&b[35 + n..]).map_err(|_| WireError::Malformed)?;
    let rights: Vec<String> = rights.split(',').filter(|s| !s.is_empty()).map(String::from).collect();
    if rights.iter().any(|r| !r.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')) {
        return Err(WireError::Malformed);
    }
    Ok((b[..32].to_vec(), account, rights))
}

/// how the executor decides who may connect
#[derive(Clone)]
pub struct ExecutorIpc {
    pub socket: PathBuf,
    pub key: KeyPair,
    pub gatekeeper_public: Vec<u8>,
    /// the operating-system user the gatekeeper runs as (None = any user the socket's permissions let in; tests and single-user setups)
    pub expected_uid: Option<u32>,
    /// the file the gatekeeper process was started from (None = not checked)
    pub expected_exe: Option<PathBuf>,
}

#[derive(Clone)]
pub struct GatekeeperIpc {
    pub socket: PathBuf,
    pub key: KeyPair,
    pub executor_public: Vec<u8>,
}

/// what the kernel says about the process on the other end of the socket
pub struct Peer {
    pub uid: u32,
    pub pid: Option<i32>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PeerVerdict {
    Ok,
    WrongUser,
    WrongProgram,
    Unknown,
}

pub fn judge_peer(ipc: &ExecutorIpc, peer: &Peer, exe_of_pid: impl Fn(i32) -> Option<PathBuf>) -> PeerVerdict {
    if let Some(u) = ipc.expected_uid {
        if peer.uid != u {
            return PeerVerdict::WrongUser;
        }
    }
    if let Some(want) = &ipc.expected_exe {
        let Some(pid) = peer.pid else { return PeerVerdict::Unknown };
        let Some(got) = exe_of_pid(pid) else { return PeerVerdict::Unknown };
        if &got != want {
            return PeerVerdict::WrongProgram;
        }
    }
    PeerVerdict::Ok
}

pub fn exe_of_pid(pid: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/exe")).ok()
}


/// Where a door's socket lives. An installation with separate system users sets `YRL_RUN` (e.g. /run/yrl) and every door gets a directory of its own there,
/// owned by the user that listens; otherwise the sockets sit next to the other files (one user, as in the tests and in the single-user setup).
pub fn sock_path(dir: &Path, door: &str, name: &str) -> PathBuf {
    match std::env::var_os("YRL_RUN") {
        Some(r) if !r.is_empty() => PathBuf::from(r).join(door).join(name),
        _ => dir.join(name),
    }
}

/// The directory a part writes its own state into: `<dir>/<role>` if the installation made one (owned by that part alone), else `<dir>` itself.
pub fn state_dir(dir: &Path, role: &str) -> PathBuf {
    let p = dir.join(role);
    if p.is_dir() {
        p
    } else {
        dir.to_path_buf()
    }
}

/// a user given as a number or by name
pub fn uid_arg(s: &str) -> Result<u32> {
    if let Ok(n) = s.parse::<u32>() {
        return Ok(n);
    }
    crate::identity::lookup_name(s).map(|p| p.uid).ok_or_else(|| anyhow::anyhow!("no such system user: {s}"))
}

pub fn gid_of_group(name: &str) -> Result<u32> {
    if let Ok(n) = name.parse::<u32>() {
        return Ok(n);
    }
    let c = std::ffi::CString::new(name)?;
    let mut buf = vec![0u8; 4096];
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::group = std::ptr::null_mut();
    let rc = unsafe { libc::getgrnam_r(c.as_ptr(), &mut grp, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), &mut res) };
    if rc != 0 || res.is_null() {
        bail!("no such group: {name}");
    }
    Ok(grp.gr_gid)
}

/// a socket that others can use is not a private channel
pub fn socket_mode_ok(mode: u32) -> bool {
    mode & 0o007 == 0
}

/// the directory the socket lives in must not be writable by group or others (they could replace the socket)
pub fn dir_ok(path: &Path) -> bool {
    path.parent().and_then(|d| std::fs::metadata(d).ok()).is_some_and(|m| m.mode() & 0o022 == 0)
}

pub fn bind_socket(path: &Path) -> Result<tokio::net::UnixListener> {
    if !dir_ok(path) {
        bail!("the directory of the socket is writable by others");
    }
    if let Ok(m) = std::fs::symlink_metadata(path) {
        if std::os::unix::fs::FileTypeExt::is_socket(&m.file_type()) {
            let _ = std::fs::remove_file(path); // a stale socket of an earlier run
        } else {
            bail!("something that is not a socket is in the way");
        }
    }
    let l = tokio::net::UnixListener::bind(path).context("cannot create the socket")?;
    // one user: only that user. With `YRL_SOCKET_GROUP` the members of that one group may connect (the door's other side runs as another system user);
    // the door still demands the peer's user id and the pre-shared key. If the group cannot be set the socket is not left behind half-open.
    match std::env::var("YRL_SOCKET_GROUP") {
        Ok(g) if !g.is_empty() => {
            let done = gid_of_group(&g).and_then(|gid| {
                let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
                if unsafe { libc::chown(c.as_ptr(), u32::MAX, gid) } != 0 {
                    bail!("cannot give the socket to group {g}: {}", std::io::Error::last_os_error());
                }
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
                Ok(())
            });
            if let Err(e) = done {
                let _ = std::fs::remove_file(path);
                return Err(e);
            }
        }
        _ => std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?,
    }
    Ok(l)
}

/// keys for both sides, made once at installation: `<dir>/ipc/{executor,gatekeeper}/static.key` (private, each readable by its own side only) and the public halves in `<dir>/ipc/*.pub`
pub fn init_keys(dir: &Path) -> Result<()> {
    let base = dir.join("ipc");
    std::fs::create_dir_all(&base)?;
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755))?;
    for side in ["executor", "gatekeeper", "broker", "audit", "owner", "firewall", "firewall-door"] {
        let k = keys::init(&base.join(side))?;
        std::fs::write(base.join(format!("{side}.pub")), hex::encode(&k.public))?;
    }
    Ok(())
}

fn read_pub(path: &Path) -> Result<Vec<u8>> {
    let v = hex::decode(std::fs::read_to_string(path)?.trim())?;
    if v.len() != 32 {
        bail!("not a public key: {}", path.display());
    }
    Ok(v)
}

pub fn load_executor(dir: &Path, expected_uid: Option<u32>, expected_exe: Option<PathBuf>) -> Result<ExecutorIpc> {
    Ok(ExecutorIpc { socket: sock_path(dir, "exec", "ipc.sock"), key: keys::load(&dir.join("ipc/executor"))?, gatekeeper_public: read_pub(&dir.join("ipc/gatekeeper.pub"))?, expected_uid, expected_exe })
}

pub fn load_gatekeeper(dir: &Path) -> Result<GatekeeperIpc> {
    Ok(GatekeeperIpc { socket: sock_path(dir, "exec", "ipc.sock"), key: keys::load(&dir.join("ipc/gatekeeper"))?, executor_public: read_pub(&dir.join("ipc/executor.pub"))? })
}

/// both sides in one process (the single-process mode): fresh keys that exist only in memory
pub fn ephemeral(socket: PathBuf, executor_key: Option<KeyPair>) -> (ExecutorIpc, GatekeeperIpc) {
    let (e, g) = (executor_key.unwrap_or_else(keys::generate), keys::generate());
    (
        ExecutorIpc { socket: socket.clone(), key: e.clone(), gatekeeper_public: g.public.clone(), expected_uid: Some(unsafe { libc::geteuid() }), expected_exe: std::env::current_exe().ok().and_then(|p| std::fs::canonicalize(p).ok()) },
        GatekeeperIpc { socket, key: g, executor_public: e.public },
    )
}

pub fn open_frame(key: &[u8], account: &str, rights: &[String]) -> Result<Frame, WireError> {
    Ok(Frame::new(IPC_OPEN, 0, encode_open(key, account, rights)?))
}

/// the broker's side and the executor's side of the door between them: the executor is the broker's only client
pub fn ephemeral_pair(socket: PathBuf, broker_key: Option<KeyPair>, executor_key: KeyPair) -> (ExecutorIpc, GatekeeperIpc) {
    let b = broker_key.unwrap_or_else(keys::generate);
    (
        ExecutorIpc { socket: socket.clone(), key: b.clone(), gatekeeper_public: executor_key.public.clone(), expected_uid: Some(unsafe { libc::geteuid() }), expected_exe: std::env::current_exe().ok().and_then(|p| std::fs::canonicalize(p).ok()) },
        GatekeeperIpc { socket, key: executor_key, executor_public: b.public },
    )
}

/// the broker's configuration: its client is the executor
pub fn load_broker(dir: &Path, expected_uid: Option<u32>, expected_exe: Option<PathBuf>) -> Result<ExecutorIpc> {
    Ok(ExecutorIpc { socket: sock_path(dir, "broker", "broker.sock"), key: keys::load(&dir.join("ipc/broker"))?, gatekeeper_public: read_pub(&dir.join("ipc/executor.pub"))?, expected_uid, expected_exe })
}

/// the executor's way to the broker
pub fn load_executor_to_broker(dir: &Path) -> Result<GatekeeperIpc> {
    Ok(GatekeeperIpc { socket: sock_path(dir, "broker", "broker.sock"), key: keys::load(&dir.join("ipc/executor"))?, executor_public: read_pub(&dir.join("ipc/broker.pub"))? })
}

/// the audit process's door: its key and the keys of the parts that may report
pub fn load_audit(dir: &Path, expected_uid: Option<u32>) -> Result<crate::audit::AuditIpc> {
    use crate::auditlog::Source::*;
    let mut sources = vec![];
    for (s, f) in [(Gatekeeper, "gatekeeper"), (Executor, "executor"), (Broker, "broker"), (Owner, "owner"), (Firewall, "firewall")] {
        if let Ok(k) = read_pub(&dir.join(format!("ipc/{f}.pub"))) {
            sources.push((s, k));
        }
    }
    Ok(crate::audit::AuditIpc { socket: sock_path(dir, "audit", "audit.sock"), key: keys::load(&dir.join("ipc/audit"))?, sources, expected_uid, expected_exe: None })
}

/// a reporting client for one part of the system, if the audit process has been set up in this directory
pub fn audit_client(dir: &Path, side: &str) -> Option<std::sync::Arc<crate::audit::AuditClient>> {
    let key = keys::load(&dir.join("ipc").join(side)).ok()?;
    let audit_pub = read_pub(&dir.join("ipc/audit.pub")).ok()?;
    Some(crate::audit::AuditClient::new(sock_path(dir, "audit", "audit.sock"), key, audit_pub))
}

/// the firewall program's door: its client is the gatekeeper (the key `firewall-door` is the firewall's own identity at that door; `firewall` is the key it reports to the audit with)
pub fn load_firewall(dir: &Path, expected_uid: Option<u32>, expected_exe: Option<PathBuf>) -> Result<ExecutorIpc> {
    Ok(ExecutorIpc { socket: sock_path(dir, "fw", "firewall.sock"), key: keys::load(&dir.join("ipc/firewall-door"))?, gatekeeper_public: read_pub(&dir.join("ipc/gatekeeper.pub"))?, expected_uid, expected_exe })
}

pub fn load_gatekeeper_to_firewall(dir: &Path) -> Result<GatekeeperIpc> {
    Ok(GatekeeperIpc { socket: sock_path(dir, "fw", "firewall.sock"), key: keys::load(&dir.join("ipc/gatekeeper"))?, executor_public: read_pub(&dir.join("ipc/firewall-door.pub"))? })
}
