#![allow(dead_code)]
//! A running server on loopback with one authorized key and the account `anna`.
pub mod chaos;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use yrl::client::Client;
use yrl::keys::{self, KeyPair};
use yrl::server::{serve, ServerConfig};
use yrl::link;
use yrl::session::{client_handshake, read_msg, write_msg, Secure, REKEY_EVERY};
use yrl::users;
use yrl::wire::{self, Frame};

pub const PW: &[u8] = b"correct horse battery";
pub const T: Duration = Duration::from_secs(5);

pub struct Rig {
    pub addr: String,
    pub server_pub: Vec<u8>,
    pub client: KeyPair,
    pub dir: tempfile::TempDir,
    pub log: Arc<Mutex<Vec<String>>>,
    pub sessions: Arc<yrl::server::Registry>,
    pub server_key: KeyPair,
    pub cfg: ServerConfig,
    /// the executor's own key (what a client pins to talk to it end to end)
    pub exec_pub: Vec<u8>,
    pub exec_key: KeyPair,
    /// the broker's key (what a client pins for ROOT step-up)
    pub broker_pub: Vec<u8>,
    pub broker_key: KeyPair,
}

impl Rig {
    pub fn server_dir(&self) -> std::path::PathBuf {
        self.dir.path().join("server")
    }
}

/// `key_rights` = what the key may ever do; the account `anna` has `exec,root`; `root` is a second account with only `root`
pub async fn rig_with(key_rights: &str, tweak: impl FnOnce(ServerConfig) -> ServerConfig) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let server_dir = dir.path().join("server");
    let sk = keys::init(&server_dir).unwrap();
    let client = keys::generate();
    keys::authorize(&server_dir.join("authorized_keys"), &hex::encode(&client.public), "laptop", key_rights).unwrap();
    users::set_user(&server_dir.join("users"), "anna", "exec,root,sudo,shell,files,tunnel", PW).unwrap();
    users::set_user(&server_dir.join("users"), "guest", "-", b"guest-password").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let log = Arc::new(Mutex::new(vec![]));
    let mut cfg = ServerConfig::new(server_dir);
    let exec_key = keys::generate();
    cfg.exec_identity = Some(exec_key.clone());
    let broker_key = keys::generate();
    cfg.broker_identity = Some(broker_key.clone());
    cfg.handshake_timeout = Duration::from_millis(400);
    cfg.log_sink = Some(log.clone());
    cfg.session_grace = Duration::from_millis(400); // abandoned hand-driven sessions disappear quickly in tests
    cfg.helper = std::path::PathBuf::from(env!("CARGO_BIN_EXE_yrld"));
    let mut cfg = tweak(cfg);
    yrl::server::ensure_executor(&mut cfg).await; // the executor and the broker exist now, and the rig can talk to their doors
    let sessions = cfg.sessions.clone();
    tokio::spawn(serve(listener, sk.clone(), cfg.clone()));
    Rig { addr, server_pub: sk.public.clone(), client, dir, log, sessions, server_key: sk, cfg, exec_pub: exec_key.public.clone(), exec_key, broker_pub: broker_key.public.clone(), broker_key }
}

pub async fn rig(key_rights: &str) -> Rig {
    rig_with(key_rights, |c| c).await
}

/// connected and logged in as anna
pub async fn open(r: &Rig) -> Client {
    let c = Client::connect_pinned(&r.addr, &r.client, &r.server_pub, &r.exec_pub, T).await.unwrap();
    c.login("anna", PW, T).await.unwrap();
    c
}

/// a raw, handshaken, NOT logged in connection
pub async fn raw(r: &Rig) -> (tokio::io::DuplexStream, Secure) {
    let mut outer = TcpStream::connect(&r.addr).await.unwrap();
    let gate = Arc::new(client_handshake(&mut outer, &r.client, &r.server_pub, REKEY_EVERY).await.unwrap());
    let (mut rd, mut wr) = tokio::io::split(outer);
    write_msg(&mut wr, &gate.seal(&Frame::new(yrl::ipc::IPC_TUNNEL, 0, vec![])).unwrap()).await.unwrap();
    let reply = gate.open(&read_msg(&mut rd).await.unwrap()).unwrap();
    assert_eq!(reply.kind, yrl::ipc::IPC_TUNNEL_OK);
    let mut s = yrl::ipc::secure_tunnel(rd, wr, gate);
    let sec = client_handshake(&mut s, &r.client, &r.exec_pub, REKEY_EVERY).await.unwrap();
    (s, sec)
}

/// sends a frame on a hand-driven connection: plain before the session starts, numbered inside it
pub async fn send<S: tokio::io::AsyncWrite + Unpin>(s: &mut S, sec: &Secure, f: Frame) {
    use std::sync::atomic::Ordering::SeqCst;
    let f = if sec.raw_mode.load(SeqCst) {
        let seq = sec.raw_out.fetch_add(1, SeqCst);
        let mut p = seq.to_be_bytes().to_vec();
        p.extend(f.encode().unwrap());
        Frame::new(link::SEQ, 0, p)
    } else {
        f
    };
    let _ = write_msg(s, &sec.seal(&f).unwrap()).await;
}

/// the next frame from the server (inside a session: the next numbered one), or None if it closed / said nothing within two seconds
pub async fn recv<S: tokio::io::AsyncRead + Unpin>(s: &mut S, sec: &Secure) -> Option<Frame> {
    use std::sync::atomic::Ordering::SeqCst;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        let m = tokio::time::timeout_at(deadline, read_msg(s)).await.ok()?.ok()?;
        let f = sec.open(&m).ok()?;
        if !sec.raw_mode.load(SeqCst) {
            return Some(f);
        }
        match f.kind {
            link::SEQ if f.payload.len() > 8 => {
                sec.raw_in.fetch_add(1, SeqCst);
                return Frame::decode(&f.payload[8..]).ok();
            }
            link::ACK | link::LINK_PONG | link::LINK_PING => continue,
            _ => return None,
        }
    }
}

/// logs in on a hand-driven connection; on success the connection switches to numbered frames
pub async fn raw_login<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(s: &mut S, sec: &Secure, login: &str, pw: &[u8]) -> Option<Frame> {
    send(s, sec, Frame::new(wire::LOGIN, 0, wire::encode_login(login.as_bytes(), pw).unwrap())).await;
    let f = recv(s, sec).await?;
    if f.kind == wire::LOGIN_OK {
        let sess = recv(s, sec).await?;
        assert_eq!(sess.kind, link::SESSION);
        sec.raw_mode.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    Some(f)
}

/// a client that reaches the server through `addr` (a chaos proxy) and reconnects quickly
pub fn fast_opts() -> yrl::client::ClientOptions {
    yrl::client::ClientOptions {
        ping_every: Duration::from_millis(100),
        dead_after: Duration::from_millis(900),
        retry_min: Duration::from_millis(20),
        retry_max: Duration::from_millis(200),
        connect_timeout: Duration::from_secs(2),
        give_up_after: Duration::from_secs(20),
        ..Default::default()
    }
}

pub async fn open_via(r: &Rig, addr: &str, opts: yrl::client::ClientOptions) -> Client {
    let opts = yrl::client::ClientOptions { executor_public: Some(r.exec_pub.clone()), ..opts };
    let c = Client::connect_opts(addr, &r.client, &r.server_pub, opts).await.unwrap();
    c.login("anna", PW, T).await.unwrap();
    c
}

pub const SUDO_PHRASE: &[u8] = b"the quick brown fox jumps over";
pub const ROOT_PHRASE: &[u8] = b"correct horse battery staple, twice";

/// verifiers for both levels, made the way the owner would
pub fn set_words(r: &Rig) {
    yrl::stepup::Verifier::set(&r.server_dir(), yrl::stepup::Level::Sudo, SUDO_PHRASE).unwrap();
    yrl::stepup::Verifier::set(&r.server_dir(), yrl::stepup::Level::Root, ROOT_PHRASE).unwrap();
}
