//! The server side: accept, handshake (silent on any failure), then a login (key first, then login + password), then PING / EXEC with rights checked by the server for every request.
//! Before the login the only frame that is accepted is LOGIN; anything else closes the connection. The rights of a session are the login's rights limited by the key's rights; the client never states a role.
use crate::keys::{read_authorized, KeyPair};
use crate::session::{read_msg, server_handshake_open, write_msg, REKEY_EVERY};
use crate::throttle::Throttle;
use crate::link::{self, drive, DriveOptions, Link};
use crate::users::{dummy_hash, read_users, verify_hash};
use crate::wire::{self, Frame};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use zeroize::Zeroize;

#[derive(Clone)]
pub struct ServerConfig {
    pub dir: PathBuf,
    pub handshake_timeout: Duration,
    /// the whole login (after the handshake) must finish within this time
    pub login_timeout: Duration,
    /// a connection that has been silent this long is dead (the client probes more often than this)
    pub dead_after: Duration,
    /// a session without a connection lives this long, then it is ended (terminals hung up, tunnels and transfers stopped)
    pub session_grace: Duration,
    pub link_window: usize,
    pub max_sessions: usize,
    pub max_sessions_per_key: usize,
    pub max_sessions_per_account: usize,
    /// shared Link-memory and active-operation admission for every session in this Executor
    pub resources: Arc<crate::resources::ResourceManager>,
    /// persistent FILE_PUT reservations shared by every Executor session
    pub disk: Option<Arc<crate::disk::DiskManager>>,
    pub sessions: Arc<Registry>,
    /// how this gatekeeper reaches its executor; None = start an executor inside this process on a private socket (single-process mode)
    pub gate: Option<crate::ipc::GatekeeperIpc>,
    /// failed step-ups, counted by the executor (shared by all its sessions)
    pub lockouts: Arc<crate::stepup::Lockouts>,
    pub enroll: Arc<crate::enroll::EnrollState>,
    /// who reports to the audit process (single-process mode starts one of its own)
    pub audit: crate::audit::AuditHandles,
    pub audit_every: u64,
    pub audit_enabled: bool,
    /// what the packet filter would decide about a source address: set only where the kernel's own filter cannot be had (tests); in real use the kernel drops and this is None
    pub gate_filter: Option<Arc<dyn Fn(std::net::IpAddr) -> bool + Send + Sync>>,
    /// the executor's own static key in single-process mode (None = a fresh one is made); clients pin its public half to talk to the executor end to end
    pub exec_identity: Option<KeyPair>,
    /// how the executor reaches the broker (None: ROOT step-ups are always refused)
    pub broker: Option<crate::ipc::GatekeeperIpc>,
    /// the broker's own static key in single-process mode; clients pin its public half for ROOT
    pub broker_identity: Option<KeyPair>,
    /// failed ROOT step-ups, counted by the broker
    pub root_lockouts: Arc<crate::stepup::Lockouts>,
    pub rekey_every: u64,
    pub max_exec_per_connection: usize,
    pub max_pty_per_connection: usize,
    pub max_transfers_per_connection: usize,
    pub max_tunnels_per_connection: usize,
    pub tunnel_connect_timeout: Duration,
    pub max_file_size: u64,
    /// limits for the child-process cgroup owned by one authenticated session
    pub session_cgroup_limits: crate::cgroup::SessionLimits,
    /// the program started as `<helper> fs-helper` for file work (by default this very executable)
    pub helper: PathBuf,
    pub max_login_attempts: u32,
    pub throttle: Arc<Throttle>,
    /// password checks running at the same time (each one needs ~20 MiB of memory)
    pub hash_slots: Arc<Semaphore>,
    /// connections served at the same time; more are dropped on arrival
    pub conn_slots: Arc<Semaphore>,
    /// every event line also goes here (tests check that no secret is ever logged)
    pub log_sink: Option<Arc<Mutex<Vec<String>>>>,
}

impl ServerConfig {
    /// reports in the background; the ordinary course of things never waits for the journal
    pub(crate) fn rec(&self, which: u8, ev: crate::auditlog::Event) {
        let c = match which {
            0 => &self.audit.gate,
            1 => &self.audit.exec,
            _ => &self.audit.broker,
        };
        if let Some(c) = c {
            c.record(ev);
        }
    }
    pub fn new(dir: PathBuf) -> Self {
        ServerConfig {
            dir,
            handshake_timeout: Duration::from_secs(5),
            login_timeout: Duration::from_secs(30),
            dead_after: Duration::from_secs(45),
            session_grace: Duration::from_secs(600),
            link_window: link::DEFAULT_WINDOW,
            max_sessions: 1024,
            max_sessions_per_key: 16,
            max_sessions_per_account: 16,
            resources: Arc::new(crate::resources::ResourceManager::default()),
            // Opened only by Executor (or by single-process `ensure_executor`); Gatekeeper must not
            // need read or write access to the persistent reservation ledger.
            disk: None,
            sessions: Arc::new(Registry::default()),
            gate: None,
            lockouts: Arc::new(crate::stepup::Lockouts::default()),
            enroll: Arc::new(crate::enroll::EnrollState::default()),
            audit: Default::default(),
            audit_every: 100,
            audit_enabled: true,
            gate_filter: None,
            exec_identity: None,
            broker: None,
            broker_identity: None,
            root_lockouts: Arc::new(crate::stepup::Lockouts::default()),
            rekey_every: REKEY_EVERY,
            max_exec_per_connection: 8,
            max_pty_per_connection: 4,
            max_transfers_per_connection: 4,
            max_tunnels_per_connection: 32,
            tunnel_connect_timeout: Duration::from_secs(10),
            max_file_size: crate::fshelper::MAX_FILE_SIZE,
            session_cgroup_limits: crate::cgroup::SessionLimits::default(),
            helper: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("yrld")),
            max_login_attempts: 3,
            throttle: Arc::new(Throttle::new(5, Duration::from_secs(30), Duration::from_secs(900))),
            hash_slots: Arc::new(Semaphore::new(4)),
            conn_slots: Arc::new(Semaphore::new(256)),
            log_sink: None,
        }
    }
    pub fn with_lock(mut self, after: u32, base: Duration, max: Duration) -> Self {
        self.throttle = Arc::new(Throttle::new(after, base, max));
        self
    }
    pub fn set_resource_limits(&mut self, limits: crate::resources::ResourceLimits) -> Result<(), &'static str> {
        self.resources = Arc::new(crate::resources::ResourceManager::new(limits)?);
        Ok(())
    }
    pub fn set_disk_limits(&mut self, limits: crate::disk::DiskLimits) -> anyhow::Result<()> {
        let ledger = crate::ipc::state_dir(&self.dir, "exec").join("disk-reservations");
        self.disk = Some(Arc::new(crate::disk::DiskManager::open(ledger, limits)?));
        Ok(())
    }
    pub(crate) fn log(&self, line: String) {
        eprintln!("[yrld] {line}");
        if let Some(s) = &self.log_sink {
            s.lock().unwrap().push(line);
        }
    }
}

pub async fn serve(listener: TcpListener, me: KeyPair, mut cfg: ServerConfig) {
    ensure_executor(&mut cfg).await;
    loop {
        let Ok((stream, peer)) = listener.accept().await else { continue };
        if cfg.gate_filter.as_ref().is_some_and(|f| !f(peer.ip().to_canonical())) {
            continue; // dropped before anything else, as the firewall would
        }
        let Ok(slot) = cfg.conn_slots.clone().try_acquire_owned() else { continue }; // full: dropped without a word
        let (cfg, me) = (cfg.clone(), me.clone());
        tokio::spawn(async move {
            handle_gate(stream, Some(peer), me, cfg).await;
            drop(slot);
        });
    }
}

/// connections one source address may hold at the same time over UDP
pub const MAX_UDP_PER_IP: usize = 8;

/// The same server over the reliable UDP stream. One socket; a datagram that belongs to a known connection goes to it, a datagram that opens one (the very first packet with something
/// in it) makes a new connection if the firewall emulation lets the address in and there is a free slot. Everything else is dropped without a word.
pub async fn serve_udp(sock: Arc<tokio::net::UdpSocket>, me: KeyPair, mut cfg: ServerConfig) {
    use std::collections::HashMap;
    ensure_executor(&mut cfg).await;
    let conns: Arc<Mutex<HashMap<u64, (SocketAddr, mpsc::Sender<Vec<u8>>)>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; 2048];
    loop {
        let Ok((n, peer)) = sock.recv_from(&mut buf).await else { continue };
        let pkt = &buf[..n];
        let Some(id) = crate::udp::conn_id_of(pkt) else { continue };
        let existing = {
            let mut g = conns.lock().unwrap();
            match g.get(&id) {
                Some((addr, tx)) if *addr == peer && !tx.is_closed() => Some(tx.clone()),
                Some((_, tx)) if tx.is_closed() => {
                    g.remove(&id);
                    None
                }
                Some(_) => continue, // the id of someone else's connection, from another address
                None => None,
            }
        };
        if let Some(tx) = existing {
            let _ = tx.try_send(pkt.to_vec());
            continue;
        }
        if crate::udp::is_opening(pkt).is_none() {
            continue;
        }
        if cfg.gate_filter.as_ref().is_some_and(|f| !f(peer.ip().to_canonical())) {
            continue;
        }
        // one address may not hold more than a few connections at once (half-open ones included): spoofing many ids from one place fills nothing
        if conns.lock().unwrap().values().filter(|(a, tx)| a.ip() == peer.ip() && !tx.is_closed()).count() >= MAX_UDP_PER_IP {
            continue;
        }
        let Ok(slot) = cfg.conn_slots.clone().try_acquire_owned() else { continue };
        let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
        let _ = tx.try_send(pkt.to_vec());
        conns.lock().unwrap().insert(id, (peer, tx));
        let s2 = sock.clone();
        let send: crate::udp::SendFn = Arc::new(move |b: &[u8]| {
            let _ = s2.try_send_to(b, peer);
        });
        let stream = crate::udp::spawn_stream(id, send, rx, true);
        let (cfg, me, conns2) = (cfg.clone(), me.clone(), conns.clone());
        tokio::spawn(async move {
            handle_gate(stream, Some(peer), me, cfg).await;
            conns2.lock().unwrap().remove(&id);
            drop(slot);
        });
    }
}

/// one password check; an unknown login is checked against a dummy hash so it costs the same
async fn check_password(cfg: &ServerConfig, login: Vec<u8>, password: zeroize::Zeroizing<Vec<u8>>) -> Option<(Vec<String>, Option<String>)> {
    let _slot = cfg.hash_slots.acquire().await.ok()?;
    let path = cfg.dir.join("users");
    let res = tokio::task::spawn_blocking(move || {
        let user = read_users(&path).into_iter().find(|u| u.login.as_bytes() == login.as_slice());
        let ok = match &user {
            Some(u) => verify_hash(&u.phc, &password),
            None => {
                verify_hash(dummy_hash(), &password);
                false
            }
        };
        if ok { user.map(|u| (u.rights, u.os_user)) } else { None }
    })
    .await;
    res.ok().flatten()
}


/// A session outlives the connections that carry it.
pub struct SessionEntry {
    link: Arc<Link>,
    key: Vec<u8>,
    account: String,
    auth: crate::executor::AuthSnapshot,
    resources: Mutex<Option<crate::resources::SessionPermit>>,
    inbound: Mutex<Option<mpsc::Sender<Frame>>>,
    attach_gen: std::sync::atomic::AtomicU64,
}

impl SessionEntry {
    fn end(&self) {
        self.link.close();
        self.inbound.lock().unwrap().take(); // the dispatcher sees the end of its input and tears everything down
        self.resources.lock().unwrap().take();
    }
}

#[derive(Default)]
pub struct Registry {
    map: Mutex<std::collections::HashMap<[u8; link::SID_LEN], Arc<SessionEntry>>>,
}

impl Registry {
    /// live sessions (for tests and for the log)
    pub fn len(&self) -> usize {
        self.map.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// one line per session: (next to send, next expected), (unconfirmed frames, bytes) - for diagnostics
    pub fn describe(&self) -> Vec<String> {
        self.map.lock().unwrap().values().map(|e| format!("pos={:?} unconfirmed={:?} closed={}", e.link.positions(), e.link.unconfirmed(), e.link.is_closed())).collect()
    }
    fn get(&self, sid: &[u8; link::SID_LEN]) -> Option<Arc<SessionEntry>> {
        self.map.lock().unwrap().get(sid).cloned()
    }
    fn remove(&self, sid: &[u8; link::SID_LEN]) {
        self.map.lock().unwrap().remove(sid);
    }
}

fn new_sid() -> [u8; link::SID_LEN] {
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    let mut b = [0u8; link::SID_LEN];
    OsRng.fill_bytes(&mut b);
    b
}

async fn send_plain<W: tokio::io::AsyncWrite + Unpin>(wr: &mut W, sec: &crate::session::Secure, f: Frame) -> bool {
    match sec.seal(&f) {
        Ok(m) => write_msg(wr, &m).await.is_ok(),
        Err(_) => false,
    }
}

/// Network-facing gatekeeper. It authenticates the device for admission and then carries only an
/// opaque Client <-> Executor Noise stream. LOGIN, RESUME, ACK/SEQ and operation frames never
/// terminate here.
async fn handle_gate<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(mut stream: S, peer: Option<SocketAddr>, me: KeyPair, cfg: ServerConfig) {
    use crate::ipc::{IPC_TUNNEL, IPC_TUNNEL_OK};
    let authorized = read_authorized(&cfg.dir.join("authorized_keys"));
    let window = crate::enroll::read_window(&cfg.dir);
    let hs = tokio::time::timeout(
        cfg.handshake_timeout,
        server_handshake_open(&mut stream, &me, &authorized, cfg.rekey_every, window.is_some()),
    ).await;
    let (sec, who) = match hs {
        Ok(Ok(x)) => x,
        Ok(Err(_)) => { cfg.log("connection dropped (gate handshake failed)".into()); return }
        Err(_) => { cfg.log("connection dropped (gate handshake timeout)".into()); return }
    };
    if !authorized.iter().any(|a| a.public == who.public) {
        if let Some(w) = window { enroll_guest(stream, sec, who, w, &cfg).await; }
        return;
    }
    let Some(gate) = cfg.gate.as_ref() else { return };
    let sec = Arc::new(sec);
    let (mut rd, mut wr) = tokio::io::split(stream);
    let Ok(Ok(msg)) = tokio::time::timeout(cfg.handshake_timeout, read_msg(&mut rd)).await else { return };
    let Ok(request) = sec.open(&msg) else { return };
    if request.kind != IPC_TUNNEL || !request.payload.is_empty() { return }
    let Some(mut executor) = crate::executor::open_tunnel(gate, peer).await else { return };
    let Ok(reply) = sec.seal(&Frame::new(IPC_TUNNEL_OK, 0, vec![])) else { return };
    if write_msg(&mut wr, &reply).await.is_err() { return }
    let mut client = crate::ipc::secure_tunnel(rd, wr, sec);
    let _ = tokio::io::copy_bidirectional(&mut client, &mut executor).await;
}

/// `peer` is None for a connection that arrived through a relay: the relay is not trusted to say who the client is, so there is no address to throttle by
pub(crate) async fn handle_inner<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(mut stream: S, peer: Option<SocketAddr>, me: KeyPair, cfg: ServerConfig) {
    // read afresh on every connection: a revoked key acts at once
    let authorized = read_authorized(&cfg.dir.join("authorized_keys"));
    // outside a window an unknown key gets silence; while the owner has one open it may complete the handshake, to present the code and nothing else
    let window = crate::enroll::read_window(&cfg.dir);
    let hs = tokio::time::timeout(cfg.handshake_timeout, server_handshake_open(&mut stream, &me, &authorized, cfg.rekey_every, window.is_some())).await;
    let (sec, who) = match hs {
        Ok(Ok(x)) => x,
        Ok(Err(_)) => {
            cfg.log("connection dropped (handshake failed)".into());
            return; // silence: nothing was written
        }
        Err(_) => {
            cfg.log("connection dropped (handshake timeout)".into());
            return;
        }
    };
    if !authorized.iter().any(|a| a.public == who.public) {
        // a guest: the only thing it may do is present the enrolment code
        if let Some(w) = window {
            enroll_guest(stream, sec, who, w, &cfg).await;
        }
        return;
    }
    cfg.log(format!("key accepted: '{}'", who.label));
    let key_id = format!("k:{}", hex::encode(&who.public));
    let ip_id = match peer {
        Some(p) => format!("ip:{}", p.ip()),
        None => format!("ip:relay:{}", hex::encode(new_sid())), // unique: the address of a relayed client is unknown, so nobody shares a lock
    };
    let sec = Arc::new(sec);
    let (mut rd, mut wr) = tokio::io::split(stream);
    let login_deadline = Instant::now() + cfg.login_timeout;
    let mut attempts = 0u32;
    // before the session starts only two things are accepted: a login (new session) or a resume (an existing one)
    loop {
        let wait = login_deadline.saturating_duration_since(Instant::now());
        let msg = match tokio::time::timeout(wait, read_msg(&mut rd)).await {
            Ok(Ok(m)) => m,
            _ => return,
        };
        let Ok(mut frame) = sec.open(&msg) else {
            cfg.log("session closed (bad frame)".into());
            return;
        };
        match frame.kind {
            link::RESUME => {
                let Ok(b) = <[u8; link::SID_LEN + 8]>::try_from(frame.payload.as_slice()) else { return };
                if cfg.throttle.locked(&key_id) || cfg.throttle.locked(&ip_id) {
                    return;
                }
                let sid: [u8; link::SID_LEN] = b[..link::SID_LEN].try_into().unwrap();
                let client_expected = u64::from_be_bytes(b[link::SID_LEN..].try_into().unwrap());
                match cfg.sessions.get(&sid) {
                    Some(e) if e.key == who.public && !e.link.is_closed() && client_expected <= e.link.positions().0 && crate::executor::auth_snapshot(&cfg.dir, &e.key, &e.account).as_ref() == Some(&e.auth) => {
                        let Some(network) = cfg.resources.try_network_connection(&e.key, &e.account) else {
                            cfg.log(format!("resume deferred via '{}': network connection budget exhausted", who.label));
                            return;
                        };
                        let reply = e.link.positions().1.to_be_bytes().to_vec();
                        if !send_plain(&mut wr, &sec, Frame::new(link::RESUMED, 0, reply)).await {
                            return;
                        }
                        cfg.log(format!("session resumed via '{}'", who.label));
                        cfg.rec(1, crate::auditlog::Event::new("resume", crate::auditlog::LEVEL_USER, crate::auditlog::RESULT_OK).session(&sid).device(&who.public));
                        run_connection(e, rd, wr, sec, client_expected, sid, &cfg, network).await;
                        return;
                    }
                    _ => {
                        cfg.throttle.fail(&key_id);
                        cfg.throttle.fail(&ip_id);
                        cfg.log(format!("resume refused via '{}'", who.label));
                        cfg.rec(1, crate::auditlog::Event::new("resume", crate::auditlog::LEVEL_NONE, crate::auditlog::RESULT_DENIED).device(&who.public));
                        let _ = send_plain(&mut wr, &sec, Frame::new(link::RESUME_REFUSED, 0, vec![])).await;
                        return;
                    }
                }
            }
            wire::LOGIN => {
            let parsed = wire::decode_login(&frame.payload).map(|(l, p)| (l.to_vec(), p.to_vec()));
            frame.payload.zeroize();
            let Ok((login, password)) = parsed else {
                cfg.log("session closed (bad login frame)".into());
                break;
            };
            let password = zeroize::Zeroizing::new(password);
            attempts += 1;
            let typed_login = String::from_utf8_lossy(&login).into_owned();
            let locked = cfg.throttle.locked(&key_id) || cfg.throttle.locked(&ip_id);
            let granted = if locked {
                None // locked: even the right password is not looked at
            } else {
                check_password(&cfg, login, password).await
            };
            // the system identity (which user the commands run as) is not the gatekeeper's business: the executor decides it
            let granted = granted.map(|(user_rights, _os_user)| user_rights.into_iter().filter(|r| who.rights.contains(r)).collect::<Vec<String>>());
            match granted {
                Some(eff) => {
                    cfg.throttle.ok(&key_id);
                    cfg.throttle.ok(&ip_id);
                    cfg.log(format!("login ok via '{}'", who.label));
                    cfg.rec(1, crate::auditlog::Event::new("login", crate::auditlog::LEVEL_USER, crate::auditlog::RESULT_OK).device(&who.public).user(&typed_login));
                    let Some(resources) = cfg.resources.try_session(
                        &who.public,
                        &typed_login,
                        cfg.max_sessions,
                        cfg.max_sessions_per_key,
                        cfg.max_sessions_per_account,
                    ) else {
                        cfg.log(format!("login refused via '{}': too many sessions", who.label));
                        let _ = send_plain(&mut wr, &sec, Frame::new(wire::LOGIN_FAIL, 0, vec![])).await;
                        return;
                    };
                    let Some(network) = cfg.resources.try_network_connection(&who.public, &typed_login) else {
                        cfg.log(format!("login refused via '{}': network connection budget exhausted", who.label));
                        let _ = send_plain(&mut wr, &sec, Frame::new(wire::LOGIN_FAIL, 0, vec![])).await;
                        return;
                    };
                    // This code runs in Executor. Identity and rights came from the authenticated
                    // inner channel and are checked against Executor-owned files here.
                    let Some(auth) = crate::executor::auth_snapshot(&cfg.dir, &who.public, &typed_login) else { return };
                    let Some((to_exec, mut from_exec)) = crate::executor::direct_session(&cfg, &who.public, &typed_login, &eff).await else {
                        cfg.log(format!("login refused via '{}': executor authorization failed", who.label));
                        let _ = send_plain(&mut wr, &sec, Frame::new(wire::LOGIN_FAIL, 0, vec![])).await;
                        return;
                    };
                    if crate::executor::auth_snapshot(&cfg.dir, &who.public, &typed_login).as_ref() != Some(&auth) { return }
                    let sid = new_sid();
                    let link = Link::new_budgeted(cfg.link_window, resources.link_budget());
                    let (in_tx, mut in_rx) = mpsc::channel::<Frame>(64);
                    let entry = Arc::new(SessionEntry {
                        link: link.clone(),
                        key: who.public.clone(),
                        account: typed_login,
                        auth,
                        resources: Mutex::new(Some(resources)),
                        inbound: Mutex::new(Some(in_tx)),
                        attach_gen: Default::default(),
                    });
                    cfg.sessions.map.lock().unwrap().insert(sid, entry.clone());
                    let (watch, watch_cfg) = (entry.clone(), cfg.clone());
                    tokio::spawn(async move {
                        let mut tick = tokio::time::interval(Duration::from_millis(200));
                        loop {
                            tick.tick().await;
                            if watch.link.is_closed() { break }
                            if crate::executor::auth_snapshot(&watch_cfg.dir, &watch.key, &watch.account).as_ref() != Some(&watch.auth) {
                                watch_cfg.log("session ended: device or account authorization changed".into());
                                let _ = tokio::time::timeout(Duration::from_millis(200), watch.link.push(&Frame::new(wire::CLOSE, 0, vec![]))).await;
                                for _ in 0..10 {
                                    if watch.link.unconfirmed().0 == 0 { break }
                                    tokio::time::sleep(Duration::from_millis(20)).await;
                                }
                                watch.end();
                                watch_cfg.sessions.remove(&sid);
                                break;
                            }
                        }
                    });
                    // what the client sends goes to the executor, what the executor says goes to the client; when either end of the pipe is gone the session is over
                    let l2 = link.clone();
                    let (e2, cfg2) = (entry.clone(), cfg.clone());
                    tokio::spawn(async move {
                        let up = async {
                            while let Some(f) = in_rx.recv().await {
                                if to_exec.send(f).await.is_err() {
                                    break;
                                }
                            }
                        };
                        let down = async {
                            while let Some(f) = from_exec.recv().await {
                                if l2.push(&f).await.is_err() {
                                    break;
                                }
                            }
                        };
                        tokio::select! { _ = up => {}, _ = down => {} }
                        e2.end();
                        cfg2.sessions.remove(&sid);
                    });
                    if !send_plain(&mut wr, &sec, Frame::new(wire::LOGIN_OK, 0, eff.join(",").into_bytes())).await || !send_plain(&mut wr, &sec, Frame::new(link::SESSION, 0, sid.to_vec())).await {
                        entry.end();
                        cfg.sessions.remove(&sid);
                        return;
                    }
                    run_connection(entry, rd, wr, sec, 0, sid, &cfg, network).await;
                    return;
                }
                None => {
                    if !locked {
                        // an attempt that was not even checked is not a new failure: the lock must not be prolonged by whoever knocks on it
                        cfg.throttle.fail(&key_id);
                        cfg.throttle.fail(&ip_id);
                    }
                    // the typed login is not logged: people type passwords there. The reason is for the owner's own log; the sender is told nothing but "no".
                    let why = if locked { "locked after repeated failures (the password was not even looked at)" } else { crate::users::why_unreadable(&cfg.dir.join("users")).unwrap_or("wrong password, or no such account") };
                    cfg.log(format!("login failed via '{}': {why}", who.label));
                    cfg.rec(1, crate::auditlog::Event::new("login", crate::auditlog::LEVEL_NONE, if locked { crate::auditlog::RESULT_LOCKED } else { crate::auditlog::RESULT_DENIED }).device(&who.public));
                    let _ = send_plain(&mut wr, &sec, Frame::new(wire::LOGIN_FAIL, 0, vec![])).await;
                    if attempts >= cfg.max_login_attempts {
                        break;
                    }
                }
            }
            }
            _ => {
                cfg.log(format!("closed '{}': a frame before the login", who.label));
                return;
            }
        }
    }
}

/// one connection of a session: runs until it breaks; the session itself stays for `session_grace`
async fn run_connection<R: tokio::io::AsyncRead + Unpin + Send, W: tokio::io::AsyncWrite + Unpin + Send>(entry: Arc<SessionEntry>, rd: R, wr: W, sec: Arc<crate::session::Secure>, peer_expected: u64, sid: [u8; link::SID_LEN], cfg: &ServerConfig, network: crate::resources::NetworkConnectionPermit) {
    let gen = entry.attach_gen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    let Some(sink) = entry.inbound.lock().unwrap().clone() else { return };
    let flow = network.flow();
    let end = drive(&entry.link, rd, wr, sec, sink, peer_expected, &DriveOptions { dead_after: cfg.dead_after, ping_every: None }, Some(flow)).await;
    if entry.link.is_closed() {
        cfg.sessions.remove(&sid);
        return;
    }
    cfg.log(format!("connection lost ({end:?}); the session is kept"));
    let (cfg2, e2) = (cfg.clone(), entry.clone());
    tokio::spawn(async move {
        tokio::time::sleep(cfg2.session_grace).await;
        if e2.attach_gen.load(std::sync::atomic::Ordering::SeqCst) == gen {
            cfg2.log("session expired without a connection".into());
            e2.end();
            cfg2.sessions.remove(&sid);
        }
    });
}

/// Serve through a relay: this machine only dials OUT. `standby` connections wait at the relay at all times; each one that gets a client is handled like an accepted connection
/// and replaced at once.
pub async fn serve_via_relay(relay_addr: String, me: KeyPair, mut cfg: ServerConfig, standby: usize) {
    ensure_executor(&mut cfg).await;
    let rid = crate::relay::rendezvous_id(&me.public);
    let mut loops = vec![];
    for _ in 0..standby.max(1) {
        let (relay_addr, me, cfg) = (relay_addr.clone(), me.clone(), cfg.clone());
        loops.push(tokio::spawn(async move {
            let mut backoff = Duration::from_millis(100);
            loop {
                let conn = tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(&relay_addr)).await;
                let Ok(Ok(mut stream)) = conn else {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(3));
                    continue;
                };
                backoff = Duration::from_millis(100);
                use tokio::io::AsyncWriteExt;
                if stream.write_all(&crate::relay::header(crate::relay::ROLE_SERVER, &rid)).await.is_err() {
                    continue;
                }
                // wait until a client's first bytes arrive (or the relay gives up on us), then hand the socket to the normal handler
                match tokio::time::timeout(Duration::from_secs(150), stream.readable()).await {
                    Ok(Ok(())) => {}
                    _ => continue,
                }
                let mut probe = [0u8; 1];
                if !matches!(stream.peek(&mut probe).await, Ok(n) if n > 0) {
                    continue; // closed without a client
                }
                cfg.log("a client came through the relay".into());
                let (cfg2, me2) = (cfg.clone(), me.clone());
                tokio::spawn(async move { handle_gate(stream, None, me2, cfg2).await });
            }
        }));
    }
    for l in loops {
        let _ = l.await;
    }
}

/// single-process mode: the executor runs inside this process, but is still reached through the real local socket and the same four checks
pub async fn ensure_executor(cfg: &mut ServerConfig) {
    if cfg.gate.is_some() {
        return;
    }
    if cfg.disk.is_none() {
        cfg.set_disk_limits(crate::disk::DiskLimits::default()).expect("cannot open the Executor disk reservation ledger");
    }
    // the broker first (the executor is its client), then the executor
    let exec_key = cfg.exec_identity.clone().unwrap_or_else(crate::keys::generate);
    cfg.exec_identity = Some(exec_key.clone());
    let (bipc, eto_b) = crate::ipc::ephemeral_pair(cfg.dir.join("broker.sock"), cfg.broker_identity.clone(), exec_key.clone());
    let (eipc, gipc) = crate::ipc::ephemeral(cfg.dir.join("ipc.sock"), cfg.exec_identity.clone());
    if cfg.audit_enabled && cfg.audit.exec.is_none() {
        // the audit process, in this process but behind its own door, with a key only it holds; each part reports with its own key
        let svc = crate::audit::AuditService::open(&cfg.dir, cfg.audit_every).expect("cannot open the audit journal");
        let audit_key = crate::keys::generate();
        let owner_key = crate::keys::generate();
        let fw_key = crate::keys::generate();
        use crate::auditlog::Source::*;
        let ipc = crate::audit::AuditIpc { socket: cfg.dir.join("audit.sock"), key: audit_key.clone(), sources: vec![(Gatekeeper, gipc.key.public.clone()), (Executor, exec_key.public.clone()), (Broker, bipc.key.public.clone()), (Owner, owner_key.public.clone()), (Firewall, fw_key.public.clone())], expected_uid: Some(unsafe { libc::geteuid() }), expected_exe: None };
        let l = crate::ipc::bind_socket(&ipc.socket).expect("cannot create the audit socket");
        let logger = cfg.clone();
        tokio::spawn(crate::audit::serve_ipc(l, svc, ipc.clone(), Arc::new(move |m| logger.log(m))));
        let mk = |k: &crate::keys::KeyPair| crate::audit::AuditClient::new(ipc.socket.clone(), k.clone(), audit_key.public.clone());
        cfg.audit = crate::audit::AuditHandles { gate: Some(mk(&gipc.key)), exec: Some(mk(&exec_key)), broker: Some(mk(&bipc.key)), owner: Some(mk(&owner_key)), firewall: Some(mk(&fw_key)) };
    }
    let blistener = crate::ipc::bind_socket(&bipc.socket).expect("cannot create the broker socket");
    tokio::spawn(crate::broker::serve_ipc(blistener, cfg.clone(), bipc));
    cfg.broker = Some(eto_b);
    let listener = crate::ipc::bind_socket(&eipc.socket).expect("cannot create the local socket");
    tokio::spawn(crate::executor::serve_ipc(listener, cfg.clone(), eipc));
    cfg.gate = Some(gipc);
}

/// a key nobody knows, during an open window: one frame is allowed, the request with the code
async fn enroll_guest<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(stream: S, sec: crate::session::Secure, who: crate::keys::Authorized, w: crate::enroll::Window, cfg: &ServerConfig) {
    use crate::enroll::*;
    let (mut rd, mut wr) = tokio::io::split(stream);
    let Ok(Ok(msg)) = tokio::time::timeout(Duration::from_secs(10), read_msg(&mut rd)).await else { return };
    let Ok(f) = sec.open(&msg) else { return };
    if f.kind != ENROLL {
        return;
    }
    let Ok((code, label)) = decode_request(&f.payload) else { return };
    cfg.log("enrolment: a request with a code".into()); // neither the code nor the key is logged
    cfg.rec(0, crate::auditlog::Event::new("enroll_guest", crate::auditlog::LEVEL_NONE, crate::auditlog::RESULT_OK).device(&who.public));
    let verdict = cfg.enroll.serve(&cfg.dir, &w, &who.public, &code, &label, &cfg.hash_slots).await;
    let kind = if matches!(verdict, Outcome::Accepted) { ENROLL_OK } else { ENROLL_FAIL };
    let _ = send_plain(&mut wr, &sec, Frame::new(kind, 0, vec![])).await;
}
