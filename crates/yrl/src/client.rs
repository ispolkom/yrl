//! The client side: connect directly to host:port with the server's known public key.
use crate::filewire::{self as fw, GetReq, PutReq};
use crate::crypto_profile::{Context as CryptoContext, Policy as CryptoPolicy, ProfileId, ProfileStore, CLASSICAL_V1};
use crate::keys::KeyPair;
use crate::link;
use crate::session::{client_handshake_context, read_msg, write_msg, Secure, REKEY_EVERY};
use crate::wire::{self, split_id, with_id, ExecReq, Frame};
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::TcpStream;

/// a connection of either kind: TCP, or the reliable stream over UDP (src/udp.rs)
pub trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}
pub type BoxIo = Box<dyn Io>;
type OwnedReadHalf = ReadHalf<BoxIo>;
type OwnedWriteHalf = WriteHalf<BoxIo>;
use tokio::sync::{mpsc, Mutex};

/// A byte-stream route below Noise and the resumable session layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Udp,
    Tcp,
    Relay,
}

/// Bounded connection-manager counters. No addresses, keys, or account names are retained.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConnectionDiagnostics {
    pub current: Option<Transport>,
    pub last_rtt: Option<Duration>,
    pub attempts_udp: u64,
    pub attempts_tcp: u64,
    pub attempts_relay: u64,
    pub failures: u64,
    pub disconnects: u64,
    pub resumes: u64,
    pub switches: u64,
    pub last_end: Option<String>,
}

#[derive(Clone, Debug)]
struct Route {
    transport: Transport,
    address: String,
}

impl ConnectionDiagnostics {
    fn attempted(&mut self, transport: Transport) {
        match transport {
            Transport::Udp => self.attempts_udp += 1,
            Transport::Tcp => self.attempts_tcp += 1,
            Transport::Relay => self.attempts_relay += 1,
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ExecResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub code: i32,
    /// (code, text) if the server answered with an error
    pub error: Option<(u16, String)>,
}

/// How the client behaves when the network under it breaks.
#[derive(Clone, Debug)]
pub struct ClientOptions {
    /// Pinned Executor static public key. When present, the Gatekeeper connection is used only as
    /// an opaque carrier and a second Noise IK handshake is established end to end.
    pub executor_public: Option<Vec<u8>>,
    pub rekey_every: u64,
    /// a probe goes out when nothing was sent for this long
    pub ping_every: Duration,
    /// nothing heard for this long: the connection is dead, reconnect
    pub dead_after: Duration,
    pub retry_min: Duration,
    pub retry_max: Duration,
    /// if the session cannot be resumed for this long it is considered lost
    pub give_up_after: Duration,
    pub window: usize,
    /// total time allowed to establish the initial session over all configured routes
    pub connect_timeout: Duration,
    /// maximum time for one route attempt, including Noise and RESUME
    pub route_timeout: Duration,
    /// optional TCP relay route; direct routes remain available and are preferred
    pub relay: Option<String>,
    /// before every direct connection (and every reconnection) send the one datagram that asks the machine's firewall to let this address in
    pub knock: Option<Knock>,
    /// host:port of the server's UDP data port: the session then runs over the reliable UDP stream, and TCP is only the fallback when this is not answered
    pub udp: Option<String>,
    /// Persistent per-peer profile high-water marks. Production clients should set this.
    pub crypto_profile_store: Option<std::path::PathBuf>,
    pub minimum_crypto_profile: ProfileId,
}

#[derive(Clone, Debug)]
pub struct Knock {
    /// host:port of the SPA datagram port (UDP)
    pub udp: String,
    /// how long to wait after the datagram before trying to connect (it gets no answer)
    pub settle: Duration,
}

impl Default for ClientOptions {
    fn default() -> Self {
        ClientOptions {
            executor_public: None,
            rekey_every: REKEY_EVERY,
            ping_every: Duration::from_secs(10),
            dead_after: Duration::from_secs(30),
            retry_min: Duration::from_millis(100),
            retry_max: Duration::from_secs(3),
            give_up_after: Duration::from_secs(900),
            window: link::DEFAULT_WINDOW,
            connect_timeout: Duration::from_secs(10),
            route_timeout: Duration::from_secs(3),
            relay: None,
            knock: None,
            udp: None,
            crypto_profile_store: None,
            minimum_crypto_profile: CLASSICAL_V1,
        }
    }
}

fn configured_routes(addr: &str, opts: &ClientOptions) -> Vec<Route> {
    let mut routes = Vec::with_capacity(3);
    if let Some(udp) = &opts.udp {
        routes.push(Route { transport: Transport::Udp, address: udp.clone() });
    }
    if !addr.is_empty() {
        routes.push(Route { transport: Transport::Tcp, address: addr.to_string() });
    }
    if let Some(relay) = &opts.relay {
        routes.push(Route { transport: Transport::Relay, address: relay.clone() });
    }
    routes
}

/// Opens one configured byte-stream route. Noise authentication is deliberately performed by the caller on every route.
async fn open_stream(route: &Route, me: &KeyPair, server_public: &[u8], opts: &ClientOptions) -> Result<BoxIo> {
    match route.transport {
        Transport::Udp => {
            if let Some(k) = &opts.knock {
                knock(k, me, server_public, crate::spa::SERVICE_WORK).await?;
            }
            let sa = tokio::net::lookup_host(route.address.as_str()).await?.next().ok_or_else(|| anyhow::anyhow!("no such address"))?;
            Ok(Box::new(crate::udp::connect(sa).await?))
        }
        Transport::Tcp => {
            if let Some(k) = &opts.knock {
                knock(k, me, server_public, crate::spa::SERVICE_WORK).await?;
            }
            Ok(Box::new(TcpStream::connect(&route.address).await?))
        }
        Transport::Relay => {
            use tokio::io::AsyncWriteExt;
            let mut s = TcpStream::connect(&route.address).await?;
            s.write_all(&crate::relay::header(crate::relay::ROLE_CLIENT, &crate::relay::rendezvous_id(server_public))).await?;
            Ok(Box::new(s))
        }
    }
}

async fn open_authenticated_stream(route: &Route, me: &KeyPair, gate_public: &[u8], opts: &ClientOptions) -> Result<(BoxIo, Secure)> {
    let mut outer = open_stream(route, me, gate_public, opts).await?;
    let gate_sec = Arc::new(profiled_handshake(&mut outer, me, gate_public, opts, CryptoContext::Gatekeeper).await?);
    let Some(executor_public) = opts.executor_public.as_deref() else {
        return Ok((outer, Arc::try_unwrap(gate_sec).map_err(|_| anyhow::anyhow!("gate handshake state is shared"))?));
    };
    let (mut rd, mut wr) = tokio::io::split(outer);
    let request = gate_sec.seal(&Frame::new(crate::ipc::IPC_TUNNEL, 0, vec![]))?;
    write_msg(&mut wr, &request).await?;
    let reply = gate_sec.open(&read_msg(&mut rd).await?)?;
    if reply.kind != crate::ipc::IPC_TUNNEL_OK || !reply.payload.is_empty() {
        bail!("gatekeeper refused the executor tunnel");
    }
    let tunnel = crate::ipc::secure_tunnel(rd, wr, gate_sec);
    let mut inner: BoxIo = Box::new(tunnel);
    let sec = profiled_handshake(&mut inner, me, executor_public, opts, CryptoContext::Executor).await?;
    Ok((inner, sec))
}

async fn profiled_handshake<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, me: &KeyPair, peer: &[u8], opts: &ClientOptions, context: CryptoContext) -> Result<Secure> {
    let mut policy = CryptoPolicy::from_env()?;
    policy.minimum = policy.minimum.max(opts.minimum_crypto_profile);
    let mut store = match &opts.crypto_profile_store { Some(path) => Some(ProfileStore::open(path)?), None => None };
    if let Some(s) = store.as_ref() { policy.minimum = s.minimum(context, peer, policy.minimum); }
    policy.validate()?;
    let secure = client_handshake_context(stream, me, peer, opts.rekey_every, context, policy).await?;
    if let Some(s) = store.as_mut() { s.remember(context, peer, secure.profile())?; }
    Ok(secure)
}

/// one signed datagram, no answer expected; the address it came from is the one that is let in
async fn knock(k: &Knock, me: &KeyPair, server_public: &[u8], service: u8) -> Result<()> {
    let sock = tokio::net::UdpSocket::bind(if k.udp.starts_with('[') { "[::]:0" } else { "0.0.0.0:0" }).await?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    sock.send_to(&crate::spa::build(me, server_public, service, now), &k.udp).await?;
    tokio::time::sleep(k.settle).await;
    Ok(())
}

struct Pre {
    rd: OwnedReadHalf,
    wr: OwnedWriteHalf,
    sec: Arc<Secure>,
    route: usize,
}

#[derive(Clone)]
struct Ident {
    me: KeyPair,
    server_public: Vec<u8>,
    opts: ClientOptions,
    routes: Vec<Route>,
    diagnostics: Arc<StdMutex<ConnectionDiagnostics>>,
}

pub struct Client {
    link: Arc<link::Link>,
    pub(crate) waiting: Arc<Mutex<HashMap<u64, mpsc::Sender<Frame>>>>,
    pongs: Mutex<mpsc::Receiver<Frame>>,
    pong_tx: mpsc::Sender<Frame>,
    pub(crate) next_id: std::sync::atomic::AtomicU64,
    pre: Mutex<Option<Pre>>,
    ident: Ident,
    running: std::sync::atomic::AtomicBool,
    lost: Arc<std::sync::atomic::AtomicBool>,
    diagnostics: Arc<StdMutex<ConnectionDiagnostics>>,
}

enum Resume {
    Ok(OwnedReadHalf, OwnedWriteHalf, Arc<Secure>, u64),
    Refused,
    Transient,
}

async fn try_resume(id: &Ident, route: usize, sid: &[u8], link: &link::Link, diagnostics: &StdMutex<ConnectionDiagnostics>) -> Resume {
    let o = &id.opts;
    let Some(selected) = id.routes.get(route) else { return Resume::Transient };
    diagnostics.lock().unwrap().attempted(selected.transport);
    let started = std::time::Instant::now();
    let attempt = async {
        let (stream, sec) = open_authenticated_stream(selected, &id.me, &id.server_public, o).await?;
        let sec = Arc::new(sec);
        let (mut rd, mut wr) = tokio::io::split(stream);
        let mut p = sid.to_vec();
        p.extend_from_slice(&link.positions().1.to_be_bytes());
        let m = sec.seal(&Frame::new(link::RESUME, 0, p))?;
        write_msg(&mut wr, &m).await?;
        let msg = read_msg(&mut rd).await?;
        let f = sec.open(&msg)?;
        Ok::<_, anyhow::Error>((rd, wr, sec, f))
    };
    let Ok(Ok((rd, wr, sec, f))) = tokio::time::timeout(o.route_timeout, attempt).await else {
        let mut d = diagnostics.lock().unwrap();
        d.failures += 1;
        return Resume::Transient;
    };
    match f.kind {
        link::RESUMED => match <[u8; 8]>::try_from(f.payload.as_slice()) {
            Ok(b) => {
                let mut d = diagnostics.lock().unwrap();
                d.current = Some(selected.transport);
                d.last_rtt = Some(started.elapsed());
                Resume::Ok(rd, wr, sec, u64::from_be_bytes(b))
            }
            Err(_) => Resume::Transient,
        },
        link::RESUME_REFUSED => Resume::Refused,
        _ => Resume::Transient,
    }
}

/// keeps the session alive over as many connections as it takes
async fn manage(link: Arc<link::Link>, id: Ident, sid: Vec<u8>, first: Pre, sink: mpsc::Sender<Frame>, lost: Arc<std::sync::atomic::AtomicBool>) {
    let o = id.opts.clone();
    let dopt = link::DriveOptions { dead_after: o.dead_after, ping_every: Some(o.ping_every) };
    let diagnostics = id.diagnostics.clone();
    let first_route = first.route;
    let mut conn = Some((first.rd, first.wr, first.sec, 0u64, first.route));
    let mut last_ok = std::time::Instant::now();
    let mut backoff = o.retry_min;
    let mut next_route = (first_route + 1) % id.routes.len();
    let mut failed_in_cycle = 0usize;
    let mut previous_route = first_route;
    loop {
        if let Some((rd, wr, sec, peer_expected, route)) = conn.take() {
            let end = link::drive(&link, rd, wr, sec, sink.clone(), peer_expected, &dopt, None).await;
            if end == link::End::Closed || link.is_closed() {
                break;
            }
            {
                let mut d = diagnostics.lock().unwrap();
                d.current = None;
                d.disconnects += 1;
                d.last_end = Some(format!("{end:?}"));
            }
            previous_route = route;
            next_route = (route + 1) % id.routes.len();
            last_ok = std::time::Instant::now();
            backoff = o.retry_min;
            failed_in_cycle = 0;
        }
        if last_ok.elapsed() > o.give_up_after {
            lost.store(true, std::sync::atomic::Ordering::SeqCst);
            break;
        }
        if failed_in_cycle >= id.routes.len() {
            let jitter = Duration::from_millis(rand_ms(backoff.as_millis() as u64 / 4 + 1));
            tokio::time::sleep(backoff + jitter).await;
            backoff = (backoff * 2).min(o.retry_max);
            failed_in_cycle = 0;
        }
        let route = next_route;
        next_route = (next_route + 1) % id.routes.len();
        match try_resume(&id, route, &sid, &link, &diagnostics).await {
            Resume::Ok(rd, wr, sec, e) => {
                let mut d = diagnostics.lock().unwrap();
                d.resumes += 1;
                if route != previous_route {
                    d.switches += 1;
                }
                drop(d);
                conn = Some((rd, wr, sec, e, route));
                backoff = o.retry_min;
                failed_in_cycle = 0;
            }
            Resume::Refused => {
                lost.store(true, std::sync::atomic::Ordering::SeqCst); // the server no longer has this session
                break;
            }
            Resume::Transient => failed_in_cycle += 1,
        }
    }
    link.close();
}

fn rand_ms(below: u64) -> u64 {
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    OsRng.next_u64() % below.max(1)
}

impl Client {
    pub async fn connect(addr: &str, me: &KeyPair, server_public: &[u8], timeout: Duration) -> Result<Client> {
        Self::connect_opts(addr, me, server_public, ClientOptions { connect_timeout: timeout, ..Default::default() }).await
    }

    pub async fn connect_with(addr: &str, me: &KeyPair, server_public: &[u8], timeout: Duration, rekey_every: u64) -> Result<Client> {
        Self::connect_opts(addr, me, server_public, ClientOptions { connect_timeout: timeout, rekey_every, ..Default::default() }).await
    }

    pub async fn connect_pinned(addr: &str, me: &KeyPair, gate_public: &[u8], executor_public: &[u8], timeout: Duration) -> Result<Client> {
        Self::connect_opts(addr, me, gate_public, ClientOptions { executor_public: Some(executor_public.to_vec()), connect_timeout: timeout, ..Default::default() }).await
    }

    pub async fn connect_pinned_with(addr: &str, me: &KeyPair, gate_public: &[u8], executor_public: &[u8], timeout: Duration, rekey_every: u64) -> Result<Client> {
        Self::connect_opts(addr, me, gate_public, ClientOptions { executor_public: Some(executor_public.to_vec()), connect_timeout: timeout, rekey_every, ..Default::default() }).await
    }

    /// connects and does the key handshake; the session starts with `login`
    pub async fn connect_opts(addr: &str, me: &KeyPair, server_public: &[u8], opts: ClientOptions) -> Result<Client> {
        let routes = configured_routes(addr, &opts);
        if routes.is_empty() {
            bail!("no connection routes configured");
        }
        let diagnostics = Arc::new(StdMutex::new(ConnectionDiagnostics::default()));
        let started = std::time::Instant::now();
        let mut route = 0usize;
        let mut last_error = None;
        let (stream, sec, selected, rtt) = loop {
            let selected = route;
            let spec = &routes[selected];
            diagnostics.lock().unwrap().attempted(spec.transport);
            let attempt_started = std::time::Instant::now();
            let remaining = opts.connect_timeout.saturating_sub(started.elapsed());
            if remaining.is_zero() {
                return Err(last_error.unwrap_or_else(|| anyhow::anyhow!("all connection routes timed out")));
            }
            let attempt = async {
                open_authenticated_stream(spec, me, server_public, &opts).await
            };
            let attempt = tokio::time::timeout(opts.route_timeout.min(remaining), attempt).await;
            match attempt {
                Ok(Ok((stream, sec))) => break (stream, sec, selected, attempt_started.elapsed()),
                Ok(Err(e)) => last_error = Some(e),
                Err(_) => last_error = Some(anyhow::anyhow!("route {:?} timed out", spec.transport)),
            }
            diagnostics.lock().unwrap().failures += 1;
            route = (route + 1) % routes.len();
            if route == 0 {
                let remaining = opts.connect_timeout.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return Err(last_error.unwrap());
                }
                tokio::time::sleep(Duration::from_millis(100).min(remaining)).await;
            }
        };
        {
            let mut d = diagnostics.lock().unwrap();
            d.current = Some(routes[selected].transport);
            d.last_rtt = Some(rtt);
        }
        let (rd, wr) = tokio::io::split(stream);
        let (pong_tx, pong_rx) = mpsc::channel(16);
        let ident = Ident {
            me: me.clone(),
            server_public: server_public.to_vec(),
            opts: opts.clone(),
            routes,
            diagnostics: diagnostics.clone(),
        };
        Ok(Client {
            link: link::Link::new(opts.window),
            waiting: Arc::new(Mutex::new(HashMap::new())),
            pongs: Mutex::new(pong_rx),
            pong_tx,
            next_id: std::sync::atomic::AtomicU64::new(random_request_id()),
            pre: Mutex::new(Some(Pre { rd, wr, sec: Arc::new(sec), route: selected })),
            ident,
            running: std::sync::atomic::AtomicBool::new(false),
            lost: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            diagnostics,
        })
    }

    /// how many requests/streams are still waiting for frames (zero when everything finished and was cleaned up)
    pub async fn pending_streams(&self) -> usize {
        self.waiting.lock().await.len()
    }

    /// (next to send, next expected) and (unconfirmed frames, bytes) of this side - for diagnostics
    pub fn link_state(&self) -> String {
        format!("transport={:?} pos={:?} unconfirmed={:?} closed={}", self.connection_diagnostics().current, self.link.positions(), self.link.unconfirmed(), self.link.is_closed())
    }

    /// Current route and bounded recovery counters. The snapshot contains no peer address or identity data.
    pub fn connection_diagnostics(&self) -> ConnectionDiagnostics {
        self.diagnostics.lock().unwrap().clone()
    }

    /// true once the server no longer has the session (it expired, or the link was impossible to restore for too long)
    pub fn session_lost(&self) -> bool {
        self.lost.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) async fn send(&self, f: &Frame) -> Result<()> {
        if !self.running.load(std::sync::atomic::Ordering::SeqCst) {
            bail!("not logged in");
        }
        self.link.push(f).await.map_err(|_| if self.session_lost() { anyhow::Error::new(SessionLost) } else { anyhow::anyhow!("the session is closed") })
    }

    /// ends the session on the server (terminals hung up, tunnels closed), politely
    pub async fn close(&self) {
        if self.running.load(std::sync::atomic::Ordering::SeqCst) && !self.link.is_closed() {
            let _ = self.link.push(&Frame::new(wire::CLOSE, 0, vec![])).await;
            for _ in 0..50 {
                if self.link.unconfirmed().0 == 0 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        self.link.close();
    }

    /// the second factor: after the key is accepted the server wants a login and a password. Returns the rights granted to this session.
    /// From here on the session survives broken connections: the client reconnects and resumes by itself.
    pub async fn login(&self, login: &str, password: &[u8], timeout: Duration) -> Result<Vec<String>> {
        if self.ident.opts.executor_public.is_none() {
            bail!("a pinned Executor public key is required before login");
        }
        let mut guard = self.pre.lock().await;
        let Some(pre) = guard.as_mut() else { bail!("already logged in") };
        let payload = wire::encode_login(login.as_bytes(), password).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let mut frame = Frame::new(wire::LOGIN, 0, payload);
        let m = pre.sec.seal(&frame);
        zeroize::Zeroize::zeroize(&mut frame.payload);
        write_msg(&mut pre.wr, &m?).await?;
        let mut next = async || -> Result<Frame> {
            let msg = tokio::time::timeout(timeout, read_msg(&mut pre.rd)).await.map_err(|_| anyhow::anyhow!("no answer to the login"))??;
            pre.sec.open(&msg)
        };
        let ok = next().await?;
        if ok.kind != wire::LOGIN_OK {
            bail!("login refused");
        }
        let rights: Vec<String> = String::from_utf8_lossy(&ok.payload).split(',').filter(|s| !s.is_empty()).map(String::from).collect();
        let sess = next().await?;
        if sess.kind != link::SESSION || sess.payload.len() != link::SID_LEN {
            bail!("the server did not open a session");
        }
        let pre = guard.take().unwrap();
        let (sink, mut inbound) = mpsc::channel::<Frame>(256);
        let (waiting, pong_tx, lost, link) = (self.waiting.clone(), self.pong_tx.clone(), self.lost.clone(), self.link.clone());
        tokio::spawn(async move {
            while let Some(f) = inbound.recv().await {
                match f.kind {
                    wire::CLOSE => {
                        lost.store(true, std::sync::atomic::Ordering::SeqCst);
                        link.close();
                        break;
                    }
                    wire::PONG => {
                        let _ = pong_tx.send(f).await;
                    }
                    wire::STDOUT | wire::STDERR | wire::EXIT | wire::ERROR | wire::OP_ACCEPTED | wire::OP_STATUS_RESULT | wire::PTY_OUT | wire::PTY_EXIT | fw::FILE_DATA | fw::FILE_READY | fw::FILE_END | crate::fsops::FS_RESP | crate::fsops::FS_DONE | crate::stepup::STEPUP_CHALLENGE | crate::stepup::STEPUP_RESULT | crate::tunwire::TUN_READY | crate::tunwire::TUN_DATA | crate::tunwire::TUN_EOF | crate::tunwire::TUN_CLOSE => {
                        if let Ok((id, _)) = split_id(&f.payload) {
                            let t = waiting.lock().await.get(&id).cloned();
                            if let Some(t) = t {
                                let _ = t.send(f).await;
                            }
                        }
                    }
                    _ => {}
                }
            }
            finish_waiters(&waiting, lost.load(std::sync::atomic::Ordering::SeqCst)).await;
        });
        self.running.store(true, std::sync::atomic::Ordering::SeqCst);
        tokio::spawn(manage(self.link.clone(), self.ident.clone(), sess.payload, pre, sink, self.lost.clone()));
        Ok(rights)
    }

    pub async fn ping(&self, payload: &[u8], timeout: Duration) -> Result<Vec<u8>> {
        self.send(&Frame::new(wire::PING, 0, payload.to_vec())).await?;
        match tokio::time::timeout(timeout, self.pongs.lock().await.recv()).await {
            Ok(Some(f)) => Ok(f.payload),
            _ => bail!("no pong"),
        }
    }

    pub fn request_id(&self) -> u64 { self.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst) }

    pub async fn exec(&self, argv: &[&[u8]], timeout_ms: u32, wait: Duration) -> Result<ExecResult> {
        let id = self.request_id();
        self.exec_with_id(id, argv, timeout_ms, wait).await
    }

    /// Explicit id lets a caller query this operation after re-authentication. Reusing it never
    /// executes the command again; Executor returns the retained state instead.
    pub async fn exec_with_id(&self, id: u64, argv: &[&[u8]], timeout_ms: u32, wait: Duration) -> Result<ExecResult> {
        let (tx, mut rx) = mpsc::channel(256);
        self.waiting.lock().await.insert(id, tx);
        let req = ExecReq { request_id: id, timeout_ms, argv: argv.iter().map(|a| a.to_vec()).collect() };
        self.send(&Frame::new(wire::EXEC_REQ, 0, req.encode().map_err(|e| anyhow::anyhow!("{e:?}"))?)).await?;
        let mut res = ExecResult::default();
        let finished = tokio::time::timeout(wait, async {
            while let Some(f) = rx.recv().await {
                let (_, rest) = split_id(&f.payload).map_err(|e| anyhow::anyhow!("{e:?}"))?;
                match f.kind {
                    wire::OP_ACCEPTED => {}
                    wire::STDOUT => res.stdout.extend_from_slice(rest),
                    wire::STDERR => res.stderr.extend_from_slice(rest),
                    wire::ERROR if rest.len() >= 2 => {
                        let code = u16::from_be_bytes([rest[0], rest[1]]);
                        if code == wire::E_SESSION_LOST { return Err(SessionLost.into()) }
                        res.error = Some((code, String::from_utf8_lossy(&rest[2..]).into_owned()));
                        if matches!(code, 1 | 2 | 5 | wire::E_OPERATION_RECORDED | wire::E_OPERATION_JOURNAL) {
                            if code == 2 { let _ = self.send(&Frame::new(wire::OP_RESULT_ACK, 0, id.to_be_bytes().to_vec())).await; }
                            return Ok::<bool, anyhow::Error>(true);
                        }
                    }
                    wire::EXIT if rest.len() == 4 => {
                        res.code = i32::from_be_bytes(rest.try_into().unwrap());
                        let _ = self.send(&Frame::new(wire::OP_RESULT_ACK, 0, id.to_be_bytes().to_vec())).await;
                        return Ok(true);
                    }
                    _ => {}
                }
            }
            Ok(false)
        })
        .await;
        self.waiting.lock().await.remove(&id);
        match finished {
            Ok(Ok(true)) => Ok(res),
            Ok(Ok(false)) if self.session_lost() => Err(SessionLost.into()),
            Ok(Ok(false)) => bail!("the link closed before the request finished"),
            Ok(Err(e)) => Err(e),
            Err(_) => bail!("timed out waiting for the result"),
        }
    }

    pub async fn operation_status(&self, id: u64, wait: Duration) -> Result<crate::opjournal::Status> {
        let (tx, mut rx) = mpsc::channel(4);
        self.waiting.lock().await.insert(id, tx);
        let r = async {
            self.send(&Frame::new(wire::OP_STATUS, 0, id.to_be_bytes().to_vec())).await?;
            match tokio::time::timeout(wait, rx.recv()).await {
                Ok(Some(f)) if f.kind == wire::OP_STATUS_RESULT => {
                    let status = crate::opjournal::decode_status(&f.payload).ok_or_else(|| anyhow::anyhow!("bad operation status"))?;
                    let _ = self.send(&Frame::new(wire::OP_RESULT_ACK, 0, id.to_be_bytes().to_vec())).await;
                    Ok(status)
                }
                Ok(Some(f)) if f.kind == wire::ERROR => Err(server_error(&f)),
                _ if self.session_lost() => Err(SessionLost.into()),
                _ => bail!("no operation status"),
            }
        }.await;
        self.waiting.lock().await.remove(&id);
        r
    }
}

async fn finish_waiters(waiting: &Arc<Mutex<HashMap<u64, mpsc::Sender<Frame>>>>, lost: bool) {
    let mut waiting = waiting.lock().await;
    if lost {
        for (id, waiter) in waiting.iter() {
            let mut p = wire::E_SESSION_LOST.to_be_bytes().to_vec(); p.extend_from_slice(b"SESSION_LOST");
            let _ = waiter.try_send(Frame::new(wire::ERROR, 0, with_id(*id, &p)));
        }
    }
    waiting.clear();
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[tokio::test]
    async fn every_pending_waiter_gets_explicit_session_lost() {
        let waiting = Arc::new(Mutex::new(HashMap::new()));
        let mut receivers = Vec::new();
        for id in [7, 8, 9] {
            let (tx, rx) = mpsc::channel(1);
            waiting.lock().await.insert(id, tx);
            receivers.push((id, rx));
        }
        finish_waiters(&waiting, true).await;
        for (id, mut rx) in receivers {
            let f = rx.recv().await.unwrap();
            let (got, rest) = split_id(&f.payload).unwrap();
            assert_eq!((f.kind, got, u16::from_be_bytes(rest[..2].try_into().unwrap())), (wire::ERROR, id, wire::E_SESSION_LOST));
        }
        assert!(waiting.lock().await.is_empty());
    }
}

fn random_request_id() -> u64 {
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    OsRng.next_u64().max(1)
}

#[allow(dead_code)]
fn _unused(_: &[u8]) -> Vec<u8> {
    with_id(0, &[])
}

#[derive(Debug, PartialEq, Eq)]
pub enum PtyEvent {
    Output(Vec<u8>),
    Exit(i32),
    Error(u16, String),
    /// the link is gone
    Closed,
    SessionLost,
}

/// an interactive terminal on the server
pub struct Pty<'a> {
    client: &'a Client,
    id: u64,
    rx: mpsc::Receiver<Frame>,
}

impl Client {
    pub async fn pty_open(&self, rows: u16, cols: u16, term: &str) -> Result<Pty<'_>> {
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (tx, rx) = mpsc::channel(256);
        self.waiting.lock().await.insert(id, tx);
        let open = wire::encode_pty_open(id, rows, cols, term.as_bytes()).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        self.send(&Frame::new(wire::PTY_OPEN, 0, open)).await?;
        Ok(Pty { client: self, id, rx })
    }
}

impl Pty<'_> {
    pub async fn write(&self, data: &[u8]) -> Result<()> {
        for part in data.chunks(32 * 1024) {
            self.client.send(&Frame::new(wire::PTY_IN, 0, with_id(self.id, part))).await?;
        }
        Ok(())
    }
    pub async fn resize(&self, rows: u16, cols: u16) -> Result<()> {
        self.client.send(&Frame::new(wire::PTY_RESIZE, 0, wire::encode_resize(self.id, rows, cols))).await
    }
    pub async fn close(&self) -> Result<()> {
        self.client.send(&Frame::new(wire::PTY_CLOSE, 0, with_id(self.id, &[]))).await
    }
    pub async fn next(&mut self) -> PtyEvent {
        loop {
            let Some(f) = self.rx.recv().await else { return if self.client.session_lost() { PtyEvent::SessionLost } else { PtyEvent::Closed } };
            let Ok((_, rest)) = split_id(&f.payload) else { continue };
            match f.kind {
                wire::PTY_OUT => return PtyEvent::Output(rest.to_vec()),
                wire::PTY_EXIT if rest.len() == 4 => return PtyEvent::Exit(i32::from_be_bytes(rest.try_into().unwrap())),
                wire::ERROR if rest.len() >= 2 => {
                    let code = u16::from_be_bytes([rest[0], rest[1]]);
                    if code == wire::E_SESSION_LOST { return PtyEvent::SessionLost }
                    return PtyEvent::Error(code, String::from_utf8_lossy(&rest[2..]).into_owned());
                }
                _ => {}
            }
        }
    }
    /// reads until `needle` shows up in the output (or the time is over); returns everything read so far
    pub async fn read_until(&mut self, needle: &str, wait: Duration) -> Result<String> {
        let mut got = Vec::new();
        let r = tokio::time::timeout(wait, async {
            loop {
                match self.next().await {
                    PtyEvent::Output(b) => {
                        got.extend_from_slice(&b);
                        if String::from_utf8_lossy(&got).contains(needle) {
                            return Ok(());
                        }
                    }
                    other => return Err(anyhow::anyhow!("{other:?} while waiting for {needle:?}; got {:?}", String::from_utf8_lossy(&got))),
                }
            }
        })
        .await;
        match r {
            Ok(Ok(())) => Ok(String::from_utf8_lossy(&got).into_owned()),
            Ok(Err(e)) => Err(e),
            Err(_) => bail!("timed out waiting for {needle:?}; got {:?}", String::from_utf8_lossy(&got)),
        }
    }
}

/// the server refused or failed a request
#[derive(Debug)]
pub struct ServerError(pub u16, pub String);
impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "server error {}: {}", self.0, self.1)
    }
}
impl std::error::Error for ServerError {}

#[derive(Debug)]
pub struct SessionLost;
impl std::fmt::Display for SessionLost { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("SESSION_LOST") } }
impl std::error::Error for SessionLost {}

#[derive(Debug, PartialEq, Eq)]
pub struct Transfer {
    /// bytes that went over the link in this run
    pub bytes: u64,
    /// where the transfer continued from (0 = from the start)
    pub resumed_from: u64,
}

fn server_error(f: &Frame) -> anyhow::Error {
    match split_id(&f.payload) {
        Ok((_, rest)) if rest.len() >= 2 && u16::from_be_bytes([rest[0], rest[1]]) == wire::E_SESSION_LOST => SessionLost.into(),
        Ok((_, rest)) if rest.len() >= 2 => ServerError(u16::from_be_bytes([rest[0], rest[1]]), String::from_utf8_lossy(&rest[2..]).into_owned()).into(),
        _ => anyhow::anyhow!("malformed error from the server"),
    }
}

fn hash_file(path: &std::path::Path) -> std::io::Result<(u64, [u8; 32])> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let (mut h, mut buf, mut n) = (blake3::Hasher::new(), vec![0u8; 1 << 20], 0u64);
    loop {
        let k = f.read(&mut buf)?;
        if k == 0 {
            return Ok((n, *h.finalize().as_bytes()));
        }
        h.update(&buf[..k]);
        n += k as u64;
    }
}

fn part_path(p: &std::path::Path) -> std::path::PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".yrl-part");
    s.into()
}

impl Drop for Client {
    fn drop(&mut self) {
        // leaving politely ends the session on the server at once; a broken network does not come through here
        if self.running.load(std::sync::atomic::Ordering::SeqCst) && !self.link.is_closed() {
            let link = self.link.clone();
            if let Ok(h) = tokio::runtime::Handle::try_current() {
                h.spawn(async move {
                    let _ = link.push(&Frame::new(wire::CLOSE, 0, vec![])).await;
                    for _ in 0..50 {
                        if link.unconfirmed().0 == 0 {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                    link.close();
                });
            }
        }
    }
}

impl Client {
    /// uploads a file; continues where the server's partial copy ends; the file appears on the server only after its hash matched
    pub async fn put_file(&self, local: &std::path::Path, remote: &[u8], mode: u16, wait: Duration) -> Result<Transfer> {
        let l = local.to_owned();
        let (size, hash) = tokio::task::spawn_blocking(move || hash_file(&l)).await??;
        self.put_file_claiming(local, remote, mode, size, hash, wait).await
    }

    /// the same with the size and hash given by the caller (tests lie here on purpose)
    pub async fn put_file_claiming(&self, local: &std::path::Path, remote: &[u8], mode: u16, size: u64, hash: [u8; 32], wait: Duration) -> Result<Transfer> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (tx, mut rx) = mpsc::channel(256);
        self.waiting.lock().await.insert(id, tx);
        let r = async {
            let req = PutReq { id, mode, size, hash, path: remote.to_vec() }.encode().map_err(|e| anyhow::anyhow!("{e:?}"))?;
            self.send(&Frame::new(fw::FILE_PUT, 0, req)).await?;
            let offset = match tokio::time::timeout(wait, rx.recv()).await {
                Ok(Some(f)) if f.kind == fw::FILE_READY => split_id(&f.payload).ok().and_then(|(_, r)| r.try_into().ok()).map(u64::from_be_bytes).ok_or_else(|| anyhow::anyhow!("bad READY"))?,
                Ok(Some(f)) if f.kind == wire::ERROR => return Err(server_error(&f)),
                _ if self.session_lost() => return Err(SessionLost.into()),
                _ => bail!("no answer to the upload request"),
            };
            let mut file = tokio::fs::File::open(local).await?;
            file.seek(std::io::SeekFrom::Start(offset)).await?;
            let (mut buf, mut sent) = (vec![0u8; fw::CHUNK], 0u64);
            loop {
                if let Ok(f) = rx.try_recv() {
                    if f.kind == wire::ERROR {
                        return Err(server_error(&f));
                    }
                }
                let n = file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                self.send(&Frame::new(fw::FILE_DATA, 0, with_id(id, &buf[..n]))).await?;
                sent += n as u64;
            }
            self.send(&Frame::new(fw::FILE_END, 0, with_id(id, &[]))).await?;
            loop {
                match tokio::time::timeout(wait, rx.recv()).await {
                    Ok(Some(f)) if f.kind == fw::FILE_END => return Ok(Transfer { bytes: sent, resumed_from: offset }),
                    Ok(Some(f)) if f.kind == wire::ERROR => return Err(server_error(&f)),
                    Ok(Some(_)) => {}
                    _ if self.session_lost() => return Err(SessionLost.into()),
                    _ => bail!("no confirmation of the upload"),
                }
            }
        }
        .await;
        self.waiting.lock().await.remove(&id);
        r
    }

    /// downloads a file into `<local>.yrl-part`, continues a partial copy, checks the whole file against the server's hash, then renames
    pub async fn get_file(&self, remote: &[u8], local: &std::path::Path, wait: Duration) -> Result<Transfer> {
        let part = part_path(local);
        match self.get_once(remote, local, &part, wait).await {
            Err(e) if e.downcast_ref::<ServerError>().is_some_and(|s| s.0 == fw::E_OFFSET) => {
                let _ = std::fs::remove_file(&part); // the partial copy is longer than the file now: start over
                self.get_once(remote, local, &part, wait).await
            }
            r => r,
        }
    }

    async fn get_once(&self, remote: &[u8], local: &std::path::Path, part: &std::path::Path, wait: Duration) -> Result<Transfer> {
        use tokio::io::{AsyncSeekExt, AsyncWriteExt};
        let have = std::fs::metadata(part).map(|m| if m.is_file() { m.len() } else { 0 }).unwrap_or(0);
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (tx, mut rx) = mpsc::channel(256);
        self.waiting.lock().await.insert(id, tx);
        let r = async {
            let req = GetReq { id, offset: have, path: remote.to_vec() }.encode().map_err(|e| anyhow::anyhow!("{e:?}"))?;
            self.send(&Frame::new(fw::FILE_GET, 0, req)).await?;
            let size = match tokio::time::timeout(wait, rx.recv()).await {
                Ok(Some(f)) if f.kind == fw::FILE_READY => split_id(&f.payload).ok().and_then(|(_, r)| r.try_into().ok()).map(u64::from_be_bytes).ok_or_else(|| anyhow::anyhow!("bad READY"))?,
                Ok(Some(f)) if f.kind == wire::ERROR => return Err(server_error(&f)),
                _ if self.session_lost() => return Err(SessionLost.into()),
                _ => bail!("no answer to the download request"),
            };
            let mut file = tokio::fs::OpenOptions::new().create(true).write(true).truncate(false).open(part).await?;
            file.set_len(have).await?;
            file.seek(std::io::SeekFrom::Start(have)).await?;
            let mut got = 0u64;
            let want_hash: [u8; 32] = loop {
                match tokio::time::timeout(wait, rx.recv()).await {
                    Ok(Some(f)) if f.kind == fw::FILE_DATA => {
                        let (_, d) = split_id(&f.payload).map_err(|e| anyhow::anyhow!("{e:?}"))?;
                        got += d.len() as u64;
                        if have + got > size {
                            bail!("the server sent more than the file");
                        }
                        file.write_all(d).await?;
                    }
                    Ok(Some(f)) if f.kind == fw::FILE_END => break split_id(&f.payload).ok().and_then(|(_, r)| r.try_into().ok()).ok_or_else(|| anyhow::anyhow!("bad END"))?,
                    Ok(Some(f)) if f.kind == wire::ERROR => return Err(server_error(&f)),
                    _ if self.session_lost() => return Err(SessionLost.into()),
                    _ => bail!("the download stopped"),
                }
            };
            file.flush().await?;
            file.sync_data().await?;
            drop(file);
            if have + got != size {
                bail!("the file is incomplete: {} of {size} bytes", have + got);
            }
            let p = part.to_owned();
            let (n, h) = tokio::task::spawn_blocking(move || hash_file(&p)).await??;
            if n != size || h != want_hash {
                let _ = std::fs::remove_file(part); // a bad partial copy is never kept: the next try starts clean
                bail!("the downloaded file does not match its hash; discarded");
            }
            std::fs::rename(part, local)?;
            Ok(Transfer { bytes: got, resumed_from: have })
        }
        .await;
        self.waiting.lock().await.remove(&id);
        r
    }
}

impl Client {
    async fn fs_call(&self, op: u8, a: &[u8], b: &[u8], wait: Duration) -> Result<Vec<crate::fsops::DirEntry>> {
        use crate::fsops::*;
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let req = FsReq { id, op, a: a.to_vec(), b: b.to_vec() }.encode().map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let (tx, mut rx) = mpsc::channel(256);
        self.waiting.lock().await.insert(id, tx);
        let r = async {
            self.send(&Frame::new(FS_REQ, 0, req)).await?;
            let mut all = Vec::new();
            loop {
                match tokio::time::timeout(wait, rx.recv()).await {
                    Ok(Some(f)) if f.kind == FS_RESP => {
                        let (_, rest) = split_id(&f.payload).map_err(|e| anyhow::anyhow!("{e:?}"))?;
                        all.extend(decode_entries(rest).map_err(|e| anyhow::anyhow!("{e:?}"))?);
                        if all.len() > MAX_ENTRIES {
                            bail!("too many entries");
                        }
                    }
                    Ok(Some(f)) if f.kind == FS_DONE => return Ok(all),
                    Ok(Some(f)) if f.kind == wire::ERROR => return Err(server_error(&f)),
                    Ok(Some(_)) => {}
                    _ if self.session_lost() => return Err(SessionLost.into()),
                    _ => bail!("no answer to the directory request"),
                }
            }
        }
        .await;
        self.waiting.lock().await.remove(&id);
        r
    }
    pub async fn fs_list(&self, dir: &[u8], wait: Duration) -> Result<Vec<crate::fsops::DirEntry>> {
        self.fs_call(crate::fsops::OP_LS, dir, &[], wait).await
    }
    /// the canonical absolute path (`.` is the home directory of the account)
    pub async fn fs_real(&self, path: &[u8], wait: Duration) -> Result<Vec<u8>> {
        Ok(self.fs_call(crate::fsops::OP_REAL, path, &[], wait).await?.pop().ok_or_else(|| anyhow::anyhow!("no answer"))?.name)
    }
    pub async fn fs_stat(&self, path: &[u8], wait: Duration) -> Result<crate::fsops::DirEntry> {
        self.fs_call(crate::fsops::OP_STAT, path, &[], wait).await?.pop().ok_or_else(|| anyhow::anyhow!("no answer"))
    }
    pub async fn fs_mkdir(&self, path: &[u8], mode: u16, wait: Duration) -> Result<()> {
        self.fs_call(crate::fsops::OP_MKDIR, path, format!("{:o}", mode & 0o777).as_bytes(), wait).await.map(|_| ())
    }
    /// a file, a link (the link itself) or an EMPTY directory
    pub async fn fs_remove(&self, path: &[u8], wait: Duration) -> Result<()> {
        self.fs_call(crate::fsops::OP_RM, path, &[], wait).await.map(|_| ())
    }
    /// fails when the new name exists
    pub async fn fs_rename(&self, from: &[u8], to: &[u8], wait: Duration) -> Result<()> {
        self.fs_call(crate::fsops::OP_MV, from, to, wait).await.map(|_| ())
    }
}

impl Client {
    /// Asks for ONE operation that needs more than a user may do. `executor_public` is the executor's key, pinned when the machine was set up: the phrase is
    /// encrypted to it, so the gatekeeper in between cannot read it. Returns the text the operation answered with.
    pub async fn elevate(&self, level: crate::stepup::Level, op: &crate::stepup::Op, phrase: &[u8], executor_public: &[u8], wait: Duration) -> Result<String> {
        use crate::stepup::*;
        let id = self.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let (tx, mut rx) = mpsc::channel(8);
        self.waiting.lock().await.insert(id, tx);
        let r = async {
            let mut hs = snow::Builder::new(NOISE_XK.parse()?)
                .local_private_key(&self.ident.me.private)
                .remote_public_key(executor_public)
                .prologue(&prologue(id, level, op, executor_public))
                .build_initiator()?;
            let mut buf = vec![0u8; 512];
            let n = hs.write_message(&[], &mut buf)?;
            self.send(&Frame::new(STEPUP_BEGIN, 0, encode_begin(id, level, op, &buf[..n]))).await?;
            let msg2 = loop {
                match tokio::time::timeout(wait, rx.recv()).await {
                    Ok(Some(f)) if f.kind == wire::OP_ACCEPTED => continue,
                    Ok(Some(f)) if f.kind == STEPUP_CHALLENGE => break decode_msg(&f.payload).map_err(|e| anyhow::anyhow!("{e:?}"))?.1.to_vec(),
                    Ok(Some(f)) if f.kind == STEPUP_RESULT => {
                        let (_, st, _) = decode_result(&f.payload).map_err(|e| anyhow::anyhow!("{e:?}"))?;
                        bail!("{}", result_text(st));
                    }
                    Ok(Some(f)) if f.kind == wire::ERROR => return Err(server_error(&f)),
                    _ if self.session_lost() => return Err(SessionLost.into()),
                    _ => bail!("no answer to the step-up request"),
                }
            };
            let mut scratch = vec![0u8; 512];
            hs.read_message(&msg2, &mut scratch)?; // the executor proves its key here: a different one fails
            let n = hs.write_message(phrase, &mut buf)?;
            self.send(&Frame::new(STEPUP_PROOF, 0, encode_msg(id, &buf[..n]))).await?;
            match tokio::time::timeout(wait, rx.recv()).await {
                Ok(Some(f)) if f.kind == STEPUP_RESULT => {
                    let (_, st, text) = decode_result(&f.payload).map_err(|e| anyhow::anyhow!("{e:?}"))?;
                    if st == R_OK {
                        let _ = self.send(&Frame::new(wire::OP_RESULT_ACK, 0, id.to_be_bytes().to_vec())).await;
                        Ok(text)
                    } else { bail!("{}", result_text(st)) }
                }
                Ok(Some(f)) if f.kind == wire::ERROR => Err(server_error(&f)),
                _ if self.session_lost() => Err(SessionLost.into()),
                _ => bail!("no answer to the step-up proof"),
            }
        }
        .await;
        self.waiting.lock().await.remove(&id);
        r
    }
}

fn result_text(status: u8) -> &'static str {
    match status {
        crate::stepup::R_LOCKED => "step-up locked",
        crate::stepup::R_EXPIRED => "step-up expired",
        crate::stepup::R_UNKNOWN => "operation result is UNKNOWN",
        _ => "step-up denied",
    }
}

impl Client {
    /// Presents the code of an open enrolment window. Blocks until the owner has compared the fingerprints and answered (or the window ends).
    /// Only possible on a connection that has not logged in; the key of this client is the one that is being added.
    pub async fn enroll(&self, code: &str, label: &str, wait: Duration) -> Result<()> {
        let mut guard = self.pre.lock().await;
        let Some(pre) = guard.as_mut() else { bail!("already logged in") };
        let payload = crate::enroll::encode_request(code, label).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        write_msg(&mut pre.wr, &pre.sec.seal(&Frame::new(crate::enroll::ENROLL, 0, payload))?).await?;
        let msg = tokio::time::timeout(wait, read_msg(&mut pre.rd)).await.map_err(|_| anyhow::anyhow!("no answer from the owner"))??;
        let f = pre.sec.open(&msg)?;
        if f.kind == crate::enroll::ENROLL_OK { Ok(()) } else { bail!("enrolment refused") }
    }
}
