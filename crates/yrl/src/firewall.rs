//! `yrld-firewall`: the only part that may change the machine's firewall. It speaks a tiny typed language - open this address for that port for N seconds, close it,
//! ask, close everything of a session - and nothing else: no rule text, no command, no "any port", no "for ever". The rules of the game (which ports, how long, how many,
//! which kinds of address) are its own policy, not the caller's. A request it cannot carry out, or cannot be sure it carried out, is a REFUSAL: there is no fall-back that lets
//! the connection through "because the firewall did not answer".
//!
//! The firewall's own state is a set with a timeout kept by the kernel (`nft` set with `flags timeout`): even if this program dies, every permission ends by itself.
use crate::audit::AuditClient;
use crate::auditlog::{Event, LEVEL_NONE, RESULT_DENIED, RESULT_OK};
use crate::ipc::{exe_of_pid, judge_peer, ExecutorIpc, GatekeeperIpc, Peer, PeerVerdict};
use crate::ipc_admission::{AdmissionLimits, IpcAdmission, IpcPermit};
use crate::keys::Authorized;
use crate::session::{client_handshake, read_msg, server_handshake, write_msg, REKEY_EVERY};
use crate::wire::{Frame, WireError};
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};

pub const FW_OPEN: u8 = 100;
pub const FW_CLOSE: u8 = 101;
pub const FW_QUERY: u8 = 102;
pub const FW_CLOSE_SESSION: u8 = 103;
pub const FW_OK: u8 = 104;
pub const FW_REFUSED: u8 = 105;
pub const FW_ANSWER: u8 = 106;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Open { addr: IpAddr, port: u16, ttl_secs: u32, session: [u8; 16] },
    Close { addr: IpAddr, port: u16 },
    Query { addr: IpAddr, port: u16 },
    CloseSession { session: [u8; 16] },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Malformed = 1,
    BadAddress = 2,
    PortNotAllowed = 3,
    TtlOutOfRange = 4,
    TooMany = 5,
    BackendFailed = 6,
    NotSure = 7,
    NotRecorded = 8,
}

fn put_addr(v: &mut Vec<u8>, a: &IpAddr) {
    match a {
        IpAddr::V4(x) => {
            v.push(4);
            v.extend_from_slice(&x.octets());
        }
        IpAddr::V6(x) => {
            v.push(6);
            v.extend_from_slice(&x.octets());
        }
    }
}

fn take_addr(b: &[u8]) -> Result<(IpAddr, &[u8]), WireError> {
    match b.first() {
        Some(4) if b.len() >= 5 => Ok((IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&b[1..5]).unwrap())), &b[5..])),
        Some(6) if b.len() >= 17 => Ok((IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&b[1..17]).unwrap())), &b[17..])),
        Some(4) | Some(6) => Err(WireError::Short),
        _ => Err(WireError::Malformed),
    }
}

impl Request {
    pub fn encode(&self) -> Frame {
        let mut v = vec![];
        let kind = match self {
            Request::Open { addr, port, ttl_secs, session } => {
                put_addr(&mut v, addr);
                v.extend_from_slice(&port.to_be_bytes());
                v.extend_from_slice(&ttl_secs.to_be_bytes());
                v.extend_from_slice(session);
                FW_OPEN
            }
            Request::Close { addr, port } | Request::Query { addr, port } => {
                put_addr(&mut v, addr);
                v.extend_from_slice(&port.to_be_bytes());
                if matches!(self, Request::Close { .. }) { FW_CLOSE } else { FW_QUERY }
            }
            Request::CloseSession { session } => {
                v.extend_from_slice(session);
                FW_CLOSE_SESSION
            }
        };
        Frame::new(kind, 0, v)
    }
    /// exact: no trailing bytes, nothing optional
    pub fn decode(f: &Frame) -> Result<Request, WireError> {
        let b = &f.payload[..];
        match f.kind {
            FW_OPEN => {
                let (addr, r) = take_addr(b)?;
                if r.len() != 2 + 4 + 16 {
                    return Err(WireError::Malformed);
                }
                Ok(Request::Open { addr, port: u16::from_be_bytes([r[0], r[1]]), ttl_secs: u32::from_be_bytes(r[2..6].try_into().unwrap()), session: r[6..22].try_into().unwrap() })
            }
            FW_CLOSE | FW_QUERY => {
                let (addr, r) = take_addr(b)?;
                if r.len() != 2 {
                    return Err(WireError::Malformed);
                }
                let port = u16::from_be_bytes([r[0], r[1]]);
                Ok(if f.kind == FW_CLOSE { Request::Close { addr, port } } else { Request::Query { addr, port } })
            }
            FW_CLOSE_SESSION => Ok(Request::CloseSession { session: b.try_into().map_err(|_| WireError::Malformed)? }),
            _ => Err(WireError::Malformed),
        }
    }
}

// ---------------------------------------------------------------- the backends

pub trait Backend: Send {
    fn add(&mut self, addr: IpAddr, port: u16, ttl_secs: u32) -> Result<()>;
    fn remove(&mut self, addr: IpAddr, port: u16) -> Result<()>;
    fn contains(&mut self, addr: IpAddr, port: u16) -> Result<bool>;
    /// forget every permission (at start: whatever was there before is not trusted)
    fn flush(&mut self) -> Result<()>;
}

/// what the kernel would know, for the tests: a set whose entries run out by themselves, with a clock the test holds
#[derive(Clone)]
pub struct MockKernel {
    inner: Arc<Mutex<MockInner>>,
}

struct MockInner {
    entries: HashMap<(IpAddr, u16), u64>,
    now: u64,
    fail: bool,
    adds: u32,
}

impl Default for MockKernel {
    fn default() -> Self {
        MockKernel { inner: Arc::new(Mutex::new(MockInner { entries: HashMap::new(), now: 1_000_000, fail: false, adds: 0 })) }
    }
}

impl MockKernel {
    pub fn advance(&self, secs: u64) {
        self.inner.lock().unwrap().now += secs;
    }
    pub fn set_failing(&self, f: bool) {
        self.inner.lock().unwrap().fail = f;
    }
    /// what the packet filter would do with a connection from `addr` to `port` (the kernel's own clock decides about the timeout)
    pub fn allows(&self, addr: IpAddr, port: u16) -> bool {
        let g = self.inner.lock().unwrap();
        g.entries.get(&(addr, port)).is_some_and(|until| *until > g.now)
    }
    /// does the filter let this ADDRESS try any port (the tests' stand-in for the kernel's decision at accept time)
    pub fn allows_addr(&self, addr: IpAddr) -> bool {
        let g = self.inner.lock().unwrap();
        g.entries.iter().any(|((a, _), until)| *a == addr && *until > g.now)
    }
    pub fn live_entries(&self) -> usize {
        let g = self.inner.lock().unwrap();
        g.entries.values().filter(|u| **u > g.now).count()
    }
    pub fn add_count(&self) -> u32 {
        self.inner.lock().unwrap().adds
    }
    pub fn now(&self) -> u64 {
        self.inner.lock().unwrap().now
    }
}

impl Backend for MockKernel {
    fn add(&mut self, addr: IpAddr, port: u16, ttl_secs: u32) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        if g.fail {
            bail!("the (mock) kernel refused");
        }
        g.adds += 1;
        let until = g.now + ttl_secs as u64;
        g.entries.insert((addr, port), until);
        Ok(())
    }
    fn remove(&mut self, addr: IpAddr, port: u16) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        if g.fail {
            bail!("the (mock) kernel refused");
        }
        g.entries.remove(&(addr, port));
        Ok(())
    }
    fn contains(&mut self, addr: IpAddr, port: u16) -> Result<bool> {
        let g = self.inner.lock().unwrap();
        if g.fail {
            bail!("the (mock) kernel does not answer");
        }
        Ok(g.entries.get(&(addr, port)).is_some_and(|until| *until > g.now))
    }
    fn flush(&mut self) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        if g.fail {
            bail!("the (mock) kernel refused");
        }
        g.entries.clear();
        Ok(())
    }
}

/// runs `nft` with a list of arguments (never a shell); the arguments are built only from typed values
pub trait Runner: Send {
    fn run(&mut self, args: &[String], stdin: Option<&str>) -> Result<String>;
}

pub struct RealRunner;

impl Runner for RealRunner {
    fn run(&mut self, args: &[String], stdin: Option<&str>) -> Result<String> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut c = Command::new("nft").args(args).stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
        if let (Some(t), Some(mut i)) = (stdin, c.stdin.take()) {
            i.write_all(t.as_bytes())?;
        }
        let out = c.wait_with_output()?;
        if !out.status.success() {
            bail!("nft failed: {}", String::from_utf8_lossy(&out.stderr).lines().next().unwrap_or(""));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

pub struct NftBackend<R: Runner> {
    pub runner: R,
}

pub const TABLE: &str = "yrl";
pub const SET4: &str = "allowed4";
pub const SET6: &str = "allowed6";

/// the permanent part: the work ports are dropped unless the source is in a set whose entries the kernel removes by itself
pub fn base_ruleset(work_ports: &[u16]) -> String {
    let ports: Vec<String> = work_ports.iter().map(|p| p.to_string()).collect();
    let list = ports.join(", ");
    format!(
        "flush table inet {t}\ndelete table inet {t}\n\
         table inet {t} {{\n\
         \x20 set {s4} {{ type ipv4_addr . inet_service; flags timeout; }}\n\
         \x20 set {s6} {{ type ipv6_addr . inet_service; flags timeout; }}\n\
         \x20 chain input {{\n\
         \x20   type filter hook input priority -10; policy accept;\n\
         \x20   ct state established,related tcp dport {{ {list} }} accept\n\
         \x20   tcp dport {{ {list} }} ip saddr . tcp dport @{s4} accept\n\
         \x20   tcp dport {{ {list} }} ip6 saddr . tcp dport @{s6} accept\n\
         \x20   tcp dport {{ {list} }} drop\n\
         \x20   ct state established,related udp dport {{ {list} }} accept\n\
         \x20   udp dport {{ {list} }} ip saddr . udp dport @{s4} accept\n\
         \x20   udp dport {{ {list} }} ip6 saddr . udp dport @{s6} accept\n\
         \x20   udp dport {{ {list} }} drop\n\
         \x20 }}\n\
         }}\n",
        t = TABLE,
        s4 = SET4,
        s6 = SET6,
        list = list
    )
}

fn set_of(a: &IpAddr) -> &'static str {
    if a.is_ipv4() { SET4 } else { SET6 }
}

impl<R: Runner> NftBackend<R> {
    pub fn install(&mut self, work_ports: &[u16]) -> Result<()> {
        // a table that is not there yet makes the first `flush` fail; that is fine, the rest decides
        let text = base_ruleset(work_ports).replace("flush table inet yrl\ndelete table inet yrl\n", "");
        let _ = self.runner.run(&["delete".into(), "table".into(), "inet".into(), TABLE.into()], None);
        self.runner.run(&["-f".into(), "-".into()], Some(&text))?;
        Ok(())
    }
}

impl<R: Runner> Backend for NftBackend<R> {
    fn add(&mut self, addr: IpAddr, port: u16, ttl_secs: u32) -> Result<()> {
        self.runner.run(&["add".into(), "element".into(), "inet".into(), TABLE.into(), set_of(&addr).into(), format!("{{ {addr} . {port} timeout {ttl_secs}s }}")], None)?;
        Ok(())
    }
    fn remove(&mut self, addr: IpAddr, port: u16) -> Result<()> {
        // deleting what is not there is not an error for us
        let _ = self.runner.run(&["delete".into(), "element".into(), "inet".into(), TABLE.into(), set_of(&addr).into(), format!("{{ {addr} . {port} }}")], None);
        Ok(())
    }
    fn contains(&mut self, addr: IpAddr, port: u16) -> Result<bool> {
        let out = self.runner.run(&["list".into(), "set".into(), "inet".into(), TABLE.into(), set_of(&addr).into()], None)?;
        Ok(out.contains(&format!("{addr} . {port}")))
    }
    fn flush(&mut self) -> Result<()> {
        for set in [SET4, SET6] {
            self.runner.run(&["flush".into(), "set".into(), "inet".into(), TABLE.into(), set.into()], None)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- the rules of the game

#[derive(Clone)]
pub struct Policy {
    pub work_ports: Vec<u16>,
    pub max_ttl_secs: u32,
    pub max_entries: usize,
    pub per_addr_max: usize,
    pub allow_loopback: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Policy { work_ports: vec![], max_ttl_secs: 120, max_entries: 1000, per_addr_max: 4, allow_loopback: false }
    }
}

pub fn address_ok(a: &IpAddr, allow_loopback: bool) -> bool {
    if a.is_unspecified() || a.is_multicast() {
        return false;
    }
    if a.is_loopback() && !allow_loopback {
        return false;
    }
    match a {
        IpAddr::V4(x) => !x.is_broadcast(),
        IpAddr::V6(_) => true,
    }
}

struct Entry {
    session: [u8; 16],
    until: u64,
}

pub struct FirewallService {
    backend: Mutex<Box<dyn Backend>>,
    policy: Policy,
    index: Mutex<HashMap<(IpAddr, u16), Entry>>,
    now: Box<dyn Fn() -> u64 + Send + Sync>,
    audit: Option<Arc<AuditClient>>,
}

impl FirewallService {
    /// the first thing it does is forget every permission the kernel may still hold: what was open before is not trusted
    pub fn start(mut backend: Box<dyn Backend>, policy: Policy, now: Box<dyn Fn() -> u64 + Send + Sync>, audit: Option<Arc<AuditClient>>) -> Result<Arc<FirewallService>> {
        backend.flush()?;
        Ok(Arc::new(FirewallService { backend: Mutex::new(backend), policy, index: Mutex::new(HashMap::new()), now, audit }))
    }

    fn note(&self, op: &str, result: u8, what: &str) {
        if let Some(a) = &self.audit {
            a.record(Event::new(op, LEVEL_NONE, result).hidden_target(what.as_bytes()));
        }
    }

    pub async fn handle(&self, req: Request) -> Result<Option<bool>, Refusal> {
        match req {
            Request::Open { addr, port, ttl_secs, session } => {
                if !address_ok(&addr, self.policy.allow_loopback) {
                    self.note("firewall_refused", RESULT_DENIED, "address");
                    return Err(Refusal::BadAddress);
                }
                if !self.policy.work_ports.contains(&port) {
                    self.note("firewall_refused", RESULT_DENIED, "port");
                    return Err(Refusal::PortNotAllowed);
                }
                if ttl_secs == 0 || ttl_secs > self.policy.max_ttl_secs {
                    self.note("firewall_refused", RESULT_DENIED, "ttl");
                    return Err(Refusal::TtlOutOfRange);
                }
                let now = (self.now)();
                {
                    let mut ix = self.index.lock().unwrap();
                    ix.retain(|_, e| e.until > now);
                    let known = ix.contains_key(&(addr, port));
                    if !known && (ix.len() >= self.policy.max_entries || ix.keys().filter(|(a, _)| *a == addr).count() >= self.policy.per_addr_max) {
                        drop(ix);
                        self.note("firewall_refused", RESULT_DENIED, "too many");
                        return Err(Refusal::TooMany);
                    }
                }
                // it is written down BEFORE it is done; if it cannot be written down it is not done
                if let Some(a) = &self.audit {
                    let ev = Event::new("firewall_open", LEVEL_NONE, RESULT_OK).hidden_target(format!("{addr}:{port}").as_bytes()).code(ttl_secs.min(65535) as u16);
                    if a.record_critical(ev).await.is_err() {
                        return Err(Refusal::NotRecorded);
                    }
                }
                if self.backend.lock().unwrap().add(addr, port, ttl_secs).is_err() {
                    return Err(Refusal::BackendFailed);
                }
                self.index.lock().unwrap().insert((addr, port), Entry { session, until: now + ttl_secs as u64 });
                Ok(None)
            }
            Request::Close { addr, port } => {
                if self.backend.lock().unwrap().remove(addr, port).is_err() {
                    return Err(Refusal::BackendFailed);
                }
                self.index.lock().unwrap().remove(&(addr, port));
                self.note("firewall_close", RESULT_OK, &format!("{addr}:{port}"));
                Ok(None)
            }
            Request::Query { addr, port } => match self.backend.lock().unwrap().contains(addr, port) {
                Ok(b) => Ok(Some(b)),
                Err(_) => Err(Refusal::NotSure), // not knowing is not "no" and not "yes"
            },
            Request::CloseSession { session } => {
                let targets: Vec<(IpAddr, u16)> = self.index.lock().unwrap().iter().filter(|(_, e)| e.session == session).map(|(k, _)| *k).collect();
                for (a, p) in targets {
                    if self.backend.lock().unwrap().remove(a, p).is_err() {
                        return Err(Refusal::BackendFailed);
                    }
                    self.index.lock().unwrap().remove(&(a, p));
                }
                self.note("firewall_close", RESULT_OK, "session");
                Ok(None)
            }
        }
    }
}

// ---------------------------------------------------------------- the door

pub const IPC_LIMITS: AdmissionLimits = AdmissionLimits { handshakes: 16, handshakes_per_peer: 8, active: 64, active_per_principal: 64 };
const IPC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const IPC_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const IPC_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn serve_ipc(listener: UnixListener, svc: Arc<FirewallService>, ipc: ExecutorIpc, log: Arc<dyn Fn(String) + Send + Sync>) {
    serve_ipc_with_limits(listener, svc, ipc, log, IPC_LIMITS).await
}

pub async fn serve_ipc_with_limits(listener: UnixListener, svc: Arc<FirewallService>, ipc: ExecutorIpc, log: Arc<dyn Fn(String) + Send + Sync>, limits: AdmissionLimits) {
    let admission = IpcAdmission::new(limits);
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let Ok(cred) = stream.peer_cred() else { continue };
        let Some(handshake) = admission.try_handshake(cred.uid()) else { continue };
        let (svc, ipc, log) = (svc.clone(), ipc.clone(), log.clone());
        let admission = admission.clone();
        let peer = Peer { uid: cred.uid(), pid: cred.pid() };
        tokio::spawn(async move { handle_conn(stream, peer, handshake, admission, svc, ipc, log).await });
    }
}

async fn handle_conn(mut stream: UnixStream, peer: Peer, handshake: IpcPermit, admission: IpcAdmission, svc: Arc<FirewallService>, ipc: ExecutorIpc, log: Arc<dyn Fn(String) + Send + Sync>) {
    let verdict = judge_peer(&ipc, &peer, exe_of_pid);
    if verdict != PeerVerdict::Ok {
        log(format!("firewall: connection refused: {verdict:?}"));
        svc.note("peer_refused", RESULT_DENIED, &format!("{verdict:?}"));
        return;
    }
    let authorized = [Authorized { public: ipc.gatekeeper_public.clone(), label: "gatekeeper".into(), rights: vec![] }];
    let Ok(Ok((sec, who))) = tokio::time::timeout(IPC_HANDSHAKE_TIMEOUT, server_handshake(&mut stream, &ipc.key, &authorized, REKEY_EVERY)).await else {
        log("firewall: connection refused: handshake".into());
        svc.note("peer_refused", RESULT_DENIED, "handshake");
        return;
    };
    let Some(_active) = admission.try_active(&who.public) else {
        log("firewall: connection refused: active IPC capacity exhausted".into());
        return;
    };
    drop(handshake);
    let (mut rd, mut wr) = stream.into_split();
    // FirewallClient deliberately uses one authenticated connection per typed request. Serving one
    // request prevents a compromised caller from retaining capacity with an idle keep-alive.
    let Ok(Ok(msg)) = tokio::time::timeout(IPC_REQUEST_TIMEOUT, read_msg(&mut rd)).await else { return };
    let Ok(f) = sec.open(&msg) else { return };
    let Ok(req) = Request::decode(&f) else { return }; // not in the language: the conversation ends
    let out = match svc.handle(req).await {
        Ok(None) => Frame::new(FW_OK, 0, vec![]),
        Ok(Some(b)) => Frame::new(FW_ANSWER, 0, vec![b as u8]),
        Err(r) => Frame::new(FW_REFUSED, 0, vec![r as u8]),
    };
    let Ok(m) = sec.seal(&out) else { return };
    let _ = tokio::time::timeout(IPC_WRITE_TIMEOUT, write_msg(&mut wr, &m)).await;
}

/// the gatekeeper's way to ask
#[derive(Clone)]
pub struct FirewallClient {
    ipc: GatekeeperIpc,
}

impl FirewallClient {
    pub fn new(ipc: GatekeeperIpc) -> FirewallClient {
        FirewallClient { ipc }
    }
    /// Ok(None) = done, Ok(Some(b)) = the answer to a query; every failure is an Err and means "NOT open"
    pub async fn call(&self, req: Request) -> Result<Option<bool>> {
        let t = Duration::from_secs(3);
        let mut s = tokio::time::timeout(t, UnixStream::connect(&self.ipc.socket)).await??;
        let sec = tokio::time::timeout(t, client_handshake(&mut s, &self.ipc.key, &self.ipc.executor_public, REKEY_EVERY)).await??;
        let (mut rd, mut wr) = s.into_split();
        tokio::time::timeout(t, write_msg(&mut wr, &sec.seal(&req.encode())?)).await??;
        let msg = tokio::time::timeout(t, read_msg(&mut rd)).await??;
        let f = sec.open(&msg)?;
        match f.kind {
            FW_OK => Ok(None),
            FW_ANSWER if f.payload.len() == 1 => Ok(Some(f.payload[0] == 1)),
            FW_REFUSED => bail!("the firewall refused ({})", f.payload.first().copied().unwrap_or(0)),
            _ => bail!("unexpected answer"),
        }
    }
}
