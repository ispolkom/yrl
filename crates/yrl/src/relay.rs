//! The relay (docs/RESILIENCE.md §3): a meeting point for a server that cannot be reached directly (behind NAT).
//! The server dials OUT to the relay and waits; a client comes with the same rendezvous id; the relay joins the two sockets and copies bytes.
//! The relay is NOT trusted: on top of the joined sockets the client and the server run their own Noise IK handshake, so the relay sees only ciphertext
//! and cannot read, alter or impersonate anything (an altered byte fails authentication; a fake server has no key). It never answers: unknown ids, garbage, limits - all silence.
//!
//! First bytes on a connection to the relay (plain, 22 bytes): `YRLR` `0x01` role (`S` server, `C` client) rendezvous id (16 bytes).
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};

pub const MAGIC: &[u8; 4] = b"YRLR";
pub const HEADER_LEN: usize = 22;
pub const ROLE_SERVER: u8 = b'S';
pub const ROLE_CLIENT: u8 = b'C';

/// both sides compute it from the server's public key, so nothing has to be configured; it is a meeting address, not a secret
pub fn rendezvous_id(server_public: &[u8]) -> [u8; 16] {
    let mut h = blake3::Hasher::new();
    h.update(b"yrl-rendezvous-v1");
    h.update(server_public);
    h.finalize().as_bytes()[..16].try_into().unwrap()
}

pub fn header(role: u8, rid: &[u8; 16]) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[..4].copy_from_slice(MAGIC);
    h[4] = 1;
    h[5] = role;
    h[6..].copy_from_slice(rid);
    h
}

#[derive(Clone)]
pub struct RelayConfig {
    /// the header must arrive within this time
    pub header_timeout: Duration,
    /// a waiting server is dropped after this long (it simply dials again)
    pub wait_timeout: Duration,
    /// a joined pair with no bytes in either direction for this long is closed
    pub idle_timeout: Duration,
    pub max_waiting_total: usize,
    pub max_waiting_per_ip: usize,
    pub max_waiting_per_id: usize,
    pub max_conns_per_ip: usize,
    /// joined pairs, independently of waiting/header connections
    pub max_active_pairs: usize,
    /// active pairs attributed only to the two socket peer addresses observed by the relay
    pub max_active_pairs_per_ip: usize,
    /// copy buffers are acquired before a pair starts and released with it
    pub max_buffer_bytes_total: usize,
    pub buffer_bytes_per_direction: usize,
    /// work-conserving fair-share quantum; it is not a byte-per-second rate
    pub fair_write_quantum: usize,
    /// stops one pair after this many bytes (None = unlimited)
    pub max_bytes_per_pair: Option<u64>,
    /// copies of everything that passes, for tests that check what the relay can see
    pub tap: Option<Arc<Mutex<Vec<u8>>>>,
    /// flips one bit in the Nth chunk server->client (tests of a hostile relay)
    pub tamper_chunk: Option<u64>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        RelayConfig {
            header_timeout: Duration::from_secs(5),
            wait_timeout: Duration::from_secs(120),
            idle_timeout: Duration::from_secs(120),
            max_waiting_total: 10_000,
            max_waiting_per_ip: 8,
            max_waiting_per_id: 4,
            max_conns_per_ip: 256,
            max_active_pairs: 4096,
            max_active_pairs_per_ip: 64,
            max_buffer_bytes_total: 256 << 20,
            buffer_bytes_per_direction: 32 << 10,
            fair_write_quantum: 16 << 10,
            max_bytes_per_pair: None,
            tap: None,
            tamper_chunk: None,
        }
    }
}

impl RelayConfig {
    pub fn from_env() -> anyhow::Result<RelayConfig> {
        fn value(name: &str, default: usize) -> anyhow::Result<usize> {
            match std::env::var(name) {
                Ok(v) => v.parse::<usize>().map_err(|_| anyhow::anyhow!("invalid {name}")),
                Err(std::env::VarError::NotPresent) => Ok(default),
                Err(_) => Err(anyhow::anyhow!("invalid {name}")),
            }
        }
        let mut cfg = RelayConfig::default();
        cfg.max_active_pairs = value("YRL_RELAY_ACTIVE_PAIRS", cfg.max_active_pairs)?;
        cfg.max_active_pairs_per_ip = value("YRL_RELAY_ACTIVE_PAIRS_PER_IP", cfg.max_active_pairs_per_ip)?;
        cfg.max_buffer_bytes_total = value("YRL_RELAY_BUFFER_BYTES_TOTAL", cfg.max_buffer_bytes_total)?;
        cfg.buffer_bytes_per_direction = value("YRL_RELAY_BUFFER_BYTES_PER_DIRECTION", cfg.buffer_bytes_per_direction)?;
        cfg.fair_write_quantum = value("YRL_RELAY_QUANTUM_BYTES", cfg.fair_write_quantum)?;
        if let Ok(v) = std::env::var("YRL_RELAY_MAX_BYTES_PER_PAIR") {
            cfg.max_bytes_per_pair = Some(v.parse().map_err(|_| anyhow::anyhow!("invalid YRL_RELAY_MAX_BYTES_PER_PAIR"))?);
        }
        cfg.validate().map_err(|e| anyhow::anyhow!(e))?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), &'static str> {
        let pair_buffer = self.buffer_bytes_per_direction.checked_mul(2).ok_or("relay pair buffer overflow")?;
        if self.max_active_pairs == 0 || self.max_active_pairs_per_ip == 0 || self.max_active_pairs_per_ip > self.max_active_pairs {
            return Err("relay active-pair limits must be non-zero and per-IP within global");
        }
        if self.buffer_bytes_per_direction == 0 || pair_buffer > self.max_buffer_bytes_total || self.max_buffer_bytes_total > u32::MAX as usize {
            return Err("relay buffer budgets are invalid");
        }
        if self.fair_write_quantum == 0 || self.fair_write_quantum > self.buffer_bytes_per_direction {
            return Err("relay fairness quantum must fit one copy buffer");
        }
        Ok(())
    }
}

struct PeerSocket {
    stream: TcpStream,
    ip: IpAddr,
}

#[derive(Default)]
struct Table {
    waiting: HashMap<[u8; 16], Vec<(u64, IpAddr, oneshot::Sender<PeerSocket>)>>,
    per_ip_conns: HashMap<IpAddr, usize>,
    active_by_ip: HashMap<IpAddr, usize>,
    next: u64,
}

/// counters only; nothing identifying is ever kept or logged
#[derive(Default)]
pub struct RelayStats {
    pub pairs: AtomicU64,
    pub dropped: AtomicU64,
    pub active_pairs: AtomicU64,
}

pub struct Relay {
    pub stats: Arc<RelayStats>,
}

struct PairPermit {
    _active: OwnedSemaphorePermit,
    _buffers: OwnedSemaphorePermit,
    table: Arc<Mutex<Table>>,
    ips: Vec<IpAddr>,
    stats: Arc<RelayStats>,
}

impl Drop for PairPermit {
    fn drop(&mut self) {
        let mut table = self.table.lock().unwrap();
        for ip in &self.ips {
            if let Some(n) = table.active_by_ip.get_mut(ip) {
                *n -= 1;
                if *n == 0 { table.active_by_ip.remove(ip); }
            }
        }
        self.stats.active_pairs.fetch_sub(1, SeqCst);
    }
}

struct RelayBudget {
    active: Arc<Semaphore>,
    buffers: Arc<Semaphore>,
    fair: Arc<crate::network::FairNetwork>,
}

pub async fn serve(listener: TcpListener, cfg: RelayConfig) -> Relay {
    cfg.validate().expect("invalid relay resource limits");
    let stats = Arc::new(RelayStats::default());
    let table = Arc::new(Mutex::new(Table::default()));
    let budget = Arc::new(RelayBudget {
        active: Arc::new(Semaphore::new(cfg.max_active_pairs)),
        buffers: Arc::new(Semaphore::new(cfg.max_buffer_bytes_total)),
        fair: crate::network::FairNetwork::new(cfg.fair_write_quantum),
    });
    let st = stats.clone();
    tokio::spawn(async move {
        loop {
            let Ok((s, peer)) = listener.accept().await else { continue };
            let ip = peer.ip();
            {
                let mut t = table.lock().unwrap();
                let n = t.per_ip_conns.entry(ip).or_insert(0);
                if *n >= cfg.max_conns_per_ip {
                    st.dropped.fetch_add(1, SeqCst);
                    continue;
                }
                *n += 1;
            }
            let (cfg, table, st, budget) = (cfg.clone(), table.clone(), st.clone(), budget.clone());
            tokio::spawn(async move {
                connection(s, ip, &cfg, &table, &st, &budget).await;
                let mut t = table.lock().unwrap();
                if let Some(n) = t.per_ip_conns.get_mut(&ip) {
                    *n = n.saturating_sub(1);
                    if *n == 0 {
                        t.per_ip_conns.remove(&ip);
                    }
                }
            });
        }
    });
    Relay { stats }
}

async fn connection(mut s: TcpStream, ip: IpAddr, cfg: &RelayConfig, table: &Arc<Mutex<Table>>, st: &Arc<RelayStats>, budget: &Arc<RelayBudget>) {
    let mut h = [0u8; HEADER_LEN];
    if !matches!(tokio::time::timeout(cfg.header_timeout, s.read_exact(&mut h)).await, Ok(Ok(_))) || &h[..4] != MAGIC || h[4] != 1 {
        st.dropped.fetch_add(1, SeqCst);
        return; // silence
    }
    let rid: [u8; 16] = h[6..].try_into().unwrap();
    match h[5] {
        ROLE_SERVER => {
            let (tx, rx) = oneshot::channel::<PeerSocket>();
            let my = {
                let mut t = table.lock().unwrap();
                let total: usize = t.waiting.values().map(|v| v.len()).sum();
                let per_id = t.waiting.get(&rid).map(|v| v.len()).unwrap_or(0);
                let per_ip = t.waiting.values().flatten().filter(|(_, i, _)| *i == ip).count();
                if total >= cfg.max_waiting_total || per_id >= cfg.max_waiting_per_id || per_ip >= cfg.max_waiting_per_ip {
                    st.dropped.fetch_add(1, SeqCst);
                    return;
                }
                t.next += 1;
                let id = t.next;
                t.waiting.entry(rid).or_default().push((id, ip, tx));
                id
            };
            // wait for a client; notice a server that went away meanwhile
            let mut probe = [0u8; 1];
            let mut rx = rx;
            let client = tokio::select! {
                c = &mut rx => c.ok(),
                _ = tokio::time::sleep(cfg.wait_timeout) => None,
                r = s.read(&mut probe) => { let _ = r; None } // a waiting server must not speak: it spoke or left
            };
            {
                let mut t = table.lock().unwrap();
                if let Some(v) = t.waiting.get_mut(&rid) {
                    v.retain(|(i, _, _)| *i != my);
                    if v.is_empty() {
                        t.waiting.remove(&rid);
                    }
                }
            }
            let client = match client {
                Some(c) => c,
                None => {
                    // the client may have been handed over at the same moment we gave up
                    match rx.try_recv() {
                        Ok(c) => c,
                        Err(_) => return,
                    }
                }
            };
            let Some(pair) = acquire_pair(ip, client.ip, cfg, table, st, budget) else {
                st.dropped.fetch_add(1, SeqCst);
                return;
            };
            st.pairs.fetch_add(1, SeqCst);
            let flow = budget.fair.flow(my);
            join(s, client.stream, cfg, flow).await;
            drop(pair);
        }
        ROLE_CLIENT => {
            // take a live waiting server for this id (skipping dead ones)
            let mut sock = Some(s);
            loop {
                let slot = {
                    let mut t = table.lock().unwrap();
                    let v = t.waiting.get_mut(&rid);
                    let slot = v.and_then(|v| if v.is_empty() { None } else { Some(v.remove(0)) });
                    if t.waiting.get(&rid).is_some_and(|v| v.is_empty()) {
                        t.waiting.remove(&rid);
                    }
                    slot
                };
                let Some((_, _, tx)) = slot else {
                    st.dropped.fetch_add(1, SeqCst);
                    return; // nobody waits for this id: silence
                };
                match tx.send(PeerSocket { stream: sock.take().unwrap(), ip }) {
                    Ok(()) => return, // the server's task joins the pair
                    Err(back) => sock = Some(back.stream), // that server was gone: try the next
                }
            }
        }
        _ => {
            st.dropped.fetch_add(1, SeqCst);
        }
    }
}

fn acquire_pair(server_ip: IpAddr, client_ip: IpAddr, cfg: &RelayConfig, table: &Arc<Mutex<Table>>, st: &Arc<RelayStats>, budget: &Arc<RelayBudget>) -> Option<PairPermit> {
    let active = budget.active.clone().try_acquire_owned().ok()?;
    let bytes = u32::try_from(cfg.buffer_bytes_per_direction.checked_mul(2)?).ok()?;
    let buffers = budget.buffers.clone().try_acquire_many_owned(bytes).ok()?;
    let ips = if server_ip == client_ip { vec![server_ip] } else { vec![server_ip, client_ip] };
    {
        let mut table = table.lock().unwrap();
        if ips.iter().any(|ip| table.active_by_ip.get(ip).copied().unwrap_or(0) >= cfg.max_active_pairs_per_ip) {
            return None;
        }
        for ip in &ips { *table.active_by_ip.entry(*ip).or_default() += 1; }
    }
    st.active_pairs.fetch_add(1, SeqCst);
    Some(PairPermit { _active: active, _buffers: buffers, table: table.clone(), ips, stats: st.clone() })
}

async fn join(a: TcpStream, b: TcpStream, cfg: &RelayConfig, flow: crate::network::NetworkFlow) {
    // a = the server's socket, b = the client's
    let (ar, aw) = a.into_split();
    let (br, bw) = b.into_split();
    let last = Arc::new(Mutex::new(Instant::now()));
    let moved = Arc::new(AtomicU64::new(0));
    let tamper = cfg.tamper_chunk;
    let up = pump(br, aw, cfg.clone(), last.clone(), moved.clone(), None, flow.clone());
    let down = pump(ar, bw, cfg.clone(), last.clone(), moved.clone(), tamper, flow);
    let idle = async {
        loop {
            tokio::time::sleep(Duration::from_millis(250).min(cfg.idle_timeout)).await;
            if last.lock().unwrap().elapsed() > cfg.idle_timeout {
                return;
            }
        }
    };
    tokio::select! {
        _ = up => {}
        _ = down => {}
        _ = idle => {}
    }
}

async fn pump(mut r: tokio::net::tcp::OwnedReadHalf, mut w: tokio::net::tcp::OwnedWriteHalf, cfg: RelayConfig, last: Arc<Mutex<Instant>>, moved: Arc<AtomicU64>, tamper: Option<u64>, flow: crate::network::NetworkFlow) {
    let mut buf = vec![0u8; cfg.buffer_bytes_per_direction];
    let mut chunk = 0u64;
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => {
                let _ = w.shutdown().await;
                return;
            }
            Ok(n) => n,
        };
        *last.lock().unwrap() = Instant::now();
        if let Some(cap) = cfg.max_bytes_per_pair {
            if moved.fetch_add(n as u64, SeqCst) + n as u64 > cap {
                return;
            }
        }
        if let Some(tap) = &cfg.tap {
            tap.lock().unwrap().extend_from_slice(&buf[..n]);
        }
        chunk += 1;
        if tamper == Some(chunk) {
            buf[n / 2] ^= 0x01;
        }
        if flow.write_all(&mut w, &buf[..n], false).await.is_err() {
            return;
        }
    }
}
