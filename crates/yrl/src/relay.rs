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
use tokio::sync::oneshot;

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
            max_bytes_per_pair: None,
            tap: None,
            tamper_chunk: None,
        }
    }
}

#[derive(Default)]
struct Table {
    waiting: HashMap<[u8; 16], Vec<(u64, IpAddr, oneshot::Sender<TcpStream>)>>,
    per_ip_conns: HashMap<IpAddr, usize>,
    next: u64,
}

/// counters only; nothing identifying is ever kept or logged
#[derive(Default)]
pub struct RelayStats {
    pub pairs: AtomicU64,
    pub dropped: AtomicU64,
}

pub struct Relay {
    pub stats: Arc<RelayStats>,
}

pub async fn serve(listener: TcpListener, cfg: RelayConfig) -> Relay {
    let stats = Arc::new(RelayStats::default());
    let table = Arc::new(Mutex::new(Table::default()));
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
            let (cfg, table, st) = (cfg.clone(), table.clone(), st.clone());
            tokio::spawn(async move {
                connection(s, ip, &cfg, &table, &st).await;
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

async fn connection(mut s: TcpStream, ip: IpAddr, cfg: &RelayConfig, table: &Arc<Mutex<Table>>, st: &Arc<RelayStats>) {
    let mut h = [0u8; HEADER_LEN];
    if !matches!(tokio::time::timeout(cfg.header_timeout, s.read_exact(&mut h)).await, Ok(Ok(_))) || &h[..4] != MAGIC || h[4] != 1 {
        st.dropped.fetch_add(1, SeqCst);
        return; // silence
    }
    let rid: [u8; 16] = h[6..].try_into().unwrap();
    match h[5] {
        ROLE_SERVER => {
            let (tx, rx) = oneshot::channel::<TcpStream>();
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
            st.pairs.fetch_add(1, SeqCst);
            join(s, client, cfg).await;
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
                match tx.send(sock.take().unwrap()) {
                    Ok(()) => return, // the server's task joins the pair
                    Err(back) => sock = Some(back), // that server was gone: try the next
                }
            }
        }
        _ => {
            st.dropped.fetch_add(1, SeqCst);
        }
    }
}

async fn join(a: TcpStream, b: TcpStream, cfg: &RelayConfig) {
    // a = the server's socket, b = the client's
    let (ar, aw) = a.into_split();
    let (br, bw) = b.into_split();
    let last = Arc::new(Mutex::new(Instant::now()));
    let moved = Arc::new(AtomicU64::new(0));
    let tamper = cfg.tamper_chunk;
    let up = pump(br, aw, cfg.clone(), last.clone(), moved.clone(), None);
    let down = pump(ar, bw, cfg.clone(), last.clone(), moved.clone(), tamper);
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

async fn pump(mut r: tokio::net::tcp::OwnedReadHalf, mut w: tokio::net::tcp::OwnedWriteHalf, cfg: RelayConfig, last: Arc<Mutex<Instant>>, moved: Arc<AtomicU64>, tamper: Option<u64>) {
    let mut buf = vec![0u8; 32 * 1024];
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
        if w.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}
