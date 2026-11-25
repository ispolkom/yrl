#![allow(dead_code)]
//! A TCP proxy that misbehaves on command: cuts connections, swallows bytes without closing, delays, refuses, cuts after N bytes.
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

struct State {
    cut: watch::Sender<u64>,
    blackhole: watch::Sender<u64>,
    refuse: AtomicBool,
    delay_ms: AtomicU64,
    accepted: AtomicUsize,
    attempts: AtomicUsize,
    cut_after: AtomicI64,
}

pub struct Chaos {
    pub addr: String,
    st: Arc<State>,
}

impl Chaos {
    pub async fn start(target: &str) -> Chaos {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let st = Arc::new(State { cut: watch::channel(0).0, blackhole: watch::channel(0).0, refuse: AtomicBool::new(false), delay_ms: AtomicU64::new(0), accepted: AtomicUsize::new(0), attempts: AtomicUsize::new(0), cut_after: AtomicI64::new(-1) });
        let (st2, target) = (st.clone(), target.to_string());
        tokio::spawn(async move {
            loop {
                let Ok((client, _)) = l.accept().await else { return };
                st2.attempts.fetch_add(1, SeqCst);
                if st2.refuse.load(SeqCst) {
                    continue; // dropped at once
                }
                st2.accepted.fetch_add(1, SeqCst);
                let (st3, target) = (st2.clone(), target.clone());
                tokio::spawn(async move {
                    let Ok(server) = TcpStream::connect(&target).await else { return };
                    one(client, server, st3).await;
                });
            }
        });
        Chaos { addr, st }
    }
    /// every connection existing now is torn down at once
    pub fn cut(&self) {
        self.st.cut.send_modify(|v| *v += 1);
    }
    /// every connection existing now keeps its sockets open but nothing passes any more (a dead link without a reset)
    pub fn blackhole_current(&self) {
        self.st.blackhole.send_modify(|v| *v += 1);
    }
    pub fn refuse(&self, on: bool) {
        self.st.refuse.store(on, SeqCst);
    }
    pub fn set_delay(&self, ms: u64) {
        self.st.delay_ms.store(ms, SeqCst);
    }
    /// the next connection that moves this many bytes (both directions together) is cut
    pub fn cut_after_bytes(&self, n: i64) {
        self.st.cut_after.store(n, SeqCst);
    }
    /// every connection attempt, refused ones included
    pub fn attempts(&self) -> usize {
        self.st.attempts.load(SeqCst)
    }
    pub fn accepted(&self) -> usize {
        self.st.accepted.load(SeqCst)
    }
}

async fn pump(mut r: tokio::net::tcp::OwnedReadHalf, mut w: tokio::net::tcp::OwnedWriteHalf, st: Arc<State>, bh: Arc<AtomicBool>, budget: Arc<AtomicI64>) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        if bh.load(SeqCst) {
            continue; // swallowed
        }
        let d = st.delay_ms.load(SeqCst);
        if d > 0 {
            tokio::time::sleep(Duration::from_millis(d)).await;
        }
        let b = budget.load(SeqCst);
        if b >= 0 {
            let left = budget.fetch_sub(n as i64, SeqCst);
            if left < n as i64 {
                let keep = left.max(0) as usize;
                let _ = w.write_all(&buf[..keep]).await; // part of the chunk goes through, then the cut
                return;
            }
        }
        if w.write_all(&buf[..n]).await.is_err() {
            return;
        }
    }
}

async fn one(client: TcpStream, server: TcpStream, st: Arc<State>) {
    let (cr, cw) = client.into_split();
    let (sr, sw) = server.into_split();
    let mut cut = st.cut.subscribe();
    cut.mark_unchanged();
    let mut bh = st.blackhole.subscribe();
    bh.mark_unchanged();
    let flag = Arc::new(AtomicBool::new(false));
    let f2 = flag.clone();
    tokio::spawn(async move {
        if bh.changed().await.is_ok() {
            f2.store(true, SeqCst);
        }
    });
    let budget = Arc::new(AtomicI64::new(st.cut_after.swap(-1, SeqCst)));
    tokio::select! {
        _ = pump(cr, sw, st.clone(), flag.clone(), budget.clone()) => {}
        _ = pump(sr, cw, st.clone(), flag.clone(), budget.clone()) => {}
        _ = cut.changed() => {}
    }
}

/// cuts everything at random moments, `min_ms..max_ms` apart (a fixed period would lock in step with the client's retry delay and prove nothing)
pub fn spawn_cutter(ch: Arc<Chaos>, min_ms: u64, max_ms: u64, seed: u64) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut x = seed | 1;
        loop {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            tokio::time::sleep(Duration::from_millis(min_ms + x % (max_ms - min_ms + 1))).await;
            ch.cut();
        }
    })
}
