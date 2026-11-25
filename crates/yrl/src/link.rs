//! The reliable session layer (docs/RESILIENCE.md): numbered frames that survive the loss of the connection under them.
//! A `Link` belongs to a SESSION, not to a TCP connection. Frames pushed into it get a sequence number and are kept until the other side confirms them;
//! a connection (`drive`) sends what the other side has not confirmed, and delivers what arrives exactly once and in order. A new connection continues where the old one stopped.
use crate::session::{read_msg, write_msg, Secure};
use crate::wire::Frame;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, watch, Notify};

pub const SEQ: u8 = 40;
pub const ACK: u8 = 41;
pub const SESSION: u8 = 42;
pub const RESUME: u8 = 43;
pub const LINK_PING: u8 = 44;
pub const LINK_PONG: u8 = 45;
pub const RESUMED: u8 = 46;
pub const RESUME_REFUSED: u8 = 47;

pub const SID_LEN: usize = 16;
/// unconfirmed bytes a side may hold; beyond this the producer waits (back-pressure), nothing is dropped and memory does not grow
pub const DEFAULT_WINDOW: usize = 8 << 20;
/// the receiver confirms after this many frames, or after `ACK_DELAY` when it is idle
const ACK_EVERY: u64 = 16;
const ACK_DELAY: Duration = Duration::from_millis(20);

#[derive(Debug, PartialEq, Eq)]
pub enum End {
    /// another connection took the session over
    Superseded,
    /// the session was closed (by us or by the other side's order)
    Closed,
    /// nothing was heard for too long
    Dead,
    /// the connection broke
    Io,
    /// the other side broke the rules (a gap in numbers, a confirmation of what was never sent, a frame that does not belong here)
    Protocol,
}

#[derive(Debug)]
pub struct LinkClosed;

struct St {
    next_seq: u64,
    unacked: VecDeque<(u64, Vec<u8>)>,
    bytes: usize,
    expected_in: u64,
    ack_told: u64,
    closed: bool,
    pong_due: bool,
}

pub struct Link {
    st: Mutex<St>,
    wake: Notify,
    space: Notify,
    window: usize,
    epoch: watch::Sender<u64>,
}

impl Link {
    pub fn new(window: usize) -> Arc<Link> {
        Arc::new(Link {
            st: Mutex::new(St { next_seq: 0, unacked: VecDeque::new(), bytes: 0, expected_in: 0, ack_told: 0, closed: false, pong_due: false }),
            wake: Notify::new(),
            space: Notify::new(),
            window,
            epoch: watch::channel(0).0,
        })
    }

    /// queue a frame for the other side; waits while too much is unconfirmed
    pub async fn push(&self, f: &Frame) -> Result<(), LinkClosed> {
        let inner = f.encode().map_err(|_| LinkClosed)?;
        loop {
            let notified = self.space.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut s = self.st.lock().unwrap();
                if s.closed {
                    return Err(LinkClosed);
                }
                if s.unacked.is_empty() || s.bytes + inner.len() <= self.window {
                    let seq = s.next_seq;
                    s.next_seq += 1;
                    s.bytes += inner.len();
                    s.unacked.push_back((seq, inner));
                    drop(s);
                    self.wake.notify_one();
                    return Ok(());
                }
            }
            notified.await;
        }
    }

    pub fn close(&self) {
        self.st.lock().unwrap().closed = true;
        self.wake.notify_one();
        self.space.notify_waiters();
        self.epoch.send_modify(|e| *e += 1);
    }

    pub fn is_closed(&self) -> bool {
        self.st.lock().unwrap().closed
    }

    /// (next number to send, next number expected from the peer): what a RESUME exchanges
    pub fn positions(&self) -> (u64, u64) {
        let s = self.st.lock().unwrap();
        (s.next_seq, s.expected_in)
    }

    pub fn unconfirmed(&self) -> (usize, usize) {
        let s = self.st.lock().unwrap();
        (s.unacked.len(), s.bytes)
    }

    fn deliver(&self, seq: u64, inner: &[u8]) -> Result<Option<Frame>, ()> {
        let mut s = self.st.lock().unwrap();
        if seq < s.expected_in {
            return Ok(None); // already had it: a retransmission after a reconnect
        }
        if seq > s.expected_in {
            return Err(()); // the connection is ordered: a gap can only be a broken peer
        }
        let f = Frame::decode(inner).map_err(|_| ())?;
        s.expected_in += 1;
        Ok(Some(f))
    }

    /// the peer confirms everything below `n`
    fn on_ack(&self, n: u64) -> Result<(), ()> {
        let mut s = self.st.lock().unwrap();
        if n > s.next_seq {
            return Err(()); // a confirmation of something never sent
        }
        let mut freed = false;
        while s.unacked.front().is_some_and(|(q, _)| *q < n) {
            let (_, b) = s.unacked.pop_front().unwrap();
            s.bytes -= b.len();
            freed = true;
        }
        drop(s);
        if freed {
            self.space.notify_waiters();
        }
        Ok(())
    }

    fn next_action(&self, cursor: &mut u64, idle_ack_due: bool) -> Action {
        let mut s = self.st.lock().unwrap();
        if s.closed {
            return Action::Stop;
        }
        if s.pong_due {
            s.pong_due = false;
            return Action::Pong;
        }
        if let Some((front, _)) = s.unacked.front() {
            if *cursor < *front {
                return Action::Bad; // the peer went back on what it had confirmed
            }
            if let Some((q, b)) = s.unacked.get((*cursor - *front) as usize) {
                debug_assert_eq!(*q, *cursor);
                *cursor += 1;
                return Action::Send(*q, b.clone());
            }
        }
        let owed = s.expected_in - s.ack_told;
        if owed >= ACK_EVERY || (owed > 0 && idle_ack_due) {
            s.ack_told = s.expected_in;
            return Action::Ack(s.expected_in);
        }
        Action::Idle
    }
}

enum Action {
    Send(u64, Vec<u8>),
    Ack(u64),
    Pong,
    Idle,
    Stop,
    Bad,
}

pub struct DriveOptions {
    /// nothing received for this long: the connection is dead
    pub dead_after: Duration,
    /// the side that wants to notice a dead link sends a probe when idle this long
    pub ping_every: Option<Duration>,
}

fn env(kind: u8, payload: Vec<u8>) -> Frame {
    Frame::new(kind, 0, payload)
}

/// Runs one connection of the session until it ends. `peer_expected` is what the other side said it already has (from RESUME / RESUMED, or 0 for a new session).
/// Everything the other side sends is delivered to `sink` exactly once and in order.
pub async fn drive<R, W>(link: &Arc<Link>, mut rd: R, mut wr: W, sec: Arc<Secure>, sink: mpsc::Sender<Frame>, peer_expected: u64, opt: &DriveOptions) -> End
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    // take the session over: any older connection is told to stop
    let mut epoch_rx = link.epoch.subscribe();
    let my_epoch = {
        let mut e = 0;
        link.epoch.send_modify(|v| {
            *v += 1;
            e = *v;
        });
        e
    };
    epoch_rx.mark_unchanged();
    if link.on_ack(peer_expected).is_err() {
        return End::Protocol;
    }
    let sec_w = sec.clone();
    let writer = async {
        let mut cursor = peer_expected;
        let mut last_sent = Instant::now();
        let mut idle_due = false;
        loop {
            let act = link.next_action(&mut cursor, idle_due);
            let (kind, payload) = match act {
                Action::Stop => return End::Closed,
                Action::Bad => return End::Protocol,
                Action::Send(q, inner) => {
                    let mut p = q.to_be_bytes().to_vec();
                    p.extend_from_slice(&inner);
                    (SEQ, p)
                }
                Action::Ack(n) => (ACK, n.to_be_bytes().to_vec()),
                Action::Pong => (LINK_PONG, vec![]),
                Action::Idle => {
                    let ping_in = opt.ping_every.map(|p| p.saturating_sub(last_sent.elapsed()));
                    tokio::select! {
                        _ = link.wake.notified() => {}
                        _ = tokio::time::sleep(ACK_DELAY) => idle_due = true,
                        _ = async { match ping_in { Some(d) => tokio::time::sleep(d).await, None => std::future::pending().await } } => {
                            let Ok(m) = sec_w.seal(&env(LINK_PING, vec![])) else { return End::Protocol };
                            if write_msg(&mut wr, &m).await.is_err() {
                                return End::Io;
                            }
                            last_sent = Instant::now();
                        }
                    }
                    continue;
                }
            };
            idle_due = false;
            let Ok(m) = sec_w.seal(&env(kind, payload)) else { return End::Protocol };
            if write_msg(&mut wr, &m).await.is_err() {
                return End::Io;
            }
            last_sent = Instant::now();
        }
    };
    let reader = async {
        loop {
            let msg = match tokio::time::timeout(opt.dead_after, read_msg(&mut rd)).await {
                Err(_) => return End::Dead,
                Ok(Err(_)) => return End::Io,
                Ok(Ok(m)) => m,
            };
            let Ok(f) = sec.open(&msg) else { return End::Protocol };
            match f.kind {
                SEQ => {
                    if f.payload.len() < 8 + 5 {
                        return End::Protocol;
                    }
                    let seq = u64::from_be_bytes(f.payload[..8].try_into().unwrap());
                    // room first, then the decision, with no waiting in between: a connection cut at any moment must never
                    // leave a frame counted as delivered that the consumer did not get
                    let Ok(permit) = sink.reserve().await else { return End::Closed };
                    match link.deliver(seq, &f.payload[8..]) {
                        Err(()) => return End::Protocol,
                        Ok(None) => {}
                        Ok(Some(fr)) => {
                            permit.send(fr);
                            link.wake.notify_one(); // an acknowledgement may be due
                        }
                    }
                }
                ACK => {
                    let Ok(b) = <[u8; 8]>::try_from(f.payload.as_slice()) else { return End::Protocol };
                    if link.on_ack(u64::from_be_bytes(b)).is_err() {
                        return End::Protocol;
                    }
                }
                LINK_PING => {
                    link.st.lock().unwrap().pong_due = true;
                    link.wake.notify_one();
                }
                LINK_PONG => {}
                _ => return End::Protocol,
            }
        }
    };
    let superseded = async {
        loop {
            if epoch_rx.changed().await.is_err() {
                return End::Closed;
            }
            if *epoch_rx.borrow() != my_epoch {
                return if link.is_closed() { End::Closed } else { End::Superseded };
            }
        }
    };
    tokio::select! {
        e = writer => e,
        e = reader => e,
        e = superseded => e,
    }
}
