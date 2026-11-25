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
/// Space that bulk/normal producers cannot consume, so one saturated file transfer cannot prevent
/// control and interactive frames from entering the same globally bounded window.
const MAX_INTERACTIVE_RESERVE: usize = 256 << 10;

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
    unacked: VecDeque<(u64, HeldFrame)>,
    pending_interactive: VecDeque<HeldFrame>,
    pending_normal: VecDeque<HeldFrame>,
    pending_bulk: VecDeque<HeldFrame>,
    bytes: usize,
    expected_in: u64,
    ack_told: u64,
    closed: bool,
    pong_due: bool,
}

struct HeldFrame {
    data: Arc<[u8]>,
    _memory: Option<crate::resources::LinkMemoryPermit>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Priority {
    Interactive,
    Normal,
    Bulk,
}

fn priority(f: &Frame) -> Priority {
    if matches!(f.kind, crate::filewire::FILE_PUT | crate::filewire::FILE_GET | crate::filewire::FILE_DATA | crate::filewire::FILE_READY | crate::filewire::FILE_END | crate::filewire::FILE_ABORT) {
        Priority::Bulk
    } else if matches!(
        f.kind,
        crate::wire::PING
            | crate::wire::PONG
            | crate::wire::EXEC_REQ
            | crate::wire::STDOUT
            | crate::wire::STDERR
            | crate::wire::EXIT
            | crate::wire::ERROR
            | crate::wire::CLOSE
            | crate::wire::PTY_OPEN
            | crate::wire::PTY_IN
            | crate::wire::PTY_OUT
            | crate::wire::PTY_RESIZE
            | crate::wire::PTY_EXIT
            | crate::wire::PTY_CLOSE
            | crate::tunwire::TUN_OPEN
            | crate::tunwire::TUN_READY
            | crate::tunwire::TUN_DATA
            | crate::tunwire::TUN_EOF
            | crate::tunwire::TUN_CLOSE
            | crate::stepup::STEPUP_BEGIN
            | crate::stepup::STEPUP_CHALLENGE
            | crate::stepup::STEPUP_PROOF
            | crate::stepup::STEPUP_RESULT
    ) {
        Priority::Interactive
    } else {
        Priority::Normal
    }
}

pub struct Link {
    st: Mutex<St>,
    wake: Notify,
    space: Notify,
    window: usize,
    budget: Option<crate::resources::LinkBudget>,
    epoch: watch::Sender<u64>,
    closed: watch::Sender<bool>,
}

impl Link {
    pub fn new(window: usize) -> Arc<Link> {
        Self::with_budget(window, None)
    }

    pub fn new_budgeted(window: usize, budget: crate::resources::LinkBudget) -> Arc<Link> {
        Self::with_budget(window, Some(budget))
    }

    fn with_budget(window: usize, budget: Option<crate::resources::LinkBudget>) -> Arc<Link> {
        Arc::new(Link {
            st: Mutex::new(St { next_seq: 0, unacked: VecDeque::new(), pending_interactive: VecDeque::new(), pending_normal: VecDeque::new(), pending_bulk: VecDeque::new(), bytes: 0, expected_in: 0, ack_told: 0, closed: false, pong_due: false }),
            wake: Notify::new(),
            space: Notify::new(),
            window,
            budget,
            epoch: watch::channel(0).0,
            closed: watch::channel(false).0,
        })
    }

    /// queue a frame for the other side; waits while too much is unconfirmed
    pub async fn push(&self, f: &Frame) -> Result<(), LinkClosed> {
        let inner: Arc<[u8]> = f.encode().map_err(|_| LinkClosed)?.into();
        let priority = priority(f);
        let reserve = (self.window / 8).min(MAX_INTERACTIVE_RESERVE);
        let limit = if priority == Priority::Interactive { self.window } else { self.window.saturating_sub(reserve) };
        loop {
            let notified = self.space.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let has_local_room = {
                let s = self.st.lock().unwrap();
                if s.closed {
                    return Err(LinkClosed);
                }
                let empty = s.unacked.is_empty() && s.pending_interactive.is_empty() && s.pending_normal.is_empty() && s.pending_bulk.is_empty();
                // Keep the historical escape hatch for a configured window smaller than one legal frame.
                // Otherwise every queue together remains within `window`, including the interactive reserve.
                s.bytes + inner.len() <= limit || (empty && inner.len() > self.window)
            };
            if !has_local_room {
                notified.await;
                continue;
            }
            let memory = match &self.budget {
                Some(budget) => {
                    let mut closed = self.closed.subscribe();
                    if *closed.borrow_and_update() {
                        return Err(LinkClosed);
                    }
                    tokio::select! {
                        p = budget.reserve(inner.len(), priority == Priority::Interactive) => Some(p.map_err(|_| LinkClosed)?),
                        _ = closed.changed() => return Err(LinkClosed),
                    }
                }
                None => None,
            };
            let mut s = self.st.lock().unwrap();
            if s.closed {
                return Err(LinkClosed);
            }
            let empty = s.unacked.is_empty() && s.pending_interactive.is_empty() && s.pending_normal.is_empty() && s.pending_bulk.is_empty();
            if s.bytes + inner.len() > limit && !(empty && inner.len() > self.window) {
                drop(s); // another producer used the local window while the global permit was awaited
                drop(memory);
                continue;
            }
            s.bytes += inner.len();
            let held = HeldFrame { data: inner.clone(), _memory: memory };
            match priority {
                Priority::Interactive => s.pending_interactive.push_back(held),
                Priority::Normal => s.pending_normal.push_back(held),
                Priority::Bulk => s.pending_bulk.push_back(held),
            }
            drop(s);
            self.wake.notify_one();
            return Ok(());
        }
    }

    pub fn close(&self) {
        let mut s = self.st.lock().unwrap();
        s.closed = true;
        s.unacked.clear();
        s.pending_interactive.clear();
        s.pending_normal.clear();
        s.pending_bulk.clear();
        s.bytes = 0;
        drop(s);
        self.wake.notify_one();
        self.space.notify_waiters();
        self.epoch.send_modify(|e| *e += 1);
        self.closed.send_replace(true);
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
        (s.unacked.len() + s.pending_interactive.len() + s.pending_normal.len() + s.pending_bulk.len(), s.bytes)
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
            s.bytes -= b.data.len();
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
        let owed = s.expected_in - s.ack_told;
        if owed >= ACK_EVERY || (owed > 0 && idle_ack_due) {
            s.ack_told = s.expected_in;
            return Action::Ack(s.expected_in);
        }
        if let Some((front, _)) = s.unacked.front() {
            if *cursor < *front {
                return Action::Bad; // the peer went back on what it had confirmed
            }
            if let Some((q, b)) = s.unacked.get((*cursor - *front) as usize) {
                debug_assert_eq!(*q, *cursor);
                *cursor += 1;
                return Action::Send(*q, b.data.clone());
            }
        }
        let inner = s.pending_interactive.pop_front().or_else(|| s.pending_normal.pop_front()).or_else(|| s.pending_bulk.pop_front());
        if let Some(inner) = inner {
            let seq = s.next_seq;
            s.next_seq += 1;
            *cursor += 1;
            let data = inner.data.clone();
            s.unacked.push_back((seq, inner));
            return Action::Send(seq, data);
        }
        Action::Idle
    }
}

enum Action {
    Send(u64, Arc<[u8]>),
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

#[cfg(test)]
mod resource_tests {
    use super::*;
    use crate::resources::{ResourceLimits, ResourceManager};

    #[tokio::test]
    async fn acknowledged_and_closed_frames_release_their_exact_link_charge() {
        let resources = Arc::new(ResourceManager::new(ResourceLimits::default()).unwrap());
        let session = resources.try_session(b"device", "account", 1, 1, 1).unwrap();
        let link = Link::new_budgeted(DEFAULT_WINDOW, session.link_budget());
        let frame = Frame::new(crate::filewire::FILE_DATA, 0, vec![7; 4096]);
        let encoded = frame.encode().unwrap().len();

        link.push(&frame).await.unwrap();
        let mut cursor = 0;
        assert!(matches!(link.next_action(&mut cursor, false), Action::Send(0, _)));
        assert_eq!(resources.usage().link_bytes, encoded);
        link.on_ack(1).unwrap();
        assert_eq!(resources.usage().link_bytes, 0, "an authoritative ACK releases the retained frame");

        link.push(&frame).await.unwrap();
        assert_eq!(resources.usage().link_bytes, encoded);
        link.close();
        assert_eq!(resources.usage().link_bytes, 0, "session teardown releases pending frames even without an ACK");
    }
}
