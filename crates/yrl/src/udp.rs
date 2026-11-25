//! A reliable ordered byte stream over UDP datagrams (docs/UDP.md). The session above it (Noise, login, `Link`) does not know the difference: it gets an
//! `AsyncRead + AsyncWrite` exactly as from a TCP connection. What this layer does: cut the stream into packets, number them, confirm them (cumulative + a
//! 64-packet selective map), resend what is lost (by timer and by the evidence of later packets), keep the sender inside a window that grows while all goes well
//! and shrinks on loss, and respect the receiver's window.
//!
//! Security notes: the headers are NOT authenticated — they carry no secret, and what they could do if forged is limited to disturbing the connection (which an
//! attacker on the path can do to any UDP flow). The data is encrypted and authenticated by the Noise layer above, so a forged or altered payload is rejected
//! there. A connection id is 64 random bits, so an attacker off the path cannot guess it. A server side connection stays MUTE (sends nothing, not even a
//! confirmation) until the layer above writes its first byte, which happens only after a valid handshake: a stranger's packet gets no answer at all.
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant; // tokio's clock: tests can freeze and advance it
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;

/// payload bytes in one packet (header 35 bytes + 1100 stays under the usual 1280-byte floor of IPv6 paths with room for tunnels)
pub const MSS: usize = 1100;
pub const HEADER: usize = 35;
const KIND_DATA: u8 = 1;
const KIND_CLOSE: u8 = 2;
/// packets the receiver is willing to hold ahead of the next expected one
const RCV_WINDOW: u64 = 512;
const MAX_CWND: f64 = 1024.0;
const INITIAL_CWND: f64 = 10.0;
const MIN_RTO: Duration = Duration::from_millis(80);
const MAX_RTO: Duration = Duration::from_secs(4);
const INITIAL_RTO: Duration = Duration::from_millis(300);
const ACK_DELAY: Duration = Duration::from_millis(15);
/// Bound pacing bursts while avoiding one sub-millisecond timer per 1100-byte packet.
const PACING_SLICES: u64 = 16;
/// resends of one packet before the connection is declared dead
const MAX_TRIES: u32 = 14;
const APP_CHUNK: usize = 64 * 1024;
const PIPE_BYTES: usize = 256 * 1024;

pub type SendFn = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// What one connection did (for tests and for the owner's diagnostics); all counters only grow.
#[derive(Default)]
pub struct Stats {
    /// every datagram put on the wire (data, resent data, bare confirmations, goodbyes)
    pub packets_sent: AtomicU64,
    /// data packets sent again (by timer or by the evidence of later packets)
    pub retransmitted: AtomicU64,
    /// the timer ran out for the oldest unconfirmed packet
    pub timeouts: AtomicU64,
    /// round trips measured (a packet that was never resent and was confirmed)
    pub rtt_samples: AtomicU64,
    /// data packets accepted in order (what the application got)
    pub delivered: AtomicU64,
    /// sending window now and the largest it reached, in packets
    pub window: AtomicU64,
    pub window_max: AtomicU64,
    /// times a ready data packet waited for its cwnd/RTT pacing slot
    pub pacing_waits: AtomicU64,
}

impl Stats {
    pub fn get(c: &AtomicU64) -> u64 {
        c.load(Ordering::Relaxed)
    }
}

struct Seg {
    seq: u64,
    data: Vec<u8>,
    sent_at: Instant,
    tries: u32,
    sacked: bool,
    /// the packets that showed up as received after this one while it was still missing
    skipped: u32,
}

struct Header {
    kind: u8,
    seq: u64,
    ack: u64,
    wnd: u16,
    sack: u64,
}

fn encode(conn: u64, h: &Header, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(HEADER + payload.len());
    b.push(h.kind);
    b.extend_from_slice(&conn.to_be_bytes());
    b.extend_from_slice(&h.seq.to_be_bytes());
    b.extend_from_slice(&h.ack.to_be_bytes());
    b.extend_from_slice(&h.wnd.to_be_bytes());
    b.extend_from_slice(&h.sack.to_be_bytes());
    b.extend_from_slice(payload);
    b
}

/// (connection id, header, payload) or None for anything that is not a well-formed packet
pub fn parse(p: &[u8]) -> Option<(u64, Header, &[u8])> {
    if p.len() < HEADER || p.len() > HEADER + MSS {
        return None;
    }
    let kind = p[0];
    if kind != KIND_DATA && kind != KIND_CLOSE {
        return None;
    }
    let conn = u64::from_be_bytes(p[1..9].try_into().ok()?);
    let seq = u64::from_be_bytes(p[9..17].try_into().ok()?);
    let ack = u64::from_be_bytes(p[17..25].try_into().ok()?);
    let wnd = u16::from_be_bytes(p[25..27].try_into().ok()?);
    let sack = u64::from_be_bytes(p[27..35].try_into().ok()?);
    Some((conn, Header { kind, seq, ack, wnd, sack }, &p[HEADER..]))
}

/// What a server needs to decide whether a datagram opens a new connection: a data packet with the very first number and something in it.
pub fn is_opening(p: &[u8]) -> Option<u64> {
    let (conn, h, payload) = parse(p)?;
    (h.kind == KIND_DATA && h.seq == 0 && !payload.is_empty()).then_some(conn)
}

pub fn conn_id_of(p: &[u8]) -> Option<u64> {
    parse(p).map(|x| x.0)
}

/// Start one connection. `send` puts a datagram on the wire, `rx` yields the datagrams that belong to this connection. Returns the stream for the session above.
/// `mute`: send nothing until the application side writes its first byte (the server side).
pub fn spawn_stream(conn: u64, send: SendFn, rx: mpsc::Receiver<Vec<u8>>, mute: bool) -> DuplexStream {
    spawn_stream_stats(conn, send, rx, mute).0
}

/// the same, and the counters of the connection
pub fn spawn_stream_stats(conn: u64, send: SendFn, rx: mpsc::Receiver<Vec<u8>>, mute: bool) -> (DuplexStream, Arc<Stats>) {
    let (app, core) = tokio::io::duplex(PIPE_BYTES);
    let stats = Arc::new(Stats::default());
    let st = stats.clone();
    let counted: SendFn = Arc::new(move |b: &[u8]| {
        st.packets_sent.fetch_add(1, Ordering::Relaxed);
        send(b);
    });
    tokio::spawn(driver(conn, counted, rx, core, mute, stats.clone()));
    (app, stats)
}

struct Rtt {
    srtt: Option<Duration>,
    var: Duration,
    rto: Duration,
}

impl Rtt {
    fn sample(&mut self, r: Duration) {
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.var = r / 2;
            }
            Some(s) => {
                let diff = if s > r { s - r } else { r - s };
                self.var = self.var * 3 / 4 + diff / 4;
                self.srtt = Some(s * 7 / 8 + r / 8);
            }
        }
        let rto = self.srtt.unwrap() + (self.var * 4).max(Duration::from_millis(10));
        self.rto = rto.clamp(MIN_RTO, MAX_RTO);
    }
}

fn pacing_interval(srtt: Duration) -> Duration {
    Duration::from_secs_f64(srtt.as_secs_f64() / PACING_SLICES as f64)
}

fn pacing_burst(window: u64) -> u64 {
    window.max(1).div_ceil(PACING_SLICES)
}

async fn driver(conn: u64, send: SendFn, mut rx: mpsc::Receiver<Vec<u8>>, core: DuplexStream, mut mute: bool, stats: Arc<Stats>) {
    let (mut core_rd, mut core_wr) = tokio::io::split(core);
    let mut next_seq: u64 = 0;
    let mut inflight: VecDeque<Seg> = VecDeque::new();
    let mut app_buf: Vec<u8> = Vec::new();
    let mut app_eof = false;
    let mut cwnd = INITIAL_CWND;
    let mut ssthresh = MAX_CWND;
    let mut peer_wnd: u64 = 64;
    let mut recover_until: u64 = 0;
    // timeouts in a row with no progress: the back-off belongs to the connection, not to one packet
    let mut timeouts: u32 = 0;
    let mut last_progress = Instant::now();
    let mut rtt = Rtt { srtt: None, var: Duration::from_millis(100), rto: INITIAL_RTO };
    // The initial cwnd remains a short startup burst. Once the first RTT sample exists, new data is
    // spread over that RTT; loss reduces cwnd and therefore automatically increases the spacing.
    let mut next_paced_send = Instant::now();
    let mut pacing_left = 0u64;

    let mut rcv_next: u64 = 0;
    let mut ooo: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
    let mut deliver: Vec<u8> = Vec::new();
    let mut deliver_pos = 0usize;
    let mut peer_closed = false;
    let mut ack_owed: u32 = 0;
    let mut ack_due: Option<Instant> = None;
    let mut sent_close = false;

    let my_wnd = |ooo: &BTreeMap<u64, Vec<u8>>, deliver_left: usize| -> u16 {
        let used = ooo.len() as u64 + (deliver_left / MSS) as u64;
        RCV_WINDOW.saturating_sub(used).min(u16::MAX as u64) as u16
    };
    let sack_map = |rcv_next: u64, ooo: &BTreeMap<u64, Vec<u8>>| -> u64 {
        let mut m = 0u64;
        for (&s, _) in ooo.range(rcv_next + 1..rcv_next + 65) {
            m |= 1 << (s - rcv_next - 1);
        }
        m
    };

    loop {
        stats.window.store(cwnd as u64, Ordering::Relaxed);
        stats.window_max.fetch_max(cwnd as u64, Ordering::Relaxed);
        // 1. cut application bytes into packets while the window allows
        let window = (cwnd as u64).min(peer_wnd).max(1);
        while (inflight.len() as u64) < window && !app_buf.is_empty() {
            if rtt.srtt.is_some() && pacing_left == 0 {
                if Instant::now() < next_paced_send {
                    stats.pacing_waits.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                pacing_left = pacing_burst(window);
            }
            let take = app_buf.len().min(MSS);
            let data: Vec<u8> = app_buf.drain(..take).collect();
            if inflight.is_empty() {
                last_progress = Instant::now(); // the clock of "no progress" starts when there is something to make progress with
            }
            let seg = Seg { seq: next_seq, data, sent_at: Instant::now(), tries: 1, sacked: false, skipped: 0 };
            next_seq += 1;
            mute = false;
            let h = Header { kind: KIND_DATA, seq: seg.seq, ack: rcv_next, wnd: my_wnd(&ooo, deliver.len() - deliver_pos), sack: sack_map(rcv_next, &ooo) };
            send(&encode(conn, &h, &seg.data));
            if let Some(srtt) = rtt.srtt {
                pacing_left = pacing_left.saturating_sub(1);
                if pacing_left == 0 {
                    next_paced_send = Instant::now() + pacing_interval(srtt);
                }
            }
            ack_owed = 0;
            ack_due = None;
            inflight.push_back(seg);
        }

        // everything written by the application has been confirmed and it closed its side: say goodbye once
        if app_eof && app_buf.is_empty() && inflight.is_empty() && !sent_close && !mute {
            sent_close = true;
            let h = Header { kind: KIND_CLOSE, seq: next_seq, ack: rcv_next, wnd: 0, sack: 0 };
            for _ in 0..3 {
                send(&encode(conn, &h, &[]));
            }
        }
        if sent_close && peer_closed && deliver_pos >= deliver.len() {
            return;
        }
        if sent_close && !peer_closed && deliver_pos >= deliver.len() && app_eof {
            // our side is done; wait a little for the other side's goodbye, then leave
        }

        // 2. what to wait for
        let now = Instant::now();
        let rto_at = inflight.iter().find(|s| !s.sacked).map(|s| s.sent_at + rtt.rto * (1u32 << timeouts.min(4)));
        let protocol_at = match (rto_at, ack_due) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let pacing_at = (rtt.srtt.is_some() && pacing_left == 0 && !app_buf.is_empty() && (inflight.len() as u64) < window && next_paced_send > now).then_some(next_paced_send);
        let wake_at = match (protocol_at, pacing_at) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        let sleep = async {
            match wake_at {
                Some(t) => tokio::time::sleep(t.saturating_duration_since(now)).await,
                None => std::future::pending().await,
            }
        };
        let want_read = !app_eof && app_buf.len() < APP_CHUNK;
        let want_write = deliver_pos < deliver.len();
        let mut rbuf = [0u8; 16 * 1024];

        tokio::select! {
            r = core_rd.read(&mut rbuf), if want_read => {
                match r {
                    Ok(0) | Err(_) => app_eof = true,
                    Ok(n) => app_buf.extend_from_slice(&rbuf[..n]),
                }
            }
            w = core_wr.write(&deliver[deliver_pos..]), if want_write => {
                match w {
                    Ok(n) if n > 0 => {
                        deliver_pos += n;
                        if deliver_pos >= deliver.len() {
                            deliver.clear();
                            deliver_pos = 0;
                        }
                    }
                    _ => return, // the application is gone
                }
            }
            p = rx.recv() => {
                let Some(p) = p else { return };
                let Some((c, h, payload)) = parse(&p) else { continue };
                if c != conn {
                    continue;
                }
                if h.kind == KIND_CLOSE {
                    // Unauthenticated, so it can only END a goodbye that we started ourselves: a forged one cannot cut a live stream.
                    // (When the other side closes first we notice by silence; the session layer above has its own orderly close.)
                    if sent_close && h.seq == rcv_next {
                        peer_closed = true;
                        let _ = core_wr.shutdown().await;
                    }
                    continue;
                }
                peer_wnd = (h.wnd as u64).max(1);
                // --- the confirmation part
                if h.ack > next_seq {
                    continue; // confirms what was never sent: not a packet of ours
                }
                let mut acked_now = 0u32;
                while inflight.front().is_some_and(|s| s.seq < h.ack) {
                    let s = inflight.pop_front().unwrap();
                    if s.tries == 1 && !s.sacked {
                        rtt.sample(s.sent_at.elapsed());
                        stats.rtt_samples.fetch_add(1, Ordering::Relaxed);
                    }
                    acked_now += 1;
                }
                if acked_now > 0 {
                    timeouts = 0;
                    last_progress = Instant::now();
                }
                for _ in 0..acked_now {
                    if cwnd < ssthresh { cwnd += 1.0 } else { cwnd += 1.0 / cwnd }
                }
                cwnd = cwnd.min(MAX_CWND);
                let mut highest_sacked: Option<u64> = None;
                for s in inflight.iter_mut() {
                    let bit = s.seq.wrapping_sub(h.ack);
                    if s.seq > h.ack && bit >= 1 && bit <= 64 && h.sack & (1 << (bit - 1)) != 0 {
                        s.sacked = true;
                        highest_sacked = Some(s.seq);
                    }
                }
                // later packets arrived while this one did not: after three of them, resend without waiting for the timer
                if let Some(hs) = highest_sacked {
                    let mut resend: Vec<usize> = Vec::new();
                    for (i, s) in inflight.iter_mut().enumerate() {
                        if !s.sacked && s.seq < hs {
                            s.skipped += 1;
                            // three later packets AND a full round trip with a margin (a little reordering must not cause a resend)
                            if s.skipped >= 3 && s.sent_at.elapsed() > rtt.srtt.map(|r| r + r / 4 + rtt.var).unwrap_or(rtt.rto) {
                                resend.push(i);
                            }
                        }
                    }
                    if !resend.is_empty() && next_seq > recover_until {
                        ssthresh = (cwnd / 2.0).max(2.0);
                        cwnd = ssthresh;
                        recover_until = next_seq;
                    }
                    for i in resend.into_iter().take(2) {
                        stats.retransmitted.fetch_add(1, Ordering::Relaxed);
                        let s = &mut inflight[i];
                        s.skipped = 0;
                        s.tries += 1;
                        s.sent_at = Instant::now();
                        let hh = Header { kind: KIND_DATA, seq: s.seq, ack: rcv_next, wnd: my_wnd(&ooo, deliver.len() - deliver_pos), sack: sack_map(rcv_next, &ooo) };
                        send(&encode(conn, &hh, &s.data));
                    }
                }
                // --- the data part
                if payload.is_empty() {
                    continue;
                }
                let in_window = h.seq >= rcv_next && h.seq < rcv_next + RCV_WINDOW;
                let mut immediate = false;
                if !in_window {
                    immediate = true; // a duplicate of something we already have: say so, it may have lost our confirmation
                } else if h.seq == rcv_next {
                    deliver.extend_from_slice(payload);
                    rcv_next += 1;
                    stats.delivered.fetch_add(1, Ordering::Relaxed);
                    while let Some(d) = ooo.remove(&rcv_next) {
                        deliver.extend_from_slice(&d);
                        rcv_next += 1;
                        stats.delivered.fetch_add(1, Ordering::Relaxed);
                        immediate = true;
                    }
                } else {
                    if ooo.len() < RCV_WINDOW as usize {
                        ooo.entry(h.seq).or_insert_with(|| payload.to_vec());
                    }
                    immediate = true;
                }
                if !ooo.is_empty() {
                    immediate = true;
                }
                if !mute {
                    ack_owed += 1;
                    if immediate || ack_owed >= 2 {
                        let hh = Header { kind: KIND_DATA, seq: next_seq, ack: rcv_next, wnd: my_wnd(&ooo, deliver.len() - deliver_pos), sack: sack_map(rcv_next, &ooo) };
                        send(&encode(conn, &hh, &[]));
                        ack_owed = 0;
                        ack_due = None;
                    } else if ack_due.is_none() {
                        ack_due = Some(Instant::now() + ACK_DELAY);
                    }
                }
            }
            _ = sleep => {
                let now = Instant::now();
                if ack_due.is_some_and(|t| t <= now) && !mute {
                    let hh = Header { kind: KIND_DATA, seq: next_seq, ack: rcv_next, wnd: my_wnd(&ooo, deliver.len() - deliver_pos), sack: sack_map(rcv_next, &ooo) };
                    send(&encode(conn, &hh, &[]));
                    ack_owed = 0;
                    ack_due = None;
                }
                // the oldest unconfirmed packet waited its whole (backed-off) timer: send the first two unconfirmed ones again and slow down a little
                if let Some(i) = inflight.iter().position(|s| !s.sacked) {
                    let wait = rtt.rto * (1u32 << timeouts.min(4));
                    if inflight[i].sent_at + wait <= now {
                        if last_progress.elapsed() > Duration::from_secs(40) || inflight[i].tries >= MAX_TRIES * 4 {
                            return; // nothing comes back: the connection is dead
                        }
                        timeouts += 1;
                        stats.timeouts.fetch_add(1, Ordering::Relaxed);
                        ssthresh = (cwnd / 2.0).max(4.0);
                        cwnd = ssthresh;
                        recover_until = next_seq;
                        let mut sent = 0;
                        for s in inflight.iter_mut().skip(i).filter(|s| !s.sacked).take(2) {
                            s.tries += 1;
                            stats.retransmitted.fetch_add(1, Ordering::Relaxed);
                            s.sent_at = now;
                            let hh = Header { kind: KIND_DATA, seq: s.seq, ack: rcv_next, wnd: my_wnd(&ooo, deliver.len() - deliver_pos), sack: sack_map(rcv_next, &ooo) };
                            send(&encode(conn, &hh, &s.data));
                            sent += 1;
                        }
                        let _ = sent;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod pacing_tests {
    use super::*;

    #[test]
    fn pacing_uses_rtt_and_the_loss_reduced_window_without_a_fixed_rate() {
        let rtt = Duration::from_millis(80);
        assert_eq!(pacing_interval(rtt), Duration::from_millis(5));
        assert_eq!(pacing_burst(64), 4);
        assert_eq!(pacing_burst(16), 1, "a smaller congestion window after loss emits fewer packets per RTT slice");
        assert!(pacing_interval(Duration::from_millis(2)) < Duration::from_micros(130), "a clean low-RTT path is not capped at an arbitrary bitrate");
    }
}

/// Client side: a UDP socket "connected" to the server; returns the stream. The id is random.
pub async fn connect(server: std::net::SocketAddr) -> std::io::Result<DuplexStream> {
    let bind: std::net::SocketAddr = if server.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
    let sock = Arc::new(tokio::net::UdpSocket::bind(bind).await?);
    sock.connect(server).await?;
    let conn = rand_u64();
    let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);
    let s2 = sock.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            let Ok(n) = s2.recv(&mut buf).await else { return };
            if tx.send(buf[..n].to_vec()).await.is_err() {
                return;
            }
        }
    });
    let s3 = sock.clone();
    let send: SendFn = Arc::new(move |b: &[u8]| {
        let _ = s3.try_send(b);
    });
    Ok(spawn_stream(conn, send, rx, false))
}

pub fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    // the system generator through snow's resolver would be overkill here; /dev/urandom or getrandom via libc
    unsafe {
        let n = libc::getrandom(b.as_mut_ptr() as *mut libc::c_void, 8, 0);
        if n != 8 {
            let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(1);
            return t ^ (std::process::id() as u64) << 32;
        }
    }
    u64::from_be_bytes(b)
}
