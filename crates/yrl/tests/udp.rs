//! The reliable stream over UDP (src/udp.rs): the bytes arrive intact and in order through loss, reordering, duplication and delay; a mute side stays silent.
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use yrl::udp::{spawn_stream, spawn_stream_stats, SendFn, Stats};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn chance(&mut self, pct: u64) -> bool {
        self.next() % 100 < pct
    }
}

/// a one-way "network": loss, duplication, and a random delay (which also reorders)
fn lossy(tx: mpsc::Sender<Vec<u8>>, loss: u64, dup: u64, max_delay_ms: u64, seed: u64) -> SendFn {
    let rng = Arc::new(Mutex::new(Rng(seed)));
    Arc::new(move |p: &[u8]| {
        let (drop_it, twice, d1, d2) = {
            let mut r = rng.lock().unwrap();
            (r.chance(loss), r.chance(dup), r.next() % (max_delay_ms + 1), r.next() % (max_delay_ms + 1))
        };
        if drop_it {
            return;
        }
        let copies: Vec<u64> = if twice { vec![d1, d2] } else { vec![d1] };
        for d in copies {
            let (tx, p) = (tx.clone(), p.to_vec());
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(d)).await;
                let _ = tx.send(p).await;
            });
        }
    })
}

fn pair(loss: u64, dup: u64, delay: u64, seed: u64) -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
    let (a_rx_tx, a_rx) = mpsc::channel(4096);
    let (b_rx_tx, b_rx) = mpsc::channel(4096);
    let a = spawn_stream(7, lossy(b_rx_tx, loss, dup, delay, seed), a_rx, false);
    let b = spawn_stream(7, lossy(a_rx_tx, loss, dup, delay, seed ^ 0x9e3779b97f4a7c15), b_rx, true);
    (a, b)
}

fn pair_stats(loss: u64, dup: u64, delay: u64, seed: u64) -> (tokio::io::DuplexStream, tokio::io::DuplexStream, Arc<Stats>) {
    let (a_rx_tx, a_rx) = mpsc::channel(4096);
    let (b_rx_tx, b_rx) = mpsc::channel(4096);
    let (a, st) = spawn_stream_stats(7, lossy(b_rx_tx, loss, dup, delay, seed), a_rx, false);
    let b = spawn_stream(7, lossy(a_rx_tx, loss, dup, delay, seed ^ 0x9e3779b97f4a7c15), b_rx, true);
    (a, b, st)
}

fn data(n: usize, seed: u64) -> Vec<u8> {
    let mut r = Rng(seed | 1);
    (0..n).map(|_| r.next() as u8).collect()
}

async fn transfer(loss: u64, dup: u64, delay: u64, bytes: usize, secs: u64) -> Arc<Stats> {
    let (mut a, mut b, st) = pair_stats(loss, dup, delay, 12345);
    let t0 = tokio::time::Instant::now();
    let real = std::time::Instant::now();
    let sent = data(bytes, 99);
    let s2 = sent.clone();
    let w = tokio::spawn(async move {
        // the opening exchange: a first message, and the server's answer (which is what un-mutes the server side)
        a.write_all(b"hello").await.unwrap();
        let mut ok = [0u8; 2];
        a.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"ok");
        a.write_all(&s2).await.unwrap();
        let mut back = vec![0u8; 5];
        a.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"thank");
    });
    let mut hello = [0u8; 5];
    b.read_exact(&mut hello).await.unwrap();
    b.write_all(b"ok").await.unwrap();
    let mut got = vec![0u8; bytes];
    tokio::time::timeout(Duration::from_secs(secs), b.read_exact(&mut got)).await.expect("the transfer finished in time").unwrap();
    assert!(got == sent, "bytes arrived intact and in order");
    b.write_all(b"thank").await.unwrap();
    tokio::time::timeout(Duration::from_secs(secs), w).await.expect("the reply arrived").unwrap();
    eprintln!("[stats loss {loss}%] logical {:?}, real {:?}, sent {}, resent {}, timeouts {}, rtt samples {}, delivered {}, window now {} max {}", t0.elapsed(), real.elapsed(), Stats::get(&st.packets_sent), Stats::get(&st.retransmitted), Stats::get(&st.timeouts), Stats::get(&st.rtt_samples), Stats::get(&st.delivered), Stats::get(&st.window), Stats::get(&st.window_max));
    st
}

#[tokio::test]
async fn a_clean_path_carries_megabytes_intact() {
    let st = transfer(0, 0, 2, 4 << 20, 30).await;
    let (sent, resent) = (Stats::get(&st.packets_sent), Stats::get(&st.retransmitted));
    assert!(resent * 50 < sent, "on a clean path almost nothing is sent twice ({resent} of {sent})");
    assert_eq!(Stats::get(&st.timeouts), 0, "no timer ran out on a clean path");
    assert!(Stats::get(&st.window_max) > 10, "the window grew");
}

#[tokio::test(start_paused = true)]
async fn ten_percent_loss_with_reordering_and_duplicates_still_delivers_everything_in_order() {
    let st = transfer(10, 5, 30, 2 << 20, 90).await;
    assert!(Stats::get(&st.retransmitted) > 0 && Stats::get(&st.rtt_samples) > 0);
    assert!(Stats::get(&st.retransmitted) * 4 < Stats::get(&st.packets_sent), "resends stay a modest share of the traffic");
}

#[tokio::test(start_paused = true)]
async fn thirty_percent_loss_is_slow_but_correct() {
    let st = transfer(30, 10, 20, 256 << 10, 600).await;
    assert!(Stats::get(&st.timeouts) > 0 && Stats::get(&st.retransmitted) > 0);
}

#[tokio::test]
async fn a_server_side_that_was_never_written_to_stays_silent() {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(16);
    let (_in_tx, in_rx) = mpsc::channel::<Vec<u8>>(16);
    let counted = Arc::new(Mutex::new(0usize));
    let c2 = counted.clone();
    let send: SendFn = Arc::new(move |_p: &[u8]| {
        *c2.lock().unwrap() += 1;
    });
    let _s = spawn_stream(9, send, in_rx, true);
    // a packet from a stranger arrives: opening, seq 0, some bytes
    let (conn_tx, conn_rx) = mpsc::channel::<Vec<u8>>(16);
    let c3 = counted.clone();
    let send2: SendFn = Arc::new(move |_p: &[u8]| {
        *c3.lock().unwrap() += 1;
    });
    let s2 = spawn_stream(9, send2, conn_rx, true);
    let mut pkt = vec![1u8];
    pkt.extend_from_slice(&9u64.to_be_bytes());
    pkt.extend_from_slice(&0u64.to_be_bytes());
    pkt.extend_from_slice(&0u64.to_be_bytes());
    pkt.extend_from_slice(&64u16.to_be_bytes());
    pkt.extend_from_slice(&0u64.to_be_bytes());
    pkt.extend_from_slice(b"hello");
    conn_tx.send(pkt).await.unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(*counted.lock().unwrap(), 0, "no confirmation, no answer of any kind");
    drop((tx, s2));
    assert!(rx.try_recv().is_err());
}

// ---- attacks on the unauthenticated headers of a live connection: nothing may corrupt, stall or cut the stream

fn header(kind: u8, conn: u64, seq: u64, ack: u64, wnd: u16, sack: u64, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![kind];
    p.extend_from_slice(&conn.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ack.to_be_bytes());
    p.extend_from_slice(&wnd.to_be_bytes());
    p.extend_from_slice(&sack.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

/// a clean pair whose input channels the test can also write into (the attacker's packets arrive there)
fn pair_with_taps() -> (tokio::io::DuplexStream, tokio::io::DuplexStream, mpsc::Sender<Vec<u8>>, mpsc::Sender<Vec<u8>>) {
    let (a_in, a_rx) = mpsc::channel(4096);
    let (b_in, b_rx) = mpsc::channel(4096);
    let a = spawn_stream(7, lossy(b_in.clone(), 0, 0, 1, 1), a_rx, false);
    let b = spawn_stream(7, lossy(a_in.clone(), 0, 0, 1, 2), b_rx, true);
    (a, b, a_in, b_in)
}

async fn attacked_transfer(attack: impl Fn(&mpsc::Sender<Vec<u8>>, &mpsc::Sender<Vec<u8>>, usize) -> Vec<Vec<u8>> + Send + 'static) {
    let (mut a, mut b, a_in, b_in) = pair_with_taps();
    let sent = data(1 << 20, 3);
    let s2 = sent.clone();
    let w = tokio::spawn(async move {
        a.write_all(b"hello").await.unwrap();
        let mut ok = [0u8; 2];
        a.read_exact(&mut ok).await.unwrap();
        a.write_all(&s2).await.unwrap();
        let mut back = [0u8; 5];
        a.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"thank");
    });
    // the attacker keeps firing at both ends all the time
    let fire = tokio::spawn(async move {
        // a forged packet with the NEXT expected number that beats the genuine one is plain corruption by someone on the path (Noise above rejects it);
        // what is tested is the replay of numbers the receiver has already passed, so the attack starts once the stream is under way
        tokio::time::sleep(Duration::from_millis(300)).await;
        for round in 0..400 {
            for p in attack(&a_in, &b_in, round) {
                let _ = a_in.send(p.clone()).await;
                let _ = b_in.send(p).await;
            }
            tokio::time::sleep(Duration::from_millis(3)).await;
        }
    });
    let mut hello = [0u8; 5];
    b.read_exact(&mut hello).await.unwrap();
    b.write_all(b"ok").await.unwrap();
    let mut got = vec![0u8; sent.len()];
    tokio::time::timeout(Duration::from_secs(60), b.read_exact(&mut got)).await.expect("finished in time").unwrap();
    assert!(got == sent, "the stream is intact");
    b.write_all(b"thank").await.unwrap();
    tokio::time::timeout(Duration::from_secs(30), w).await.unwrap().unwrap();
    fire.abort();
}

#[tokio::test]
async fn x1_a_confirmation_of_packets_never_sent_changes_nothing() {
    attacked_transfer(|_, _, r| vec![header(1, 7, 1_000_000 + r as u64, 1_000_000 + r as u64, 512, u64::MAX, &[]), header(1, 7, 0, u64::MAX, 0, 0, &[])]).await;
}

#[tokio::test]
async fn x2_replays_of_old_packets_with_other_contents_are_ignored() {
    // number 0 was passed by both ends long ago: the replays carry other contents under it
    attacked_transfer(|_, _, r| vec![header(1, 7, 0, 0, 512, 0, b"EVIL EVIL EVIL"), header(1, 7, 0, r as u64 % 2, 512, 0, b"REPLAY")]).await;
}

#[tokio::test]
async fn x3_forged_closes_cannot_cut_the_stream() {
    attacked_transfer(|_, _, r| (0..5u64).map(|k| header(2, 7, r as u64 * 5 + k, 0, 0, 0, &[])).collect()).await;
}

#[tokio::test]
async fn x4_a_window_of_zero_or_a_lying_selective_map_does_not_stall_the_sender_for_good() {
    attacked_transfer(|_, _, r| vec![header(1, 7, 1 << 40, 0, 0, u64::MAX, &[]), header(1, 7, r as u64 + 10_000, 0, 0, 0x5555_5555_5555_5555, b"x")]).await;
}
