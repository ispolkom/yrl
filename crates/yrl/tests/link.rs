//! The reliable session layer on its own: exactly once, in order, through any number of broken connections.
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{duplex, split};
use tokio::sync::mpsc;
use yrl::keys::{self, Authorized, KeyPair};
use yrl::link::{self, drive, DriveOptions, End, Link};
use yrl::session::{client_handshake, server_handshake, write_msg, Secure, REKEY_EVERY};
use yrl::wire::Frame;

fn opt() -> DriveOptions {
    DriveOptions { dead_after: Duration::from_secs(5), ping_every: None }
}

struct Keys {
    client: KeyPair,
    server: KeyPair,
    auth: Vec<Authorized>,
}

fn keys() -> Keys {
    let (client, server) = (keys::generate(), keys::generate());
    let auth = vec![Authorized { public: client.public.clone(), label: "c".into(), rights: vec![] }];
    Keys { client, server, auth }
}

/// a fresh encrypted connection (both ends) over an in-memory pipe
async fn pipe(k: &Keys) -> ((impl tokio::io::AsyncRead + Unpin + Send, impl tokio::io::AsyncWrite + Unpin + Send, Arc<Secure>), (impl tokio::io::AsyncRead + Unpin + Send, impl tokio::io::AsyncWrite + Unpin + Send, Arc<Secure>)) {
    let (mut a, mut b) = duplex(1 << 16);
    let (cs, ss) = tokio::join!(client_handshake(&mut a, &k.client, &k.server.public, REKEY_EVERY), server_handshake(&mut b, &k.server, &k.auth, REKEY_EVERY));
    let (ar, aw) = split(a);
    let (br, bw) = split(b);
    ((ar, aw, Arc::new(cs.unwrap())), (br, bw, Arc::new(ss.ok().unwrap().0)))
}

type Sink = Arc<Mutex<Vec<Frame>>>;

fn collector() -> (mpsc::Sender<Frame>, Sink) {
    let (tx, mut rx) = mpsc::channel::<Frame>(32);
    let got: Sink = Arc::new(Mutex::new(vec![]));
    let g = got.clone();
    tokio::spawn(async move {
        while let Some(f) = rx.recv().await {
            g.lock().unwrap().push(f);
        }
    });
    (tx, got)
}

fn frame(i: u32, len: usize) -> Frame {
    let mut x = (i as u64 + 1).wrapping_mul(0x9E3779B97F4A7C15);
    let payload: Vec<u8> = (0..len).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x as u8 }).collect();
    let mut p = i.to_be_bytes().to_vec();
    p.extend(payload);
    Frame::new(7, 0, p)
}

#[tokio::test]
async fn s1_exactly_once_in_order_through_many_broken_connections() {
    let k = keys();
    let (a, b) = (Link::new(64 << 10), Link::new(64 << 10));
    let (atx, a_got) = collector();
    let (btx, b_got) = collector();
    const N: u32 = 6000;
    for (link, base) in [(a.clone(), 0u32), (b.clone(), 1_000_000)] {
        tokio::spawn(async move {
            for i in 0..N {
                link.push(&frame(base + i, (i as usize * 37) % 3000)).await.unwrap();
            }
        });
    }
    let mut reconnects = 0;
    let mut x = 0xDEADBEEFu64;
    loop {
        let done = a_got.lock().unwrap().len() as u32 == N && b_got.lock().unwrap().len() as u32 == N;
        if done {
            break;
        }
        assert!(reconnects < 3000, "no progress after {reconnects} connections");
        reconnects += 1;
        let ((ar, aw, asec), (br, bw, bsec)) = pipe(&k).await;
        let (a_exp, b_exp) = (a.positions().1, b.positions().1);
        let (a2, b2, atx2, btx2) = (a.clone(), b.clone(), atx.clone(), btx.clone());
        let ta = tokio::spawn(async move { drive(&a2, ar, aw, asec, atx2, b_exp, &opt(), None).await });
        let tb = tokio::spawn(async move { drive(&b2, br, bw, bsec, btx2, a_exp, &opt(), None).await });
        x ^= x << 13; x ^= x >> 7; x ^= x << 17;
        tokio::time::sleep(Duration::from_millis(2 + x % 9)).await;
        ta.abort();
        tb.abort();
    }
    for (got, base) in [(&a_got, 1_000_000u32), (&b_got, 0u32)] {
        let g = got.lock().unwrap();
        assert_eq!(g.len() as u32, N);
        for (i, f) in g.iter().enumerate() {
            assert_eq!(f, &frame(base + i as u32, (i * 37) % 3000), "frame {i} lost, duplicated or out of order");
        }
    }
    eprintln!("[link] {reconnects} broken connections survived");
    assert!(reconnects >= 20, "the test must really break connections");
}

#[tokio::test]
async fn s2_the_window_holds_producers_back_and_nothing_is_lost() {
    let k = keys();
    let (a, b) = (Link::new(1000), Link::new(1000));
    for i in 0..2 {
        a.push(&frame(i, 400)).await.unwrap();
    }
    let a2 = a.clone();
    let third = tokio::spawn(async move { a2.push(&frame(2, 400)).await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(!third.is_finished(), "the third frame must wait: 2 x 400+ bytes fill the 1000-byte window");
    assert_eq!(a.unconfirmed().0, 2);
    let (btx, b_got) = collector();
    let (atx, _a_got) = collector();
    let ((ar, aw, asec), (br, bw, bsec)) = pipe(&k).await;
    let (a3, b3) = (a.clone(), b.clone());
    tokio::spawn(async move { drive(&a3, ar, aw, asec, atx, 0, &opt(), None).await });
    tokio::spawn(async move { drive(&b3, br, bw, bsec, btx, 0, &opt(), None).await });
    third.await.unwrap().unwrap();
    for _ in 0..100 {
        if b_got.lock().unwrap().len() == 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(b_got.lock().unwrap().len(), 3);
    for _ in 0..100 {
        if a.unconfirmed().0 == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the confirmations never freed the window: {:?}", a.unconfirmed());
}

/// the "other side" by hand: a handshaken connection whose frames we write ourselves
async fn rude_peer(k: &Keys, link: &Arc<Link>, peer_expected: u64) -> (impl tokio::io::AsyncRead + Unpin + Send, impl tokio::io::AsyncWrite + Unpin + Send, Arc<Secure>, tokio::task::JoinHandle<End>) {
    let ((ar, aw, asec), (br, bw, bsec)) = pipe(k).await;
    let (tx, _) = collector();
    let l = link.clone();
    let h = tokio::spawn(async move { drive(&l, br, bw, bsec, tx, peer_expected, &opt(), None).await });
    (ar, aw, asec, h)
}

fn seq_payload(seq: u64, f: &Frame) -> Vec<u8> {
    let mut p = seq.to_be_bytes().to_vec();
    p.extend(f.encode().unwrap());
    p
}

#[tokio::test]
async fn s3_a_broken_peer_is_cut_off() {
    let k = keys();
    let end = |h: tokio::task::JoinHandle<End>| async move { tokio::time::timeout(Duration::from_secs(3), h).await.expect("the connection must end").unwrap() };
    // a gap in the numbers
    let (_r, mut w, sec, h) = rude_peer(&k, &Link::new(1 << 20), 0).await;
    write_msg(&mut w, &sec.seal(&Frame::new(link::SEQ, 0, seq_payload(5, &frame(0, 3)))).unwrap()).await.unwrap();
    assert_eq!(end(h).await, End::Protocol, "gap");
    // a confirmation of something that was never sent
    let (_r, mut w, sec, h) = rude_peer(&k, &Link::new(1 << 20), 0).await;
    write_msg(&mut w, &sec.seal(&Frame::new(link::ACK, 0, 9u64.to_be_bytes().to_vec())).unwrap()).await.unwrap();
    assert_eq!(end(h).await, End::Protocol, "ack of the unsent");
    // a frame kind that does not belong in a session; a seq too short; an ack of the wrong size
    for f in [Frame::new(link::SESSION, 0, vec![0; 16]), Frame::new(6, 0, vec![]), Frame::new(link::SEQ, 0, vec![1, 2, 3]), Frame::new(link::ACK, 0, vec![1]), Frame::new(link::SEQ, 0, seq_payload(0, &frame(0, 3))[..12].to_vec())] {
        let (_r, mut w, sec, h) = rude_peer(&k, &Link::new(1 << 20), 0).await;
        write_msg(&mut w, &sec.seal(&f).unwrap()).await.unwrap();
        assert_eq!(end(h).await, End::Protocol, "kind {}", f.kind);
    }
    // the peer claims to have more than we ever sent / went back on what it confirmed
    let l = Link::new(1 << 20);
    let (_r, _w, _sec, h) = rude_peer(&k, &l, 3).await;
    assert_eq!(end(h).await, End::Protocol, "peer_expected beyond what was sent");
    let l = Link::new(1 << 20);
    for i in 0..4 {
        l.push(&frame(i, 5)).await.unwrap();
    }
    let (_r, mut w, sec, h) = rude_peer(&k, &l, 0).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    write_msg(&mut w, &sec.seal(&Frame::new(link::ACK, 0, 2u64.to_be_bytes().to_vec())).unwrap()).await.unwrap(); // confirms 0 and 1 after they were sent
    tokio::time::sleep(Duration::from_millis(100)).await;
    h.abort();
    let (_r, _w, _sec, h) = rude_peer(&k, &l, 0).await; // now claims to have nothing again
    assert_eq!(end(h).await, End::Protocol, "going back on a confirmation");
}

#[tokio::test]
async fn s4_a_repeated_frame_is_ignored_and_the_rest_goes_on() {
    let k = keys();
    let l = Link::new(1 << 20);
    let (tx, got) = collector();
    let ((_ar, mut aw, asec), (br, bw, bsec)) = pipe(&k).await;
    let l2 = l.clone();
    tokio::spawn(async move { drive(&l2, br, bw, bsec, tx, 0, &opt(), None).await });
    for seq in [0u64, 1, 1, 0, 2] {
        let f = frame(seq as u32, 4);
        write_msg(&mut aw, &asec.seal(&Frame::new(link::SEQ, 0, seq_payload(seq, &f))).unwrap()).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let g = got.lock().unwrap();
    assert_eq!(g.iter().map(|f| u32::from_be_bytes(f.payload[..4].try_into().unwrap())).collect::<Vec<_>>(), vec![0, 1, 2]);
}

#[tokio::test]
async fn s5_a_new_connection_takes_the_session_over_and_the_old_one_ends() {
    let k = keys();
    let l = Link::new(1 << 20);
    let (_r1, _w1, _s1, first) = rude_peer(&k, &l, 0).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let (_r2, _w2, _s2, second) = rude_peer(&k, &l, 0).await;
    assert_eq!(tokio::time::timeout(Duration::from_secs(3), first).await.unwrap().unwrap(), End::Superseded);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!second.is_finished(), "the new connection stays");
}

#[tokio::test]
async fn s6_closing_the_session_ends_connections_and_refuses_new_frames() {
    let k = keys();
    let l = Link::new(1 << 20);
    let (_r, _w, _s, h) = rude_peer(&k, &l, 0).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    l.close();
    assert_eq!(tokio::time::timeout(Duration::from_secs(3), h).await.unwrap().unwrap(), End::Closed);
    assert!(l.push(&frame(0, 1)).await.is_err());
    let (_r, _w, _s, h) = rude_peer(&k, &l, 0).await;
    assert_eq!(tokio::time::timeout(Duration::from_secs(3), h).await.unwrap().unwrap(), End::Closed, "a closed session cannot be driven");
}

#[tokio::test]
async fn s7_silence_means_a_dead_link_and_a_probe_keeps_an_idle_link_alive() {
    let k = keys();
    // no probes: dead after the deadline
    let l = Link::new(1 << 20);
    let ((_ar, _aw, _asec), (br, bw, bsec)) = pipe(&k).await;
    let (tx, _) = collector();
    let l2 = l.clone();
    let o = DriveOptions { dead_after: Duration::from_millis(300), ping_every: None };
    let t = std::time::Instant::now();
    let e = drive(&l2, br, bw, bsec, tx, 0, &o, None).await;
    assert_eq!(e, End::Dead);
    assert!(t.elapsed() >= Duration::from_millis(290) && t.elapsed() < Duration::from_secs(2));
    // with probes on one side and answers on the other, an idle link lives well past the deadline
    let (a, b) = (Link::new(1 << 20), Link::new(1 << 20));
    let ((ar, aw, asec), (br, bw, bsec)) = pipe(&k).await;
    let (atx, _) = collector();
    let (btx, b_got) = collector();
    let o = || DriveOptions { dead_after: Duration::from_millis(400), ping_every: Some(Duration::from_millis(80)) };
    let o_b = DriveOptions { dead_after: Duration::from_millis(400), ping_every: None };
    let (a2, b2) = (a.clone(), b.clone());
    let ta = tokio::spawn(async move { drive(&a2, ar, aw, asec, atx, 0, &o(), None).await });
    let tb = tokio::spawn(async move { drive(&b2, br, bw, bsec, btx, 0, &o_b, None).await });
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(!ta.is_finished() && !tb.is_finished(), "an idle link with probes must stay up");
    a.push(&frame(1, 10)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(b_got.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn s8_interactive_frames_pass_queued_file_data_without_losing_order() {
    let k = keys();
    let (a, b) = (Link::new(1 << 20), Link::new(1 << 20));
    for i in 0..8u8 {
        a.push(&Frame::new(yrl::filewire::FILE_DATA, 0, vec![i; 1024])).await.unwrap();
    }
    a.push(&Frame::new(yrl::wire::PTY_IN, 0, b"keypress".to_vec())).await.unwrap();

    let (atx, _) = collector();
    let (btx, b_got) = collector();
    let ((ar, aw, asec), (br, bw, bsec)) = pipe(&k).await;
    let (a2, b2) = (a.clone(), b.clone());
    tokio::spawn(async move { drive(&a2, ar, aw, asec, atx, 0, &opt(), None).await });
    tokio::spawn(async move { drive(&b2, br, bw, bsec, btx, 0, &opt(), None).await });

    tokio::time::timeout(Duration::from_secs(3), async {
        while b_got.lock().unwrap().len() != 9 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    let got = b_got.lock().unwrap();
    assert_eq!(got[0].kind, yrl::wire::PTY_IN, "interactive input goes before an unsent bulk backlog");
    assert_eq!(got[0].payload, b"keypress");
    for (i, frame) in got[1..].iter().enumerate() {
        assert_eq!(frame.kind, yrl::filewire::FILE_DATA);
        assert_eq!(frame.payload[0], i as u8, "file chunks retain their original order");
    }
}

#[tokio::test]
async fn s9_a_file_saturated_window_still_admits_interactive_input_within_the_same_memory_limit() {
    let link = Link::new(4096);
    for i in 0..3u8 {
        link.push(&Frame::new(yrl::filewire::FILE_DATA, 0, vec![i; 1000])).await.unwrap();
    }

    let l2 = link.clone();
    let blocked_file = tokio::spawn(async move { l2.push(&Frame::new(yrl::filewire::FILE_DATA, 0, vec![3; 1000])).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!blocked_file.is_finished(), "bulk data must stop before consuming the interactive reserve");

    let l3 = link.clone();
    let interactive = tokio::spawn(async move { l3.push(&Frame::new(yrl::wire::PTY_IN, 0, b"keypress".to_vec())).await });
    tokio::time::timeout(Duration::from_millis(500), interactive).await.expect("interactive input must enter a bulk-saturated window").unwrap().unwrap();
    let (frames, bytes) = link.unconfirmed();
    assert_eq!(frames, 4);
    assert!(bytes <= 4096, "the reserve must not increase the total memory bound: {bytes}");

    link.close();
    assert!(blocked_file.await.unwrap().is_err());
}
