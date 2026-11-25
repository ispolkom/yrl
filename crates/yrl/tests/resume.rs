//! Sessions that survive the network: cut, swallowed, delayed, expired, stolen. Everything goes through a misbehaving proxy.
mod common;
use common::chaos::Chaos;
use common::*;
use std::sync::Arc;
use std::time::Duration;
use yrl::client::PtyEvent;
use yrl::link;
use yrl::wire::{self, Frame};

const W: Duration = Duration::from_secs(40);

/// output lines of a terminal with the control noise in front of them removed ("\x1b[?2004l\r42" -> "42")
fn clean_lines(s: &str) -> Vec<String> {
    s.split('\n').map(|l| l.trim_end_matches('\r').rsplit('\r').next().unwrap_or("").trim().to_string()).collect()
}

fn data(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; (x >> 24) as u8 }).collect()
}

async fn setup() -> (Rig, Chaos) {
    let r = rig_with("exec,shell,files,tunnel", |mut c| { c.session_grace = Duration::from_secs(60); c }).await;
    let ch = Chaos::start(&r.addr).await;
    (r, ch)
}

#[tokio::test]
async fn r1_the_same_shell_goes_on_after_the_connection_is_cut() {
    let (r, ch) = setup().await;
    let c = open_via(&r, &ch.addr, fast_opts()).await;
    let mut p = c.pty_open(24, 80, "xterm").await.unwrap();
    p.write(b"echo pid-$$-end; X=remembered\n").await.unwrap();
    let first = p.read_until("-end\r\n", W).await.unwrap();
    let pid1 = clean_lines(&first).into_iter().find(|l| l.starts_with("pid-") && l.ends_with("-end") && !l.contains('$')).unwrap().trim_start_matches("pid-").trim_end_matches("-end").to_string();
    for round in 0..3 {
        ch.cut();
        tokio::time::sleep(Duration::from_millis(60)).await;
        p.write(format!("echo again-{round}-$$-$X-f$((1+1))n\n").as_bytes()).await.unwrap();
        let out = p.read_until("-f2n\r\n", W).await.unwrap();
        assert!(out.contains(&format!("again-{round}-{pid1}-remembered-f2n")), "round {round}: the same process with the same memory: {out}");
    }
    assert!(ch.accepted() >= 4, "the client really reconnected ({} connections)", ch.accepted());
    assert_eq!(r.sessions.len(), 1, "one session all along");
}

#[tokio::test]
async fn r2_a_big_upload_through_a_constantly_cutting_network_arrives_intact() {
    let (r, ch) = setup().await;
    let c = open_via(&r, &ch.addr, fast_opts()).await;
    let d = r.dir.path();
    let bytes = data(48 << 20, 21);
    std::fs::write(d.join("src"), &bytes).unwrap();
    let ch = Arc::new(ch);
    let cutter = (ch.clone(), common::chaos::spawn_cutter(ch.clone(), 5, 60, 11));
    let t = c.put_file(&d.join("src"), d.join("dst").to_str().unwrap().as_bytes(), 0o600, Duration::from_secs(15)).await;
    if t.is_err() { eprintln!("[dbg] client {} | server {:?} | dst exists={} part={:?}", c.link_state(), r.sessions.describe(), d.join("dst").exists(), std::fs::metadata(d.join("dst.yrl-part")).map(|m| m.len())); }
    let t = t.unwrap();
    cutter.1.abort();
    assert_eq!(std::fs::read(d.join("dst")).unwrap(), bytes, "every byte exactly once, in order");
    assert_eq!(t.resumed_from, 0, "it is one transfer, not a restart");
    assert!(cutter.0.accepted() > 3, "the network really was cut ({} connections)", cutter.0.accepted());
}

#[tokio::test]
async fn r3_a_big_download_through_cuts_arrives_intact() {
    let (r, ch) = setup().await;
    let c = open_via(&r, &ch.addr, fast_opts()).await;
    let d = r.dir.path();
    let bytes = data(48 << 20, 22);
    std::fs::write(d.join("remote"), &bytes).unwrap();
    let ch = Arc::new(ch);
    let h = common::chaos::spawn_cutter(ch.clone(), 5, 60, 7);
    c.get_file(d.join("remote").to_str().unwrap().as_bytes(), &d.join("local"), W).await.unwrap();
    h.abort();
    assert_eq!(std::fs::read(d.join("local")).unwrap(), bytes);
    assert!(ch.accepted() > 3);
}

#[tokio::test]
async fn r4_terminal_output_has_no_gaps_and_no_repeats_across_cuts() {
    let (r, ch) = setup().await;
    let c = open_via(&r, &ch.addr, fast_opts()).await;
    let mut p = c.pty_open(24, 80, "xterm").await.unwrap();
    let ch = Arc::new(ch);
    let h = common::chaos::spawn_cutter(ch.clone(), 5, 60, 7);
    p.write(b"seq 1 60000; echo finished-$((2+2))\n").await.unwrap();
    let out = p.read_until("finished-4", Duration::from_secs(90)).await.unwrap();
    h.abort();
    let nums: Vec<u64> = clean_lines(&out).iter().filter_map(|l| l.parse().ok()).collect();
    assert_eq!(nums.len(), 60_000, "lines seen: {}", nums.len());
    assert!(nums.iter().enumerate().all(|(i, n)| *n == i as u64 + 1), "in order, none missing, none twice");
    assert!(ch.accepted() > 3);
}

#[tokio::test]
async fn r5_a_tunnel_carries_bytes_across_cuts() {
    let (r, ch) = setup().await;
    let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = echo.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = echo.accept().await else { return };
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    std::fs::write(r.server_dir().join("tunnels"), format!("anna 127.0.0.1 {port}\n")).unwrap();
    std::fs::set_permissions(r.server_dir().join("tunnels"), std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let c = Arc::new(open_via(&r, &ch.addr, fast_opts()).await);
    let t = Arc::new(c.tunnel_open("127.0.0.1", port, W).await.unwrap());
    let ch = Arc::new(ch);
    let h = common::chaos::spawn_cutter(ch.clone(), 5, 60, 7);
    let payload = data(30_000_000, 5);
    let (t2, p2) = (t.clone(), payload.clone());
    let sender = tokio::spawn(async move {
        t2.send(&p2).await.unwrap();
        t2.eof().await.unwrap();
    });
    let mut back = Vec::new();
    while let Some(d) = tokio::time::timeout(W, t.recv()).await.unwrap() {
        back.extend_from_slice(&d);
    }
    sender.await.unwrap();
    h.abort();
    assert_eq!(back.len(), payload.len());
    assert!(back == payload, "bytes intact and in order through the cuts");
    assert!(ch.accepted() > 3);
}

#[tokio::test]
async fn r6_a_link_that_dies_silently_is_noticed_and_replaced() {
    let (r, ch) = setup().await;
    let c = open_via(&r, &ch.addr, fast_opts()).await;
    assert!(c.ping(b"before", T).await.is_ok());
    let before = ch.accepted();
    ch.blackhole_current(); // sockets stay open, nothing passes: no reset will ever tell the client
    let t = std::time::Instant::now();
    assert_eq!(c.ping(b"after", Duration::from_secs(15)).await.unwrap(), b"after", "the ping is answered once the link is replaced");
    assert!(t.elapsed() < Duration::from_secs(8), "noticed within the dead_after window: {:?}", t.elapsed());
    assert!(ch.accepted() > before);
    assert_eq!(r.sessions.len(), 1);
}

#[tokio::test]
async fn r7_a_session_is_ended_when_nobody_comes_back_and_the_client_learns_it() {
    let r = rig_with("exec,shell,files,tunnel", |mut c| { c.session_grace = Duration::from_millis(700); c }).await;
    let ch = Chaos::start(&r.addr).await;
    let c = open_via(&r, &ch.addr, fast_opts()).await;
    let mut p = c.pty_open(24, 80, "xterm").await.unwrap();
    let pidfile = r.dir.path().join("pid");
    p.write(format!("echo $$ > {}; echo up-$((1+1))\n", pidfile.display()).as_bytes()).await.unwrap();
    p.read_until("up-2", W).await.unwrap();
    let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
    ch.refuse(true);
    ch.cut();
    tokio::time::sleep(Duration::from_millis(1500)).await; // longer than the grace
    assert_eq!(r.sessions.len(), 0, "the session expired on the server");
    let mut gone = false;
    for _ in 0..50 {
        let dead = unsafe { libc::kill(pid, 0) != 0 } || std::fs::read_to_string(format!("/proc/{pid}/stat")).map(|s| s.contains(") Z ")).unwrap_or(true);
        if dead {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(gone, "its shell was hung up");
    ch.refuse(false);
    for _ in 0..100 {
        if c.session_lost() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(c.session_lost(), "the client was told that the server no longer has the session");
    assert!(c.ping(b"x", Duration::from_secs(1)).await.is_err(), "calls fail clearly instead of hanging");
    let mut ended = false;
    for _ in 0..20 {
        match tokio::time::timeout(Duration::from_secs(5), p.next()).await {
            Ok(PtyEvent::Closed) => {
                ended = true;
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    assert!(ended, "the terminal handle reports the loss");
}

/// a hand-driven login that also returns the session id
async fn raw_with_sid(r: &Rig, key: &yrl::keys::KeyPair) -> (tokio::net::TcpStream, yrl::session::Secure, Vec<u8>) {
    let mut s = tokio::net::TcpStream::connect(&r.addr).await.unwrap();
    let sec = yrl::session::client_handshake(&mut s, key, &r.server_pub, yrl::session::REKEY_EVERY).await.unwrap();
    send(&mut s, &sec, Frame::new(wire::LOGIN, 0, wire::encode_login(b"anna", PW).unwrap())).await;
    assert_eq!(recv(&mut s, &sec).await.unwrap().kind, wire::LOGIN_OK);
    let sess = recv(&mut s, &sec).await.unwrap();
    assert_eq!(sess.kind, link::SESSION);
    (s, sec, sess.payload)
}

async fn try_resume(r: &Rig, key: &yrl::keys::KeyPair, sid: &[u8]) -> Option<u8> {
    let mut s = tokio::net::TcpStream::connect(&r.addr).await.unwrap();
    let sec = yrl::session::client_handshake(&mut s, key, &r.server_pub, yrl::session::REKEY_EVERY).await.ok()?;
    let mut p = sid.to_vec();
    p.extend_from_slice(&0u64.to_be_bytes());
    send(&mut s, &sec, Frame::new(link::RESUME, 0, p)).await;
    recv(&mut s, &sec).await.map(|f| f.kind)
}

#[tokio::test]
async fn r8_only_the_same_key_can_take_a_session_over() {
    let r = rig("exec,shell,files,tunnel").await;
    let (_s, _sec, sid) = raw_with_sid(&r, &r.client).await;
    let other = yrl::keys::generate();
    yrl::keys::authorize(&r.server_dir().join("authorized_keys"), &hex::encode(&other.public), "second", "exec").unwrap();
    assert_eq!(try_resume(&r, &other, &sid).await, Some(link::RESUME_REFUSED), "another authorized key, right session id: refused");
    assert_eq!(try_resume(&r, &r.client, &sid).await, Some(link::RESUMED), "the owner of the session may take it");
    let stranger = yrl::keys::generate();
    assert_eq!(try_resume(&r, &stranger, &sid).await, None, "an unknown key gets silence as always");
    assert_eq!(try_resume(&r, &r.client, &[7u8; 16]).await, Some(link::RESUME_REFUSED), "an unknown session id");
    assert_eq!(try_resume(&r, &r.client, &[7u8; 5]).await, None, "a malformed request is dropped");
}

#[tokio::test]
async fn r9_guessing_session_ids_is_throttled() {
    let r = rig_with("exec,shell,files,tunnel", |c| c.with_lock(3, Duration::from_secs(30), Duration::from_secs(60))).await;
    for i in 0..3u8 {
        assert_eq!(try_resume(&r, &r.client, &[i; 16]).await, Some(link::RESUME_REFUSED));
    }
    let (_s, _sec, sid) = {
        // even the right password is locked out now, so create the session first through a key that is not locked: same ip, so use the ip lock too
        (0, 0, vec![0u8; 16])
    };
    let _ = sid;
    assert_eq!(try_resume(&r, &r.client, &[9; 16]).await, None, "after three misses the key and the address are locked: silence");
}

#[tokio::test]
async fn r10_a_polite_goodbye_ends_the_session_at_once_but_a_cut_does_not() {
    let (r, ch) = setup().await;
    let c = open_via(&r, &ch.addr, fast_opts()).await;
    let c2 = open_via(&r, &ch.addr, fast_opts()).await;
    assert_eq!(r.sessions.len(), 2);
    ch.cut();
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(r.sessions.len(), 2, "a cut connection leaves the session standing");
    assert!(c.ping(b"still", W).await.is_ok() && c2.ping(b"still", W).await.is_ok());
    drop(c);
    for _ in 0..50 {
        if r.sessions.len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(r.sessions.len(), 1, "dropping the client says goodbye");
    c2.close().await;
    for _ in 0..50 {
        if r.sessions.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(r.sessions.is_empty());
}

#[tokio::test]
async fn r11_the_number_of_sessions_is_limited() {
    let r = rig_with("exec,shell,files,tunnel", |mut c| { c.max_sessions_per_key = 2; c }).await;
    let a = open(&r).await;
    let b = open(&r).await;
    let third = yrl::client::Client::connect(&r.addr, &r.client, &r.server_pub, T).await.unwrap();
    assert!(third.login("anna", PW, T).await.is_err(), "the third session of one key is refused");
    drop(a);
    tokio::time::sleep(Duration::from_millis(400)).await;
    let fourth = yrl::client::Client::connect(&r.addr, &r.client, &r.server_pub, T).await.unwrap();
    assert!(fourth.login("anna", PW, T).await.is_ok(), "a place was freed");
    drop(b);
}

#[tokio::test]
async fn r12_two_sessions_do_not_disturb_each_other() {
    let (r, ch) = setup().await;
    let a = open_via(&r, &ch.addr, fast_opts()).await;
    let quiet = open(&r).await; // goes straight to the server, not through the proxy
    let mut pa = a.pty_open(24, 80, "xterm").await.unwrap();
    let mut pq = quiet.pty_open(24, 80, "xterm").await.unwrap();
    pq.write(b"echo quiet-$$-x$((1+1))\n").await.unwrap();
    let q1 = pq.read_until("-x2\r\n", W).await.unwrap();
    for _ in 0..3 {
        ch.cut();
        pa.write(b"echo a-alive-$((2+3))\n").await.unwrap();
        pa.read_until("a-alive-5", W).await.unwrap();
    }
    pq.write(b"echo quiet-$$-y$((1+1))\n").await.unwrap();
    let q2 = pq.read_until("-y2\r\n", W).await.unwrap();
    let pid = |s: &str, tail: &str| clean_lines(s).into_iter().find(|l| l.starts_with("quiet-") && l.ends_with(tail) && !l.contains('$')).unwrap().replace("quiet-", "").replace(tail, "");
    assert_eq!(pid(&q1, "-x2"), pid(&q2, "-y2"), "the other session never noticed");
}

#[tokio::test]
async fn r13_a_flood_while_the_link_is_down_is_held_back_not_lost() {
    let r = rig_with("exec,shell,files,tunnel", |mut c| { c.link_window = 256 << 10; c.session_grace = Duration::from_secs(60); c }).await;
    let ch = Chaos::start(&r.addr).await;
    let mut o = fast_opts();
    o.window = 256 << 10;
    let c = open_via(&r, &ch.addr, o).await;
    let mut p = c.pty_open(24, 80, "xterm").await.unwrap();
    p.write(b"seq 1 200000; echo done-$((3+3))\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    ch.blackhole_current(); // the flood goes on while nothing can be delivered
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let out = p.read_until("done-6", Duration::from_secs(90)).await.unwrap();
    let nums: Vec<u64> = clean_lines(&out).iter().filter_map(|l| l.parse().ok()).collect();
    assert_eq!(nums.len(), 200_000);
    assert!(nums.iter().enumerate().all(|(i, n)| *n == i as u64 + 1));
}

#[tokio::test]
async fn r14_a_slow_network_is_just_slow() {
    let (r, ch) = setup().await;
    ch.set_delay(40);
    let c = open_via(&r, &ch.addr, fast_opts()).await;
    let res = c.exec(&[b"echo", b"slow but sure"], 5000, W).await.unwrap();
    assert_eq!(res.stdout, b"slow but sure\n");
    let d = r.dir.path();
    std::fs::write(d.join("s"), data(300_000, 3)).unwrap();
    c.put_file(&d.join("s"), d.join("d").to_str().unwrap().as_bytes(), 0o600, W).await.unwrap();
    assert_eq!(std::fs::read(d.join("d")).unwrap(), std::fs::read(d.join("s")).unwrap());
    assert_eq!(ch.accepted(), 1, "slowness alone does not make the client give up on a connection that works");
}

#[tokio::test]
async fn r15_a_client_cannot_claim_to_have_received_what_was_never_sent() {
    let r = rig("exec,shell,files,tunnel").await;
    let (_s, _sec, sid) = raw_with_sid(&r, &r.client).await;
    let mut s = tokio::net::TcpStream::connect(&r.addr).await.unwrap();
    let sec = yrl::session::client_handshake(&mut s, &r.client, &r.server_pub, yrl::session::REKEY_EVERY).await.unwrap();
    let mut p = sid.clone();
    p.extend_from_slice(&1_000_000u64.to_be_bytes());
    send(&mut s, &sec, Frame::new(link::RESUME, 0, p)).await;
    assert_eq!(recv(&mut s, &sec).await.map(|f| f.kind), Some(link::RESUME_REFUSED));
}

#[tokio::test]
async fn r16_a_session_that_was_taken_back_in_time_is_not_ended_by_the_old_timer() {
    let r = rig_with("exec,shell,files,tunnel", |mut c| { c.session_grace = Duration::from_millis(800); c }).await;
    let ch = Chaos::start(&r.addr).await;
    let c = open_via(&r, &ch.addr, fast_opts()).await;
    ch.cut(); // the grace timer of this loss starts now
    assert!(c.ping(b"back", W).await.is_ok(), "the client came back within the grace");
    tokio::time::sleep(Duration::from_millis(1800)).await; // well past the first timer
    assert_eq!(r.sessions.len(), 1, "the old timer must not end a session that has a connection again");
    assert!(c.ping(b"still", W).await.is_ok());
}

#[tokio::test]
async fn r17_the_total_number_of_sessions_is_limited_too() {
    let r = rig_with("exec,shell,files,tunnel", |mut c| { c.max_sessions = 1; c }).await;
    let _a = open(&r).await;
    let other = yrl::keys::generate();
    yrl::keys::authorize(&r.server_dir().join("authorized_keys"), &hex::encode(&other.public), "second", "exec").unwrap();
    let b = yrl::client::Client::connect(&r.addr, &other, &r.server_pub, T).await.unwrap();
    assert!(b.login("anna", PW, T).await.is_err(), "a different key is refused as well: the server is full");
}

#[tokio::test]
async fn r18_a_client_gives_up_after_its_own_deadline_even_if_the_server_would_wait() {
    let r = rig_with("exec,shell,files,tunnel", |mut c| { c.session_grace = Duration::from_secs(60); c }).await;
    let ch = Chaos::start(&r.addr).await;
    let mut o = fast_opts();
    o.give_up_after = Duration::from_millis(900);
    let c = open_via(&r, &ch.addr, o).await;
    ch.refuse(true);
    ch.cut();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(c.session_lost(), "after its deadline the client reports the session lost");
    assert_eq!(r.sessions.len(), 1, "(the server still holds it: the client decided on its own)");
}

#[tokio::test]
async fn r19_retries_start_fast_and_slow_down() {
    let r = rig_with("exec,shell,files,tunnel", |mut c| { c.session_grace = Duration::from_secs(60); c }).await;
    let ch = Chaos::start(&r.addr).await;
    let c = open_via(&r, &ch.addr, fast_opts()).await; // retry 20 ms, doubling, at most 200 ms
    let base = ch.attempts();
    ch.refuse(true);
    ch.cut();
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let n = ch.attempts() - base;
    assert!((6..=14).contains(&n), "in one second of refusals a client that starts at 20 ms and backs off to 200 ms tries about 8 times, not {n}");
    ch.refuse(false);
    assert!(c.ping(b"ok", W).await.is_ok());
}
