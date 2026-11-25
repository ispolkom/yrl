//! The relay: a server that only dials out, a meeting point that sees nothing, and what a hostile one can and cannot do.
mod common;
use common::*;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use yrl::client::{Client, ClientOptions};
use yrl::relay::{self, header, rendezvous_id, RelayConfig, ROLE_CLIENT, ROLE_SERVER};
use yrl::server::serve_via_relay;

const W: Duration = Duration::from_secs(30);

async fn start_relay(cfg: RelayConfig) -> (String, Arc<relay::Relay>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    (addr, Arc::new(relay::serve(l, cfg).await))
}

/// a server that is reachable ONLY through the relay (the direct listener of the rig is simply not used)
async fn behind_relay(relay_addr: &str) -> Rig {
    let r = rig_with("exec,shell,files,tunnel", |mut c| { c.session_grace = Duration::from_secs(30); c }).await;
    tokio::spawn(serve_via_relay(relay_addr.to_string(), r.server_key.clone(), r.cfg.clone(), 2));
    r
}

fn via(relay_addr: &str) -> ClientOptions {
    ClientOptions { relay: Some(relay_addr.to_string()), connect_timeout: Duration::from_secs(5), ..fast_opts() }
}

async fn client_via(r: &Rig, relay_addr: &str) -> Client {
    let c = Client::connect_opts("label-only", &r.client, &r.server_pub, ClientOptions { executor_public: Some(r.exec_pub.clone()), ..via(relay_addr) }).await.unwrap();
    c.login("anna", PW, T).await.unwrap();
    c
}

#[tokio::test]
async fn rl1_everything_works_through_the_relay_with_no_open_port_on_the_server() {
    let (ra, stats) = start_relay(RelayConfig::default()).await;
    let r = behind_relay(&ra).await;
    let c = client_via(&r, &ra).await;
    assert_eq!(c.exec(&[b"echo", b"through the relay"], 5000, W).await.unwrap().stdout, b"through the relay\n");
    let mut p = c.pty_open(24, 80, "xterm").await.unwrap();
    p.write(b"echo pty-$((6*7))\n").await.unwrap();
    p.read_until("pty-42", W).await.unwrap();
    let d = r.dir.path();
    std::fs::write(d.join("f"), vec![7u8; 3_000_000]).unwrap();
    c.put_file(&d.join("f"), d.join("g").to_str().unwrap().as_bytes(), 0o600, W).await.unwrap();
    assert_eq!(std::fs::read(d.join("g")).unwrap(), std::fs::read(d.join("f")).unwrap());
    assert!(stats.stats.pairs.load(std::sync::atomic::Ordering::SeqCst) >= 1);
}

#[tokio::test]
async fn rl2_the_relay_sees_only_ciphertext() {
    let tap = Arc::new(Mutex::new(Vec::new()));
    let (ra, _s) = start_relay(RelayConfig { tap: Some(tap.clone()), ..Default::default() }).await;
    let r = behind_relay(&ra).await;
    let c = client_via(&r, &ra).await;
    let secret = "plaintext-marker-4f1c9a-do-not-leak";
    let out = c.exec(&[b"echo", secret.as_bytes()], 5000, W).await.unwrap();
    assert_eq!(out.stdout, format!("{secret}\n").as_bytes());
    let d = r.dir.path();
    std::fs::write(d.join("f"), format!("{secret}{secret}").repeat(1000)).unwrap();
    c.put_file(&d.join("f"), d.join("g").to_str().unwrap().as_bytes(), 0o600, W).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let seen = tap.lock().unwrap().clone();
    assert!(seen.len() > 20_000);
    let has = |needle: &[u8]| seen.windows(needle.len()).any(|w| w == needle);
    for n in [secret.as_bytes(), PW, b"anna", b"echo", b"correct horse", &r.client.public[..], &r.client.private[..]] {
        assert!(!has(n), "the relay saw {:?}", String::from_utf8_lossy(n));
    }
}

#[tokio::test]
async fn rl3_a_relay_that_alters_bytes_cannot_get_anything_altered_through() {
    // the 40th chunk from the server to the client has one bit flipped: authentication fails, the client reconnects, nothing wrong is ever accepted
    let (ra, _s) = start_relay(RelayConfig { tamper_chunk: Some(40), ..Default::default() }).await;
    let r = behind_relay(&ra).await;
    let c = client_via(&r, &ra).await;
    let d = r.dir.path();
    let bytes: Vec<u8> = (0..20_000_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
    std::fs::write(d.join("remote"), &bytes).unwrap();
    c.get_file(d.join("remote").to_str().unwrap().as_bytes(), &d.join("local"), W).await.unwrap();
    assert_eq!(std::fs::read(d.join("local")).unwrap(), bytes, "intact despite the tampering");
    assert!(r.log.lock().unwrap().iter().any(|l| l.contains("connection lost")), "the tampering really cost a connection");
}

#[tokio::test]
async fn rl4_a_fake_server_at_the_relay_learns_nothing_and_gets_no_password() {
    let (ra, _s) = start_relay(RelayConfig::default()).await;
    let victim = rig("exec").await; // the real server is NOT behind this relay: the impostor takes its place
    let mut fake = TcpStream::connect(&ra).await.unwrap();
    fake.write_all(&header(ROLE_SERVER, &rendezvous_id(&victim.server_pub))).await.unwrap();
    let got = Arc::new(Mutex::new(Vec::new()));
    let g = got.clone();
    tokio::spawn(async move {
        // the impostor records what the client sends and answers with garbage of its own
        let mut buf = vec![0u8; 4096];
        loop {
            match fake.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    g.lock().unwrap().extend_from_slice(&buf[..n]);
                    let _ = fake.write_all(&[0x55; 64]).await;
                }
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let opts = ClientOptions { executor_public: Some(victim.exec_pub.clone()), connect_timeout: Duration::from_millis(1500), ..via(&ra) };
    let res = Client::connect_opts("x", &victim.client, &victim.server_pub, opts).await;
    assert!(res.is_err(), "the client must not accept a server that cannot prove its key");
    tokio::time::sleep(Duration::from_millis(200)).await;
    let seen = got.lock().unwrap().clone();
    assert!(seen.len() < 200, "only the opening handshake message went out ({} bytes)", seen.len());
    for n in [PW, &b"anna"[..], &victim.client.public[..]] {
        assert!(!seen.windows(n.len()).any(|w| w == n), "the impostor got something it must not");
    }
}

#[tokio::test]
async fn rl5_the_relay_is_silent_to_garbage_unknown_ids_and_wrong_roles() {
    let (ra, _s) = start_relay(RelayConfig { header_timeout: Duration::from_millis(400), ..Default::default() }).await;
    let rid = [3u8; 16];
    let mut cases: Vec<Vec<u8>> = vec![vec![], b"GET / HTTP/1.1\r\n\r\n".to_vec(), vec![0xFF; 100], header(b'X', &rid).to_vec(), header(ROLE_CLIENT, &rid).to_vec(), header(ROLE_SERVER, &rid)[..10].to_vec()];
    let mut bad_version = header(ROLE_CLIENT, &rid);
    bad_version[4] = 9;
    cases.push(bad_version.to_vec());
    for c in cases {
        let mut s = TcpStream::connect(&ra).await.unwrap();
        let _ = s.write_all(&c).await;
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut out)).await;
        assert!(out.is_empty(), "the relay answered {:?} with {} bytes", &c[..c.len().min(8)], out.len());
    }
}

#[tokio::test]
async fn rl6_limits_hold() {
    let cfg = RelayConfig { max_waiting_per_ip: 3, max_waiting_per_id: 2, max_conns_per_ip: 6, wait_timeout: Duration::from_millis(500), ..Default::default() };
    let (ra, stats) = start_relay(cfg).await;
    // per id: the third waiting server for the same id is dropped
    let mut socks = vec![];
    for _ in 0..3 {
        let mut s = TcpStream::connect(&ra).await.unwrap();
        s.write_all(&header(ROLE_SERVER, &[1u8; 16])).await.unwrap();
        socks.push(s);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut closed = 0;
    for s in socks.iter_mut() {
        let mut b = [0u8; 1];
        if matches!(tokio::time::timeout(Duration::from_millis(100), s.read(&mut b)).await, Ok(Ok(0))) {
            closed += 1;
        }
    }
    assert_eq!(closed, 1, "exactly the third waiting server for one id was refused");
    // a waiting server is dropped after the wait timeout
    tokio::time::sleep(Duration::from_millis(700)).await;
    for s in socks.iter_mut() {
        let mut b = [0u8; 1];
        assert!(matches!(tokio::time::timeout(Duration::from_secs(1), s.read(&mut b)).await, Ok(Ok(0)) | Ok(Err(_))));
    }
    // per address: more than max_conns_per_ip simultaneous connections are dropped on arrival
    let mut open = vec![];
    for _ in 0..10 {
        open.push(TcpStream::connect(&ra).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(stats.stats.dropped.load(std::sync::atomic::Ordering::SeqCst) >= 4);
}

#[tokio::test]
async fn rl7_a_server_that_vanished_is_not_matched_with_a_client() {
    let (ra, _s) = start_relay(RelayConfig::default()).await;
    let rid = [5u8; 16];
    {
        let mut dead = TcpStream::connect(&ra).await.unwrap();
        dead.write_all(&header(ROLE_SERVER, &rid)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    } // gone
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut alive = TcpStream::connect(&ra).await.unwrap();
    alive.write_all(&header(ROLE_SERVER, &rid)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut cl = TcpStream::connect(&ra).await.unwrap();
    cl.write_all(&header(ROLE_CLIENT, &rid)).await.unwrap();
    cl.write_all(b"hello server").await.unwrap();
    let mut b = [0u8; 12];
    tokio::time::timeout(Duration::from_secs(3), alive.read_exact(&mut b)).await.expect("the live server must get the client").unwrap();
    assert_eq!(&b, b"hello server");
}

#[tokio::test]
async fn rl8_several_clients_are_served_one_after_another_and_at_once() {
    let (ra, _s) = start_relay(RelayConfig::default()).await;
    let r = behind_relay(&ra).await;
    let mut cs = vec![];
    for i in 0..3 {
        let c = client_via(&r, &ra).await;
        assert_eq!(c.exec(&[b"echo", format!("client {i}").as_bytes()], 5000, W).await.unwrap().stdout, format!("client {i}\n").as_bytes());
        cs.push(c);
    }
    for (i, c) in cs.iter().enumerate() {
        assert_eq!(c.exec(&[b"echo", format!("again {i}").as_bytes()], 5000, W).await.unwrap().stdout, format!("again {i}\n").as_bytes(), "the first clients still work after later ones joined");
    }
}

#[tokio::test]
async fn rl9_a_relay_that_goes_away_for_a_while_loses_nobody() {
    // everyone reaches the relay through a proxy we can switch off and on: for the server and the client that is the same as a relay restart
    let (relay_addr, _s) = start_relay(RelayConfig::default()).await;
    let ch = common::chaos::Chaos::start(&relay_addr).await;
    let r = behind_relay(&ch.addr).await;
    let c = client_via(&r, &ch.addr).await;
    let mut p = c.pty_open(24, 80, "xterm").await.unwrap();
    p.write(b"export KEPT=still-here; echo pid-$$-a$((1+1))\n").await.unwrap();
    let out = p.read_until("-a2\r\n", W).await.unwrap();
    let pid = out.lines().map(|l| l.trim_end_matches('\r').rsplit('\r').next().unwrap_or("").trim().to_string()).find(|l| l.starts_with("pid-") && l.ends_with("-a2") && !l.contains('$')).unwrap();
    for round in 0..2 {
        ch.refuse(true);
        ch.cut(); // the relay is gone: every connection dies, nobody can reconnect
        tokio::time::sleep(Duration::from_millis(1200)).await;
        ch.refuse(false); // and it is back
        p.write(format!("echo back-{round}-$$-$KEPT-b$((1+1))\n").as_bytes()).await.unwrap();
        let out = p.read_until("-b2\r\n", Duration::from_secs(40)).await.unwrap();
        let want = format!("back-{round}-{}-still-here-b2", pid.trim_start_matches("pid-").trim_end_matches("-a2"));
        assert!(out.contains(&want), "round {round}: the same shell, same memory, after the relay came back: {out}");
    }
    assert_eq!(r.sessions.len(), 1);
}
