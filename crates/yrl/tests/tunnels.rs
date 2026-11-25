//! Tunnels: what the server may reach is decided by the rules file; the bytes are copied faithfully; nothing leaks or hangs.
mod common;
use common::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use yrl::client::{Client, ServerError};
use yrl::client_tun::{forward_local, socks5};
use yrl::tunnel::permits;
use yrl::tunwire::{self as tw};
use yrl::wire::{self, Frame};

const W: Duration = Duration::from_secs(20);

fn write_rules(r: &Rig, text: &str) {
    use std::os::unix::fs::PermissionsExt;
    let p = r.server_dir().join("tunnels");
    std::fs::write(&p, text).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn code(e: &anyhow::Error) -> Option<u16> {
    e.downcast_ref::<ServerError>().map(|s| s.0)
}

/// a destination that echoes everything; counts the connections it got
async fn echo() -> (u16, Arc<AtomicUsize>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let n = Arc::new(AtomicUsize::new(0));
    let n2 = n.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            n2.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    (port, n)
}

fn data(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; (x >> 24) as u8 }).collect()
}

async fn trig() -> (Rig, Arc<Client>) {
    let r = rig("exec,tunnel").await;
    let c = Arc::new(open(&r).await);
    (r, c)
}

#[tokio::test]
async fn t1_bytes_go_through_both_ways_intact() {
    let (r, c) = trig().await;
    let (port, _) = echo().await;
    write_rules(&r, &format!("anna 127.0.0.1 {port}\n"));
    let mut t = c.tunnel_open("127.0.0.1", port, W).await.unwrap();
    let payload = data(5_000_000, 3);
    let (c2, p2) = (c.clone(), payload.clone());
    let mut got = Vec::new();
    // sending and receiving go on at the same time, or a full pipe would stall both sides
    let sender = {
        let t2 = c2.tunnel_open("127.0.0.1", port, W).await.unwrap();
        tokio::spawn(async move {
            t2.send(&p2).await.unwrap();
            t2.eof().await.unwrap();
            let mut t2 = t2;
            let mut back = Vec::new();
            while let Some(d) = t2.recv().await {
                back.extend_from_slice(&d);
            }
            back
        })
    };
    t.send(b"hello through a tunnel").await.unwrap();
    while got.len() < 22 {
        got.extend(t.recv().await.unwrap());
    }
    assert_eq!(got, b"hello through a tunnel");
    assert_eq!(sender.await.unwrap(), payload, "5 MB came back identical after a half-close");
    t.close().await;
}

#[tokio::test]
async fn t2_nothing_is_allowed_by_default_and_the_destination_is_never_touched() {
    let (_r, c) = trig().await; // no rules file at all
    let (port, hits) = echo().await;
    let e = c.tunnel_open("127.0.0.1", port, W).await.err().unwrap();
    assert_eq!(code(&e), Some(tw::E_DENIED));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0, "the server did not even try to connect");
}

#[test]
fn t3_rule_matching() {
    let rules = "# comment\nanna 127.0.0.1 8000-8010\n* Example.COM 443\nbob * *\nanna broken\nanna host 80 extra\n   \nanna lo 7-3\nanna x 99999\n";
    assert!(permits(rules, "anna", "127.0.0.1", 8000) && permits(rules, "anna", "127.0.0.1", 8010) && permits(rules, "anna", "127.0.0.1", 8005));
    assert!(!permits(rules, "anna", "127.0.0.1", 7999) && !permits(rules, "anna", "127.0.0.1", 8011) && !permits(rules, "anna", "127.0.0.2", 8005));
    assert!(permits(rules, "zoe", "example.com", 443) && permits(rules, "anna", "EXAMPLE.com", 443) && !permits(rules, "anna", "example.com", 80));
    assert!(permits(rules, "bob", "anything", 1) && !permits(rules, "anna", "anything", 1), "a wildcard rule belongs to its login only");
    assert!(!permits(rules, "anna", "host", 80), "a damaged rule allows nothing");
    assert!(!permits(rules, "anna", "lo", 5) && !permits(rules, "anna", "x", 80), "reversed or impossible ranges allow nothing");
    assert!(!permits("", "anna", "h", 1) && !permits("# only comments", "anna", "h", 1));
    assert!(!permits("annaa h 1\nan h 1", "anna", "h", 1), "logins are compared whole");
}

#[tokio::test]
async fn t4_rules_are_per_login_fresh_and_ignored_when_open_to_others() {
    use std::os::unix::fs::PermissionsExt;
    let (r, c) = trig().await;
    let (port, hits) = echo().await;
    write_rules(&r, &format!("guest 127.0.0.1 {port}\n"));
    assert_eq!(code(&c.tunnel_open("127.0.0.1", port, W).await.err().unwrap()), Some(tw::E_DENIED), "a rule for another login");
    write_rules(&r, &format!("guest 127.0.0.1 {port}\nanna 127.0.0.1 {port}\n"));
    c.tunnel_open("127.0.0.1", port, W).await.unwrap().close().await; // acts at once, no restart
    std::fs::set_permissions(r.server_dir().join("tunnels"), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(code(&c.tunnel_open("127.0.0.1", port, W).await.err().unwrap()), Some(tw::E_DENIED), "a rules file others can read/change is not trusted");
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn t5_without_the_tunnel_right_nothing_is_contacted() {
    let r = rig("exec").await; // the key has no 'tunnel'
    let c = Arc::new(open(&r).await);
    let (port, hits) = echo().await;
    write_rules(&r, "* * *\n");
    assert_eq!(code(&c.tunnel_open("127.0.0.1", port, W).await.err().unwrap()), Some(1));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn t6_a_scan_cannot_tell_open_ports_from_closed_ones() {
    let (r, c) = trig().await;
    let (port, _) = echo().await;
    write_rules(&r, &format!("anna 127.0.0.1 {port}\n"));
    // every port but the allowed one gives the same answer, open or closed
    let mut answers = std::collections::HashSet::new();
    for p in [port.wrapping_add(1).max(1024), 22, 80, 631, 5432, 1, 65535] {
        if p == port {
            continue;
        }
        answers.insert(code(&c.tunnel_open("127.0.0.1", p, W).await.err().unwrap()));
    }
    assert_eq!(answers, std::collections::HashSet::from([Some(tw::E_DENIED)]));
}

#[tokio::test]
async fn t7_allowed_but_unreachable_destinations_report_an_error_quickly() {
    let r = rig_with("exec,tunnel", |mut c| { c.tunnel_connect_timeout = Duration::from_millis(400); c }).await;
    let c = Arc::new(open(&r).await);
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port(); // closed again at once
    write_rules(&r, &format!("anna 127.0.0.1 {dead}\nanna 192.0.2.1 80\nanna no-such-host.invalid 80\n"));
    let t = std::time::Instant::now();
    for (h, p) in [("127.0.0.1", dead), ("192.0.2.1", 80), ("no-such-host.invalid", 80)] {
        assert_eq!(code(&c.tunnel_open(h, p, W).await.err().unwrap()), Some(tw::E_CONNECT), "{h}");
    }
    assert!(t.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn t8_half_close_works_in_both_directions() {
    let (r, c) = trig().await;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    write_rules(&r, &format!("anna 127.0.0.1 {port}\n"));
    // destination: says hello, closes its sending side, then still reads until the client is done and reports the count
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        s.write_all(b"hello").await.unwrap();
        s.shutdown().await.unwrap();
        let mut n = 0;
        let mut buf = [0u8; 1024];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(k) => n += k,
            }
        }
        let _ = s.write_all(format!("[got {n}]").as_bytes()).await; // after we closed our side: the peer must not hear this
    });
    let mut t = c.tunnel_open("127.0.0.1", port, W).await.unwrap();
    let mut got = Vec::new();
    while let Some(d) = t.recv().await {
        got.extend(d);
    }
    assert_eq!(got, b"hello", "the destination's half-close arrived as an end of data");
    t.send(&[7u8; 1000]).await.unwrap(); // our side is still open
    t.eof().await.unwrap();
    t.close().await;
}

#[tokio::test]
async fn t17_our_end_of_data_reaches_the_destination_and_a_close_really_closes() {
    let (r, c) = trig().await;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    write_rules(&r, &format!("anna 127.0.0.1 {port}\n"));
    let (seen_tx, seen_rx) = tokio::sync::oneshot::channel();
    let (write_tx, write_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut n = 0;
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(k) => n += k,
            }
        }
        let _ = seen_tx.send(n); // our half-close arrived as an end of data
        // keep the connection open and silent; then try to write after the client closed the tunnel
        tokio::time::sleep(Duration::from_millis(700)).await;
        let first = s.write_all(b"a").await.is_ok();
        tokio::time::sleep(Duration::from_millis(300)).await;
        let second = s.write_all(b"b").await.is_ok();
        let _ = write_tx.send((first, second));
    });
    let t = c.tunnel_open("127.0.0.1", port, W).await.unwrap();
    t.send(&[1u8; 777]).await.unwrap();
    t.eof().await.unwrap();
    assert_eq!(tokio::time::timeout(Duration::from_secs(5), seen_rx).await.expect("EOF must reach the destination").unwrap(), 777);
    tokio::time::sleep(Duration::from_millis(100)).await;
    t.close().await; // the destination is silent and still open: only an explicit close can end this
    let (_first, second) = tokio::time::timeout(Duration::from_secs(5), write_rx).await.unwrap().unwrap();
    assert!(!second, "after the close the server's socket is gone: a write to it must fail (reset), not vanish into a leaked half-open socket");
}

#[tokio::test]
async fn t18_a_finished_forwarded_connection_leaves_nothing_behind() {
    let (r, c) = trig().await;
    let (port, _) = echo().await;
    write_rules(&r, &format!("anna 127.0.0.1 {port}\n"));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = l.local_addr().unwrap();
    tokio::spawn(forward_local(c.clone(), l, "127.0.0.1".into(), port));
    for i in 0..5 {
        let mut s = TcpStream::connect(local).await.unwrap();
        s.write_all(format!("round {i}").as_bytes()).await.unwrap();
        s.shutdown().await.unwrap(); // our end of data must travel: the echo ends only then
        let mut back = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut back)).await.expect("the end of data must reach the destination and come back").unwrap();
        assert_eq!(back, format!("round {i}").as_bytes());
    }
    for _ in 0..50 {
        if c.pending_streams().await == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{} streams are still registered after everything finished", c.pending_streams().await);
}

#[tokio::test]
async fn t9_the_number_of_tunnels_is_limited_and_closing_frees_a_place() {
    let r = rig_with("exec,tunnel", |mut c| { c.max_tunnels_per_connection = 2; c }).await;
    let c = Arc::new(open(&r).await);
    let (port, _) = echo().await;
    write_rules(&r, &format!("anna 127.0.0.1 {port}\n"));
    let a = c.tunnel_open("127.0.0.1", port, W).await.unwrap();
    let b = c.tunnel_open("127.0.0.1", port, W).await.unwrap();
    assert_eq!(code(&c.tunnel_open("127.0.0.1", port, W).await.err().unwrap()), Some(5));
    a.close().await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let _third = c.tunnel_open("127.0.0.1", port, W).await.unwrap();
    drop(b);
}

#[tokio::test]
async fn t10_raw_frames_before_the_login_and_garbage_are_harmless() {
    let r = rig("exec,tunnel").await;
    let (port, hits) = echo().await;
    write_rules(&r, "* * *\n");
    let open_frame = tw::encode_open(1, "127.0.0.1", port).unwrap();
    let (mut s, sec) = raw(&r).await;
    send(&mut s, &sec, Frame::new(tw::TUN_OPEN, 0, open_frame.clone())).await;
    assert!(recv(&mut s, &sec).await.is_none(), "no tunnel before the login");
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    let (mut s, sec) = raw(&r).await;
    raw_login(&mut s, &sec, "anna", PW).await;
    for k in [tw::TUN_DATA, tw::TUN_EOF, tw::TUN_CLOSE] {
        send(&mut s, &sec, Frame::new(k, 0, wire::with_id(77, b"zz"))).await;
    }
    send(&mut s, &sec, Frame::new(wire::PING, 0, b"alive".to_vec())).await;
    assert_eq!(recv(&mut s, &sec).await.map(|f| f.payload), Some(b"alive".to_vec()));
    for bad in [vec![], vec![0; 10], {
        let mut v = open_frame.clone();
        v.push(0);
        v
    }, {
        let mut v = wire::with_id(1, &0u16.to_be_bytes()); // port 0
        v.push(1);
        v.push(b'h');
        v
    }, {
        let mut v = wire::with_id(1, &80u16.to_be_bytes());
        v.push(3);
        v.extend_from_slice(b"a b"); // a space in a host
        v
    }] {
        let (mut s, sec) = raw(&r).await;
        raw_login(&mut s, &sec, "anna", PW).await;
        send(&mut s, &sec, Frame::new(tw::TUN_OPEN, 0, bad)).await;
        send(&mut s, &sec, Frame::new(wire::PING, 0, b"x".to_vec())).await;
        assert!(recv(&mut s, &sec).await.is_none(), "a malformed tunnel request ends the session");
    }
    assert_eq!(hits.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn t11_a_dropped_link_closes_the_destination_connection() {
    let r = rig("exec,tunnel").await;
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    write_rules(&r, &format!("anna 127.0.0.1 {port}\n"));
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut s, _) = l.accept().await.unwrap();
        let mut b = [0u8; 16];
        let n = s.read(&mut b).await.unwrap_or(0); // returns 0 once the server drops its side
        let _ = done_tx.send(n);
    });
    {
        let c = Arc::new(open(&r).await);
        let _t = c.tunnel_open("127.0.0.1", port, W).await.unwrap();
    } // the whole client is gone
    let n = tokio::time::timeout(Duration::from_secs(5), done_rx).await.expect("the destination must see the end").unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn t12_a_local_port_leads_to_the_destination_for_many_connections_at_once() {
    let (r, c) = trig().await;
    let (port, _) = echo().await;
    write_rules(&r, &format!("anna 127.0.0.1 {port}\n"));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = l.local_addr().unwrap();
    tokio::spawn(forward_local(c.clone(), l, "127.0.0.1".into(), port));
    let mut jobs = vec![];
    for i in 0..8u64 {
        jobs.push(tokio::spawn(async move {
            let payload = data(300_000 + i as usize, i + 1);
            let mut s = TcpStream::connect(local).await.unwrap();
            let (mut rd, mut wr) = s.split();
            let mut back = vec![0u8; payload.len()];
            let (w, r) = tokio::join!(async { wr.write_all(&payload).await.unwrap() }, async { rd.read_exact(&mut back).await.unwrap() });
            let _ = (w, r);
            back == payload
        }));
    }
    for j in jobs {
        assert!(j.await.unwrap(), "every parallel connection got its own bytes back");
    }
}

async fn socks_connect(proxy: std::net::SocketAddr, atyp_host: &[u8], port: u16) -> (TcpStream, u8) {
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    assert_eq!(m, [5, 0]);
    let mut req = vec![5, 1, 0];
    req.extend_from_slice(atyp_host);
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    (s, rep[1])
}

#[tokio::test]
async fn t13_socks5_proxy_connects_by_address_and_by_name_and_reports_failures() {
    let (r, c) = trig().await;
    let (port, _) = echo().await;
    write_rules(&r, &format!("anna 127.0.0.1 {port}\nanna localhost {port}\n"));
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = l.local_addr().unwrap();
    tokio::spawn(socks5(c.clone(), l));
    let (mut s, code) = socks_connect(proxy, &[1, 127, 0, 0, 1], port).await;
    assert_eq!(code, 0);
    s.write_all(b"ping through socks").await.unwrap();
    let mut b = [0u8; 18];
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"ping through socks");
    let mut name = vec![3, 9];
    name.extend_from_slice(b"localhost");
    let (mut s, code) = socks_connect(proxy, &name, port).await;
    assert_eq!(code, 0, "a name is resolved by the server");
    s.write_all(b"x").await.unwrap();
    let mut b = [0u8; 1];
    s.read_exact(&mut b).await.unwrap();
    let (_, code) = socks_connect(proxy, &[1, 10, 1, 2, 3], 80).await;
    assert_eq!(code, 2, "not allowed by the rules");
    write_rules(&r, "anna 127.0.0.1 *\n");
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().port();
    let (_, code) = socks_connect(proxy, &[1, 127, 0, 0, 1], dead).await;
    assert_eq!(code, 5, "connection refused");
}

#[tokio::test]
async fn t14_socks5_garbage_and_unsupported_requests_are_handled() {
    let (r, c) = trig().await;
    write_rules(&r, "* * *\n");
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = l.local_addr().unwrap();
    tokio::spawn(socks5(c.clone(), l));
    // wrong version, no acceptable method, BIND command, unknown address type
    for bytes in [vec![4u8, 1, 0, 80], vec![5, 1, 2], vec![]] {
        let mut s = TcpStream::connect(proxy).await.unwrap();
        let _ = s.write_all(&bytes).await;
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut out)).await;
        assert!(out.is_empty() || out == vec![5, 0xFF], "{bytes:?} -> {out:?}");
    }
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    let mut m = [0u8; 2];
    s.read_exact(&mut m).await.unwrap();
    s.write_all(&[5, 2, 0, 1, 127, 0, 0, 1, 0, 80]).await.unwrap(); // BIND
    let mut rep = [0u8; 10];
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 7);
    let mut s = TcpStream::connect(proxy).await.unwrap();
    s.write_all(&[5, 1, 0]).await.unwrap();
    s.read_exact(&mut m).await.unwrap();
    s.write_all(&[5, 1, 0, 9, 1, 2, 3, 4, 0, 80]).await.unwrap();
    s.read_exact(&mut rep).await.unwrap();
    assert_eq!(rep[1], 8);
    // the proxy still works afterwards
    let (port, _) = echo().await;
    let (_, code) = socks_connect(proxy, &[1, 127, 0, 0, 1], port).await;
    assert_eq!(code, 0);
}

#[tokio::test]
async fn t15_logs_do_not_name_the_destinations() {
    let (r, c) = trig().await;
    let (port, _) = echo().await;
    write_rules(&r, &format!("anna 127.0.0.1 {port}\n"));
    c.tunnel_open("127.0.0.1", port, W).await.unwrap().close().await;
    let _ = c.tunnel_open("secret-host.example", 4443, W).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let log = r.log.lock().unwrap().join("\n");
    assert!(log.contains("tunnel opened") && log.contains("refused by the rules"));
    for s in ["secret-host", "4443", &port.to_string(), "127.0.0.1"] {
        assert!(!log.contains(s), "the log names {s}");
    }
}

#[test]
fn t16_open_codec() {
    let e = tw::encode_open(9, "example.org", 443).unwrap();
    assert_eq!(tw::decode_open(&e).unwrap(), (9, "example.org".to_string(), 443));
    assert!(tw::encode_open(1, "", 80).is_err() && tw::encode_open(1, "a b", 80).is_err() && tw::encode_open(1, "h", 0).is_err() && tw::encode_open(1, &"h".repeat(256), 80).is_err());
    assert!(tw::encode_open(1, &"h".repeat(255), 80).is_ok());
    assert!(tw::decode_open(&e[..e.len() - 1]).is_err() && tw::decode_open(&e[..10]).is_err());
    let mut longer = e.clone();
    longer.push(b'x'); // a printable trailing byte would pass as part of the host if the length were not exact
    assert!(tw::decode_open(&longer).is_err());
    let mut x = 5u64;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    for _ in 0..30_000 {
        let b: Vec<u8> = (0..(rnd() % 40) as usize).map(|_| rnd() as u8).collect();
        let _ = tw::decode_open(&b);
    }
}
