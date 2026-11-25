//! The whole stack over UDP: handshake, login, commands and files through a datagram path that loses packets; a stranger's datagrams get no answer at all.
mod common;
use common::*;
use std::sync::Arc;
use std::time::Duration;
use yrl::client::ClientOptions;

const W: Duration = Duration::from_secs(90);

fn data(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n).map(|_| { x ^= x << 13; x ^= x >> 7; x ^= x << 17; (x >> 24) as u8 }).collect()
}

async fn udp_rig() -> (Rig, String) {
    let r = rig_with("exec,shell,files,tunnel", |mut c| { c.session_grace = Duration::from_secs(30); c }).await;
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = sock.local_addr().unwrap().to_string();
    tokio::spawn(yrl::server::serve_udp(sock, r.server_key.clone(), r.cfg.clone()));
    (r, addr)
}

/// a UDP forwarder that drops a share of the datagrams in both directions
async fn lossy_proxy(target: String, loss_pct: u64) -> String {
    let front = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = front.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let mut seed = 0x1234_5678_9abc_def1u64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let back = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        back.connect(&target).await.unwrap();
        let mut client: Option<std::net::SocketAddr> = None;
        let (mut a, mut b) = (vec![0u8; 2048], vec![0u8; 2048]);
        loop {
            tokio::select! {
                r = front.recv_from(&mut a) => {
                    let Ok((n, from)) = r else { continue };
                    client = Some(from);
                    if rnd() % 100 >= loss_pct { let _ = back.send(&a[..n]).await; }
                }
                r = back.recv(&mut b) => {
                    let Ok(n) = r else { continue };
                    if let Some(c) = client { if rnd() % 100 >= loss_pct { let _ = front.send_to(&b[..n], c).await; } }
                }
            }
        }
    });
    addr
}

fn opts(udp: &str) -> ClientOptions {
    ClientOptions { udp: Some(udp.to_string()), ..fast_opts() }
}

#[tokio::test]
async fn u1_login_command_and_a_big_file_go_over_udp_and_arrive_intact() {
    let (r, udp) = udp_rig().await;
    let c = open_via(&r, "unused:0", ClientOptions { dead_after: Duration::from_secs(10), ping_every: Duration::from_secs(2), ..opts(&udp) }).await;
    let out = c.exec(&[b"/bin/echo", b"over-udp"], 5000, W).await.unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("over-udp"));
    let d = r.dir.path();
    let bytes = data(6 << 20, 5);
    std::fs::write(d.join("src"), &bytes).unwrap();
    c.put_file(&d.join("src"), d.join("dst").to_str().unwrap().as_bytes(), 0o600, W).await.unwrap();
    assert_eq!(std::fs::read(d.join("dst")).unwrap(), bytes);
    c.get_file(d.join("dst").to_str().unwrap().as_bytes(), &d.join("back"), W).await.unwrap();
    assert_eq!(std::fs::read(d.join("back")).unwrap(), bytes);
}

#[tokio::test]
async fn u2_five_percent_loss_in_both_directions_still_gives_a_working_session() {
    let (r, udp) = udp_rig().await;
    let px = lossy_proxy(udp, 5).await;
    let c = open_via(&r, "unused:0", ClientOptions { dead_after: Duration::from_secs(15), ping_every: Duration::from_secs(2), connect_timeout: Duration::from_secs(10), ..opts(&px) }).await;
    let out = c.exec(&[b"/bin/echo", b"lossy"], 5000, W).await.unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("lossy"));
    let d = r.dir.path();
    let bytes = data(2 << 20, 8);
    std::fs::write(d.join("src"), &bytes).unwrap();
    c.put_file(&d.join("src"), d.join("dst").to_str().unwrap().as_bytes(), 0o600, W).await.unwrap();
    assert_eq!(std::fs::read(d.join("dst")).unwrap(), bytes);
}

#[tokio::test]
async fn u3_a_stranger_gets_no_answer_whatever_it_sends() {
    let (_r, udp) = udp_rig().await;
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.connect(&udp).await.unwrap();
    // garbage, a well-formed opening packet with a junk "handshake", an opening packet of maximal size
    s.send(&[1, 2, 3]).await.unwrap();
    for body in [&b"not a noise message"[..], &[0u8; 1100][..], &[0xffu8; 96][..]] {
        let mut p = vec![1u8];
        p.extend_from_slice(&77u64.to_be_bytes());
        p.extend_from_slice(&0u64.to_be_bytes());
        p.extend_from_slice(&0u64.to_be_bytes());
        p.extend_from_slice(&64u16.to_be_bytes());
        p.extend_from_slice(&0u64.to_be_bytes());
        p.extend_from_slice(body);
        s.send(&p).await.unwrap();
    }
    let mut buf = [0u8; 2048];
    let got = tokio::time::timeout(Duration::from_millis(1500), s.recv(&mut buf)).await;
    assert!(got.is_err(), "not a single byte comes back to a stranger");
}

fn opening(conn: u64, body: &[u8]) -> Vec<u8> {
    let mut p = vec![1u8];
    p.extend_from_slice(&conn.to_be_bytes());
    p.extend_from_slice(&0u64.to_be_bytes());
    p.extend_from_slice(&0u64.to_be_bytes());
    p.extend_from_slice(&64u16.to_be_bytes());
    p.extend_from_slice(&0u64.to_be_bytes());
    p.extend_from_slice(body);
    p
}

#[tokio::test]
async fn u4_many_ids_from_one_address_hold_only_a_few_slots_and_they_are_given_back() {
    let (r, udp) = udp_rig().await;
    let before = r.cfg.conn_slots.available_permits();
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.connect(&udp).await.unwrap();
    for id in 1..=500u64 {
        s.send(&opening(id, b"junk junk junk")).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let used = before - r.cfg.conn_slots.available_permits();
    assert!(used <= yrl::server::MAX_UDP_PER_IP, "{used} slots held by one address");
    // after the handshake timeout (400 ms in the rig) the junk is gone and the slots are free again
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(r.cfg.conn_slots.available_permits(), before, "slots returned");
}

#[tokio::test]
async fn u5_forged_headers_do_not_break_a_live_connection() {
    let (r, udp) = udp_rig().await;
    let c = open_via(&r, "unused:0", ClientOptions { dead_after: Duration::from_secs(10), ping_every: Duration::from_secs(2), ..opts(&udp) }).await;
    // a stranger sprays packets with every kind/ack/window value at the server, including ones that claim to close or to confirm things never sent
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.connect(&udp).await.unwrap();
    for id in 0..2000u64 {
        for kind in [1u8, 2u8, 9u8] {
            let mut p = vec![kind];
            p.extend_from_slice(&id.to_be_bytes());
            p.extend_from_slice(&u64::MAX.to_be_bytes());
            p.extend_from_slice(&u64::MAX.to_be_bytes());
            p.extend_from_slice(&0u16.to_be_bytes());
            p.extend_from_slice(&u64::MAX.to_be_bytes());
            let _ = s.send(&p).await;
        }
    }
    let out = c.exec(&[b"/bin/echo", b"still-alive"], 5000, W).await.unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("still-alive"));
}
