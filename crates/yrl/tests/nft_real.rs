//! The firewall program against the REAL kernel packet filter (nftables), inside a private network namespace made with `unshare -rn`
//! (no root needed; nothing outside the test is touched). Skipped, loudly, if `nft` or `unshare` are not usable here.
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::time::Duration;
use yrl::firewall::*;

const PORT: u16 = 24222;
const OTHER: u16 = 24223;

fn path_with_sbin() -> String {
    format!("{}:/usr/sbin:/sbin", std::env::var("PATH").unwrap_or_default())
}

fn usable() -> bool {
    Command::new("unshare").args(["-rn", "sh", "-c", "nft add table inet probe && nft delete table inet probe"]).env("PATH", path_with_sbin()).output().map(|o| o.status.success()).unwrap_or(false)
}

#[test]
fn n0_outer_runs_the_real_checks_in_a_private_network() {
    if !usable() {
        eprintln!("SKIPPED: no usable nft/unshare here (the mock-kernel tests still cover the logic)");
        return;
    }
    let me = std::env::current_exe().unwrap();
    let out = Command::new("unshare").args(["-rn", "sh", "-c"]).arg(format!("ip link set lo up && {} --exact n1_inner --ignored --nocapture --test-threads=1", me.display())).env("PATH", path_with_sbin()).env("YRL_NETNS", "1").output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && text.contains("1 passed"), "the checks inside the private network failed:\n{text}");
}

fn lo() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

fn can_connect(port: u16) -> bool {
    TcpStream::connect_timeout(&SocketAddr::new(lo(), port), Duration::from_millis(400)).is_ok()
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

fn echo_server(port: u16) {
    let l = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { continue };
            std::thread::spawn(move || {
                let mut b = [0u8; 64];
                while let Ok(n) = s.read(&mut b) {
                    if n == 0 || s.write_all(&b[..n]).is_err() {
                        break;
                    }
                }
            });
        }
    });
}

fn service() -> std::sync::Arc<FirewallService> {
    let mut be = NftBackend { runner: RealRunner };
    be.install(&[PORT]).expect("the permanent ruleset is accepted by the real nft");
    FirewallService::start(Box::new(be), Policy { work_ports: vec![PORT], allow_loopback: true, max_ttl_secs: 60, ..Default::default() }, Box::new(now), None).unwrap()
}

fn open(ttl: u32) -> Request {
    Request::Open { addr: lo(), port: PORT, ttl_secs: ttl, session: [3; 16] }
}

/// a UDP echo on the port, and a probe that says whether a datagram gets its echo back
fn udp_echo_server(port: u16) {
    let s = std::net::UdpSocket::bind(SocketAddr::new(lo(), port)).unwrap();
    std::thread::spawn(move || {
        let mut b = [0u8; 64];
        while let Ok((n, from)) = s.recv_from(&mut b) {
            let _ = s.send_to(&b[..n], from);
        }
    });
}

fn udp_answers(port: u16) -> bool {
    let c = std::net::UdpSocket::bind(SocketAddr::new(lo(), 0)).unwrap();
    c.set_read_timeout(Some(Duration::from_millis(400))).unwrap();
    let _ = c.send_to(b"ping", SocketAddr::new(lo(), port));
    let mut b = [0u8; 8];
    c.recv(&mut b).is_ok()
}

#[tokio::test]
#[ignore = "runs only inside the private network made by n0_outer"]
async fn n1_inner() {
    assert_eq!(std::env::var("YRL_NETNS").as_deref(), Ok("1"));
    echo_server(PORT);
    echo_server(OTHER);
    let f = service();
    // the wall
    udp_echo_server(PORT);
    assert!(!can_connect(PORT), "without a permission the work port is dropped (even from the machine itself)");
    assert!(!udp_answers(PORT), "the UDP data port is behind the same wall");
    assert!(can_connect(OTHER), "a port that is not a work port is not touched");
    // the door, for a while
    assert_eq!(f.handle(open(3)).await, Ok(None));
    assert!(can_connect(PORT), "with a permission the connection goes through");
    assert!(udp_answers(PORT), "and so do the datagrams");
    assert_eq!(f.handle(Request::Query { addr: lo(), port: PORT }).await, Ok(Some(true)), "the kernel itself says it holds the entry");
    let mut live = TcpStream::connect(SocketAddr::new(lo(), PORT)).unwrap();
    live.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    // the kernel removes it by itself: nobody calls Close
    std::thread::sleep(Duration::from_millis(4500));
    assert!(!can_connect(PORT), "after the timeout new connections are dropped again");
    assert!(!udp_answers(PORT), "and new datagram flows too");
    live.write_all(b"still alive").unwrap();
    let mut b = [0u8; 16];
    let n = live.read(&mut b).unwrap();
    assert_eq!(&b[..n], b"still alive", "a connection that was already running goes on (ct state established)");
    // close at once
    assert_eq!(f.handle(open(30)).await, Ok(None));
    assert!(can_connect(PORT));
    assert_eq!(f.handle(Request::Close { addr: lo(), port: PORT }).await, Ok(None));
    assert!(!can_connect(PORT), "an explicit close takes effect immediately");
    assert_eq!(f.handle(Request::Query { addr: lo(), port: PORT }).await, Ok(Some(false)));
    // a restart forgets old permissions
    assert_eq!(f.handle(open(30)).await, Ok(None));
    assert!(can_connect(PORT));
    let f2 = service();
    assert!(!can_connect(PORT), "a new firewall program starts with nothing allowed");
    // a permission for another port is not one for this port
    assert_eq!(f2.handle(Request::Open { addr: lo(), port: OTHER, ttl_secs: 5, session: [0; 16] }).await, Err(Refusal::PortNotAllowed));
    assert!(!can_connect(PORT));
}
