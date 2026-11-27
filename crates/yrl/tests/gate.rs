//! The whole gate working together, with a mock kernel standing in for the packet filter: knock, firewall program, work port, and what each of them does NOT do.
mod common;
use common::*;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use yrl::auditlog::*;
use yrl::client::{Client, ClientOptions, Knock};
use yrl::firewall::*;
use yrl::spa::*;

const W: Duration = Duration::from_secs(20);

struct Gate {
    r: Rig,
    k: MockKernel,
    spa: SocketAddr,
    work_port: u16,
    verifier: Arc<SpaVerifier>,
}

fn lo(n: u8) -> IpAddr {
    IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, n))
}

async fn gate_with(ttl: u32, audit_for_firewall: bool, tweak: impl FnOnce(&MockKernel)) -> Gate {
    gate_on("127.0.0.1:0", ttl, audit_for_firewall, tweak).await
}

async fn gate_on(bind: &str, ttl: u32, audit_for_firewall: bool, tweak: impl FnOnce(&MockKernel)) -> Gate {
    let k = MockKernel::default();
    tweak(&k);
    let kf = k.clone();
    let r = rig_with("exec,shell,files,tunnel", |mut c| {
        c.gate_filter = Some(Arc::new(move |ip| kf.allows_addr(ip)));
        c.session_grace = Duration::from_secs(60);
        c
    })
    .await;
    let work_port: u16 = r.addr.rsplit(':').next().unwrap().parse().unwrap();
    // the firewall program, behind its own door
    let fw_key = yrl::keys::generate();
    let gate_key = r.cfg.gate.clone().unwrap().key;
    let sock = r.dir.path().join("fw.sock");
    let kk = k.clone();
    let audit = if audit_for_firewall { r.cfg.audit.firewall.clone() } else { None };
    let service = FirewallService::start(Box::new(k.clone()), Policy { work_ports: vec![work_port], allow_loopback: true, max_ttl_secs: 60, ..Default::default() }, Box::new(move || kk.now()), audit).unwrap();
    let ipc = yrl::ipc::ExecutorIpc { socket: sock.clone(), key: fw_key.clone(), gatekeeper_public: gate_key.public.clone(), expected_uid: Some(unsafe { libc::geteuid() }), expected_exe: None };
    tokio::spawn(serve_ipc(yrl::ipc::bind_socket(&sock).unwrap(), service, ipc, Arc::new(|_| {})));
    let fw = FirewallClient::new(yrl::ipc::GatekeeperIpc { socket: sock, key: gate_key, executor_public: fw_key.public.clone() });
    // the knock port
    let udp = UdpSocket::bind(bind).await.unwrap();
    let spa = udp.local_addr().unwrap();
    let verifier = Arc::new(SpaVerifier::new(r.server_key.clone(), r.server_dir(), SpaConfig::default()));
    tokio::spawn(yrl::gatenet::spa_listen(udp, verifier.clone(), fw, work_port, ttl, r.cfg.clone()));
    Gate { r, k, spa, work_port, verifier }
}

async fn gate() -> Gate {
    gate_with(30, true, |_| {}).await
}

async fn knock(g: &Gate) {
    let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    u.send_to(&build(&g.r.client, &g.r.server_pub, SERVICE_WORK, yrl::gatenet::now_secs()), g.spa).await.unwrap();
    tokio::time::sleep(Duration::from_millis(250)).await;
}

fn quick() -> ClientOptions {
    ClientOptions { connect_timeout: Duration::from_millis(1200), ..fast_opts() }
}

async fn try_connect(g: &Gate, key: &yrl::keys::KeyPair) -> Result<Client, String> {
    Client::connect_opts(&g.r.addr, key, &g.r.server_pub, ClientOptions { executor_public: Some(g.r.exec_pub.clone()), ..quick() }).await.map_err(|e| e.to_string())
}

fn read_j(dir: &std::path::Path, j: Journal) -> Vec<Record> {
    let b = std::fs::read(dir.join("audit").join(format!("{}.log", j.file()))).unwrap_or_default();
    let (mut v, mut at) = (vec![], 0usize);
    while at + 4 <= b.len() {
        let n = u32::from_be_bytes(b[at..at + 4].try_into().unwrap()) as usize;
        if b.len() < at + 4 + n {
            break;
        }
        if let Ok(r) = Record::parse(&b[at + 4..at + 4 + n - 64]) {
            v.push(r);
        }
        at += 4 + n;
    }
    v
}

async fn wait_j(dir: &std::path::Path, j: Journal, want: impl Fn(&[Record]) -> bool) -> Vec<Record> {
    for _ in 0..100 {
        let r = read_j(dir, j);
        if want(&r) {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("not seen; the {} journal: {:?}", j.file(), read_j(dir, j).iter().map(|r| (r.source.name(), r.ev.op.clone(), String::from_utf8_lossy(&r.ev.target).into_owned())).collect::<Vec<_>>());
}

#[tokio::test]
async fn g1_without_a_knock_the_work_port_is_a_wall_and_with_one_it_is_a_door() {
    let g = gate().await;
    assert!(try_connect(&g, &g.r.client).await.is_err(), "no knock: dropped before any handshake, even for the right key");
    knock(&g).await;
    let c = try_connect(&g, &g.r.client).await.expect("after the knock the handshake goes through");
    c.login("anna", PW, T).await.unwrap();
    assert_eq!(c.exec(&[b"echo", b"through the gate"], 5000, W).await.unwrap().stdout, b"through the gate\n");
}

#[tokio::test]
async fn g2_a_knock_is_not_trust_and_not_a_session() {
    let g = gate().await;
    knock(&g).await;
    assert!(g.k.allows(lo(1), g.work_port));
    assert_eq!(g.r.sessions.len(), 0, "the knock made no session");
    // the door is open for the address, but a key nobody knows still gets silence, and a known key still needs its password
    let stranger = yrl::keys::generate();
    assert!(try_connect(&g, &stranger).await.is_err(), "an open firewall does not replace the key check");
    let c = try_connect(&g, &g.r.client).await.unwrap();
    assert!(c.login("anna", b"wrong password", T).await.is_err(), "nor the password");
    assert_eq!(g.r.sessions.len(), 0);
}

#[tokio::test]
async fn g3_only_the_address_the_knock_came_from_is_let_in() {
    let g = gate().await;
    knock(&g).await; // from 127.0.0.1
    assert!(g.k.allows_addr(lo(1)) && !g.k.allows_addr(lo(2)));
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind("127.0.0.2:0".parse().unwrap()).unwrap();
    let mut s = sock.connect(g.r.addr.parse().unwrap()).await.unwrap();
    let res = yrl::session::client_handshake_context(&mut s, &g.r.client, &g.r.server_pub, yrl::session::REKEY_EVERY, yrl::crypto_profile::Context::Gatekeeper, yrl::crypto_profile::Policy::default()).await;
    assert!(res.is_err(), "another address on the same machine, with the right key, is still outside: a roaming device must knock again from where it is now");
}

#[tokio::test]
async fn g4_a_permission_ends_but_a_session_that_is_running_does_not() {
    let g = gate_with(5, true, |_| {}).await;
    let c = Client::connect_opts(&g.r.addr, &g.r.client, &g.r.server_pub, ClientOptions {
        executor_public: Some(g.r.exec_pub.clone()),
        knock: Some(Knock { udp: g.spa.to_string(), settle: Duration::from_millis(150) }),
        ..quick()
    }).await.unwrap();
    c.login("anna", PW, T).await.unwrap();
    g.k.advance(6); // the kernel's timeout
    assert!(!g.k.allows_addr(lo(1)));
    assert!(try_connect(&g, &g.r.client).await.is_err(), "new connections are dropped again");
    let result = c.exec(&[b"echo", b"still here"], 5000, W).await.unwrap_or_else(|e| panic!("established session failed: {e}; diagnostics: {:?}", c.connection_diagnostics()));
    assert_eq!(result.stdout, b"still here\n", "the established session lives on (the real ruleset accepts established connections)");
}

#[tokio::test]
async fn g5_the_knock_port_never_answers_anything() {
    let g = gate().await;
    let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut forged = build(&g.r.client, &g.r.server_pub, SERVICE_WORK, yrl::gatenet::now_secs());
    forged[90] ^= 1;
    let stranger = yrl::keys::generate();
    let for_others = build(&g.r.client, &stranger.public, SERVICE_WORK, yrl::gatenet::now_secs());
    let valid = build(&g.r.client, &g.r.server_pub, SERVICE_WORK, yrl::gatenet::now_secs());
    for dgram in [forged, for_others, vec![0u8; 94], vec![1, 2, 3], vec![], valid.clone(), valid /* a replay */] {
        u.send_to(&dgram, g.spa).await.unwrap();
        let mut buf = [0u8; 2048];
        let got = tokio::time::timeout(Duration::from_millis(250), u.recv_from(&mut buf)).await;
        assert!(got.is_err(), "not a byte comes back, for {} bytes sent", dgram.len());
    }
}

#[tokio::test]
async fn g6_the_client_knocks_by_itself_before_connecting_and_before_every_reconnection() {
    let g = gate().await;
    let ch = common::chaos::Chaos::start(&g.r.addr).await;
    let mut o = quick();
    o.connect_timeout = Duration::from_secs(5);
    o.knock = Some(Knock { udp: g.spa.to_string(), settle: Duration::from_millis(150) });
    let c = Client::connect_opts(&ch.addr, &g.r.client, &g.r.server_pub, ClientOptions { executor_public: Some(g.r.exec_pub.clone()), ..o }).await.expect("the knock is sent before the connection");
    c.login("anna", PW, T).await.unwrap();
    let mut p = c.pty_open(24, 80, "xterm").await.unwrap();
    p.write(b"echo pid-$$-a$((1+1))\n").await.unwrap();
    let out = p.read_until("-a2\r\n", W).await.unwrap();
    let adds_before = g.k.add_count();
    g.k.advance(100); // the permission ran out
    ch.cut(); // and the connection is gone: the way back needs a new knock
    p.write(b"echo again-$$-b$((1+1))\n").await.unwrap();
    let out2 = p.read_until("-b2\r\n", Duration::from_secs(30)).await.unwrap();
    assert!(g.k.add_count() > adds_before, "a new knock was sent for the reconnection");
    let pid = |s: &str, tag: &str| s.lines().map(|l| l.trim_end_matches('\r').rsplit('\r').next().unwrap_or("").trim().to_string()).find(|l| l.contains(tag) && !l.contains('$')).unwrap();
    let a = pid(&out, "pid-").replace("pid-", "").replace("-a2", "");
    let b = pid(&out2, "again-").replace("again-", "").replace("-b2", "");
    assert_eq!(a, b, "the same shell, over a connection the gate had to be knocked open again for");
}

#[tokio::test]
async fn g7_when_the_firewall_cannot_open_nothing_is_open_and_it_is_written_down_locally() {
    let g = gate().await;
    g.k.set_failing(true); // the kernel breaks after the firewall program has started
    knock(&g).await;
    assert!(!g.k.allows_addr(lo(1)));
    assert!(try_connect(&g, &g.r.client).await.is_err(), "no fall-back to 'let it through'");
    let sec = wait_j(&g.r.server_dir(), Journal::Security, |r| r.iter().any(|x| x.ev.op == "spa_error")).await;
    assert!(sec.iter().any(|x| x.source == Source::Gatekeeper && x.ev.op == "spa_error" && x.ev.target == b"firewall"));
    // and when the kernel works again the next knock is enough
    g.k.set_failing(false);
    knock(&g).await;
    assert!(try_connect(&g, &g.r.client).await.is_ok());
}

#[tokio::test]
async fn g8_the_reasons_go_to_the_local_security_journal_and_only_there() {
    let g = gate().await;
    let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let now = yrl::gatenet::now_secs();
    let stranger = yrl::keys::generate();
    let valid = build(&g.r.client, &g.r.server_pub, SERVICE_WORK, now);
    u.send_to(&build(&stranger, &g.r.server_pub, SERVICE_WORK, now), g.spa).await.unwrap();
    u.send_to(&build(&g.r.client, &g.r.server_pub, SERVICE_WORK, now - 400), g.spa).await.unwrap();
    u.send_to(&valid, g.spa).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    u.send_to(&valid, g.spa).await.unwrap(); // a replay
    let mut forged = build(&g.r.client, &g.r.server_pub, SERVICE_WORK, now);
    forged[90] ^= 1;
    u.send_to(&forged, g.spa).await.unwrap();
    u.send_to(&vec![7u8; 33], g.spa).await.unwrap();
    let sec = wait_j(&g.r.server_dir(), Journal::Security, |r| ["unknown-client", "clock-skew", "replay", "bad-signature", "size"].iter().all(|why| r.iter().any(|x| x.ev.op == "spa_rejected" && x.ev.target == why.as_bytes())) && r.iter().any(|x| x.ev.op == "spa_ok") && r.iter().any(|x| x.ev.op == "firewall_open")).await;
    assert!(sec.iter().filter(|x| x.ev.op == "firewall_open").all(|x| x.source == Source::Firewall), "the firewall program reports its own work");
    assert!(sec.iter().filter(|x| x.ev.op.starts_with("spa_")).all(|x| x.source == Source::Gatekeeper));
    assert!(sec.iter().filter(|x| x.ev.op == "spa_ok").all(|x| x.ev.result == RESULT_OK), "a good knock is recorded as good: {:?}", sec.iter().map(|x| (x.source.name(), x.ev.op.clone(), x.ev.result, x.ev.target.clone())).collect::<Vec<_>>());
    let ord = read_j(&g.r.server_dir(), Journal::Ordinary);
    assert!(!ord.iter().any(|x| x.ev.op.starts_with("spa_") || x.ev.op.starts_with("firewall")), "none of it is in the ordinary journal");
    // a flood of the same mistake is written down once, not a thousand times
    for _ in 0..20 {
        u.send_to(&vec![7u8; 33], g.spa).await.unwrap();
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let n = read_j(&g.r.server_dir(), Journal::Security).iter().filter(|x| x.ev.op == "spa_rejected" && x.ev.target == b"size").count();
    assert_eq!(n, 1, "one record per reason and source in a while");
    // the sender is never told: nothing on the wire (checked in g5), and the mock kernel holds only the one valid knock
    assert_eq!(g.k.live_entries(), 1);
    let _ = &g.verifier;
}

#[tokio::test]
async fn g9_an_opening_that_cannot_be_recorded_does_not_happen() {
    let g = gate_with(30, false, |_| {}).await;
    let k = MockKernel::default();
    let dead = yrl::audit::AuditClient::new(g.r.dir.path().join("nobody.sock"), yrl::keys::generate(), vec![0u8; 32]);
    let kk = k.clone();
    let f = FirewallService::start(Box::new(k.clone()), Policy { work_ports: vec![2222], allow_loopback: true, ..Default::default() }, Box::new(move || kk.now()), Some(dead)).unwrap();
    let res = f.handle(Request::Open { addr: lo(1), port: 2222, ttl_secs: 30, session: [0; 16] }).await;
    assert_eq!(res, Err(Refusal::NotRecorded));
    assert!(!k.allows(lo(1), 2222) && k.add_count() == 0, "the kernel was not even asked");
}

#[tokio::test]
async fn g10_a_knock_that_arrives_on_a_dual_stack_socket_opens_the_plain_address() {
    // a socket on [::] sees an IPv4 sender as ::ffff:a.b.c.d; the permission must be for 127.0.0.1, which is what the TCP side will see
    let g = gate_on("[::]:0", 30, true, |_| {}).await;
    let u = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    u.send_to(&build(&g.r.client, &g.r.server_pub, SERVICE_WORK, yrl::gatenet::now_secs()), SocketAddr::new(lo(1), g.spa.port())).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(g.k.allows_addr(lo(1)), "the plain IPv4 address was let in");
    assert!(try_connect(&g, &g.r.client).await.is_ok());
}
