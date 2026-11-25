//! The network gate: one silent datagram, a firewall program with a tiny typed language, a mock kernel that forgets by itself.
mod common;
use common::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use yrl::firewall::*;
use yrl::spa::*;

const W: Duration = Duration::from_secs(20);
const T0: u64 = 1_760_000_000;
fn ip(a: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, a))
}

struct World {
    dir: tempfile::TempDir,
    server: yrl::keys::KeyPair,
    client: yrl::keys::KeyPair,
    v: SpaVerifier,
}

fn world(cfg: SpaConfig) -> World {
    let dir = tempfile::tempdir().unwrap();
    let (server, client) = (yrl::keys::generate(), yrl::keys::generate());
    yrl::keys::authorize(&dir.path().join("authorized_keys"), &hex::encode(&client.public), "laptop", "exec").unwrap();
    let v = SpaVerifier::new(server.clone(), dir.path().to_path_buf(), cfg);
    World { dir, server, client, v }
}

fn pkt(w: &World, now: u64) -> Vec<u8> {
    build(&w.client, &w.server.public, SERVICE_WORK, now)
}

// ---------------------------------------------------------------- the packet

#[test]
fn s1_a_good_packet_is_accepted_and_every_part_of_it_matters() {
    let w = world(SpaConfig::default());
    let p = pkt(&w, T0);
    assert_eq!(p.len(), LEN);
    let a = w.v.verify(&p, ip(1), T0).unwrap();
    assert_eq!((a.client_public.clone(), a.vip, a.service), (w.client.public.clone(), virtual_ipv6(&w.client.public), SERVICE_WORK));
    // each region altered, one at a time, on fresh nonces
    let regions = [("magic", 0usize, Reject::Format), ("version", 4, Reject::Format), ("client id", 5, Reject::UnknownClient), ("server id", 13, Reject::WrongServer), ("service", 21, Reject::BadMac), ("timestamp", 29, Reject::BadMac), ("nonce", 31, Reject::BadMac), ("virtual address", 50, Reject::BadMac), ("mac", 80, Reject::BadMac)];
    for (name, at, want) in regions {
        let mut q = pkt(&w, T0);
        q[at] ^= 1;
        assert_eq!(w.v.verify(&q, ip(2), T0).unwrap_err(), want, "{name}");
    }
    // a device that writes someone else's virtual address into a packet it signs itself
    let other = yrl::keys::generate();
    let lying = build_raw(&w.client, &w.server.public, SERVICE_WORK, T0, [9; 16], virtual_ipv6(&other.public));
    assert_eq!(w.v.verify(&lying, ip(3), T0).unwrap_err(), Reject::VipMismatch, "the virtual address must be the one that belongs to the key");
    assert_ne!(virtual_ipv6(&w.client.public), virtual_ipv6(&other.public));
    assert_eq!(virtual_ipv6(&w.client.public)[0], 0xfd);
}

#[test]
fn s2_what_costs_nothing_is_checked_before_what_costs_something() {
    let w = world(SpaConfig::default());
    let before = |w: &World| w.v.mac_checks.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(w.v.verify(&[0u8; 10], ip(1), T0).unwrap_err(), Reject::Size);
    assert_eq!(w.v.verify(&vec![0u8; LEN], ip(1), T0).unwrap_err(), Reject::Format);
    let stranger = yrl::keys::generate();
    assert_eq!(w.v.verify(&build(&stranger, &w.server.public, SERVICE_WORK, T0), ip(1), T0).unwrap_err(), Reject::UnknownClient);
    assert_eq!(w.v.verify(&build(&w.client, &yrl::keys::generate().public, SERVICE_WORK, T0), ip(1), T0).unwrap_err(), Reject::WrongServer);
    assert_eq!(w.v.verify(&pkt(&w, T0 - 500), ip(1), T0).unwrap_err(), Reject::ClockSkew);
    let ok = pkt(&w, T0);
    w.v.verify(&ok, ip(1), T0).unwrap();
    assert_eq!(before(&w), 1, "so far the expensive check ran once: for the one packet that got past everything cheap");
    assert_eq!(w.v.verify(&ok, ip(1), T0).unwrap_err(), Reject::Replay);
    assert_eq!(before(&w), 1, "a replay is found before the check, not after");
    let mut forged = pkt(&w, T0);
    forged[90] ^= 1;
    assert_eq!(w.v.verify(&forged, ip(4), T0).unwrap_err(), Reject::BadMac);
    assert_eq!(before(&w), 2, "and a forged one is the only kind that costs it");
}

#[test]
fn s3_the_time_window_is_exact_in_both_directions() {
    let w = world(SpaConfig::default());
    assert!(w.v.verify(&pkt(&w, T0 - 30), ip(1), T0).is_ok());
    assert!(w.v.verify(&pkt(&w, T0 + 30), ip(2), T0).is_ok());
    assert_eq!(w.v.verify(&pkt(&w, T0 - 31), ip(3), T0).unwrap_err(), Reject::ClockSkew, "a packet too old");
    assert_eq!(w.v.verify(&pkt(&w, T0 + 31), ip(4), T0).unwrap_err(), Reject::ClockSkew, "a packet from the future");
    assert_eq!(w.v.verify(&pkt(&w, 0), ip(5), T0).unwrap_err(), Reject::ClockSkew);
    assert_eq!(w.v.verify(&pkt(&w, u64::MAX), ip(6), T0).unwrap_err(), Reject::ClockSkew, "no overflow");
}

#[test]
fn s4_a_replay_never_works_and_the_memory_of_nonces_is_bounded() {
    let w = world(SpaConfig { max_replay_entries: 3, per_source_per_sec: 100, ..Default::default() });
    let p = pkt(&w, T0);
    w.v.verify(&p, ip(1), T0).unwrap();
    for later in [0u64, 1, 10, 29] {
        assert_eq!(w.v.verify(&p, ip(1), T0 + later).unwrap_err(), Reject::Replay, "{later} seconds later, still inside the time window");
    }
    assert_eq!(w.v.verify(&p, ip(1), T0 + 31).unwrap_err(), Reject::ClockSkew, "and when the window is over it is simply too old");
    // the nonce is remembered longer than the window
    w.v.verify(&pkt(&w, T0), ip(1), T0).unwrap();
    w.v.verify(&pkt(&w, T0), ip(1), T0).unwrap();
    assert_eq!(w.v.verify(&pkt(&w, T0), ip(1), T0).unwrap_err(), Reject::CacheFull, "full of live entries: refuse rather than forget");
    // invalid packets did not fill it
    let w2 = world(SpaConfig { max_replay_entries: 3, per_source_per_sec: 1000, ..Default::default() });
    for _ in 0..50 {
        let mut bad = pkt(&w2, T0);
        bad[90] ^= 1;
        let _ = w2.v.verify(&bad, ip(1), T0);
    }
    for _ in 0..3 {
        w2.v.verify(&pkt(&w2, T0), ip(1), T0).unwrap();
    }
    // old entries free their place
    assert!(w2.v.verify(&pkt(&w2, T0 + 100), ip(1), T0 + 100).is_ok(), "after the memory time the entries are gone");
}

#[test]
fn s5_flooding_is_cut_off_early_and_cannot_be_used_to_lock_a_real_device_out() {
    let w = world(SpaConfig { per_source_per_sec: 3, global_per_sec: 50, ..Default::default() });
    let mut results = vec![];
    for _ in 0..6 {
        results.push(w.v.verify(&pkt(&w, T0), ip(7), T0));
    }
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 3);
    assert_eq!(results.iter().filter(|r| matches!(r, Err(Reject::RateLimited))).count(), 3);
    assert!(w.v.verify(&pkt(&w, T0), ip(8), T0).is_ok(), "another source is not affected");
    assert!(w.v.verify(&pkt(&w, T0 + 1), ip(7), T0 + 1).is_ok(), "and the next second starts fresh");
    // somebody who does not know the device id cannot use up that device's turns by faking its address
    let w2 = world(SpaConfig { per_source_per_sec: 3, ..Default::default() });
    let stranger = yrl::keys::generate();
    for _ in 0..50 {
        let _ = w2.v.verify(&build(&stranger, &w2.server.public, SERVICE_WORK, T0), ip(9), T0);
    }
    assert!(w2.v.verify(&pkt(&w2, T0), ip(9), T0).is_ok(), "the real device, from the address that was flooded in its name, still gets in");
    // the whole gate has a limit too
    let w3 = world(SpaConfig { global_per_sec: 5, per_source_per_sec: 100, ..Default::default() });
    let n = (0..20).filter(|i| w3.v.verify(&pkt(&w3, T0), IpAddr::V4(Ipv4Addr::new(10, 1, 0, *i)), T0).is_ok()).count();
    assert_eq!(n, 5);
}

#[test]
fn s6_a_service_that_is_off_and_a_device_that_was_removed_are_refused() {
    let w = world(SpaConfig { enabled_services: vec![], ..Default::default() });
    assert_eq!(w.v.verify(&pkt(&w, T0), ip(1), T0).unwrap_err(), Reject::ServiceDisabled);
    let w = world(SpaConfig::default());
    assert!(w.v.verify(&pkt(&w, T0), ip(1), T0).is_ok());
    std::fs::write(w.dir.path().join("authorized_keys"), "# nobody\n").unwrap();
    assert!(w.v.verify(&pkt(&w, T0), ip(2), T0).is_ok(), "(the list is read at most once a second: in the same second the old copy is used)");
    assert_eq!(w.v.verify(&pkt(&w, T0 + 1), ip(3), T0 + 1).unwrap_err(), Reject::UnknownClient, "a device that was removed stops being let in within a second");
    for r in [Reject::Size, Reject::Format, Reject::WrongServer, Reject::RateLimited, Reject::UnknownClient, Reject::ClockSkew, Reject::Replay, Reject::BadMac, Reject::VipMismatch, Reject::ServiceDisabled, Reject::CacheFull] {
        assert!(!r.name().is_empty() && !r.name().contains(' '));
    }
}

#[test]
fn s7_garbage_never_panics() {
    let w = world(SpaConfig { per_source_per_sec: u32::MAX, global_per_sec: u32::MAX, ..Default::default() });
    let mut x = 99u64;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    for i in 0..20_000u32 {
        let n = if i % 3 == 0 { LEN } else { (rnd() % 200) as usize };
        let mut b: Vec<u8> = (0..n).map(|_| rnd() as u8).collect();
        if i % 2 == 0 && b.len() >= 5 {
            b[..4].copy_from_slice(MAGIC);
            b[4] = VERSION;
        }
        let _ = w.v.verify(&b, ip((i % 250) as u8), T0);
    }
}

// ---------------------------------------------------------------- the firewall program

fn svc(kernel: &MockKernel, ports: &[u16]) -> Arc<FirewallService> {
    let k = kernel.clone();
    FirewallService::start(Box::new(kernel.clone()), Policy { work_ports: ports.to_vec(), allow_loopback: true, max_ttl_secs: 60, max_entries: 5, per_addr_max: 2, ..Default::default() }, Box::new(move || k.now()), None).unwrap()
}

fn open(addr: IpAddr, port: u16, ttl: u32) -> Request {
    Request::Open { addr, port, ttl_secs: ttl, session: [1; 16] }
}

#[tokio::test]
async fn s8_the_firewall_does_only_what_its_language_allows_and_its_policy_permits() {
    let k = MockKernel::default();
    let f = svc(&k, &[2222]);
    assert_eq!(f.handle(open(ip(1), 2222, 30)).await, Ok(None));
    assert!(k.allows(ip(1), 2222) && !k.allows(ip(1), 22) && !k.allows(ip(2), 2222));
    assert_eq!(f.handle(Request::Query { addr: ip(1), port: 2222 }).await, Ok(Some(true)));
    assert_eq!(f.handle(Request::Query { addr: ip(2), port: 2222 }).await, Ok(Some(false)));
    // refusals, each for its own reason, and each leaves nothing behind
    let live = k.live_entries();
    assert_eq!(f.handle(open(ip(3), 22, 30)).await, Err(Refusal::PortNotAllowed), "not a port of the policy");
    assert_eq!(f.handle(open(ip(3), 2222, 0)).await, Err(Refusal::TtlOutOfRange));
    assert_eq!(f.handle(open(ip(3), 2222, 61)).await, Err(Refusal::TtlOutOfRange), "not for ever, not even for longer than the policy");
    assert_eq!(f.handle(open(ip(3), 2222, u32::MAX)).await, Err(Refusal::TtlOutOfRange));
    for bad in [IpAddr::V4(Ipv4Addr::UNSPECIFIED), IpAddr::V4(Ipv4Addr::BROADCAST), IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), IpAddr::V6(Ipv6Addr::UNSPECIFIED), IpAddr::V6("ff02::1".parse().unwrap())] {
        assert_eq!(f.handle(open(bad, 2222, 30)).await, Err(Refusal::BadAddress), "{bad}");
    }
    assert_eq!(k.live_entries(), live, "nothing was opened by any of these");
    let strict = FirewallService::start(Box::new(MockKernel::default()), Policy { work_ports: vec![2222], ..Default::default() }, Box::new(|| 0), None).unwrap();
    assert_eq!(strict.handle(open(IpAddr::V4(Ipv4Addr::LOCALHOST), 2222, 30)).await, Err(Refusal::BadAddress), "loopback only where the policy says so");
    assert_eq!(f.handle(open("2001:db8::1".parse().unwrap(), 2222, 30)).await, Ok(None), "an IPv6 source is fine");
    // limits: 2 per address, 5 in all
    assert_eq!(f.handle(open(ip(1), 2222, 30)).await, Ok(None), "the same entry again just renews it");
    f.handle(open(ip(5), 2222, 30)).await.unwrap();
    f.handle(open(ip(6), 2222, 30)).await.unwrap();
    f.handle(open(ip(8), 2222, 30)).await.unwrap();
    assert_eq!(f.handle(open(ip(7), 2222, 30)).await, Err(Refusal::TooMany), "the table is full (5 entries)");
    assert_eq!(f.handle(open(ip(8), 2222, 30)).await, Ok(None), "but an entry that exists can still be renewed");
    // closing
    assert_eq!(f.handle(Request::Close { addr: ip(1), port: 2222 }).await, Ok(None));
    assert!(!k.allows(ip(1), 2222));
    assert_eq!(f.handle(Request::Close { addr: ip(1), port: 2222 }).await, Ok(None), "closing what is closed is fine");
    assert_eq!(f.handle(open(ip(7), 2222, 30)).await, Ok(None), "and room is made");
}

#[tokio::test]
async fn s9_permissions_end_by_themselves_and_a_restart_forgets_them() {
    let k = MockKernel::default();
    let f = svc(&k, &[2222]);
    f.handle(open(ip(1), 2222, 30)).await.unwrap();
    k.advance(29);
    assert!(k.allows(ip(1), 2222));
    k.advance(2);
    assert!(!k.allows(ip(1), 2222), "the kernel's own timeout ended it, with the firewall program doing nothing");
    // the program dies and a new one starts: everything it finds is wiped
    f.handle(open(ip(2), 2222, 60)).await.unwrap();
    assert!(k.allows(ip(2), 2222));
    let k2 = k.clone();
    let _f2 = FirewallService::start(Box::new(k.clone()), Policy { work_ports: vec![2222], allow_loopback: true, ..Default::default() }, Box::new(move || k2.now()), None).unwrap();
    assert!(!k.allows(ip(2), 2222), "a permission left from before is not trusted");
    // a session's permissions are closed together
    let f = svc(&k, &[2222, 2223]);
    f.handle(Request::Open { addr: ip(1), port: 2222, ttl_secs: 30, session: [7; 16] }).await.unwrap();
    f.handle(Request::Open { addr: ip(1), port: 2223, ttl_secs: 30, session: [7; 16] }).await.unwrap();
    f.handle(Request::Open { addr: ip(2), port: 2222, ttl_secs: 30, session: [8; 16] }).await.unwrap();
    f.handle(Request::CloseSession { session: [7; 16] }).await.unwrap();
    assert!(!k.allows(ip(1), 2222) && !k.allows(ip(1), 2223) && k.allows(ip(2), 2222), "only that session's");
}

#[tokio::test]
async fn s10_when_the_firewall_cannot_be_sure_nothing_is_opened() {
    let k = MockKernel::default();
    let f = svc(&k, &[2222]);
    k.set_failing(true);
    assert_eq!(f.handle(open(ip(1), 2222, 30)).await, Err(Refusal::BackendFailed));
    assert_eq!(f.handle(Request::Query { addr: ip(1), port: 2222 }).await, Err(Refusal::NotSure), "'I do not know' is neither yes nor no");
    assert_eq!(f.handle(Request::Close { addr: ip(1), port: 2222 }).await, Err(Refusal::BackendFailed));
    k.set_failing(false);
    assert!(!k.allows(ip(1), 2222), "and the failed attempt left no trace that a later success could be mistaken for");
    assert_eq!(f.handle(open(ip(1), 2222, 30)).await, Ok(None));
    assert!(FirewallService::start({ let k = MockKernel::default(); k.set_failing(true); Box::new(k) }, Policy::default(), Box::new(|| 0), None).is_err(), "a firewall that cannot even be cleared at the start does not start");
}

#[test]
fn s11_the_language_is_exact_and_has_no_word_for_a_rule() {
    let reqs = [open(ip(1), 2222, 30), open("2001:db8::1".parse().unwrap(), 65535, 1), Request::Close { addr: ip(2), port: 1 }, Request::Query { addr: ip(3), port: 2 }, Request::CloseSession { session: [5; 16] }];
    for r in &reqs {
        assert_eq!(&Request::decode(&r.encode()).unwrap(), r);
    }
    for r in &reqs {
        let f = r.encode();
        let mut longer = f.clone();
        longer.payload.push(0);
        assert!(Request::decode(&longer).is_err(), "trailing byte");
        let mut cut = f.clone();
        cut.payload.pop();
        assert!(Request::decode(&cut).is_err(), "cut short");
    }
    // there is no frame kind for 'run nft', 'a rule', 'a port for ever': everything else is nonsense to it
    for kind in (0u8..=255).filter(|k| ![FW_OPEN, FW_CLOSE, FW_QUERY, FW_CLOSE_SESSION].contains(k)) {
        assert!(Request::decode(&yrl::wire::Frame::new(kind, 0, vec![4, 1, 2, 3, 4, 0, 1])).is_err(), "kind {kind}");
    }
    assert!(Request::decode(&yrl::wire::Frame::new(FW_OPEN, 0, vec![5, 1, 2, 3, 4])).is_err(), "an address kind that does not exist");
    let mut x = 5u64;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    for _ in 0..30_000 {
        let v: Vec<u8> = (0..(rnd() % 50) as usize).map(|_| rnd() as u8).collect();
        for kind in [FW_OPEN, FW_CLOSE, FW_QUERY, FW_CLOSE_SESSION] {
            let _ = Request::decode(&yrl::wire::Frame::new(kind, 0, v.clone()));
        }
    }
}

struct Recorder(Arc<std::sync::Mutex<Vec<(Vec<String>, Option<String>)>>>);
impl Runner for Recorder {
    fn run(&mut self, args: &[String], stdin: Option<&str>) -> anyhow::Result<String> {
        self.0.lock().unwrap().push((args.to_vec(), stdin.map(String::from)));
        Ok(String::from("elements = { 10.0.0.1 . 2222 timeout 30s expires 29s }"))
    }
}

#[test]
fn s12_the_real_backend_builds_its_commands_from_typed_values_only() {
    let log = Arc::new(std::sync::Mutex::new(vec![]));
    let mut b = NftBackend { runner: Recorder(log.clone()) };
    b.add(ip(1), 2222, 30).unwrap();
    b.add("2001:db8::7".parse().unwrap(), 2222, 5).unwrap();
    b.remove(ip(1), 2222).unwrap();
    assert!(b.contains(ip(1), 2222).unwrap() && !b.contains(ip(9), 2222).unwrap());
    b.flush().unwrap();
    let l = log.lock().unwrap().clone();
    assert_eq!(l[0].0, vec!["add", "element", "inet", "yrl", "allowed4", "{ 10.0.0.1 . 2222 timeout 30s }"]);
    assert_eq!(l[1].0, vec!["add", "element", "inet", "yrl", "allowed6", "{ 2001:db8::7 . 2222 timeout 5s }"]);
    assert_eq!(l[2].0, vec!["delete", "element", "inet", "yrl", "allowed4", "{ 10.0.0.1 . 2222 }"]);
    assert_eq!(l[3].0, vec!["list", "set", "inet", "yrl", "allowed4"]);
    assert_eq!(l[5].0, vec!["flush", "set", "inet", "yrl", "allowed4"]);
    assert_eq!(l[6].0, vec!["flush", "set", "inet", "yrl", "allowed6"]);
    assert!(l.iter().all(|(_, stdin)| stdin.is_none()));
    // the permanent rules: established connections live on, new ones only from the set, the rest of the work port is dropped
    let rules = base_ruleset(&[2222, 2223]);
    let est = rules.find("ct state established,related tcp dport { 2222, 2223 } accept").expect("established connections must survive the end of a permission");
    let allow4 = rules.find("ip saddr . tcp dport @allowed4 accept").unwrap();
    let allow6 = rules.find("ip6 saddr . tcp dport @allowed6 accept").unwrap();
    let drop = rules.find("tcp dport { 2222, 2223 } drop").unwrap();
    // the same wall stands in front of the UDP data ports
    assert!(rules.contains("ct state established,related udp dport { 2222, 2223 } accept"));
    assert!(rules.contains("ip saddr . udp dport @allowed4 accept") && rules.contains("ip6 saddr . udp dport @allowed6 accept"));
    assert!(rules.contains("udp dport { 2222, 2223 } drop"));
    assert!(est < drop && allow4 < drop && allow6 < drop, "the drop comes last:\n{rules}");
    assert!(rules.contains("flags timeout") && rules.contains("policy accept"), "only the work ports are touched: everything else on the machine is left as it is");
    let log2 = Arc::new(std::sync::Mutex::new(vec![]));
    NftBackend { runner: Recorder(log2.clone()) }.install(&[2222]).unwrap();
    let l2 = log2.lock().unwrap().clone();
    assert_eq!(l2.last().unwrap().0, vec!["-f", "-"]);
    assert!(l2.last().unwrap().1.as_ref().unwrap().contains("dport { 2222 } drop"));
}

// ---------------------------------------------------------------- the door of the firewall program

fn fw_door(r: &Rig, k: &MockKernel, ports: &[u16], audit: Option<Arc<yrl::audit::AuditClient>>) -> (FirewallClient, ExecutorIpcLike) {
    let key = yrl::keys::generate();
    let gate_key = r.cfg.gate.clone().unwrap().key;
    let sock = r.dir.path().join(format!("fw-{}.sock", ports[0]));
    let kk = k.clone();
    let service = FirewallService::start(Box::new(k.clone()), Policy { work_ports: ports.to_vec(), allow_loopback: true, max_ttl_secs: 60, ..Default::default() }, Box::new(move || kk.now()), audit).unwrap();
    let ipc = yrl::ipc::ExecutorIpc { socket: sock.clone(), key: key.clone(), gatekeeper_public: gate_key.public.clone(), expected_uid: Some(unsafe { libc::geteuid() }), expected_exe: None };
    let listener = yrl::ipc::bind_socket(&sock).unwrap();
    tokio::spawn(serve_ipc(listener, service, ipc.clone(), Arc::new(|_| {})));
    (FirewallClient::new(yrl::ipc::GatekeeperIpc { socket: sock, key: gate_key, executor_public: key.public.clone() }), ExecutorIpcLike { ipc, key })
}

struct ExecutorIpcLike {
    ipc: yrl::ipc::ExecutorIpc,
    key: yrl::keys::KeyPair,
}

#[tokio::test]
async fn s13_through_the_door_only_the_four_things_can_be_asked_and_the_policy_is_not_the_callers() {
    let r = rig("exec").await;
    let k = MockKernel::default();
    let (c, door) = fw_door(&r, &k, &[3333], None);
    assert!(c.call(open(ip(1), 3333, 30)).await.is_ok() && k.allows(ip(1), 3333));
    assert_eq!(c.call(Request::Query { addr: ip(1), port: 3333 }).await.unwrap(), Some(true));
    assert_eq!(c.call(Request::Query { addr: ip(9), port: 3333 }).await.unwrap(), Some(false), "'no' arrives as 'no'");
    assert!(c.call(open(ip(1), 22, 30)).await.unwrap_err().to_string().contains("refused"), "a port that is not a work port cannot be opened by the gatekeeper's say-so");
    assert!(c.call(open(ip(1), 3333, 100_000)).await.is_err(), "for ever is not available");
    assert!(c.call(Request::Close { addr: ip(1), port: 3333 }).await.is_ok() && !k.allows(ip(1), 3333));
    // a stranger at the door and a hand-made frame outside the language
    let stranger = FirewallClient::new(yrl::ipc::GatekeeperIpc { socket: door.ipc.socket.clone(), key: yrl::keys::generate(), executor_public: door.key.public.clone() });
    assert!(stranger.call(open(ip(2), 3333, 30)).await.is_err() && !k.allows(ip(2), 3333));
    let mut s = tokio::net::UnixStream::connect(&door.ipc.socket).await.unwrap();
    let sec = yrl::session::client_handshake(&mut s, &r.cfg.gate.clone().unwrap().key, &door.key.public, yrl::session::REKEY_EVERY).await.unwrap();
    for raw in [yrl::wire::Frame::new(120, 0, b"add rule ip saddr 1.2.3.4 accept".to_vec()), yrl::wire::Frame::new(FW_OPEN, 0, vec![1, 2, 3])] {
        let mut s2 = tokio::net::UnixStream::connect(&door.ipc.socket).await.unwrap();
        let sec2 = yrl::session::client_handshake(&mut s2, &r.cfg.gate.clone().unwrap().key, &door.key.public, yrl::session::REKEY_EVERY).await.unwrap();
        yrl::session::write_msg(&mut s2, &sec2.seal(&raw).unwrap()).await.unwrap();
        assert!(tokio::time::timeout(Duration::from_secs(3), yrl::session::read_msg(&mut s2)).await.unwrap().is_err(), "no answer, the conversation ends");
    }
    drop((s, sec));
    assert_eq!(k.live_entries(), 0);
}

#[tokio::test]
async fn s14_the_door_is_as_narrow_as_the_others() {
    let r = rig("exec").await;
    let k = MockKernel::default();
    let (_c, door) = fw_door(&r, &k, &[3334], None);
    // judged like every other door: a wrong user or a wrong program at the other end is refused
    let me = unsafe { libc::geteuid() };
    let peer = yrl::ipc::Peer { uid: me + 1, pid: Some(1) };
    assert_eq!(yrl::ipc::judge_peer(&door.ipc, &peer, yrl::ipc::exe_of_pid), yrl::ipc::PeerVerdict::WrongUser);
    // the executor's key and the broker's key do not open it either: only the gatekeeper asks the firewall
    for wrong in [r.exec_key.clone(), r.broker_key.clone()] {
        let c = FirewallClient::new(yrl::ipc::GatekeeperIpc { socket: door.ipc.socket.clone(), key: wrong, executor_public: door.key.public.clone() });
        assert!(c.call(open(ip(3), 3334, 30)).await.is_err());
    }
    assert!(!k.allows(ip(3), 3334));
}

#[test]
fn s15_a_packet_is_exactly_its_length_and_the_two_kinds_of_id_are_not_interchangeable() {
    let w = world(SpaConfig::default());
    let mut longer = pkt(&w, T0);
    longer.push(0);
    assert_eq!(w.v.verify(&longer, ip(1), T0).unwrap_err(), Reject::Size, "one byte too many is not 'a good packet with something extra'");
    assert_ne!(client_id(&w.client.public), server_id(&w.client.public), "the same key as a client and as a server gives different ids");
}

#[tokio::test]
async fn s16_one_address_may_hold_only_so_many_permissions() {
    let k = MockKernel::default();
    let f = svc(&k, &[2222, 3333, 4444]); // per_addr_max is 2
    assert_eq!(f.handle(open(ip(1), 2222, 30)).await, Ok(None));
    assert_eq!(f.handle(open(ip(1), 3333, 30)).await, Ok(None), "the second is the last one allowed");
    assert_eq!(f.handle(open(ip(1), 4444, 30)).await, Err(Refusal::TooMany));
    assert_eq!(f.handle(open(ip(1), 3333, 30)).await, Ok(None), "renewing one that exists is not 'one more'");
    assert_eq!(f.handle(open(ip(2), 4444, 30)).await, Ok(None), "another address has its own count");
}
