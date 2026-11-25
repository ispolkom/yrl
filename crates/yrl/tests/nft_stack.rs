//! The whole thing with the real programs and the REAL kernel filter: audit, broker, executor, firewall (nft), gatekeeper (with the knock port), and a client.
//! Everything runs in a private network namespace made with `unshare -rn` (no root needed, nothing outside is touched). Skipped, loudly, if nft is not usable.
mod common;
use common::*;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use yrl::auditlog::*;
use yrl::client::{Client, ClientOptions, Knock};

const YRLD: &str = env!("CARGO_BIN_EXE_yrld");
const W: Duration = Duration::from_secs(20);

fn path_with_sbin() -> String {
    format!("{}:/usr/sbin:/sbin", std::env::var("PATH").unwrap_or_default())
}

#[test]
fn k0_outer_runs_the_whole_stack_in_a_private_network() {
    let ok = Command::new("unshare").args(["-rn", "sh", "-c", "nft add table inet probe && nft delete table inet probe"]).env("PATH", path_with_sbin()).output().map(|o| o.status.success()).unwrap_or(false);
    if !ok {
        eprintln!("SKIPPED: no usable nft/unshare here");
        return;
    }
    let me = std::env::current_exe().unwrap();
    let out = Command::new("unshare").args(["-rn", "sh", "-c"]).arg(format!("ip link set lo up && {} --exact k1_inner --ignored --nocapture --test-threads=1", me.display())).env("PATH", path_with_sbin()).env("YRL_NETNS", "1").output().unwrap();
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && text.contains("1 passed"), "the stack inside the private network failed:\n{text}");
}

struct Procs(Vec<Child>);
impl Drop for Procs {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn spawn(args: &[&str]) -> Child {
    Command::new(YRLD).args(args).env("PATH", path_with_sbin()).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::inherit()).spawn().unwrap()
}

async fn wait_for_file(p: std::path::PathBuf) {
    for _ in 0..200 {
        if p.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{} never appeared", p.display());
}

fn free_tcp() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn read(dir: &std::path::Path, j: Journal) -> Vec<Record> {
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

#[tokio::test]
#[ignore = "runs only inside the private network made by k0_outer"]
async fn k1_inner() {
    assert_eq!(std::env::var("YRL_NETNS").as_deref(), Ok("1"));
    let dir = tempfile::tempdir().unwrap();
    let sd = dir.path().join("srv");
    let s = sd.to_str().unwrap().to_string();
    let out = Command::new(YRLD).args(["init", &s]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let server_pub = hex::decode(text.lines().find(|l| l.contains("server public")).unwrap().split_whitespace().last().unwrap()).unwrap();
    let executor_pub = hex::decode(text.lines().find(|l| l.contains("executor public")).unwrap().split_whitespace().last().unwrap()).unwrap();
    let client = yrl::keys::generate();
    yrl::keys::authorize(&sd.join("authorized_keys"), &hex::encode(&client.public), "laptop", "exec,shell,root").unwrap();
    // inside the private namespace the only user is "root" (this process's own account), so the account names it, with the right the server demands for that
    yrl::users::set_user_os(&sd.join("users"), "anna", "exec,shell,root", Some("root"), PW).unwrap();
    let (work, knock) = (free_tcp(), free_tcp());
    let mut procs = Procs(vec![]);
    procs.0.push(spawn(&["audit", &s]));
    wait_for_file(sd.join("audit.sock")).await;
    procs.0.push(spawn(&["broker", &s]));
    wait_for_file(sd.join("broker.sock")).await;
    procs.0.push(spawn(&["executor", &s]));
    wait_for_file(sd.join("ipc.sock")).await;
    procs.0.push(spawn(&["firewall", &s, "--ports", &work.to_string(), "--allow-loopback", "--max-ttl", "30"]));
    wait_for_file(sd.join("firewall.sock")).await;
    procs.0.push(spawn(&["gatekeeper", &s, &format!("127.0.0.1:{work}"), "--spa", &format!("127.0.0.1:{knock}"), "--work-port", &work.to_string(), "--knock-ttl", "4"]));
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let addr = format!("127.0.0.1:{work}");
    let quiet = ClientOptions { executor_public: Some(executor_pub), connect_timeout: Duration::from_millis(600), give_up_after: Duration::from_millis(1500), ..fast_opts() };
    // 1. the wall: the right key, the right password, and still nothing
    assert!(Client::connect_opts(&addr, &client, &server_pub, quiet.clone()).await.is_err(), "no knock: the real kernel drops the connection");
    // 2. with the client's own knock
    let mut o = quiet.clone();
    o.connect_timeout = Duration::from_secs(5);
    o.give_up_after = Duration::from_secs(10);
    o.knock = Some(Knock { udp: format!("127.0.0.1:{knock}"), settle: Duration::from_millis(300) });
    let c = Client::connect_opts(&addr, &client, &server_pub, o).await.expect("after the knock the real firewall lets the handshake through");
    c.login("anna", PW, T).await.unwrap();
    let r = c.exec(&[b"echo", b"through the real wall"], 5000, W).await.unwrap();
    assert_eq!(r.stdout, b"through the real wall\n", "stderr {:?} code {} error {:?}", String::from_utf8_lossy(&r.stderr), r.code, r.error);
    // 3. the kernel's own timeout (4 s): new connections are dropped again, the running one goes on
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(Client::connect_opts(&addr, &client, &server_pub, quiet).await.is_err(), "the permission ran out inside the kernel");
    assert_eq!(c.exec(&[b"echo", b"still here"], 5000, W).await.unwrap().stdout, b"still here\n", "the session that was already running goes on");
    // 4. what was written down
    let sec = read(&sd, Journal::Security);
    assert!(sec.iter().any(|r| r.source == Source::Gatekeeper && r.ev.op == "spa_ok"), "the knock is in the security journal");
    assert!(sec.iter().any(|r| r.source == Source::Firewall && r.ev.op == "firewall_open"), "and so is the opening, written by the firewall program itself");
    let ord = read(&sd, Journal::Ordinary);
    assert!(!ord.iter().any(|r| r.ev.op.starts_with("spa_") || r.ev.op.starts_with("firewall")));
}
