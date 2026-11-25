//! The audit process as a program of its own, with the other parts and the owner's commands around it.
mod common;
use common::*;
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use yrl::auditlog::*;
use yrl::stepup::*;

const W: Duration = Duration::from_secs(20);

struct Procs(Vec<Child>);
impl Drop for Procs {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

struct Stand {
    _dir: tempfile::TempDir,
    sd: std::path::PathBuf,
    procs: Procs,
    port: u16,
    server_pub: Vec<u8>,
    exec_pub: Vec<u8>,
    broker_pub: Vec<u8>,
    client: yrl::keys::KeyPair,
}

const YRLD: &str = env!("CARGO_BIN_EXE_yrld");

fn spawn(args: &[&str]) -> Child {
    Command::new(YRLD).args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap()
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

/// all four programs: audit, broker, executor, gatekeeper
async fn stand(checkpoint_every: u32) -> Stand {
    let dir = tempfile::tempdir().unwrap();
    let sd = dir.path().join("srv");
    let out = Command::new(YRLD).args(["init", sd.to_str().unwrap()]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let key_of = |tag: &str| hex::decode(text.lines().find(|l| l.contains(tag)).unwrap().split_whitespace().last().unwrap()).unwrap();
    let client = yrl::keys::generate();
    yrl::keys::authorize(&sd.join("authorized_keys"), &hex::encode(&client.public), "laptop", "exec,sudo,root").unwrap();
    yrl::users::set_user(&sd.join("users"), "anna", "exec,sudo,root", PW).unwrap();
    Verifier::set(&sd, Level::Sudo, SUDO_PHRASE).unwrap();
    Verifier::set(&sd, Level::Root, ROOT_PHRASE).unwrap();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut procs = Procs(vec![]);
    let s = sd.to_str().unwrap().to_string();
    procs.0.push(spawn(&["audit", &s, "--checkpoint-every", &checkpoint_every.to_string()]));
    wait_for_file(sd.join("audit.sock")).await;
    procs.0.push(spawn(&["broker", &s]));
    wait_for_file(sd.join("broker.sock")).await;
    procs.0.push(spawn(&["executor", &s]));
    wait_for_file(sd.join("ipc.sock")).await;
    procs.0.push(spawn(&["gatekeeper", &s, &format!("127.0.0.1:{port}")]));
    tokio::time::sleep(Duration::from_millis(700)).await;
    Stand { server_pub: key_of("server public"), exec_pub: key_of("executor public"), broker_pub: key_of("broker public"), _dir: dir, sd, procs, port, client }
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

async fn wait_ops(dir: &std::path::Path, j: Journal, ops: &[(&str, Source)]) -> Vec<Record> {
    for _ in 0..100 {
        let r = read(dir, j);
        if ops.iter().all(|(op, s)| r.iter().any(|x| x.ev.op == *op && x.source == *s)) {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("not all of {ops:?} appeared in {:?}", read(dir, j).iter().map(|r| (r.source.name(), r.ev.op.clone())).collect::<Vec<_>>());
}

#[tokio::test]
async fn p1_four_programs_one_journal_and_the_owners_commands_in_it() {
    let st = stand(5).await;
    let addr = format!("127.0.0.1:{}", st.port);
    let c = yrl::client::Client::connect(&addr, &st.client, &st.server_pub, T).await.unwrap();
    c.login("anna", PW, T).await.unwrap();
    c.exec(&[b"echo", b"audited"], 5000, W).await.unwrap();
    c.elevate(Level::Sudo, &Op::TestPrivileged("p".into()), SUDO_PHRASE, &st.exec_pub, W).await.unwrap_or_else(|e| panic!("elevate(Sudo) failed: {e:#}\n--- journal so far: {:?}", read(&st.sd, Journal::Ordinary).iter().map(|r| (r.source.name(), r.ev.op.clone())).collect::<Vec<_>>()));
    c.elevate(Level::Root, &Op::RestartService("svc".into()), ROOT_PHRASE, &st.broker_pub, W).await.unwrap_or_else(|e| panic!("elevate(Root) failed: {e:#}"));
    wait_ops(&st.sd, Journal::Ordinary, &[("login", Source::Gatekeeper), ("session_open", Source::Executor), ("exec", Source::Executor), ("stepup_sudo", Source::Executor), ("stepup_root", Source::Broker), ("broker_op", Source::Broker)]).await;
    // the owner's commands on the machine leave their mark in the security journal
    let mut w = Command::new(YRLD).args(["word", "set", st.sd.to_str().unwrap(), "sudo"]).stdin(Stdio::piped()).stdout(Stdio::null()).spawn().unwrap();
    w.stdin.take().unwrap().write_all(b"a brand new sudo phrase, long\n").unwrap();
    assert!(w.wait().unwrap().success());
    assert!(Command::new(YRLD).args(["unlock", st.sd.to_str().unwrap(), "all"]).stdout(Stdio::null()).status().unwrap().success());
    let sec = wait_ops(&st.sd, Journal::Security, &[("word_set", Source::Owner), ("unlock", Source::Owner)]).await;
    assert!(!std::fs::read(st.sd.join("audit/security.log")).unwrap().windows(10).any(|w| w == b"brand new "), "the new phrase is not in the journal");
    assert!(sec.iter().all(|r| r.ev.op != "word_set" || r.ev.target == b"sudo"));
    // `yrld audit verify` reads everything and is happy
    let ok = Command::new(YRLD).args(["audit", "verify", st.sd.to_str().unwrap()]).output().unwrap();
    assert!(ok.status.success(), "{}", String::from_utf8_lossy(&ok.stdout));
    assert!(String::from_utf8_lossy(&ok.stdout).contains("all journals verify"));
}

#[tokio::test]
async fn p2_an_edit_to_the_files_is_found_by_the_command_and_the_audit_process_will_not_continue_on_it() {
    let mut st = stand(3).await;
    let addr = format!("127.0.0.1:{}", st.port);
    let c = yrl::client::Client::connect(&addr, &st.client, &st.server_pub, T).await.unwrap();
    c.login("anna", PW, T).await.unwrap();
    for i in 0..6 {
        c.exec(&[b"echo", format!("{i}").as_bytes()], 5000, W).await.unwrap();
    }
    wait_ops(&st.sd, Journal::Ordinary, &[("exec", Source::Executor)]).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    // stop the audit process, then change one old record in place
    let mut audit = st.procs.0.remove(0);
    audit.kill().unwrap();
    audit.wait().unwrap();
    let p = st.sd.join("audit/ordinary.log");
    let mut b = std::fs::read(&p).unwrap();
    b[4 + 30] ^= 0x01;
    std::fs::write(&p, &b).unwrap();
    let bad = Command::new(YRLD).args(["audit", "verify", st.sd.to_str().unwrap()]).output().unwrap();
    assert!(!bad.status.success());
    assert!(String::from_utf8_lossy(&bad.stdout).contains("PROBLEM"));
    // started again on that journal, the audit process refuses
    let mut again = Command::new(YRLD).args(["audit", st.sd.to_str().unwrap()]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped()).spawn().unwrap();
    let status = loop {
        if let Some(s) = again.try_wait().unwrap() {
            break s;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(!status.success());
    let mut err = String::new();
    std::io::Read::read_to_string(&mut again.stderr.take().unwrap(), &mut err).unwrap();
    assert!(err.contains("does not verify"), "{err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn p3_a_new_device_is_not_added_when_the_journal_cannot_take_note_of_it() {
    let mut st = stand(100).await;
    // the audit process goes away
    let mut audit = st.procs.0.remove(0);
    audit.kill().unwrap();
    audit.wait().unwrap();
    std::fs::remove_file(st.sd.join("audit.sock")).ok();
    let kdir = st.sd.parent().unwrap().join("newdev");
    let kp = yrl::keys::init(&kdir).unwrap();
    let mut owner = Command::new(YRLD).args(["enroll", "enable", st.sd.to_str().unwrap(), "--ttl", "30", "--rights", "exec"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let mut out = std::io::BufReader::new(owner.stdout.take().unwrap());
    let mut line = String::new();
    std::io::BufRead::read_line(&mut out, &mut line).unwrap();
    let code = line.split("code: ").nth(1).unwrap().trim().to_string();
    let addr = format!("127.0.0.1:{}", st.port);
    let k2 = kp.clone();
    let sp = st.server_pub.clone();
    let dev = tokio::spawn(async move {
        let c = yrl::client::Client::connect(&addr, &k2, &sp, Duration::from_secs(10)).await;
        let r = c.unwrap().enroll(&code, "unrecorded", Duration::from_secs(40)).await;
        r
    });
    // the owner sees the request and says yes - but it cannot be written down, so it does not happen
    let mut shown = String::new();
    loop {
        let mut l = String::new();
        std::io::BufRead::read_line(&mut out, &mut l).unwrap();
        shown.push_str(&l);
        if l.contains("[y/N]") || l.is_empty() {
            break;
        }
    }
    owner.stdin.take().unwrap().write_all(b"y\n").unwrap();
    let res = owner.wait_with_output().unwrap();
    assert!(!res.status.success(), "the owner's command fails");
    assert!(String::from_utf8_lossy(&res.stderr).contains("audit journal"), "{}", String::from_utf8_lossy(&res.stderr));
    assert!(dev.await.unwrap().is_err(), "and the device is told no");
    assert!(!yrl::keys::read_authorized(&st.sd.join("authorized_keys")).iter().any(|a| a.public == kp.public), "no key was added");
}
