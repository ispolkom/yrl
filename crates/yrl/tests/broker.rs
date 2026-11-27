//! The broker: the only part that may ever hold privileges, and the end of the encrypted channel for ROOT.
mod common;
use common::*;
use std::time::Duration;
use yrl::executor::open_session;
use yrl::stepup::*;
use yrl::wire::{self, Frame};

const W: Duration = Duration::from_secs(20);

async fn prepared() -> (Rig, yrl::client::Client) {
    let r = rig("exec,sudo,root").await;
    set_words(&r);
    let c = open(&r).await;
    (r, c)
}

#[tokio::test]
async fn b1_root_is_answered_by_the_broker_and_by_nobody_else() {
    let (r, c) = prepared().await;
    let op = Op::RestartService("yandi".into());
    assert_eq!(c.elevate(Level::Root, &op, ROOT_PHRASE, &r.broker_pub, W).await.unwrap(), "restarted yandi (mock)");
    // pinned to the EXECUTOR's key instead, ROOT is refused: the executor is not the end of that channel
    let e = c.elevate(Level::Root, &op, ROOT_PHRASE, &r.exec_pub, W).await.unwrap_err().to_string();
    assert!(e.contains("denied"), "{e}");
    // and the SUDO phrase of the executor's file does not open ROOT: the verifiers live in different files
    assert!(c.elevate(Level::Root, &op, SUDO_PHRASE, &r.broker_pub, W).await.is_err());
    assert_eq!(std::fs::read_to_string(r.server_dir().join("broker.log")).unwrap(), "restart yandi\n");
}

#[tokio::test]
async fn b2_the_executor_cannot_read_what_it_carries() {
    let (r, _c) = prepared().await;
    let (mut s, sec) = raw(&r).await;
    raw_login(&mut s, &sec, "anna", PW).await;
    let op = Op::RestartService("carried".into());
    let mut hs = snow::Builder::new(NOISE_XK.parse().unwrap()).local_private_key(&r.client.private).remote_public_key(&r.broker_pub).prologue(&prologue(7, Level::Root, &op, &r.broker_pub)).build_initiator().unwrap();
    let mut buf = vec![0u8; 512];
    let n = hs.write_message(&[], &mut buf).unwrap();
    let msg1 = buf[..n].to_vec();
    let mut seen: Vec<u8> = vec![];
    let begin = Frame::new(STEPUP_BEGIN, 0, encode_begin(7, Level::Root, &op, &msg1));
    seen.extend(&begin.payload);
    send(&mut s, &sec, begin).await;
    let accepted = recv(&mut s, &sec).await.unwrap();
    assert_eq!(accepted.kind, yrl::wire::OP_ACCEPTED);
    let ch = recv(&mut s, &sec).await.unwrap();
    assert_eq!(ch.kind, STEPUP_CHALLENGE);
    seen.extend(&ch.payload);
    let mut scratch = vec![0u8; 512];
    hs.read_message(decode_msg(&ch.payload).unwrap().1, &mut scratch).unwrap();
    let n = hs.write_message(ROOT_PHRASE, &mut buf).unwrap();
    let proof = Frame::new(STEPUP_PROOF, 0, encode_msg(7, &buf[..n]));
    seen.extend(&proof.payload);
    send(&mut s, &sec, proof).await;
    assert_eq!(decode_result(&recv(&mut s, &sec).await.unwrap().payload).unwrap().1, R_OK);
    assert!(!seen.windows(8).any(|w| w == &ROOT_PHRASE[..8]), "the phrase is not in the clear on the way through the gatekeeper and the executor");
    // the executor, with ITS OWN key, cannot even open the first message: the channel was made for the broker's key
    let mut as_executor = snow::Builder::new(NOISE_XK.parse().unwrap()).local_private_key(&r.exec_key.private).prologue(&prologue(7, Level::Root, &op, &r.broker_pub)).build_responder().unwrap();
    assert!(as_executor.read_message(&msg1, &mut scratch).is_err());
    let mut as_executor2 = snow::Builder::new(NOISE_XK.parse().unwrap()).local_private_key(&r.exec_key.private).prologue(&prologue(7, Level::Root, &op, &r.exec_pub)).build_responder().unwrap();
    assert!(as_executor2.read_message(&msg1, &mut scratch).is_err(), "nor with a prologue made for itself");
}

#[tokio::test]
async fn b3_a_taken_over_executor_cannot_get_root_either() {
    let r = rig("exec,sudo,root").await;
    set_words(&r);
    // the executor's own door to the broker, opened with the executor's own key: what a taken-over executor has
    let b = r.cfg.broker.clone().unwrap();
    let op = Op::RestartService("evil".into());
    let (to, mut from) = open_session(&b, &r.client.public, "anna", &["exec".to_string(), "root".to_string()]).await.unwrap();
    let mut hs = snow::Builder::new(NOISE_XK.parse().unwrap()).local_private_key(&b.key.private).remote_public_key(&r.broker_pub).prologue(&prologue(1, Level::Root, &op, &r.broker_pub)).build_initiator().unwrap();
    let mut buf = vec![0u8; 512];
    let n = hs.write_message(&[], &mut buf).unwrap();
    to.send(Frame::new(STEPUP_BEGIN, 0, encode_begin(1, Level::Root, &op, &buf[..n]))).await.unwrap();
    let ch = tokio::time::timeout(W, from.recv()).await.unwrap().unwrap();
    assert_eq!(ch.kind, STEPUP_CHALLENGE);
    let mut scratch = vec![0u8; 512];
    hs.read_message(decode_msg(&ch.payload).unwrap().1, &mut scratch).unwrap();
    let n = hs.write_message(ROOT_PHRASE, &mut buf).unwrap(); // the executor even has the right phrase
    to.send(Frame::new(STEPUP_PROOF, 0, encode_msg(1, &buf[..n]))).await.unwrap();
    let f = tokio::time::timeout(W, from.recv()).await.unwrap().unwrap();
    assert_eq!(decode_result(&f.payload).unwrap().1, R_DENIED, "its device key is not the session's: the owner's device is the only one that counts");
    assert!(!r.server_dir().join("broker.log").exists());
    assert_eq!(r.cfg.root_lockouts.standing(&r.client.public, Level::Root), Standing::Open, "and the owner is not blamed");
    // the broker answers for ROOT only: a SUDO request to it is turned away, whatever the executor wishes
    let (to2, mut from2) = open_session(&b, &r.client.public, "anna", &["exec".to_string(), "sudo".to_string()]).await.unwrap();
    let sop = Op::TestPrivileged("not-for-the-broker".into());
    let mut hs2 = snow::Builder::new(NOISE_XK.parse().unwrap()).local_private_key(&b.key.private).remote_public_key(&r.broker_pub).prologue(&prologue(5, Level::Sudo, &sop, &r.broker_pub)).build_initiator().unwrap();
    let n = hs2.write_message(&[], &mut buf).unwrap();
    to2.send(Frame::new(STEPUP_BEGIN, 0, encode_begin(5, Level::Sudo, &sop, &buf[..n]))).await.unwrap();
    let f = tokio::time::timeout(W, from2.recv()).await.unwrap().unwrap();
    assert_eq!((f.kind, decode_result(&f.payload).unwrap().1), (STEPUP_RESULT, R_DENIED));
    // it also cannot ask the broker to do anything but a step-up
    to.send(Frame::new(wire::PING, 0, vec![])).await.unwrap();
    to.send(Frame::new(wire::EXEC_REQ, 0, vec![])).await.unwrap();
    let ended = tokio::time::timeout(W, async { while from.recv().await.is_some() {} }).await;
    assert!(ended.is_ok(), "the broker hangs up on anything else");
}

#[tokio::test]
async fn b4_the_broker_checks_the_account_files_itself() {
    let r = rig("exec,sudo").await; // the key has no `root`
    let b = r.cfg.broker.clone().unwrap();
    assert!(open_session(&b, &r.client.public, "anna", &["root".to_string()]).await.is_none(), "an executor claiming a right the key does not carry is turned away");
    assert!(open_session(&b, &r.client.public, "anna", &["sudo".to_string()]).await.is_some());
    assert!(open_session(&b, &yrl::keys::generate().public, "anna", &[]).await.is_none(), "an unknown key");
    assert!(open_session(&b, &r.client.public, "nobody", &[]).await.is_none(), "an unknown account");
}

#[tokio::test]
async fn b5_the_door_of_the_broker_is_as_narrow_as_the_executors() {
    let r = rig("exec,sudo,root").await;
    let b = r.cfg.broker.clone().unwrap();
    // another key at the door
    let impostor = yrl::ipc::GatekeeperIpc { key: yrl::keys::generate(), ..b.clone() };
    assert!(open_session(&impostor, &r.client.public, "anna", &[]).await.is_none());
    // the gatekeeper's key (a different compartment) does not open the broker's door either
    let gate_key = r.cfg.gate.clone().unwrap().key;
    let gatekeeper_at_broker = yrl::ipc::GatekeeperIpc { key: gate_key, ..b.clone() };
    assert!(open_session(&gatekeeper_at_broker, &r.client.public, "anna", &[]).await.is_none(), "the gatekeeper can never talk to the broker directly");
    // a fake broker is not trusted by the executor's key: the pinned public key decides
    let fake = yrl::ipc::GatekeeperIpc { executor_public: yrl::keys::generate().public, ..b.clone() };
    assert!(open_session(&fake, &r.client.public, "anna", &[]).await.is_none());
    assert!(r.log.lock().unwrap().iter().any(|l| l.contains("broker: connection refused")));
}

#[tokio::test]
async fn b6_without_a_broker_root_is_simply_unavailable() {
    let r = rig_with("exec,sudo,root", |mut c| {
        c.broker_identity = None;
        c
    })
    .await;
    set_words(&r);
    // a server whose executor was told of no broker
    let mut cfg = r.cfg.clone();
    cfg.broker = None;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let (e, g) = yrl::ipc::ephemeral(r.dir.path().join("nb.sock"), Some(r.exec_key.clone()));
    let el = yrl::ipc::bind_socket(&e.socket).unwrap();
    tokio::spawn(yrl::executor::serve_ipc(el, cfg.clone(), e));
    cfg.gate = Some(g);
    tokio::spawn(yrl::server::serve(l, r.server_key.clone(), cfg));
    let c = yrl::client::Client::connect_pinned(&addr, &r.client, &r.server_pub, &r.exec_pub, T).await.unwrap();
    c.login("anna", PW, T).await.unwrap();
    let e = c.elevate(Level::Root, &Op::RestartService("x".into()), ROOT_PHRASE, &r.broker_pub, W).await.unwrap_err().to_string();
    assert!(e.contains("denied"), "{e}");
    assert!(c.elevate(Level::Sudo, &Op::TestPrivileged("fine".into()), SUDO_PHRASE, &r.exec_pub, W).await.is_ok(), "SUDO does not depend on the broker");
}

struct Procs(Vec<std::process::Child>);
impl Drop for Procs {
    fn drop(&mut self) {
        for c in &mut self.0 {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

#[tokio::test]
async fn b7_three_programs_and_what_happens_when_one_of_them_dies() {
    use std::process::{Command, Stdio};
    let dir = tempfile::tempdir().unwrap();
    let sd = dir.path().join("srv");
    let yrld = env!("CARGO_BIN_EXE_yrld");
    let out = Command::new(yrld).args(["init", sd.to_str().unwrap()]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let key_of = |tag: &str| hex::decode(text.lines().find(|l| l.contains(tag)).unwrap().split_whitespace().last().unwrap()).unwrap();
    let (server_pub, exec_pub, broker_pub) = (key_of("server public"), key_of("executor public"), key_of("broker public"));
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
    let mk = |args: &[&str]| Command::new(yrld).args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    // once `init` has set the audit door up, privileged approvals need the audit process: that is the design (fail-closed)
    procs.0.push(mk(&["audit", sd.to_str().unwrap()]));
    for _ in 0..100 {
        if sd.join("audit.sock").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    procs.0.push(mk(&["broker", sd.to_str().unwrap()]));
    for _ in 0..100 {
        if sd.join("broker.sock").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    procs.0.push(mk(&["executor", sd.to_str().unwrap()]));
    for _ in 0..100 {
        if sd.join("ipc.sock").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    procs.0.push(mk(&["gatekeeper", sd.to_str().unwrap(), &format!("127.0.0.1:{port}")]));
    tokio::time::sleep(Duration::from_millis(600)).await;
    let addr = format!("127.0.0.1:{port}");
    let c = yrl::client::Client::connect_pinned(&addr, &client, &server_pub, &exec_pub, T).await.unwrap();
    c.login("anna", PW, T).await.unwrap();
    let op = Op::RestartService("three-programs".into());
    assert_eq!(c.elevate(Level::Root, &op, ROOT_PHRASE, &broker_pub, W).await.unwrap(), "restarted three-programs (mock)");
    assert_eq!(c.elevate(Level::Sudo, &Op::TestPrivileged("x".into()), SUDO_PHRASE, &exec_pub, W).await.unwrap(), "privileged-test:x:level=sudo");
    // the broker dies: ROOT stops, everything else goes on
    let mut broker = procs.0.remove(1); // (0 is the audit process)
    broker.kill().unwrap();
    broker.wait().unwrap();
    let c2 = yrl::client::Client::connect_pinned(&addr, &client, &server_pub, &exec_pub, T).await.unwrap();
    c2.login("anna", PW, T).await.unwrap();
    assert!(c2.elevate(Level::Root, &op, ROOT_PHRASE, &broker_pub, Duration::from_secs(8)).await.is_err(), "no ROOT without the broker");
    assert!(c2.elevate(Level::Sudo, &Op::TestPrivileged("y".into()), SUDO_PHRASE, &exec_pub, W).await.is_ok());
    assert_eq!(c2.exec(&[b"echo", b"alive"], 5000, W).await.unwrap().stdout, b"alive\n");
}
