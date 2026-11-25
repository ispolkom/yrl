//! The audit journal in the running system: what gets written, by whom, and what happens when it cannot be.
mod common;
use common::*;
use std::time::Duration;
use yrl::audit::AuditClient;
use yrl::auditlog::*;
use yrl::stepup::*;

const W: Duration = Duration::from_secs(20);

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

/// waits until the journal shows `want` (events are delivered in the background)
async fn wait_for(dir: &std::path::Path, j: Journal, want: impl Fn(&[Record]) -> bool) -> Vec<Record> {
    for _ in 0..100 {
        let r = read(dir, j);
        if want(&r) {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let r = read(dir, j);
    panic!("never saw it; the {} journal holds: {:?}", j.file(), r.iter().map(|r| (r.source.name(), r.ev.op.clone(), r.ev.result)).collect::<Vec<_>>());
}

fn has(r: &[Record], src: Source, op: &str) -> bool {
    r.iter().any(|x| x.source == src && x.ev.op == op)
}

#[tokio::test]
async fn e1_an_ordinary_session_leaves_its_marks_with_the_right_names_on_them() {
    let r = rig("exec,shell,files,tunnel").await;
    let c = std::sync::Arc::new(open(&r).await);
    c.exec(&[b"echo", b"hello-from-audit"], 5000, W).await.unwrap();
    let mut p = c.pty_open(24, 80, "xterm").await.unwrap();
    p.write(b"exit\n").await.unwrap();
    let d = r.dir.path();
    std::fs::write(d.join("up"), b"x").unwrap();
    c.put_file(&d.join("up"), d.join("secret-up-name").to_str().unwrap().as_bytes(), 0o600, W).await.unwrap();
    c.fs_mkdir(d.join("a-new-dir").to_str().unwrap().as_bytes(), 0o755, W).await.unwrap();
    assert!(c.tunnel_open("127.0.0.1", 9, W).await.is_err()); // not allowed: no rules
    c.close().await;
    let ord = wait_for(&r.server_dir(), Journal::Ordinary, |r| has(r, Source::Executor, "session_close") && has(r, Source::Executor, "login") && has(r, Source::Executor, "fs")).await;
    for (src, op) in [(Source::Executor, "login"), (Source::Executor, "session_open"), (Source::Executor, "exec"), (Source::Executor, "pty"), (Source::Executor, "file"), (Source::Executor, "fs"), (Source::Executor, "denied"), (Source::Executor, "session_close")] {
        assert!(has(&ord, src, op), "missing {} by {}", op, src.name());
    }
    let exec = ord.iter().find(|x| x.ev.op == "exec").unwrap();
    assert_eq!((exec.ev.user.as_str(), exec.ev.level, exec.ev.result), ("anna", LEVEL_USER, RESULT_OK));
    assert_eq!(exec.ev.device, r.client.public);
    assert_eq!(exec.ev.session.len(), 8);
    assert!(String::from_utf8_lossy(&exec.ev.target).starts_with("echo|h:"), "the program name is kept, what was typed after it is only a hash");
    // nothing sensitive anywhere in the files
    let all = std::fs::read(r.server_dir().join("audit/ordinary.log")).unwrap();
    for needle in [&b"hello-from-audit"[..], b"secret-up-name", b"a-new-dir", PW] {
        assert!(!all.windows(needle.len()).any(|w| w == needle), "{:?} is in the journal", String::from_utf8_lossy(needle));
    }
    // the denied tunnel is in as a denial, not as a tunnel
    assert!(ord.iter().any(|x| x.ev.op == "denied" && x.ev.result == RESULT_DENIED));
    assert!(!ord.iter().any(|x| x.ev.op == "tunnel" && x.ev.result == RESULT_OK));
}

#[tokio::test]
async fn e2_a_failed_login_is_recorded_without_the_name_or_the_password_that_was_typed() {
    let r = rig("exec").await;
    let c = yrl::client::Client::connect_pinned(&r.addr, &r.client, &r.server_pub, &r.exec_pub, T).await.unwrap();
    assert!(c.login("typed-by-mistake-hunter2", b"wrong password here", T).await.is_err());
    let ord = wait_for(&r.server_dir(), Journal::Ordinary, |r| has(r, Source::Executor, "login")).await;
    let l = ord.iter().find(|x| x.ev.op == "login").unwrap();
    assert_eq!((l.ev.result, l.ev.level), (RESULT_DENIED, LEVEL_NONE));
    assert_eq!(l.ev.device, r.client.public);
    let all = std::fs::read(r.server_dir().join("audit/ordinary.log")).unwrap();
    for needle in [&b"hunter2"[..], b"wrong password"] {
        assert!(!all.windows(needle.len()).any(|w| w == needle));
    }
}

#[tokio::test]
async fn e3_step_ups_are_recorded_at_every_outcome_and_never_with_the_phrase() {
    let r = rig("exec,sudo,root").await;
    set_words(&r);
    let c = open(&r).await;
    let sop = Op::TestPrivileged("audited".into());
    let rop = Op::RestartService("yandi".into());
    c.elevate(Level::Sudo, &sop, SUDO_PHRASE, &r.exec_pub, W).await.unwrap();
    c.elevate(Level::Root, &rop, ROOT_PHRASE, &r.broker_pub, W).await.unwrap();
    for _ in 0..3 {
        let _ = c.elevate(Level::Root, &rop, b"a wrong phrase, long enough", &r.broker_pub, W).await;
    }
    let _ = c.elevate(Level::Root, &rop, ROOT_PHRASE, &r.broker_pub, W).await; // locked now
    let ord = wait_for(&r.server_dir(), Journal::Ordinary, |r| r.iter().filter(|x| x.ev.op == "stepup_root").count() >= 5).await;
    let sudo = ord.iter().find(|x| x.ev.op == "stepup_sudo").unwrap();
    assert_eq!((sudo.source, sudo.ev.level, sudo.ev.result, sudo.ev.cap.len()), (Source::Executor, LEVEL_SUDO, RESULT_OK, 16), "an approval names its one-use permission");
    assert_eq!(sudo.ev.target, b"test:audited");
    let roots: Vec<&Record> = ord.iter().filter(|x| x.ev.op == "stepup_root").collect();
    assert!(roots.iter().all(|x| x.source == Source::Broker), "ROOT is reported by the broker and by nobody else");
    let results: Vec<u8> = roots.iter().map(|x| x.ev.result).collect();
    assert_eq!(results, vec![RESULT_OK, RESULT_DENIED, RESULT_DENIED, RESULT_LOCKED, RESULT_LOCKED], "approved, wrong, wrong, wrong (now locked), then refused as locked");
    assert!(has(&ord, Source::Broker, "broker_op"), "what the broker did is recorded, with the same permission id as the approval");
    let ok = roots.iter().find(|x| x.ev.result == RESULT_OK).unwrap();
    let bop = ord.iter().find(|x| x.ev.op == "broker_op").unwrap();
    assert_eq!(ok.ev.cap, bop.ev.cap);
    assert!(roots.iter().all(|x| x.ev.device == r.client.public));
    // the phrases are nowhere
    for f in ["ordinary.log", "security.log"] {
        let all = std::fs::read(r.server_dir().join("audit").join(f)).unwrap();
        for needle in [ROOT_PHRASE, SUDO_PHRASE, b"a wrong phrase", b"correct horse"] {
            assert!(!all.windows(needle.len()).any(|w| w == needle), "{f} holds a phrase");
        }
    }
}

#[tokio::test]
async fn e4_the_security_journal_gets_the_events_about_the_protection_itself() {
    let r = rig_with("exec,sudo,root", |mut c| {
        c.lockouts = std::sync::Arc::new(Lockouts::persistent(&c.dir, "sudo"));
        c.root_lockouts = std::sync::Arc::new(Lockouts::persistent(&c.dir, "root"));
        c
    })
    .await;
    set_words(&r);
    let rop = Op::RestartService("x".into());
    // three different keys fail three times: the global switch
    for i in 0..3 {
        let k = yrl::keys::generate();
        yrl::keys::authorize(&r.server_dir().join("authorized_keys"), &hex::encode(&k.public), &format!("d{i}"), "exec,sudo,root").unwrap();
        let cl = yrl::client::Client::connect_pinned(&r.addr, &k, &r.server_pub, &r.exec_pub, T).await.unwrap();
        cl.login("anna", PW, T).await.unwrap();
        for _ in 0..3 {
            let _ = cl.elevate(Level::Root, &rop, b"a wrong phrase, long enough", &r.broker_pub, W).await;
        }
    }
    let sec = wait_for(&r.server_dir(), Journal::Security, |r| has(r, Source::Broker, "global_root_off")).await;
    assert_eq!(sec.iter().filter(|x| x.ev.op == "global_root_off").count(), 1, "said once");
    // somebody damages the store of lockouts: said once, in the security journal
    let c = open(&r).await;
    let p = r.server_dir().join("lockouts.sudo");
    std::fs::write(&p, "junk").unwrap();
    for _ in 0..3 {
        let _ = c.elevate(Level::Sudo, &Op::TestPrivileged("t".into()), SUDO_PHRASE, &r.exec_pub, W).await;
    }
    let sec = wait_for(&r.server_dir(), Journal::Security, |r| has(r, Source::Executor, "lockout_tamper")).await;
    assert_eq!(sec.iter().filter(|x| x.ev.op == "lockout_tamper").count(), 1);
    // a door that refuses a stranger writes that down too
    let stranger = yrl::keys::generate();
    let g = r.cfg.gate.clone().unwrap();
    let bad = yrl::ipc::GatekeeperIpc { key: stranger, ..g };
    assert!(yrl::executor::open_session(&bad, &r.client.public, "anna", &[]).await.is_none());
    let sec = wait_for(&r.server_dir(), Journal::Security, |r| has(r, Source::Executor, "peer_refused")).await;
    assert!(sec.iter().any(|x| x.ev.op == "peer_refused" && x.ev.target == b"handshake"));
    // none of this is in the ordinary journal
    let ord = read(&r.server_dir(), Journal::Ordinary);
    assert!(!ord.iter().any(|x| Journal::of(&x.ev.op) == Journal::Security));
}

#[tokio::test]
async fn e5_a_replayed_answer_is_in_the_security_journal() {
    let r = rig("exec,sudo").await;
    set_words(&r);
    let (mut s, sec) = raw(&r).await;
    raw_login(&mut s, &sec, "anna", PW).await;
    // a PROOF for a challenge that was never given
    let proof = encode_msg(77, &[1u8; 60]);
    send(&mut s, &sec, yrl::wire::Frame::new(STEPUP_PROOF, 0, proof.clone())).await;
    let _ = recv(&mut s, &sec).await;
    send(&mut s, &sec, yrl::wire::Frame::new(STEPUP_PROOF, 0, proof)).await;
    let _ = recv(&mut s, &sec).await;
    let sec_j = wait_for(&r.server_dir(), Journal::Security, |r| r.iter().filter(|x| x.ev.op == "replay").count() >= 2).await;
    let rep = sec_j.iter().find(|x| x.ev.op == "replay").unwrap();
    assert_eq!((rep.source, rep.ev.request_id, rep.ev.result), (Source::Executor, 77, RESULT_DENIED));
}

#[tokio::test]
async fn e6_the_same_request_twice_shows_as_a_repeat() {
    let r = rig("exec").await;
    let (mut s, sec) = raw(&r).await;
    raw_login(&mut s, &sec, "anna", PW).await;
    let req = yrl::wire::ExecReq { request_id: 5, timeout_ms: 2000, argv: vec![b"true".to_vec()] }.encode().unwrap();
    for _ in 0..2 {
        send(&mut s, &sec, yrl::wire::Frame::new(yrl::wire::EXEC_REQ, 0, req.clone())).await;
        let _ = recv(&mut s, &sec).await;
    }
    let ord = wait_for(&r.server_dir(), Journal::Ordinary, |r| r.iter().filter(|x| x.ev.op == "exec").count() >= 2).await;
    let flags: Vec<u8> = ord.iter().filter(|x| x.ev.op == "exec").map(|x| x.flags).collect();
    assert_eq!(flags, vec![0, FLAG_REPEAT]);
}

#[tokio::test]
async fn e7_each_part_can_report_only_for_itself_through_the_real_socket() {
    let r = rig("exec,sudo,root").await;
    let gate = r.cfg.audit.gate.clone().unwrap();
    // the gatekeeper's own key at the audit socket: allowed its own things only
    assert!(gate.record_critical(Event::new("enroll_guest", LEVEL_NONE, RESULT_OK)).await.is_ok());
    assert!(gate.record_critical(Event::new("login", LEVEL_USER, RESULT_OK).user("anna")).await.is_err(), "login now terminates at Executor");
    for op in ["stepup_root", "broker_op", "exec", "unlock", "global_root_off", "checkpoint"] {
        assert!(gate.record_critical(Event::new(op, LEVEL_ROOT, RESULT_OK)).await.is_err(), "the gatekeeper must not be able to say '{op}'");
    }
    let broker = r.cfg.audit.broker.clone().unwrap();
    assert!(broker.record_critical(Event::new("stepup_root", LEVEL_ROOT, RESULT_OK)).await.is_ok());
    assert!(broker.record_critical(Event::new("login", LEVEL_USER, RESULT_OK)).await.is_err());
    // a key nobody knows gets silence
    let sock = r.server_dir().join("audit.sock");
    let intruder = AuditClient::new(sock.clone(), yrl::keys::generate(), vec![0u8; 32]);
    assert!(intruder.record_critical(Event::new("login", LEVEL_USER, RESULT_OK)).await.is_err());
    let ord = wait_for(&r.server_dir(), Journal::Ordinary, |r| has(r, Source::Broker, "stepup_root")).await;
    assert!(!ord.iter().any(|x| x.source == Source::Gatekeeper && x.ev.op != "login"));
}

#[tokio::test]
async fn e8_without_a_journal_privileged_things_do_not_happen_and_ordinary_ones_go_on_counted() {
    // the executor and the broker report to a socket where nothing listens
    let dir = tempfile::tempdir().unwrap();
    let dead = |k: yrl::keys::KeyPair| AuditClient::new(dir.path().join("nobody-home.sock"), k, vec![0u8; 32]);
    let r = rig_with("exec,sudo,root", |mut c| {
        c.audit.exec = Some(dead(yrl::keys::generate()));
        c.audit.broker = Some(dead(yrl::keys::generate()));
        c.audit.gate = Some(dead(yrl::keys::generate()));
        c
    })
    .await;
    set_words(&r);
    let c = open(&r).await;
    assert_eq!(c.exec(&[b"echo", b"still works"], 5000, W).await.unwrap().stdout, b"still works\n", "ordinary work goes on");
    let e = c.elevate(Level::Sudo, &Op::TestPrivileged("x".into()), SUDO_PHRASE, &r.exec_pub, W).await.unwrap_err().to_string();
    assert!(e.contains("denied"), "SUDO is not approved when it cannot be written down: {e}");
    let e = c.elevate(Level::Root, &Op::RestartService("x".into()), ROOT_PHRASE, &r.broker_pub, W).await.unwrap_err().to_string();
    assert!(e.contains("denied"), "nor ROOT: {e}");
    assert!(!r.server_dir().join("broker.log").exists(), "and nothing was done");
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(r.cfg.audit.exec.as_ref().unwrap().lost() > 0, "the events that could not be delivered are counted, not forgotten");
    let log = r.log.lock().unwrap().join("\n");
    assert!(log.contains("audit journal is not available"));
}

#[tokio::test]
async fn e9_after_an_absence_the_loss_is_reported_when_the_journal_is_back() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let sock = dir.path().join("a.sock");
    let (client_key, audit_key) = (yrl::keys::generate(), yrl::keys::generate());
    let client = AuditClient::new(sock.clone(), client_key.clone(), audit_key.public.clone());
    for _ in 0..3 {
        client.record(Event::new("exec", LEVEL_USER, RESULT_OK));
    }
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(client.lost(), 3);
    // the audit process comes up
    let svc = yrl::audit::AuditService::open(dir.path(), 100).unwrap();
    let listener = yrl::ipc::bind_socket(&sock).unwrap();
    let ipc = yrl::audit::AuditIpc { socket: sock, key: audit_key, sources: vec![(Source::Executor, client_key.public.clone())], expected_uid: None, expected_exe: None };
    tokio::spawn(yrl::audit::serve_ipc(listener, svc, ipc, std::sync::Arc::new(|_| {})));
    client.record(Event::new("exec", LEVEL_USER, RESULT_OK));
    let sec = wait_for(dir.path(), Journal::Security, |r| has(r, Source::Executor, "audit_degraded")).await;
    assert_eq!(sec.iter().find(|x| x.ev.op == "audit_degraded").unwrap().ev.code, 3, "how many were lost");
    for _ in 0..100 {
        if client.lost() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await; // the counter is cleared just after the report is acknowledged
    }
    assert_eq!(client.lost(), 0);
    wait_for(dir.path(), Journal::Ordinary, |r| has(r, Source::Executor, "exec")).await;
}

#[tokio::test]
async fn e10_the_whole_journal_of_a_busy_run_verifies() {
    let r = rig_with("exec,shell,files,tunnel,sudo,root", |mut c| {
        c.audit_every = 5;
        c
    })
    .await;
    set_words(&r);
    let c = open(&r).await;
    for i in 0..20 {
        c.exec(&[b"echo", format!("{i}").as_bytes()], 5000, W).await.unwrap();
    }
    let _ = c.elevate(Level::Sudo, &Op::TestPrivileged("v".into()), SUDO_PHRASE, &r.exec_pub, W).await;
    c.close().await;
    wait_for(&r.server_dir(), Journal::Ordinary, |r| has(r, Source::Executor, "session_close")).await;
    for j in [Journal::Ordinary, Journal::Security] {
        let rep = verify_dir(&r.server_dir(), j).unwrap();
        assert_eq!(rep.fault, None, "{}: {rep:?}", j.file());
    }
    let rep = verify_dir(&r.server_dir(), Journal::Ordinary).unwrap();
    assert!(rep.checkpoints >= 4 && rep.records > 25, "{rep:?}");
}

/// an audit process of its own on a socket of its own, with known keys; the test plays the part of a client by hand
async fn raw_audit() -> (tempfile::TempDir, std::path::PathBuf, yrl::keys::KeyPair, yrl::keys::KeyPair) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let sock = dir.path().join("a.sock");
    let (client_key, audit_key) = (yrl::keys::generate(), yrl::keys::generate());
    let svc = yrl::audit::AuditService::open(dir.path(), 100).unwrap();
    let listener = yrl::ipc::bind_socket(&sock).unwrap();
    let ipc = yrl::audit::AuditIpc { socket: sock.clone(), key: audit_key.clone(), sources: vec![(Source::Executor, client_key.public.clone())], expected_uid: None, expected_exe: None };
    tokio::spawn(yrl::audit::serve_ipc(listener, svc, ipc, std::sync::Arc::new(|_| {})));
    (dir, sock, client_key, audit_key)
}

#[tokio::test]
async fn e11_the_audit_door_hangs_up_on_anything_that_is_not_an_event() {
    let (_d, sock, ck, ak) = raw_audit().await;
    let mut s = tokio::net::UnixStream::connect(&sock).await.unwrap();
    let sec = yrl::session::client_handshake(&mut s, &ck, &ak.public, yrl::session::REKEY_EVERY).await.unwrap();
    // an event is answered
    let good = yrl::wire::Frame::new(yrl::audit::AUDIT_EVENT, 0, yrl::audit::encode_event(&Event::new("exec", LEVEL_USER, RESULT_OK)).unwrap());
    yrl::session::write_msg(&mut s, &sec.seal(&good).unwrap()).await.unwrap();
    let m = yrl::session::read_msg(&mut s).await.unwrap();
    assert_eq!(sec.open(&m).unwrap().kind, yrl::audit::AUDIT_ACK);
    // anything else ends the conversation without an answer
    yrl::session::write_msg(&mut s, &sec.seal(&yrl::wire::Frame::new(yrl::wire::PING, 0, vec![])).unwrap()).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(3), yrl::session::read_msg(&mut s)).await.unwrap().is_err());
}

#[tokio::test]
async fn e12_a_refusal_is_not_retried() {
    // a stand-in audit process that refuses everything and counts what it was sent
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let sock = dir.path().join("r.sock");
    let (ck, ak) = (yrl::keys::generate(), yrl::keys::generate());
    let listener = yrl::ipc::bind_socket(&sock).unwrap();
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (c2, ak2, ckp) = (count.clone(), ak.clone(), ck.public.clone());
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            let (c3, ak3, ckp) = (c2.clone(), ak2.clone(), ckp.clone());
            tokio::spawn(async move {
                let auth = [yrl::keys::Authorized { public: ckp, label: "x".into(), rights: vec![] }];
                let Ok((sec, _)) = yrl::session::server_handshake(&mut s, &ak3, &auth, yrl::session::REKEY_EVERY).await else { return };
                while let Ok(m) = yrl::session::read_msg(&mut s).await {
                    let Ok(f) = sec.open(&m) else { return };
                    if f.kind == yrl::audit::AUDIT_EVENT {
                        c3.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    let _ = yrl::session::write_msg(&mut s, &sec.seal(&yrl::wire::Frame::new(yrl::audit::AUDIT_REJECT, 0, vec![])).unwrap()).await;
                }
            });
        }
    });
    let client = AuditClient::new(sock, ck, ak.public.clone());
    assert!(client.record_critical(Event::new("exec", LEVEL_USER, RESULT_OK)).await.is_err());
    assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 1, "a 'no' is final: the event is sent once");
}
