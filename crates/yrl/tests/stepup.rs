//! Raising a session above USER: levels, one-use permissions, encrypted step-up, lockouts. Principle under test:
//! a completely taken over gatekeeper may disturb, but must not be able to get a SUDO or ROOT approval of its own.
mod common;
use common::*;
use std::time::{Duration, Instant};
use yrl::stepup::*;
use yrl::wire::{self, Frame};

const W: Duration = Duration::from_secs(20);

async fn prepared() -> (Rig, yrl::client::Client) {
    let r = rig("exec,sudo,root").await;
    set_words(&r);
    let c = open(&r).await;
    (r, c)
}

/// the key a client pins: the executor's for SUDO, the broker's for ROOT
fn pin(r: &Rig, level: Level) -> Vec<u8> {
    if level == Level::Root { r.broker_pub.clone() } else { r.exec_pub.clone() }
}

async fn go(c: &yrl::client::Client, r: &Rig, level: Level, op: &Op, phrase: &[u8]) -> Result<String, String> {
    c.elevate(level, op, phrase, &pin(r, level), W).await.map_err(|e| e.to_string())
}

#[test]
fn u1_operations_and_frames_are_exact() {
    for op in [Op::Status, Op::TestPrivileged(String::new()), Op::TestPrivileged("note-1".into()), Op::RestartService("yandi@2.service".into())] {
        assert_eq!(Op::decode(&op.encode()).unwrap(), op);
    }
    assert_eq!(Op::Status.required(), None);
    assert_eq!(Op::TestPrivileged("x".into()).required(), Some(Level::Sudo));
    assert_eq!(Op::RestartService("x".into()).required(), Some(Level::Root));
    let e = Op::RestartService("yandi".into()).encode();
    let mut longer = e.clone();
    longer.push(b'x');
    assert!(Op::decode(&longer).is_err() && Op::decode(&e[..e.len() - 1]).is_err() && Op::decode(&[]).is_err());
    for bad in [&b"a b"[..], b"a;b", b"", b"../x", b"x\n", &[b'a'; 65]] {
        let mut v = vec![3u8];
        v.extend_from_slice(&(bad.len() as u16).to_be_bytes());
        v.extend_from_slice(bad);
        assert!(Op::decode(&v).is_err(), "{:?}", String::from_utf8_lossy(bad));
    }
    for bad in [&b"a b"[..], b"a;b", b"../x", b"x\n", &[b'a'; 65]] {
        let mut v = vec![2u8];
        v.extend_from_slice(&(bad.len() as u16).to_be_bytes());
        v.extend_from_slice(bad);
        assert!(Op::decode(&v).is_err(), "TestPrivileged note {:?}", String::from_utf8_lossy(bad));
    }
    assert!(Op::decode(&[2, 0, 0]).is_ok(), "an empty note is fine");
    assert!(Op::decode(&[1, 0, 1, b'x']).is_err(), "Status takes no argument");
    assert!(Op::decode(&[9, 0, 0]).is_err(), "no such operation");
    assert_ne!(Op::RestartService("a".into()).digest(), Op::RestartService("b".into()).digest());
    let b = encode_begin(77, Level::Root, &Op::RestartService("y".into()), &[1, 2, 3]);
    assert_eq!(decode_begin(&b).unwrap(), (77, Level::Root, Op::RestartService("y".into()), vec![1, 2, 3]));
    assert!(decode_begin(&b[..10]).is_err() && decode_begin(&{ let mut v = b.clone(); v[8] = 9; v }).is_err() && decode_begin(&{ let mut v = b.clone(); v.extend(vec![0; 300]); v }).is_err());
    assert_eq!(decode_msg(&encode_msg(5, b"hello")).unwrap(), (5, &b"hello"[..]));
    assert!(decode_msg(&[0; 5]).is_err() && decode_msg(&vec![0; 500]).is_err());
    assert_eq!(decode_result(&encode_result(9, R_LOCKED, "t")).unwrap(), (9, R_LOCKED, "t".to_string()));
    let mut x = 31u64;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    for _ in 0..30_000 {
        let v: Vec<u8> = (0..(rnd() % 100) as usize).map(|_| rnd() as u8).collect();
        let _ = decode_begin(&v);
        let _ = decode_msg(&v);
        let _ = decode_result(&v);
        let _ = Op::decode(&v);
    }
}

#[tokio::test]
async fn u2_a_step_up_with_the_right_phrase_does_exactly_the_one_thing_asked() {
    let (r, c) = prepared().await;
    assert_eq!(go(&c, &r, Level::Sudo, &Op::TestPrivileged("hello".into()), SUDO_PHRASE).await.unwrap(), "privileged-test:hello:level=sudo");
    assert_eq!(go(&c, &r, Level::Root, &Op::RestartService("yandi".into()), ROOT_PHRASE).await.unwrap(), "restarted yandi (mock)");
    assert_eq!(std::fs::read_to_string(r.server_dir().join("broker.log")).unwrap(), "restart yandi\n");
    // approval is for that operation only: the same phrase does not run another one without asking again
    assert_eq!(go(&c, &r, Level::Root, &Op::RestartService("other".into()), ROOT_PHRASE).await.unwrap(), "restarted other (mock)");
    assert_eq!(std::fs::read_to_string(r.server_dir().join("broker.log")).unwrap(), "restart yandi\nrestart other\n");
    assert_eq!(c.exec(&[b"echo", b"still a user"], 5000, W).await.unwrap().stdout, b"still a user\n", "the session itself stayed what it was");
}

#[tokio::test]
async fn u3_without_the_right_for_the_level_nothing_starts() {
    let r = rig("exec,sudo").await; // the key may try SUDO, not ROOT
    set_words(&r);
    let c = open(&r).await;
    assert!(go(&c, &r, Level::Sudo, &Op::TestPrivileged("a".into()), SUDO_PHRASE).await.is_ok());
    let e = go(&c, &r, Level::Root, &Op::RestartService("yandi".into()), ROOT_PHRASE).await.unwrap_err();
    assert!(e.contains("denied"), "{e}");
    assert!(!r.server_dir().join("broker.log").exists());
    let r2 = rig("exec").await; // a key with neither
    set_words(&r2);
    let c2 = open(&r2).await;
    assert!(go(&c2, &r2, Level::Sudo, &Op::TestPrivileged("a".into()), SUDO_PHRASE).await.is_err());
}

#[tokio::test]
async fn u4_sudo_is_not_root_and_root_is_not_sudo() {
    let (r, c) = prepared().await;
    // an operation that needs ROOT cannot be approved at SUDO, nor the other way round - even with the right phrase for the level asked
    assert!(go(&c, &r, Level::Sudo, &Op::RestartService("yandi".into()), SUDO_PHRASE).await.is_err());
    assert!(go(&c, &r, Level::Root, &Op::TestPrivileged("x".into()), ROOT_PHRASE).await.is_err());
    // the phrase of one level does not open the other
    assert!(go(&c, &r, Level::Root, &Op::RestartService("yandi".into()), SUDO_PHRASE).await.is_err());
    assert!(go(&c, &r, Level::Sudo, &Op::TestPrivileged("x".into()), ROOT_PHRASE).await.is_err());
    assert!(!r.server_dir().join("broker.log").exists());
}

#[tokio::test]
async fn u5_three_wrong_phrases_lock_that_key_out_of_root_and_only_that() {
    let (r, c) = prepared().await;
    let op = Op::RestartService("yandi".into());
    for _ in 0..2 {
        assert!(go(&c, &r, Level::Root, &op, b"a wrong phrase, long enough").await.unwrap_err().contains("denied"));
    }
    let e = go(&c, &r, Level::Root, &op, b"a wrong phrase, long enough").await.unwrap_err();
    assert!(e.contains("locked"), "the third wrong phrase says it: {e}");
    assert!(go(&c, &r, Level::Root, &op, ROOT_PHRASE).await.unwrap_err().contains("locked"), "even the right phrase is refused now");
    assert!(go(&c, &r, Level::Sudo, &Op::TestPrivileged("still".into()), SUDO_PHRASE).await.is_ok(), "SUDO of the same key is a different matter");
    assert_eq!(c.exec(&[b"echo", b"user"], 5000, W).await.unwrap().stdout, b"user\n", "the ordinary session goes on");
    // another device key of the same owner is not touched
    let other = yrl::keys::generate();
    yrl::keys::authorize(&r.server_dir().join("authorized_keys"), &hex::encode(&other.public), "phone", "exec,sudo,root").unwrap();
    let c2 = yrl::client::Client::connect_pinned(&r.addr, &other, &r.server_pub, &r.exec_pub, T).await.unwrap();
    c2.login("anna", PW, T).await.unwrap();
    assert_eq!(c2.elevate(Level::Root, &op, ROOT_PHRASE, &r.broker_pub, W).await.unwrap(), "restarted yandi (mock)");
    // the owner on the machine lifts it
    r.cfg.root_lockouts.lift_all();
    assert_eq!(go(&c, &r, Level::Root, &op, ROOT_PHRASE).await.unwrap(), "restarted yandi (mock)");
}

#[tokio::test]
async fn u6_a_good_answer_forgives_the_earlier_mistakes() {
    let (r, c) = prepared().await;
    let op = Op::RestartService("yandi".into());
    for _ in 0..2 {
        let _ = go(&c, &r, Level::Root, &op, b"a wrong phrase, long enough").await;
    }
    assert!(go(&c, &r, Level::Root, &op, ROOT_PHRASE).await.is_ok());
    for _ in 0..2 {
        assert!(go(&c, &r, Level::Root, &op, b"a wrong phrase, long enough").await.unwrap_err().contains("denied"), "the count started again from zero");
    }
}

#[tokio::test]
async fn u7_failures_by_three_different_keys_switch_remote_root_off_for_everybody() {
    let (r, c) = prepared().await;
    let op = Op::RestartService("yandi".into());
    for i in 0..3 {
        let k = yrl::keys::generate();
        yrl::keys::authorize(&r.server_dir().join("authorized_keys"), &hex::encode(&k.public), &format!("dev{i}"), "exec,sudo,root").unwrap();
        let cl = yrl::client::Client::connect_pinned(&r.addr, &k, &r.server_pub, &r.exec_pub, T).await.unwrap();
        cl.login("anna", PW, T).await.unwrap();
        for _ in 0..3 {
            let _ = cl.elevate(Level::Root, &op, b"a wrong phrase, long enough", &r.broker_pub, W).await;
        }
    }
    assert!(r.cfg.root_lockouts.remote_root_off());
    assert!(go(&c, &r, Level::Root, &op, ROOT_PHRASE).await.unwrap_err().contains("locked"), "the owner's own clean key is stopped too");
    assert!(go(&c, &r, Level::Sudo, &Op::TestPrivileged("fine".into()), SUDO_PHRASE).await.is_ok(), "SUDO and the ordinary session are not affected");
    r.cfg.root_lockouts.lift_all();
    assert!(go(&c, &r, Level::Root, &op, ROOT_PHRASE).await.is_ok(), "lifted on the machine");
}

#[tokio::test]
async fn u8_what_the_gatekeeper_sees_is_not_the_phrase_and_a_fake_executor_gets_nothing() {
    let (r, c) = prepared().await;
    // an executor that is not the one the client pinned: the handshake fails on the client's side before the phrase leaves
    let impostor = yrl::keys::generate();
    let e = c.elevate(Level::Sudo, &Op::TestPrivileged("x".into()), SUDO_PHRASE, &impostor.public, W).await.unwrap_err().to_string();
    assert!(e.contains("denied"), "the real executor cannot read a first message made for another key: {e}");
    assert!(c.ping(b"alive", W).await.is_ok());
    // play the part of everything between the client and the executor: the frames carry no phrase in the clear
    let (mut s, sec) = raw(&r).await;
    raw_login(&mut s, &sec, "anna", PW).await;
    let level = Level::Sudo;
    let op = Op::TestPrivileged("seen".into());
    let key = yrl::keys::generate();
    let _ = key;
    let mut hs = snow::Builder::new(NOISE_XK.parse().unwrap()).local_private_key(&r.client.private).remote_public_key(&r.exec_pub).prologue(&prologue(5, level, &op, &r.exec_pub)).build_initiator().unwrap();
    let mut buf = vec![0u8; 512];
    let n = hs.write_message(&[], &mut buf).unwrap();
    let mut seen: Vec<u8> = vec![];
    let begin = Frame::new(STEPUP_BEGIN, 0, encode_begin(5, level, &op, &buf[..n]));
    seen.extend(begin.payload.clone());
    send(&mut s, &sec, begin).await;
    let ch = recv(&mut s, &sec).await.unwrap();
    assert_eq!(ch.kind, STEPUP_CHALLENGE);
    seen.extend(ch.payload.clone());
    let mut scratch = vec![0u8; 512];
    hs.read_message(decode_msg(&ch.payload).unwrap().1, &mut scratch).unwrap();
    let n = hs.write_message(SUDO_PHRASE, &mut buf).unwrap();
    let proof = Frame::new(STEPUP_PROOF, 0, encode_msg(5, &buf[..n]));
    seen.extend(proof.payload.clone());
    send(&mut s, &sec, proof).await;
    let res = recv(&mut s, &sec).await.unwrap();
    assert_eq!(decode_result(&res.payload).unwrap().1, R_OK);
    assert!(!seen.windows(SUDO_PHRASE.len()).any(|w| w == SUDO_PHRASE), "the phrase is not in the clear anywhere on the way");
    assert!(!seen.windows(8).any(|w| w == &SUDO_PHRASE[..8]), "not even a piece of it");
}

#[tokio::test]
async fn u9_a_recorded_answer_is_useless() {
    let (r, _c) = prepared().await;
    let (mut s, sec) = raw(&r).await;
    raw_login(&mut s, &sec, "anna", PW).await;
    let op = Op::RestartService("replay".into());
    let mk = |id: u64| {
        let hs = snow::Builder::new(NOISE_XK.parse().unwrap()).local_private_key(&r.client.private).remote_public_key(&r.broker_pub).prologue(&prologue(id, Level::Root, &op, &r.broker_pub)).build_initiator().unwrap();
        hs
    };
    // a full, successful run, recorded
    let mut hs = mk(1);
    let mut buf = vec![0u8; 512];
    let n = hs.write_message(&[], &mut buf).unwrap();
    let msg1 = buf[..n].to_vec();
    send(&mut s, &sec, Frame::new(STEPUP_BEGIN, 0, encode_begin(1, Level::Root, &op, &msg1))).await;
    assert_eq!(recv(&mut s, &sec).await.unwrap().kind, wire::OP_ACCEPTED);
    let ch = recv(&mut s, &sec).await.unwrap();
    let mut scratch = vec![0u8; 512];
    hs.read_message(decode_msg(&ch.payload).unwrap().1, &mut scratch).unwrap();
    let n = hs.write_message(ROOT_PHRASE, &mut buf).unwrap();
    let proof = encode_msg(1, &buf[..n]);
    send(&mut s, &sec, Frame::new(STEPUP_PROOF, 0, proof.clone())).await;
    assert_eq!(decode_result(&recv(&mut s, &sec).await.unwrap().payload).unwrap().1, R_OK);
    let log_after_first = std::fs::read_to_string(r.server_dir().join("broker.log")).unwrap();
    // 1. the same PROOF again: the challenge is used up
    send(&mut s, &sec, Frame::new(STEPUP_PROOF, 0, proof.clone())).await;
    assert_eq!(decode_result(&recv(&mut s, &sec).await.unwrap().payload).unwrap().1, R_EXPIRED);
    // 2. the same BEGIN and the same recorded PROOF again: the executor's fresh key makes the old answer not decrypt
    send(&mut s, &sec, Frame::new(STEPUP_BEGIN, 0, encode_begin(1, Level::Root, &op, &msg1))).await;
    let duplicate = recv(&mut s, &sec).await.unwrap();
    assert_eq!(duplicate.kind, STEPUP_RESULT);
    assert_eq!(decode_result(&duplicate.payload).unwrap().1, R_UNKNOWN);
    send(&mut s, &sec, Frame::new(STEPUP_PROOF, 0, proof)).await;
    assert_eq!(decode_result(&recv(&mut s, &sec).await.unwrap().payload).unwrap().1, R_EXPIRED);
    assert_eq!(std::fs::read_to_string(r.server_dir().join("broker.log")).unwrap(), log_after_first, "nothing was done a second time");
    // 3. an answer made for another operation cannot be used for this one (the operation is part of what both sides agreed at the start)
    let other = Op::RestartService("something-else".into());
    let mut hs2 = snow::Builder::new(NOISE_XK.parse().unwrap()).local_private_key(&r.client.private).remote_public_key(&r.broker_pub).prologue(&prologue(2, Level::Root, &op, &r.broker_pub)).build_initiator().unwrap();
    let n = hs2.write_message(&[], &mut buf).unwrap();
    send(&mut s, &sec, Frame::new(STEPUP_BEGIN, 0, encode_begin(2, Level::Root, &other, &buf[..n]))).await; // announces another operation than the handshake was made for
    assert_eq!(recv(&mut s, &sec).await.unwrap().kind, wire::OP_ACCEPTED);
    let ch3 = recv(&mut s, &sec).await.unwrap();
    assert_eq!(decode_result(&ch3.payload).unwrap().1, R_DENIED, "the handshake does not fit what is being announced");
}

#[tokio::test]
async fn u10_a_taken_over_gatekeeper_cannot_get_an_approval_of_its_own() {
    use yrl::executor::open_session;
    let r = rig("exec,sudo,root").await;
    set_words(&r);
    // the real executor's door, opened with the gatekeeper's own key: that is what a taken-over gatekeeper has
    let g = r.cfg.gate.clone().unwrap();
    let ask = |rights: Vec<String>| {
        let g = g.clone();
        let key = r.client.public.clone();
        async move { open_session(&g, &key, "anna", &rights).await }
    };
    assert!(ask(vec!["exec".into()]).await.is_none());
    assert!(ask(vec!["exec".into(), "sudo".into()]).await.is_none(), "Gatekeeper assertions cannot create a channel on which to start SUDO");
    assert!(ask(vec!["exec".into(), "root".into()]).await.is_none(), "Gatekeeper assertions cannot reach the broker through a forged session");
    assert_eq!(r.cfg.lockouts.standing(&r.client.public, Level::Sudo), Standing::Open);
    assert_eq!(r.cfg.root_lockouts.standing(&r.client.public, Level::Root), Standing::Open);
    assert!(!r.server_dir().join("broker.log").exists());
}

#[tokio::test]
async fn u11_pending_challenges_are_few() {
    let (r, _c) = prepared().await;
    let (mut s, sec) = raw(&r).await;
    raw_login(&mut s, &sec, "anna", PW).await;
    let op = Op::TestPrivileged("p".into());
    let mut results = vec![];
    for id in 1..=(MAX_PENDING as u64 + 2) {
        let mut hs = snow::Builder::new(NOISE_XK.parse().unwrap()).local_private_key(&r.client.private).remote_public_key(&r.exec_pub).prologue(&prologue(id, Level::Sudo, &op, &r.exec_pub)).build_initiator().unwrap();
        let mut buf = vec![0u8; 512];
        let n = hs.write_message(&[], &mut buf).unwrap();
        send(&mut s, &sec, Frame::new(STEPUP_BEGIN, 0, encode_begin(id, Level::Sudo, &op, &buf[..n]))).await;
        results.push(recv(&mut s, &sec).await.unwrap().kind);
    }
    assert_eq!(results.iter().filter(|k| **k == STEPUP_CHALLENGE).count(), MAX_PENDING);
    assert_eq!(results.iter().filter(|k| **k == STEPUP_RESULT).count(), 2, "the rest are turned away");
    // malformed requests end the session
    send(&mut s, &sec, Frame::new(STEPUP_BEGIN, 0, vec![1, 2, 3])).await;
    send(&mut s, &sec, Frame::new(wire::PING, 0, b"x".to_vec())).await;
    assert!(recv(&mut s, &sec).await.is_none());
}

#[test]
fn u12_a_cap_is_for_one_thing_one_session_one_use_and_a_short_time() {
    let op = Op::RestartService("yandi".into());
    let mk = || Cap::issue(Level::Root, &op, 7, Duration::from_secs(60));
    let now = Instant::now();
    let mut c = mk();
    assert_eq!(c.spend(&op, 7, now), Ok(()));
    assert_eq!(c.spend(&op, 7, now), Err(CapError::Used), "one use");
    assert_eq!(mk().spend(&op, 8, now), Err(CapError::WrongSession), "another session");
    assert_eq!(mk().spend(&Op::RestartService("other".into()), 7, now), Err(CapError::WrongOperation), "another operation");
    assert_eq!(mk().spend(&Op::TestPrivileged("x".into()), 7, now), Err(CapError::WrongLevel), "an operation of another level");
    assert_eq!(mk().spend(&op, 7, now + Duration::from_secs(61)), Err(CapError::Expired), "after its time");
    let mut sudo_cap = Cap::issue(Level::Sudo, &op, 7, Duration::from_secs(60));
    assert_eq!(sudo_cap.spend(&op, 7, now), Err(CapError::WrongLevel), "a SUDO cap does not do a ROOT thing");
    assert_ne!(mk().id, mk().id);
    // the broker refuses all of this too, whatever the executor says
    let d = tempfile::tempdir().unwrap();
    let mut c = mk();
    assert!(broker_execute(d.path(), &mut c, &op, 7).is_ok());
    assert_eq!(broker_execute(d.path(), &mut c, &op, 7), Err(CapError::Used));
    assert_eq!(std::fs::read_to_string(d.path().join("broker.log")).unwrap(), "restart yandi\n", "done once");
    let mut wrong_session = mk();
    assert!(broker_execute(d.path(), &mut wrong_session, &op, 99).is_err());
    assert_eq!(std::fs::read_to_string(d.path().join("broker.log")).unwrap(), "restart yandi\n");
}

#[test]
fn u13_the_verifiers_are_kept_properly() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    assert!(Verifier::set(d.path(), Level::Root, b"too short").is_err() && Verifier::set(d.path(), Level::Root, &[b'x'; 300]).is_err());
    assert!(!Verifier::check(d.path(), Level::Root, ROOT_PHRASE), "nothing set up: nothing passes");
    Verifier::set(d.path(), Level::Root, ROOT_PHRASE).unwrap();
    Verifier::set(d.path(), Level::Sudo, SUDO_PHRASE).unwrap();
    let text = format!("{}{}", std::fs::read_to_string(d.path().join("words")).unwrap(), std::fs::read_to_string(d.path().join("words.root")).unwrap());
    assert!(!text.contains("correct horse") && !text.contains("quick brown") && text.matches("$argon2id$").count() == 2, "only verifiers are stored");
    for f in ["words", "words.root"] {
        assert_eq!(std::fs::metadata(d.path().join(f)).unwrap().permissions().mode() & 0o777, 0o600);
    }
    assert!(std::fs::read_to_string(d.path().join("words")).unwrap().starts_with("sudo ") && std::fs::read_to_string(d.path().join("words.root")).unwrap().starts_with("root "), "SUDO and ROOT keep their verifiers in different files: the broker alone needs the second");
    assert!(Verifier::check(d.path(), Level::Root, ROOT_PHRASE) && Verifier::check(d.path(), Level::Sudo, SUDO_PHRASE));
    assert!(!Verifier::check(d.path(), Level::Root, SUDO_PHRASE) && !Verifier::check(d.path(), Level::Sudo, ROOT_PHRASE) && !Verifier::check(d.path(), Level::Root, b"") && !Verifier::check(d.path(), Level::Root, b"correct horse battery staple, twice "));
    Verifier::set(d.path(), Level::Root, b"a different long phrase now").unwrap();
    assert!(!Verifier::check(d.path(), Level::Root, ROOT_PHRASE) && Verifier::check(d.path(), Level::Root, b"a different long phrase now"), "setting again replaces");
    assert!(Verifier::check(d.path(), Level::Sudo, SUDO_PHRASE), "and leaves the other level alone");
    std::fs::set_permissions(d.path().join("words"), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!Verifier::check(d.path(), Level::Sudo, SUDO_PHRASE), "a file others can read is not trusted");
}

#[tokio::test]
async fn u14_phrases_never_reach_the_log() {
    let (r, c) = prepared().await;
    let _ = go(&c, &r, Level::Root, &Op::RestartService("yandi".into()), b"a wrong phrase, long enough").await;
    let _ = go(&c, &r, Level::Root, &Op::RestartService("yandi".into()), ROOT_PHRASE).await;
    let _ = go(&c, &r, Level::Sudo, &Op::TestPrivileged("n".into()), SUDO_PHRASE).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let log = r.log.lock().unwrap().join("\n");
    assert!(log.contains("step-up failed") && log.contains("step-up approved"));
    for s in ["a wrong phrase", "correct horse", "quick brown", "argon2"] {
        assert!(!log.contains(s), "the log holds {s:?}");
    }
}

#[tokio::test]
async fn u15_a_challenge_does_not_wait_for_ever() {
    let d = tempfile::tempdir().unwrap();
    Verifier::set(d.path(), Level::Sudo, SUDO_PHRASE).unwrap();
    let me = yrl::keys::generate();
    let device = yrl::keys::generate();
    let lockouts = Lockouts::default();
    let rights = vec!["sudo".to_string()];
    let ctx = Ctx { dir: d.path(), lockouts: &lockouts, my_key: &me, session_rights: &rights, device_key: &device.public, session_no: 1, label: "t", serves: &[Level::Sudo], log: &|_| {}, audit: None, account: "t" };
    let op = Op::TestPrivileged("late".into());
    let mut server = StepServer::default();
    server.life = Duration::from_millis(80);
    let mut hs = snow::Builder::new(NOISE_XK.parse().unwrap()).local_private_key(&device.private).remote_public_key(&me.public).prologue(&prologue(1, Level::Sudo, &op, &me.public)).build_initiator().unwrap();
    let mut buf = vec![0u8; 512];
    let n = hs.write_message(&[], &mut buf).unwrap();
    let out = server.begin(&encode_begin(1, Level::Sudo, &op, &buf[..n]), &ctx).unwrap();
    assert_eq!(out[0].kind, STEPUP_CHALLENGE);
    let mut scratch = vec![0u8; 512];
    hs.read_message(decode_msg(&out[0].payload).unwrap().1, &mut scratch).unwrap();
    let n = hs.write_message(SUDO_PHRASE, &mut buf).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let out = server.proof(&encode_msg(1, &buf[..n]), &ctx).await.unwrap();
    assert_eq!(decode_result(&out[0].payload).unwrap().1, R_EXPIRED, "a right answer, but too late");
    // and the same, in time, works (so the test is about the time and nothing else)
    let mut server = StepServer::default();
    let mut hs = snow::Builder::new(NOISE_XK.parse().unwrap()).local_private_key(&device.private).remote_public_key(&me.public).prologue(&prologue(2, Level::Sudo, &op, &me.public)).build_initiator().unwrap();
    let n = hs.write_message(&[], &mut buf).unwrap();
    let out = server.begin(&encode_begin(2, Level::Sudo, &op, &buf[..n]), &ctx).unwrap();
    hs.read_message(decode_msg(&out[0].payload).unwrap().1, &mut scratch).unwrap();
    let n = hs.write_message(SUDO_PHRASE, &mut buf).unwrap();
    let out = server.proof(&encode_msg(2, &buf[..n]), &ctx).await.unwrap();
    assert_eq!(decode_result(&out[0].payload).unwrap().1, R_OK);
}

#[tokio::test]
async fn u16_a_request_whose_level_does_not_fit_its_operation_is_turned_away_before_any_challenge() {
    let (r, _c) = prepared().await;
    let (mut s, sec) = raw(&r).await;
    raw_login(&mut s, &sec, "anna", PW).await;
    // SUDO asked for an operation that needs ROOT (and the reverse)
    for (id, level, op, pin) in [(1u64, Level::Sudo, Op::RestartService("x".into()), r.exec_pub.clone()), (2, Level::Root, Op::TestPrivileged("x".into()), r.broker_pub.clone())] {
        let mut hs = snow::Builder::new(NOISE_XK.parse().unwrap()).local_private_key(&r.client.private).remote_public_key(&pin).prologue(&prologue(id, level, &op, &pin)).build_initiator().unwrap();
        let mut buf = vec![0u8; 512];
        let n = hs.write_message(&[], &mut buf).unwrap();
        send(&mut s, &sec, Frame::new(STEPUP_BEGIN, 0, encode_begin(id, level, &op, &buf[..n]))).await;
        let mut f = recv(&mut s, &sec).await.unwrap();
        if level == Level::Root {
            assert_eq!(f.kind, wire::OP_ACCEPTED);
            f = recv(&mut s, &sec).await.unwrap();
        }
        assert_eq!(f.kind, STEPUP_RESULT, "no challenge is given for a request that cannot be right");
        assert_eq!(decode_result(&f.payload).unwrap().1, R_DENIED);
    }
}

#[tokio::test]
async fn u17_challenges_that_ran_out_do_not_use_up_the_places() {
    let d = tempfile::tempdir().unwrap();
    let me = yrl::keys::generate();
    let device = yrl::keys::generate();
    let lockouts = Lockouts::default();
    let rights = vec!["sudo".to_string()];
    let ctx = Ctx { dir: d.path(), lockouts: &lockouts, my_key: &me, session_rights: &rights, device_key: &device.public, session_no: 1, label: "t", serves: &[Level::Sudo], log: &|_| {}, audit: None, account: "t" };
    let op = Op::TestPrivileged("p".into());
    let mut server = StepServer::default();
    server.life = Duration::from_millis(80);
    let begin = |server: &mut StepServer, id: u64| {
        let mut hs = snow::Builder::new(NOISE_XK.parse().unwrap()).local_private_key(&device.private).remote_public_key(&me.public).prologue(&prologue(id, Level::Sudo, &op, &me.public)).build_initiator().unwrap();
        let mut buf = vec![0u8; 512];
        let n = hs.write_message(&[], &mut buf).unwrap();
        server.begin(&encode_begin(id, Level::Sudo, &op, &buf[..n]), &ctx).unwrap()[0].kind
    };
    for id in 1..=MAX_PENDING as u64 {
        assert_eq!(begin(&mut server, id), STEPUP_CHALLENGE);
    }
    assert_eq!(begin(&mut server, 100), STEPUP_RESULT, "full");
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(begin(&mut server, 101), STEPUP_CHALLENGE, "the old ones ran out and made room");
}
