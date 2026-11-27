//! The second factor and the attacks on it. Every test is an attack or a guarantee from docs/THREATS.md (section L).
mod common;
use common::*;
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use yrl::client::Client;
use yrl::throttle::Throttle;
use yrl::wire::{self, Frame};

fn ok(f: &Option<Frame>) -> bool {
    matches!(f, Some(f) if f.kind == wire::LOGIN_OK)
}
fn fail(f: &Option<Frame>) -> bool {
    matches!(f, Some(f) if f.kind == wire::LOGIN_FAIL)
}

#[tokio::test]
async fn l1_nothing_works_before_the_login_and_nothing_runs() {
    let r = rig("exec,root").await;
    let marker = r.dir.path().join("ran");
    let exec = wire::ExecReq { request_id: 1, timeout_ms: 5000, argv: vec![b"touch".to_vec(), marker.to_str().unwrap().as_bytes().to_vec()] }.encode().unwrap();
    for f in [Frame::new(wire::PING, 0, b"x".to_vec()), Frame::new(wire::EXEC_REQ, 0, exec), Frame::new(wire::CLOSE, 0, vec![]), Frame::new(200, 0, vec![1, 2, 3]), Frame::new(wire::LOGIN_OK, 0, b"exec,root".to_vec())] {
        let (mut s, sec) = raw(&r).await;
        send(&mut s, &sec, f.clone()).await;
        assert!(recv(&mut s, &sec).await.is_none(), "kind {} before the login must get no answer", f.kind);
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!marker.exists(), "a command ran without a login");
}

#[tokio::test]
async fn l2_every_kind_of_wrong_attempt_looks_the_same() {
    let r = rig("exec,root").await;
    let mut answers = vec![];
    for (login, pw) in [("anna", &b"wrong password"[..]), ("nobody", PW), ("nobody", b"wrong password"), ("ANNA", PW), ("anna ", PW), ("anna", b""), ("guest", PW)] {
        let (mut s, sec) = raw(&r).await;
        let a = raw_login(&mut s, &sec, login, pw).await;
        assert!(fail(&a), "{login:?} must be refused");
        answers.push(a.unwrap());
    }
    assert!(answers.iter().all(|a| a == &answers[0]), "unknown login, wrong password, wrong case: the answers must be identical");
    assert!(answers[0].payload.is_empty(), "the refusal carries no hint");
}

#[tokio::test]
async fn l3_three_attempts_per_connection_then_the_door_closes_even_for_the_right_password() {
    let r = rig("exec,root").await;
    let (mut s, sec) = raw(&r).await;
    for _ in 0..3 {
        assert!(fail(&raw_login(&mut s, &sec, "anna", b"nope nope nope").await));
    }
    assert!(!ok(&raw_login(&mut s, &sec, "anna", PW).await), "a fourth attempt on the same connection is not looked at");
}

#[tokio::test]
async fn l4_brute_force_is_locked_out_and_the_lock_ends_by_itself() {
    let r = rig_with("exec,root", |c| c.with_lock(4, Duration::from_millis(1500), Duration::from_secs(3))).await;
    for _ in 0..4 {
        let (mut s, sec) = raw(&r).await;
        assert!(fail(&raw_login(&mut s, &sec, "anna", b"guess guess").await));
    }
    let (mut s, sec) = raw(&r).await;
    assert!(!ok(&raw_login(&mut s, &sec, "anna", PW).await), "locked: even the right password must not pass");
    tokio::time::sleep(Duration::from_millis(1800)).await;
    let (mut s, sec) = raw(&r).await;
    assert!(ok(&raw_login(&mut s, &sec, "anna", PW).await), "the lock expired");
    // a success wipes the record: four more failures are needed again
    for _ in 0..3 {
        let (mut s, sec) = raw(&r).await;
        assert!(fail(&raw_login(&mut s, &sec, "anna", b"guess guess").await));
    }
    let (mut s, sec) = raw(&r).await;
    assert!(ok(&raw_login(&mut s, &sec, "anna", PW).await), "3 failures after a success are below the limit of 4");
}

#[tokio::test]
async fn l5_the_lock_doubles_and_is_capped() {
    let t = Throttle::new(2, Duration::from_millis(100), Duration::from_millis(400));
    t.fail("a");
    assert!(!t.locked("a"));
    t.fail("a");
    assert!(t.locked("a"));
    for _ in 0..40 {
        t.fail("a"); // would overflow a naive shift
    }
    tokio::time::sleep(Duration::from_millis(450)).await;
    assert!(!t.locked("a"), "never longer than the cap");
    assert!(!t.locked("b"), "other keys are not touched");
}

#[tokio::test]
async fn l6_the_throttle_table_stays_bounded() {
    let t = Throttle::new(1, Duration::from_secs(60), Duration::from_secs(60));
    for i in 0..10_000 {
        t.fail(&format!("ip:{i}"));
    }
    assert!(t.len() <= 4096, "{} entries", t.len());
    assert!(t.locked("ip:0"), "what was recorded stays");
}

#[tokio::test]
async fn l7_unknown_and_known_logins_cost_the_same_time() {
    let r = rig_with("exec", |c| c.with_lock(1000, Duration::from_secs(1), Duration::from_secs(1))).await;
    let time = |login: &'static str| {
        let addr = r.addr.clone();
        let (client, sp) = (r.client.clone(), r.server_pub.clone());
        async move {
            let mut v = vec![];
            for _ in 0..9 {
                let mut s = TcpStream::connect(&addr).await.unwrap();
                let sec = yrl::session::client_handshake_context(&mut s, &client, &sp, yrl::session::REKEY_EVERY, yrl::crypto_profile::Context::Gatekeeper, yrl::crypto_profile::Policy::default()).await.unwrap();
                let t = Instant::now();
                raw_login(&mut s, &sec, login, b"wrong password").await;
                v.push(t.elapsed());
            }
            v.sort();
            v[4]
        }
    };
    let (known, unknown) = (time("anna").await, time("nobody-here").await);
    let ratio = known.as_secs_f64() / unknown.as_secs_f64();
    assert!((0.5..2.0).contains(&ratio), "known {known:?} vs unknown {unknown:?}: the time gives the existence of a login away");
}

#[tokio::test]
async fn l8_rights_come_from_the_server_and_are_cut_by_the_key() {
    // key may only exec; anna's account says exec+root: the session gets exec
    let r = rig("exec").await;
    let c = Client::connect_pinned(&r.addr, &r.client, &r.server_pub, &r.exec_pub, T).await.unwrap();
    assert_eq!(c.login("anna", PW, T).await.unwrap(), vec!["exec".to_string()]);
    // an account without rights: logged in, but nothing may be run
    let c = Client::connect_pinned(&r.addr, &r.client, &r.server_pub, &r.exec_pub, T).await.unwrap();
    assert!(c.login("guest", b"guest-password", T).await.unwrap().is_empty());
    let res = c.exec(&[b"true"], 1000, T).await.unwrap();
    assert_eq!(res.error.map(|e| e.0), Some(1));
    // key with both rights: both
    let r2 = rig("exec,root").await;
    let c = Client::connect_pinned(&r2.addr, &r2.client, &r2.server_pub, &r2.exec_pub, T).await.unwrap();
    let mut got = c.login("anna", PW, T).await.unwrap();
    got.sort();
    assert_eq!(got, vec!["exec".to_string(), "root".to_string()]);
}

#[tokio::test]
async fn l9_a_client_cannot_add_rights_to_the_login_message() {
    let r = rig("exec,root").await;
    for payload in [
        [&[4u8][..], b"anna", &(PW.len() as u16).to_be_bytes(), PW, b",root"].concat(), // trailing bytes
        [&[4u8][..], b"anna", &(PW.len() as u16 + 5).to_be_bytes(), PW].concat(),       // a length that lies
        [&[255u8][..], &[b'a'; 255], &0u16.to_be_bytes()].concat(),                    // login too long
        [&[4u8][..], b"anna", &u16::MAX.to_be_bytes(), &vec![0u8; 500]].concat(),       // password too long
        vec![0, 0, 0],                                                                  // empty login
        vec![4, b'a'],                                                                  // cut
        vec![],
    ] {
        let (mut s, sec) = raw(&r).await;
        send(&mut s, &sec, Frame::new(wire::LOGIN, 0, payload)).await;
        assert!(!ok(&recv(&mut s, &sec).await));
    }
    assert!(wire::encode_login(&[b'a'; 65], b"x").is_err() && wire::encode_login(b"a", &[0; 257]).is_err() && wire::encode_login(b"", b"x").is_err());
}

#[tokio::test]
async fn l10_a_recorded_login_is_useless_on_another_connection_and_in_the_same_one() {
    let r = rig("exec,root").await;
    let (mut s, sec) = raw(&r).await;
    let login_msg = sec.seal(&Frame::new(wire::LOGIN, 0, wire::encode_login(b"anna", PW).unwrap())).unwrap();
    yrl::session::write_msg(&mut s, &login_msg).await.unwrap();
    assert!(ok(&recv(&mut s, &sec).await));
    assert_eq!(recv(&mut s, &sec).await.map(|f| f.kind), Some(yrl::link::SESSION), "the session opens right after the login");
    // the same bytes again in the same session
    yrl::session::write_msg(&mut s, &login_msg).await.unwrap();
    assert!(recv(&mut s, &sec).await.is_none(), "replay inside the session");
    // the same bytes in a brand new session
    let (mut s2, sec2) = raw(&r).await;
    yrl::session::write_msg(&mut s2, &login_msg).await.unwrap();
    assert!(!ok(&recv(&mut s2, &sec2).await), "replay into another session");
}

#[tokio::test]
async fn l11_a_connection_that_never_logs_in_is_cut() {
    let r = rig_with("exec", |mut c| { c.login_timeout = Duration::from_millis(500); c }).await;
    let (mut s, _sec) = raw(&r).await;
    let t = Instant::now();
    let mut b = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut b)).await.expect("must be closed by the server").unwrap_or(0);
    assert_eq!(n, 0);
    assert!(t.elapsed() < Duration::from_millis(2500));
}

#[tokio::test]
async fn l12_a_second_login_inside_a_session_ends_it() {
    let r = rig("exec,root").await;
    let (mut s, sec) = raw(&r).await;
    assert!(ok(&raw_login(&mut s, &sec, "anna", PW).await));
    assert!(raw_login(&mut s, &sec, "guest", b"guest-password").await.is_none(), "no switching of identity in a live session");
    send(&mut s, &sec, Frame::new(wire::PING, 0, b"x".to_vec())).await;
    assert!(recv(&mut s, &sec).await.is_none(), "the session is over after a second login, not just unanswered");
}

#[tokio::test]
async fn l13_account_changes_act_at_once_and_a_readable_users_file_means_no_accounts() {
    use std::os::unix::fs::PermissionsExt;
    let r = rig("exec").await;
    let users = r.server_dir().join("users");
    let (mut s, sec) = raw(&r).await;
    assert!(ok(&raw_login(&mut s, &sec, "anna", PW).await));
    yrl::users::set_user(&users, "anna", "exec", b"a brand new password").unwrap();
    let (mut s, sec) = raw(&r).await;
    assert!(!ok(&raw_login(&mut s, &sec, "anna", PW).await), "the old password is dead at once");
    let (mut s, sec) = raw(&r).await;
    assert!(ok(&raw_login(&mut s, &sec, "anna", b"a brand new password").await));
    std::fs::set_permissions(&users, std::fs::Permissions::from_mode(0o644)).unwrap();
    let (mut s, sec) = raw(&r).await;
    assert!(!ok(&raw_login(&mut s, &sec, "anna", b"a brand new password").await), "a users file open to others is not trusted at all");
    std::fs::set_permissions(&users, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&users, "# empty\n").unwrap();
    std::fs::set_permissions(&users, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (mut s, sec) = raw(&r).await;
    assert!(!ok(&raw_login(&mut s, &sec, "anna", b"a brand new password").await), "removed account");
}

#[test]
fn l14_account_file_rules() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("users");
    assert!(yrl::users::set_user(&f, "bob", "exec", b"short").is_err(), "short password");
    assert!(yrl::users::set_user(&f, "b ob", "exec", b"long enough pw").is_err(), "space in a login");
    assert!(yrl::users::set_user(&f, "#bob", "exec", b"long enough pw").is_err(), "comment sign");
    assert!(yrl::users::set_user(&f, "bob", "ex ec", b"long enough pw").is_err());
    assert!(yrl::users::set_user(&f, "bob", "exec", &[b'x'; 300]).is_err(), "longer than the wire allows");
    yrl::users::set_user(&f, "bob", "exec", b"long enough pw").unwrap();
    yrl::users::set_user(&f, "bob", "-", b"another long pw").unwrap();
    assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600);
    let u = yrl::users::read_users(&f);
    assert_eq!(u.len(), 1, "same login replaces");
    assert!(u[0].rights.is_empty());
    assert!(u[0].phc.starts_with("$argon2id$") && !u[0].phc.contains("another long pw"));
    assert!(yrl::users::verify_hash(&u[0].phc, b"another long pw") && !yrl::users::verify_hash(&u[0].phc, b"long enough pw"));
    // damaged lines are skipped, not trusted
    let mut text = std::fs::read_to_string(&f).unwrap();
    text.push_str("eve exec plaintext-password\nmal exec\n\nx y z w\n");
    std::fs::write(&f, text).unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(yrl::users::read_users(&f).len(), 1);
    assert!(!yrl::users::verify_hash("not a hash", b"x") && !yrl::users::verify_hash("", b""));
}

#[tokio::test]
async fn l15_passwords_and_typed_logins_never_reach_the_log() {
    let r = rig_with("exec", |c| c.with_lock(1000, Duration::from_secs(1), Duration::from_secs(1))).await;
    let typed_pw = b"hunter2-typed-in-the-login-field";
    for (l, p) in [("anna", &b"definitely-wrong"[..]), ("typo-login-xyz", typed_pw), ("anna", PW)] {
        let (mut s, sec) = raw(&r).await;
        raw_login(&mut s, &sec, l, p).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let log = r.log.lock().unwrap().join("\n");
    let hash = yrl::users::read_users(&r.server_dir().join("users"))[0].phc.clone();
    for secret in ["definitely-wrong", "typo-login-xyz", "hunter2", "correct horse", "argon2", &hash] {
        assert!(!log.contains(secret), "the log leaked {secret:?}");
    }
    assert!(log.contains("login failed") && log.contains("login ok"));
}

#[tokio::test]
async fn l16_too_many_connections_are_dropped_and_the_slots_come_back() {
    let r = rig_with("exec", |mut c| { c.conn_slots = std::sync::Arc::new(tokio::sync::Semaphore::new(3)); c }).await;
    let mut hold = vec![];
    for _ in 0..3 {
        hold.push(TcpStream::connect(&r.addr).await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut extra = TcpStream::connect(&r.addr).await.unwrap();
    let mut b = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_millis(250), extra.read(&mut b)).await.expect("dropped at once, not after the handshake timeout").unwrap_or(0);
    assert_eq!(n, 0);
    drop(hold);
    tokio::time::sleep(Duration::from_millis(600)).await; // idle ones are cut by the handshake timeout / closed by the peer
    let c = open(&r).await;
    assert!(c.ping(b"back", T).await.is_ok(), "the slots were freed");
}

#[tokio::test]
async fn l17_the_wrong_key_with_the_right_password_gets_silence() {
    let r = rig("exec").await;
    let stranger = yrl::keys::generate();
    let mut s = TcpStream::connect(&r.addr).await.unwrap();
    assert!(yrl::session::client_handshake_context(&mut s, &stranger, &r.server_pub, yrl::session::REKEY_EVERY, yrl::crypto_profile::Context::Gatekeeper, yrl::crypto_profile::Policy::default()).await.is_err(), "the password is worthless without the key");
}

#[tokio::test]
async fn l18_fuzz_random_frames_after_the_login_never_hurt_the_server() {
    let r = rig("exec,root").await;
    let mut x = 0x9E3779B97F4A7C15u64;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    for round in 0..40 {
        let (mut s, sec) = raw(&r).await;
        if round % 2 == 0 {
            raw_login(&mut s, &sec, "anna", PW).await;
        }
        for _ in 0..30 {
            let len = (rnd() % 300) as usize;
            let payload: Vec<u8> = (0..len).map(|_| rnd() as u8).collect();
            send(&mut s, &sec, Frame::new((rnd() % 14) as u8, rnd() as u32, payload)).await;
        }
    }
    // raw garbage on the wire too, in the shape of a message: [u16 len][bytes]
    for _ in 0..60 {
        let mut s = TcpStream::connect(&r.addr).await.unwrap();
        let len = (rnd() % 200) as usize;
        let mut m = (len as u16).to_be_bytes().to_vec();
        m.extend((0..len).map(|_| rnd() as u8));
        let _ = tokio::io::AsyncWriteExt::write_all(&mut s, &m).await;
    }
    let c = open(&r).await;
    assert_eq!(c.exec(&[b"echo", b"alive"], 5000, T).await.unwrap().stdout, b"alive\n");
}

#[test]
fn l19_login_frame_codec_never_panics_and_roundtrips() {
    let mut x = 12345u64;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    for _ in 0..20_000 {
        let n = (rnd() % 400) as usize;
        let b: Vec<u8> = (0..n).map(|_| rnd() as u8).collect();
        let _ = wire::decode_login(&b);
    }
    for (l, p) in [(&b"a"[..], &b""[..]), (b"anna", b"pw"), (&[b'z'; 64], &[7u8; 256]), ("жук".as_bytes(), "пароль".as_bytes())] {
        let e = wire::encode_login(l, p).unwrap();
        assert_eq!(wire::decode_login(&e).unwrap(), (l, p));
    }
}

#[tokio::test]
async fn l20_only_the_login_kind_counts_as_a_login() {
    let r = rig("exec,root").await;
    let valid = wire::encode_login(b"anna", PW).unwrap();
    for kind in [wire::PING, wire::EXEC_REQ, wire::LOGIN_OK, wire::CLOSE, 0xFF] {
        let (mut s, sec) = raw(&r).await;
        send(&mut s, &sec, Frame::new(kind, 0, valid.clone())).await;
        assert!(!ok(&recv(&mut s, &sec).await), "kind {kind} with a perfectly valid login inside is not a login");
        send(&mut s, &sec, Frame::new(wire::PING, 0, b"x".to_vec())).await;
        assert!(recv(&mut s, &sec).await.is_none());
    }
}

async fn raw_from(r: &Rig, key: &yrl::keys::KeyPair, source: &str) -> (tokio::io::DuplexStream, yrl::session::Secure) {
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind(format!("{source}:0").parse().unwrap()).unwrap();
    let mut outer = sock.connect(r.addr.parse().unwrap()).await.unwrap();
    let gate = std::sync::Arc::new(yrl::session::client_handshake_context(&mut outer, key, &r.server_pub, yrl::session::REKEY_EVERY, yrl::crypto_profile::Context::Gatekeeper, yrl::crypto_profile::Policy::default()).await.unwrap());
    let (mut rd, mut wr) = tokio::io::split(outer);
    yrl::session::write_msg(&mut wr, &gate.seal(&Frame::new(yrl::ipc::IPC_TUNNEL, 0, vec![])).unwrap()).await.unwrap();
    assert_eq!(gate.open(&yrl::session::read_msg(&mut rd).await.unwrap()).unwrap().kind, yrl::ipc::IPC_TUNNEL_OK);
    let mut s = yrl::ipc::secure_tunnel(rd, wr, gate);
    let sec = yrl::session::client_handshake_context(&mut s, key, &r.exec_pub, yrl::session::REKEY_EVERY, yrl::crypto_profile::Context::Executor, yrl::crypto_profile::Policy::default()).await.unwrap();
    (s, sec)
}

#[tokio::test]
async fn l21_the_lock_follows_the_key_and_the_address_separately() {
    let r = rig_with("exec,root", |c| c.with_lock(3, Duration::from_secs(30), Duration::from_secs(60))).await;
    let other = yrl::keys::generate();
    yrl::keys::authorize(&r.server_dir().join("authorized_keys"), &hex::encode(&other.public), "second", "exec,root").unwrap();
    for _ in 0..3 {
        let (mut s, sec) = raw_from(&r, &r.client, "127.0.0.1").await;
        assert!(fail(&raw_login(&mut s, &sec, "anna", b"guess guess").await));
    }
    let (mut s, sec) = raw_from(&r, &r.client, "127.0.0.2").await;
    assert!(!ok(&raw_login(&mut s, &sec, "anna", PW).await), "the same key from a new address stays locked");
    let (mut s, sec) = raw_from(&r, &other, "127.0.0.1").await;
    assert!(!ok(&raw_login(&mut s, &sec, "anna", PW).await), "another key from the locked address is locked too");
    let (mut s, sec) = raw_from(&r, &other, "127.0.0.2").await;
    assert!(ok(&raw_login(&mut s, &sec, "anna", PW).await), "another key from another address is untouched");
}

#[tokio::test]
async fn l22_expired_locks_make_room_in_a_full_table() {
    let t = Throttle::new(1, Duration::from_millis(1), Duration::from_millis(1));
    for i in 0..4096 {
        t.fail(&format!("k{i}"));
    }
    tokio::time::sleep(Duration::from_millis(20)).await;
    let big = Throttle::new(1, Duration::from_secs(60), Duration::from_secs(60));
    t.fail("fresh");
    assert_eq!(t.len(), 1, "the 4096 expired entries were dropped");
    big.fail("x");
    assert!(big.locked("x"));
}

#[test]
fn l23_login_codec_edges() {
    let good = wire::encode_login(b"anna", b"pw").unwrap();
    let mut extra = good.clone();
    extra.push(0);
    assert_eq!(wire::decode_login(&extra), Err(wire::WireError::Malformed), "a trailing byte");
    assert_eq!(wire::decode_login(&good[..good.len() - 1]), Err(wire::WireError::Malformed), "cut by one byte");
    assert_eq!(wire::decode_login(&[0, 0, 0]), Err(wire::WireError::TooLarge), "empty login");
    assert_eq!(wire::decode_login(&[65, 0]), Err(wire::WireError::TooLarge), "login of 65");
    let mut big = vec![1u8, b'a'];
    big.extend_from_slice(&257u16.to_be_bytes());
    big.extend(vec![0u8; 257]);
    assert_eq!(wire::decode_login(&big), Err(wire::WireError::TooLarge), "password of 257 with an exact length");
    let mut max = vec![1u8, b'a'];
    max.extend_from_slice(&256u16.to_be_bytes());
    max.extend(vec![0u8; 256]);
    assert!(wire::decode_login(&max).is_ok(), "256 is allowed");
}
