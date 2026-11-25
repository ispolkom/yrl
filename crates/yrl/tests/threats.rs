//! One test per row of docs/THREATS.md (v0.1), plus the happy path and key rotation.
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use yrl::client::Client;
use yrl::keys;
use yrl::server::{serve, ServerConfig};
use yrl::session::{client_handshake, write_msg, REKEY_EVERY};
mod common;
use common::*;
use yrl::wire::{self, ExecReq, Frame};


/// all bytes the server sends to a raw socket before it closes it
async fn drain(mut s: TcpStream) -> Vec<u8> {
    let mut out = vec![];
    let _ = tokio::time::timeout(Duration::from_secs(3), s.read_to_end(&mut out)).await;
    out
}

#[tokio::test]
async fn a_paired_client_can_ping_and_run_a_program_without_a_shell() {
    let r = rig("exec").await;
    let c = open(&r).await;
    assert_eq!(c.ping(b"hello", T).await.unwrap(), b"hello");
    let res = c.exec(&[b"echo", b"hi; echo injected"], 5000, T).await.unwrap();
    assert_eq!((res.stdout.as_slice(), res.code), (&b"hi; echo injected\n"[..], 0), "arguments are passed as they are: no shell, no injection");
    let res = c.exec(&[b"sh", b"-c", b"echo out; echo err 1>&2; exit 3"], 5000, T).await.unwrap();
    assert_eq!((res.stdout, res.stderr, res.code), (b"out\n".to_vec(), b"err\n".to_vec(), 3), "stdout, stderr and the exit code stay separate");
}

#[tokio::test]
async fn t1_garbage_gets_silence() {
    let r = rig("exec").await;
    for payload in [vec![], vec![0u8], vec![0u8, 0, 0], vec![0xFF; 70_000], b"GET / HTTP/1.1\r\n\r\n".to_vec(), vec![0, 5, 1, 2, 3, 4, 5], vec![0xFF, 0xFF, 1]] {
        let mut s = TcpStream::connect(&r.addr).await.unwrap();
        let _ = s.write_all(&payload).await;
        assert!(drain(s).await.is_empty(), "the server must not answer garbage with a single byte");
    }
    let c = open(&r).await;
    assert!(c.ping(b"still alive", T).await.is_ok(), "garbage must not harm the server");
}

#[tokio::test]
async fn t2_unauthorized_client_gets_silence() {
    let r = rig("exec").await;
    let stranger = keys::generate();
    let mut s = TcpStream::connect(&r.addr).await.unwrap();
    assert!(client_handshake(&mut s, &stranger, &r.server_pub, REKEY_EVERY).await.is_err());
    assert!(drain(s).await.is_empty(), "no byte may come back for an unknown key");
}

#[tokio::test]
async fn t3_wrong_server_key_is_refused_by_the_client() {
    let r = rig("exec").await;
    let impostor = keys::generate();
    let res = Client::connect(&r.addr, &r.client, &impostor.public, T).await;
    assert!(res.is_err(), "a client that expects another server key must not complete the handshake");
    // and an impostor SERVER with its own key cannot answer a client that expects the real one
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let fake_addr = l.local_addr().unwrap().to_string();
    let fake_dir = tempfile::tempdir().unwrap();
    let fk = keys::init(&fake_dir.path().join("k")).unwrap();
    keys::authorize(&fake_dir.path().join("k/authorized_keys"), &hex::encode(&r.client.public), "x", "exec").unwrap();
    tokio::spawn(serve(l, fk, ServerConfig::new(fake_dir.path().join("k"))));
    assert!(Client::connect(&fake_addr, &r.client, &r.server_pub, T).await.is_err(), "the impostor has no key that opens the client's first message");
}

#[tokio::test]
async fn t4_tampered_replayed_and_reordered_frames_close_the_session() {
    let r = rig("exec").await;
    let ping = |sec: &yrl::session::Secure| {
        let seq = sec.raw_out.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut p = seq.to_be_bytes().to_vec();
        p.extend(Frame::new(wire::PING, 0, b"x".to_vec()).encode().unwrap());
        sec.seal(&Frame::new(yrl::link::SEQ, 0, p)).unwrap()
    };
    // replay
    let (mut s, sec) = raw(&r).await;
    assert_eq!(raw_login(&mut s, &sec, "anna", PW).await.map(|f| f.kind), Some(wire::LOGIN_OK));
    let m = ping(&sec);
    write_msg(&mut s, &m).await.unwrap();
    assert_eq!(recv(&mut s, &sec).await.map(|f| f.kind), Some(wire::PONG), "the first ping is answered");
    write_msg(&mut s, &m).await.unwrap();
    assert!(recv(&mut s, &sec).await.is_none(), "the same ciphertext again is a replay: the connection ends");
    // tamper
    let (mut s, sec) = raw(&r).await;
    raw_login(&mut s, &sec, "anna", PW).await;
    let mut m = ping(&sec);
    let last = m.len() - 1;
    m[last] ^= 1;
    write_msg(&mut s, &m).await.unwrap();
    assert!(recv(&mut s, &sec).await.is_none());
    // reorder: the second message first
    let (mut s, sec) = raw(&r).await;
    raw_login(&mut s, &sec, "anna", PW).await;
    let (_first, second) = (ping(&sec), ping(&sec));
    write_msg(&mut s, &second).await.unwrap();
    assert!(recv(&mut s, &sec).await.is_none(), "out of order is rejected");
}

#[tokio::test]
async fn t5_wrong_version_is_dropped_silently() {
    let r = rig("exec").await;
    let mut s = TcpStream::connect(&r.addr).await.unwrap();
    let mut hs = snow::Builder::new(keys::PARAMS.parse().unwrap()).local_private_key(&r.client.private).remote_public_key(&r.server_pub).build_initiator().unwrap();
    let mut buf = vec![0u8; 512];
    let n = hs.write_message(b"YRL2\x01", &mut buf).unwrap();
    write_msg(&mut s, &buf[..n]).await.unwrap();
    assert!(drain(s).await.is_empty());
}

#[test]
fn t6_oversized_inputs_are_bounded() {
    let big = ExecReq { request_id: 1, timeout_ms: 1, argv: vec![vec![b'a'; wire::MAX_ARG_LEN + 1]] };
    assert!(big.encode().is_err());
    assert!(ExecReq { request_id: 1, timeout_ms: 1, argv: vec![b"x".to_vec(); wire::MAX_ARGS + 1] }.encode().is_err());
    assert!(ExecReq { request_id: 1, timeout_ms: 1, argv: vec![] }.encode().is_err());
    // a hostile peer declares 65535 arguments of 65535 bytes in 14 bytes of message: refused without allocating
    let mut lie = vec![0u8; 12];
    lie.extend_from_slice(&u16::MAX.to_be_bytes());
    assert_eq!(ExecReq::decode(&lie), Err(wire::WireError::TooLarge));
    let mut lie2 = vec![0u8; 12];
    lie2.extend_from_slice(&1u16.to_be_bytes());
    lie2.extend_from_slice(&u16::MAX.to_be_bytes());
    assert!(ExecReq::decode(&lie2).is_err());
    assert!(Frame::new(wire::STDOUT, 0, vec![0; wire::MAX_FRAME]).encode().is_err());
    assert!(Frame::decode(&vec![0; wire::MAX_FRAME + 1]).is_err());
    // trailing bytes are malformed
    let mut ok = ExecReq { request_id: 1, timeout_ms: 1, argv: vec![b"x".to_vec()] }.encode().unwrap();
    ok.push(0);
    assert_eq!(ExecReq::decode(&ok), Err(wire::WireError::Malformed));
}

#[tokio::test]
async fn t7_a_silent_connection_is_cut_by_the_handshake_timeout() {
    let r = rig("exec").await;
    let mut s = TcpStream::connect(&r.addr).await.unwrap();
    let t = std::time::Instant::now();
    let mut b = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(3), s.read(&mut b)).await.expect("the server must close by itself").unwrap();
    assert_eq!(n, 0);
    assert!(t.elapsed() < Duration::from_secs(2), "closed after the handshake timeout (400 ms here), not left hanging");
}

#[tokio::test]
async fn t8_exec_without_the_right_is_denied_and_nothing_runs() {
    let r = rig("").await;
    let marker = r.dir.path().join("created_by_exec");
    let c = open(&r).await;
    let res = c.exec(&[b"touch", marker.to_str().unwrap().as_bytes()], 5000, T).await.unwrap();
    assert_eq!(res.error.as_ref().map(|e| e.0), Some(1));
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!marker.exists(), "the program must not have been started");
}

#[tokio::test]
async fn t9_exec_timeout_kills_the_program() {
    let r = rig("exec").await;
    let c = open(&r).await;
    let t = std::time::Instant::now();
    let res = c.exec(&[b"sleep", b"30"], 300, T).await.unwrap();
    assert_eq!(res.code, -1);
    assert!(res.error.as_ref().map(|e| e.0) == Some(3));
    assert!(t.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn t10_logs_contain_no_keys_and_no_commands() {
    let r = rig("exec").await;
    {
        let c = open(&r).await;
        let _ = c.exec(&[b"echo", b"top-secret-argument"], 5000, T).await.unwrap();
    }
    let mut s = TcpStream::connect(&r.addr).await.unwrap();
    let _ = s.write_all(&[1, 2, 3]).await;
    drop(s);
    tokio::time::sleep(Duration::from_millis(900)).await;
    let log = r.log.lock().unwrap().join("\n");
    assert!(!log.is_empty());
    for secret in [hex::encode(&r.client.public), hex::encode(&r.client.private), hex::encode(&r.server_pub), "top-secret-argument".to_string()] {
        assert!(!log.contains(&secret), "the log leaked {secret}");
    }
}

#[test]
fn t11_key_files_must_be_private() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("k");
    let kp = keys::init(&dir).unwrap();
    assert_eq!(std::fs::metadata(dir.join("static.key")).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
    assert_eq!(keys::load(&dir).unwrap().public, kp.public);
    std::fs::set_permissions(dir.join("static.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(keys::load(&dir).is_err(), "a key readable by others is refused");
    std::fs::set_permissions(dir.join("static.key"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(keys::load(&dir).is_err(), "a key directory open to others is refused");
    assert!(keys::init(&dir).is_err(), "an existing identity is never replaced");
}

#[tokio::test]
async fn t12_a_revoked_key_is_refused_at_once() {
    let r = rig("exec").await;
    assert!(Client::connect(&r.addr, &r.client, &r.server_pub, T).await.is_ok());
    std::fs::write(r.server_dir().join("authorized_keys"), "# everybody revoked\n").unwrap();
    assert!(Client::connect(&r.addr, &r.client, &r.server_pub, T).await.is_err(), "the removed line acts on the next connection");
}

#[tokio::test]
async fn keys_rotate_every_n_messages_in_step_on_both_sides() {
    let r = rig_with("exec", |mut c| { c.rekey_every = 3; c }).await;
    let c = Client::connect_pinned_with(&r.addr, &r.client, &r.server_pub, &r.exec_pub, T, 3).await.unwrap();
    c.login("anna", PW, T).await.unwrap();
    for i in 0..25u8 {
        assert_eq!(c.ping(&[i], T).await.unwrap(), vec![i], "message {i} after rotations");
    }
}
