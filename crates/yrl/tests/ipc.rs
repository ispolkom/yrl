//! The border between the gatekeeper and the executor (docs/THREATS.md, section G).
//! The principle every test here serves: a gatekeeper that has been completely taken over can annoy and cut connections, but it cannot make the executor do more than
//! an account AND a key already allow, cannot choose the system user, and cannot be replaced by some other program on the machine.
mod common;
use common::*;
use std::path::PathBuf;
use std::time::Duration;
use yrl::executor::{open_session, serve_ipc};
use yrl::ipc::{self, ExecutorIpc, GatekeeperIpc, Peer, PeerVerdict};
use yrl::wire::{self, Frame};

const W: Duration = Duration::from_secs(20);

async fn next(from: &mut tokio::sync::mpsc::Receiver<Frame>) -> Frame {
    tokio::time::timeout(W, from.recv()).await.unwrap().unwrap()
}

fn rights(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// an executor of its own on a socket of its own, using the account files of a rig; the test plays the gatekeeper
async fn executor_of(r: &Rig, tweak: impl FnOnce(&mut ExecutorIpc)) -> (GatekeeperIpc, ExecutorIpc) {
    let (mut e, g) = ipc::ephemeral(r.dir.path().join("test-ipc.sock"), None);
    tweak(&mut e);
    let l = ipc::bind_socket(&e.socket).unwrap();
    let mut cfg = r.cfg.clone();
    cfg.helper = PathBuf::from(env!("CARGO_BIN_EXE_yrld"));
    tokio::spawn(serve_ipc(l, cfg, e.clone()));
    (g, e)
}

#[test]
fn g1_the_kernels_word_about_the_other_process_is_judged() {
    let (mut e, _) = ipc::ephemeral(PathBuf::from("/tmp/x.sock"), None);
    e.expected_uid = Some(1000);
    e.expected_exe = Some(PathBuf::from("/usr/sbin/yrld"));
    let exe = |p: i32| if p == 7 { Some(PathBuf::from("/usr/sbin/yrld")) } else if p == 8 { Some(PathBuf::from("/tmp/evil/yrld")) } else { None };
    assert_eq!(ipc::judge_peer(&e, &Peer { uid: 1000, pid: Some(7) }, exe), PeerVerdict::Ok);
    assert_eq!(ipc::judge_peer(&e, &Peer { uid: 1001, pid: Some(7) }, exe), PeerVerdict::WrongUser);
    assert_eq!(ipc::judge_peer(&e, &Peer { uid: 0, pid: Some(7) }, exe), PeerVerdict::WrongUser, "even root is not the gatekeeper's user");
    assert_eq!(ipc::judge_peer(&e, &Peer { uid: 1000, pid: Some(8) }, exe), PeerVerdict::WrongProgram, "the right user with another program");
    assert_eq!(ipc::judge_peer(&e, &Peer { uid: 1000, pid: Some(9) }, exe), PeerVerdict::Unknown, "a process whose program cannot be found");
    assert_eq!(ipc::judge_peer(&e, &Peer { uid: 1000, pid: None }, exe), PeerVerdict::Unknown, "no pid at all");
    e.expected_exe = None;
    assert_eq!(ipc::judge_peer(&e, &Peer { uid: 1000, pid: None }, exe), PeerVerdict::Ok, "the program is checked only when asked for");
    e.expected_uid = None;
    assert_eq!(ipc::judge_peer(&e, &Peer { uid: 4242, pid: None }, exe), PeerVerdict::Ok);
}

#[test]
fn g2_the_socket_is_private_and_its_place_is_safe() {
    use std::os::unix::fs::PermissionsExt;
    assert!(ipc::socket_mode_ok(0o600) && ipc::socket_mode_ok(0o660) && !ipc::socket_mode_ok(0o666) && !ipc::socket_mode_ok(0o602) && !ipc::socket_mode_ok(0o604));
    let d = tempfile::tempdir().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let _g = rt.enter();
    let sock = d.path().join("a.sock");
    let _l = ipc::bind_socket(&sock).unwrap();
    assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o600);
    // a stale socket of an earlier run is replaced; a file that is not a socket is never touched
    drop(_l);
    let _l2 = ipc::bind_socket(&sock).unwrap();
    let plain = d.path().join("plain");
    std::fs::write(&plain, b"precious").unwrap();
    assert!(ipc::bind_socket(&plain).is_err());
    assert_eq!(std::fs::read(&plain).unwrap(), b"precious");
    // a directory that others can write to could have its socket swapped
    let open_dir = d.path().join("open");
    std::fs::create_dir(&open_dir).unwrap();
    std::fs::set_permissions(&open_dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(ipc::bind_socket(&open_dir.join("s.sock")).is_err());
    std::fs::set_permissions(&open_dir, std::fs::Permissions::from_mode(0o775)).unwrap();
    assert!(ipc::bind_socket(&open_dir.join("s.sock")).is_err(), "group-writable too");
}

#[tokio::test]
async fn g3_only_the_gatekeeper_with_the_key_set_up_for_it_gets_in() {
    let r = rig("exec,shell").await;
    let (g, _e) = executor_of(&r, |_| {}).await;
    assert!(yrl::executor::open_tunnel(&g, None).await.is_some(), "the real gatekeeper gets a carrier tunnel");
    let impostor = GatekeeperIpc { key: yrl::keys::generate(), ..g.clone() };
    assert!(yrl::executor::open_tunnel(&impostor, None).await.is_none(), "a program with another key does not");
    let wrong_executor = GatekeeperIpc { executor_public: yrl::keys::generate().public, ..g.clone() };
    assert!(yrl::executor::open_tunnel(&wrong_executor, None).await.is_none(), "and a gatekeeper does not talk to a fake executor either");
    assert!(r.log.lock().unwrap().iter().any(|l| l.contains("handshake")));
}

#[tokio::test]
async fn g4_the_program_and_the_user_on_the_other_end_must_be_the_expected_ones() {
    let r = rig("exec,shell").await;
    // right key, wrong program
    let (g, _e) = executor_of(&r, |e| e.expected_exe = Some(PathBuf::from("/bin/true"))).await;
    assert!(yrl::executor::open_tunnel(&g, None).await.is_none());
    assert!(r.log.lock().unwrap().iter().any(|l| l.contains("WrongProgram")), "{:?}", r.log.lock().unwrap());
    // right key, wrong user
    let me = unsafe { libc::geteuid() };
    let r2 = rig("exec,shell").await;
    let (g2, _e2) = executor_of(&r2, |e| e.expected_uid = Some(me + 1)).await;
    assert!(yrl::executor::open_tunnel(&g2, None).await.is_none());
    assert!(r2.log.lock().unwrap().iter().any(|l| l.contains("WrongUser")));
    // the right program and user pass (here: this very test program)
    let r3 = rig("exec,shell").await;
    let (g3, _e3) = executor_of(&r3, |e| {
        e.expected_uid = Some(me);
        e.expected_exe = Some(std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap());
    })
    .await;
    assert!(yrl::executor::open_tunnel(&g3, None).await.is_some());
}

#[tokio::test]
async fn g5_a_request_for_more_than_the_files_allow_is_refused() {
    let r = rig("exec,shell").await; // the key has exec and shell; anna has exec, root, shell, files, tunnel
    let (g, _e) = executor_of(&r, |_| {}).await;
    let ask = |key: Vec<u8>, who: &'static str, want: Vec<String>| {
        let g = g.clone();
        async move { open_session(&g, &key, who, &want).await.is_some() }
    };
    assert!(!ask(r.client.public.clone(), "anna", rights(&["exec"])).await, "even a truthful Gatekeeper assertion is not an authentication mechanism");
    assert!(!ask(r.client.public.clone(), "anna", rights(&["exec", "shell"])).await);
    assert!(!ask(r.client.public.clone(), "anna", rights(&[])).await);
    assert!(!ask(r.client.public.clone(), "anna", rights(&["root"])).await, "anna has root, the KEY does not");
    assert!(!ask(r.client.public.clone(), "anna", rights(&["exec", "files"])).await, "anna has files, the key does not");
    assert!(!ask(r.client.public.clone(), "guest", rights(&["exec"])).await, "the key has exec, guest does not");
    assert!(!ask(r.client.public.clone(), "nobody", rights(&[])).await, "an account that does not exist");
    assert!(!ask(yrl::keys::generate().public, "anna", rights(&["exec"])).await, "a key that is not authorized");
    assert!(!ask(r.client.public.clone(), "anna", rights(&["exec", "made-up-right"])).await);
    assert!(!ask(vec![1; 5], "anna", rights(&[])).await, "a malformed request");
}

#[tokio::test]
async fn g6_the_gatekeeper_cannot_pick_the_system_user() {
    // an account bound to another system user: a server that is not root cannot give it, whatever the gatekeeper wishes
    let r = rig("exec,shell").await;
    yrl::users::set_user_os(&r.server_dir().join("users"), "bound", "exec", Some("daemon"), b"some good password").unwrap();
    let (g, _e) = executor_of(&r, |_| {}).await;
    if unsafe { libc::geteuid() } != 0 {
        assert!(open_session(&g, &r.client.public, "bound", &rights(&["exec"])).await.is_none());
        assert!(r.log.lock().unwrap().iter().any(|l| l.contains("no tunnel request")), "legacy identity assertions are rejected before account resolution");
    }
    // through the whole server the same refusal reaches the client as an ordinary failed login, not as silence
    if unsafe { libc::geteuid() } != 0 {
        let r2 = rig("exec,shell").await;
        yrl::users::set_user_os(&r2.server_dir().join("users"), "bound", "exec", Some("daemon"), PW).unwrap();
        let (mut s, sec) = raw(&r2).await;
        let f = raw_login(&mut s, &sec, "bound", PW).await;
        assert_eq!(f.map(|f| f.kind), Some(wire::LOGIN_FAIL));
    }
    // and the request has no field in which a user could be named
    let f = ipc::encode_open(&r.client.public, "anna", &rights(&["exec"])).unwrap();
    assert_eq!(f.len(), 32 + 1 + 4 + 2 + 4);
}

#[tokio::test]
async fn g7_what_a_session_may_do_is_what_was_granted_not_what_the_gatekeeper_sends() {
    let r = rig("exec").await;
    let (g, _e) = executor_of(&r, |_| {}).await;
    assert!(open_session(&g, &r.client.public, "anna", &rights(&["exec", "shell", "files"])).await.is_none());
    let c = open(&r).await;
    assert_eq!(c.exec(&[b"echo", b"e2e"], 5000, W).await.unwrap().stdout, b"e2e\n");
    let mut p = c.pty_open(24, 80, "xterm").await.unwrap();
    assert!(matches!(tokio::time::timeout(W, p.next()).await.unwrap(), yrl::client::PtyEvent::Error(1, _)), "Executor applies the authenticated key/account intersection, not Gatekeeper assertions");
}

#[tokio::test]
async fn g8_a_door_with_nothing_behind_it_for_bad_manners() {
    use tokio::net::UnixStream;
    let r = rig("exec").await;
    let (g, e) = executor_of(&r, |_| {}).await;
    // garbage instead of a handshake, an empty connection, a handshake that is right but whose first message is not an open
    for junk in [vec![], vec![0u8; 3], vec![0xff; 2000], b"GET / HTTP/1.0\r\n\r\n".to_vec()] {
        let mut s = UnixStream::connect(&e.socket).await.unwrap();
        let _ = tokio::io::AsyncWriteExt::write_all(&mut s, &junk).await;
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(7), tokio::io::AsyncReadExt::read_to_end(&mut s, &mut out)).await;
        assert!(out.is_empty(), "no answer to junk");
    }
    let mut s = UnixStream::connect(&e.socket).await.unwrap();
    let sec = yrl::session::client_handshake(&mut s, &g.key, &g.executor_public, yrl::session::REKEY_EVERY).await.unwrap();
    yrl::session::write_msg(&mut s, &sec.seal(&Frame::new(wire::PING, 0, vec![])).unwrap()).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(7), yrl::session::read_msg(&mut s)).await.unwrap();
    assert!(r.is_err(), "a first message that is not an open request closes the connection");
    assert!(open_session(&g, &[0u8; 32], "anna", &[]).await.is_none());
}

#[test]
fn g9_the_open_request_is_exact() {
    let ok = ipc::encode_open(&[7u8; 32], "anna", &rights(&["exec", "shell"])).unwrap();
    assert_eq!(ipc::decode_open(&ok).unwrap(), (vec![7u8; 32], "anna".to_string(), rights(&["exec", "shell"])));
    let mut longer = ok.clone();
    longer.push(b'x');
    assert!(ipc::decode_open(&longer).is_err() && ipc::decode_open(&ok[..ok.len() - 1]).is_err());
    assert!(ipc::encode_open(&[1; 31], "a", &[]).is_err() && ipc::encode_open(&[1; 32], "", &[]).is_err() && ipc::encode_open(&[1; 32], &"a".repeat(65), &[]).is_err());
    let mut bad_right = ipc::encode_open(&[1; 32], "a", &rights(&["ex;ec"])).unwrap();
    assert!(ipc::decode_open(&bad_right).is_err(), "a right is a plain word");
    bad_right.clear();
    let mut x = 5u64;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    for _ in 0..30_000 {
        let b: Vec<u8> = (0..(rnd() % 90) as usize).map(|_| rnd() as u8).collect();
        let _ = ipc::decode_open(&b);
    }
}

#[test]
fn g10_the_keys_of_the_local_door_are_made_once_and_kept_private() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    assert!(ipc::load_executor(d.path(), None, None).is_err() && ipc::load_gatekeeper(d.path()).is_err(), "nothing is invented when the keys were not set up");
    ipc::init_keys(d.path()).unwrap();
    for side in ["executor", "gatekeeper"] {
        let key = d.path().join("ipc").join(side).join("static.key");
        assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let e = ipc::load_executor(d.path(), None, None).unwrap();
    let g = ipc::load_gatekeeper(d.path()).unwrap();
    assert_eq!(e.gatekeeper_public, g.key.public);
    assert_eq!(g.executor_public, e.key.public);
    assert!(ipc::init_keys(d.path()).is_err(), "existing keys are never replaced");
    std::fs::write(d.path().join("ipc/gatekeeper.pub"), "abcd").unwrap();
    assert!(ipc::load_executor(d.path(), None, None).is_err(), "a damaged public key is refused");
}

// ---------------------------------------------------------------- two real processes

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
async fn g11_the_gatekeeper_and_the_executor_as_two_separate_programs() {
    use std::process::{Command, Stdio};
    let dir = tempfile::tempdir().unwrap();
    let sd = dir.path().join("srv");
    let yrld = env!("CARGO_BIN_EXE_yrld");
    assert!(Command::new(yrld).args(["init", sd.to_str().unwrap()]).stdout(Stdio::null()).status().unwrap().success());
    let server_pub = hex::decode(std::fs::read_to_string(sd.join("static.key")).unwrap().lines().nth(1).unwrap().trim()).unwrap();
    let executor_pub = hex::decode(std::fs::read_to_string(sd.join("ipc/executor.pub")).unwrap().trim()).unwrap();
    let client = yrl::keys::generate();
    yrl::keys::authorize(&sd.join("authorized_keys"), &hex::encode(&client.public), "laptop", "exec").unwrap();
    yrl::users::set_user(&sd.join("users"), "anna", "exec", PW).unwrap();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut procs = Procs(vec![]);
    let mk = |args: &[&str]| Command::new(yrld).args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    procs.0.push(mk(&["executor", sd.to_str().unwrap()]));
    for _ in 0..100 {
        if sd.join("ipc.sock").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    procs.0.push(mk(&["gatekeeper", sd.to_str().unwrap(), &format!("127.0.0.1:{port}")]));
    tokio::time::sleep(Duration::from_millis(600)).await;
    // the running gatekeeper really is behind the wall: the kernel says so
    let status = std::fs::read_to_string(format!("/proc/{}/status", procs.0[1].id())).unwrap();
    assert!(status.contains("NoNewPrivs:\t1") && status.contains("Seccomp:\t2"), "{status}");
    let exec_status = std::fs::read_to_string(format!("/proc/{}/status", procs.0[0].id())).unwrap();
    assert!(exec_status.contains("Seccomp:\t0"), "the executor must NOT be walled in: it has to start programs");
    let addr = format!("127.0.0.1:{port}");
    let c = yrl::client::Client::connect_pinned(&addr, &client, &server_pub, &executor_pub, T).await.unwrap();
    c.login("anna", PW, T).await.unwrap();
    assert_eq!(c.exec(&[b"echo", b"two programs"], 5000, W).await.unwrap().stdout, b"two programs\n");
    // the executor goes away: the session ends, the gatekeeper stays and says no to new logins instead of hanging
    let mut exec_proc = procs.0.remove(0);
    exec_proc.kill().unwrap();
    exec_proc.wait().unwrap();
    assert!(c.exec(&[b"echo", b"x"], 5000, Duration::from_secs(5)).await.is_err(), "nothing is executed without the executor");
    assert!(yrl::client::Client::connect_pinned(&addr, &client, &server_pub, &executor_pub, T).await.is_err(), "no new end-to-end connection without the executor");
    assert!(procs.0[0].try_wait().unwrap().is_none(), "the gatekeeper is still running");
}

#[test]
fn g12_the_wall_around_the_gatekeeper_stops_what_it_never_needs_and_nothing_else() {
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_yrld")).arg("sandbox-selftest").output().unwrap();
    let out = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(o.status.success(), "{out}");
    for want in ["before_exec=true", "nnp=true", "seccomp=2", "exec_after_ok=false", "read=true", "unix=true", "tcp=true", "thread=true", "setuid_blocked=true"] {
        assert!(out.contains(want), "{want} missing in: {out}");
    }
}

/// A local conversation recorded on the way and played back to the executor on a new connection does not open a session: the key of the
/// new handshake is different, so what was recorded cannot be read (the executor says nothing after its handshake answer).
#[tokio::test]
async fn g13_a_recorded_conversation_played_back_opens_nothing() {
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{UnixListener, UnixStream};
    let r = rig("exec,shell").await;
    let (mut g, e) = executor_of(&r, |_| {}).await;
    // a recording relay in front of the executor's door
    let relay_path = r.dir.path().join("relay.sock");
    let listener = UnixListener::bind(&relay_path).unwrap();
    let to_server: Arc<Mutex<Vec<u8>>> = Arc::default();
    let from_server: Arc<Mutex<Vec<u8>>> = Arc::default();
    let (ts, fs, real) = (to_server.clone(), from_server.clone(), e.socket.clone());
    tokio::spawn(async move {
        while let Ok((mut c, _)) = listener.accept().await {
            let Ok(mut s) = UnixStream::connect(&real).await else { continue };
            let (ts, fs) = (ts.clone(), fs.clone());
            tokio::spawn(async move {
                let (mut cr, mut cw) = c.split();
                let (mut sr, mut sw) = s.split();
                let up = async {
                    let mut b = [0u8; 4096];
                    while let Ok(n) = cr.read(&mut b).await {
                        if n == 0 { break; }
                        ts.lock().unwrap().extend_from_slice(&b[..n]);
                        if sw.write_all(&b[..n]).await.is_err() { break; }
                    }
                };
                let down = async {
                    let mut b = [0u8; 4096];
                    while let Ok(n) = sr.read(&mut b).await {
                        if n == 0 { break; }
                        fs.lock().unwrap().extend_from_slice(&b[..n]);
                        if cw.write_all(&b[..n]).await.is_err() { break; }
                    }
                };
                tokio::select! { _ = up => {}, _ = down => {} }
            });
        }
    });
    g.socket = relay_path.clone();
    let session = yrl::executor::open_tunnel(&g, None).await;
    assert!(session.is_some(), "the real conversation works through the relay");
    drop(session);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let recorded = to_server.lock().unwrap().clone();
    let answer = from_server.lock().unwrap().clone();
    assert!(recorded.len() > 40 && answer.len() > 20);
    let first_reply_len = 2 + u16::from_be_bytes([answer[0], answer[1]]) as usize;
    assert!(answer.len() > first_reply_len, "a real conversation has more than the handshake answer");
    // the replay, straight to the executor
    let mut s = UnixStream::connect(&e.socket).await.unwrap();
    s.write_all(&recorded).await.unwrap();
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), s.read_to_end(&mut got)).await;
    assert!(got.len() <= first_reply_len, "after the handshake answer the executor said nothing ({} bytes, the handshake answer is {})", got.len(), first_reply_len);
}

// These two tests describe the required Client <-> Executor boundary.

#[tokio::test]
async fn g14_gatekeeper_impersonation_without_the_client_private_key_or_password_is_refused() {
    let r = rig("exec").await;
    let (gate, _executor) = executor_of(&r, |_| {}).await;

    // A captured gatekeeper needs only public configuration. It neither performs a client Noise
    // handshake nor knows the account password, yet the current Executor accepts its assertion.
    let claimed_public = yrl::keys::read_authorized(&r.server_dir().join("authorized_keys"))[0].public.clone();
    let forged = open_session(&gate, &claimed_public, "anna", &rights(&["exec"])).await;
    assert!(forged.is_none(), "Executor accepted an asserted identity without end-to-end proof of the client private key or password");
}

#[tokio::test]
async fn g15_gatekeeper_impersonation_cannot_inject_an_exec_operation() {
    let r = rig("exec").await;
    let gate = r.cfg.gate.clone().unwrap();
    let claimed_public = yrl::keys::read_authorized(&r.server_dir().join("authorized_keys"))[0].public.clone();
    let marker = r.dir.path().join("injected-by-gatekeeper");
    let forged = open_session(&gate, &claimed_public, "anna", &rights(&["exec"])).await;
    assert!(forged.is_none(), "Executor opened an operation channel from Gatekeeper assertions");

    // Keep a genuine, authorized session alive. The attacker learns its session id but has only
    // Gatekeeper's private key; neither the client's private key nor its password is available.
    let (mut client, sec) = raw(&r).await;
    send(&mut client, &sec, Frame::new(wire::LOGIN, 0, wire::encode_login(b"anna", PW).unwrap())).await;
    assert_eq!(recv(&mut client, &sec).await.unwrap().kind, wire::LOGIN_OK);
    let session = recv(&mut client, &sec).await.unwrap();
    assert_eq!(session.kind, yrl::link::SESSION);
    sec.raw_mode.store(true, std::sync::atomic::Ordering::SeqCst);

    let request = wire::ExecReq { request_id: 91, timeout_ms: 5_000, argv: vec![b"/usr/bin/touch".to_vec(), marker.as_os_str().as_encoded_bytes().to_vec()] };
    let command = Frame::new(wire::EXEC_REQ, 0, request.encode().unwrap());
    let mut resume = session.payload.clone();
    resume.extend_from_slice(&0u64.to_be_bytes());
    let mut tunnel = yrl::executor::open_tunnel(&gate, None).await.expect("captured Gatekeeper can open IPC_TUNNEL");
    yrl::session::write_msg(&mut tunnel, &Frame::new(yrl::link::RESUME, 0, resume).encode().unwrap()).await.unwrap();
    let _ = yrl::session::write_msg(&mut tunnel, &command.encode().unwrap()).await;
    assert!(tokio::time::timeout(Duration::from_secs(2), yrl::session::read_msg(&mut tunnel)).await.unwrap().is_err(), "plaintext RESUME/command was accepted inside the tunnel");

    // Even a fresh, correctly framed inner Noise handshake signed by Gatekeeper's own key
    // cannot attach to the client's existing session or submit the command.
    let mut tunnel = yrl::executor::open_tunnel(&gate, None).await.unwrap();
    assert!(tokio::time::timeout(Duration::from_secs(2), yrl::session::client_handshake(&mut tunnel, &gate.key, &gate.executor_public, yrl::session::REKEY_EVERY)).await.unwrap().is_err());
    send(&mut client, &sec, Frame::new(wire::PING, 0, b"still-authorized".to_vec())).await;
    assert_eq!(recv(&mut client, &sec).await.unwrap().kind, wire::PONG, "the original session remains usable");
    assert!(!marker.exists(), "Executor ran an operation created by Gatekeeper rather than authenticated end-to-end from Client");
}
