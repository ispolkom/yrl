//! Adding a device: a short window opened by the owner on the machine, a code, a fingerprint compared by two people.
mod common;
use common::*;
use std::time::Duration;
use yrl::client::Client;
use yrl::enroll::*;
use yrl::keys;

const W: Duration = Duration::from_secs(20);

fn rights(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

/// the owner's program: waits for a request, checks the fingerprint, answers
async fn owner(dir: std::path::PathBuf, expect_fp: Option<String>, accept: bool, grant: Vec<String>) -> Option<Request> {
    // (like the real program, it closes the window the moment it has answered)
    for _ in 0..200 {
        if let Some(req) = pending_request(&dir) {
            if let Some(fp) = &expect_fp {
                assert_eq!(&fingerprint(&req.public), fp, "the owner sees the fingerprint of the key that really asked");
            }
            decide(&dir, &req, accept, &grant).unwrap();
            close_window(&dir);
            return Some(req);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    None
}

#[tokio::test]
async fn n1_outside_a_window_an_unknown_key_still_gets_silence() {
    let r = rig("exec").await;
    let stranger = keys::generate();
    let mut s = tokio::net::TcpStream::connect(&r.addr).await.unwrap();
    assert!(yrl::session::client_handshake(&mut s, &stranger, &r.server_pub, yrl::session::REKEY_EVERY).await.is_err());
    // a window that ended is the same as none
    open_window(&r.server_dir(), 1, &rights(&["exec"])).unwrap();
    tokio::time::sleep(Duration::from_millis(2200)).await;
    let mut s = tokio::net::TcpStream::connect(&r.addr).await.unwrap();
    assert!(yrl::session::client_handshake(&mut s, &stranger, &r.server_pub, yrl::session::REKEY_EVERY).await.is_err());
}

#[tokio::test]
async fn n2_the_whole_way_a_new_device_is_added_and_can_then_log_in_with_exactly_the_granted_rights() {
    let r = rig("exec").await;
    let dir = r.server_dir();
    let code = open_window(&dir, 60, &rights(&["exec", "files"])).unwrap();
    let phone = keys::generate();
    let o = tokio::spawn(owner(dir.clone(), Some(fingerprint(&phone.public)), true, rights(&["exec", "files"])));
    let c = Client::connect(&r.addr, &phone, &r.server_pub, T).await.unwrap();
    c.enroll(&code, "phone", W).await.unwrap();
    assert_eq!(o.await.unwrap().unwrap().label, "phone");
    close_window(&dir);
    assert!(!dir_of(&dir).join("decision").exists(), "the gatekeeper removed the decision after reading it");
    // the new key is in the list, with exactly those rights
    let list = yrl::keys::read_authorized(&dir.join("authorized_keys"));
    let me = list.iter().find(|a| a.public == phone.public).unwrap();
    assert_eq!((me.label.as_str(), me.rights.clone()), ("phone", rights(&["exec", "files"])));
    // and it logs in as usual, with the account's password; the window is not needed any more
    let c2 = Client::connect(&r.addr, &phone, &r.server_pub, T).await.unwrap();
    assert_eq!(c2.login("anna", PW, T).await.unwrap(), rights(&["exec", "files"]), "rights = account and key; the key has exec and files");
    assert_eq!(c2.exec(&[b"echo", b"enrolled"], 5000, W).await.unwrap().stdout, b"enrolled\n");
}

#[tokio::test]
async fn n3_a_guest_can_do_nothing_but_present_the_code() {
    let r = rig("exec").await;
    let code = open_window(&r.server_dir(), 60, &rights(&["exec"])).unwrap();
    let guest = keys::generate();
    let valid = encode_request(&code, "sneaky").unwrap();
    for f in [yrl::wire::Frame::new(yrl::wire::PING, 0, valid.clone()), yrl::wire::Frame::new(ENROLL_OK, 0, valid.clone()), yrl::wire::Frame::new(yrl::wire::LOGIN, 0, yrl::wire::encode_login(b"anna", PW).unwrap()), yrl::wire::Frame::new(yrl::wire::PING, 0, vec![]), yrl::wire::Frame::new(yrl::link::RESUME, 0, vec![0; 24]), yrl::wire::Frame::new(ENROLL_OK, 0, vec![]), yrl::wire::Frame::new(ENROLL, 0, vec![1, 2, 3])] {
        let mut s = tokio::net::TcpStream::connect(&r.addr).await.unwrap();
        let sec = yrl::session::client_handshake(&mut s, &guest, &r.server_pub, yrl::session::REKEY_EVERY).await.expect("during the window the handshake completes");
        yrl::session::write_msg(&mut s, &sec.seal(&f).unwrap()).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(3), yrl::session::read_msg(&mut s)).await.unwrap();
        assert!(got.is_err(), "kind {}: no answer, the connection is closed", f.kind);
    }
    assert!(pending_request(&r.server_dir()).is_none());
    assert_eq!(yrl::keys::read_authorized(&r.server_dir().join("authorized_keys")).len(), 1, "nobody was added");
}

#[tokio::test]
async fn n4_three_wrong_codes_close_the_window_for_good() {
    let r = rig("exec").await;
    let dir = r.server_dir();
    let code = open_window(&dir, 60, &rights(&["exec"])).unwrap();
    for i in 0..3 {
        let k = keys::generate();
        let c = Client::connect(&r.addr, &k, &r.server_pub, T).await.unwrap();
        assert!(c.enroll(&format!("WRONG-{i}CODE"), "evil", W).await.is_err());
    }
    // the window is closed now: even the right code on a new connection is turned away - in silence
    let k = keys::generate();
    let mut s = tokio::net::TcpStream::connect(&r.addr).await.unwrap();
    assert!(yrl::session::client_handshake(&mut s, &k, &r.server_pub, yrl::session::REKEY_EVERY).await.is_err(), "silence again");
    assert!(read_window(&dir).is_none());
    let _ = code;
    assert_eq!(yrl::keys::read_authorized(&dir.join("authorized_keys")).len(), 1);
}

#[tokio::test]
async fn n5_a_right_code_is_not_enough_the_owner_must_agree() {
    let r = rig("exec").await;
    let dir = r.server_dir();
    let code = open_window(&dir, 60, &rights(&["exec"])).unwrap();
    let k = keys::generate();
    let o = tokio::spawn(owner(dir.clone(), None, false, vec![]));
    let c = Client::connect(&r.addr, &k, &r.server_pub, T).await.unwrap();
    assert!(c.enroll(&code, "unwanted", W).await.is_err(), "refused by the owner");
    o.await.unwrap().unwrap();
    assert!(!yrl::keys::read_authorized(&dir.join("authorized_keys")).iter().any(|a| a.public == k.public));
    // an answer ends the window, yes or no: a second try needs the owner to open a new one
    let k2 = keys::generate();
    let mut sock = tokio::net::TcpStream::connect(&r.addr).await.unwrap();
    assert!(yrl::session::client_handshake(&mut sock, &k2, &r.server_pub, yrl::session::REKEY_EVERY).await.is_err(), "silence again after the refusal");
    let code2 = open_window(&dir, 60, &rights(&["exec"])).unwrap();
    assert_ne!(code, code2, "every window has its own code");
    let o2 = tokio::spawn(owner(dir.clone(), None, true, rights(&["exec"])));
    let c2 = Client::connect(&r.addr, &k2, &r.server_pub, T).await.unwrap();
    c2.enroll(&code2, "wanted", W).await.unwrap();
    o2.await.unwrap().unwrap();
    assert!(yrl::keys::read_authorized(&dir.join("authorized_keys")).iter().any(|a| a.public == k2.public));
}

#[tokio::test]
async fn n6_a_lying_gatekeeper_cannot_add_a_key() {
    // everything the gatekeeper can write in the enrolment folder is a request and a decision; neither adds a key by itself
    let r = rig("exec").await;
    let dir = r.server_dir();
    let _code = open_window(&dir, 60, &rights(&["exec"])).unwrap();
    let attacker = keys::generate();
    std::fs::write(dir_of(&dir).join("decision"), format!("accept {}", hex::encode(&attacker.public))).unwrap();
    std::fs::write(dir_of(&dir).join("request"), format!("{} sneaky 0\n", hex::encode(&attacker.public))).unwrap();
    assert_eq!(yrl::keys::read_authorized(&dir.join("authorized_keys")).len(), 1, "files in the folder add nothing");
    let c = Client::connect(&r.addr, &attacker, &r.server_pub, T).await.unwrap();
    assert!(c.login("anna", PW, T).await.is_err(), "and the key is still a guest");
    // the owner sees the fingerprint COMPUTED FROM THE KEY, so a request with a made-up fingerprint cannot pass for another key
    let req = pending_request(&dir).unwrap();
    assert_eq!(fingerprint(&req.public), fingerprint(&attacker.public));
    assert_ne!(fingerprint(&req.public), fingerprint(&keys::generate().public));
}

#[tokio::test]
async fn n7_one_request_at_a_time_and_an_unanswered_one_ends_with_the_window() {
    let r = rig("exec").await;
    let dir = r.server_dir();
    let code = open_window(&dir, 3, &rights(&["exec"])).unwrap(); // a 3-second window
    let k1 = keys::generate();
    let c1 = Client::connect(&r.addr, &k1, &r.server_pub, T).await.unwrap();
    let first = tokio::spawn({
        let code = code.clone();
        async move { c1.enroll(&code, "first", Duration::from_secs(10)).await }
    });
    tokio::time::sleep(Duration::from_millis(600)).await;
    let k2 = keys::generate();
    let c2 = Client::connect(&r.addr, &k2, &r.server_pub, T).await.unwrap();
    let t = std::time::Instant::now();
    assert!(c2.enroll(&code, "second", W).await.is_err(), "a second request while the first waits is refused");
    assert!(t.elapsed() < Duration::from_millis(1500), "...at once, not after waiting for the window: {:?}", t.elapsed());
    assert!(first.await.unwrap().is_err(), "nobody answered: the window ended and the request with it");
    assert!(pending_request(&dir).is_none(), "the request is gone");
    assert_eq!(yrl::keys::read_authorized(&dir.join("authorized_keys")).len(), 1);
}

#[test]
fn n8_codes_fingerprints_and_the_files_of_the_window() {
    use std::os::unix::fs::PermissionsExt;
    let a = new_code();
    let b = new_code();
    assert_ne!(a, b);
    assert_eq!(a.len(), 11);
    assert!(a.chars().all(|c| c == '-' || "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".contains(c)), "{a}");
    let k = keys::generate();
    let fp = fingerprint(&k.public);
    assert_eq!(fp.len(), 24);
    assert_eq!(fp, fingerprint(&k.public));
    assert_ne!(fp, fingerprint(&keys::generate().public));
    let d = tempfile::tempdir().unwrap();
    assert!(open_window(d.path(), 0, &[]).is_err() && open_window(d.path(), 901, &[]).is_err() && open_window(d.path(), 60, &rights(&["a b"])).is_err());
    let code = open_window(d.path(), 60, &rights(&["exec"])).unwrap();
    let text = std::fs::read_to_string(dir_of(d.path()).join("window")).unwrap();
    assert!(!text.contains(&code) && text.contains("$argon2id$"), "only a hash of the code is stored");
    assert!(read_window(d.path()).is_some());
    std::fs::set_permissions(dir_of(d.path()).join("window"), std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(read_window(d.path()).is_none(), "a window file anyone could have written is not an open window");
    std::fs::set_permissions(dir_of(d.path()).join("window"), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_window(d.path()).is_some());
    close_window(d.path());
    assert!(read_window(d.path()).is_none());
    // a request frame is exact
    let e = encode_request("ABCDE-FGHJK", "my-phone").unwrap();
    assert_eq!(decode_request(&e).unwrap(), ("ABCDE-FGHJK".to_string(), "my-phone".to_string()));
    assert!(decode_request(&e[..e.len() - 1]).is_err() && decode_request(&{ let mut v = e.clone(); v.push(b'x'); v }).is_err());
    for bad in ["", "a b", "a/b", "a\nb", &"x".repeat(33)] {
        assert!(encode_request("C", bad).is_err(), "{bad:?}");
    }
    assert!(encode_request("", "x").is_err() && encode_request(&"c".repeat(33), "x").is_err());
    let mut x = 3u64;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    for _ in 0..20_000 {
        let v: Vec<u8> = (0..(rnd() % 80) as usize).map(|_| rnd() as u8).collect();
        let _ = decode_request(&v);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn n9_the_command_line_of_the_owner_and_of_the_new_device() {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let r = rig("exec").await;
    let dir = r.server_dir();
    let yrld = env!("CARGO_BIN_EXE_yrld");
    let yrl = env!("CARGO_BIN_EXE_yrl");
    let kdir = r.dir.path().join("newdevice");
    let kp = keys::init(&kdir).unwrap();
    let mut owner = Command::new(yrld).args(["enroll", "enable", dir.to_str().unwrap(), "--ttl", "60", "--rights", "exec"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    let mut out = std::io::BufReader::new(owner.stdout.take().unwrap());
    let mut line = String::new();
    std::io::BufRead::read_line(&mut out, &mut line).unwrap();
    let code = line.split("code: ").nth(1).expect(&line).trim().to_string();
    let mut dev = Command::new(yrl).args(["enroll", kdir.to_str().unwrap(), &r.addr, &hex::encode(&r.server_pub), "laptop2"]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    dev.stdin.take().unwrap().write_all(format!("{code}\n").as_bytes()).unwrap();
    // the owner's program shows the fingerprint of the key that asked and waits for a yes
    let mut shown = String::new();
    for _ in 0..4 {
        let mut l = String::new();
        std::io::BufRead::read_line(&mut out, &mut l).unwrap();
        shown.push_str(&l);
        if l.contains("[y/N]") {
            break;
        }
    }
    assert!(shown.contains(&fingerprint(&kp.public)) && shown.contains("laptop2"), "{shown}");
    owner.stdin.take().unwrap().write_all(b"y\n").unwrap();
    let dev_out = dev.wait_with_output().unwrap();
    assert!(dev_out.status.success(), "{}", String::from_utf8_lossy(&dev_out.stderr));
    assert!(String::from_utf8_lossy(&dev_out.stderr).contains(&fingerprint(&kp.public)), "the new device shows its own fingerprint, for the owner to compare");
    assert!(owner.wait().unwrap().success());
    assert!(yrl::keys::read_authorized(&dir.join("authorized_keys")).iter().any(|a| a.public == kp.public && a.label == "laptop2"));
}

#[tokio::test]
async fn n10_a_new_window_starts_clean() {
    let r = rig("exec").await;
    let dir = r.server_dir();
    // a window closed by wrong codes does not poison the next one
    open_window(&dir, 60, &rights(&["exec"])).unwrap();
    for i in 0..3 {
        let c = Client::connect(&r.addr, &keys::generate(), &r.server_pub, T).await.unwrap();
        let _ = c.enroll(&format!("NOPE{i}-XXXXX"), "x", W).await;
    }
    assert!(read_window(&dir).is_none());
    let code = open_window(&dir, 61, &rights(&["exec"])).unwrap();
    assert!(read_window(&dir).is_some(), "the owner opened a new window: the old 'closed' mark is gone");
    // two wrong codes in the first window and two in the second are not four in a row
    let c = Client::connect(&r.addr, &keys::generate(), &r.server_pub, T).await.unwrap();
    let _ = c.enroll("WRONG-ONE11", "x", W).await;
    let c = Client::connect(&r.addr, &keys::generate(), &r.server_pub, T).await.unwrap();
    let _ = c.enroll("WRONG-TWO22", "x", W).await;
    let code_b = open_window(&dir, 62, &rights(&["exec"])).unwrap(); // another window: the count of wrong tries starts again
    let _ = code;
    let o = tokio::spawn(owner(dir.clone(), None, true, rights(&["exec"])));
    for i in 0..2 {
        let c = Client::connect(&r.addr, &keys::generate(), &r.server_pub, T).await.unwrap();
        let _ = c.enroll(&format!("WRONG-{i}{i}{i}33"), "x", W).await;
    }
    let good = keys::generate();
    let c = Client::connect(&r.addr, &good, &r.server_pub, T).await.unwrap();
    c.enroll(&code_b, "fine", W).await.expect("two wrong in this window, then the right one: it works");
    o.await.unwrap().unwrap();
}

#[test]
fn n11_a_window_file_with_nonsense_in_it_is_not_a_window() {
    let d = tempfile::tempdir().unwrap();
    open_window(d.path(), 60, &rights(&["exec"])).unwrap();
    let p = dir_of(d.path()).join("window");
    let good = std::fs::read_to_string(&p).unwrap();
    let rewrite = |t: String| {
        let tmp = dir_of(d.path()).join("w2");
        std::fs::write(&tmp, t).unwrap();
        std::fs::rename(&tmp, &p).unwrap();
    };
    let mut lines: Vec<&str> = good.lines().collect();
    lines[1] = "exec,a b";
    rewrite(lines.join("\n") + "\n");
    assert!(read_window(d.path()).is_none(), "a right with a space in it");
    lines[1] = "exec";
    lines[0] = "12";
    rewrite(lines.join("\n") + "\n");
    assert!(read_window(d.path()).is_none(), "a window that ended long ago");
    rewrite("not a number\nexec\nhash\n".into());
    assert!(read_window(d.path()).is_none());
    rewrite(String::new());
    assert!(read_window(d.path()).is_none());
    // a request file with a key of the wrong length or a bad name is not a request
    for bad in ["abcd laptop 0", "zz laptop 0", &format!("{} bad/name 0", "11".repeat(32)), ""] {
        std::fs::write(dir_of(d.path()).join("request"), bad).unwrap();
        assert!(pending_request(d.path()).is_none(), "{bad:?}");
    }
    std::fs::write(dir_of(d.path()).join("request"), format!("{} laptop 0", "11".repeat(32))).unwrap();
    assert_eq!(pending_request(d.path()).unwrap().label, "laptop");
}

#[tokio::test]
async fn n12_the_gatekeepers_own_checks_hold_even_if_the_door_was_open_a_moment_too_long() {
    let d = tempfile::tempdir().unwrap();
    let code = open_window(d.path(), 60, &rights(&["exec"])).unwrap();
    let w = read_window(d.path()).unwrap();
    let state = EnrollState::default();
    let slots = tokio::sync::Semaphore::new(2);
    let key = vec![5u8; 32];
    // three wrong codes, then the right one on a connection that was already in: refused
    for _ in 0..3 {
        assert!(matches!(state.serve(d.path(), &w, &key, "WRONG-WRONG", "x", &slots).await, Outcome::Refused));
    }
    let t = std::time::Instant::now();
    assert!(matches!(state.serve(d.path(), &w, &key, &code, "x", &slots).await, Outcome::Refused));
    assert!(t.elapsed() < Duration::from_secs(3), "refused at once, not after waiting for an owner who was never asked: {:?}", t.elapsed());
    assert!(pending_request(d.path()).is_none(), "and no request was made");
    assert!(dir_of(d.path()).join("closed").exists());
    // an owner who answers for another key does not enrol this one
    let d2 = tempfile::tempdir().unwrap();
    let code2 = open_window(d2.path(), 60, &rights(&["exec"])).unwrap();
    let w2 = read_window(d2.path()).unwrap();
    let state2 = EnrollState::default();
    let dd = d2.path().to_path_buf();
    let answer = tokio::spawn(async move {
        for _ in 0..100 {
            if pending_request(&dd).is_some() {
                std::fs::write(dir_of(&dd).join("decision"), format!("accept {}", hex::encode(vec![9u8; 32]))).unwrap();
                return;
            }
            tokio::time::sleep(Duration::from_millis(30)).await;
        }
    });
    assert!(matches!(state2.serve(d2.path(), &w2, &key, &code2, "x", &slots).await, Outcome::Refused), "'accept' for a different key");
    answer.await.unwrap();
    // two requests at the same moment: the second is refused at once
    let state3 = std::sync::Arc::new(EnrollState::default());
    let d3 = tempfile::tempdir().unwrap();
    let code3 = open_window(d3.path(), 60, &rights(&["exec"])).unwrap();
    let w3 = read_window(d3.path()).unwrap();
    let slots = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
    let first = {
        let (s, p, w, c, sl) = (state3.clone(), d3.path().to_path_buf(), w3.clone(), code3.clone(), slots.clone());
        tokio::spawn(async move { s.serve(&p, &w, &[1u8; 32], &c, "one", &sl).await })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    let t = std::time::Instant::now();
    assert!(matches!(state3.serve(d3.path(), &w3, &[2u8; 32], &code3, "two", &slots).await, Outcome::Refused));
    assert!(t.elapsed() < Duration::from_secs(2));
    close_window(d3.path());
    std::fs::write(dir_of(d3.path()).join("decision"), format!("accept {}", hex::encode([1u8; 32]))).unwrap();
    assert!(matches!(first.await.unwrap(), Outcome::Accepted), "and the first, answered for ITS key, is accepted");
}
