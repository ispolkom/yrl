//! Lockouts that outlive the process, and that fail closed when anybody has touched them.
mod common;
use common::*;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use yrl::stepup::*;

fn key(n: u8) -> Vec<u8> {
    vec![n; 32]
}

fn dir() -> tempfile::TempDir {
    let d = tempfile::tempdir().unwrap();
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    d
}

#[test]
fn k1_a_new_store_is_created_private_and_empty() {
    let d = dir();
    let l = Lockouts::persistent(d.path(), "root");
    assert_eq!(l.standing(&key(1), Level::Root), Standing::Open);
    for f in ["lockouts.root", "lockouts.root.key"] {
        assert_eq!(std::fs::metadata(d.path().join(f)).unwrap().permissions().mode() & 0o777, 0o600, "{f}");
    }
    assert!(!l.remote_root_off());
    let text = std::fs::read_to_string(d.path().join("lockouts.root")).unwrap();
    assert!(text.starts_with("YRLLOCK 1\n") && text.contains("\nMAC "));
}

#[test]
fn k2_what_was_counted_survives_a_restart() {
    let d = dir();
    {
        let l = Lockouts::persistent(d.path(), "root");
        l.fail(&key(1), Level::Root);
        l.fail(&key(1), Level::Root);
    }
    let l = Lockouts::persistent(d.path(), "root"); // "restart"
    assert_eq!(l.standing(&key(1), Level::Root), Standing::Open);
    l.fail(&key(1), Level::Root); // the third, counted together with the two before the restart
    assert_eq!(l.standing(&key(1), Level::Root), Standing::Locked);
    let l = Lockouts::persistent(d.path(), "root");
    assert_eq!(l.standing(&key(1), Level::Root), Standing::Locked, "and a lock stays a lock after another restart");
    assert_eq!(l.standing(&key(2), Level::Root), Standing::Open, "other keys are untouched");
    assert_eq!(l.standing(&key(1), Level::Sudo), Standing::Open, "so is the other level of the same key");
}

#[test]
fn k3_the_kill_switch_survives_too() {
    let d = dir();
    {
        let l = Lockouts::persistent(d.path(), "root");
        for k in 1..=3u8 {
            for _ in 0..3 {
                l.fail(&key(k), Level::Root);
            }
        }
        assert!(l.remote_root_off());
    }
    let l = Lockouts::persistent(d.path(), "root");
    assert!(l.remote_root_off());
    assert_eq!(l.standing(&key(9), Level::Root), Standing::Locked, "a key nobody has seen before is stopped as well");
}

#[test]
fn k4_a_sudo_lock_ends_by_the_servers_clock_and_that_is_remembered_as_a_time() {
    let d = dir();
    let mut l = Lockouts::persistent(d.path(), "sudo");
    l.sudo_lock = Duration::from_secs(2);
    for _ in 0..3 {
        l.fail(&key(1), Level::Sudo);
    }
    assert_eq!(l.standing(&key(1), Level::Sudo), Standing::Locked);
    let l2 = Lockouts::persistent(d.path(), "sudo");
    assert_eq!(l2.standing(&key(1), Level::Sudo), Standing::Locked, "a restart does not shorten it");
    std::thread::sleep(Duration::from_millis(2300));
    assert_eq!(l2.standing(&key(1), Level::Sudo), Standing::Open, "it ends by itself");
}

/// everything done to the file by somebody who does not hold the seal key must make the level refuse everybody
fn assert_fails_closed(d: &std::path::Path, why: &str) {
    let before = std::fs::read(d.join("lockouts.root")).ok();
    let l = Lockouts::persistent(d, "root");
    assert_eq!(l.standing(&key(1), Level::Root), Standing::Locked, "{why}: a damaged store must not mean 'no lockouts'");
    assert_eq!(l.standing(&key(77), Level::Root), Standing::Locked, "{why}: for every key");
    assert!(l.remote_root_off(), "{why}");
    l.ok(&key(1), Level::Root);
    l.fail(&key(1), Level::Root); // nothing is saved over a damaged store
    assert_eq!(std::fs::read(d.join("lockouts.root")).ok(), before, "{why}: nothing is written over a damaged store, only the owner repairs it");
}

#[test]
fn k5_any_change_to_the_file_by_somebody_else_is_noticed() {
    for (name, edit) in [
        ("a lock removed", Box::new(|t: String| t.lines().filter(|l| !l.starts_with("REC ")).collect::<Vec<_>>().join("\n") + "\n") as Box<dyn Fn(String) -> String>),
        ("the count lowered", Box::new(|t: String| t.replace(" 2 0 0", " 0 0 0"))),
        ("the global switch turned off", Box::new(|t: String| t.replace("GLOBAL 1", "GLOBAL 0"))),
        ("a line added", Box::new(|t: String| t.replacen("GLOBAL", "REC 00 root 0 0 0\nGLOBAL", 1))),
        ("the seal copied from another file", Box::new(|t: String| { let i = t.rfind("MAC ").unwrap(); format!("{}MAC {}\n", &t[..i], "0".repeat(64)) })),
        ("the seal removed", Box::new(|t: String| { let i = t.rfind("MAC ").unwrap(); t[..i].to_string() })),
        ("emptied", Box::new(|_t: String| String::new())),
        ("garbage", Box::new(|_t: String| "garbage".repeat(100))),
    ] {
        let d = dir();
        {
            let l = Lockouts::persistent(d.path(), "root");
            if name == "the global switch turned off" {
                for k in 1..=3u8 {
                    for _ in 0..3 {
                        l.fail(&key(k), Level::Root);
                    }
                }
            } else {
                l.fail(&key(1), Level::Root);
                l.fail(&key(1), Level::Root);
            }
        }
        let p = d.path().join("lockouts.root");
        let t = std::fs::read_to_string(&p).unwrap();
        assert!(!name.contains("global") || t.contains("GLOBAL 1"));
        let edited = edit(t.clone());
        assert_ne!(edited, t, "{name}: the edit must really change the file");
        std::fs::write(&p, edited).unwrap();
        assert_fails_closed(d.path(), name);
    }
}

#[test]
fn k6_a_deleted_store_is_not_a_clean_start() {
    let d = dir();
    {
        let l = Lockouts::persistent(d.path(), "root");
        for _ in 0..3 {
            l.fail(&key(1), Level::Root);
        }
    }
    std::fs::remove_file(d.path().join("lockouts.root")).unwrap(); // to wipe the lock
    assert_fails_closed(d.path(), "the file deleted while its key remains");
    // the reverse: the key deleted
    let d2 = dir();
    {
        Lockouts::persistent(d2.path(), "root").fail(&key(1), Level::Root);
    }
    std::fs::remove_file(d2.path().join("lockouts.root.key")).unwrap();
    assert_fails_closed(d2.path(), "the key deleted while its file remains");
}

#[test]
fn k7_files_that_others_can_write_or_read_are_not_trusted() {
    let d = dir();
    Lockouts::persistent(d.path(), "root");
    std::fs::set_permissions(d.path().join("lockouts.root"), std::fs::Permissions::from_mode(0o666)).unwrap();
    assert_fails_closed(d.path(), "a store anyone can write");
    let d = dir();
    Lockouts::persistent(d.path(), "root");
    std::fs::set_permissions(d.path().join("lockouts.root.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_fails_closed(d.path(), "a seal key others can read");
    let d = dir();
    Lockouts::persistent(d.path(), "root");
    std::fs::write(d.path().join("lockouts.root"), vec![b'x'; 2 << 20]).unwrap();
    std::fs::set_permissions(d.path().join("lockouts.root"), std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_fails_closed(d.path(), "an absurdly big store");
}

#[test]
fn k8_only_the_owner_on_the_machine_can_repair_and_it_acts_at_once() {
    let d = dir();
    let running = Lockouts::persistent(d.path(), "root"); // the running broker's object
    for _ in 0..3 {
        running.fail(&key(1), Level::Root);
    }
    assert_eq!(running.standing(&key(1), Level::Root), Standing::Locked);
    assert!(running.remote_root_off() == false);
    running.lift_all(); // an over-the-wire path: does nothing to a persistent store
    assert_eq!(running.standing(&key(1), Level::Root), Standing::Locked);
    Lockouts::reset_files(d.path(), "root").unwrap(); // `yrld unlock`, on the machine
    assert_eq!(running.standing(&key(1), Level::Root), Standing::Open, "the running object sees it without a restart");
    // and a damaged store is repaired the same way
    std::fs::write(d.path().join("lockouts.root"), "junk").unwrap();
    assert!(running.remote_root_off());
    Lockouts::reset_files(d.path(), "root").unwrap();
    assert!(!running.remote_root_off() && running.standing(&key(1), Level::Root) == Standing::Open);
}

#[tokio::test]
async fn k9_through_the_whole_system_a_restarted_broker_keeps_its_locks_and_unlock_clears_them() {
    use std::process::{Command, Stdio};
    let dir = tempfile::tempdir().unwrap();
    let sd = dir.path().join("srv");
    let yrld = env!("CARGO_BIN_EXE_yrld");
    let out = Command::new(yrld).args(["init", sd.to_str().unwrap()]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let key_of = |tag: &str| hex::decode(text.lines().find(|l| l.contains(tag)).unwrap().split_whitespace().last().unwrap()).unwrap();
    let (server_pub, broker_pub) = (key_of("server public"), key_of("broker public"));
    let client = yrl::keys::generate();
    yrl::keys::authorize(&sd.join("authorized_keys"), &hex::encode(&client.public), "laptop", "exec,root").unwrap();
    yrl::users::set_user(&sd.join("users"), "anna", "exec,root", PW).unwrap();
    Verifier::set(&sd, Level::Root, ROOT_PHRASE).unwrap();
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    struct Procs(Vec<std::process::Child>);
    impl Drop for Procs {
        fn drop(&mut self) {
            for c in &mut self.0 {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }
    let mut procs = Procs(vec![]);
    let mk = |args: &[&str]| Command::new(yrld).args(args).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap();
    let wait_for = |f: &str| {
        let p = sd.join(f);
        async move {
            for _ in 0..100 {
                if p.exists() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    };
    // once `init` has set the audit door up, privileged approvals need the audit process: that is the design (fail-closed)
    procs.0.push(mk(&["audit", sd.to_str().unwrap()]));
    for _ in 0..100 {
        if sd.join("audit.sock").exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    procs.0.push(mk(&["broker", sd.to_str().unwrap()]));
    wait_for("broker.sock").await;
    procs.0.push(mk(&["executor", sd.to_str().unwrap()]));
    wait_for("ipc.sock").await;
    procs.0.push(mk(&["gatekeeper", sd.to_str().unwrap(), &format!("127.0.0.1:{port}")]));
    tokio::time::sleep(Duration::from_millis(600)).await;
    let addr = format!("127.0.0.1:{port}");
    let c = yrl::client::Client::connect(&addr, &client, &server_pub, T).await.unwrap();
    c.login("anna", PW, T).await.unwrap();
    let op = Op::RestartService("kept".into());
    for _ in 0..3 {
        let _ = c.elevate(Level::Root, &op, b"a wrong phrase, long enough", &broker_pub, Duration::from_secs(8)).await;
    }
    // the broker is killed and started again: the lock is still there
    let mut b = procs.0.remove(1); // (0 is the audit process)
    b.kill().unwrap();
    b.wait().unwrap();
    std::fs::remove_file(sd.join("broker.sock")).unwrap();
    procs.0.push(mk(&["broker", sd.to_str().unwrap()]));
    wait_for("broker.sock").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let c2 = yrl::client::Client::connect(&addr, &client, &server_pub, T).await.unwrap();
    c2.login("anna", PW, T).await.unwrap();
    let e = c2.elevate(Level::Root, &op, ROOT_PHRASE, &broker_pub, Duration::from_secs(8)).await.unwrap_err().to_string();
    assert!(e.contains("locked"), "after the restart: {e}");
    // the owner clears it on the machine; no restart needed
    assert!(Command::new(yrld).args(["unlock", sd.to_str().unwrap(), "root"]).stdout(Stdio::null()).status().unwrap().success());
    assert_eq!(c2.elevate(Level::Root, &op, ROOT_PHRASE, &broker_pub, Duration::from_secs(8)).await.unwrap(), "restarted kept (mock)");
}

#[test]
fn k10_not_being_able_to_remember_is_not_the_same_as_all_is_well() {
    let d = dir();
    let l = Lockouts::persistent(d.path(), "root");
    assert_eq!(l.standing(&key(1), Level::Root), Standing::Open);
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o500)).unwrap(); // nothing can be written any more
    if std::fs::write(d.path().join("probe"), b"x").is_ok() {
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        return; // running as root: permissions do not stop it, the situation cannot be made
    }
    l.fail(&key(1), Level::Root); // this cannot be written down
    assert_eq!(l.standing(&key(1), Level::Root), Standing::Locked, "a failure that could not be remembered must not be forgotten: refuse");
    assert_eq!(l.standing(&key(2), Level::Root), Standing::Locked);
    assert!(l.remote_root_off());
    std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn k11_the_store_stays_small_and_tidy() {
    let d = dir();
    let l = Lockouts::persistent(d.path(), "root");
    for i in 0..40u8 {
        l.fail(&key(i), Level::Root);
        l.ok(&key(i), Level::Root); // a success wipes the count: nothing needs remembering
    }
    let text = std::fs::read_to_string(d.path().join("lockouts.root")).unwrap();
    assert_eq!(text.lines().filter(|l| l.starts_with("REC ")).count(), 0, "records with nothing in them are not kept:\n{text}");
    let names: Vec<String> = std::fs::read_dir(d.path()).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    assert!(names.iter().all(|n| !n.ends_with(".tmp")), "no leftovers of the atomic write: {names:?}");
    assert_eq!(names.len(), 2, "{names:?}");
}

#[test]
fn k12_a_store_with_a_bad_key_file_is_repaired_by_the_owner_too() {
    let d = dir();
    Lockouts::persistent(d.path(), "root").fail(&key(1), Level::Root);
    std::fs::set_permissions(d.path().join("lockouts.root.key"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let l = Lockouts::persistent(d.path(), "root");
    assert!(l.remote_root_off());
    Lockouts::reset_files(d.path(), "root").unwrap();
    assert!(!l.remote_root_off(), "a key file with the wrong rights was replaced, not kept");
    assert_eq!(std::fs::metadata(d.path().join("lockouts.root.key")).unwrap().permissions().mode() & 0o777, 0o600);
}
