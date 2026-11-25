//! A program must start even when the account's home directory exists but cannot be entered (found with the real-kernel stand, where /root is hidden by the namespace).
use std::os::unix::fs::PermissionsExt;
use yrl::identity::{Pw, Target};

fn target(home: &str) -> Target {
    Target { pw: Pw { name: "anna".into(), uid: unsafe { libc::geteuid() }, gid: unsafe { libc::getegid() }, home: home.into(), shell: String::new() }, switch: false }
}

#[tokio::test]
async fn h1_a_home_that_cannot_be_entered_does_not_stop_the_program() {
    let d = tempfile::tempdir().unwrap();
    let locked = d.path().join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if unsafe { libc::geteuid() } == 0 {
        return; // root enters everything; the case cannot be made
    }
    let mut c = tokio::process::Command::new("pwd");
    yrl::exec::prepare(&mut c, &target(locked.to_str().unwrap()));
    let out = c.output().await.expect("the program starts");
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "/", "it starts in / instead");
    // and an ordinary home is still used
    let ok = d.path().join("ok");
    std::fs::create_dir(&ok).unwrap();
    let mut c = tokio::process::Command::new("pwd");
    yrl::exec::prepare(&mut c, &target(ok.to_str().unwrap()));
    assert_eq!(String::from_utf8_lossy(&c.output().await.unwrap().stdout).trim(), std::fs::canonicalize(&ok).unwrap().to_str().unwrap());
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
}
