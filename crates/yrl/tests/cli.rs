//! The command-line client says what is missing instead of crashing.
use std::process::Command;

const YRL: &str = env!("CARGO_BIN_EXE_yrl");

fn run(args: &[&str]) -> (bool, String) {
    let o = Command::new(YRL).args(args).output().unwrap();
    (o.status.success(), String::from_utf8_lossy(&o.stderr).into_owned() + &String::from_utf8_lossy(&o.stdout))
}

#[test]
fn c1_a_command_that_logs_in_but_has_no_login_explains_instead_of_panicking() {
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().to_str().unwrap();
    for cmd in ["ping", "exec", "shell"] {
        let (ok, text) = run(&[cmd, dir, "127.0.0.1:1", &"ab".repeat(32)]);
        assert!(!ok, "{cmd}");
        assert!(text.contains("<login>") && !text.contains("panicked"), "{cmd}: {text}");
    }
    let (ok, text) = run(&["no-such-command"]);
    assert!(!ok && text.contains("usage: yrl keygen") && text.contains("ping <dir> <host:port> <server-public-hex> <login>"), "{text}");
}

#[test]
fn root_stepup_requires_a_separate_login_pin() {
    let key = "ab".repeat(32);
    let output = Command::new(YRL)
        .env_remove("YRL_EXECUTOR_KEY")
        .args(["elevate", "unused", "127.0.0.1:1", &key, "anna", "root", &key, "restart", "test"])
        .output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ROOT step-up requires --executor"));
}

mod common;

#[tokio::test]
async fn finishing_exec_releases_session_before_the_reconnect_grace() {
    use std::{process::Stdio, time::Duration};
    use tokio::io::AsyncWriteExt;
    let rig = common::rig_with("exec", |mut cfg| {
        cfg.session_grace = Duration::from_secs(60);
        cfg
    }).await;
    let dir = rig.dir.path().join("cli");
    let key = yrl::keys::init(&dir).unwrap();
    yrl::keys::authorize(
        &rig.server_dir().join("authorized_keys"),
        &hex::encode(&key.public),
        "cli",
        "exec",
    ).unwrap();

    let mut client = tokio::process::Command::new(YRL)
        .arg("exec").arg(dir)
        .args([&rig.addr, &hex::encode(&rig.server_pub), "anna", "--executor", &hex::encode(&rig.exec_pub)])
        .args(["--", "/bin/echo", "executed"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn().unwrap();
    let mut stdin = client.stdin.take().unwrap();
    stdin.write_all(common::PW).await.unwrap();
    stdin.write_all(b"\n").await.unwrap();
    drop(stdin);
    let out = client.wait_with_output().await.unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(out.stdout, b"executed\n");

    tokio::time::timeout(Duration::from_secs(2), async {
        while rig.sessions.len() != 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await.expect("CLI must close the session without waiting for RESUME grace");
}
