//! The single-process CLI must use the identities published by `yrld init`.
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use yrl::client::Client;

struct Serve(Child);
impl Drop for Serve {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(dir: &std::path::Path, addr: &str) -> Serve {
    Serve(
        Command::new(env!("CARGO_BIN_EXE_yrld"))
            .args(["serve", dir.to_str().unwrap(), addr])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

#[tokio::test]
async fn published_executor_identity_survives_serve_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("server");
    assert!(Command::new(env!("CARGO_BIN_EXE_yrld"))
        .args(["init", dir.to_str().unwrap()])
        .output()
        .unwrap()
        .status
        .success());

    let server = yrl::keys::load(&dir).unwrap();
    let executor = yrl::keys::load(&dir.join("ipc/executor")).unwrap();
    let client = yrl::keys::generate();
    yrl::keys::authorize(
        &dir.join("authorized_keys"),
        &hex::encode(&client.public),
        "test",
        "exec",
    )
    .unwrap();
    yrl::users::set_user(&dir.join("users"), "test", "exec", b"test-password-007").unwrap();

    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let addr = format!("127.0.0.1:{port}");
    for _ in 0..2 {
        let process = start(&dir, &addr);
        let mut connected = None;
        for _ in 0..50 {
            if let Ok(c) = Client::connect_pinned(
                &addr,
                &client,
                &server.public,
                &executor.public,
                Duration::from_secs(2),
            )
            .await
            {
                connected = Some(c);
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let c = connected.expect("serve must use the published Executor identity");
        c.login("test", b"test-password-007", Duration::from_secs(5))
            .await
            .unwrap();
        c.ping(b"identity", Duration::from_secs(5)).await.unwrap();
        c.close().await;
        drop(process);
    }
}

#[test]
fn serve_refuses_missing_or_damaged_persistent_role_keys() {
    for (role, damage) in [
        ("executor", "missing"),
        ("executor", "damaged"),
        ("executor", "mismatched-public"),
        ("broker", "missing"),
        ("broker", "damaged"),
        ("broker", "mismatched-public"),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("server");
        assert!(Command::new(env!("CARGO_BIN_EXE_yrld"))
            .args(["init", dir.to_str().unwrap()])
            .output()
            .unwrap()
            .status
            .success());
        let key = dir.join("ipc").join(role).join("static.key");
        if damage == "missing" {
            std::fs::remove_file(key).unwrap();
        } else if damage == "damaged" {
            std::fs::write(key, b"invalid\n").unwrap();
        } else {
            std::fs::write(
                dir.join("ipc").join(format!("{role}.pub")),
                format!("{}\n", hex::encode(yrl::keys::generate().public)),
            )
            .unwrap();
        }
        let mut child = Command::new(env!("CARGO_BIN_EXE_yrld"))
            .args(["serve", dir.to_str().unwrap(), "127.0.0.1:0"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut exited = false;
        for _ in 0..100 {
            if child.try_wait().unwrap().is_some() {
                exited = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if !exited {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("{role} {damage} unexpectedly kept serving");
        }
        let result = child.wait_with_output().unwrap();
        assert!(
            !result.status.success(),
            "{role} {damage} unexpectedly started"
        );
        assert!(String::from_utf8_lossy(&result.stderr).contains("cannot load persistent"));
    }
}
