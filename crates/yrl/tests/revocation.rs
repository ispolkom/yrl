mod common;
use common::*;
use std::time::Duration;

async fn gone(r: &Rig) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !r.sessions.is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await.expect("revoked session remained in the Executor registry");
}

#[tokio::test]
async fn device_revocation_ends_a_live_terminal_and_running_command() {
    let r = rig("exec,shell").await;
    let c = open(&r).await;
    let mut pty = c.pty_open(24, 80, "xterm").await.unwrap();
    pty.write(b"echo ready\n").await.unwrap();
    pty.read_until("ready", T).await.unwrap();
    let marker = r.dir.path().join("revoked-command-ran");
    // The background child must die as well, even though killing only /bin/sh would make the
    // request fail and could otherwise leave this child running after the revoked session.
    let script = format!("(sleep 4; touch {}) & wait", marker.display());
    let args: [&[u8]; 3] = [b"/bin/sh", b"-c", script.as_bytes()];
    let pending = c.exec(&args, 15_000, Duration::from_secs(12));
    tokio::pin!(pending);
    tokio::select! {
        _ = &mut pending => panic!("command ended before revocation"),
        _ = tokio::time::sleep(Duration::from_millis(200)) => {}
    }
    std::fs::write(r.server_dir().join("authorized_keys"), b"").unwrap();
    gone(&r).await;
    assert!(tokio::time::timeout(Duration::from_secs(6), &mut pending).await.unwrap().is_err());
    assert!(tokio::time::timeout(Duration::from_secs(6), pty.next()).await.is_ok());
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!marker.exists(), "a command descendant kept running after its device was revoked");
}

#[tokio::test]
async fn account_removal_and_permission_change_end_existing_sessions() {
    let r = rig("exec,shell,files,tunnel").await;
    let c = open(&r).await;
    yrl::users::set_user(&r.server_dir().join("users"), "anna", "exec", PW).unwrap();
    gone(&r).await;
    assert!(c.exec(&[b"/bin/true"], 1000, T).await.is_err());

    let next = open(&r).await;
    let mut denied_pty = next.pty_open(24, 80, "xterm").await.unwrap();
    assert!(matches!(tokio::time::timeout(T, denied_pty.next()).await.unwrap(), yrl::client::PtyEvent::Error(1, _)));
    std::fs::write(r.server_dir().join("users"), b"").unwrap();
    gone(&r).await;
    assert!(next.exec(&[b"/bin/true"], 1000, T).await.is_err());
    assert!(yrl::client::Client::connect_pinned(&r.addr, &r.client, &r.server_pub, &r.exec_pub, T).await.unwrap().login("anna", PW, T).await.is_err());
}
