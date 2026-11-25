mod common;
use common::*;
use common::chaos::Chaos;
use std::process::Command;
use std::time::Duration;

#[tokio::test]
async fn detached_descendant_dies_with_its_session_after_resume_without_touching_a_neighbor() {
    if std::env::var_os("YRL_CGROUP_TEST_IN_SCOPE").is_none() {
        let exe = std::env::current_exe().unwrap();
        let out = Command::new("systemd-run").args(["--user", "--scope", "-p", "Delegate=yes", "env", "YRL_CGROUP_TEST_IN_SCOPE=1"])
            .arg(exe).args(["--exact", "detached_descendant_dies_with_its_session_after_resume_without_touching_a_neighbor", "--nocapture"])
            .output().expect("systemd-run is required for the cgroup regression");
        assert!(out.status.success(), "{}\n{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        return;
    }
    yrl::cgroup::verify_delegation().unwrap();
    std::env::set_var("YRL_SESSION_CGROUPS", "required");
    let r = rig_with("exec,shell", |mut c| { c.session_grace = Duration::from_secs(10); c }).await;
    let proxy = Chaos::start(&r.addr).await;
    let first = open_via(&r, &proxy.addr, fast_opts()).await;
    let second = open(&r).await;
    let (mut a, mut b) = (first.pty_open(24, 80, "xterm").await.unwrap(), second.pty_open(24, 80, "xterm").await.unwrap());
    let marker_a = r.dir.path().join("detached-a");
    let marker_b = r.dir.path().join("detached-b");
    a.write(b"cg=$(awk -F: '$1==\"0\" {print $3}' /proc/self/cgroup); printf 'limit-before-%s\\n' \"$(cat /sys/fs/cgroup$cg/memory.max)\"\n").await.unwrap();
    a.read_until("limit-before-2147483648", T).await.unwrap();
    a.write(format!("setsid /bin/sh -c 'sleep 4; touch {}' </dev/null >/dev/null 2>&1 & echo first-$((2+2))ready\n", marker_a.display()).as_bytes()).await.unwrap();
    b.write(format!("setsid /bin/sh -c 'sleep 2; touch {}' </dev/null >/dev/null 2>&1 & echo second-$((2+2))ready\n", marker_b.display()).as_bytes()).await.unwrap();
    a.read_until("first-4ready", T).await.unwrap();
    b.read_until("second-4ready", T).await.unwrap();
    assert_eq!(r.sessions.len(), 2);
    proxy.cut();
    a.write(b"echo resumed-$((3+3))session\n").await.unwrap();
    a.read_until("resumed-6session", T).await.unwrap();
    a.write(b"printf 'limit-after-%s\\n' \"$(cat /sys/fs/cgroup$cg/memory.max)\"\n").await.unwrap();
    a.read_until("limit-after-2147483648", T).await.unwrap();
    assert!(proxy.accepted() >= 2, "the transport did not reconnect");
    assert_eq!(r.sessions.len(), 2, "RESUME kept both server sessions");
    first.close().await;
    tokio::time::timeout(T, async { while r.sessions.len() != 1 { tokio::time::sleep(Duration::from_millis(20)).await; } }).await.unwrap();
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(!marker_a.exists(), "setsid descendant escaped the closed session");
    assert!(marker_b.exists(), "the neighboring session's descendant was killed");
    b.write(b"echo neighbor-$((4+4))alive\n").await.unwrap();
    b.read_until("neighbor-8alive", T).await.unwrap();
    second.close().await;
}
