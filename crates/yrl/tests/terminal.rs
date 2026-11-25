//! The interactive terminal: it must really be a terminal, and it must not outlive its session.
mod common;
use common::*;
use std::time::{Duration, Instant};
use yrl::client::PtyEvent;
use yrl::wire::{self, Frame};

const W: Duration = Duration::from_secs(8);

async fn shell_rig() -> Rig {
    rig("exec,root,shell,files,tunnel").await
}

#[tokio::test]
async fn p1_typing_and_output_and_the_exit_code() {
    let r = shell_rig().await;
    let c = open(&r).await;
    let mut p = c.pty_open(24, 80, "xterm-256color").await.unwrap();
    p.write(b"echo hello-$((6*7))\n").await.unwrap();
    p.read_until("hello-42", W).await.unwrap();
    p.write(b"exit 3\n").await.unwrap();
    loop {
        match tokio::time::timeout(W, p.next()).await.expect("the shell must end") {
            PtyEvent::Exit(code) => {
                assert_eq!(code, 3);
                break;
            }
            PtyEvent::Output(_) => {}
            other => panic!("{other:?}"),
        }
    }
}

#[tokio::test]
async fn p2_it_is_a_real_terminal_with_the_requested_type_and_size() {
    let r = shell_rig().await;
    let c = open(&r).await;
    let mut p = c.pty_open(30, 100, "screen-256color").await.unwrap();
    p.write(b"[ -t 0 ] && [ -t 1 ] && echo istty-yes; echo term=$TERM; stty size; echo end-$((1+1))p2\n").await.unwrap();
    let out = p.read_until("end-2p2", W).await.unwrap();
    assert!(out.contains("istty-yes") && out.contains("term=screen-256color") && out.contains("30 100"), "{out}");
    p.write(b"[ $(cut -d' ' -f7 /proc/$$/stat) -ne 0 ] && echo hasctty-$((1+1)); echo end-$((2+2))ctty\n").await.unwrap();
    let out = p.read_until("end-4ctty", W).await.unwrap();
    assert!(out.contains("hasctty-2"), "the terminal must be the controlling one of the shell's session: {out}");
    p.resize(50, 132).await.unwrap();
    p.write(b"stty size; echo end-$((1+1))resize\n").await.unwrap();
    let out = p.read_until("end-2resize", W).await.unwrap();
    assert!(out.contains("50 132"), "the new size reached the program: {out}");
}

#[tokio::test]
async fn p3_ctrl_c_interrupts_the_program_not_the_session() {
    let r = shell_rig().await;
    let c = open(&r).await;
    let mut p = c.pty_open(24, 80, "xterm").await.unwrap();
    p.write(b"sleep 30\n").await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let t = Instant::now();
    p.write(&[0x03]).await.unwrap();
    p.write(b"echo after-$((1+1))\n").await.unwrap();
    p.read_until("after-2\r\n", W).await.unwrap();
    assert!(t.elapsed() < Duration::from_secs(5), "sleep 30 was interrupted at once");
}

#[tokio::test]
async fn p4_without_the_shell_right_nothing_starts() {
    let r = rig("exec").await; // the key does not carry 'shell'
    let marker = r.dir.path().join("shell_ran");
    let c = open(&r).await;
    let mut p = c.pty_open(24, 80, "xterm").await.unwrap();
    assert!(matches!(tokio::time::timeout(W, p.next()).await.unwrap(), PtyEvent::Error(1, _)));
    p.write(format!("touch {}\n", marker.display()).as_bytes()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!marker.exists(), "input to a terminal that was refused must go nowhere");
}

#[tokio::test]
async fn p5_a_dropped_link_kills_the_shell_and_what_it_started() {
    let r = shell_rig().await;
    let pidfile = r.dir.path().join("pid");
    {
        let c = open(&r).await;
        let mut p = c.pty_open(24, 80, "xterm").await.unwrap();
        p.write(format!("sleep 100 & echo $! > {}; echo bgpid-$((1+1))ready\n", pidfile.display()).as_bytes()).await.unwrap();
        p.read_until("bgpid-2ready", W).await.unwrap();
    } // the client is dropped: the link closes
    let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
    let t = Instant::now();
    loop {
        if unsafe { libc::kill(pid, 0) } != 0 {
            break;
        }
        // a zombie still answers kill(0): look at its state
        if std::fs::read_to_string(format!("/proc/{pid}/stat")).map(|s| s.contains(") Z ")).unwrap_or(true) {
            break;
        }
        assert!(t.elapsed() < Duration::from_secs(6), "the background program of a dead session is still running");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test]
async fn p6_explicit_close_ends_the_shell() {
    let r = shell_rig().await;
    let c = open(&r).await;
    let mut p = c.pty_open(24, 80, "xterm").await.unwrap();
    p.write(b"echo up-$((3+3))p6\n").await.unwrap();
    p.read_until("up-6p6", W).await.unwrap();
    p.close().await.unwrap();
    loop {
        match tokio::time::timeout(W, p.next()).await.expect("must end") {
            PtyEvent::Exit(_) => break,
            PtyEvent::Output(_) => {}
            other => panic!("{other:?}"),
        }
    }
}

#[tokio::test]
async fn p7_a_hostile_terminal_type_never_reaches_the_environment() {
    let r = shell_rig().await;
    let c = open(&r).await;
    for bad in ["x y", "a;touch /tmp/yrl_pwned", "$(id)", "line\nbreak", "tab\there"] {
        let mut p = c.pty_open(24, 80, bad).await.unwrap();
        p.write(b"echo T=[$TERM]-$((1+1))\n").await.unwrap();
        let out = p.read_until("]-2", W).await.unwrap();
        assert!(out.contains("T=[xterm]-2"), "{bad:?} must be replaced, got {out}");
        p.write(b"exit\n").await.unwrap();
    }
    // too long for the codec: the server also refuses it on the wire
    let (mut s, sec) = raw(&r).await;
    raw_login(&mut s, &sec, "anna", PW).await;
    let mut long = wire::encode_pty_open(1, 24, 80, b"x").unwrap();
    long[12] = 40;
    long.extend(vec![b't'; 39]);
    send(&mut s, &sec, Frame::new(wire::PTY_OPEN, 0, long)).await;
    send(&mut s, &sec, Frame::new(wire::PING, 0, b"x".to_vec())).await;
    assert!(recv(&mut s, &sec).await.is_none());
    assert!(!std::path::Path::new("/tmp/yrl_pwned").exists());
    assert_eq!(yrl::pty::clean_term(b"xterm-256color"), "xterm-256color");
    for bad in [&b""[..], b"x y", b"a;b", b"$(id)", b"a\nb", b"\xff", &[b'a'; 33]] {
        assert_eq!(yrl::pty::clean_term(bad), "xterm");
    }
}

#[tokio::test]
async fn p8_the_number_of_terminals_is_limited() {
    let r = rig_with("exec,root,shell,files,tunnel", |mut c| { c.max_pty_per_connection = 2; c }).await;
    let c = open(&r).await;
    let (mut a, mut b) = (c.pty_open(24, 80, "xterm").await.unwrap(), c.pty_open(24, 80, "xterm").await.unwrap());
    a.write(b"echo a-$((1+1))up\n").await.unwrap();
    b.write(b"echo b-$((1+1))up\n").await.unwrap();
    a.read_until("a-2up", W).await.unwrap();
    b.read_until("b-2up", W).await.unwrap();
    let mut third = c.pty_open(24, 80, "xterm").await.unwrap();
    assert!(matches!(tokio::time::timeout(W, third.next()).await.unwrap(), PtyEvent::Error(5, _)));
}

#[tokio::test]
async fn p9_a_lot_of_output_flows_through_without_stalling() {
    let r = shell_rig().await;
    let c = open(&r).await;
    let mut p = c.pty_open(24, 80, "xterm").await.unwrap();
    p.write(b"seq 1 200000; echo done-$((5*5))\n").await.unwrap();
    let out = p.read_until("done-25", Duration::from_secs(30)).await.unwrap();
    assert!(out.contains("199999\r\n200000\r\n"), "the tail of the numbers arrived in order");
}

#[tokio::test]
async fn p10_malformed_terminal_frames_are_handled() {
    let r = shell_rig().await;
    // bad open requests end the session; frames for unknown ids are ignored
    for payload in [vec![], vec![0; 12], wire::encode_pty_open(1, 24, 80, b"x").map(|mut v| { v.push(0); v }).unwrap(), {
        let mut v = wire::encode_pty_open(1, 24, 80, b"x").unwrap();
        v[8] = 0; v[9] = 0; // rows = 0
        v
    }, {
        let mut v = wire::encode_pty_open(1, 24, 80, b"x").unwrap();
        v[10] = 0xFF; v[11] = 0xFF; // cols = 65535
        v
    }] {
        let (mut s, sec) = raw(&r).await;
        raw_login(&mut s, &sec, "anna", PW).await;
        send(&mut s, &sec, Frame::new(wire::PTY_OPEN, 0, payload)).await;
        send(&mut s, &sec, Frame::new(wire::PING, 0, b"x".to_vec())).await;
        assert!(recv(&mut s, &sec).await.is_none(), "a bad terminal request closes the session");
    }
    let (mut s, sec) = raw(&r).await;
    raw_login(&mut s, &sec, "anna", PW).await;
    for f in [Frame::new(wire::PTY_IN, 0, wire::with_id(999, b"ls\n")), Frame::new(wire::PTY_CLOSE, 0, wire::with_id(999, &[])), Frame::new(wire::PTY_RESIZE, 0, wire::encode_resize(999, 10, 10))] {
        send(&mut s, &sec, f).await;
    }
    send(&mut s, &sec, Frame::new(wire::PING, 0, b"alive".to_vec())).await;
    assert_eq!(recv(&mut s, &sec).await.map(|f| f.payload), Some(b"alive".to_vec()), "unknown ids are harmless");
    send(&mut s, &sec, Frame::new(wire::PTY_RESIZE, 0, vec![1, 2, 3])).await;
    send(&mut s, &sec, Frame::new(wire::PING, 0, b"x".to_vec())).await;
    assert!(recv(&mut s, &sec).await.is_none(), "a malformed resize ends the session");
}

#[tokio::test]
async fn p11_nothing_of_the_terminal_works_before_the_login() {
    let r = shell_rig().await;
    let marker = r.dir.path().join("pre_login_shell");
    for kind in [wire::PTY_OPEN, wire::PTY_IN, wire::PTY_RESIZE, wire::PTY_CLOSE] {
        let (mut s, sec) = raw(&r).await;
        let payload = if kind == wire::PTY_OPEN { wire::encode_pty_open(1, 24, 80, b"xterm").unwrap() } else { wire::with_id(1, b"x") };
        send(&mut s, &sec, Frame::new(kind, 0, payload)).await;
        assert!(recv(&mut s, &sec).await.is_none());
    }
    assert!(!marker.exists());
}

#[tokio::test]
async fn p12_the_shell_belongs_to_the_account_and_has_a_clean_environment() {
    std::env::set_var("YRL_SERVER_SECRET2", "leak-check");
    let r = shell_rig().await;
    let c = open(&r).await;
    let mut p = c.pty_open(24, 80, "xterm").await.unwrap();
    p.write(b"echo U=$USER H=$HOME S=[$YRL_SERVER_SECRET2] L=$0; pwd; echo end-$((1+1))p12\n").await.unwrap();
    let out = p.read_until("end-2p12", W).await.unwrap();
    let me = yrl::identity::lookup_uid(yrl::identity::euid()).unwrap();
    assert!(out.contains(&format!("U={} H={}", me.name, me.home)) && out.contains("S=[]"), "{out}");
    assert!(out.contains("L=-"), "started as a login shell: {out}");
}

#[test]
fn p13_codecs_and_shell_rules() {
    assert!(wire::encode_pty_open(1, 0, 80, b"x").is_err() && wire::encode_pty_open(1, 24, 1001, b"x").is_err() && wire::encode_pty_open(1, 24, 80, &[b'a'; 33]).is_err());
    let e = wire::encode_pty_open(7, 1000, 1, b"vt100").unwrap();
    assert_eq!(wire::decode_pty_open(&e).unwrap(), (7, 1000, 1, &b"vt100"[..]));
    assert!(wire::decode_pty_open(&e[..e.len() - 1]).is_err());
    assert_eq!(wire::decode_resize(&wire::encode_resize(3, 5, 6)).unwrap(), (3, 5, 6));
    assert!(wire::decode_resize(&wire::encode_resize(3, 0, 6)).is_err());
    let mut x = 99u64;
    let mut rnd = move || { x ^= x << 13; x ^= x >> 7; x ^= x << 17; x };
    for _ in 0..20_000 {
        let b: Vec<u8> = (0..(rnd() % 40) as usize).map(|_| rnd() as u8).collect();
        let _ = wire::decode_pty_open(&b);
        let _ = wire::decode_resize(&b);
    }
    let shells = "/bin/sh\n/bin/bash\n/usr/sbin/nologin\n/bin/false\n";
    assert!(yrl::identity::usable_shell("/bin/bash", shells));
    for no in ["/usr/sbin/nologin", "/bin/false", "bash", "", "/bin/zsh-not-listed", "/etc/passwd", "/nonexistent/sh"] {
        assert!(!yrl::identity::usable_shell(no, shells), "{no}");
    }
    assert!(!yrl::identity::usable_shell("/bin/bash", "# only comments\n"), "not listed in /etc/shells");
}
