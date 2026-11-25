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
