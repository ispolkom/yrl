// REV-003: real process death and persistent replay protection.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use yrl::opjournal::{
    Journal, Limits, Refusal, State, KIND_EXEC,
};

const KEY: &[u8] = b"rev003-test-key";
const ACCOUNT: &str = "test-account";
const ID: u64 = 9001;
const PAYLOAD: &[u8] = b"test-operation";

fn limits() -> Limits {
    Limits { max_records: 16 }
}

#[test]
#[ignore = "invoked by parent crash test"]
fn journal_crash_child() {
    let path = std::env::var_os(
        "YRL_TEST_JOURNAL_PATH"
    ).expect("missing test journal path");

    let journal = Arc::new(
        Journal::open(path.into(), limits()).unwrap()
    );

    let guard = journal.accept(
        KEY, ACCOUNT, ID, KIND_EXEC, PAYLOAD
    ).unwrap();

    assert!(guard.running());

    println!("REV003_CHILD_RUNNING");
    std::io::stdout().flush().unwrap();

    // Keep both the guard and journal alive until SIGKILL.
    loop {
        std::thread::park_timeout(
            Duration::from_secs(1)
        );

        std::hint::black_box(&guard);
    }
}

struct ChildCleanup(std::process::Child);

impl Drop for ChildCleanup {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn sigkill_releases_ownership_and_preserves_replay_protection() {
    use std::os::unix::process::ExitStatusExt;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("operation-states");

    let mut child = ChildCleanup(
        Command::new(
            std::env::current_exe().unwrap()
        )
        .args([
            "--ignored",
            "--exact",
            "journal_crash_child",
            "--nocapture",
        ])
        .env("YRL_TEST_JOURNAL_PATH", &path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
    );

    let stdout = child.0.stdout.take().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();

    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };

            if line.contains("REV003_CHILD_RUNNING") {
                let _ = tx.send(());
            }
        }
    });

    rx.recv_timeout(Duration::from_secs(15))
        .expect("child did not enter RUNNING");

    // A genuinely separate process owns this journal.
    assert!(
        Journal::open(path.clone(), limits()).is_err(),
        "second process acquired an occupied journal"
    );

    // On Unix Child::kill sends SIGKILL.
    child.0.kill().unwrap();

    let status = child.0.wait().unwrap();

    assert_eq!(status.signal(), Some(libc::SIGKILL));

    reader.join().unwrap();

    // No Rust destructors ran in the killed process.
    let recovered = Arc::new(
        Journal::open(path.clone(), limits()).unwrap()
    );

    let retained = recovered.status(
        KEY, ACCOUNT, ID
    ).unwrap();

    assert_eq!(retained.state, State::Unknown);
    assert_eq!(retained.result, None);

    assert!(matches!(
        recovered.accept(
            KEY, ACCOUNT, ID, KIND_EXEC, PAYLOAD
        ),
        Err(Refusal::Duplicate(_))
    ));

    assert!(matches!(
        recovered.accept(
            KEY, ACCOUNT, ID, KIND_EXEC, b"changed"
        ),
        Err(Refusal::Conflict)
    ));

    // Recovery must allow unrelated new operations.
    let guard = recovered.accept(
        KEY, ACCOUNT, ID + 1, KIND_EXEC, PAYLOAD
    ).unwrap();

    assert!(guard.running());
    assert!(guard.finish(State::Completed, Some(0)));

    drop(recovered);

    let reopened = Journal::open(path, limits()).unwrap();

    assert_eq!(
        reopened.status(KEY, ACCOUNT, ID)
            .unwrap().state,
        State::Unknown
    );

    assert_eq!(
        reopened.status(KEY, ACCOUNT, ID + 1)
            .unwrap().state,
        State::Completed
    );

    println!("REV-003 REAL SIGKILL RECOVERY: PASS");
}
