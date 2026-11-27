// REV-004: real process death and disk reservation recovery.

use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use yrl::disk::{DiskLimits, DiskManager, Refusal};
use yrl::identity::{Pw, Target};

const TAG: &[u8] = b"user.yrl.partial\0";
const DATA: &[u8] = b"persistent upload fragment";

fn limits() -> DiskLimits {
    DiskLimits {
        bytes_total: 100,
        bytes_per_key: 100,
        bytes_per_account: 100,
        free_space_reserve: 0,
        partial_ttl: Duration::from_secs(3600),
    }
}

fn target(home: &Path) -> Target {
    Target {
        pw: Pw {
            name: "test".into(),
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            home: home.display().to_string(),
            shell: String::new(),
        },
        switch: false,
    }
}

#[test]
#[ignore = "invoked by parent crash test"]
fn disk_crash_child() {
    let home = std::path::PathBuf::from(
        std::env::var_os("YRL_TEST_DISK_HOME")
            .expect("missing test directory")
    );

    let manager = Arc::new(
        DiskManager::open(
            home.join("ledger"), limits()
        ).unwrap()
    );

    let reservation = manager.reserve(
        b"key-a", "alice", &target(&home),
        b"upload", 60
    ).unwrap();

    let token_hex = reservation.token_hex();
    let token = hex::decode(&token_hex).unwrap();

    let partial = home.join("upload.yrl-part");

    let mut file = std::fs::File::create(&partial)
        .unwrap();

    file.write_all(DATA).unwrap();

    assert_eq!(
        unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                TAG.as_ptr().cast(),
                token.as_ptr().cast(),
                token.len(),
                0,
            )
        },
        0
    );

    file.sync_all().unwrap();

    std::fs::File::open(&home)
        .unwrap().sync_all().unwrap();

    drop(file);

    println!("REV004_READY {token_hex}");
    std::io::stdout().flush().unwrap();

    loop {
        std::thread::park_timeout(
            Duration::from_secs(1)
        );

        std::hint::black_box(&reservation);
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
fn sigkill_preserves_disk_reservation_and_partial() {
    use std::os::unix::process::ExitStatusExt;

    let temp = tempfile::tempdir().unwrap();
    let home = temp.path();
    let ledger = home.join("ledger");
    let partial = home.join("upload.yrl-part");

    let mut child = ChildCleanup(
        Command::new(
            std::env::current_exe().unwrap()
        )
        .args([
            "--ignored",
            "--exact",
            "disk_crash_child",
            "--nocapture",
        ])
        .env("YRL_TEST_DISK_HOME", home)
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

            if let Some(token) =
                line.strip_prefix("REV004_READY ")
            {
                let _ = tx.send(token.to_string());
            }
        }
    });

    let original_token = rx.recv_timeout(
        Duration::from_secs(15)
    ).expect("child did not reserve disk space");

    assert_eq!(original_token.len(), 32);

    assert!(
        DiskManager::open(
            ledger.clone(), limits()
        ).is_err(),
        "second ledger owner was admitted"
    );

    child.0.kill().unwrap();

    let status = child.0.wait().unwrap();

    assert_eq!(status.signal(), Some(libc::SIGKILL));

    reader.join().unwrap();

    // Recovery after process death without Rust destructors.
    let recovered = Arc::new(
        DiskManager::open(
            ledger.clone(), limits()
        ).unwrap()
    );

    let t = target(home);

    assert_eq!(
        std::fs::read(&partial).unwrap(),
        DATA
    );

    // The original charge must survive.
    assert!(matches!(
        recovered.reserve(
            b"key-b", "bob", &t, b"another", 41
        ),
        Err(Refusal::Quota)
    ));

    // Another principal cannot claim the partial.
    assert!(matches!(
        recovered.reserve(
            b"key-b", "bob", &t, b"upload", 60
        ),
        Err(Refusal::Busy)
    ));

    let resumed = recovered.reserve(
        b"key-a", "alice", &t, b"upload", 60
    ).unwrap();

    assert_eq!(
        resumed.token_hex(),
        original_token
    );

    let file = std::fs::File::open(&partial).unwrap();
    let mut attr = [0u8; 64];

    let n = unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            TAG.as_ptr().cast(),
            attr.as_mut_ptr().cast(),
            attr.len(),
        )
    };

    assert_eq!(n, 16);
    assert_eq!(hex::encode(&attr[..16]), original_token);

    drop(file);

    // Exact remaining quota is still available.
    let remaining = recovered.reserve(
        b"key-b", "bob", &t, b"another", 40
    ).unwrap();

    remaining.complete();

    // Cancellation of the resumed reservation removes
    // the matching tagged partial and releases its charge.
    drop(resumed);

    assert!(!partial.exists());

    let full = recovered.reserve(
        b"key-c", "charlie", &t, b"new", 100
    ).unwrap();

    full.complete();

    drop(recovered);

    let reopened = Arc::new(
        DiskManager::open(ledger, limits()).unwrap()
    );

    assert!(
        reopened.reserve(
            b"key-c", "charlie", &t, b"new", 100
        ).is_ok()
    );

    println!("REV-004 REAL SIGKILL RECOVERY: PASS");
}
