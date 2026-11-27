//! The key directory (`~/.yandi_keys`) and the files in it: opened only if they are really ours and private.
use crate::error::{KeyRootError, Result};
use std::fs::{self, DirBuilder};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub(crate) fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

pub struct KeyDir {
    path: PathBuf,
}

impl KeyDir {
    /// Create the directory 0700, or accept an existing one that is a real directory of this user. A directory that is only too
    /// open (0755 is what earlier versions left) is tightened to 0700; anything else strange — a link, another owner, not a
    /// directory — is refused and left alone.
    pub fn open(path: impl Into<PathBuf>) -> Result<KeyDir> {
        let path = path.into();
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.is_dir() || meta.uid() != euid() {
                    return Err(KeyRootError::PermissionDenied);
                }
                if meta.mode() & 0o077 != 0 {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                DirBuilder::new().mode(0o700).create(&path)?;
            }
            Err(e) => return Err(e.into()),
        }
        Ok(KeyDir { path })
    }

    /// Exclusive guard for a complete key-store operation.
    /// The stable lock file is never removed by the library.
    pub(crate) fn transaction_lock(&self) -> Result<fs::File> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;

        let path = self.file(".key-root.lock");

        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(
                libc::O_NOFOLLOW |
                libc::O_CLOEXEC |
                libc::O_NONBLOCK
            )
            .open(&path)?;

        let meta = file.metadata()?;

        if !meta.is_file()
            || meta.uid() != euid()
            || meta.mode() & 0o077 != 0
            || meta.nlink() != 1
        {
            return Err(KeyRootError::PermissionDenied);
        }

        loop {
            let rc = unsafe {
                libc::flock(
                    file.as_raw_fd(),
                    libc::LOCK_EX | libc::LOCK_NB
                )
            };

            if rc == 0 {
                break;
            }

            let error = std::io::Error::last_os_error();

            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }

            if error.kind() == std::io::ErrorKind::WouldBlock {
                return Err(KeyRootError::Refused(
                    "another key-store operation is running"
                ));
            }

            return Err(error.into());
        }

        // Confirm that the name still refers to the locked inode.
        let current = fs::symlink_metadata(&path)?;

        if current.dev() != meta.dev()
            || current.ino() != meta.ino()
            || !current.is_file()
            || current.nlink() != 1
            || current.uid() != euid()
            || current.mode() & 0o077 != 0
        {
            return Err(KeyRootError::PermissionDenied);
        }

        Ok(file)
    }

    // A persistent transaction marker contains no secrets.
    fn pending_path(&self) -> PathBuf {
        self.file(".key-root.pending")
    }

    pub(crate) fn ensure_clean(&self) -> Result<()> {
        match fs::symlink_metadata(self.pending_path()) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
            Ok(_) => Err(KeyRootError::Refused(
                "unfinished key-store transaction; local recovery required"
            )),
        }
    }

    // These methods must be called while holding the
    // exclusive transaction guard.
    pub(crate) fn begin_pending(&self) -> Result<()> {
        self.ensure_clean()?;

        crate::atomic::create_new_file(
            &self.pending_path(),
            b"YRL KEY ROOT PENDING 1\n",
        )
    }

    pub(crate) fn finish_pending(&self) -> Result<()> {
        fs::remove_file(self.pending_path())?;

        if crate::atomic::sync_parent(
            &self.pending_path()
        ).is_err() {
            // Best effort to restore the refusal marker.
            let _ = self.begin_pending();

            return Err(KeyRootError::Refused(
                "transaction completion uncertain; local recovery required"
            ));
        }

        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    pub fn auth_file(&self) -> PathBuf {
        self.file("auth.json")
    }

    pub fn identity_file(&self, port: u16) -> PathBuf {
        self.file(&format!("node_identity_{port}.json"))
    }

    /// Names of any identity-like files here (for any port, including backups), so that "nothing found" can be told from "something
    /// I cannot open".
    pub fn identity_artifacts(&self) -> Vec<String> {
        let mut found = Vec::new();
        if let Ok(entries) = fs::read_dir(&self.path) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("node_identity_") {
                    found.push(name);
                }
            }
        }
        found.sort();
        found
    }
}

/// A key file must be a regular file (not a link) of this user that others cannot read.
pub fn check_private_file(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink()
        || !meta.is_file()
        || meta.uid() != euid()
        || meta.mode() & 0o077 != 0
    {
        return Err(KeyRootError::PermissionDenied);
    }
    Ok(())
}

/// Read a key file that has passed `check_private_file`; the read itself does not follow links either.
pub fn read_private_file(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    check_private_file(path)?;
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut bytes = Vec::new();
    file.take(1 << 20).read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod rev006_lock_tests {
    use super::*;

    #[test]
    fn independent_instances_cannot_overlap() {
        let d = tempfile::tempdir().unwrap();

        let first = KeyDir::open(d.path()).unwrap();
        let second = KeyDir::open(d.path()).unwrap();

        let guard = first.transaction_lock().unwrap();

        assert!(matches!(
            second.transaction_lock(),
            Err(KeyRootError::Refused(_))
        ));

        drop(guard);

        assert!(second.transaction_lock().is_ok());
    }

    #[test]
    fn lock_inode_remains_stable() {
        let d = tempfile::tempdir().unwrap();
        let dir = KeyDir::open(d.path()).unwrap();

        let path = dir.file(".key-root.lock");

        let guard = dir.transaction_lock().unwrap();

        let inode = fs::metadata(&path).unwrap().ino();

        drop(guard);

        let _next = dir.transaction_lock().unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().ino(),
            inode
        );
    }

    #[test]
    fn public_lock_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let dir = KeyDir::open(d.path()).unwrap();

        let path = dir.file(".key-root.lock");

        fs::write(&path, b"").unwrap();

        fs::set_permissions(
            &path,
            fs::Permissions::from_mode(0o666)
        ).unwrap();

        assert!(matches!(
            dir.transaction_lock(),
            Err(KeyRootError::PermissionDenied)
        ));
    }

    #[test]
    fn symbolic_lock_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let dir = KeyDir::open(d.path()).unwrap();

        let target = dir.file("unrelated");

        fs::write(&target, b"unchanged").unwrap();

        std::os::unix::fs::symlink(
            &target,
            dir.file(".key-root.lock")
        ).unwrap();

        assert!(dir.transaction_lock().is_err());

        assert_eq!(
            fs::read(&target).unwrap(),
            b"unchanged"
        );
    }

    #[test]
    fn multiply_linked_lock_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let dir = KeyDir::open(d.path()).unwrap();

        let guard = dir.transaction_lock().unwrap();
        drop(guard);

        fs::hard_link(
            dir.file(".key-root.lock"),
            dir.file("extra-link")
        ).unwrap();

        assert!(matches!(
            dir.transaction_lock(),
            Err(KeyRootError::PermissionDenied)
        ));
    }

    #[test]
    fn separate_directories_are_independent() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();

        let first = KeyDir::open(a.path()).unwrap();
        let second = KeyDir::open(b.path()).unwrap();

        let _one = first.transaction_lock().unwrap();
        let _two = second.transaction_lock().unwrap();
    }
}

#[cfg(test)]
mod rev006_pending_tests {
    use super::*;

    #[test]
    fn unfinished_transaction_survives_reopen() {
        let d = tempfile::tempdir().unwrap();

        {
            let dir = KeyDir::open(d.path()).unwrap();
            let _guard = dir.transaction_lock().unwrap();

            dir.begin_pending().unwrap();

            assert!(dir.ensure_clean().is_err());
        }

        let reopened = KeyDir::open(d.path()).unwrap();
        let _guard = reopened.transaction_lock().unwrap();

        assert!(matches!(
            reopened.ensure_clean(),
            Err(KeyRootError::Refused(_))
        ));
    }

    #[test]
    fn completed_transaction_allows_next_operation() {
        let d = tempfile::tempdir().unwrap();
        let dir = KeyDir::open(d.path()).unwrap();

        let _guard = dir.transaction_lock().unwrap();

        dir.begin_pending().unwrap();
        dir.finish_pending().unwrap();

        assert!(dir.ensure_clean().is_ok());

        dir.begin_pending().unwrap();
        dir.finish_pending().unwrap();
    }

    #[test]
    fn pending_marker_cannot_be_overwritten() {
        let d = tempfile::tempdir().unwrap();
        let dir = KeyDir::open(d.path()).unwrap();

        let _guard = dir.transaction_lock().unwrap();

        dir.begin_pending().unwrap();

        let original = fs::read(dir.pending_path())
            .unwrap();

        assert!(dir.begin_pending().is_err());

        assert_eq!(
            fs::read(dir.pending_path()).unwrap(),
            original
        );
    }

    #[test]
    fn malformed_marker_requires_recovery() {
        let d = tempfile::tempdir().unwrap();
        let dir = KeyDir::open(d.path()).unwrap();

        let _guard = dir.transaction_lock().unwrap();

        fs::write(dir.pending_path(), b"").unwrap();

        assert!(dir.ensure_clean().is_err());
    }

    #[test]
    fn marker_has_private_permissions() {
        let d = tempfile::tempdir().unwrap();
        let dir = KeyDir::open(d.path()).unwrap();

        let _guard = dir.transaction_lock().unwrap();

        dir.begin_pending().unwrap();

        let meta = fs::metadata(dir.pending_path())
            .unwrap();

        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(meta.nlink(), 1);
        assert_eq!(meta.uid(), euid());
    }
}

#[cfg(test)]
mod rev006_process_tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    #[test]
    #[ignore]
    fn process_worker() {
        let path = std::env::var_os(
            "REV006_TEST_DIRECTORY"
        ).expect("test directory");

        let stage = std::env::var(
            "REV006_TEST_STAGE"
        ).unwrap();

        let dir = KeyDir::open(
            PathBuf::from(path)
        ).unwrap();

        let _guard = dir.transaction_lock().unwrap();

        dir.begin_pending().unwrap();

        if stage == "published" || stage == "completed" {
            crate::atomic::create_new_file(
                &dir.file("synthetic-data"),
                b"synthetic payload",
            ).unwrap();
        }

        if stage == "completed" {
            dir.finish_pending().unwrap();
        }

        fs::write(
            dir.file("worker-ready"),
            b"ready",
        ).unwrap();

        loop {
            std::thread::sleep(
                Duration::from_millis(100)
            );
        }
    }

    fn check_interruption(stage: &str) {
        let d = tempfile::tempdir().unwrap();

        let dir = KeyDir::open(d.path()).unwrap();

        let mut child = Command::new(
            std::env::current_exe().unwrap()
        )
        .args([
            "--exact",
            "keydir::rev006_process_tests::process_worker",
            "--ignored",
            "--nocapture",
        ])
        .env("REV006_TEST_DIRECTORY", d.path())
        .env("REV006_TEST_STAGE", stage)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();

        let deadline =
            Instant::now() + Duration::from_secs(10);

        while !dir.file("worker-ready").exists() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!("worker exited early: {status}");
            }

            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("worker readiness timeout");
            }

            std::thread::sleep(
                Duration::from_millis(10)
            );
        }

        let competing = dir.transaction_lock();
        let refused = matches!(
            competing,
            Err(KeyRootError::Refused(_))
        );

        child.kill().unwrap();

        let status = child.wait().unwrap();

        use std::os::unix::process::ExitStatusExt;

        assert_eq!(status.signal(), Some(libc::SIGKILL));
        assert!(refused);

        let reopened = KeyDir::open(d.path()).unwrap();

        let _guard = reopened.transaction_lock().unwrap();

        assert_eq!(
            reopened.ensure_clean().is_ok(),
            stage == "completed"
        );

        if stage == "marker" {
            assert!(!reopened.file("synthetic-data").exists());
        } else {
            assert_eq!(
                fs::read(
                    reopened.file("synthetic-data")
                ).unwrap(),
                b"synthetic payload"
            );
        }
    }

    #[test]
    fn interruption_after_marker_publication() {
        check_interruption("marker");
    }

    #[test]
    fn interruption_after_data_publication() {
        check_interruption("published");
    }

    #[test]
    fn interruption_after_transaction_completion() {
        check_interruption("completed");
    }
}
