//! Writing that can fail without harm: the original bytes are replaced only by a file that has been written, flushed and read back
//! and passed the caller's own check. Backups are copies that are never overwritten and never removed by this code.
use crate::error::{KeyRootError, Result};
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};


#[cfg(test)]
std::thread_local! {
    pub(crate) static REV006_FAIL_DIR_SYNC: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };

    pub(crate) static REV006_FAIL_SYNC_AT: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

pub(crate) fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(test)]
    if REV006_FAIL_DIR_SYNC.with(|flag| flag.replace(false)) {
        return Err(KeyRootError::Io);
    }

    #[cfg(test)]
    if REV006_FAIL_SYNC_AT.with(|counter| {
        let n = counter.get();

        if n == 0 {
            false
        } else {
            counter.set(n - 1);
            n == 1
        }
    }) {
        return Err(KeyRootError::Io);
    }

    let parent = path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    fs::File::open(parent)?.sync_all()?;

    Ok(())
}

fn temp_name(path: &Path) -> PathBuf {
    let mut tag = [0u8; 6];
    rand::rngs::OsRng.fill_bytes(&mut tag);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!(".{name}.tmp-{}", hex::encode(tag)))
}

/// Replace `path` with verified bytes (mode 0600).
/// Success requires both file and parent directory synchronization.
/// Before rename, a failure leaves the original unchanged.
/// After rename, a directory synchronization failure is returned
/// to the caller, but the replacement may already be visible.
/// Callers must not assume that an error implies rollback.
pub fn write_atomic(path: &Path, bytes: &[u8], verify: impl FnOnce(&[u8]) -> bool) -> Result<()> {
    let tmp = temp_name(path);
    let mut owns_tmp = false;
    let result = (|| -> Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        owns_tmp = true;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        let back = fs::read(&tmp)?;
        if back != bytes || !verify(&back) {
            return Err(KeyRootError::Corrupt);
        }
        fs::rename(&tmp, path)?;
        sync_parent(path)?;
        Ok(())
    })();
    if result.is_err() && owns_tmp {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Create a new private file without replacing an existing file.
/// Success requires file and directory synchronization.
/// A directory synchronization failure leaves the published file
/// in place and returns an error.
pub fn create_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    create_new_file_inner(path, bytes).map_err(Into::into)
}

// Publish a prepared file without replacing an existing
// destination and without creating an extra hard link.
fn rename_noreplace(
    source: &Path,
    destination: &Path,
) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let source = CString::new(
        source.as_os_str().as_bytes()
    ).map_err(|_| {
        std::io::Error::from_raw_os_error(libc::EINVAL)
    })?;

    let destination = CString::new(
        destination.as_os_str().as_bytes()
    ).map_err(|_| {
        std::io::Error::from_raw_os_error(libc::EINVAL)
    })?;

    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };

    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn create_new_file_inner(
    path: &Path,
    bytes: &[u8],
) -> std::io::Result<()> {
    let tmp = temp_name(path);

    // Only clean up a temporary file that this call
    // actually created.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)?;

    let prepared = file.write_all(bytes)
        .and_then(|_| file.sync_all());

    drop(file);

    if let Err(e) = prepared {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    // Atomic publication without replacement.
    if let Err(e) = rename_noreplace(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    // Publication consumed the temporary name.
    // Never remove the destination on a later error.

    sync_parent(path).map_err(|_| {
        std::io::Error::from_raw_os_error(libc::EIO)
    })?;

    Ok(())
}

/// Copy `path` to `<name>.<label>-<counter>` next to it, exclusively (an earlier backup is never overwritten). Returns the copy.
pub fn backup_copy(path: &Path, label: &str) -> Result<PathBuf> {
    let bytes = fs::read(path)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    for n in 0..1000u32 {
        let target = path.with_file_name(format!("{name}.{label}-{n:03}"));
        match create_new_file_inner(&target, &bytes) {
            Ok(()) => return Ok(target),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(KeyRootError::Io)
}

#[cfg(test)]
mod rev006_tests {
    use super::*;

    fn inject_failure() {
        REV006_FAIL_DIR_SYNC.with(|flag| flag.set(true));
    }

    #[test]
    fn atomic_write_requires_directory_sync() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("sample");

        fs::write(&path, b"original").unwrap();

        inject_failure();

        let result = write_atomic(
            &path, b"replacement", |_| true
        );

        assert_eq!(result, Err(KeyRootError::Io));
    }

    #[test]
    fn new_file_requires_directory_sync() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("sample");

        inject_failure();

        let result = create_new_file(
            &path, b"synthetic data"
        );

        assert_eq!(result, Err(KeyRootError::Io));
    }

    #[test]
    fn backup_requires_directory_sync() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("sample");

        fs::write(&path, b"original").unwrap();

        inject_failure();

        let result = backup_copy(&path, "test");

        assert_eq!(result, Err(KeyRootError::Io));
    }

    #[test]
    fn rejected_replacement_preserves_original() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("sample");

        fs::write(&path, b"original").unwrap();

        assert_eq!(
            write_atomic(&path, b"replacement", |_| false),
            Err(KeyRootError::Corrupt)
        );

        assert_eq!(
            fs::read(&path).unwrap(),
            b"original"
        );

        assert_eq!(
            fs::read_dir(d.path()).unwrap().count(),
            1
        );
    }

    #[test]
    fn exclusive_creation_preserves_existing_file() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("sample");

        create_new_file(&path, b"original").unwrap();

        assert!(
            create_new_file(&path, b"replacement").is_err()
        );

        assert_eq!(
            fs::read(&path).unwrap(),
            b"original"
        );
    }

    #[test]
    fn successful_replacement_is_readable() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("sample");

        create_new_file(&path, b"original").unwrap();

        write_atomic(
            &path,
            b"replacement",
            |bytes| bytes == b"replacement"
        ).unwrap();

        assert_eq!(
            fs::read(&path).unwrap(),
            b"replacement"
        );
    }
}

#[cfg(test)]
mod rev006_extended_tests {
    use super::*;

    #[test]
    fn failed_backup_publication_is_not_retried() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("sample");

        fs::write(&path, b"original").unwrap();

        REV006_FAIL_DIR_SYNC.with(|flag| flag.set(true));

        assert_eq!(
            backup_copy(&path, "test"),
            Err(KeyRootError::Io)
        );

        assert_eq!(
            fs::read(&path).unwrap(),
            b"original"
        );

        assert!(!d.path().join("sample.test-001").exists());
    }

    #[test]
    fn existing_backup_is_never_overwritten() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("sample");

        fs::write(&path, b"current").unwrap();

        let previous = d.path().join("sample.test-000");

        fs::write(&previous, b"previous").unwrap();

        let backup = backup_copy(&path, "test").unwrap();

        assert_eq!(
            backup,
            d.path().join("sample.test-001")
        );

        assert_eq!(
            fs::read(&previous).unwrap(),
            b"previous"
        );

        assert_eq!(
            fs::read(&backup).unwrap(),
            b"current"
        );
    }

    #[test]
    fn uncertain_replacement_is_not_reported_as_success() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("sample");

        create_new_file(&path, b"original").unwrap();

        REV006_FAIL_DIR_SYNC.with(|flag| flag.set(true));

        assert_eq!(
            write_atomic(&path, b"replacement", |_| true),
            Err(KeyRootError::Io)
        );

        assert_eq!(
            fs::read(&path).unwrap(),
            b"replacement"
        );

        assert_eq!(
            fs::read_dir(d.path()).unwrap().count(),
            1
        );
    }

    #[test]
    fn new_file_is_preserved_after_publication_error() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("sample");

        REV006_FAIL_DIR_SYNC.with(|flag| flag.set(true));

        assert_eq!(
            create_new_file(&path, b"synthetic"),
            Err(KeyRootError::Io)
        );

        assert_eq!(
            fs::read(&path).unwrap(),
            b"synthetic"
        );

        assert!(
            create_new_file(&path, b"replacement").is_err()
        );

        assert_eq!(
            fs::read(&path).unwrap(),
            b"synthetic"
        );
    }

    #[test]
    fn private_file_permissions_are_preserved() {
        use std::os::unix::fs::PermissionsExt;

        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("sample");

        create_new_file(&path, b"original").unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap()
                .permissions().mode() & 0o777,
            0o600
        );

        write_atomic(&path, b"replacement", |_| true)
            .unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap()
                .permissions().mode() & 0o777,
            0o600
        );

        let backup = backup_copy(&path, "test").unwrap();

        assert_eq!(
            fs::metadata(&backup).unwrap()
                .permissions().mode() & 0o777,
            0o600
        );
    }
}

#[cfg(test)]
mod rev006_concurrency_tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn exclusive_creation_has_exactly_one_winner() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("sample");

        let workers = 16;
        let barrier = Barrier::new(workers);

        let results = std::thread::scope(|scope| {
            let mut handles = Vec::new();

            for i in 0..workers {
                let path = &path;
                let barrier = &barrier;

                handles.push(scope.spawn(move || {
                    let data = vec![i as u8; 65536];

                    barrier.wait();

                    let result =
                        create_new_file(path, &data);

                    (i, result)
                }));
            }

            handles.into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });

        let winners: Vec<_> = results.iter()
            .filter(|(_, result)| result.is_ok())
            .collect();

        assert_eq!(winners.len(), 1);

        let expected = vec![
            winners[0].0 as u8; 65536
        ];

        assert_eq!(
            fs::read(&path).unwrap(),
            expected
        );

        assert_eq!(
            fs::read_dir(d.path()).unwrap().count(),
            1,
            "temporary files were leaked"
        );
    }

    #[test]
    fn concurrent_backups_are_distinct_and_complete() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("sample");

        let original = vec![0x42u8; 65536];

        create_new_file(&path, &original).unwrap();

        let workers = 16;
        let barrier = Barrier::new(workers);

        let backups = std::thread::scope(|scope| {
            let mut handles = Vec::new();

            for _ in 0..workers {
                let path = &path;
                let barrier = &barrier;

                handles.push(scope.spawn(move || {
                    barrier.wait();
                    backup_copy(path, "parallel").unwrap()
                }));
            }

            handles.into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });

        let unique: std::collections::HashSet<_> =
            backups.iter().collect();

        assert_eq!(unique.len(), workers);

        for backup in &backups {
            assert_eq!(
                fs::read(backup).unwrap(),
                original
            );
        }

        assert_eq!(
            fs::read(&path).unwrap(),
            original
        );

        assert_eq!(
            fs::read_dir(d.path()).unwrap().count(),
            workers + 1
        );
    }

    #[test]
    fn published_file_has_only_one_link() {
        use std::os::unix::fs::MetadataExt;

        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("sample");

        create_new_file(&path, b"synthetic").unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().nlink(),
            1
        );

        assert_eq!(
            fs::read_dir(d.path()).unwrap().count(),
            1
        );
    }
}

#[cfg(test)]
mod rev006_publication_tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn publication_consumes_temporary_name() {
        let d = tempfile::tempdir().unwrap();

        let source = d.path().join("prepared");
        let destination = d.path().join("published");

        fs::write(&source, b"synthetic data").unwrap();

        let inode = fs::metadata(&source).unwrap().ino();

        rename_noreplace(&source, &destination)
            .unwrap();

        assert!(!source.exists());

        let metadata = fs::metadata(&destination)
            .unwrap();

        assert_eq!(metadata.ino(), inode);
        assert_eq!(metadata.nlink(), 1);

        assert_eq!(
            fs::read(&destination).unwrap(),
            b"synthetic data"
        );
    }

    #[test]
    fn publication_never_replaces_existing_destination() {
        let d = tempfile::tempdir().unwrap();

        let source = d.path().join("prepared");
        let destination = d.path().join("published");

        fs::write(&source, b"new data").unwrap();
        fs::write(&destination, b"original").unwrap();

        let error = rename_noreplace(
            &source, &destination
        ).unwrap_err();

        assert_eq!(
            error.kind(),
            std::io::ErrorKind::AlreadyExists
        );

        assert_eq!(
            fs::read(&destination).unwrap(),
            b"original"
        );

        assert_eq!(
            fs::read(&source).unwrap(),
            b"new data"
        );
    }

    #[test]
    fn publication_refuses_existing_symbolic_link() {
        let d = tempfile::tempdir().unwrap();

        let source = d.path().join("prepared");
        let destination = d.path().join("published");
        let target = d.path().join("unrelated");

        fs::write(&source, b"new data").unwrap();
        fs::write(&target, b"original").unwrap();

        std::os::unix::fs::symlink(
            &target, &destination
        ).unwrap();

        assert!(
            rename_noreplace(
                &source, &destination
            ).is_err()
        );

        assert_eq!(
            fs::read(&target).unwrap(),
            b"original"
        );

        assert!(
            fs::symlink_metadata(&destination)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn uncertain_publication_leaves_no_extra_link() {
        let d = tempfile::tempdir().unwrap();

        let path = d.path().join("sample");

        REV006_FAIL_DIR_SYNC.with(|flag| {
            flag.set(true);
        });

        assert_eq!(
            create_new_file(&path, b"synthetic"),
            Err(KeyRootError::Io)
        );

        assert_eq!(
            fs::metadata(&path).unwrap().nlink(),
            1
        );

        assert_eq!(
            fs::read(&path).unwrap(),
            b"synthetic"
        );

        assert_eq!(
            fs::read_dir(d.path()).unwrap().count(),
            1
        );
    }
}
