use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use yrl::{ipc, keylife, keys};

#[test]
fn encrypted_recovery_rotation_revocation_and_legacy_migration() {
    let home = tempfile::tempdir().unwrap();
    std::fs::set_permissions(home.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::env::set_var("GNUPGHOME", home.path());
    let created = Command::new("gpg").args(["--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", "YRL Stage4 Test <stage4@example.invalid>", "default", "default", "never"])
        .output().expect("GnuPG is required for recovery");
    assert!(created.status.success(), "{}", String::from_utf8_lossy(&created.stderr));
    let listed = Command::new("gpg").args(["--batch", "--with-colons", "--list-keys"]).output().unwrap();
    let fingerprint = String::from_utf8_lossy(&listed.stdout).lines().find(|l| l.starts_with("fpr:")).unwrap().split(':').nth(9).unwrap().to_string();

    let root = tempfile::tempdir().unwrap();
    let state = root.path().join("state");
    let server = keys::init(&state).unwrap();
    ipc::init_keys(&state).unwrap();
    drop(yrl::audit::AuditService::open(&state, 5).unwrap());
    let old_exec = keys::load(&state.join("ipc/executor")).unwrap().public;
    let client = keys::generate();
    keys::authorize(&state.join("authorized_keys"), &hex::encode(&client.public), "laptop", "exec").unwrap();
    let other = keys::generate();
    keys::authorize(&state.join("authorized_keys"), &hex::encode(&other.public), "other", "exec").unwrap();

    let backup = root.path().join("backup.gpg");
    let running = keylife::service_guard(&state).unwrap();
    assert!(keylife::backup(&state, &backup, &fingerprint).is_err(), "backup raced a running service");
    drop(running);
    keylife::backup(&state, &backup, &fingerprint).unwrap();
    let ciphertext = std::fs::read(&backup).unwrap();
    assert!(!ciphertext.windows(64).any(|w| w == hex::encode(&server.private).as_bytes()), "plaintext private key leaked into backup");
    let restored = root.path().join("restored");
    keylife::restore(&backup, &restored).unwrap();
    assert_eq!(keys::load(&restored).unwrap().public, server.public);
    assert_eq!(keys::load(&restored.join("ipc/executor")).unwrap().public, old_exec);
    drop(yrl::audit::AuditService::open(&restored, 5).unwrap());
    let mut damaged = ciphertext.clone();
    let middle = damaged.len() / 2;
    damaged[middle] ^= 1;
    let bad_backup = root.path().join("damaged.gpg");
    std::fs::write(&bad_backup, damaged).unwrap();
    assert!(keylife::restore(&bad_backup, &root.path().join("damaged-restored")).is_err());

    let recovery = root.path().join("before-rotate.gpg");
    let new_exec = keylife::rotate(&state, "executor", &recovery, &fingerprint).unwrap();
    assert_ne!(new_exec, old_exec);
    assert_eq!(keys::load(&state.join("ipc/executor")).unwrap().public, new_exec);
    let old = root.path().join("pre-rotation");
    keylife::restore(&recovery, &old).unwrap();
    assert_eq!(keys::load(&old.join("ipc/executor")).unwrap().public, old_exec);

    let migration_backup = root.path().join("before-migration.gpg");
    keylife::migrate(&state, &migration_backup, &fingerprint).unwrap();
    assert_eq!(keys::load(&state.join("ipc/executor")).unwrap().public, new_exec);
    let pubfile = state.join("ipc/executor.pub");
    std::fs::write(&pubfile, hex::encode(&old_exec)).unwrap();
    assert!(keys::load(&state.join("ipc/executor")).is_err(), "a partly rotated identity was accepted");
    std::fs::write(&pubfile, hex::encode(&new_exec)).unwrap();
    keylife::revoke_device(&state, &hex::encode(&client.public)).unwrap();
    let authorized = keys::read_authorized(&state.join("authorized_keys"));
    assert_eq!(authorized.len(), 1);
    assert_eq!(authorized[0].public, other.public);

    let keyfile = state.join("ipc/executor/static.key");
    let good = std::fs::read(&keyfile).unwrap();
    std::fs::remove_file(&keyfile).unwrap();
    std::os::unix::fs::symlink(state.join("ipc/broker/static.key"), &keyfile).unwrap();
    assert!(keys::load(&state.join("ipc/executor")).is_err(), "a component followed a key symlink");
    std::fs::remove_file(&keyfile).unwrap();
    std::fs::write(&keyfile, good).unwrap();
    std::fs::set_permissions(&keyfile, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(keys::load(&state.join("ipc/executor")).is_err(), "a shared private key was accepted");
}
