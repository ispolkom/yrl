//! The web account: the login password, the first-time creation of the keys from what the person typed, and the reset of the login
//! password by the recovery secret. ONE implementation, used by the node's web page, by `yandi-keys`, and — through `yandi-keys` — by the
//! second web page (the Python assistant), so that both open with the same password and the same recovery secret.
//!
//! Error messages are short, in Russian, and safe to show to the person: they never contain a password, a key or a path.
use crate::machine::MachineContext;
use crate::root::RootDocument;
use crate::wrap::{KdfParams, KdfPolicy};
use crate::{recovery_secret, DeviceKeyProvider, KeyDir, KeyRootError, RecoveryCode, Zeroizing};

/// Hash a login password (Argon2id, PHC string).
pub fn hash_login_password(password: &str) -> Result<String, String> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("Password hash failed: {}", e))
}

/// Verify a login password against a stored PHC hash.
pub fn verify_login_password(password: &str, stored_hash: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    let Ok(hash) = PasswordHash::new(stored_hash) else {
        return false;
    };
    argon2::Argon2::default()
        .verify_password(password.as_bytes(), &hash)
        .is_ok()
}

/// The web login hash of either auth.json format (1: machine-wrapped key, 2: device + recovery wrappers).
pub fn login_hash_of(json: &str) -> Result<String, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("Failed to parse auth.json: {}", e))?;
    value
        .get("login_hash")
        .and_then(|v| v.as_str())
        .map(str::to_owned)
        .ok_or_else(|| "auth.json has no login hash".to_string())
}

/// Is `password` the login password of the account in `dir`? `Err` when there is no account or its file cannot be read.
pub fn verify_login_in(dir: &KeyDir, password: &str) -> Result<bool, String> {
    let bytes = crate::keydir::read_private_file(&dir.auth_file()).map_err(|e| match e {
        KeyRootError::NotFound => "Вход ещё не настроен".to_string(),
        _ => "Файл ключей недоступен".to_string(),
    })?;
    let json = String::from_utf8(bytes).map_err(|_| "Файл ключей повреждён".to_string())?;
    Ok(verify_login_password(password, &login_hash_of(&json)?))
}

/// Never overwrite existing key material: an auth.json that exists (even one this build cannot open) is somebody's master key.
pub fn ensure_no_existing_auth(path: &std::path::Path) -> Result<(), String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(
            "Auth is already set up; refusing to overwrite the existing key file".to_string(),
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(
            "Не удалось проверить существующее хранилище ключей".to_string(),
        ),
    }
}

/// The rules for what the person typed at first setup, in words that are safe to show.
pub fn check_setup_inputs(
    login: &str,
    login_repeat: &str,
    master: &str,
    master_repeat: &str,
) -> Result<(), String> {
    if login.chars().count() < 8 {
        return Err("Пароль входа: минимум 8 символов".to_string());
    }
    if login != login_repeat {
        return Err("Пароли входа не совпадают".to_string());
    }
    if master.chars().count() < 12 {
        return Err(
            "Мастер-пароль: минимум 12 символов (лучше фраза из нескольких слов)".to_string(),
        );
    }
    if master != master_repeat {
        return Err("Мастер-пароли не совпадают".to_string());
    }
    if master == login {
        return Err("Мастер-пароль должен отличаться от пароля входа".to_string());
    }
    Ok(())
}

/// First-time creation of the keys from what the person typed: a login password and a master password (the person's own recovery
/// secret — not generated). The actual root key is random; it is wrapped for THIS device (a device key file) and for the master password
/// (Argon2id). Nothing is stored that could open the root without the device key or the master password. Refuses initialization if key
/// material already exists. Returns the root (the caller decides what to do with it: the node keeps it in memory, the tool drops it).
pub fn create_keys(
    dir: &KeyDir,
    machine: &dyn MachineContext,
    device: &dyn DeviceKeyProvider,
    login_password: &str,
    master_password: &str,
    params: KdfParams,
    policy: &KdfPolicy,
) -> Result<Zeroizing<[u8; 32]>, String> {
    let _transaction = dir.transaction_lock()
        .map_err(|e| format!(
            "Хранилище ключей недоступно: {}", e
        ))?;
    dir.ensure_clean()
        .map_err(|e| format!(
            "Хранилище ключей недоступно: {}", e
        ))?;


    let auth_path = dir.auth_file();
    ensure_no_existing_auth(&auth_path)?;
    if device.load().map(|k| k.is_some()).unwrap_or(true) {
        return Err("В каталоге ключей уже есть ключ устройства; настройка не выполнена, чтобы ничего не затереть".to_string());
    }
    let root = Zeroizing::new(crate::wrap::random_bytes::<32>());
    let login_hash = hash_login_password(login_password)?;
    // Validate the recovery parameters before modifying disk.
    RootDocument::create(
        &root,
        &login_hash,
        &[0u8; 32],
        "validation",
        machine,
        master_password,
        params,
        policy,
    ).map_err(|e| format!(
        "Не удалось проверить параметры ключей: {}", e
    ))?;

    dir.begin_pending()
        .map_err(|_| {
            "Не удалось начать транзакцию ключей".to_string()
        })?;

    let device_key = device
        .create()
        .map_err(|_| {
            "Создание ключа устройства не подтверждено; требуется локальная проверка"
                .to_string()
        })?;
    let created = (|| -> Result<(), String> {
        let doc = RootDocument::create(
            &root,
            &login_hash,
            &device_key,
            device.name(),
            machine,
            master_password,
            params,
            policy,
        )
        .map_err(|e| format!("Не удалось создать ключи: {}", e))?;
        crate::atomic::create_new_file(&auth_path, &doc.to_json())
            .map_err(|_| "Не удалось записать файл ключей".to_string())?;
        // both ways in must open the very root that was just made, read back from disk
        let bytes = crate::keydir::read_private_file(&auth_path)
            .map_err(|_| "Файл ключей не прочитался".to_string())?;
        let doc = RootDocument::parse(&bytes)
            .map_err(|_| "Файл ключей не прошёл проверку".to_string())?;
        let by_device = doc
            .unlock_with_device(&device_key, machine)
            .map_err(|_| "Ключ устройства не открывает корень".to_string())?;
        let by_password = doc
            .unlock_with_password(master_password, policy)
            .map_err(|_| "Мастер-пароль не открывает корень".to_string())?;
        if *by_device != *root || *by_password != *root {
            return Err("Проверка ключей не прошла".to_string());
        }
        Ok(())
    })();
    // Publication may already have happened despite an error.
    // Preserve all artifacts and leave the pending marker intact.
    created?;

    dir.finish_pending()
        .map_err(|_| {
            "Завершение транзакции ключей не подтверждено; требуется локальная проверка"
                .to_string()
        })?;

    Ok(root)
}

/// Forgot the web password: the recovery secret proves ownership and sets a new one. The recovery wrapper is opened (Argon2id: about half
/// a second per attempt, and the caller throttles attempts); only then is `auth.json` rewritten, atomically, with the same wrappers and
/// the new login hash. Errors are short messages that are safe to show.
pub fn reset_login(
    dir: &KeyDir,
    code_input: &str,
    new_login_password: &str,
    policy: &KdfPolicy,
) -> Result<(), String> {
    let _transaction = dir.transaction_lock()
        .map_err(|e| format!(
            "Хранилище ключей недоступно: {}", e
        ))?;
    dir.ensure_clean()
        .map_err(|e| format!(
            "Хранилище ключей недоступно: {}", e
        ))?;


    if new_login_password.chars().count() < 8 {
        return Err("Новый пароль входа должен быть не короче 8 символов".to_string());
    }
    let bytes = crate::keydir::read_private_file(&dir.auth_file())
        .map_err(|_| "Файл ключей недоступен".to_string())?;
    match crate::legacy::auth_format(&bytes) {
        Ok(crate::legacy::AuthFormat::RootV2) => {}
        Ok(_) => {
            return Err(
                "Ключи в старом формате: сначала выполните `yandi-keys migrate`".to_string(),
            )
        }
        Err(_) => return Err("Файл ключей повреждён".to_string()),
    }
    // a code with a typo is a typo, not "wrong"
    if crate::recovery_code::looks_like_code(code_input) && RecoveryCode::parse(code_input).is_err()
    {
        return Err(
            "В коде опечатка: он не проходит проверку. Проверьте, что записано, и введите ещё раз"
                .to_string(),
        );
    }
    let doc = RootDocument::parse(&bytes).map_err(|_| "Файл ключей повреждён".to_string())?;
    let secret = recovery_secret(code_input);
    let root = match doc.unlock_with_password(&secret, policy) {
        Ok(r) => r,
        Err(KeyRootError::RecoveryFailed) => {
            return Err("Код восстановления не подошёл".to_string())
        }
        Err(_) => return Err("Файл ключей повреждён".to_string()),
    };
    let hash = hash_login_password(new_login_password)?;
    let next = doc.with_login_hash(&hash).to_json();
    let auth_path = dir.auth_file();
    crate::atomic::backup_copy(&auth_path, "before-login-reset")
        .map_err(|_| "Не удалось сохранить копию ключей; ничего не изменено".to_string())?;
    crate::atomic::write_atomic(&auth_path, &next, |written| {
        RootDocument::parse(written)
            .and_then(|d| {
                Ok(d.login_hash == hash && *d.unlock_with_password(&secret, policy)? == *root)
            })
            .unwrap_or(false)
    })
    .map_err(|_| "Не удалось подтвердить запись нового пароля; проверьте состояние ключей".to_string())?;
    Ok(())
}

#[cfg(test)]
mod rev006_setup_tests {
    use super::*;
    use crate::{FileDeviceKey, FixedMachine};

    const LOGIN: &str = "synthetic-login";
    const MASTER: &str = "synthetic-recovery-phrase";

    const PARAMS: KdfParams = KdfParams {
        memory_kib: 32,
        iterations: 1,
        parallelism: 1,
    };

    #[test]
    fn successful_setup_is_reopenable() {
        let d = tempfile::tempdir().unwrap();
        let dir = KeyDir::open(d.path()).unwrap();

        let machine = FixedMachine("test-machine".into());
        let device = FileDeviceKey::new(
            dir.file("device.key")
        );

        let root = create_keys(
            &dir,
            &machine,
            &device,
            LOGIN,
            MASTER,
            PARAMS,
            &KdfPolicy::for_tests(),
        ).unwrap();

        assert!(dir.ensure_clean().is_ok());

        let reopened = KeyDir::open(d.path()).unwrap();

        let (loaded, _) = crate::unlock_root(
            &reopened,
            &machine,
            &device,
        ).unwrap();

        assert!(*root == *loaded);

        assert!(verify_login_in(
            &reopened, LOGIN
        ).unwrap());
    }

    #[test]
    fn existing_setup_is_never_replaced() {
        let d = tempfile::tempdir().unwrap();
        let dir = KeyDir::open(d.path()).unwrap();

        let machine = FixedMachine("test-machine".into());

        let device = FileDeviceKey::new(
            dir.file("device.key")
        );

        create_keys(
            &dir,
            &machine,
            &device,
            LOGIN,
            MASTER,
            PARAMS,
            &KdfPolicy::for_tests(),
        ).unwrap();

        let auth = std::fs::read(
            dir.auth_file()
        ).unwrap();

        let key = std::fs::read(
            dir.file("device.key")
        ).unwrap();

        assert!(create_keys(
            &dir,
            &machine,
            &device,
            "another-login",
            "another-recovery-phrase",
            PARAMS,
            &KdfPolicy::for_tests(),
        ).is_err());

        assert_eq!(
            std::fs::read(dir.auth_file()).unwrap(),
            auth
        );

        assert_eq!(
            std::fs::read(dir.file("device.key")).unwrap(),
            key
        );

        assert!(dir.ensure_clean().is_ok());
    }

    #[test]
    fn invalid_parameters_do_not_create_key_material() {
        let d = tempfile::tempdir().unwrap();
        let dir = KeyDir::open(d.path()).unwrap();

        let machine = FixedMachine("test-machine".into());

        let device = FileDeviceKey::new(
            dir.file("device.key")
        );

        assert!(create_keys(
            &dir,
            &machine,
            &device,
            LOGIN,
            "short",
            PARAMS,
            &KdfPolicy::for_tests(),
        ).is_err());

        assert!(!dir.auth_file().exists());
        assert!(!dir.file("device.key").exists());
        assert!(dir.ensure_clean().is_ok());
    }

    #[test]
    fn pending_setup_refuses_reinitialization() {
        let d = tempfile::tempdir().unwrap();
        let dir = KeyDir::open(d.path()).unwrap();

        {
            let _guard = dir.transaction_lock().unwrap();
            dir.begin_pending().unwrap();
        }

        let machine = FixedMachine("test-machine".into());

        let device = FileDeviceKey::new(
            dir.file("device.key")
        );

        assert!(create_keys(
            &dir,
            &machine,
            &device,
            LOGIN,
            MASTER,
            PARAMS,
            &KdfPolicy::for_tests(),
        ).is_err());

        assert!(!dir.auth_file().exists());
        assert!(!dir.file("device.key").exists());
        assert!(dir.ensure_clean().is_err());
    }

    #[test]
    fn failed_marker_publication_prevents_setup() {
        let d = tempfile::tempdir().unwrap();
        let dir = KeyDir::open(d.path()).unwrap();

        let machine = FixedMachine("test-machine".into());

        let device = FileDeviceKey::new(
            dir.file("device.key")
        );

        crate::atomic::REV006_FAIL_DIR_SYNC.with(
            |flag| flag.set(true)
        );

        assert!(create_keys(
            &dir,
            &machine,
            &device,
            LOGIN,
            MASTER,
            PARAMS,
            &KdfPolicy::for_tests(),
        ).is_err());

        assert!(!dir.auth_file().exists());
        assert!(!dir.file("device.key").exists());

        let reopened = KeyDir::open(d.path()).unwrap();

        assert!(reopened.ensure_clean().is_err());
    }
}

#[cfg(test)]
mod rev006_setup_fault_tests {
    use super::*;
    use crate::{FileDeviceKey, FixedMachine};

    const PARAMS: KdfParams = KdfParams {
        memory_kib: 32,
        iterations: 1,
        parallelism: 1,
    };

    fn check_failure(stage: usize) {
        let d = tempfile::tempdir().unwrap();

        let dir = KeyDir::open(d.path()).unwrap();

        let machine =
            FixedMachine("synthetic-test-machine".into());

        let device =
            FileDeviceKey::new(dir.file("device.key"));

        let policy = KdfPolicy::for_tests();

        crate::atomic::REV006_FAIL_SYNC_AT.with(
            |counter| counter.set(stage)
        );

        let result = create_keys(
            &dir,
            &machine,
            &device,
            "synthetic-login",
            "synthetic-recovery-phrase",
            PARAMS,
            &policy,
        );

        assert!(
            result.is_err(),
            "setup reported success at stage {stage}"
        );

        crate::atomic::REV006_FAIL_SYNC_AT.with(
            |counter| {
                assert_eq!(
                    counter.get(),
                    0,
                    "requested fault was not reached"
                );
            }
        );

        assert!(
            dir.file(".key-root.pending").exists()
        );

        assert_eq!(
            dir.file("device.key").exists(),
            stage >= 2
        );

        assert_eq!(
            dir.auth_file().exists(),
            stage >= 3
        );

        let key_before =
            std::fs::read(dir.file("device.key")).ok();

        let auth_before =
            std::fs::read(dir.auth_file()).ok();

        let reopened = KeyDir::open(d.path()).unwrap();

        assert!(reopened.ensure_clean().is_err());

        assert!(
            crate::unlock_root(
                &reopened,
                &machine,
                &device
            ).is_err()
        );

        assert!(
            create_keys(
                &reopened,
                &machine,
                &device,
                "another-synthetic-login",
                "another-synthetic-recovery",
                PARAMS,
                &policy,
            ).is_err()
        );

        assert_eq!(
            std::fs::read(
                reopened.file("device.key")
            ).ok(),
            key_before
        );

        assert_eq!(
            std::fs::read(
                reopened.auth_file()
            ).ok(),
            auth_before
        );
    }

    #[test]
    fn marker_sync_failure_prevents_key_creation() {
        check_failure(1);
    }

    #[test]
    fn device_sync_failure_preserves_published_file() {
        check_failure(2);
    }

    #[test]
    fn auth_sync_failure_preserves_both_files() {
        check_failure(3);
    }
}

#[cfg(test)]
mod rev006_completion_tests {
    use super::*;
    use crate::{FileDeviceKey, FixedMachine};

    const LOGIN: &str = "synthetic-login";
    const MASTER: &str = "synthetic-recovery-phrase";

    const PARAMS: KdfParams = KdfParams {
        memory_kib: 32,
        iterations: 1,
        parallelism: 1,
    };

    #[test]
    fn completed_setup_opens_by_both_wrappers() {
        let d = tempfile::tempdir().unwrap();
        let dir = KeyDir::open(d.path()).unwrap();

        let machine = FixedMachine("test-machine".into());
        let device = FileDeviceKey::new(
            dir.file("device.key")
        );

        let policy = KdfPolicy::for_tests();

        let root = create_keys(
            &dir, &machine, &device,
            LOGIN, MASTER, PARAMS, &policy,
        ).unwrap();

        let bytes = crate::keydir::read_private_file(
            &dir.auth_file()
        ).unwrap();

        let doc = RootDocument::parse(&bytes).unwrap();

        let device_key = device.load()
            .unwrap().unwrap();

        let by_device = doc.unlock_with_device(
            &device_key, &machine
        ).unwrap();

        let by_password = doc.unlock_with_password(
            MASTER, &policy
        ).unwrap();

        assert!(*root == *by_device);
        assert!(*root == *by_password);

        assert!(dir.ensure_clean().is_ok());
    }

    #[test]
    fn completion_sync_failure_preserves_key_material() {
        let d = tempfile::tempdir().unwrap();
        let dir = KeyDir::open(d.path()).unwrap();

        let machine = FixedMachine("test-machine".into());

        let device = FileDeviceKey::new(
            dir.file("device.key")
        );

        let policy = KdfPolicy::for_tests();

        // 1: pending marker
        // 2: device file
        // 3: auth document
        // 4: transaction completion
        crate::atomic::REV006_FAIL_SYNC_AT.with(
            |counter| counter.set(4)
        );

        assert!(create_keys(
            &dir, &machine, &device,
            LOGIN, MASTER, PARAMS, &policy,
        ).is_err());

        crate::atomic::REV006_FAIL_SYNC_AT.with(
            |counter| assert_eq!(counter.get(), 0)
        );

        assert!(dir.auth_file().exists());
        assert!(dir.file("device.key").exists());
        assert!(dir.file(".key-root.pending").exists());

        let reopened = KeyDir::open(d.path()).unwrap();

        assert!(reopened.ensure_clean().is_err());

        assert!(crate::unlock_root(
            &reopened, &machine, &device
        ).is_err());

        // Verify integrity without modifying the
        // synthetic test files.
        let doc = RootDocument::parse(
            &std::fs::read(
                reopened.auth_file()
            ).unwrap()
        ).unwrap();

        let key = device.load().unwrap().unwrap();

        let first = doc.unlock_with_device(
            &key, &machine
        ).unwrap();

        let second = doc.unlock_with_password(
            MASTER, &policy
        ).unwrap();

        assert!(*first == *second);
    }
}
