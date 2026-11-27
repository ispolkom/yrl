//! Offline key lifecycle. GnuPG supplies encryption and integrity for backups; this module only
//! frames files with fixed bounds and never writes an unencrypted intermediate archive.
use anyhow::{bail, Context, Result};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8; 8] = b"YRLKEY4\0";
const MAX_FILES: usize = 1024;
const MAX_BYTES: u64 = 8 << 30;
const SIDES: &[&str] = &[
    "executor",
    "gatekeeper",
    "broker",
    "audit",
    "owner",
    "firewall",
    "firewall-door",
];
const TOP: &[&str] = &[
    "static.key",
    "authorized_keys",
    "users",
    "tunnels",
    "words",
    "words.root",
    "ipc",
    "audit",
    "exec",
    "broker",
    "enroll",
];

pub struct ServiceGuard {
    _file: File,
}

fn lock_state(dir: &Path, how: i32) -> Result<ServiceGuard> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)?;
    if unsafe { libc::flock(f.as_raw_fd(), how | libc::LOCK_NB) } != 0 {
        bail!("state directory is in use by a server service or another key operation");
    }
    Ok(ServiceGuard { _file: f })
}

pub fn service_guard(dir: &Path) -> Result<ServiceGuard> {
    lock_state(dir, libc::LOCK_SH)
}
fn offline_guard(dir: &Path) -> Result<ServiceGuard> {
    lock_state(dir, libc::LOCK_EX)
}

fn validate_path(rel: &Path) -> Result<()> {
    if rel.components().count() > 8
        || rel.components().any(|c| !matches!(c, Component::Normal(_)))
        || !rel
            .components()
            .next()
            .and_then(|c| c.as_os_str().to_str())
            .is_some_and(|s| TOP.contains(&s))
    {
        bail!("invalid backup path");
    }
    Ok(())
}

fn collect(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(PathBuf, u64)>,
    total: &mut u64,
    nodes: &mut usize,
) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let rel = path.strip_prefix(root)?;
        validate_path(rel)?;
        *nodes += 1;
        if *nodes > MAX_FILES * 4 || rel.components().count() > 8 {
            bail!("backup directory limit exceeded");
        }
        let m = fs::symlink_metadata(&path)?;
        if m.is_dir() {
            collect(root, &path, out, total, nodes)?;
        } else if m.is_file() {
            if m.nlink() != 1 || m.len() > MAX_BYTES || *total > MAX_BYTES - m.len() {
                bail!("backup size or hard-link limit exceeded");
            }
            *total += m.len();
            out.push((rel.to_path_buf(), m.len()));
            if out.len() > MAX_FILES {
                bail!("too many backup files");
            }
        } else if m.file_type().is_socket() {
            continue;
        }
        // stale runtime socket after shutdown
        else {
            bail!("backup refuses special file or symlink {}", path.display());
        }
    }
    Ok(())
}

fn inventory(dir: &Path) -> Result<Vec<(PathBuf, u64)>> {
    let base = fs::symlink_metadata(dir)?;
    if !base.is_dir() || base.mode() & 0o022 != 0 {
        bail!("state directory is unsafe");
    }
    let mut out = vec![];
    let mut total = 0;
    let mut nodes = 0;
    for name in TOP {
        let path = dir.join(name);
        let m = match fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e.into()),
        };
        if m.is_dir() {
            collect(dir, &path, &mut out, &mut total, &mut nodes)?;
        } else if m.is_file() {
            if m.nlink() != 1 || m.len() > MAX_BYTES || total > MAX_BYTES - m.len() {
                bail!("backup size or hard-link limit exceeded");
            }
            total += m.len();
            out.push((PathBuf::from(name), m.len()));
        } else {
            bail!("backup refuses special file or symlink {}", path.display());
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    if out.len() > MAX_FILES {
        bail!("too many backup files");
    }
    Ok(out)
}

fn private_file(path: &Path) -> Result<File> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || m.nlink() != 1 {
        bail!("unsafe backup file {}", path.display());
    }
    Ok(f)
}

/// Encrypted backup of keys, verifiers, authorization state and signed audit journals.
pub fn backup(dir: &Path, output: &Path, recipient: &str) -> Result<()> {
    let _guard = offline_guard(dir)?;
    backup_unlocked(dir, output, recipient)
}

fn backup_unlocked(dir: &Path, output: &Path, recipient: &str) -> Result<()> {
    services_stopped()?;
    if output.exists() {
        bail!("backup destination already exists");
    }
    if output
        .parent()
        .context("backup needs an output directory")?
        .canonicalize()?
        .starts_with(dir.canonicalize()?)
    {
        bail!("encrypted backup must be stored outside the live state directory");
    }
    if ![40, 64].contains(&recipient.len()) || !recipient.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("recipient must be a full GnuPG fingerprint");
    }
    let files = inventory(dir)?;
    if !files.iter().any(|(p, _)| p == Path::new("static.key")) {
        bail!("no server key to back up");
    }
    let tmp = output.with_extension(format!("gpg-{}.tmp", std::process::id()));
    let out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let mut child = Command::new("/usr/bin/gpg")
        .args([
            "--batch",
            "--yes",
            "--trust-model",
            "always",
            "--encrypt",
            "--recipient",
            recipient,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::from(out))
        .stderr(Stdio::null())
        .spawn()
        .context("start GnuPG")?;
    let result = (|| -> Result<()> {
        let mut input = child.stdin.take().unwrap();
        input.write_all(MAGIC)?;
        input.write_all(&(files.len() as u32).to_be_bytes())?;
        let mut buf = Zeroizing::new(vec![0u8; 64 * 1024]);
        for (rel, size) in files {
            let name = rel.to_str().context("non-UTF8 backup path")?.as_bytes();
            if name.len() > 255 {
                bail!("backup path too long");
            }
            input.write_all(&(name.len() as u16).to_be_bytes())?;
            input.write_all(name)?;
            input.write_all(&size.to_be_bytes())?;
            let mut f = private_file(&dir.join(rel))?;
            if f.metadata()?.len() != size {
                bail!("file changed during backup");
            }
            let mut left = size;
            while left > 0 {
                let want = left.min(buf.len() as u64) as usize;
                let n = f.read(&mut buf[..want])?;
                if n == 0 {
                    bail!("file changed during backup");
                }
                input.write_all(&buf[..n])?;
                buf[..n].zeroize();
                left -= n as u64;
            }
        }
        drop(input);
        if !child.wait()?.success() {
            bail!("GnuPG backup failed");
        }
        File::open(&tmp)?.sync_all()?;
        fs::hard_link(&tmp, output)?; // fail if another process created the destination
        fs::remove_file(&tmp)?;
        File::open(output.parent().unwrap())?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn services_stopped() -> Result<()> {
    for unit in [
        "yrl-gatekeeper.service",
        "yrl-executor.service",
        "yrl-broker.service",
        "yrl-audit.service",
        "yrl-firewall.service",
    ] {
        if Command::new("/usr/bin/systemctl")
            .args(["is-active", "--quiet", unit])
            .status()
            .is_ok_and(|s| s.success())
        {
            bail!("stop {unit} before changing or backing up keys");
        }
    }
    Ok(())
}

fn replace_private(path: &Path, key: &crate::keys::KeyPair) -> Result<()> {
    let old = fs::symlink_metadata(path)?;
    if !old.is_file() || old.nlink() != 1 || old.mode() & 0o077 != 0 {
        bail!("unsafe existing key {}", path.display());
    }
    let tmp = path.with_extension(format!("key-{}.tmp", std::process::id()));
    let mut body = Zeroizing::new(hex::encode(&key.private));
    body.push('\n');
    body.push_str(&hex::encode(&key.public));
    body.push('\n');
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)?;
    if unsafe { libc::geteuid() } == 0
        && unsafe { libc::fchown(std::os::fd::AsRawFd::as_raw_fd(&file), old.uid(), old.gid()) }
            != 0
    {
        let _ = fs::remove_file(&tmp);
        bail!("cannot preserve key owner");
    }
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    File::open(path.parent().unwrap())?.sync_all()?;
    Ok(())
}

/// Offline rotation: an encrypted recovery copy is made first. Active sessions end when the
/// owner stops services; new public fingerprints must be distributed through a trusted channel.
pub fn rotate(dir: &Path, side: &str, recovery: &Path, recipient: &str) -> Result<Vec<u8>> {
    let _guard = offline_guard(dir)?;
    if side != "server" && !SIDES.contains(&side) {
        bail!("unknown key role");
    }
    backup_unlocked(dir, recovery, recipient)?;
    let (path, public) = if side == "server" {
        (dir.join("static.key"), None)
    } else {
        (
            dir.join("ipc").join(side).join("static.key"),
            Some(dir.join("ipc").join(format!("{side}.pub"))),
        )
    };
    let old = private_file(&path)?.metadata()?;
    if old.mode() & 0o077 != 0 {
        bail!("unsafe existing key mode");
    }
    let key = crate::keys::generate();
    if let Some(pub_path) = &public {
        let old_pub = fs::symlink_metadata(pub_path)?;
        if !old_pub.is_file() || old_pub.nlink() != 1 {
            bail!("unsafe public key file");
        }
        let tmp = pub_path.with_extension(format!("pub-{}.tmp", std::process::id()));
        let mut f = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o644)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        if unsafe { libc::geteuid() } == 0
            && unsafe {
                libc::fchown(
                    std::os::fd::AsRawFd::as_raw_fd(&f),
                    old_pub.uid(),
                    old_pub.gid(),
                )
            } != 0
        {
            bail!("cannot preserve public key owner");
        }
        f.write_all(hex::encode(&key.public).as_bytes())?;
        f.sync_all()?;
        // A crash between these renames leaves a mismatch, which key loading refuses.
        fs::rename(&tmp, pub_path)?;
    }
    replace_private(&path, &key)?;
    Ok(key.public.clone())
}

fn audit_signing_key(dir: &Path) -> Result<crate::auditsign::Secret> {
    let public = crate::auditlog::load_verifying_key(dir)?;
    crate::auditsign::Secret::load(
        &dir.join("audit/sign.key"), &public, crate::auditsign::Purpose::Journal,
    )
}

pub fn audit_register_recovery(
    dir: &Path,
    public: &str,
    backup: &Path,
    recipient: &str,
) -> Result<()> {
    let _guard = offline_guard(dir)?;
    backup_unlocked(dir, backup, recipient)?;
    crate::auditkeys::register_recovery(dir, public)
}

pub fn audit_rotate(dir: &Path, backup: &Path, recipient: &str) -> Result<Vec<u8>> {
    let _guard = offline_guard(dir)?;
    backup_unlocked(dir, backup, recipient)?;
    let old = audit_signing_key(dir)?;
    let svc = crate::audit::AuditService::open_with_policy(
        dir,
        100,
        crate::auditsegments::RotationPolicy::default(),
    )?;
    svc.rotate_all()?;
    drop(svc);
    let base = dir.join("audit");
    let mut states = Vec::new();
    for journal in [
        crate::auditlog::Journal::Ordinary,
        crate::auditlog::Journal::Security,
    ] {
        states.push((
            journal,
            crate::auditsegments::read_active(&base, journal, &old.verifying_key(), 0)?,
        ));
    }
    let public = crate::auditkeys::planned_transition(dir, &old)?;
    let new = audit_signing_key(dir)?;
    for (journal, active) in states {
        crate::auditsegments::write_active(&base, journal, &active, &new)?;
    }
    Ok(public.to_bytes().to_vec())
}

pub fn audit_emergency_rotate(
    dir: &Path,
    recovery_seed: &Path,
    backup: &Path,
    recipient: &str,
) -> Result<Vec<u8>> {
    let _guard = offline_guard(dir)?;
    backup_unlocked(dir, backup, recipient)?;
    let history = crate::auditkeys::load(dir)?;
    let base = dir.join("audit");
    let mut old = Vec::new();
    for journal in [
        crate::auditlog::Journal::Ordinary,
        crate::auditlog::Journal::Security,
    ] {
        let active = crate::auditsegments::read_active(&base, journal, &history.current, 0)?;
        let log = base.join(format!("{}.log", journal.file()));
        let bytes = fs::read(&log).unwrap_or_default();
        old.push((journal, active, bytes));
    }
    let public = crate::auditkeys::emergency_transition(dir, recovery_seed)?;
    let new = audit_signing_key(dir)?;
    let transition_hash = *blake3::hash(&fs::read(base.join("key-transitions.log"))?).as_bytes();
    for (journal, active, bytes) in old {
        let log = base.join(format!("{}.log", journal.file()));
        if log.exists() {
            fs::rename(
                &log,
                crate::auditsegments::archived(&base, journal, active.generation, "orphan"),
            )?;
        }
        let head = base.join(format!("{}.head", journal.file()));
        if head.exists() {
            fs::rename(
                &head,
                crate::auditsegments::archived(&base, journal, active.generation, "orphan-head"),
            )?;
        }
        crate::auditsegments::append_deletion(
            &base,
            journal,
            active.generation,
            transition_hash,
            *blake3::hash(&bytes).as_bytes(),
            &new,
            crate::gatenet::now_secs(),
        )?;
        crate::auditsegments::atomic_write(&log, &[], 0o600)?;
        crate::auditsegments::write_active(
            &base,
            journal,
            &crate::auditsegments::Active {
                generation: active.generation + 1,
                started: crate::gatenet::now_secs(),
                previous_seal: transition_hash,
            },
            &new,
        )?;
    }
    crate::auditkeys::revoke(
        dir,
        history.current_generation,
        "emergency transition: prior key lost or compromised",
        &new,
    )?;
    Ok(public.to_bytes().to_vec())
}

pub fn audit_revoke(
    dir: &Path,
    generation: u64,
    reason: &str,
    backup: &Path,
    recipient: &str,
) -> Result<()> {
    let _guard = offline_guard(dir)?;
    backup_unlocked(dir, backup, recipient)?;
    crate::auditkeys::revoke(dir, generation, reason, &audit_signing_key(dir)?)
}

/// Validate and rewrite legacy plaintext key files under their existing owners and modes.
/// The encrypted backup is mandatory, and the public identity does not change.
pub fn migrate(dir: &Path, recovery: &Path, recipient: &str) -> Result<()> {
    let _guard = offline_guard(dir)?;
    backup_unlocked(dir, recovery, recipient)?;
    for side in std::iter::once("server").chain(SIDES.iter().copied()) {
        let path = if side == "server" {
            dir.join("static.key")
        } else {
            dir.join("ipc").join(side).join("static.key")
        };
        let mut data = Zeroizing::new(Vec::new());
        private_file(&path)?.read_to_end(&mut data)?;
        if data.len() > 256 {
            bail!("oversized legacy key");
        }
        let text = std::str::from_utf8(&data)?;
        let mut lines = text.lines();
        let private = Zeroizing::new(hex::decode(lines.next().context("missing private key")?)?);
        let public = hex::decode(lines.next().context("missing public key")?)?;
        if private.len() != 32 || public.len() != 32 || lines.next().is_some() {
            bail!("malformed legacy key");
        }
        let mut secret: [u8; 32] = private.as_slice().try_into()?;
        let derived = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
        secret.zeroize();
        if derived.as_bytes() != public.as_slice() {
            bail!("mismatched legacy key pair");
        }
        if side != "server" {
            let published = fs::read_to_string(dir.join("ipc").join(format!("{side}.pub")))?;
            if hex::decode(published.trim())? != public {
                bail!("legacy public file does not match {side}");
            }
        }
        replace_private(&path, &crate::keys::KeyPair { private, public })?;
    }
    Ok(())
}

/// Remove one device public key atomically. Executor's authority watcher then ends its sessions.
pub fn revoke_device(dir: &Path, public_hex: &str) -> Result<()> {
    let key = hex::decode(public_hex)?;
    if key.len() != 32 {
        bail!("device public key must be 32 bytes");
    }
    let path = dir.join("authorized_keys");
    let old = fs::symlink_metadata(&path)?;
    if !old.is_file() || old.nlink() != 1 || !crate::keys::mode_ok_for_reading(old.mode()) {
        bail!("unsafe authorized_keys file");
    }
    let text = fs::read_to_string(&path)?;
    let mut found = false;
    let mut kept = String::new();
    for line in text.lines() {
        if line
            .split_whitespace()
            .next()
            .and_then(|s| hex::decode(s).ok())
            .as_deref()
            == Some(key.as_slice())
        {
            found = true;
        } else {
            kept.push_str(line);
            kept.push('\n');
        }
    }
    if !found {
        bail!("device key is not authorized");
    }
    let tmp = path.with_extension(format!("revoke-{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(old.mode() & 0o777)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)?;
    if unsafe { libc::geteuid() } == 0
        && unsafe { libc::fchown(std::os::fd::AsRawFd::as_raw_fd(&file), old.uid(), old.gid()) }
            != 0
    {
        bail!("cannot preserve authorized_keys owner");
    }
    file.write_all(kept.as_bytes())?;
    file.sync_all()?;
    fs::rename(&tmp, &path)?;
    File::open(dir)?.sync_all()?;
    Ok(())
}

fn read_exact<const N: usize>(r: &mut impl Read) -> Result<[u8; N]> {
    let mut b = [0; N];
    r.read_exact(&mut b)?;
    Ok(b)
}

fn rename_new(from: &Path, to: &Path) -> Result<()> {
    let a = std::ffi::CString::new(from.as_os_str().as_encoded_bytes())?;
    let b = std::ffi::CString::new(to.as_os_str().as_encoded_bytes())?;
    if unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            a.as_ptr(),
            libc::AT_FDCWD,
            b.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn restore_owners(stage: &Path) -> Result<()> {
    use crate::install::Names;
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }
    let names = yrl_names_available();
    if !names {
        return Ok(());
    } // a single-user installation, or accounts are installed later
    let layout = crate::install::state_layout();
    crate::install::apply(stage, &layout, &crate::install::SystemNames)?;
    fn extras(base: &Path, dir: &Path, layout: &[crate::install::Item]) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let rel = path.strip_prefix(base)?.to_string_lossy().to_string();
            if !layout.iter().any(|i| i.path == rel) {
                if let Some(parent) = layout
                    .iter()
                    .filter(|i| rel.starts_with(&(i.path.clone() + "/")))
                    .max_by_key(|i| i.path.len())
                {
                    let owner = crate::install::SystemNames
                        .uid(parent.owner)
                        .context("missing service account")?;
                    let group = crate::install::SystemNames
                        .gid(parent.group)
                        .context("missing service group")?;
                    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
                    if unsafe { libc::chown(c.as_ptr(), owner, group) } != 0 {
                        return Err(std::io::Error::last_os_error().into());
                    }
                    let mode = if path.is_dir() {
                        0o700
                    } else if rel.starts_with("enroll/") {
                        0o640
                    } else {
                        0o600
                    };
                    fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
                }
            }
            if path.is_dir() {
                extras(base, &path, layout)?;
            }
        }
        Ok(())
    }
    extras(stage, stage, &layout)
}

fn yrl_names_available() -> bool {
    ["yrl-gate", "yrl-fw", "yrl-audit", "yrl-broker"]
        .iter()
        .all(|n| crate::identity::lookup_name(n).is_some())
}

/// Restore only to a non-existing directory. Files remain private until the owner runs
/// `yrld install layout` to assign the separate service users again.
pub fn restore(input: &Path, destination: &Path) -> Result<()> {
    if destination.exists() {
        bail!("restore destination already exists");
    }
    let stage = destination.with_extension(format!("restore-{}", std::process::id()));
    fs::create_dir(&stage)?;
    fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
    let mut child = Command::new("/usr/bin/gpg")
        .args(["--batch", "--decrypt"])
        .arg(input)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("start GnuPG")?;
    let result = (|| -> Result<()> {
        let mut output = child.stdout.take().unwrap();
        if &read_exact::<8>(&mut output)? != MAGIC {
            bail!("wrong backup format");
        }
        let count = u32::from_be_bytes(read_exact::<4>(&mut output)?) as usize;
        if count == 0 || count > MAX_FILES {
            bail!("invalid backup file count");
        }
        let mut total = 0u64;
        let mut buf = Zeroizing::new(vec![0u8; 64 * 1024]);
        for _ in 0..count {
            let n = u16::from_be_bytes(read_exact::<2>(&mut output)?) as usize;
            if n == 0 || n > 255 {
                bail!("invalid backup path length");
            }
            let mut name = vec![0u8; n];
            output.read_exact(&mut name)?;
            let rel = PathBuf::from(std::str::from_utf8(&name)?);
            validate_path(&rel)?;
            let size = u64::from_be_bytes(read_exact::<8>(&mut output)?);
            if size > MAX_BYTES || total > MAX_BYTES - size {
                bail!("backup size limit exceeded");
            }
            total += size;
            let path = stage.join(rel);
            fs::create_dir_all(path.parent().unwrap())?;
            let mut parent = stage.clone();
            for component in path.parent().unwrap().strip_prefix(&stage)?.components() {
                parent.push(component);
                fs::set_permissions(&parent, fs::Permissions::from_mode(0o700))?;
            }
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&path)?;
            let mut left = size;
            while left > 0 {
                let n = left.min(buf.len() as u64) as usize;
                output.read_exact(&mut buf[..n])?;
                file.write_all(&buf[..n])?;
                buf[..n].zeroize();
                left -= n as u64;
            }
            file.sync_all()?;
        }
        if output.read(&mut [0u8; 1])? != 0 {
            bail!("trailing backup bytes");
        }
        if !child.wait()?.success() {
            bail!("GnuPG authentication failed");
        }
        crate::keys::load(&stage)?;
        for side in SIDES {
            crate::keys::load(&stage.join("ipc").join(side))?;
        }
        let signing = stage.join("audit/sign.key");
        if signing.exists() {
            let key = audit_signing_key(&stage)?;
            let public = crate::auditlog::load_verifying_key(&stage)?;
            if key.verifying_key() != public {
                bail!("Audit signing key does not match its public key");
            }
            crate::auditkeys::load(&stage)?;
            crate::auditsegments::verify_chain(&stage, None)
                .context("restored Audit journal does not verify")?;
        }
        restore_owners(&stage)?;
        rename_new(&stage, destination)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_dir_all(&stage);
    }
    result
}
