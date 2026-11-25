//! Static Noise keys and the list of authorized client keys. Private key files must be owned by the user and not readable by others (mode 0600, directory 0700), else we refuse to start.
use anyhow::{bail, Context, Result};
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

#[derive(Clone)]
pub struct KeyPair {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

pub fn generate() -> KeyPair {
    let kp = snow::Builder::new(PARAMS.parse().unwrap()).generate_keypair().unwrap();
    KeyPair { private: kp.private, public: kp.public }
}

fn ensure_private_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let mode = fs::metadata(dir)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!("key directory {} is accessible by others (mode {:o}); refusing to use it", dir.display(), mode);
    }
    Ok(())
}

pub fn key_path(dir: &Path) -> PathBuf {
    dir.join("static.key")
}

/// Create the key pair once (never overwrites an existing one) and return it.
pub fn init(dir: &Path) -> Result<KeyPair> {
    ensure_private_dir(dir)?;
    let path = key_path(dir);
    if path.exists() {
        bail!("{} already exists: not replacing an identity", path.display());
    }
    let kp = generate();
    let body = format!("{}\n{}\n", hex::encode(&kp.private), hex::encode(&kp.public));
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
    std::io::Write::write_all(&mut f, body.as_bytes())?;
    Ok(kp)
}

pub fn load(dir: &Path) -> Result<KeyPair> {
    ensure_private_dir(dir)?;
    let path = key_path(dir);
    let mode = fs::metadata(&path).with_context(|| format!("no key at {}", path.display()))?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!("private key {} has mode {:o}; it must not be accessible by others", path.display(), mode);
    }
    parse_key_file(&path)
}

fn parse_key_file(path: &Path) -> Result<KeyPair> {
    let text = fs::read_to_string(path)?;
    let mut lines = text.lines();
    let private = hex::decode(lines.next().context("empty key file")?.trim())?;
    let public = hex::decode(lines.next().context("key file has no public key")?.trim())?;
    if private.len() != 32 || public.len() != 32 {
        bail!("malformed key file");
    }
    Ok(KeyPair { private, public })
}

/// For a key that sits in a directory shared with other system users (the server key of the gatekeeper in the state directory): the FILE must be private and ours,
/// and nobody else may be able to replace it (the directory is not writable by group or others).
pub fn load_shared(dir: &Path) -> Result<KeyPair> {
    use std::os::unix::fs::MetadataExt;
    let path = key_path(dir);
    let dm = fs::metadata(dir).with_context(|| format!("no directory {}", dir.display()))?;
    if dm.mode() & 0o022 != 0 {
        bail!("directory {} is writable by others (mode {:o}); refusing to use a key in it", dir.display(), dm.mode() & 0o777);
    }
    let m = fs::metadata(&path).with_context(|| format!("no key at {}", path.display()))?;
    if m.mode() & 0o077 != 0 {
        bail!("private key {} has mode {:o}; it must not be accessible by others", path.display(), m.mode() & 0o777);
    }
    if m.uid() != unsafe { libc::geteuid() } {
        bail!("private key {} belongs to another user", path.display());
    }
    parse_key_file(&path)
}

/// A file with secrets that is read by a part running as another system user is read through a GROUP: the group may read it, nobody may write it but the owner,
/// and others may do nothing. (Where one user does everything the file is 0600, which this also accepts.) Which group is the installation's table, checked by `yrld install check`.
pub fn mode_ok_for_reading(mode: u32) -> bool {
    mode & 0o027 == 0
}

/// A file is replaced by writing a new one beside it and renaming it over the old one. The new one takes the old one's owner, group and mode, so that a command
/// run by the owner (as root) does not take the file away from the part that reads it. Nothing to take over from when there was no old file.
pub fn inherit(old: &Path, new: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let Ok(m) = fs::metadata(old) else { return Ok(()) };
    let c = std::ffi::CString::new(new.as_os_str().as_encoded_bytes())?;
    if unsafe { libc::chown(c.as_ptr(), m.uid(), m.gid()) } != 0 && unsafe { libc::geteuid() } == 0 {
        bail!("cannot give {} to the owner of {}: {}", new.display(), old.display(), std::io::Error::last_os_error());
    }
    fs::set_permissions(new, fs::Permissions::from_mode(m.mode() & 0o7777))?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorized {
    pub public: Vec<u8>,
    pub label: String,
    pub rights: Vec<String>,
}

/// `<hex public key> <label> <right,right,...>` per line; `#` comments. Read afresh on every connection, so a removed line (revocation) acts at once.
pub fn read_authorized(path: &Path) -> Vec<Authorized> {
    let Ok(text) = fs::read_to_string(path) else { return vec![] };
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .filter_map(|l| {
            let mut p = l.split_whitespace();
            let public = hex::decode(p.next()?).ok()?;
            if public.len() != 32 {
                return None;
            }
            let label = p.next().unwrap_or("-").to_string();
            let rights = p.next().unwrap_or("").split(',').filter(|s| !s.is_empty()).map(String::from).collect();
            Some(Authorized { public, label, rights })
        })
        .collect()
}

pub fn authorize(path: &Path, public_hex: &str, label: &str, rights: &str) -> Result<()> {
    let key = hex::decode(public_hex).context("public key is not hex")?;
    if key.len() != 32 {
        bail!("a public key is 32 bytes (64 hex digits)");
    }
    if label.contains(char::is_whitespace) || rights.contains(char::is_whitespace) {
        bail!("label and rights must not contain spaces");
    }
    let mut f = fs::OpenOptions::new().create(true).append(true).mode(0o600).open(path)?;
    std::io::Write::write_all(&mut f, format!("{public_hex} {label} {rights}\n").as_bytes())?;
    Ok(())
}
