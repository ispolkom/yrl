//! Static Noise keys and the list of authorized client keys. Private key files must be owned by the user and not readable by others (mode 0600, directory 0700), else we refuse to start.
use anyhow::{bail, Context, Result};
use std::fs;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

pub const PARAMS: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

#[derive(Clone)]
pub struct KeyPair {
    pub private: Zeroizing<Vec<u8>>,
    pub public: Vec<u8>,
}

pub fn generate() -> KeyPair {
    let kp = snow::Builder::new(PARAMS.parse().unwrap()).generate_keypair().unwrap();
    KeyPair { private: Zeroizing::new(kp.private), public: kp.public }
}

fn ensure_private_dir(dir: &Path) -> Result<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    let m = fs::symlink_metadata(dir)?;
    if !m.file_type().is_dir() || m.uid() != unsafe { libc::geteuid() } { bail!("key directory is not owned by this service: {}", dir.display()); }
    let mode = m.permissions().mode() & 0o777;
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
    let mut body = Zeroizing::new(hex::encode(&kp.private));
    body.push('\n');
    body.push_str(&hex::encode(&kp.public));
    body.push('\n');
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&path)?;
    std::io::Write::write_all(&mut f, body.as_bytes())?;
    f.sync_all()?;
    Ok(kp)
}

pub fn load(dir: &Path) -> Result<KeyPair> {
    ensure_private_dir(dir)?;
    let path = key_path(dir);
    let key = parse_key_file(&path)?;
    let public_path = dir.with_extension("pub");
    if public_path.exists() && hex::decode(fs::read_to_string(&public_path)?.trim())? != key.public {
        bail!("public key does not match private key in {}", dir.display());
    }
    Ok(key)
}

/// Read a small single-line secret without following links or accepting files shared with
/// another user. The returned buffer clears itself when dropped.
pub fn read_secret_hex(path: &Path, length: usize) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    let mut f = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    let m = f.metadata()?;
    if !m.file_type().is_file() || m.nlink() != 1 || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 || m.len() > (length * 2 + 2) as u64 {
        bail!("unsafe secret file {}", path.display());
    }
    let mut text = Zeroizing::new(String::new());
    f.read_to_string(&mut text)?;
    let bytes = Zeroizing::new(hex::decode(text.trim())?);
    if bytes.len() != length { bail!("invalid secret length in {}", path.display()); }
    Ok(bytes)
}

fn parse_key_file(path: &Path) -> Result<KeyPair> {
    use std::io::Read;
    let mut f = fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    let m = f.metadata()?;
    if !m.file_type().is_file() || m.nlink() != 1 || m.uid() != unsafe { libc::geteuid() } || m.mode() & 0o077 != 0 || m.len() > 256 {
        bail!("private key {} has unsafe owner, mode, type or size", path.display());
    }
    let mut text = Zeroizing::new(String::new());
    f.read_to_string(&mut text)?;
    let mut lines = text.lines();
    let private = Zeroizing::new(hex::decode(lines.next().context("empty key file")?.trim())?);
    let public = hex::decode(lines.next().context("key file has no public key")?.trim())?;
    if private.len() != 32 || public.len() != 32 || lines.next().is_some() {
        bail!("malformed key file");
    }
    let mut secret: [u8; 32] = private.as_slice().try_into()?;
    let derived = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
    secret.zeroize();
    if derived.as_bytes() != public.as_slice() { bail!("private and public keys do not match"); }
    Ok(KeyPair { private: Zeroizing::new(private.to_vec()), public })
}

/// For a key that sits in a directory shared with other system users (the server key of the gatekeeper in the state directory): the FILE must be private and ours,
/// and nobody else may be able to replace it (the directory is not writable by group or others).
pub fn load_shared(dir: &Path) -> Result<KeyPair> {
    let path = key_path(dir);
    let dm = fs::symlink_metadata(dir).with_context(|| format!("no directory {}", dir.display()))?;
    if !dm.file_type().is_dir() || dm.mode() & 0o022 != 0 {
        bail!("directory {} is writable by others (mode {:o}); refusing to use a key in it", dir.display(), dm.mode() & 0o777);
    }
    let m = fs::symlink_metadata(&path).with_context(|| format!("no key at {}", path.display()))?;
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
    let m = match fs::symlink_metadata(old) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if !m.file_type().is_file() || m.nlink() != 1 || m.mode() & 0o7000 != 0 || !mode_ok_for_reading(m.mode()) { bail!("unsafe file to replace: {}", old.display()); }
    let c = std::ffi::CString::new(new.as_os_str().as_encoded_bytes())?;
    if unsafe { libc::chown(c.as_ptr(), m.uid(), m.gid()) } != 0 && unsafe { libc::geteuid() } == 0 {
        bail!("cannot give {} to the owner of {}: {}", new.display(), old.display(), std::io::Error::last_os_error());
    }
    fs::set_permissions(new, fs::Permissions::from_mode(m.mode() & 0o777))?;
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
