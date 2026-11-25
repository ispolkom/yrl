//! Accounts: `<login> <right,right,...|-> <argon2id PHC hash>` per line in `<dir>/users` (0600). Read afresh on every attempt, so a removed account acts at once.
//! A password is only ever compared through the hash; an unknown login costs the same work as a known one (a dummy hash), so the answer does not reveal which logins exist.
use crate::wire::{MAX_LOGIN, MAX_PASSWORD};
use anyhow::{bail, Context, Result};
use argon2::password_hash::{rand_core::OsRng, rand_core::RngCore, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use std::fs;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

#[derive(Clone, Debug)]
pub struct User {
    pub login: String,
    pub rights: Vec<String>,
    pub phc: String,
    /// the operating-system user whose rights the commands of this account run with (None = the user `yrld` itself runs as)
    pub os_user: Option<String>,
}

pub fn hash_password(password: &[u8]) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default().hash_password(password, &salt).map_err(|e| anyhow::anyhow!("hash: {e}"))?.to_string())
}

pub fn verify_hash(phc: &str, password: &[u8]) -> bool {
    match PasswordHash::new(phc) {
        Ok(h) => Argon2::default().verify_password(password, &h).is_ok(),
        Err(_) => false,
    }
}

/// a hash nobody knows the password of, made once, verified against when the login does not exist
pub fn dummy_hash() -> &'static str {
    static D: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    D.get_or_init(|| {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        hash_password(&b).expect("hash")
    })
}

/// a users file that others can read or write is refused as a whole (no accounts at all)
/// Why `read_users` would give an empty list for this file, in words for the owner's own log (None = nothing is wrong with the file itself).
pub fn why_unreadable(path: &Path) -> Option<&'static str> {
    let Ok(meta) = fs::metadata(path) else { return Some("the accounts file is missing, or this part may not look at it") };
    if !crate::keys::mode_ok_for_reading(meta.mode()) {
        return Some("the accounts file is writable by its group or open to others, so it is refused");
    }
    if fs::read_to_string(path).is_err() {
        return Some("the accounts file cannot be read by this part");
    }
    None
}

pub fn read_users(path: &Path) -> Vec<User> {
    let Ok(meta) = fs::metadata(path) else { return vec![] };
    if !crate::keys::mode_ok_for_reading(meta.mode()) {
        return vec![];
    }
    let Ok(text) = fs::read_to_string(path) else { return vec![] };
    text.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .filter_map(|l| {
            let mut p = l.split_whitespace();
            let login = p.next()?.to_string();
            let rights = p.next()?;
            let phc = p.next()?.to_string();
            let os_user = match p.next() {
                None => None,
                Some(f) => Some(f.strip_prefix("os=").filter(|n| valid_os_name(n))?.to_string()),
            };
            if p.next().is_some() || PasswordHash::new(&phc).is_err() {
                return None;
            }
            let rights = if rights == "-" { vec![] } else { rights.split(',').filter(|s| !s.is_empty()).map(String::from).collect() };
            Some(User { login, rights, phc, os_user })
        })
        .collect()
}

/// the shape of a Linux user name; anything else never reaches /etc/passwd lookups or a setuid call
pub fn valid_os_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty() && b.len() <= 32 && (b[0].is_ascii_lowercase() || b[0] == b'_') && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_' || *c == b'-')
}

pub fn set_user(path: &Path, login: &str, rights: &str, password: &[u8]) -> Result<()> {
    set_user_os(path, login, rights, None, password)
}

/// adds an account or replaces the existing one with the same login
pub fn set_user_os(path: &Path, login: &str, rights: &str, os_user: Option<&str>, password: &[u8]) -> Result<()> {
    if os_user.is_some_and(|n| !valid_os_name(n)) {
        bail!("not a valid operating-system user name");
    }
    if login.is_empty() || login.len() > MAX_LOGIN || login.contains(char::is_whitespace) || login.starts_with('#') {
        bail!("a login is 1-{MAX_LOGIN} characters without spaces");
    }
    if rights.is_empty() || rights.contains(char::is_whitespace) {
        bail!("rights: comma-separated, or - for none; no spaces");
    }
    if password.len() < 8 || password.len() > MAX_PASSWORD {
        bail!("a password is 8-{MAX_PASSWORD} bytes");
    }
    let mut lines: Vec<String> = fs::read_to_string(path).unwrap_or_default().lines().filter(|l| l.split_whitespace().next() != Some(login)).map(String::from).collect();
    let os = os_user.map(|n| format!(" os={n}")).unwrap_or_default();
    lines.push(format!("{login} {rights} {}{os}", hash_password(password)?));
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(&tmp).context("cannot write the users file")?;
    std::io::Write::write_all(&mut f, (lines.join("\n") + "\n").as_bytes())?;
    crate::keys::inherit(path, &tmp)?;
    fs::rename(&tmp, path)?;
    Ok(())
}
