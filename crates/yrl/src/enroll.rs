//! Adding a new device (docs/THREATS.md, section N). Never "whoever knocks first becomes trusted": the OWNER, on the machine, opens a short window.
//!   1. `yrld enroll enable <dir> --ttl 120 --rights exec` opens it and prints a one-time CODE (its hash is stored, not the code).
//!   2. During the window - and only then - a key the server does not know may complete the handshake, but the ONLY thing it can do is present the code.
//!   3. A right code produces a request that shows the new key's FINGERPRINT to the owner; the new device shows the same fingerprint to its user. The owner compares and answers.
//!   4. Only the owner's own program on the machine adds the key to `authorized_keys`; the gatekeeper cannot, even if it lies.
//! Three wrong codes close the window for good. One request at a time. The window ends by itself.
use crate::users::{hash_password, verify_hash};
use anyhow::{bail, Result};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::SeqCst};
use std::time::Duration;

pub const ENROLL: u8 = 80;
pub const ENROLL_OK: u8 = 81;
pub const ENROLL_FAIL: u8 = 82;

pub const MAX_BAD_CODES: u32 = 3;
pub const MAX_WAIT: Duration = Duration::from_secs(300);
const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O, 1/I

pub fn dir_of(dir: &Path) -> PathBuf {
    dir.join("enroll")
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// a short code for people to carry across the room: 10 characters of 32 = 50 bits (three wrong tries close the window, so this is plenty)
pub fn new_code() -> String {
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    let mut b = [0u8; 10];
    OsRng.fill_bytes(&mut b);
    let s: String = b.iter().map(|x| ALPHABET[(*x as usize) % ALPHABET.len()] as char).collect();
    format!("{}-{}", &s[..5], &s[5..])
}

/// what both people read aloud and compare: the first 15 bytes of a hash of the key, in five groups
pub fn fingerprint(public: &[u8]) -> String {
    let h = blake3::hash(public);
    let b = h.as_bytes();
    let mut s = String::new();
    for i in 0..5 {
        let v = u32::from_be_bytes([0, b[i * 3], b[i * 3 + 1], b[i * 3 + 2]]);
        let mut g = String::new();
        for k in 0..4 {
            g.push(ALPHABET[((v >> (5 * k)) & 31) as usize] as char);
        }
        if i > 0 {
            s.push('-');
        }
        s.push_str(&g);
    }
    s
}

#[derive(Clone, Debug)]
pub struct Window {
    pub expires: u64,
    pub rights: Vec<String>,
    code_hash: String,
}

fn right_ok(r: &str) -> bool {
    !r.is_empty() && r.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// the OWNER opens a window; returns the code (shown once)
pub fn open_window(dir: &Path, ttl_secs: u64, rights: &[String]) -> Result<String> {
    if ttl_secs == 0 || ttl_secs > 900 {
        bail!("a window lasts 1-900 seconds");
    }
    if rights.iter().any(|r| !right_ok(r)) {
        bail!("rights are plain words");
    }
    let e = dir_of(dir);
    std::fs::create_dir_all(&e)?;
    let code = new_code();
    let body = format!("{}\n{}\n{}\n", now() + ttl_secs, rights.join(","), hash_password(code.as_bytes())?);
    let tmp = e.join("window.tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o644).open(&tmp)?;
    std::io::Write::write_all(&mut f, body.as_bytes())?;
    std::fs::rename(&tmp, e.join("window"))?;
    for stale in ["request", "decision", "closed"] {
        let _ = std::fs::remove_file(e.join(stale));
    }
    Ok(code)
}

pub fn close_window(dir: &Path) {
    let e = dir_of(dir);
    // the decision is left for the gatekeeper to pick up and remove itself: the owner's program closes the window right after answering
    for f in ["window", "request"] {
        let _ = std::fs::remove_file(e.join(f));
    }
}

/// an open, unexpired window whose file only the owner could have written
pub fn read_window(dir: &Path) -> Option<Window> {
    let p = dir_of(dir).join("window");
    let m = std::fs::metadata(&p).ok()?;
    if m.mode() & 0o022 != 0 || m.len() > 4096 {
        return None;
    }
    let text = std::fs::read_to_string(&p).ok()?;
    let mut l = text.lines();
    let expires: u64 = l.next()?.parse().ok()?;
    let rights: Vec<String> = l.next()?.split(',').filter(|s| !s.is_empty()).map(String::from).collect();
    let code_hash = l.next()?.to_string();
    if now() >= expires || rights.iter().any(|r| !right_ok(r)) {
        return None;
    }
    if dir_of(dir).join("closed").exists() {
        return None; // three wrong codes were enough
    }
    Some(Window { expires, rights, code_hash })
}

/// `[code_len u8][code][label_len u8][label]`, exact
pub fn encode_request(code: &str, label: &str) -> Result<Vec<u8>, crate::wire::WireError> {
    if code.is_empty() || code.len() > 32 || !label_ok(label) {
        return Err(crate::wire::WireError::TooLarge);
    }
    let mut v = vec![code.len() as u8];
    v.extend_from_slice(code.as_bytes());
    v.push(label.len() as u8);
    v.extend_from_slice(label.as_bytes());
    Ok(v)
}

pub fn decode_request(b: &[u8]) -> Result<(String, String), crate::wire::WireError> {
    use crate::wire::WireError::*;
    let n = *b.first().ok_or(Short)? as usize;
    if n == 0 || n > 32 || b.len() < 2 + n {
        return Err(if n > 32 { TooLarge } else { Short });
    }
    let m = b[1 + n] as usize;
    if b.len() != 2 + n + m {
        return Err(Malformed);
    }
    let code = std::str::from_utf8(&b[1..1 + n]).map_err(|_| Malformed)?.to_string();
    let label = std::str::from_utf8(&b[2 + n..]).map_err(|_| Malformed)?.to_string();
    if !label_ok(&label) {
        return Err(Malformed);
    }
    Ok((code, label))
}

pub fn label_ok(l: &str) -> bool {
    !l.is_empty() && l.len() <= 32 && l.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'-'))
}

#[derive(Default)]
pub struct EnrollState {
    bad: AtomicU32,
    window: AtomicU64,
    busy: AtomicBool,
}

pub enum Outcome {
    Accepted,
    Refused,
}

impl EnrollState {
    /// the gatekeeper's side, after a connection of an unknown key presented a request. The decision comes from the owner's program through the `enroll` folder.
    pub async fn serve(&self, dir: &Path, w: &Window, public: &[u8], code: &str, label: &str, hash_slots: &tokio::sync::Semaphore) -> Outcome {
        if self.window.swap(w.expires, SeqCst) != w.expires {
            self.bad.store(0, SeqCst); // a new window starts clean
        }
        if self.bad.load(SeqCst) >= MAX_BAD_CODES {
            return Outcome::Refused;
        }
        let (hash, code) = (w.code_hash.clone(), code.as_bytes().to_vec());
        let ok = {
            let _slot = hash_slots.acquire().await;
            tokio::task::spawn_blocking(move || verify_hash(&hash, &code)).await.unwrap_or(false)
        };
        if !ok {
            if self.bad.fetch_add(1, SeqCst) + 1 >= MAX_BAD_CODES {
                let _ = std::fs::write(dir_of(dir).join("closed"), b"too many wrong codes\n");
            }
            return Outcome::Refused;
        }
        if self.busy.swap(true, SeqCst) {
            return Outcome::Refused; // one request at a time
        }
        let e = dir_of(dir);
        let _ = std::fs::remove_file(e.join("decision"));
        let wrote = std::fs::write(e.join("request"), format!("{} {} {}\n", hex::encode(public), label, now()));
        let mut result = Outcome::Refused;
        if wrote.is_ok() {
            let end = std::time::Instant::now() + MAX_WAIT.min(Duration::from_secs(w.expires.saturating_sub(now())));
            while std::time::Instant::now() < end {
                if let Ok(d) = std::fs::read_to_string(e.join("decision")) {
                    if d.trim() == format!("accept {}", hex::encode(public)) {
                        result = Outcome::Accepted;
                    }
                    break;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
        let _ = std::fs::remove_file(e.join("request"));
        let _ = std::fs::remove_file(e.join("decision"));
        self.busy.store(false, SeqCst);
        result
    }
}

// ---------------------------------------------------------------- the owner's side

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub public: Vec<u8>,
    pub label: String,
}

/// the pending request, if any (the fingerprint is computed here, from the key itself, never taken from the file)
pub fn pending_request(dir: &Path) -> Option<Request> {
    let t = std::fs::read_to_string(dir_of(dir).join("request")).ok()?;
    let mut p = t.split_whitespace();
    let public = hex::decode(p.next()?).ok()?;
    let label = p.next()?.to_string();
    if public.len() != 32 || !label_ok(&label) {
        return None;
    }
    Some(Request { public, label })
}

/// the owner's answer. Only here is the key added to `authorized_keys`.
pub fn decide(dir: &Path, req: &Request, accept: bool, rights: &[String]) -> Result<()> {
    if accept {
        crate::keys::authorize(&dir.join("authorized_keys"), &hex::encode(&req.public), &req.label, &rights.join(","))?;
    }
    let e = dir_of(dir);
    let word = if accept { format!("accept {}", hex::encode(&req.public)) } else { "reject".to_string() };
    std::fs::write(e.join("decision"), word)?;
    Ok(())
}
