//! Raising the level of what a session may do: USER (what every session has) -> SUDO -> ROOT, one operation at a time.
//!
//! What this is, honestly named: an ENCRYPTED STEP-UP AUTHENTICATION. The person types a phrase for the level; it travels only inside a Noise XK handshake between the
//! client and the EXECUTOR (the gatekeeper just carries the bytes and cannot read, alter, or answer them). The executor's ephemeral key is fresh for every attempt, so it is
//! also the challenge: a recorded answer is useless. Both the phrase AND the client's device key take part (XK: the client's static key is proven in the third message).
//! It is not yet a proof of knowing the phrase WITHOUT revealing it to the executor - that needs a PAKE (OPAQUE); the interface (`Verifier`) is kept apart so it can be replaced.
//!
//! A success does not hand the client a "root session". It creates one `Cap` for exactly the operation that was asked for: this level, this operation, this session, a short life,
//! one use. The operation is carried out at once and the cap is gone.
use crate::users::{hash_password, verify_hash};
use crate::wire::WireError;
use anyhow::{bail, Result};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const STEPUP_BEGIN: u8 = 70;
pub const STEPUP_CHALLENGE: u8 = 71;
pub const STEPUP_PROOF: u8 = 72;
pub const STEPUP_RESULT: u8 = 73;
pub const FIDO_STEPUP_BEGIN: u8 = 74;
pub const FIDO_STEPUP_CHALLENGE: u8 = 75;
pub const FIDO_STEPUP_ASSERTION: u8 = 76;

pub const NOISE_XK: &str = "Noise_XK_25519_ChaChaPoly_BLAKE2s";
pub const MAX_PHRASE: usize = 256;
pub const MIN_PHRASE: usize = 12;
pub const PENDING_LIFE: Duration = Duration::from_secs(30);
pub const CAP_LIFE: Duration = Duration::from_secs(60);
pub const MAX_PENDING: usize = 4;

pub const R_OK: u8 = 0;
/// wrong phrase, no right for the level, wrong device key, a level that does not fit the operation: all the same answer
pub const R_DENIED: u8 = 1;
pub const R_LOCKED: u8 = 2;
pub const R_EXPIRED: u8 = 3;
pub const R_UNKNOWN: u8 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Level {
    Sudo,
    Root,
}

impl Level {
    pub fn code(self) -> u8 {
        match self {
            Level::Sudo => 1,
            Level::Root => 2,
        }
    }
    pub fn from_code(c: u8) -> Option<Level> {
        match c {
            1 => Some(Level::Sudo),
            2 => Some(Level::Root),
            _ => None,
        }
    }
    /// the right an account and a key must both carry to even try this level
    pub fn right(self) -> &'static str {
        match self {
            Level::Sudo => "sudo",
            Level::Root => "root",
        }
    }
}

/// the operations that need more than USER; a list of exact, typed things - never "run this command"
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// needs nothing; answers that the broker is alive
    Status,
    /// does nothing but report the level it was approved at (for tests of the whole chain)
    TestPrivileged(String),
    RestartService(String),
}

pub fn name_ok(n: &str) -> bool {
    !n.is_empty() && n.len() <= 64 && n.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'.' | b'@' | b'-'))
}

impl Op {
    /// the level this operation needs; None = none
    pub fn required(&self) -> Option<Level> {
        match self {
            Op::Status => None,
            Op::TestPrivileged(_) => Some(Level::Sudo),
            Op::RestartService(_) => Some(Level::Root),
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let (k, arg): (u8, &str) = match self {
            Op::Status => (1, ""),
            Op::TestPrivileged(s) => (2, s),
            Op::RestartService(s) => (3, s),
        };
        let mut v = vec![k];
        v.extend_from_slice(&(arg.len() as u16).to_be_bytes());
        v.extend_from_slice(arg.as_bytes());
        v
    }
    pub fn decode(b: &[u8]) -> Result<Op, WireError> {
        if b.len() < 3 {
            return Err(WireError::Short);
        }
        let n = u16::from_be_bytes([b[1], b[2]]) as usize;
        if n > 64 {
            return Err(WireError::TooLarge);
        }
        if b.len() != 3 + n {
            return Err(WireError::Malformed);
        }
        let arg = std::str::from_utf8(&b[3..]).map_err(|_| WireError::Malformed)?.to_string();
        match b[0] {
            1 if arg.is_empty() => Ok(Op::Status),
            2 if arg.is_empty() || name_ok(&arg) => Ok(Op::TestPrivileged(arg)),
            3 if name_ok(&arg) => Ok(Op::RestartService(arg)),
            _ => Err(WireError::Malformed),
        }
    }
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.encode()).as_bytes()
    }
}

/// everything both sides mix into the handshake before it starts: what is being asked, for which request, from which executor
pub fn prologue(request_id: u64, level: Level, op: &Op, executor_public: &[u8]) -> Vec<u8> {
    let mut p = b"yrl-stepup-v1".to_vec();
    p.extend_from_slice(&request_id.to_be_bytes());
    p.push(level.code());
    p.extend_from_slice(&op.digest());
    p.extend_from_slice(executor_public);
    p
}

#[cfg(feature = "hybrid-signatures")]
pub(crate) fn proof_context(level: Level) -> crate::crypto_profile::Context {
    match level {
        Level::Sudo => crate::crypto_profile::Context::Executor,
        Level::Root => crate::crypto_profile::Context::Broker,
    }
}

pub(crate) fn hybrid_required(level: Level) -> bool {
    let setting = match level {
        Level::Sudo => "YRL_HYBRID_EXECUTOR_KEYS",
        Level::Root => "YRL_HYBRID_BROKER_KEYS",
    };
    std::env::var_os(setting).is_some()
}

pub(crate) fn proof_prologue(request_id: u64, level: Level, op: &Op, public: &[u8], hybrid: bool) -> Vec<u8> {
    let mut p = prologue(request_id, level, op, public);
    if hybrid {
        p.extend_from_slice(b"\0YRL Ed25519 ML-DSA step-up 1");
    }
    p
}

#[cfg(feature = "hybrid-signatures")]
pub(crate) fn hybrid_stepup_body(level: Level, handshake_hash: &[u8], device: &[u8], authority: &[u8], signer: u8) -> Vec<u8> {
    let mut bytes = b"YRL hybrid step-up proof v1\0".to_vec();
    bytes.extend_from_slice(&crate::hybrid_signature::PROFILE.to_be_bytes());
    bytes.push(proof_context(level) as u8);
    bytes.push(signer);
    bytes.extend_from_slice(handshake_hash);
    bytes.extend_from_slice(device);
    bytes.extend_from_slice(authority);
    bytes
}

pub(crate) fn proof_buffer(hybrid: bool) -> usize {
    if hybrid { 4096 } else { 512 }
}

/// BEGIN: `[request_id u64][level u8][op_len u16][op][noise message 1]`, exact
pub fn encode_begin(request_id: u64, level: Level, op: &Op, msg1: &[u8]) -> Vec<u8> {
    let o = op.encode();
    let mut v = request_id.to_be_bytes().to_vec();
    v.push(level.code());
    v.extend_from_slice(&(o.len() as u16).to_be_bytes());
    v.extend_from_slice(&o);
    v.extend_from_slice(msg1);
    v
}

pub fn decode_begin(b: &[u8]) -> Result<(u64, Level, Op, Vec<u8>), WireError> {
    if b.len() < 11 {
        return Err(WireError::Short);
    }
    let level = Level::from_code(b[8]).ok_or(WireError::Malformed)?;
    let n = u16::from_be_bytes([b[9], b[10]]) as usize;
    if n > 80 || b.len() < 11 + n + 1 {
        return Err(if n > 80 { WireError::TooLarge } else { WireError::Short });
    }
    let op = Op::decode(&b[11..11 + n])?;
    let msg1 = b[11 + n..].to_vec();
    if msg1.len() > 200 {
        return Err(WireError::TooLarge);
    }
    Ok((u64::from_be_bytes(b[..8].try_into().unwrap()), level, op, msg1))
}

/// CHALLENGE / PROOF: `[request_id u64][noise message]`
pub fn encode_msg(request_id: u64, msg: &[u8]) -> Vec<u8> {
    let mut v = request_id.to_be_bytes().to_vec();
    v.extend_from_slice(msg);
    v
}

pub fn decode_msg(b: &[u8]) -> Result<(u64, &[u8]), WireError> {
    decode_proof_msg(b, false)
}

pub(crate) fn decode_proof_msg(b: &[u8], hybrid: bool) -> Result<(u64, &[u8]), WireError> {
    if b.len() < 9 {
        return Err(WireError::Short);
    }
    let max = if hybrid { proof_buffer(true) } else { 400 };
    if b.len() > 8 + max {
        return Err(WireError::TooLarge);
    }
    Ok((u64::from_be_bytes(b[..8].try_into().unwrap()), &b[8..]))
}

/// RESULT: `[request_id u64][status u8][text]`
pub fn encode_result(request_id: u64, status: u8, text: &str) -> Vec<u8> {
    let mut v = request_id.to_be_bytes().to_vec();
    v.push(status);
    v.extend_from_slice(text.as_bytes());
    v
}

pub fn decode_result(b: &[u8]) -> Result<(u64, u8, String), WireError> {
    if b.len() < 9 {
        return Err(WireError::Short);
    }
    Ok((u64::from_be_bytes(b[..8].try_into().unwrap()), b[8], String::from_utf8_lossy(&b[9..]).into_owned()))
}

// ---------------------------------------------------------------- the phrases

/// where the verifiers of the phrases are, 0600: `<dir>/words` for SUDO (read by the executor), `<dir>/words.root` for ROOT (read by the broker only).
/// A line is `<level> <argon2id hash>`. The phrase itself is never stored; nothing is built into the program.
pub struct Verifier;

impl Verifier {
    pub fn file(dir: &Path, level: Level) -> std::path::PathBuf {
        dir.join(match level {
            Level::Sudo => "words",
            Level::Root => "words.root",
        })
    }

    pub fn set(dir: &Path, level: Level, phrase: &[u8]) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        if phrase.len() < MIN_PHRASE || phrase.len() > MAX_PHRASE {
            bail!("a phrase is {MIN_PHRASE}-{MAX_PHRASE} bytes: use a long sentence, not a word");
        }
        let path = Self::file(dir, level);
        let mut lines: Vec<String> = std::fs::read_to_string(&path).unwrap_or_default().lines().filter(|l| l.split_whitespace().next() != Some(level.right())).map(String::from).collect();
        lines.push(format!("{} {}", level.right(), hash_password(phrase)?));
        let tmp = path.with_extension("tmp");
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&tmp)?;
        std::io::Write::write_all(&mut f, (lines.join("\n") + "\n").as_bytes())?;
        crate::keys::inherit(&path, &tmp)?;
        f.sync_all()?;
        std::fs::rename(&tmp, &path)?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    }
    /// true only if a verifier for this level exists, the file is private, and the phrase fits it
    pub fn check(dir: &Path, level: Level, phrase: &[u8]) -> bool {
        use std::os::unix::fs::MetadataExt;
        let path = Self::file(dir, level);
        let Ok(meta) = std::fs::symlink_metadata(&path) else { return false };
        if !meta.is_file() || meta.nlink() != 1 || !crate::keys::mode_ok_for_reading(meta.mode()) {
            return false;
        }
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        let phc = text.lines().find_map(|l| {
            let mut p = l.split_whitespace();
            (p.next() == Some(level.right())).then(|| p.next().map(String::from)).flatten()
        });
        match phc {
            Some(h) => verify_hash(&h, phrase),
            None => {
                // no verifier: still do the work, so that "not set up" is not told apart by time
                verify_hash(crate::users::dummy_hash(), phrase);
                false
            }
        }
    }
}

// ---------------------------------------------------------------- failures

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    Open,
    Locked,
}

#[derive(Clone, Default)]
struct Rec {
    fails: u32,
    /// locked until the owner lifts it (ROOT)
    locked: bool,
    /// locked until this moment, in seconds since 1970 by the SERVER's clock (SUDO)
    until: u64,
}

#[derive(Clone, Default)]
struct State {
    recs: HashMap<(Vec<u8>, Level), Rec>,
    /// remote ROOT switched off for everybody
    global: bool,
    /// the stored state was damaged or is missing: everything at this level is refused until the owner resets it on the machine
    tampered: bool,
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// where a persistent set of lockouts lives, and the secret that seals it
struct Store {
    path: std::path::PathBuf,
    key_path: std::path::PathBuf,
}

const MAX_STORE: u64 = 1 << 20;

#[cfg(test)]
std::thread_local! {
    static REV005_FAIL_SYNC: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };

    static REV005_FAIL_SYNC_AT: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

fn lockout_sync_parent(path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if REV005_FAIL_SYNC.with(|flag| flag.replace(false)) {
        return Err(std::io::Error::from_raw_os_error(libc::EIO));
    }

    #[cfg(test)]
    if REV005_FAIL_SYNC_AT.with(|counter| {
        let n = counter.get();
        if n == 0 {
            false
        } else {
            counter.set(n - 1);
            n == 1
        }
    }) {
        return Err(std::io::Error::from_raw_os_error(libc::EIO));
    }

    let parent = path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    std::fs::File::open(parent)?.sync_all()
}


impl Store {
    fn dirty_path(&self) -> std::path::PathBuf {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(".dirty");
        std::path::PathBuf::from(name)
    }

    fn is_dirty(&self) -> bool {
        match std::fs::symlink_metadata(self.dirty_path()) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            _ => true,
        }
    }

    // Called only under the exclusive transaction lock.
    fn begin_transaction(&self) -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::io::Write;

        let path = self.dirty_path();

        let mut f = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;

        f.write_all(b"YRLLOCK DIRTY 1\n")?;
        f.sync_all()?;

        // Deliberately retain the marker on every error.
        lockout_sync_parent(&path)?;

        Ok(())
    }

    fn finish_transaction(&self) -> std::io::Result<()> {
        let path = self.dirty_path();

        std::fs::remove_file(&path)?;

        if let Err(e) = lockout_sync_parent(&path) {
            // Best effort to restore the refusal marker.
            let _ = self.begin_transaction();
            return Err(e);
        }

        Ok(())
    }

    fn transaction_lock(&self) -> std::io::Result<std::fs::File> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{OpenOptionsExt, MetadataExt};

        let mut name = self.path.as_os_str().to_os_string();
        name.push(".lock");

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(
                libc::O_NOFOLLOW |
                libc::O_CLOEXEC |
                libc::O_NONBLOCK
            )
            .open(std::path::PathBuf::from(name))?;

        let meta = file.metadata()?;

        if !meta.is_file()
            || meta.nlink() != 1
            || meta.mode() & 0o077 != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "unsafe lockout transaction lock"
            ));
        }

        loop {
            let rc = unsafe {
                libc::flock(file.as_raw_fd(), libc::LOCK_EX)
            };

            if rc == 0 {
                break;
            }

            let err = std::io::Error::last_os_error();

            if err.kind() != std::io::ErrorKind::Interrupted {
                return Err(err);
            }
        }

        Ok(file)
    }

    fn mac(key: &[u8; 32], body: &str) -> String {
        hex::encode(blake3::keyed_hash(key, body.as_bytes()).as_bytes())
    }
    fn read_key(&self) -> Option<zeroize::Zeroizing<[u8; 32]>> {
        let bytes = crate::keys::read_secret_hex(&self.key_path, 32).ok()?;
        Some(zeroize::Zeroizing::new(bytes.as_slice().try_into().ok()?))
    }
    fn make_key(&self) -> Option<zeroize::Zeroizing<[u8; 32]>> {
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        use std::os::unix::fs::OpenOptionsExt;
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        let mut f = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&self.key_path).ok()?;
        let key = zeroize::Zeroizing::new(k);
        use zeroize::Zeroize;
        k.zeroize();
        let text = zeroize::Zeroizing::new(hex::encode(&*key));
        std::io::Write::write_all(&mut f, text.as_bytes()).ok()?;
        f.sync_all().ok()?;
        lockout_sync_parent(&self.key_path).ok()?;
        Some(key)
    }
    /// the stored state, or None if it cannot be trusted
    fn load(&self) -> Option<State> {
        if self.is_dirty() {
            return None;
        }

        use std::os::unix::fs::MetadataExt;
        let key = self.read_key()?;
        let m = std::fs::metadata(&self.path).ok()?;
        if m.mode() & 0o022 != 0 || m.len() > MAX_STORE {
            return None; // writable by others, or absurdly big
        }
        let text = std::fs::read_to_string(&self.path).ok()?;
        let (body, mac_line) = text.trim_end_matches('\n').rsplit_once('\n')?;
        let mac = mac_line.strip_prefix("MAC ")?;
        let want = blake3::keyed_hash(&key, format!("{body}\n").as_bytes());
        let got = blake3::Hash::from_hex(mac).ok()?;
        if want != got {
            return None; // blake3's comparison takes the same time whatever the difference
        }
        let mut lines = body.lines();
        if lines.next()? != "YRLLOCK 1" {
            return None;
        }
        let mut st = State::default();
        for l in lines {
            let f: Vec<&str> = l.split(' ').collect();
            match f.as_slice() {
                ["GLOBAL", g] => st.global = *g == "1",
                ["REC", k, lv, fails, locked, until] => {
                    let level = match *lv {
                        "sudo" => Level::Sudo,
                        "root" => Level::Root,
                        _ => return None,
                    };
                    st.recs.insert((hex::decode(k).ok()?, level), Rec { fails: fails.parse().ok()?, locked: *locked == "1", until: until.parse().ok()? });
                }
                _ => return None,
            }
        }
        Some(st)
    }
    fn save(&self, st: &State) -> Option<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let key = self.read_key().or_else(|| self.make_key())?;
        let mut body = String::from("YRLLOCK 1\n");
        body.push_str(&format!("GLOBAL {}\n", st.global as u8));
        let mut recs: Vec<_> = st.recs.iter().collect();
        recs.sort_by(|a, b| a.0.cmp(b.0));
        for ((k, lv), r) in recs {
            if r.fails == 0 && !r.locked && r.until <= now_secs() {
                continue;
            }
            body.push_str(&format!("REC {} {} {} {} {}\n", hex::encode(k), lv.right(), r.fails, r.locked as u8, r.until));
        }
        let text = format!("{body}MAC {}\n", Self::mac(&key, &body));
        let mut name = self.path.as_os_str().to_os_string();
        name.push(".tmp");

        let tmp = std::path::PathBuf::from(name);

        let _ = std::fs::remove_file(&tmp);

        let result = (|| -> Option<()> {
            let mut f = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&tmp).ok()?;

            std::io::Write::write_all(
                &mut f, text.as_bytes()
            ).ok()?;

            f.sync_all().ok()?;

            std::fs::rename(&tmp, &self.path).ok()?;

            lockout_sync_parent(&self.path).ok()?;

            Some(())
        })();

        if result.is_none() {
            let _ = std::fs::remove_file(&tmp);
        }

        result
    }
}

/// Wrong phrases are counted per DEVICE KEY and per level, never per account name: whoever fails does not lock the owner out.
/// Root: three failures lock that key out of ROOT until the owner lifts it on the machine. Sudo: three failures lock that key out of SUDO for a while.
/// Three DIFFERENT keys locked out of ROOT switch remote ROOT off for everybody until the owner lifts it. A user session keeps working throughout.
///
/// Kept in memory (single-process development) or in a file (`persistent`): then it survives restarts, is sealed with a keyed hash that only its owner knows,
/// and is read again on every use, so what the owner does on the machine acts at once. A file that is missing (while its key exists), altered, unreadable or
/// writable by others is not "no lockouts": everything at that level is REFUSED until the owner resets it on the machine.
pub struct Lockouts {
    mem: Mutex<State>,
    store: Option<Store>,
    pub max_fails: u32,
    pub sudo_lock: Duration,
    pub kill_switch_after: usize,
    tamper_reported: std::sync::atomic::AtomicBool,
    global_reported: std::sync::atomic::AtomicBool,
}

impl Default for Lockouts {
    fn default() -> Self {
        Lockouts { mem: Mutex::new(State::default()), store: None, max_fails: 3, sudo_lock: Duration::from_secs(900), kill_switch_after: 3, tamper_reported: Default::default(), global_reported: Default::default() }
    }
}

impl Lockouts {
    /// `<dir>/lockouts.<name>` and its seal key `<dir>/lockouts.<name>.key`
    pub fn persistent(dir: &Path, name: &str) -> Lockouts {
        let store = Store { path: dir.join(format!("lockouts.{name}")), key_path: dir.join(format!("lockouts.{name}.key")) };
        // first run: both files are made; a key without its file (or the reverse) is not a first run
        let initialization_failed = match store.transaction_lock() {
            Ok(_guard) => {
                if store.is_dirty() {
                    true
                } else if !store.path.exists()
                    && !store.key_path.exists()
                {
                    store.begin_transaction().is_err()
                        || store.save(&State::default()).is_none()
                        || store.finish_transaction().is_err()
                } else {
                    false
                }
            }
            Err(_) => true,
        };

        Lockouts {
            mem: Mutex::new(State {
                tampered: initialization_failed,
                ..State::default()
            }),
            store: Some(store),
            ..Lockouts::default()
        }
    }

    /// the owner, on the machine: forget everything and start clean (also repairs a damaged store)
    pub fn reset_files(dir: &Path, name: &str) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let store = Store { path: dir.join(format!("lockouts.{name}")), key_path: dir.join(format!("lockouts.{name}.key")) };
        // the owner runs this as another user (root) than the part that uses the store: the new files must stay the old files' user's, or that part could not read them again
        let transaction = store.transaction_lock()?;

        let owner = std::fs::metadata(&store.path)
            .or_else(|_| std::fs::metadata(&store.key_path))
            .ok()
            .map(|m| (m.uid(), m.gid()));

        // Preserve service ownership when reset is run by root.
        if let Some((uid, gid)) = owner {
            use std::os::fd::AsRawFd;

            if unsafe { libc::geteuid() } == 0 {
                if unsafe {
                    libc::fchown(transaction.as_raw_fd(), uid, gid)
                } != 0 {
                    bail!("cannot preserve lockout lock ownership");
                }

                transaction.sync_all()?;
            }
        }
        if !store.is_dirty() {
            store.begin_transaction()?;
        } else {
            lockout_sync_parent(&store.dirty_path())?;
        }

        for path in [&store.path, &store.key_path] {
            match std::fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }

        match store.save(&State::default()) {
            Some(()) => {
                if let Some((u, g)) = owner {
                    for f in [&store.path, &store.key_path] {
                        if let Ok(c) = std::ffi::CString::new(f.as_os_str().as_encoded_bytes()) {
                            if unsafe { libc::chown(c.as_ptr(), u, g) } != 0 && unsafe { libc::geteuid() } == 0 {
                                bail!("cannot give the lockout store back to its user");
                            }
                        }
                    }
                }
                std::fs::File::open(&store.path)?.sync_all()?;
                std::fs::File::open(&store.key_path)?.sync_all()?;

                lockout_sync_parent(&store.path)?;

                store.finish_transaction()?;

                Ok(())
            }
            None => bail!("cannot write the lockout store"),
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut State) -> R, write: bool) -> (R, bool) {
        let mut g = self.mem.lock().unwrap();

        let Some(store) = &self.store else {
            return (f(&mut g), true);
        };

        let _transaction = match store.transaction_lock() {
            Ok(guard) => guard,
            Err(_) => {
                *g = State {
                    tampered: true,
                    ..State::default()
                };
                return (f(&mut *g), false);
            }
        };

        let mut st = store.load().unwrap_or(State {
            tampered: true,
            ..State::default()
        });

        st.tampered |= g.tampered;

        if st.tampered {
            *g = State {
                tampered: true,
                ..State::default()
            };
            return (f(&mut *g), false);
        }

        if write && store.begin_transaction().is_err() {
            *g = State {
                tampered: true,
                ..State::default()
            };
            return (f(&mut *g), false);
        }

        let result = f(&mut st);

        if write && (
            store.save(&st).is_none()
                || store.finish_transaction().is_err()
        ) {
            *g = State {
                tampered: true,
                ..State::default()
            };
            return (result, false);
        }

        (result, true)
    }

    pub fn standing(&self, key: &[u8], level: Level) -> Standing {
        self.with(
            |st| {
                if st.tampered || (level == Level::Root && st.global) {
                    return Standing::Locked;
                }
                match st.recs.get(&(key.to_vec(), level)) {
                    Some(r) if r.locked || now_secs() < r.until => Standing::Locked,
                    _ => Standing::Open,
                }
            },
            false,
        ).0
    }
    pub fn fail(&self, key: &[u8], level: Level) {
        let (max, sudo_lock, kill) = (self.max_fails, self.sudo_lock, self.kill_switch_after);
        self.with(
            |st| {
                if st.tampered {
                    return;
                }
                let r = st.recs.entry((key.to_vec(), level)).or_default();
                r.fails += 1;
                if r.fails >= max {
                    match level {
                        Level::Root => r.locked = true,
                        Level::Sudo => r.until = now_secs() + sudo_lock.as_secs().max(1),
                    }
                    r.fails = 0;
                }
                if st.recs.iter().filter(|((_, l), r)| *l == Level::Root && r.locked).count() >= kill {
                    st.global = true;
                }
            },
            true,
        );
    }
    #[must_use]
    pub fn ok(&self, key: &[u8], level: Level) -> bool {
        let (allowed, durable) = self.with(
            |st| {
                // A challenge issued earlier does not override
                // a lockout established before proof completion.
                if st.tampered || (level == Level::Root && st.global) {
                    return false;
                }

                if let Some(r) = st.recs.get_mut(&(key.to_vec(), level)) {
                    if r.locked || now_secs() < r.until {
                        return false;
                    }
                    r.fails = 0;
                }

                true
            },
            true,
        );

        allowed && durable
    }
    /// in-memory sets only (a persistent one is lifted with `reset_files`, by the owner, on the machine)
    pub fn lift_all(&self) {
        if self.store.is_some() {
            return;
        }
        *self.mem.lock().unwrap() = State::default();
    }
    /// true ONCE when the stored state was found damaged (so that it is written to the security journal once, not at every request)
    pub fn take_tamper_news(&self) -> bool {
        let t = self.with(|st| st.tampered, false).0;
        let was = self.tamper_reported.swap(t, std::sync::atomic::Ordering::SeqCst);
        t && !was
    }
    /// true ONCE when remote ROOT has been switched off for everybody
    pub fn take_global_news(&self) -> bool {
        let g = self.with(|st| st.global, false).0;
        let was = self.global_reported.swap(g, std::sync::atomic::Ordering::SeqCst);
        g && !was
    }
    pub fn remote_root_off(&self) -> bool {
        self.with(|st| st.global || st.tampered, false).0
    }
}

// ---------------------------------------------------------------- the one-use permission

#[derive(Debug)]
pub struct Cap {
    pub id: [u8; 16],
    pub level: Level,
    pub op_digest: [u8; 32],
    /// which session may use it (the executor's own number for the session)
    pub session: u64,
    pub expires: Instant,
    pub uses: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CapError {
    WrongLevel,
    WrongOperation,
    WrongSession,
    Expired,
    Used,
}

impl Cap {
    pub fn issue(level: Level, op: &Op, session: u64, life: Duration) -> Cap {
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        let mut id = [0u8; 16];
        OsRng.fill_bytes(&mut id);
        Cap { id, level, op_digest: op.digest(), session, expires: Instant::now() + life, uses: 1 }
    }
    /// everything is checked, and the use is taken, before anything is done
    pub fn spend(&mut self, op: &Op, session: u64, now: Instant) -> Result<(), CapError> {
        if now >= self.expires {
            return Err(CapError::Expired);
        }
        if self.session != session {
            return Err(CapError::WrongSession);
        }
        if op.required() != Some(self.level) {
            return Err(CapError::WrongLevel);
        }
        if op.digest() != self.op_digest {
            return Err(CapError::WrongOperation);
        }
        if self.uses == 0 {
            return Err(CapError::Used);
        }
        self.uses -= 1;
        Ok(())
    }
}

/// the broker's part (a stand-in until the broker is a process of its own): carries out an operation, but only against a cap that fits it
pub fn broker_execute(dir: &Path, cap: &mut Cap, op: &Op, session: u64) -> Result<String, CapError> {
    if let Some(need) = op.required() {
        if need != cap.level {
            return Err(CapError::WrongLevel);
        }
    }
    if op.required().is_some() {
        cap.spend(op, session, Instant::now())?;
    }
    Ok(match op {
        Op::Status => "broker alive".to_string(),
        Op::TestPrivileged(note) => format!("privileged-test:{note}:level={}", cap.level.right()),
        Op::RestartService(name) => {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(crate::ipc::state_dir(dir, "broker").join("broker.log")) {
                let _ = writeln!(f, "restart {name}");
            }
            format!("restarted {name} (mock)")
        }
    })
}

// ---------------------------------------------------------------- the server side of a step-up, used by whoever is the end of the encrypted channel

pub struct Pending {
    hs: snow::HandshakeState,
    level: Level,
    op: Op,
    born: Instant,
    #[cfg(feature = "hybrid-signatures")]
    hybrid_peer: Option<crate::hybrid_signature::PublicKey>,
}

/// everything one side of a step-up needs to know about the session it serves
pub struct Ctx<'a> {
    pub dir: &'a Path,
    pub lockouts: &'a Lockouts,
    /// this side's static key: the one the client pinned
    pub my_key: &'a crate::keys::KeyPair,
    /// what this session may do (from the account files)
    pub session_rights: &'a [String],
    /// the device key of the session
    pub device_key: &'a [u8],
    pub session_no: u64,
    pub label: &'a str,
    /// the levels this side answers for (the executor: SUDO; the broker: ROOT)
    pub serves: &'a [Level],
    pub log: &'a (dyn Fn(String) + Sync),
    /// where the outcome is written down; an approval is not given unless it could be
    pub audit: Option<&'a std::sync::Arc<crate::audit::AuditClient>>,
    pub account: &'a str,
}

impl Ctx<'_> {
    fn event(&self, level: Level, result: u8, rid: u64) -> crate::auditlog::Event {
        let lv = match level {
            Level::Sudo => crate::auditlog::LEVEL_SUDO,
            Level::Root => crate::auditlog::LEVEL_ROOT,
        };
        let op = match level {
            Level::Sudo => "stepup_sudo",
            Level::Root => "stepup_root",
        };
        crate::auditlog::Event::new(op, lv, result).session(&self.session_no.to_be_bytes()).device(self.device_key).user(self.account).request(rid)
    }
    fn report(&self, ev: crate::auditlog::Event) {
        if let Some(a) = self.audit {
            a.record(ev);
        }
    }
    /// the tamper state of the lockouts is a fact about the protection itself: written to the security journal, once
    fn report_tamper(&self, level: Level) {
        if self.lockouts.take_tamper_news() {
            let op = if level == Level::Root { "lockout_tamper" } else { "lockout_tamper" };
            self.report(crate::auditlog::Event::new(op, crate::auditlog::LEVEL_NONE, crate::auditlog::RESULT_ERROR).target(level.right()));
        }
    }
}

pub struct StepServer {
    pending: HashMap<u64, Pending>,
    #[cfg(feature = "fido2")]
    pending_fido: HashMap<u64, (Level, Op, crate::fido::Challenge)>,
    /// how long a challenge may wait for its answer
    pub life: Duration,
}

impl Default for StepServer {
    fn default() -> Self {
        StepServer {
            pending: HashMap::new(),
            #[cfg(feature = "fido2")]
            pending_fido: HashMap::new(),
            life: PENDING_LIFE,
        }
    }
}

fn frame(kind: u8, payload: Vec<u8>) -> crate::wire::Frame {
    crate::wire::Frame::new(kind, 0, payload)
}

impl StepServer {
    #[cfg(feature = "fido2")]
    pub fn fido_begin(&mut self, payload: &[u8], ctx: &Ctx) -> Result<Vec<crate::wire::Frame>, ()> {
        if payload.len() < 11 {
            return Err(());
        }
        let rid = u64::from_be_bytes(payload[..8].try_into().map_err(|_| ())?);
        let level = Level::from_code(payload[8]).ok_or(())?;
        let n = u16::from_be_bytes(payload[9..11].try_into().map_err(|_| ())?) as usize;
        if n > 80 || payload.len() != 11 + n {
            return Err(());
        }
        let op = Op::decode(&payload[11..]).map_err(|_| ())?;
        let reply = |status| vec![frame(STEPUP_RESULT, encode_result(rid, status, ""))];
        ctx.report_tamper(level);
        if !ctx.serves.contains(&level)
            || !ctx.session_rights.iter().any(|r| r == level.right())
            || op.required() != Some(level)
            || self.pending_fido.len() >= MAX_PENDING
            || self.pending_fido.contains_key(&rid)
        {
            return Ok(reply(R_DENIED));
        }
        if ctx.lockouts.standing(ctx.device_key, level) == Standing::Locked {
            return Ok(reply(R_LOCKED));
        }
        let policy = crate::fido::Policy::from_env().map_err(|_| ())?;
        let root = if level == Level::Root {
            crate::ipc::state_dir(ctx.dir, "broker")
        } else {
            ctx.dir.to_path_buf()
        };
        let credentials =
            crate::fido::CredentialStore::open(&root.join("fido/credentials")).map_err(|_| ())?;
        let ah = *blake3::hash(ctx.account.as_bytes()).as_bytes();
        let dh = *blake3::hash(ctx.device_key).as_bytes();
        let ids: Vec<_> = credentials
            .for_account_hash(&ah)
            .map_err(|_| ())?
            .into_iter()
            .filter(|r| r.device_hash == dh && !r.revoked)
            .map(|r| r.id)
            .collect();
        if ids.is_empty() {
            return Ok(reply(R_DENIED));
        }
        let operation = prologue(rid, level, &op, &ctx.my_key.public);
        let challenges =
            crate::fido::ChallengeStore::open(&root.join("fido/challenges")).map_err(|_| ())?;
        let challenge = challenges
            .issue(
                crate::fido::Ceremony::RootStepUp,
                ctx.account.as_bytes(),
                ctx.device_key,
                &operation,
                crate::fido::now_secs(),
                PENDING_LIFE.as_secs(),
                policy.user_verification,
            )
            .map_err(|_| ())?;
        let encoded =
            crate::fido::encode_challenge(rid, &policy, &challenge, &ids).map_err(|_| ())?;
        self.pending_fido.insert(rid, (level, op, challenge));
        Ok(vec![frame(FIDO_STEPUP_CHALLENGE, encoded)])
    }

    #[cfg(feature = "fido2")]
    pub async fn fido_proof(
        &mut self,
        payload: &[u8],
        ctx: &Ctx<'_>,
    ) -> Result<Vec<crate::wire::Frame>, ()> {
        let (rid, assertion) = crate::fido::decode_assertion(payload).map_err(|_| ())?;
        let reply =
            |status, text: &str| vec![frame(STEPUP_RESULT, encode_result(rid, status, text))];
        let Some((level, op, challenge)) = self.pending_fido.remove(&rid) else {
            return Ok(reply(R_EXPIRED, ""));
        };
        let policy = crate::fido::Policy::from_env().map_err(|_| ())?;
        let root = if level == Level::Root {
            crate::ipc::state_dir(ctx.dir, "broker")
        } else {
            ctx.dir.to_path_buf()
        };
        let operation = prologue(rid, level, &op, &ctx.my_key.public);
        let challenges =
            crate::fido::ChallengeStore::open(&root.join("fido/challenges")).map_err(|_| ())?;
        let credentials =
            crate::fido::CredentialStore::open(&root.join("fido/credentials")).map_err(|_| ())?;
        let ah = *blake3::hash(ctx.account.as_bytes()).as_bytes();
        let dh = *blake3::hash(ctx.device_key).as_bytes();
        let good = (|| -> anyhow::Result<()> {
            let uv = challenges.consume(
                &challenge.client_data,
                crate::fido::Ceremony::RootStepUp,
                ctx.account.as_bytes(),
                ctx.device_key,
                &operation,
                crate::fido::now_secs(),
            )?;
            let mut record = credentials.load(&assertion.credential_id)?;
            if record.account_hash != ah || record.device_hash != dh {
                anyhow::bail!("credential identity mismatch")
            }
            crate::fido::verify_assertion(
                &policy,
                &mut record,
                &challenge.client_data,
                &assertion,
                uv,
            )?;
            credentials.save(&record)
        })()
        .is_ok();
        if !good {
            ctx.lockouts.fail(ctx.device_key, level);
            let locked = ctx.lockouts.standing(ctx.device_key, level) == Standing::Locked;
            ctx.report(
                ctx.event(
                    level,
                    if locked {
                        crate::auditlog::RESULT_LOCKED
                    } else {
                        crate::auditlog::RESULT_DENIED
                    },
                    rid,
                )
                .target("FIDO2 assertion denied"),
            );
            return Ok(reply(if locked { R_LOCKED } else { R_DENIED }, ""));
        }
        if !ctx.lockouts.ok(ctx.device_key, level) {
            ctx.report(
                ctx.event(level, crate::auditlog::RESULT_DENIED, rid)
                    .target("lockout state persistence failed"),
            );
            return Ok(reply(R_DENIED, ""));
        }

        let mut cap = Cap::issue(level, &op, ctx.session_no, CAP_LIFE);
        if let Some(a) = ctx.audit {
            let desc = match &op {
                Op::Status => "status".into(),
                Op::TestPrivileged(n) => format!("test:{n}"),
                Op::RestartService(n) => format!("restart:{n}"),
            };
            if a.record_critical(
                ctx.event(level, crate::auditlog::RESULT_OK, rid)
                    .cap(&cap.id)
                    .target(&desc),
            )
            .await
            .is_err()
            {
                return Ok(reply(R_DENIED, ""));
            }
        }
        Ok(
            match broker_execute(ctx.dir, &mut cap, &op, ctx.session_no) {
                Ok(text) => {
                    if level == Level::Root {
                        ctx.report(
                            crate::auditlog::Event::new(
                                "broker_op",
                                crate::auditlog::LEVEL_ROOT,
                                crate::auditlog::RESULT_OK,
                            )
                            .session(&ctx.session_no.to_be_bytes())
                            .device(ctx.device_key)
                            .user(ctx.account)
                            .request(rid)
                            .cap(&cap.id)
                            .target(&text),
                        );
                    }
                    reply(R_OK, &text)
                }
                Err(_) => reply(R_DENIED, ""),
            },
        )
    }
    /// Err = the request is malformed: end the session
    pub fn begin(&mut self, payload: &[u8], ctx: &Ctx) -> Result<Vec<crate::wire::Frame>, ()> {
        let (rid, level, op, msg1) = decode_begin(payload).map_err(|_| ())?;
        let reply = |status: u8| vec![frame(STEPUP_RESULT, encode_result(rid, status, ""))];
        ctx.report_tamper(level);
        let life = self.life;
        self.pending.retain(|_, p| p.born.elapsed() < life);
        if !ctx.serves.contains(&level) || !ctx.session_rights.iter().any(|r| r == level.right()) || op.required() != Some(level) || self.pending.len() >= MAX_PENDING || self.pending.contains_key(&rid) {
            (ctx.log)(format!("step-up refused via '{}'", ctx.label));
            ctx.report(ctx.event(level, crate::auditlog::RESULT_DENIED, rid).target("refused at the start"));
            return Ok(reply(R_DENIED));
        }
        if ctx.lockouts.standing(ctx.device_key, level) == Standing::Locked {
            (ctx.log)(format!("step-up refused via '{}': locked", ctx.label));
            ctx.report(ctx.event(level, crate::auditlog::RESULT_LOCKED, rid).target("locked"));
            return Ok(reply(R_LOCKED));
        }
        #[cfg(feature = "fido2")]
        {
            let root = if level == Level::Root {
                crate::ipc::state_dir(ctx.dir, "broker")
            } else {
                ctx.dir.to_path_buf()
            };
            let required = match crate::fido::CredentialStore::open(&root.join("fido/credentials"))
                .and_then(|s| s.for_account_hash(blake3::hash(ctx.account.as_bytes()).as_bytes()))
            {
                Ok(v) => v.into_iter().any(|r| !r.revoked),
                Err(_) => return Ok(reply(R_DENIED)),
            };
            if required {
                ctx.report(
                    ctx.event(level, crate::auditlog::RESULT_DENIED, rid)
                        .target("password fallback forbidden by FIDO2 policy"),
                );
                return Ok(reply(R_DENIED));
            }
        }
        let hybrid = hybrid_required(level);
        if hybrid && !cfg!(feature = "hybrid-signatures") {
            return Ok(reply(R_DENIED));
        }
        let built = snow::Builder::new(NOISE_XK.parse().expect("params"))
            .local_private_key(&ctx.my_key.private)
            .prologue(&proof_prologue(rid, level, &op, &ctx.my_key.public, hybrid))
            .build_responder();
        let (Ok(mut hs), mut buf, mut out) = (built, vec![0u8; 512], vec![0u8; proof_buffer(hybrid)]) else {
            return Ok(reply(R_DENIED));
        };
        if !matches!(hs.read_message(&msg1, &mut buf), Ok(0)) {
            return Ok(reply(R_DENIED));
        }
        #[cfg(feature = "hybrid-signatures")]
        let (proof, hybrid_peer) = if hybrid {
            let Ok((own, peer)) = crate::hybrid_signature::handshake_keys(proof_context(level), &ctx.my_key.public, ctx.device_key) else {
                return Ok(reply(R_DENIED));
            };
            let body = hybrid_stepup_body(level, hs.get_handshake_hash(), ctx.device_key, &ctx.my_key.public, b'R');
            let Ok(proof) = own.sign(&body) else { return Ok(reply(R_DENIED)); };
            (proof.encode(), Some(peer))
        } else { (Vec::new(), None) };
        #[cfg(not(feature = "hybrid-signatures"))]
        let proof = [];
        let Ok(n) = hs.write_message(&proof, &mut out) else { return Ok(reply(R_DENIED)) };
        self.pending.insert(rid, Pending {
            hs, level, op, born: Instant::now(),
            #[cfg(feature = "hybrid-signatures")]
            hybrid_peer,
        });
        Ok(vec![frame(STEPUP_CHALLENGE, encode_msg(rid, &out[..n]))])
    }

    pub async fn proof(&mut self, payload: &[u8], ctx: &Ctx<'_>) -> Result<Vec<crate::wire::Frame>, ()> {
        #[cfg(feature = "hybrid-signatures")]
        let hybrid = payload.get(..8)
            .and_then(|bytes| bytes.try_into().ok())
            .and_then(|bytes| self.pending.get(&u64::from_be_bytes(bytes)))
            .is_some_and(|pending| pending.hybrid_peer.is_some());
        #[cfg(not(feature = "hybrid-signatures"))]
        let hybrid = false;
        let (rid, msg3) = decode_proof_msg(payload, hybrid).map_err(|_| ())?;
        let reply = |status: u8, text: &str| vec![frame(STEPUP_RESULT, encode_result(rid, status, text))];
        // one attempt per challenge: whatever happens next, this one is used up
        let Some(mut p) = self.pending.remove(&rid) else {
            // an answer to a challenge that does not exist (any more): a repeat, or a guess
            ctx.report(crate::auditlog::Event::new("replay", crate::auditlog::LEVEL_NONE, crate::auditlog::RESULT_DENIED).session(&ctx.session_no.to_be_bytes()).device(ctx.device_key).user(ctx.account).request(rid).target("proof without a challenge"));
            return Ok(reply(R_EXPIRED, ""));
        };
        if p.born.elapsed() >= self.life {
            ctx.report(ctx.event(p.level, crate::auditlog::RESULT_DENIED, rid).target("expired"));
            return Ok(reply(R_EXPIRED, ""));
        }
        #[cfg(feature = "hybrid-signatures")]
        let hybrid_body = p.hybrid_peer.as_ref().map(|_| {
            hybrid_stepup_body(p.level, p.hs.get_handshake_hash(), ctx.device_key, &ctx.my_key.public, b'I')
        });
        let mut phrase = zeroize::Zeroizing::new(vec![0u8; proof_buffer(hybrid)]);
        let Ok(n) = p.hs.read_message(msg3, &mut phrase) else {
            // not authenticated: whoever sent this did not hold a device key, so no key is blamed for it
            return Ok(reply(R_DENIED, ""));
        };
        phrase.truncate(n);
        #[cfg(feature = "hybrid-signatures")]
        if let Some((pin, body)) = p.hybrid_peer.as_ref().zip(hybrid_body) {
            use crate::hybrid_signature::{SignatureEnvelope, ENVELOPE_LEN};
            if phrase.len() <= ENVELOPE_LEN {
                return Ok(reply(R_DENIED, ""));
            }
            let boundary = phrase.len() - ENVELOPE_LEN;
            if SignatureEnvelope::decode(&phrase[boundary..]).and_then(|sig| pin.verify(&body, &sig)).is_err() {
                return Ok(reply(R_DENIED, ""));
            }
            phrase.truncate(boundary);
        }
        let device = p.hs.get_remote_static().map(|k| k.to_vec()).unwrap_or_default();
        if device != ctx.device_key || phrase.is_empty() || phrase.len() > MAX_PHRASE {
            // the device key that took part is not the key of this session: nobody in between can make one up
            zeroize::Zeroize::zeroize(&mut phrase);
            return Ok(reply(R_DENIED, ""));
        }
        let (dir, level) = (ctx.dir.to_path_buf(), p.level);
        let good = tokio::task::spawn_blocking(move || {
            let ok = Verifier::check(&dir, level, &phrase);
            zeroize::Zeroize::zeroize(&mut phrase);
            ok
        })
        .await
        .unwrap_or(false);
        if !good {
            ctx.lockouts.fail(ctx.device_key, p.level);
            let locked = ctx.lockouts.standing(ctx.device_key, p.level) == Standing::Locked;
            (ctx.log)(format!("step-up failed via '{}'{}", ctx.label, if locked { ": now locked" } else { "" }));
            ctx.report(ctx.event(p.level, if locked { crate::auditlog::RESULT_LOCKED } else { crate::auditlog::RESULT_DENIED }, rid).target(if locked { "wrong phrase, now locked" } else { "wrong phrase" })); // the phrase itself is nowhere
            if p.level == Level::Root && ctx.lockouts.take_global_news() {
                ctx.report(crate::auditlog::Event::new("global_root_off", crate::auditlog::LEVEL_ROOT, crate::auditlog::RESULT_LOCKED).target("remote ROOT switched off for everybody"));
            }
            return Ok(reply(if locked { R_LOCKED } else { R_DENIED }, ""));
        }
        if !ctx.lockouts.ok(ctx.device_key, p.level) {
            ctx.report(
                ctx.event(p.level, crate::auditlog::RESULT_DENIED, rid)
                    .target("lockout state persistence failed"),
            );
            return Ok(reply(R_DENIED, ""));
        }

        let mut cap = Cap::issue(p.level, &p.op, ctx.session_no, CAP_LIFE);
        // an approval nobody can account for is not given: if it cannot be written down, it does not happen
        if let Some(a) = ctx.audit {
            let desc = match &p.op {
                Op::Status => "status".to_string(),
                Op::TestPrivileged(n) => format!("test:{n}"),
                Op::RestartService(n) => format!("restart:{n}"),
            };
            if a.record_critical(ctx.event(p.level, crate::auditlog::RESULT_OK, rid).cap(&cap.id).target(&desc)).await.is_err() {
                (ctx.log)(format!("step-up not approved via '{}': the audit journal is not available", ctx.label));
                return Ok(reply(R_DENIED, ""));
            }
        }
        (ctx.log)(format!("step-up approved via '{}' for {}", ctx.label, p.level.right()));
        Ok(match broker_execute(ctx.dir, &mut cap, &p.op, ctx.session_no) {
            Ok(text) => {
                if p.level == Level::Root {
                    ctx.report(crate::auditlog::Event::new("broker_op", crate::auditlog::LEVEL_ROOT, crate::auditlog::RESULT_OK).session(&ctx.session_no.to_be_bytes()).device(ctx.device_key).user(ctx.account).request(rid).cap(&cap.id).target(&text));
                }
                reply(R_OK, &text)
            }
            Err(_) => reply(R_DENIED, ""),
        })
    }
}

#[cfg(test)]
mod rev005_tests {
    use super::*;

    fn store(dir: &Path) -> Store {
        Store {
            path: dir.join("lockouts.root"),
            key_path: dir.join("lockouts.root.key"),
        }
    }

    fn fail_sync() {
        REV005_FAIL_SYNC.with(|flag| flag.set(true));
    }

    #[test]
    fn key_creation_requires_directory_sync() {
        let d = tempfile::tempdir().unwrap();
        let store = store(d.path());

        fail_sync();

        assert!(
            store.make_key().is_none(),
            "key creation succeeded without durable publication"
        );
    }

    #[test]
    fn lockout_save_requires_directory_sync() {
        let d = tempfile::tempdir().unwrap();
        let store = store(d.path());

        assert!(store.save(&State::default()).is_some());

        fail_sync();

        assert!(
            store.save(&State::default()).is_none(),
            "lockout publication succeeded despite sync failure"
        );
    }

    #[test]
    fn failed_counter_persistence_locks_all_privileged_attempts() {
        let d = tempfile::tempdir().unwrap();

        let lockouts = Lockouts::persistent(
            d.path(), "root"
        );

        let key = [1u8; 32];
        let other = [2u8; 32];

        assert_eq!(
            lockouts.standing(&key, Level::Root),
            Standing::Open
        );

        fail_sync();
        lockouts.fail(&key, Level::Root);

        assert_eq!(
            lockouts.standing(&key, Level::Root),
            Standing::Locked
        );

        assert_eq!(
            lockouts.standing(&other, Level::Root),
            Standing::Locked
        );
    }

    #[test]
    fn failed_success_persistence_locks_privileged_attempts() {
        let d = tempfile::tempdir().unwrap();

        let lockouts = Lockouts::persistent(
            d.path(), "sudo"
        );

        let key = [3u8; 32];

        lockouts.fail(&key, Level::Sudo);

        assert_eq!(
            lockouts.standing(&key, Level::Sudo),
            Standing::Open
        );

        fail_sync();
        assert!(!lockouts.ok(&key, Level::Sudo));

        assert_eq!(
            lockouts.standing(&key, Level::Sudo),
            Standing::Locked
        );
    }
}

#[cfg(test)]
mod rev005_approval_tests {
    use super::*;

    #[test]
    fn locked_root_cannot_receive_approval() {
        let lockouts = Lockouts::default();
        let key = [11u8; 32];

        assert!(lockouts.ok(&key, Level::Root));

        for _ in 0..3 {
            lockouts.fail(&key, Level::Root);
        }

        assert_eq!(
            lockouts.standing(&key, Level::Root),
            Standing::Locked
        );

        assert!(!lockouts.ok(&key, Level::Root));
    }

    #[test]
    fn locked_sudo_cannot_receive_approval() {
        let lockouts = Lockouts::default();
        let key = [12u8; 32];

        for _ in 0..3 {
            lockouts.fail(&key, Level::Sudo);
        }

        assert!(!lockouts.ok(&key, Level::Sudo));
    }

    #[test]
    fn global_root_lock_blocks_late_approval() {
        let lockouts = Lockouts::default();

        for i in 1..=3u8 {
            for _ in 0..3 {
                lockouts.fail(&[i; 32], Level::Root);
            }
        }

        let clean = [99u8; 32];

        assert!(lockouts.remote_root_off());
        assert!(!lockouts.ok(&clean, Level::Root));
        assert!(lockouts.ok(&clean, Level::Sudo));
    }

    #[test]
    fn failed_initialization_refuses_approval() {
        let d = tempfile::tempdir().unwrap();

        REV005_FAIL_SYNC.with(|flag| flag.set(true));

        let lockouts = Lockouts::persistent(
            d.path(), "root"
        );

        let key = [13u8; 32];

        assert!(!lockouts.ok(&key, Level::Root));

        assert_eq!(
            lockouts.standing(&key, Level::Root),
            Standing::Locked
        );
    }

    #[test]
    fn persistent_root_lock_survives_reopen() {
        let d = tempfile::tempdir().unwrap();
        let key = [14u8; 32];

        {
            let lockouts = Lockouts::persistent(
                d.path(), "root"
            );

            for _ in 0..3 {
                lockouts.fail(&key, Level::Root);
            }

            assert!(!lockouts.ok(&key, Level::Root));
        }

        let reopened = Lockouts::persistent(
            d.path(), "root"
        );

        assert_eq!(
            reopened.standing(&key, Level::Root),
            Standing::Locked
        );

        assert!(!reopened.ok(&key, Level::Root));
    }

    #[test]
    fn persistence_failure_refuses_current_approval() {
        let d = tempfile::tempdir().unwrap();

        let lockouts = Lockouts::persistent(
            d.path(), "root"
        );

        let key = [15u8; 32];

        assert!(lockouts.ok(&key, Level::Root));

        REV005_FAIL_SYNC.with(|flag| flag.set(true));

        assert!(!lockouts.ok(&key, Level::Root));
        assert!(!lockouts.ok(&key, Level::Root));
        assert!(!lockouts.ok(&[16u8; 32], Level::Root));
    }
}

#[cfg(test)]
mod rev005_concurrency_tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn independent_instances_preserve_all_failures() {
        let d = tempfile::tempdir().unwrap();
        let initial = Lockouts::persistent(d.path(), "root");
        let key = [21u8; 32];

        assert_eq!(
            initial.standing(&key, Level::Root),
            Standing::Open
        );

        let barrier = Arc::new(Barrier::new(3));

        std::thread::scope(|scope| {
            for _ in 0..3 {
                let barrier = barrier.clone();
                let dir = d.path();

                scope.spawn(move || {
                    let lockouts =
                        Lockouts::persistent(dir, "root");

                    barrier.wait();

                    lockouts.fail(&key, Level::Root);
                });
            }
        });

        assert_eq!(
            initial.standing(&key, Level::Root),
            Standing::Locked,
            "concurrent updates lost failure counters"
        );
    }

    #[test]
    fn root_and_sudo_stores_are_independent() {
        let d = tempfile::tempdir().unwrap();

        let root = Lockouts::persistent(d.path(), "root");
        let sudo = Lockouts::persistent(d.path(), "sudo");

        let key = [22u8; 32];
        let barrier = Barrier::new(2);

        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();

                for _ in 0..3 {
                    root.fail(&key, Level::Root);
                }
            });

            scope.spawn(|| {
                barrier.wait();

                for _ in 0..3 {
                    sudo.fail(&key, Level::Sudo);
                }
            });
        });

        let root = Lockouts::persistent(d.path(), "root");
        let sudo = Lockouts::persistent(d.path(), "sudo");

        assert_eq!(
            root.standing(&key, Level::Root),
            Standing::Locked
        );

        assert_eq!(
            sudo.standing(&key, Level::Sudo),
            Standing::Locked
        );
    }
}

#[cfg(test)]
mod rev005_process_tests {
    use super::*;
    use std::process::{Command, Stdio};

    const WORKER: &str =
        "stepup::rev005_process_tests::process_worker";

    fn spawn_worker(
        dir: &Path,
        mode: &str,
    ) -> std::process::Child {
        Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(WORKER)
            .arg("--ignored")
            .arg("--test-threads=1")
            .env("YRL_REV005_TEST_DIR", dir)
            .env("YRL_REV005_TEST_MODE", mode)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap()
    }

    #[test]
    #[ignore]
    fn process_worker() {
        let dir = std::path::PathBuf::from(
            std::env::var_os("YRL_REV005_TEST_DIR")
                .expect("missing test directory")
        );

        let mode = std::env::var(
            "YRL_REV005_TEST_MODE"
        ).unwrap();

        match mode.as_str() {
            "fail" => {
                let lockouts =
                    Lockouts::persistent(&dir, "root");

                lockouts.fail(&[31u8; 32], Level::Root);
            }

            "hold" => {
                let store = Store {
                    path: dir.join("lockouts.root"),
                    key_path: dir.join("lockouts.root.key"),
                };

                let _guard =
                    store.transaction_lock().unwrap();

                std::fs::write(
                    dir.join("worker.ready"), b"ready"
                ).unwrap();

                loop {
                    std::thread::sleep(
                        Duration::from_millis(100)
                    );
                }
            }

            _ => panic!("unknown worker mode"),
        }
    }

    #[test]
    fn independent_processes_preserve_failure_counters() {
        let d = tempfile::tempdir().unwrap();

        let initial = Lockouts::persistent(
            d.path(), "root"
        );

        let key = [31u8; 32];

        assert_eq!(
            initial.standing(&key, Level::Root),
            Standing::Open
        );

        let mut children: Vec<_> = (0..3)
            .map(|_| spawn_worker(d.path(), "fail"))
            .collect();

        for child in &mut children {
            assert!(child.wait().unwrap().success());
        }

        let reopened = Lockouts::persistent(
            d.path(), "root"
        );

        assert_eq!(
            reopened.standing(&key, Level::Root),
            Standing::Locked,
            "cross-process failure counters were lost"
        );

        assert!(!reopened.ok(&key, Level::Root));
    }

    #[test]
    fn sigkill_releases_transaction_lock() {
        let d = tempfile::tempdir().unwrap();

        let initial = Lockouts::persistent(
            d.path(), "root"
        );

        let key = [31u8; 32];

        initial.fail(&key, Level::Root);
        initial.fail(&key, Level::Root);

        let mut holder = spawn_worker(
            d.path(), "hold"
        );

        let deadline =
            Instant::now() + Duration::from_secs(5);

        while !d.path().join("worker.ready").exists() {
            if Instant::now() >= deadline {
                let _ = holder.kill();
                let _ = holder.wait();
                panic!("worker did not acquire lock");
            }

            std::thread::sleep(
                Duration::from_millis(10)
            );
        }

        let mut waiter = spawn_worker(
            d.path(), "fail"
        );

        std::thread::sleep(
            Duration::from_millis(100)
        );

        let blocked =
            waiter.try_wait().unwrap().is_none();

        // On Unix Child::kill sends SIGKILL.
        holder.kill().unwrap();

        assert!(!holder.wait().unwrap().success());

        let deadline =
            Instant::now() + Duration::from_secs(5);

        loop {
            if let Some(status) =
                waiter.try_wait().unwrap()
            {
                assert!(status.success());
                break;
            }

            if Instant::now() >= deadline {
                let _ = waiter.kill();
                let _ = waiter.wait();

                panic!("lock remained held after SIGKILL");
            }

            std::thread::sleep(
                Duration::from_millis(10)
            );
        }

        assert!(blocked,
            "second process bypassed transaction lock");

        let reopened = Lockouts::persistent(
            d.path(), "root"
        );

        assert_eq!(
            reopened.standing(&key, Level::Root),
            Standing::Locked
        );
    }

    #[test]
    fn symlink_transaction_lock_is_refused() {
        let d = tempfile::tempdir().unwrap();

        let target = d.path().join("unrelated");

        std::fs::write(&target, b"unchanged").unwrap();

        std::os::unix::fs::symlink(
            &target,
            d.path().join("lockouts.root.lock")
        ).unwrap();

        let lockouts = Lockouts::persistent(
            d.path(), "root"
        );

        assert!(!lockouts.ok(
            &[32u8; 32], Level::Root
        ));

        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"unchanged"
        );
    }

    #[test]
    fn public_transaction_lock_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let d = tempfile::tempdir().unwrap();

        let path = d.path().join("lockouts.root.lock");

        std::fs::write(&path, b"").unwrap();

        std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o666)
        ).unwrap();

        let lockouts = Lockouts::persistent(
            d.path(), "root"
        );

        assert_eq!(
            lockouts.standing(&[33u8; 32], Level::Root),
            Standing::Locked
        );

        assert!(!lockouts.ok(
            &[33u8; 32], Level::Root
        ));
    }
}

#[cfg(test)]
mod rev005_recovery_tests {
    use super::*;

    fn fail_sync() {
        REV005_FAIL_SYNC.with(|flag| flag.set(true));
    }

    #[test]
    fn failed_counter_write_remains_closed_after_reopen() {
        let d = tempfile::tempdir().unwrap();
        let key = [41u8; 32];

        {
            let lockouts =
                Lockouts::persistent(d.path(), "root");

            assert_eq!(
                lockouts.standing(&key, Level::Root),
                Standing::Open
            );

            fail_sync();

            lockouts.fail(&key, Level::Root);

            assert_eq!(
                lockouts.standing(&key, Level::Root),
                Standing::Locked
            );
        }

        let reopened =
            Lockouts::persistent(d.path(), "root");

        assert_eq!(
            reopened.standing(&key, Level::Root),
            Standing::Locked,
            "persistence fault was forgotten after reopen"
        );
    }

    #[test]
    fn failed_approval_remains_closed_after_reopen() {
        let d = tempfile::tempdir().unwrap();
        let key = [42u8; 32];

        {
            let lockouts =
                Lockouts::persistent(d.path(), "sudo");

            assert!(lockouts.ok(&key, Level::Sudo));

            fail_sync();

            assert!(!lockouts.ok(&key, Level::Sudo));
        }

        let reopened =
            Lockouts::persistent(d.path(), "sudo");

        assert!(
            !reopened.ok(&key, Level::Sudo),
            "reopen discarded previous persistence fault"
        );
    }

    #[test]
    fn administrative_reset_recovers_persistent_store() {
        let d = tempfile::tempdir().unwrap();
        let key = [43u8; 32];

        {
            let lockouts =
                Lockouts::persistent(d.path(), "root");

            for _ in 0..3 {
                lockouts.fail(&key, Level::Root);
            }

            assert!(!lockouts.ok(&key, Level::Root));
        }

        Lockouts::reset_files(d.path(), "root")
            .unwrap();

        let reopened =
            Lockouts::persistent(d.path(), "root");

        assert_eq!(
            reopened.standing(&key, Level::Root),
            Standing::Open
        );

        assert!(reopened.ok(&key, Level::Root));
    }
}

#[cfg(test)]
mod rev005_transaction_fault_tests {
    use super::*;

    fn inject_at(stage: usize) {
        REV005_FAIL_SYNC_AT.with(|counter| {
            counter.set(stage);
        });
    }

    fn assert_fault_consumed() {
        REV005_FAIL_SYNC_AT.with(|counter| {
            assert_eq!(
                counter.get(), 0,
                "requested fault stage was not reached"
            );
        });
    }

    fn check_failure(stage: usize, level: Level) {
        let d = tempfile::tempdir().unwrap();

        let name = match level {
            Level::Root => "root",
            Level::Sudo => "sudo",
        };

        let key = [51u8; 32];
        let other = [52u8; 32];

        let dirty = d.path().join(
            format!("lockouts.{name}.dirty")
        );

        {
            let lockouts =
                Lockouts::persistent(d.path(), name);

            assert!(lockouts.ok(&key, level));

            assert!(!dirty.exists());

            lockouts.fail(&key, level);

            inject_at(stage);

            assert!(
                !lockouts.ok(&key, level),
                "approval succeeded at fault stage {stage}"
            );

            assert_fault_consumed();

            assert_eq!(
                lockouts.standing(&key, level),
                Standing::Locked
            );

            assert_eq!(
                lockouts.standing(&other, level),
                Standing::Locked
            );

            assert!(
                dirty.exists(),
                "missing refusal marker at stage {stage}"
            );

            // A separate instance must also refuse.
            let independent =
                Lockouts::persistent(d.path(), name);

            assert!(!independent.ok(&other, level));
        }

        // Reopen without the original in-memory fault.
        {
            let reopened =
                Lockouts::persistent(d.path(), name);

            assert_eq!(
                reopened.standing(&key, level),
                Standing::Locked
            );

            assert!(!reopened.ok(&key, level));
            assert!(!reopened.ok(&other, level));
        }

        // Only explicit local recovery clears the fault.
        Lockouts::reset_files(d.path(), name)
            .unwrap();

        assert!(!dirty.exists());

        let recovered =
            Lockouts::persistent(d.path(), name);

        assert_eq!(
            recovered.standing(&key, level),
            Standing::Open
        );

        assert!(recovered.ok(&key, level));
        assert!(!dirty.exists());
    }

    #[test]
    fn root_dirty_publication_failure() {
        check_failure(1, Level::Root);
    }

    #[test]
    fn root_state_publication_failure() {
        check_failure(2, Level::Root);
    }

    #[test]
    fn root_dirty_removal_failure() {
        check_failure(3, Level::Root);
    }

    #[test]
    fn sudo_dirty_publication_failure() {
        check_failure(1, Level::Sudo);
    }

    #[test]
    fn sudo_state_publication_failure() {
        check_failure(2, Level::Sudo);
    }

    #[test]
    fn sudo_dirty_removal_failure() {
        check_failure(3, Level::Sudo);
    }
}

#[cfg(test)]
mod rev005_crash_tests {
    use super::*;
    use std::process::{Command, Stdio};

    const WORKER: &str =
        "stepup::rev005_crash_tests::crash_worker";

    const KEY: [u8; 32] = [61u8; 32];

    #[test]
    #[ignore]
    fn crash_worker() {
        let dir = std::path::PathBuf::from(
            std::env::var_os("YRL_REV005_CRASH_DIR")
                .unwrap()
        );

        let stage: usize = std::env::var(
            "YRL_REV005_CRASH_STAGE"
        ).unwrap().parse().unwrap();

        let store = Store {
            path: dir.join("lockouts.root"),
            key_path: dir.join("lockouts.root.key"),
        };

        let _guard = store.transaction_lock().unwrap();

        let mut state = store.load().unwrap();

        store.begin_transaction().unwrap();

        if stage >= 2 {
            state.recs.insert(
                (KEY.to_vec(), Level::Root),
                Rec {
                    fails: 0,
                    locked: true,
                    until: 0,
                }
            );

            store.save(&state).unwrap();
        }

        if stage >= 3 {
            store.finish_transaction().unwrap();
        }

        std::fs::write(
            dir.join("crash.ready"),
            b"ready"
        ).unwrap();

        loop {
            std::thread::sleep(
                Duration::from_millis(100)
            );
        }
    }

    fn check_crash(stage: usize) {
        let d = tempfile::tempdir().unwrap();

        {
            let initial =
                Lockouts::persistent(d.path(), "root");

            assert_eq!(
                initial.standing(&KEY, Level::Root),
                Standing::Open
            );

            initial.fail(&KEY, Level::Root);
            initial.fail(&KEY, Level::Root);

            assert_eq!(
                initial.standing(&KEY, Level::Root),
                Standing::Open
            );
        }

        let mut child =
            Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(WORKER)
                .arg("--ignored")
                .arg("--test-threads=1")
                .env("YRL_REV005_CRASH_DIR", d.path())
                .env(
                    "YRL_REV005_CRASH_STAGE",
                    stage.to_string()
                )
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap();

        let deadline =
            Instant::now() + Duration::from_secs(5);

        while !d.path().join("crash.ready").exists() {
            if Instant::now() >= deadline
                || child.try_wait().unwrap().is_some()
            {
                let _ = child.kill();
                let _ = child.wait();

                panic!(
                    "worker failed at stage {stage}"
                );
            }

            std::thread::sleep(
                Duration::from_millis(10)
            );
        }

        child.kill().unwrap();

        let status = child.wait().unwrap();

        use std::os::unix::process::ExitStatusExt;

        assert_eq!(
            status.signal(),
            Some(libc::SIGKILL)
        );

        let dirty =
            d.path().join("lockouts.root.dirty");

        assert_eq!(
            dirty.exists(),
            stage < 3
        );

        let reopened =
            Lockouts::persistent(d.path(), "root");

        assert_eq!(
            reopened.standing(&KEY, Level::Root),
            Standing::Locked
        );

        assert!(!reopened.ok(&KEY, Level::Root));

        let other = [62u8; 32];

        if stage < 3 {
            // Incomplete transaction refuses the entire store.
            assert_eq!(
                reopened.standing(&other, Level::Root),
                Standing::Locked
            );

            assert!(!reopened.ok(&other, Level::Root));
        } else {
            // Completed transaction preserves only the
            // intended device lockout.
            assert_eq!(
                reopened.standing(&other, Level::Root),
                Standing::Open
            );

            assert!(reopened.ok(&other, Level::Root));
        }

        drop(reopened);

        Lockouts::reset_files(d.path(), "root")
            .unwrap();

        assert!(!dirty.exists());

        let recovered =
            Lockouts::persistent(d.path(), "root");

        assert!(recovered.ok(&KEY, Level::Root));
    }

    #[test]
    fn sigkill_after_dirty_publication() {
        check_crash(1);
    }

    #[test]
    fn sigkill_after_state_publication() {
        check_crash(2);
    }

    #[test]
    fn sigkill_after_transaction_completion() {
        check_crash(3);
    }
}
