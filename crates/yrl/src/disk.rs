//! Persistent, process-wide admission for managed FILE_PUT operations.
//!
//! Reservations are charged by the announced final size before the helper opens the partial file.
//! The ledger survives Executor restart; the in-memory `active` set deliberately does not, so an
//! interrupted upload can be resumed but an old, inactive one can eventually expire.
use crate::identity::Target;
use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsStr, OsString};
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TAG: &[u8] = b"user.yrl.partial\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiskLimits {
    pub bytes_total: u64,
    pub bytes_per_key: u64,
    pub bytes_per_account: u64,
    /// Space which managed uploads must leave available on the destination filesystem.
    pub free_space_reserve: u64,
    pub partial_ttl: Duration,
}

impl Default for DiskLimits {
    fn default() -> Self {
        DiskLimits {
            bytes_total: 64 << 30,
            bytes_per_key: 16 << 30,
            bytes_per_account: 16 << 30,
            free_space_reserve: 1 << 30,
            partial_ttl: Duration::from_secs(7 * 24 * 60 * 60),
        }
    }
}

impl DiskLimits {
    pub fn from_env() -> anyhow::Result<Self> {
        fn value(name: &str, default: u64) -> anyhow::Result<u64> {
            match std::env::var(name) {
                Ok(v) => v.parse().map_err(|_| anyhow::anyhow!("invalid {name}")),
                Err(std::env::VarError::NotPresent) => Ok(default),
                Err(_) => Err(anyhow::anyhow!("invalid {name}")),
            }
        }
        let d = Self::default();
        let limits = DiskLimits {
            bytes_total: value("YRL_DISK_BYTES_TOTAL", d.bytes_total)?,
            bytes_per_key: value("YRL_DISK_BYTES_PER_KEY", d.bytes_per_key)?,
            bytes_per_account: value("YRL_DISK_BYTES_PER_ACCOUNT", d.bytes_per_account)?,
            free_space_reserve: value("YRL_DISK_FREE_RESERVE", d.free_space_reserve)?,
            partial_ttl: Duration::from_secs(value(
                "YRL_PARTIAL_TTL_SECS",
                d.partial_ttl.as_secs(),
            )?),
        };
        limits.validate()?;
        Ok(limits)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.bytes_total == 0
            || self.bytes_per_key == 0
            || self.bytes_per_account == 0
            || self.bytes_per_key > self.bytes_total
            || self.bytes_per_account > self.bytes_total
            || self.partial_ttl.is_zero()
        {
            anyhow::bail!("disk budgets and partial TTL must be non-zero and principal budgets must fit the global budget");
        }
        Ok(())
    }
}

#[derive(Clone)]
struct Record {
    token: [u8; 16],
    key: Vec<u8>,
    account: String,
    uid: u32,
    path: Vec<u8>,
    size: u64,
    touched: u64,
}

#[derive(Default)]
struct State {
    records: HashMap<[u8; 16], Record>,
    active: HashSet<[u8; 16]>,
    faulted: bool,
}

pub struct DiskManager {
    ledger: PathBuf,
    limits: DiskLimits,
    state: Mutex<State>,
    // Exclusive ownership survives while reservations exist.
    _ownership: std::fs::File,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Quota,
    NoSpace,
    Busy,
    State,
}

pub struct Reservation {
    manager: Arc<DiskManager>,
    token: [u8; 16],
    finished: bool,
}

impl DiskManager {
    pub fn open(ledger: PathBuf, limits: DiskLimits) -> anyhow::Result<Self> {
        limits.validate()?;
        let ownership = acquire_ownership(&ledger)?;
        let records = read_ledger(&ledger)?;

        // Establish a durable baseline before allowing admission.
        persist(&ledger, &records)?;
        let manager = DiskManager {
            ledger,
            limits,
            state: Mutex::new(State {
                records,
                active: HashSet::new(),
                faulted: false,
            }),
            _ownership: ownership,
        };
        manager.expire()?;
        Ok(manager)
    }

    pub fn limits(&self) -> &DiskLimits {
        &self.limits
    }

    pub fn reserve(
        self: &Arc<Self>,
        key: &[u8],
        account: &str,
        target: &Target,
        request_path: &[u8],
        size: u64,
    ) -> Result<Reservation, Refusal> {
        self.expire().map_err(|_| Refusal::State)?;
        let path = absolute_path(target, request_path).ok_or(Refusal::State)?;
        let path_bytes = path.as_os_str().as_bytes().to_vec();
        let now = now();
        let mut s = self.state.lock().unwrap();

        if s.faulted {
            return Err(Refusal::State);
        }

        // The same authenticated principal may resume the exact reservation without being charged
        // twice. No other upload may concurrently claim the pathname.
        if let Some(token) = s
            .records
            .iter()
            .find(|(_, r)| r.uid == target.pw.uid && r.path == path_bytes)
            .map(|(t, _)| *t)
        {
            if s.active.contains(&token) {
                return Err(Refusal::Busy);
            }
            let record = s
                .records
                .get_mut(&token)
                .expect("reservation disappeared while locked");
            if record.key != key || record.account != account || record.size != size {
                return Err(Refusal::Busy);
            }
            record.touched = now;
            s.active.insert(token);
            if persist(&self.ledger, &s.records).is_err() {
                s.active.remove(&token);
                mark_faulted(&mut s);
                return Err(Refusal::State);
            }
            return Ok(Reservation {
                manager: self.clone(),
                token,
                finished: false,
            });
        }

        let mut total = 0u64;
        let mut key_total = 0u64;
        let mut account_total = 0u64;
        for r in s.records.values() {
            total = total.saturating_add(r.size);
            if r.key == key {
                key_total = key_total.saturating_add(r.size);
            }
            if r.account == account {
                account_total = account_total.saturating_add(r.size);
            }
        }
        if total.saturating_add(size) > self.limits.bytes_total
            || key_total.saturating_add(size) > self.limits.bytes_per_key
            || account_total.saturating_add(size) > self.limits.bytes_per_account
        {
            return Err(Refusal::Quota);
        }
        // This is performed while holding the same lock as logical admission, so parallel requests
        // cannot all consume the same free bytes. Full reservations are deliberately conservative:
        // already-written partial bytes can be counted twice, never omitted.
        let available = available_bytes(&path).ok_or(Refusal::State)?;
        if available
            < self
                .limits
                .free_space_reserve
                .saturating_add(total)
                .saturating_add(size)
        {
            return Err(Refusal::NoSpace);
        }
        let token = random_token().map_err(|_| Refusal::State)?;
        s.records.insert(
            token,
            Record {
                token,
                key: key.to_vec(),
                account: account.to_string(),
                uid: target.pw.uid,
                path: path_bytes,
                size,
                touched: now,
            },
        );
        s.active.insert(token);
        if persist(&self.ledger, &s.records).is_err() {
            s.active.remove(&token);

            // Publication may have happened. Retain the charge
            // and refuse further admission until recovery.
            mark_faulted(&mut s);

            return Err(Refusal::State);
        }
        Ok(Reservation {
            manager: self.clone(),
            token,
            finished: false,
        })
    }

    fn expire(&self) -> anyhow::Result<()> {
        let cutoff = now().saturating_sub(self.limits.partial_ttl.as_secs());
        let mut s = self.state.lock().unwrap();

        if s.faulted {
            anyhow::bail!("disk reservation ledger is faulted");
        }

        let expired: Vec<_> = s
            .records
            .iter()
            .filter(|(t, r)| !s.active.contains(*t) && r.touched <= cutoff)
            .map(|(t, _)| *t)
            .collect();
        let mut removed = Vec::new();
        for token in expired {
            if let Some(r) = s.records.remove(&token) {
                remove_tagged_partial(&r);
                removed.push((token, r));
            }
        }
        if removed.is_empty() {
            return Ok(());
        }
        if let Err(e) = persist(&self.ledger, &s.records) {
            s.records.extend(removed);
            mark_faulted(&mut s);
            return Err(e);
        }
        Ok(())
    }

    fn release(&self, token: [u8; 16], completed: bool) {
        let mut s = self.state.lock().unwrap();
        s.active.remove(&token);

        // Once persistence is uncertain, do not perform more
        // destructive cleanup or release persistent charges.
        if s.faulted {
            return;
        }

        if let Some(r) = s.records.remove(&token) {
            if !completed {
                remove_tagged_partial(&r);
            }
            // A ledger write failure retains the charge in memory too. This is deliberately
            // fail-closed: storage trouble cannot turn cancellation into a quota bypass.
            if persist(&self.ledger, &s.records).is_err() {
                s.records.insert(token, r);
                mark_faulted(&mut s);
            }
        }
    }
}

impl Reservation {
    /// Keep a tagged partial and its ledger charge after an unplanned disconnect.
    pub fn preserve(mut self) {
        self.manager.state.lock().unwrap().active.remove(&self.token);
        self.finished = true;
    }

    pub fn token_hex(&self) -> String {
        hex::encode(self.token)
    }
    /// Refresh persistent activity at most once per minute. This makes TTL reflect a long-running
    /// transfer without turning every chunk into a synchronous ledger write.
    pub fn touch(&self) {
        let now = now();
        let mut s = self.manager.state.lock().unwrap();

        if s.faulted {
            return;
        }

        let Some(r) = s.records.get_mut(&self.token) else {
            return;
        };
        if now.saturating_sub(r.touched) < 60 {
            return;
        }
        r.touched = now;
        if persist(&self.manager.ledger, &s.records).is_err() {
            mark_faulted(&mut s);
        }
    }
    pub fn complete(mut self) {
        self.manager.release(self.token, true);
        self.finished = true;
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.finished {
            self.manager.release(self.token, false);
        }
    }
}

fn absolute_path(target: &Target, raw: &[u8]) -> Option<PathBuf> {
    if raw.is_empty() || raw.contains(&0) {
        return None;
    }
    let p = PathBuf::from(OsString::from_vec(raw.to_vec()));
    Some(if p.is_absolute() {
        p
    } else {
        Path::new(&target.pw.home).join(p)
    })
}

fn part_path(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_os_string();
    p.push(".yrl-part");
    PathBuf::from(p)
}

fn remove_tagged_partial(r: &Record) {
    let p = part_path(Path::new(OsStr::from_bytes(&r.path)));
    let Ok(f) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&p)
    else {
        return;
    };
    let Ok(m) = f.metadata() else { return };
    if !m.is_file() || m.uid() != r.uid || m.nlink() != 1 {
        return;
    }
    if file_tag(&f).as_deref() != Some(r.token.as_slice()) {
        return;
    }
    // Do not unlink by the checked pathname: the account owning its parent directory could swap
    // that name between the check and unlink. Atomically move the name aside without replacing
    // anything, then verify that the moved inode is the one we opened. A raced user file is moved
    // back (or, if the attacker occupied the old name, retained under the quarantine name), never
    // deleted. The quarantine is in the same directory so rename cannot cross filesystems.
    let Ok(random) = random_token() else { return };
    let mut q = p.as_os_str().to_os_string();
    q.push(format!(".yrl-clean-{}", hex::encode(random)));
    let q = PathBuf::from(q);
    if !rename_noreplace(&p, &q) {
        return;
    }
    let moved = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&q);
    let same = moved
        .as_ref()
        .ok()
        .and_then(|moved| moved.metadata().ok())
        .is_some_and(|after| {
            after.is_file()
                && after.uid() == r.uid
                && after.nlink() == 1
                && after.dev() == m.dev()
                && after.ino() == m.ino()
                && moved.as_ref().ok().and_then(file_tag).as_deref() == Some(r.token.as_slice())
        });
    drop(moved);
    if same {
        let _ = std::fs::remove_file(q);
    } else {
        let _ = rename_noreplace(&q, &p); // failure preserves the raced file under q
    }
}

fn rename_noreplace(from: &Path, to: &Path) -> bool {
    let (Ok(from), Ok(to)) = (
        CString::new(from.as_os_str().as_bytes()),
        CString::new(to.as_os_str().as_bytes()),
    ) else {
        return false;
    };
    unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            from.as_ptr(),
            libc::AT_FDCWD,
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        ) == 0
    }
}

fn file_tag(f: &std::fs::File) -> Option<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let mut b = [0u8; 64];
    let n = unsafe {
        libc::fgetxattr(
            f.as_raw_fd(),
            TAG.as_ptr().cast(),
            b.as_mut_ptr().cast(),
            b.len(),
        )
    };
    (n >= 0).then(|| b[..n as usize].to_vec())
}

fn available_bytes(path: &Path) -> Option<u64> {
    let mut p = path.parent().unwrap_or(Path::new("/")).to_path_buf();
    while !p.exists() {
        p = p.parent()?.to_path_buf();
    }
    let c = CString::new(p.as_os_str().as_bytes()).ok()?;
    let mut v = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    if unsafe { libc::statvfs(c.as_ptr(), v.as_mut_ptr()) } != 0 {
        return None;
    }
    let v = unsafe { v.assume_init() };
    Some((v.f_bavail as u64).saturating_mul(v.f_frsize as u64))
}

fn random_token() -> std::io::Result<[u8; 16]> {
    let mut t = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut t)?;
    Ok(t)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn mark_faulted(state: &mut State) {
    state.faulted = true;
    eprintln!(
        "[yrld] disk reservation ledger faulted: admission disabled until recovery"
    );
}

fn ledger_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn acquire_ownership(path: &Path) -> anyhow::Result<std::fs::File> {
    use std::os::fd::AsRawFd;

    std::fs::create_dir_all(ledger_parent(path))?;

    let mut name = path.as_os_str().to_os_string();
    name.push(".lock");

    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(
            libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
        )
        .open(PathBuf::from(name))?;

    let meta = lock.metadata()?;

    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
    {
        anyhow::bail!("unsafe disk reservation ledger lock");
    }

    loop {
        let rc = unsafe {
            libc::flock(
                lock.as_raw_fd(),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        };

        if rc == 0 {
            return Ok(lock);
        }

        let error = std::io::Error::last_os_error();

        if error.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }

        if error.kind() == std::io::ErrorKind::WouldBlock {
            anyhow::bail!("disk reservation ledger already owned");
        }

        return Err(error.into());
    }
}

fn read_ledger(path: &Path) -> anyhow::Result<HashMap<[u8; 16], Record>> {
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(
            libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK
        )
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(e.into()),
    };
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.nlink() != 1
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
    {
        anyhow::bail!("unsafe disk reservation ledger");
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let mut out = HashMap::new();
    for line in text.lines() {
        let f: Vec<_> = line.split(' ').collect();
        if f.len() != 7 {
            anyhow::bail!("damaged disk reservation ledger")
        }
        let token: [u8; 16] = hex::decode(f[0])?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad reservation token"))?;
        let account = String::from_utf8(hex::decode(f[2])?)?;
        let r = Record {
            token,
            key: hex::decode(f[1])?,
            account,
            uid: f[3].parse()?,
            size: f[4].parse()?,
            touched: f[5].parse()?,
            path: hex::decode(f[6])?,
        };
        if out.insert(token, r).is_some() {
            anyhow::bail!("duplicate disk reservation")
        }
    }
    Ok(out)
}

fn persist(
    path: &Path,
    records: &HashMap<[u8; 16], Record>,
) -> anyhow::Result<()> {
    let parent = ledger_parent(path);
    std::fs::create_dir_all(parent)?;

    let tmp = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        hex::encode(random_token()?)
    ));

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)?;

    let result = (|| -> anyhow::Result<()> {
        let mut rows: Vec<_> = records.values().collect();
        rows.sort_by_key(|r| r.token);

        for r in rows {
            writeln!(
                f,
                "{} {} {} {} {} {} {}",
                hex::encode(r.token),
                hex::encode(&r.key),
                hex::encode(r.account.as_bytes()),
                r.uid,
                r.size,
                r.touched,
                hex::encode(&r.path)
            )?;
        }

        f.sync_all()?;
        std::fs::rename(&tmp, path)?;

        // Atomic publication is not durable publication.
        sync_directory(parent)?;

        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }

    result
}

// REV-004: fault injection is available only in unit tests.
#[cfg(test)]
std::thread_local! {
    static FAIL_DIRECTORY_SYNC: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_DIRECTORY_SYNC.with(|flag| flag.replace(false)) {
        return Err(
            std::io::Error::from_raw_os_error(libc::EIO)
        );
    }

    std::fs::File::open(path)?.sync_all()
}

use std::os::unix::fs::OpenOptionsExt;

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    fn fail_next_directory_sync() {
        FAIL_DIRECTORY_SYNC.with(|flag| flag.set(true));
    }

    #[test]
    fn rev004_new_reservation_requires_durable_ledger() {
        let d = tempfile::tempdir().unwrap();

        let m = Arc::new(
            DiskManager::open(
                d.path().join("ledger"),
                limits(),
            ).unwrap()
        );

        let t = target(d.path());

        fail_next_directory_sync();

        assert!(
            matches!(
                m.reserve(
                    b"key", "alice", &t, b"one", 60
                ),
                Err(Refusal::State)
            ),
            "reservation granted despite directory sync failure"
        );
    }

    #[test]
    fn rev004_failed_release_cannot_enable_new_admission() {
        let d = tempfile::tempdir().unwrap();

        let m = Arc::new(
            DiskManager::open(
                d.path().join("ledger"),
                limits(),
            ).unwrap()
        );

        let t = target(d.path());

        let reservation = m.reserve(
            b"key-a", "alice", &t, b"one", 60
        ).unwrap();

        fail_next_directory_sync();

        reservation.complete();

        assert!(
            matches!(
                m.reserve(
                    b"key-b", "bob", &t, b"two", 70
                ),
                Err(Refusal::State)
            ),
            "new upload admitted after uncertain ledger release"
        );
    }

    #[test]
    fn rev004_resume_requires_durable_ledger() {
        let d = tempfile::tempdir().unwrap();

        let m = Arc::new(
            DiskManager::open(
                d.path().join("ledger"),
                limits(),
            ).unwrap()
        );

        let t = target(d.path());

        let reservation = m.reserve(
            b"key", "alice", &t, b"one", 60
        ).unwrap();

        reservation.preserve();

        fail_next_directory_sync();

        assert!(
            matches!(
                m.reserve(
                    b"key", "alice", &t, b"one", 60
                ),
                Err(Refusal::State)
            ),
            "resume granted despite directory sync failure"
        );
    }

    #[test]
    fn rev004_rejects_second_ledger_owner() {
        let d = tempfile::tempdir().unwrap();
        let ledger = d.path().join("ledger");

        let m = Arc::new(
            DiskManager::open(
                ledger.clone(), limits()
            ).unwrap()
        );

        let t = target(d.path());

        let reservation = m.reserve(
            b"key-a", "alice", &t, b"one", 60
        ).unwrap();

        assert!(
            DiskManager::open(
                ledger, limits()
            ).is_err(),
            "second independent ledger owner was admitted"
        );

        drop(reservation);
    }

    fn target(home: &Path) -> Target {
        Target {
            pw: crate::identity::Pw {
                name: "test".into(),
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
                home: home.display().to_string(),
                shell: String::new(),
            },
            switch: false,
        }
    }

    fn limits() -> DiskLimits {
        DiskLimits {
            bytes_total: 100,
            bytes_per_key: 70,
            bytes_per_account: 80,
            free_space_reserve: 0,
            partial_ttl: Duration::from_secs(3600),
        }
    }

    #[test]
    fn reservations_are_atomic_across_global_key_and_account_budgets_and_release_once() {
        let d = tempfile::tempdir().unwrap();
        let m = Arc::new(DiskManager::open(d.path().join("ledger"), limits()).unwrap());
        let t = target(d.path());
        let a = m.reserve(b"key-a", "alice", &t, b"one", 60).unwrap();
        assert!(matches!(
            m.reserve(b"key-a", "bob", &t, b"two", 11),
            Err(Refusal::Quota)
        ));
        assert!(matches!(
            m.reserve(b"key-b", "alice", &t, b"two", 21),
            Err(Refusal::Quota)
        ));
        assert!(matches!(
            m.reserve(b"key-b", "bob", &t, b"one", 60),
            Err(Refusal::Busy)
        ));
        drop(a);
        let b = m.reserve(b"key-b", "bob", &t, b"two", 70).unwrap();
        drop(b); // a second release is impossible because Reservation is consumed/dropped once
    }

    #[test]
    fn parallel_reservations_cannot_both_spend_the_same_global_bytes() {
        let d = tempfile::tempdir().unwrap();
        let mut l = limits();
        l.bytes_total = 70;
        l.bytes_per_account = 70;
        let m = Arc::new(DiskManager::open(d.path().join("ledger"), l).unwrap());
        let t = target(d.path());
        let start = Arc::new(std::sync::Barrier::new(3));
        let release = Arc::new(std::sync::Barrier::new(2));
        let (tx, rx) = std::sync::mpsc::channel();
        let mut threads = Vec::new();
        for (key, account, path) in [
            (b"key-a".as_slice(), "alice", b"one".as_slice()),
            (b"key-b".as_slice(), "bob", b"two".as_slice()),
        ] {
            let (m, t, start, release, tx) = (
                m.clone(),
                t.clone(),
                start.clone(),
                release.clone(),
                tx.clone(),
            );
            let (key, account, path) = (key.to_vec(), account.to_string(), path.to_vec());
            threads.push(std::thread::spawn(move || {
                start.wait();
                let reservation = m.reserve(&key, &account, &t, &path, 60).ok();
                tx.send(reservation.is_some()).unwrap();
                if reservation.is_some() {
                    release.wait();
                }
            }));
        }
        start.wait();
        assert_eq!(
            [rx.recv().unwrap(), rx.recv().unwrap()]
                .into_iter()
                .filter(|ok| *ok)
                .count(),
            1
        );
        release.wait();
        for thread in threads {
            thread.join().unwrap();
        }
    }

    #[test]
    fn ledger_survives_restart_and_exact_owner_can_resume_without_double_charge() {
        let d = tempfile::tempdir().unwrap();
        let ledger = d.path().join("ledger");
        let t = target(d.path());
        let m = Arc::new(DiskManager::open(ledger.clone(), limits()).unwrap());
        let a = m.reserve(b"key-a", "alice", &t, b"one", 60).unwrap();
        let mut a = a;
        a.finished = true;
        drop(a); // suppress reservation cleanup
        drop(m);
        let m = Arc::new(DiskManager::open(ledger, limits()).unwrap());
        assert!(matches!(
            m.reserve(b"key-b", "bob", &t, b"two", 50),
            Err(Refusal::Quota)
        ));
        let resumed = m.reserve(b"key-a", "alice", &t, b"one", 60).unwrap();
        resumed.complete();
        assert!(m.reserve(b"key-b", "bob", &t, b"two", 70).is_ok());
    }

    #[test]
    fn free_space_floor_refuses_before_a_partial_is_opened() {
        let d = tempfile::tempdir().unwrap();
        let mut l = limits();
        l.free_space_reserve = u64::MAX;
        let m = Arc::new(DiskManager::open(d.path().join("ledger"), l).unwrap());
        assert!(matches!(
            m.reserve(b"key", "alice", &target(d.path()), b"file", 1),
            Err(Refusal::NoSpace)
        ));
        assert!(!d.path().join("file.yrl-part").exists());
    }

    #[test]
    fn cancellation_removes_only_the_matching_tagged_single_link_partial() {
        let d = tempfile::tempdir().unwrap();
        let m = Arc::new(DiskManager::open(d.path().join("ledger"), limits()).unwrap());
        let r = m
            .reserve(b"key", "alice", &target(d.path()), b"file", 10)
            .unwrap();
        let p = d.path().join("file.yrl-part");
        let f = std::fs::File::create(&p).unwrap();
        let token = hex::decode(r.token_hex()).unwrap();
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    f.as_raw_fd(),
                    TAG.as_ptr().cast(),
                    token.as_ptr().cast(),
                    token.len(),
                    0,
                )
            },
            0
        );
        drop(f);
        drop(r);
        assert!(!p.exists());

        let r = m
            .reserve(b"key", "alice", &target(d.path()), b"file", 10)
            .unwrap();
        std::fs::write(&p, b"user data").unwrap(); // no reservation tag
        drop(r);
        assert_eq!(std::fs::read(p).unwrap(), b"user data");
    }

    #[test]
    fn ttl_cleanup_skips_active_reservations() {
        let d = tempfile::tempdir().unwrap();
        let mut l = limits();
        l.partial_ttl = Duration::from_secs(1);
        let m = Arc::new(DiskManager::open(d.path().join("ledger"), l).unwrap());
        let r = m
            .reserve(b"key", "alice", &target(d.path()), b"file", 10)
            .unwrap();
        {
            let mut s = m.state.lock().unwrap();
            s.records.get_mut(&r.token).unwrap().touched = 0;
        }
        m.expire().unwrap();
        assert!(m.state.lock().unwrap().records.contains_key(&r.token));
        drop(r);
    }

    #[test]
    fn restart_removes_an_expired_tagged_partial_and_its_charge() {
        let d = tempfile::tempdir().unwrap();
        let ledger = d.path().join("ledger");
        let mut l = limits();
        l.partial_ttl = Duration::from_secs(1);
        let m = Arc::new(DiskManager::open(ledger.clone(), l.clone()).unwrap());
        let r = m
            .reserve(b"key", "alice", &target(d.path()), b"file", 60)
            .unwrap();
        let p = d.path().join("file.yrl-part");
        let f = std::fs::File::create(&p).unwrap();
        let token = hex::decode(r.token_hex()).unwrap();
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    f.as_raw_fd(),
                    TAG.as_ptr().cast(),
                    token.as_ptr().cast(),
                    token.len(),
                    0,
                )
            },
            0
        );
        drop(f);
        {
            let mut s = m.state.lock().unwrap();
            s.records.get_mut(&r.token).unwrap().touched = 0;
            persist(&ledger, &s.records).unwrap();
        }
        let mut r = r;
        r.finished = true;
        drop(r); // suppress reservation cleanup
        drop(m); // restart loses only the active marker
        let m = Arc::new(DiskManager::open(ledger, l).unwrap());
        assert!(!p.exists());
        assert!(m
            .reserve(b"key", "alice", &target(d.path()), b"next", 70)
            .is_ok());
    }
}

#[cfg(test)]
mod rev004_extended_tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn limits() -> DiskLimits {
        DiskLimits {
            bytes_total: 100,
            bytes_per_key: 100,
            bytes_per_account: 100,
            free_space_reserve: 0,
            partial_ttl: Duration::from_secs(3600),
        }
    }

    fn target(home: &Path) -> Target {
        Target {
            pw: crate::identity::Pw {
                name: "test".into(),
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
                home: home.display().to_string(),
                shell: String::new(),
            },
            switch: false,
        }
    }

    fn fail_sync() {
        FAIL_DIRECTORY_SYNC.with(|flag| flag.set(true));
    }

    fn charge(m: &DiskManager) -> u64 {
        m.state.lock().unwrap().records.values()
            .map(|record| record.size)
            .sum()
    }

    #[test]
    fn failed_admission_retains_conservative_charge() {
        let d = tempfile::tempdir().unwrap();

        let m = Arc::new(
            DiskManager::open(
                d.path().join("ledger"), limits()
            ).unwrap()
        );

        fail_sync();

        assert!(matches!(
            m.reserve(
                b"key", "alice", &target(d.path()), b"one", 60
            ),
            Err(Refusal::State)
        ));

        assert_eq!(charge(&m), 60);

        let state = m.state.lock().unwrap();
        assert!(state.faulted);
        assert!(state.active.is_empty());
    }

    #[test]
    fn failed_completion_retains_conservative_charge() {
        let d = tempfile::tempdir().unwrap();

        let m = Arc::new(
            DiskManager::open(
                d.path().join("ledger"), limits()
            ).unwrap()
        );

        let r = m.reserve(
            b"key", "alice", &target(d.path()), b"one", 60
        ).unwrap();

        fail_sync();
        r.complete();

        assert_eq!(charge(&m), 60);
        assert!(m.state.lock().unwrap().faulted);
    }

    #[test]
    fn failed_touch_faults_manager_and_preserves_partial() {
        let d = tempfile::tempdir().unwrap();
        let ledger = d.path().join("ledger");
        let partial = d.path().join("one.yrl-part");

        let m = Arc::new(
            DiskManager::open(ledger.clone(), limits()).unwrap()
        );

        let t = target(d.path());

        let r = m.reserve(
            b"key", "alice", &t, b"one", 60
        ).unwrap();

        let original_token = r.token_hex();

        std::fs::write(&partial, b"persistent partial")
            .unwrap();

        let file = std::fs::File::open(&partial).unwrap();
        let token = hex::decode(&original_token).unwrap();

        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    file.as_raw_fd(),
                    TAG.as_ptr().cast(),
                    token.as_ptr().cast(),
                    token.len(),
                    0,
                )
            },
            0
        );

        drop(file);

        // Force a persistent activity update without waiting.
        {
            let mut state = m.state.lock().unwrap();
            state.records.get_mut(&r.token)
                .unwrap().touched = 0;
        }

        fail_sync();
        r.touch();

        assert!(m.state.lock().unwrap().faulted);

        assert!(matches!(
            m.reserve(b"other", "bob", &t, b"two", 1),
            Err(Refusal::State)
        ));

        assert!(m.expire().is_err());

        // Drop must not delete the partial while faulted.
        drop(r);

        assert_eq!(
            std::fs::read(&partial).unwrap(),
            b"persistent partial"
        );

        assert_eq!(charge(&m), 60);
        drop(m);

        // Recovery must preserve the original reservation.
        let recovered = Arc::new(
            DiskManager::open(ledger, limits()).unwrap()
        );

        assert_eq!(charge(&recovered), 60);

        assert!(matches!(
            recovered.reserve(
                b"other", "bob", &t, b"two", 41
            ),
            Err(Refusal::Quota)
        ));

        let resumed = recovered.reserve(
            b"key", "alice", &t, b"one", 60
        ).unwrap();

        assert_eq!(resumed.token_hex(), original_token);
        assert_eq!(charge(&recovered), 60);

        resumed.preserve();
    }

    #[test]
    fn reservation_retains_exclusive_ownership() {
        let d = tempfile::tempdir().unwrap();
        let ledger = d.path().join("ledger");

        let m = Arc::new(
            DiskManager::open(ledger.clone(), limits()).unwrap()
        );

        let r = m.reserve(
            b"key", "alice", &target(d.path()), b"one", 60
        ).unwrap();

        drop(m);

        assert!(
            DiskManager::open(
                ledger.clone(), limits()
            ).is_err()
        );

        r.preserve();

        let reopened = DiskManager::open(
            ledger, limits()
        ).unwrap();

        assert_eq!(charge(&reopened), 60);
    }

    #[test]
    fn refuses_symlink_ledger_lock() {
        let d = tempfile::tempdir().unwrap();
        let victim = d.path().join("victim");
        let ledger = d.path().join("ledger");

        std::fs::write(&victim, b"unchanged").unwrap();

        symlink(
            &victim,
            d.path().join("ledger.lock")
        ).unwrap();

        assert!(
            DiskManager::open(ledger.clone(), limits())
                .is_err()
        );

        assert_eq!(
            std::fs::read(victim).unwrap(),
            b"unchanged"
        );

        assert!(!ledger.exists());
    }

    #[test]
    fn refuses_public_ledger_lock() {
        let d = tempfile::tempdir().unwrap();
        let lock = d.path().join("ledger.lock");

        std::fs::write(&lock, b"").unwrap();

        std::fs::set_permissions(
            &lock,
            std::fs::Permissions::from_mode(0o666)
        ).unwrap();

        assert!(
            DiskManager::open(
                d.path().join("ledger"), limits()
            ).is_err()
        );
    }

    #[test]
    fn failed_publication_removes_temporary_file() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("ledger");

        std::fs::create_dir(&path).unwrap();

        assert!(persist(&path, &HashMap::new()).is_err());

        assert_eq!(
            std::fs::read_dir(d.path()).unwrap().count(),
            1
        );

        assert!(path.is_dir());
    }
}
