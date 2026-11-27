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
}

pub struct DiskManager {
    ledger: PathBuf,
    limits: DiskLimits,
    state: Mutex<State>,
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
        let records = read_ledger(&ledger)?;
        let manager = DiskManager {
            ledger,
            limits,
            state: Mutex::new(State {
                records,
                active: HashSet::new(),
            }),
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
            let old_touched = record.touched;
            record.touched = now;
            s.active.insert(token);
            if persist(&self.ledger, &s.records).is_err() {
                s.active.remove(&token);
                s.records.get_mut(&token).unwrap().touched = old_touched;
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
            s.records.remove(&token);
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
            return Err(e);
        }
        Ok(())
    }

    fn release(&self, token: [u8; 16], completed: bool) {
        let mut s = self.state.lock().unwrap();
        s.active.remove(&token);
        if let Some(r) = s.records.remove(&token) {
            if !completed {
                remove_tagged_partial(&r);
            }
            // A ledger write failure retains the charge in memory too. This is deliberately
            // fail-closed: storage trouble cannot turn cancellation into a quota bypass.
            if persist(&self.ledger, &s.records).is_err() {
                s.records.insert(token, r);
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
        let Some(r) = s.records.get_mut(&self.token) else {
            return;
        };
        if now.saturating_sub(r.touched) < 60 {
            return;
        }
        let old = r.touched;
        r.touched = now;
        if persist(&self.manager.ledger, &s.records).is_err() {
            if let Some(r) = s.records.get_mut(&self.token) {
                r.touched = old;
            }
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

fn read_ledger(path: &Path) -> anyhow::Result<HashMap<[u8; 16], Record>> {
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
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

fn persist(path: &Path, records: &HashMap<[u8; 16], Record>) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        hex::encode(random_token()?)
    ));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
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
    if let Some(parent) = path.parent() {
        // The atomic publication above is the commit point. Directory fsync improves crash
        // durability, but an exotic filesystem refusing it must not make callers roll back an
        // already-published ledger in memory and thereby create double accounting.
        let _ = std::fs::File::open(parent).and_then(|d| d.sync_all());
    }
    Ok(())
}

use std::os::unix::fs::OpenOptionsExt;

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

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
        std::mem::forget(a); // model a process crash: Drop did not run
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
        std::mem::forget(r);
        drop(m); // restart loses only the active marker
        let m = Arc::new(DiskManager::open(ledger, l).unwrap());
        assert!(!p.exists());
        assert!(m
            .reserve(b"key", "alice", &target(d.path()), b"next", 70)
            .is_ok());
    }
}
