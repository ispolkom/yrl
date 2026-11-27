//! Bounded persistent states for operations accepted by Executor.
//!
//! The journal is an anti-replay and recovery-status mechanism, not a command queue. Entries that
//! were accepted/running when the process died become UNKNOWN on open and are never run again.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_records: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_records: 100_000,
        }
    }
}

impl Limits {
    pub fn from_env() -> anyhow::Result<Self> {
        let d = Self::default();
        let max_records = std::env::var("YRL_OPERATION_RECORDS")
            .map(|v| v.parse())
            .unwrap_or(Ok(d.max_records))?;
        let limits = Limits { max_records };
        if limits.max_records == 0 {
            anyhow::bail!("operation journal limit must be non-zero")
        }
        Ok(limits)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    Accepted = 1,
    Running = 2,
    Completed = 3,
    Failed = 4,
    Unknown = 5,
    Acknowledged = 6,
}

pub const KIND_EXEC: u8 = 1;
pub const KIND_SUDO: u8 = 2;
pub const KIND_ROOT: u8 = 3;

impl State {
    fn parse(n: u8) -> Option<Self> {
        Some(match n {
            1 => Self::Accepted,
            2 => Self::Running,
            3 => Self::Completed,
            4 => Self::Failed,
            5 => Self::Unknown,
            6 => Self::Acknowledged,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub id: u64,
    pub kind: u8,
    pub state: State,
    pub updated: u64,
    pub result: Option<i32>,
}

#[derive(Clone)]
struct Record {
    key: Vec<u8>,
    account: String,
    id: u64,
    kind: u8,
    digest: [u8; 32],
    state: State,
    updated: u64,
    result: Option<i32>,
}

type RecordKey = (Vec<u8>, String, u64);

pub struct Journal {
    path: PathBuf,
    limits: Limits,
    records: Mutex<HashMap<RecordKey, Record>>,
    // Once persistence becomes uncertain, no operation may be
    // admitted or dispatched until the journal is reopened.
    faulted: AtomicBool,
    // Keep exclusive ownership for the lifetime of the journal.
    _ownership: std::fs::File,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Duplicate(Status),
    Conflict,
    Full,
    State,
}

pub struct Guard {
    journal: Arc<Journal>,
    key: RecordKey,
    done: bool,
}

impl Journal {
    pub fn open(path: PathBuf, limits: Limits) -> anyhow::Result<Self> {
        let ownership = acquire_ownership(&path)?;
        let mut records = read(&path)?;
        let now = now();
        for r in records.values_mut() {
            if matches!(r.state, State::Accepted | State::Running) {
                r.state = State::Unknown;
                r.updated = now;
                r.result = None;
            }
        }
        if records.len() > limits.max_records {
            anyhow::bail!("operation journal exceeds configured bound")
        }
        let journal = Journal {
            path,
            limits,
            records: Mutex::new(records),
            faulted: AtomicBool::new(false),
            _ownership: ownership,
        };
        journal.persist()?;
        Ok(journal)
    }

    pub fn accept(
        self: &Arc<Self>,
        key: &[u8],
        account: &str,
        id: u64,
        kind: u8,
        payload: &[u8],
    ) -> Result<Guard, Refusal> {
        if id == 0 {
            return Err(Refusal::Conflict);
        }
        let rk = (key.to_vec(), account.to_string(), id);
        let digest = *blake3::hash(payload).as_bytes();
        let mut records = self.records.lock().unwrap();

        if self.faulted.load(Ordering::SeqCst) {
            return Err(Refusal::State);
        }

        if let Some(r) = records.get(&rk) {
            let status = Status {
                id,
                kind: r.kind,
                state: r.state,
                updated: r.updated,
                result: r.result,
            };
            return if r.kind == kind && r.digest == digest {
                Err(Refusal::Duplicate(status))
            } else {
                Err(Refusal::Conflict)
            };
        }
        if records.len() >= self.limits.max_records {
            return Err(Refusal::Full);
        }
        records.insert(
            rk.clone(),
            Record {
                key: key.to_vec(),
                account: account.to_string(),
                id,
                kind,
                digest,
                state: State::Accepted,
                updated: now(),
                result: None,
            },
        );
        if persist(&self.path, &records).is_err() {
            // Publication may already have happened. Never remove
            // the replay record or continue admitting operations.
            if let Some(r) = records.get_mut(&rk) {
                r.state = State::Unknown;
                r.result = None;
            }
            self.faulted.store(true, Ordering::SeqCst);
            eprintln!("[yrld] operation journal faulted: admission persistence failed");
            return Err(Refusal::State);
        }
        Ok(Guard {
            journal: self.clone(),
            key: rk,
            done: false,
        })
    }

    pub fn status(&self, key: &[u8], account: &str, id: u64) -> Option<Status> {
        let records = self.records.lock().unwrap();

        if self.faulted.load(Ordering::SeqCst) {
            return None;
        }

        let r = records.get(&(key.to_vec(), account.to_string(), id))?;
        Some(Status {
            id,
            kind: r.kind,
            state: r.state,
            updated: r.updated,
            result: r.result,
        })
    }

    fn set(&self, key: &RecordKey, state: State, result: Option<i32>) -> bool {
        let mut records = self.records.lock().unwrap();

        if self.faulted.load(Ordering::SeqCst) {
            return false;
        }

        let Some(r) = records.get_mut(key) else {
            return false;
        };
        r.state = state;
        r.updated = now();
        r.result = result;
        if persist(&self.path, &records).is_err() {
            // The persistent state is uncertain. Do not claim
            // rollback or attempt another state publication.
            let r = records.get_mut(key).unwrap();
            r.state = State::Unknown;
            r.result = None;
            self.faulted.store(true, Ordering::SeqCst);
            eprintln!("[yrld] operation journal faulted: transition persistence failed");
            return false;
        }
        true
    }

    fn persist(&self) -> anyhow::Result<()> {
        persist(&self.path, &self.records.lock().unwrap())
    }

    /// Acknowledgement compacts the terminal result into a replay tombstone. The key/account/id
    /// remains forever within the bounded file; at capacity admission fails closed rather than
    /// deleting an id and making it executable again.
    pub fn acknowledge(&self, key: &[u8], account: &str, id: u64) -> bool {
        let rk = (key.to_vec(), account.to_string(), id);
        let terminal = self.records.lock().unwrap().get(&rk).is_some_and(|r| {
            matches!(
                r.state,
                State::Completed | State::Failed | State::Unknown | State::Acknowledged
            )
        });
        terminal && self.set(&rk, State::Acknowledged, None)
    }
}

impl Guard {
    /// Must succeed before the operation is dispatched. A failed state write means "do not run".
    pub fn running(&self) -> bool {
        self.journal.set(&self.key, State::Running, None)
    }
    pub fn finish(mut self, state: State, result: Option<i32>) -> bool {
        let ok = self.journal.set(&self.key, state, result);
        if !ok {
            let _ = self.journal.set(&self.key, State::Unknown, None);
        }
        self.done = true;
        ok
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if !self.done {
            let _ = self.journal.set(&self.key, State::Unknown, None);
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn journal_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn acquire_ownership(path: &Path) -> anyhow::Result<std::fs::File> {
    std::fs::create_dir_all(journal_parent(path))?;

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
        anyhow::bail!("unsafe operation journal lock");
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
            anyhow::bail!("operation journal already owned");
        }

        return Err(error.into());
    }
}

fn read(path: &Path) -> anyhow::Result<HashMap<RecordKey, Record>> {
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
    let m = file.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
    {
        anyhow::bail!("unsafe operation journal")
    }
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    let mut records = HashMap::new();
    for line in text.lines() {
        let f: Vec<_> = line.split(' ').collect();
        if !matches!(f.len(), 7 | 8) {
            anyhow::bail!("damaged operation journal")
        }
        let key = hex::decode(f[0])?;
        let account = String::from_utf8(hex::decode(f[1])?)?;
        let id = f[2].parse()?;
        let kind = f[3].parse()?;
        let digest = hex::decode(f[4])?
            .try_into()
            .map_err(|_| anyhow::anyhow!("bad operation digest"))?;
        let state =
            State::parse(f[5].parse()?).ok_or_else(|| anyhow::anyhow!("bad operation state"))?;
        let updated = f[6].parse()?;
        let result = match f.get(7) {
            None | Some(&"-") => None,
            Some(v) => Some(v.parse()?),
        };
        let r = Record {
            key: key.clone(),
            account: account.clone(),
            id,
            kind,
            digest,
            state,
            updated,
            result,
        };
        if records.insert((key, account, id), r).is_some() {
            anyhow::bail!("duplicate operation record")
        }
    }
    Ok(records)
}

fn persist(
    path: &Path,
    records: &HashMap<RecordKey, Record>,
) -> anyhow::Result<()> {
    let parent = journal_parent(path);
    std::fs::create_dir_all(parent)?;

    let random = hex::encode(crate::keys::generate().public);
    let tmp = path.with_extension(
        format!("tmp-{}-{random}", std::process::id())
    );

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)?;

    let result = (|| -> anyhow::Result<()> {
        let mut rows: Vec<_> = records.values().collect();

        rows.sort_by(|a, b| {
            (&a.key, &a.account, a.id)
                .cmp(&(&b.key, &b.account, b.id))
        });

        for r in rows {
            writeln!(
                f,
                "{} {} {} {} {} {} {} {}",
                hex::encode(&r.key),
                hex::encode(r.account.as_bytes()),
                r.id,
                r.kind,
                hex::encode(r.digest),
                r.state as u8,
                r.updated,
                r.result
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "-".into())
            )?;
        }

        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        sync_directory(parent)?;
        Ok(())
    })();

    // Only remove the temporary file created by this invocation.
    // After a successful rename this path no longer exists.
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }

    result
}

// Fault injection exists only in the unit-test build.
#[cfg(test)]
std::thread_local! {
    static FAIL_DIRECTORY_SYNC: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    if FAIL_DIRECTORY_SYNC.with(|flag| flag.replace(false)) {
        return Err(std::io::Error::from_raw_os_error(libc::EIO));
    }

    std::fs::File::open(path)?.sync_all()
}

pub fn encode_status(s: &Status) -> Vec<u8> {
    let mut p = s.id.to_be_bytes().to_vec();
    p.push(s.kind);
    p.push(s.state as u8);
    p.extend_from_slice(&s.updated.to_be_bytes());
    match s.result {
        Some(n) => {
            p.push(1);
            p.extend_from_slice(&n.to_be_bytes());
        }
        None => p.push(0),
    }
    p
}

pub fn decode_status(p: &[u8]) -> Option<Status> {
    if !matches!(p.len(), 19 | 23) || (p[18] == 0 && p.len() != 19) || (p[18] == 1 && p.len() != 23)
    {
        return None;
    }
    let result = if p[18] == 1 {
        Some(i32::from_be_bytes(p[19..23].try_into().ok()?))
    } else {
        None
    };
    Some(Status {
        id: u64::from_be_bytes(p[..8].try_into().ok()?),
        kind: p[8],
        state: State::parse(p[9])?,
        updated: u64::from_be_bytes(p[10..18].try_into().ok()?),
        result,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fail_next_directory_sync() {
        FAIL_DIRECTORY_SYNC.with(|flag| flag.set(true));
    }

    fn test_journal(path: PathBuf) -> Arc<Journal> {
        Arc::new(
            Journal::open(path, Limits { max_records: 16 })
                .unwrap()
        )
    }


    #[test]
    fn rev003_fault_blocks_all_further_admission() {
        let d = tempfile::tempdir().unwrap();
        let j = test_journal(d.path().join("operations"));

        fail_next_directory_sync();

        assert!(matches!(
            j.accept(b"key", "account", 201, KIND_EXEC, b"cmd"),
            Err(Refusal::State)
        ));

        // Even a different operation must not be admitted.
        assert!(matches!(
            j.accept(b"key", "account", 202, KIND_EXEC, b"next"),
            Err(Refusal::State)
        ));

        // A fault must not expose an unconfirmed result.
        assert!(j.status(b"key", "account", 201).is_none());

        assert!(!j.acknowledge(b"key", "account", 201));
    }

    #[test]
    fn rev003_fault_blocks_existing_guard_dispatch() {
        let d = tempfile::tempdir().unwrap();
        let j = test_journal(d.path().join("operations"));

        let g = j.accept(
            b"key", "account", 203, KIND_EXEC, b"cmd"
        ).unwrap();

        fail_next_directory_sync();

        assert!(matches!(
            j.accept(b"key", "account", 204, KIND_EXEC, b"other"),
            Err(Refusal::State)
        ));

        assert!(!g.running());
    }

    #[test]
    fn rev003_reopen_preserves_replay_protection() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("operations");

        {
            let j = test_journal(path.clone());

            let g = j.accept(
                b"key", "account", 205, KIND_EXEC, b"cmd"
            ).unwrap();

            fail_next_directory_sync();

            assert!(!g.running());
            drop(g);
        }

        let reopened = test_journal(path);

        assert_eq!(
            reopened.status(b"key", "account", 205)
                .unwrap().state,
            State::Unknown
        );

        assert!(matches!(
            reopened.accept(
                b"key", "account", 205, KIND_EXEC, b"cmd"
            ),
            Err(Refusal::Duplicate(_))
        ));

        // Successful recovery permits unrelated operations.
        let g = reopened.accept(
            b"key", "account", 206, KIND_EXEC, b"new"
        ).unwrap();

        assert!(g.running());
        assert!(g.finish(State::Completed, Some(0)));
    }


    #[test]
    fn rev003_exclusive_journal_ownership() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("operations");

        let j = test_journal(path.clone());

        let g = j.accept(
            b"key", "account", 301, KIND_EXEC, b"cmd"
        ).unwrap();

        assert!(g.running());

        assert!(
            Journal::open(
                path.clone(),
                Limits { max_records: 16 },
            ).is_err(),
            "second journal owner was admitted"
        );

        assert!(g.finish(State::Completed, Some(0)));

        drop(j);

        let reopened = test_journal(path);

        assert_eq!(
            reopened.status(b"key", "account", 301)
                .unwrap().state,
            State::Completed
        );

        assert!(matches!(
            reopened.accept(
                b"key", "account", 301, KIND_EXEC, b"cmd"
            ),
            Err(Refusal::Duplicate(_))
        ));
    }

    #[test]
    fn rev003_guard_retains_journal_ownership() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("operations");

        let j = test_journal(path.clone());

        let g = j.accept(
            b"key", "account", 302, KIND_EXEC, b"cmd"
        ).unwrap();

        drop(j);

        assert!(
            Journal::open(
                path.clone(),
                Limits { max_records: 16 },
            ).is_err()
        );

        drop(g);

        let reopened = test_journal(path);

        assert_eq!(
            reopened.status(b"key", "account", 302)
                .unwrap().state,
            State::Unknown
        );
    }

    #[test]
    fn rev003_refuses_symlink_lock() {
        use std::os::unix::fs::symlink;

        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("operations");
        let victim = d.path().join("victim");

        std::fs::write(&victim, b"unchanged").unwrap();

        symlink(
            &victim,
            d.path().join("operations.lock"),
        ).unwrap();

        assert!(
            Journal::open(
                path.clone(),
                Limits { max_records: 16 },
            ).is_err()
        );

        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"unchanged"
        );

        assert!(!path.exists());
    }

    #[test]
    fn rev003_refuses_public_lock() {
        use std::os::unix::fs::PermissionsExt;

        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("operations");
        let lock = d.path().join("operations.lock");

        std::fs::write(&lock, b"").unwrap();

        std::fs::set_permissions(
            &lock,
            std::fs::Permissions::from_mode(0o666),
        ).unwrap();

        assert!(
            Journal::open(
                path.clone(),
                Limits { max_records: 16 },
            ).is_err()
        );

        assert!(!path.exists());
    }

    #[test]
    fn rev003_failed_rename_removes_temporary_file() {
        let d = tempfile::tempdir().unwrap();

        let target = d.path().join("operations");

        // A regular temporary file cannot replace a directory.
        std::fs::create_dir(&target).unwrap();

        let records = HashMap::new();

        assert!(persist(&target, &records).is_err());
        assert!(target.is_dir());

        let entries: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();

        assert_eq!(
            entries,
            vec![std::ffi::OsString::from("operations")],
            "failed publication leaked a temporary file"
        );
    }

    #[test]
    fn rev003_accept_requires_durable_publication() {
        let d = tempfile::tempdir().unwrap();
        let j = test_journal(d.path().join("operations"));

        fail_next_directory_sync();

        assert!(
            matches!(
                j.accept(b"key", "account", 101, KIND_EXEC, b"cmd"),
                Err(Refusal::State)
            ),
            "accepted an operation after directory sync failed"
        );
    }

    #[test]
    fn rev003_running_requires_durable_publication() {
        let d = tempfile::tempdir().unwrap();
        let j = test_journal(d.path().join("operations"));

        let g = j.accept(
            b"key", "account", 102, KIND_EXEC, b"cmd"
        ).unwrap();

        fail_next_directory_sync();

        assert!(
            !g.running(),
            "allowed dispatch after directory sync failed"
        );
    }

    #[test]
    fn rev003_completion_requires_durable_publication() {
        let d = tempfile::tempdir().unwrap();
        let j = test_journal(d.path().join("operations"));

        let g = j.accept(
            b"key", "account", 103, KIND_EXEC, b"cmd"
        ).unwrap();

        assert!(g.running());

        fail_next_directory_sync();

        assert!(
            !g.finish(State::Completed, Some(0)),
            "reported completion after directory sync failed"
        );
    }

    #[test]
    fn rev003_ack_requires_durable_publication() {
        let d = tempfile::tempdir().unwrap();
        let j = test_journal(d.path().join("operations"));

        let g = j.accept(
            b"key", "account", 104, KIND_EXEC, b"cmd"
        ).unwrap();

        assert!(g.running());
        assert!(g.finish(State::Completed, Some(0)));

        fail_next_directory_sync();

        assert!(
            !j.acknowledge(b"key", "account", 104),
            "acknowledged result after directory sync failed"
        );
    }

    #[test]
    fn accepted_and_running_become_unknown_after_crash_and_never_reexecute() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("operations");
        let j = Arc::new(Journal::open(path.clone(), Limits { max_records: 4 }).unwrap());
        let g = j
            .accept(b"key", "account", 7, KIND_EXEC, b"command")
            .unwrap();
        assert!(g.running());
        let mut g = g;
        g.done = true;
        drop(g); // simulate death without a guard transition
        drop(j); // release journal ownership
        let j = Arc::new(Journal::open(path, Limits { max_records: 4 }).unwrap());
        assert_eq!(
            j.status(b"key", "account", 7).unwrap().state,
            State::Unknown
        );
        assert!(matches!(
            j.accept(b"key", "account", 7, KIND_EXEC, b"command"),
            Err(Refusal::Duplicate(_))
        ));
        assert!(matches!(
            j.accept(b"key", "account", 7, KIND_EXEC, b"different"),
            Err(Refusal::Conflict)
        ));
        assert!(j.status(b"other-key", "account", 7).is_none());
        assert!(j.status(b"key", "other-account", 7).is_none());
    }

    #[test]
    fn final_result_survives_until_ack_then_becomes_a_replay_tombstone() {
        let d = tempfile::tempdir().unwrap();
        let j = Arc::new(
            Journal::open(d.path().join("operations"), Limits { max_records: 1 }).unwrap(),
        );
        let g = j
            .accept(b"key", "account", 9, KIND_EXEC, b"command")
            .unwrap();
        assert!(g.running());
        assert!(g.finish(State::Completed, Some(23)));
        assert_eq!(j.status(b"key", "account", 9).unwrap().result, Some(23));
        assert!(j.acknowledge(b"key", "account", 9));
        let status = j.status(b"key", "account", 9).unwrap();
        assert_eq!((status.state, status.result), (State::Acknowledged, None));
        assert!(matches!(
            j.accept(b"key", "account", 9, KIND_EXEC, b"command"),
            Err(Refusal::Duplicate(_))
        ));
        assert!(
            matches!(
                j.accept(b"key", "account", 10, KIND_EXEC, b"next"),
                Err(Refusal::Full)
            ),
            "capacity fails closed instead of deleting replay protection"
        );
    }

    #[test]
    fn status_wire_preserves_unknown_and_terminal_result() {
        let s = Status {
            id: 42,
            kind: KIND_EXEC,
            state: State::Completed,
            updated: 99,
            result: Some(-7),
        };
        assert_eq!(decode_status(&encode_status(&s)), Some(s));
    }
}
