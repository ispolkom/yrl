//! Bounded persistent states for operations accepted by Executor.
//!
//! The journal is an anti-replay and recovery-status mechanism, not a command queue. Entries that
//! were accepted/running when the process died become UNKNOWN on open and are never run again.
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
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
            records.remove(&rk);
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
        let Some(r) = records.get_mut(key) else {
            return false;
        };
        let (old_state, old_updated, old_result) = (r.state, r.updated, r.result);
        r.state = state;
        r.updated = now();
        r.result = result;
        if persist(&self.path, &records).is_err() {
            let r = records.get_mut(key).unwrap();
            r.state = old_state;
            r.updated = old_updated;
            r.result = old_result;
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

fn read(path: &Path) -> anyhow::Result<HashMap<RecordKey, Record>> {
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
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

fn persist(path: &Path, records: &HashMap<RecordKey, Record>) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let random = hex::encode(crate::keys::generate().public);
    let tmp = path.with_extension(format!("tmp-{}-{random}", std::process::id()));
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let mut rows: Vec<_> = records.values().collect();
    rows.sort_by(|a, b| (&a.key, &a.account, a.id).cmp(&(&b.key, &b.account, b.id)));
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
    if let Some(parent) = path.parent() {
        let _ = std::fs::File::open(parent).and_then(|d| d.sync_all());
    }
    Ok(())
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

    #[test]
    fn accepted_and_running_become_unknown_after_crash_and_never_reexecute() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("operations");
        let j = Arc::new(Journal::open(path.clone(), Limits { max_records: 4 }).unwrap());
        let g = j
            .accept(b"key", "account", 7, KIND_EXEC, b"command")
            .unwrap();
        assert!(g.running());
        std::mem::forget(g);
        drop(j); // process death: no RAII transition
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
