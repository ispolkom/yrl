//! The audit process: keeps the journals (see auditlog.rs). It listens on a local socket and nowhere else, does nothing but append, and holds the only copy of the signing key.
//! Gatekeeper, executor, broker and the owner's own programs each connect with their OWN key; the source written into a record is the one that key belongs to, and each
//! source may only report the operations it could actually have seen. A taken-over gatekeeper therefore cannot write in the name of the broker, and none of them can
//! change an old record: the only way into the files is this process's append.
use crate::auditlog::*;
use crate::ipc::{exe_of_pid, judge_peer, ExecutorIpc, PeerVerdict};
use crate::keys::{Authorized, KeyPair};
use crate::session::{client_handshake, read_msg, server_handshake, write_msg, Secure, REKEY_EVERY};
use crate::wire::Frame;
use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use std::collections::HashSet;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};

pub const AUDIT_EVENT: u8 = 90;
pub const AUDIT_ACK: u8 = 91;
pub const AUDIT_REJECT: u8 = 92;

struct J {
    path: PathBuf,
    head: PathBuf,
    prev: Hash,
    next: u64,
    since_cp: u64,
}

struct Inner {
    journals: [J; 2],
    seen: HashSet<(Source, Vec<u8>, u64, String)>,
    /// a failed write: the chain must not go on from a place nobody knows
    broken: bool,
}

pub struct AuditService {
    key: SigningKey,
    every: u64,
    inner: Mutex<Inner>,
    _lock: std::fs::File,
}

fn now() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

impl AuditService {
    /// Opens (or creates) the journals in `<dir>/audit`. A journal that does not verify - a changed record, a damaged tail, a bad signature, a log cut short - is NOT
    /// continued: the process refuses to start until the owner has looked at it and run `repair`.
    pub fn open(dir: &Path, every: u64) -> Result<Arc<AuditService>> {
        use std::os::unix::fs::PermissionsExt;
        let base = dir.join("audit");
        // The journals are for the owner (who reads them as root) and for nobody else: the part that faces the network must not be able to look at who logs in and when.
        // A directory that is already there is the installation's: its owner and mode are not touched. A new one is private.
        if !base.exists() {
            std::fs::create_dir_all(&base)?;
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))?;
        }
        // one audit process per directory
        let lock = std::fs::OpenOptions::new().create(true).write(true).truncate(false).mode(0o600).open(base.join("lock"))?;
        if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&lock), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            bail!("another audit process holds this journal");
        }
        let key_path = base.join("sign.key");
        let key = if key_path.exists() {
            let seed = crate::keys::read_secret_hex(&key_path, 32)?;
            SigningKey::from_bytes(seed.as_slice().try_into().map_err(|_| anyhow::anyhow!("damaged signing key"))?)
        } else {
            let k = SigningKey::generate(&mut argon2::password_hash::rand_core::OsRng);
            let mut f = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&key_path)?;
            f.write_all_hex(&k.to_bytes())?;
            f.sync_all()?;
            std::fs::write(base.join("sign.pub"), hex::encode(k.verifying_key().to_bytes()))?;
            std::fs::set_permissions(base.join("sign.pub"), std::fs::Permissions::from_mode(0o644))?;
            k
        };
        let vk = key.verifying_key();
        let mut journals = vec![];
        for j in [Journal::Ordinary, Journal::Security] {
            let path = base.join(format!("{}.log", j.file()));
            let head = base.join(format!("{}.head", j.file()));
            let bytes = std::fs::read(&path).unwrap_or_default();
            let headb = std::fs::read(&head).ok();
            let rep = verify(&bytes, j, &vk, headb.as_deref());
            if let Some(f) = rep.fault {
                bail!("the {} journal does not verify ({f:?}); it is not continued. Look at it, then run `yrld audit repair`", j.file());
            }
            let (prev, next) = rep.last.map(|(s, h)| (h, s + 1)).unwrap_or(([0u8; 32], 0));
            journals.push(J { path, head, prev, next, since_cp: rep.unsealed });
        }
        let [a, b]: [J; 2] = journals.try_into().ok().context("journals")?;
        let svc = Arc::new(AuditService { key, every: every.max(1), inner: Mutex::new(Inner { journals: [a, b], seen: HashSet::new(), broken: false }), _lock: lock });
        svc.append(Source::Audit, Event::new("start", LEVEL_NONE, RESULT_OK))?;
        Ok(svc)
    }

    pub fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
        self.key.verifying_key()
    }

    /// writes one event; returns its number. Errors are real: the caller decides what that means for what it was about to do.
    pub fn append(&self, src: Source, mut ev: Event) -> Result<u64> {
        if !src.may_report(&ev.op) {
            bail!("{} cannot report '{}'", src.name(), ev.op);
        }
        ev.user = ev.user.chars().filter(|c| !c.is_control()).take(64).collect();
        let journal = Journal::of(&ev.op);
        let mut g = self.inner.lock().unwrap();
        if g.broken {
            bail!("the journal could not be written earlier and is closed");
        }
        let mut flags = 0u8;
        if ev.request_id != 0 {
            if g.seen.len() > 200_000 {
                g.seen.clear();
            }
            if !g.seen.insert((src, ev.session.clone(), ev.request_id, ev.op.clone())) {
                flags |= FLAG_REPEAT;
            }
        }
        let idx = journal as usize;
        let rec = Record { kind: KIND_EVENT, journal, source: src, seq: g.journals[idx].next, time: now(), flags, ev, extra: vec![] };
        let (bytes, h) = frame(&rec, &g.journals[idx].prev)?;
        if append_file(&g.journals[idx].path, &bytes).is_err() {
            g.broken = true;
            bail!("cannot write the journal");
        }
        let seq = rec.seq;
        g.journals[idx].prev = h;
        g.journals[idx].next += 1;
        g.journals[idx].since_cp += 1;
        if g.journals[idx].since_cp >= self.every && self.checkpoint_locked(&mut g, journal).is_err() {
            g.broken = true;
            bail!("cannot write the checkpoint");
        }
        Ok(seq)
    }

    fn checkpoint_locked(&self, g: &mut Inner, journal: Journal) -> Result<()> {
        use ed25519_dalek::Signer;
        let idx = journal as usize;
        let j = &g.journals[idx];
        if j.next == 0 {
            return Ok(());
        }
        let (last_seq, last_hash) = (j.next - 1, j.prev);
        let sig = self.key.sign(&checkpoint_message(journal, last_seq, &last_hash));
        let rec = Record { kind: KIND_CHECKPOINT, journal, source: Source::Audit, seq: j.next, time: now(), flags: 0, ev: Event::new("checkpoint", LEVEL_NONE, RESULT_OK), extra: sig.to_bytes().to_vec() };
        let (bytes, h) = frame(&rec, &j.prev)?;
        append_file(&j.path, &bytes)?;
        let head = make_head(journal, rec.seq, &h, &self.key);
        let tmp = j.head.with_extension("tmp");
        std::fs::write(&tmp, head)?;
        std::fs::rename(&tmp, &j.head)?;
        let j = &mut g.journals[idx];
        j.prev = h;
        j.next += 1;
        j.since_cp = 0;
        Ok(())
    }

    /// seals everything written so far (on a clean stop, and for tests)
    pub fn seal(&self) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        for j in [Journal::Ordinary, Journal::Security] {
            if g.journals[j as usize].since_cp > 0 {
                self.checkpoint_locked(&mut g, j)?;
            }
        }
        Ok(())
    }
}

trait WriteHex {
    fn write_all_hex(&mut self, b: &[u8]) -> std::io::Result<()>;
}
impl WriteHex for std::fs::File {
    fn write_all_hex(&mut self, b: &[u8]) -> std::io::Result<()> {
        let text = zeroize::Zeroizing::new(hex::encode(b));
        std::io::Write::write_all(self, text.as_bytes())
    }
}

// ---------------------------------------------------------------- the local door

#[derive(Clone)]
pub struct AuditIpc {
    pub socket: PathBuf,
    pub key: KeyPair,
    /// which key is which part of the system
    pub sources: Vec<(Source, Vec<u8>)>,
    pub expected_uid: Option<u32>,
    pub expected_exe: Option<PathBuf>,
}

pub fn encode_event(ev: &Event) -> Result<Vec<u8>> {
    Record { kind: KIND_EVENT, journal: Journal::Ordinary, source: Source::Audit, seq: 0, time: 0, flags: 0, ev: ev.clone(), extra: vec![] }.canonical()
}

pub fn decode_event(b: &[u8]) -> Result<Event> {
    let r = Record::parse(b)?;
    if r.kind != KIND_EVENT || r.seq != 0 || r.time != 0 || r.flags != 0 || !r.extra.is_empty() {
        bail!("not a plain event");
    }
    Ok(r.ev)
}

pub async fn serve_ipc(listener: UnixListener, svc: Arc<AuditService>, ipc: AuditIpc, log: Arc<dyn Fn(String) + Send + Sync>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else { continue };
        let (svc, ipc, log) = (svc.clone(), ipc.clone(), log.clone());
        tokio::spawn(async move { handle(stream, svc, ipc, log).await });
    }
}

async fn handle(mut stream: UnixStream, svc: Arc<AuditService>, ipc: AuditIpc, log: Arc<dyn Fn(String) + Send + Sync>) {
    let Ok(cred) = stream.peer_cred() else { return };
    let as_exec = ExecutorIpc { socket: ipc.socket.clone(), key: ipc.key.clone(), gatekeeper_public: vec![], expected_uid: ipc.expected_uid, expected_exe: None };
    let verdict = judge_peer(&as_exec, &crate::ipc::Peer { uid: cred.uid(), pid: cred.pid() }, exe_of_pid);
    if verdict != PeerVerdict::Ok {
        log(format!("audit: connection refused: {verdict:?}"));
        return;
    }
    let authorized: Vec<Authorized> = ipc.sources.iter().map(|(s, k)| Authorized { public: k.clone(), label: s.name().into(), rights: vec![] }).collect();
    let Ok(Ok((sec, who))) = tokio::time::timeout(Duration::from_secs(5), server_handshake(&mut stream, &ipc.key, &authorized, REKEY_EVERY)).await else {
        log("audit: connection refused: handshake".into());
        return;
    };
    // the source is the key that connected
    let Some((src, _)) = ipc.sources.iter().find(|(_, k)| *k == who.public) else { return };
    let src = *src;
    let (mut rd, mut wr) = stream.into_split();
    while let Ok(msg) = read_msg(&mut rd).await {
        let Ok(f) = sec.open(&msg) else { break };
        if f.kind != AUDIT_EVENT {
            break;
        }
        let out = match decode_event(&f.payload).and_then(|ev| svc.append(src, ev)) {
            Ok(seq) => Frame::new(AUDIT_ACK, 0, seq.to_be_bytes().to_vec()),
            Err(_) => Frame::new(AUDIT_REJECT, 0, vec![]),
        };
        let Ok(m) = sec.seal(&out) else { break };
        if write_msg(&mut wr, &m).await.is_err() {
            break;
        }
    }
}

// ---------------------------------------------------------------- the part that reports

pub struct AuditClient {
    socket: PathBuf,
    key: KeyPair,
    audit_public: Vec<u8>,
    conn: tokio::sync::Mutex<Option<(Secure, tokio::net::unix::OwnedReadHalf, tokio::net::unix::OwnedWriteHalf)>>,
    /// events that could not be delivered while the audit process was away
    lost: AtomicU64,
    timeout: Duration,
}

impl AuditClient {
    pub fn new(socket: PathBuf, key: KeyPair, audit_public: Vec<u8>) -> Arc<AuditClient> {
        Arc::new(AuditClient { socket, key, audit_public, conn: tokio::sync::Mutex::new(None), lost: AtomicU64::new(0), timeout: Duration::from_secs(2) })
    }

    async fn send_once(&self, ev: &Event) -> Result<u64> {
        let mut g = self.conn.lock().await;
        if g.is_none() {
            let mut s = tokio::time::timeout(self.timeout, UnixStream::connect(&self.socket)).await??;
            let sec = tokio::time::timeout(self.timeout, client_handshake(&mut s, &self.key, &self.audit_public, REKEY_EVERY)).await??;
            let (r, w) = s.into_split();
            *g = Some((sec, r, w));
        }
        let (sec, rd, wr) = g.as_mut().unwrap();
        let r: Result<u64> = async {
            write_msg(wr, &sec.seal(&Frame::new(AUDIT_EVENT, 0, encode_event(ev)?))?).await?;
            let msg = tokio::time::timeout(self.timeout, read_msg(rd)).await??;
            let f = sec.open(&msg)?;
            if f.kind != AUDIT_ACK || f.payload.len() != 8 {
                bail!("the audit process refused the event");
            }
            Ok(u64::from_be_bytes(f.payload[..8].try_into().unwrap()))
        }
        .await;
        if r.is_err() {
            *g = None; // the next attempt starts a new connection
        }
        r
    }

    /// For things that must not happen unrecorded (SUDO and ROOT approvals, a new device): an error means "do not go on".
    pub async fn record_critical(&self, ev: Event) -> Result<u64> {
        match self.send_once(&ev).await {
            Ok(n) => Ok(n),
            Err(e) if e.to_string().contains("refused") => Err(e), // the audit process said no: it will say no again
            Err(_) => self.send_once(&ev).await,
        }
    }

    /// For the ordinary course of things: delivered in the background; if the audit process is away the loss is counted, and reported once it is back
    pub fn record(self: &Arc<Self>, ev: Event) {
        let me = self.clone();
        tokio::spawn(async move {
            let lost = me.lost.load(SeqCst);
            if lost > 0 {
                let mut d = Event::new("audit_degraded", LEVEL_NONE, RESULT_ERROR);
                d.code = lost.min(65535) as u16;
                if me.send_once(&d).await.is_ok() {
                    me.lost.fetch_sub(lost.min(me.lost.load(SeqCst)), SeqCst);
                }
            }
            if me.send_once(&ev).await.is_err() && me.send_once(&ev).await.is_err() {
                me.lost.fetch_add(1, SeqCst);
            }
        });
    }

    pub fn lost(&self) -> u64 {
        self.lost.load(SeqCst)
    }
}

/// who reports for each part (filled in by the part that runs; in the single-process mode all three exist)
#[derive(Clone, Default)]
pub struct AuditHandles {
    pub gate: Option<Arc<AuditClient>>,
    pub exec: Option<Arc<AuditClient>>,
    pub broker: Option<Arc<AuditClient>>,
    pub owner: Option<Arc<AuditClient>>,
    pub firewall: Option<Arc<AuditClient>>,
}

pub fn exists(dir: &Path) -> bool {
    dir.join("audit/sign.pub").exists()
}

/// the owner's repair after a damaged tail: only a partial record at the very end may be cut off, and the cut is written down. Anything else is not repaired here.
pub fn repair(dir: &Path) -> Result<String> {
    let vk = load_verifying_key(dir)?;
    let mut said = String::new();
    for j in [Journal::Ordinary, Journal::Security] {
        let path = dir.join("audit").join(format!("{}.log", j.file()));
        let bytes = std::fs::read(&path).unwrap_or_default();
        let rep = verify(&bytes, j, &vk, None);
        match rep.fault {
            None => said.push_str(&format!("{}: fine\n", j.file())),
            Some(Fault::DamagedTail) => {
                // cut back to the end of the last good record
                let keep = good_prefix(&bytes, j, &vk);
                std::fs::write(&path, &bytes[..keep])?;
                let _ = std::fs::remove_file(dir.join("audit").join(format!("{}.head", j.file())));
                said.push_str(&format!("{}: cut {} damaged bytes at the end\n", j.file(), bytes.len() - keep));
            }
            Some(f) => said.push_str(&format!("{}: {f:?} - NOT repaired (this is not a damaged tail; it needs a person)\n", j.file())),
        }
    }
    Ok(said)
}

fn good_prefix(bytes: &[u8], j: Journal, vk: &ed25519_dalek::VerifyingKey) -> usize {
    let (mut at, mut last_ok) = (0usize, 0usize);
    while at + 4 <= bytes.len() {
        let n = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        if n < 64 || n > MAX_RECORD || bytes.len() < at + 4 + n {
            break;
        }
        let end = at + 4 + n;
        if verify(&bytes[..end], j, vk, None).fault.is_some() {
            break;
        }
        last_ok = end;
        at = end;
    }
    last_ok
}
