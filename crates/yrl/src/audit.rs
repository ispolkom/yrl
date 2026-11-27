//! The audit process: keeps the journals (see auditlog.rs). It listens on a local socket and nowhere else, does nothing but append, and holds the only copy of the signing key.
//! Gatekeeper, executor, broker and the owner's own programs each connect with their OWN key; the source written into a record is the one that key belongs to, and each
//! source may only report the operations it could actually have seen. A taken-over gatekeeper therefore cannot write in the name of the broker, and none of them can
//! change an old record: the only way into the files is this process's append.
use crate::auditlog::*;
use crate::auditsegments::{self, Active, RotationPolicy, SegmentSeal};
use crate::ipc::{exe_of_pid, judge_peer, ExecutorIpc, PeerVerdict};
use crate::ipc_admission::{AdmissionLimits, IpcAdmission, IpcPermit};
use crate::keys::{Authorized, KeyPair};
use crate::session::{
    client_handshake, read_msg, server_handshake, write_msg, Secure, REKEY_EVERY,
};
use crate::wire::Frame;
use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use crate::auditsign::{Public, Purpose, Secret, Sign};
use std::collections::HashSet;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

pub const AUDIT_EVENT: u8 = 90;
pub const AUDIT_ACK: u8 = 91;
pub const AUDIT_REJECT: u8 = 92;
pub const AUDIT_ANCHOR_REQUEST: u8 = 93;
pub const AUDIT_ANCHOR_RESPONSE: u8 = 94;
pub const AUDIT_EXPORT_SIGN_REQUEST: u8 = 95;
pub const AUDIT_EXPORT_SIGN_RESPONSE: u8 = 96;

struct J {
    path: PathBuf,
    head: PathBuf,
    prev: Hash,
    next: u64,
    since_cp: u64,
    active: Active,
}

struct Inner {
    journals: [J; 2],
    seen: HashSet<(Source, Vec<u8>, u64, String)>,
    /// a failed write: the chain must not go on from a place nobody knows
    broken: bool,
}

pub struct AuditService {
    key: Secret,
    every: u64,
    base: PathBuf,
    rotation: RotationPolicy,
    inner: Mutex<Inner>,
    _lock: std::fs::File,
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl AuditService {
    /// Opens (or creates) the journals in `<dir>/audit`. A journal that does not verify - a changed record, a damaged tail, a bad signature, a log cut short - is NOT
    /// continued: the process refuses to start until the owner has looked at it and run `repair`.
    pub fn open(dir: &Path, every: u64) -> Result<Arc<AuditService>> {
        Self::open_with_policy(dir, every, RotationPolicy::from_env()?)
    }

    pub fn open_with_policy(
        dir: &Path,
        every: u64,
        rotation: RotationPolicy,
    ) -> Result<Arc<AuditService>> {
        use std::os::unix::fs::PermissionsExt;
        let base = dir.join("audit");
        // The journals are for the owner (who reads them as root) and for nobody else: the part that faces the network must not be able to look at who logs in and when.
        // A directory that is already there is the installation's: its owner and mode are not touched. A new one is private.
        if !base.exists() {
            std::fs::create_dir_all(&base)?;
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))?;
        }
        // one audit process per directory
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(base.join("lock"))?;
        if unsafe {
            libc::flock(
                std::os::fd::AsRawFd::as_raw_fd(&lock),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        } != 0
        {
            bail!("another audit process holds this journal");
        }
        let key_path = base.join("sign.key");
        let require_hybrid = std::env::var_os("YRL_AUDIT_REQUIRE_HYBRID").is_some();
        let key = if key_path.exists() {
            let public = load_verifying_key(dir)?;
            if require_hybrid && matches!(public, Public::Classical(_)) {
                bail!("Audit requires a provisioned hybrid signing key");
            }
            Secret::load(&key_path, &public, Purpose::Journal)?
        } else {
            if require_hybrid || base.join("sign.pub").exists() || base.join("root.pub").exists() {
                bail!("Audit signing key is missing");
            }
            let k = SigningKey::generate(&mut argon2::password_hash::rand_core::OsRng);
            let mut f = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&key_path)?;
            f.write_all_hex(&k.to_bytes())?;
            f.sync_all()?;
            auditsegments::atomic_write(&base.join("sign.pub"), hex::encode(k.verifying_key().to_bytes()).as_bytes(), 0o644)?;
            Secret::Classical(k)
        };
        crate::auditkeys::initialize(&base, &key.verifying_key())?;
        crate::auditkeys::reconcile_private(dir, &key.verifying_key())?;
        let history = crate::auditkeys::load(dir)?;
        if history.current != key.verifying_key() {
            bail!("Audit signing key generation is inconsistent");
        }
        let vk = key.verifying_key();
        recover_rotation(&base, &key, &history)?;
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
            let active = auditsegments::read_active(&base, j, &vk, now())?;
            if !base.join(format!("{}.active", j.file())).exists() {
                auditsegments::write_active(&base, j, &active, &key)?;
            }
            journals.push(J {
                path,
                head,
                prev,
                next,
                since_cp: rep.unsealed,
                active,
            });
        }
        let [a, b]: [J; 2] = journals.try_into().ok().context("journals")?;
        auditsegments::verify_chain(dir, None).context("Audit segment chain does not verify")?;
        let svc = Arc::new(AuditService {
            key,
            every: every.max(1),
            base,
            rotation,
            inner: Mutex::new(Inner {
                journals: [a, b],
                seen: HashSet::new(),
                broken: false,
            }),
            _lock: lock,
        });
        svc.append(Source::Audit, Event::new("start", LEVEL_NONE, RESULT_OK))?;
        Ok(svc)
    }

    pub fn verifying_key(&self) -> Public {
        self.key.verifying_key()
    }

    /// Produces a portable signed checkpoint after sealing both current tails.
    pub fn trust_anchor(&self) -> Result<Vec<u8>> {
        let mut g = self.inner.lock().unwrap();
        if g.broken {
            bail!("the Audit journal is closed");
        }
        for journal in [Journal::Ordinary, Journal::Security] {
            if g.journals[journal as usize].since_cp > 0 {
                self.checkpoint_locked(&mut g, journal)?;
            }
        }
        let point = |journal: Journal| {
            let j = &g.journals[journal as usize];
            auditsegments::AnchorPoint {
                journal,
                generation: j.active.generation,
                seq: j.next.checked_sub(1),
                hash: if j.next == 0 { [0; 32] } else { j.prev },
            }
        };
        let anchor = auditsegments::TrustAnchor {
            created: now(),
            key: self.key.verifying_key().to_bytes(),
            points: [point(Journal::Ordinary), point(Journal::Security)],
        };
        anchor.encode(&self.key)
    }

    pub fn sign_export(&self, digest: &[u8; 32]) -> Result<Vec<u8>> {
        let anchor = self.trust_anchor()?;
        let mut message = b"yrl-audit-export-v1".to_vec();
        message.extend_from_slice(digest);
        message.extend_from_slice(blake3::hash(&anchor).as_bytes());
        let mut out = (anchor.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(&anchor);
        out.extend_from_slice(&self.key.sign_bytes(&message)?);
        Ok(out)
    }

    /// writes one event; returns its number. Errors are real: the caller decides what that means for what it was about to do.
    pub fn append(&self, src: Source, mut ev: Event) -> Result<u64> {
        if !src.may_report(&ev.op) {
            bail!("{} cannot report '{}'", src.name(), ev.op);
        }
        ev.user = ev
            .user
            .chars()
            .filter(|c| !c.is_control())
            .take(64)
            .collect();
        let journal = Journal::of(&ev.op);
        let mut g = self.inner.lock().unwrap();
        if g.broken {
            bail!("the journal could not be written earlier and is closed");
        }
        if self.prepare_locked(&mut g, journal).is_err() {
            g.broken = true;
            bail!("Audit storage budget or rotation failed");
        }
        let mut flags = 0u8;
        if ev.request_id != 0 {
            if g.seen.len() > 200_000 {
                g.seen.clear();
            }
            if !g
                .seen
                .insert((src, ev.session.clone(), ev.request_id, ev.op.clone()))
            {
                flags |= FLAG_REPEAT;
            }
        }
        let idx = journal as usize;
        let rec = Record {
            kind: KIND_EVENT,
            journal,
            source: src,
            seq: g.journals[idx].next,
            time: now(),
            flags,
            ev,
            extra: vec![],
        };
        let (bytes, h) = frame(&rec, &g.journals[idx].prev)?;
        if append_file(&g.journals[idx].path, &bytes).is_err() {
            g.broken = true;
            bail!("cannot write the journal");
        }
        let seq = rec.seq;
        g.journals[idx].prev = h;
        g.journals[idx].next += 1;
        g.journals[idx].since_cp += 1;
        if g.journals[idx].since_cp >= self.every
            && self.checkpoint_locked(&mut g, journal).is_err()
        {
            g.broken = true;
            bail!("cannot write the checkpoint");
        }
        Ok(seq)
    }

    fn prepare_locked(&self, g: &mut Inner, journal: Journal) -> Result<()> {
        let idx = journal as usize;
        let age = now().saturating_sub(g.journals[idx].active.started);
        let size = std::fs::metadata(&g.journals[idx].path)
            .map(|m| m.len())
            .unwrap_or(0);
        if size >= self.rotation.max_bytes || (size > 0 && age >= self.rotation.max_age_secs) {
            self.rotate_locked(g, journal)?;
        }
        self.prune_locked(journal)?;
        if auditsegments::free_bytes(&self.base)?
            < self
                .rotation
                .min_free_bytes
                .saturating_add(MAX_RECORD as u64)
            || auditsegments::total_bytes(&self.base)? >= self.rotation.max_total_bytes
        {
            bail!("Audit disk budget exhausted");
        }
        Ok(())
    }

    fn rotate_locked(&self, g: &mut Inner, journal: Journal) -> Result<()> {
        let idx = journal as usize;
        if g.journals[idx].next == 0 {
            return Ok(());
        }
        if g.journals[idx].since_cp > 0 {
            self.checkpoint_locked(g, journal)?;
        }
        let j = &g.journals[idx];
        let bytes = std::fs::read(&j.path)?;
        let seal = SegmentSeal {
            journal,
            generation: j.active.generation,
            started: j.active.started,
            ended: now(),
            records: j.next,
            last_seq: j.next - 1,
            last_hash: j.prev,
            file_hash: *blake3::hash(&bytes).as_bytes(),
            previous_seal: j.active.previous_seal,
        };
        let pending = auditsegments::archived(&self.base, journal, seal.generation, "seal.pending");
        let encoded = seal.encode_signed(&self.key)?;
        auditsegments::atomic_write(&pending, &encoded, 0o600)?;
        finish_rotation(&self.base, &self.key, &seal)?;
        let j = &mut g.journals[idx];
        j.prev = [0; 32];
        j.next = 0;
        j.since_cp = 0;
        j.active = Active {
            generation: seal.generation + 1,
            started: now(),
            previous_seal: *blake3::hash(&encoded).as_bytes(),
        };
        self.prune_locked(journal)?;
        Ok(())
    }

    fn prune_locked(&self, journal: Journal) -> Result<()> {
        let state_dir = self
            .base
            .parent()
            .context("Audit directory has no state parent")?;
        let history = crate::auditkeys::load(state_dir)?;
        let mut seals = Vec::new();
        for entry in std::fs::read_dir(&self.base)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let prefix = format!("{}.", journal.file());
            if name.starts_with(&prefix) && name.ends_with(".seal") {
                let (seal, _, _) =
                    auditsegments::decode_seal_any(&std::fs::read(entry.path())?, &history)?;
                seals.push((seal.generation, entry.path(), seal));
            }
        }
        seals.sort_by_key(|x| x.0);
        while seals.len() > 2
            && (seals.len() as u64 > self.rotation.retain_segments
                || auditsegments::total_bytes(&self.base)? > self.rotation.max_total_bytes)
        {
            let (_, seal_path, seal) = seals.remove(0);
            let log = auditsegments::archived(&self.base, journal, seal.generation, "log");
            let head = auditsegments::archived(&self.base, journal, seal.generation, "head");
            auditsegments::safe_regular(&seal_path)?;
            auditsegments::safe_regular(&log)?;
            let encoded = std::fs::read(&seal_path)?;
            auditsegments::append_deletion(
                &self.base,
                journal,
                seal.generation,
                *blake3::hash(&encoded).as_bytes(),
                seal.file_hash,
                &self.key,
                now(),
            )?;
            std::fs::remove_file(&log)?;
            if head.exists() {
                auditsegments::safe_regular(&head)?;
                std::fs::remove_file(head)?;
            }
            std::fs::remove_file(seal_path)?;
            std::fs::File::open(&self.base)?.sync_all()?;
        }
        Ok(())
    }

    fn checkpoint_locked(&self, g: &mut Inner, journal: Journal) -> Result<()> {
        let idx = journal as usize;
        let j = &g.journals[idx];
        if j.next == 0 {
            return Ok(());
        }
        let (last_seq, last_hash) = (j.next - 1, j.prev);
        let sig = self
            .key
            .sign_bytes(&checkpoint_message(journal, last_seq, &last_hash))?;
        let rec = Record {
            kind: KIND_CHECKPOINT,
            journal,
            source: Source::Audit,
            seq: j.next,
            time: now(),
            flags: 0,
            ev: Event::new("checkpoint", LEVEL_NONE, RESULT_OK),
            extra: sig,
        };
        let (bytes, h) = frame(&rec, &j.prev)?;
        append_file(&j.path, &bytes)?;
        let head = make_signed_head(journal, rec.seq, &h, &self.key)?;
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

    pub fn rotate_all(&self) -> Result<()> {
        let mut g = self.inner.lock().unwrap();
        for journal in [Journal::Ordinary, Journal::Security] {
            self.rotate_locked(&mut g, journal)?;
        }
        Ok(())
    }
}

fn finish_rotation(base: &Path, key: &Secret, seal: &SegmentSeal) -> Result<()> {
    let live_log = base.join(format!("{}.log", seal.journal.file()));
    let live_head = base.join(format!("{}.head", seal.journal.file()));
    let archive_log = auditsegments::archived(base, seal.journal, seal.generation, "log");
    let archive_head = auditsegments::archived(base, seal.journal, seal.generation, "head");
    let pending = auditsegments::archived(base, seal.journal, seal.generation, "seal.pending");
    let final_seal = auditsegments::archived(base, seal.journal, seal.generation, "seal");
    if !archive_log.exists() {
        std::fs::rename(&live_log, &archive_log)?;
    }
    auditsegments::safe_regular(&archive_log)?;
    if *blake3::hash(&std::fs::read(&archive_log)?).as_bytes() != seal.file_hash {
        bail!("rotated Audit segment changed");
    }
    if live_head.exists() && !archive_head.exists() {
        std::fs::rename(&live_head, &archive_head)?;
    }
    if !final_seal.exists() {
        std::fs::rename(&pending, &final_seal)?;
    }
    if !live_log.exists() {
        auditsegments::atomic_write(&live_log, &[], 0o600)?;
    }
    let active = Active {
        generation: seal.generation + 1,
        started: now(),
        previous_seal: *blake3::hash(&std::fs::read(&final_seal)?).as_bytes(),
    };
    auditsegments::write_active(base, seal.journal, &active, key)?;
    std::fs::File::open(base)?.sync_all()?;
    Ok(())
}

fn recover_rotation(base: &Path, key: &Secret, history: &crate::auditkeys::KeyHistory) -> Result<()> {
    let vk = key.verifying_key();
    for journal in [Journal::Ordinary, Journal::Security] {
        let prefix = format!("{}.", journal.file());
        let mut pending = Vec::new();
        let mut completed = Vec::new();
        for entry in std::fs::read_dir(base)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(&prefix) && name.ends_with(".seal.pending") {
                pending.push(SegmentSeal::decode(&std::fs::read(entry.path())?, &vk)?);
            } else if name.starts_with(&prefix) && name.ends_with(".seal") {
                let bytes = std::fs::read(entry.path())?;
                let (seal, _, _) = auditsegments::decode_seal_any(&bytes, history)?;
                completed.push((seal.generation, *blake3::hash(&bytes).as_bytes(), seal));
            }
        }
        pending.sort_by_key(|s| s.generation);
        for seal in pending {
            finish_rotation(base, key, &seal)?;
        }
        if let Some((generation, digest, _)) = completed.into_iter().max_by_key(|x| x.0) {
            let active = auditsegments::read_active(base, journal, &vk, now())?;
            if active.generation <= generation {
                if !base.join(format!("{}.log", journal.file())).exists() {
                    auditsegments::atomic_write(
                        &base.join(format!("{}.log", journal.file())),
                        &[],
                        0o600,
                    )?;
                }
                auditsegments::write_active(
                    base,
                    journal,
                    &Active {
                        generation: generation + 1,
                        started: now(),
                        previous_seal: digest,
                    },
                    key,
                )?;
            }
        }
    }
    Ok(())
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
    Record {
        kind: KIND_EVENT,
        journal: Journal::Ordinary,
        source: Source::Audit,
        seq: 0,
        time: 0,
        flags: 0,
        ev: ev.clone(),
        extra: vec![],
    }
    .canonical()
}

pub fn decode_event(b: &[u8]) -> Result<Event> {
    let r = Record::parse(b)?;
    if r.kind != KIND_EVENT || r.seq != 0 || r.time != 0 || r.flags != 0 || !r.extra.is_empty() {
        bail!("not a plain event");
    }
    Ok(r.ev)
}

pub const IPC_LIMITS: AdmissionLimits = AdmissionLimits {
    handshakes: 16,
    handshakes_per_peer: 4,
    active: 32,
    active_per_principal: 8,
};
const IPC_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const IPC_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const IPC_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const BACKGROUND_EVENTS: usize = 256;

pub async fn serve_ipc(
    listener: UnixListener,
    svc: Arc<AuditService>,
    ipc: AuditIpc,
    log: Arc<dyn Fn(String) + Send + Sync>,
) {
    serve_ipc_with_limits(listener, svc, ipc, log, IPC_LIMITS).await
}

pub async fn serve_ipc_with_limits(
    listener: UnixListener,
    svc: Arc<AuditService>,
    ipc: AuditIpc,
    log: Arc<dyn Fn(String) + Send + Sync>,
    limits: AdmissionLimits,
) {
    let admission = IpcAdmission::new(limits);
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let Ok(cred) = stream.peer_cred() else {
            continue;
        };
        let Some(handshake) = admission.try_handshake(cred.uid()) else {
            continue;
        };
        let (svc, ipc, log) = (svc.clone(), ipc.clone(), log.clone());
        let admission = admission.clone();
        let peer = crate::ipc::Peer {
            uid: cred.uid(),
            pid: cred.pid(),
        };
        tokio::spawn(
            async move { handle(stream, peer, handshake, admission, svc, ipc, log).await },
        );
    }
}

async fn handle(
    mut stream: UnixStream,
    peer: crate::ipc::Peer,
    handshake: IpcPermit,
    admission: IpcAdmission,
    svc: Arc<AuditService>,
    ipc: AuditIpc,
    log: Arc<dyn Fn(String) + Send + Sync>,
) {
    let as_exec = ExecutorIpc {
        socket: ipc.socket.clone(),
        key: ipc.key.clone(),
        gatekeeper_public: vec![],
        expected_uid: ipc.expected_uid,
        expected_exe: ipc.expected_exe.clone(),
    };
    let verdict = judge_peer(&as_exec, &peer, exe_of_pid);
    if verdict != PeerVerdict::Ok {
        log(format!("audit: connection refused: {verdict:?}"));
        return;
    }
    let authorized: Vec<Authorized> = ipc
        .sources
        .iter()
        .map(|(s, k)| Authorized {
            public: k.clone(),
            label: s.name().into(),
            rights: vec![],
        })
        .collect();
    let Ok(Ok((sec, who))) = tokio::time::timeout(
        IPC_HANDSHAKE_TIMEOUT,
        server_handshake(&mut stream, &ipc.key, &authorized, REKEY_EVERY),
    )
    .await
    else {
        log("audit: connection refused: handshake".into());
        return;
    };
    // the source is the key that connected
    let Some((src, _)) = ipc.sources.iter().find(|(_, k)| *k == who.public) else {
        return;
    };
    let src = *src;
    let Some(_active) = admission.try_active(&who.public) else {
        log(format!(
            "audit: connection refused: {:?} source capacity exhausted",
            src
        ));
        return;
    };
    drop(handshake);
    let (mut rd, mut wr) = stream.into_split();
    while let Ok(Ok(msg)) = tokio::time::timeout(IPC_IDLE_TIMEOUT, read_msg(&mut rd)).await {
        let Ok(f) = sec.open(&msg) else { break };
        if f.kind == AUDIT_ANCHOR_REQUEST && f.payload.is_empty() && src == Source::Owner {
            let svc = svc.clone();
            let anchor = tokio::task::spawn_blocking(move || svc.trust_anchor())
                .await
                .unwrap_or_else(|_| Err(anyhow::anyhow!("Audit anchor task failed")));
            let out = match anchor {
                Ok(a) => Frame::new(AUDIT_ANCHOR_RESPONSE, 0, a),
                Err(_) => Frame::new(AUDIT_REJECT, 0, vec![]),
            };
            let Ok(m) = sec.seal(&out) else { break };
            if !matches!(
                tokio::time::timeout(IPC_WRITE_TIMEOUT, write_msg(&mut wr, &m)).await,
                Ok(Ok(()))
            ) {
                break;
            }
            continue;
        } else if f.kind == AUDIT_EXPORT_SIGN_REQUEST
            && f.payload.len() == 32
            && src == Source::Owner
        {
            let digest: [u8; 32] = f.payload.as_slice().try_into().unwrap();
            let svc = svc.clone();
            let signed = tokio::task::spawn_blocking(move || svc.sign_export(&digest))
                .await
                .unwrap_or_else(|_| Err(anyhow::anyhow!("Audit export-sign task failed")));
            let out = match signed {
                Ok(v) => Frame::new(AUDIT_EXPORT_SIGN_RESPONSE, 0, v),
                Err(_) => Frame::new(AUDIT_REJECT, 0, vec![]),
            };
            let Ok(m) = sec.seal(&out) else { break };
            if !matches!(
                tokio::time::timeout(IPC_WRITE_TIMEOUT, write_msg(&mut wr, &m)).await,
                Ok(Ok(()))
            ) {
                break;
            }
            continue;
        } else if f.kind != AUDIT_EVENT {
            break;
        }
        // Journal I/O and its process-wide chain lock must not occupy an async worker. Admission
        // bounds the number of blocking jobs, and awaiting completion preserves the ACK contract.
        let appended = match decode_event(&f.payload) {
            Ok(ev) => {
                let svc = svc.clone();
                tokio::task::spawn_blocking(move || svc.append(src, ev))
                    .await
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("audit append task failed")))
            }
            Err(e) => Err(e),
        };
        let out = match appended {
            Ok(seq) => Frame::new(AUDIT_ACK, 0, seq.to_be_bytes().to_vec()),
            Err(_) => Frame::new(AUDIT_REJECT, 0, vec![]),
        };
        let Ok(m) = sec.seal(&out) else { break };
        if !matches!(
            tokio::time::timeout(IPC_WRITE_TIMEOUT, write_msg(&mut wr, &m)).await,
            Ok(Ok(()))
        ) {
            break;
        }
    }
}

// ---------------------------------------------------------------- the part that reports

pub struct AuditClient {
    socket: PathBuf,
    key: KeyPair,
    audit_public: Vec<u8>,
    conn: tokio::sync::Mutex<
        Option<(
            Secure,
            tokio::net::unix::OwnedReadHalf,
            tokio::net::unix::OwnedWriteHalf,
        )>,
    >,
    /// Critical records never wait behind the bounded ordinary-event backlog.
    critical_conn: tokio::sync::Mutex<
        Option<(
            Secure,
            tokio::net::unix::OwnedReadHalf,
            tokio::net::unix::OwnedWriteHalf,
        )>,
    >,
    /// events that could not be delivered while the audit process was away
    lost: AtomicU64,
    timeout: Duration,
    background: Arc<Semaphore>,
}

impl AuditClient {
    pub fn new(socket: PathBuf, key: KeyPair, audit_public: Vec<u8>) -> Arc<AuditClient> {
        Arc::new(AuditClient {
            socket,
            key,
            audit_public,
            conn: tokio::sync::Mutex::new(None),
            critical_conn: tokio::sync::Mutex::new(None),
            lost: AtomicU64::new(0),
            timeout: Duration::from_secs(2),
            background: Arc::new(Semaphore::new(BACKGROUND_EVENTS)),
        })
    }

    async fn send_once_on(
        &self,
        conn: &tokio::sync::Mutex<
            Option<(
                Secure,
                tokio::net::unix::OwnedReadHalf,
                tokio::net::unix::OwnedWriteHalf,
            )>,
        >,
        ev: &Event,
    ) -> Result<u64> {
        let mut g = conn.lock().await;
        if g.is_none() {
            let mut s =
                tokio::time::timeout(self.timeout, UnixStream::connect(&self.socket)).await??;
            let sec = tokio::time::timeout(
                self.timeout,
                client_handshake(&mut s, &self.key, &self.audit_public, REKEY_EVERY),
            )
            .await??;
            let (r, w) = s.into_split();
            *g = Some((sec, r, w));
        }
        let (sec, rd, wr) = g.as_mut().unwrap();
        let r: Result<u64> = async {
            tokio::time::timeout(
                self.timeout,
                write_msg(
                    wr,
                    &sec.seal(&Frame::new(AUDIT_EVENT, 0, encode_event(ev)?))?,
                ),
            )
            .await??;
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

    async fn send_once(&self, ev: &Event) -> Result<u64> {
        self.send_once_on(&self.conn, ev).await
    }

    /// For things that must not happen unrecorded (SUDO and ROOT approvals, a new device): an error means "do not go on".
    pub async fn record_critical(&self, ev: Event) -> Result<u64> {
        match self.send_once_on(&self.critical_conn, &ev).await {
            Ok(n) => Ok(n),
            Err(e) if e.to_string().contains("refused") => Err(e), // the audit process said no: it will say no again
            Err(_) => self.send_once_on(&self.critical_conn, &ev).await,
        }
    }

    /// For the ordinary course of things: delivered in the background; if the audit process is away the loss is counted, and reported once it is back
    pub fn record(self: &Arc<Self>, ev: Event) {
        let Ok(slot) = self.background.clone().try_acquire_owned() else {
            self.lost.fetch_add(1, SeqCst);
            return;
        };
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
            drop(slot);
        });
    }

    pub fn lost(&self) -> u64 {
        self.lost.load(SeqCst)
    }

    /// Fetches a signed checkpoint over the authenticated local Noise channel.
    pub async fn fetch_anchor(&self) -> Result<Vec<u8>> {
        let mut g = self.critical_conn.lock().await;
        if g.is_none() {
            let mut s =
                tokio::time::timeout(self.timeout, UnixStream::connect(&self.socket)).await??;
            let sec = tokio::time::timeout(
                self.timeout,
                client_handshake(&mut s, &self.key, &self.audit_public, REKEY_EVERY),
            )
            .await??;
            let (r, w) = s.into_split();
            *g = Some((sec, r, w));
        }
        let (sec, rd, wr) = g.as_mut().unwrap();
        let result: Result<Vec<u8>> = async {
            tokio::time::timeout(
                self.timeout,
                write_msg(wr, &sec.seal(&Frame::new(AUDIT_ANCHOR_REQUEST, 0, vec![]))?),
            )
            .await??;
            let f = sec.open(&tokio::time::timeout(self.timeout, read_msg(rd)).await??)?;
            if f.kind != AUDIT_ANCHOR_RESPONSE {
                bail!("the Audit service refused the checkpoint request");
            }
            Ok(f.payload)
        }
        .await;
        if result.is_err() {
            *g = None;
        }
        result
    }

    pub async fn sign_export_digest(&self, digest: [u8; 32]) -> Result<Vec<u8>> {
        let mut g = self.critical_conn.lock().await;
        if g.is_none() {
            let mut s =
                tokio::time::timeout(self.timeout, UnixStream::connect(&self.socket)).await??;
            let sec = tokio::time::timeout(
                self.timeout,
                client_handshake(&mut s, &self.key, &self.audit_public, REKEY_EVERY),
            )
            .await??;
            let (r, w) = s.into_split();
            *g = Some((sec, r, w));
        }
        let (sec, rd, wr) = g.as_mut().unwrap();
        let result: Result<Vec<u8>> = async {
            tokio::time::timeout(
                self.timeout,
                write_msg(
                    wr,
                    &sec.seal(&Frame::new(AUDIT_EXPORT_SIGN_REQUEST, 0, digest.to_vec()))?,
                ),
            )
            .await??;
            let f = sec.open(&tokio::time::timeout(self.timeout, read_msg(rd)).await??)?;
            if f.kind != AUDIT_EXPORT_SIGN_RESPONSE {
                bail!("the Audit service refused export signing");
            }
            Ok(f.payload)
        }
        .await;
        if result.is_err() {
            *g = None;
        }
        result
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

#[cfg(test)]
mod overload_tests {
    use super::*;

    #[tokio::test]
    async fn ordinary_backlog_is_bounded_and_critical_lane_is_reserved() {
        let client = AuditClient::new(
            PathBuf::from("/does/not/exist"),
            crate::keys::generate(),
            vec![0; 32],
        );
        let mut held = Vec::new();
        for _ in 0..BACKGROUND_EVENTS {
            held.push(client.background.clone().try_acquire_owned().unwrap());
        }
        client.record(Event::new("session", LEVEL_NONE, RESULT_OK));
        assert_eq!(
            client.lost(),
            1,
            "ordinary overload is explicit and counted"
        );

        let _ordinary_busy = client.conn.lock().await;
        assert!(
            client.critical_conn.try_lock().is_ok(),
            "mandatory records have an independent connection lane"
        );
        drop(held);
    }
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
                said.push_str(&format!(
                    "{}: cut {} damaged bytes at the end\n",
                    j.file(),
                    bytes.len() - keep
                ));
            }
            Some(f) => said.push_str(&format!(
                "{}: {f:?} - NOT repaired (this is not a damaged tail; it needs a person)\n",
                j.file()
            )),
        }
    }
    Ok(said)
}

fn good_prefix(bytes: &[u8], j: Journal, vk: &impl crate::auditsign::Verify) -> usize {
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
