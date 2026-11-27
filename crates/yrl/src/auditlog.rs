//! The audit journal: what the journal IS (records, chain, signed checkpoints, verification). The process that keeps it is in `audit.rs`.
//!
//! Each journal is a chain: `H[n] = BLAKE3(H[n-1] || canonical_record[n])`. The record is a fixed binary layout (not JSON: order of fields, spaces or a different serializer
//! must not change a hash). Every `checkpoint_every` events a CHECKPOINT record is added whose signature (Ed25519, by a key that only the audit process holds) covers the
//! sequence number and hash of the record before it; so history up to a checkpoint cannot be rewritten by anybody who gets at the file but not at the key.
//! A small signed `head` file follows the newest checkpoint, to notice a log that was cut short.
//! Nothing secret is ever put in a record: no passwords, phrases, keys, file contents or output. Sensitive targets are stored as a hash.
use anyhow::{bail, Context, Result};
use crate::auditsign::{Public, Purpose, Sign, Verify};
use ed25519_dalek::SigningKey;
use std::io::Write;
use std::path::Path;

pub const MAGIC: &[u8; 4] = b"YAR1";
pub const KIND_EVENT: u8 = 1;
pub const KIND_CHECKPOINT: u8 = 2;
pub const MAX_FIELD: usize = 4096;
pub const MAX_RECORD: usize = 64 * 1024;

/// who wrote the event, decided by WHICH KEY connected to the audit process, never by what the event claims
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    Gatekeeper = 1,
    Executor = 2,
    Broker = 3,
    Owner = 4,
    Audit = 5,
    Firewall = 6,
}

impl Source {
    pub fn from_code(c: u8) -> Option<Source> {
        Some(match c {
            1 => Source::Gatekeeper,
            2 => Source::Executor,
            3 => Source::Broker,
            4 => Source::Owner,
            5 => Source::Audit,
            6 => Source::Firewall,
            _ => return None,
        })
    }
    pub fn name(self) -> &'static str {
        match self {
            Source::Gatekeeper => "gatekeeper",
            Source::Executor => "executor",
            Source::Broker => "broker",
            Source::Owner => "owner",
            Source::Audit => "audit",
            Source::Firewall => "firewall",
        }
    }
    /// the operations each part may report (a taken-over gatekeeper cannot write what only the broker could have seen)
    pub fn may_report(self, op: &str) -> bool {
        match self {
            Source::Gatekeeper => matches!(op, "enroll_guest" | "audit_degraded" | "spa_ok" | "spa_rejected" | "spa_error"),
            Source::Executor => matches!(op, "login" | "resume" | "session_open" | "session_close" | "exec" | "pty" | "file" | "fs" | "tunnel" | "denied" | "stepup_sudo" | "peer_refused" | "replay" | "lockout_tamper" | "audit_degraded"),
            Source::Broker => matches!(op, "stepup_root" | "broker_op" | "peer_refused" | "replay" | "lockout_tamper" | "global_root_off" | "audit_degraded"),
            Source::Owner => matches!(op, "unlock" | "enroll_open" | "enroll_decision" | "word_set" | "init" | "audit_degraded" | "update_prepare" | "update_activate" | "update_rollback" | "update_failed"),
            Source::Firewall => matches!(op, "firewall_open" | "firewall_close" | "firewall_refused" | "firewall_reset" | "peer_refused" | "audit_degraded"),
            Source::Audit => matches!(op, "checkpoint" | "start" | "audit_degraded" | "repair"),
        }
    }
}

/// which of the two journals an operation belongs to; decided here, by the operation
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Journal {
    /// what users did, at USER / SUDO / ROOT
    Ordinary = 0,
    /// how the protection itself fared: pairing, unlocks, policy changes, damaged stores, refused peers, replays, the global ROOT switch
    Security = 1,
}

impl Journal {
    pub fn of(op: &str) -> Journal {
        match op {
            "peer_refused" | "lockout_tamper" | "unlock" | "enroll_open" | "enroll_decision" | "enroll_guest" | "word_set" | "global_root_off" | "replay" | "audit_degraded" | "repair" | "init" | "start" | "spa_ok" | "spa_rejected" | "spa_error" | "firewall_open" | "firewall_close" | "firewall_refused" | "firewall_reset" | "update_prepare" | "update_activate" | "update_rollback" | "update_failed" => Journal::Security,
            _ => Journal::Ordinary,
        }
    }
    pub fn file(self) -> &'static str {
        match self {
            Journal::Ordinary => "ordinary",
            Journal::Security => "security",
        }
    }
}

pub const LEVEL_NONE: u8 = 0;
pub const LEVEL_USER: u8 = 1;
pub const LEVEL_SUDO: u8 = 2;
pub const LEVEL_ROOT: u8 = 3;

pub const RESULT_OK: u8 = 0;
pub const RESULT_DENIED: u8 = 1;
pub const RESULT_ERROR: u8 = 2;
pub const RESULT_LOCKED: u8 = 3;

pub const FLAG_REPEAT: u8 = 1;

/// what a part of the system reports (it does not choose the number, the time, the source, or the hashes)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Event {
    pub session: Vec<u8>,
    pub device: Vec<u8>,
    pub user: String,
    pub level: u8,
    pub op: String,
    pub target: Vec<u8>,
    pub request_id: u64,
    pub cap: Vec<u8>,
    pub result: u8,
    pub code: u16,
}

impl Event {
    pub fn new(op: &str, level: u8, result: u8) -> Event {
        Event { session: vec![], device: vec![], user: String::new(), level, op: op.into(), target: vec![], request_id: 0, cap: vec![], result, code: 0 }
    }
    pub fn session(mut self, s: &[u8]) -> Event {
        self.session = s.to_vec();
        self
    }
    pub fn device(mut self, d: &[u8]) -> Event {
        self.device = d.to_vec();
        self
    }
    pub fn user(mut self, u: &str) -> Event {
        self.user = u.chars().filter(|c| !c.is_control()).take(64).collect();
        self
    }
    pub fn request(mut self, id: u64) -> Event {
        self.request_id = id;
        self
    }
    pub fn cap(mut self, c: &[u8]) -> Event {
        self.cap = c.to_vec();
        self
    }
    pub fn code(mut self, c: u16) -> Event {
        self.code = c;
        self
    }
    /// a plain, harmless description of the target (a program name, a service name)
    pub fn target(mut self, t: &str) -> Event {
        self.target = t.as_bytes().iter().copied().take(256).collect();
        self
    }
    /// a target that may be sensitive (a path, an address, a command line): only its hash is kept
    /// a short plain name and the hash of the sensitive detail: `ls|h:3fa9...` (who ran what, without what they typed)
    pub fn named_hidden_target(mut self, name: &str, secret: &[u8]) -> Event {
        let mut v: Vec<u8> = name.bytes().filter(|c| !c.is_ascii_control() && *c != b'|').take(48).collect();
        v.extend_from_slice(b"|h:");
        v.extend_from_slice(hex::encode(&blake3::hash(secret).as_bytes()[..16]).as_bytes());
        self.target = v;
        self
    }
    pub fn hidden_target(mut self, t: &[u8]) -> Event {
        let mut v = b"h:".to_vec();
        v.extend_from_slice(hex::encode(&blake3::hash(t).as_bytes()[..16]).as_bytes());
        self.target = v;
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub kind: u8,
    pub journal: Journal,
    pub source: Source,
    pub seq: u64,
    pub time: u64,
    pub flags: u8,
    pub ev: Event,
    /// the signature of a checkpoint
    pub extra: Vec<u8>,
}

fn put(v: &mut Vec<u8>, b: &[u8]) -> Result<()> {
    if b.len() > MAX_FIELD {
        bail!("a field is too long");
    }
    v.extend_from_slice(&(b.len() as u16).to_be_bytes());
    v.extend_from_slice(b);
    Ok(())
}

impl Record {
    /// the canonical bytes: fixed order, fixed widths, length-prefixed fields, nothing optional
    pub fn canonical(&self) -> Result<Vec<u8>> {
        let mut v = MAGIC.to_vec();
        v.push(self.kind);
        v.push(self.journal as u8);
        v.push(self.source as u8);
        v.extend_from_slice(&self.seq.to_be_bytes());
        v.extend_from_slice(&self.time.to_be_bytes());
        v.push(self.ev.level);
        v.push(self.flags);
        v.push(self.ev.result);
        v.extend_from_slice(&self.ev.code.to_be_bytes());
        v.extend_from_slice(&self.ev.request_id.to_be_bytes());
        put(&mut v, &self.ev.session)?;
        put(&mut v, &self.ev.device)?;
        put(&mut v, self.ev.user.as_bytes())?;
        put(&mut v, self.ev.op.as_bytes())?;
        put(&mut v, &self.ev.target)?;
        put(&mut v, &self.ev.cap)?;
        put(&mut v, &self.extra)?;
        Ok(v)
    }

    pub fn parse(b: &[u8]) -> Result<Record> {
        struct R<'a>(&'a [u8], usize);
        impl<'a> R<'a> {
            fn take(&mut self, n: usize) -> Result<&'a [u8]> {
                if self.0.len() < self.1 + n {
                    bail!("record is cut short");
                }
                self.1 += n;
                Ok(&self.0[self.1 - n..self.1])
            }
            fn u8(&mut self) -> Result<u8> {
                Ok(self.take(1)?[0])
            }
            fn u16(&mut self) -> Result<u16> {
                Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
            }
            fn u64(&mut self) -> Result<u64> {
                Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
            }
            fn field(&mut self) -> Result<Vec<u8>> {
                let n = self.u16()? as usize;
                if n > MAX_FIELD {
                    bail!("a field is too long");
                }
                Ok(self.take(n)?.to_vec())
            }
        }
        let mut r = R(b, 0);
        if r.take(4)? != MAGIC {
            bail!("not a record");
        }
        let kind = r.u8()?;
        if kind != KIND_EVENT && kind != KIND_CHECKPOINT {
            bail!("unknown record kind");
        }
        let journal = match r.u8()? {
            0 => Journal::Ordinary,
            1 => Journal::Security,
            _ => bail!("unknown journal"),
        };
        let source = Source::from_code(r.u8()?).context("unknown source")?;
        let (seq, time) = (r.u64()?, r.u64()?);
        let (level, flags, result, code, request_id) = (r.u8()?, r.u8()?, r.u8()?, r.u16()?, r.u64()?);
        let session = r.field()?;
        let device = r.field()?;
        let user = String::from_utf8(r.field()?).context("user is not text")?;
        let op = String::from_utf8(r.field()?).context("operation is not text")?;
        let target = r.field()?;
        let cap = r.field()?;
        let extra = r.field()?;
        if r.1 != b.len() {
            bail!("trailing bytes in a record");
        }
        Ok(Record { kind, journal, source, seq, time, flags, ev: Event { session, device, user, level, op, target, request_id, cap, result, code }, extra })
    }
}

pub type Hash = [u8; 32];

pub fn chain_hash(prev: &Hash, canonical: &[u8]) -> Hash {
    let mut h = blake3::Hasher::new();
    h.update(prev);
    h.update(canonical);
    *h.finalize().as_bytes()
}

/// what a checkpoint signs: the journal, and the number and hash of the last record before the checkpoint
pub fn checkpoint_message(journal: Journal, seq: u64, hash: &Hash) -> Vec<u8> {
    let mut m = b"yrl-audit-checkpoint-v1".to_vec();
    m.push(journal as u8);
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(hash);
    m
}

/// on disk: `[u32 length][canonical record][prev hash 32][hash 32]`
pub fn frame(rec: &Record, prev: &Hash) -> Result<(Vec<u8>, Hash)> {
    let c = rec.canonical()?;
    let h = chain_hash(prev, &c);
    let mut out = ((c.len() + 64) as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&c);
    out.extend_from_slice(prev);
    out.extend_from_slice(&h);
    Ok((out, h))
}

#[derive(Debug, PartialEq, Eq)]
pub enum Fault {
    /// the record at this place has been changed, or one is missing or inserted or moved (its hash does not follow from the one before)
    BrokenChain(u64),
    /// the numbers do not go 0,1,2...
    BadNumber(u64),
    /// a checkpoint whose signature is not by the audit key
    BadSignature(u64),
    /// the file ends in the middle of a record, or in garbage
    DamagedTail,
    /// the log ends before a signed head says it must (it was cut short)
    Truncated { has: u64, should_have: u64 },
    /// the signed head itself is wrong
    BadHead,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub records: u64,
    pub checkpoints: u64,
    /// the number and hash of the newest record that a checkpoint seals (None: no checkpoint yet)
    pub sealed: Option<(u64, Hash)>,
    /// records after the newest checkpoint: intact as a chain, but not yet sealed by a signature
    pub unsealed: u64,
    pub last: Option<(u64, Hash)>,
    pub fault: Option<Fault>,
}

/// reads a whole journal and checks everything: lengths, numbers, the chain, every checkpoint signature, and the signed head (if there is one)
pub fn verify(bytes: &[u8], journal: Journal, key: &impl Verify, head: Option<&[u8]>) -> Report {
    let mut rep = Report { records: 0, checkpoints: 0, sealed: None, unsealed: 0, last: None, fault: None };
    let head_claim = match head {
        None => None,
        Some(h) => match parse_head(h, journal, key) {
            None => {
                rep.fault = Some(Fault::BadHead);
                return rep;
            }
            Some(c) => Some(c),
        },
    };
    let mut hash_at_head: Option<Hash> = None;
    let (mut at, mut prev, mut expect) = (0usize, [0u8; 32], 0u64);
    let mut last_hash_before_cp: Option<(u64, Hash)> = None;
    while at < bytes.len() {
        if bytes.len() < at + 4 {
            rep.fault = Some(Fault::DamagedTail);
            return rep;
        }
        let n = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        if n < 64 || n > MAX_RECORD || bytes.len() < at + 4 + n {
            rep.fault = Some(Fault::DamagedTail);
            return rep;
        }
        let body = &bytes[at + 4..at + 4 + n - 64];
        let (p, h) = (&bytes[at + 4 + n - 64..at + 4 + n - 32], &bytes[at + 4 + n - 32..at + 4 + n]);
        let Ok(rec) = Record::parse(body) else {
            rep.fault = Some(Fault::BrokenChain(expect));
            return rep;
        };
        if rec.seq != expect {
            rep.fault = Some(Fault::BadNumber(rec.seq));
            return rep;
        }
        if rec.journal != journal || p != prev || chain_hash(&prev, body).as_slice() != h {
            rep.fault = Some(Fault::BrokenChain(rec.seq));
            return rep;
        }
        if rec.kind == KIND_CHECKPOINT {
            let ok = last_hash_before_cp.is_some_and(|(s, lh)| {
                key.verify_bytes(&checkpoint_message(journal, s, &lh), &rec.extra).is_ok()
            });
            if !ok {
                rep.fault = Some(Fault::BadSignature(rec.seq));
                return rep;
            }
            rep.checkpoints += 1;
            rep.sealed = last_hash_before_cp;
            rep.unsealed = 0;
        } else {
            rep.unsealed += 1;
        }
        rep.records += 1;
        prev = h.try_into().unwrap();
        if head_claim.is_some_and(|(hs, _)| hs == rec.seq) {
            hash_at_head = Some(prev);
        }
        last_hash_before_cp = Some((rec.seq, prev));
        rep.last = Some((rec.seq, prev));
        expect += 1;
        at += 4 + n;
    }
    if let Some((hs, hh)) = head_claim {
        // the log must still contain the record the head vouches for, with that very hash
        if hs >= rep.records {
            rep.fault = Some(Fault::Truncated { has: rep.records, should_have: hs + 1 });
        } else if hash_at_head != Some(hh) {
            rep.fault = Some(Fault::BrokenChain(hs));
        }
    }
    rep
}

/// `head` file: `journal seq hash signature`, signed like a checkpoint
pub fn make_head(journal: Journal, seq: u64, hash: &Hash, key: &SigningKey) -> Vec<u8> {
    make_signed_head(journal, seq, hash, key).expect("Ed25519 signing is infallible")
}

pub(crate) fn make_signed_head(journal: Journal, seq: u64, hash: &Hash, key: &impl Sign) -> Result<Vec<u8>> {
    let sig = key.sign_bytes(&checkpoint_message(journal, seq, hash))?;
    Ok(format!("{} {} {} {}\n", journal.file(), seq, hex::encode(hash), hex::encode(sig)).into_bytes())
}

pub fn parse_head(b: &[u8], journal: Journal, key: &impl Verify) -> Option<(u64, Hash)> {
    let t = std::str::from_utf8(b).ok()?;
    let f: Vec<&str> = t.split_whitespace().collect();
    if f.len() != 4 || f[0] != journal.file() {
        return None;
    }
    let seq: u64 = f[1].parse().ok()?;
    let hash: Hash = hex::decode(f[2]).ok()?.try_into().ok()?;
    let sig = hex::decode(f[3]).ok()?;
    key.verify_bytes(&checkpoint_message(journal, seq, &hash), &sig).ok()?;
    Some((seq, hash))
}

pub fn load_verifying_key(dir: &Path) -> Result<Public> {
    let bytes = std::fs::read(dir.join("audit/sign.pub"))?;
    if bytes.starts_with(b"YHP1") {
        Public::decode(&bytes, Purpose::Journal, None)
    } else {
        Public::decode(&hex::decode(std::str::from_utf8(&bytes)?.trim())?, Purpose::Journal, None)
    }
}

/// verifies a journal of a directory with the public key written next to it
pub fn verify_dir(dir: &Path, journal: Journal) -> Result<Report> {
    let key = load_verifying_key(dir)?;
    let bytes = std::fs::read(dir.join("audit").join(format!("{}.log", journal.file()))).unwrap_or_default();
    let head = std::fs::read(dir.join("audit").join(format!("{}.head", journal.file()))).ok();
    Ok(verify(&bytes, journal, &key, head.as_deref()))
}

pub fn append_file(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().create(true).append(true).mode(0o600).open(path)?;
    f.write_all(bytes)?;
    f.sync_data()?;
    Ok(())
}
