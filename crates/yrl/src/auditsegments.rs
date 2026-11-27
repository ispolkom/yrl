//! Crash-safe rotation metadata for Audit journals.  Record framing remains in `auditlog`;
//! these signed envelopes connect independently verifiable files into one segment chain.
use crate::auditlog::{Hash, Journal};
use anyhow::{bail, Context, Result};
use crate::auditsign::{Public, Purpose, Sign, Verify};
use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const FORMAT: &str = "YRL-AUDIT-SEGMENT-1";

#[derive(Clone, Copy, Debug)]
pub struct RotationPolicy {
    pub max_bytes: u64,
    pub max_age_secs: u64,
    pub max_total_bytes: u64,
    pub retain_segments: u64,
    pub min_free_bytes: u64,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self {
            max_bytes: 64 << 20,
            max_age_secs: 24 * 60 * 60,
            max_total_bytes: 4 << 30,
            retain_segments: 64,
            min_free_bytes: 256 << 20,
        }
    }
}

impl RotationPolicy {
    pub fn from_env() -> Result<Self> {
        fn n(name: &str, default: u64) -> Result<u64> {
            Ok(std::env::var(name)
                .ok()
                .map(|v| v.parse())
                .transpose()?
                .unwrap_or(default))
        }
        let d = Self::default();
        let p = Self {
            max_bytes: n("YRL_AUDIT_SEGMENT_BYTES", d.max_bytes)?,
            max_age_secs: n("YRL_AUDIT_SEGMENT_SECS", d.max_age_secs)?,
            max_total_bytes: n("YRL_AUDIT_TOTAL_BYTES", d.max_total_bytes)?,
            retain_segments: n("YRL_AUDIT_RETAIN_SEGMENTS", d.retain_segments)?,
            min_free_bytes: n("YRL_AUDIT_FREE_RESERVE", d.min_free_bytes)?,
        };
        if p.max_bytes < 1 << 20
            || p.max_age_secs < 60
            || p.max_total_bytes < p.max_bytes * 2
            || p.retain_segments < 2
        {
            bail!("unsafe Audit rotation limits");
        }
        Ok(p)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegmentSeal {
    pub journal: Journal,
    pub generation: u64,
    pub started: u64,
    pub ended: u64,
    pub records: u64,
    pub last_seq: u64,
    pub last_hash: Hash,
    pub file_hash: Hash,
    pub previous_seal: Hash,
}

impl SegmentSeal {
    fn body(&self) -> String {
        format!(
            "{} {} {} {} {} {} {} {} {} {}",
            FORMAT,
            self.journal.file(),
            self.generation,
            self.started,
            self.ended,
            self.records,
            self.last_seq,
            hex::encode(self.last_hash),
            hex::encode(self.file_hash),
            hex::encode(self.previous_seal)
        )
    }

    pub fn encode(&self, key: &SigningKey) -> Vec<u8> {
        self.encode_signed(key).expect("Ed25519 signing is infallible")
    }

    pub(crate) fn encode_signed(&self, key: &impl Sign) -> Result<Vec<u8>> {
        let body = self.body();
        let sig = key.sign_bytes(body.as_bytes())?;
        Ok(format!("{body} {}\n", hex::encode(sig)).into_bytes())
    }

    pub fn decode(bytes: &[u8], key: &impl Verify) -> Result<Self> {
        let text = std::str::from_utf8(bytes)?;
        let f: Vec<_> = text.split_whitespace().collect();
        if f.len() != 11 || f[0] != FORMAT {
            bail!("invalid segment seal");
        }
        let journal = match f[1] {
            "ordinary" => Journal::Ordinary,
            "security" => Journal::Security,
            _ => bail!("invalid journal"),
        };
        let seal = Self {
            journal,
            generation: f[2].parse()?,
            started: f[3].parse()?,
            ended: f[4].parse()?,
            records: f[5].parse()?,
            last_seq: f[6].parse()?,
            last_hash: hex::decode(f[7])?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid last hash"))?,
            file_hash: hex::decode(f[8])?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid file hash"))?,
            previous_seal: hex::decode(f[9])?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid previous seal"))?,
        };
        let body = seal.body();
        let sig = hex::decode(f[10])?;
        key.verify_bytes(body.as_bytes(), &sig)
            .context("invalid segment signature")?;
        Ok(seal)
    }

    pub fn digest(&self, key: &SigningKey) -> Hash {
        *blake3::hash(&self.encode(key)).as_bytes()
    }
}

#[derive(Clone, Debug)]
pub struct Active {
    pub generation: u64,
    pub started: u64,
    pub previous_seal: Hash,
}

fn state_message(j: Journal, a: &Active) -> String {
    format!(
        "YRL-AUDIT-ACTIVE-1 {} {} {} {}",
        j.file(),
        a.generation,
        a.started,
        hex::encode(a.previous_seal)
    )
}

pub fn write_active(base: &Path, j: Journal, a: &Active, key: &impl Sign) -> Result<()> {
    let body = state_message(j, a);
    let text = format!(
        "{body} {}\n",
        hex::encode(key.sign_bytes(body.as_bytes())?)
    );
    atomic_write(
        &base.join(format!("{}.active", j.file())),
        text.as_bytes(),
        0o600,
    )
}

pub fn read_active(base: &Path, j: Journal, key: &impl Verify, now: u64) -> Result<Active> {
    let path = base.join(format!("{}.active", j.file()));
    if !path.exists() {
        return Ok(Active {
            generation: 0,
            started: now,
            previous_seal: [0; 32],
        });
    }
    let text = fs::read_to_string(path)?;
    let f: Vec<_> = text.split_whitespace().collect();
    if f.len() != 6 || f[0] != "YRL-AUDIT-ACTIVE-1" || f[1] != j.file() {
        bail!("invalid active segment state");
    }
    let a = Active {
        generation: f[2].parse()?,
        started: f[3].parse()?,
        previous_seal: hex::decode(f[4])?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid previous seal"))?,
    };
    let sig = hex::decode(f[5])?;
    key.verify_bytes(state_message(j, &a).as_bytes(), &sig)
        .context("invalid active segment signature")?;
    Ok(a)
}

pub fn archived(base: &Path, j: Journal, generation: u64, ext: &str) -> PathBuf {
    base.join(format!("{}.{generation:020}.{ext}", j.file()))
}

pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    File::open(path.parent().context("file without parent")?)?.sync_all()?;
    Ok(())
}

pub fn free_bytes(path: &Path) -> Result<u64> {
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok((s.f_bavail as u64).saturating_mul(s.f_frsize as u64))
}

pub fn total_bytes(base: &Path) -> Result<u64> {
    let mut total = 0u64;
    for e in fs::read_dir(base)? {
        let e = e?;
        let m = e.metadata()?;
        if m.is_file() {
            total = total.checked_add(m.len()).context("Audit size overflow")?;
        }
    }
    Ok(total)
}

pub fn append_deletion(
    base: &Path,
    j: Journal,
    generation: u64,
    seal_hash: Hash,
    file_hash: Hash,
    key: &impl Sign,
    at: u64,
) -> Result<()> {
    let body = format!(
        "YRL-AUDIT-DELETE-1 {} {} {} {} {}",
        j.file(),
        generation,
        at,
        hex::encode(seal_hash),
        hex::encode(file_hash)
    );
    let line = format!(
        "{body} {}\n",
        hex::encode(key.sign_bytes(body.as_bytes())?)
    );
    let path = base.join("deletions.log");
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(line.as_bytes())?;
    f.sync_data()?;
    Ok(())
}

pub fn safe_regular(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file() || m.nlink() != 1 {
        bail!("unsafe Audit archive {}", path.display());
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deletion {
    pub journal: Journal,
    pub generation: u64,
    pub at: u64,
    pub seal_hash: Hash,
    pub file_hash: Hash,
}

fn deletion_body(d: &Deletion) -> String {
    format!(
        "YRL-AUDIT-DELETE-1 {} {} {} {} {}",
        d.journal.file(),
        d.generation,
        d.at,
        hex::encode(d.seal_hash),
        hex::encode(d.file_hash)
    )
}

pub fn read_deletions(base: &Path, keys: &[Public]) -> Result<BTreeMap<(u8, u64), Deletion>> {
    let text = match fs::read_to_string(base.join("deletions.log")) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() != 7 || f[0] != "YRL-AUDIT-DELETE-1" {
            bail!("invalid Audit deletion witness");
        }
        let d = Deletion {
            journal: match f[1] {
                "ordinary" => Journal::Ordinary,
                "security" => Journal::Security,
                _ => bail!("invalid deletion journal"),
            },
            generation: f[2].parse()?,
            at: f[3].parse()?,
            seal_hash: hex::decode(f[4])?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid seal hash"))?,
            file_hash: hex::decode(f[5])?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid file hash"))?,
        };
        let sig = hex::decode(f[6])?;
        if !keys
            .iter()
            .any(|key| key.verify_bytes(deletion_body(&d).as_bytes(), &sig).is_ok())
        {
            bail!("invalid deletion witness signature");
        }
        if out.insert((d.journal as u8, d.generation), d).is_some() {
            bail!("duplicate Audit deletion witness");
        }
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorPoint {
    pub journal: Journal,
    pub generation: u64,
    pub seq: Option<u64>,
    pub hash: Hash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchor {
    pub created: u64,
    pub key: Vec<u8>,
    pub points: [AnchorPoint; 2],
}

impl TrustAnchor {
    fn body(&self) -> String {
        let p = |x: &AnchorPoint| {
            format!(
                "{} {} {} {}",
                x.journal.file(),
                x.generation,
                x.seq.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
                hex::encode(x.hash)
            )
        };
        format!(
            "YRL-AUDIT-ANCHOR-1 {} {} {} {}",
            self.created,
            hex::encode(&self.key),
            p(&self.points[0]),
            p(&self.points[1])
        )
    }
    pub(crate) fn encode(&self, key: &impl Sign) -> Result<Vec<u8>> {
        let body = self.body();
        Ok(format!("{body} {} END\n", hex::encode(key.sign_bytes(body.as_bytes())?)).into_bytes())
    }
    pub fn decode(bytes: &[u8], trusted: Option<&Public>) -> Result<Self> {
        let f: Vec<_> = std::str::from_utf8(bytes)?.split_whitespace().collect();
        if f.len() != 13 || f[0] != "YRL-AUDIT-ANCHOR-1" || f[12] != "END" {
            bail!("invalid Audit trust anchor");
        }
        let key_bytes = hex::decode(f[2])?;
        let key = Public::decode(&key_bytes, Purpose::Journal, None)?;
        if trusted.is_some_and(|t| t != &key) {
            bail!("anchor is signed by an unexpected key");
        }
        let point = |at: usize, journal: Journal| -> Result<AnchorPoint> {
            if f[at] != journal.file() {
                bail!("anchor journals are out of order");
            }
            Ok(AnchorPoint {
                journal,
                generation: f[at + 1].parse()?,
                seq: if f[at + 2] == "-" {
                    None
                } else {
                    Some(f[at + 2].parse()?)
                },
                hash: hex::decode(f[at + 3])?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid anchor hash"))?,
            })
        };
        let anchor = Self {
            created: f[1].parse()?,
            key: key_bytes,
            points: [point(3, Journal::Ordinary)?, point(7, Journal::Security)?],
        };
        key.verify_bytes(
            anchor.body().as_bytes(),
            &hex::decode(f[11])?,
        )
        .context("invalid anchor signature")?;
        Ok(anchor)
    }
}

#[derive(Debug)]
pub struct ChainReport {
    pub archived: u64,
    pub deleted: u64,
    pub active_records: u64,
    pub revoked_key_segments: u64,
}

pub fn decode_seal_any(
    bytes: &[u8],
    history: &crate::auditkeys::KeyHistory,
) -> Result<(SegmentSeal, u64, Public)> {
    for (generation, key) in &history.keys {
        if let Ok(seal) = SegmentSeal::decode(bytes, key) {
            return Ok((seal, *generation, key.clone()));
        }
    }
    bail!("segment seal is not signed by a trusted Audit key generation")
}

fn hash_at(bytes: &[u8], seq: u64) -> Option<Hash> {
    let mut at = 0usize;
    while at + 4 <= bytes.len() {
        let n = u32::from_be_bytes(bytes[at..at + 4].try_into().ok()?) as usize;
        if n < 64 || at + 4 + n > bytes.len() {
            return None;
        }
        let rec = crate::auditlog::Record::parse(&bytes[at + 4..at + 4 + n - 64]).ok()?;
        if rec.seq == seq {
            return bytes[at + 4 + n - 32..at + 4 + n].try_into().ok();
        }
        at += 4 + n;
    }
    None
}

pub fn verify_chain(dir: &Path, external: Option<&TrustAnchor>) -> Result<ChainReport> {
    let base = dir.join("audit");
    let history = crate::auditkeys::load(dir)?;
    let key = &history.current;
    if external.is_some_and(|a| !history.keys.values().any(|k| k.to_bytes() == a.key)) {
        bail!("trusted anchor key is not in the Audit transition chain");
    }
    let all_keys: Vec<_> = history.keys.values().cloned().collect();
    let deletions = read_deletions(&base, &all_keys)?;
    let mut out = ChainReport {
        archived: 0,
        deleted: 0,
        active_records: 0,
        revoked_key_segments: 0,
    };
    for journal in [Journal::Ordinary, Journal::Security] {
        let active = read_active(&base, journal, key, 0)?;
        let mut previous = [0u8; 32];
        for generation in 0..active.generation {
            let seal_path = archived(&base, journal, generation, "seal");
            if seal_path.exists() {
                safe_regular(&seal_path)?;
                let seal_bytes = fs::read(&seal_path)?;
                let (seal, key_generation, segment_key) = decode_seal_any(&seal_bytes, &history)?;
                if seal.generation != generation
                    || seal.journal != journal
                    || seal.previous_seal != previous
                {
                    bail!("broken Audit segment sequence");
                }
                let log = archived(&base, journal, generation, "log");
                safe_regular(&log)?;
                let bytes = fs::read(&log)?;
                if *blake3::hash(&bytes).as_bytes() != seal.file_hash {
                    bail!("Audit segment file hash mismatch");
                }
                let head = fs::read(archived(&base, journal, generation, "head")).ok();
                let r = crate::auditlog::verify(&bytes, journal, &segment_key, head.as_deref());
                if r.fault.is_some()
                    || r.records != seal.records
                    || r.last != Some((seal.last_seq, seal.last_hash))
                {
                    bail!("Audit segment records do not match its seal");
                }
                if let Some(p) = external.and_then(|a| {
                    a.points
                        .iter()
                        .find(|p| p.journal == journal && p.generation == generation)
                }) {
                    if p.seq.and_then(|s| hash_at(&bytes, s)) != p.seq.map(|_| p.hash) {
                        bail!("Audit history does not extend trusted anchor");
                    }
                }
                previous = *blake3::hash(&seal_bytes).as_bytes();
                out.archived += 1;
                if history.revoked.contains(&key_generation) {
                    out.revoked_key_segments += 1;
                }
            } else if let Some(d) = deletions.get(&(journal as u8, generation)) {
                previous = d.seal_hash;
                out.deleted += 1;
            } else {
                bail!(
                    "missing Audit segment {} generation {}",
                    journal.file(),
                    generation
                );
            }
        }
        if active.previous_seal != previous {
            bail!("active Audit segment is detached from its history");
        }
        let bytes = fs::read(base.join(format!("{}.log", journal.file()))).unwrap_or_default();
        let head = fs::read(base.join(format!("{}.head", journal.file()))).ok();
        let r = crate::auditlog::verify(&bytes, journal, key, head.as_deref());
        if let Some(f) = r.fault {
            bail!("active Audit journal fault: {f:?}");
        }
        if let Some(p) = external.and_then(|a| a.points.iter().find(|p| p.journal == journal)) {
            if active.generation < p.generation {
                bail!("Audit journal was rolled back before trusted generation");
            }
            if active.generation == p.generation
                && p.seq.and_then(|s| hash_at(&bytes, s)) != p.seq.map(|_| p.hash)
            {
                bail!("active Audit journal does not extend trusted checkpoint");
            }
        }
        out.active_records += r.records;
    }
    Ok(out)
}
