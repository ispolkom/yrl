//! Crash-safe rotation metadata for Audit journals.  Record framing remains in `auditlog`;
//! these signed envelopes connect independently verifiable files into one segment chain.
use crate::auditlog::{Hash, Journal};
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
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
        let body = self.body();
        let sig = key.sign(body.as_bytes());
        format!("{body} {}\n", hex::encode(sig.to_bytes())).into_bytes()
    }

    pub fn decode(bytes: &[u8], key: &VerifyingKey) -> Result<Self> {
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
        let sig = Signature::from_slice(&hex::decode(f[10])?)?;
        key.verify(body.as_bytes(), &sig)
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

pub fn write_active(base: &Path, j: Journal, a: &Active, key: &SigningKey) -> Result<()> {
    let body = state_message(j, a);
    let text = format!(
        "{body} {}\n",
        hex::encode(key.sign(body.as_bytes()).to_bytes())
    );
    atomic_write(
        &base.join(format!("{}.active", j.file())),
        text.as_bytes(),
        0o600,
    )
}

pub fn read_active(base: &Path, j: Journal, key: &VerifyingKey, now: u64) -> Result<Active> {
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
    let sig = Signature::from_slice(&hex::decode(f[5])?)?;
    key.verify(state_message(j, &a).as_bytes(), &sig)
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
    key: &SigningKey,
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
        hex::encode(key.sign(body.as_bytes()).to_bytes())
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
