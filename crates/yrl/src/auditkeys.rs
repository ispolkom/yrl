//! Audit signing-key generations and cross-signed transitions.
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

const TRANSITION: &str = "YRL-AUDIT-KEY-TRANSITION-1";
const REVOCATION: &str = "YRL-AUDIT-KEY-REVOCATION-1";

#[derive(Clone)]
pub struct KeyHistory {
    pub root: VerifyingKey,
    pub current_generation: u64,
    pub current: VerifyingKey,
    pub keys: BTreeMap<u64, VerifyingKey>,
    pub revoked: BTreeSet<u64>,
}

fn pub_at(base: &Path, generation: u64) -> std::path::PathBuf {
    base.join("keys").join(format!("{generation:020}.pub"))
}
fn read_pub(path: &Path) -> Result<VerifyingKey> {
    let b: [u8; 32] = hex::decode(fs::read_to_string(path)?.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid Audit public key"))?;
    Ok(VerifyingKey::from_bytes(&b)?)
}

fn transition_body(
    mode: &str,
    old_generation: u64,
    old: &VerifyingKey,
    new_generation: u64,
    new: &VerifyingKey,
    at: u64,
    recovery: Option<&VerifyingKey>,
) -> String {
    format!(
        "{TRANSITION} {mode} {old_generation} {} {new_generation} {} {at} {}",
        hex::encode(old.to_bytes()),
        hex::encode(new.to_bytes()),
        recovery
            .map(|k| hex::encode(k.to_bytes()))
            .unwrap_or_else(|| "-".into())
    )
}

pub fn initialize(base: &Path, current: &VerifyingKey) -> Result<()> {
    fs::create_dir_all(base.join("keys"))?;
    if !base.join("root.pub").exists() {
        crate::auditsegments::atomic_write(
            &base.join("root.pub"),
            hex::encode(current.to_bytes()).as_bytes(),
            0o644,
        )?;
    }
    if !pub_at(base, 0).exists() {
        crate::auditsegments::atomic_write(
            &pub_at(base, 0),
            hex::encode(current.to_bytes()).as_bytes(),
            0o644,
        )?;
    }
    Ok(())
}

pub fn load(dir: &Path) -> Result<KeyHistory> {
    let base = dir.join("audit");
    let current = crate::auditlog::load_verifying_key(dir)?;
    let root = read_pub(&base.join("root.pub"))?;
    let mut keys = BTreeMap::new();
    keys.insert(0, root);
    let transitions = fs::read_to_string(base.join("key-transitions.log")).unwrap_or_default();
    for line in transitions.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() != 11 || f[0] != TRANSITION {
            bail!("invalid Audit key transition");
        }
        let mode = f[1];
        let old_gen: u64 = f[2].parse()?;
        let new_gen: u64 = f[4].parse()?;
        if new_gen != old_gen + 1 {
            bail!("non-monotonic Audit key generation");
        }
        let old = VerifyingKey::from_bytes(
            &hex::decode(f[3])?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid old key"))?,
        )?;
        let new = VerifyingKey::from_bytes(
            &hex::decode(f[5])?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid new key"))?,
        )?;
        if keys.get(&old_gen) != Some(&old) {
            bail!("Audit key transition is detached");
        }
        let recovery = if f[7] == "-" {
            None
        } else {
            Some(VerifyingKey::from_bytes(
                &hex::decode(f[7])?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid recovery key"))?,
            )?)
        };
        let body = transition_body(
            mode,
            old_gen,
            &old,
            new_gen,
            &new,
            f[6].parse()?,
            recovery.as_ref(),
        );
        new.verify(
            body.as_bytes(),
            &Signature::from_slice(&hex::decode(f[9])?)?,
        )
        .context("new Audit key possession proof failed")?;
        match mode {
            "planned" => old
                .verify(
                    body.as_bytes(),
                    &Signature::from_slice(&hex::decode(f[8])?)?,
                )
                .context("old Audit key did not authorize transition")?,
            "emergency" => {
                let configured = read_pub(&base.join("recovery.pub"))
                    .context("no pretrusted Audit recovery key")?;
                if recovery.as_ref() != Some(&configured) {
                    bail!("wrong Audit recovery key");
                }
                configured
                    .verify(
                        body.as_bytes(),
                        &Signature::from_slice(&hex::decode(f[10])?)?,
                    )
                    .context("emergency transition is not recovery-authorized")?;
            }
            _ => bail!("unknown Audit key transition mode"),
        }
        keys.insert(new_gen, new);
    }
    let current_generation = keys
        .iter()
        .find_map(|(g, k)| (k == &current).then_some(*g))
        .context("current Audit key is not in its transition chain")?;
    let mut revoked = BTreeSet::new();
    for line in fs::read_to_string(base.join("key-revocations.log"))
        .unwrap_or_default()
        .lines()
    {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() != 7 || f[0] != REVOCATION {
            bail!("invalid Audit key revocation");
        }
        let generation: u64 = f[1].parse()?;
        let at: u64 = f[2].parse()?;
        let key = keys
            .get(&generation)
            .context("revocation names unknown Audit key")?;
        if hex::encode(key.to_bytes()) != f[3] {
            bail!("revocation key mismatch");
        }
        let signer_generation: u64 = f[5].parse()?;
        let signer = keys
            .get(&signer_generation)
            .context("revocation signer is unknown")?;
        let body = format!(
            "{REVOCATION} {generation} {at} {} {} {signer_generation}",
            f[3], f[4]
        );
        signer
            .verify(
                body.as_bytes(),
                &Signature::from_slice(&hex::decode(f[6])?)?,
            )
            .context("invalid Audit key revocation signature")?;
        revoked.insert(generation);
    }
    Ok(KeyHistory {
        root,
        current_generation,
        current,
        keys,
        revoked,
    })
}

pub fn reconcile_private(dir: &Path, private_public: &VerifyingKey) -> Result<()> {
    let published = crate::auditlog::load_verifying_key(dir)?;
    if &published == private_public {
        return Ok(());
    }
    let history = load(dir)?;
    if !history.keys.values().any(|k| k == private_public) {
        bail!("Audit private key is not authorized by the key transition chain");
    }
    crate::auditsegments::atomic_write(
        &dir.join("audit/sign.pub"),
        format!("{}\n", hex::encode(private_public.to_bytes())).as_bytes(),
        0o644,
    )
}

fn append_transition(base: &Path, line: &str) -> Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(base.join("key-transitions.log"))?;
    f.write_all(line.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_data()?;
    Ok(())
}

pub fn register_recovery(dir: &Path, public_hex: &str) -> Result<()> {
    let base = dir.join("audit");
    if base.join("recovery.pub").exists() {
        bail!("Audit recovery key is already registered");
    }
    let bytes: [u8; 32] = hex::decode(public_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("recovery public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&bytes)?;
    crate::auditsegments::atomic_write(
        &base.join("recovery.pub"),
        format!("{}\n", hex::encode(bytes)).as_bytes(),
        0o600,
    )
}

fn replace_current(base: &Path, new: &SigningKey) -> Result<()> {
    let key_path = base.join("sign.key");
    let mut secret = Zeroizing::new(format!("{}\n", hex::encode(new.to_bytes())));
    crate::auditsegments::atomic_write(&key_path, secret.as_bytes(), 0o600)?;
    secret.zeroize();
    crate::auditsegments::atomic_write(
        &base.join("sign.pub"),
        format!("{}\n", hex::encode(new.verifying_key().to_bytes())).as_bytes(),
        0o644,
    )
}

pub fn planned_transition(dir: &Path, old: &SigningKey) -> Result<VerifyingKey> {
    let base = dir.join("audit");
    let history = load(dir)?;
    if old.verifying_key() != history.current {
        bail!("Audit private key does not match current history");
    }
    let new = SigningKey::generate(&mut argon2::password_hash::rand_core::OsRng);
    let ng = history.current_generation + 1;
    let at = crate::gatenet::now_secs();
    let body = transition_body(
        "planned",
        history.current_generation,
        &history.current,
        ng,
        &new.verifying_key(),
        at,
        None,
    );
    let line = format!(
        "{body} {} {} -",
        hex::encode(old.sign(body.as_bytes()).to_bytes()),
        hex::encode(new.sign(body.as_bytes()).to_bytes())
    );
    crate::auditsegments::atomic_write(
        &pub_at(&base, ng),
        hex::encode(new.verifying_key().to_bytes()).as_bytes(),
        0o644,
    )?;
    append_transition(&base, &line)?;
    replace_current(&base, &new)?;
    Ok(new.verifying_key())
}

pub fn emergency_transition(dir: &Path, recovery_seed: &Path) -> Result<VerifyingKey> {
    let base = dir.join("audit");
    let history = load(dir)?;
    let recovery_bytes = crate::keys::read_secret_hex(recovery_seed, 32)?;
    let recovery = SigningKey::from_bytes(recovery_bytes.as_slice().try_into()?);
    if recovery.verifying_key() != read_pub(&base.join("recovery.pub"))? {
        bail!("recovery private key does not match the pretrusted public key");
    }
    let new = SigningKey::generate(&mut argon2::password_hash::rand_core::OsRng);
    let ng = history.current_generation + 1;
    let at = crate::gatenet::now_secs();
    let body = transition_body(
        "emergency",
        history.current_generation,
        &history.current,
        ng,
        &new.verifying_key(),
        at,
        Some(&recovery.verifying_key()),
    );
    let line = format!(
        "{body} - {} {}",
        hex::encode(new.sign(body.as_bytes()).to_bytes()),
        hex::encode(recovery.sign(body.as_bytes()).to_bytes())
    );
    crate::auditsegments::atomic_write(
        &pub_at(&base, ng),
        hex::encode(new.verifying_key().to_bytes()).as_bytes(),
        0o644,
    )?;
    append_transition(&base, &line)?;
    replace_current(&base, &new)?;
    Ok(new.verifying_key())
}

pub fn revoke(dir: &Path, generation: u64, reason: &str, current: &SigningKey) -> Result<()> {
    let base = dir.join("audit");
    let h = load(dir)?;
    if current.verifying_key() != h.current || generation >= h.current_generation {
        bail!("only an older Audit generation can be revoked by the current key");
    }
    let key = h
        .keys
        .get(&generation)
        .context("unknown Audit key generation")?;
    let reason_hash = hex::encode(blake3::hash(reason.as_bytes()).as_bytes());
    let at = crate::gatenet::now_secs();
    let body = format!(
        "{REVOCATION} {generation} {at} {} {reason_hash} {}",
        hex::encode(key.to_bytes()),
        h.current_generation
    );
    let line = format!(
        "{body} {}\n",
        hex::encode(current.sign(body.as_bytes()).to_bytes())
    );
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(base.join("key-revocations.log"))?;
    f.write_all(line.as_bytes())?;
    f.sync_data()?;
    Ok(())
}
