//! Audit signing-key generations and cross-signed transitions.
use anyhow::{bail, Context, Result};
use crate::auditsign::{Public, Purpose, Secret, Sign, Verify};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const TRANSITION: &str = "YRL-AUDIT-KEY-TRANSITION-1";
const REVOCATION: &str = "YRL-AUDIT-KEY-REVOCATION-1";

#[derive(Clone)]
pub struct KeyHistory {
    pub root: Public,
    pub current_generation: u64,
    pub current: Public,
    pub keys: BTreeMap<u64, Public>,
    pub revoked: BTreeSet<u64>,
}

fn pub_at(base: &Path, generation: u64) -> std::path::PathBuf {
    base.join("keys").join(format!("{generation:020}.pub"))
}
fn read_pub(path: &Path, purpose: Purpose, generation: Option<u64>) -> Result<Public> {
    Public::decode(&hex::decode(fs::read_to_string(path)?.trim())?, purpose, generation)
}

fn read_optional_log(path: &Path) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(log) => Ok(log),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e.into()),
    }
}

fn transition_body(
    mode: &str,
    old_generation: u64,
    old: &Public,
    new_generation: u64,
    new: &Public,
    at: u64,
    recovery: Option<&Public>,
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

pub fn initialize(base: &Path, current: &Public) -> Result<()> {
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
    let root = read_pub(&base.join("root.pub"), Purpose::Journal, Some(0))?;
    let mut keys = BTreeMap::new();
    keys.insert(0, root.clone());
    let transitions = read_optional_log(&base.join("key-transitions.log"))?;
    for line in transitions.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() != 11 || f[0] != TRANSITION {
            bail!("invalid Audit key transition");
        }
        let mode = f[1];
        let old_gen: u64 = f[2].parse()?;
        let new_gen: u64 = f[4].parse()?;
        if old_gen.checked_add(1) != Some(new_gen) || keys.contains_key(&new_gen) {
            bail!("non-monotonic Audit key generation");
        }
        let old = Public::decode(&hex::decode(f[3])?, Purpose::Journal, Some(old_gen))?;
        let new = Public::decode(&hex::decode(f[5])?, Purpose::Journal, Some(new_gen))?;
        if keys.get(&old_gen) != Some(&old) || !old.same_profile(&new) {
            bail!("Audit key transition is detached or changes signature profile");
        }
        let recovery = if f[7] == "-" {
            None
        } else {
            Some(Public::decode(&hex::decode(f[7])?, Purpose::Recovery, None)?)
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
        new.verify_bytes(
            body.as_bytes(),
            &hex::decode(f[9])?,
        )
        .context("new Audit key possession proof failed")?;
        match mode {
            "planned" => old
                .verify_bytes(
                    body.as_bytes(),
                    &hex::decode(f[8])?,
                )
                .context("old Audit key did not authorize transition")?,
            "emergency" => {
                let configured = read_pub(&base.join("recovery.pub"), Purpose::Recovery, None)
                    .context("no pretrusted Audit recovery key")?;
                if recovery.as_ref() != Some(&configured) || !configured.same_profile(&old) {
                    bail!("wrong Audit recovery key");
                }
                configured
                    .verify_bytes(
                        body.as_bytes(),
                        &hex::decode(f[10])?,
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
    for line in read_optional_log(&base.join("key-revocations.log"))?.lines() {
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
            .verify_bytes(
                body.as_bytes(),
                &hex::decode(f[6])?,
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

pub fn reconcile_private(dir: &Path, private_public: &Public) -> Result<()> {
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
    let bytes = hex::decode(public_hex)?;
    let recovery = Public::decode(&bytes, Purpose::Recovery, None)?;
    if !load(dir)?.current.same_profile(&recovery) {
        bail!("Audit recovery key uses a different signature profile");
    }
    crate::auditsegments::atomic_write(
        &base.join("recovery.pub"),
        format!("{}\n", hex::encode(bytes)).as_bytes(),
        0o600,
    )
}

fn replace_current(base: &Path, new: &Secret, bytes: &[u8]) -> Result<()> {
    crate::auditsegments::atomic_write(&base.join("sign.key"), bytes, 0o600)?;
    crate::auditsegments::atomic_write(
        &base.join("sign.pub"),
        format!("{}\n", hex::encode(new.verifying_key().to_bytes())).as_bytes(),
        0o644,
    )
}

pub fn planned_transition(dir: &Path, old: &impl Sign) -> Result<Public> {
    let base = dir.join("audit");
    let history = load(dir)?;
    if old.public_key() != history.current {
        bail!("Audit private key does not match current history");
    }
    let ng = history.current_generation.checked_add(1).context("Audit key generation overflow")?;
    let (new, new_bytes) = Secret::generate(&history.current, ng);
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
        hex::encode(old.sign_bytes(body.as_bytes())?),
        hex::encode(new.sign_bytes(body.as_bytes())?)
    );
    crate::auditsegments::atomic_write(
        &pub_at(&base, ng),
        hex::encode(new.verifying_key().to_bytes()).as_bytes(),
        0o644,
    )?;
    append_transition(&base, &line)?;
    replace_current(&base, &new, &new_bytes)?;
    Ok(new.verifying_key())
}

pub fn emergency_transition(dir: &Path, recovery_seed: &Path) -> Result<Public> {
    let base = dir.join("audit");
    let history = load(dir)?;
    let pin = read_pub(&base.join("recovery.pub"), Purpose::Recovery, None)?;
    let recovery = Secret::load(recovery_seed, &pin, Purpose::Recovery)?;
    if recovery.verifying_key() != pin || !pin.same_profile(&history.current) {
        bail!("recovery private key does not match the pretrusted public key and profile");
    }
    let ng = history.current_generation.checked_add(1).context("Audit key generation overflow")?;
    let (new, new_bytes) = Secret::generate(&history.current, ng);
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
        hex::encode(new.sign_bytes(body.as_bytes())?),
        hex::encode(recovery.sign_bytes(body.as_bytes())?)
    );
    crate::auditsegments::atomic_write(
        &pub_at(&base, ng),
        hex::encode(new.verifying_key().to_bytes()).as_bytes(),
        0o644,
    )?;
    append_transition(&base, &line)?;
    replace_current(&base, &new, &new_bytes)?;
    Ok(new.verifying_key())
}

pub fn revoke(dir: &Path, generation: u64, reason: &str, current: &impl Sign) -> Result<()> {
    let base = dir.join("audit");
    let h = load(dir)?;
    if current.public_key() != h.current || generation >= h.current_generation {
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
        hex::encode(current.sign_bytes(body.as_bytes())?)
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
