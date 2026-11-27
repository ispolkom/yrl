//! Canonical Ed25519 + ML-DSA-65 signatures for Stage 7.4.
//!
//! Verification is an AND operation. There is no API which accepts a partial
//! hybrid envelope. Existing Ed25519-only objects keep their old, explicitly
//! classical format and are never re-labelled as hybrid.
use anyhow::{bail, Result};
use ed25519_dalek::Signer as _;
use ml_dsa::{Keypair as _, SignatureEncoding as _, Signer as _, Verifier as _};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub const PROFILE: u32 = 0x0003_0001;
pub const ED_PUBLIC_LEN: usize = 32;
pub const ED_SIGNATURE_LEN: usize = 64;
pub const ML_PUBLIC_LEN: usize = 1952;
pub const ML_SIGNATURE_LEN: usize = 3309;
pub const PUBLIC_LEN: usize = 4 + 1 + 8 + 32 + ED_PUBLIC_LEN + ML_PUBLIC_LEN;
pub const ENVELOPE_LEN: usize = 4 + 1 + 8 + 32 + ED_SIGNATURE_LEN + ML_SIGNATURE_LEN;
const PUBLIC_MAGIC: &[u8; 4] = b"YHP1";
const SIG_MAGIC: &[u8; 4] = b"YHS1";

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    DeviceIdentity = 1,
    ServerIdentity = 2,
    Handshake = 3,
    Audit = 4,
    AuditCheckpoint = 5,
    AuditDeletion = 6,
    ReleaseRoot = 7,
    ReleaseDelegated = 8,
    KeyTransition = 9,
    Recovery = 10,
}
impl Purpose {
    fn from_byte(v: u8) -> Result<Self> {
        Ok(match v {
            1 => Self::DeviceIdentity, 2 => Self::ServerIdentity, 3 => Self::Handshake,
            4 => Self::Audit, 5 => Self::AuditCheckpoint, 6 => Self::AuditDeletion,
            7 => Self::ReleaseRoot, 8 => Self::ReleaseDelegated, 9 => Self::KeyTransition,
            10 => Self::Recovery, _ => bail!("unknown hybrid signature purpose"),
        })
    }
    pub fn parse(name: &str) -> Result<Self> {
        Ok(match name {
            "device" => Self::DeviceIdentity, "server" => Self::ServerIdentity,
            "handshake" => Self::Handshake, "audit" => Self::Audit,
            "audit-checkpoint" => Self::AuditCheckpoint, "audit-deletion" => Self::AuditDeletion,
            "release-root" => Self::ReleaseRoot, "release-delegated" => Self::ReleaseDelegated,
            "transition" => Self::KeyTransition, "recovery" => Self::Recovery,
            _ => bail!("unknown hybrid key purpose"),
        })
    }
}

#[derive(Clone)]
pub struct PublicKey {
    pub purpose: Purpose,
    pub generation: u64,
    pub key_id: [u8; 32],
    ed: ed25519_dalek::VerifyingKey,
    ml: ml_dsa::VerifyingKey<ml_dsa::MlDsa65>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretSeeds {
    pub ed25519: [u8; 32],
    pub ml_dsa65: [u8; 32],
}

pub struct SigningKey {
    purpose: Purpose,
    generation: u64,
    ed: ed25519_dalek::SigningKey,
    ml: ml_dsa::SigningKey<ml_dsa::MlDsa65>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignatureEnvelope {
    pub purpose: Purpose,
    pub generation: u64,
    pub key_id: [u8; 32],
    ed: [u8; ED_SIGNATURE_LEN],
    ml: Vec<u8>,
}

pub(crate) fn handshake_keys(context: crate::crypto_profile::Context, local: &[u8], remote: &[u8]) -> Result<(SigningKey, PublicKey)> {
    use crate::crypto_profile::Context as Role;
    let variable = match context {
        Role::Gatekeeper => "YRL_HYBRID_GATE_KEYS",
        Role::Executor => "YRL_HYBRID_EXECUTOR_KEYS",
        Role::Broker => "YRL_HYBRID_BROKER_KEYS",
        _ => bail!("no hybrid identity store for this context"),
    };
    let root = std::env::var_os(variable).ok_or_else(|| anyhow::anyhow!("hybrid handshake identity store missing"))?;
    let root = Path::new(&root);
    if !root.is_absolute() || local.len() != 32 || remote.len() != 32 {
        bail!("invalid hybrid handshake identity store or Noise identity");
    }
    let own = root.join("local").join(hex::encode(local));
    let pin = root.join("peers").join(hex::encode(remote)).with_extension("pub");
    let peer = PublicKey::load_file(&pin, Purpose::Handshake)?;
    let key = SigningKey::load_files(&own.with_extension("key"), &own.with_extension("pub"), Purpose::Handshake)?;
    Ok((key, peer))
}

/// Canonical transition body. Planned rotation requires signatures from both
/// generations (proof of old authorization and possession of the new key).
pub fn transition_body(old: &PublicKey, new: &PublicKey) -> Result<Vec<u8>> {
    if old.purpose != new.purpose || new.generation != old.generation.checked_add(1).ok_or_else(|| anyhow::anyhow!("generation overflow"))? { bail!("invalid hybrid key transition") }
    let old_bytes = old.encode(); let new_bytes = new.encode();
    let mut out = b"YRL hybrid key transition v1\0".to_vec();
    out.extend_from_slice(&(old_bytes.len() as u32).to_be_bytes()); out.extend_from_slice(&old_bytes);
    out.extend_from_slice(&(new_bytes.len() as u32).to_be_bytes()); out.extend_from_slice(&new_bytes); Ok(out)
}

pub fn verify_transition(old: &PublicKey, new: &PublicKey, old_signature: &SignatureEnvelope, new_signature: &SignatureEnvelope) -> Result<()> {
    let body = transition_body(old, new)?;
    old.verify(&body, old_signature)?;
    new.verify(&body, new_signature)?;
    Ok(())
}

/// Emergency replacement deliberately cannot look like a normal transition.
/// It must be signed by a separately pre-trusted Recovery-purpose key.
pub fn emergency_transition_body(lost: &PublicKey, replacement: &PublicKey, incident: &[u8]) -> Result<Vec<u8>> {
    if lost.purpose != replacement.purpose || replacement.generation <= lost.generation || incident.is_empty() || incident.len() > 1024 { bail!("invalid emergency transition") }
    let mut out = b"YRL hybrid emergency transition v1\0".to_vec();
    out.extend_from_slice(&lost.encode()); out.extend_from_slice(&replacement.encode());
    out.extend_from_slice(&(incident.len() as u16).to_be_bytes()); out.extend_from_slice(incident); Ok(out)
}

pub fn verify_emergency_transition(lost: &PublicKey, replacement: &PublicKey, recovery: &PublicKey, incident: &[u8], signature: &SignatureEnvelope) -> Result<()> {
    if recovery.purpose != Purpose::Recovery { bail!("emergency transition requires a recovery key") }
    recovery.verify(&emergency_transition_body(lost, replacement, incident)?, signature)
}

impl SigningKey {
    pub fn generate(purpose: Purpose, generation: u64) -> (Self, SecretSeeds) {
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        let mut seeds = SecretSeeds { ed25519: [0; 32], ml_dsa65: [0; 32] };
        OsRng.fill_bytes(&mut seeds.ed25519);
        OsRng.fill_bytes(&mut seeds.ml_dsa65);
        let key = Self::from_seeds(purpose, generation, &seeds);
        (key, seeds)
    }

    pub fn from_seeds(purpose: Purpose, generation: u64, seeds: &SecretSeeds) -> Self {
        let ml_seed = ml_dsa::Seed::try_from(seeds.ml_dsa65.as_slice()).expect("fixed ML-DSA seed");
        Self {
            purpose, generation,
            ed: ed25519_dalek::SigningKey::from_bytes(&seeds.ed25519),
            ml: ml_dsa::SigningKey::from_seed(&ml_seed),
        }
    }

    pub fn public(&self) -> PublicKey {
        PublicKey::new(self.purpose, self.generation, self.ed.verifying_key(), self.ml.verifying_key())
    }

    pub fn sign(&self, message: &[u8]) -> Result<SignatureEnvelope> {
        let public = self.public();
        let tbs = tbs(self.purpose, self.generation, &public.key_id, message)?;
        let ed = self.ed.sign(&tbs).to_bytes();
        let ml = self.ml.try_sign(&tbs).map_err(|_| anyhow::anyhow!("ML-DSA signing failed"))?.to_bytes().to_vec();
        if ml.len() != ML_SIGNATURE_LEN { bail!("unexpected ML-DSA signature size") }
        Ok(SignatureEnvelope { purpose: self.purpose, generation: self.generation, key_id: public.key_id, ed, ml })
    }

    /// Explicit owner-driven key creation; no production key is embedded or
    /// generated during service startup.
    pub fn generate_files(private: &Path, public: &Path, purpose: Purpose, generation: u64) -> Result<PublicKey> {
        if private.exists() || public.exists() { bail!("hybrid key path already exists") }
        let (key, seeds) = Self::generate(purpose, generation);
        let public_key = key.public();
        write_new(private, &key.encode_secret(&seeds), 0o600)?;
        write_new(public, &public_key.encode(), 0o644)?;
        Ok(public_key)
    }

    pub(crate) fn encode_secret(&self, seeds: &SecretSeeds) -> zeroize::Zeroizing<Vec<u8>> {
        let mut secret = zeroize::Zeroizing::new(b"YRL-HYBRID-SECRET-1\0".to_vec());
        secret.push(self.purpose as u8);
        secret.extend_from_slice(&self.generation.to_be_bytes());
        secret.extend_from_slice(&self.public().key_id);
        secret.extend_from_slice(&seeds.ed25519);
        secret.extend_from_slice(&seeds.ml_dsa65);
        secret
    }

    pub fn load_files(private: &Path, public: &Path, expected: Purpose) -> Result<Self> {
        let pinned = PublicKey::load_file(public, expected)?;
        Self::load_pinned(private, &pinned)
    }

    pub(crate) fn load_pinned(private: &Path, pinned: &PublicKey) -> Result<Self> {
        let key = Self::load_secret(private, pinned.purpose)?;
        if key.public().encode() != pinned.encode() { bail!("hybrid public/private key mismatch") }
        Ok(key)
    }

    pub(crate) fn load_secret(private: &Path, expected: Purpose) -> Result<Self> {
        let mut bytes = zeroize::Zeroizing::new(read_bounded(private, 256, true)?);
        let prefix = b"YRL-HYBRID-SECRET-1\0";
        if bytes.len() != prefix.len() + 1 + 8 + 32 + 64 || !bytes.starts_with(prefix) { bytes.zeroize(); bail!("invalid hybrid private key") }
        let purpose = Purpose::from_byte(bytes[prefix.len()])?;
        if purpose != expected { bytes.zeroize(); bail!("hybrid key purpose mismatch") }
        let at = prefix.len() + 1;
        let generation = u64::from_be_bytes(bytes[at..at+8].try_into()?);
        let claimed: [u8; 32] = bytes[at+8..at+40].try_into()?;
        let seeds = SecretSeeds { ed25519: bytes[at+40..at+72].try_into()?, ml_dsa65: bytes[at+72..at+104].try_into()? };
        bytes.zeroize();
        let key = Self::from_seeds(purpose, generation, &seeds);
        let actual = key.public();
        if actual.key_id != claimed { bail!("hybrid public/private key mismatch") }
        Ok(key)
    }
}

impl PublicKey {
    fn new(purpose: Purpose, generation: u64, ed: ed25519_dalek::VerifyingKey, ml: ml_dsa::VerifyingKey<ml_dsa::MlDsa65>) -> Self {
        let key_id = key_id(purpose, generation, ed.as_bytes(), &ml.encode());
        Self { purpose, generation, key_id, ed, ml }
    }

    pub fn verify(&self, message: &[u8], signature: &SignatureEnvelope) -> Result<()> {
        if signature.purpose != self.purpose || signature.generation != self.generation || signature.key_id != self.key_id { bail!("hybrid signature identity mismatch") }
        let tbs = tbs(self.purpose, self.generation, &self.key_id, message)?;
        self.ed.verify_strict(&tbs, &ed25519_dalek::Signature::from_bytes(&signature.ed)).map_err(|_| anyhow::anyhow!("Ed25519 signature invalid"))?;
        let ml_sig = ml_dsa::Signature::<ml_dsa::MlDsa65>::try_from(signature.ml.as_slice()).map_err(|_| anyhow::anyhow!("ML-DSA signature encoding invalid"))?;
        self.ml.verify(&tbs, &ml_sig).map_err(|_| anyhow::anyhow!("ML-DSA signature invalid"))?;
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_LEN);
        out.extend_from_slice(PUBLIC_MAGIC); out.push(self.purpose as u8); out.extend_from_slice(&self.generation.to_be_bytes()); out.extend_from_slice(&self.key_id);
        out.extend_from_slice(self.ed.as_bytes()); out.extend_from_slice(&self.ml.encode()); out
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() != PUBLIC_LEN || &input[..4] != PUBLIC_MAGIC { bail!("invalid hybrid public key envelope") }
        let purpose = Purpose::from_byte(input[4])?;
        let generation = u64::from_be_bytes(input[5..13].try_into()?);
        let claimed: [u8; 32] = input[13..45].try_into()?;
        let ed = ed25519_dalek::VerifyingKey::from_bytes(input[45..77].try_into()?)?;
        let encoded = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::try_from(&input[77..]).map_err(|_| anyhow::anyhow!("invalid ML-DSA public key size"))?;
        let result = Self::new(purpose, generation, ed, ml_dsa::VerifyingKey::decode(&encoded));
        if result.key_id != claimed { bail!("hybrid public key binding mismatch") }
        Ok(result)
    }
    pub fn load_file(path: &Path, expected: Purpose) -> Result<Self> {
        let key = Self::decode(&read_bounded(path, PUBLIC_LEN, false)?)?;
        if key.purpose != expected { bail!("hybrid public key purpose mismatch") }
        Ok(key)
    }
}

impl SignatureEnvelope {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENVELOPE_LEN);
        out.extend_from_slice(SIG_MAGIC); out.push(self.purpose as u8); out.extend_from_slice(&self.generation.to_be_bytes()); out.extend_from_slice(&self.key_id);
        out.extend_from_slice(&self.ed); out.extend_from_slice(&self.ml); out
    }
    pub fn decode(input: &[u8]) -> Result<Self> {
        if input.len() != ENVELOPE_LEN || &input[..4] != SIG_MAGIC { bail!("invalid or partial hybrid signature envelope") }
        Ok(Self { purpose: Purpose::from_byte(input[4])?, generation: u64::from_be_bytes(input[5..13].try_into()?), key_id: input[13..45].try_into()?, ed: input[45..109].try_into()?, ml: input[109..].to_vec() })
    }
}

fn key_id(purpose: Purpose, generation: u64, ed: &[u8], ml: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("YRL hybrid Ed25519 ML-DSA-65 key binding v1");
    h.update(&PROFILE.to_be_bytes()); h.update(&[purpose as u8]); h.update(&generation.to_be_bytes()); h.update(ed); h.update(ml); *h.finalize().as_bytes()
}

fn tbs(purpose: Purpose, generation: u64, key_id: &[u8; 32], message: &[u8]) -> Result<Vec<u8>> {
    if message.len() > u32::MAX as usize { bail!("message too large") }
    let mut out = b"YRL hybrid signature TBS v1\0".to_vec();
    out.extend_from_slice(&PROFILE.to_be_bytes()); out.push(purpose as u8); out.extend_from_slice(&generation.to_be_bytes()); out.extend_from_slice(key_id); out.extend_from_slice(&(message.len() as u32).to_be_bytes()); out.extend_from_slice(message); Ok(out)
}

fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let parent = path.parent().ok_or_else(|| anyhow::anyhow!("key path has no parent"))?;
    fs::create_dir_all(parent)?;
    if mode == 0o600 { fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?; }
    let mut f = OpenOptions::new().create_new(true).write(true).mode(mode).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    f.write_all(bytes)?; f.sync_all()?; fs::File::open(parent)?.sync_all()?; Ok(())
}

fn read_bounded(path: &Path, max: usize, private: bool) -> Result<Vec<u8>> {
    let f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    let m = f.metadata()?;
    if !m.is_file() || m.nlink() != 1 || m.len() as usize > max || (private && m.mode() & 0o077 != 0) { bail!("unsafe hybrid key file") }
    let mut out = Vec::new(); f.take(max as u64 + 1).read_to_end(&mut out)?;
    if out.len() > max { bail!("oversized hybrid key file") } Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn both_signatures_and_identity_binding_are_required() {
        let (key, _seeds) = SigningKey::generate(Purpose::Audit, 7);
        let public = PublicKey::decode(&key.public().encode()).unwrap();
        let signature = SignatureEnvelope::decode(&key.sign(b"entry").unwrap().encode()).unwrap();
        public.verify(b"entry", &signature).unwrap();
        let mut stripped = signature.encode(); stripped.truncate(stripped.len() - 1);
        assert!(SignatureEnvelope::decode(&stripped).is_err());
        let mut changed = signature.clone(); changed.ml[0] ^= 1;
        assert!(public.verify(b"entry", &changed).is_err());
        let mut changed = signature.clone(); changed.ed[0] ^= 1;
        assert!(public.verify(b"entry", &changed).is_err());
    }
    #[test]
    fn transition_requires_old_and_new_generations() {
        let (old, _) = SigningKey::generate(Purpose::ReleaseRoot, 3);
        let (new, _) = SigningKey::generate(Purpose::ReleaseRoot, 4);
        let body = transition_body(&old.public(), &new.public()).unwrap();
        verify_transition(&old.public(), &new.public(), &old.sign(&body).unwrap(), &new.sign(&body).unwrap()).unwrap();
        assert!(verify_transition(&old.public(), &new.public(), &new.sign(&body).unwrap(), &new.sign(&body).unwrap()).is_err());
    }
}
