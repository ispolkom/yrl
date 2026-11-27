//! Optional TPM 2.0 secret backend using the stable `tss-esapi`/TPM2-TSS stack.
//!
//! The TPM seals a random XChaCha20-Poly1305 wrapping key. YRL secrets remain
//! software algorithms and are decrypted into zeroizing host memory when used;
//! this is deliberately not described as TPM-native X25519/Ed25519/PQ.
use anyhow::{bail, Context as _, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use std::{
    convert::{TryFrom, TryInto},
    fs,
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    str::FromStr,
};
use tss_esapi::{
    abstraction::cipher::Cipher,
    attributes::{NvIndexAttributesBuilder, ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::{nv_index_type::NvIndexType, SessionType},
    handles::NvIndexTpmHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        ecc::EccCurve,
        key_bits::RsaKeyBits,
        resource_handles::{Hierarchy, NvAuth, Provision},
        session_handles::PolicySession,
    },
    structures::{
        Auth, Digest, EccScheme, HashScheme, KeyedHashScheme, MaxBuffer, NvPublicBuilder,
        PcrSelectionList, PcrSelectionListBuilder, PcrSlot, Private, Public, PublicBuilder,
        PublicKeyedHashParameters, RsaExponent, SensitiveData, SignatureScheme,
        SymmetricDefinition,
    },
    traits::{Marshall, UnMarshall},
    utils, Context, TctiNameConf,
};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8] = b"YRL-TPM2-SEALED-1\0";
const MAX_BLOB: usize = 16 * 1024 * 1024;
const MAX_SECRET: usize = 8 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Requirement {
    Off,
    Optional,
    Required,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub requirement: Requirement,
    pub tcti: String,
    pub pcrs: Vec<u8>,
    pub nv_index: Option<u32>,
    pub owner_auth_file: Option<PathBuf>,
}

impl Policy {
    pub fn from_env() -> Result<Self> {
        let requirement = match std::env::var("YRL_TPM_POLICY")
            .unwrap_or_else(|_| "off".into())
            .as_str()
        {
            "off" => Requirement::Off,
            "optional" => Requirement::Optional,
            "required" => Requirement::Required,
            _ => bail!("YRL_TPM_POLICY must be off, optional, or required"),
        };
        let tcti = std::env::var("YRL_TPM_TCTI").unwrap_or_else(|_| "device:/dev/tpmrm0".into());
        TctiNameConf::from_str(&tcti).context("invalid YRL_TPM_TCTI")?;
        let mut pcrs = Vec::new();
        if let Ok(value) = std::env::var("YRL_TPM_PCRS") {
            for part in value.split(',').filter(|v| !v.is_empty()) {
                let slot: u8 = part.parse().context("invalid PCR number")?;
                if slot > 23 || pcrs.contains(&slot) {
                    bail!("PCRs must be unique values 0..23")
                }
                pcrs.push(slot);
            }
            pcrs.sort_unstable();
            if pcrs.len() > 8 {
                bail!("at most eight PCRs may be bound")
            }
        }
        let nv_index = std::env::var("YRL_TPM_NV_INDEX")
            .ok()
            .map(|v| {
                let v = v.strip_prefix("0x").unwrap_or(&v);
                u32::from_str_radix(v, 16).context("invalid YRL_TPM_NV_INDEX")
            })
            .transpose()?;
        if let Some(index) = nv_index {
            NvIndexTpmHandle::new(index).context("NV index is outside the TPM owner range")?;
        }
        if requirement == Requirement::Required && nv_index.is_none() {
            bail!("required TPM policy needs YRL_TPM_NV_INDEX rollback protection")
        }
        let owner_auth_file = std::env::var_os("YRL_TPM_OWNER_AUTH_FILE").map(PathBuf::from);
        Ok(Self {
            requirement,
            tcti,
            pcrs,
            nv_index,
            owner_auth_file,
        })
    }
}

#[derive(Clone, Debug)]
struct Blob {
    purpose: String,
    generation: u64,
    pcrs: Vec<u8>,
    public: Vec<u8>,
    private: Vec<u8>,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

pub struct Backend {
    context: Context,
    policy: Policy,
}

impl Backend {
    pub fn connect(policy: Policy) -> Result<Self> {
        if policy.requirement == Requirement::Off {
            bail!("TPM policy is disabled")
        }
        let tcti = TctiNameConf::from_str(&policy.tcti)?;
        let mut context = Context::new(tcti).context("cannot connect to TPM2-TSS TCTI")?;
        if let Some(path) = &policy.owner_auth_file {
            context.tr_set_auth(
                Hierarchy::Owner.into(),
                Auth::try_from(read_owner_auth(path)?.to_vec())?,
            )?;
        }
        install_hmac_session(&mut context)?;
        Ok(Self { context, policy })
    }

    /// Explicitly provisions the configured owner-authorized NV counter. This
    /// never runs during service startup and refuses an already existing index.
    pub fn provision_counter(&mut self) -> Result<u64> {
        let index = self.nv_tpm_handle()?;
        if self.context.tr_from_tpm_public(index.into()).is_ok() {
            bail!("TPM NV counter already exists")
        }
        let attrs = NvIndexAttributesBuilder::new()
            .with_owner_write(true)
            .with_owner_read(true)
            .with_nv_index_type(NvIndexType::Counter)
            .build()?;
        let public = NvPublicBuilder::new()
            .with_nv_index(index)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_attributes(attrs)
            .with_data_area_size(8)
            .build()?;
        let handle = self
            .context
            .nv_define_space(Provision::Owner, None, public)?;
        self.context.nv_increment(NvAuth::Owner, handle)?;
        self.read_counter_handle(handle)
    }

    pub fn current_generation(&mut self) -> Result<u64> {
        let index = self.nv_tpm_handle()?;
        let handle = self.context.tr_from_tpm_public(index.into())?;
        self.read_counter_handle(handle.into())
    }

    pub fn advance_generation(&mut self) -> Result<u64> {
        let index = self.nv_tpm_handle()?;
        let handle = self.context.tr_from_tpm_public(index.into())?;
        self.context.nv_increment(NvAuth::Owner, handle.into())?;
        self.read_counter_handle(handle.into())
    }

    pub fn seal(&mut self, purpose: &str, generation: u64, secret: &[u8]) -> Result<Vec<u8>> {
        validate_purpose(purpose)?;
        if secret.is_empty() || secret.len() > MAX_SECRET {
            bail!("invalid TPM secret size")
        }
        if let Some(_) = self.policy.nv_index {
            let current = self.current_generation()?;
            if generation != current
                && generation != current.checked_add(1).context("TPM generation overflow")?
            {
                bail!("TPM generation is neither current nor the next transactional generation")
            }
        } else if self.policy.requirement == Requirement::Required {
            bail!("required TPM policy has no NV rollback counter")
        }
        let parent = self.create_parent()?;
        let auth_policy = self.policy_digest()?;
        let sealed_public = sealed_public(auth_policy, !self.policy.pcrs.is_empty())?;
        let mut wrapping_key = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *wrapping_key);
        let result = self.context.create(
            parent,
            sealed_public,
            None,
            Some(SensitiveData::try_from(wrapping_key.to_vec())?),
            None,
            None,
        )?;
        let public = result.out_public.marshall()?;
        let private = result.out_private.value().to_vec();
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let aad = aad(purpose, generation, &self.policy.pcrs, &public, &private);
        let ciphertext = XChaCha20Poly1305::new((&*wrapping_key).into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: secret,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("TPM envelope encryption failed"))?;
        Blob {
            purpose: purpose.into(),
            generation,
            pcrs: self.policy.pcrs.clone(),
            public,
            private,
            nonce,
            ciphertext,
        }
        .encode()
    }

    pub fn unseal(&mut self, expected_purpose: &str, encoded: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        validate_purpose(expected_purpose)?;
        let blob = Blob::decode(encoded)?;
        if blob.purpose != expected_purpose || blob.pcrs != self.policy.pcrs {
            bail!("TPM blob purpose or PCR policy mismatch")
        }
        if let Some(_) = self.policy.nv_index {
            if blob.generation != self.current_generation()? {
                bail!("TPM blob rollback or incomplete rotation detected")
            }
        } else if self.policy.requirement == Requirement::Required {
            bail!("required TPM policy has no NV rollback counter")
        }
        let parent = self.create_parent()?;
        let private = Private::try_from(blob.private.clone())?;
        let public = Public::unmarshall(&blob.public)?;
        let loaded = self.context.load(parent, private, public)?;
        if !blob.pcrs.is_empty() {
            self.install_pcr_policy_session()?;
        }
        let mut wrapping = Zeroizing::new(self.context.unseal(loaded.into())?.value().to_vec());
        if wrapping.len() != 32 {
            bail!("invalid TPM wrapping key")
        }
        let aad = aad(
            &blob.purpose,
            blob.generation,
            &blob.pcrs,
            &blob.public,
            &blob.private,
        );
        let cipher = XChaCha20Poly1305::new_from_slice(&wrapping)
            .map_err(|_| anyhow::anyhow!("invalid TPM wrapping key"))?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&blob.nonce),
                Payload {
                    msg: &blob.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("TPM envelope authentication failed"))?;
        wrapping.zeroize();
        Ok(Zeroizing::new(plaintext))
    }

    /// Generates a TPM-native, non-exportable NIST P-256 ECDSA key. Current
    /// YRL identities remain X25519/Ed25519 and do not silently substitute it;
    /// callers must use a protocol purpose that explicitly permits P-256.
    pub fn generate_native_p256(&mut self, purpose: &str, generation: u64) -> Result<Vec<u8>> {
        validate_purpose(purpose)?;
        if self.policy.nv_index.is_some() && generation != self.current_generation()? {
            bail!("TPM generation does not match NV counter")
        }
        let parent = self.create_parent()?;
        let public = native_signing_public(self.policy_digest()?, !self.policy.pcrs.is_empty())?;
        let result = self
            .context
            .create(parent, public, None, None, None, None)?;
        NativeKey {
            purpose: purpose.into(),
            generation,
            public: result.out_public.marshall()?,
            private: result.out_private.value().to_vec(),
        }
        .encode()
    }

    /// Signs one bounded message with a previously generated TPM-native key.
    /// The returned value is the standard marshalled TPMT_SIGNATURE structure.
    pub fn sign_native_p256(
        &mut self,
        encoded: &[u8],
        expected_purpose: &str,
        message: &[u8],
    ) -> Result<Vec<u8>> {
        if message.len() > 1024 * 1024 {
            bail!("TPM signing message too large")
        }
        let key = NativeKey::decode(encoded)?;
        if key.purpose != expected_purpose {
            bail!("TPM native-key purpose mismatch")
        }
        if self.policy.nv_index.is_some() && key.generation != self.current_generation()? {
            bail!("TPM native-key rollback detected")
        }
        let parent = self.create_parent()?;
        let loaded = self.context.load(
            parent,
            Private::try_from(key.private)?,
            Public::unmarshall(&key.public)?,
        )?;
        let (digest, ticket) = self.context.hash(
            MaxBuffer::try_from(message.to_vec())?,
            HashingAlgorithm::Sha256,
            Hierarchy::Owner,
        )?;
        if !self.policy.pcrs.is_empty() {
            self.install_pcr_policy_session()?;
        }
        Ok(self
            .context
            .sign(
                loaded,
                digest,
                SignatureScheme::EcDsa {
                    hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                },
                ticket,
            )?
            .marshall()?)
    }

    pub fn native_p256_public_sec1(encoded: &[u8], expected_purpose: &str) -> Result<[u8; 65]> {
        let key = NativeKey::decode(encoded)?;
        if key.purpose != expected_purpose {
            bail!("TPM native-key purpose mismatch")
        }
        match Public::unmarshall(&key.public)? {
            Public::Ecc { unique, .. } => {
                if unique.x().len() != 32 || unique.y().len() != 32 {
                    bail!("TPM key is not P-256")
                }
                let mut out = [0u8; 65];
                out[0] = 4;
                out[1..33].copy_from_slice(unique.x().value());
                out[33..].copy_from_slice(unique.y().value());
                Ok(out)
            }
            _ => bail!("TPM native key is not ECC"),
        }
    }

    fn create_parent(&mut self) -> Result<tss_esapi::handles::KeyHandle> {
        let public = utils::create_restricted_decryption_rsa_public(
            Cipher::aes_256_cfb().try_into()?,
            RsaKeyBits::Rsa2048,
            RsaExponent::default(),
        )?;
        Ok(self
            .context
            .create_primary(Hierarchy::Owner, public, None, None, None, None)?
            .key_handle)
    }
    fn nv_tpm_handle(&self) -> Result<NvIndexTpmHandle> {
        NvIndexTpmHandle::new(
            self.policy
                .nv_index
                .context("YRL_TPM_NV_INDEX is not configured")?,
        )
        .map_err(Into::into)
    }
    fn read_counter_handle(&mut self, handle: tss_esapi::handles::NvIndexHandle) -> Result<u64> {
        let value = self.context.nv_read(NvAuth::Owner, handle, 8, 0)?;
        Ok(u64::from_be_bytes(
            value
                .value()
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid TPM NV counter"))?,
        ))
    }
    fn policy_digest(&mut self) -> Result<Digest> {
        if self.policy.pcrs.is_empty() {
            return Ok(Digest::default());
        }
        let (selection, digest) = current_pcr_digest(&mut self.context, &self.policy.pcrs)?;
        let session = self
            .context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Trial,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .context("TPM did not create trial policy session")?;
        let policy = PolicySession::try_from(session)?;
        self.context.policy_pcr(policy, digest, selection)?;
        Ok(self.context.policy_get_digest(policy)?)
    }
    fn install_pcr_policy_session(&mut self) -> Result<()> {
        let (selection, digest) = current_pcr_digest(&mut self.context, &self.policy.pcrs)?;
        let session = self
            .context
            .start_auth_session(
                None,
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )?
            .context("TPM did not create policy session")?;
        self.context
            .policy_pcr(PolicySession::try_from(session)?, digest, selection)?;
        self.context.set_sessions((Some(session), None, None));
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct NativeKey {
    purpose: String,
    generation: u64,
    public: Vec<u8>,
    private: Vec<u8>,
}
impl NativeKey {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = b"YRL-TPM2-NATIVE-P256-1\0".to_vec();
        out.push(self.purpose.len() as u8);
        out.extend_from_slice(self.purpose.as_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        for v in [&self.public, &self.private] {
            if v.len() > 8192 {
                bail!("oversized TPM native key")
            }
            out.extend_from_slice(&(v.len() as u16).to_be_bytes());
            out.extend_from_slice(v)
        }
        Ok(out)
    }
    fn decode(input: &[u8]) -> Result<Self> {
        let magic = b"YRL-TPM2-NATIVE-P256-1\0";
        if !input.starts_with(magic) || input.len() > 16384 {
            bail!("invalid TPM native key")
        }
        let mut at = magic.len();
        let n = *input.get(at).context("short TPM native key")? as usize;
        at += 1;
        if n == 0 || n > 64 || input.len() < at + n + 8 {
            bail!("invalid TPM native purpose")
        }
        let purpose = std::str::from_utf8(&input[at..at + n])?.to_owned();
        validate_purpose(&purpose)?;
        at += n;
        let generation = u64::from_be_bytes(input[at..at + 8].try_into()?);
        at += 8;
        let mut fields = Vec::new();
        for _ in 0..2 {
            if input.len() < at + 2 {
                bail!("short TPM native field")
            }
            let n = u16::from_be_bytes(input[at..at + 2].try_into()?) as usize;
            at += 2;
            if n == 0 || n > 8192 || input.len() < at + n {
                bail!("invalid TPM native field")
            }
            fields.push(input[at..at + n].to_vec());
            at += n
        }
        if at != input.len() {
            bail!("trailing TPM native-key bytes")
        }
        Ok(Self {
            purpose,
            generation,
            public: fields.remove(0),
            private: fields.remove(0),
        })
    }
}

fn install_hmac_session(context: &mut Context) -> Result<()> {
    let session = context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Hmac,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )?
        .context("TPM did not create HMAC session")?;
    let (attrs, mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
    context.tr_sess_set_attributes(session, attrs, mask)?;
    context.set_sessions((Some(session), None, None));
    Ok(())
}

fn sealed_public(policy: Digest, pcr_bound: bool) -> Result<Public> {
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_no_da(true)
        .with_admin_with_policy(pcr_bound)
        .with_user_with_auth(!pcr_bound)
        .build()?;
    Ok(PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(attrs)
        .with_auth_policy(policy)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Default::default())
        .build()?)
}

fn native_signing_public(policy: Digest, pcr_bound: bool) -> Result<Public> {
    let base = utils::create_unrestricted_signing_ecc_public(
        EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
        EccCurve::NistP256,
    )?;
    if !pcr_bound {
        return Ok(base);
    }
    let Public::Ecc {
        name_hashing_algorithm,
        parameters,
        unique,
        ..
    } = base
    else {
        unreachable!()
    };
    let attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_admin_with_policy(true)
        .with_user_with_auth(false)
        .with_decrypt(false)
        .with_sign_encrypt(true)
        .with_restricted(false)
        .build()?;
    Ok(Public::Ecc {
        object_attributes: attrs,
        name_hashing_algorithm,
        auth_policy: policy,
        parameters,
        unique,
    })
}

fn slots(input: &[u8]) -> Result<Vec<PcrSlot>> {
    input
        .iter()
        .map(|v| {
            Ok(match v {
                0 => PcrSlot::Slot0,
                1 => PcrSlot::Slot1,
                2 => PcrSlot::Slot2,
                3 => PcrSlot::Slot3,
                4 => PcrSlot::Slot4,
                5 => PcrSlot::Slot5,
                6 => PcrSlot::Slot6,
                7 => PcrSlot::Slot7,
                8 => PcrSlot::Slot8,
                9 => PcrSlot::Slot9,
                10 => PcrSlot::Slot10,
                11 => PcrSlot::Slot11,
                12 => PcrSlot::Slot12,
                13 => PcrSlot::Slot13,
                14 => PcrSlot::Slot14,
                15 => PcrSlot::Slot15,
                16 => PcrSlot::Slot16,
                17 => PcrSlot::Slot17,
                18 => PcrSlot::Slot18,
                19 => PcrSlot::Slot19,
                20 => PcrSlot::Slot20,
                21 => PcrSlot::Slot21,
                22 => PcrSlot::Slot22,
                23 => PcrSlot::Slot23,
                _ => bail!("invalid PCR"),
            })
        })
        .collect()
}
fn current_pcr_digest(context: &mut Context, pcrs: &[u8]) -> Result<(PcrSelectionList, Digest)> {
    let selection = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &slots(pcrs)?)
        .build()?;
    let (_, selected, values) = context.pcr_read(selection.clone())?;
    if selected != selection || values.len() != pcrs.len() {
        bail!("TPM returned an incomplete PCR selection")
    }
    let joined: Vec<u8> = values
        .value()
        .iter()
        .flat_map(|d| d.value().iter().copied())
        .collect();
    let (digest, _) = context.hash(
        MaxBuffer::try_from(joined)?,
        HashingAlgorithm::Sha256,
        Hierarchy::Owner,
    )?;
    Ok((selection, digest))
}

fn aad(purpose: &str, generation: u64, pcrs: &[u8], public: &[u8], private: &[u8]) -> Vec<u8> {
    let mut out = b"YRL TPM2 envelope AAD v1\0".to_vec();
    out.push(purpose.len() as u8);
    out.extend_from_slice(purpose.as_bytes());
    out.extend_from_slice(&generation.to_be_bytes());
    out.push(pcrs.len() as u8);
    out.extend_from_slice(pcrs);
    out.extend_from_slice(blake3::hash(public).as_bytes());
    out.extend_from_slice(blake3::hash(private).as_bytes());
    out
}
fn validate_purpose(purpose: &str) -> Result<()> {
    if purpose.is_empty()
        || purpose.len() > 64
        || !purpose
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._:-".contains(&b))
    {
        bail!("invalid TPM secret purpose")
    }
    Ok(())
}

impl Blob {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut out = MAGIC.to_vec();
        out.push(self.purpose.len() as u8);
        out.extend_from_slice(self.purpose.as_bytes());
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.push(self.pcrs.len() as u8);
        out.extend_from_slice(&self.pcrs);
        for value in [&self.public, &self.private, &self.ciphertext] {
            if value.len() > MAX_BLOB {
                bail!("oversized TPM blob field")
            }
            out.extend_from_slice(&(value.len() as u32).to_be_bytes());
            out.extend_from_slice(value);
        }
        out.extend_from_slice(&self.nonce);
        if out.len() > MAX_BLOB {
            bail!("oversized TPM blob")
        }
        Ok(out)
    }
    fn decode(input: &[u8]) -> Result<Self> {
        if input.len() > MAX_BLOB || !input.starts_with(MAGIC) {
            bail!("invalid TPM blob")
        }
        let mut at = MAGIC.len();
        let pn = *input.get(at).context("short TPM blob")? as usize;
        at += 1;
        if pn == 0 || pn > 64 || input.len() < at + pn + 9 {
            bail!("invalid TPM purpose")
        }
        let purpose = std::str::from_utf8(&input[at..at + pn])?.to_owned();
        validate_purpose(&purpose)?;
        at += pn;
        let generation = u64::from_be_bytes(input[at..at + 8].try_into()?);
        at += 8;
        let n = *input.get(at).context("short TPM PCR list")? as usize;
        at += 1;
        if n > 8 || input.len() < at + n {
            bail!("invalid TPM PCR list")
        }
        let pcrs = input[at..at + n].to_vec();
        at += n;
        let mut fields = Vec::new();
        for _ in 0..3 {
            if input.len() < at + 4 {
                bail!("short TPM field")
            }
            let len = u32::from_be_bytes(input[at..at + 4].try_into()?) as usize;
            at += 4;
            if len > MAX_BLOB || input.len() < at + len {
                bail!("invalid TPM field")
            }
            fields.push(input[at..at + len].to_vec());
            at += len;
        }
        if input.len() != at + 24 {
            bail!("trailing TPM blob bytes")
        }
        let nonce = input[at..].try_into()?;
        Ok(Self {
            purpose,
            generation,
            pcrs,
            public: fields.remove(0),
            private: fields.remove(0),
            ciphertext: fields.remove(0),
            nonce,
        })
    }
}

pub fn blob_path(key_path: &Path) -> PathBuf {
    key_path.with_extension("key.tpm")
}
pub fn read_blob(path: &Path) -> Result<Vec<u8>> {
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.len() as usize > MAX_BLOB
    {
        bail!("unsafe TPM blob file")
    };
    let mut out = Vec::new();
    f.take(MAX_BLOB as u64 + 1).read_to_end(&mut out)?;
    if out.len() > MAX_BLOB {
        bail!("oversized TPM blob")
    };
    Ok(out)
}
pub fn write_blob(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_BLOB {
        bail!("oversized TPM blob")
    }
    let parent = path.parent().context("TPM blob has no parent")?;
    fs::create_dir_all(parent)?;
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let tmp = parent.join(format!(".tpm-{}.tmp", hex::encode(random)));
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::rename(&tmp, path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// Converts one verified Noise key file to TPM-sealed storage. The sealed blob
/// is written and successfully unsealed before the plaintext file is removed.
/// A crash before removal leaves the original recoverable; startup prefers the
/// blob and never falls back after a blob/unseal error.
pub fn migrate_noise_key(dir: &Path) -> Result<()> {
    let policy = Policy::from_env()?;
    if policy.requirement == Requirement::Off {
        bail!("enable optional or required TPM policy first")
    }
    let source = crate::keys::key_path(dir);
    let target = blob_path(&source);
    if target.exists() {
        bail!("TPM key already exists")
    }
    let clear = read_private_source(&source, 256)?;
    validate_noise_key(&clear)?;
    let generation = if policy.nv_index.is_some() {
        let mut probe = Backend::connect(policy.clone())?;
        probe.current_generation()?
    } else {
        0
    };
    let mut backend = Backend::connect(policy)?;
    let encoded = backend.seal("noise-static", generation, &clear)?;
    write_blob(&target, &encoded)?;
    let check = backend.unseal("noise-static", &read_blob(&target)?)?;
    if check.as_slice() != clear.as_slice() {
        bail!("TPM migration verification failed")
    }
    fs::remove_file(&source)?;
    fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Transactional Noise-key rotation. A next-generation blob is durable before
/// the NV counter advances. Startup can finish the rename after a crash; it can
/// never return to the old generation once the hardware counter advanced.
pub fn rotate_noise_key(dir: &Path) -> Result<Vec<u8>> {
    let policy = Policy::from_env()?;
    if policy.requirement != Requirement::Required {
        bail!("TPM key rotation requires required policy and its dedicated NV counter")
    }
    let target = blob_path(&crate::keys::key_path(dir));
    recover_pending(&target, &policy)?;
    if !target.exists() {
        bail!("TPM key is missing")
    }
    let mut backend = Backend::connect(policy.clone())?;
    let next = backend
        .current_generation()?
        .checked_add(1)
        .context("TPM generation overflow")?;
    let key = crate::keys::generate();
    let mut body = Zeroizing::new(hex::encode(&key.private));
    body.push('\n');
    body.push_str(&hex::encode(&key.public));
    body.push('\n');
    let encoded = backend.seal("noise-static", next, body.as_bytes())?;
    let pending = target.with_extension("tpm.pending");
    if pending.exists() {
        bail!("TPM rotation already pending")
    }
    write_blob(&pending, &encoded)?;
    let actual = backend.advance_generation()?;
    if actual != next {
        bail!("unexpected TPM NV generation after increment")
    }
    let check = backend.unseal("noise-static", &read_blob(&pending)?)?;
    if check.as_slice() != body.as_bytes() {
        bail!("TPM rotated key verification failed")
    }
    fs::rename(&pending, &target)?;
    fs::File::open(dir)?.sync_all()?;
    Ok(key.public)
}

pub fn recover_pending(target: &Path, policy: &Policy) -> Result<()> {
    let pending = target.with_extension("tpm.pending");
    if !pending.exists() {
        return Ok(());
    }
    let blob = Blob::decode(&read_blob(&pending)?)?;
    let mut backend = Backend::connect(policy.clone())?;
    let current = backend.current_generation()?;
    if blob.generation == current {
        backend.unseal("noise-static", &read_blob(&pending)?)?;
        fs::rename(&pending, target)?;
        if let Some(parent) = target.parent() {
            fs::File::open(parent)?.sync_all()?
        }
        return Ok(());
    }
    if blob.generation == current.checked_add(1).unwrap_or(u64::MAX) {
        fs::remove_file(pending)?;
        return Ok(());
    }
    bail!("inconsistent TPM rotation journal")
}

/// Explicit recovery export. It is disabled unless the administrator opts in;
/// ordinary service startup never writes unsealed material to disk.
pub fn recovery_export(blob: &Path, purpose: &str, output: &Path) -> Result<()> {
    if std::env::var("YRL_TPM_ALLOW_RECOVERY_EXPORT").as_deref() != Ok("1") {
        bail!("set YRL_TPM_ALLOW_RECOVERY_EXPORT=1 for explicit recovery export")
    }
    let mut backend = Backend::connect(Policy::from_env()?)?;
    let clear = backend.unseal(purpose, &read_blob(blob)?)?;
    let mut f = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)?;
    f.write_all(&clear)?;
    f.sync_all()?;
    Ok(())
}

fn read_private_source(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>> {
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o077 != 0
        || m.len() as usize > max
    {
        bail!("unsafe software key file")
    };
    let mut out = Zeroizing::new(Vec::new());
    f.take(max as u64 + 1).read_to_end(&mut out)?;
    if out.len() > max {
        bail!("oversized software key")
    };
    Ok(out)
}
fn read_owner_auth(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let text = read_private_source(path, 130)?;
    let value = Zeroizing::new(hex::decode(std::str::from_utf8(&text)?.trim())?);
    if value.len() > 64 {
        bail!("TPM owner authorization is too long")
    }
    Ok(value)
}
fn validate_noise_key(input: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(input)?;
    let mut lines = text.lines();
    let private = Zeroizing::new(hex::decode(lines.next().context("missing private key")?)?);
    let public = hex::decode(lines.next().context("missing public key")?)?;
    if private.len() != 32 || public.len() != 32 || lines.next().is_some() {
        bail!("malformed Noise key")
    };
    let mut raw: [u8; 32] = private.as_slice().try_into()?;
    let derived = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(raw));
    raw.zeroize();
    if derived.as_bytes() != public.as_slice() {
        bail!("Noise public/private mismatch")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn blob_codec_rejects_damage_and_trailing_data() {
        let b = Blob {
            purpose: "noise:executor".into(),
            generation: 7,
            pcrs: vec![7],
            public: vec![1, 2],
            private: vec![3, 4],
            nonce: [5; 24],
            ciphertext: vec![6; 32],
        };
        let encoded = b.encode().unwrap();
        let decoded = Blob::decode(&encoded).unwrap();
        assert_eq!(decoded.generation, 7);
        let mut bad = encoded;
        bad.push(0);
        assert!(Blob::decode(&bad).is_err());
    }
    #[test]
    fn native_codec_rejects_wrong_purpose_and_truncation() {
        let key = NativeKey {
            purpose: "release:p256".into(),
            generation: 2,
            public: vec![1; 64],
            private: vec![2; 64],
        }
        .encode()
        .unwrap();
        assert!(NativeKey::decode(&key[..key.len() - 1]).is_err());
        assert!(Backend::native_p256_public_sec1(&key, "other").is_err());
    }
    /// Prepared simulator acceptance. Stage 8 supplies an isolated swtpm and
    /// TEST_TCTI=swtpm:host=...,port=...; this stage intentionally does not run it.
    #[test]
    #[ignore]
    fn swtpm_seal_unseal_and_native_sign() {
        let tcti = std::env::var("TEST_TCTI").expect("isolated swtpm TCTI");
        let policy = Policy {
            requirement: Requirement::Optional,
            tcti,
            pcrs: vec![],
            nv_index: None,
            owner_auth_file: None,
        };
        let mut backend = Backend::connect(policy).unwrap();
        let blob = backend.seal("test:secret", 1, b"secret").unwrap();
        assert!(backend.unseal("test:other", &blob).is_err());
        assert_eq!(
            backend.unseal("test:secret", &blob).unwrap().as_slice(),
            b"secret"
        );
        let mut damaged = blob;
        *damaged.last_mut().unwrap() ^= 1;
        assert!(backend.unseal("test:secret", &damaged).is_err());
        let key = backend.generate_native_p256("test:sign", 1).unwrap();
        assert_eq!(
            Backend::native_p256_public_sec1(&key, "test:sign").unwrap()[0],
            4
        );
        assert!(!backend
            .sign_native_p256(&key, "test:sign", b"message")
            .unwrap()
            .is_empty());
    }

    #[test]
    #[ignore]
    fn swtpm_nv_counter_rejects_rollback() {
        let tcti = std::env::var("TEST_TCTI").expect("fresh isolated swtpm TCTI");
        let policy = Policy {
            requirement: Requirement::Required,
            tcti,
            pcrs: vec![],
            nv_index: Some(0x0150_0030),
            owner_auth_file: None,
        };
        let mut backend = Backend::connect(policy).unwrap();
        assert_eq!(backend.provision_counter().unwrap(), 1);
        let old = backend.seal("test:rollback", 1, b"secret").unwrap();
        assert_eq!(backend.advance_generation().unwrap(), 2);
        assert!(backend.unseal("test:rollback", &old).is_err());
    }
}
