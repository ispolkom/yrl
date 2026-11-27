//! Optional native FIDO2/CTAP2 support backed by Yubico libfido2.
//!
//! YRL is a native client, not a web origin. The configured RP ID is a stable
//! DNS-style administrative name; the account, device key, server role, Noise
//! channel and (for step-up) exact operation digest live in the one-use client
//! data. No cloud service is involved.
use anyhow::{bail, Context, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use p256::ecdsa::{signature::Verifier as _, Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const MAX_CREDENTIAL_ID: usize = 1024;
pub const MAX_CREDENTIALS_PER_ACCOUNT: usize = 16;
pub const MAX_PENDING_CHALLENGES: usize = 128;
pub const MAX_CHALLENGE_TTL: u64 = 300;
const CHALLENGE_MAGIC: &[u8] = b"YRL-FIDO2-CHALLENGE-1\0";
const RECORD_MAGIC: &[u8] = b"YRL-FIDO2-CREDENTIAL-1\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ceremony {
    Register = 1,
    Login = 2,
    RootStepUp = 3,
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub rp_id: String,
    pub user_verification: bool,
}
impl Policy {
    pub fn from_env() -> Result<Self> {
        let rp_id = std::env::var("YRL_FIDO2_RP_ID").unwrap_or_else(|_| "yrl.local".into());
        if rp_id.len() > 253
            || rp_id.split('.').any(|p| {
                p.is_empty()
                    || p.len() > 63
                    || !p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            bail!("YRL_FIDO2_RP_ID must be a stable DNS-style name")
        }
        let user_verification = matches!(
            std::env::var("YRL_FIDO2_UV").as_deref(),
            Ok("required" | "1" | "true")
        );
        Ok(Self {
            rp_id,
            user_verification,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Challenge {
    pub client_data: Vec<u8>,
    pub expires: u64,
    pub user_verification: bool,
}

pub struct ChallengeStore {
    root: PathBuf,
}
impl ChallengeStore {
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        let meta = fs::symlink_metadata(root)?;
        if !meta.is_dir() || meta.mode() & 0o077 != 0 {
            bail!("unsafe FIDO2 challenge directory")
        }
        Ok(Self {
            root: root.to_owned(),
        })
    }
    pub fn issue(
        &self,
        ceremony: Ceremony,
        account: &[u8],
        device: &[u8],
        operation: &[u8],
        now: u64,
        ttl: u64,
        uv: bool,
    ) -> Result<Challenge> {
        if ttl == 0
            || ttl > MAX_CHALLENGE_TTL
            || account.is_empty()
            || account.len() > crate::wire::MAX_LOGIN
            || device.len() != 32
            || operation.len() > 4096
        {
            bail!("invalid FIDO2 challenge context")
        }
        self.cleanup(now)?;
        if fs::read_dir(&self.root)?.filter_map(|x| x.ok()).count() >= MAX_PENDING_CHALLENGES {
            bail!("FIDO2 challenge budget exhausted")
        }
        let expires = now.checked_add(ttl).context("challenge expiry overflow")?;
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let mut data = CHALLENGE_MAGIC.to_vec();
        data.push(ceremony as u8);
        data.extend_from_slice(&expires.to_be_bytes());
        data.push(uv as u8);
        data.extend_from_slice(blake3::hash(account).as_bytes());
        data.extend_from_slice(blake3::hash(device).as_bytes());
        data.extend_from_slice(blake3::hash(operation).as_bytes());
        data.extend_from_slice(&nonce);
        let path = self.pending_path(&data);
        write_new(&path, &data, 0o600)?;
        Ok(Challenge {
            client_data: data,
            expires,
            user_verification: uv,
        })
    }
    /// Atomically burns a challenge before signature verification. Invalid
    /// assertions may cause denial of this one challenge but cannot replay it.
    pub fn consume(
        &self,
        challenge: &[u8],
        ceremony: Ceremony,
        account: &[u8],
        device: &[u8],
        operation: &[u8],
        now: u64,
    ) -> Result<bool> {
        let path = self.pending_path(challenge);
        let used = path.with_extension("used");
        fs::rename(&path, &used).context("unknown or already consumed FIDO2 challenge")?;
        let actual = read_bounded(&used, 256, true)?;
        let p = CHALLENGE_MAGIC.len();
        if actual != challenge
            || actual.len() != p + 1 + 8 + 1 + 32 * 4
            || actual[p] != ceremony as u8
        {
            bail!("FIDO2 challenge context mismatch")
        }
        let expires = u64::from_be_bytes(actual[p + 1..p + 9].try_into()?);
        if now > expires {
            bail!("FIDO2 challenge expired")
        }
        let uv = actual[p + 9] != 0;
        let at = p + 10;
        if actual[at..at + 32] != *blake3::hash(account).as_bytes()
            || actual[at + 32..at + 64] != *blake3::hash(device).as_bytes()
            || actual[at + 64..at + 96] != *blake3::hash(operation).as_bytes()
        {
            bail!("FIDO2 challenge identity or operation mismatch")
        }
        Ok(uv)
    }
    fn pending_path(&self, challenge: &[u8]) -> PathBuf {
        self.root
            .join(format!("{}.pending", blake3::hash(challenge).to_hex()))
    }
    fn cleanup(&self, now: u64) -> Result<()> {
        for e in fs::read_dir(&self.root)? {
            let e = e?;
            let name = e.file_name();
            let Some(name) = name.to_str() else { continue };
            if !(name.ends_with(".pending") || name.ends_with(".used")) {
                continue;
            }
            if let Ok(data) = read_bounded(&e.path(), 256, true) {
                let p = CHALLENGE_MAGIC.len();
                if data.len() >= p + 9
                    && u64::from_be_bytes(data[p + 1..p + 9].try_into().unwrap())
                        < now.saturating_sub(MAX_CHALLENGE_TTL)
                {
                    let _ = fs::remove_file(e.path());
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct CredentialRecord {
    pub id: Vec<u8>,
    pub public_xy: [u8; 64],
    pub counter: u32,
    pub account_hash: [u8; 32],
    pub device_hash: [u8; 32],
    pub uv_required: bool,
    pub revoked: bool,
    pub label: String,
}
impl CredentialRecord {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.id.is_empty()
            || self.id.len() > MAX_CREDENTIAL_ID
            || self.label.len() > 64
            || self.label.bytes().any(|b| b.is_ascii_control())
        {
            bail!("invalid FIDO2 credential record")
        }
        let mut out = RECORD_MAGIC.to_vec();
        out.extend_from_slice(&(self.id.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.id);
        out.extend_from_slice(&self.public_xy);
        out.extend_from_slice(&self.counter.to_be_bytes());
        out.extend_from_slice(&self.account_hash);
        out.extend_from_slice(&self.device_hash);
        out.push(self.uv_required as u8);
        out.push(self.revoked as u8);
        out.push(self.label.len() as u8);
        out.extend_from_slice(self.label.as_bytes());
        Ok(out)
    }
    pub fn decode(input: &[u8]) -> Result<Self> {
        if !input.starts_with(RECORD_MAGIC) {
            bail!("invalid FIDO2 credential record")
        }
        let p = RECORD_MAGIC.len();
        if input.len() < p + 2 {
            bail!("short FIDO2 record")
        }
        let n = u16::from_be_bytes(input[p..p + 2].try_into()?) as usize;
        let at = p + 2 + n;
        if n == 0 || n > MAX_CREDENTIAL_ID || input.len() < at + 64 + 4 + 64 + 3 {
            bail!("invalid FIDO2 record lengths")
        }
        let label_n = input[at + 64 + 4 + 64 + 2] as usize;
        if input.len() != at + 64 + 4 + 64 + 3 + label_n {
            bail!("trailing FIDO2 record data")
        }
        Ok(Self {
            id: input[p + 2..at].to_vec(),
            public_xy: input[at..at + 64].try_into()?,
            counter: u32::from_be_bytes(input[at + 64..at + 68].try_into()?),
            account_hash: input[at + 68..at + 100].try_into()?,
            device_hash: input[at + 100..at + 132].try_into()?,
            uv_required: input[at + 132] != 0,
            revoked: input[at + 133] != 0,
            label: std::str::from_utf8(&input[at + 135..])?.to_owned(),
        })
    }
}

pub struct CredentialStore {
    root: PathBuf,
}
impl CredentialStore {
    pub fn open(root: &Path) -> Result<Self> {
        fs::create_dir_all(root)?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
        Ok(Self {
            root: root.to_owned(),
        })
    }
    pub fn save(&self, record: &CredentialRecord) -> Result<()> {
        let existing = self.for_account_hash(&record.account_hash)?.len();
        if existing >= MAX_CREDENTIALS_PER_ACCOUNT && !self.path(&record.id).exists() {
            bail!("FIDO2 credential quota exhausted")
        }
        atomic_private(&self.path(&record.id), &record.encode()?)
    }
    pub fn load(&self, id: &[u8]) -> Result<CredentialRecord> {
        CredentialRecord::decode(&read_bounded(&self.path(id), 2048, true)?)
    }
    pub fn revoke(&self, id: &[u8]) -> Result<()> {
        let mut r = self.load(id)?;
        r.revoked = true;
        self.save(&r)
    }
    pub fn for_account_hash(&self, account: &[u8; 32]) -> Result<Vec<CredentialRecord>> {
        let mut out = Vec::new();
        for e in fs::read_dir(&self.root)? {
            let e = e?;
            if !e.file_name().to_string_lossy().starts_with("cred-") {
                continue;
            }
            if let Ok(r) = CredentialRecord::decode(&read_bounded(&e.path(), 2048, true)?) {
                if &r.account_hash == account {
                    out.push(r)
                }
            }
        }
        Ok(out)
    }
    fn path(&self, id: &[u8]) -> PathBuf {
        self.root
            .join(format!("cred-{}", blake3::hash(id).to_hex()))
    }
}

pub fn create_registration_artifact(
    output: &Path,
    device_path: &str,
    policy: &Policy,
    account: &str,
    device_key: &[u8],
    label: &str,
    pin: Option<&Zeroizing<String>>,
) -> Result<Vec<u8>> {
    if device_key.len() != 32 {
        bail!("device key must be 32 bytes")
    }
    let mut client_data = b"YRL native FIDO2 registration v1\0".to_vec();
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    client_data.extend_from_slice(&nonce);
    client_data.extend_from_slice(blake3::hash(account.as_bytes()).as_bytes());
    client_data.extend_from_slice(blake3::hash(device_key).as_bytes());
    let new = hardware_register(device_path, policy, account, device_key, &client_data, pin)?;
    let record = CredentialRecord {
        id: new.id.clone(),
        public_xy: new.public_xy,
        counter: 0,
        account_hash: *blake3::hash(account.as_bytes()).as_bytes(),
        device_hash: *blake3::hash(device_key).as_bytes(),
        uv_required: policy.user_verification,
        revoked: false,
        label: label.to_owned(),
    };
    write_new(output, &record.encode()?, 0o600)?;
    Ok(new.id)
}
pub fn read_registration_artifact(path: &Path) -> Result<CredentialRecord> {
    CredentialRecord::decode(&read_bounded(path, 2048, true)?)
}

#[derive(Clone, Debug)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>,
}

pub fn encode_login_begin(login: &[u8]) -> Result<Vec<u8>> {
    if login.is_empty() || login.len() > crate::wire::MAX_LOGIN {
        bail!("invalid FIDO2 login")
    }
    let mut out = vec![login.len() as u8];
    out.extend_from_slice(login);
    Ok(out)
}
pub fn decode_login_begin(input: &[u8]) -> Result<&[u8]> {
    let n = *input.first().context("short FIDO2 login")? as usize;
    if n == 0 || n > crate::wire::MAX_LOGIN || input.len() != n + 1 {
        bail!("invalid FIDO2 login")
    }
    Ok(&input[1..])
}
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn encode_challenge(
    request_id: u64,
    policy: &Policy,
    challenge: &Challenge,
    credential_ids: &[Vec<u8>],
) -> Result<Vec<u8>> {
    if policy.rp_id.len() > 253
        || challenge.client_data.len() > 256
        || credential_ids.is_empty()
        || credential_ids.len() > MAX_CREDENTIALS_PER_ACCOUNT
    {
        bail!("invalid FIDO2 challenge frame")
    }
    let mut out = request_id.to_be_bytes().to_vec();
    out.push(policy.user_verification as u8);
    out.push(policy.rp_id.len() as u8);
    out.extend_from_slice(policy.rp_id.as_bytes());
    out.extend_from_slice(&(challenge.client_data.len() as u16).to_be_bytes());
    out.extend_from_slice(&challenge.client_data);
    out.push(credential_ids.len() as u8);
    for id in credential_ids {
        if id.is_empty() || id.len() > MAX_CREDENTIAL_ID {
            bail!("invalid credential ID")
        }
        out.extend_from_slice(&(id.len() as u16).to_be_bytes());
        out.extend_from_slice(id);
    }
    Ok(out)
}
pub fn decode_challenge(input: &[u8]) -> Result<(u64, Policy, Vec<u8>, Vec<Vec<u8>>)> {
    if input.len() < 12 {
        bail!("short FIDO2 challenge frame")
    }
    let rid = u64::from_be_bytes(input[..8].try_into()?);
    let uv = input[8] != 0;
    let rn = input[9] as usize;
    if input.len() < 10 + rn + 2 {
        bail!("short FIDO2 RP")
    };
    let rp_id = std::str::from_utf8(&input[10..10 + rn])?.to_owned();
    let mut at = 10 + rn;
    let cn = u16::from_be_bytes(input[at..at + 2].try_into()?) as usize;
    at += 2;
    if cn > 256 || input.len() < at + cn + 1 {
        bail!("invalid FIDO2 challenge size")
    }
    let client = input[at..at + cn].to_vec();
    at += cn;
    let count = input[at] as usize;
    at += 1;
    if count == 0 || count > MAX_CREDENTIALS_PER_ACCOUNT {
        bail!("invalid credential count")
    }
    let mut ids = Vec::new();
    for _ in 0..count {
        if input.len() < at + 2 {
            bail!("short credential ID")
        }
        let n = u16::from_be_bytes(input[at..at + 2].try_into()?) as usize;
        at += 2;
        if n == 0 || n > MAX_CREDENTIAL_ID || input.len() < at + n {
            bail!("invalid credential ID")
        }
        ids.push(input[at..at + n].to_vec());
        at += n;
    }
    if at != input.len() {
        bail!("trailing FIDO2 challenge bytes")
    }
    Ok((
        rid,
        Policy {
            rp_id,
            user_verification: uv,
        },
        client,
        ids,
    ))
}
pub fn encode_assertion(request_id: u64, a: &Assertion) -> Result<Vec<u8>> {
    if a.credential_id.is_empty()
        || a.credential_id.len() > MAX_CREDENTIAL_ID
        || a.auth_data.len() > 1024
        || a.signature.len() > 128
    {
        bail!("invalid FIDO2 assertion frame")
    }
    let mut out = request_id.to_be_bytes().to_vec();
    for b in [&a.credential_id, &a.auth_data, &a.signature] {
        out.extend_from_slice(&(b.len() as u16).to_be_bytes());
        out.extend_from_slice(b);
    }
    Ok(out)
}
pub fn decode_assertion(input: &[u8]) -> Result<(u64, Assertion)> {
    if input.len() < 14 {
        bail!("short FIDO2 assertion frame")
    }
    let rid = u64::from_be_bytes(input[..8].try_into()?);
    let mut at = 8;
    let mut fields = Vec::new();
    for max in [MAX_CREDENTIAL_ID, 1024, 128] {
        let n = u16::from_be_bytes(input[at..at + 2].try_into()?) as usize;
        at += 2;
        if n == 0 || n > max || input.len() < at + n {
            bail!("invalid FIDO2 assertion field")
        }
        fields.push(input[at..at + n].to_vec());
        at += n;
    }
    if at != input.len() {
        bail!("trailing FIDO2 assertion bytes")
    }
    Ok((
        rid,
        Assertion {
            credential_id: fields.remove(0),
            auth_data: fields.remove(0),
            signature: fields.remove(0),
        },
    ))
}

/// Verifies RP hash, UP, optional UV, exact one-use client data, signature and
/// monotonic counter. Counter zero is permitted by WebAuthn for authenticators
/// that do not implement counters; a positive counter may never go backwards.
pub fn verify_assertion(
    policy: &Policy,
    record: &mut CredentialRecord,
    client_data: &[u8],
    assertion: &Assertion,
    require_uv: bool,
) -> Result<()> {
    if record.revoked
        || assertion.credential_id != record.id
        || assertion.auth_data.len() < 37
        || assertion.auth_data.len() > 1024
        || assertion.signature.len() > 128
    {
        bail!("invalid FIDO2 assertion")
    }
    if assertion.auth_data[..32] != Sha256::digest(policy.rp_id.as_bytes())[..] {
        bail!("FIDO2 RP ID mismatch")
    }
    let flags = assertion.auth_data[32];
    if flags & 0x01 == 0 {
        bail!("FIDO2 user presence missing")
    }
    if (require_uv || record.uv_required) && flags & 0x04 == 0 {
        bail!("FIDO2 user verification missing")
    }
    let counter = u32::from_be_bytes(assertion.auth_data[33..37].try_into()?);
    if record.counter != 0 && counter != 0 && counter <= record.counter {
        bail!("FIDO2 signature counter did not advance")
    }
    let mut point = [0u8; 65];
    point[0] = 4;
    point[1..].copy_from_slice(&record.public_xy);
    let key = VerifyingKey::from_sec1_bytes(&point)
        .map_err(|_| anyhow::anyhow!("invalid FIDO2 ES256 public key"))?;
    let sig = Signature::from_der(&assertion.signature)
        .map_err(|_| anyhow::anyhow!("invalid FIDO2 ES256 signature"))?;
    let mut signed = assertion.auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(client_data));
    key.verify(&signed, &sig)
        .map_err(|_| anyhow::anyhow!("FIDO2 assertion signature invalid"))?;
    if counter != 0 {
        record.counter = counter;
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub struct NewCredential {
    pub id: Vec<u8>,
    pub public_xy: [u8; 64],
}

/// Blocking hardware registration via libfido2. Call from `spawn_blocking` in
/// async code. `device_path` comes from libfido2 enumeration, never the server.
pub fn hardware_register(
    device_path: &str,
    policy: &Policy,
    account: &str,
    device_key: &[u8],
    client_data: &[u8],
    pin: Option<&Zeroizing<String>>,
) -> Result<NewCredential> {
    use fido2_rs::credentials::{AttestationFormat, CoseType, Credential, Opt, Protection};
    let dev = fido2_rs::device::Device::open(device_path)?;
    dev.force_fido2();
    let mut cred = Credential::new()?;
    cred.set_client_data(client_data)?;
    cred.set_rp(&policy.rp_id, "YRL")?;
    let mut user = blake3::Hasher::new_derive_key("YRL FIDO2 user handle v1");
    user.update(account.as_bytes());
    user.update(device_key);
    cred.set_user(user.finalize().as_bytes(), account, Some(account), None)?;
    cred.set_cose_type(CoseType::ES256)?;
    cred.set_rk(Opt::False)?;
    cred.set_uv(if policy.user_verification {
        Opt::True
    } else {
        Opt::Omit
    })?;
    if policy.user_verification {
        cred.set_protection(Protection::UvRequired)?;
    }
    cred.set_attestation_format(AttestationFormat::None)?;
    dev.make_credential(&mut cred, pin.map(|p| p.as_str()))?;
    if cred.id().is_empty() || cred.id().len() > MAX_CREDENTIAL_ID || cred.public_key().len() != 64
    {
        bail!("unsupported libfido2 credential result")
    }
    let auth = cred.auth_data_raw();
    if auth.len() < 37
        || auth[..32] != Sha256::digest(policy.rp_id.as_bytes())[..]
        || auth[32] & 0x01 == 0
        || (policy.user_verification && auth[32] & 0x04 == 0)
    {
        bail!("FIDO2 registration lacks required RP, UP, or UV binding")
    }
    Ok(NewCredential {
        id: cred.id().to_vec(),
        public_xy: cred.public_key().try_into().unwrap(),
    })
}

/// Blocking hardware assertion via libfido2. CTAP1 fallback is disabled.
pub fn hardware_assert(
    device_path: &str,
    policy: &Policy,
    credential_id: &[u8],
    client_data: &[u8],
    require_uv: bool,
    pin: Option<&Zeroizing<String>>,
) -> Result<Assertion> {
    hardware_assert_any(
        device_path,
        policy,
        &[credential_id.to_vec()],
        client_data,
        require_uv,
        pin,
    )
}
pub fn hardware_assert_any(
    device_path: &str,
    policy: &Policy,
    credential_ids: &[Vec<u8>],
    client_data: &[u8],
    require_uv: bool,
    pin: Option<&Zeroizing<String>>,
) -> Result<Assertion> {
    use fido2_rs::assertion::AssertRequest;
    use fido2_rs::credentials::Opt;
    let dev = fido2_rs::device::Device::open(device_path)?;
    dev.force_fido2();
    if credential_ids.is_empty() || credential_ids.len() > MAX_CREDENTIALS_PER_ACCOUNT {
        bail!("invalid FIDO2 allow list")
    }
    let mut request = AssertRequest::new()?;
    request.set_client_data(client_data)?;
    request.set_rp(&policy.rp_id)?;
    for id in credential_ids {
        request.set_allow_credential(id)?;
    }
    request.set_up(Opt::True)?;
    request.set_uv(if require_uv { Opt::True } else { Opt::Omit })?;
    let assertions = dev.get_assertion(request, pin.map(|p| p.as_str()))?;
    if assertions.count() != 1 {
        bail!("libfido2 returned an ambiguous assertion set")
    }
    let assertion = assertions.iter().next().unwrap();
    if !credential_ids
        .iter()
        .any(|id| id.as_slice() == assertion.id())
    {
        bail!("libfido2 credential substitution")
    }
    Ok(Assertion {
        credential_id: assertion.id().to_vec(),
        auth_data: cbor_byte_string(assertion.auth_data())?.to_vec(),
        signature: assertion.signature().to_vec(),
    })
}

pub fn list_devices(max: usize) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for d in fido2_rs::device::DeviceList::list_devices(max.min(32))? {
        out.push((
            d.path.to_string_lossy().into_owned(),
            d.product.to_string_lossy().into_owned(),
        ));
    }
    Ok(out)
}

fn cbor_byte_string(input: &[u8]) -> Result<&[u8]> {
    let first = *input.first().context("empty CBOR authenticator data")?;
    if first >> 5 != 2 {
        bail!("authenticator data is not a CBOR byte string")
    }
    let (head, n) = match first & 31 {
        n @ 0..=23 => (1, n as usize),
        24 if input.len() >= 2 => (2, input[1] as usize),
        25 if input.len() >= 3 => (3, u16::from_be_bytes([input[1], input[2]]) as usize),
        _ => bail!("unsupported or indefinite CBOR authenticator data"),
    };
    if input.len() != head + n {
        bail!("malformed CBOR authenticator data")
    }
    Ok(&input[head..])
}

fn read_bounded(path: &Path, max: usize, private: bool) -> Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = f.metadata()?;
    if !m.is_file()
        || m.nlink() != 1
        || m.len() as usize > max
        || (private && m.mode() & 0o077 != 0)
    {
        bail!("unsafe FIDO2 state file")
    }
    let mut out = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut out)?;
    if out.len() > max {
        bail!("oversized FIDO2 state file")
    }
    Ok(out)
}
fn write_new(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
fn atomic_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("state path has no parent")?;
    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);
    let tmp = parent.join(format!(".fido-{}.tmp", hex::encode(nonce)));
    write_new(&tmp, bytes, 0o600)?;
    let result = (|| -> Result<()> {
        fs::rename(&tmp, path)?;
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn challenge_is_context_bound_and_one_use() {
        let dir = tempfile::tempdir().unwrap();
        let s = ChallengeStore::open(dir.path()).unwrap();
        let c = s
            .issue(
                Ceremony::RootStepUp,
                b"alice",
                &[1; 32],
                b"restart:ssh",
                100,
                30,
                true,
            )
            .unwrap();
        assert!(s
            .consume(
                &c.client_data,
                Ceremony::RootStepUp,
                b"alice",
                &[1; 32],
                b"restart:other",
                101
            )
            .is_err());
        assert!(s
            .consume(
                &c.client_data,
                Ceremony::RootStepUp,
                b"alice",
                &[1; 32],
                b"restart:ssh",
                101
            )
            .is_err());
    }
    #[test]
    fn assertion_requires_up_uv_rp_signature_and_counter() {
        use p256::ecdsa::signature::Signer as _;
        let signing = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let point = signing.verifying_key().to_encoded_point(false);
        let xy: [u8; 64] = point.as_bytes()[1..].try_into().unwrap();
        let policy = Policy {
            rp_id: "yrl.local".into(),
            user_verification: true,
        };
        let client = b"bound challenge";
        let mut auth = Sha256::digest(policy.rp_id.as_bytes()).to_vec();
        auth.push(0x05);
        auth.extend_from_slice(&1u32.to_be_bytes());
        let mut message = auth.clone();
        message.extend_from_slice(&Sha256::digest(client));
        let sig: p256::ecdsa::Signature = signing.sign(&message);
        let mut record = CredentialRecord {
            id: vec![7; 32],
            public_xy: xy,
            counter: 0,
            account_hash: [1; 32],
            device_hash: [2; 32],
            uv_required: true,
            revoked: false,
            label: "token".into(),
        };
        let assertion = Assertion {
            credential_id: record.id.clone(),
            auth_data: auth,
            signature: sig.to_der().as_bytes().to_vec(),
        };
        verify_assertion(&policy, &mut record, client, &assertion, true).unwrap();
        assert_eq!(record.counter, 1);
        assert!(verify_assertion(&policy, &mut record, client, &assertion, true).is_err());
    }
}
