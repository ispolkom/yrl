//! RFC 9807 OPAQUE using the standardized Ristretto255-SHA512 suite.
//!
//! This module deliberately exposes protocol messages, not a password verifier.
//! The server never receives the password.  Applications must supply the same
//! account/device/role/channel context at both ends; `opaque-ke` authenticates
//! it as the TripleDH context.
use anyhow::{bail, Context, Result};
use opaque_ke::argon2::Argon2;
use opaque_ke::ciphersuite::CipherSuite;
use argon2::password_hash::rand_core::{OsRng, RngCore};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialFinalization, CredentialRequest,
    CredentialResponse, Identifiers, RegistrationRequest, RegistrationResponse,
    RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration,
    ServerSetup,
};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

pub const SUITE_ID: &str = "OPAQUE-3DH-Ristretto255-SHA512-Argon2id-RFC9807";
pub const MAX_MESSAGE: usize = 4096;
const FORMAT: &[u8] = b"YRL-OPAQUE-1\0";

pub struct YrlSuite;
impl CipherSuite for YrlSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

pub type Setup = ServerSetup<YrlSuite>;
pub type Record = ServerRegistration<YrlSuite>;

/// Canonical, length-delimited binding.  It prevents account, device, server
/// role, profile, and Noise-channel substitution without logging any secret.
pub fn context(account: &[u8], device_key: &[u8], server_role: &[u8], profile: u32, channel: &[u8]) -> Result<Vec<u8>> {
    if account.is_empty() || account.len() > crate::wire::MAX_LOGIN || device_key.len() > 128 || server_role.is_empty() || server_role.len() > 32 || channel.len() > 64 {
        bail!("invalid OPAQUE context field");
    }
    let mut out = b"YRL OPAQUE channel binding v1\0".to_vec();
    for field in [account, device_key, server_role, channel] {
        out.extend_from_slice(&(field.len() as u16).to_be_bytes());
        out.extend_from_slice(field);
    }
    out.extend_from_slice(&profile.to_be_bytes());
    Ok(out)
}

fn ids<'a>(account: &'a [u8], role: &'a [u8]) -> Identifiers<'a> {
    Identifiers { client: Some(account), server: Some(role) }
}

pub struct ClientRegistrationState {
    inner: ClientRegistration<YrlSuite>,
}
pub struct ClientLoginState {
    inner: ClientLogin<YrlSuite>,
}
pub struct ServerLoginState {
    inner: ServerLogin<YrlSuite>,
}

pub fn registration_start(password: &[u8]) -> Result<(ClientRegistrationState, Vec<u8>)> {
    if password.len() < 8 || password.len() > crate::wire::MAX_PASSWORD { bail!("password outside configured bounds") }
    let mut rng = OsRng;
    let r = ClientRegistration::<YrlSuite>::start(&mut rng, password).map_err(|e| anyhow::anyhow!("OPAQUE registration start: {e}"))?;
    Ok((ClientRegistrationState { inner: r.state }, r.message.serialize().to_vec()))
}

pub fn registration_response(setup: &Setup, account: &[u8], request: &[u8]) -> Result<Vec<u8>> {
    bounded(request)?;
    let request = RegistrationRequest::deserialize(request).map_err(|e| anyhow::anyhow!("bad OPAQUE registration request: {e}"))?;
    let r = ServerRegistration::<YrlSuite>::start(setup, request, account).map_err(|e| anyhow::anyhow!("OPAQUE registration response: {e}"))?;
    Ok(r.message.serialize().to_vec())
}

pub fn registration_finish(state: ClientRegistrationState, password: &[u8], account: &[u8], role: &[u8], response: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    bounded(response)?;
    let response = RegistrationResponse::deserialize(response).map_err(|e| anyhow::anyhow!("bad OPAQUE registration response: {e}"))?;
    let mut rng = OsRng;
    let argon = Argon2::default();
    let r = state.inner.finish(&mut rng, password, response, ClientRegistrationFinishParameters::new(ids(account, role), Some(&argon))).map_err(|e| anyhow::anyhow!("OPAQUE registration finish: {e}"))?;
    Ok((r.message.serialize().to_vec(), Zeroizing::new(r.export_key.to_vec())))
}

pub fn registration_store(upload: &[u8]) -> Result<Record> {
    bounded(upload)?;
    let upload = RegistrationUpload::deserialize(upload).map_err(|e| anyhow::anyhow!("bad OPAQUE registration upload: {e}"))?;
    Ok(ServerRegistration::finish(upload))
}

pub fn login_start(password: &[u8]) -> Result<(ClientLoginState, Vec<u8>)> {
    if password.len() > crate::wire::MAX_PASSWORD { bail!("password outside configured bounds") }
    let mut rng = OsRng;
    let r = ClientLogin::<YrlSuite>::start(&mut rng, password).map_err(|e| anyhow::anyhow!("OPAQUE login start: {e}"))?;
    Ok((ClientLoginState { inner: r.state }, r.message.serialize().to_vec()))
}

/// `record == None` intentionally produces an indistinguishable fake response.
pub fn login_response(setup: &Setup, record: Option<Record>, account: &[u8], role: &[u8], binding: &[u8], request: &[u8]) -> Result<(ServerLoginState, Vec<u8>)> {
    bounded(request)?;
    let request = CredentialRequest::deserialize(request).map_err(|e| anyhow::anyhow!("bad OPAQUE credential request: {e}"))?;
    let mut rng = OsRng;
    let params = ServerLoginParameters { context: Some(binding), identifiers: ids(account, role) };
    let r = ServerLogin::start(&mut rng, setup, record, request, account, params).map_err(|e| anyhow::anyhow!("OPAQUE login response: {e}"))?;
    Ok((ServerLoginState { inner: r.state }, r.message.serialize().to_vec()))
}

pub fn login_client_finish(state: ClientLoginState, password: &[u8], account: &[u8], role: &[u8], binding: &[u8], response: &[u8]) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    bounded(response)?;
    let response = CredentialResponse::deserialize(response).map_err(|e| anyhow::anyhow!("bad OPAQUE credential response: {e}"))?;
    let mut rng = OsRng;
    let argon = Argon2::default();
    let params = ClientLoginFinishParameters::new(Some(binding), ids(account, role), Some(&argon));
    let r = state.inner.finish(&mut rng, password, response, params).map_err(|e| anyhow::anyhow!("OPAQUE authentication failed: {e}"))?;
    Ok((r.message.serialize().to_vec(), Zeroizing::new(r.session_key.to_vec())))
}

pub fn login_server_finish(state: ServerLoginState, account: &[u8], role: &[u8], binding: &[u8], finalization: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    bounded(finalization)?;
    let finalization = CredentialFinalization::deserialize(finalization).map_err(|e| anyhow::anyhow!("bad OPAQUE finalization: {e}"))?;
    let params = ServerLoginParameters { context: Some(binding), identifiers: ids(account, role) };
    let r = state.inner.finish(finalization, params).map_err(|e| anyhow::anyhow!("OPAQUE authentication failed: {e}"))?;
    Ok(Zeroizing::new(r.session_key.to_vec()))
}

fn bounded(m: &[u8]) -> Result<()> {
    if m.is_empty() || m.len() > MAX_MESSAGE { bail!("OPAQUE message outside bounds") }
    Ok(())
}

pub struct Store { root: PathBuf, setup: Setup }
impl Store {
    /// Explicit initialization.  Services never silently replace missing state.
    pub fn init(root: &Path) -> Result<()> {
        fs::create_dir_all(root)?;
        fs::set_permissions(root, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
        if fs::symlink_metadata(root.join("setup")).is_ok() { bail!("OPAQUE server state already exists") }
        let mut rng = OsRng;
        let setup = Setup::new(&mut rng);
        atomic_private(&root.join("setup"), &setup.serialize())
    }
    pub fn open(root: &Path) -> Result<Self> {
        let bytes = Zeroizing::new(read_private(&root.join("setup"), 4096)?);
        let setup = Setup::deserialize(&bytes).map_err(|e| anyhow::anyhow!("invalid OPAQUE setup: {e}"))?;
        Ok(Self { root: root.to_owned(), setup })
    }
    pub fn setup(&self) -> &Setup { &self.setup }
    pub fn load(&self, account: &[u8]) -> Result<Option<Record>> {
        let path = self.record_path(account);
        let bytes = match read_private(&path, 4096) { Ok(v) => v, Err(e) if e.downcast_ref::<std::io::Error>().is_some_and(|x| x.kind() == std::io::ErrorKind::NotFound) => return Ok(None), Err(e) => return Err(e) };
        if !bytes.starts_with(FORMAT) || bytes.len() < FORMAT.len() + 32 { bail!("invalid OPAQUE record envelope") }
        let expected = blake3::hash(account);
        if bytes[FORMAT.len()..FORMAT.len()+32] != *expected.as_bytes() { bail!("OPAQUE record/account mismatch") }
        Record::deserialize(&bytes[FORMAT.len()+32..]).map(Some).map_err(|e| anyhow::anyhow!("invalid OPAQUE record: {e}"))
    }
    pub fn save(&self, account: &[u8], record: &Record) -> Result<()> {
        let mut bytes = FORMAT.to_vec();
        bytes.extend_from_slice(blake3::hash(account).as_bytes());
        bytes.extend_from_slice(&record.serialize());
        let result = atomic_private(&self.record_path(account), &bytes);
        bytes.zeroize();
        result
    }
    fn record_path(&self, account: &[u8]) -> PathBuf { self.root.join(format!("record-{}", blake3::hash(account).to_hex())) }
}

fn read_private(path: &Path, max: usize) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.nlink() != 1 || meta.mode() & 0o077 != 0 || meta.len() as usize > max { bail!("unsafe OPAQUE state file") }
    let f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(path)?;
    let mut bytes = Vec::new();
    std::io::Read::take(f, max as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > max { bail!("oversized OPAQUE state file") }
    Ok(bytes)
}

fn atomic_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("OPAQUE path has no parent")?;
    fs::create_dir_all(parent)?;
    let mut nonce = [0u8; 8]; OsRng.fill_bytes(&mut nonce);
    let tmp = parent.join(format!(".opaque-{}.tmp", hex::encode(nonce)));
    let mut f = OpenOptions::new().create_new(true).write(true).mode(0o600).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&tmp)?;
    let result = (|| -> Result<()> { f.write_all(bytes)?; f.sync_all()?; fs::rename(&tmp, path)?; fs::File::open(parent)?.sync_all()?; Ok(()) })();
    if result.is_err() { let _ = fs::remove_file(&tmp); }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc9807_flow_and_context_mismatch() {
        let mut rng = OsRng;
        let setup = Setup::new(&mut rng);
        let (cr, request) = registration_start(b"correct horse battery staple").unwrap();
        let response = registration_response(&setup, b"alice", &request).unwrap();
        let (upload, _) = registration_finish(cr, b"correct horse battery staple", b"alice", b"executor", &response).unwrap();
        let record = registration_store(&upload).unwrap();
        let binding = context(b"alice", &[7; 32], b"executor", 0x10001, &[9; 32]).unwrap();
        let (cl, ke1) = login_start(b"correct horse battery staple").unwrap();
        let (sl, ke2) = login_response(&setup, Some(record), b"alice", b"executor", &binding, &ke1).unwrap();
        let (ke3, ck) = login_client_finish(cl, b"correct horse battery staple", b"alice", b"executor", &binding, &ke2).unwrap();
        let sk = login_server_finish(sl, b"alice", b"executor", &binding, &ke3).unwrap();
        assert_eq!(&*ck, &*sk);
    }
}
