//! Offline-rooted signed release metadata.  This module never downloads or executes artifacts.
use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};
use zeroize::Zeroizing;

pub const MANIFEST_MAGIC: &str = "YRL-RELEASE-MANIFEST-1";

fn atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    if path.exists() {
        bail!("destination already exists: {}", path.display());
    }
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
    File::open(path.parent().context("path has no parent")?)?.sync_all()?;
    Ok(())
}

pub fn generate_key(private: &Path, public: &Path) -> Result<()> {
    let key = SigningKey::generate(&mut argon2::password_hash::rand_core::OsRng);
    let secret = Zeroizing::new(format!("{}\n", hex::encode(key.to_bytes())));
    atomic(private, secret.as_bytes(), 0o600)?;
    atomic(
        public,
        format!("{}\n", hex::encode(key.verifying_key().to_bytes())).as_bytes(),
        0o644,
    )
}

#[derive(Clone)]
pub enum ReleasePublic {
    Classical(VerifyingKey),
    #[cfg(feature = "hybrid-signatures")]
    Hybrid(Box<crate::hybrid_signature::PublicKey>),
}
impl std::fmt::Debug for ReleasePublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "release public key {}", blake3::hash(&self.to_bytes()))
    }
}
impl PartialEq for ReleasePublic {
    fn eq(&self, other: &Self) -> bool { self.to_bytes() == other.to_bytes() }
}
impl ReleasePublic {
    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Classical(key) => key.to_bytes().to_vec(),
            #[cfg(feature = "hybrid-signatures")]
            Self::Hybrid(key) => key.encode(),
        }
    }

    fn decode(bytes: &[u8], root: bool, generation: Option<u64>) -> Result<Self> {
        if bytes.len() == 32 {
            return Ok(Self::Classical(VerifyingKey::from_bytes(bytes.try_into()?)?));
        }
        #[cfg(feature = "hybrid-signatures")]
        {
            use crate::hybrid_signature::{PublicKey, Purpose};
            let key = PublicKey::decode(bytes)?;
            let purpose = if root { Purpose::ReleaseRoot } else { Purpose::ReleaseDelegated };
            if key.purpose != purpose || generation.is_some_and(|g| key.generation != g) {
                bail!("wrong hybrid release key purpose or generation");
            }
            return Ok(Self::Hybrid(Box::new(key)));
        }
        #[cfg(not(feature = "hybrid-signatures"))]
        {
            let _ = (root, generation);
            bail!("unsupported release public key format");
        }
    }

    fn same_profile(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }

    fn verify(&self, body: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            Self::Classical(key) => Ok(key.verify(body, &Signature::from_slice(signature)?)?),
            #[cfg(feature = "hybrid-signatures")]
            Self::Hybrid(key) => key.verify(body, &crate::hybrid_signature::SignatureEnvelope::decode(signature)?),
        }
    }
}

enum ReleaseSecret {
    Classical(SigningKey),
    #[cfg(feature = "hybrid-signatures")]
    Hybrid(Box<crate::hybrid_signature::SigningKey>),
}
impl ReleaseSecret {
    fn load(path: &Path, public: &ReleasePublic) -> Result<Self> {
        match public {
            ReleasePublic::Classical(key) => {
                let seed = crate::keys::read_secret_hex(path, 32)?;
                let secret = SigningKey::from_bytes(seed.as_slice().try_into()?);
                if secret.verifying_key() != *key { bail!("release private key mismatch"); }
                Ok(Self::Classical(secret))
            }
            #[cfg(feature = "hybrid-signatures")]
            ReleasePublic::Hybrid(key) => Ok(Self::Hybrid(Box::new(crate::hybrid_signature::SigningKey::load_pinned(path, key)?))),
        }
    }

    fn sign(&self, body: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Classical(key) => Ok(key.sign(body).to_bytes().to_vec()),
            #[cfg(feature = "hybrid-signatures")]
            Self::Hybrid(key) => Ok(key.sign(body)?.encode()),
        }
    }
}

fn verifying(path: &Path, root: bool, generation: u64) -> Result<ReleasePublic> {
    let bytes = fs::read(path)?;
    if bytes.starts_with(b"YHP1") {
        ReleasePublic::decode(&bytes, root, Some(generation))
    } else {
        ReleasePublic::decode(&hex::decode(std::str::from_utf8(&bytes)?.trim())?, root, Some(generation))
    }
}

#[derive(Clone)]
pub struct TrustStore {
    pub generation: u64,
    pub current: ReleasePublic,
    pub roots: BTreeMap<u64, ReleasePublic>,
    pub minimum_root: u64,
    pub revoked_delegates: BTreeSet<(u64, String)>,
}

fn optional_log(path: &Path) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(log) => Ok(log),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e.into()),
    }
}

#[cfg(feature = "hybrid-signatures")]
fn release_recovery_key(path: &Path) -> Result<crate::hybrid_signature::PublicKey> {
    crate::hybrid_signature::PublicKey::load_file(path, crate::hybrid_signature::Purpose::Recovery)
}

#[cfg(feature = "hybrid-signatures")]
pub fn register_root_recovery(trust: &Path, public: &Path) -> Result<()> {
    if !matches!(load_trust(trust)?.current, ReleasePublic::Hybrid(_)) {
        bail!("recovery requires a hybrid release trust store");
    }
    atomic(&trust.join("recovery.pub"), &release_recovery_key(public)?.encode(), 0o644)
}

#[cfg(feature = "hybrid-signatures")]
pub fn recover_root(trust: &Path, recovery_private: &Path, new_private: &Path, new_public: &Path) -> Result<()> {
    use crate::hybrid_signature::{Purpose, SigningKey};
    let store = load_trust(trust)?;
    let ReleasePublic::Hybrid(old) = store.current else { bail!("recovery requires hybrid release trust"); };
    let recovery = release_recovery_key(&trust.join("recovery.pub"))?;
    let recovery = SigningKey::load_pinned(recovery_private, &recovery)?;
    let generation = store.generation.checked_add(1).context("release root generation overflow")?;
    let new = SigningKey::generate_files(new_private, new_public, Purpose::ReleaseRoot, generation)?;
    let private = SigningKey::load_pinned(new_private, &new)?;
    let body = format!(
        "YRL-RELEASE-ROOT-RECOVERY-1 {} {} {generation} {}",
        store.generation, hex::encode(old.encode()), hex::encode(new.encode())
    );
    publish_root(trust, generation, &new.encode(), &format!(
        "{body} {} {}\n", hex::encode(recovery.sign(body.as_bytes())?.encode()),
        hex::encode(private.sign(body.as_bytes())?.encode()),
    ))
}

pub fn init_trust(root_public: &Path, trust_dir: &Path) -> Result<()> {
    if trust_dir.exists() {
        bail!("release trust directory already exists");
    }
    fs::create_dir(trust_dir)?;
    fs::set_permissions(trust_dir, fs::Permissions::from_mode(0o755))?;
    let key = verifying(root_public, true, 0)?;
    atomic(
        &trust_dir.join("root.pub"),
        format!("{}\n", hex::encode(key.to_bytes())).as_bytes(),
        0o644,
    )?;
    atomic(
        &trust_dir.join("current.pub"),
        format!("0 {}\n", hex::encode(key.to_bytes())).as_bytes(),
        0o644,
    )
}

pub fn rotate_root(
    trust_dir: &Path,
    old_private: &Path,
    new_private: &Path,
    new_public: &Path,
) -> Result<()> {
    let store = load_trust(trust_dir)?;
    let old = ReleaseSecret::load(old_private, &store.current)?;
    let generation = store.generation.checked_add(1).context("release root generation overflow")?;
    match &store.current {
        ReleasePublic::Classical(_) => generate_key(new_private, new_public)?,
        #[cfg(feature = "hybrid-signatures")]
        ReleasePublic::Hybrid(_) => {
            crate::hybrid_signature::SigningKey::generate_files(new_private, new_public, crate::hybrid_signature::Purpose::ReleaseRoot, generation)?;
        }
    }
    let public = verifying(new_public, true, generation)?;
    let new = ReleaseSecret::load(new_private, &public)?;
    let body = format!(
        "YRL-RELEASE-ROOT-TRANSITION-1 {} {} {} {}",
        store.generation,
        hex::encode(store.current.to_bytes()),
        generation,
        hex::encode(public.to_bytes())
    );
    let line = format!(
        "{body} {} {}\n",
        hex::encode(old.sign(body.as_bytes())?),
        hex::encode(new.sign(body.as_bytes())?)
    );
    publish_root(trust_dir, generation, &public.to_bytes(), &line)
}

fn publish_root(trust_dir: &Path, generation: u64, public: &[u8], line: &str) -> Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o644)
        .open(trust_dir.join("root-transitions.log"))?;
    f.write_all(line.as_bytes())?;
    f.sync_data()?;
    let current = trust_dir.join("current.pub");
    let tmp = current.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(
        &tmp,
        format!(
            "{generation} {}\n",
            hex::encode(public)
        ),
    )?;
    File::open(&tmp)?.sync_all()?;
    fs::rename(tmp, current)?;
    File::open(trust_dir)?.sync_all()?;
    Ok(())
}

pub fn load_trust(dir: &Path) -> Result<TrustStore> {
    let root = verifying(&dir.join("root.pub"), true, 0)?;
    let mut roots = BTreeMap::new();
    roots.insert(0, root);
    let mut minimum_root = 0;
    for line in optional_log(&dir.join("root-transitions.log"))?.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() != 7 || !matches!(f[0], "YRL-RELEASE-ROOT-TRANSITION-1" | "YRL-RELEASE-ROOT-RECOVERY-1") {
            bail!("invalid release root transition");
        }
        let og: u64 = f[1].parse()?;
        let ng: u64 = f[3].parse()?;
        if og.checked_add(1) != Some(ng) || roots.contains_key(&ng) {
            bail!("non-monotonic release root generation");
        }
        let old = ReleasePublic::decode(&hex::decode(f[2])?, true, Some(og))?;
        let new = ReleasePublic::decode(&hex::decode(f[4])?, true, Some(ng))?;
        if roots.get(&og) != Some(&old) || !old.same_profile(&new) {
            bail!("detached release root transition or profile change");
        }
        let body = format!("{} {og} {} {ng} {}", f[0], f[2], f[4]);
        if f[0] == "YRL-RELEASE-ROOT-RECOVERY-1" {
            #[cfg(feature = "hybrid-signatures")]
            {
                if !matches!(old, ReleasePublic::Hybrid(_)) {
                    bail!("recovery requires hybrid release trust");
                }
                let recovery = release_recovery_key(&dir.join("recovery.pub"))?;
                recovery.verify(body.as_bytes(), &crate::hybrid_signature::SignatureEnvelope::decode(&hex::decode(f[5])?)?)?;
                minimum_root = ng;
            }
            #[cfg(not(feature = "hybrid-signatures"))]
            bail!("unsupported release root recovery");
        } else {
            old.verify(body.as_bytes(), &hex::decode(f[5])?)?;
        }
        new.verify(
            body.as_bytes(),
            &hex::decode(f[6])?,
        )?;
        roots.insert(ng, new);
    }
    let current_fields: Vec<_> = fs::read_to_string(dir.join("current.pub"))?
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    if current_fields.len() != 2 {
        bail!("invalid current release root");
    }
    let generation: u64 = current_fields[0].parse()?;
    let current = ReleasePublic::decode(&hex::decode(&current_fields[1])?, true, Some(generation))?;
    if roots.get(&generation) != Some(&current) {
        bail!("release trust store was rolled back or detached");
    }
    // The signed history is authoritative if publication was interrupted
    // after syncing it and before replacing current.pub.
    let (generation, current) = roots.last_key_value().context("release trust has no root")?;
    let (generation, current) = (*generation, current.clone());
    let mut revoked_delegates = BTreeSet::new();
    for line in optional_log(&dir.join("revocations.log"))?.lines() {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() != 6 || f[0] != "YRL-RELEASE-REVOKE-1" {
            bail!("invalid release revocation");
        }
        let rg: u64 = f[1].parse()?;
        let dg: u64 = f[2].parse()?;
        let signer = roots.get(&rg).context("unknown revocation root")?;
        let body = format!("YRL-RELEASE-REVOKE-1 {rg} {dg} {} {}", f[3], f[4]);
        signer.verify(
            body.as_bytes(),
            &hex::decode(f[5])?,
        )?;
        revoked_delegates.insert((dg, f[3].to_owned()));
    }
    Ok(TrustStore {
        generation,
        current,
        roots,
        minimum_root,
        revoked_delegates,
    })
}

#[derive(Clone, Debug)]
pub struct Delegation {
    pub root_generation: u64,
    pub generation: u64,
    pub public: ReleasePublic,
    pub valid_from: u64,
    pub valid_until: u64,
    pub min_release: u64,
    pub max_release: u64,
}
impl Delegation {
    fn body(&self) -> String {
        format!(
            "YRL-RELEASE-DELEGATION-1 {} {} {} {} {} {} {}",
            self.root_generation,
            self.generation,
            hex::encode(self.public.to_bytes()),
            self.valid_from,
            self.valid_until,
            self.min_release,
            self.max_release
        )
    }
}

pub fn delegate(
    trust_dir: &Path,
    root_private: &Path,
    delegate_public: &Path,
    generation: u64,
    valid_from: u64,
    valid_until: u64,
    min_release: u64,
    max_release: u64,
    output: &Path,
) -> Result<()> {
    if valid_until <= valid_from || max_release < min_release {
        bail!("invalid delegation bounds");
    }
    let store = load_trust(trust_dir)?;
    let root = ReleaseSecret::load(root_private, &store.current)?;
    let d = Delegation {
        root_generation: store.generation,
        generation,
        public: verifying(delegate_public, false, generation)?,
        valid_from,
        valid_until,
        min_release,
        max_release,
    };
    if !store.current.same_profile(&d.public) { bail!("release delegation changes signature profile"); }
    let body = d.body();
    atomic(
        output,
        format!(
            "{body} {}\n",
            hex::encode(root.sign(body.as_bytes())?)
        )
        .as_bytes(),
        0o644,
    )
}

pub fn parse_delegation(path: &Path, store: &TrustStore) -> Result<Delegation> {
    let text = fs::read_to_string(path)?;
    let f: Vec<_> = text.split_whitespace().collect();
    if f.len() != 9 || f[0] != "YRL-RELEASE-DELEGATION-1" {
        bail!("invalid release delegation");
    }
    let d = Delegation {
        root_generation: f[1].parse()?,
        generation: f[2].parse()?,
        public: ReleasePublic::decode(&hex::decode(f[3])?, false, Some(f[2].parse()?))?,
        valid_from: f[4].parse()?,
        valid_until: f[5].parse()?,
        min_release: f[6].parse()?,
        max_release: f[7].parse()?,
    };
    let root = store
        .roots
        .get(&d.root_generation)
        .context("delegation uses unknown root")?;
    if d.root_generation < store.minimum_root {
        bail!("delegation uses a root retired by emergency recovery");
    }
    if !root.same_profile(&d.public) { bail!("release delegation changes signature profile"); }
    root.verify(
        d.body().as_bytes(),
        &hex::decode(f[8])?,
    )?;
    if store
        .revoked_delegates
        .contains(&(d.generation, hex::encode(d.public.to_bytes())))
    {
        bail!("release delegation was revoked");
    }
    Ok(d)
}

pub fn revoke_delegate(
    trust_dir: &Path,
    root_private: &Path,
    generation: u64,
    delegate_public: &Path,
    at: u64,
) -> Result<()> {
    let store = load_trust(trust_dir)?;
    let root = ReleaseSecret::load(root_private, &store.current)?;
    let public = verifying(delegate_public, false, generation)?;
    let body = format!(
        "YRL-RELEASE-REVOKE-1 {} {generation} {} {at}",
        store.generation,
        hex::encode(public.to_bytes())
    );
    let line = format!(
        "{body} {}\n",
        hex::encode(root.sign(body.as_bytes())?)
    );
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o644)
        .open(trust_dir.join("revocations.log"))?;
    f.write_all(line.as_bytes())?;
    f.sync_data()?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub number: u64,
    pub version: String,
    pub platform: String,
    pub arch: String,
    pub data_min: u32,
    pub data_max: u32,
    pub data_target: u32,
    pub created: u64,
    pub expires: u64,
    pub delegation: u64,
    pub files: Vec<(String, u64, [u8; 32])>,
}
impl Manifest {
    pub fn encode(&self) -> Vec<u8> {
        let mut s = format!(
            "{MANIFEST_MAGIC} {} {} {} {} {} {} {} {} {} {} {}\n",
            self.number,
            self.version,
            self.platform,
            self.arch,
            self.data_min,
            self.data_max,
            self.data_target,
            self.created,
            self.expires,
            self.delegation,
            self.files.len()
        );
        for (p, n, h) in &self.files {
            s.push_str(&format!("F {n} {} {p}\n", hex::encode(h)));
        }
        s.into_bytes()
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes)?;
        let mut lines = text.lines();
        let h: Vec<_> = lines
            .next()
            .context("empty release manifest")?
            .split_whitespace()
            .collect();
        if h.len() != 12 || h[0] != MANIFEST_MAGIC {
            bail!("invalid release manifest header");
        }
        let count: usize = h[11].parse()?;
        let mut files = Vec::new();
        for line in lines {
            let f: Vec<_> = line.split_whitespace().collect();
            if f.len() != 4 || f[0] != "F" {
                bail!("invalid release file entry");
            }
            let path = f[3].to_owned();
            validate_rel(&path)?;
            files.push((
                path,
                f[1].parse()?,
                hex::decode(f[2])?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid artifact hash"))?,
            ));
        }
        if files.len() != count || !files.windows(2).all(|w| w[0].0 < w[1].0) {
            bail!("release file set is incomplete, duplicated or unsorted");
        }
        Ok(Self {
            number: h[1].parse()?,
            version: h[2].into(),
            platform: h[3].into(),
            arch: h[4].into(),
            data_min: h[5].parse()?,
            data_max: h[6].parse()?,
            data_target: h[7].parse()?,
            created: h[8].parse()?,
            expires: h[9].parse()?,
            delegation: h[10].parse()?,
            files,
        })
    }
}

fn validate_rel(s: &str) -> Result<()> {
    let p = Path::new(s);
    if s.is_empty()
        || s.bytes().any(|b| b.is_ascii_whitespace())
        || p.is_absolute()
        || p.components().any(|c| !matches!(c, Component::Normal(_)))
    {
        bail!("unsafe release artifact path");
    }
    Ok(())
}

pub fn create_manifest(
    artifacts: &Path,
    number: u64,
    version: &str,
    platform: &str,
    arch: &str,
    data_min: u32,
    data_max: u32,
    data_target: u32,
    created: u64,
    expires: u64,
    delegation: u64,
    output: &Path,
) -> Result<()> {
    if number == 0
        || expires <= created
        || data_max < data_min
        || data_target < data_min
        || data_target > data_max
    {
        bail!("invalid release metadata bounds");
    }
    for v in [version, platform, arch] {
        if v.is_empty()
            || v.bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
        {
            bail!("unsafe release metadata text");
        }
    }
    let mut files = Vec::new();
    for e in fs::read_dir(artifacts)? {
        let e = e?;
        let m = fs::symlink_metadata(e.path())?;
        if !m.is_file() || m.nlink() != 1 {
            bail!("release artifacts must be regular single-link files");
        }
        let name = e
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF8 artifact"))?;
        validate_rel(&name)?;
        let bytes = fs::read(e.path())?;
        files.push((name, m.len(), *blake3::hash(&bytes).as_bytes()));
    }
    files.sort_by(|a, b| a.0.cmp(&b.0));
    if files.is_empty() {
        bail!("release has no artifacts");
    }
    atomic(
        output,
        &Manifest {
            number,
            version: version.into(),
            platform: platform.into(),
            arch: arch.into(),
            data_min,
            data_max,
            data_target,
            created,
            expires,
            delegation,
            files,
        }
        .encode(),
        0o644,
    )
}

pub fn sign_manifest(
    manifest: &Path,
    delegation: &Path,
    delegate_private: &Path,
    signature: &Path,
    trust: &Path,
) -> Result<()> {
    let store = load_trust(trust)?;
    let d = parse_delegation(delegation, &store)?;
    let key = ReleaseSecret::load(delegate_private, &d.public)?;
    let bytes = fs::read(manifest)?;
    let m = Manifest::parse(&bytes)?;
    if m.delegation != d.generation || m.number < d.min_release || m.number > d.max_release {
        bail!("manifest is outside delegation scope");
    }
    atomic(
        signature,
        format!("{}\n", hex::encode(key.sign(&bytes)?)).as_bytes(),
        0o644,
    )
}

pub fn verify_release(
    artifacts: &Path,
    manifest: &Path,
    signature: &Path,
    delegation: &Path,
    trust: &Path,
    now: u64,
) -> Result<Manifest> {
    let store = load_trust(trust)?;
    let d = parse_delegation(delegation, &store)?;
    if now < d.valid_from || now > d.valid_until {
        bail!("release delegation is not currently valid");
    }
    let bytes = fs::read(manifest)?;
    let m = Manifest::parse(&bytes)?;
    if now < m.created || now > m.expires {
        bail!("release metadata is not currently valid");
    }
    if m.delegation != d.generation || m.number < d.min_release || m.number > d.max_release {
        bail!("release is outside delegated scope");
    }
    let sig = hex::decode(fs::read_to_string(signature)?.trim())?;
    d.public.verify(&bytes, &sig)?;
    let mut actual = BTreeSet::new();
    for e in fs::read_dir(artifacts)? {
        let e = e?;
        let name = e
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("non-UTF8 artifact"))?;
        let mta = fs::symlink_metadata(e.path())?;
        if !mta.is_file() || mta.nlink() != 1 {
            bail!("unsafe release artifact");
        }
        actual.insert(name);
    }
    let expected: BTreeSet<_> = m.files.iter().map(|x| x.0.clone()).collect();
    if actual != expected {
        bail!("release component set does not match manifest");
    }
    for (path, size, hash) in &m.files {
        let p = artifacts.join(path);
        let meta = fs::symlink_metadata(&p)?;
        if meta.len() != *size || *blake3::hash(&fs::read(&p)?).as_bytes() != *hash {
            bail!("release artifact mismatch: {path}");
        }
    }
    Ok(m)
}
