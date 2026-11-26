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

fn signing(path: &Path) -> Result<SigningKey> {
    let seed = crate::keys::read_secret_hex(path, 32)?;
    Ok(SigningKey::from_bytes(seed.as_slice().try_into()?))
}
fn verifying(path: &Path) -> Result<VerifyingKey> {
    let b: [u8; 32] = hex::decode(fs::read_to_string(path)?.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
    Ok(VerifyingKey::from_bytes(&b)?)
}

#[derive(Clone)]
pub struct TrustStore {
    pub generation: u64,
    pub current: VerifyingKey,
    pub roots: BTreeMap<u64, VerifyingKey>,
    pub revoked_delegates: BTreeSet<(u64, String)>,
}

pub fn init_trust(root_public: &Path, trust_dir: &Path) -> Result<()> {
    if trust_dir.exists() {
        bail!("release trust directory already exists");
    }
    fs::create_dir(trust_dir)?;
    fs::set_permissions(trust_dir, fs::Permissions::from_mode(0o755))?;
    let key = verifying(root_public)?;
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
    let old = signing(old_private)?;
    if old.verifying_key() != store.current {
        bail!("old release root private key does not match trust store");
    }
    generate_key(new_private, new_public)?;
    let new = signing(new_private)?;
    let generation = store.generation + 1;
    let body = format!(
        "YRL-RELEASE-ROOT-TRANSITION-1 {} {} {} {}",
        store.generation,
        hex::encode(old.verifying_key().to_bytes()),
        generation,
        hex::encode(new.verifying_key().to_bytes())
    );
    let line = format!(
        "{body} {} {}\n",
        hex::encode(old.sign(body.as_bytes()).to_bytes()),
        hex::encode(new.sign(body.as_bytes()).to_bytes())
    );
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
            hex::encode(new.verifying_key().to_bytes())
        ),
    )?;
    File::open(&tmp)?.sync_all()?;
    fs::rename(tmp, current)?;
    Ok(())
}

pub fn load_trust(dir: &Path) -> Result<TrustStore> {
    let root = verifying(&dir.join("root.pub"))?;
    let mut roots = BTreeMap::new();
    roots.insert(0, root);
    for line in fs::read_to_string(dir.join("root-transitions.log"))
        .unwrap_or_default()
        .lines()
    {
        let f: Vec<_> = line.split_whitespace().collect();
        if f.len() != 7 || f[0] != "YRL-RELEASE-ROOT-TRANSITION-1" {
            bail!("invalid release root transition");
        }
        let og: u64 = f[1].parse()?;
        let ng: u64 = f[3].parse()?;
        if ng != og + 1 {
            bail!("non-monotonic release root generation");
        }
        let old = VerifyingKey::from_bytes(
            &hex::decode(f[2])?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid old root"))?,
        )?;
        let new = VerifyingKey::from_bytes(
            &hex::decode(f[4])?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid new root"))?,
        )?;
        if roots.get(&og) != Some(&old) {
            bail!("detached release root transition");
        }
        let body = format!("YRL-RELEASE-ROOT-TRANSITION-1 {og} {} {ng} {}", f[2], f[4]);
        old.verify(
            body.as_bytes(),
            &Signature::from_slice(&hex::decode(f[5])?)?,
        )?;
        new.verify(
            body.as_bytes(),
            &Signature::from_slice(&hex::decode(f[6])?)?,
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
    let current = verifying(&dir.join("current.pub")).or_else(|_| {
        let b: [u8; 32] = hex::decode(&current_fields[1])?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid current root"))?;
        Ok::<_, anyhow::Error>(VerifyingKey::from_bytes(&b)?)
    })?;
    if roots.get(&generation) != Some(&current) {
        bail!("release trust store was rolled back or detached");
    }
    let mut revoked_delegates = BTreeSet::new();
    for line in fs::read_to_string(dir.join("revocations.log"))
        .unwrap_or_default()
        .lines()
    {
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
            &Signature::from_slice(&hex::decode(f[5])?)?,
        )?;
        revoked_delegates.insert((dg, f[3].to_owned()));
    }
    Ok(TrustStore {
        generation,
        current,
        roots,
        revoked_delegates,
    })
}

#[derive(Clone, Debug)]
pub struct Delegation {
    pub root_generation: u64,
    pub generation: u64,
    pub public: VerifyingKey,
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
    let root = signing(root_private)?;
    if root.verifying_key() != store.current {
        bail!("root private key does not match current generation");
    }
    let d = Delegation {
        root_generation: store.generation,
        generation,
        public: verifying(delegate_public)?,
        valid_from,
        valid_until,
        min_release,
        max_release,
    };
    let body = d.body();
    atomic(
        output,
        format!(
            "{body} {}\n",
            hex::encode(root.sign(body.as_bytes()).to_bytes())
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
        public: VerifyingKey::from_bytes(
            &hex::decode(f[3])?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid delegate key"))?,
        )?,
        valid_from: f[4].parse()?,
        valid_until: f[5].parse()?,
        min_release: f[6].parse()?,
        max_release: f[7].parse()?,
    };
    let root = store
        .roots
        .get(&d.root_generation)
        .context("delegation uses unknown root")?;
    root.verify(
        d.body().as_bytes(),
        &Signature::from_slice(&hex::decode(f[8])?)?,
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
    let root = signing(root_private)?;
    if root.verifying_key() != store.current {
        bail!("wrong release root private key");
    }
    let public = verifying(delegate_public)?;
    let body = format!(
        "YRL-RELEASE-REVOKE-1 {} {generation} {} {at}",
        store.generation,
        hex::encode(public.to_bytes())
    );
    let line = format!(
        "{body} {}\n",
        hex::encode(root.sign(body.as_bytes()).to_bytes())
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

#[derive(Clone, Debug)]
pub struct Manifest {
    pub number: u64,
    pub version: String,
    pub platform: String,
    pub arch: String,
    pub data_min: u32,
    pub data_max: u32,
    pub created: u64,
    pub expires: u64,
    pub delegation: u64,
    pub files: Vec<(String, u64, [u8; 32])>,
}
impl Manifest {
    pub fn encode(&self) -> Vec<u8> {
        let mut s = format!(
            "{MANIFEST_MAGIC} {} {} {} {} {} {} {} {} {} {}\n",
            self.number,
            self.version,
            self.platform,
            self.arch,
            self.data_min,
            self.data_max,
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
        if h.len() != 11 || h[0] != MANIFEST_MAGIC {
            bail!("invalid release manifest header");
        }
        let count: usize = h[10].parse()?;
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
            created: h[7].parse()?,
            expires: h[8].parse()?,
            delegation: h[9].parse()?,
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
    created: u64,
    expires: u64,
    delegation: u64,
    output: &Path,
) -> Result<()> {
    if number == 0 || expires <= created || data_max < data_min {
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
    let key = signing(delegate_private)?;
    if key.verifying_key() != d.public {
        bail!("delegate private key mismatch");
    }
    let bytes = fs::read(manifest)?;
    let m = Manifest::parse(&bytes)?;
    if m.delegation != d.generation || m.number < d.min_release || m.number > d.max_release {
        bail!("manifest is outside delegation scope");
    }
    atomic(
        signature,
        format!("{}\n", hex::encode(key.sign(&bytes).to_bytes())).as_bytes(),
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
    let sig = Signature::from_slice(&hex::decode(fs::read_to_string(signature)?.trim())?)?;
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
