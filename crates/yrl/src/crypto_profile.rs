//! Versioned cryptographic suites and authenticated negotiation payloads.
use anyhow::{bail, Context as _, Result};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub type ProfileId = u32;
pub const CLASSICAL_V1: ProfileId = 0x0001_0001;
/// Reserved for a future reviewed X25519 + ML-KEM-768 construction. It is
/// intentionally not returned by `suite` and therefore cannot be advertised.
pub const HYBRID_X25519_MLKEM768_RESERVED: ProfileId = 0x0002_0001;
pub const NEGOTIATION_VERSION: u8 = 1;
pub const MAX_PROFILES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    Gatekeeper = 1,
    Executor = 2,
    Broker = 3,
    LocalIpc = 4,
}

impl Context {
    pub fn label(self) -> &'static [u8] {
        match self {
            Self::Gatekeeper => b"gatekeeper",
            Self::Executor => b"executor",
            Self::Broker => b"broker",
            Self::LocalIpc => b"local-ipc",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Suite {
    pub id: ProfileId,
    pub noise: &'static str,
    pub authentication: &'static str,
    pub kdf: &'static str,
    pub aead: &'static str,
}
pub const CLASSICAL: Suite = Suite {
    id: CLASSICAL_V1,
    noise: "Noise_IK_25519_ChaChaPoly_BLAKE2s",
    authentication: "X25519 static IK",
    kdf: "BLAKE2s/Noise",
    aead: "ChaChaPoly",
};

pub fn suite(id: ProfileId) -> Option<&'static Suite> {
    (id == CLASSICAL_V1).then_some(&CLASSICAL)
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub minimum: ProfileId,
    pub supported: Vec<ProfileId>,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            minimum: CLASSICAL_V1,
            supported: vec![CLASSICAL_V1],
        }
    }
}
impl Policy {
    pub fn from_env() -> Result<Self> {
        let mut p = Self::default();
        if let Ok(v) = std::env::var("YRL_CRYPTO_MIN_PROFILE") {
            p.minimum = parse_id(&v)?;
        }
        p.validate()?;
        Ok(p)
    }
    pub fn validate(&self) -> Result<()> {
        if self.supported.is_empty() || self.supported.len() > MAX_PROFILES {
            bail!("invalid cryptographic profile count")
        };
        for id in &self.supported {
            if suite(*id).is_none() {
                bail!("unknown cryptographic profile {id:#x}")
            }
        }
        if !self.supported.iter().any(|id| *id >= self.minimum) {
            bail!("minimum cryptographic profile is unsupported")
        };
        Ok(())
    }
    pub fn select(&self, offer: &Offer) -> Result<ProfileId> {
        self.validate()?;
        let selected = self
            .supported
            .iter()
            .copied()
            .filter(|id| {
                *id >= self.minimum && *id >= offer.minimum && offer.supported.contains(id)
            })
            .max()
            .context("no mutually permitted cryptographic profile")?;
        Ok(selected)
    }
}
fn parse_id(s: &str) -> Result<ProfileId> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(s, 16)
        .or_else(|_| s.parse())
        .map_err(Into::into)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub context: Context,
    pub minimum: ProfileId,
    pub supported: Vec<ProfileId>,
}
impl Offer {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.supported.is_empty() || self.supported.len() > MAX_PROFILES {
            bail!("bad profile offer")
        };
        let mut v = b"YRL-CRYPTO-OFFER".to_vec();
        v.push(NEGOTIATION_VERSION);
        v.push(self.context as u8);
        v.extend_from_slice(&self.minimum.to_be_bytes());
        v.push(self.supported.len() as u8);
        for id in &self.supported {
            v.extend_from_slice(&id.to_be_bytes())
        }
        Ok(v)
    }
    pub fn decode(b: &[u8]) -> Result<Self> {
        let prefix = b"YRL-CRYPTO-OFFER";
        if b.len() < prefix.len() + 7
            || &b[..prefix.len()] != prefix
            || b[prefix.len()] != NEGOTIATION_VERSION
        {
            bail!("unknown crypto negotiation")
        };
        let context = match b[prefix.len() + 1] {
            1 => Context::Gatekeeper,
            2 => Context::Executor,
            3 => Context::Broker,
            4 => Context::LocalIpc,
            _ => bail!("unknown crypto context"),
        };
        let minimum = u32::from_be_bytes(b[prefix.len() + 2..prefix.len() + 6].try_into().unwrap());
        let n = b[prefix.len() + 6] as usize;
        if n == 0 || n > MAX_PROFILES || b.len() != prefix.len() + 7 + n * 4 {
            bail!("invalid crypto offer length")
        };
        let mut supported = Vec::with_capacity(n);
        for c in b[prefix.len() + 7..].chunks_exact(4) {
            let id = u32::from_be_bytes(c.try_into().unwrap());
            if suite(id).is_none() || supported.contains(&id) {
                bail!("unknown or repeated crypto profile")
            };
            supported.push(id)
        }
        Ok(Self {
            context,
            minimum,
            supported,
        })
    }
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(*blake3::hash(&self.encode()?).as_bytes())
    }
}

pub fn response(context: Context, selected: ProfileId, offer_hash: [u8; 32]) -> Result<Vec<u8>> {
    if suite(selected).is_none() {
        bail!("unknown selected profile")
    };
    let mut v = b"YRL-CRYPTO-SELECT".to_vec();
    v.push(NEGOTIATION_VERSION);
    v.push(context as u8);
    v.extend_from_slice(&selected.to_be_bytes());
    v.extend_from_slice(&offer_hash);
    Ok(v)
}
pub fn parse_response(b: &[u8], offer: &Offer) -> Result<ProfileId> {
    let p = b"YRL-CRYPTO-SELECT";
    if b.len() != p.len() + 38
        || &b[..p.len()] != p
        || b[p.len()] != NEGOTIATION_VERSION
        || b[p.len() + 1] != offer.context as u8
    {
        bail!("invalid crypto selection")
    };
    let id = u32::from_be_bytes(b[p.len() + 2..p.len() + 6].try_into().unwrap());
    if b[p.len() + 6..] != offer.digest()?
        || !offer.supported.contains(&id)
        || id < offer.minimum
        || suite(id).is_none()
    {
        bail!("crypto selection downgrade or substitution")
    };
    Ok(id)
}

pub fn prologue(context: Context) -> Vec<u8> {
    let mut v = b"YRL crypto profiles v1\0".to_vec();
    v.extend_from_slice(context.label());
    v
}

pub struct ProfileStore {
    path: PathBuf,
    entries: BTreeMap<String, ProfileId>,
}
impl ProfileStore {
    pub fn open(path: &Path) -> Result<Self> {
        let entries = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
        {
            Ok(mut f) => {
                let m = f.metadata()?;
                if !m.is_file() || m.nlink() != 1 || m.mode() & 0o077 != 0 || m.len() > 1 << 20 {
                    bail!("unsafe crypto profile store")
                };
                use std::io::Read;
                let mut s = String::new();
                f.read_to_string(&mut s)?;
                let mut map = BTreeMap::new();
                for l in s.lines() {
                    let f: Vec<_> = l.split_whitespace().collect();
                    if f.len() != 2 {
                        bail!("damaged crypto profile store")
                    };
                    let id = parse_id(f[1])?;
                    if suite(id).is_none() || map.insert(f[0].into(), id).is_some() {
                        bail!("damaged crypto profile store")
                    }
                }
                map
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path: path.into(),
            entries,
        })
    }
    fn peer(context: Context, key: &[u8]) -> String {
        let mut h = blake3::Hasher::new();
        h.update(b"yrl-profile-peer-v1");
        h.update(context.label());
        h.update(key);
        hex::encode(h.finalize().as_bytes())
    }
    pub fn minimum(&self, context: Context, key: &[u8], configured: ProfileId) -> ProfileId {
        configured.max(*self.entries.get(&Self::peer(context, key)).unwrap_or(&0))
    }
    pub fn remember(&mut self, context: Context, key: &[u8], selected: ProfileId) -> Result<()> {
        if suite(selected).is_none() {
            bail!("unknown profile")
        };
        let k = Self::peer(context, key);
        let old = *self.entries.get(&k).unwrap_or(&0);
        if selected < old {
            bail!("cryptographic profile rollback")
        };
        if selected == old {
            return Ok(());
        }
        self.entries.insert(k, selected);
        let parent = self.path.parent().context("profile store needs parent")?;
        fs::create_dir_all(parent)?;
        let mut perms = fs::metadata(parent)?.permissions();
        use std::os::unix::fs::PermissionsExt;
        perms.set_mode(0o700);
        fs::set_permissions(parent, perms)?;
        let mut text = String::new();
        for (k, v) in &self.entries {
            text.push_str(&format!("{k} {v:#010x}\n"))
        }
        let tmp =
            self.path
                .with_extension(format!("tmp-{}-{}", std::process::id(), random_suffix()));
        let result = (|| -> Result<()> {
            let mut f = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&tmp)?;
            f.write_all(text.as_bytes())?;
            f.sync_all()?;
            fs::rename(&tmp, &self.path)?;
            File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }
}

fn random_suffix() -> u64 {
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    OsRng.next_u64()
}
