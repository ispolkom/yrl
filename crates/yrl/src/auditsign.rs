//! Keys and signatures shared by the Audit writer, verifier and key history.
use anyhow::{bail, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use std::path::Path;
use zeroize::Zeroizing;

#[derive(Clone)]
pub enum Public {
    Classical(VerifyingKey),
    #[cfg(feature = "hybrid-signatures")]
    Hybrid(Box<crate::hybrid_signature::PublicKey>),
}

pub enum Secret {
    Classical(SigningKey),
    #[cfg(feature = "hybrid-signatures")]
    Hybrid(Box<crate::hybrid_signature::SigningKey>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    Journal,
    Recovery,
}

#[cfg(feature = "hybrid-signatures")]
impl Purpose {
    fn hybrid(self) -> crate::hybrid_signature::Purpose {
        match self {
            Self::Journal => crate::hybrid_signature::Purpose::Audit,
            Self::Recovery => crate::hybrid_signature::Purpose::Recovery,
        }
    }
}

impl Public {
    pub fn decode(bytes: &[u8], purpose: Purpose, generation: Option<u64>) -> Result<Self> {
        if bytes.len() == 32 {
            return Ok(Self::Classical(VerifyingKey::from_bytes(bytes.try_into()?)?));
        }
        #[cfg(feature = "hybrid-signatures")]
        {
            let key = crate::hybrid_signature::PublicKey::decode(bytes)?;
            if key.purpose != purpose.hybrid() || generation.is_some_and(|g| key.generation != g) {
                bail!("Audit key purpose or generation mismatch");
            }
            Ok(Self::Hybrid(Box::new(key)))
        }
        #[cfg(not(feature = "hybrid-signatures"))]
        {
            let _ = (purpose, generation);
            bail!("unsupported Audit key format")
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Classical(key) => key.to_bytes().to_vec(),
            #[cfg(feature = "hybrid-signatures")]
            Self::Hybrid(key) => key.encode(),
        }
    }

    pub fn same_profile(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }
}

impl PartialEq for Public {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

pub trait Verify {
    fn verify_bytes(&self, message: &[u8], signature: &[u8]) -> Result<()>;
}

impl Verify for VerifyingKey {
    fn verify_bytes(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        Ok(self.verify_strict(message, &Signature::from_slice(signature)?)?)
    }
}

impl Verify for Public {
    fn verify_bytes(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        match self {
            Self::Classical(key) => key.verify_bytes(message, signature),
            #[cfg(feature = "hybrid-signatures")]
            Self::Hybrid(key) => key.verify(message, &crate::hybrid_signature::SignatureEnvelope::decode(signature)?),
        }
    }
}

pub trait Sign {
    fn public_key(&self) -> Public;
    fn sign_bytes(&self, message: &[u8]) -> Result<Vec<u8>>;
}

impl Sign for SigningKey {
    fn public_key(&self) -> Public { Public::Classical(self.verifying_key()) }
    fn sign_bytes(&self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(self.sign(message).to_bytes().to_vec())
    }
}

impl Sign for Secret {
    fn public_key(&self) -> Public { self.verifying_key() }
    fn sign_bytes(&self, message: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Classical(key) => key.sign_bytes(message),
            #[cfg(feature = "hybrid-signatures")]
            Self::Hybrid(key) => Ok(key.sign(message)?.encode()),
        }
    }
}

impl Secret {
    pub fn load(path: &Path, profile: &Public, _purpose: Purpose) -> Result<Self> {
        match profile {
            Public::Classical(_) => {
                let seed = crate::keys::read_secret_hex(path, 32)?;
                Ok(Self::Classical(SigningKey::from_bytes(seed.as_slice().try_into()?)))
            }
            #[cfg(feature = "hybrid-signatures")]
            Public::Hybrid(_) => Ok(Self::Hybrid(Box::new(
                crate::hybrid_signature::SigningKey::load_secret(path, _purpose.hybrid())?,
            ))),
        }
    }

    pub fn verifying_key(&self) -> Public {
        match self {
            Self::Classical(key) => Public::Classical(key.verifying_key()),
            #[cfg(feature = "hybrid-signatures")]
            Self::Hybrid(key) => Public::Hybrid(Box::new(key.public())),
        }
    }

    pub fn generate(profile: &Public, _generation: u64) -> (Self, Zeroizing<Vec<u8>>) {
        match profile {
            Public::Classical(_) => {
                let key = SigningKey::generate(&mut argon2::password_hash::rand_core::OsRng);
                let bytes = Zeroizing::new(hex::encode(key.to_bytes()).into_bytes());
                (Self::Classical(key), bytes)
            }
            #[cfg(feature = "hybrid-signatures")]
            Public::Hybrid(_) => {
                let (key, seeds) = crate::hybrid_signature::SigningKey::generate(Purpose::Journal.hybrid(), _generation);
                let bytes = key.encode_secret(&seeds);
                (Self::Hybrid(Box::new(key)), bytes)
            }
        }
    }
}
