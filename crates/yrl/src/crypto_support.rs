//! Compile-time visibility for Stage 7 mechanisms that must remain fail-closed
//! until their reviewed backend and protocol integration are available.

use anyhow::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    OpaqueRfc9807,
    HybridEd25519MlDsa65,
    Fido2,
    Tpm2,
}

/// A feature flag never makes an unavailable security mechanism usable.
pub fn require(mechanism: Mechanism) -> Result<()> {
    match mechanism {
        Mechanism::OpaqueRfc9807 => {
            #[cfg(feature = "opaque-rfc9807")]
            { Ok(()) }
            #[cfg(not(feature = "opaque-rfc9807"))]
            { anyhow::bail!("OPAQUE RFC 9807 backend is unavailable") }
        },
        Mechanism::HybridEd25519MlDsa65 => {
            #[cfg(feature = "hybrid-signatures")]
            { Ok(()) }
            #[cfg(not(feature = "hybrid-signatures"))]
            {
                anyhow::bail!("hybrid Ed25519 + ML-DSA-65 backend is unavailable")
            }
        }
        Mechanism::Fido2 => {
            #[cfg(feature = "fido2")]
            {
                Ok(())
            }
            #[cfg(not(feature = "fido2"))]
            {
                anyhow::bail!("FIDO2/CTAP2 backend is unavailable")
            }
        }
        Mechanism::Tpm2 => {
            #[cfg(feature = "tpm2")]
            { Ok(()) }
            #[cfg(not(feature = "tpm2"))]
            { anyhow::bail!("TPM 2.0 backend is unavailable") }
        },
    }
}
