# YRL cryptographic profiles

This document records the specification status, threat boundary and dependency decision for Stage 7 mechanisms. A profile is not production-supported merely because its primitive exists in a library. The full authenticated composition, transcript binding, resource limits, migration and negative tests must also be reviewable.

## 7.2 X25519 + ML-KEM-768 transport assessment

ML-KEM-768 itself is standardized by [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final). RustCrypto `ml-kem` 0.3.4 is a plausible Apache-2.0/MIT implementation candidate, but it implements the primitive rather than a YRL/Noise hybrid handshake.

The candidate general-purpose X25519 + ML-KEM-768 combiner is [X-Wing draft 11](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/). As of 2026-11-26 it remains an individual Internet-Draft with no RFC status and explicitly says it is work in progress. The available `x-wing` crate targets obsolete draft 06, while `rxwing` 0.1.0 targets draft 11 and has not established the maturity needed for an obligatory YRL production profile.

Noise revision 34 specifies DH patterns and PSK mixing, but no ML-KEM or X-Wing token and no reviewed mapping of this KEM exchange into authenticated Noise IK. Treating a KEM result as an application-chosen Noise PSK would require YRL to select token placement, ciphertext ordering, failure semantics, transcript/domain binding and key-erasure rules. That would be a new project-specific cryptographic construction, which Stage 7 explicitly forbids.

The blocker is resolved with a default-off compound construction based on Clatter 2.3's documented `HybridDualLayerHandshake`: the existing authenticated Noise IK completes first, negotiates profile `0x00020001`, and provides its handshake hash. A Noise `pqNN` exchange using RustCrypto ML-KEM-768 then runs inside the outer transport; domain-separated `MixHash` and `MixKeyAndHash` bind the outer transcript into the PQ symmetric state. Only the inner PQ transport keys protect application frames. This preserves the classical X25519 authentication and confidentiality even if ML-KEM fails, while adding ML-KEM forward secrecy against record-now/decrypt-later attacks.

I2P's released NTCP2 hybrid uses the more tightly interleaved Noise HFS `e1/ekem1` construction. YRL's compound construction has two extra encrypted messages but follows the same principles: ephemeral ML-KEM, authenticated/encrypted KEM material, transcript binding, and no PQ work per data frame. PQ work occurs only after the outer device key is authenticated and admitted, bounding anonymous computational DoS. Clatter is MIT; RustCrypto ML-KEM is Apache-2.0/MIT. Both are license-compatible. Clatter is not formally audited and currently selects `ml-kem` 0.2.x, so the feature remains experimental and disabled by default pending Stage 8 vectors, interoperability, performance and independent review.

## 7.3 OPAQUE implementation

[RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html) is implemented with stable `opaque-ke` 4.0.1 (MIT/Apache-2.0), Ristretto255/SHA-512/Argon2id. Its published historical audit covered an older release, so Stage 8 must execute official vectors and independently review this exact integration; a successful build is not such validation.

YRL therefore uses separate bounded KE1/KE2/KE3 frames. The context includes canonical length-delimited account, authenticated device key, Executor role, selected crypto profile and transcript binding. Unknown users take the library fake-record path. Setup and records are bounded 0600 single-link files with no-follow reads and atomic directory-synced replacement. Registration/password change occurs inside an already authenticated session and never sends the password. A failed OPAQUE attempt never falls back to Argon2 LOGIN.

ROOT step-up needs a separate Broker-owned OPAQUE server configuration and record/secret lifecycle, with the OPAQUE context bound to the one-shot operation digest and Executor/Broker identities. Reusing an Executor login PAKE session would destroy Broker independence. The ROOT password must still never enter Executor.

The feature is default-off and production activation waits for Stage 8. Passwords, export/session keys and temporary messages are not logged and sensitive buffers are cleared. OPAQUE reduces precomputation risk but does not eliminate guessing risk after complete server-state compromise. Existing lifecycle backup must include the `opaque` directory; losing setup makes records unrecoverable and the service fails closed rather than regenerating it.

## 7.4 Ed25519 + ML-DSA-65 signature profile

ML-DSA is standardized by [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final). YRL uses RustCrypto `ml-dsa` 0.1.2 under Apache-2.0/MIT with zeroization. It is an early, explicitly unaudited release, so the feature is default-off and requires Stage 8 official-vector and independent integration review before production activation.

A versioned `YHP1` key envelope binds purpose, generation, Ed25519 and ML-DSA-65 keys to one BLAKE3-derived key ID. The fixed-size `YHS1` signature envelope repeats that identity and contains exactly one 64-byte Ed25519 and one 3309-byte ML-DSA-65 signature over a canonical length-delimited TBS. Verification always checks both. Purpose identifiers cover device/server identity, handshakes, Audit records/checkpoints/deletion evidence, release roots/delegates, transitions and recovery, preventing cross-contour substitution.

Handshake helpers exchange the fixed envelopes through the already encrypted channel and sign both X25519 identities, initiator/responder role, selected profile and transcript binding. Hybrid public keys are caller-supplied pins; peer-supplied unpinned keys are never trusted. Planned rotation requires valid old and new hybrid signatures. Emergency replacement is domain-separated and requires a separately trusted Recovery-purpose key. Keys are generated only by an explicit owner CLI and never embedded. Existing Ed25519-only history remains verifiable only as classical profile data; it is not upgraded by attaching a new signature later.

## 7.5 FIDO2/CTAP2 assessment

FIDO2 is a client-authenticator protocol plus a relying-party ceremony, not a signature primitive to imitate in YRL frames. A conforming design needs a real CTAP2 client backend (for example Yubico libfido2), WebAuthn-compatible authenticator data/clientDataHash verification, a stable RP ID/origin model for a non-browser native client, credential public-key/algorithm validation, sign-counter policy, UP/UV flags and PIN/user-verification enforcement.

The development host has no libfido2 installation. Rust `libfido2-sys`/`fido2-rs` bindings exist, but adding an unbuildable FFI feature would violate the required supported feature compilation. `webauthn-rs` primarily supplies server-side WebAuthn ceremonies and does not provide the native CTAP2 device interaction YRL CLI needs. YRL also lacks reviewed persistent credential/challenge/recovery state and operation-bound ROOT ceremony messages.

Therefore `fido2` is compile-only and `require(Fido2)` fails closed. It cannot be selected, and no nonstandard challenge is accepted. Unblocking requires a packaged/supported libfido2 backend, an explicit native-client RP ID/origin decision, bounded one-use challenge storage, credential/account/device binding, multiple-token revocation and audited recovery. ROOT assertions must cover the exact level/operation/parameters and Broker identity; if policy requires FIDO2, token/PIN/UV failure must never fall back to a password. FIDO2 authenticators are classical unless a particular standardized authenticator algorithm says otherwise.

## 7.6 TPM 2.0 assessment

The standard Rust backend is `tss-esapi`, a wrapper over TPM2-TSS. The current crates.io head is 8.0.0-alpha.4. This host has neither the TPM2-TSS `tss2-esys` development package nor `swtpm`, so a real or simulator backend cannot be compiled and exercised here without adding unverified system/runtime dependencies. The bundled TSS build option does not supply a TPM/simulator or validate device/PCR lifecycle behavior.

Most TPM 2.0 devices do not implement YRL's X25519, Ed25519, ML-KEM or ML-DSA algorithms. Such keys can only be sealed as software secrets: unsealing releases private material to host memory and is not hardware execution. Supported TPM-native RSA/ECC keys could be non-exportable only for separately specified roles whose wire formats accept those algorithms; silently substituting them for current identities would change trust anchors and protocol profiles.

The `tpm2` feature is therefore compile-only and `require(Tpm2)` fails closed. It never probes or changes a host TPM, PCR, NV index or firmware and never falls back to software storage when TPM is required. Unblocking requires a pinned non-alpha TSS backend and license/provenance review, swtpm integration tests, typed policy separating native keys from sealed blobs, bounded TPM command timeouts, owner-auth handling, PCR policy/update resealing workflow, anti-rollback NV strategy, rotation/revocation and documented recovery for TPM/motherboard/OS replacement. Optional policy must preserve full software operation for users who never enable TPM.
