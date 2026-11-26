# YRL cryptographic profiles

This document records the specification status, threat boundary and dependency decision for Stage 7 mechanisms. A profile is not production-supported merely because its primitive exists in a library. The full authenticated composition, transcript binding, resource limits, migration and negative tests must also be reviewable.

## 7.2 X25519 + ML-KEM-768 transport assessment

ML-KEM-768 itself is standardized by [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final). RustCrypto `ml-kem` 0.3.4 is a plausible Apache-2.0/MIT implementation candidate, but it implements the primitive rather than a YRL/Noise hybrid handshake.

The candidate general-purpose X25519 + ML-KEM-768 combiner is [X-Wing draft 11](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/). As of 2026-11-26 it remains an individual Internet-Draft with no RFC status and explicitly says it is work in progress. The available `x-wing` crate targets obsolete draft 06, while `rxwing` 0.1.0 targets draft 11 and has not established the maturity needed for an obligatory YRL production profile.

Noise revision 34 specifies DH patterns and PSK mixing, but no ML-KEM or X-Wing token and no reviewed mapping of this KEM exchange into authenticated Noise IK. Treating a KEM result as an application-chosen Noise PSK would require YRL to select token placement, ciphertext ordering, failure semantics, transcript/domain binding and key-erasure rules. That would be a new project-specific cryptographic construction, which Stage 7 explicitly forbids.

Consequently profile `0x00020001` is reserved but not registered, advertised or accepted, even with the `pq-hybrid` build feature. The feature only makes the unsupported combination explicit in compile matrices; it cannot activate the profile. There are no PQ computations and no claim of PQ confidentiality or authentication.

Unblocking requires either a stable reviewed Noise hybrid pattern/composition that covers X25519 + ML-KEM-768, or an owner-approved switch to a standardized transport construction with equivalent independent Gatekeeper and Executor authentication. It also requires a maintained implementation of the exact final construction, official FIPS 203 and combiner vectors, malformed-ciphertext/decapsulation tests, bounded pre-authentication work, benchmarking and independent cryptographic review. At that point secrets must be mixed through the specified construction, erased after key schedule use, and never recomputed per data frame.

## 7.3 OPAQUE assessment

[RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html) is final and defines OPAQUE-3DH, including application context, identity binding, enumeration defenses and official vectors. The upstream Rust `opaque-ke` project says its current 4.x/5.x code targets RFC 9807, but 5.x is pre-release and its published independent NCC audit covered release 0.5.0 in 2021, years before the final RFC and the current implementation. That audit does not establish correctness of the present RFC 9807 code or YRL integration.

YRL cannot safely bolt a PAKE onto the existing one-frame LOGIN. Registration, KE1/KE2/KE3 state, fake records for unknown accounts, Argon2 KSF parameters, server OPRF/masking/AKE secrets, channel binding to the inner Executor Noise transcript, device key/account/server-role identities, password change and crash-safe record migration must be designed and reviewed together. A failed OPAQUE attempt must never fall back to Argon2 LOGIN. Migration can occur only after a successful legacy login with explicit client support, or by re-registration.

ROOT step-up needs a separate Broker-owned OPAQUE server configuration and record/secret lifecycle, with the OPAQUE context bound to the one-shot operation digest and Executor/Broker identities. Reusing an Executor login PAKE session would destroy Broker independence. The ROOT password must still never enter Executor.

The `opaque-rfc9807` feature therefore exposes no authentication backend. `crypto_support::require(OpaqueRfc9807)` always fails closed, including when compiled. No OPAQUE record, secret or password is logged or persisted. Unblocking requires a current independent audit (or project-sponsored review) of the exact library version, official RFC vectors, a reviewed multi-message wire/state design, constant-observable unknown-account handling, resource admission, lifecycle/backup integration and migration tests. OPAQUE reduces precomputation risk but does not eliminate offline guessing after complete server-state compromise.

## 7.4 Ed25519 + ML-DSA-65 signature assessment

ML-DSA is standardized by [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final). RustCrypto `ml-dsa` 0.1.2 implements the final standard under Apache-2.0/MIT and offers zeroization, but is an early 0.1 release with no published independent audit establishing the implementation for YRL's mandatory trust roots.

A safe hybrid profile is more than concatenating signatures. It needs a versioned canonical envelope binding purpose, identity, Ed25519 key, ML-DSA-65 key, both key generations and the message digest; verification must require both signatures and reject stripping, duplication and cross-purpose/key substitution. That envelope must replace formats in device/server identity, Noise authentication, Audit checkpoints/deletion/key transitions, release roots/delegations/manifests and recovery anchors while retaining explicitly classical historical verification. Release and Audit trust stores also need paired revocation, rotation, backup and rollback-high-water semantics.

No reviewed common hybrid signature format covering these contours is currently adopted by YRL, and `snow` Noise IK authenticates X25519 static DH keys rather than accepting an external hybrid signature transcript. Retrofitting only Audit or releases would not meet the requested mandatory profile and could create misleading mixed assurance. Therefore `hybrid-signatures` is compile-only and the support gate fails closed. No ML-DSA dependency or key is generated. Unblocking requires selection/review of the canonical hybrid envelope and Noise authentication construction, audit of the exact ML-DSA library, official FIPS 204 vectors, size/resource limits, cross-contour migration tests and independent review.
