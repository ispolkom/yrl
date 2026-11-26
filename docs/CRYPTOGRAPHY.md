# YRL cryptographic profiles

This document records the specification status, threat boundary and dependency decision for Stage 7 mechanisms. A profile is not production-supported merely because its primitive exists in a library. The full authenticated composition, transcript binding, resource limits, migration and negative tests must also be reviewable.

## 7.2 X25519 + ML-KEM-768 transport assessment

ML-KEM-768 itself is standardized by [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final). RustCrypto `ml-kem` 0.3.4 is a plausible Apache-2.0/MIT implementation candidate, but it implements the primitive rather than a YRL/Noise hybrid handshake.

The candidate general-purpose X25519 + ML-KEM-768 combiner is [X-Wing draft 11](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/). As of 2026-11-26 it remains an individual Internet-Draft with no RFC status and explicitly says it is work in progress. The available `x-wing` crate targets obsolete draft 06, while `rxwing` 0.1.0 targets draft 11 and has not established the maturity needed for an obligatory YRL production profile.

Noise revision 34 specifies DH patterns and PSK mixing, but no ML-KEM or X-Wing token and no reviewed mapping of this KEM exchange into authenticated Noise IK. Treating a KEM result as an application-chosen Noise PSK would require YRL to select token placement, ciphertext ordering, failure semantics, transcript/domain binding and key-erasure rules. That would be a new project-specific cryptographic construction, which Stage 7 explicitly forbids.

Consequently profile `0x00020001` is reserved but not registered, advertised or accepted, even with the `pq-hybrid` build feature. The feature only makes the unsupported combination explicit in compile matrices; it cannot activate the profile. There are no PQ computations and no claim of PQ confidentiality or authentication.

Unblocking requires either a stable reviewed Noise hybrid pattern/composition that covers X25519 + ML-KEM-768, or an owner-approved switch to a standardized transport construction with equivalent independent Gatekeeper and Executor authentication. It also requires a maintained implementation of the exact final construction, official FIPS 203 and combiner vectors, malformed-ciphertext/decapsulation tests, bounded pre-authentication work, benchmarking and independent cryptographic review. At that point secrets must be mixed through the specified construction, erased after key schedule use, and never recomputed per data frame.
