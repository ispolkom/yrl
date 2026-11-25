# What was copied from the YANDI node (copied, not moved) — 2026-10-05

Source: the YANDI node source tree. Only the code required to establish a secure connection was copied; the source tree was not modified.

| YRL file | source | purpose |
|---|---|---|
| `crates/yrl_link/src/util/types.rs` | `node/src/util/types.rs` | `HashId` (32-byte node identifier), `NodeName` |
| `crates/yrl_link/src/core/identity.rs` | `node/src/core/identity.rs` | node identity (Ed25519/X25519), loaded through `key_root` |
| `crates/yrl_link/src/netlayer/encryption.rs` | `node/src/netlayer/encryption.rs` | X25519 + AES-256-GCM, sessions, nonce-replay protection |
| `.../packet.rs`, `peer.rs`, `nat.rs`, `port_manager.rs` | `node/src/netlayer/` | dependencies of encryption/peer (packet types, `PeerInfo`, `NatStatus`, ports) |
| `.../tls_cert.rs`, `ws_transport.rs` | `node/src/netlayer/` | self-signed TLS certificate with fingerprint pinning, WebSocket over TLS (port-443 path) |
| `.../pairing.rs` | `node/src/netlayer/pairing.rs` | QR pairing and resume tokens (copied but not yet verified) |
| `crates/key_root/` | `node/key_root/src` (without `bin/`, `examples/`, `tests/`) | root of the key hierarchy: device, recovery, and identity format |

Not copied (not yet needed): the “station/train/carriage” UDP transport (`netlayer/transport.rs`, `protocol/*`), relay, DHT, bootstrap, and dataplane. They can be integrated after the WS connection has been verified and NAT/relay/multipath is needed. The files were copied unchanged except for removing `bin/` from `key_root`. Build command: `cargo build --offline`; `Cargo.lock` came from the node to support offline dependencies.

## First connection check: `crates/yrl_link/tests/link_loopback.rs`

Four tests pass over loopback: TLS with a pinned fingerprint, WebSocket, X25519 exchange, and encrypted messages in both directions. A foreign certificate, bit tampering, ciphertext replay, and a foreign sender are rejected.

## Properties found in the copied code (inputs to YRL's own handshake)

1. There is no forward secrecy: the session key is derived from both sides' long-lived (for the process lifetime) X25519 keys. A `known_limitation_...` test records this. YRL replaces it with a Noise handshake using ephemeral keys, plus ML-KEM and a device-identity signature.
2. Encryption adds 0–32 random zero-padding bytes and the receiver does not strip them. A YRL frame must therefore carry an explicit length (covered by the `frame/unframe` test).
3. `sender_id` (the sender's NodeID) is in a plaintext header, so a relay can see who is sending, as required by routing. Metadata minimization is separate work.
4. The library writes to stdout with `println!`, including shortened NodeIDs. YRL should replace this with masked `tracing` output.
5. Authentication of the node's X25519 public key relies on a signed Ed25519 Hello that is not present in this copy. The test exchanges keys over an already authenticated, pinned TLS channel; without a signed handshake, an active intermediary could replace the key.

## v0.1 (`crates/yrl`)

Original code, with nothing copied: Noise IK (`snow`) over plain TCP, a direct `host:port`, and `exec` without a shell.

Tests: `crates/yrl/tests/threats.rs` — one test per row T1–T12 in `docs/THREATS.md`, plus the happy path and rekeying.
