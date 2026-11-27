# YRL v0.1 — wire format (direct connection, without NAT/DHT/relay)

Scope of v0.1 (owner decision, 2026-10-05): the server has a public address; the client supplies its address and port (the port is known only to us). Everything else — NAT, DHT, relay, WS/443, redundant UDP transport, remote desktop, and files — comes later.

## Layers

1. TCP to `host:port`.
2. Transport framing: `[u16 big-endian length][Noise message]` (length ≤ 65535; zero is forbidden).
3. Outer Noise `Noise_IK_25519_ChaChaPoly_BLAKE2s` authenticates Client↔Gatekeeper for network admission. The client pins the Gatekeeper/server static key. An unknown key, wrong version, decryption failure, or timeout causes a **silent close without a single response byte**. An authorized client requests `IPC_TUNNEL`; the outer channel then carries bounded opaque chunks only.
4. Inside that carrier, a second independent Noise IK handshake authenticates Client↔Executor. The client pins the separately provisioned Executor public key printed by `yrld init`; it is never learned from Gatekeeper. LOGIN, RESUME, ACK/SEQ, and application frames exist only in this inner channel. Every connection and reconnection performs fresh outer and inner handshakes, so their transport keys and nonce spaces are independent.
5. Inner Noise transport mode: every message contains exactly one YRL frame (no padding; frame length = decrypted-message length). The maximum frame size is 65,519 bytes. The two directions use different keys, nonce counters are monotonic (preventing replay), and keys rotate every 2^20 messages.
6. YRL frame: `[kind u8][stream u32][payload…]`.
   Kinds: 0 PING, 1 PONG, 2 EXEC_REQ, 3 STDOUT, 4 STDERR, 5 EXIT, 6 ERROR, 7 CLOSE. Reserved: 0x10–0x1F files, 0x20–0x2F tunnels, 0x30–0x3F remote desktop/input/clipboard/audio, and 0x40+ agent RPC.
   `EXEC_REQ` payload: `[request_id u64][timeout_ms u32][argc u16]{[len u16][bytes]}*argc` (the first string is the executable, with no host shell).
   `STDOUT`/`STDERR` payload: `[request_id u64][data]`; `EXIT`: `[request_id u64][code i32]` (`code = -1` on signal/timeout); `ERROR`: `[request_id u64][code u16][text]`.
7. Frame-parsing errors close the connection; internal state is never exposed.

## v0.1 permissions

An `authorized_keys` entry is `<hex public key> <label> <comma-separated permissions>` (permission: `exec`). An operation without its permission returns ERROR and is not performed. More permissions (files, tunnels, and so on) are added with their operations.

## Login (v0.1.1)

Frames: `LOGIN=8` `[login_len u8 ≤64][login][password_len u16 ≤256][password]` (exactly, with no trailing bytes); `LOGIN_OK=9`, whose payload is the comma-separated session permissions; and `LOGIN_FAIL=10`, whose payload is always empty.

Before `LOGIN_OK`, Executor accepts only LOGIN or RESUME. The Executor-owned `users` file contains `<login> <permissions|-> <argon2id PHC>` and has mode 0600; Gatekeeper neither reads the password nor supplies an account or rights assertion.
## Cryptographic profile negotiation (Stage 7.1)

When the default-off `crypto-profiles` feature is enabled, each outer Gatekeeper and inner Executor Noise IK handshake replaces the legacy `YRL1` payload with a bounded canonical profile offer. The Noise prologue is `"YRL crypto profiles v1\0" || role`, where role is one of `gatekeeper`, `executor`, `broker`, or `local-ipc`.

The initiator payload is `"YRL-CRYPTO-OFFER" || version:u8 || role:u8 || minimum:u32be || count:u8 || profile[count]:u32be`. Version is 1 and count is 1..8. Unknown and repeated IDs are invalid. The responder payload is `"YRL-CRYPTO-SELECT" || version:u8 || role:u8 || selected:u32be || BLAKE3(exact_offer)`. Selection must be in the offer and no lower than either peer's configured minimum. Since both payloads are processed by Noise handshake messages, and the exact offer digest is returned, removal and substitution are authenticated failures.

Profile `0x00010001` denotes the existing `Noise_IK_25519_ChaChaPoly_BLAKE2s` suite. Profile negotiation is independent for Gatekeeper and Executor and independent of UDP/TCP/Relay selection. There is no on-error downgrade or automatic retry with the legacy payload. The feature remains disabled in production pending Stage 8 migration acceptance.

Profile `0x00020001` is the default-off hybrid profile. After the classical profile-selection reply, the initiator sends a Noise `pqNN` ML-KEM-768 public-key message encrypted by the outer Noise transport; the responder returns the encrypted ML-KEM ciphertext message. Before that exchange, both sides apply `MixHash("clatter.hybrid_dual_layer.outer")` and `MixKeyAndHash(outer_handshake_hash)` to the PQ state. Empty PQ payloads are required. Subsequent YRL frames use the PQ Noise transport, not nested per-frame encryption.

With default-off `opaque-rfc9807`, frames 110/111/112 carry bounded RFC 9807 KE1/KE2/KE3 after the authenticated device-key Noise handshake. KE1 includes the bounded account name; KE2 is indistinguishable for absent accounts; KE3 must validate before a session opens. Frames 113–116 perform client-side password registration inside an already authenticated session and carry the existing request ID. The OPAQUE context binds account, device key, Executor role, negotiated profile and a hash of the Noise transcript. OPAQUE is selected explicitly and never falls back to LOGIN.

Default-off hybrid signatures use `YHP1` public envelopes (purpose, generation, paired-key ID, 32-byte Ed25519 key, 1952-byte ML-DSA-65 key) and `YHS1` signature envelopes (same identity, 64-byte Ed25519 signature, 3309-byte ML-DSA-65 signature). Both members sign the canonical profile/purpose/generation/key/message TBS and both must verify. Frames 117/118 carry mutual handshake proofs bound to both X25519 identities, role, selected profile and transcript. Hybrid public keys are pre-pinned; these frames never introduce a trust anchor.

With default-off `fido2`, Executor login uses `FIDO_LOGIN_BEGIN=119`, `FIDO_CHALLENGE=120` and `FIDO_ASSERTION=121`. The begin contains the account; the bounded challenge carries request ID, UV policy, RP ID, one-use client data and an allow-list. The assertion carries credential ID, authenticator data and ES256 signature. Step-up uses `FIDO_STEPUP_BEGIN=74`, `FIDO_STEPUP_CHALLENGE=75` and `FIDO_STEPUP_ASSERTION=76`; ROOT client data binds the exact operation and Broker identity. Challenges are persisted and consumed once. Registration is an offline local-token artifact plus audited administrative import, not an unauthenticated network frame.

TPM 2.0 is a local key backend and has no wire frame. A future TPM-backed key must retain the explicit cryptographic profile and public identity; sealing alone does not change the algorithm or prove remote platform state.
