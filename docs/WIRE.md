# YRL v0.1 — wire format (direct connection, without NAT/DHT/relay)

Scope of v0.1 (owner decision, 2026-10-05): the server has a public address; the client supplies its address and port (the port is known only to us). Everything else — NAT, DHT, relay, WS/443, redundant UDP transport, remote desktop, and files — comes later.

## Layers

1. TCP to `host:port`.
2. Transport framing: `[u16 big-endian length][Noise message]` (length ≤ 65535; zero is forbidden).
3. Noise `Noise_IK_25519_ChaChaPoly_BLAKE2s`. The client knows the server's static public key (pairing: `yrld init` displays the server key and the client stores it). The client's first message contains `YRL1` + version in its payload; the server's second message contains `YRL1` + `ok`. The server decrypts message 1, obtains the client's static key, and checks it against `authorized_keys`. An unknown key, wrong version, decryption failure, or timeout causes a **silent close without a single response byte**.
4. Noise transport mode: every message contains exactly one YRL frame (no padding; frame length = decrypted-message length). The maximum frame size is 65,519 bytes. The two directions use different keys, nonce counters are monotonic (preventing replay), and keys rotate every 2^20 messages.
5. YRL frame: `[kind u8][stream u32][payload…]`.
   Kinds: 0 PING, 1 PONG, 2 EXEC_REQ, 3 STDOUT, 4 STDERR, 5 EXIT, 6 ERROR, 7 CLOSE. Reserved: 0x10–0x1F files, 0x20–0x2F tunnels, 0x30–0x3F remote desktop/input/clipboard/audio, and 0x40+ agent RPC.
   `EXEC_REQ` payload: `[request_id u64][timeout_ms u32][argc u16]{[len u16][bytes]}*argc` (the first string is the executable, with no host shell).
   `STDOUT`/`STDERR` payload: `[request_id u64][data]`; `EXIT`: `[request_id u64][code i32]` (`code = -1` on signal/timeout); `ERROR`: `[request_id u64][code u16][text]`.
6. Frame-parsing errors close the connection; internal state is never exposed.

## v0.1 permissions

An `authorized_keys` entry is `<hex public key> <label> <comma-separated permissions>` (permission: `exec`). An operation without its permission returns ERROR and is not performed. More permissions (files, tunnels, and so on) are added with their operations.

## Login (v0.1.1)

Frames: `LOGIN=8` `[login_len u8 ≤64][login][password_len u16 ≤256][password]` (exactly, with no trailing bytes); `LOGIN_OK=9`, whose payload is the comma-separated session permissions; and `LOGIN_FAIL=10`, whose payload is always empty.

Before `LOGIN_OK`, the server accepts only LOGIN. The `users` file contains `<login> <permissions|-> <argon2id PHC>` and has mode 0600.
