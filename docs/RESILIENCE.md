# YRL — connection resilience (stage 2): resumable sessions and relay

## Goal

Wi-Fi drops, the address changes, or the laptop sleeps, yet open shells, tunnels, and transfers **do not die**. The client reconnects and everything continues from the same point, with no loss or duplication. A server behind NAT is reachable through a relay that sees only ciphertext.

## 1. Reliable session layer (above Noise, below frames)

A session is not a connection. Session state lives on the server (permissions, identity, terminals, tunnels, and transfers) and survives a TCP disconnect.

- After successful login, the server sends `SESSION` (kind 42): `[sid: 16 random bytes]`. From then on, all frames use envelopes:
  - `SEQ` (40): `[seq u64][inner frame]` — numbered, ordered, and delivered exactly once;
  - `ACK` (41): `[expected seq u64]` — cumulative acknowledgement;
  - `LINK_PING/LINK_PONG` (44/45): link liveness, **without** sequence numbers.
- The sender stores unacknowledged frames up to `unacked_limit` (8 MiB by default). At the limit it **waits** — natural backpressure stops terminal reads and slows transfers — instead of losing data or growing without bound.
- The receiver accepts `seq == expected`, discards duplicates (`seq < expected`), and treats a gap (`seq > expected`) as a protocol error that closes the connection. The underlying transport is ordered, so gaps cannot occur legitimately.
- Instead of logging in, a new connection sends `RESUME` (43): `[sid][client expected seq]` after the normal Noise IK handshake, which rechecks the client key. If the sid exists and the **key is the same**, the server responds with `RESUMED` (46): `[server expected seq]`; both sides discard acknowledged frames and retransmit the rest in order. Otherwise the server closes silently, as for a foreign key. The password is not needed again: the session has already logged in, while the sid is 128 random bits inside the encrypted channel and is bound to the key.
- If the old connection is still hanging because the server has not noticed the outage, the new connection **replaces** it.
- Without a connection, a session lives for `session_grace` (10 minutes by default), then is destroyed: terminals receive hangup, tunnels and transfers close, and partial files remain resumable.
- Failed RESUME attempts count toward the same per-key/per-address lockout as wrong passwords.

## 2. Client and route selection

`Client::connect_opts(...)` builds one ordered route set from the configured endpoints: UDP, direct TCP, then TCP relay. Initial connection and recovery use the first working route. A write error or the bounded liveness deadline ends the current connection; the manager immediately tries the next route, performs fresh outer Client↔Gatekeeper and inner Client↔Executor Noise IK handshakes, and sends RESUME inside the new end-to-end channel for the existing Executor-owned session. After a complete unsuccessful route cycle, retries use bounded exponential backoff with jitter.

Application calls (`exec`, `pty`, `put_file`, `tunnel`) keep waiting and do not observe the replacement. Accepted requests remain in the same server session, so reconnecting does not submit or execute them again. If the server has destroyed the session because its grace period expired, all pending calls receive `session lost`.

`connect_timeout` bounds initial establishment across all routes, `route_timeout` bounds each route attempt (including both Noise handshakes and RESUME), `give_up_after` bounds recovery, and `window` bounds the combined queued and unacknowledged data. Unsent control, command, terminal, and tunnel frames are scheduled before bulk file frames; already-numbered frames retain strict order across reconnects. ACK/SEQ are inside the authenticated inner channel, so Gatekeeper cannot advance either endpoint's authoritative position. Link retransmission reuses stored logical frames on the fresh inner Noise connection; Noise ciphertext and nonces are never reused across connections.

`Client::connection_diagnostics()` reports the selected transport, latest establishment/RESUME round-trip duration, attempts by transport, failures, disconnects, successful resumes, route switches, and the last link termination reason. It deliberately retains no addresses, keys, account names, or payloads.

## 3. Relay (`yrl-relay`)

For a server behind NAT, the server makes an **outbound** connection to the relay and waits. The client arrives with the same rendezvous ID; the relay joins the two sockets and copies bytes. The ordinary client↔server Noise IK channel runs on top. The relay is **untrusted**: it sees ciphertext, sizes, and timing, but cannot read or alter data (alteration fails authentication). The rendezvous ID is neither secret nor a security boundary; keys provide the security.

- The relay limits waiting servers, wait time, per-pair rate/volume, and table size. It records only counters.
- The server keeps a spare outbound connection waiting and opens a replacement as soon as a pair consumes it.

## 4. Deliberately outside this stage

NAT hole punching, a UDP relay, WebSocket-on-443 camouflage, simultaneous multipath, route racing, and adaptive route scoring are not implemented. The manager uses configured endpoints in a fixed order and changes routes only after the current one fails. Session state is in memory and cannot survive an `yrld` restart or expiry of `session_grace`.

## 5. Verification

A chaos proxy sits between client and server: disconnect during a file transfer (matching hash, no duplicated bytes), terminal output (no gaps or duplicates), a command response, or an active tunnel; repeated outages; replacement while the server has not noticed the old connection; RESUME with a foreign key, foreign sid, or expired session; a full window; overwritten/replayed SEQ; latency and fragmentation. `tests/routes.rs` additionally removes an active UDP path and verifies UDP → TCP recovery, then removes a direct TCP path and verifies direct → relay recovery while the same PTY, file transfer, tunnel, and server session remain alive. The UDP test starts a command before the cut and verifies its side effect occurred exactly once.
