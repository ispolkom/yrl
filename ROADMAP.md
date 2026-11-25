# YRL roadmap

This file distinguishes the **accepted implementation-stage sequence** from the older long-term product plan in `docs/DESIGN.md` §10. It records the state after the initial corrective work in implementation Stage 5. Stage numbers in these two plans are separate; completing a security stage does not imply that an aspirational desktop, transport or cross-platform milestone is complete.

## Accepted implementation stages, in order

| Stage | Scope | State |
|---|---|---|
| **0. Resilient remote-access transport** | One connection manager selects configured direct UDP, direct TCP and TCP relay routes. Failover preserves a live session, operations and confirmed data through RESUME, with bounded resources and interactive priority. | Implemented and accepted. Focused route tests cover UDP → TCP and direct TCP → relay during file transfer. |
| **1. Independent Client ↔ Executor cryptographic authority** | An inner pinned Noise IK channel authenticates the client to Executor, protects authoritative ACK/SEQ and operations from Gatekeeper, and places password/rights checks inside Executor. | Implemented and accepted; G14/G15 are active regression tests. |
| **2. Authority refresh and revocation** | Device-key removal, account disablement and rights changes end affected live sessions and prevent their RESUME, including active PTY, commands, files and tunnels. | Implemented and accepted; focused tests in `tests/revocation.rs`. |
| **3. Component isolation** | Gatekeeper, Executor, Broker, Audit and Firewall have separate privileges and filesystem policies; seccomp covers all threads; user children join a per-session cgroup before execution and are killed with that session. | Implemented; deployment acceptance remains in `STAGE3_ACCEPTANCE.md`. |
| **4. Key and secret lifecycle** | Protect role-private key files, clear secret buffers, support unattended services, offline encrypted recovery, safe Noise-key rotation, device revocation and protected migration. | Implemented in **`f69e4b7`**; deployment acceptance and the Audit journal-signing rollover limit are in `STAGE4_ACCEPTANCE.md`. |
| **5. Failure and overload resilience** | Find and remove failure modes exposed by sustained load, repeated disconnects and bounded-resource operation without weakening authentication, cryptography or delivery guarantees. | In progress. The initial throughput/liveness correction and substage 5.1 global resource admission are implemented. Final integration and deployment acceptance remain pending. |

## Current Stage 5: Failure and overload resilience

The initial Stage 5 investigation traced both the 5.9 MiB/s throughput regression and a missing final upload confirmation to one cause: Stage 4 wrapped every encoded Noise plaintext frame in `Zeroizing`, so an unoptimized build performed a costly volatile wipe for every 60 KiB bulk frame. Link already retains the same bulk payload until its authoritative ACK, so wiping that additional encoded copy did not shorten the payload's lifetime. Restricting this extra wipe to the LOGIN frame restored 70 MiB/s upload and 62 MiB/s download on the same host; Noise authentication, rekeying, pinned identities, ACK/SEQ and bounded Link retention are unchanged.

Sensitive control data retains explicit lifecycle handling. The CLI input and decoded server password use `Zeroizing`; LOGIN payloads and their temporary Noise plaintext encodings are cleared; failed Noise opens clear their output buffer. A CLI step-up phrase is held in a zeroizing caller buffer, travels inside the independent Noise XK proof, and is cleared by Executor or Broker after denial or verifier use. `STEPUP_PROOF` in the ordinary session contains the inner Noise ciphertext, not the phrase.

The original failing 48 MiB chaos upload now completes in about 1.7 seconds through repeated connection cuts with the existing 15-second confirmation deadline. The final FILE_END response was delayed by the same throughput regression; no loss, duplication, ACK/SEQ fault or command replay was found. The Audit unsafe-key test now asserts rejection of a mode-0644 signing key without depending on an obsolete error string.

### Substage 5.1: global resource admission

Executor now shares one configurable resource manager across all of its sessions. Link charges the exact encoded bytes retained until ACK against global, device-key and account budgets (defaults: 256 MiB globally and 64 MiB per principal). Admission waits through the existing backpressure path; it does not drop frames or impose a transfer-rate limit. Global and per-principal pools retain a protected interactive reserve inside the same hard ceiling, while Link's existing per-session window and interactive-first scheduling remain in force.

Active EXEC, PTY, file-transfer, tunnel and filesystem operations retain their existing per-session limits and additionally acquire global, per-session, per-key, per-account and per-operation-type permits. The default aggregate ceiling is 256 active operations, with smaller principal and type shares. Session admission is now atomic and also limits sessions per account as well as globally and per key. RAII permits are released on normal completion, errors, session close, authorization revocation and task cancellation; closing a Link releases pending and unacknowledged memory immediately. `ResourceLimits` and `ServerConfig::set_resource_limits` provide explicit configuration with validation that every memory pool can carry one maximum legal frame.

Focused tests were added for hierarchical admission, release of all quota levels, the protected interactive reserve, and Link-memory release on ACK/close. They are intentionally not executed yet; comprehensive and repeated runs remain reserved for final Stage 5 acceptance.

The comprehensive workspace run, installed-service checks, real nftables and recovery on another host are reserved for final acceptance. Do not lower performance requirements or extend operation deadlines to mask overload or liveness defects.

Private Discovery is deferred and is not part of Stage 5. Multipath, route racing, NAT hole punching, UDP relay, GUI/desktop, other operating systems and YANDI NODE changes also remain outside this stage.

## Long-term product plan: original order retained

The following order comes from `docs/DESIGN.md` §10 (2026-10-05). That document describes the product goal; later owner-approved implementation stages above deliberately tackled security and transport prerequisites in another schedule. Do not infer completion from matching words.

0. Write `WIRE.md` and `THREATS.md` before code.
1. Build network-free core framing, multiplexing, handshake, capabilities and audit with negative tests and mutants.
2. Bring terminal and structured EXEC from loopback to transport, measuring input latency.
3. Benchmark chunked, delta-capable, resumable files against scp/rsync at 0/5/20% loss.
4. Build view-only desktop on X11 with hardware encoding, then input and cursor, and measure latency.
5. Resume across address changes and exercise relay/443 paths under filtering.
6. Add Android client, common-RPC panel and Windows support.
7. Add the agent layer with structured RPC and transactions.

These aspirations are not a license to change YANDI NODE or to start desktop, another OS, multipath, NAT hole punching or unapproved discovery work while working on the next implementation stage. Current implementation and explicit limits are summarized in `HANDOFF.md`.
