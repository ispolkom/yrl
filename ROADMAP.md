# YRL roadmap

This file distinguishes the **accepted implementation-stage sequence** from the older long-term product plan in `docs/DESIGN.md` §10. It records the state after implementation commit `f69e4b7`. Stage numbers in these two plans are separate; completing a security stage does not imply that an aspirational desktop, transport or cross-platform milestone is complete.

## Accepted implementation stages, in order

| Stage | Scope | State |
|---|---|---|
| **0. Resilient remote-access transport** | One connection manager selects configured direct UDP, direct TCP and TCP relay routes. Failover preserves a live session, operations and confirmed data through RESUME, with bounded resources and interactive priority. | Implemented and accepted. Focused route tests cover UDP → TCP and direct TCP → relay during file transfer. |
| **1. Independent Client ↔ Executor cryptographic authority** | An inner pinned Noise IK channel authenticates the client to Executor, protects authoritative ACK/SEQ and operations from Gatekeeper, and places password/rights checks inside Executor. | Implemented and accepted; G14/G15 are active regression tests. |
| **2. Authority refresh and revocation** | Device-key removal, account disablement and rights changes end affected live sessions and prevent their RESUME, including active PTY, commands, files and tunnels. | Implemented and accepted; focused tests in `tests/revocation.rs`. |
| **3. Component isolation** | Gatekeeper, Executor, Broker, Audit and Firewall have separate privileges and filesystem policies; seccomp covers all threads; user children join a per-session cgroup before execution and are killed with that session. | Implemented; deployment acceptance remains in `STAGE3_ACCEPTANCE.md`. |
| **4. Key and secret lifecycle** | Protect role-private key files, clear secret buffers, support unattended services, offline encrypted recovery, safe Noise-key rotation, device revocation and protected migration. | Implemented in **`f69e4b7`**; deployment acceptance and the Audit journal-signing rollover limit are in `STAGE4_ACCEPTANCE.md`. |

The next implementation stage is described below. Its requirements are a specification for future work, not an instruction to start coding during this documentation handoff.

## Next stage candidate: Private Discovery (requires owner confirmation)

`ROADMAP.md` did not exist before this handoff, and no committed document assigns a title or number after implementation Stage 4. **Private Discovery** is the only later workstream explicitly named in the owner-approved Stage 0 exclusions. The following is a detailed candidate for **Stage 5**, not a claim that its scope has been approved. Confirm the title, privacy target and deployment model with the owner before implementation. Preserve Stages 0–4 and their accepted order regardless of that decision.

### Objective and trust boundary

An enrolled client should be able to find current candidate server routes without publishing a stable, enumerable mapping from the user's identity to the host address. A discovery provider, relay or compromised Gatekeeper must not become an authority over endpoint identity, account rights, commands, RESUME or key distribution. Discovery returns *hints*; the client still authenticates the configured Gatekeeper/server and independently pinned Executor with fresh Noise handshakes before using a route. No discovery response can substitute or update a pinned public key.

Before design, specify precisely who should be unable to learn which metadata: an unauthenticated scanner, the discovery provider, other enrolled devices, the relay, and a passive network observer have different visibility. Decide whether discovery is self-hosted or uses an untrusted rendezvous service and document the remaining IP/timing leakage. Do not promise invisibility that an active connection cannot provide.

### Minimum security and lifecycle requirements

1. Use established cryptographic libraries and existing device identities. No password, private key, password verifier, authorization file or capability grant may be sent to a discovery provider. Derive any discovery authorization from owner-approved enrollment, not from a Gatekeeper assertion.
2. Refuse enumeration by unknown devices. Bind records to a specific server identity, authorized audience, protocol version and short expiry. Detect replay, rollback, forged routes, cross-server substitution and stale keys. Keep record sizes, response work, storage, retry and rate limits bounded.
3. Treat discovery as optional availability input to the existing ordered route manager. Keep configured direct UDP, direct TCP and TCP-relay routes working without it. A discovered route still uses the Stage 0 failover/RESUME flow, fresh outer and inner Noise state, protected ACK/SEQ and the same live Executor session. Do not re-execute accepted commands or duplicate confirmed data.
4. Device revocation, account disablement and rights changes retain Stage 2 semantics. A revoked device cannot use a cached discovery record to gain access or RESUME. Key rotation invalidates affected discovery material and requires trusted re-pinning; recovery and migration must include any new server-side discovery secret under the Stage 4 backup policy.
5. Keep discovery logic outside Executor's user-operation authority. Preserve component users, seccomp, filesystem policy and per-session cgroups. Diagnostics may show discovery attempts and freshness without logging identities, secret tokens, candidate addresses or route payloads.

### Acceptance evidence to require

- A written protocol and threat model before code, with the privacy target, trust roots, record lifecycle, provider compromise and metadata limits stated explicitly.
- Focused integration tests using a hostile discovery provider: unknown-device enumeration, forged/redirected/expired/replayed records, wrong pinned server or Executor key, key revocation and key rotation.
- A route test in which a discovered path disappears while a PTY and file transfer are active; the client falls back to an already configured path through RESUME with unchanged session identity, hash and operation count.
- Deployment tests for bounded resource use and offline/provider-unavailable behavior. Record what cannot be verified in a test environment.

Do not fold multipath, route racing, NAT hole punching, UDP relay, GUI/desktop, other operating systems or YANDI NODE changes into this candidate stage. If the owner names a different Stage 5, replace this candidate section while leaving the recorded 0–4 sequence and the historical product plan below intact.

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
