# YRL development handoff

## Snapshot

- Project: **YRL — YANDI Remote Link**, a Linux-first Rust remote-access prototype.
- Repository: `https://github.com/ispolkom/yrl`, branch `main`.
- Implementation baseline: Stage 4 was published in **`f69e4b7`** (`Harden secret handling and add offline key recovery lifecycle`). Stage 5 — failure and overload resilience — is in progress: the throughput/liveness correction and substages 5.1–5.4 global admission, containment, IPC overload protection and network fairness are implemented. Formal end-to-end deployment acceptance has not been recorded.
- Scope boundary: this repository is YRL. Do not modify the separate YANDI NODE source tree. Do not interpret the future desktop or other-OS design documents as implemented features.
- This handoff records outcomes and verification at the baseline, not a development diary.

## Architecture at the baseline

```text
Client
  │ configured UDP → direct TCP → TCP relay; fresh outer Noise IK on each route
  ▼
Gatekeeper ── SPA request ──► Firewall (nftables, CAP_NET_ADMIN)
  │ bounded opaque IPC carrier; no user-operation authority
  │ independent inner Noise IK, with Executor key pinned by Client
  ▼
Executor ── typed ROOT step-up ──► Broker
  │    password, key/account rights, RESUME, authoritative Link ACK/SEQ
  ├── account-identity commands and PTYs
  ├── file/directory helpers
  ├── restricted TCP tunnels
  └── per-session cgroup v2 with memory/process/CPU/I/O controls for child processes

Gatekeeper, Executor, Broker and Firewall ── authenticated local events ──► Audit
```

The network-facing Gatekeeper authenticates the outer device key for admission and carries an opaque tunnel. Client and Executor then authenticate independently with Noise IK. Executor verifies the account password and reads the authorized device key, account and rights from its own files. It owns the resumable session, Link numbering and authoritative ACKs; Gatekeeper cannot forge a command or advance delivery state. Broker permits only typed, one-operation ROOT step-up, with a separate pinned key and fresh proof. Audit records authenticated sources in hash-chained journals with Ed25519 checkpoints. Firewall alone can modify nftables. The relay forwards ciphertext and can still deny service or observe timing and volume.

Key code: `client.rs` (route manager), `link.rs` (SEQ/ACK, bounded buffers, priority), `session.rs` (Noise), `udp.rs` and `relay.rs` (transports), `server.rs` (outer admission), `ipc.rs` (local carrier), `executor.rs` (inner authorization and session operations), `broker.rs`, `audit.rs`, `firewall.rs`, `sandbox.rs`, `cgroup.rs`, `keys.rs` and `keylife.rs`. Deployment policy is in `deploy/systemd/` and `deploy/INSTALL.md`.

## Accepted implementation sequence and security invariants

| Stage | Outcome | Evidence and boundary |
|---|---|---|
| 0 — resilient transport | Implemented and accepted. Configured UDP, direct TCP and TCP relay are tried in order. An active server session survives route replacement through RESUME. | `tests/routes.rs`, `tests/link.rs`, `tests/resume.rs`. No multipath, route racing, hole punching or UDP relay. |
| 1 — Client ↔ Executor authority | Implemented and accepted. Independent pinned Noise channel protects login, operations and authoritative ACK/SEQ from a compromised Gatekeeper. | `tests/ipc.rs` G14/G15, `docs/THREATS.md`. A carrier can still deny service. |
| 2 — authority refresh and revocation | Implemented and accepted. Removing a device key, disabling an account or changing rights ends affected live sessions and prevents old RESUME. | `tests/revocation.rs`, `docs/STAGE2_ACCEPTANCE.md`. A new login is required for changed rights. |
| 3 — component and process isolation | Implemented. Seccomp uses TSYNC for existing and future threads; systemd sets separate users/capabilities and filesystem policy. User processes join a per-session cgroup before `exec`; close/revocation invokes `cgroup.kill`. | `tests/cgroup_session.rs`, `STAGE3_ACCEPTANCE.md`. A deliberately privileged host-root command can alter delegated cgroups; root authority is outside that isolation boundary. |
| 4 — key and secret lifecycle | Implemented in **`f69e4b7`**. Private-file checks, zeroizing buffers, separated role keys, offline encrypted recovery, Noise-key rotation, device revocation and migration. Services start without an interactive unlock. | `tests/keylife.rs`, `STAGE4_ACCEPTANCE.md`. Audit journal-signing-key rollover is not implemented. |
| 5 — failure and overload resilience | In progress. Throughput/liveness correction and substages 5.1–5.4 are implemented: hierarchical budgets, cgroup/service containment, bounded IPC, UDP pacing and network/Relay fairness. | New focused resource/cgroup/IPC/network tests are prepared but intentionally not run. Final workspace and installed-host acceptance are pending. |

Stage 0 guarantees apply only while the Executor's server session remains alive. After a server-process restart or session-grace expiry, RESUME cannot recover it. Link retransmits stored logical frames after a fresh Noise handshake, so connection-local nonces are not reused. Confirmed frames are not re-executed, and control/interactive traffic has priority over unsent bulk file data within the bounded Link window. Stage 2 rechecks authority during a live session and before RESUME. Stages 3 and 4 must preserve these properties.

## Stage 4 operating model

Private Noise key files are checked for regular-file type, one link, owner, mode, size and private/public consistency; key directories must be private. Audit signing and lockout secret reads have corresponding checks. The installed systemd units use separate service identities and `LimitCORE=0`. Private key material, password and step-up phrase buffers use upstream `zeroize`; LOGIN payloads and their temporary Noise plaintext encodings are cleared on both sides, and failed Noise opens clear their output buffer. A step-up phrase travels inside Noise XK, so the ordinary `STEPUP_PROOF` payload is ciphertext; Executor or Broker clears the decrypted phrase after denial or verifier use. GnuPG performs backup encryption. There is no project-specific cryptographic primitive. Live key files remain on the host for unattended startup: use OS disk encryption and physical protection for at-rest confidentiality.

`yrld keys backup <state-dir> <encrypted-output> <recipient-fingerprint>` streams a bounded, fixed-scope archive to GnuPG without a plaintext temporary archive. `keys restore <encrypted-input> <new-state-dir>` checks the decrypted content, key pairs and Audit journal, then publishes a new private directory; the service-account layout must be checked before startup. `keys rotate <state-dir> <server|role> <encrypted-backup> <recipient>` first makes a recovery copy and replaces one Noise identity while services are stopped. `keys migrate` preserves existing public identities; `keys revoke-device` removes a device key atomically while services may be active. Running services hold shared locks; offline backup, migration and rotation require an exclusive lock. Changed server/Executor/Broker public keys must be re-pinned over a trusted channel. Keep the GnuPG decryption key and trusted public fingerprints outside the server. Encryption to a public recipient does not authenticate the archive's creator.

The Audit journal signing key is distinct from the Audit IPC Noise key. Preserve `audit/sign.key`, its public key and signed journals together. In-place signing-key rotation would invalidate old journal verification and requires a separately designed signed rollover. See `STAGE4_ACCEPTANCE.md` for exact commands and deployment checks.

## Verification recorded for the Stage 4 implementation

The following passed during Stage 4 work:

- `cargo test -p yrl --test keylife` — encrypted backup/restore, damaged ciphertext rejection, role-key rotation and mismatch refusal, migration, device revocation, private-file refusal and offline locking (1 test).
- `cargo test -p yrl --test audit_proc p1_four_programs_one_journal_and_the_owners_commands_in_it` — separate services still authenticate and write Audit events (1 test).
- `cargo test -p yrl --test login` — 23 tests; `cargo test -p yrl --test stepup` — 17 tests. Focused L14 and U13 checks also passed after file-read hardening.
- `cargo test -p yrl --test ipc g14_gatekeeper_impersonation_without_the_client_private_key_or_password_is_refused` and `g15_gatekeeper_impersonation_cannot_inject_an_exec_operation` — both passed.
- `cargo test -p yrl --test install i5_the_unit_files_agree_with_the_table`, `cargo check -p yrl --all-targets`, and `systemd-analyze verify deploy/systemd/yrl-*.service` — passed.

Earlier, the Stage 3 delegated-systemd-scope regression in `tests/cgroup_session.rs` passed: a `setsid` descendant died with its own closed session after RESUME while a neighboring session remained usable. An exploratory workspace run after `f69e4b7` exposed the Stage 5 issues below, but a complete successful post-correction `cargo test --workspace --all-targets` run has not been recorded. Stage 0 route switching, real nftables, and a root/separate-service-user deployment must also be repeated at the final gate before reporting them as passing at the current baseline. `STAGE3_ACCEPTANCE.md`, `STAGE4_ACCEPTANCE.md` and `docs/STAGE2_ACCEPTANCE.md` contain the extended acceptance scenarios.

## Stage 5 initial corrective work

The Stage 4 `Zeroizing` wrapper around every encoded Noise plaintext caused an unoptimized build to wipe every 60 KiB bulk frame with expensive volatile writes. Loopback file performance fell from the Stage 3 comparison of 68 MiB/s upload and 64 MiB/s download to 5.9 MiB/s in both directions. Link retains bulk payloads until their authoritative ACK, so clearing the additional encoded copy did not shorten their actual lifetime. Stage 5 limits that extra wipe to LOGIN, retains full output-buffer clearing after failed Noise authentication, and leaves all key, password, verifier and step-up phrase cleanup intact.

On the same host, the unchanged `f13_throughput_on_the_loopback_is_reported_and_sane` threshold measured 70 MiB/s upload and 62 MiB/s download after the correction. The unchanged 48 MiB `r2_a_big_upload_through_a_constantly_cutting_network_arrives_intact` scenario completed in about 1.7 seconds through repeated cuts with its existing 15-second final-confirmation deadline. The earlier missing FILE_END confirmation was a consequence of the throughput regression; no ACK/SEQ, integrity or duplicate-delivery defect was found.

Focused post-change verification passed: all 20 `auditlog`, 15 `files`, 23 `login`, 17 `stepup` and the `keylife` tests; the original resume R2 case; G14 and G15; and `cargo check -p yrl --all-targets`. The unsafe Audit signing-key test continues to reject mode 0644 but no longer depends on the obsolete pre-Stage-4 error text. Per owner direction, the comprehensive workspace rerun, deployed services, real nftables and recovery on a separate host remain for final acceptance.

## Stage 5.1–5.4 resource, IPC and network containment

Stage 5.1 introduced one Executor-wide resource manager. Link accounts for retained encoded bytes against global, device-key and account pools while preserving backpressure and a protected interactive reserve. Active EXEC, PTY, transfer, tunnel and filesystem work additionally holds global, session, key, account and operation-type permits. Default Link ceilings are 256 MiB globally and 64 MiB per principal; operation defaults are documented in `resources.rs`. Permits release on ACK/completion, error, cancellation, session close and revocation. There is no byte-rate limiter.

Stage 5.2 extends the existing per-session cgroup rather than adding another lifecycle. The cgroup is created once with the authenticated Executor session and therefore survives transport loss and RESUME. Defaults are `memory.high=1 GiB`, `memory.max=2 GiB`, `pids.max=512`, unlimited `cpu.max`, neutral CPU/I/O weights and no `io.max`; all are typed and configurable through `SessionLimits` and the installed environment file. `memory.oom.group=1` confines a session OOM to that session's children. Executor observes memory/process-limit counters, audits overload, returns specific spawn/OOM errors where the operation protocol permits, and continues serving neighboring sessions. Close, grace expiry and authority revocation still invoke `cgroup.kill` before removal.

The five systemd services have memory/task ceilings, accounting and CPU/I/O weights. Executor has a larger 4 GiB soft / 8 GiB hard envelope, contains delegated session children, and uses `OOMPolicy=continue`; the other single-purpose services use smaller budgets and `OOMPolicy=stop`. Five starts per 60 seconds stops crash loops. These limits do not add CPU quotas or I/O bandwidth caps. Focused tests cover typed cgroup controls/events, systemd policy, cgroup retention across RESUME and neighbor isolation; per owner direction they were compiled but not executed in this substage. Real delegated controllers, OOM behavior and service restart policy still require final installed-host acceptance.

Stage 5.3 adds a shared two-level RAII admission mechanism to the Audit, Broker and Firewall Unix/Noise doors. Pre-authentication handshakes are limited globally and per kernel UID; authenticated connections are limited globally and by Noise public key. Audit defaults are 16 handshakes (4 per UID) and 32 active connections (8 per reporting source); Broker uses 16/8 and 256 active Executor pipes; Firewall uses 16/8 and 64 one-request connections. These ceilings bound task and connection memory within the Stage 5.2 service envelopes and do not rate-limit file data or change Executor session/operation accounting.

Handshake, read/idle and write waits are bounded. Audit's 60-second idle expiry is transparently retried by reporters. Broker uses a 15-minute idle interval appropriate to a quiet session-scoped step-up pipe; the coordinated client pump drops both halves on EOF, Executor preserves the user session, and a later ROOT begin reconnects while an unavailable Broker is denied. Firewall closes after its single typed request; every transport failure remains fail-closed for opening a rule. The Audit ordinary backlog is capped at 256 and reports overflow through `audit_degraded`; mandatory `record_critical` operations have a separate connection lane and cannot be accepted without a journal ACK. Blocking journal append work is itself behind connection admission. Focused RAII/fairness and Audit backlog/critical-lane tests were added but intentionally not run.

Stage 5.4 paces reliable UDP across 16 slices of the measured RTT after the initial congestion-window burst. Slice size follows the effective `cwnd` and peer window, so packet loss slows emission through the existing congestion response rather than through an unrelated fixed rate. SACK/RTO retransmission, Noise, Link ACK/SEQ, RESUME and route switching are unchanged. Batching bounds bursts without relying on one sub-millisecond timer per 1100-byte packet.

On the authenticated side, attached transports now have configurable global/device/account ceilings of 256/32/32. Principal ceilings are twice the default 16-session share so a replacement route can attach before its superseded transport releases capacity. A work-conserving scheduler rotates 16 KiB quanta between session flows and gives control/interactive work a protected, bounded-burst lane. It has no byte-per-second setting: an uncontended flow proceeds immediately. `FILE_DATA` is bulk while file setup/final confirmation/abort remain control. Both outbound writes and admitted inbound frame work participate, and the connection permit releases on disconnect, cancellation, route replacement or error without destroying the resumable session. Overrides are `YRL_NETWORK_CONNECTIONS_TOTAL`, `YRL_NETWORK_CONNECTIONS_PER_KEY`, `YRL_NETWORK_CONNECTIONS_PER_ACCOUNT` and `YRL_NETWORK_QUANTUM_BYTES`.

Relay does not authenticate clients and therefore does not treat a rendezvous ID as identity. It limits joined pairs globally (4096) and per observed endpoint IP (64), reserves two 32 KiB buffers per pair from a 256 MiB global pool, and fairly rotates opaque 16 KiB chunks between pairs. Existing connection/waiting limits and the optional per-pair lifetime byte cap remain. `YRL_RELAY_ACTIVE_PAIRS`, `YRL_RELAY_ACTIVE_PAIRS_PER_IP`, `YRL_RELAY_BUFFER_BYTES_TOTAL`, `YRL_RELAY_BUFFER_BYTES_PER_DIRECTION`, `YRL_RELAY_QUANTUM_BYTES` and `YRL_RELAY_MAX_BYTES_PER_PAIR` are validated startup overrides. All pair/IP/buffer capacity is RAII-released. Focused tests are compiled but intentionally not run. Substage 5.5 and Private Discovery remain untouched.

## Remaining limits and pending checks

1. Run the complete workspace suite and the cross-stage route/revocation scenarios at a final integration gate. Test the installed units with real Linux service users, seccomp/capability and mount inspection, delegated cgroup v2 controllers, per-session OOM/pids exhaustion, systemd service budgets/restart storms and nftables. This development environment did not establish those deployment-wide properties.
2. Test offline recovery on a separate host: GnuPG key availability, trusted origin and public fingerprints, ownership remapping, large journals, interrupted rotation, and service restart. Backup encryption does not supply sender authentication. Audit journal-signing-key rollover and a signed chain between journal eras remain open.
3. Host-root operations deliberately retain broad host authority and can escape delegated cgroup containment. A compromised Gatekeeper or relay can deny service and expose metadata. The seccomp policy is a denylist. Sessions are in memory and do not survive Executor restart.
4. OS-level disk encryption or a hardware-backed key store is needed to resist physical disk theft while keeping unattended service startup. The current code does not provide TPM-backed live key storage or a second-device approval flow.
5. UDP still has no path-MTU discovery; NAT hole punching, UDP relay, multipath, route racing and adaptive route scoring are absent. Broker operations are deliberately limited to typed primitives. Desktop and additional-OS support remain unimplemented. Product proposals in `docs/DESIGN.md` and `docs/DESKTOP.md` must not be treated as delivered features or started as incidental work.

## How to continue

Start from the published baseline and this documentation commit, confirm `git status` is clean, and continue the owner-approved Stage 5 failure and overload work with focused tests for each affected invariant. Keep the comprehensive workspace run and deployment-only claims pending until the final integration gate. Private Discovery is deferred and must not be implemented as incidental Stage 5 work. Do not touch YANDI NODE.
