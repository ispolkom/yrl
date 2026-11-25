# YRL development handoff

## Snapshot

- Project: **YRL — YANDI Remote Link**, a Linux-first Rust remote-access prototype.
- Repository: `https://github.com/ispolkom/yrl`, branch `main`.
- Implementation baseline: **`f69e4b7`** (`Harden secret handling and add offline key recovery lifecycle`). The Stage 4 implementation is published. Formal end-to-end deployment acceptance has not been recorded.
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
  └── per-session cgroup v2 for child processes

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

Stage 0 guarantees apply only while the Executor's server session remains alive. After a server-process restart or session-grace expiry, RESUME cannot recover it. Link retransmits stored logical frames after a fresh Noise handshake, so connection-local nonces are not reused. Confirmed frames are not re-executed, and control/interactive traffic has priority over unsent bulk file data within the bounded Link window. Stage 2 rechecks authority during a live session and before RESUME. Stages 3 and 4 must preserve these properties.

## Stage 4 operating model

Private Noise key files are checked for regular-file type, one link, owner, mode, size and private/public consistency; key directories must be private. Audit signing and lockout secret reads have corresponding checks. The installed systemd units use separate service identities and `LimitCORE=0`. Private key material and selected password, phrase and plaintext-frame buffers use upstream `zeroize`; GnuPG performs backup encryption. There is no project-specific cryptographic primitive. Live key files remain on the host for unattended startup: use OS disk encryption and physical protection for at-rest confidentiality.

`yrld keys backup <state-dir> <encrypted-output> <recipient-fingerprint>` streams a bounded, fixed-scope archive to GnuPG without a plaintext temporary archive. `keys restore <encrypted-input> <new-state-dir>` checks the decrypted content, key pairs and Audit journal, then publishes a new private directory; the service-account layout must be checked before startup. `keys rotate <state-dir> <server|role> <encrypted-backup> <recipient>` first makes a recovery copy and replaces one Noise identity while services are stopped. `keys migrate` preserves existing public identities; `keys revoke-device` removes a device key atomically while services may be active. Running services hold shared locks; offline backup, migration and rotation require an exclusive lock. Changed server/Executor/Broker public keys must be re-pinned over a trusted channel. Keep the GnuPG decryption key and trusted public fingerprints outside the server. Encryption to a public recipient does not authenticate the archive's creator.

The Audit journal signing key is distinct from the Audit IPC Noise key. Preserve `audit/sign.key`, its public key and signed journals together. In-place signing-key rotation would invalidate old journal verification and requires a separately designed signed rollover. See `STAGE4_ACCEPTANCE.md` for exact commands and deployment checks.

## Verification recorded for the Stage 4 implementation

The following passed during Stage 4 work:

- `cargo test -p yrl --test keylife` — encrypted backup/restore, damaged ciphertext rejection, role-key rotation and mismatch refusal, migration, device revocation, private-file refusal and offline locking (1 test).
- `cargo test -p yrl --test audit_proc p1_four_programs_one_journal_and_the_owners_commands_in_it` — separate services still authenticate and write Audit events (1 test).
- `cargo test -p yrl --test login` — 23 tests; `cargo test -p yrl --test stepup` — 17 tests. Focused L14 and U13 checks also passed after file-read hardening.
- `cargo test -p yrl --test ipc g14_gatekeeper_impersonation_without_the_client_private_key_or_password_is_refused` and `g15_gatekeeper_impersonation_cannot_inject_an_exec_operation` — both passed.
- `cargo test -p yrl --test install i5_the_unit_files_agree_with_the_table`, `cargo check -p yrl --all-targets`, and `systemd-analyze verify deploy/systemd/yrl-*.service` — passed.

Earlier, the Stage 3 delegated-systemd-scope regression in `tests/cgroup_session.rs` passed: a `setsid` descendant died with its own closed session after RESUME while a neighboring session remained usable. The full `cargo test --workspace --all-targets` suite, Stage 0 route-switch tests, real nftables, and a root/separate-service-user deployment were **not rerun after `f69e4b7`**. Do not report them as passing at the current baseline without running them. `STAGE3_ACCEPTANCE.md`, `STAGE4_ACCEPTANCE.md` and `docs/STAGE2_ACCEPTANCE.md` contain the extended acceptance scenarios.

## Remaining limits and pending checks

1. Run the complete workspace suite and the cross-stage route/revocation scenarios at a final integration gate. Test the installed units with real Linux service users, seccomp/capability and mount inspection, delegated cgroup v2 and nftables. This development environment did not establish those deployment-wide properties.
2. Test offline recovery on a separate host: GnuPG key availability, trusted origin and public fingerprints, ownership remapping, large journals, interrupted rotation, and service restart. Backup encryption does not supply sender authentication. Audit journal-signing-key rollover and a signed chain between journal eras remain open.
3. Host-root operations deliberately retain broad host authority and can escape delegated cgroup containment. A compromised Gatekeeper or relay can deny service and expose metadata. The seccomp policy is a denylist. Sessions are in memory and do not survive Executor restart.
4. OS-level disk encryption or a hardware-backed key store is needed to resist physical disk theft while keeping unattended service startup. The current code does not provide TPM-backed live key storage or a second-device approval flow.
5. UDP has no path-MTU discovery or pacing; NAT hole punching, UDP relay, multipath, route racing and adaptive route scoring are absent. Broker operations are deliberately limited to typed primitives. Desktop and additional-OS support remain unimplemented. Product proposals in `docs/DESIGN.md` and `docs/DESKTOP.md` must not be treated as delivered features or started as incidental work.

## How to continue

Start from the published baseline and this documentation commit, confirm `git status` is clean, read `ROADMAP.md` and the acceptance documents, and take the next stage only when the owner authorizes its implementation. `ROADMAP.md` records Private Discovery as a **candidate** Stage 5 because no committed plan names the post-Stage-4 milestone; confirm its title, privacy target and deployment model before implementation. Keep fixes in logical commits, verify the affected security invariant with focused integration tests, and record deployment-only claims as pending until measured. Do not touch YANDI NODE.
