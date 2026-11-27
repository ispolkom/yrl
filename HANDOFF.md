# YRL development handoff

## Snapshot

- Project: **YRL — YANDI Remote Link**, a Linux-first Rust remote-access prototype.
- Repository: `https://github.com/ispolkom/yrl`, branch `main`.
- Implementation baseline: Stage 4 was published in **`f69e4b7`** (`Harden secret handling and add offline key recovery lifecycle`). Stage 5 — failure and overload resilience — is in progress: the throughput/liveness correction and substages 5.1–5.6 are implemented. Formal end-to-end deployment acceptance has not been recorded.
- Scope boundary: this repository is YRL. Do not modify the separate YANDI NODE source tree. Do not interpret the future desktop or other-OS design documents as implemented features.
- Stage 6 substages 6.1–6.6 are implemented: trusted segmented Audit, key lifecycle/export, offline-rooted releases and manual downgrade-safe transactional activation. Comprehensive and installed-host acceptance is intentionally deferred to Stage 8.
- Stage 7.1–7.5 are implemented behind default-off features. No Stage 7 profile is enabled in an installed production service before Stage 8 acceptance.
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
| 5 — failure and overload resilience | In progress. Throughput/liveness correction and substages 5.1–5.6 are implemented: hierarchical budgets, containment, bounded IPC, network/disk admission and explicit crash/restart semantics. | Focused tests are prepared but intentionally not run. Final workspace and installed-host acceptance are pending. |
| 6 — trusted audit and software delivery | Implemented through 6.1–6.6: signed segment rotation/retention, rollback anchors, offline verification/export, Audit key generations, offline-rooted releases and transactional downgrade-safe activation. | Focused tests compile but were intentionally not run. Real signed publication, service activation/recovery and final integration acceptance remain Stage 8. |
| 7 — extended cryptographic protection | Substages 7.1–7.6 are implemented: profiles, hybrid transport/signatures, OPAQUE, FIDO2 and optional TPM2-TSS key protection. | All are default-off; focused tests are compile-only until Stage 8 hardware/interoperability acceptance. |

## Stage 7.1 cryptographic profiles

`crypto_profile.rs` defines bounded canonical offers and selections. The offer is authenticated as a Noise handshake payload, its exact BLAKE3 digest is returned in the authenticated selection, and a Gatekeeper/Executor/Broker/local-IPC context is included in both the payload and Noise prologue. Unknown, repeated, stripped, substituted and below-minimum selections fail closed. Direct UDP, TCP and Relay all use the same policy; changing a route cannot weaken it.

The production CLI stores separate monotonic high-water marks by pinned public key and role under its private key directory. Writes are private, atomic and directory-synced. `YRL_CRYPTO_MIN_PROFILE` can raise the local floor. Gatekeeper and Executor still negotiate independently and retain separate pinned identities. Embedded library callers must set `ClientOptions::crypto_profile_store` if they require persistent downgrade memory.

Only classical profile `0x00010001` is registered: Noise IK with X25519, ChaChaPoly and BLAKE2s. The new wire exchange is behind `crypto-profiles`, disabled by default, and has no automatic fallback to the old wire format. This is intentional until explicit migration and Stage 8 interoperability/performance acceptance. Prepared tests in `tests/crypto_profiles.rs` cover downgrade/stripping/substitution, context binding, feature-gated handshake and private persistent high-water state; they were not run.

## Stage 7.2 hybrid transport

Profile `0x00020001` is implemented behind `pq-hybrid`. Classical Noise IK authenticates and admits the peer first, then an encrypted Clatter Noise `pqNN` ML-KEM-768 exchange mixes the outer handshake hash into its key schedule. The resulting inner transport protects application frames. This is the documented Clatter dual-layer composition and preserves classical security rather than substituting it.

Both peers must explicitly set `YRL_CRYPTO_ENABLE_EXPERIMENTAL_PQ=1`; no error path downgrades. Gatekeeper and Executor upgrade independently with their own outer transcript. Clatter/RustCrypto dependencies are MIT/Apache-2.0-compatible. The feature remains production-disabled because Clatter lacks formal audit and Stage 8 must run FIPS vectors, malformed-message, interoperability, resource and performance tests.

## Stage 7.3 OPAQUE

RFC 9807 authentication is implemented behind default-off `opaque-rfc9807` using `opaque-ke` 4.0.1. The Executor supports bounded KE1/KE2/KE3, fake records for unknown accounts, existing login throttling and a context binding account + device key + Executor role + crypto profile + Noise transcript. Setup/records are private, bounded and atomically replaced. `yrld opaque-init` is explicit; services never regenerate missing setup.

An authenticated account can migrate with `yrl opaque-register`: the client performs Argon2id and sends only RFC registration messages. OPAQUE login requires explicit `YRL_AUTH_OPAQUE=1`; failure never retries Argon2 LOGIN. Prepared unit coverage exercises registration/login and matching keys; it was not run. `cargo check -p yrl --all-targets --features opaque-rfc9807` passes. Broker ROOT OPAQUE remains deliberately unavailable because it needs separate Broker secrets and operation-bound context; the existing independent step-up path remains in force.

## Stage 7.4 hybrid signatures

The default-off `hybrid-signatures` feature implements a single canonical Ed25519 + FIPS 204 ML-DSA-65 envelope with mandatory AND verification. Profile, purpose, generation, paired-key ID and exact message are signed by both algorithms. Purpose values separate identities, handshake proofs, Audit/checkpoints/deletions, release root/delegates, transitions and recovery. Truncation, member stripping, key substitution and cross-purpose use fail before acceptance.

Mutual handshake-proof helpers operate after Noise and bind pre-pinned hybrid keys to both X25519 identities, role, negotiated profile and transcript; no asymmetric signature is added per data frame. Key creation is explicit owner action; planned rotation requires old+new proof and emergency replacement requires a distinct Recovery key. Offline `yrl-release hybrid-keygen|hybrid-sign|hybrid-verify` commands use the same format for release and exported Audit artifacts. Existing historical formats stay classical rather than being relabelled. RustCrypto `ml-dsa` 0.1.2 is MIT/Apache-2.0 but explicitly unaudited, so the feature remains production-off pending Stage 8 vectors/review.

## Stage 7.5 FIDO2

The default-off `fido2` feature uses `fido2-rs` 0.6 and Yubico libfido2 for real CTAP2 device interaction. Registration produces a private artifact that an authorized administrator imports after Audit records the change; the first assertion proves token possession. Login and SUDO use Executor-owned records, while ROOT uses a separate Broker store and an operation-bound challenge. Multiple credentials, revocation, UP, optional mandatory UV/PIN, RP hash, ES256 signature, replay and counter checks are implemented. PINs stay in zeroizing client memory and never cross the wire.

The native RP model uses a stable DNS-style `YRL_FIDO2_RP_ID` and raw CTAP2 client data rather than claiming a browser origin. One-use challenge files bind account, device key and channel/operation context and are burned before verification. A configured FIDO credential forbids password/OPAQUE fallback for that account or step-up contour. Build verification used isolated Debian libfido2/libcbor development packages because the host has no system installation; no host configuration or token was changed. Real hardware interoperability, PIN/UV variants, loss/recovery and counter behavior remain Stage 8 acceptance.

## Stage 7.6 TPM 2.0

The default-off `tpm2` feature uses stable Apache-2.0 `tss-esapi` 7.7 over BSD-2-Clause TPM2-TSS. `YRL_TPM_TCTI` selects a device or swtpm TCTI. The backend seals a random XChaCha20-Poly1305 wrapping key and encrypts bounded software secrets with purpose/generation/PCR/blob binding; Noise key loading understands `static.key.tpm`. This protects at rest and binds the blob to its TPM, but unsealing exposes software key bytes to zeroizing process memory. A separate API creates and signs with native non-exportable P-256 ECDSA keys; current X25519/Ed25519/PQ protocol identities are not silently replaced.

`YRL_TPM_POLICY=required` requires a dedicated `YRL_TPM_NV_INDEX`; missing TPM/blob/PCR/counter fails startup with no plaintext fallback. `YRL_TPM_PCRS` optionally binds up to eight SHA-256 PCRs. `yrld tpm-provision-counter`, `tpm-seal-key`, `tpm-rotate-key`, `tpm-generation` and guarded `tpm-recovery-export` implement explicit lifecycle operations. Rotation writes and fsyncs a next-generation pending blob before incrementing NV and startup completes an interrupted rename. Allocate a distinct NV counter to each independently rotated key/service.

Because `yrld init` creates several independent service identities at once, it refuses required TPM policy: initialize with TPM policy off, make the encrypted Stage 4 recovery package, then provision and migrate each role under its own service environment and dedicated NV index. This prevents one role's rotation from invalidating every other role sharing a counter.

Compilation used TPM2-TSS 3.2 headers/libraries extracted into an isolated build sysroot; nothing was installed and no host TPM state was touched. The ignored swtpm round-trip/native-sign test and physical PCR/update/replacement exercises remain Stage 8. Before enabling PCR policy, retain a Stage 4 encrypted offline recovery copy. After firmware/OS changes, reseal from that recovery through an explicitly provisioned new generation; never reset the counter to make an old blob work.

The selected Rust/TSS licenses are compatible and the stable line includes the historical ESAPI session-nonce fix. A RustSec web lookup found no advisory for `tss-esapi`, `tss-esapi-sys` or RustCrypto `chacha20poly1305`; the local `cargo audit` attempt could not refresh its advisory Git repository because that fetch failed, so Stage 8 must rerun the complete lockfile audit rather than treating this as a clean-audit claim.

Stage 7.1–7.6 are now implemented but remain production-disabled pending Stage 8 acceptance. Prepared tests were not run.

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

## Stage 5.1–5.6 resilience and containment

Stage 5.1 introduced one Executor-wide resource manager. Link accounts for retained encoded bytes against global, device-key and account pools while preserving backpressure and a protected interactive reserve. Active EXEC, PTY, transfer, tunnel and filesystem work additionally holds global, session, key, account and operation-type permits. Default Link ceilings are 256 MiB globally and 64 MiB per principal; operation defaults are documented in `resources.rs`. Permits release on ACK/completion, error, cancellation, session close and revocation. There is no byte-rate limiter.

Stage 5.2 extends the existing per-session cgroup rather than adding another lifecycle. The cgroup is created once with the authenticated Executor session and therefore survives transport loss and RESUME. Defaults are `memory.high=1 GiB`, `memory.max=2 GiB`, `pids.max=512`, unlimited `cpu.max`, neutral CPU/I/O weights and no `io.max`; all are typed and configurable through `SessionLimits` and the installed environment file. `memory.oom.group=1` confines a session OOM to that session's children. Executor observes memory/process-limit counters, audits overload, returns specific spawn/OOM errors where the operation protocol permits, and continues serving neighboring sessions. Close, grace expiry and authority revocation still invoke `cgroup.kill` before removal.

The five systemd services have memory/task ceilings, accounting and CPU/I/O weights. Executor has a larger 4 GiB soft / 8 GiB hard envelope, contains delegated session children, and uses `OOMPolicy=continue`; the other single-purpose services use smaller budgets and `OOMPolicy=stop`. Five starts per 60 seconds stops crash loops. These limits do not add CPU quotas or I/O bandwidth caps. Focused tests cover typed cgroup controls/events, systemd policy, cgroup retention across RESUME and neighbor isolation; per owner direction they were compiled but not executed in this substage. Real delegated controllers, OOM behavior and service restart policy still require final installed-host acceptance.

Stage 5.3 adds a shared two-level RAII admission mechanism to the Audit, Broker and Firewall Unix/Noise doors. Pre-authentication handshakes are limited globally and per kernel UID; authenticated connections are limited globally and by Noise public key. Audit defaults are 16 handshakes (4 per UID) and 32 active connections (8 per reporting source); Broker uses 16/8 and 256 active Executor pipes; Firewall uses 16/8 and 64 one-request connections. These ceilings bound task and connection memory within the Stage 5.2 service envelopes and do not rate-limit file data or change Executor session/operation accounting.

Handshake, read/idle and write waits are bounded. Audit's 60-second idle expiry is transparently retried by reporters. Broker uses a 15-minute idle interval appropriate to a quiet session-scoped step-up pipe; the coordinated client pump drops both halves on EOF, Executor preserves the user session, and a later ROOT begin reconnects while an unavailable Broker is denied. Firewall closes after its single typed request; every transport failure remains fail-closed for opening a rule. The Audit ordinary backlog is capped at 256 and reports overflow through `audit_degraded`; mandatory `record_critical` operations have a separate connection lane and cannot be accepted without a journal ACK. Blocking journal append work is itself behind connection admission. Focused RAII/fairness and Audit backlog/critical-lane tests were added but intentionally not run.

Stage 5.4 paces reliable UDP across 16 slices of the measured RTT after the initial congestion-window burst. Slice size follows the effective `cwnd` and peer window, so packet loss slows emission through the existing congestion response rather than through an unrelated fixed rate. SACK/RTO retransmission, Noise, Link ACK/SEQ, RESUME and route switching are unchanged. Batching bounds bursts without relying on one sub-millisecond timer per 1100-byte packet.

On the authenticated side, attached transports now have configurable global/device/account ceilings of 256/32/32. Principal ceilings are twice the default 16-session share so a replacement route can attach before its superseded transport releases capacity. A work-conserving scheduler rotates 16 KiB quanta between session flows and gives control/interactive work a protected, bounded-burst lane. It has no byte-per-second setting: an uncontended flow proceeds immediately. `FILE_DATA` is bulk while file setup/final confirmation/abort remain control. Both outbound writes and admitted inbound frame work participate, and the connection permit releases on disconnect, cancellation, route replacement or error without destroying the resumable session. Overrides are `YRL_NETWORK_CONNECTIONS_TOTAL`, `YRL_NETWORK_CONNECTIONS_PER_KEY`, `YRL_NETWORK_CONNECTIONS_PER_ACCOUNT` and `YRL_NETWORK_QUANTUM_BYTES`.

Relay does not authenticate clients and therefore does not treat a rendezvous ID as identity. It limits joined pairs globally (4096) and per observed endpoint IP (64), reserves two 32 KiB buffers per pair from a 256 MiB global pool, and fairly rotates opaque 16 KiB chunks between pairs. Existing connection/waiting limits and the optional per-pair lifetime byte cap remain. `YRL_RELAY_ACTIVE_PAIRS`, `YRL_RELAY_ACTIVE_PAIRS_PER_IP`, `YRL_RELAY_BUFFER_BYTES_TOTAL`, `YRL_RELAY_BUFFER_BYTES_PER_DIRECTION`, `YRL_RELAY_QUANTUM_BYTES` and `YRL_RELAY_MAX_BYTES_PER_PAIR` are validated startup overrides. All pair/IP/buffer capacity is RAII-released. Focused tests are compiled but intentionally not run.

Stage 5.5 adds an Executor-only persistent ledger for managed `FILE_PUT` reservations. Admission reserves the complete announced size atomically against 64 GiB global and 16 GiB per-device/per-account defaults before the target-user helper can write. The same serialized decision retains a 1 GiB default free-space floor, preventing parallel uploads from overcommitting currently available space. Overrides are `YRL_DISK_BYTES_TOTAL`, `YRL_DISK_BYTES_PER_KEY`, `YRL_DISK_BYTES_PER_ACCOUNT`, `YRL_DISK_FREE_RESERVE` and `YRL_PARTIAL_TTL_SECS`; none is an I/O rate limiter.

Managed partials carry a random xattr tied to the ledger. Helper open/resume requires `O_NOFOLLOW`, a regular file owned by the target uid, exactly one hard link and the matching token. The ledger is atomic and survives restart; the exact principal/path/size resumes the existing charge rather than acquiring a second one. Untagged legacy/user files and mismatched tags are refused, not cleaned. Active reservations are excluded from TTL cleanup; inactive tagged partials default to seven days and are revalidated before deletion. RAII releases reservations exactly once on completion, abort, error, revocation or session termination. A transport loss does not end the transfer task, so RESUME keeps its cgroup, partial and reservation. ENOSPC/EDQUOT has a distinct result. BLAKE3 verification and atomic final rename are unchanged.

The disk budgets are reservations for YRL-managed uploads, not filesystem usage accounting for arbitrary programs. EXEC and PTY processes use the account's OS identity and can write anywhere that identity is already allowed; cgroup I/O controls limit load, not capacity. Enforce filesystem user/project quotas or a dedicated volume when those writes must share a hard storage quota. This is also the trust boundary for name manipulation by the same OS identity; the FILE_PUT helper itself refuses symlink, hardlink and token aliasing. Audit journal rotation is implemented separately in Stage 6. Focused disk tests are compiled but were not run.

Stage 5.6 adds an Executor-local persistent operation journal without distributed consensus. EXEC and typed ROOT write `ACCEPTED` durably before execution/client confirmation, then `RUNNING`; terminal state remains queryable until client acknowledgement. Identity is `(device key, account, request id)` plus operation kind and request digest. Acknowledgement removes the retained result but leaves an anti-replay tombstone. The journal defaults to 100,000 records and fails new admission closed at its bound rather than making an expired identifier executable again. `YRL_OPERATION_RECORDS` configures the ceiling.

An Executor crash converts persisted incomplete operations to `UNKNOWN` at restart and never re-executes them. Its sessions are lost, its service cgroup kills remaining children, and every pending client waiter receives `SESSION_LOST`; callers needing later status use a stable request id and query after reauthentication with the same key/account. No claim is made that a destroyed PTY can be restored or that an external EXEC side effect can be proved absent. Gatekeeper restart is different: Executor remains alive and continues to own the session, cgroup, Link state and RESUME window.

Broker EOF after proof submission produces `UNKNOWN`; failure before execution is definite. Audit still verifies its chained journal on open and refuses service on damage. Firewall installs its closed baseline before readiness. Executor process-local permits vanish with the dead process, while the persistent managed-upload ledger reloads reservations and tagged partials. All services use systemd `Type=notify`, a 30-second watchdog and the existing bounded restart policy. Recoverable dependencies are `Wants`, allowing independent restart without weakening fail-closed authorization, Audit or Firewall decisions. Focused journal/session-loss/watchdog/unit tests were prepared but intentionally not run; compilation passed.

## Stage 6 trusted audit and delivery

Audit retains its original canonical record chain but rotates into signed, monotonically numbered segments. Signed active state, start/end boundaries, deletion witnesses and crash completion prevent silent gaps; storage exhaustion closes mandatory recording fail-closed. Portable anchors can be retained independently and the separate `yrl-audit` tool classifies complete, partial, damaged and unverifiable history without a private key or running service. Authenticated export snapshots never include `sign.key` or user plaintext payloads.

Audit signing keys now form cross-signed Ed25519 generations rooted at `audit/root.pub`. Planned rotation requires an encrypted Stage 4 backup and proof by old/new keys. Emergency rotation requires a pretrusted offline recovery key, preserves the unverifiable old tail as orphan evidence and marks the affected history partial. Revocation does not retroactively claim that a compromised key's historical signatures prove truth. A complete local rollback still requires an independently retained anchor to detect.

`yrl-release` uses a separate offline root and bounded delegated keys. Its signed canonical manifest covers release number, platform/architecture, validity, persistent-format compatibility and the exact artifact set. `yrl-update` accepts only a separately trusted root chain, persists release/time high-water marks, stages and health-checks a complete release, switches one directory pointer atomically and retains a crash transaction. Rollback is limited to the prior ledger entry and never lowers the maximum. Update Audit events are mandatory. The updater has no downloader, generic command field, timer or automatic enablement; services are restarted separately by the administrator.

The current persistent data format is 1. Releases targeting another format fail closed until a reviewed built-in transactional migration exists; package-supplied migration scripts are not executed. Time expiry depends on the host clock, and root can roll back both trust and update ledgers unless their fingerprints/state are retained independently. A real production root/delegation, reproducibility comparison, signed publication, offline installation, interrupted activation/recovery and coordinated installed-service restart remain acceptance work, not claims of this implementation pass.

## Remaining limits and pending checks

1. Run the complete workspace suite and the cross-stage route/revocation scenarios at a final integration gate. Test the installed units with real Linux service users, seccomp/capability and mount inspection, delegated cgroup v2 controllers, per-session OOM/pids exhaustion, systemd service budgets/restart storms and nftables. This development environment did not establish those deployment-wide properties.
2. Test offline recovery on a separate host: GnuPG key availability, trusted origin and public fingerprints, ownership remapping, large journals, interrupted rotation, and service restart. Backup encryption does not supply sender authentication. Audit journal-signing-key rollover and a signed chain between journal eras remain open.
3. Host-root operations deliberately retain broad host authority and can escape delegated cgroup containment. A compromised Gatekeeper or relay can deny service and expose metadata. The seccomp policy is a denylist. Gatekeeper restart preserves an Executor session only within its existing RESUME window; Executor restart always means `SESSION_LOST`. Incomplete accepted operations become `UNKNOWN`, never automatic retries. Managed partial reservations survive and can be resumed only by a new authorized session with the same key/account/path/size.
4. OS-level disk encryption or a hardware-backed key store is needed to resist physical disk theft while keeping unattended service startup. The current code does not provide TPM-backed live key storage or a second-device approval flow.
5. UDP still has no path-MTU discovery; NAT hole punching, UDP relay, multipath, route racing and adaptive route scoring are absent. Broker operations are deliberately limited to typed primitives. Desktop and additional-OS support remain unimplemented. Product proposals in `docs/DESIGN.md` and `docs/DESKTOP.md` must not be treated as delivered features or started as incidental work.

## How to continue

Continue Stage 7 sequentially from the latest published substage. Keep every new profile default-off until Stage 8, do not replace a missing standardized construction or reviewed library with project-specific cryptography, and record an exact blocker where the requested guarantee cannot safely be delivered. Do not touch YANDI NODE, Private Discovery, multipath, route racing or Stage 8 acceptance work.
