# Independent YRL security review

Baseline: b4744da.
Branch: bsi/security-review.

## REV-001: Concurrent cryptographic profile persistence

Priority: HIGH.

### Defect

Independently opened ProfileStore instances retained stale
snapshots and replaced the complete persistent profile map.

This permitted lost peer entries and overwriting a stronger
previously recorded profile with a weaker profile.

### Remediation

- Stable dedicated lock file.
- Exclusive flock during profile publication.
- Reload current persistent state under the lock.
- Reject profile regression against current state.
- Preserve entries belonging to other peers.
- Reject symbolic links and insecure lock files.
- Preserve atomic replacement and directory synchronization.

No wire-format or cryptographic algorithm changes.

### Verification

Before remediation:
- 10 PASS, 2 FAIL.
- Both lost-update and downgrade defects reproduced.

After remediation:
- Default and PQ feature regressions passed.
- Extended crypto_profiles: 16 PASS, 0 FAIL.
- Hybrid handshake: 1 PASS, 0 FAIL.
- Concurrent test: 32 independent writers.
- Repeated concurrency test: 20/20 PASS.
- Symlink and insecure lock rejection: PASS.
- Stable lock inode: PASS.

Status: FIXED within the verified regression scope.

Limits:
- Concurrent independent file descriptors were tested using threads.
- Separate-process stress and power-loss durability were not tested.
- Full workspace regression remains pending.

## REV-002: Durable upload publication

Priority: HIGH.

### Defect

The upload helper acknowledged success after rename and
reservation-tag removal without synchronizing the destination
directory and final inode metadata.

Atomic visibility did not imply crash durability.

### Remediation

- Synchronize file contents and permissions before rename.
- Remove the reservation tag after publication.
- Synchronize final inode metadata.
- Synchronize the destination directory.
- Acknowledge success only after all synchronization succeeds.
- Support absolute and relative destination paths.
- Propagate synchronization errors to the caller.

### Verification

Default configuration:
- File transfers: 15/15 PASS.
- Filesystem operations: 10/10 PASS.
- Resource limits: 5/5 PASS.

Hybrid-signatures configuration:
- File transfers: 15/15 PASS.
- Filesystem operations: 10/10 PASS.
- Resource limits: 5/5 PASS.

Direct helper syscall inspection with strace 6.1:
- Absolute destination: PASS.
- Relative destination: PASS.
- First file fsync EIO injection: PASS.
- Second file fsync EIO injection: PASS.
- Directory fsync EIO injection: PASS.

All injected synchronization failures returned ERR 13.
No injected failure produced an OK acknowledgement.
Successful publication preserved the requested permissions
and removed the partial-file reservation tag.

Status: FIXED within the verified regression scope.

Limits:
- Physical power-loss durability was not tested.
- Direct syscall fault tests used empty files.
- Errors after rename may leave a published target without
  a success acknowledgement.
- Write-only destination directories may require additional
  compatibility handling.
- End-to-end reservation recovery after injected fsync
  failures remains unverified.

## REV-003: Durable operation journal and exclusive ownership

Priority: HIGH.

### Defects

Directory synchronization failures were ignored during
operation journal publication.

Independent journal instances could retain separate snapshots
and overwrite persistent replay protection records.

Failed persistence could leave temporary files behind.

### Remediation

- Propagate directory synchronization errors.
- Enter a fail-closed journal state after persistence failure.
- Refuse further admission and state transitions while faulted.
- Do not report unconfirmed operation status.
- Do not assume rollback after uncertain publication.
- Require successful journal recovery before restoring service.
- Hold an exclusive flock for the journal lifetime.
- Retain ownership while outstanding operation guards exist.
- Reject symbolic links and insecure lock files.
- Remove temporary files after failed persistence.
- Preserve existing replay tombstones and journal format.

### Verification

Before remediation:
- 3 PASS, 4 FAIL.
- ACCEPTED, RUNNING, COMPLETED and ACKNOWLEDGED
  durability defects reproduced.

Initial remediation:
- Journal and integration regressions: 121 PASS, 0 FAIL.

Exclusive ownership remediation:
- Default journal: 15/15 PASS.
- Hybrid journal: 15/15 PASS.
- Hybrid integration: 44/44 PASS.

Real separate-process crash regression:
- Default configuration: PASS.
- Hybrid configuration: PASS.
- Repeated SIGKILL recovery: 20/20 PASS.
- Concurrent journal ownership refused.
- Kernel released ownership after SIGKILL.
- RUNNING recovered as UNKNOWN.
- Duplicate operation refused.
- Conflicting operation refused.
- Unrelated operation accepted after recovery.
- Persistent history preserved across reopen.

The ignored child test is a subprocess entry point invoked
explicitly by the parent crash test.

Status: FIXED within the verified regression scope.

Limits:
- Physical power-loss durability remains untested.
- Real process crash tests exercise the journal directly,
  not a complete installed Executor service.
- Already dispatched operations are not automatically
  terminated when the journal becomes faulted.
- Exclusive ownership assumes a trusted state directory.
- Full workspace and installed-system regression pending.

## REV-004: Durable disk reservations and exclusive ledger ownership

Priority: HIGH.

### Defects

Directory synchronization failures were ignored after
atomic ledger publication.

New reservations and resumed uploads could be admitted
without confirmed durable persistence.

Uncertain reservation release could enable further admission.

Independent DiskManager instances could overwrite each
other's persistent reservation records.

### Remediation

- Require successful directory synchronization.
- Establish a durable ledger baseline during startup.
- Hold exclusive flock for the DiskManager lifetime.
- Retain ownership while outstanding reservations exist.
- Enter fail-closed state after persistence failure.
- Refuse new reservations and resume while faulted.
- Conservatively retain uncertain reservation charges.
- Disable further destructive cleanup while faulted.
- Reject symbolic links and insecure lock files.
- Remove temporary files after failed publication.
- Preserve existing ledger format and reservation tokens.

### Verification

Before remediation:
- 7 PASS, 4 FAIL.
- All four targeted defects reproduced.

Initial remediation:
- Default disk tests: 11/11 PASS.
- Hybrid disk tests: 11/11 PASS.
- File transfers: 15/15 PASS.
- Filesystem operations: 10/10 PASS.
- Resource limits: 5/5 PASS.
- RESUME: 19/19 PASS.
- Total: 71 PASS, 0 FAIL.

Extended regression:
- Default disk tests: 18/18 PASS.
- Hybrid disk tests: 18/18 PASS.
- Conservative accounting after failed admission: PASS.
- Conservative accounting after failed release: PASS.
- Activity update failure: PASS.
- Partial preservation while faulted: PASS.
- Original reservation token after recovery: PASS.
- Exclusive ownership through reservation lifetime: PASS.
- Unsafe lock rejection: PASS.
- Temporary file cleanup: PASS.

Real separate-process crash regression:
- Default configuration: PASS.
- Hybrid configuration: PASS.
- Repeated SIGKILL recovery: 20/20 PASS.
- Concurrent ledger ownership refused.
- Partial contents and reservation xattr preserved.
- Original token preserved.
- Global quota enforced after recovery.
- Different principal refused access to reservation.
- Resume without double charging: PASS.
- Cancellation releases reservation and tagged partial.
- Full quota available after completed cleanup.

The ignored child test is a subprocess entry point
explicitly invoked by the parent crash test.

Status: FIXED within the verified regression scope.

Limits:
- Physical power-loss durability remains untested.
- Crash tests exercise DiskManager directly.
- Installed Executor fault recovery remains unverified.
- Existing transfers are not automatically terminated
  when the ledger becomes faulted.
- Cleanup performed before a persistence failure cannot
  be rolled back.
- Exclusive ownership assumes a trusted state directory.
- Full workspace and installed-system regression pending.

## REV-005: Durable privileged lockout state

Priority: HIGH.

### Remediation

- Require durable persistence before privileged approval.
- Propagate file and directory synchronization errors.
- Refuse approval when persistent lockout state is faulted.
- Serialize independent persistent store instances.
- Preserve a stable exclusive transaction lock inode.
- Reject unsafe transaction lock files.
- Publish a durable pending marker before state mutation.
- Preserve fail-closed behavior across process restart.
- Apply persistence checks to password and FIDO2 approval.

### Recovery contract

Ordinary administrative unlocking remains effective
without restarting a healthy running instance.

A detected integrity or persistence fault remains latched
in the affected instance. Local administrative repair
followed by service restart is required.

The persistent lock file is an intentional store artifact
and must not be removed during ordinary operation.

### Verification

- Default workspace regression: PASS.
- Hybrid-signatures and FIDO2 regression: PASS.
- Lockstore integration: 12/12 PASS in both configurations.
- Step-up integration: 17/17 PASS in hybrid configuration.
- Separate-process serialization: PASS.
- SIGKILL transaction recovery: PASS.
- Targeted persistence fault injection: PASS.
- Administrative repair and fresh-instance recovery: PASS.

Status: CONDITIONALLY ACCEPTED.

Limits:
- Physical power-loss durability remains untested.
- Combined storage failures can prevent durable
  publication of the refusal marker.
- The marker protects state mutation, not the entire
  credential verification interval.
- Direct proof-path persistence fault testing remains
  incomplete.
- Installed-service restart after integrity repair
  remains unverified.

## REV-006: Durable key-root storage transactions

Priority: HIGH.

### Remediation

- Require directory synchronization after publication.
- Preserve published files after uncertain persistence.
- Publish new files without replacing existing targets.
- Use renameat2 with RENAME_NOREPLACE.
- Preserve existing backup files during concurrent creation.
- Report incomplete rollback explicitly.
- Serialize high-level key-store mutations.
- Reject unsafe transaction lock files.
- Publish a durable pending transaction marker.
- Refuse normal root loading while a transaction is pending.
- Preserve key material after uncertain initial setup.
- Verify successful setup through both root wrappers.

### Verification

- Key Root: 47 PASS, 0 FAIL, 1 helper ignored.
- Default workspace regression: PASS.
- Hybrid-signatures and FIDO2 regression: PASS.
- All-target compilation: PASS.
- Concurrent publication and backup stress: PASS.
- Targeted setup persistence faults: PASS.
- Transaction completion persistence fault: PASS.
- Separate-process SIGKILL regression: PASS.
- Repeated crash regression: 20/20 PASS.
- Legacy-to-Root-V2 migration: PASS.
- Identity preservation during migration: PASS.
- Recovery using a different machine identifier
  without the original device key: PASS.

Status: CONDITIONALLY ACCEPTED.

Limits:
- A pending marker detects interrupted transactions;
  it is not a complete recovery journal.
- Verified recovery of interrupted transactions
  remains to be implemented.
- SIGKILL tests exercised storage transaction primitives,
  not interruption inside a complete migration.
- Not all low-level readers and writers participate
  in the transaction protocol.
- Marker recreation after uncertain removal is best effort.
- Physical power loss and recovery on a separate
  physical computer remain untested.
- Installed-system acceptance remains pending.

## REV-007: Cross-build cryptographic policy and CLI role identity

Priority: HIGH.

### Defects

The handshake ignored an invalid local cryptographic policy in builds without
`crypto-profiles`. A negotiated build rejected an offer containing a known,
optional profile that the local build did not implement. This prevented a
permitted common profile from being selected. Separately, `yrld init` published
persistent Executor and Broker keys, but `yrld serve` supplied neither key to
`ServerConfig`; the single-process runtime generated temporary identities.
Clients pinning the published Executor key could not authenticate.

### Remediation

- Validate local policy before handshake traffic in every build.
- Decode known profile identifiers independently of local implementation.
- Select only a locally implemented, mutually offered profile at or above both
  minimums. Preserve the existing high-water mark and no-fallback rules.
- Load the persistent Executor and Broker identities in `yrld serve`, verify
  their published public keys, and refuse startup if either is absent or
  inconsistent.

### Verification

- Initial REV-007 matrix: 60 PASS. Post-decoding matrix: 90 PASS.
- Focused invariant checks before CLI repair: 42 PASS, 0 FAIL.
- The old `yrld serve` with a valid published Executor pin: FAIL (`early eof`).
- The repaired Default → Default connection: PING/PONG PASS; repeat after
  service restart with the same pin: PASS.
- Missing and damaged persistent Executor keys: startup refused. Regression
  tests also cover missing, damaged and mismatched published keys for both
  Executor and Broker.
- VM cross-build matrix: 10/10 compatible negotiated or legacy pairs passed
  PING/PONG. All 6/6 legacy/negotiated mixed pairs failed closed with `early
  eof`; this remains the documented rolling-migration interoperability FAIL.
- Optional PQ: PQ ↔ PQ selected `0x00020001`; a classical-only client and a
  PQ-capable client with a server lacking PQ selected `0x00010001` when policy
  permitted. A mandatory PQ minimum refused a classical-only peer.
- The client's persisted `0x00020001` marks for Gatekeeper and Executor
  survived process and server restarts and prevented automatic downgrade.
- An unsupported minimum in a default build was refused.
- Full default workspace regression with one test thread: 534 PASS, 0 FAIL,
  7 ignored. An initial parallel run had one Key Root lock-contention FAIL;
  the isolated retry and complete sequential run passed. The first failure is
  retained as a test-concurrency observation, not attributed to REV-007.
- Full `crypto-profiles` regression: 447 PASS, 0 FAIL, 6 ignored.
- Full `pq-hybrid` regression: 448 PASS, 0 FAIL, 6 ignored.
- The first full `hybrid-signatures,fido2` run had one FAIL in the pre-existing
  slow-network `resume::r14` assertion: authenticated EXEC and upload worked,
  but the client reconnected once under the fixture's 40 ms per-block delay
  and 900 ms dead-link threshold. An isolated retry passed. A second full
  `hybrid-signatures,fido2` run passed: 456 PASS, 0 FAIL, 6 ignored. The
  first failure remains recorded and warrants follow-up in REV-011.
- The final `serve_identity` regression after test timeout hardening passed
  2/2 in the default build. The hybrid-signature proof integration also passed
  within the full hybrid suite.

The VM network blocker was the server guest's nftables `allowed4` set: it was
empty and port 2222 had an explicit drop. TCP/22 worked between both guests.
A temporary entry permitting only `192.168.77.12 . 2222` for two hours restored
YRL traffic. The host bridge had three forwarding TAP ports, VLAN filtering
off and bridge iptables hooks off; the host nftables service was active, but
reading its live rules required unavailable host sudo privileges. A network
timeout was not used as cryptographic evidence.

Status: CONDITIONALLY ACCEPTED within the tested scope.

Limits:
- The matrix used `yrld serve`, which does not establish installed
  separation of system users. Installed isolation acceptance remains REV-010.
- Hybrid-signature profile activation with provisioned signing keys was not
  part of this cross-build matrix; its existing focused suite is a separate
  check.
- The legacy/negotiated wire incompatibility remains a functional migration
  failure even though mixed connections fail closed.
- Physical hardware and power-loss behavior of REV-007 were not tested.
