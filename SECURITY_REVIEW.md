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
