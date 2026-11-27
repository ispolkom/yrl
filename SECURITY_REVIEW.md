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
