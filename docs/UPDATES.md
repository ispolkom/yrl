# Safe YRL updates

Automatic installation is disabled. `yrl-update.service` is a static, network-isolated oneshot unit with no `[Install]` section or timer. The owner must place a complete offline bundle locally and explicitly invoke the update.

A bundle contains `artifacts/`, `manifest.txt`, `manifest.sig`, and `delegation.txt`. Install the root trust store independently at `/etc/yrl/release-trust`; never take its initial key from the same untrusted server or bundle being verified. Configure only the local bundle path in root-owned `/etc/yrl/update.env`:

```text
YRL_UPDATE_BUNDLE=/path/to/offline/bundle
```

Then run `systemctl start yrl-update.service`. The updater:

1. verifies the root/delegation chain, validity windows, exact component set, sizes and hashes before copying anything;
2. rejects a release number at or below the persistent maximum and rejects metadata whose expiry regresses;
3. detects a backward system-clock jump relative to its persisted time floor (a correct trusted clock is still required to enforce expiry; an attacker who can freeze both network delivery and system time cannot be detected without an independent time/update source);
4. stages one complete release, fsyncs it, and runs the signed `yrld install check` with fixed arguments;
5. atomically replaces `/opt/yrl/current`, never individual component files;
6. retains a crash transaction and can finish it with `yrl-update recover TRUST /opt/yrl /var/lib/yrl-update /var/lib/yrl`;
7. records prepare/activate/failure/rollback over the authenticated owner Audit channel; unavailable Audit makes activation fail closed.

The updater never downloads code and has no generic command or ROOT-EXEC field. It executes only the verified `yrld` binary with the fixed health-check command. Persistent YRL state, keys, configuration, Audit journals, upload ledger and operation crash journal remain under `/var/lib/yrl` and are never copied into a release directory.

The manifest declares the compatible data-format interval and target. The current implementation has data format 1 and refuses any release requiring another format. Future migrations must be built into and reviewed with the updater, use a crash-safe transaction and preserve a rollback-compatible snapshot; signed package scripts are deliberately unsupported.

If post-activation health or mandatory Audit confirmation fails, the pointer returns to the immediately previous, pre-authorized release. Manual `rollback` is limited to that ledger entry. The maximum trusted release number and freshness floor are never reduced, so rollback does not authorize a later downgrade or replay. Revoked release delegations remain rejected. A host root can destroy or roll back the local updater ledger and trust store; detect that class of attack by independently retaining their fingerprints/state and Audit checkpoints.

The service does not restart running YRL components automatically. Existing processes continue with their mapped executable; the administrator performs the normal coordinated service restart after successful activation and observes health. This avoids an updater becoming a remote service-control or arbitrary execution channel.
