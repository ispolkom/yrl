# Stage 4 key and secret acceptance

## Storage and service startup

YRL's live Noise and Audit private keys remain on the host as owner-only files. The installed service accounts and the `install` layout give each component access to its own key only. Key loading refuses links, hard links, wrong owners, insecure modes, oversized files, malformed key pairs and mismatched public files. Private Noise bytes and several temporary password and verifier buffers use `zeroize` on drop. The Ed25519 and X25519 implementations use their upstream zeroization features. Services start without an operator entering a password; the host's filesystem and disk encryption remain the root of trust for unattended startup.

On a deployed machine, verify the owner and mode of `static.key`, `ipc/*/static.key`, `audit/sign.key`, `users`, `words*` and `lockouts.*.key` with `yrld install check`. Start each service independently, check that it can load only its own private key, and verify no secret appears in logs, environment, argv, core dumps or child process descriptors. Test abnormal termination and restart as well as normal shutdown.

## Encrypted recovery copy

Stop all five services, provision a GnuPG public encryption key, and record its **full fingerprint**. The owner runs:

```text
yrld keys backup /var/lib/yrl /secure/offhost/yrl-backup.gpg RECIPIENT_FINGERPRINT
```

The command also takes an exclusive lock against running `yrld` services. It streams a bounded archive directly into GnuPG, rejects links and special files, omits stale Unix sockets, and creates the ciphertext with mode `0600`. No plaintext intermediate archive is written. Keep the GnuPG decryption key separately from the server and test that it can decrypt the archive. Protect the archive's origin: encryption to a public recipient alone does not authenticate who created it. Keep trusted copies of the server, Executor, Broker and Audit public fingerprints outside the archive.

Restore to a **new, absent** state directory, with service accounts installed first:

```text
yrld keys restore /secure/offhost/yrl-backup.gpg /var/lib/yrl-restored
yrld install layout /var/lib/yrl-restored
yrld install check /var/lib/yrl-restored
yrld audit verify /var/lib/yrl-restored
```

Compare restored public fingerprints with the trusted copies before starting services. Restore rejects malformed and tampered ciphertext, unsafe paths, duplicate files and excessive archive sizes. It keeps every extracted file private until verification finishes. If the service accounts are installed, it reapplies the repository's ownership table, including variable journal and lockout files. Practice recovery on a separate host with the intended account names and group IDs; do not overwrite a live state directory.

## Rotation, revocation and migration

Stop services before rotating a Noise identity. Each rotation requires a distinct encrypted recovery file:

```text
yrld keys rotate /var/lib/yrl executor /secure/offhost/before-executor.gpg RECIPIENT_FINGERPRINT
yrld keys migrate /var/lib/yrl /secure/offhost/before-migration.gpg RECIPIENT_FINGERPRINT
yrld keys revoke-device /var/lib/yrl DEVICE_PUBLIC_HEX
```

`rotate` supports `server`, `executor`, `gatekeeper`, `broker`, `audit`, `owner`, `firewall` and `firewall-door` Noise identities. It makes the encrypted recovery copy first, replaces the private file and public file, and prints the new public key. A crash between the two replacements leaves a mismatch that service key loading refuses; recover from the encrypted copy. Re-pin changed public identities on clients and restart the services together. A rotation intentionally ends old sessions; RESUME with the old identity must fail. Device revocation may run while services are active: it atomically removes one authorized key and the Stage 2 watcher ends its sessions. `migrate` validates legacy Noise key pairs and rewrites them with safe ownership and an encrypted recovery copy while preserving their public identities.

To rotate a **client device** identity, create a new client key in a new private directory, authorize its public half with the intended rights, verify a login, then run `keys revoke-device` for the old public half. Confirm old sessions end and old RESUME attempts fail. Remove the old private file from the device according to its storage medium's secure deletion procedure.

The Audit **journal signing** key is separate from the Audit IPC Noise key. It cannot be rotated in place without breaking verification of earlier records; preserve the signing key and journal together in the encrypted recovery copy. A future journal-era rollover would need an explicit signed chain of trust. This stage does not claim that capability.

## Targeted and extended checks

- `cargo test -p yrl --test keylife`: encrypted backup/restore, tamper rejection, identity rotation, migration, device revocation, private-file refusal and offline locking.
- `cargo test -p yrl --test audit_proc p1_four_programs_one_journal_and_the_owners_commands_in_it`: all separate services still authenticate and audit an operation.
- Repeat the Stage 0 route switching and RESUME scenarios and Stage 1 impersonation tests after each key operation. Verify a wrong or revoked pin fails closed, an unchanged pin still works after migration, and device revocation terminates active PTY, file, tunnel and command work.
- Interrupt rotation after the public-file replacement; verify startup refuses the mismatched pair, then restore the encrypted recovery copy and re-run the audit verification.
- Exercise backup and restore with journals near the archive size limit, malicious paths and links, missing GnuPG keys, wrong owner or mode, and service accounts with different numeric IDs.
