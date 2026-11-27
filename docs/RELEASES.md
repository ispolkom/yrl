# Trusted YRL releases

`yrl-release` uses Ed25519 signatures and BLAKE3 artifact hashes. Release trust is independent of GitHub, HTTPS, CDN certificates, Audit/Noise/device keys and the host being updated. This repository contains no production private key.

Generate the root on an offline owner-controlled machine and keep `root.key` encrypted and offline:

```text
yrl-release keygen root.key root.pub
yrl-release trust-init root.pub release-trust
```

Install `release-trust/` initially from a physically or otherwise independently authenticated copy. Record its root fingerprint out of band. Copying a key from the same download server as the first release does not establish independent trust.

Generate a delegated key separately, then use the offline root to issue a bounded delegation. Times are Unix seconds and release-number bounds are inclusive:

```text
yrl-release keygen delegated.key delegated.pub
yrl-release delegate release-trust root.key delegated.pub 1 VALID_FROM VALID_UNTIL MIN_RELEASE MAX_RELEASE delegation.txt
```

`deploy/build-release.sh NEW-DIR` builds all YRL binaries with `--release --locked` and adds source/toolchain provenance. This documents inputs; it does not claim reproducibility. Reproducibility may be claimed only after independent builders compare every artifact hash under a pinned compiler, target, dependencies and build environment.

Create one manifest for the entire directory and sign it with the delegated key:

```text
yrl-release manifest artifacts RELEASE VERSION linux x86_64 DATA_MIN DATA_MAX DATA_TARGET CREATED EXPIRES DELEGATION_GENERATION manifest.txt
yrl-release sign manifest.txt delegation.txt delegated.key manifest.sig release-trust
yrl-release verify artifacts manifest.txt manifest.sig delegation.txt release-trust NOW
```

Publish the artifacts, manifest, signature and delegation together. The verifier uses only the separately installed trust store. It rejects missing, additional, modified or mixed-release components, expired metadata, out-of-scope release numbers and revoked delegations.

Root rotation is cross-signed by old and newly generated roots:

```text
yrl-release root-rotate release-trust old-root.key new-root.key new-root.pub
```

Distribute the updated trust store over an authenticated channel. Revoke a delegated key with the current offline root using `yrl-release revoke`. Root/private delegated keys must never enter the repository, release bundle, CI logs or command output. CI may hold a narrowly scoped delegated key only under the project's explicit secret-management policy; the root remains offline.

## Hybrid release trust

A build with `hybrid-signatures` can provision a separate hybrid trust store. Run `yrl-release hybrid-keygen release-root 0 ROOT_KEY ROOT_PUBLIC` and initialize the store with `yrl-release trust-init ROOT_PUBLIC TRUST_DIR`. Generate delegates with `hybrid-keygen release-delegated GENERATION KEY PUBLIC`. Pass the exact generation to `delegate`. The existing `delegate`, `sign`, `verify`, `root-rotate` and `revoke` commands derive the signature profile from the pinned release root. The updater uses the same trust store and verification code. A hybrid trust store requires Ed25519 and ML-DSA-65 at each verification step. Importing a different root is an explicit trust provisioning operation. Keep the pinned root and state on trusted storage.

Classical trust stores and their wire formats remain supported. The hybrid key files are separate from classical keys. Hybrid mode requires explicit trust setup. Pre-register a distinct offline `recovery` public key with `root-recovery-init TRUST PUBLIC`. Use `root-recover TRUST RECOVERY_PRIVATE NEW_PRIVATE NEW_PUBLIC` for a lost hybrid root. The recovery key and replacement root sign the same transition, and update verification rejects delegations issued by earlier roots after an emergency transition.
