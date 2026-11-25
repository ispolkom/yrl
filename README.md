<div align="center">

# YRL

### YANDI Remote Link

**Secure, resilient remote access for machines you control.**<br>
Structured commands, real terminals, resumable file transfers, restricted tunnels, untrusted relays, and explicit privilege boundaries — without relying on a central service.

[![Language](https://img.shields.io/badge/language-Rust-dea584)](Cargo.toml)
[![Platform](https://img.shields.io/badge/platform-Linux-1793d1)](#honest-status)
[![Protocol](https://img.shields.io/badge/transport-Noise%20IK-6f42c1)](docs/WIRE.md)
[![Status](https://img.shields.io/badge/status-working%20prototype-orange)](#honest-status)
[![Tests](https://img.shields.io/badge/tests-150%2B%20integration-2ea043)](#verification)

[**Quick start**](#quick-start) · [Features](#features) · [How it works](#how-it-works) · [Security model](#security-model) · [Honest status](#honest-status) · [Documentation](#documentation)

</div>

---

> [!WARNING]
> **YRL is a working research prototype, not an independently audited security product.** Its security properties are extensively tested, but it should not yet protect systems where a failure could endanger people or irreplaceable data.

## Why YRL?

YRL stands for **YANDI Remote Link**. It is an SSH-like remote access system designed around three priorities:

1. **Security** — a device key and account password are both required; permissions are the intersection of the key and account grants.
2. **Reachability** — sessions survive network outages and can reach a server behind NAT through an untrusted relay.
3. **Performance** — interactive work stays responsive while commands, files, terminals, and tunnels share one encrypted session.

The relay and network-facing process are deliberately not trusted with machine privileges.

## Features

| Feature | State |
|---|---|
| **Key + password login** with Argon2id and bounded lockouts by device key and address | works |
| **Structured execution** through `yrl exec`, without invoking a host shell | works |
| **Interactive shell** on a real PTY, including resize, Ctrl-C, and disconnect cleanup | works |
| **Resumable file transfer** with BLAKE3 verification and atomic final placement | works |
| **Directory operations** and a mouse-enabled terminal file browser (`yrl visual`) | works |
| **Restricted forwarding and SOCKS5**, denied by default unless allowed by server policy | works |
| **Resumable sessions** across repeated TCP disconnects without loss or duplication | works |
| **Automatic route failover** from configured UDP to direct TCP to TCP relay, preserving the live session | works |
| **Reliable ordered stream over UDP** with loss recovery, congestion windows, and silence for strangers | works; see [limits](docs/UDP.md#not-implemented) |
| **Server behind NAT through `yrl-relay`**; relay sees ciphertext and metadata only | works |
| **Privilege separation** between gatekeeper, executor, broker, firewall, and audit processes | works in tested deployments |
| **One-operation SUDO/ROOT step-up** with separately pinned executor/broker keys | prototype; privileged operations are intentionally limited |
| **Hash-chained audit logs** with signed checkpoints and source authentication | works |
| **Single-packet authorization (SPA)** in front of the working port | works in tests and an isolated real nft network |
| **Remote desktop** | designed, not implemented; see [DESKTOP.md](docs/DESKTOP.md) |
| Windows, macOS, Android | not implemented |

## How it works

```text
 client
   │  Noise IK + key authorization + account password
   ▼
 gatekeeper ─────► audit
   │               append-only, hash-chained events
   │ authenticated local IPC
   ▼
 executor ───────► broker
   │               typed ROOT operations only
   ├── command / PTY
   ├── file helper
   └── restricted tunnel
```

- The **gatekeeper** is the only component exposed to the network. It authenticates, owns session transport, and runs behind `no_new_privs` + seccomp, but cannot execute commands or access privileged broker operations directly.
- The **executor** rechecks account and key permissions, selects the OS identity, and performs user-level work.
- The **broker** accepts only typed ROOT-level requests from the executor. It cannot run arbitrary shell commands.
- The **audit process** authenticates every local source and writes separate ordinary and security logs with a BLAKE3 chain and Ed25519 checkpoints.
- The optional **firewall process** is the only component with `CAP_NET_ADMIN`; it opens a short-lived nftables path only after a valid SPA knock has been recorded.
- An optional **relay** joins two byte streams. End-to-end Noise encryption remains between the client and server.

The session layer sits above TCP, UDP, or relay transport. The client selects configured routes in that order and moves to the next one when liveness fails. Numbered frames, cumulative acknowledgements, bounded retransmission buffers, and RESUME allow a live terminal, file transfer, or tunnel to continue after a connection is replaced. Control and interactive frames are scheduled ahead of unsent bulk file data.

## Quick start

Requires Linux and a stable Rust toolchain.

```bash
# build all binaries
cargo build --release -p yrl

# create server and client identities
./target/release/yrld init srv
./target/release/yrl keygen cli

# authorize the printed client key and create an account
./target/release/yrld authorize srv <CLIENT_PUBLIC_KEY> laptop exec,shell,files,tunnel
./target/release/yrld passwd srv anna exec,shell,files,tunnel

# development mode: all server components in one process
./target/release/yrld serve srv 0.0.0.0:2222

# connect from another terminal or machine
./target/release/yrl shell cli host:2222 <SERVER_PUBLIC_KEY> anna --executor <EXECUTOR_PUBLIC_KEY>
```

For a server behind NAT:

```bash
yrl-relay 0.0.0.0:7000
yrld serve srv - --relay relay.example:7000
yrl shell cli ignored:0 <SERVER_PUBLIC_KEY> anna --executor <EXECUTOR_PUBLIC_KEY> --relay relay.example:7000
```

Production-style installation uses separate system users and systemd units. Read [deploy/INSTALL.md](deploy/INSTALL.md) before running `sudo ./deploy/install.sh prepare …`; preparation does not start services or touch firewall rules.

## Security model

YRL follows a closed-by-default chain:

```text
device identity → authorized key → account password → intersected rights → typed action
```

Important properties:

- unknown client keys receive no response bytes;
- the client pins the server key, and step-up separately pins executor/broker keys;
- permissions are recomputed from server-owned files and cannot be supplied by the client or gatekeeper;
- malformed or replayed protocol messages fail closed;
- secrets, typed passwords, raw paths, and destination addresses are excluded from audit schemas;
- lockout stores are authenticated on disk and fail closed when damaged;
- privileged actions do not proceed when the security audit cannot record them;
- the relay is allowed to observe timing and volume and to deny service, but not to decrypt or modify traffic undetected.

The complete threat-to-test traceability matrix is in [docs/THREATS.md](docs/THREATS.md).

## Verification

The workspace contains more than 150 integration tests covering happy paths, malformed frames, replay, lockouts, privilege boundaries, audit integrity, network interruption, file safety, terminal behavior, tunnels, SPA, nftables, relay attacks, and UDP loss/reordering.

```bash
cargo test --workspace --all-targets
```

Security rules are also checked with targeted source mutants listed under `tools/mutants*.json`: each mutant must be caught by a test rather than merely covered by a line counter.

## Honest status

**Working prototype, not a finished product.** The core Linux scenarios are implemented and heavily tested, but the project has not had an independent security audit.

- Real privileged broker operations are deliberately incomplete; current operations are typed test/restart primitives, not a general root shell.
- Remote desktop, Windows, macOS, and Android clients are not implemented.
- UDP lacks NAT hole punching, UDP relay, path-MTU discovery, in-place address migration, and pacing. Automatic failover uses a fresh Noise-authenticated connection and RESUME; it does not race or score routes.
- Sessions survive connection loss but not an `yrld` restart; active session state is currently in memory.
- The transport does not yet include hybrid post-quantum key exchange (ML-KEM).
- PAKE/OPAQUE, FIDO2/TPM-backed confirmation, and second-device approval are planned hardening steps.
- Audit logs need deployment-level append-only protection, off-host checkpoint retention, and rotation.
- Metadata such as IP addresses, timing, and traffic volume remains visible to the network or relay.

Do not treat a secret port, SPA, or an untrusted relay as authentication. Device keys, passwords, explicit rights, and end-to-end cryptography remain mandatory.

## Documentation

| Document | Purpose |
|---|---|
| [DESIGN.md](docs/DESIGN.md) | product goals, architecture, streams, operations, and roadmap |
| [WIRE.md](docs/WIRE.md) | Noise handshake and the original wire framing |
| [THREATS.md](docs/THREATS.md) | security requirements mapped to tests |
| [RESILIENCE.md](docs/RESILIENCE.md) | resumable sessions and relay behavior |
| [UDP.md](docs/UDP.md) | reliable stream over UDP, security properties, and limits |
| [DESKTOP.md](docs/DESKTOP.md) | remote-desktop design and prerequisites |
| [INSTALL.md](deploy/INSTALL.md) | separated system users, systemd services, and deployment checks |
| [COPIED_FROM.md](COPIED_FROM.md) | provenance and known properties of code copied from YANDI |

## Repository layout

```text
crates/yrl/          YRL client, server, relay, protocols, and integration tests
crates/yrl_link/     link code copied from the YANDI node for evaluation
crates/key_root/     copied key-root library
deploy/              installer, systemd units, and environment example
docs/                architecture, protocol, threat model, and design notes
tools/               mutation-test manifests and runner
```

## Development principles

Threats and failing tests come before implementation. Every security promise should have a test that fails against a deliberately broken mutant. Negative findings and known limitations are documented rather than hidden.

The upstream YANDI source tree is not changed or committed as part of YRL work without separate authorization.
