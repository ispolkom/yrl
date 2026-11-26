# YRL — YANDI Remote Link: design v1 (2026-10-05)

Sources: the project requirements (fast file transfer; a visual, mouse-driven shell—in other words, a cross-platform remote desktop like TeamViewer—with security and speed as priorities); GPT's v0 specification (streams, operations, capabilities, audit, `request_id`); and an audit of the existing YANDI transport.

## 1. What YRL is

A secure, controlled session between two of the owner's devices—and later autonomous agents—providing a terminal and structured execution, files (replacing scp/rsync), tunnels, service management, **remote desktop with mouse and keyboard**, clipboard, and audio. There is no company-operated central server; identity = NodeID; relays are untrusted.

Invariant priority order: (1) security, (2) reachability behind NAT and filtering, (3) speed. Speed is never purchased by weakening security.

## 2. Architecture (GPT decisions accepted, with refinements)

- A shared `yandi-transport` library extracted from the current node is used by `yandi-node`, `yrld` (the managed-machine daemon), and `yrl` (the client). The network node receives **no** authority over the OS. Extracting the library is separate work in the upstream YANDI repository and requires explicit permission; until then, YRL uses a thin `trait Transport` interface with a test stub.
- Access chain: Identity → Pairing → Capability → Policy → Action. Confirming a NodeID means “this is that node,” not “this node is allowed.”
- The transport selects the route: direct UDP → NAT traversal → multipath → UDP relay → TLS/WS 443 → TCP. The application does not select a path.
- Resumption uses SessionID + a transport resume token, allowing Wi-Fi → mobile network → Wi-Fi without ending the session.

## 3. Streams and priorities

CONTROL and INPUT (keyboard and mouse) have the highest priority, followed by EXEC/STDOUT/STDERR, DESKTOP_VIDEO, DESKTOP_CONTROL, CLIPBOARD, AUDIO, FILE, TUNNEL, and finally TELEMETRY. Namespaces for DESKTOP_*, INPUT, CLIPBOARD, and AUDIO are reserved immediately.

One session has two delivery modes: reliable ordered delivery for commands, files, and clicks; and unreliable “latest value wins” delivery for mouse movement, cursor position, telemetry, and video frames whose value expires. A late frame or intermediate mouse point is not retransmitted; a newer value replaces it. This keeps the desktop responsive on a poor link. YANDI's cloned transport “carriages,” which duplicate data over two paths, are used selectively for CONTROL/INPUT and keyframes rather than doubling the entire video stream.

## 4. Operations (GPT v0 plus extensions)

SESSION_OPEN/RESUME; structured EXEC (executable, argv, cwd, environment changes, timeout, stdio modes, required capabilities) + EXEC_STATUS/CANCEL; FILE_STAT/LIST/READ/WRITE; TUNNEL_OPEN/CLOSE; CAP_LIST/REVOKE; and interactive SHELL as a separate mode of the same mechanisms. Every request has a `request_id`. After an outage, the client **queries state** (unknown/accepted/running/completed/failed/cancelled) instead of repeating the command. Completed results are retained for a bounded period. Operations are idempotent where possible.

Reserved for agents: PROCESS_*, SERVICE_*, LOG_SUBSCRIBE, SYSTEM_INFO, PATCH_FILE, and TRANSACTION_BEGIN/COMMIT/ROLLBACK.

## 5. Files: fast and rsync-like (owner's goal)

From day one, a file is a BLAKE3 hash tree over content-defined chunks (FastCDC, 64 KiB–1 MiB). Only missing chunks are transferred, providing rsync-like deltas and deduplication. Transfers resume after any outage and are verified while streaming. Performance uses parallel streams and multipath, adaptive zstd that skips already-compressed data, and direct disk-to-socket I/O without needless copies (`io_uring`/`sendfile` where available). FILE stays below INPUT priority so a large transfer does not increase cursor latency. Directories are Merkle trees, allowing folder synchronization in one request. Dangerous paths (`..`, outward symlinks) are canonicalized and rejected by a capability check on every read and write.

## 6. Remote desktop (like TeamViewer, without someone else's server)

- Capture: Linux X11 (XShm/XDamage), Wayland through the PipeWire portal, Windows through DXGI Desktop Duplication, Android client for viewing/input, and Android hosting later through MediaProjection.
- Encoding: hardware H.264/HEVC/AV1 where available, with VAAPI and software x264/SVT fallbacks; changed regions mean ordinary UI/text sends small updates instead of full frames; loss triggers keyframes on request.
- Cursor is separate from video: shape and position travel as data and the client renders it locally, yielding zero pointer-display latency.
- Mouse/keyboard: movement is latest-value-wins; clicks and keys are reliable and ordered; the client predicts and smooths movement.
- Adaptation: bitrate and quality follow transport measurements (loss and RTT). On a poor link, frame rate and resolution fall before input responsiveness.
- Verifiable latency goals: input-to-pixel ≤ 50 ms on LAN and ≤ 120 ms over the Internet with up to 5% loss.
- Desktop protection: explicit owner permission, with separate “confirm every connection” and unattended-access capabilities; a permanent active-session indicator on the host; optional host-screen blanking and lock-on-disconnect; policy-controlled recording; separate view/input/clipboard/audio permissions.

## 7. Security hardening

1. Noise handshake (XX for first contact, IK after pairing) with a **hybrid X25519 + ML-KEM exchange**, protecting relay traffic from “record now, decrypt later”; forward secrecy and key rotation in long sessions.
2. Capabilities as signed, attenuable tokens (macaroon/biscuit): the owner can grant “read `/srv/x` until Friday, at most three times”; a device can narrow but never widen a grant. Checks happen at action time; host-side revocation is immediate and its log is hash-chained.
3. `yrld` privilege separation: a small unprivileged broker plus sandboxed executors (Landlock/seccomp on Linux), with root only through a separate capability. Terminals and files do not share the network process.
4. Device keys in hardware-backed storage (TPM/Keystore/system keychain), recovery phrase kept separately; pairing only with physical presence (QR + short verification code) and attempt limits.
5. Clipboard and drag-and-drop are classic exfiltration channels: separate capability, size limits, no automatic paste, and audit logging.
6. Critical actions—changing permissions or network configuration, deleting data, disabling protection—require a second signature from another device or host-side confirmation.
7. AI agents receive capability budgets, a rehearsal/dry-run mode, a human approval queue, and rollback transactions.
8. Audit is built in: who, which identity and capability, what, when, result, and `request_id`; a hash chain (modeled after `yandi_mem`) makes silent editing detectable.
9. A relay sees only NodeID, sizes, and timing. Traffic, commands, capabilities, and files are end-to-end ciphertext. Policy can reduce metadata through packet-length padding and cover traffic.
10. DoS and scan resistance: the PC exposes no open ports; anonymous packets are rejected before expensive work through a cookie check; unpaired peers are rate-limited.

## 8. Cross-platform design

Protocol and cryptography live in a platform-free Rust library, `yrl-core`, tested with mutants. Platform adapters provide capture, input, clipboard, audio, and process access (Linux → Windows → macOS). Clients: native Linux with wgpu; Android with Kotlin + Rust through JNI (the node already has `mobile/`); Windows; and later a WebTransport client if useful. Delivery sequence: Linux host + Linux client → Android client → Windows.

## 9. Differences from TeamViewer/AnyDesk/SSH

No intermediary company or closed source; untrusted relays; identity is your NodeID; fine-grained, revocable permissions; the same protocol for people and AI agents; terminal, files, tunnels, and desktop in one session; operation without a public IP and through filters via YANDI transport.

## 10. Plan (tests first, like a laboratory)

0. Write WIRE.md (frames, streams, errors) and THREATS.md (threats → tests) before code.
1. Build network-free `yrl-core`: frames, multiplexer, handshake, capabilities, and audit; failing replay/tampering/downgrade/escalation tests plus mutants.
2. Terminal and EXEC over loopback, then through node transport; measure input latency.
3. Files (chunks, deltas, resumption) benchmarked against scp/rsync at 0/5/20% loss.
4. View-only desktop using X11 + NVENC, followed by input and cursor; treat latency goals as measurements.
5. Resume across address changes; exercise relay/443 paths under emulated filtering.
6. Android client, common-RPC panel, Windows.
7. Agent layer: structured RPC and transactions.

## 11. Questions for the owner

1. Should remote desktop be part of the first stage, or follow terminal/files? (Recommendation: terminal + files → viewing → input.)
2. Is there a target number of simultaneous connections—one device or several?
3. May `yandi-transport` be extracted into a separate library in the upstream YANDI repository (changing existing code with tests), or should work continue through a stub?
4. Are audio and clipboard transfer required in the first version?
5. After Linux, which client OS matters more: Android or Windows?

## 12. Server/client responsibilities

This decision combines my proposal with GPT's section 12, with corrections. The server is the source of truth for real machine state and the only authority that answers “is this allowed?” The client presents and controls that state. The server has a narrow interface but understands operation semantics, permissions, and OS state. Semantic actions are preferred to pixels and coordinates (`FILE_LIST` instead of clicking an icon; `SERVICE_RESTART` instead of typing a command). Graphics and mouse are used where no structured operation exists. Modes are structured (primary), visual (on demand, designed into the protocol immediately and retained as a product goal), and agent. An unprivileged broker works with sandboxed executors. A capability controls both the client's permission and which executor may be started at all; a desktop executor is not started on a headless machine.

Corrections and additions to GPT's proposal:

1. **Reactive resources instead of polling.** Server state is published as subscribable, versioned, typed resources (directory contents, process table, service status, log tail, terminal screen). The client subscribes to DELTAS (inotify/netlink) and caches by version. This reduces traffic and latency, supports a live phone UI, and gives humans and agents the same model. Request/response remains for actions such as EXEC and WRITE.
2. **A small fixed operation set plus a catalog of tasks and extension executors**, rather than an endless RPC list (`PROJECT_STATUS`, `PATCH_FILE`, ...). Every operation expands the attack surface of a privileged host. An extension is a separate executor with a manifest describing requested permissions and published resources, enabled by the owner. Platform differences such as systemd versus Windows services hide behind `ServiceManager`.
3. **A server-side terminal state emulator early, not “later.”** Screen state—grid, cursor, attributes, and scrollback on request—is required for correct resumption: after reconnect, the client receives a screen rather than a stream fragment, and can provide local echo. Raw streaming remains a fallback. Escape-sequence parsing is an attack surface and therefore runs inside the PTY executor sandbox.
4. **Distrust in both directions.** The client does not trust the host. Host data—file names containing controls, terminal escapes, OSC 52 clipboard operations, window titles, images, video—is parsed as untrusted input. The client is sandboxed, size-limited, and filtered. A compromised host must not gain control of the client.
5. **Remote desktop remains a product goal**, because the owner wants TeamViewer-like mouse control. Its streams and permissions are designed immediately; implementation alone waits until after the structured core.
6. A **host-capability manifest**—presence of a screen, service manager, supported codecs—is returned when a session opens. Message schemas are versioned using an evolvable compact binary format rather than JSON; the choice belongs in WIRE.md.
7. **TOCTOU and canonicalization:** paths and permissions are checked at action time, not request time; descriptors replace repeated name resolution.

Accepted from GPT unchanged: shared transport; identity ≠ permission; `request_id` and state queries after outages; separate STDOUT/STDERR; built-in audit; a GUI tree for agents after a stable first version; and the hybrid goal of application pixels alongside FILE/PTY/RPC.

## 13. Default shell: portable commands (owner's idea, 2026-10-05)

By default, a session opens in a terminal with familiar commands (`cd ls cp mv rm cat ps kill ip df …`); `visual` switches to visual mode. These are **not translations of Linux command lines into Windows commands**, but a portable verb set over structured server operations.

1. The CLIENT parses a verb (`ls`, `ps`, `ip`, `kill`, `rm`, ...) with a strict, simple grammar (name, arguments, quoting, and `>` redirection; no eval, substitutions, or nested shells) and produces a structured request (`FILE_LIST`, `PROCESS_LIST`, `NET_INFO`, `PROCESS_KILL`, `FILE_DELETE`, ...). The server performs it through native OS APIs: `ip a` reads netlink on Linux or calls GetAdaptersAddresses on Windows; it does not launch `ipconfig` and parse text. The response is data. The client renders familiar text such as `ls -l`/`ip a`, while `--json` exposes the same structured data to scripts and agents.
2. Be honest instead of pretending: every verb and flag has an OS support matrix. Unsupported behavior (`chmod 755` on Windows, unprivileged symlinks) returns “not supported on this host” instead of silently doing something different. Paths use a common virtual root (`/` on Linux and `/c/Users/...` on Windows, like WSL); the client hides case and separator details, while the real host path remains available.
3. An escape hatch always exists: `native` (or `!command`) opens the host's **real** shell in a PTY—bash/zsh on Linux, PowerShell on Windows, WSL when present—for anything outside the portable set. Modes are `yrl>` portable (default), `native`, `visual` (files/processes/logs/desktop panels), and `exit`.
4. Security: no host-shell parsing means no injection through substitutions. Each verb requires its own capability (`rm` ≠ `ls`). Destructive commands (`rm -r`, `dd`, `kill`) require confirmation or `--dry` according to policy; dry run shows the intended changes. `native` is a separate, stronger capability.
5. `visual` is a CLIENT command that changes presentation. If remote desktop is needed, the client requests DESKTOP_START and the server checks the capability. Tab completion uses a FILE_LIST subscription; history and suggestions remain local.
6. Pipelines: v0 supports one verb and redirection to a file. Nushell/PowerShell-style typed pipelines (`ps | where cpu > 50 | kill`) come later and operate on structured data rather than text. Nushell is a model, and possibly a native mode, but not the core because it is a large program on a privileged host.
7. AI agents do not need this shell; they call the same structured operations directly.

Proposed first verb set (about 25, subject to agreement): `cd pwd ls cat head tail cp mv rm mkdir touch stat find du df ps kill top uname uptime whoami ip hostname env which svc` (`status/start/stop/restart`), `logs`, and `ping`.
## Stage 7 cryptographic profile architecture

Cryptographic agility is represented by complete, versioned profiles rather than independently negotiable algorithm names. This prevents invalid combinations and keeps Gatekeeper, Executor and Broker cryptographic authority separate. The authenticated Noise transcript covers a canonical offer, role context and exact selected profile; persistent per-key/per-role high-water state adds downgrade memory across connections and transport changes.

Stage 7 additions are opt-in build features until Stage 8 acceptance. A failed handshake never causes an automatic weaker retry. New post-quantum, password, hardware-token and TPM profiles may be registered only when their standardized construction and maintained library satisfy the documented threat model; reserved or proposed algorithms are not advertised as supported.

Stage 7.2 uses a compound Noise construction rather than inventing KEM mixing: authenticated Noise IK negotiates and encrypts a Clatter PQ Noise NN handshake, whose key schedule is bound to the outer handshake hash using Clatter's hybrid dual-layer domain. Gatekeeper and Executor run independent upgrades. The extra round trip is accepted only in the explicit experimental profile.

OPAQUE is an Executor-owned multi-message protocol, not a replacement hash inside LOGIN. `opaque-ke` 4.0.1 performs RFC 9807 with Ristretto255/SHA-512 and client-side Argon2id. Its authenticated context binds account, device key, Executor role, profile and Noise transcript. Migration registration runs only after existing account authentication; records and the OPRF/AKE setup are private atomic state. OPAQUE login is explicit and cannot fall back. Broker step-up keeps its independent verifier until a separately keyed, operation-bound Broker OPAQUE protocol is designed and accepted.

Hybrid signatures require one common canonical envelope and lifecycle across identity, Audit, releases and recovery. Partial contour upgrades are not labeled hybrid, and asymmetric signatures remain handshake-time/control-plane operations rather than per-frame work.

FIDO2 is an optional policy implemented through a real CTAP2 client and standards-compatible relying party. Hardware policy is fail-closed; users without an enabled policy keep existing authentication. Broker owns an independent, operation-bound ROOT assertion flow.

TPM support is an optional local key backend. Policy records whether a role uses a TPM-native operation or a sealed software secret. Required TPM policy never falls back; absent policy keeps software operation. PCR binding is optional and must include an update/recovery workflow before activation.
