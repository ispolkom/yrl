# YRL v0.1 — threats and verification (every row = a failing test + mutant)

| # | threat | requirement | test |
|---|---|---|---|
| T1 | a scanner connects and sends garbage/nothing | return no bytes, close, do not panic | `garbage_gets_silence` |
| T2 | client with an unknown key | close silently with no response or distinguishable behavior | `unauthorized_client_gets_silence` |
| T3 | server substitution (MITM with another key) | client never completes the handshake | `wrong_server_key_is_refused_by_client` |
| T4 | tampered/corrupted/replayed/reordered transport frame | close; execute nothing | `tampered_replayed_reordered_frame_closes` |
| T5 | foreign protocol version | close silently | `wrong_version_is_dropped` |
| T6 | oversized frame/argument length or argument count | enforce bounds and close without allocating the claimed size | `oversized_inputs_are_bounded` |
| T7 | slow client holds resources | handshake and idle timeouts | `slow_handshake_times_out` |
| T8 | command without `exec` | ERROR; do not start a process | `exec_without_right_is_denied` |
| T9 | command exceeds its timeout | kill it and return EXIT -1 | `exec_timeout_kills_process` |
| T10 | keys leak into logs | log neither keys nor commands | `logs_do_not_contain_secrets` |
| T11 | loose key-file permissions | private keys must be 0600 in a 0700 directory; otherwise refuse startup | `key_files_must_be_private` |
| T12 | stolen client key | deleting its `authorized_keys` entry immediately affects new connections | `revoked_key_is_refused` |

## Login: key, then username and password (section L, `tests/login.rs`)

Order: Noise IK key authentication → LOGIN → LOGIN_OK(permissions) / LOGIN_FAIL. Session permissions = login permissions ∩ key permissions; the client does not declare a role.

| # | attack | requirement | test |
|---|---|---|---|
| L1 | command/ping/any frame before login | close without response; start nothing | `l1_*` |
| L2 | wrong password, unknown/miscased/spaced login, empty password | identical response without hints | `l2_*` |
| L3 | guessing on one connection | three attempts, then close even if the next password is correct | `l3_*` |
| L4 | guessing across connections | exponential lockout by key and address; correct passwords fail while locked; expiry is automatic; success clears the count; attempts during a lock do not extend it | `l4_*`, `l5_*` |
| L6 | fill the lockout table | bound it to 4096 entries | `l6_*` |
| L7 | username timing oracle | verify unknown names against a dummy hash at equivalent cost | `l7_*` |
| L8 | permission escalation | permissions come only from `users` and are intersected with key permissions | `l8_*` |
| L9 | append permissions/bytes to LOGIN, false lengths, truncation | reject | `l9_*` |
| L10 | replay a recorded login | useless in this or another session | `l10_*` |
| L11 | connect after key authentication and stay silent | login timeout | `l11_*` |
| L12 | second LOGIN inside a session | close the session | `l12_*` |
| L13 | password/account change; world-accessible `users` | changes apply immediately; an exposed file means no accounts at all | `l13_*`, `l14_*` |
| L15 | password, typed “login,” or hash in logs | none may appear | `l15_*` |
| L16 | connection flood | drop excess immediately and return slots | `l16_*` |
| L17 | correct password without the key | handshake fails before a password can be sent | `l17_*` |
| L18 | fuzzed frames/raw garbage | server remains healthy | `l18_*`, `l19_*` |

## Command identity (section I, `tests/identity.rs`, `src/identity.rs`)

An account in `users` may name an OS user (`os=name`). The identity is decided once at login and defaults closed.

| # | rule | test |
|---|---|---|
| I1 | when the server is root, an account without `os=` is denied, preventing accidental root grants | `i1_*` |
| I2 | a non-root server serves only accounts mapped to its own user; foreign/unknown users fail even with the correct password | `i1_*`, `i4_*` |
| I3 | uid 0 requires the `root` permission | `i1_*` |
| I4 | a program sees only HOME, USER, LOGNAME, PATH; server environment such as LD_PRELOAD/secrets is not inherited; start in the home directory | `i3_*` |
| I5 | validate usernames syntactically; discard an entire line with invalid `os=` | `i5_*` |

Not exercised live: uid/gid switching (`initgroups` + `setgid` + `setuid`, followed by verifying root cannot be regained), because this environment has no root. The surrounding logic is tested and must be run once on a root-capable machine before use. Known limitation: when started as root, the network handshake/login parser runs as root and only command children switch identity. Per-session privilege separation is the next stage; until then, run `yrld` as an ordinary user.

## Terminal (section P, `tests/terminal.rs`, `src/pty.rs`)

PTY_OPEN/IN/OUT/RESIZE/EXIT/CLOSE are frames 11–16. The account's login shell from `/etc/passwd` runs on a real controlling PTY; Ctrl-C, Ctrl-Z, and resizing use normal terminal mechanisms.

| # | requirement | test |
|---|---|---|
| P1 | input, output, and exit status arrive | `p1_*` |
| P2 | real controlling tty, with type/size and resize propagation | `p2_*` |
| P3 | Ctrl-C interrupts the program, not the session | `p3_*` |
| P4 | without `shell` in account ∩ key, no shell starts and input is discarded | `p4_*` |
| P5 | disconnect kills the shell and background children (HUP, KILL after 2 s) | `p5_*`, `p6_*` |
| P6 | terminal type is a short safe word, otherwise `xterm` | `p7_*` |
| P7 | limit terminals per connection and reject duplicate IDs | `p8_*` |
| P8 | large output uses backpressure without hangs or reordering | `p9_*` |
| P9 | malformed frames close the session; foreign IDs are harmless | `p10_*`, `p13_*` |
| P10 | no terminal before login | `p11_*` |
| P11 | clean environment; login shell (`-bash`); account user only | `p12_*` |
| P12 | shell must be executable and listed in `/etc/shells`, not nologin/false | `p13_*` |

Not verified: root-driven user switching for terminals and behavior outside Linux. Client syntax is `yrl shell <directory> <host:port> <server key> <login>`; local raw mode is restored on every exit, and pipeline EOF is sent as Ctrl-D.

## File transfer (section F, `tests/files.rs`, `src/files.rs`, `src/fshelper.rs`)

Requires `files`. A small `yrld fs-helper` process runs under the account identity, so the OS decides access. Integrity is a whole-file BLAKE3 hash. Only after a match is `<name>.yrl-part` renamed into place. Both directions resume.

| # | requirement | test |
|---|---|---|
| F1 | byte-identical round trips for size 0, frame boundaries, and 5 MiB | `f1_*` |
| F2 | without `files`, read/write nothing | `f2_*` |
| F3 | wrong hash/size leaves target untouched and removes the partial | `f3_*` |
| F4 | interrupted upload sends only the remainder; partial is hidden under its real name | `f4_*` |
| F5 | resume download; detect/remove a corrupted partial; restart if partial is longer than source | `f5_*` |
| F6 | more/fewer bytes than declared is an error and creates no file | `f6_*` |
| F7 | symlinks cannot redirect writes (`O_NOFOLLOW` on partial; destination symlink replaced, not followed); do not download directories/devices | `f7_*` |
| F8 | mask mode to 0777, stripping setuid/setgid/sticky; refuse unreadable files | `f8_*` |
| F9 | spaces, newlines, and command-looking names are data (hex to helper); reject empty/long/NUL paths | `f9_*` |
| F10 | bound size and concurrent transfers; reject duplicate IDs | `f10_*` |
| F11 | nothing before login; unknown IDs harmless; malformed frames close | `f11_*`, `f12_*` |
| F12 | helper enforces limits and returns ERR on garbage without crashing | `f15_*` |
| F13 | disconnect during download does not harm the server | `f14_*` |

Observed loopback speed in test builds: about 90 MiB/s upload and 135 MiB/s download; release with 200 MiB: about 200 MiB/s. This measures CPU and crypto, not the network. Limitations: paths are not jailed (OS-user permissions apply and `..` is allowed); writing one transfer blocks other frame reads on that connection; no compression or directory transfer yet.

## Tunnels (section T, `tests/tunnels.rs`, `src/tunnel.rs`, `src/client_tun.rs`)

Requires `tunnel` plus `<directory>/tunnels` rules (`<login|*> <host|*> <port|range|*>`); **deny by default**. The server connects to the destination and copies bytes. Clients use `yrl forward ... <local port> <host> <port>` and `yrl socks ... <local port>` (SOCKS5 bound only to 127.0.0.1).

| # | requirement | test |
|---|---|---|
| T1 | unmodified bidirectional bytes (5 MiB) and half-close | `t1_*`, `t8_*`, `t17_*` |
| T2 | without rules, deny without contacting the destination | `t2_*` |
| T3 | exact logins, case-insensitive hosts, ranges; malformed rule grants nothing | `t3_*` |
| T4 | reread rules for every request; ignore a file writable by others | `t4_*` |
| T5 | without `tunnel`, open nothing | `t5_*` |
| T6 | scanning cannot distinguish open and closed destination ports | `t6_*` |
| T7 | allowed but unreachable destination fails quickly; connect timeout | `t7_*` |
| T9 | bound tunnel count; close returns capacity | `t9_*` |
| T10 | no tunnels before login; malformed frames close; foreign IDs harmless | `t10_*`, `t16_*` |
| T11 | disconnect closes destinations; tunnel close fully releases server socket | `t11_*`, `t17_*` |
| T12 | eight parallel local connections get their own bytes and leave no client accounting | `t12_*`, `t18_*` |
| T13 | SOCKS5 address/name, policy denial (2), connect denial (5), BIND (7), bad address type (8), garbage | `t13_*`, `t14_*` |
| T14 | destination addresses never enter logs | `t15_*` |

Limitations: unauthenticated SOCKS5 listens only on loopback; no reverse (`-R`) tunnels; one slow transfer delays other frame reads until per-stream session windows exist; server-side DNS prevents client DNS leakage but exposes names to the server.

## Resumable session (sections S/R, `tests/link.rs`, `tests/resume.rs`, `src/link.rs`)

A session is not a connection. After login, every frame is numbered (SEQ), acknowledged (ACK), and retained until acknowledged. A new key-authenticated connection sends RESUME and continues at the exact point described in `docs/RESILIENCE.md`.

| # | requirement | test |
|---|---|---|
| S1 | exactly once, in order, across hundreds of breaks (6,000 frames each way) | `s1_*` |
| S2 | bounded unacknowledged window; producer waits with no loss/unbounded memory | `s2_*`, `r13_*` |
| S3 | reject gaps, ACK beyond sent, foreign kinds, malformed frames, ACK rollback | `s3_*` |
| S4 | ignore duplicates and continue | `s4_*` |
| S5 | a new connection replaces a hanging old one; closed session cannot resume | `s5_*`, `s6_*` |
| S6 | silence marks a dead link; probes keep idle links alive | `s7_*` |
| R1 | same terminal process and memory after outages | `r1_*` |
| R2–R5 | upload/download (48 MiB each), 60,000 terminal lines, and 30 MiB tunnel survive repeated random breaks without loss/duplicates/reordering | `r2_*`–`r5_*` |
| R6 | detect and replace a silent open socket | `r6_*` |
| R7 | absent client expires the session, ends shell, and yields clear “session lost” errors | `r7_*` |
| R8 | only the same key can take a session; foreign/unknown key or malformed sid is rejected/silent | `r8_*` |
| R9 | sid guessing is locked out like password guessing | `r9_*` |
| R10 | graceful close ends immediately; network break does not | `r10_*` |
| R11 | bound sessions globally and per key | `r11_*` |
| R12 | sessions do not interfere | `r12_*` |
| R14 | slow network remains slow without reconnect churn | `r14_*` |

A race found by S1—cancellation between “frame accepted” and delivery to the consumer—was fixed by reserving capacity before deciding. Sessions live in server memory, so restarting `yrld` destroys them and clients receive “session lost.”

## Relay (section RL, `tests/relay.rs`, `src/relay.rs`, `yrl-relay`)

A server behind NAT **dials out** with `yrld serve <directory> - --relay host:port`; the client uses the same rendezvous ID (hash of server public key) and `--relay`. The relay joins sockets; the normal client↔server handshake runs over them.

| # | requirement | test |
|---|---|---|
| RL1 | commands, terminal, and files work through relay | `rl1_*` |
| RL2 | relay sees only ciphertext: no password, commands, content, or client keys | `rl2_*` |
| RL3 | bit-changing relay cannot pass modified data; reconnect preserves file integrity | `rl3_*` |
| RL4 | fake relay-side server is rejected and sees only the first handshake message, never password | `rl4_*` |
| RL5 | silence for garbage, unknown ID, wrong roles, truncated/invalid header | `rl5_*` |
| RL6 | limits by ID/address, connection count, and wait duration | `rl6_*` |
| RL7 | vanished server cannot be paired | `rl7_*` |
| RL8 | sequential and simultaneous clients | `rl8_*` |
| RL9 | relay disappears and returns while session/shell survive | `rl9_*` |

An untrusted relay can deny service by consuming wait slots or server spares; limits mitigate but cannot prevent this. The server does not know relayed client addresses, so address lockouts do not apply, while key lockouts do. Timing and volume metadata remain visible. UDP relay, hole punching, WebSocket-on-443, and multiple relays are not implemented.

## Route failover (`tests/routes.rs`, `src/client.rs`)

The client tries configured UDP, direct TCP, and TCP-relay routes in that order. Every replacement route performs Noise IK again and may only continue the existing server session through RESUME; route selection never bypasses key authorization or session rights.

| Test | Requirement |
|---|---|
| `udp_to_tcp_*` | an active command and PTY survive UDP → TCP; the command side effect occurs once; one server session remains |
| `direct_tcp_to_relay_*` | the same PTY, file transfer, tunnel, and server session survive direct TCP → relay |

Attempts, route timeouts, queued bytes, recovery time, and retry intervals are bounded. Diagnostics expose transport type and counters, not endpoints, identities, or payloads. Fixed route order is availability policy, not an authentication decision.

## Directories and `visual` mode (sections D/V, `tests/fsops.rs`, `tests/visual*.rs`)

With `files`, the account-identity helper lists/stat/canonicalizes, creates one directory level with a masked mode, removes files/symlinks/empty directories, and renames without replacement (`renameat2 NOREPLACE`).

| # | requirement | test |
|---|---|---|
| D1 | distinguish file/directory/symlink/other without following links; odd and non-UTF-8 names are data | `d1_*` |
| D2 | return all 3,000 directory entries exactly once | `d2_*` |
| D3–D6 | stat/real/mkdir/rm/mv boundaries and refusal without collateral damage | `d3_*`–`d6_*` |
| D7 | no `files`, no effect; nothing before login; malformed requests close | `d7_*` |
| D8–D9 | exact non-panicking codecs; helper returns an error on garbage | `d8_*`, `d9_*` |
| V1–V4 | parse keys and SGR mouse from fragmented bytes, lone Esc, garbage, endless sequences | `v1_*`–`v4_*` |
| V5–V8 | sorting, movement, scrolling, return path, click/double-click/wheel/off-target input | `v5_*`–`v8_*` |
| V9 | bottom buttons are clickable; omit overflow on narrow screens | `v9_*` |
| V10–V12 | validate create/rename/upload/go-to prompts; safe line editor; delete requires literal `y` | `v10_*`–`v12_*` |
| V14 | control sequences, OSC/DCS/APC/C1, bidi overrides, and zero-width characters in names/errors render as harmless text | `v14_*`, `e2_*` |
| V15 | reject foreign-list entries that are not one ordinary name; downloads cannot escape the directory or overwrite | `v15_*`, `e1_*` |
| V16 | render exactly within every screen from 1×1 through 200×300 | `v16_*` |
| V18–V19 | incoming listing does not cancel prompts; selection follows renamed entry | `v18_*`, `v19_*` |
| E1–E3 | real PTY program: browse, transfer, create/rename/delete with confirmation and mouse; restore terminal and close gracefully | `e1_*`–`e3_*` |

Missing: recursive deletion, server-side copy/move, parallel progress UI, embedded terminal. Character width is treated as one, so wide glyph alignment can drift without exceeding the character grid.

## Gatekeeper ↔ executor boundary (section G, `tests/ipc.rs`, `src/ipc.rs`, `src/executor.rs`)

The **gatekeeper** handles network, key handshake, login, sessions, and resumption, but contains no implementation for programs, PTYs, files, directories, or tunnels. The **executor** acts on the machine and listens only on `<directory>/ipc.sock`. Development command `yrld serve` hosts both in one process through the same socket and checks.

Executor admission has four independent checks: (1) 0600 socket and a directory not writable by others; (2) kernel `SO_PEERCRED` uid/pid; (3) `/proc/<pid>/exe`; (4) Noise IK with a pre-provisioned pair-specific key from `yrld init`. The executor independently recomputes requested permissions ⊆ account ∩ key and selects the OS user itself.

| # | requirement | test |
|---|---|---|
| G1 | judge foreign user/program, unknown process, and missing pid | `g1_*` |
| G2 | private socket/directory; never remove foreign file; replace stale socket | `g2_*` |
| G3 | reject foreign gatekeeper/executor keys | `g3_*` |
| G4 | correct key with wrong program/user still fails | `g4_*` |
| G5 | reject excess/invented rights, unknown account/key, malformed request | `g5_*` |
| G6 | gatekeeper cannot select the OS user | `g6_*` |
| G7 | session can do only granted work; extra OPEN/LOGIN closes | `g7_*` |
| G8 | garbage, empty connection, or handshake without OPEN closes silently | `g8_*` |
| G9 | exact non-panicking request codec | `g9_*` |
| G10 | door keys created once, 0600, never replaced; reject damaged public key | `g10_*` |
| G12 | gatekeeper `no_new_privs` + seccomp blocks exec, tracing, mounts, modules, namespaces, uid/gid changes while retaining network/files/threads/local sockets | `g12_*`, `g11_*` |
| G11 | separate real processes; executor death denies commands/new logins while gatekeeper lives | `g11_*` |

Invariant: a fully compromised gatekeeper can disrupt service but cannot make the executor exceed account **and** key permissions, choose an OS user, or be replaced by another local program. Remaining gaps: the gatekeeper chooses account+key without knowing the password; SUDO/ROOT need fresh human proof; seccomp is a denylist and no filesystem jail exists; real separate-user uid checks require root; pid reuse makes the key check essential.

## Step-up: USER → SUDO → ROOT (section U, `tests/stepup.rs`, `src/stepup.rs`)

Every session remains USER. SUDO/ROOT authorize **one typed operation** (`Status`, `TestPrivileged`, `RestartService`) through a short-lived, single-use `Cap`; there is no root session. SUDO is authorized by the executor, ROOT by the broker.

The phrase travels only inside a Noise XK client↔executor/broker handshake. The gatekeeper forwards unreadable bytes. A fresh ephemeral key challenges each attempt; the client device key and a prologue bind request, level, operation, and executor key. This is encrypted step-up authentication, not zero-knowledge proof; PAKE/OPAQUE can replace the separate `Verifier`. Clients pin executor/broker public keys printed by `yrld init`.

| # | requirement | test |
|---|---|---|
| U1 | exact bounded operation/frame codecs; garbage never panics | `u1_*` |
| U2 | correct phrase performs exactly one requested operation; next needs new proof; session remains USER | `u2_*` |
| U3 | missing level permission prevents even beginning | `u3_*` |
| U4 | SUDO and ROOT phrases/operations are not interchangeable | `u4_*` |
| U5 | three bad phrases lock this key out of ROOT until local unlock; other level/session/keys unaffected | `u5_*` |
| U6 | success clears failure count | `u6_*` |
| U7 | failures by three keys disable remote ROOT globally; USER/SUDO continue; local unlock restores | `u7_*` |
| U8 | phrase absent from transit bytes; fake executor key learns nothing | `u8_*` |
| U9 | replayed PROOF/BEGIN or proof for another operation is useless; never execute twice | `u9_*` |
| U10 | compromised gatekeeper cannot approve itself even with phrase; garbage does not blame owner | `u10_*` |
| U11 | at most four pending challenges; malformed request closes | `u11_*` |
| U12 | cap binds one operation/session/use/level and expires quickly; broker checks independently | `u12_*` |
| U13 | Argon2id verifier in trusted 0600 file; absent verifier denies; phrase ≥12 bytes; replacement works | `u13_*` |
| U14 | phrases and hashes never enter logs | `u14_*` |

Single-process development mode keeps counters in memory; separate processes persist them as described in K and `yrld unlock` clears them. Current proof is phrase + device key, without FIDO2/TPM or a second device.

## Broker (section B, `tests/broker.rs`, `src/broker.rs`)

The small third process, `yrld broker`, is the only component that may be privileged. It listens on `<directory>/broker.sock` and accepts only the executor through the same four door checks. It terminates ROOT step-up under its own encrypted key—so even the forwarding executor cannot read the phrase—and performs a small typed ROOT operation set. It cannot execute arbitrary commands. ROOT verifier `words.root` and ROOT counters belong only to the broker; SUDO uses executor-owned `words`.

| # | requirement | test |
|---|---|---|
| B1 | broker answers ROOT; wrong pinned key or SUDO phrase fails | `b1_*` |
| B2 | executor cannot decrypt forwarded bytes, even with its own key | `b2_*` |
| B3 | compromised executor cannot obtain root or impersonate session key; other requests close | `b3_*` |
| B4 | broker independently checks account/key/root rights | `b4_*` |
| B5 | reject foreign key, gatekeeper key, and fake broker | `b5_*` |
| B6 | without broker, ROOT is unavailable while SUDO works | `b6_*` |
| B7 | real three-process setup; broker death affects only ROOT | `b7_*` |

Real root privileges and operations remain unverified; current ROOT operations are stubs. Installation assigns separate OS users and secret-file ownership.

## Persistent lockouts (section K, `tests/lockstore.rs`)

Step-up failures live in executor `lockouts.sudo` and broker `lockouts.root`. They survive restart and are sealed with keyed BLAKE3 using owner-only `lockouts.<name>.key`. Every access rereads them so local repairs apply immediately. A missing store with a live key, modification, emptiness, garbage, oversized/world-accessible files, or readable key fails the entire level closed until local `yrld unlock <directory> <sudo|root|all>` repair; damaged state is never overwritten.

| # | requirement | test |
|---|---|---|
| K1 | new store is private 0600 and empty | `k1_*` |
| K2 | counts and locks survive restart without affecting other keys/levels | `k2_*` |
| K3 | global remote-ROOT switch survives restart and applies to unknown keys | `k3_*` |
| K4 | SUDO timeout follows server clock and is not shortened by restart | `k4_*` |
| K5 | any unauthenticated edit fails the level closed and is not overwritten | `k5_*` |
| K6 | missing store with live key, or vice versa, is not a clean start | `k6_*` |
| K7 | loose or huge files are untrusted | `k7_*` |
| K8 | only local owner repair works immediately; network `lift_all` cannot clear persistent state | `k8_*` |
| K9 | broker restart preserves lock; `yrld unlock` removes it without restart | `k9_*` |

This ultimately relies on directory permissions: someone who can delete both store and key can create a clean start; deleting only one fails closed. The MAC catches edits by writers who do not know the key. Hardware confirmation is future work.

## Device enrollment (section N, `tests/enroll.rs`, `src/enroll.rs`)

There is no trust-on-first-contact. The **local owner** opens a short window with `yrld enroll enable <directory> --ttl 120 --rights exec`; only an Argon2id hash of the one-time code is stored. `yrl enroll <directory> <address> <server key> <name>` shows the new device's own fingerprint and asks for the code. A correct code creates a request; the owner compares a fingerprint computed from the actual key and answers y/N. Only the owner's program edits `authorized_keys`. The window closes after one answer, three bad codes, or expiry; only one request is pending.

| # | requirement | test |
|---|---|---|
| N1 | unknown key gets silence outside/after a window | `n1_*` |
| N2 | code → fingerprint → approval adds exactly the window rights, then normal login | `n2_*` |
| N3 | guest can only submit the code; other frames close | `n3_*` |
| N4 | three wrong codes close the window permanently | `n4_*` |
| N5 | code without owner consent fails; either answer closes; new window has new code | `n5_*` |
| N6 | lying gatekeeper cannot add a key; fingerprint is computed, not read from request file | `n6_*` |
| N7 | one request; unanswered request expires without adding | `n7_*` |
| N8 | safe alphabet, deadlines, stored hash, trusted window file, exact request codec | `n8_*` |
| N9 | real `yrld enroll enable` + `yrl enroll` programs | `n9_*` |

While open, strangers can observe that the port responds and get three code attempts. The defense is the code, human fingerprint comparison, and short window. SUDO/ROOT are granted only if explicitly listed, and account password remains required.

## Hash-chained audit log (section A, `tests/auditlog.rs`, `tests/audit_e2e.rs`, `tests/audit_proc.rs`)

The fourth process, `yrld audit`, only appends through `audit.sock` and alone holds Ed25519 `audit/sign.key` (0600). Gatekeeper, executor, broker, and owner tools each authenticate with their own key. The key determines the source, and each source may report only events it could observe. Audit assigns time, sequence, and hashes; clients cannot.

`ordinary.log` records USER/SUDO/ROOT activity; `security.log` records defense state. Fixed binary records include number, time, source, level, flags, result, code, request/session/device/user/operation/target/cap IDs, and checkpoint signature. `H[n] = BLAKE3(H[n-1] ‖ record[n])`; every N events has a signed checkpoint and signed `*.head`. The schema has no fields for phrases, secrets, or raw paths.

| # | requirement | test |
|---|---|---|
| A1–A7 | canonical binary form; validate intact chain; detect edit/delete/reorder/insertion/truncation/foreign rewrite; refuse damaged tail except explicit safe repair | `a1_*`–`a7_*` |
| A8–A11 | sources report only their own events; route log classes; mark replayed request IDs; no secrets/control text | `a8_*`–`a11_*` |
| A12–A15 | periodic/sealed checkpoints across restart; failed write closes log; one audit/key per directory; network cannot choose metadata/signature | `a12_*`–`a15_*` |
| E1–E3 | ordinary sessions, failed login, and every step-up outcome are recorded without typed values, paths, passwords, or phrases | `e1_*`–`e3_*` |
| E4–E7 | security events, unsolicited proofs, repeated requests, and source restrictions through real socket | `e4_*`–`e7_*` |
| E8–E10 | no log means no SUDO/ROOT; report accumulated loss after recovery; verify a busy run fully | `e8_*`–`e10_*` |
| P1–P3 | four real processes; owner commands leave safe traces; detect file edits; enrollment fails if it cannot be logged | `p1_*`–`p3_*` |

## SPA gateway, real firewall, installation, and system tests

| # | requirement | test |
|---|---|---|
| S1–S14 | authenticate every SPA field; exact ±30 s window; replay cache/limits; typed firewall language; expiry/restart clears grants; backend failure stays closed; safe nft argv; established before DROP; firewall door only for gatekeeper | `tests/spa.rs` |
| N1 | real nft in a private network: closed without grant, only work port affected, kernel expiry, established survives, explicit close/restart, mutant rules detected | `tests/nft_real.rs` |
| K1 | full real-process stack plus knock client on a real kernel: wall, login, expiry, live session, audit records | `tests/nft_stack.rs` |
| H1 | inability to enter home does not prevent program launch | `tests/exec_home.rs` |
| G1–G9 | simulated-kernel full gateway: knock does not replace key/password; source address only; expiry affects new connections; knock port silent; reconnect re-knocks; firewall/audit failure stays closed | `tests/gate.rs` |
| I1 | ownership table: narrowly shared account/rule files and public keys; 0600 secrets in per-user 0700 directories; server key only at gatekeeper; no gatekeeper→broker door | `tests/install.rs` |
| I2–I3 | detect missing/wrong-type/owner/group/mode/extra-world-readable/symlink entries; never apply through symlink | `install.rs` |
| I4 | account/tmpfiles commands exactly match table and never create root | `install.rs` |
| I5 | systemd users/groups/write paths/capabilities/socket families/no-new-privileges/protection match table and dependencies | `install.rs` |
| I6–I9 | door socket groups/modes, private state, shared server-key checks, unlock preserves owner, cross-user uid doors with optional `/proc` check | `install.rs` |
| I10–I14 | owner commands preserve ownership/modes; group-readable secrets only; audit directory remains private; owner log distinguishes login reason while client sees only denial | `tests/install.rs`, `tests/cli.rs` |

An SPA knock is one silent 94-byte datagram (`YSPA`, client/server IDs, time, nonce, virtual IPv6, MAC). The MAC is keyed BLAKE3 derived from X25519(device key, server key). Cheap validation precedes the one MAC; only valid packets enter the replay cache. The real source address is admitted, never an embedded address. A separate firewall process with `CAP_NET_ADMIN` accepts only typed Open/Close/Query/CloseSession operations and logs **before** opening.

Honest limitations: SPA does not hide the listening UDP port; clocks must agree within 30 seconds; one NAT address is admitted as a unit, though key and password remain required. Real nft behavior is tested in an isolated network, while separate production users/systemd capabilities require target-machine verification.

The first real systemd run found and fixed group-readable `users` rejection, owner loss on `passwd`, audit-directory mode widening, and a client `ping` panic without login. It confirmed five separate service users, intended effective capabilities, the nft knock wall, login, execution under a dedicated test account, and full audit verification. Cross-user `/proc/<pid>/exe` access required optional `--gate-exe -`/`--exec-exe -`; socket groups were added; unlock now preserves file ownership; shared server-key loading validates the file; executor runs as root only to switch users.

Without root, owner-ID checks are tested with substituted IDs. Anyone able to write the audit directory can delete it entirely, so signed heads should be copied elsewhere; append-only deployment hardening and rotation remain future work. Logs grow without bound, and repair verifies record by record.

Login tradeoffs: a stolen key can trigger a bounded lockout against its owner; address lockouts affect everyone behind one NAT; passwords use Argon2id (19 MiB, t=2) with at most four simultaneous checks; changing identity requires a new connection; theft of `users` permits offline guessing, mitigated by mode 0600 and Argon2id.

## Remaining v0.1 limitations

A secret port is not treated as authentication. TCP SYN-flood defense belongs to the firewall. The network sees client address, timing, and volume. Hybrid post-quantum ML-KEM remains future work. The host executor is not yet sandboxed beyond running under the `yrld` user.
