# Stage 3 isolation acceptance

## Automated checks in this stage

- `cargo test -p yrl --test ipc g12`: the Gatekeeper seccomp policy is active in the calling thread, an existing thread, and a new thread; forbidden exec and uid changes fail.
- `cargo test -p yrl --test ipc g11`: separate Gatekeeper and Executor processes remain operational with seccomp enabled.
- `cargo test -p yrl --test ipc g16`: every Firewall thread has seccomp and no-new-privileges enabled with a mock nft backend.
- `cargo test -p yrl --test audit_proc p1_four_programs_one_journal_and_the_owners_commands_in_it`: all four core services still perform an authenticated operation and write to Audit with their respective policies installed.
- `cargo test -p yrl --test revocation device_revocation_ends_a_live_terminal_and_running_command`: a command's background child cannot complete after device revocation.
- `cargo test -p yrl --test terminal p5_a_dropped_link_kills_the_shell_and_what_it_started`: a disconnected terminal and its ordinary background job terminate.
- `cargo test -p yrl --test cgroup_session`: in a delegated systemd scope, a `setsid` descendant survives RESUME but dies with its own session; a neighboring session continues.

## Full deployment acceptance

Run on the intended Linux distribution with the installed systemd units, real nftables, separate service users and filesystem permissions. Record the service PID, each thread's `/proc/<pid>/task/<tid>/status` `Seccomp` and `NoNewPrivs` values, `/proc/<pid>/status` effective capabilities, and `/proc/<pid>/mountinfo`. Every thread must show seccomp mode 2 and no-new-privileges 1. Gatekeeper, Broker and Audit must have no effective capabilities; Firewall may have only `CAP_NET_ADMIN`; Executor may have only `CAP_SETUID` and `CAP_SETGID`.

1. Confirm Gatekeeper, Broker, Audit and Firewall cannot write outside their declared `ReadWritePaths`. Verify their Unix sockets, private keys and journal are inaccessible to other service users. Firewall must be able to apply and remove its nftables rules but must not gain access to Executor private state.
2. Confirm Executor starts a command and PTY as the resolved account with only that account's uid, gid, supplementary groups and minimal environment. The account must retain its granted file access, including root operations after the existing step-up; no server secret or inherited file descriptor may become readable in the child.
3. With a live session, start commands and terminals that have foreground children, ordinary background children, ignore `SIGHUP`, and hold output pipes open. Close the session and separately revoke the device, disable the account and remove rights. Confirm all operations stop, the session cannot RESUME, and no file, tunnel or command continues after revocation.
4. Exercise descendants that call `setsid` or create a new process group. With `YRL_SESSION_CGROUPS=required`, confirm each authenticated session gets a distinct cgroup v2, all commands, PTYs and file helpers enter it before `exec`, and `cgroup.kill` empties only that cgroup at close or revocation. A transport interruption followed by RESUME must keep the same cgroup and processes. Executor must refuse startup when its cgroup is not delegated.
5. Repeat UDP-to-TCP and direct-to-relay RESUME with active terminal, file transfer and tunnel; verify Noise authentication, protected ACK/SEQ, transfer hashes, lack of duplicate commands, and authority refresh after rights changes.
6. Restart each service while the others are active. Verify fail-closed behavior, bounded reconnect and resource use, Audit continuity, firewall rule cleanup, and that systemd kills every process in each service cgroup on stop.

The unit and syscall checks require a real systemd deployment. Local tests do not prove mount-namespace or kernel capability behavior of the installed services.

The cgroup guarantee covers processes that remain inside their assigned cgroup, including processes that call `setsid` or change process groups. A command deliberately granted host root authority can modify the delegated cgroup hierarchy and escape containment; root authority is outside this isolation boundary.
