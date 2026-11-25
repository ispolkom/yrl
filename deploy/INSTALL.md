# Installing YRL with separate system users

This is preparation only. It **starts nothing** and **does not change firewall rules** until you explicitly run `start`.

## Resulting layout

| component | runs as | responsibility |
|---|---|---|
| gatekeeper `yrl-gatekeeper` | `yrl-gate` (unprivileged) | the only process that listens on the network |
| firewall `yrl-firewall` | `yrl-fw` | the only process that changes `nft` rules (`CAP_NET_ADMIN`) |
| audit `yrl-audit` | `yrl-audit` | writes the audit log and trusts no other component |
| broker `yrl-broker` | `yrl-broker` | performs typed ROOT-level operations |
| executor `yrl-executor` | `root`, but only with permission to assume another user | acts on behalf of the authenticated user |

The doors between components are sockets under `/run/yrl/<door>/`, each with its own group (`yrl-to-…`). State lives in `/var/lib/yrl`; ownership and permissions follow the table embedded in the program.

## Steps

1. Build the program: `cargo build --release -p yrl`; the result is `target/release/yrld`.
2. Prepare it: `sudo ./deploy/install.sh prepare /path/to/yrld`. The script first prints what it will do and asks for `y`.
3. Add your device and account.
4. Run `sudo ./deploy/install.sh fix` to restore the intended owners and permissions after those commands.
5. Run `sudo ./deploy/install.sh start`, then `sudo ./deploy/install.sh status`.

Remove the installation with `sudo ./deploy/install.sh remove` (data and keys remain) or `remove --purge`.

## Verified on a real machine (2026-10-05, systemd, separate users)

- All five services start under their own users. Effective process privileges match the design: audit, broker, and gatekeeper have none; the executor can only switch users (`CapEff=c0`); the firewall has only `CAP_NET_ADMIN` (`1000`).
- Without a knock, real `nft` rules close port 2222. After a knock, the address appears in a timed set; an established session outlives that permission.
- Key-and-password login, command execution under a dedicated test account (with all of that account's groups), a terminal in its home directory, byte-identical file upload/download, and full audit-log verification all work.
- The gatekeeper cannot read other components' keys or see the audit directory.
- A remote terminal cannot elevate through `sudo`/`su` because `no_new_privs` is inherited. Elevation is possible only through the broker's separate step-up path.

## Not yet verified

- Real-machine SUDO and ROOT step-up (phrases and broker). The broker currently supports only test operations; real privileged operations require separate design and implementation.
- A second clean installation from scratch; the script has been exercised once.
- TCP only: the UDP transport has not been implemented yet (see THREATS and the project memory).
