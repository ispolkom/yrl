#!/bin/bash
# YRL: install with separate system users. Run as root: sudo ./install.sh <command>
#   prepare <artifact-directory> prepare everything WITHOUT starting it (users, directories, permissions, units)
#   fix                    restore owners and permissions (after yrld authorize / passwd / word set), then verify
#   check                  verify only
#   status                 show service and firewall-rule status
#   update                 refused: use a verified bundle with yrl-update
#   start | stop           start or stop every component
#   remove [--purge]       remove units, rules, and service users; keep data and keys unless --purge is given
set -euo pipefail

STATE=/var/lib/yrl
RUN=/run/yrl
INSTALL=/opt/yrl
BOOT_RELEASE="$INSTALL/releases/00000000000000000000/artifacts"
BIN="$INSTALL/current/yrld"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

[ "$(id -u)" = 0 ] || { echo "Run as root: sudo $0 $*"; exit 1; }

ask() { read -r -p "$1 [y/N] " a; [ "$a" = y ] || [ "$a" = Y ] || { echo "Stopped; no further changes were made."; exit 1; }; }

case "${1:-}" in
prepare)
  SRC="${2:?provide the directory containing the built YRL binaries}"
  [ -x "$SRC/yrld" ] && [ -x "$SRC/yrl-update" ] || { echo "$SRC does not contain executable yrld and yrl-update binaries"; exit 1; }
  cat <<TXT
The following changes will be made (nothing will be started):
  1. install the bootstrap yrld as release 0 under $INSTALL
  2. create login-disabled system users yrl-gate, yrl-fw, yrl-audit, yrl-broker, and yrl-* groups
  3. create $STATE with service keys (yrld init)
  4. apply owners and permissions from the layout table (yrld install layout)
  5. install systemd units in /etc/systemd/system and configuration in /etc/yrl, without enabling or starting them
Firewall rules and ports remain untouched until you start the services yourself.
TXT
  ask "Continue?"
  mkdir -p -m 0755 "$BOOT_RELEASE"
  for name in yrl yrld yrl-relay yrl-audit yrl-release yrl-update; do
    [ ! -e "$SRC/$name" ] || install -m 0755 -o root -g root "$SRC/$name" "$BOOT_RELEASE/$name"
  done
  if [ ! -e "$INSTALL/current" ]; then ln -s "releases/00000000000000000000/artifacts" "$INSTALL/current"; fi
  "$BIN" install accounts | sh
  if [ ! -e "$STATE/static.key" ]; then
    mkdir -p -m 700 "$STATE"
    "$BIN" init "$STATE" | tee /root/yrl-init.txt
    echo "(public keys were saved to /root/yrl-init.txt)"
  fi
  mkdir -p /etc/yrl
  [ -e /etc/yrl/yrl.env ] || install -m 0644 "$HERE/yrl.env.example" /etc/yrl/yrl.env
  "$BIN" install tmpfiles "$RUN" > /etc/tmpfiles.d/yrl.conf
  systemd-tmpfiles --create /etc/tmpfiles.d/yrl.conf
  "$BIN" install layout "$STATE" "$RUN"
  for u in "$HERE"/systemd/*; do install -m 0644 "$u" /etc/systemd/system/; done
  systemctl daemon-reload
  echo
  "$BIN" install check "$STATE" "$RUN" || true
  cat <<TXT

Next steps:
  sudo $BIN authorize $STATE <device-public-key-hex> <name> exec,shell
  sudo $BIN passwd $STATE <login> exec,shell <system-user>
  sudo $0 fix          # restore owners and permissions after these commands
  sudo $0 start
TXT
  ;;
fix)
  "$BIN" install layout "$STATE" "$RUN"
  "$BIN" install check "$STATE" "$RUN"
  ;;
check)
  "$BIN" install check "$STATE" "$RUN"
  ;;
status)
  systemctl --no-pager --lines=0 status yrl-audit yrl-broker yrl-executor yrl-firewall yrl-gatekeeper || true
  command -v nft >/dev/null && nft list table inet yrl 2>/dev/null || echo "(the yrl rules table does not exist yet)"
  ;;
start)
  "$BIN" install check "$STATE" "$RUN" || { echo "Repair the layout first: sudo $0 fix"; exit 1; }
  systemctl start yrl.target
  sleep 2
  systemctl --no-pager --lines=0 status yrl-audit yrl-broker yrl-executor yrl-firewall yrl-gatekeeper || true
  ;;
update)
  echo "Unsigned in-place updates are disabled. Verify a complete signed bundle and use yrl-update as documented in docs/UPDATES.md." >&2
  exit 1
  ;;
stop)
  systemctl stop yrl.target yrl-gatekeeper yrl-firewall yrl-executor yrl-broker yrl-audit || true
  nft delete table inet yrl 2>/dev/null || true
  ;;
remove)
  systemctl stop yrl.target yrl-gatekeeper yrl-firewall yrl-executor yrl-broker yrl-audit 2>/dev/null || true
  systemctl disable yrl.target 2>/dev/null || true
  nft delete table inet yrl 2>/dev/null || true
  rm -f /etc/systemd/system/yrl-*.service /etc/systemd/system/yrl.target /etc/tmpfiles.d/yrl.conf
  systemctl daemon-reload
  rm -rf "$RUN"
  if [ "${2:-}" = "--purge" ]; then
    ask "Delete ALL data and keys in $STATE, along with yrl-* users and groups?"
    rm -rf "$STATE" /etc/yrl /var/lib/yrl-update "$INSTALL"
    for u in yrl-gate yrl-fw yrl-audit yrl-broker; do userdel "$u" 2>/dev/null || true; done
    for g in yrl-conf yrl-to-audit yrl-to-exec yrl-to-broker yrl-to-fw; do groupdel "$g" 2>/dev/null || true; done
  fi
  if [ "${2:-}" = "--purge" ]; then echo "removed; data deleted"; else echo "removed; data and keys remain in $STATE"; fi
  ;;
*)
  sed -n '2,10p' "$0"
  exit 1
  ;;
esac
