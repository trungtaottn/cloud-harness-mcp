#!/usr/bin/env bash
# network-invariant.sh [root] — assert the guest image ships ZERO leftover
# network-manager link configs under every persistent systemd-networkd
# search path. Runs as root inside the build VM near the end of
# provision.sh (after the netplan/ifupdown purge); also runnable standalone
# against a fixture root for tests.
#
# Exit 0 = clean. Exit 1 = a forbidden *.network/*.netdev/*.nmconnection was
# found OR the scan itself failed OR a search path could not be verified —
# all refuse the build (fail closed).
#
# Design notes:
#   - Only directories that genuinely do not exist are skipped: minimal
#     bases may lack /usr/local/lib/systemd/network, and provision.sh
#     deletes /etc/netplan and /etc/network/interfaces.d before this runs.
#   - A path that EXISTS but is not a directory (regular file, fifo, broken
#     or file-pointing symlink) is rejected, never silently omitted.
#   - `[[ -e ]]`/`[[ -L ]]` cannot tell ENOENT from EACCES/ENOTDIR/ELOOP on a
#     path component, so a both-false candidate is re-checked with stat:
#     only a real "No such file or directory" counts as absent; every other
#     stat failure refuses the build.
#   - find's own exit status is checked into a variable: a real
#     read/permission/I/O error fails the build instead of being swallowed.
#   - `find -H` follows symlinks only in the enumerated starting points, so
#     a legitimately symlinked search dir is still scanned while interior
#     symlinks are never followed (no escape via planted links).
#   - Output is bounded by `-print -quit` (first match only) and never piped
#     to `grep -q`: under pipefail a SIGPIPE'd find would mask a found match.
set -euo pipefail

root="${1:-/}"
[[ "$root" == /* ]] || { echo "network-invariant: root must be absolute: $root" >&2; exit 2; }
root="${root%/}"   # '/tmp/fix/' -> '/tmp/fix'; '/' -> ''

scan_dirs=()
for d in etc/systemd/network usr/lib/systemd/network usr/local/lib/systemd/network \
         etc/netplan etc/NetworkManager/system-connections etc/network/interfaces.d; do
  candidate="${root}/$d"
  if [[ ! -e "$candidate" && ! -L "$candidate" ]]; then
    # Both tests false: genuinely absent (ENOENT) OR unverifiable (EACCES on
    # a path component, ENOTDIR, ELOOP). stat's error text distinguishes.
    stat_out="$(LC_ALL=C stat -c %F -- "$candidate" 2>&1)" && stat_rc=0 || stat_rc=$?
    if ((stat_rc == 0)); then
      : # path appeared between tests — classify it normally below
    elif [[ "$stat_out" == *"No such file or directory"* ]]; then
      continue   # genuine ENOENT — optional dir, skip
    else
      echo "network-config search path $candidate cannot be verified ($stat_out) — refusing to ship" >&2
      exit 1
    fi
  fi
  if [[ -L "$candidate" && ! -e "$candidate" ]]; then
    echo "network-config search path $candidate is a broken symlink — refusing to ship" >&2
    exit 1
  fi
  if [[ ! -d "$candidate" ]]; then
    echo "network-config search path $candidate exists but is not a directory — refusing to ship" >&2
    exit 1
  fi
  scan_dirs+=("$candidate")
done

if ((${#scan_dirs[@]} == 0)); then
  exit 0
fi

scan_rc=0
scan_out="$(find -H "${scan_dirs[@]}" \
    \( -name '*.network' -o -name '*.netdev' -o -name '*.nmconnection' \) \
    -print -quit 2>&1)" || scan_rc=$?

if ((scan_rc != 0)); then
  echo "network-config scan failed (find rc=${scan_rc}) — refusing to ship" >&2
  [[ -n "$scan_out" ]] && printf '%s\n' "$scan_out" >&2
  exit 1
fi
if [[ -n "$scan_out" ]]; then
  echo "base image left network configs behind — refusing to ship" >&2
  printf '%s\n' "$scan_out" >&2
  exit 1
fi
exit 0
