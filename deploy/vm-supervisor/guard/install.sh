#!/bin/sh
# Install the Cloud Harness VM network guard systemd unit.
#
# This is an INSTALL FRAGMENT, not a live operation: run it only on the VM
# host after the vm-supervisor package has been built (dist/network/live.js
# must exist) and /etc/cloud-harness-vm/guard.env has been provisioned with
# the VM_* keys documented in cloud-harness-vm-guard.service.
#
# Guarantee boundary: the guard is a bounded poller plus `nft monitor`
# wakeups — there is no zero-window protection claim. An administrator who
# deletes ALL enforcement layers (nft table, tagged permits, bridge) outside
# the guard's view is outside the trusted single-owner threat model.
set -eu

# Prerequisite gate: the guard's atomic nft table apply uses `destroy table`,
# which requires nftables >= 1.0.7 on kernel >= 6.3. Refuse to install on an
# unsupported host — the guard must never enable network on a floor it
# cannot enforce.
if ! command -v nft >/dev/null 2>&1; then
  echo "nft (nftables) not found — install nftables >= 1.0.7 first" >&2
  exit 1
fi
NFT_VER="$(nft --version 2>/dev/null | sed -n 's/.*v\([0-9][0-9]*\)\.\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2 \3/p' | head -n 1)"
if [ -z "$NFT_VER" ]; then
  echo "could not parse 'nft --version' output — nftables >= 1.0.7 required" >&2
  exit 1
fi
KREL="$(uname -r)"
KVER="$(printf '%s\n' "$KREL" | sed -n 's/^\([0-9][0-9]*\)\.\([0-9][0-9]*\).*/\1 \2/p' | head -n 1)"
if [ -z "$KVER" ]; then
  echo "could not parse kernel release '$KREL'" >&2
  exit 1
fi
version_ge() { # $1 = "maj min pat" have, $2 = "maj min pat" want (lexicographic)
  h1=${1%% *}; rest=${1#* }; h2=${rest%% *}; h3=${rest#* }
  w1=${2%% *}; rest=${2#* }; w2=${rest%% *}; w3=${rest#* }
  [ "$h1" -gt "$w1" ] && return 0
  [ "$h1" -lt "$w1" ] && return 1
  [ "$h2" -gt "$w2" ] && return 0
  [ "$h2" -lt "$w2" ] && return 1
  [ "$h3" -ge "$w3" ]
}
kernel_ge_63() { # kernel >= 6.3  <=>  (maj,min) >= (6,3)
  k1=${KVER%% *}; k2=${KVER#* }
  [ "$k1" -gt 6 ] && return 0
  [ "$k1" -lt 6 ] && return 1
  [ "$k2" -ge 3 ]
}
if ! version_ge "$NFT_VER" "1 0 7" || ! kernel_ge_63; then
  echo "unsupported host for nft destroy: nftables '$NFT_VER' (need >= 1.0.7), kernel '$KREL' (need >= 6.3)" >&2
  exit 1
fi

UNIT_NAME="cloud-harness-vm-guard.service"
UNIT_SRC="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/$UNIT_NAME"
UNIT_DST="/etc/systemd/system/$UNIT_NAME"
ENV_DIR="/etc/cloud-harness-vm"
ENV_FILE="$ENV_DIR/guard.env"

if [ ! -f "$UNIT_SRC" ]; then
  echo "unit source not found: $UNIT_SRC" >&2
  exit 1
fi

install -d -m 0755 "$ENV_DIR"
if [ ! -f "$ENV_FILE" ]; then
  cat > "$ENV_FILE" <<'EOF'
# Cloud Harness VM guard configuration (VM_* keys shared with the supervisor).
# Required:
VM_INCUS_PROJECT=cloudharness
VM_INCUS_SOCKET=/var/lib/incus/unix.socket
# Optional overrides (defaults shown):
# VM_GUARD_STATE_PATH=/run/cloud-harness-vm/guard-state.json
# VM_GUARD_POLL_MS=5000
# VM_BRIDGE_PATTERN=chmbr%d
# VM_SUBNET_PLAN=10.240.0.0/16
# VM_UPLINK=
# VM_DNS_RESOLVERS=1.1.1.1,8.8.8.8
# VM_NONPUBLIC_CIDRS=
EOF
  chmod 0600 "$ENV_FILE"
  echo "created $ENV_FILE — review VM_INCUS_PROJECT before starting"
fi

install -m 0644 "$UNIT_SRC" "$UNIT_DST"
systemctl daemon-reload
systemctl enable "$UNIT_NAME"
echo "installed $UNIT_DST (enabled; start with: systemctl start $UNIT_NAME)"
