#!/bin/sh
# Install the Cloud Harness VM supervisor systemd unit.
#
# This is an INSTALL FRAGMENT, not a live operation: run it only on the VM
# host after the vm-supervisor package has been built
# (apps/vm-supervisor/dist/index.js must exist) and
# /etc/cloud-harness-vm/supervisor.env has been provisioned with the VM_*
# keys documented in cloudharness-vm-supervisor.service.
#
# The supervisor is the only component that talks to Incus. It binds a
# root-owned Unix socket under /run/cloud-harness-vm; the runner container
# reaches it through the compose bind mount and authenticates with the
# VM_SUPERVISOR_TOKEN bearer token. Docker remains the default executor
# backend — nothing here starts VMs by itself.
set -eu

UNIT_NAME="cloudharness-vm-supervisor.service"
UNIT_SRC="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/$UNIT_NAME"
UNIT_DST="/etc/systemd/system/$UNIT_NAME"
ENV_DIR="/etc/cloud-harness-vm"
ENV_FILE="$ENV_DIR/supervisor.env"
SOCKET_DIR="/run/cloud-harness-vm"
STATE_DIR="/var/lib/cloud-harness-vm"

if [ ! -f "$UNIT_SRC" ]; then
  echo "unit source not found: $UNIT_SRC" >&2
  exit 1
fi

install -d -m 0755 "$ENV_DIR" "$SOCKET_DIR" "$STATE_DIR"
chmod 0700 "$STATE_DIR"
if [ ! -f "$ENV_FILE" ]; then
  cat > "$ENV_FILE" <<'EOF'
# Cloud Harness VM supervisor configuration (VM_* keys).
# Required:
#   VM_SUPERVISOR_TOKEN=<shared bearer token, min 32 chars, no whitespace>
#     or VM_SUPERVISOR_TOKEN_FILE=/path/to/root-owned-0600-token-file
#   VM_INCUS_PROJECT=<dedicated Incus project; never "default">
#   VM_TEMPLATE_ID=<trusted template id>
#   VM_TEMPLATE_DIGEST=<lowercase sha256 hex of the trusted template>
# Optional overrides (defaults shown):
# VM_SUPERVISOR_SOCKET=/run/cloud-harness-vm/supervisor.sock
# VM_SUPERVISOR_STATE_DIR=/var/lib/cloud-harness-vm
# VM_INCUS_SOCKET=/var/lib/incus/unix.socket
# VM_GUARD_STATE_PATH=/run/cloud-harness-vm/guard-state.json
# VM_BRIDGE_PATTERN=chmbr%d
# VM_SUBNET_PLAN=10.240.0.0/16
# VM_UPLINK=
# VM_DNS_RESOLVERS=1.1.1.1,8.8.8.8
# VM_NONPUBLIC_CIDRS=
# VM_POOL_PATH=/var/lib/incus-pool
# VM_MAX_TTL_SECONDS=86400
# VM_MAX_ACTIVE=1
# VM_CPUS=4
# VM_MEMORY_BYTES=8589934592
# VM_DISK_BYTES=21474836480
# VM_POOL_RESERVE_BYTES=10737418240
EOF
  chmod 0600 "$ENV_FILE"
  echo "created $ENV_FILE — fill in the required VM_* keys before starting"
fi

install -m 0644 "$UNIT_SRC" "$UNIT_DST"
systemctl daemon-reload
systemctl enable "$UNIT_NAME"
echo "installed $UNIT_DST (enabled; start with: systemctl start $UNIT_NAME)"
