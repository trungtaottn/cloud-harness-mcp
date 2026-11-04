#!/usr/bin/env bash
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Root is required to install the host firewall.' >&2; exit 1; }
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
umask 077
backup_dir=$(mktemp -d /var/lib/cloud-harness/vm-network-backup.XXXXXXXX)
iptables-save > "$backup_dir/iptables.rules"
echo "Firewall backup: $backup_dir/iptables.rules"
# Existing CH policy: public DNS and TCP 80/443, deny host/private/metadata addresses.
# This neither changes the instance default nor attaches existing workspaces.
bash "$script_dir/../deploy/scripts/setup-dependency-firewall.sh"
echo 'Dependency bridge prepared. Existing workspace network profiles were not changed.'
