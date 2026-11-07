#!/usr/bin/env bash
# guest-df — workspace byte measurement for the incus-vm executor.
# The docker backend measures workspace usage with
#   du -sb --apparent-size /workspace /opt/user-tools /var/cache/harness
# inside the executor container. This helper keeps that contract on the VM
# guest: pass paths as arguments, or rely on the same three defaults.
set -euo pipefail

paths=("$@")
if [[ ${#paths[@]} -eq 0 ]]; then
  paths=(/workspace /opt/user-tools /var/cache/harness)
fi

exec /usr/bin/du -sb --apparent-size "${paths[@]}"
