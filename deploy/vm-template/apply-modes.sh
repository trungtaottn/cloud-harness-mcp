#!/usr/bin/env bash
# apply-modes.sh <root> — normalize MODES of a staged guest payload or the
# installed guest tree. Single source of truth for payload modes, used by
# `vm-template-build.sh stage` (on the staged tree) and by provision.sh (on
# the payload copy inside the build VM). Ownership is normalized separately:
# provision.sh chowns the whole payload to root:root before install, and
# provision additionally chowns the workspace-writable directories to uid
# 10001 — this script only ever chmods.
set -euo pipefail

root="${1:?usage: apply-modes.sh <root>}"
[[ -d "$root" ]] || { echo "apply-modes: not a directory: $root" >&2; exit 1; }

# Default: directories traversable, files readable.
find "$root" -type d -exec chmod 0755 {} +
find "$root" -type f -exec chmod 0644 {} +

# Executables under any bin/sbin directory are user-invokable.
find "$root" -type f \( -path '*/bin/*' -o -path '*/sbin/*' \) -exec chmod 0755 {} +

# /opt/harness mirrors the docker executor: worker scripts and launchers are
# read-execute only (0555); package.json stays 0644 so Node treats the
# extensionless bin/* launchers as ES modules.
if [[ -d "$root/opt/harness" ]]; then
  find "$root/opt/harness" -type f ! -name package.json -exec chmod 0555 {} +
  if [[ -f "$root/opt/harness/package.json" ]]; then
    chmod 0644 "$root/opt/harness/package.json"
  fi
fi

# sudoers drop-ins must be root-only readable.
if [[ -d "$root/etc/sudoers.d" ]]; then
  find "$root/etc/sudoers.d" -type f -exec chmod 0440 {} +
fi
