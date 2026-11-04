#!/usr/bin/env bash
set -euo pipefail

# Installs only the pinned runtime. Does not change Docker defaults or restart services.
archive=${1:?Usage: sudo bash install-kata-runtime.sh /absolute/path/to/kata-go-static-4.3.1-amd64.tar.zst}
expected=66b35b06f6b41b56f8606ddf3ed3e5660b0971d1e309d903457c4056a0b9eff0
[[ $EUID == 0 ]] || { echo 'Run as root to install /opt/kata.' >&2; exit 1; }
[[ $(uname -m) == x86_64 && -c /dev/kvm ]] || { echo 'Requires x86_64 Linux with /dev/kvm.' >&2; exit 1; }
[[ -f $archive && $archive == /* ]] || { echo 'Archive must be an existing absolute path.' >&2; exit 1; }
[[ ! -e /opt/kata && ! -L /opt/kata ]] || { echo '/opt/kata already exists; refusing to overwrite a runtime.' >&2; exit 1; }
[[ ! -e /usr/local/bin/containerd-shim-kata-v2 && ! -L /usr/local/bin/containerd-shim-kata-v2 ]] || { echo 'Kata shim already exists; inspect it first.' >&2; exit 1; }
command -v zstd >/dev/null
command -v docker >/dev/null
staging=$(mktemp -d /opt/.cloud-harness-kata.XXXXXXXX)
trap 'rm -rf -- "$staging"' EXIT
# Copy first, then hash and extract the root-owned copy to avoid an unprivileged archive swap.
cp -- "$archive" "$staging/runtime.tar.zst"
printf '%s  %s\n' "$expected" "$staging/runtime.tar.zst" | sha256sum --check --strict -
mkdir "$staging/unpack"
tar --zstd --extract --file "$staging/runtime.tar.zst" --directory "$staging/unpack" --no-same-owner
test -x "$staging/unpack/opt/kata/bin/containerd-shim-kata-v2"
mv -- "$staging/unpack/opt/kata" /opt/kata
ln -s /opt/kata/bin/containerd-shim-kata-v2 /usr/local/bin/containerd-shim-kata-v2
echo 'Kata 4.3.1 installed. Docker defaults and running containers were not changed.'
echo 'Next: run the isolated custom/smoke-kata-runtime.sh test; do not enable VM workspaces yet.'
