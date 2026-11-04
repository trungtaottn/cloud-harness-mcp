#!/usr/bin/env bash
set -euo pipefail
image=${1:?Usage: bash smoke-kata-runtime.sh existing-executor-image}
name="ch-kata-smoke-$(date +%s)-$$"
cleanup() { docker rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
docker image inspect "$image" >/dev/null
docker create --pull never --name "$name" --runtime io.containerd.kata.v2 \
  --label cloud-harness.role=vm-smoke --network none --memory 2g --memory-swap 2g \
  --cpus 1 --pids-limit 512 --user 10001:10001 --entrypoint /usr/bin/tini "$image" -- sleep infinity >/dev/null
docker start "$name" >/dev/null
guest=$(docker exec "$name" uname -r)
[[ -n $guest && $guest != "$(uname -r)" ]] || { echo 'Separate guest kernel was not verified.' >&2; exit 1; }
docker exec "$name" sudo -n sh -c 'echo retained > /usr/local/share/cloud-harness-vm-smoke'
docker stop --time 10 "$name" >/dev/null
docker start "$name" >/dev/null
test "$(docker exec "$name" cat /usr/local/share/cloud-harness-vm-smoke)" = retained
docker exec "$name" node --version
printf 'PASS: separate guest kernel (%s), guest sudo and writable root retained across stop/start.\n' "$guest"
