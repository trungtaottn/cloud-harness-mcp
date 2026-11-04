#!/usr/bin/env bash
set -euo pipefail
image=${1:-cloud-harness-executor:0.80.0-go1.27.3-rust1.99.1}
docker run --rm -i --name cloud-harness-toolchain-smoke \
  --network none --user 10001:10001 --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --pids-limit 256 --memory 1g --memory-swap 1g --cpus 1 \
  --ulimit nofile=1024:1024 \
  --tmpfs /tmp:rw,exec,nosuid,nodev,size=128m \
  --tmpfs /run:rw,nosuid,nodev,size=8m \
  --tmpfs /workspace:rw,exec,nosuid,nodev,size=256m,uid=10001,gid=10001 \
  --tmpfs /opt/user-tools:rw,exec,nosuid,nodev,size=128m,uid=10001,gid=10001 \
  --tmpfs /var/cache/harness:rw,exec,nosuid,nodev,size=512m,uid=10001,gid=10001 \
  --env HOME=/tmp/cloud-harness-home \
  --env PATH=/opt/user-tools/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  "$image" bash -se <<'SMOKE'
test "$(id -u)" = 10001
mkdir -p "$HOME" /workspace/go-smoke
go version
rustc --version
cargo --version
cd /workspace/go-smoke
go mod init example.invalid/toolchain-smoke
cat > main.go <<'GO'
package main
/*
int answer(void) { return 42; }
*/
import "C"
import "fmt"
func main() { fmt.Println(C.answer()) }
GO
CGO_ENABLED=1 go build -o go-smoke .
test "$(./go-smoke)" = 42
go install .
test "$(/opt/user-tools/bin/toolchain-smoke)" = 42
cd /workspace
cargo new --quiet --vcs none rust-smoke
cd rust-smoke
cargo build --offline
test "$(./target/debug/rust-smoke)" = 'Hello, world!'
cargo install --offline --path .
test "$(/opt/user-tools/bin/rust-smoke)" = 'Hello, world!'
pkg-config --exists openssl
echo 'PASS: Go/CGO and Rust build, run and install as UID 10001 with read-only root and no network'
SMOKE
