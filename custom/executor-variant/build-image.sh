#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
base=sha256:dd7cf9b05f145996bdecb904f4b5bf8071f5977b26660b6744a59077714829e1
docker image inspect "$base" >/dev/null
docker tag "$base" cloud-harness-executor:upstream-0.80.0-dd7cf9b05f14
docker build --tag cloud-harness-executor:0.80.0-go1.27.3-rust1.99.1 .
