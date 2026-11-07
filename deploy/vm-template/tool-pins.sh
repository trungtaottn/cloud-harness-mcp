# Pinned non-apt tool installs for the VM template. Sourced by provision.sh
# inside the build VM. Every tarball/zip download is https and sha256
# verified before install; npm globals are pinned to exact versions (npm
# verifies registry integrity itself). v1 supports amd64 only — provision.sh
# asserts the architecture before sourcing this file.

# Node.js runtime for worker/harness-worker.mjs and the worker/bin launchers.
# Matches the docker executor's node:24.11.0 base.
NODE_VERSION="v24.11.0"
NODE_TARBALL_SHA256_AMD64="46da9a098973ab7ba4fca76945581ecb2eaf468de347173897044382f10e0a0a"

# bun runtime (docker image tracks the 1.2 line via oven/bun:1.2-slim).
BUN_VERSION="1.2.23"
BUN_ZIP_SHA256_AMD64="cf0ed0a920799d576ffde4e0cae66d732bf23c2530407f26f59c7831dffe1f0e"

# uv / uvx (docker image tracks ghcr.io/astral-sh/uv:latest; pinned here for
# reproducibility).
UV_VERSION="0.13.7"
UV_TARBALL_SHA256_AMD64="c5221ff41b7892bfc223543883600125f6a47fe845093e0f5bdff4f359196d83"

# npm-global tools. docker/executor.Dockerfile floats these at `latest`;
# the template pins exact versions for reproducibility.
PNPM_VERSION="12.18.0"
WRANGLER_VERSION="4.158.0"

# AgentKit CLI — identical pin and checksums to docker/executor.Dockerfile.
AK_VERSION="2.18.0-beta.7"
AK_TARBALL_SHA256_AMD64="bd724a56807fca9ce39a54b32a4964cf11a4026797fac53a5c105b74467343b9"
