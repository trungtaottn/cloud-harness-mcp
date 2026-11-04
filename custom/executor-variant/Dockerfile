FROM golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9 AS go-source
FROM rust:1.99.1-slim-bookworm@sha256:ed2c95ca377d6571b124b05e75e01207973ded639dce7d5542eb7bcd797e32aa AS rust-source
RUN set -eu; set -- /usr/local/rustup/toolchains/*; test "$#" -eq 1; cp -a "$1" /opt/rust-toolchain

FROM cloud-harness-executor:upstream-0.80.0-dd7cf9b05f14
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*
COPY --from=go-source /usr/local/go /usr/local/go
COPY --from=rust-source /opt/rust-toolchain /opt/rust-toolchain
# The runner overrides PATH, so expose compilers through its existing bin path.
RUN set -eu; \
    for binary in /usr/local/go/bin/* /opt/rust-toolchain/bin/*; do \
      ln -s "$binary" "/usr/local/bin/$(basename "$binary")"; \
    done
ENV GOPATH=/opt/user-tools/go \
    GOBIN=/opt/user-tools/bin \
    GOCACHE=/var/cache/harness/go-build \
    GOMODCACHE=/var/cache/harness/go-mod \
    CARGO_HOME=/var/cache/harness/cargo \
    CARGO_INSTALL_ROOT=/opt/user-tools
LABEL org.opencontainers.image.description="Cloud Harness 0.80.0 executor with Go 1.27.3 and Rust 1.99.1" \
      cloud-harness.executor-base="sha256:dd7cf9b05f145996bdecb904f4b5bf8071f5977b26660b6744a59077714829e1"
USER 10001:10001
