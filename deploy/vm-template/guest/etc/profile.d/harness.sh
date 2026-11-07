#!/usr/bin/env bash
# Cloud Harness workspace PATH — mirrors docker/executor.Dockerfile ENV PATH.
# Sourced by login/interactive shells; the worker runners export the same
# value explicitly for non-login exec sessions.
export PATH="/opt/harness/bin:/workspace/node_modules/.bin:/opt/user-tools/bin:/opt/user-tools/pnpm/bin:/opt/user-tools/pnpm:/opt/user-tools/bun/bin:/tmp/cloud-harness-home/.local/bin${CLOUD_HARNESS_MANAGED_PATH:+:$CLOUD_HARNESS_MANAGED_PATH}:$PATH"
