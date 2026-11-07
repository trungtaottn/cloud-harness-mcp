---
title: Self-Hosting & Deployment
description: Deploying a private Cloud Harness MCP server on your own infrastructure.
---

# Self-Hosting & Deployment

Cloud Harness MCP is designed for straightforward self-hosting on any modern Linux VPS or cloud instance.

## Deployment Architectures

### 1. 1-Click Automated Deployment (Caddy / Cloudflare Tunnel)

For a modern, zero-fuss self-hosted deployment on standard Linux (Ubuntu 24.04 LTS):

```bash
# Single-command install with Let's Encrypt TLS (Caddy)
curl -fsSL https://raw.githubusercontent.com/bestagentkits/cloud-harness-mcp/main/scripts/install.sh | sudo bash
```

- **Caddy Ingress:** Automatically requests and renews Let's Encrypt TLS certificates, proxying traffic to the loopback ingress `127.0.0.1:3100`.
- **Cloudflare Tunnel:** Connects `cloudflared` directly to the `ingress` network, exposing zero host listening ports.
- **Management:** Uses the `cloudharness` CLI (`cloudharness status`, `cloudharness logs`, `cloudharness token`).

### 2. Traditional NGINX Reverse Proxy Runbook

For custom infrastructure with existing NGINX setups:

1. **Bootstrap VPS:** Run `deploy/scripts/bootstrap-vps.sh` to install Docker, systemd unit, and permissions.
2. **Deploy Release:** Run `deploy/scripts/deploy-release.sh <git-sha>` to build and start production containers. The deploy runs as a host systemd unit (`cloud-harness-deploy-<sha>`), so a dropped SSH session does not interrupt it; follow it with `journalctl -fu cloud-harness-deploy-<sha>`.
3. **Canary Verification:** Run `scripts/deploy-canary.mjs` to execute an automated end-to-end workspace test against the newly deployed instance.

When you deploy from GitHub Actions (`.github/workflows/deploy.yml`), each merge to `main` deploys once. If that merge cuts a release, the Release workflow requests a second CI run for its version commit and production deploys the tagged commit once that run passes, so the reported server version matches the newest release tag. That adds one CI cycle before the merge reaches production. If the version commit's CI fails, the merge itself deploys instead; a flaky failure can be retried with `gh workflow run ci.yml --ref main` while the version commit is still the head of `main`.

## Optional: Incus VM executor backend

Workspaces normally run as Docker containers. An operator can additionally
enable an **Incus VM backend** so that workspaces opened with
`executionBackend: "incus-vm"` run inside their own VM instead. It is strictly
opt-in: Docker remains the default, only newly opened workspaces can select it,
and there is no in-place conversion of an existing workspace.

Enabling it is a host-level operation, not a dashboard toggle. Prerequisites:

- An Incus install with the **extension-gated build** (the VM backend needs
  features a stock build may not ship).
- The VM **supervisor** and **egress-guard** systemd units from
  `deploy/vm-supervisor/` running on the host.
- A host kernel **≥ 6.3** and **nftables ≥ 1.0.7** — the guard replaces its
  nft table atomically (`destroy table` plus the canonical ruleset in one
  `nft -f` transaction), and `destroy` is rejected below those versions, so
  enforcement fails closed. Check `nft --version` and `uname -r` on the actual
  host before enabling.
- A dedicated Incus **storage pool** for workspace disks.
- The opt-in **`compose.vm.yaml`** Compose overlay, which mounts the
  supervisor's Unix socket into the runner — the default Compose stack never
  sees `/run/cloud-harness-vm`. Add `-f compose.vm.yaml` after the base files:
  `docker compose -f compose.yaml -f compose.vm.yaml up -d` for development,
  or append it after `compose.production.yaml` in production.
- Runner environment keys (`VM_BACKEND_ENABLED`, `VM_SUPERVISOR_SOCKET`,
  `VM_SUPERVISOR_TOKEN`, `VM_TEMPLATE_ID`, `VM_TEMPLATE_DIGEST`, and the
  sizing/admission bounds) — see the configuration reference for what each
  controls.

Until all of that is in place, `workspace_open` with
`executionBackend: "incus-vm"` fails closed (`VM_BACKEND_DISABLED` or
`VM_SUPERVISOR_UNAVAILABLE`); nothing else changes. VM workspaces are capped
at one concurrent VM at fixed sizing (4 CPUs / 8 GiB / 20 GiB), and two
capabilities are explicitly unsupported on them — host package binding and
workspace/repository skill browsing — which surface as
`VM_CAPABILITY_UNSUPPORTED`. The honest security boundary (guest root can read
injected runtime secrets and tamper with guest-side state; control credentials
never enter the guest; enforcement is the external guard, not the guest
firewall) is documented in the security model.
