# Custom fork and agent handoff

## Source of truth

- Fork: https://github.com/trungtaottn/cloud-harness-mcp/tree/custom
- Upstream: https://github.com/bestagentkits/cloud-harness-mcp
- Base: upstream 0.80.0, commit `157ed2e61ad6240b79f44ba64b8fffbf4a0f9c2f`.
- `origin` is the fork; `upstream` is for fetching upstream releases. Develop and
  push custom changes on `custom`. This branch is not an upstream release.
- The fork's [.agents skill](../.agents/skills/cloudharness/SKILL.md) and synced
  [plugin skill](../plugins/cloud-harness/skills/cloudharness/SKILL.md) describe
  the added lifecycle behavior. An installed upstream skill can be stale.

## Added behavior

### Persistent VM executor

The opt-in `EXECUTOR_KIND=kata` backend uses Docker's Kata shim with a separate
guest kernel, writable root, guest sudo and retained installed software. New
workspaces snapshot the backend; existing Docker workspaces are not converted.
Use direct guest package-manager commands without per-package managed approval.
The existing host-attested network profiles still apply. Root privileges inside
the guest do not grant the host Docker socket or control-plane credentials.

`workspace_recover` mode `stop` retains a VM; `resume` starts it. Compute expiry
stops rather than deletes a VM, and a resumed stopped VM gets a new compute
lease. `recreate` refuses VM replacement. Explicit `workspace_close` deletes the
retained executor and workspace. Resource ceilings include the writable root
layer plus workspace mounts; the storage ceiling remains soft, with periodic
measurement, not a block-device reservation. Stopped VMs consume host disk.

`VM_MEMORY_MIB` and `VM_CPUS` bound new VM executors. Source defaults are 4096 MiB
and 2 CPUs; Docker and toolbox limits remain unchanged. The separate-kernel
probe and exact Kata runtime check fail closed. Missing retained machines require
operator recovery rather than creating an empty replacement.

Operator artifacts are `custom/install-kata-runtime.sh`,
`custom/prepare-vm-network.sh`, and `custom/smoke-kata-runtime.sh`. Runtime
installation and a smoke pass alone do not activate this backend in production;
the branch's executor changes remain subject to final review and canary
activation. Do not infer a deployed image or a production migration from the
source or these operator scripts. New workspaces use Kata only after the
operator has activated that backend; existing Docker workspaces are not
converted.

### Opt-in InstaBox remote executor

The custom runner also contains an InstaBox backend, disabled unless the
operator sets `INSTABOX_ENABLED=true` and supplies the schema-required
`INSTABOX_API_KEY_FILE`, `INSTABOX_MACHINE_IDS`, `INSTABOX_PRINCIPAL_ID`, and
`INSTABOX_ALLOW_PUBLIC_NETWORK=true` settings. The API key is read from the
runner-only secret file; `INSTABOX_API_KEY` is rejected and the key is never
placed in the API, a guest, a checkout, or a document. Production Compose's
existing runner mount exposes the host secret directory read-only at
`/run/cloud-harness-secrets`; keep the key there and do not print it.

When enabled, an open is remote-first only when it omits `networkProfile` and
the instance has no persisted network default. An explicit
`network-none` or `dependency-access` request, or a persisted instance default,
keeps the workspace on the local backend. Exhausted or cooling remote capacity
falls back to local Kata when configured; the active-workspace quota still
applies and is not bypassed. Remote work reports `provider-managed` networking,
not host-attested `dependency-access`, and remains within the private,
single-owner threat model. A persisted Dashboard network override must be
cleared with **Settings → Default network profile → Reset to runner default**;
enabling the backend does not reset that operator choice.

Remote allocations use only the exact operator allowlist and one canonical
principal. The provider machines are borrowed: stopping and resuming retains
the same machine, checkout, installed software, and workspace identity; an
explicit `workspace_close` is the destructive release path and never asks the
provider to delete a machine. Finish work and stop the workspace when it should
remain available. If work is incomplete, save or checkpoint what is useful,
then stop and later resume the same workspace; do not close it as a substitute
for a checkpoint. Explicit close may need a provider start for scoped cleanup
and then stop it again; if close fails, retry close after reconciliation or
cooldown and do not resume an allocation whose cleanup intent remains pinned.

Remote guests install packages directly; managed package mounts and approved
project dependency caches are unavailable there. Provider-managed public
networking is not a local firewall-attested boundary. The provider's Free
policy is no-billing, with the observed 30-minute idle pause, eight-hour
maximum run, and start cooldowns; these limits are distinct from the harness's
workspace quota and lifecycle settings. A single remote archive upload is
limited to 5 GiB, separately from the runner's soft workspace-size ceiling.
Guest bootstrap requires Node.js, Bash, Python 3 with Linux child-subreaper
support, and passwordless noninteractive `sudo` for scoped close cleanup and
read-only allocation quota measurement. See
[configuration](configuration.md#optional-instabox-remote-executor).
Remote terminal browser reconnect works while the provider connection remains
live; after that provider WebSocket is lost, open a fresh terminal and do not
replay input.

The backend is operator-opt-in and source changes do not establish production
activation or prove that the latest image is deployed. Its executable owners
are [`apps/runner/src/remote-workspace.ts`](../apps/runner/src/remote-workspace.ts),
[`apps/runner/src/executors/instabox-backend.ts`](../apps/runner/src/executors/instabox-backend.ts),
and [`apps/runner/src/workspace-service.ts`](../apps/runner/src/workspace-service.ts).


### Approved project dependency downloads

The custom branch also supports `dependencies_plan`, `dependencies_apply` and
`dependencies_status`. Enable with `DEPENDENCIES_ENABLED=true` only after
deploying the matching contracts, API, Dashboard and runner. This is independent
of managed CLI approval policy: each project download always requires a
Dashboard decision. The owning contracts are
[`dependency-schemas.ts`](../packages/contracts/src/dependency-schemas.ts), and
the agent workflow is in the
[managed-package reference](../.agents/skills/cloudharness/references/managed-packages.md#approved-project-dependency-caches).

Operators must permit the Go proxy/checksum/storage hosts and npm registry on
the provisioning proxy. Each download has an additional exact-host proxy and
internal Docker network, so the existing broader provisioning allowlist does
not grant broader helper access. The helper receives approved manifests only,
no workspace secrets; lifecycle scripts and hooks remain disabled. The
`DEPENDENCIES_MAX_BYTES` and `DEPENDENCIES_TIMEOUT_MS` settings bound the job.
Transfer limits are strict; the disk monitor has a polling interval and may
briefly overshoot before stopping. Cache is checked again before installation.

Use public Go module manifests or standalone pnpm 10.30.1 version-9 lockfiles;
matching public semver overrides are allowed. Private/git/local dependency
sources, workspace catalogs and patches require separate reviewed support and
are refused rather than downloading outside the approved registry route.
Toolchain/browser/system-package downloads are not silently enabled.

Applying replaces that ecosystem's workspace cache after successful download,
with the executor paused and current manifests rechecked. It preserves source
and network policy and does not require recreation. After a runner restart, stale helpers are removed and interrupted publication
restores a displaced old cache or keeps a fully published new cache. Interrupted
plans are marked failed and require a new approval to retry.
Do not use an old deployment manifest to activate images for this feature;
rebuild and verify the current branch first.

### Executor recreation

For an idle Docker workspace, `workspace_recover({workspaceId, mode:
"recreate"})` replaces the executor so newly applied managed package bindings
become read-only mounts and their executables enter PATH. It retains workspace
ID, checkout, user-tools and cache volumes, secret snapshot, network profile and
hard lease deadline. Ephemeral container-layer changes are discarded. Ordinary
`resume` is unchanged. Persistent Kata and InstaBox workspaces do not support
`recreate`; stop and resume the existing executor instead.

Active calls, tasks, agents, shells, sessions and terminals block recreation with
CONFLICT. Finish those operations first; do not close the workspace. Failed
replacement retains recoverable data. Local stdio/multi-local backends return
NOT_SUPPORTED. A temporarily released active-workspace quota slot can be taken
by another admission; if that happens, retry after capacity becomes available.

Recreation does not change package scope, approve a plan, grant dependency
network access or extend hard expiry. Never use `workspace_close` to refresh
packages: closing removes workspace data.

## Instructions to give another agent

You are using the custom fork above, based on upstream 0.80.0. Read its
workspace lifecycle and managed-package skill references instead of assuming
the upstream skill lists every supported mode.

### Resume work after reconnecting

Reconnecting does not deploy a PR, enable an executor backend, migrate an existing
workspace, or prove that the client received the current tool schema. Keep source
documentation, the live server contract and the client's visible catalog separate.

Use `workspace_list` to rediscover the existing workspace for the intended
repository, then inspect `workspace_status` and `workspace_capabilities` with that
exact ID. Check tasks and interactive sessions before changing lifecycle state.
If a list is unexpectedly empty, verify the endpoint and authenticated principal;
do not conclude that data was deleted or create a replacement immediately.

Resume stopped retained compute only through a mode present in the live schema.
After resume, inspect Git status/HEAD and installed tool versions against the
project's manifests before continuing tests. A lost client connection does not
prove the last command stopped: inspect its task/operation result before retrying.
If the client lacks a required mode, report that precise mismatch; do not invent
tool parameters, substitute close, or promise another reconnect will fix it.

Start with `workspace_status` and `workspace_capabilities`. For `instabox` or
`kata`, install tools and dependencies directly in the guest, following its
reported network policy. Stop compute after work and resume the same workspace
to continue; never use recreation or close to activate an installation. On
InstaBox, inspect `compute` to distinguish an active CH lease from paused
provider compute. The package-mount recovery steps below apply only to Docker
workspaces.

1. Inspect the live tool schema. It must expose `workspace_recover` mode
   `recreate`. If the client only advertises resume/status/patch/export, refresh
   or reconnect the CH integration. Do not substitute resume or close.
2. Check managed package status and the existing workspace-scoped binding. Do
   not request a broader owner-wide installation just to refresh a mount.
3. Finish running work and close interactive sessions/terminals while retaining
   the workspace. Then call `workspace_recover` with the exact workspace ID and
   `mode: "recreate"`. A busy response means inspect and finish the work first.
4. Verify package status no longer lists that workspace as pending recreation.
   Through `exec_run`, check `command -v pnpm` and `pnpm --version` against the
   project's declared package-manager version. Confirm checkout
   and Git state remain intact before resuming tests.
5. A `network-none` workspace stays network-none. Use `dependencies_plan` for project dependencies, obtain Dashboard approval,
   then call `dependencies_apply` and poll `dependencies_status`. This separate
   downloader does not require opening internet access for the workspace.

## Operator customizations

Deployment overlays, image selections, and runtime limits are operational state,
not source defaults. This guide does not assert production activation, a deployed
image, or a particular live quota. For InstaBox, `MAX_WORKSPACE_BYTES` remains a
soft allocation-root measurement and is not a provider-machine disk quota.

Managed packages are enabled for npm/uv with approval required and npm lifecycle
scripts denied. Go and Rust are supplied by a separate executor variant, not
by adding managed Go/Cargo package ecosystems.

The [custom directory](../custom) archives the deployment helper, executor
Dockerfile/build/smoke/activation scripts and package-enabling helper. These
are operator scripts tied to the existing host service/configuration layout;
they are not a portable installer. No runtime credentials or dotenv files are
included. Image manifests are operator artifacts tied to a specific deployment;
rebuilds require renewed validation and updated manifests.

`custom/recreate-hotfix/deploy.py` backs up configuration/database, uses the
deployment lock, changes API/runner images and the quota, verifies readiness
and canary, and rolls back on failure. Pause client traffic during deployment.
The executor/package activation helpers invoke the stock upstream deployment:
running them later can replace the custom API/runner overlay. Reapply a verified
overlay afterward. Future upstream upgrades require rebasing and revalidation.
