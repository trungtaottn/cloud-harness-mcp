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
installation and a smoke pass alone do not activate this backend in production.
The local operator activation on 2026-11-04 at 17:08 passed exact-image, readiness,
VM configuration, durable pre-start guard and public stop/resume retention canary
checks. New workspaces use Kata; existing Docker workspaces were not converted.


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

`workspace_recover({workspaceId, mode: "recreate"})` replaces an idle remote
executor so newly applied managed package bindings become read-only mounts and
their executables enter PATH. It retains workspace ID, checkout, user-tools and
cache volumes, secret snapshot, network profile and hard lease deadline.
Ephemeral container-layer changes are discarded. Ordinary `resume` is unchanged.

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

1. Inspect the live tool schema. It must expose `workspace_recover` mode
   `recreate`. If the client only advertises resume/status/patch/export, refresh
   or reconnect the CH integration. Do not substitute resume or close.
2. Check managed package status and the existing workspace-scoped binding. Do
   not request a broader owner-wide installation just to refresh a mount.
3. Finish running work and close interactive sessions/terminals while retaining
   the workspace. Then call `workspace_recover` with the exact workspace ID and
   `mode: "recreate"`. A busy response means inspect and finish the work first.
4. Verify package status no longer lists that workspace as pending recreation.
   Through `exec_run`, check `command -v pnpm` and `pnpm --version`; for the
   current Relaw request the expected version is **10.30.1**. Confirm checkout
   and Git state remain intact before resuming tests.
5. A `network-none` workspace stays network-none. Use `dependencies_plan` for project dependencies, obtain Dashboard approval,
   then call `dependencies_apply` and poll `dependencies_status`. This separate
   downloader does not require opening internet access for the workspace.

## Operator customizations

The installation activated the API/runner overlay on 2026-11-04; readiness,
recreate schema, exact image IDs and public deployment canary passed. The
instance uses `MAX_WORKSPACE_BYTES=10737418240`: a **10 GiB soft disk ceiling per
workspace**, covering checkout, tools and cache, not reserved storage or RAM.
The setting is operational configuration, not a new global source default.

Managed packages are enabled for npm/uv with approval required and npm lifecycle
scripts denied. Go and Rust are supplied by a separate executor variant, not
by adding managed Go/Cargo package ecosystems.

The [custom directory](../custom) archives the deployment helper, executor
Dockerfile/build/smoke/activation scripts and package-enabling helper. These
are operator scripts tied to the existing host service/configuration layout;
they are not a portable installer. No runtime credentials or dotenv files are
included. Image manifests contain the tested IDs from this installation, which
must exist locally; rebuilds require renewed smoke tests and updated manifests.

`custom/recreate-hotfix/deploy.py` backs up configuration/database, uses the
deployment lock, changes API/runner images and the quota, verifies readiness
and canary, and rolls back on failure. Pause client traffic during deployment.
The executor/package activation helpers invoke the stock upstream deployment:
running them later can replace the custom API/runner overlay. Reapply a verified
overlay afterward. Future upstream upgrades require rebasing and revalidation.

## Validation recorded for the earlier recreate patch

Plugin synchronization, lint and typechecks passed. Backend: 3519 passed,
2 skipped. Dashboard: 709 passed under Node 24.22.2; Node 26.13.0 failed browser
storage globals. Production build passed under Node 24. Docker package lifecycle:
6 passed, including real package mount refresh and preserved files. API/runner
image schema probes passed. The deployment helper's Docker process preflight
was corrected to request `pid,args` and verified against the live container.
