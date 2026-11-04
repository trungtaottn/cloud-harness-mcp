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
5. A `network-none` workspace stays network-none. Dependency downloads need a
   prepopulated cache or a separately authorized network-enabled workflow.
   Report this separately from package mounting.

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

## Validation recorded for this patch

Plugin synchronization, lint and typechecks passed. Backend: 3519 passed,
2 skipped. Dashboard: 709 passed under Node 24.22.2; Node 26.13.0 failed browser
storage globals. Production build passed under Node 24. Docker package lifecycle:
6 passed, including real package mount refresh and preserved files. API/runner
image schema probes passed. The deployment helper's Docker process preflight
was corrected to request `pid,args` and verified against the live container.
