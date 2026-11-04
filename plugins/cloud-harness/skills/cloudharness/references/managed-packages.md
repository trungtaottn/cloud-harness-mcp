# Managed toolbox packages

Use these for a CLI tool you want in every new workspace and in the `bash`
toolbox target, kept across workspace recreation and redeploys. For a
project dependency, use the approved Go/pnpm cache workflow below when the
workspace is offline, or the permitted workspace package manager otherwise. All
six managed-toolbox tools return `FORBIDDEN` unless the operator set `PACKAGES_ENABLED=true`.

Flow: `packages_plan` (→ `packages_status` with its `resolutionId` while it
is `RESOLVING`) → (operator approves in the Dashboard when `approval` is
`required`) → `packages_apply` → `packages_status` until `SUCCEEDED` → recreate
a workspace with `workspace_recover({workspaceId, mode: "recreate"})` after
finishing active work, or use `bash` with `target: "toolbox"` for owner-scoped
packages. Recreate keeps the same workspace and package scope; do not close
the workspace or broaden scope just to refresh a mount. It preserves the
network profile, so `network-none` still cannot download project dependencies.
`packages_remove`
uninstalls.

<!-- cloudharness-tool:packages_plan -->
### `packages_plan`

- Required: `ecosystem` (`npm` or `uv`) and `name`. `version` is an npm
  version, range, or tag (default `latest`) or a PEP 440 specifier for uv. URL,
  git, and file specs are refused.
- `scope` defaults to `owner`. `workspace` needs `workspaceId` and overrides
  the owner binding for the same package in that workspace only.
- `apt` returns `NOT_SUPPORTED`: system packages need a reviewed executor image
  variant, not an install.
- Planning never runs package code. uv installs pre-built wheels only: a
  package or dependency published only as a source distribution fails with
  `PACKAGE_BUILD_FAILED` ("only wheels are supported"); pick a version that
  ships wheels or install it in the workspace instead.
- A slow resolution (cold uv toolchain, large npm tree) returns
  `{resolutionId, state: "RESOLVING", package}` after about 20 seconds instead
  of the plan. Poll `packages_status` with that `resolutionId` and `waitMs`.
- Nothing is installed yet. Read `binaries`, `conflicts`, `sizeEstimateBytes`,
  and `affectedWorkspaces` before applying. Keep `planId` and `planDigest`.
- `approval: "required"` means ask the operator to approve the plan on the
  Dashboard Approvals page. `"unavailable"` means this instance cannot approve
  plans, so `packages_apply` will be refused; tell the operator.

<!-- cloudharness-example:packages_plan
{"ecosystem":"npm","name":"prettier","version":"3.3.3"}
-->

<!-- cloudharness-tool:packages_apply -->
### `packages_apply`

- Required: `planId` and the exact `planDigest` from the plan. A different
  digest, an expired plan, or a binding that changed since planning returns
  `STALE_GENERATION` or `EXPIRED`: plan again. A plan approved by policy
  also returns `STALE_GENERATION` once the operator switched to required
  approval.
- Returns an `applyId` at once. Calling it again for the same plan returns the
  same apply.
- `PACKAGE_APPROVAL_REQUIRED` means the plan still waits for the operator.

<!-- cloudharness-tool:packages_status -->
### `packages_status`

- With `applyId`, returns the apply `state` (`QUEUED`, `BUILDING`,
  `VERIFYING`, `PUBLISHING`, `SUCCEEDED`, `FAILED`), its error code, and a
  bounded output tail. Set `waitMs` (up to 30000) to wait for the next change.
- Only `SUCCEEDED` means installed. `PACKAGE_BUILD_FAILED`,
  `PACKAGE_VERIFICATION_FAILED` (for example a binary that fails `--version`
  and `--help` without network), and `RUNNER_RESTARTED` leave the previous
  release in place.
- With `resolutionId` (from a `RESOLVING` plan), returns `resolution` with
  `state` `RESOLVING`, `READY` (with `plan`), or `FAILED` (with `errorCode`
  and `errorMessage`); `waitMs` works the same way. Pass `applyId` or
  `resolutionId`, never both. Resolutions live in runner memory: after a
  runner restart, about 30 minutes after it finished, or once many newer
  resolutions finished, the id returns `NOT_FOUND`; run `packages_plan` again.
- Without either id, summarizes in-flight applies, plans waiting for approval,
  missing releases, and workspaces that need recreation.
- `UNAVAILABLE` from a plan or apply while the runner shuts down is
  retryable once it is back.

<!-- cloudharness-example:packages_status
{"applyId":"pka_0123456789abcdefghijklmn","waitMs":10000}
-->

<!-- cloudharness-example:packages_status
{"resolutionId":"pkq_0123456789abcdefghijklmn","waitMs":20000}
-->

<!-- cloudharness-tool:packages_list -->
### `packages_list`

- Lists bindings (which release each scope uses) and verified releases. A
  `stale` release was built for an older executor image; plan it again if it
  misbehaves. `includeHistory: true` shows releases you can roll back to.

<!-- cloudharness-tool:packages_rollback -->
### `packages_rollback`

- Required: `bindingId`, a `releaseId` from that binding's history, and the
  binding `generation` you last read as `expectedGeneration`. A moved
  generation returns `STALE_GENERATION`; list again and retry deliberately.
- Needs no new approval. Existing workspaces keep their mounts until they are
  recreated.

<!-- cloudharness-tool:packages_remove -->
### `packages_remove`

- Uninstalls a package from one scope. Required: `bindingId` and the binding
  `generation` you last read as `expectedGeneration`. Destructive and needs no
  approval; the binding and its rollback history are deleted, so reinstalling
  needs a new plan.
- `STALE_GENERATION` means the binding moved; list again. `CONFLICT` means an
  apply for it is still running; wait for it to finish.
- New workspaces and the `bash` toolbox stop seeing the tool at once; running
  workspaces keep it until recreated. Use it to free quota when a plan or
  apply returns `LIMIT_EXCEEDED`.

<!-- cloudharness-example:packages_remove
{"bindingId":"pkb_0123456789abcdefghijklmn","expectedGeneration":3}
-->

## Approved project dependency caches

These tools are separate from managed CLI packages. The operator enables
`DEPENDENCIES_ENABLED=true`; Dashboard approval is mandatory even when managed
package approvals are disabled. Only public-registry Go modules and standalone
pnpm 10.30.1 lockfiles are supported. Custom URLs, Git/local sources, hooks and
lifecycle scripts are refused. This does not grant an executor internet access.

<!-- cloudharness-tool:dependencies_plan -->
### `dependencies_plan`

Required: `workspaceId`, `ecosystem` (`go` or `pnpm`). Optional `directory`
(default `.`) is relative to the checkout. Planning captures go.mod/go.sum or
package.json/pnpm-lock.yaml and makes no network request. Inspect returned
`plan`: hashes, hosts, dependency changes, byte/time budgets and expiry. Ask the
operator to approve that exact plan in Dashboard Approvals. Changed manifests,
executor image or managed tool profile require a new plan.

<!-- cloudharness-example:dependencies_plan
{"workspaceId":"ws_aaaaaaaaaaaaaaaaaaaa","ecosystem":"pnpm","directory":"ui/web"}
-->

<!-- cloudharness-tool:dependencies_apply -->
### `dependencies_apply`

Required: `workspaceId`, `planId`, `planDigest` from the approved plan. Finish
active commands/tasks/agents and close terminals first. The call starts a bounded
isolated downloader and returns `plan`; poll status until SUCCEEDED or FAILED.
The executor keeps its network profile and is briefly paused while cache is installed. Do
not close or recreate the workspace. Same-plan replay returns the existing
outcome; failure needs a new plan and approval, never a blind retry with new IDs.
Only approved manifests are sent to the network-enabled helper, without the source checkout or workspace secrets. Package script declarations may be in the manifest but are never executed.

<!-- cloudharness-example:dependencies_apply
{"workspaceId":"ws_aaaaaaaaaaaaaaaaaaaa","planId":"dep_aaaaaaaaaaaaaaaaaaaa","planDigest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
-->

<!-- cloudharness-tool:dependencies_status -->
### `dependencies_status`

Required: `workspaceId`; optional `planId`. Returns `plans`. Download progress
survives disconnection; a runner restart marks unfinished downloads FAILED.
SUCCEEDED means cache is ready, not tests passed. Install UI packages offline
with the frozen lockfile before build/test; Go can use GOPROXY=off to verify
cache completeness. These commands do not approve additional sources or scripts.
Browser binaries, system libraries and network-dependent tests remain separate.

<!-- cloudharness-example:dependencies_status
{"workspaceId":"ws_aaaaaaaaaaaaaaaaaaaa","planId":"dep_aaaaaaaaaaaaaaaaaaaa"}
-->
