# Executor backend (incus-vm)

Cloud Harness workspaces normally run as Docker containers. An operator can
enable a second executor backend, `incus-vm`, that runs workspaces inside
Incus VMs. The backend is selected per workspace at open time and is immutable
afterwards; there is no in-place conversion.

## Selecting a backend

`workspace_open` accepts an optional `executionBackend` field:

- Omit it or pass `"docker"` for the default Docker executor. Both are
  idempotent-equivalent: the open fingerprint includes the backend only for
  `incus-vm`.
- Pass `"incus-vm"` to request a VM workspace. It applies only to newly
  opened workspaces and only succeeds when the operator enabled the backend
  (`VM_BACKEND_ENABLED` plus supervisor, template, and sizing configuration).
  Otherwise the call fails with `VM_BACKEND_DISABLED`.

A principal can hold Docker and VM workspaces concurrently; the VM backend is
bounded (currently one concurrent VM) and fails with `VM_QUOTA_EXCEEDED` when
full.

## Reading backend data

Workspace results (`workspace_open`, `workspace_list`, `workspace_status`,
`workspace_context`, `workspace_capabilities`, `workspace_close`) carry
`executionBackend` (`"docker"` or `"incus-vm"`) and, when the backend
resolves, a structured `backend` block `{ kind, templateId?, capabilities }`.
`capabilities` maps each capability id to `"supported"` or `"unsupported"`.

Check the matrix before calling an operation — it is intent, not proof: the
runner re-checks every call server-side, so the UI or this matrix never grants
a capability.

## Unsupported capabilities on incus-vm

The v1 VM backend declares these capabilities unsupported:

- `packages-bind` — host package mounts have no guest path.
- `dashboard-repo-skills` — the dashboard/native-extension skill browser's
  workspace-tier reads are served from a host checkout path a guest cannot
  have. A request **bound** to an `incus-vm` workspace fails entirely with
  `VM_CAPABILITY_UNSUPPORTED` before tier resolution; unbound requests — and
  requests bound to docker workspaces — retain owner, built-in, and
  workspace tiers. MCP `skills_list`/`skills_read`/`skills_run`/
  `skill_suggest` use the supported `skills` capability and are unaffected.

Refusals return `VM_CAPABILITY_UNSUPPORTED` (400, terminal). Open a Docker
workspace for those operations; do not retry unchanged. `workspace_capabilities`
and the `backend.capabilities` map name exactly which operations are affected.

## VM error codes

| Code | HTTP | Retryable | Meaning |
| --- | --- | --- | --- |
| `VM_BACKEND_DISABLED` | 503 | No | The `incus-vm` kind is not enabled on this instance. |
| `VM_CAPABILITY_UNSUPPORTED` | 400 | No | The workspace backend does not support this operation. |
| `VM_QUOTA_EXCEEDED` | 429 | Later | The single-VM concurrency bound is full; retry after a VM closes. |
| `VM_GENERATION_MISMATCH` | 409 | Refetch | The VM generation fence moved; re-read `workspace_status`. |
| `VM_IDENTITY_MISMATCH` | 409 | Refetch | The persisted VM identity no longer matches; re-read `workspace_status`. |
| `VM_ATTESTATION_FAILED` | 503 | No | The VM failed template attestation at admission. |
| `VM_UNKNOWN_STATE` | 503 | Reconcile | A mutation's outcome is unknown; `workspace_status` reports the retained record. Never delete it. |
| `VM_SUPERVISOR_UNAVAILABLE` | 503 | Yes | The host supervisor socket is unreachable; retry later. |
| `LIMIT_EXCEEDED` | 429 | Later | Generic bound (also used for VM admission limits). |

For `VM_UNKNOWN_STATE` and `VM_SUPERVISOR_UNAVAILABLE`, reconcile with
`workspace_status` before retrying; an `UNKNOWN` workspace is retained, never
auto-deleted, and `workspace_recover` performs the offline clean-check before
any removal decision.

## Trust boundary

VM workspaces do not get a stronger trust boundary than Docker for guest-side
state: guest root can read secrets injected for that exec and can tamper with
all guest-side state, including baked worker files. Host-side control
credentials (supervisor token, runner token, GitHub App key, database
credentials) never enter the guest, and there is no durable guest env file —
each exec carries an explicit environment. Enforcing egress is the external
host guard, not the guest firewall, which is not trusted. Host-root removal
of every enforcement layer is outside the guarantee.
