import { HarnessError } from '@cloud-harness/contracts';
import type {
  BackendCapabilityId,
  BackendCapabilityMap,
  BackendCapabilityValue,
  ExecutorBackendKind,
  InternalRunnerOperation,
  RunnerOperation
} from '@cloud-harness/contracts';

/**
 * Phase-09 capability gating: the per-backend `BackendCapabilityMap` content and
 * the operation→capability classification the executor gate consults.
 *
 * The maps below are the frozen v1 matrix from
 * `plans/261107-incus-vm-backend/phase-09-capability-gating.md`. They declare
 * what each backend's `ExecutorBackend.capabilities()` reports; the phase-03
 * gate in `workspace-service.ts` rejects an operation whose capability is
 * `unsupported` before dispatch, so an unsupported operation never reaches a
 * backend verb. Rows marked SUPPORTED still depend on the phase-07/08 backend
 * implementations landing; until a backend is registered its factory refuses
 * with VM_BACKEND_DISABLED, so the map cannot advertise a backend that does
 * not exist.
 */

const SUPPORTED: BackendCapabilityValue = 'supported';
const UNSUPPORTED: BackendCapabilityValue = 'unsupported';

/**
 * Docker capability map: every capability id is supported — this is today's
 * behavior and the regression baseline (no operation may be newly rejected for
 * docker workspaces).
 */
export const DOCKER_BACKEND_CAPABILITIES: BackendCapabilityMap = {
  exec: SUPPORTED,
  files: SUPPORTED,
  search: SUPPORTED,
  symbols: SUPPORTED,
  context: SUPPORTED,
  'git-local': SUPPORTED,
  'git-remote': SUPPORTED,
  'git-broker': SUPPORTED,
  shells: SUPPORTED,
  sessions: SUPPORTED,
  tasks: SUPPORTED,
  terminal: SUPPORTED,
  artifacts: SUPPORTED,
  skills: SUPPORTED,
  'toolkits-owner': SUPPORTED,
  'toolkits-workspace': SUPPORTED,
  'packages-bind': SUPPORTED,
  agents: SUPPORTED,
  secrets: SUPPORTED,
  deployments: SUPPORTED,
  worktrees: SUPPORTED,
  recovery: SUPPORTED,
  pty: SUPPORTED,
  'dashboard-repo-skills': SUPPORTED
};

/**
 * incus-vm capability map (v1, frozen). Everything the matrix marks supported
 * runs inside the guest through the phase-07 backend verbs or stays on host
 * helpers that never touch workspace data; the two unsupported rows are the
 * explicit rejections:
 *
 * - `packages-bind`: managed package releases are host directories mounted
 *   into Docker executors; a VM has no mount channel, so binding a package to
 *   an incus-vm workspace is rejected (owner-scope package operations still
 *   work — the builder stays Docker).
 * - `dashboard-repo-skills`: workspace/repository skill reads are served from
 *   a host checkout path that cannot exist for a guest checkout; owner and
 *   built-in skill directories are host-side and unaffected.
 */
export const INCUS_VM_BACKEND_CAPABILITIES: BackendCapabilityMap = {
  exec: SUPPORTED,
  files: SUPPORTED,
  search: SUPPORTED,
  symbols: SUPPORTED,
  context: SUPPORTED,
  'git-local': SUPPORTED,
  'git-remote': SUPPORTED,
  'git-broker': SUPPORTED,
  shells: SUPPORTED,
  sessions: SUPPORTED,
  tasks: SUPPORTED,
  terminal: SUPPORTED,
  artifacts: SUPPORTED,
  skills: SUPPORTED,
  'toolkits-owner': SUPPORTED,
  'toolkits-workspace': SUPPORTED,
  'packages-bind': UNSUPPORTED,
  agents: SUPPORTED,
  secrets: SUPPORTED,
  deployments: SUPPORTED,
  worktrees: SUPPORTED,
  recovery: SUPPORTED,
  pty: SUPPORTED,
  'dashboard-repo-skills': UNSUPPORTED
};

/** The declared capability map for a backend kind. Exhaustive over the enum. */
export function backendCapabilityMap(kind: ExecutorBackendKind): BackendCapabilityMap {
  switch (kind) {
    case 'docker':
      return DOCKER_BACKEND_CAPABILITIES;
    case 'incus-vm':
      return INCUS_VM_BACKEND_CAPABILITIES;
  }
}

/**
 * Phase-09 gate primitive: throws VM_CAPABILITY_UNSUPPORTED when the map marks
 * the capability unsupported. The message names the capability and the
 * supported alternative so callers can route around the rejection.
 */
export function assertVmCapability(
  map: BackendCapabilityMap,
  capabilityId: BackendCapabilityId,
  operation?: string
): void {
  if (map[capabilityId] !== 'unsupported') return;
  const subject = operation === undefined ? `capability '${capabilityId}'` : `operation ${operation} (capability '${capabilityId}')`;
  throw new HarnessError(
    'VM_CAPABILITY_UNSUPPORTED',
    `${subject} is not supported by this executor backend; use a docker workspace for this operation`,
    400,
    false
  );
}

/**
 * Exhaustive executor-operation classification. Every RunnerOperation is
 * either executor-bound (names the BackendCapabilityId the gate checks) or
 * 'host-only' (lifecycle, metadata, artifact store, owner-scoped packages,
 * model config — never reaches an executor verb). TypeScript enforces
 * completeness: a new RunnerOperation cannot compile without a class.
 */
export type ExecutorOperationClass = BackendCapabilityId | 'host-only';

export const EXECUTOR_OPERATION_CLASS: Readonly<Record<RunnerOperation, ExecutorOperationClass>> = {
  // Workspace lifecycle and principal-level operations never enter the executor.
  workspace_open: 'host-only',
  workspace_list: 'host-only',
  workspace_status: 'host-only',
  workspace_capabilities: 'host-only',
  workspace_close: 'host-only',
  workspace_lease_renew: 'host-only',
  workspace_recover: 'host-only',
  workspace_set_active: 'host-only',
  workspace_finalize: 'host-only',
  operation_status: 'host-only',
  operation_cancel: 'host-only',
  operation_wait: 'host-only',
  git_identity_status: 'host-only',
  git_identity_set: 'host-only',
  secrets_list: 'host-only',
  github_repository_create: 'host-only',
  memories_list: 'host-only',
  memories_read: 'host-only',
  memories_write: 'host-only',
  memories_search: 'host-only',
  memories_delete: 'host-only',
  knowledge_create: 'host-only',
  knowledge_read: 'host-only',
  knowledge_update: 'host-only',
  knowledge_delete: 'host-only',
  knowledge_list: 'host-only',
  knowledge_search: 'host-only',
  knowledge_link: 'host-only',
  knowledge_unlink: 'host-only',
  knowledge_graph: 'host-only',
  deployments_list: 'host-only',
  artifacts_list: 'host-only',
  artifacts_read: 'host-only',
  artifacts_delete: 'host-only',
  hooks_activate: 'host-only',
  hooks_deactivate: 'host-only',
  packages_plan: 'host-only',
  packages_apply: 'host-only',
  packages_list: 'host-only',
  packages_status: 'host-only',
  packages_rollback: 'host-only',
  packages_remove: 'host-only',
  model_provider_list: 'host-only',
  model_catalog_search: 'host-only',
  model_connection_verify: 'host-only',
  model_profile_list: 'host-only',
  model_profile_validate: 'host-only',
  model_profile_create: 'host-only',
  model_profile_update: 'host-only',
  model_spend_summary: 'host-only',
  // Executor-bound operations mapped to their backend capability.
  workspace_context: 'context',
  files_list: 'files',
  files_read: 'files',
  files_write: 'files',
  files_write_batch: 'files',
  files_apply_patch: 'files',
  files_delete: 'files',
  files_move: 'files',
  files_mkdir: 'files',
  grep_search: 'search',
  symbols_search: 'symbols',
  symbols_references: 'symbols',
  exec_run: 'exec',
  bash: 'exec',
  shell_open: 'shells',
  shell_io: 'shells',
  shell_close: 'shells',
  sessions_list: 'sessions',
  sessions_open: 'sessions',
  sessions_io: 'sessions',
  sessions_close: 'sessions',
  tasks_list: 'tasks',
  tasks_run: 'tasks',
  tasks_status: 'tasks',
  tasks_cancel: 'tasks',
  tasks_graph: 'tasks',
  git_status: 'git-local',
  git_diff: 'git-local',
  git_log: 'git-local',
  git_branch: 'git-local',
  git_checkout: 'git-local',
  git_add: 'git-local',
  git_commit: 'git-local',
  git_merge: 'git-local',
  git_rebase: 'git-local',
  git_fetch: 'git-remote',
  git_pull: 'git-remote',
  git_push: 'git-remote',
  worktrees_list: 'worktrees',
  worktrees_create: 'worktrees',
  worktrees_remove: 'worktrees',
  skills_list: 'skills',
  skills_read: 'skills',
  skills_run: 'skills',
  skill_suggest: 'skills',
  hooks_list: 'exec',
  hooks_run: 'exec',
  deployments_run: 'deployments',
  artifacts_snapshot: 'artifacts',
  artifacts_restore: 'artifacts',
  github_action: 'git-broker',
  github_read: 'git-broker',
  agent_spawn: 'agents',
  agent_status: 'agents',
  agent_logs: 'agents',
  agent_message: 'agents',
  agent_cancel: 'agents',
  agent_list: 'agents'
};

/**
 * Internal (non-MCP) runner operations, classified the same way. Only the
 * dashboard PTY operations reach an executor verb; every other internal
 * operation is host-side state or settings.
 */
export const INTERNAL_EXECUTOR_OPERATION_CLASS: Readonly<Record<InternalRunnerOperation, ExecutorOperationClass>> = {
  workspace_detail: 'host-only',
  workspace_close_fenced: 'host-only',
  toolkits_list: 'host-only',
  toolkits_preview: 'host-only',
  settings_get: 'host-only',
  settings_update: 'host-only',
  settings_network_check: 'host-only',
  oauth_settings_get: 'host-only',
  oauth_settings_update: 'host-only',
  terminal_open: 'terminal',
  terminal_read: 'terminal',
  terminal_input: 'terminal',
  terminal_resize: 'terminal',
  terminal_close: 'terminal',
  terminal_list: 'host-only'
};

/**
 * The capability an operation needs, or undefined for host-only and unknown
 * operations. Unknown names return undefined because callers can only pass
 * schema-validated operations; the classification records above are the
 * audited completeness boundary (matrix tests enumerate every enum member).
 */
export function executorCapabilityForOperation(operation: string): BackendCapabilityId | undefined {
  const cls = (EXECUTOR_OPERATION_CLASS as Record<string, ExecutorOperationClass>)[operation]
    ?? (INTERNAL_EXECUTOR_OPERATION_CLASS as Record<string, ExecutorOperationClass>)[operation];
  return cls === undefined || cls === 'host-only' ? undefined : cls;
}

/**
 * The full class of a known operation: a BackendCapabilityId when executor-bound,
 * 'host-only' when it never touches an executor, undefined when the name is not
 * a known operation at all. Tests use this to prove every enum member is
 * explicitly classified rather than silently ungated.
 */
export function executorOperationClass(operation: string): ExecutorOperationClass | undefined {
  return (EXECUTOR_OPERATION_CLASS as Record<string, ExecutorOperationClass>)[operation]
    ?? (INTERNAL_EXECUTOR_OPERATION_CLASS as Record<string, ExecutorOperationClass>)[operation];
}

/** True when the operation is executor-bound and the backend marks its capability unsupported. */
export function executorCapabilityUnsupported(
  backend: { capabilities(): BackendCapabilityMap },
  operation: string
): boolean {
  const capability = executorCapabilityForOperation(operation);
  if (capability === undefined) return false;
  return backend.capabilities()[capability] === 'unsupported';
}

/**
 * Throws VM_CAPABILITY_UNSUPPORTED when an executor-bound operation's
 * capability is unsupported on the backend — the single-call form of the gate
 * for callers that already hold a resolved backend.
 */
export function assertExecutorOperationSupported(
  backend: { kind: ExecutorBackendKind; capabilities(): BackendCapabilityMap },
  operation: string
): void {
  const capability = executorCapabilityForOperation(operation);
  if (capability === undefined) return;
  if (backend.capabilities()[capability] === 'unsupported') {
    throw new HarnessError(
      'VM_CAPABILITY_UNSUPPORTED',
      `operation ${operation} is not supported by the ${backend.kind} executor backend; use a docker workspace for this operation`,
      400,
      false
    );
  }
}
