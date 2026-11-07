import { z } from 'zod';

/**
 * Executor backend kinds. `docker` is the shipped default and the only backend
 * existing workspaces may carry; `incus-vm` is the opt-in Incus VM backend for
 * newly opened workspaces. The kind is persisted on the workspace record at
 * admit and is immutable afterwards.
 */
export const ExecutorBackendKindSchema = z.enum(['docker', 'incus-vm']);
export type ExecutorBackendKind = z.infer<typeof ExecutorBackendKindSchema>;

/**
 * Persisted/supervisor VM identity formats. `vm_name` is the deterministic
 * DNS-safe name `chm-vm-<sha256(workspaceId)[:32]>`; the truncated hash is not
 * injective, so full identity verification (instance id + template + metadata)
 * is the collision check and mismatches surface as VM_IDENTITY_MISMATCH.
 * `backend_instance_id` is a random UUID assigned at admit and persisted before
 * any Incus call so a lost create reply can be reconciled.
 */
export const VmNameSchema = z.string().regex(/^chm-vm-[0-9a-f]{32}$/, 'invalid VM name');
export const VmInstanceIdSchema = z.string().uuid('invalid VM instance id');
export const VmTemplateIdSchema = z.string().min(1).max(256).regex(
  /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$/,
  'invalid VM template id'
);
export const VmTemplateDigestSchema = z.string().regex(/^[0-9a-f]{64}$/, 'expected lowercase SHA-256 hex template digest');

/**
 * The capability ids a backend declares support for. Enumerated once here so the
 * runner capability surface, the supervisor contract, and the dashboard gating
 * all read the same vocabulary. Order is stable for snapshot tests.
 */
export const BACKEND_CAPABILITY_IDS = [
  'exec',
  'files',
  'search',
  'symbols',
  'context',
  'git-local',
  'git-remote',
  'git-broker',
  'shells',
  'sessions',
  'tasks',
  'terminal',
  'artifacts',
  'skills',
  'toolkits-owner',
  'toolkits-workspace',
  'packages-bind',
  'agents',
  'secrets',
  'deployments',
  'worktrees',
  'recovery',
  'pty',
  'dashboard-repo-skills'
] as const;

export const BackendCapabilityIdSchema = z.enum(BACKEND_CAPABILITY_IDS);
export type BackendCapabilityId = z.infer<typeof BackendCapabilityIdSchema>;

export const BackendCapabilityValueSchema = z.enum(['supported', 'unsupported']);
export type BackendCapabilityValue = z.infer<typeof BackendCapabilityValueSchema>;

/** Every capability id must be present: a backend declares its whole matrix, never a subset. */
export const BackendCapabilityMapSchema = z.record(BackendCapabilityIdSchema, BackendCapabilityValueSchema);
export type BackendCapabilityMap = z.infer<typeof BackendCapabilityMapSchema>;

/**
 * The structured backend block on a workspace capability result: which executor
 * backend the workspace runs on, its template identity when it is a VM, and the
 * per-capability support matrix clients check before calling an operation.
 */
export const WorkspaceBackendInfoSchema = z.object({
  kind: ExecutorBackendKindSchema,
  templateId: VmTemplateIdSchema.optional(),
  capabilities: BackendCapabilityMapSchema
}).strict();
export type WorkspaceBackendInfo = z.infer<typeof WorkspaceBackendInfoSchema>;
