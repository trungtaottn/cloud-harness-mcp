import { z } from 'zod';
import { WorkspaceIdSchema } from './identifiers.js';

export const DependencyPlanIdSchema = z.string().regex(/^dep_[A-Za-z0-9_-]{20,80}$/);
export const DependencyDigestSchema = z.string().regex(/^[a-f0-9]{64}$/);
export const DependencyEcosystemSchema = z.enum(['go', 'pnpm']);
export const DependencyStateSchema = z.enum(['PENDING_APPROVAL', 'APPROVED', 'REJECTED', 'EXPIRED', 'RUNNING', 'SUCCEEDED', 'FAILED']);
export const DependencyDirectorySchema = z.string().min(1).max(512).refine(
  (path) => path === '.' || /^(?:[A-Za-z0-9_.-]+\/)*[A-Za-z0-9_.-]+$/.test(path)
    && !path.split('/').some((part) => part === '..' || part === '.'),
  'directory must be workspace-relative without dot segments'
);
export const DependenciesPlanInputSchema = z.object({
  workspaceId: WorkspaceIdSchema,
  ecosystem: DependencyEcosystemSchema,
  directory: DependencyDirectorySchema.default('.')
}).strict();
export const DependenciesApplyInputSchema = z.object({
  workspaceId: WorkspaceIdSchema,
  planId: DependencyPlanIdSchema,
  planDigest: DependencyDigestSchema
}).strict();
export const DependenciesStatusInputSchema = z.object({
  workspaceId: WorkspaceIdSchema,
  planId: DependencyPlanIdSchema.optional()
}).strict();
export const DependencyPlanApproveInputSchema = z.object({
  planId: DependencyPlanIdSchema, planDigest: DependencyDigestSchema
}).strict();
export const DependencyPlanRejectInputSchema = z.object({ planId: DependencyPlanIdSchema }).strict();
export const DependencyPlanListInputSchema = z.object({}).strict();
export const DependencyPlanViewSchema = z.object({
  planId: DependencyPlanIdSchema,
  planDigest: DependencyDigestSchema,
  workspaceId: WorkspaceIdSchema,
  ecosystem: DependencyEcosystemSchema,
  directory: DependencyDirectorySchema,
  state: DependencyStateSchema,
  manifests: z.array(z.object({ path: z.string(), sha256: DependencyDigestSchema })),
  hosts: z.array(z.string()),
  dependencyCount: z.number().int().nonnegative(),
  changes: z.object({ added: z.number().int().nonnegative(), removed: z.number().int().nonnegative() }),
  timeoutMs: z.number().int().positive(),
  maxBytes: z.number().int().positive(),
  scripts: z.literal('deny'),
  createdAt: z.number(),
  expiresAt: z.number(),
  completedAt: z.number().nullable(),
  sizeBytes: z.number().nullable(),
  error: z.string().nullable()
});
export type DependencyEcosystem = z.infer<typeof DependencyEcosystemSchema>;
export type DependencyPlanView = z.infer<typeof DependencyPlanViewSchema>;
export type DependenciesPlanInput = z.infer<typeof DependenciesPlanInputSchema>;
export type DependenciesApplyInput = z.infer<typeof DependenciesApplyInputSchema>;
