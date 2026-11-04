import { WorkspaceIdSchema } from '@cloud-harness/contracts';
import { describe, expect, it } from 'vitest';
import { pendingDependencyCount } from '@/lib/approvals-summary';
import { dependencyPlanCanWithdraw, dependencyPlanIsActionable, dependencyPlanStatusLabel, type DependencyPlanView } from './approvals-model';
const plan: DependencyPlanView = {
  planId: `dep_${'a'.repeat(24)}`, planDigest: 'b'.repeat(64), workspaceId: WorkspaceIdSchema.parse(`ws_${'c'.repeat(24)}`),
  ecosystem: 'go', directory: '.', state: 'PENDING_APPROVAL', manifests: [], hosts: ['proxy.golang.org'],
  dependencyCount: 2, changes: { added: 1, removed: 0 }, timeoutMs: 900000, maxBytes: 1024,
  scripts: 'deny', createdAt: 100, expiresAt: 1000, completedAt: null, sizeBytes: null, error: null
};
describe('dependency approval decisions', () => {
  it('counts only pending unexpired plans using numeric timestamps', () => {
    const plans = [plan, { ...plan, state: 'APPROVED' }, { ...plan, expiresAt: 200 }];
    expect(pendingDependencyCount({ data: { plans } }, 500)).toBe(1);
    expect(dependencyPlanIsActionable(plan, 1000)).toBe(false);
    expect(dependencyPlanStatusLabel(plan, 1000)).toBe('Expired');
  });
  it('allows withdrawal only before download starts and approval expires', () => {
    expect(dependencyPlanCanWithdraw({ ...plan, state: 'APPROVED' }, 500)).toBe(true);
    expect(dependencyPlanCanWithdraw({ ...plan, state: 'APPROVED' }, 1000)).toBe(false);
    expect(dependencyPlanCanWithdraw({ ...plan, state: 'RUNNING' }, 500)).toBe(false);
  });
  it('distinguishes approval, active download and successful completion', () => {
    expect(dependencyPlanStatusLabel({ ...plan, state: 'APPROVED' }, 500)).toBe('Approved, awaiting download');
    expect(dependencyPlanStatusLabel({ ...plan, state: 'RUNNING' }, 500)).toBe('Downloading');
    expect(dependencyPlanStatusLabel({ ...plan, state: 'SUCCEEDED' }, 500)).toBe('Downloaded');
  });
});
