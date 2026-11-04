import { DependencyPlanViewSchema } from '@cloud-harness/contracts';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { DependencyPlansSection } from './dependency-plans-section';

const plan = DependencyPlanViewSchema.parse({
  planId: `dep_${'a'.repeat(24)}`, planDigest: 'b'.repeat(64), workspaceId: `ws_${'c'.repeat(24)}`,
  ecosystem: 'pnpm', directory: 'app', state: 'PENDING_APPROVAL',
  manifests: [{ path: 'app/pnpm-lock.yaml', sha256: 'd'.repeat(64) }], hosts: ['registry.npmjs.org'],
  dependencyCount: 3, changes: { added: 2, removed: 1 }, timeoutMs: 900000, maxBytes: 2048,
  scripts: 'deny', createdAt: Date.now(), expiresAt: Date.now() + 600000, completedAt: null, sizeBytes: null, error: null
});
function show(plans: Array<typeof plan>) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: Infinity, retry: false } } });
  queryClient.setQueryData(['bff', '/dependency-plans', {}], { data: { plans } });
  const decide = vi.fn();
  render(<QueryClientProvider client={queryClient}><DependencyPlansSection onDecide={decide} /></QueryClientProvider>);
  return decide;
}
describe('dependency approval cards', () => {
  it('shows approved download boundaries and forwards the exact displayed plan for confirmation', () => {
    const decide = show([plan]);
    const card = within(screen.getByTestId('dependency-plan-card'));
    expect(card.getByText('registry.npmjs.org')).toBeVisible();
    expect(card.getByText(plan.planDigest)).toBeVisible();
    expect(card.getByText(`app/pnpm-lock.yaml: ${'d'.repeat(64)}`)).toBeVisible();
    expect(card.getByText('Disabled')).toBeVisible();
    fireEvent.click(card.getByRole('button', { name: 'Approve' }));
    expect(decide).toHaveBeenCalledWith(plan, 'approve');
  });
  it('does not offer decisions once downloading starts', () => {
    show([{ ...plan, state: 'RUNNING' }]);
    const card = within(screen.getByTestId('dependency-plan-card'));
    expect(card.getByText('Downloading')).toBeVisible();
    expect(card.queryByRole('button')).not.toBeInTheDocument();
  });
});
