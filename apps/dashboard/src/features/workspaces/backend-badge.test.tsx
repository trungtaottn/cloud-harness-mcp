import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, within } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { apiClient } from '@/lib/api-client';
import { BackendBadge } from './backend-badge';
import SummaryTab from '@/features/workspace-cockpit/tabs/summary-tab';
import type { Workspace } from './workspace-model';

function wrap(children: ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

const VM_WORKSPACE: Workspace = {
  workspaceId: `ws_${'v'.repeat(24)}`, status: 'ACTIVE', ref: 'main', executionBackend: 'incus-vm',
  backend: {
    kind: 'incus-vm', templateId: 'cloudharness-ubuntu-2404',
    capabilities: { exec: 'supported', skills: 'supported', 'packages-bind': 'unsupported', 'dashboard-repo-skills': 'unsupported' }
  }
};

const DOCKER_WORKSPACE: Workspace = {
  workspaceId: `ws_${'d'.repeat(24)}`, status: 'ACTIVE', executionBackend: 'docker',
  backend: { kind: 'docker', capabilities: { exec: 'supported', 'packages-bind': 'supported' } }
};

describe('BackendBadge', () => {
  it('labels an Incus VM workspace', () => {
    render(<BackendBadge workspace={VM_WORKSPACE} />);
    expect(screen.getByText('Incus VM')).toBeInTheDocument();
  });

  it('labels a Docker workspace', () => {
    render(<BackendBadge workspace={DOCKER_WORKSPACE} />);
    expect(screen.getByText('Docker')).toBeInTheDocument();
  });

  it('says Not reported when the runner sent no backend kind', () => {
    render(<BackendBadge workspace={{ workspaceId: `ws_${'x'.repeat(24)}`, status: 'ACTIVE' }} />);
    expect(screen.getByText('Not reported')).toBeInTheDocument();
  });
});

describe('SummaryTab backend display', () => {
  beforeEach(() => {
    vi.spyOn(apiClient, 'get').mockResolvedValue({ data: { branch: 'main', capabilities: {}, manifest: { itemCount: 0 } } } as never);
  });

  function renderTab(workspace: Workspace) {
    return render(wrap(<SummaryTab workspaceId={workspace.workspaceId} workspace={workspace} search={{}} onSearch={() => undefined} />));
  }

  it('shows the backend kind, template and the unsupported capabilities a VM declares', async () => {
    renderTab(VM_WORKSPACE);
    expect(await screen.findByText('Incus VM · cloudharness-ubuntu-2404')).toBeInTheDocument();
    expect(screen.getByText('Repository skill browsing, Package binding')).toBeInTheDocument();
  });

  it('shows Docker with no unsupported capabilities', async () => {
    renderTab(DOCKER_WORKSPACE);
    expect(await screen.findByText('Docker')).toBeInTheDocument();
    expect(screen.getByText('None declared')).toBeInTheDocument();
  });

  it('says Not reported for backend details when the runner sent none', async () => {
    renderTab({ workspaceId: `ws_${'y'.repeat(24)}`, status: 'ACTIVE' });
    const backendRow = await screen.findByText('Not supported on this backend');
    expect(within(backendRow.parentElement as HTMLElement).getByText('Not reported')).toBeInTheDocument();
    const backendFact = screen.getByText('Backend', { selector: 'dt' });
    expect(within(backendFact.parentElement as HTMLElement).getByText('Not reported')).toBeInTheDocument();
  });
});
