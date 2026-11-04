import { expect, it } from 'vitest';
import { mapDashboardData } from '../src/dashboard-response.js';
it('projects remote execution posture without provider identifiers or credentials', () => {
  const result = mapDashboardData('workspace_status', { workspaceId: 'ws_example', networkProfile: 'provider-managed',
    executorKind: 'instabox', installedSoftwareRetained: true, retention: 'explicit-close-only',
    machineId: 'private-machine', ownerId: 'private-owner', apiKey: 'credential-sentinel', root: '/private/provider/root' });
  expect(result).toEqual({ workspaceId: 'ws_example', networkProfile: 'provider-managed', executorKind: 'instabox', installedSoftwareRetained: true, retention: 'explicit-close-only' });
});
