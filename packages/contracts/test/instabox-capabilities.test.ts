import { describe, expect, it } from 'vitest';
import { ExecutorNetworkProfileSchema, WorkspaceCapabilitiesSchema, WorkspaceNetworkExposureSchema, TOOL_SCHEMA_BY_NAME } from '../src/index.js';
const capabilities = { shell: true, tasks: true, sessions: true, deployments: true, privileged: false, networkProfile: 'provider-managed',
  executorKind: 'instabox', installedSoftwareRetained: true, retention: 'explicit-close-only',
  recovery: { stop: true, resume: true, recreate: false }, installations: { direct: true, managedPackages: false, managedDependencies: false } };
describe('remote workspace capabilities', () => {
  it('validates actual network, retained recovery and direct installation without widening restricted request profiles', () => {
    expect(WorkspaceCapabilitiesSchema.parse(capabilities)).toMatchObject(capabilities);
    expect(WorkspaceNetworkExposureSchema.parse('provider-managed')).toBe('provider-managed');
    expect(ExecutorNetworkProfileSchema.safeParse('provider-managed').success).toBe(false);
    expect(TOOL_SCHEMA_BY_NAME.workspace_open.safeParse({ repositoryUrl: 'https://github.com/example/repository.git', networkProfile: 'provider-managed' }).success).toBe(false);
  });
  it('rejects remote claims of restricted network, managed mounts or recreation', () => {
    for (const change of [
      { networkProfile: 'dependency-access' }, { networkProfile: 'network-none' },
      { installations: { direct: true, managedPackages: true, managedDependencies: false } },
      { recovery: { stop: true, resume: true, recreate: true } }
    ]) expect(WorkspaceCapabilitiesSchema.safeParse({ ...capabilities, ...change }).success).toBe(false);
  });
  it('preserves old local responses without requiring new metadata', () => {
    for (const networkProfile of ['network-none', 'dependency-access', 'local-host']) {
      expect(WorkspaceCapabilitiesSchema.safeParse({ shell: true, tasks: true, sessions: true, deployments: true, networkProfile }).success).toBe(true);
    }
  });
});
