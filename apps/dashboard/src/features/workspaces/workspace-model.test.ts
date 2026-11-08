import { describe, expect, it } from 'vitest';
import {
  backendCapability, backendKindOf, backendLabel, backendTemplateId, capabilityLabel,
  filterWorkspaces, networkLabel, repositoryName, unsupportedBackendCapabilities, type Workspace, workspaceHasAction
} from './workspace-model';

const VM_CAPABILITIES: Record<string, string> = {
  exec: 'supported', files: 'supported', skills: 'supported', 'packages-bind': 'unsupported',
  'dashboard-repo-skills': 'unsupported', pty: 'supported'
};

const vmWorkspace: Workspace = {
  workspaceId: `ws_${'v'.repeat(24)}`, status: 'ACTIVE', executionBackend: 'incus-vm',
  backend: { kind: 'incus-vm', templateId: 'cloudharness-ubuntu-2404', capabilities: VM_CAPABILITIES }
};

describe('backend helpers', () => {
  it('reads the kind from the structured block first, then the flat field', () => {
    expect(backendKindOf(vmWorkspace)).toBe('incus-vm');
    expect(backendKindOf({ executionBackend: 'docker' })).toBe('docker');
    expect(backendKindOf({ backend: { kind: 'incus-vm' } })).toBe('incus-vm');
  });

  it('reports an unknown or absent kind as undefined rather than guessing Docker', () => {
    expect(backendKindOf(undefined)).toBeUndefined();
    expect(backendKindOf({})).toBeUndefined();
    expect(backendKindOf({ executionBackend: 'gvisor' })).toBeUndefined();
    expect(backendKindOf({ backend: { kind: 'other' } })).toBeUndefined();
    expect(backendLabel(undefined)).toBe('Not reported');
    expect(backendLabel('docker')).toBe('Docker');
    expect(backendLabel('incus-vm')).toBe('Incus VM');
  });

  it('reads the template id only when the backend block carries one', () => {
    expect(backendTemplateId(vmWorkspace)).toBe('cloudharness-ubuntu-2404');
    expect(backendTemplateId({ executionBackend: 'docker' })).toBeUndefined();
    expect(backendTemplateId({ backend: { kind: 'incus-vm', templateId: '' } })).toBeUndefined();
  });

  it('reads capability support only from the declared matrix', () => {
    expect(backendCapability(vmWorkspace, 'packages-bind')).toBe('unsupported');
    expect(backendCapability(vmWorkspace, 'exec')).toBe('supported');
    expect(backendCapability(vmWorkspace, 'unknown-cap')).toBeUndefined();
    expect(backendCapability({ executionBackend: 'incus-vm' }, 'exec')).toBeUndefined();
    expect(backendCapability({ backend: { capabilities: { exec: 'maybe' } } }, 'exec')).toBeUndefined();
  });

  it('lists unsupported capabilities sorted, and nothing when no matrix was reported', () => {
    expect(unsupportedBackendCapabilities(vmWorkspace)).toEqual(['dashboard-repo-skills', 'packages-bind']);
    expect(unsupportedBackendCapabilities({ backend: { capabilities: { exec: 'supported' } } })).toEqual([]);
    expect(unsupportedBackendCapabilities({ executionBackend: 'incus-vm' })).toEqual([]);
    expect(unsupportedBackendCapabilities(undefined)).toEqual([]);
  });

  it('labels known capability ids and humanizes unknown ones', () => {
    expect(capabilityLabel('packages-bind')).toBe('Package binding');
    expect(capabilityLabel('dashboard-repo-skills')).toBe('Repository skill browsing');
    expect(capabilityLabel('pty')).toBe('Pty');
    expect(capabilityLabel('git-local')).toBe('Git local');
  });
});

describe('existing workspace helpers still hold', () => {
  it('keeps repository, network and action helpers unchanged', () => {
    expect(repositoryName('https://github.com/acme/project.git')).toBe('acme/project');
    expect(networkLabel('dependency-access')).toBe('Dependency access');
    expect(workspaceHasAction({ workspaceId: `ws_${'h'.repeat(24)}`, status: 'ACTIVE' }, 'workspace_context')).toBe(true);
    expect(workspaceHasAction({ workspaceId: `ws_${'h'.repeat(24)}`, status: 'CLOSED' }, 'workspace_context')).toBe(false);
    expect(filterWorkspaces([vmWorkspace], { q: 'example' })).toHaveLength(0);
  });
});
