import { describe, expect, it } from 'vitest';
import {
  BACKEND_CAPABILITY_IDS,
  BackendCapabilityMapSchema,
  ErrorCodeSchema,
  ExecutorBackendKindSchema,
  RunnerConfigSchema,
  TOOL_SCHEMA_BY_NAME,
  VmHostOperationSchema,
  VmInstanceStateSchema,
  VmSupervisorHostRequestSchema,
  VmSupervisorOpResultSchemas,
  VmSupervisorRequestSchema,
  VmSupervisorResponseSchema,
  VmSupervisorWorkspaceRequestSchema,
  VmWorkspaceOperationSchema,
  WorkspaceBackendInfoSchema,
  WorkspaceCapabilityResultSchema
} from '../src/index.js';

const WORKSPACE_ID = 'ws_0123456789abcdef0123';
const VM_INSTANCE_ID = '123e4567-e89b-42d3-a456-426614174000';
const TEMPLATE_DIGEST = 'a'.repeat(64);

const workspaceEnvelope = {
  version: 1 as const,
  requestId: 'req-0001',
  workspaceId: WORKSPACE_ID,
  workspaceGeneration: 3,
  vmInstanceId: VM_INSTANCE_ID,
  idempotencyKey: 'open-key-0001',
  issuedAt: 1_700_000_000_000
};

const hostEnvelope = {
  version: 1 as const,
  requestId: 'req-0002',
  issuedAt: 1_700_000_000_001
};

describe('executor backend contract', () => {
  it('enumerates exactly the docker and incus-vm backend kinds', () => {
    expect(ExecutorBackendKindSchema.options).toEqual(['docker', 'incus-vm']);
    expect(ExecutorBackendKindSchema.parse('docker')).toBe('docker');
    expect(ExecutorBackendKindSchema.parse('incus-vm')).toBe('incus-vm');
    expect(ExecutorBackendKindSchema.safeParse('containerd').success).toBe(false);
  });

  it('exposes the full stable capability id vocabulary', () => {
    expect(BACKEND_CAPABILITY_IDS).toHaveLength(24);
    expect(BACKEND_CAPABILITY_IDS).toContain('exec');
    expect(BACKEND_CAPABILITY_IDS).toContain('dashboard-repo-skills');
  });

  it('requires every capability id in a backend capability map', () => {
    const full = Object.fromEntries(BACKEND_CAPABILITY_IDS.map((id) => [id, 'supported']));
    expect(BackendCapabilityMapSchema.safeParse(full).success).toBe(true);
    const partial = { ...full } as Record<string, unknown>;
    delete partial.exec;
    expect(BackendCapabilityMapSchema.safeParse(partial).success).toBe(false);
    expect(BackendCapabilityMapSchema.safeParse({ ...full, exec: 'maybe' }).success).toBe(false);
  });

  it('validates the structured workspace backend info block', () => {
    const capabilities = Object.fromEntries(BACKEND_CAPABILITY_IDS.map((id) => [id, 'supported']));
    expect(WorkspaceBackendInfoSchema.safeParse({ kind: 'docker', capabilities }).success).toBe(true);
    expect(WorkspaceBackendInfoSchema.safeParse({
      kind: 'incus-vm', templateId: 'cloud-harness/ubuntu-vm:24.04', capabilities
    }).success).toBe(true);
    expect(WorkspaceBackendInfoSchema.safeParse({ kind: 'incus-vm', capabilities, extra: 1 }).success).toBe(false);
  });
});

describe('workspace_open executionBackend', () => {
  const open = (executionBackend?: string) => TOOL_SCHEMA_BY_NAME.workspace_open.safeParse({
    repositoryUrl: 'https://github.com/example/repository.git',
    idempotencyKey: 'open-key-0001',
    ...(executionBackend === undefined ? {} : { executionBackend })
  });

  it('accepts an omitted backend, docker, and incus-vm', () => {
    expect(open().success).toBe(true);
    expect(open('docker').success).toBe(true);
    expect(open('incus-vm').success).toBe(true);
  });

  it('rejects an unknown backend kind', () => {
    expect(open('incus-container').success).toBe(false);
  });
});

describe('workspace capability result backend fields', () => {
  it('accepts additive executionBackend and backend fields', () => {
    const capabilities = Object.fromEntries(BACKEND_CAPABILITY_IDS.map((id) => [id, 'supported']));
    const result = WorkspaceCapabilityResultSchema.safeParse({
      workspaceId: WORKSPACE_ID,
      repository: null,
      repositoryUrl: 'https://github.com/example/repository.git',
      capabilities: {
        repository: { read: true, push: true, issuesRead: true, issuesWrite: false, pullRequestsRead: true, pullRequestsWrite: false },
        workspace: { shell: true, tasks: true, sessions: true, deployments: false, networkProfile: 'network-none' }
      },
      permissions: {
        contents: { read: true, write: true },
        issues: { read: true, write: false },
        pullRequests: { read: true, write: false }
      },
      operations: {
        gitFetch: true, gitPull: true, gitPush: true,
        issueList: true, issueView: true, issueCreate: false, issueComment: false,
        issueUpdate: false, issuePublish: false, labelCreate: false,
        pullRequestList: true, pullRequestView: true, pullRequestCreate: false,
        execRun: true, privilegedExec: false, deploymentsRun: false
      },
      executionBackend: 'incus-vm',
      backend: { kind: 'incus-vm', templateId: 'cloud-harness/ubuntu-vm:24.04', capabilities }
    });
    expect(result.success).toBe(true);
  });
});

describe('VM error taxonomy', () => {
  it('contains all eight VM error codes', () => {
    for (const code of [
      'VM_BACKEND_DISABLED',
      'VM_CAPABILITY_UNSUPPORTED',
      'VM_QUOTA_EXCEEDED',
      'VM_UNKNOWN_STATE',
      'VM_GENERATION_MISMATCH',
      'VM_ATTESTATION_FAILED',
      'VM_SUPERVISOR_UNAVAILABLE',
      'VM_IDENTITY_MISMATCH'
    ]) {
      expect(ErrorCodeSchema.safeParse(code).success).toBe(true);
    }
  });
});

describe('VM supervisor request envelopes', () => {
  it('parses a workspace-scoped request with the full identity fence', () => {
    const request = {
      ...workspaceEnvelope,
      op: 'vm.status',
      params: {}
    };
    const parsed = VmSupervisorWorkspaceRequestSchema.safeParse(request);
    expect(parsed.success).toBe(true);
    expect(VmSupervisorRequestSchema.safeParse(request).success).toBe(true);
  });

  it('parses a host-scoped request without any workspace fields', () => {
    const request = { ...hostEnvelope, op: 'pool.info', params: {} };
    expect(VmSupervisorHostRequestSchema.safeParse(request).success).toBe(true);
    expect(VmSupervisorRequestSchema.safeParse(request).success).toBe(true);
  });

  it('rejects workspace fields on a host envelope', () => {
    const request = {
      ...hostEnvelope,
      workspaceId: WORKSPACE_ID,
      workspaceGeneration: 1,
      vmInstanceId: VM_INSTANCE_ID,
      idempotencyKey: 'open-key-0001',
      op: 'pool.info',
      params: {}
    };
    expect(VmSupervisorHostRequestSchema.safeParse(request).success).toBe(false);
    expect(VmSupervisorRequestSchema.safeParse(request).success).toBe(false);
  });

  it('rejects a workspace envelope missing any identity fence field', () => {
    for (const missing of ['workspaceId', 'workspaceGeneration', 'vmInstanceId', 'idempotencyKey'] as const) {
      const request = { ...workspaceEnvelope, op: 'vm.status', params: {} } as Record<string, unknown>;
      delete request[missing];
      expect(VmSupervisorWorkspaceRequestSchema.safeParse(request).success).toBe(false);
    }
  });

  it('rejects params that do not match the operation', () => {
    const wrongParams = { ...workspaceEnvelope, op: 'vm.create', params: {} };
    expect(VmSupervisorWorkspaceRequestSchema.safeParse(wrongParams).success).toBe(false);
    const extraParams = { ...workspaceEnvelope, op: 'vm.status', params: { bogus: 1 } };
    expect(VmSupervisorWorkspaceRequestSchema.safeParse(extraParams).success).toBe(false);
  });

  it('rejects an unknown operation', () => {
    const request = { ...workspaceEnvelope, op: 'vm.format', params: {} };
    expect(VmSupervisorRequestSchema.safeParse(request).success).toBe(false);
  });

  it('round-trips a serialized workspace request byte-identically', () => {
    const request = {
      ...workspaceEnvelope,
      op: 'vm.admit',
      params: { networkProfile: 'network-none' }
    };
    const parsed = VmSupervisorWorkspaceRequestSchema.parse(request);
    expect(JSON.parse(JSON.stringify(parsed))).toEqual(request);
  });

  it('splits the operation vocabulary into workspace and host sets', () => {
    expect(VmWorkspaceOperationSchema.options).toHaveLength(25);
    expect(VmHostOperationSchema.options).toEqual(['vm.list', 'lease.list', 'pool.info', 'reconcile', 'guard.state']);
    expect(VmSupervisorOpResultSchemas['vm.status']).toBeDefined();
    expect(VmSupervisorOpResultSchemas['pool.info']).toBeDefined();
  });
});

describe('VM supervisor response envelope', () => {
  it('parses ok and error responses', () => {
    expect(VmSupervisorResponseSchema.safeParse({
      version: 1, requestId: 'req-0001', ok: true, result: { state: 'running' }
    }).success).toBe(true);
    expect(VmSupervisorResponseSchema.safeParse({
      version: 1, requestId: 'req-0001', ok: false,
      error: { code: 'VM_SUPERVISOR_UNAVAILABLE', message: 'socket unreachable', retryable: true },
      unknown: true
    }).success).toBe(true);
  });

  it('rejects a response with an unknown error code or missing requestId', () => {
    expect(VmSupervisorResponseSchema.safeParse({
      version: 1, requestId: 'req-0001', ok: false,
      error: { code: 'BOGUS', message: 'x', retryable: false }
    }).success).toBe(false);
    expect(VmSupervisorResponseSchema.safeParse({ version: 1, ok: true, result: {} }).success).toBe(false);
  });
});

describe('VM instance state vocabulary', () => {
  it('normalizes Incus statuses into the frozen enum', () => {
    for (const state of ['stopped', 'starting', 'running', 'stopping', 'frozen', 'error', 'unknown']) {
      expect(VmInstanceStateSchema.safeParse(state).success).toBe(true);
    }
    expect(VmInstanceStateSchema.safeParse('paused').success).toBe(false);
  });
});

describe('VM runner configuration schema', () => {
  const base = {
    serviceToken: 's'.repeat(32),
    jobsRoot: '/var/lib/cloud-harness/jobs',
    stateDb: '/var/lib/cloud-harness/state/cloud-harness.db',
    executorImage: 'cloud-harness-executor:local',
    allowedGitHosts: ['github.com']
  };

  it('defaults the backend off with the documented sizing defaults', () => {
    const config = RunnerConfigSchema.parse(base);
    expect(config.vmBackendEnabled).toBe(false);
    expect(config.vmSupervisorSocket).toBe('/run/cloud-harness-vm/supervisor.sock');
    expect(config.vmMaxActive).toBe(1);
    expect(config.vmCpus).toBe(4);
    expect(config.vmMemoryBytes).toBe(8_589_934_592);
    expect(config.vmDiskBytes).toBe(21_474_836_480);
    expect(config.vmPoolReserveBytes).toBe(10_737_418_240);
    expect(config.vmMaxWorkspaceBytes).toBe(12_884_901_888);
    expect(config.vmInlineMaxBytes).toBe(8_388_608);
    expect(config.vmSupervisorToken).toBeUndefined();
    expect(config.vmTemplateId).toBeUndefined();
    expect(config.vmTemplateDigest).toBeUndefined();
  });

  it('accepts VM keys while the backend stays disabled', () => {
    const config = RunnerConfigSchema.parse({ ...base, vmMaxActive: '2', vmCpus: '8' });
    expect(config.vmMaxActive).toBe(2);
    expect(config.vmCpus).toBe(8);
  });

  it('refuses an enabled backend without token, template id, or digest', () => {
    expect(() => RunnerConfigSchema.parse({ ...base, vmBackendEnabled: true })).toThrow();
    expect(() => RunnerConfigSchema.parse({
      ...base, vmBackendEnabled: true, vmSupervisorToken: 't'.repeat(32)
    })).toThrow();
    expect(() => RunnerConfigSchema.parse({
      ...base, vmBackendEnabled: true,
      vmSupervisorToken: 't'.repeat(32), vmTemplateId: 'cloud-harness/ubuntu-vm:24.04'
    })).toThrow();
  });

  it('accepts a fully configured enabled backend', () => {
    const config = RunnerConfigSchema.parse({
      ...base,
      vmBackendEnabled: 'true',
      vmSupervisorToken: 't'.repeat(32),
      vmTemplateId: 'cloud-harness/ubuntu-vm:24.04',
      vmTemplateDigest: TEMPLATE_DIGEST,
      vmSupervisorSocket: '/run/custom/vm.sock'
    });
    expect(config.vmBackendEnabled).toBe(true);
    expect(config.vmSupervisorToken).toBe('t'.repeat(32));
    expect(config.vmTemplateId).toBe('cloud-harness/ubuntu-vm:24.04');
    expect(config.vmTemplateDigest).toBe(TEMPLATE_DIGEST);
    expect(config.vmSupervisorSocket).toBe('/run/custom/vm.sock');
  });

  it('rejects a malformed template digest even when disabled', () => {
    expect(() => RunnerConfigSchema.parse({ ...base, vmTemplateDigest: 'not-hex' })).toThrow();
    expect(() => RunnerConfigSchema.parse({ ...base, vmTemplateDigest: 'A'.repeat(64) })).toThrow();
  });

  it('rejects a non-absolute supervisor socket path', () => {
    expect(() => RunnerConfigSchema.parse({ ...base, vmSupervisorSocket: 'relative/path.sock' })).toThrow();
  });
});
