import { createServer, request as httpRequest, type Server } from 'node:http';
import express from 'express';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ApiConfig, ErrorCode, RunnerOperation, RunnerPrincipalSelector, RunnerResponse } from '@cloud-harness/contracts';
import { createDashboardRouter } from '../src/dashboard-router.js';
import { mapDashboardData, mergeWorkspaceBackend } from '../src/dashboard-response.js';
import type { DashboardRunnerClient } from '../src/dashboard-types.js';

const workspaceId = `ws_${'b'.repeat(24)}`;
const principal: RunnerPrincipalSelector = { kind: 'external', issuer: 'https://team.cloudflareaccess.com', subject: 'operator' };
const config: ApiConfig = {
  host: '127.0.0.1', port: 3000, authMode: 'cloudflare-access', ownerId: 'owner',
  accessIssuer: 'https://team.cloudflareaccess.com', accessAudience: 'audience',
  accessJwksUrl: 'https://team.cloudflareaccess.com/cdn-cgi/access/certs', runnerUrl: 'http://runner:3001',
  apiKeyAuthEnabled: true, apiKeyGatewayAccessAudience: 'api-key-audience',
  apiKeyGatewayServiceSubject: 'cf-service:d29ya2Vy', apiKeyGatewayPublicUrl: 'https://api.example/mcp',
  runnerToken: 'runner-token-that-is-longer-than-32-characters', publicHosts: ['dashboard.example'],
  allowedOrigins: ['https://dashboard.example'], requestTimeoutMs: 2_000, maxBodyBytes: 65_536,
  mcpGatewayTimeoutMs: 30_000, mcpGatewayMaxResponseBytes: 262_144, mcpGatewayMaxSchemaBytes: 65_536,
  mcpGatewayMaxCatalogBytes: 2_097_152, mcpGatewayMaxTraceRows: 20_000,
  mcpGatewayMaxConnections: 32, mcpGatewayAllowInsecureHttp: false, mcpGatewayAllowPrivateEndpoints: false
};

const VM_CAPABILITIES = {
  exec: 'supported', files: 'supported', search: 'supported', symbols: 'supported', context: 'supported',
  'git-local': 'supported', 'git-remote': 'supported', 'git-broker': 'supported', shells: 'supported',
  sessions: 'supported', tasks: 'supported', terminal: 'supported', artifacts: 'supported',
  skills: 'supported', 'toolkits-owner': 'supported', 'toolkits-workspace': 'supported',
  'packages-bind': 'unsupported', agents: 'supported', secrets: 'supported', deployments: 'supported',
  worktrees: 'supported', recovery: 'supported', pty: 'supported', 'dashboard-repo-skills': 'unsupported'
} as const;

const VM_BACKEND = { kind: 'incus-vm', templateId: 'cloudharness-ubuntu-2404', capabilities: { ...VM_CAPABILITIES } };
const VM_WORKSPACE = {
  workspaceId, repositoryUrl: 'https://github.com/example/project.git', ref: 'main', status: 'ACTIVE',
  networkProfile: 'dependency-access', createdAt: '2026-11-07T00:00:00.000Z', lastActivityAt: '2026-11-07T00:01:00.000Z',
  expiresAt: '2026-11-07T00:10:00.000Z', executionBackend: 'incus-vm', backend: VM_BACKEND,
  ownerId: 'internal-owner', workspacePath: '/host/jobs/private', vmName: 'chm-vm-secret', instanceId: 'uuid-secret'
};

type Reply = { status: number; json: any; text: string };
let server: Server;
let port: number;
let runner: DashboardRunnerClient;
let calls: Array<{ operation: string; input: Record<string, unknown> }>;

beforeEach(async () => {
  calls = [];
  runner = {
    call: vi.fn(async (operation: RunnerOperation, input: Record<string, unknown>): Promise<RunnerResponse> => {
      calls.push({ operation, input });
      if (operation === 'workspace_list') {
        return { ok: true, message: 'listed', truncated: false, data: { workspaces: [VM_WORKSPACE] } };
      }
      if (operation === 'workspace_status') {
        return { ok: true, message: 'status', truncated: false, data: { ...VM_WORKSPACE, generation: 9 } };
      }
      if (operation === 'workspace_context') {
        return { ok: true, message: 'context', truncated: false, data: {
          workspace: { ...VM_WORKSPACE },
          branch: 'feature/vm',
          gitIdentity: { name: 'Operator', email: 'owner@example.com' },
          capabilities: { repository: { read: true }, workspace: { tasks: true } },
          manifest: { truncated: false, items: [] }
        } };
      }
      if (operation === 'skills_list') {
        return { ok: false, message: 'refused', truncated: false, error: { code: 'VM_CAPABILITY_UNSUPPORTED', message: 'operation skills_list (capability \'skills\') supervisor detail must not leak', retryable: false } };
      }
      return { ok: true, message: 'ok', truncated: false, data: {} };
    }),
    callInternal: vi.fn(async (operation: string): Promise<RunnerResponse> => {
      calls.push({ operation, input: {} });
      // The internal detail projection deliberately lacks the backend block —
      // the BFF is expected to merge it from workspace_status.
      return { ok: true, message: 'detail', truncated: false, data: {
        workspaceId, repositoryUrl: 'https://github.com/example/project.git', status: 'ACTIVE',
        networkProfile: 'dependency-access', generation: 9,
        createdAt: '2026-11-07T00:00:00.000Z', lastActivityAt: '2026-11-07T00:01:00.000Z', expiresAt: '2026-11-07T00:10:00.000Z',
        availableActions: ['workspace_close'], ownerId: 'internal-owner', vmName: 'chm-vm-secret'
      } };
    })
  };
  const app = express();
  app.use((request: any, _response, next) => { request.auth = { token: 'cloudflare-access', clientId: 'operator', scopes: [], extra: { principal } }; next(); });
  app.use('/dashboard', createDashboardRouter(config, runner));
  server = createServer(app);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('server unavailable');
  port = address.port;
});

afterEach(async () => await new Promise<void>((resolve) => server.close(() => resolve())));

function send(path: string): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const request = httpRequest({ hostname: '127.0.0.1', port, path: `/dashboard${path}`, method: 'GET', headers: { host: 'dashboard.example' } }, (response) => {
      const chunks: Buffer[] = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json: any = undefined;
        try { if (text) json = JSON.parse(text); } catch { /* not json */ }
        resolve({ status: response.statusCode ?? 0, json, text });
      });
    });
    request.on('error', reject); request.end();
  });
}

describe('VM executor backend projection', () => {
  it('projects the backend block on workspace_list rows and drops runner internals', async () => {
    const response = await send('/api/v1/workspaces');
    expect(response.status).toBe(200);
    const row = response.json.data.workspaces[0];
    expect(row.executionBackend).toBe('incus-vm');
    expect(row.backend).toMatchObject({ kind: 'incus-vm', templateId: 'cloudharness-ubuntu-2404' });
    expect(row.backend.capabilities['packages-bind']).toBe('unsupported');
    expect(row.backend.capabilities['dashboard-repo-skills']).toBe('unsupported');
    const raw = JSON.stringify(response.json);
    for (const forbidden of ['internal-owner', '/host/jobs', 'chm-vm-secret', 'uuid-secret']) {
      expect(raw, forbidden).not.toContain(forbidden);
    }
  });

  it('merges backend fields from workspace_status into workspace_detail', async () => {
    const response = await send(`/api/v1/workspaces/${workspaceId}`);
    expect(response.status).toBe(200);
    expect(response.json.data.executionBackend).toBe('incus-vm');
    expect(response.json.data.backend.kind).toBe('incus-vm');
    expect(response.json.data.version).toBe(9);
    expect(calls.some((call) => call.operation === 'workspace_status')).toBe(true);
    const raw = JSON.stringify(response.json);
    expect(raw).not.toContain('chm-vm-secret');
    expect(raw).not.toContain('internal-owner');
  });

  it('leaves workspace_detail unchanged when the status read carries no backend', async () => {
    const original = runner.call;
    runner.call = vi.fn(async (operation: RunnerOperation, input: Record<string, unknown>): Promise<RunnerResponse> => {
      if (operation === 'workspace_status') return { ok: true, message: 'status', truncated: false, data: { workspaceId, status: 'ACTIVE' } };
      return original(operation, input, principal);
    }) as DashboardRunnerClient['call'];
    const response = await send(`/api/v1/workspaces/${workspaceId}`);
    expect(response.status).toBe(200);
    expect(response.json.data.executionBackend).toBeUndefined();
    expect(response.json.data.backend).toBeUndefined();
    expect(response.json.data.version).toBe(9);
  });

  it('surfaces backend fields through the nested workspace record on workspace_context', async () => {
    const response = await send(`/api/v1/workspaces/${workspaceId}/context`);
    expect(response.status).toBe(200);
    expect(response.json.data.executionBackend).toBe('incus-vm');
    expect(response.json.data.backend.kind).toBe('incus-vm');
    expect(response.json.data.branch).toBe('feature/vm');
    const raw = JSON.stringify(response.json);
    for (const forbidden of ['internal-owner', '/host/jobs', 'chm-vm-secret', 'uuid-secret', 'owner@example.com']) {
      expect(raw, forbidden).not.toContain(forbidden);
    }
  });

  it('maps VM_CAPABILITY_UNSUPPORTED to a sanitized 400 without runner detail', async () => {
    const response = await send(`/api/v1/workspaces/${workspaceId}/skills`);
    expect(response.status).toBe(400);
    expect(response.json.error).toBe('vm_capability_unsupported');
    expect(response.json.message).toContain('not supported');
    expect(response.text).not.toContain('supervisor detail must not leak');
  });
});

describe('VM error mapping', () => {
  const cases: Array<[ErrorCode, number, string]> = [
    ['VM_BACKEND_DISABLED', 503, 'vm_backend_disabled'],
    ['VM_CAPABILITY_UNSUPPORTED', 400, 'vm_capability_unsupported'],
    ['VM_QUOTA_EXCEEDED', 429, 'vm_quota_exceeded'],
    ['VM_UNKNOWN_STATE', 503, 'vm_unknown_state'],
    ['VM_GENERATION_MISMATCH', 409, 'vm_generation_mismatch'],
    ['VM_ATTESTATION_FAILED', 503, 'vm_attestation_failed'],
    ['VM_SUPERVISOR_UNAVAILABLE', 503, 'vm_supervisor_unavailable'],
    ['VM_IDENTITY_MISMATCH', 409, 'vm_identity_mismatch']
  ];
  for (const [code, status, error] of cases) {
    it(`maps ${code} to HTTP ${status} with a sanitized message`, async () => {
      const original = runner.call;
      runner.call = vi.fn(async (operation: RunnerOperation, input: Record<string, unknown>): Promise<RunnerResponse> => {
        if (operation === 'skills_list') {
          return { ok: false, message: 'refused', truncated: false, error: { code, message: `runner detail for ${code}`, retryable: code === 'VM_UNKNOWN_STATE' || code === 'VM_SUPERVISOR_UNAVAILABLE' } };
        }
        return original(operation, input, principal);
      }) as DashboardRunnerClient['call'];
      const response = await send(`/api/v1/workspaces/${workspaceId}/skills`);
      expect(response.status).toBe(status);
      expect(response.json.error).toBe(error);
      expect(response.json.message).toBeTruthy();
      expect(response.text).not.toContain(`runner detail for ${code}`);
    });
  }
});

describe('cleanWorkspace backend sanitization', () => {
  it('drops malformed backend blocks instead of repairing them', () => {
    const hostile = {
      executionBackend: 'incus-vm',
      backend: { kind: 'incus-vm', templateId: 'tpl', capabilities: { ...VM_CAPABILITIES, exec: 'maybe', 'evil-key': 'supported' }, extra: 'field' },
      generation: 4
    };
    const clean = mapDashboardData('workspace_status', { workspaceId, status: 'ACTIVE', ...hostile });
    expect(clean.executionBackend).toBe('incus-vm');
    // 'maybe' is outside the capability vocabulary: the strict record fails and the whole block drops.
    expect(clean.backend).toBeUndefined();
  });

  it('drops an unknown backend kind entirely', () => {
    const clean = mapDashboardData('workspace_status', { workspaceId, status: 'ACTIVE', executionBackend: 'gvisor', backend: { kind: 'gvisor', capabilities: {} } });
    expect(clean.executionBackend).toBeUndefined();
    expect(clean.backend).toBeUndefined();
  });
});

describe('mergeWorkspaceBackend', () => {
  it('overlays only validated backend fields from a successful status read', () => {
    const detail: RunnerResponse = { ok: true, message: 'detail', truncated: false, data: { workspaceId, status: 'ACTIVE', generation: 3 } };
    const status: RunnerResponse = { ok: true, message: 'status', truncated: false, data: { executionBackend: 'incus-vm', backend: VM_BACKEND, status: 'CLOSED', workspacePath: '/host/secret' } };
    const merged = mergeWorkspaceBackend(detail, status);
    expect(merged.data).toMatchObject({ workspaceId, status: 'ACTIVE', generation: 3, executionBackend: 'incus-vm' });
    expect((merged.data as Record<string, unknown>).backend).toBeDefined();
    expect(JSON.stringify(merged)).not.toContain('/host/secret');
  });

  it('returns detail untouched on failed or backend-less status', () => {
    const detail: RunnerResponse = { ok: true, message: 'detail', truncated: false, data: { workspaceId } };
    expect(mergeWorkspaceBackend(detail, { ok: false, message: 'no', truncated: false, error: { code: 'NOT_FOUND', message: 'x', retryable: false } })).toBe(detail);
    expect(mergeWorkspaceBackend(detail, undefined)).toBe(detail);
    expect(mergeWorkspaceBackend(detail, { ok: true, message: 's', truncated: false, data: {} })).toBe(detail);
  });
});
