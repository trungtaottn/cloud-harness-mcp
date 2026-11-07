import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { HarnessError, type BackendCapabilityMap, type RunnerConfig } from '@cloud-harness/contracts';
import { StateStore, type WorkspaceRecord } from '../src/state-store.js';
import type { ExecutorBackend, ExecutorRef, ProvisionContext, StreamHandle, ExecResult } from '../src/executor-backend.js';
import type { GitDataPlane } from '../src/git-data-plane.js';
import { IncusExecutorBackend, type VmSupervisorGateway } from '../src/incus-executor-backend.js';
import { VmSupervisorCallError } from '../src/vm-supervisor-client.js';
import { createVmLeaseSync } from '../src/backend-factory.js';
import type * as GitHubAppBroker from '../src/github-app-broker.js';

const docker = vi.hoisted(() => ({
  runDocker: vi.fn(async (args: string[]) => {
    if (args[0] === 'create') return { stdout: 'container-created\n', stderr: '', exitCode: 0, truncated: false };
    if (args[0] === 'start') return { stdout: 'container-started\n', stderr: '', exitCode: 0, truncated: false };
    if (args.includes('/opt/harness/worker-runner.sh')) {
      return { stdout: JSON.stringify({ ok: true, message: 'worker complete', data: {}, truncated: false }), stderr: '', exitCode: 0, truncated: false };
    }
    if (args.includes('/usr/bin/du')) return { stdout: '0\t/workspace\n', stderr: '', exitCode: 0, truncated: false };
    return { stdout: '', stderr: '', exitCode: 0, truncated: false };
  }),
  removeContainer: vi.fn(async () => undefined),
  inspectContainer: vi.fn(async () => undefined),
  terminateContainerProcessGroup: vi.fn(async () => undefined),
  spawnDocker: vi.fn(() => ({
    stdout: { on: vi.fn() },
    stderr: { on: vi.fn() },
    stdin: { write: vi.fn(), end: vi.fn() },
    on: vi.fn(),
    kill: vi.fn()
  }))
}));

vi.mock('../src/docker-engine.js', () => docker);
vi.mock('../src/repository-policy.js', () => ({ validateRepositoryUrl: vi.fn(async (value: string) => new URL(value)) }));
vi.mock('../src/github-app-broker.js', async (importOriginal) => ({
  ...(await importOriginal<typeof GitHubAppBroker>()),
  mintRepositoryToken: vi.fn(async () => 'mock-token'),
  mintPrincipalRepositoryScopedToken: vi.fn(async () => ({ token: 'mock-token', permissions: {} })),
  mintPrincipalRepositoryToken: vi.fn(async () => 'mock-token')
}));

import { computeWorkspaceOpenFingerprint, WorkspaceService, type WorkspaceBackendFactory } from '../src/workspace-service.js';
import { mintPrincipalRepositoryScopedToken } from '../src/github-app-broker.js';

const temporaryDirectories: string[] = [];
const openStores: StateStore[] = [];
const OWNER = 'owner-1';

const ALL_SUPPORTED: BackendCapabilityMap = Object.fromEntries([
  'exec', 'files', 'search', 'symbols', 'context', 'git-local', 'git-remote', 'git-broker',
  'shells', 'sessions', 'tasks', 'terminal', 'artifacts', 'skills', 'toolkits-owner',
  'toolkits-workspace', 'packages-bind', 'agents', 'secrets', 'deployments', 'worktrees',
  'recovery', 'pty', 'dashboard-repo-skills'
].map((id) => [id, 'supported'])) as BackendCapabilityMap;

function makeConfig(directory: string): RunnerConfig {
  const jobsRoot = join(directory, 'jobs');
  mkdirSync(jobsRoot, { recursive: true });
  return {
    jobsRoot,
    stateDb: join(directory, 'state.db'),
    wallTtlSeconds: 900,
    idleTtlSeconds: 300,
    maxOutputBytes: 262144,
    maxWorkspaceBytes: 104857600,
    minFreeBytes: 0,
    networkProfile: 'network-none',
    allowedGitHosts: ['github.com'],
    executorImage: 'cloud-harness-executor:test',
    vmTemplateId: 'chm-vm-template-test',
    vmTemplateDigest: 'a'.repeat(64),
    vmBackendEnabled: true
  } as RunnerConfig;
}

function fixture(factory?: WorkspaceBackendFactory) {
  const directory = mkdtempSync(join(tmpdir(), 'ch-backend-migration-'));
  temporaryDirectories.push(directory);
  const config = makeConfig(directory);
  const store = new StateStore(config.stateDb);
  openStores.push(store);
  const service = new WorkspaceService(config, store, undefined, undefined, undefined, undefined, undefined, factory);
  // workspaces are stored under the resolved principal id, not the raw owner string
  const ownerId = store.resolvePrincipal({ kind: 'owner', ownerId: OWNER });
  return { config, store, service, ownerId };
}

function openInput(extra: Record<string, unknown> = {}) {
  return {
    repositoryUrl: 'https://github.com/acme/widgets.git',
    ref: 'main',
    idempotencyKey: `ik-${Math.random().toString(36).slice(2)}`,
    ...extra
  };
}

type VmCalls = {
  provision: ProvisionContext[];
  exec: Array<{ ctx: ProvisionContext; req: unknown }>;
  destroyed: number;
  stopped: number;
  ensureActive: number;
  offlineExports: Array<{ ctx: ProvisionContext; opts: { maxBytes: number; cloneRef?: string } }>;
};

type OfflineExportResult = {
  verdict: 'clean' | 'retain' | 'unknown';
  uncommittedPaths?: number;
  stashes?: number;
  unpushedCommits?: number;
  reason?: string;
  workDir?: string;
  checkoutDir?: string;
};

/** Minimal fake Incus backend: records every verb, returns deterministic refs. */
function fakeVmBackend(
  calls: VmCalls,
  capabilities: BackendCapabilityMap = ALL_SUPPORTED,
  offlineExport?: (ctx: ProvisionContext, opts: { maxBytes: number; cloneRef?: string }) => Promise<OfflineExportResult>,
  gitExtras?: Record<string, unknown>
) {
  const ref = (ctx: ProvisionContext): ExecutorRef => ({
    backend: 'incus-vm', workspaceId: ctx.record.id, executorId: ctx.record.vmName!,
    generation: ctx.record.generation, instanceId: ctx.record.backendInstanceId!
  });
  const backend: ExecutorBackend = {
    kind: 'incus-vm',
    capabilities: () => capabilities,
    provision: vi.fn(async (ctx: ProvisionContext) => { calls.provision.push(ctx); return ref(ctx); }),
    ensureActive: vi.fn(async (ctx: ProvisionContext) => { calls.ensureActive += 1; return ref(ctx); }),
    exec: vi.fn(async (ctx: ProvisionContext, req: unknown): Promise<ExecResult> => {
      calls.exec.push({ ctx, req });
      return { exitCode: 0, signal: null, stdout: '{}', stderr: '', truncated: false, timedOut: false };
    }),
    spawnStream: vi.fn(async (): Promise<StreamHandle> => { throw new HarnessError('UNAVAILABLE', 'fake stream', 503, true); }),
    pty: vi.fn(() => { throw new HarnessError('UNAVAILABLE', 'no pty', 503, true); }),
    pullFile: vi.fn(async () => Buffer.alloc(0)),
    pushTree: vi.fn(async () => ({ sha256: '0'.repeat(64), bytes: 0, entryCount: 0 })),
    pullTree: vi.fn(async () => ({ sha256: '0'.repeat(64), bytes: 0, entryCount: 0 })),
    measureWorkspaceBytes: vi.fn(async () => 0),
    killProcessGroup: vi.fn(async () => undefined),
    stop: vi.fn(async () => { calls.stopped += 1; }),
    destroy: vi.fn(async () => { calls.destroyed += 1; }),
    inspect: vi.fn(async () => ({ state: 'missing' as const }))
  };
  const git: GitDataPlane & { exportCheckoutOffline?: (ctx: ProvisionContext, opts: { maxBytes: number; cloneRef?: string }) => Promise<unknown> } = {
    backend: 'incus-vm',
    seedCheckout: vi.fn(async () => undefined),
    exportObjects: vi.fn(async () => ({ sha256: '0'.repeat(64), bytes: 0 })),
    importObjects: vi.fn(async () => undefined),
    guestGit: vi.fn(async () => ({ exitCode: 0, signal: null, stdout: 'main\n', stderr: '', truncated: false, timedOut: false })),
    stagingDir: (ctx: ProvisionContext) => ctx.stagingDir,
    ...(offlineExport
      ? { exportCheckoutOffline: vi.fn(async (ctx: ProvisionContext, opts: { maxBytes: number; cloneRef?: string }) => {
          calls.offlineExports.push({ ctx, opts });
          return await offlineExport(ctx, opts);
        }) }
      : {}),
    ...(gitExtras ?? {})
  };
  return { backend, git };
}

function vmFactory(stack: { backend: ExecutorBackend; git: GitDataPlane }): WorkspaceBackendFactory {
  return (kind) => {
    if (kind === 'incus-vm') return stack;
    throw new HarnessError('VM_BACKEND_DISABLED', 'docker backend not registered in this test', 503, false);
  };
}

afterEach(() => {
  vi.clearAllMocks();
  for (const store of openStores.splice(0)) { try { store.close(); } catch { /* closed */ } }
  for (const path of temporaryDirectories.splice(0)) { try { rmSync(path, { recursive: true, force: true }); } catch { /* gone */ } }
});

describe('computeWorkspaceOpenFingerprint backend discrimination', () => {
  const base = { repositoryUrl: 'https://github.com/a/b.git', ref: 'main' };
  it('omitted and explicit docker produce the historical identical fingerprint', () => {
    expect(computeWorkspaceOpenFingerprint({ ...base, executionBackend: 'docker' }))
      .toBe(computeWorkspaceOpenFingerprint(base));
  });
  it('incus-vm adds the discriminator and differs from docker', () => {
    expect(computeWorkspaceOpenFingerprint({ ...base, executionBackend: 'incus-vm' }))
      .not.toBe(computeWorkspaceOpenFingerprint(base));
  });
});

describe('backend selection at workspace_open', () => {
  it('rejects incus-vm with VM_BACKEND_DISABLED when no backend is registered', async () => {
    const { service, ownerId } = fixture();
    await expect(service.execute(ownerId, 'workspace_open', openInput({ executionBackend: 'incus-vm' })))
      .rejects.toMatchObject({ code: 'VM_BACKEND_DISABLED' });
  });

  it('keeps docker as default and reports the docker capability surface', async () => {
    const { service, store, ownerId } = fixture();
    const response = await service.execute(ownerId, 'workspace_open', openInput());
    expect(response.ok).toBe(true);
    const record = store.list(ownerId)[0]!;
    expect(record.backendKind ?? 'docker').toBe('docker');
    expect(record.vmName ?? null).toBeNull();
    expect(record.backendInstanceId ?? null).toBeNull();
    const createCall = docker.runDocker.mock.calls.find((c) => c[0][0] === 'create');
    expect(createCall).toBeDefined();
    const caps = await service.execute(ownerId, 'workspace_capabilities', { workspaceId: record.id });
    const data = caps.data as Record<string, unknown>;
    expect(data.executionBackend).toBe('docker');
    expect((data.backend as { kind?: string }).kind).toBe('docker');
  });

  it('persists immutable VM identity at admission and routes provision through the injected backend', async () => {
    const calls: VmCalls = { provision: [], exec: [], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] };
    const stack = fakeVmBackend(calls);
    const { service, store, ownerId } = fixture(vmFactory(stack));
    const response = await service.execute(ownerId, 'workspace_open', openInput({ executionBackend: 'incus-vm' }));
    expect(response.ok).toBe(true);
    const record = store.list(ownerId)[0]!;
    expect(record.backendKind).toBe('incus-vm');
    expect(record.vmName).toMatch(/^chm-vm-[0-9a-f]{32}$/);
    expect(record.vmName).toBe(`chm-vm-${createHash('sha256').update(record.id).digest('hex').slice(0, 32)}`);
    expect(record.backendInstanceId).toMatch(/^[0-9a-f-]{36}$/);
    expect(record.templateId).toBe('chm-vm-template-test');
    expect(record.templateDigest).toBe('a'.repeat(64));
    expect(record.containerName).toBe(record.vmName);
    expect(calls.provision).toHaveLength(1);
    expect(calls.provision[0]!.record.id).toBe(record.id);
    expect(calls.provision[0]!.stagingDir).toContain(record.workspacePath);
    // No docker executor container was created for the VM workspace.
    const createCalls = docker.runDocker.mock.calls.filter((c) => c[0][0] === 'create' && c[0].includes(`cloud-harness.workspace=${record.id}`));
    expect(createCalls).toHaveLength(0);
  });
});

describe('executor verb routing', () => {
  it('routes exec_run through backend.exec with the worker-runner argv and empty env override', async () => {
    const { service, store, ownerId } = fixture();
    const opened = await service.execute(ownerId, 'workspace_open', openInput());
    expect(opened.ok).toBe(true);
    const record = store.list(ownerId)[0]!;
    const before = docker.runDocker.mock.calls.length;
    const response = await service.execute(ownerId, 'exec_run', { workspaceId: record.id, command: 'echo hi' });
    const execArgs = docker.runDocker.mock.calls.slice(before)
      .map((c) => c[0] as string[])
      .find((args) => args[0] === 'exec' && args.includes('/opt/harness/worker-runner.sh'));
    expect(execArgs).toBeDefined();
    expect(execArgs!.slice(0, 3)).toEqual(['exec', '-i', record.containerName]);
    expect(response.ok).toBe(true);
  });

  it('fails workspace operations with VM_CAPABILITY_UNSUPPORTED when the backend declares a capability unsupported', async () => {
    const calls: VmCalls = { provision: [], exec: [], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] };
    const stack = fakeVmBackend(calls, { ...ALL_SUPPORTED, exec: 'unsupported' });
    const { service, store, ownerId } = fixture(vmFactory(stack));
    const opened = await service.execute(ownerId, 'workspace_open', openInput({ executionBackend: 'incus-vm' }));
    expect(opened.ok).toBe(true);
    const record = store.list(ownerId)[0]!;
    // open()'s internal guidance scan may already have exec'd; the gate must
    // prevent the dispatched exec_run specifically.
    const execsBefore = calls.exec.length;
    await expect(service.execute(ownerId, 'exec_run', { workspaceId: record.id, command: 'echo hi' }))
      .rejects.toMatchObject({ code: 'VM_CAPABILITY_UNSUPPORTED' });
    expect(calls.exec).toHaveLength(execsBefore);
  });
});

describe('offline recovery export (phase-08 hook)', () => {
  type RecoveryService = {
    runRecoveryWorker: (record: WorkspaceRecord, operation: 'workspace_recover', input: Record<string, unknown>) => Promise<{ ok: boolean; data?: unknown }>;
  };

  it('routes close_check through exportCheckoutOffline and never starts the guest', async () => {
    const calls: VmCalls = { provision: [], exec: [], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] };
    const stack = fakeVmBackend(calls, ALL_SUPPORTED, async () => ({ verdict: 'clean' as const, uncommittedPaths: 0, stashes: 0, unpushedCommits: 0 }));
    const { service, store, ownerId } = fixture(vmFactory(stack));
    await service.execute(ownerId, 'workspace_open', openInput({ executionBackend: 'incus-vm' }));
    const record = store.list(ownerId)[0]!;
    const ensureActiveBefore = calls.ensureActive;
    const execsBefore = calls.exec.length;

    const result = await (service as unknown as RecoveryService)
      .runRecoveryWorker(record, 'workspace_recover', { mode: 'close_check', cloneRef: 'main' });

    expect(result.ok).toBe(true);
    expect(result.data).toMatchObject({ uncommittedPaths: 0, stashes: 0, unpushedCommits: 0, verdict: 'clean' });
    expect(calls.offlineExports).toHaveLength(1);
    expect(calls.offlineExports[0]!.opts.cloneRef).toBe('main');
    // The whole point of the offline path: no guest start, no guest exec.
    expect(calls.ensureActive).toBe(ensureActiveBefore);
    expect(calls.exec).toHaveLength(execsBefore);
  });

  it('returns a deferring result when offline inspection is unknown', async () => {
    const calls: VmCalls = { provision: [], exec: [], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] };
    const stack = fakeVmBackend(calls, ALL_SUPPORTED, async () => ({ verdict: 'unknown' as const, reason: 'export truncated' }));
    const { service, store, ownerId } = fixture(vmFactory(stack));
    await service.execute(ownerId, 'workspace_open', openInput({ executionBackend: 'incus-vm' }));
    const record = store.list(ownerId)[0]!;

    const result = await (service as unknown as RecoveryService)
      .runRecoveryWorker(record, 'workspace_recover', { mode: 'close_check' });

    expect(result.ok).toBe(false);
    expect(calls.ensureActive).toBe(0);
  });

  it('removes the exported staging dir on every close_check, including unknown verdicts', async () => {
    const calls: VmCalls = { provision: [], exec: [], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] };
    const removeOpDir = vi.fn(async () => undefined);
    const workDirs = ['/staging/vm-git-aaa', '/staging/vm-git-bbb'];
    let probe = 0;
    const stack = fakeVmBackend(calls, ALL_SUPPORTED, async () => {
      const workDir = workDirs[probe]!;
      probe += 1;
      // First probe is unknown (still must clean up); second is clean.
      return probe === 1
        ? { verdict: 'unknown' as const, reason: 'export truncated', workDir }
        : { verdict: 'clean' as const, uncommittedPaths: 0, stashes: 0, unpushedCommits: 0, workDir };
    }, { gitStaging: { removeOpDir } });
    const { service, store, ownerId } = fixture(vmFactory(stack));
    await service.execute(ownerId, 'workspace_open', openInput({ executionBackend: 'incus-vm' }));
    const record = store.list(ownerId)[0]!;

    // Repeated expiry sweeps must not accumulate extracted checkouts on the
    // host: every probe's staging dir is removed exactly once, whatever the
    // verdict, while the canonical VM data stays untouched in the guest.
    for (let i = 0; i < 2; i += 1) {
      await (service as unknown as RecoveryService)
        .runRecoveryWorker(record, 'workspace_recover', { mode: 'close_check' });
    }

    expect(removeOpDir).toHaveBeenCalledTimes(2);
    expect(removeOpDir).toHaveBeenNthCalledWith(1, '/staging/vm-git-aaa');
    expect(removeOpDir).toHaveBeenNthCalledWith(2, '/staging/vm-git-bbb');
    expect(calls.destroyed).toBe(0);
  });

  it('fails closed when the data plane has no offline export wired', async () => {
    const calls: VmCalls = { provision: [], exec: [], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] };
    const stack = fakeVmBackend(calls);
    const { service, store, ownerId } = fixture(vmFactory(stack));
    await service.execute(ownerId, 'workspace_open', openInput({ executionBackend: 'incus-vm' }));
    const record = store.list(ownerId)[0]!;

    await expect((service as unknown as RecoveryService)
      .runRecoveryWorker(record, 'workspace_recover', { mode: 'close_check' }))
      .rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(calls.ensureActive).toBe(0);
  });

  it('refuses guest recovery modes past the hard deadline without ensureActive', async () => {
    const calls: VmCalls = { provision: [], exec: [], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] };
    const stack = fakeVmBackend(calls, ALL_SUPPORTED, async () => ({ verdict: 'clean' as const, uncommittedPaths: 0, stashes: 0, unpushedCommits: 0 }));
    const { service, store, ownerId } = fixture(vmFactory(stack));
    await service.execute(ownerId, 'workspace_open', openInput({ executionBackend: 'incus-vm' }));
    const record = store.list(ownerId)[0]!;
    store.update(record.id, { hardExpiresAt: Date.now() - 1_000 });
    const expired = store.byId(record.id)!;
    // workspace_open's internal guidance scan may already have exec'd; the
    // hard-deadline guard must prevent any new exec/ensureActive.
    const execsBefore = calls.exec.length;
    const ensureActiveBefore = calls.ensureActive;

    await expect((service as unknown as RecoveryService)
      .runRecoveryWorker(expired, 'workspace_recover', { mode: 'status' }))
      .rejects.toMatchObject({ code: 'EXPIRED' });
    expect(calls.ensureActive).toBe(ensureActiveBefore);
    expect(calls.exec).toHaveLength(execsBefore);
    expect(calls.offlineExports).toHaveLength(0);
  });
});

describe('VM remote git transport routing (phase-08)', () => {
  type RemoteCalls = {
    fetch: Array<{ ctx: ProvisionContext; params: Record<string, unknown> }>;
    push: Array<{ ctx: ProvisionContext; params: Record<string, unknown> }>;
    probe: Array<{ ctx: ProvisionContext; params: Record<string, unknown> }>;
  };

  function remoteStack(remoteImpls?: {
    fetch?: (ctx: ProvisionContext, params: Record<string, unknown>) => Promise<unknown>;
    push?: (ctx: ProvisionContext, params: Record<string, unknown>) => Promise<unknown>;
    probe?: (ctx: ProvisionContext, params: Record<string, unknown>) => Promise<unknown>;
  }) {
    const calls: VmCalls = { provision: [], exec: [], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] };
    const remote: RemoteCalls = { fetch: [], push: [], probe: [] };
    const helperResult = { exitCode: 0, signal: null, stdout: 'remote: ok\n', stderr: '', truncated: false, timedOut: false };
    const stack = fakeVmBackend(calls, ALL_SUPPORTED, undefined, {
      remoteFetch: vi.fn(async (ctx: ProvisionContext, params: Record<string, unknown>) => {
        remote.fetch.push({ ctx, params });
        return remoteImpls?.fetch ? remoteImpls.fetch(ctx, params) : { fetched: helperResult, imported: helperResult };
      }),
      remotePush: vi.fn(async (ctx: ProvisionContext, params: Record<string, unknown>) => {
        remote.push.push({ ctx, params });
        return remoteImpls?.push ? remoteImpls.push(ctx, params) : { exitCode: 0, stdout: 'remote: ok\n', stderr: '', truncated: false };
      }),
      probeRemoteRefOid: vi.fn(async (ctx: ProvisionContext, params: Record<string, unknown>) => {
        remote.probe.push({ ctx, params });
        return remoteImpls?.probe ? remoteImpls.probe(ctx, params) : 'a'.repeat(40);
      })
    });
    return { stack, calls, remote };
  }

  const dockerTransferHelpers = (since: number) =>
    docker.runDocker.mock.calls.slice(since)
      .map((c) => c[0] as string[])
      .filter((args) => args.some((arg) => arg.includes('git-transfer-helper') || arg.includes('chm-git-')));

  it('git_fetch routes through plane.remoteFetch with the validated URL and read token', async () => {
    const { stack, remote } = remoteStack();
    const { service, store, ownerId } = fixture(vmFactory(stack));
    await service.execute(ownerId, 'workspace_open', openInput({ executionBackend: 'incus-vm' }));
    const record = store.list(ownerId)[0]!;
    const dockerCallsBefore = docker.runDocker.mock.calls.length;

    const response = await service.execute(ownerId, 'git_fetch', { workspaceId: record.id, refspec: 'refs/heads/main' });

    expect(response.ok).toBe(true);
    expect(remote.fetch).toHaveLength(1);
    expect(remote.fetch[0]!.params).toMatchObject({
      repositoryUrl: 'https://github.com/acme/widgets.git',
      remoteRef: 'refs/heads/main',
      token: 'mock-token'
    });
    expect(dockerTransferHelpers(dockerCallsBefore)).toHaveLength(0);
  });

  it('git_push routes through plane.remotePush with refspec, lease, and write token', async () => {
    const { stack, remote } = remoteStack();
    const { service, store, ownerId } = fixture(vmFactory(stack));
    await service.execute(ownerId, 'workspace_open', openInput({ executionBackend: 'incus-vm' }));
    const record = store.list(ownerId)[0]!;
    const dockerCallsBefore = docker.runDocker.mock.calls.length;

    const response = await service.execute(ownerId, 'git_push', {
      workspaceId: record.id,
      refspec: 'HEAD:refs/heads/feature',
      forceWithLease: true,
      expectedRemoteOid: 'b'.repeat(40)
    });

    expect(response.ok).toBe(true);
    expect(remote.push).toHaveLength(1);
    expect(remote.push[0]!.params).toMatchObject({
      repositoryUrl: 'https://github.com/acme/widgets.git',
      refspec: 'HEAD:refs/heads/feature',
      expectedRemoteOid: 'b'.repeat(40),
      token: 'mock-token'
    });
    expect(dockerTransferHelpers(dockerCallsBefore)).toHaveLength(0);
  });

  it('probeRemoteRefOid returns the transport OID and maps failures to undefined', async () => {
    const { stack, remote } = remoteStack();
    const { service, store, ownerId } = fixture(vmFactory(stack));
    await service.execute(ownerId, 'workspace_open', openInput({ executionBackend: 'incus-vm' }));
    const record = store.list(ownerId)[0]!;
    const probe = (service as unknown as {
      probeRemoteRefOid: (record: WorkspaceRecord, branch: string, token?: string) => Promise<string | null | undefined>;
    }).probeRemoteRefOid.bind(service);

    await expect(probe(record, 'main', 'tok')).resolves.toBe('a'.repeat(40));
    expect(remote.probe[0]!.params).toMatchObject({
      repositoryUrl: 'https://github.com/acme/widgets.git',
      branch: 'main',
      token: 'tok'
    });

    const failing = remoteStack({ probe: async () => { throw new Error('wire down'); } });
    const other = fixture(vmFactory(failing.stack));
    await other.service.execute(other.ownerId, 'workspace_open', openInput({ executionBackend: 'incus-vm' }));
    const otherRecord = other.store.list(other.ownerId)[0]!;
    const otherProbe = (other.service as unknown as {
      probeRemoteRefOid: (record: WorkspaceRecord, branch: string, token?: string) => Promise<string | null | undefined>;
    }).probeRemoteRefOid.bind(other.service);
    await expect(otherProbe(otherRecord, 'main')).resolves.toBeUndefined();
  });

  it('fails closed with VM_CAPABILITY_UNSUPPORTED when the plane lacks remote ops', async () => {
    const calls: VmCalls = { provision: [], exec: [], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] };
    const stack = fakeVmBackend(calls);
    const { service, store, ownerId } = fixture(vmFactory(stack));
    await service.execute(ownerId, 'workspace_open', openInput({ executionBackend: 'incus-vm' }));
    const record = store.list(ownerId)[0]!;

    await expect(service.execute(ownerId, 'git_fetch', { workspaceId: record.id, refspec: 'refs/heads/main' }))
      .rejects.toMatchObject({ code: 'VM_CAPABILITY_UNSUPPORTED' });
    await expect(service.execute(ownerId, 'git_push', { workspaceId: record.id, refspec: 'HEAD:refs/heads/x' }))
      .rejects.toMatchObject({ code: 'VM_CAPABILITY_UNSUPPORTED' });
  });
});

describe('hard-expired VM export (offline vm.export)', () => {
  it('exports through exportCheckoutOffline + host staging with zero guest calls', async () => {
    const calls: VmCalls = { provision: [], exec: [], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] };
    const workDir = mkdtempSync(join(tmpdir(), 'ch-vm-export-'));
    temporaryDirectories.push(workDir);
    const checkoutDir = join(workDir, 'extract', 'repo');
    mkdirSync(checkoutDir, { recursive: true });
    const stagingCalls = {
      git: [] as Array<{ mountDir: string; args: string[]; opts: Record<string, unknown> }>,
      stagePushBare: [] as Array<{ opDir: string; bundleName: string }>,
      pushBare: [] as Array<{ opDir: string; params: Record<string, unknown> }>,
      removeOpDir: [] as string[]
    };
    const ok = (stdout = '') => ({ exitCode: 0, signal: null, stdout, stderr: '', truncated: false, timedOut: false });
    const staging = {
      git: vi.fn(async (mountDir: string, args: string[], opts: Record<string, unknown>) => {
        stagingCalls.git.push({ mountDir, args, opts });
        const sub = args.slice(2).join(' ');
        if (sub.startsWith('branch --show-current')) return ok('feature-x\n');
        if (sub.includes('status --porcelain')) return ok(' M dirty.txt\n');
        if (sub.startsWith('add ') || sub.startsWith('commit ')) return ok('');
        if (sub.startsWith('rev-parse HEAD')) return ok(`${'f'.repeat(40)}\n`);
        if (sub.startsWith('bundle create')) {
          writeFileSync(join(mountDir, 'push.bundle'), 'bundle-bytes');
          return ok('');
        }
        return ok('');
      }),
      stagePushBare: vi.fn(async (opDir: string, bundleName: string) => { stagingCalls.stagePushBare.push({ opDir, bundleName }); }),
      pushBare: vi.fn(async (opDir: string, params: Record<string, unknown>) => {
        stagingCalls.pushBare.push({ opDir, params });
        return { exitCode: 0, signal: null, stdout: 'remote: ok\n', stderr: '', truncated: false };
      }),
      removeOpDir: vi.fn(async (opDir: string) => { stagingCalls.removeOpDir.push(opDir); })
    };
    const stack = fakeVmBackend(calls, ALL_SUPPORTED, async () => ({
      verdict: 'clean' as const,
      uncommittedPaths: 0,
      stashes: 0,
      unpushedCommits: 0,
      workDir,
      checkoutDir
    }), { gitStaging: staging });
    const { service, store, ownerId } = fixture(vmFactory(stack));
    await service.execute(ownerId, 'workspace_open', openInput({ executionBackend: 'incus-vm' }));
    const record = store.list(ownerId)[0]!;
    store.update(record.id, {
      status: 'EXPIRED_RECOVERABLE',
      expiresAt: Date.now() - 1_000,
      hardExpiresAt: Date.now() - 1_000,
      recoverableUntil: Date.now() + 3_600_000
    });
    const guestGitMock = stack.git.guestGit as ReturnType<typeof vi.fn>;
    const ensureActiveBefore = calls.ensureActive;
    const execsBefore = calls.exec.length;
    const guestGitBefore = guestGitMock.mock.calls.length;
    const stoppedBefore = calls.stopped;

    const response = await service.execute(ownerId, 'workspace_recover', { workspaceId: record.id, mode: 'export' });

    expect(response.ok).toBe(true);
    const data = response.data as Record<string, unknown>;
    expect(data.branch).toBe('feature-x');
    expect(data.commitSha).toBe('f'.repeat(40));
    expect(data.committedChanges).toBe(true);
    // Branch came from the exported data via the staging helper — never the guest.
    expect(stagingCalls.git[0]!.args.slice(0, 2)).toEqual(['-C', expect.stringContaining('/job/')]);
    expect(stagingCalls.git.map((c) => c.args.slice(2).join(' '))).toEqual(expect.arrayContaining([
      expect.stringContaining('branch --show-current'),
      expect.stringContaining('status --porcelain'),
      expect.stringContaining('bundle create')
    ]));
    expect(stagingCalls.stagePushBare).toHaveLength(1);
    expect(stagingCalls.stagePushBare[0]!.bundleName).toBe('push.bundle');
    expect(stagingCalls.pushBare).toHaveLength(1);
    expect(stagingCalls.pushBare[0]!.params).toMatchObject({
      repositoryUrl: 'https://github.com/acme/widgets.git',
      refspec: 'HEAD:refs/heads/feature-x',
      token: 'mock-token'
    });
    expect(stagingCalls.removeOpDir).toEqual([workDir]);
    // The hard contract: zero guest interaction after cutoff — no ensureActive,
    // no exec, no guestGit/currentBranch/probe. Only the lifecycle stop ran.
    expect(calls.ensureActive).toBe(ensureActiveBefore);
    expect(calls.exec).toHaveLength(execsBefore);
    expect(guestGitMock.mock.calls.length).toBe(guestGitBefore);
    expect(calls.stopped).toBe(stoppedBefore + 1);
    expect(calls.offlineExports).toHaveLength(1);
    expect(calls.offlineExports[0]!.opts.cloneRef).toBe('main');
  });

  it('honors an explicit targetBranch over the exported branch', async () => {
    const calls: VmCalls = { provision: [], exec: [], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] };
    const workDir = mkdtempSync(join(tmpdir(), 'ch-vm-export-'));
    temporaryDirectories.push(workDir);
    const checkoutDir = join(workDir, 'extract', 'repo');
    mkdirSync(checkoutDir, { recursive: true });
    const staging = {
      git: vi.fn(async (mountDir: string, args: string[]) => {
        const sub = args.slice(2).join(' ');
        const ok = (stdout = '') => ({ exitCode: 0, signal: null, stdout, stderr: '', truncated: false, timedOut: false });
        if (sub.startsWith('branch --show-current')) return ok('detached-head\n');
        if (sub.startsWith('rev-parse HEAD')) return ok(`${'e'.repeat(40)}\n`);
        if (sub.startsWith('bundle create')) { writeFileSync(join(mountDir, 'push.bundle'), 'b'); return ok(''); }
        return ok('');
      }),
      stagePushBare: vi.fn(async () => undefined),
      pushBare: vi.fn(async () => ({ exitCode: 0, signal: null, stdout: '', stderr: '', truncated: false })),
      removeOpDir: vi.fn(async () => undefined)
    };
    const stack = fakeVmBackend(calls, ALL_SUPPORTED, async () => ({
      verdict: 'clean' as const, workDir, checkoutDir
    }), { gitStaging: staging });
    const { service, store, ownerId } = fixture(vmFactory(stack));
    await service.execute(ownerId, 'workspace_open', openInput({ executionBackend: 'incus-vm' }));
    const record = store.list(ownerId)[0]!;
    store.update(record.id, {
      status: 'EXPIRED_RECOVERABLE',
      expiresAt: Date.now() - 1_000,
      hardExpiresAt: Date.now() - 1_000,
      recoverableUntil: Date.now() + 3_600_000
    });

    const response = await service.execute(ownerId, 'workspace_recover', {
      workspaceId: record.id,
      mode: 'export',
      targetBranch: 'recovery-snapshot'
    });

    expect(response.ok).toBe(true);
    expect((response.data as Record<string, unknown>).branch).toBe('recovery-snapshot');
    expect(staging.pushBare).toHaveBeenCalledWith(workDir, expect.objectContaining({
      refspec: 'HEAD:refs/heads/recovery-snapshot'
    }));
  });
});

describe('brokered GitHub actions on VM workspaces', () => {
  it('runs checkout-dependent actions through the host gh-helper, not the guest', async () => {
    const calls: VmCalls = { provision: [], exec: [], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] };
    const stack = fakeVmBackend(calls);
    const { service, store, ownerId } = fixture(vmFactory(stack));
    await service.execute(ownerId, 'workspace_open', openInput({ executionBackend: 'incus-vm' }));
    const record = store.list(ownerId)[0]!;
    vi.mocked(mintPrincipalRepositoryScopedToken).mockResolvedValueOnce({
      token: 'mock-token',
      permissions: { issues: 'read' }
    });
    const dockerCallsBefore = docker.runDocker.mock.calls.length;

    const response = await service.execute(ownerId, 'github_read', { workspaceId: record.id, action: 'issue_list' });

    expect(response.ok).toBe(true);
    const ghCall = docker.runDocker.mock.calls.slice(dockerCallsBefore)
      .map((c) => c[0] as string[])
      .find((args) => args.some((arg) => arg.includes('gh-helper.sh')));
    expect(ghCall).toBeDefined();
    // The checkout mount is the host staging clone, read-only — never guest state.
    expect(ghCall!.join(' ')).toContain(`${record.workspacePath}/repo:/workspace:ro`);
    // And the guest was never touched for the action.
    expect(calls.ensureActive).toBe(0);
  });
});

describe('H5 lease-gated recovery through the real IncusExecutorBackend', () => {
  type SupervisorCall = { op: string; detail: Record<string, unknown> };

  /** Seed a persisted incus-vm record directly — no open/provision needed. */
  function seedVmRecord(
    store: StateStore,
    ownerId: string,
    config: RunnerConfig,
    overrides: Partial<WorkspaceRecord> = {}
  ): WorkspaceRecord {
    const now = Date.now();
    const id = `ws_seed${Math.random().toString(36).slice(2).padEnd(30, '0')}`.slice(0, 40);
    const vmName = `chm-vm-${createHash('sha256').update(id).digest('hex').slice(0, 32)}`;
    const record: WorkspaceRecord = {
      id,
      ownerId,
      idempotencyKey: `ik-seed-${id}`,
      repositoryUrl: 'https://github.com/acme/widgets.git',
      repositoryRef: 'main',
      containerName: vmName,
      workspacePath: join(config.jobsRoot, id),
      environmentId: null,
      backendKind: 'incus-vm',
      vmName,
      backendInstanceId: '00000000-0000-4000-8000-000000000001',
      templateId: config.vmTemplateId ?? null,
      templateDigest: config.vmTemplateDigest ?? null,
      status: 'EXPIRED_RECOVERABLE',
      networkProfile: 'network-none',
      createdAt: now - 7_200_000,
      lastActivityAt: now - 3_600_000,
      expiresAt: now - 60_000,
      hardExpiresAt: now + 3_600_000,
      gitAuthorName: null,
      gitAuthorEmail: null,
      mutationLockedUntil: null,
      generation: 1,
      error: null,
      requestFingerprint: `fp-${id}`,
      idleTtlSeconds: 300,
      recoverableGraceSeconds: 3_600,
      expiredAt: now - 60_000,
      recoverableUntil: now + 1_800_000,
      ...overrides
    };
    store.admit(record, 100);
    return record;
  }

  /**
   * Real IncusExecutorBackend over a recording fake supervisor gateway. Only
   * the verbs the recovery path can reach are implemented; anything else
   * throws so an unexpected call fails the test loudly.
   */
  function realVmStack(
    config: RunnerConfig,
    record: WorkspaceRecord,
    calls: SupervisorCall[],
    overrides: {
      leaseClear?: () => Promise<unknown>;
      leaseSet?: () => Promise<unknown>;
      leaseSyncSet?: () => Promise<unknown>;
      leaseSyncClear?: () => Promise<unknown>;
    } = {}
  ) {
    const gateway = {
      leaseClear: vi.fn(async (ident: unknown, opts: unknown) => {
        calls.push({ op: 'leaseClear', detail: { ident, opts } });
        return overrides.leaseClear ? overrides.leaseClear() : {};
      }),
      leaseSet: vi.fn(async (ident: unknown, times: unknown, opts: unknown) => {
        calls.push({ op: 'leaseSet', detail: { ident, times, opts } });
        return overrides.leaseSet ? overrides.leaseSet() : {};
      }),
      vmStatus: vi.fn(async (ident: unknown, opts: unknown) => {
        calls.push({ op: 'vmStatus', detail: { ident, opts } });
        return {
          state: 'stopped',
          userCloudHarness: {
            workspaceId: record.id,
            instanceId: record.backendInstanceId,
            templateId: record.templateId,
            templateDigest: record.templateDigest
          }
        };
      }),
      vmStart: vi.fn(async (ident: unknown, params: unknown, opts: unknown) => {
        calls.push({ op: 'vmStart', detail: { ident, params, opts } });
        return { state: 'running' };
      })
    };
    const backend = new IncusExecutorBackend({
      client: gateway as unknown as VmSupervisorGateway,
      config,
      provisionAssets: async () => []
    });
    const git: GitDataPlane = {
      backend: 'incus-vm',
      seedCheckout: vi.fn(async () => undefined),
      exportObjects: vi.fn(async () => ({ sha256: '0'.repeat(64), bytes: 0 })),
      importObjects: vi.fn(async () => undefined),
      guestGit: vi.fn(async () => ({ exitCode: 0, signal: null, stdout: '', stderr: '', truncated: false, timedOut: false })),
      stagingDir: (ctx: ProvisionContext) => ctx.stagingDir
    };
    // The REAL lease-sync adapter over a tagged facade: service-driven lease
    // ops land in `calls` with via:'leaseSync' so tests can distinguish them
    // from the backend's own leaseClear/leaseSet channel.
    const leaseGateway = {
      leaseSet: vi.fn(async (ident: unknown, times: unknown, opts: unknown) => {
        calls.push({ op: 'leaseSet', detail: { ident, times, opts, via: 'leaseSync' } });
        return overrides.leaseSyncSet ? overrides.leaseSyncSet() : {};
      }),
      leaseClear: vi.fn(async (ident: unknown, opts: unknown) => {
        calls.push({ op: 'leaseClear', detail: { ident, opts, via: 'leaseSync' } });
        return overrides.leaseSyncClear ? overrides.leaseSyncClear() : {};
      })
    };
    return {
      backend,
      git,
      leaseSync: createVmLeaseSync(leaseGateway as unknown as VmSupervisorGateway)
    };
  }

  function deferredStack() {
    let stack: { backend: ExecutorBackend; git: GitDataPlane } | undefined;
    const factory = (kind: string) => {
      if (kind !== 'incus-vm' || stack === undefined) {
        throw new HarnessError('VM_BACKEND_DISABLED', 'incus-vm stack not wired in this test', 503, false);
      }
      return stack;
    };
    return {
      factory: factory as ConstructorParameters<typeof WorkspaceService>[7],
      setStack: (next: { backend: ExecutorBackend; git: GitDataPlane }) => { stack = next; }
    };
  }

  /** Standalone real leaseSync adapter over a recording facade (via:'leaseSync'). */
  function leaseSyncProbe(
    calls: SupervisorCall[],
    overrides: { set?: (times: { expiresAt: number; hardExpiresAt: number }) => Promise<unknown> } = {}
  ) {
    const gateway = {
      leaseSet: vi.fn(async (ident: unknown, times: unknown, opts: unknown) => {
        calls.push({ op: 'leaseSet', detail: { ident, times, opts, via: 'leaseSync' } });
        return overrides.set ? overrides.set(times as { expiresAt: number; hardExpiresAt: number }) : {};
      }),
      leaseClear: vi.fn(async (ident: unknown, opts: unknown) => {
        calls.push({ op: 'leaseClear', detail: { ident, opts, via: 'leaseSync' } });
        return {};
      })
    };
    return { leaseSync: createVmLeaseSync(gateway as unknown as VmSupervisorGateway), gateway };
  }

  function leaseSets(calls: SupervisorCall[]) {
    return calls.filter((c) => c.op === 'leaseSet' && c.detail.via === 'leaseSync');
  }

  function lastLeaseTimes(calls: SupervisorCall[]): { expiresAt: number; hardExpiresAt: number } {
    const sets = leaseSets(calls);
    expect(sets.length).toBeGreaterThan(0);
    return sets.at(-1)!.detail.times as { expiresAt: number; hardExpiresAt: number };
  }

  it('lease_renew on EXPIRED_RECOVERABLE re-establishes the supervisor lease BEFORE status/start, then activates', async () => {
    const deferred = deferredStack();
    const { service, store, config, ownerId } = fixture(deferred.factory);
    const record = seedVmRecord(store, ownerId, config, { recoverableUntil: Date.now() + 1_800_000 });
    const calls: SupervisorCall[] = [];
    const stack = realVmStack(config, record, calls);
    deferred.setStack(stack);
    service.leaseSync = stack.leaseSync;
    // Capture the caller-threaded recovery deadline the backend consumes.
    const seenLeaseExpiresAt: Array<number | undefined> = [];
    const origEnsure = stack.backend.ensureActive.bind(stack.backend);
    stack.backend.ensureActive = (async (ctx: ProvisionContext) => {
      seenLeaseExpiresAt.push(ctx.leaseExpiresAt);
      return origEnsure(ctx);
    }) as ExecutorBackend['ensureActive'];

    const response = await service.execute(ownerId, 'workspace_lease_renew', { workspaceId: record.id, extensionSeconds: 600 });

    expect(response.ok).toBe(true);
    // H5 ordering: the stale stored lease is cleared and re-set with recovery
    // times BEFORE any vm.status/vm.start — the request-time deadline cutoff
    // would otherwise refuse every workspace op. The service then pushes the
    // REQUESTED renewal expiry as the acknowledged final lease — the durable
    // deadline ends at newExpires, not the wider recoverable window.
    expect(calls.map((c) => `${c.detail.via ?? 'backend'}:${c.op}`))
      .toEqual(['backend:leaseClear', 'backend:leaseSet', 'backend:vmStatus', 'backend:vmStart', 'leaseSync:leaseSet']);
    const backendSet = calls.find((c) => c.op === 'leaseSet' && c.detail.via === undefined)!;
    const serviceSet = calls.find((c) => c.op === 'leaseSet' && c.detail.via === 'leaseSync')!;
    const serviceTimes = serviceSet.detail.times as { expiresAt: number; hardExpiresAt: number };
    // ctx.leaseExpiresAt landed: the backend's pre-start lease already carries
    // the REQUESTED renewal (~now+600s) — not the wider recoverable window —
    // so the VM never executes under a broader lease than acknowledged.
    expect(backendSet.detail.times).toEqual(serviceTimes);
    expect(serviceTimes.hardExpiresAt).toBe(record.hardExpiresAt);
    expect(serviceTimes.expiresAt).toBeGreaterThan(Date.now() + 500_000);
    expect(serviceTimes.expiresAt).toBeLessThan(Date.now() + 700_000);
    expect(serviceTimes.expiresAt).toBeLessThan(record.recoverableUntil!);
    // The intended bounded deadline reached the backend BEFORE vm.start via
    // ProvisionContext.leaseExpiresAt — identical to the published expiry.
    expect(seenLeaseExpiresAt).toEqual([serviceTimes.expiresAt]);
    const updated = store.byId(record.id)!;
    expect(updated.status).toBe('ACTIVE');
    expect(updated.expiresAt).toBe(serviceTimes.expiresAt);
    expect(updated.expiresAt).toBeLessThanOrEqual(record.hardExpiresAt);
    // Immutable identity is preserved through recovery.
    expect(updated.vmName).toBe(record.vmName);
    expect(updated.backendInstanceId).toBe(record.backendInstanceId);

    // A repeated renewal on the now-ACTIVE record takes the durable-before-store
    // path: the service pushes the renewed lease itself (pre-set + confirmed
    // final), the backend is not touched again.
    const countAfterFirst = calls.length;
    const second = await service.execute(ownerId, 'workspace_lease_renew', { workspaceId: record.id, extensionSeconds: 600 });
    expect(second.ok).toBe(true);
    const secondSets = calls.slice(countAfterFirst).filter((c) => c.op === 'leaseSet' && c.detail.via === 'leaseSync');
    expect(secondSets.length).toBeGreaterThanOrEqual(1);
    expect(calls.slice(countAfterFirst).filter((c) => c.detail.via === undefined)).toHaveLength(0);
    expect(store.byId(record.id)!.status).toBe('ACTIVE');
  });

  it('workspace_recover mode:resume takes the same lease-gated path', async () => {
    const deferred = deferredStack();
    const { service, store, config, ownerId } = fixture(deferred.factory);
    const record = seedVmRecord(store, ownerId, config);
    const calls: SupervisorCall[] = [];
    const stack = realVmStack(config, record, calls);
    deferred.setStack(stack);
    service.leaseSync = stack.leaseSync;

    const response = await service.execute(ownerId, 'workspace_recover', { workspaceId: record.id, mode: 'resume' });

    expect(response.ok).toBe(true);
    expect(calls.map((c) => `${c.detail.via ?? 'backend'}:${c.op}`))
      .toEqual(['backend:leaseClear', 'backend:leaseSet', 'backend:vmStatus', 'backend:vmStart', 'leaseSync:leaseSet']);
    expect(store.byId(record.id)!.status).toBe('ACTIVE');
  });

  it('hard-expired and closed-window records get zero guest/supervisor calls', async () => {
    const deferred = deferredStack();
    const { service, store, config, ownerId } = fixture(deferred.factory);
    const now = Date.now();
    const hardExpired = seedVmRecord(store, ownerId, config, {
      hardExpiresAt: now - 1_000,
      recoverableUntil: now + 1_800_000
    });
    const windowClosed = seedVmRecord(store, ownerId, config, {
      expiresAt: now - 120_000,
      recoverableUntil: now - 60_000,
      hardExpiresAt: now + 3_600_000
    });
    const calls: SupervisorCall[] = [];
    // One gateway serves both records; identity fields differ per record so
    // build the stack per record below via two gateways is overkill — the
    // assertions only need "no calls at all".
    const stack = realVmStack(config, hardExpired, calls);
    deferred.setStack(stack);
    service.leaseSync = stack.leaseSync;

    await expect(service.execute(ownerId, 'workspace_lease_renew', { workspaceId: hardExpired.id }))
      .rejects.toMatchObject({ code: 'EXPIRED' });
    await expect(service.execute(ownerId, 'workspace_recover', { workspaceId: hardExpired.id, mode: 'resume' }))
      .rejects.toMatchObject({ code: 'EXPIRED' });
    // Soft-expired but past recoverableUntil: the backend's assertNotExpired
    // refuses before recoverSupervisorLease — still zero BACKEND calls. The
    // service compensation may push the already-past expiry (fail-closed
    // bound on any still-running VM), never a live deadline.
    await expect(service.execute(ownerId, 'workspace_lease_renew', { workspaceId: windowClosed.id }))
      .rejects.toMatchObject({ code: 'EXPIRED' });
    expect(calls.filter((c) => c.detail.via === undefined)).toHaveLength(0);
    for (const set of leaseSets(calls)) {
      const t = set.detail.times as { expiresAt: number };
      expect(t.expiresAt).toBeLessThanOrEqual(Date.now());
    }
    expect(store.byId(hardExpired.id)!.status).toBe('EXPIRED_RECOVERABLE');
    expect(store.byId(windowClosed.id)!.status).toBe('EXPIRED_RECOVERABLE');
  });

  it('terminal records are rejected before any supervisor call', async () => {
    const deferred = deferredStack();
    const { service, store, config, ownerId } = fixture(deferred.factory);
    const closed = seedVmRecord(store, ownerId, config, { status: 'CLOSED' });
    const calls: SupervisorCall[] = [];
    deferred.setStack(realVmStack(config, closed, calls));

    await expect(service.execute(ownerId, 'workspace_lease_renew', { workspaceId: closed.id }))
      .rejects.toMatchObject({ code: 'EXPIRED' });
    expect(calls).toHaveLength(0);
    expect(store.byId(closed.id)!.status).toBe('CLOSED');
  });

  it('leaseClear failure fails closed: no status/start, record stays recoverable', async () => {
    const deferred = deferredStack();
    const { service, store, config, ownerId } = fixture(deferred.factory);
    const record = seedVmRecord(store, ownerId, config);
    const calls: SupervisorCall[] = [];
    deferred.setStack(realVmStack(config, record, calls, {
      leaseClear: async () => { throw new Error('supervisor unreachable'); }
    }));

    await expect(service.execute(ownerId, 'workspace_lease_renew', { workspaceId: record.id }))
      .rejects.toThrow('supervisor unreachable');
    expect(calls.map((c) => c.op)).toEqual(['leaseClear']);
    expect(store.byId(record.id)!.status).toBe('EXPIRED_RECOVERABLE');
  });

  it('leaseSet failure after a successful clear is equally fail-closed', async () => {
    const deferred = deferredStack();
    const { service, store, config, ownerId } = fixture(deferred.factory);
    const record = seedVmRecord(store, ownerId, config);
    const calls: SupervisorCall[] = [];
    deferred.setStack(realVmStack(config, record, calls, {
      leaseSet: async () => { throw new Error('lease write rejected'); }
    }));

    await expect(service.execute(ownerId, 'workspace_recover', { workspaceId: record.id, mode: 'resume' }))
      .rejects.toThrow('lease write rejected');
    expect(calls.map((c) => c.op)).toEqual(['leaseClear', 'leaseSet']);
    expect(store.byId(record.id)!.status).toBe('EXPIRED_RECOVERABLE');
  });

  it('leaseClear NOT_FOUND falls through to status (no stale lease to recover)', async () => {
    const deferred = deferredStack();
    const { service, store, config, ownerId } = fixture(deferred.factory);
    const record = seedVmRecord(store, ownerId, config);
    const calls: SupervisorCall[] = [];
    const stack = realVmStack(config, record, calls, {
      leaseClear: async () => {
        throw new VmSupervisorCallError('NOT_FOUND', 'no journal row', 404, false);
      }
    });
    deferred.setStack(stack);
    service.leaseSync = stack.leaseSync;

    const response = await service.execute(ownerId, 'workspace_lease_renew', { workspaceId: record.id });

    expect(response.ok).toBe(true);
    // NOT_FOUND on leaseClear means the supervisor journal has no lease row:
    // there is nothing stale to clear and no lease to re-set, so the backend
    // falls straight through to vm.status (which then drives adopt/provision).
    // The acknowledged publish still ends with the service's durable leaseSet.
    expect(calls.map((c) => `${c.detail.via ?? 'backend'}:${c.op}`))
      .toEqual(['backend:leaseClear', 'backend:vmStatus', 'backend:vmStart', 'leaseSync:leaseSet']);
    expect(store.byId(record.id)!.status).toBe('ACTIVE');
  });

  it('ACTIVE activity touches push each extended expiry to the durable lease', async () => {
    const deferred = deferredStack();
    const { service, store, config, ownerId } = fixture(deferred.factory);
    const now = Date.now();
    // ACTIVE with a short remaining lease: the next activity must cross the
    // old expiry and the durable supervisor lease must follow it.
    const record = seedVmRecord(store, ownerId, config, {
      status: 'ACTIVE',
      expiresAt: now + 60_000,
      expiredAt: null,
      recoverableUntil: null,
      lastActivityAt: now - 1_000
    });
    const calls: SupervisorCall[] = [];
    const stack = fakeVmBackend({ provision: [], exec: [], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] });
    (stack.backend.exec as ReturnType<typeof vi.fn>).mockImplementation(async () => ({
      exitCode: 0, signal: null,
      stdout: JSON.stringify({ ok: true, message: 'worker complete', data: {}, truncated: false }),
      stderr: '', truncated: false, timedOut: false
    }));
    deferred.setStack(stack);
    service.leaseSync = leaseSyncProbe(calls).leaseSync;

    const res = await service.execute(ownerId, 'exec_run', { workspaceId: record.id, command: 'echo hi' });
    expect(res.ok).toBe(true);
    const touched = store.byId(record.id)!;
    expect(touched.status).toBe('ACTIVE');
    expect(touched.expiresAt).toBeGreaterThan(now + 60_000);
    // The durable lease converges on exactly the store's acknowledged expiry.
    await vi.waitFor(() => {
      expect(lastLeaseTimes(calls).expiresAt).toBe(touched.expiresAt);
    });
    expect(lastLeaseTimes(calls).hardExpiresAt).toBe(record.hardExpiresAt);
  });

  it('repeated and concurrent touches serialize; durable ends at the newest store expiry', async () => {
    const deferred = deferredStack();
    const { service, store, config, ownerId } = fixture(deferred.factory);
    const now = Date.now();
    const record = seedVmRecord(store, ownerId, config, {
      status: 'ACTIVE',
      expiresAt: now + 60_000,
      expiredAt: null,
      recoverableUntil: null
    });
    const calls: SupervisorCall[] = [];
    const stack = fakeVmBackend({ provision: [], exec: [], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] });
    (stack.backend.exec as ReturnType<typeof vi.fn>).mockImplementation(async () => ({
      exitCode: 0, signal: null,
      stdout: JSON.stringify({ ok: true, message: 'worker complete', data: {}, truncated: false }),
      stderr: '', truncated: false, timedOut: false
    }));
    deferred.setStack(stack);
    service.leaseSync = leaseSyncProbe(calls).leaseSync;

    // Sequential activity: each touch extends and each extension is pushed.
    await service.execute(ownerId, 'exec_run', { workspaceId: record.id, command: 'one' });
    await new Promise((r) => setTimeout(r, 5));
    await service.execute(ownerId, 'exec_run', { workspaceId: record.id, command: 'two' });
    // Concurrent activity: touches race but the queue serializes the pushes.
    await Promise.all([
      service.execute(ownerId, 'exec_run', { workspaceId: record.id, command: 'a' }),
      service.execute(ownerId, 'exec_run', { workspaceId: record.id, command: 'b' }),
      service.execute(ownerId, 'exec_run', { workspaceId: record.id, command: 'c' })
    ]);

    const finalRecord = store.byId(record.id)!;
    await vi.waitFor(() => {
      const times = lastLeaseTimes(calls);
      expect(times.expiresAt).toBe(finalRecord.expiresAt);
    });
    // No pushed deadline ever exceeded the hard TTL.
    for (const set of leaseSets(calls)) {
      const t = set.detail.times as { expiresAt: number; hardExpiresAt: number };
      expect(t.expiresAt).toBeLessThanOrEqual(record.hardExpiresAt);
      expect(t.hardExpiresAt).toBe(record.hardExpiresAt);
    }
  });

  it('recoverable renew rolls back store+lease when the final durable sync fails', async () => {
    const deferred = deferredStack();
    const { service, store, config, ownerId } = fixture(deferred.factory);
    const record = seedVmRecord(store, ownerId, config, { recoverableUntil: Date.now() + 1_800_000 });
    const calls: SupervisorCall[] = [];
    const stack = realVmStack(config, record, calls, {
      leaseSyncSet: async () => { throw new Error('durable lease rejected'); }
    });
    deferred.setStack(stack);
    service.leaseSync = stack.leaseSync;

    await expect(service.execute(ownerId, 'workspace_lease_renew', { workspaceId: record.id, extensionSeconds: 600 }))
      .rejects.toThrow('durable lease rejected');

    // The backend activation ran (bounded by ctx.leaseExpiresAt), the store
    // published ACTIVE, then the strict final sync failed → full rollback:
    // status, expiry AND the recoverable window are restored exactly.
    expect(calls.filter((c) => c.detail.via === undefined).map((c) => c.op))
      .toEqual(['leaseClear', 'leaseSet', 'vmStatus', 'vmStart']);
    const after = store.byId(record.id)!;
    expect(after.status).toBe('EXPIRED_RECOVERABLE');
    expect(after.expiresAt).toBe(record.expiresAt);
    expect(after.recoverableUntil).toBe(record.recoverableUntil);
    expect(after.expiredAt).toBe(record.expiredAt);
    expect(after.error).toBe(record.error);
    // Compensation pushed the pre-transition (already-past) expiry best-effort;
    // it failed too and was swallowed — never masking the primary error.
    expect(leaseSets(calls).length).toBeGreaterThanOrEqual(2);
  });

  it('ACTIVE renew is durable-before-store: a lease failure publishes nothing', async () => {
    const deferred = deferredStack();
    const { service, store, config, ownerId } = fixture(deferred.factory);
    const now = Date.now();
    const record = seedVmRecord(store, ownerId, config, {
      status: 'ACTIVE',
      expiresAt: now + 600_000,
      expiredAt: null,
      recoverableUntil: null
    });
    const calls: SupervisorCall[] = [];
    deferred.setStack(fakeVmBackend({ provision: [], exec: [], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] }));
    service.leaseSync = leaseSyncProbe(calls, {
      set: async () => { throw new Error('durable lease rejected'); }
    }).leaseSync;

    await expect(service.execute(ownerId, 'workspace_lease_renew', { workspaceId: record.id, extensionSeconds: 600 }))
      .rejects.toThrow('durable lease rejected');

    // Store untouched: still ACTIVE with the OLD expiry — the renewed store
    // state was never published without its durable lease.
    const after = store.byId(record.id)!;
    expect(after.status).toBe('ACTIVE');
    expect(after.expiresAt).toBe(record.expiresAt);
    expect(leaseSets(calls)).toHaveLength(1);
  });

  it('renewal never exceeds hardExpiresAt even with an extreme extension request', async () => {
    const deferred = deferredStack();
    const { service, store, config, ownerId } = fixture(deferred.factory);
    const now = Date.now();
    const record = seedVmRecord(store, ownerId, config, {
      hardExpiresAt: now + 700_000,
      recoverableUntil: now + 1_800_000
    });
    const calls: SupervisorCall[] = [];
    const stack = realVmStack(config, record, calls);
    deferred.setStack(stack);
    service.leaseSync = stack.leaseSync;

    const response = await service.execute(ownerId, 'workspace_lease_renew', { workspaceId: record.id, extensionSeconds: 86_400 });

    expect(response.ok).toBe(true);
    const times = lastLeaseTimes(calls);
    // newExpires clamps to the hard TTL — the durable lease can never cross it.
    expect(times.expiresAt).toBe(record.hardExpiresAt);
    expect(times.hardExpiresAt).toBe(record.hardExpiresAt);
    expect(store.byId(record.id)!.expiresAt).toBe(record.hardExpiresAt);
  });

  it('a stale finally-touch never shortens a concurrent renewal in store or durable lease (M1)', async () => {
    const deferred = deferredStack();
    const { service, store, config, ownerId } = fixture(deferred.factory);
    const now = Date.now();
    const record = seedVmRecord(store, ownerId, config, {
      status: 'ACTIVE',
      expiresAt: now + 300_000,
      expiredAt: null,
      recoverableUntil: null,
      lastActivityAt: now - 1_000,
      hardExpiresAt: now + 28_800_000
    });
    const calls: SupervisorCall[] = [];
    const vmCalls = { provision: [] as unknown[], exec: [] as unknown[], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] as unknown[] };
    const stack = fakeVmBackend(vmCalls as never);
    // Hold the exec open so the record snapshot inside withMutationLease goes
    // stale while an explicit long renewal lands underneath it.
    let releaseExec!: () => void;
    const execGate = new Promise<void>((resolve) => { releaseExec = resolve; });
    (stack.backend.exec as ReturnType<typeof vi.fn>).mockImplementation(async (ctx: ProvisionContext, req: unknown) => {
      vmCalls.exec.push({ ctx, req });
      await execGate;
      return {
        exitCode: 0, signal: null,
        stdout: JSON.stringify({ ok: true, message: 'worker complete', data: {}, truncated: false }),
        stderr: '', truncated: false, timedOut: false
      };
    });
    deferred.setStack(stack);
    service.leaseSync = leaseSyncProbe(calls).leaseSync;

    const execPromise = service.execute(ownerId, 'exec_run', { workspaceId: record.id, command: 'sleep' });
    await vi.waitFor(() => { expect(vmCalls.exec).toHaveLength(1); });

    // Explicit long renewal while the mutation is in flight — the acknowledged
    // deadline jumps far beyond the idle TTL the stale touch would compute.
    const renew = await service.execute(ownerId, 'workspace_lease_renew', { workspaceId: record.id, extensionSeconds: 7200 });
    expect(renew.ok).toBe(true);
    const renewed = store.byId(record.id)!;
    expect(renewed.expiresAt).toBeGreaterThan(now + 3_600_000);

    releaseExec();
    await execPromise;

    // The finally touch re-reads the authoritative row: it can extend but
    // never shorten — store keeps the renewal and the durable lease mirrors it.
    const after = store.byId(record.id)!;
    expect(after.status).toBe('ACTIVE');
    expect(after.expiresAt).toBe(renewed.expiresAt);
    await vi.waitFor(() => {
      expect(lastLeaseTimes(calls).expiresAt).toBe(after.expiresAt);
    });
    expect(lastLeaseTimes(calls).hardExpiresAt).toBe(record.hardExpiresAt);
  });

  it('concurrent renew rollback never restores older times over a newer completed renewal (L2)', async () => {
    const deferred = deferredStack();
    const { service, store, config, ownerId } = fixture(deferred.factory);
    const now = Date.now();
    const record = seedVmRecord(store, ownerId, config, {
      status: 'ACTIVE',
      expiresAt: now + 120_000,
      expiredAt: null,
      recoverableUntil: null,
      hardExpiresAt: now + 28_800_000
    });
    const calls: SupervisorCall[] = [];
    deferred.setStack(fakeVmBackend({ provision: [], exec: [], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] }));
    // Fail only the SECOND push carrying the short renewal's intended expiry —
    // its durable pre-set succeeds, the post-publish confirmation fails, so
    // the transition must roll back. The long renewal's times never match.
    let shortSets = 0;
    service.leaseSync = leaseSyncProbe(calls, {
      set: async (times) => {
        if (times.expiresAt > now + 250_000 && times.expiresAt < now + 350_000) {
          shortSets += 1;
          if (shortSets >= 2) throw new Error('final sync rejected');
        }
        return {};
      }
    }).leaseSync;

    // Fire the long renewal first so the per-workspace lock runs it first;
    // the short renewal's entry snapshot was still read before the long
    // publish, so its rollback must re-read the pre-transition record inside
    // the lock — restoring the stale snapshot would clobber the new expiry.
    const [longResult, shortResult] = await Promise.allSettled([
      service.execute(ownerId, 'workspace_lease_renew', { workspaceId: record.id, extensionSeconds: 7200 }),
      service.execute(ownerId, 'workspace_lease_renew', { workspaceId: record.id, extensionSeconds: 300 })
    ]);

    // The short renewal always rolls back; the long one always succeeds.
    expect(longResult.status).toBe('fulfilled');
    expect(shortResult.status).toBe('rejected');
    expect((shortResult as PromiseRejectedResult).reason).toMatchObject({ message: 'final sync rejected' });

    // The failed rollback restored the NEWER pre-transition expiry (re-read
    // inside the lock), never the stale entry snapshot — store and durable
    // lease both end at the completed long renewal.
    const after = store.byId(record.id)!;
    expect(after.status).toBe('ACTIVE');
    expect(after.expiresAt).toBeGreaterThan(now + 3_600_000);
    expect(lastLeaseTimes(calls).expiresAt).toBe(after.expiresAt);
    for (const set of leaseSets(calls)) {
      const t = set.detail.times as { expiresAt: number; hardExpiresAt: number };
      expect(t.expiresAt).toBeLessThanOrEqual(after.hardExpiresAt);
      expect(t.hardExpiresAt).toBe(record.hardExpiresAt);
    }
  });

  it('high-frequency touches coalesce into bounded lease pushes that converge on the newest expiry', async () => {
    const deferred = deferredStack();
    const { service, store, config, ownerId } = fixture(deferred.factory);
    const now = Date.now();
    const record = seedVmRecord(store, ownerId, config, {
      status: 'ACTIVE',
      expiresAt: now + 300_000,
      expiredAt: null,
      recoverableUntil: null
    });
    const calls: SupervisorCall[] = [];
    const vmCalls = { provision: [] as unknown[], exec: [] as unknown[], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] as unknown[] };
    const stack = fakeVmBackend(vmCalls as never);
    (stack.backend.exec as ReturnType<typeof vi.fn>).mockImplementation(async (ctx: ProvisionContext, req: unknown) => {
      vmCalls.exec.push({ ctx, req });
      return {
        exitCode: 0, signal: null,
        stdout: JSON.stringify({ ok: true, message: 'worker complete', data: {}, truncated: false }),
        stderr: '', truncated: false, timedOut: false
      };
    });
    deferred.setStack(stack);
    // Block the FIRST durable push so every touch commits while it is in
    // flight — they must collapse into the single pending slot, not N queue
    // entries. Later pushes run free.
    let setCalls = 0;
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((resolve) => { releaseFirst = resolve; });
    service.leaseSync = leaseSyncProbe(calls, {
      set: async () => {
        setCalls += 1;
        if (setCalls === 1) await firstGate;
        return {};
      }
    }).leaseSync;

    const TOUCHES = 24;
    const execs = Array.from({ length: TOUCHES }, (_, i) =>
      service.execute(ownerId, 'exec_run', { workspaceId: record.id, command: `c${i}` })
    );
    // Every touch commits before its dispatch reaches the backend, so once all
    // executions settle the pending slot holds only the newest record while
    // the first durable push is still blocked.
    await Promise.allSettled(execs);
    releaseFirst();
    // Let the serialized queue drain completely.
    await vi.waitFor(() => {
      const finalRecord = store.byId(record.id)!;
      expect(lastLeaseTimes(calls).expiresAt).toBe(finalRecord.expiresAt);
    });

    // Coalescing: far fewer durable pushes than touches — the pending slot
    // keeps only the newest record per workspace.
    expect(leaseSets(calls).length).toBeLessThan(TOUCHES / 2);
    const finalRecord = store.byId(record.id)!;
    expect(lastLeaseTimes(calls).expiresAt).toBe(finalRecord.expiresAt);
    for (const set of leaseSets(calls)) {
      const t = set.detail.times as { expiresAt: number; hardExpiresAt: number };
      expect(t.expiresAt).toBeLessThanOrEqual(finalRecord.hardExpiresAt);
    }
  });

  it('failed-transition compensation pushes the post-revert row, not stale base, when a touch lands in the window (R1)', async () => {
    const deferred = deferredStack();
    const { service, store, config, ownerId } = fixture(deferred.factory);
    const now = Date.now();
    const record = seedVmRecord(store, ownerId, config, {
      status: 'ACTIVE',
      expiresAt: now + 5_000,
      expiredAt: null,
      recoverableUntil: null,
      hardExpiresAt: now + 28_800_000
    });
    const calls: SupervisorCall[] = [];
    const vmCalls = { provision: [] as unknown[], exec: [] as unknown[], destroyed: 0, stopped: 0, ensureActive: 0, offlineExports: [] as unknown[] };
    const stack = fakeVmBackend(vmCalls as never);
    (stack.backend.exec as ReturnType<typeof vi.fn>).mockImplementation(async (ctx: ProvisionContext, req: unknown) => {
      vmCalls.exec.push({ ctx, req });
      return {
        exitCode: 0, signal: null,
        stdout: JSON.stringify({ ok: true, message: 'worker complete', data: {}, truncated: false }),
        stderr: '', truncated: false, timedOut: false
      };
    });
    deferred.setStack(stack);
    // Deterministic barrier: the SECOND push carrying the short renewal's
    // intended expiry (~now+60s) is its post-publish confirmation. Inside the
    // real leaseSync adapter call we run a real exec_run — its touch commits
    // a NEWER expiry (~now+300s idle) inside the publish→revert window — then
    // reject, forcing the rollback path with a concurrent-commit in flight.
    let windowSets = 0;
    service.leaseSync = leaseSyncProbe(calls, {
      set: async (times) => {
        if (times.expiresAt > now + 30_000 && times.expiresAt < now + 90_000) {
          windowSets += 1;
          if (windowSets === 2) {
            await service.execute(ownerId, 'exec_run', { workspaceId: record.id, command: 'touch' });
            throw new Error('final sync rejected');
          }
        }
        return {};
      }
    }).leaseSync;

    await expect(service.execute(ownerId, 'workspace_lease_renew', { workspaceId: record.id, extensionSeconds: 60 }))
      .rejects.toThrow('final sync rejected');

    // The revert preserved the touch's newer expiry (max-guard) and the
    // compensation pushed the POST-REVERT row — durable must equal the store,
    // never the stale base expiry (~now+5s).
    const after = store.byId(record.id)!;
    expect(after.status).toBe('ACTIVE');
    expect(after.expiresAt).toBeGreaterThan(now + 250_000);
    await vi.waitFor(() => {
      expect(lastLeaseTimes(calls).expiresAt).toBe(after.expiresAt);
    });
    for (const set of leaseSets(calls)) {
      const t = set.detail.times as { expiresAt: number };
      // No pushed deadline is the stale ~5s base or beyond hard TTL.
      expect(t.expiresAt).not.toBe(now + 5_000);
      expect(t.expiresAt).toBeLessThanOrEqual(after.hardExpiresAt);
    }
  });
});
