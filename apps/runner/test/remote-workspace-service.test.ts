import { mkdirSync, mkdtempSync, rmSync, readFileSync, writeFileSync, symlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { RunnerConfig } from '@cloud-harness/contracts';
import { StateStore, type WorkspaceRecord } from '../src/state-store.js';
import type { ExecutorStore } from '../src/executor-store.js';
import type { RemoteJobSpec } from '../src/executors/execution-backend.js';
const boundary = vi.hoisted(() => ({
  provision: vi.fn(), stop: vi.fn(), resume: vi.fn(), release: vi.fn(), invoke: vi.fn(), jobs: new Map<string, RemoteJobSpec>(),
  inspect: vi.fn().mockResolvedValue({ ready: true, state: 'running' }),
  payloads: new Map<string, Buffer>(),
  runDocker: vi.fn(async (args: string[]) => ({ stdout: args.includes('/usr/bin/du') ? '0\t/workspace\n' : '', stderr: '', exitCode: 0, truncated: false }))
}));
vi.mock('../src/docker-engine.js', () => ({ runDocker: boundary.runDocker, removeContainer: vi.fn().mockResolvedValue(undefined), inspectContainer: vi.fn(), spawnDocker: vi.fn(), terminateContainerProcessGroup: vi.fn() }));
vi.mock('../src/repository-policy.js', () => ({ validateRepositoryUrl: vi.fn(async (value: string) => new URL(value)) }));
vi.mock('../src/remote-workspace.js', () => ({ RemoteWorkspace: class {
  constructor(readonly allocations: ExecutorStore, readonly config: RunnerConfig) {}
  backend = {
    inspect: boundary.inspect,
    writeFile: vi.fn(async (_ref, path: string, data: Buffer) => { boundary.payloads.set(path, data); }),
    startJob: vi.fn(async (_ref, spec: RemoteJobSpec) => { boundary.jobs.set(spec.id, spec); }),
    readJob: vi.fn(async (_ref, id: string, offset: number) => {
      const output = Buffer.from(JSON.stringify({ ok: true, message: 'remote worker', data: { output: 'remote checkout' }, truncated: false }));
      return { status: 'exited', exitCode: 0, output: output.subarray(offset), nextOffset: output.length, outputBytes: output.length, truncated: false };
    }),
    cancelJob: vi.fn().mockResolvedValue(undefined), activity: vi.fn().mockResolvedValue(undefined)
  };
  ref(record: WorkspaceRecord) { const ref = this.allocations.byWorkspace(record.id); if (!ref) throw Error('missing allocation'); return ref; }
  async reserve(record: WorkspaceRecord) { return record.ownerId === this.config.instabox!.principalId && Boolean(this.allocations.reserve(record.id, record.ownerId, this.config.instabox!.machineIds)); }
  async provision(record: WorkspaceRecord) { await boundary.provision(record); this.allocations.setState(this.ref(record), 'ACTIVE'); }
  async resume(record: WorkspaceRecord) { await boundary.resume(record); this.allocations.setState(this.ref(record), 'ACTIVE'); }
  async stop(record: WorkspaceRecord) { await boundary.stop(record); this.allocations.setState(this.ref(record), 'STOPPED'); }
  async release(record: WorkspaceRecord) { await boundary.release(record); const ref = this.ref(record); this.allocations.setState(ref, 'RELEASING'); this.allocations.release(ref); }
  async invoke(record: WorkspaceRecord, command: string, input?: Record<string, unknown>) { return boundary.invoke(record, command, input); }
  async snapshotCheckout(record: WorkspaceRecord) { return join(record.workspacePath, 'remote-skills'); }
} }));
import { WorkspaceService } from '../src/workspace-service.js';
const fixtures: Array<{ service: WorkspaceService; store: StateStore; dir: string }> = [];
function fixture(limit = 4) {
  const dir = mkdtempSync(join(tmpdir(), 'remote-workspace-service-')); mkdirSync(join(dir, 'jobs'));
  const store = new StateStore(join(dir, 'state.db'));
  const principal = { kind: 'external' as const, issuer: 'https://issuer.test', subject: 'owner' };
  const owner = store.resolvePrincipal(principal);
  const config = { jobsRoot: join(dir, 'jobs'), stateDb: join(dir, 'state.db'), wallTtlSeconds: 900, idleTtlSeconds: 300,
    maxOutputBytes: 262144, maxWorkspaceBytes: 104857600, minFreeBytes: 0, networkProfile: 'network-none',
    maxActiveWorkspacesPerOwner: limit, allowedGitHosts: ['github.com'], executorImage: 'executor:test', maxArtifactBytes: 1024,
    instabox: { apiKey: 'test', principalId: owner, machineIds: ['one', 'two', 'three'], allowPublicNetwork: true } } as RunnerConfig;
  const service = new WorkspaceService(config, store);
  boundary.invoke.mockImplementation(async (_record, command: string) => ({ stdout: command.startsWith('sudo -n -- du ') ? '0\t/remote\n' : '', stderr: '', exitCode: 0, truncated: false }));
  fixtures.push({ service, store, dir });
  return { service, store, owner, principal, config };
}
const open = (service: WorkspaceService, owner: string, key: string, extra = {}) => service.open(owner, { repositoryUrl: 'https://github.com/org/repo', idempotencyKey: `workspace-${key}`, ...extra });
afterEach(async () => {
  for (const { service, store, dir } of fixtures.splice(0)) { await service.stop(); store.close(); rmSync(dir, { recursive: true, force: true }); }
  vi.clearAllMocks(); boundary.provision.mockReset(); boundary.stop.mockReset(); boundary.jobs.clear(); boundary.payloads.clear();
});
describe('remote workspace service routing', () => {
  it('measures the complete retained allocation through bounded noninteractive privilege and fails closed', async () => {
    const { service, store, owner } = fixture();
    await open(service, owner, 'quota');
    const record = store.list(owner)[0]!;
    const probe = service as unknown as { workspaceBytes(record: WorkspaceRecord): Promise<number | undefined> };
    boundary.invoke.mockResolvedValueOnce({ stdout: '12345\t/remote\n', stderr: '', exitCode: 0, truncated: false });
    expect(await probe.workspaceBytes(record)).toBe(12345);
    expect(boundary.invoke).toHaveBeenLastCalledWith(record,
      expect.stringMatching(/^sudo -n -- du -sb --apparent-size -- '\/data\/home\/\.cloud-harness\/[a-f0-9]{36}\/ws_/),
      { timeoutMs: 30000, maxBytes: 8192 });
    boundary.invoke.mockResolvedValueOnce({ stdout: '', stderr: 'permission denied', exitCode: 1, truncated: false });
    expect(await probe.workspaceBytes(record)).toBeUndefined();
    boundary.invoke.mockResolvedValueOnce({ stdout: 'not-a-size\t/remote\n', stderr: '', exitCode: 0, truncated: false });
    expect(await probe.workspaceBytes(record)).toBeUndefined();
  });
  it('reports paused compute and provider outages without waking or replacing retained machines', async () => {
    const { service, store, owner, principal } = fixture();
    await open(service, owner, 'status');
    const row = store.list(owner)[0]!;
    boundary.inspect.mockResolvedValueOnce({ state: 'suspended', ready: false });
    const paused = await service.execute(principal, 'workspace_status', { workspaceId: row.id });
    expect(paused.data).toMatchObject({ status: 'ACTIVE', compute: { state: 'suspended', ready: false, allocationState: 'ACTIVE' } });
    boundary.inspect.mockRejectedValueOnce(new Error('provider disconnected'));
    const unavailable = await service.execute(principal, 'workspace_status', { workspaceId: row.id });
    expect(unavailable.data).toMatchObject({ compute: { state: 'unavailable', ready: false } });
    expect(boundary.resume).not.toHaveBeenCalled(); expect(boundary.stop).not.toHaveBeenCalled();
    expect(store.list(owner)).toHaveLength(1);
  });
  it('uses three remote allocations then local overflow without bypassing the owner quota', async () => {
    const { service, store, owner } = fixture();
    for (let index = 0; index < 4; index++) await open(service, owner, `open-${index}`);
    const rows = store.list(owner);
    expect(rows.filter(row => row.executorKind === 'instabox')).toHaveLength(3);
    expect(rows.filter(row => row.executorKind === 'instabox').every(row => row.containerName === null)).toBe(true);
    expect(boundary.runDocker.mock.calls.filter(([args]) => args[0] === 'create')).toHaveLength(1);
    await expect(open(service, owner, 'fifth')).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
  });
  it('keeps explicit and persisted restricted network requests on local compute', async () => {
    const { service, store, owner } = fixture();
    await open(service, owner, 'explicit', { networkProfile: 'network-none' });
    store.setWorkspaceDefaultNetworkProfile('network-none', Date.now());
    await open(service, owner, 'setting');
    expect(boundary.provision).not.toHaveBeenCalled();
    expect(store.list(owner).every(row => row.executorKind !== 'instabox')).toBe(true);
  });
  it('retains allocation and staging after ambiguous provisioning without local fallback', async () => {
    const { service, store, owner } = fixture();
    boundary.provision.mockRejectedValueOnce(new Error('response lost'));
    await expect(open(service, owner, 'ambiguous')).rejects.toThrow('response lost');
    const row = store.list(owner)[0]!;
    expect(row).toMatchObject({ executorKind: 'instabox', status: 'EXPIRED_RECOVERABLE', containerName: null, recoverableUntil: null });
    expect(store.database.prepare('SELECT count(*) AS total FROM executor_allocations WHERE released=0').get()).toMatchObject({ total: 1 });
    expect(boundary.runDocker.mock.calls.some(([args]) => args[0] === 'create')).toBe(false);
  });
  it('routes files through guest workers and retains identity through stop/resume before explicit close', async () => {
    const { service, store, owner, principal } = fixture();
    await open(service, owner, 'remote');
    const row = store.list(owner)[0]!;
    const result = await service.execute(principal, 'files_read', { workspaceId: row.id, path: 'README.md' });
    expect(result.data).toMatchObject({ output: 'remote checkout' });
    expect([...boundary.payloads.values()].some(payload => JSON.parse(payload.toString()).operation === 'files_read')).toBe(true);
    await service.execute(principal, 'workspace_recover', { workspaceId: row.id, mode: 'stop' });
    expect(store.byId(row.id)).toMatchObject({ status: 'EXPIRED_RECOVERABLE', executorKind: 'instabox', recoverableUntil: null });
    const callsBefore = boundary.resume.mock.calls.length;
    await expect(service.execute(principal, 'workspace_recover', { workspaceId: row.id, mode: 'status' })).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(boundary.resume).toHaveBeenCalledTimes(callsBefore);
    await service.execute(principal, 'workspace_recover', { workspaceId: row.id, mode: 'resume' });
    await service.execute(principal, 'workspace_close', { workspaceId: row.id });
    expect(boundary.release).toHaveBeenCalledOnce();
    expect(store.byId(row.id)?.status).toBe('CLOSED');
  });
  it('does not report stopped or release allocation when provider termination fails', async () => {
    const { service, store, owner, principal } = fixture();
    await open(service, owner, 'failure');
    const record = store.list(owner)[0]!;
    boundary.stop.mockRejectedValueOnce(new Error('stop uncertain'));
    await expect(service.execute(principal, 'workspace_recover', { workspaceId: record.id, mode: 'stop' })).rejects.toThrow('stop uncertain');
    expect(store.byId(record.id)?.status).toBe('REAPING');
    expect(boundary.release).not.toHaveBeenCalled();
  });
  it('transfers large worker payloads outside shell arguments', async () => {
    const { service, store, owner, principal } = fixture();
    await open(service, owner, 'large-payload');
    const content = 'x'.repeat(256 * 1024);
    await service.execute(principal, 'files_write', { workspaceId: store.list(owner)[0]!.id, path: 'large.txt', content });
    expect([...boundary.payloads.values()].map(value => JSON.parse(value.toString())).find(value => value.operation === 'files_write')?.input.content).toBe(content);
    expect([...boundary.jobs.values()].every(spec => Buffer.byteLength(spec.command ?? '') < 4096)).toBe(true);
  });

  it('removes executable Git configuration before the host broker can see a remote stage', async () => {
    const { service, config } = fixture();
    const stage = join(config.jobsRoot, 'stage');
    mkdirSync(join(stage, 'objects'), { recursive: true }); mkdirSync(join(stage, 'hooks'));
    writeFileSync(join(stage, 'config'), '[include]\npath=/secrets\n[url "https://evil.invalid/"]\ninsteadOf=https://github.com/\n');
    writeFileSync(join(stage, 'config.worktree'), '[core]\nsshCommand=unsafe\n');
    writeFileSync(join(stage, 'hooks', 'pre-push'), 'unsafe');
    await (service as unknown as { sanitizeRemoteGitStage(path: string, sha256: boolean): Promise<void> }).sanitizeRemoteGitStage(stage, false);
    expect(readFileSync(join(stage, 'config'), 'utf8')).toBe('[core]\nrepositoryformatversion = 0\nbare = true\n');
    expect(existsSync(join(stage, 'config.worktree'))).toBe(false);
    expect(existsSync(join(stage, 'hooks'))).toBe(false);
    symlinkSync('/tmp', join(stage, 'redirect'));
    await expect((service as unknown as { sanitizeRemoteGitStage(path: string, sha256: boolean): Promise<void> }).sanitizeRemoteGitStage(stage, false)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('finishes host cleanup from a released tombstone without repeating remote release', async () => {
    const { service, store, owner, principal } = fixture();
    await open(service, owner, 'cleanup-retry');
    const record = store.list(owner)[0]!;
    const cleanup = vi.spyOn(service as unknown as { safeRemovePath(path: string): Promise<void> }, 'safeRemovePath');
    cleanup.mockRejectedValueOnce(new Error('host cleanup interrupted'));
    await expect(service.execute(principal, 'workspace_close', { workspaceId: record.id })).rejects.toThrow('host cleanup interrupted');
    expect(boundary.release).toHaveBeenCalledTimes(1);
    expect(store.byId(record.id)?.status).toBe('REAPING');
    await service.execute(principal, 'workspace_close', { workspaceId: record.id });
    expect(boundary.release).toHaveBeenCalledTimes(1);
    expect(store.byId(record.id)?.status).toBe('CLOSED');
  });

  it('does not turn an explicit close into a stop while release awaits the provider', async () => {
    const { service, store, owner, principal } = fixture();
    await open(service, owner, 'close-race');
    const record = store.list(owner)[0]!;
    let finish!: () => void;
    boundary.release.mockReturnValueOnce(new Promise<void>(resolve => { finish = resolve; }));
    const closing = service.execute(principal, 'workspace_close', { workspaceId: record.id });
    await vi.waitFor(() => expect(boundary.release).toHaveBeenCalled());
    await (service as unknown as { reapExpired(): Promise<void> }).reapExpired();
    expect(store.byId(record.id)).toMatchObject({ status: 'REAPING', error: 'Remote close pending' });
    expect(boundary.stop).not.toHaveBeenCalled();
    finish(); await closing;
    expect(store.byId(record.id)?.status).toBe('CLOSED');
  });

});
