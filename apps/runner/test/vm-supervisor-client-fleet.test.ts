import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import { assertVmAdmissionAllowed, type VmAdmissionDeps } from '../src/vm-admission.js';
import { reconcileVmFleet, reconcileVmShutdown, type VmReconcileRecord } from '../src/vm-reconcile.js';
import { createVmLeaseSync, createVmExportWorkspace, createWorkspaceBackendFactory } from '../src/backend-factory.js';
import { VmGitTransport } from '../src/git-vm-transport.js';
import { VmSupervisorCallError } from '../src/vm-supervisor-client.js';
import type { RunnerConfig } from '@cloud-harness/contracts';

const IID = '123e4567-e89b-42d3-a456-426614174000';
const TID = 'chm-ubuntu-2404';
const TDIG = 'a'.repeat(64);

function rec(overrides: Partial<VmReconcileRecord> = {}): VmReconcileRecord {
  return {
    id: 'ws_0123456789abcdef0123456789abcdef', ownerId: 'o1', status: 'ACTIVE', generation: 3,
    backendKind: 'incus-vm', vmName: 'chm-vm-abc', backendInstanceId: IID,
    templateId: TID, templateDigest: TDIG, expiresAt: 1, hardExpiresAt: 2, recoverableUntil: null,
    workspacePath: '/tmp/ch-vm-reconcile-test-job',
    ...overrides
  } as VmReconcileRecord;
}

const IDENT = { workspaceId: 'ws_0123456789abcdef0123456789abcdef', generation: 3, instanceId: IID };
const UCH = { workspaceId: IDENT.workspaceId, instanceId: IID, templateId: TID, templateDigest: TDIG, generationPolicy: 'external' as const };

function client(overrides: Record<string, unknown> = {}) {
  return {
    vmList: vi.fn(async () => []),
    vmStatus: vi.fn(async () => ({ state: 'running' as const, userCloudHarness: UCH })),
    vmDelete: vi.fn(async () => ({ state: 'deleted' as const })),
    vmStop: vi.fn(async () => ({ state: 'stopped' as const })),
    vmExport: vi.fn(),
    leaseSet: vi.fn(async () => ({ effective: { expiresAt: 1, hardExpiresAt: 2 } })),
    leaseClear: vi.fn(async () => ({ cleared: true as const })),
    poolInfo: vi.fn(async () => ({ poolPath: '/p', statfsFree: 10 ** 12, statfsTotal: 2 * 10 ** 12, volumes: [], imageCacheBytes: 0, managedRunningCount: 0 })),
    ...overrides
  } as any;
}

const cfg = { vmBackendEnabled: true, vmMaxActive: 2, vmDiskBytes: 20 * 2 ** 30, vmPoolReserveBytes: 10 * 2 ** 30, maxActiveWorkspacesPerOwner: 4 } as unknown as RunnerConfig;

describe('vm-admission', () => {
  const store = (vmCount: number, ownerCount: number, limit = 4) => ({
    countActiveByBackend: vi.fn(() => vmCount),
    countOwnerCountedWorkspaces: vi.fn(() => ownerCount),
    effectiveActiveWorkspaceLimit: vi.fn(() => limit)
  });
  const deps = (s: ReturnType<typeof store>, c = client()): VmAdmissionDeps => ({ store: s, client: c, config: cfg });

  it('passes under all caps', async () => {
    await expect(assertVmAdmissionAllowed(deps(store(0, 0)), { ownerId: 'o1' })).resolves.toBeUndefined();
  });
  it('rejects at the global VM cap with VM_QUOTA_EXCEEDED', async () => {
    await expect(assertVmAdmissionAllowed(deps(store(2, 0)), { ownerId: 'o1' })).rejects.toMatchObject({ code: 'VM_QUOTA_EXCEEDED' });
  });
  it('enforces the per-owner limit with LIMIT_EXCEEDED', async () => {
    await expect(assertVmAdmissionAllowed(deps(store(0, 4)), { ownerId: 'o1' })).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
  });
  it('rejects when pool free cannot cover reserve+disk+retained+cache', async () => {
    const c = client({ poolInfo: vi.fn(async () => ({ poolPath: '/p', statfsFree: 25 * 2 ** 30, statfsTotal: 100 * 2 ** 30, volumes: [{ vmName: 'v', configuredBytes: 20 * 2 ** 30, allocatedBytesStBlocks: 0 }], imageCacheBytes: 2 * 2 ** 30, managedRunningCount: 1 })) });
    // required = 10GiB reserve + 20GiB disk + 20GiB retained + 2GiB cache = 52GiB > 25GiB free
    await expect(assertVmAdmissionAllowed(deps(store(0, 0), c), { ownerId: 'o1' })).rejects.toMatchObject({ code: 'VM_QUOTA_EXCEEDED' });
  });
  it('rejects disabled backend', async () => {
    const d = deps(store(0, 0));
    d.config = { ...cfg, vmBackendEnabled: false } as RunnerConfig;
    await expect(assertVmAdmissionAllowed(d, { ownerId: 'o1' })).rejects.toMatchObject({ code: 'VM_BACKEND_DISABLED' });
  });
});

describe('vm-reconcile', () => {
  it('adopts a running VM only on full identity match', async () => {
    const c = client({ vmList: vi.fn(async () => [{ vmName: 'chm-vm-abc', workspaceId: IDENT.workspaceId, instanceId: IID }]) });
    const report = await reconcileVmFleet({ client: c }, [rec()]);
    expect(report.actions).toEqual([{ type: 'adopted', workspaceId: IDENT.workspaceId, vmName: 'chm-vm-abc' }]);
  });
  it('quarantines identity mismatches and orphans — never deletes them', async () => {
    const c = client({
      vmList: vi.fn(async () => [
        { vmName: 'chm-vm-bad', workspaceId: IDENT.workspaceId, instanceId: 'other-id' },
        { vmName: 'chm-vm-foreign', workspaceId: 'ws_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' }
      ]),
      vmStatus: vi.fn(async () => ({ state: 'running' as const, userCloudHarness: { ...UCH, templateDigest: 'b'.repeat(64) } }))
    });
    const report = await reconcileVmFleet({ client: c }, [rec(), rec({ id: 'ws_ffffffffffffffffffffffffffffffff', vmName: 'chm-vm-foreign' })]);
    // 'chm-vm-bad' quarantined (instanceId mismatch), 'chm-vm-foreign' orphaned
    // (no record), rec()'s own 'chm-vm-abc' absent from the list → deferred.
    expect(report.actions.map((a) => a.type)).toEqual(['quarantined', 'orphaned', 'deferred']);
    expect(c.vmDelete).not.toHaveBeenCalled();
  });
  it('reports a verified CREATING orphan without deleting — close authority stays with the caller', async () => {
    const c = client({ vmList: vi.fn(async () => [{ vmName: 'chm-vm-abc', workspaceId: IDENT.workspaceId, instanceId: IID }]) });
    const report = await reconcileVmFleet({ client: c }, [rec({ status: 'CREATING' })]);
    expect(report.actions[0]).toMatchObject({ type: 'orphaned', workspaceId: IDENT.workspaceId });
    expect(c.vmDelete).not.toHaveBeenCalled();
  });
  it('defers expired records when no export/inspector is wired — never deletes unknown', async () => {
    const c = client({ vmList: vi.fn(async () => [{ vmName: 'chm-vm-abc', workspaceId: IDENT.workspaceId, instanceId: IID }]), vmStatus: vi.fn(async () => ({ state: 'stopped' as const, userCloudHarness: UCH })) });
    const report = await reconcileVmFleet({ client: c, now: () => 3 }, [rec({ status: 'EXPIRED_RECOVERABLE', hardExpiresAt: 2 })]);
    expect(report.actions[0]!.type).toBe('deferred');
    expect(c.vmDelete).not.toHaveBeenCalled();
  });
  it('expire-before-adopt: a hard-expired record is never adopted even when the VM is running (M4)', async () => {
    const c = client({
      vmList: vi.fn(async () => [{ vmName: 'chm-vm-abc', workspaceId: IDENT.workspaceId, instanceId: IID }]),
      vmStatus: vi.fn(async () => ({ state: 'running' as const, userCloudHarness: UCH }))
    });
    let seenDest = '';
    const exportFn = vi.fn(async (_ctx: unknown, opts: { destPath: string }) => {
      seenDest = opts.destPath;
      const { writeFile } = await import('node:fs/promises');
      await writeFile(opts.destPath, 'x');
      return { sha256: createHash('sha256').update('x').digest('hex'), bytes: 1 };
    });
    const report = await reconcileVmFleet(
      { client: c, exportWorkspace: exportFn, inspectExport: async () => 'clean', now: () => 3 },
      [rec({ status: 'EXPIRED_RECOVERABLE', hardExpiresAt: 2 })]
    );
    // Export-clean, NOT adopted — expiry wins over the running-state adopt path.
    expect(report.actions[0]!.type).toBe('export-clean');
    expect(c.vmStop).toHaveBeenCalledTimes(1);
    // L11: staging lives under the record's workspace job dir (disk-backed),
    // never a bare os.tmpdir() mkdtemp which may sit on tmpfs.
    expect(seenDest.startsWith('/tmp/ch-vm-reconcile-test-job/.reconcile-')).toBe(true);
  });
  it('bounded reconcile: abort stops scheduling later records and cancels in-flight work (M5)', async () => {
    const controller = new AbortController();
    const seenSignals: AbortSignal[] = [];
    const c = client({
      vmList: vi.fn(async () => [
        { vmName: 'chm-vm-a', workspaceId: IDENT.workspaceId, instanceId: IID },
        { vmName: 'chm-vm-b', workspaceId: 'ws_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', instanceId: 'iid-b' }
      ]),
      vmStatus: vi.fn(async (_id: unknown, opts?: { signal?: AbortSignal }) => {
        seenSignals.push(opts?.signal as AbortSignal);
        return { state: 'running' as const, userCloudHarness: UCH };
      })
    });
    // First record is hard-expired → export path; abort mid-export.
    const exportFn = vi.fn(async (_ctx: unknown, opts: { signal?: AbortSignal; destPath: string }) => {
      seenSignals.push(opts.signal as AbortSignal);
      controller.abort();
      const { writeFile } = await import('node:fs/promises');
      await writeFile(opts.destPath, 'partial');
      throw Object.assign(new Error('aborted'), { name: 'AbortError' });
    });
    const records = [
      rec({ status: 'EXPIRED_RECOVERABLE', hardExpiresAt: 2, vmName: 'chm-vm-a' }),
      rec({ id: 'ws_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', vmName: 'chm-vm-b', backendInstanceId: 'iid-b', generation: 4 })
    ];
    const report = await reconcileVmFleet(
      { client: c, exportWorkspace: exportFn, inspectExport: async () => 'unknown', now: () => 3 },
      records,
      { signal: controller.signal }
    );
    const types = report.actions.map((a) => a.type);
    // First record's export was cancelled → deferred; second never scheduled.
    expect(types).toContain('deferred');
    expect(types.filter((t) => t === 'deferred').length).toBeGreaterThanOrEqual(2);
    // Every supervisor call received the abort signal.
    expect(seenSignals.length).toBeGreaterThan(0);
    expect(seenSignals.every((s) => s === controller.signal)).toBe(true);
  });
  it('deadlineMs bounds the sweep: records past the deadline are deferred unprocessed', async () => {
    let tick = 0;
    const c = client({
      vmList: vi.fn(async () => [
        { vmName: 'chm-vm-a', workspaceId: IDENT.workspaceId, instanceId: IID },
        { vmName: 'chm-vm-b', workspaceId: 'ws_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', instanceId: 'iid-b' }
      ]),
      // First record's status call consumes the whole budget.
      vmStatus: vi.fn(async () => { tick += 200; return { state: 'running' as const, userCloudHarness: UCH }; })
    });
    const report = await reconcileVmFleet({ client: c, now: () => tick }, [
      rec({ vmName: 'chm-vm-a' }),
      rec({ id: 'ws_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', vmName: 'chm-vm-b', backendInstanceId: 'iid-b' })
    ], { deadlineMs: 150 });
    // First adopted (budget checked before its status call at tick=0); second
    // sees nowFn()=200 ≥ 150 → deferred without any status call.
    expect(report.actions.map((a) => a.type)).toEqual(['adopted', 'deferred']);
    expect(c.vmStatus).toHaveBeenCalledTimes(1);
  });
  it('reports export-clean on clean verdict, retains on dirty, defers on unknown — never deletes', async () => {
    const mk = () => client({
      vmList: vi.fn(async () => [{ vmName: 'chm-vm-abc', workspaceId: IDENT.workspaceId, instanceId: IID }]),
      vmStatus: vi.fn(async () => ({ state: 'stopped' as const, userCloudHarness: UCH }))
    });
    const expired = () => rec({ status: 'EXPIRED_RECOVERABLE', hardExpiresAt: 2 });
    const exportFn = vi.fn(async (_ctx: unknown, opts: { destPath: string }) => {
      const { writeFile } = await import('node:fs/promises');
      await writeFile(opts.destPath, 'tar');
      return { sha256: 'e'.repeat(64), bytes: 3 };
    });
    // clean → export-clean report, VM retained (no delete authority)
    let c = mk();
    let report = await reconcileVmFleet({ client: c, exportWorkspace: exportFn, inspectExport: async () => 'clean', now: () => 3 }, [expired()]);
    expect(report.actions[0]!.type).toBe('export-clean');
    expect(c.vmDelete).not.toHaveBeenCalled();
    expect(c.vmStop).toHaveBeenCalledTimes(1); // stop precedes offline export
    // dirty → retained
    c = mk();
    report = await reconcileVmFleet({ client: c, exportWorkspace: exportFn, inspectExport: async () => 'dirty', now: () => 3 }, [expired()]);
    expect(report.actions[0]!.type).toBe('retained-dirty');
    expect(c.vmDelete).not.toHaveBeenCalled();
    // unknown → deferred
    c = mk();
    report = await reconcileVmFleet({ client: c, exportWorkspace: exportFn, inspectExport: async () => 'unknown', now: () => 3 }, [expired()]);
    expect(report.actions[0]!.type).toBe('deferred');
    expect(c.vmDelete).not.toHaveBeenCalled();
  });
  it('defers everything when vm.list is unavailable', async () => {
    const c = client({ vmList: vi.fn(async () => { throw new VmSupervisorCallError('VM_SUPERVISOR_UNAVAILABLE', 'down', 503, true); }) });
    const report = await reconcileVmFleet({ client: c }, [rec()]);
    expect(report.actions[0]!.type).toBe('deferred');
  });
  it('shutdown clears lease + stops each VM best-effort', async () => {
    const c = client();
    const report = await reconcileVmShutdown({ client: c }, [rec(), rec({ backendKind: 'docker', id: 'ws_docker0000000000000000000000' })]);
    expect(c.leaseClear).toHaveBeenCalledTimes(1);
    expect(c.vmStop).toHaveBeenCalledTimes(1);
    expect(report.actions[0]!.type).toBe('stopped');
  });
});

describe('backend-factory + leaseSync + export', () => {
  const deps = (overrides: Record<string, unknown> = {}) => ({
    config: { ...cfg, executorImage: 'img', jobsRoot: '/tmp', minFreeBytes: 0, packagesEnabled: false } as unknown as RunnerConfig,
    instanceId: 'inst-1',
    supervisorClient: client(),
    ...overrides
  }) as any;

  it('docker is default; incus-vm gated on vmBackendEnabled; unknown kinds rejected', () => {
    const disabled = deps({ config: { ...deps().config, vmBackendEnabled: false } });
    const f = createWorkspaceBackendFactory(disabled);
    expect(f('docker').backend.kind).toBe('docker');
    expect(f('docker').git.backend).toBe('docker');
    expect(() => f('incus-vm')).toThrowError(expect.objectContaining({ code: 'VM_BACKEND_DISABLED' }));
    const f2 = createWorkspaceBackendFactory(deps({ config: { ...deps().config, vmBackendEnabled: true } }));
    const stack = f2('incus-vm');
    expect(stack.backend.kind).toBe('incus-vm');
    expect(stack.git.backend).toBe('incus-vm');
    // real VmGitTransport — exportWorkspace auto-wired from the supervisor client
    expect(stack.git).toBeInstanceOf(VmGitTransport);
    expect(() => f2('bogus' as never)).toThrowError(expect.objectContaining({ code: 'VM_BACKEND_DISABLED' }));
  });

  it('leaseSync pushes lease.set with fenced identity and clears on demand', async () => {
    const c = client();
    const sync = createVmLeaseSync(c);
    const record = { ...rec(), expiresAt: 111, hardExpiresAt: 222 } as never;
    await sync.set(record);
    expect(c.leaseSet).toHaveBeenCalledWith(IDENT, { expiresAt: 111, hardExpiresAt: 222 }, expect.objectContaining({ idempotencyKey: expect.stringContaining(IID) }));
    await sync.clear(record);
    expect(c.leaseClear).toHaveBeenCalledTimes(1);
    // docker record → no-op
    await sync.set({ ...rec(), backendKind: 'docker', backendInstanceId: null } as never);
    expect(c.leaseSet).toHaveBeenCalledTimes(1);
  });

  it('createVmExportWorkspace streams vm.export to a host file with verified digest (M7)', async () => {
    const payload = Buffer.concat([Buffer.from('abc'), Buffer.from('def')]);
    const c = client({
      vmExport: vi.fn(async (_id: unknown, _p: unknown, opts: { sink: (b: Buffer) => void | Promise<void> }) => {
        for (const ch of [payload.subarray(0, 3), payload.subarray(3)]) await opts.sink(ch);
        return { sha256: createHash('sha256').update(payload).digest('hex'), bytes: 6, entryCount: 1 };
      })
    });
    const { mkdtemp, readFile, rm } = await import('node:fs/promises');
    const { tmpdir } = await import('node:os');
    const { join } = await import('node:path');
    const dir = await mkdtemp(join(tmpdir(), 'ch-exp-'));
    const dest = join(dir, 'out.tar');
    const fn = createVmExportWorkspace(c);
    const out = await fn({ record: rec(), signal: undefined } as never, { guestPath: '/workspace', destPath: dest, maxBytes: 1024 });
    expect(out.bytes).toBe(6);
    expect(await readFile(dest, 'utf8')).toBe('abcdef');
    expect(c.vmExport).toHaveBeenCalledWith(IDENT, { guestPath: '/workspace', maxBytes: 1024 }, expect.anything());
    await rm(dir, { recursive: true, force: true });
  });
});
