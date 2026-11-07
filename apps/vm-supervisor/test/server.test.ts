import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { VmSupervisorConfig } from '../src/config.js';
import { VmJournal } from '../src/journal.js';
import { RequestDigester } from '../src/request-digest.js';
import type { IncusClient, IncusInstanceInfo } from '../src/incus.js';
import { identityConfigBlock, vmNameForWorkspace } from '../src/identity.js';
import { VmLifecycle } from '../src/lifecycle.js';
import { VmSessionManager } from '../src/sessions.js';
import type { VmNetworkGuard } from '../src/network-ops.js';
import type { VmWorkspaceSubjectPlanner } from '../src/network-plan.js';
import { createSupervisorHandler } from '../src/server.js';
import type { WireHandlerOutcome, WireRequestContext, WireSessionChannel } from '../src/transport.js';

/**
 * Dispatcher tests: contract validation, fencing, lease cutoff, idempotency,
 * lifecycle ops against injected fake Incus/guard. No live Incus, no sockets.
 * Resource sizes are small so admission's pool-reserve check passes on tmpfs.
 */

const TEMPLATE_ID = 'cloudharness-vm-debian13';
const TEMPLATE_DIGEST = 'a'.repeat(64);
// WorkspaceIdSchema: ws_ + 20..80 of [A-Za-z0-9_-]
const WORKSPACE_ID = 'ws_testworkspace0000000001';
const INSTANCE_ID = '11111111-2222-4333-8444-555555555555';
const CPUS = 4;
const MEMORY_BYTES = 8 * 1024 ** 3;
const DISK_BYTES = 4 * 1024 ** 3;

function makeConfig(dir: string): VmSupervisorConfig {
  return {
    socketPath: join(dir, 'supervisor.sock'),
    token: 't'.repeat(48),
    stateDir: dir,
    incusSocketPath: '/nonexistent/incus.sock',
    incusProject: 'cloud-harness',
    guardStatePath: join(dir, 'guard-state.json'),
    bridgePattern: 'chmbr%d',
    subnetPlan: '10.240.0.0/16',
    uplink: '',
    dnsResolvers: ['10.0.0.2'],
    nonpublicCidrs: [],
    poolPath: dir,
    maxTtlSeconds: 3600,
    maxActive: 1,
    cpus: CPUS,
    memoryBytes: MEMORY_BYTES,
    diskBytes: DISK_BYTES,
    poolReserveBytes: 1024 ** 3,
    templateId: TEMPLATE_ID,
    templateDigest: TEMPLATE_DIGEST
  };
}

interface FakeInstance extends IncusInstanceInfo {
  _status: string;
}

function managedConfig(ws: string, inst: string): Record<string, string> {
  return {
    ...identityConfigBlock({ workspaceId: ws, instanceId: inst, templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST }),
    'boot.autostart': 'false',
    'limits.cpu': String(CPUS),
    'limits.memory': String(MEMORY_BYTES)
  };
}

function makeInstance(name: string, status: string, ws = WORKSPACE_ID, inst = INSTANCE_ID): FakeInstance {
  return {
    name,
    status,
    statusCode: 0,
    expandedConfig: managedConfig(ws, inst),
    expandedDevices: {
      root: { type: 'disk', path: '/', pool: 'default', size: String(DISK_BYTES) }
    },
    profiles: [],
    _status: status
  };
}

class FakeIncus {
  instances = new Map<string, FakeInstance>();
  createCalls: unknown[] = [];
  stateCalls: Array<{ name: string; action: string }> = [];
  deleted: string[] = [];

  asClient = (): IncusClient => {
    return {
      listInstances: async () => [...this.instances.values()],
      getInstance: async (name: string) => this.instances.get(name) ?? null,
      getInstanceState: async (name: string) => {
        const i = this.instances.get(name);
        return i === undefined ? null : { status: i.status, statusCode: 0 };
      },
      createInstance: async (spec: { name: string }) => {
        this.createCalls.push(spec);
        this.instances.set(spec.name, makeInstance(spec.name, 'Stopped'));
        return { synchronous: true };
      },
      setInstanceState: async (name: string, action: string) => {
        this.stateCalls.push({ name, action });
        const i = this.instances.get(name);
        if (i !== undefined) i.status = action === 'start' ? 'Running' : 'Stopped';
        return { synchronous: true };
      },
      deleteInstance: async (name: string) => {
        this.deleted.push(name);
        this.instances.delete(name);
        return { synchronous: true };
      },
      waitOperation: async () => ({ elapsedMs: 1, status: 'Success' }),
      findPoolNameBySourcePath: async () => 'default',
      openExecFds: async () => ({ fds: [] }),
      readInstanceFile: async () => Buffer.from('x'),
      writeInstanceFile: async () => undefined,
      writeInstanceFileStream: async () => undefined,
      deleteInstanceFile: async () => undefined,
      listInstancePath: async () => []
    } as unknown as IncusClient;
  }
}

function makeGuard(overrides: Partial<VmNetworkGuard> = {}): VmNetworkGuard {
  const guard: VmNetworkGuard = {
    program: vi.fn(async () => ({ rulesetDigest: 'b'.repeat(64) })),
    attest: vi.fn(async () => ({ ok: true, rulesetDigest: 'b'.repeat(64) })),
    tearDown: vi.fn(async () => ({ removed: true as const })),
    quarantine: vi.fn(async () => ({ quarantined: true, outcomes: [] })),
    // Contract shape: fn runs under ONE lock hold with unlocked tx ops.
    // Delegating tx.* to the public mocks keeps call assertions and
    // per-test overrides working; property lookup happens at call time so
    // `overrides` replacements still apply inside the transaction.
    withStartTransaction: vi.fn(async (args, fn) => fn({
      program: () => guard.program(args),
      attest: () => guard.attest(args)
    })),
    ...overrides
  };
  return guard;
}

/** Deterministic planner stub — the REAL derivation is covered in server-network.test.ts. */
function makePlanner(): VmWorkspaceSubjectPlanner {
  return {
    plan: ({ workspaceId, vmName }) => ({
      workspaceId,
      vmName,
      slotIndex: 7,
      bridgeName: 'chmbr7',
      hostIp: '10.240.0.29',
      guestIp: '10.240.0.30',
      prefixLength: 30,
      mac: '02:00:00:00:00:07',
      tapName: 'chmvt7'
    }),
    stamp: () => ({
      type: 'nic',
      nictype: 'bridged',
      parent: 'chmbr7',
      name: 'eth0',
      hwaddr: '02:00:00:00:00:07',
      host_name: 'chmvt7',
      'ipv4.address': '10.240.0.30/30',
      'security.mac_filtering': 'true',
      'security.ipv4_filtering': 'true',
      'security.ipv6_filtering': 'true'
    }),
    findCollisions: () => []
  };
}

const fakeChannel: WireSessionChannel = {
  emitData: async () => undefined,
  emitMeta: () => undefined,
  emitEnd: () => undefined,
  open: true
};

function ctx(): WireRequestContext {
  return { channel: fakeChannel, signal: new AbortController().signal, closed: new Promise(() => undefined) };
}

interface Harness {
  handler: ReturnType<typeof createSupervisorHandler>;
  journal: VmJournal;
  digester: RequestDigester;
  incus: FakeIncus;
  guard: VmNetworkGuard;
  dir: string;
  lifecycle: VmLifecycle;
  sessions: VmSessionManager;
}

let dir: string;
let harness: Harness;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'vmsup-test-'));
  const config = makeConfig(dir);
  const journal = new VmJournal(join(dir, 'journal.sqlite'));
  const digester = new RequestDigester(join(dir, 'hmac-key'));
  const incus = new FakeIncus();
  const guard = makeGuard();
  const lifecycle = new VmLifecycle({
    config, journal, incus: incus.asClient(), guard: async () => guard
  });
  const sessions = new VmSessionManager({
    journal, incus: incus.asClient(), incusSocketPath: config.incusSocketPath, lifecycle
  });
  const handler = createSupervisorHandler({
    config, journal, digester, incus: incus.asClient(), incusSocketPath: config.incusSocketPath,
    lifecycle, sessions, guard: async () => guard, networkPlan: async () => makePlanner(),
    execFile: async () => ({ exitCode: 0, stdout: '', stderr: '', timedOut: false, truncated: false })
  });
  harness = { handler, journal, digester, incus, guard, dir, lifecycle, sessions };
});

afterEach(() => {
  harness.journal.close();
  rmSync(dir, { recursive: true, force: true });
});

let reqCounter = 0;
function wsReq(op: string, params: unknown, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  reqCounter += 1;
  return {
    version: 1,
    requestId: `req-${reqCounter}`,
    workspaceId: WORKSPACE_ID,
    workspaceGeneration: 1,
    vmInstanceId: INSTANCE_ID,
    idempotencyKey: `idem-${reqCounter}-key`,
    issuedAt: Date.now(),
    op,
    params,
    ...overrides
  };
}

function hostReq(op: string, params: unknown = {}): Record<string, unknown> {
  reqCounter += 1;
  return { version: 1, requestId: `req-${reqCounter}`, issuedAt: Date.now(), op, params };
}

function admitWorkspace(state: 'stopped' | 'running' = 'stopped'): void {
  const vmName = vmNameForWorkspace(WORKSPACE_ID);
  harness.journal.recordWorkspaceAdmit({
    workspaceId: WORKSPACE_ID, vmName, instanceId: INSTANCE_ID,
    templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST,
    generation: 1, networkProfile: 'dependency-access'
  });
  harness.journal.setWorkspaceState(WORKSPACE_ID, state);
  harness.journal.acceptGeneration(WORKSPACE_ID, 1);
  if (!harness.incus.instances.has(vmName)) {
    harness.incus.instances.set(vmName, makeInstance(vmName, state === 'running' ? 'Running' : 'Stopped'));
  }
}

async function call(raw: unknown): Promise<WireHandlerOutcome> {
  return harness.handler(raw, ctx());
}

describe('contract validation', () => {
  it('rejects malformed requests with INVALID_INPUT', async () => {
    await expect(call({ version: 2, op: 'vm.status' })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(call({ version: 1, requestId: 'r', issuedAt: 1, op: 'bogus.op', params: {} }))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('rejects workspace ops with extra params (strict schema)', async () => {
    await expect(call(wsReq('vm.status', { evil: true }))).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});

describe('workspace fencing', () => {
  it('vm.status on unknown workspace → NOT_FOUND', async () => {
    await expect(call(wsReq('vm.status', {}))).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('vmInstanceId mismatch → VM_IDENTITY_MISMATCH', async () => {
    admitWorkspace();
    await expect(call(wsReq('vm.status', {}, { vmInstanceId: '99999999-9999-4999-8999-999999999999' })))
      .rejects.toMatchObject({ code: 'VM_IDENTITY_MISMATCH' });
  });

  it('stale generation → VM_GENERATION_MISMATCH', async () => {
    admitWorkspace();
    harness.journal.acceptGeneration(WORKSPACE_ID, 5);
    await expect(call(wsReq('vm.status', {}, { workspaceGeneration: 3 })))
      .rejects.toMatchObject({ code: 'VM_GENERATION_MISMATCH' });
  });

  it('deleted workspace rejects ops', async () => {
    admitWorkspace();
    harness.journal.setWorkspaceState(WORKSPACE_ID, 'deleted');
    await expect(call(wsReq('vm.status', {}))).rejects.toMatchObject({ code: 'CONFLICT' });
  });
});

describe('lease deadline cutoff', () => {
  it('ops issued at/after deadline → EXPIRED; lease.clear still works', async () => {
    admitWorkspace('running');
    const past = Math.floor(Date.now() / 1000) - 10;
    harness.journal.setLease({
      workspaceId: WORKSPACE_ID, instanceId: INSTANCE_ID, generation: 1,
      expiresAt: past, hardExpiresAt: past + 100, lastRenewalAt: past, state: 'active'
    });
    // issuedAt now is past the deadline → EXPIRED
    await expect(call(wsReq('vm.status', {}))).rejects.toMatchObject({ code: 'EXPIRED' });
    // lease.clear bypasses cutoff
    const outcome = await call(wsReq('lease.clear', {}));
    expect(outcome).toMatchObject({ kind: 'result', result: { cleared: true } });
  });
});

describe('idempotency', () => {
  it('replays completed mutation result without re-executing', async () => {
    admitWorkspace('running');
    const req = wsReq('vm.stop', {});
    const first = await call(req);
    expect(first).toMatchObject({ kind: 'result' });
    const second = await call(req);
    expect(second).toEqual(first);
    // stop ran exactly once against Incus
    expect(harness.incus.stateCalls.filter((c) => c.action === 'stop')).toHaveLength(1);
  });

  it('same key + different params → CONFLICT', async () => {
    admitWorkspace('running');
    const key = 'shared-idem-key-1';
    const now = Math.floor(Date.now() / 1000);
    await call(wsReq('lease.set', { expiresAt: now + 500, hardExpiresAt: now + 700 }, { idempotencyKey: key }));
    await expect(call(wsReq('lease.set', { expiresAt: now + 800, hardExpiresAt: now + 900 }, { idempotencyKey: key })))
      .rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('pending record (simulated crash) → unknown:true error', async () => {
    admitWorkspace('running');
    const key = 'crash-pending-key';
    // Seed a pending idempotency record with the SAME digest the dispatcher
    // will compute — exactly what a crashed attempt leaves behind.
    const digest = harness.digester.digest({ op: 'vm.stop', params: {} });
    harness.journal.beginIdempotent({ workspaceId: WORKSPACE_ID, op: 'vm.stop', key, digest });
    await expect(call(wsReq('vm.stop', {}, { idempotencyKey: key })))
      .rejects.toMatchObject({ code: 'VM_UNKNOWN_STATE', unknown: true });
    // The mutation was NOT re-executed.
    expect(harness.incus.stateCalls.filter((c) => c.action === 'stop')).toHaveLength(0);
  });
});

describe('vm.admit / vm.create / vm.start / vm.stop', () => {
  it('vm.admit returns admitted when under limits', async () => {
    const outcome = await call(wsReq('vm.admit', { networkProfile: 'network-none' }));
    expect(outcome).toMatchObject({ kind: 'result', result: { decision: 'admitted' } });
  });

  it('vm.create stamps identity, creates stopped, journals admit', async () => {
    const outcome = await call(wsReq('vm.create', {
      instanceId: INSTANCE_ID,
      networkProfile: 'network-none',
      templateId: TEMPLATE_ID,
      templateDigest: TEMPLATE_DIGEST
    }));
    expect(outcome).toMatchObject({ kind: 'result', result: { state: 'stopped' } });
    const vmName = vmNameForWorkspace(WORKSPACE_ID);
    expect(harness.incus.createCalls).toHaveLength(1);
    const spec = harness.incus.createCalls[0] as { name: string; config: Record<string, string>; devices: Record<string, Record<string, string>>; profiles: string[] };
    expect(spec.name).toBe(vmName);
    expect(spec.profiles).toEqual([]);
    expect(spec.config['user.cloud-harness.workspace-id']).toBe(WORKSPACE_ID);
    expect(spec.config['boot.autostart']).toBe('false');
    expect(spec.devices['eth0']).toBeUndefined(); // network-none → no nic
    expect(spec.devices['root']?.type).toBe('disk');
    const row = harness.journal.getWorkspace(WORKSPACE_ID);
    expect(row?.state).toBe('stopped');
    expect(row?.vmName).toBe(vmName);
  });

  it('vm.create rejects non-allowlisted template', async () => {
    await expect(call(wsReq('vm.create', {
      instanceId: INSTANCE_ID, networkProfile: 'network-none',
      templateId: 'evil-template', templateDigest: TEMPLATE_DIGEST
    }))).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('vm.create refuses foreign instance squatting on derived name', async () => {
    const vmName = vmNameForWorkspace(WORKSPACE_ID);
    harness.incus.instances.set(vmName, {
      ...makeInstance(vmName, 'Stopped'),
      expandedConfig: { 'user.cloud-harness.workspace-id': 'ws_other0000000000000000' }
    });
    await expect(call(wsReq('vm.create', {
      instanceId: INSTANCE_ID, networkProfile: 'network-none',
      templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST
    }))).rejects.toMatchObject({ code: 'VM_IDENTITY_MISMATCH' });
  });

  it('vm.start runs admission + guard attest + start + journal running', async () => {
    admitWorkspace('stopped');
    // sessions.openAndCapture probe → stub sessions to avoid exec transport
    vi.spyOn(harness.sessions, 'openAndCapture').mockResolvedValue({
      opId: 'probe', exitCode: 0, signal: null, stdout: '', stderr: '', truncated: false, timedOut: false
    } as never);
    const outcome = await call(wsReq('vm.start', { networkProfile: 'dependency-access' }));
    expect(outcome).toMatchObject({ kind: 'result', result: { state: 'running' } });
    expect(harness.guard.attest).toHaveBeenCalledOnce();
    expect(harness.incus.stateCalls).toContainEqual({ name: vmNameForWorkspace(WORKSPACE_ID), action: 'start' });
    expect(harness.journal.getWorkspace(WORKSPACE_ID)?.state).toBe('running');
  });

  it('vm.start fails closed when guard attest fails', async () => {
    admitWorkspace('stopped');
    vi.spyOn(harness.sessions, 'openAndCapture').mockResolvedValue({
      opId: 'probe', exitCode: 0, signal: null, stdout: '', stderr: '', truncated: false, timedOut: false
    } as never);
    (harness.guard.attest as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ ok: false, rulesetDigest: 'b'.repeat(64) });
    await expect(call(wsReq('vm.start', { networkProfile: 'dependency-access' })))
      .rejects.toMatchObject({ code: 'VM_ATTESTATION_FAILED' });
    expect(harness.incus.stateCalls.filter((c) => c.action === 'start')).toHaveLength(0);
  });

  it('vm.start fails closed when guard module missing (shim error)', async () => {
    admitWorkspace('stopped');
    const { VmNetworkGuardNotImplementedError } = await import('../src/network-ops.js');
    const failingGuard = makeGuard({
      attest: vi.fn(async () => { throw new VmNetworkGuardNotImplementedError('absent'); })
    });
    const config = makeConfig(dir);
    const journal = harness.journal;
    const handler2 = createSupervisorHandler({
      config, journal, digester: new RequestDigester(join(dir, 'hmac-key2')),
      incus: harness.incus.asClient(), incusSocketPath: config.incusSocketPath,
      lifecycle: new VmLifecycle({ config, journal, incus: harness.incus.asClient(), guard: async () => failingGuard }),
      sessions: harness.sessions,
      guard: async () => failingGuard,
      networkPlan: async () => makePlanner(),
      execFile: async () => ({ exitCode: 0, stdout: '', stderr: '', timedOut: false, truncated: false })
    });
    await expect(handler2(wsReq('vm.start', { networkProfile: 'dependency-access' }), ctx()))
      .rejects.toMatchObject({ code: 'VM_ATTESTATION_FAILED' });
  });

  it('vm.stop stops and retains (journal stopped, instance kept)', async () => {
    admitWorkspace('running');
    const outcome = await call(wsReq('vm.stop', {}));
    expect(outcome).toMatchObject({ kind: 'result', result: { state: 'stopped' } });
    expect(harness.journal.getWorkspace(WORKSPACE_ID)?.state).toBe('stopped');
    expect(harness.incus.instances.has(vmNameForWorkspace(WORKSPACE_ID))).toBe(true);
  });

  it('vm.delete requires confirmInstanceId and removes instance', async () => {
    admitWorkspace('stopped');
    await expect(call(wsReq('vm.delete', { confirmInstanceId: 'wrong' })))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const outcome = await call(wsReq('vm.delete', { confirmInstanceId: INSTANCE_ID }));
    expect(outcome).toMatchObject({ kind: 'result', result: { state: 'deleted' } });
    expect(harness.incus.deleted).toContain(vmNameForWorkspace(WORKSPACE_ID));
    expect(harness.journal.getWorkspace(WORKSPACE_ID)?.state).toBe('deleted');
  });

  it('vm.delete refuses a running instance', async () => {
    admitWorkspace('running');
    await expect(call(wsReq('vm.delete', { confirmInstanceId: INSTANCE_ID })))
      .rejects.toMatchObject({ code: 'CONFLICT' });
  });
});

describe('lease.set semantics', () => {
  it('clamps to maxTtl and never extends hardExpiresAt on renewal', async () => {
    admitWorkspace('running');
    const now = Math.floor(Date.now() / 1000);
    const first = await call(wsReq('lease.set', {
      expiresAt: now + 500, hardExpiresAt: now + 700
    }));
    expect(first).toMatchObject({ kind: 'result' });
    const eff1 = (first as { result: { effective: { expiresAt: number; hardExpiresAt: number } } }).result.effective;
    expect(Math.abs(eff1.hardExpiresAt - (now + 700))).toBeLessThanOrEqual(1);
    // Renewal tries to push hard deadline out — must NOT extend.
    const second = await call(wsReq('lease.set', {
      expiresAt: now + 900, hardExpiresAt: now + 5000
    }, { workspaceGeneration: 2 }));
    const eff2 = (second as { result: { effective: { expiresAt: number; hardExpiresAt: number } } }).result.effective;
    expect(Math.abs(eff2.hardExpiresAt - eff1.hardExpiresAt)).toBeLessThanOrEqual(1);
    expect(eff2.expiresAt).toBeLessThanOrEqual(eff2.hardExpiresAt);
  });
});

describe('host ops', () => {
  it('vm.list returns journaled workspaces with live state', async () => {
    admitWorkspace('running');
    const outcome = await call(hostReq('vm.list', {}));
    expect(outcome).toMatchObject({ kind: 'result' });
    const result = (outcome as { result: unknown[] }).result;
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({ vmName: vmNameForWorkspace(WORKSPACE_ID), state: 'running' });
  });

  it('lease.list returns stored leases', async () => {
    admitWorkspace('running');
    const now = Math.floor(Date.now() / 1000);
    harness.journal.setLease({
      workspaceId: WORKSPACE_ID, instanceId: INSTANCE_ID, generation: 1,
      expiresAt: now + 100, hardExpiresAt: now + 200, lastRenewalAt: now, state: 'active'
    });
    const outcome = await call(hostReq('lease.list'));
    const result = (outcome as { result: unknown[] }).result;
    expect(result).toHaveLength(1);
    expect(result[0]).toMatchObject({ workspaceId: WORKSPACE_ID, state: 'active' });
  });

  it('pool.info returns statfs + volumes + counts', async () => {
    admitWorkspace('running');
    const outcome = await call(hostReq('pool.info'));
    const result = (outcome as { result: { statfsFree: number; volumes: unknown[]; managedRunningCount: number } }).result;
    expect(result.statfsFree).toBeGreaterThan(0);
    expect(result.managedRunningCount).toBe(1);
  });

  it('reconcile returns all report buckets', async () => {
    admitWorkspace('running');
    const outcome = await call(hostReq('reconcile'));
    const result = (outcome as { result: Record<string, unknown[]> }).result;
    for (const key of ['adopted', 'quarantined', 'stoppedUnleased', 'foreignIgnored', 'deferred']) {
      expect(Array.isArray(result[key])).toBe(true);
    }
  });

  it('guard.state returns unknown verdict when file absent', async () => {
    const outcome = await call(hostReq('guard.state'));
    expect(outcome).toMatchObject({ kind: 'result', result: { verdict: 'unknown' } });
  });
});

describe('network ops fail closed', () => {
  it('network.program maps guard errors to VM_ATTESTATION_FAILED', async () => {
    admitWorkspace('stopped');
    const { VmNetworkGuardNotImplementedError } = await import('../src/network-ops.js');
    const failingGuard = makeGuard({
      program: vi.fn(async () => { throw new VmNetworkGuardNotImplementedError('absent'); })
    });
    const handler2 = createSupervisorHandler({
      config: makeConfig(dir), journal: harness.journal,
      digester: new RequestDigester(join(dir, 'hmac-key3')),
      incus: harness.incus.asClient(), incusSocketPath: '/x',
      lifecycle: harness.lifecycle, sessions: harness.sessions,
      guard: async () => failingGuard,
      networkPlan: async () => makePlanner(),
      execFile: async () => ({ exitCode: 0, stdout: '', stderr: '', timedOut: false, truncated: false })
    });
    await expect(handler2(wsReq('network.program', { networkProfile: 'dependency-access' }), ctx()))
      .rejects.toMatchObject({ code: 'VM_ATTESTATION_FAILED' });
  });
});
