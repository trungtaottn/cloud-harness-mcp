import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { VmSupervisorConfig } from '../src/config.js';
import type { VmApplianceProcess, VmApplianceSpawner } from '../src/export.js';
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
  /** Test-controlled exec/list responses (native shapes). */
  execChannels: Record<string, string> = {};
  execOperation = '/1.0/operations/fake-exec';
  execExit: { exitCode: number | null; signal: string | null; error?: string } = { exitCode: 0, signal: null };
  listNames: string[] = [];
  stopFails = false;
  getInstanceError: Error | undefined;

  asClient = (): IncusClient => {
    return {
      listInstances: async () => [...this.instances.values()],
      getInstance: async (name: string) => {
        if (this.getInstanceError !== undefined) throw this.getInstanceError;
        return this.instances.get(name) ?? null;
      },
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
        if (this.stopFails && action === 'stop') throw new Error('stop transport failure');
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
      openExecFds: async () => ({ channels: this.execChannels, operation: this.execOperation }),
      waitExecExit: async () => this.execExit,
      readInstanceFile: async () => Buffer.from('x'),
      writeInstanceFile: async () => undefined,
      writeInstanceFileStream: async () => undefined,
      deleteInstanceFile: async () => undefined,
      listInstancePath: async () => this.listNames
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

/** Minimal appliance fake: streams a fixed tar on stdout, closes cleanly. */
class FakeApplianceProc extends EventEmitter implements VmApplianceProcess {
  readonly stdout: Readable;
  readonly stderr: Readable;
  constructor(tar: Buffer) {
    super();
    this.stdout = Readable.from([tar]);
    this.stderr = Readable.from([]);
    setImmediate(() => this.emit('close', 0, null));
  }
  kill(): boolean {
    setImmediate(() => this.emit('close', null, 'SIGKILL'));
    return true;
  }
}

const EMPTY_TAR = Buffer.alloc(1024);
function exportSpawner(): VmApplianceSpawner {
  return () => new FakeApplianceProc(EMPTY_TAR);
}

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
    spawnAppliance: exportSpawner(),
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
  it('lifecycle/read ops stay reachable past deadline; live ops → EXPIRED; lease.clear works', async () => {
    admitWorkspace('running');
    const past = Math.floor(Date.now() / 1000) - 10;
    harness.journal.setLease({
      workspaceId: WORKSPACE_ID, instanceId: INSTANCE_ID, generation: 1,
      expiresAt: past, hardExpiresAt: past + 100, lastRenewalAt: past, state: 'active'
    });
    // Deadline passed but watchdog has not marked 'expired' — the gap window.
    // Lifecycle/inspection ops must stay reachable (safe stop/status); live
    // execution ops remain fenced.
    const status = await call(wsReq('vm.status', {}));
    expect(status).toMatchObject({ kind: 'result' });
    await expect(call(wsReq('exec.run', {
      opId: 'op-gap', argv: ['/bin/true'], environment: {}, timeoutMs: 1000, maxBytes: 1024
    }))).rejects.toMatchObject({ code: 'EXPIRED' });
    await expect(call(wsReq('vm.start', { networkProfile: 'network-none' }))).rejects.toMatchObject({ code: 'EXPIRED' });
    // lease.clear bypasses cutoff
    const outcome = await call(wsReq('lease.clear', {}));
    expect(outcome).toMatchObject({ kind: 'result', result: { cleared: true } });
  });
});

describe('lease expiry offline export', () => {
  const exportParams = { guestPath: '/workspace', maxBytes: 1024 * 1024 };

  function expireLease(hardOffset = 700): void {
    const now = Math.floor(Date.now() / 1000);
    harness.journal.setLease({
      workspaceId: WORKSPACE_ID, instanceId: INSTANCE_ID, generation: 1,
      expiresAt: now - 10, hardExpiresAt: now + hardOffset, lastRenewalAt: now - 10, state: 'active'
    });
    harness.journal.setLeaseState(WORKSPACE_ID, 'expired');
  }

  it('expired lease + stopped VM → vm.export dispatches a download outcome', async () => {
    admitWorkspace('stopped');
    expireLease();
    const outcome = await call(wsReq('vm.export', exportParams));
    expect(outcome).toMatchObject({ kind: 'download' });
    const produced = await (outcome as { produce: (emit: (c: Buffer) => Promise<void>) => Promise<unknown> }).produce(async () => undefined);
    expect(produced).toMatchObject({ bytes: EMPTY_TAR.length, entryCount: 0 });
  });

  it('expired lease + running VM → vm.export CONFLICT (stopped required)', async () => {
    admitWorkspace('running');
    expireLease();
    await expect(call(wsReq('vm.export', exportParams))).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('expired lease + wrong identity/generation → mismatch BEFORE EXPIRED', async () => {
    admitWorkspace('stopped');
    expireLease();
    await expect(call(wsReq('vm.export', exportParams, { vmInstanceId: '99999999-9999-4999-8999-999999999999' })))
      .rejects.toMatchObject({ code: 'VM_IDENTITY_MISMATCH' });
    harness.journal.acceptGeneration(WORKSPACE_ID, 5);
    await expect(call(wsReq('vm.export', exportParams, { workspaceGeneration: 3 })))
      .rejects.toMatchObject({ code: 'VM_GENERATION_MISMATCH' });
  });

  it('expired lease still fences exec.run and file.push', async () => {
    admitWorkspace('stopped');
    expireLease();
    await expect(call(wsReq('exec.run', {
      opId: 'op-exp2', argv: ['/bin/true'], environment: {}, timeoutMs: 1000, maxBytes: 1024
    }))).rejects.toMatchObject({ code: 'EXPIRED' });
    await expect(call(wsReq('file.push', {
      guestPath: '/workspace/x', dataBase64: 'eA==', sha256: '0'.repeat(64),
      maxBytes: 1024, mode: 0o644, uid: 1000, gid: 1000
    }))).rejects.toMatchObject({ code: 'EXPIRED' });
  });

  it('hard-TTL renewal through lease.set cannot extend the hard deadline', async () => {
    admitWorkspace('stopped');
    const now = Math.floor(Date.now() / 1000);
    harness.journal.setLease({
      workspaceId: WORKSPACE_ID, instanceId: INSTANCE_ID, generation: 1,
      expiresAt: now - 10, hardExpiresAt: now - 5, lastRenewalAt: now - 10, state: 'active'
    });
    harness.journal.setLeaseState(WORKSPACE_ID, 'expired');
    const outcome = await call(wsReq('lease.set', {
      expiresAt: now + 99999, hardExpiresAt: now + 99999
    }));
    expect(outcome).toMatchObject({ kind: 'result' });
    const eff = (outcome as { result: { effective: { expiresAt: number; hardExpiresAt: number } } }).result.effective;
    // hardExpiresAt is monotonic non-increasing: the stored past hard cap wins.
    expect(eff.hardExpiresAt).toBeLessThanOrEqual(now - 5);
    expect(eff.expiresAt).toBeLessThanOrEqual(eff.hardExpiresAt);
    // Ops remain fenced — the "renewal" cannot resurrect the workspace.
    await expect(call(wsReq('exec.run', {
      opId: 'op-hard', argv: ['/bin/true'], environment: {}, timeoutMs: 1000, maxBytes: 1024
    }))).rejects.toMatchObject({ code: 'EXPIRED' });
  });

  it('gap window: active lease past deadline → vm.stop and vm.status still work', async () => {
    admitWorkspace('running');
    const past = Math.floor(Date.now() / 1000) - 10;
    harness.journal.setLease({
      workspaceId: WORKSPACE_ID, instanceId: INSTANCE_ID, generation: 1,
      expiresAt: past, hardExpiresAt: past + 100, lastRenewalAt: past, state: 'active'
    });
    // Watchdog has NOT run: state is still 'active', deadline already passed.
    const status = await call(wsReq('vm.status', {}));
    expect(status).toMatchObject({ kind: 'result' });
    const stop = await call(wsReq('vm.stop', {}));
    expect(stop).toMatchObject({ kind: 'result' });
    // After the stop lands, offline export on the stopped VM is reachable
    // even before the watchdog marks the lease expired.
    const outcome = await call(wsReq('vm.export', exportParams));
    expect(outcome).toMatchObject({ kind: 'download' });
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

// -- round-2 core regressions ----------------------------------------------------

describe('round-2: attestation shape, lease fencing, session binding, exec.run transport', () => {
  it('assertSupervisorShape tolerates volatile.* runtime keys but still rejects raw.*', async () => {
    // Admit once with network-none (matches the vm.start param below and
    // skips guest provisioning — the shape gate still runs on the instance).
    const vmName = vmNameForWorkspace(WORKSPACE_ID);
    harness.journal.recordWorkspaceAdmit({
      workspaceId: WORKSPACE_ID, vmName, instanceId: INSTANCE_ID,
      templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST,
      generation: 1, networkProfile: 'network-none'
    });
    harness.journal.setWorkspaceState(WORKSPACE_ID, 'stopped');
    harness.journal.acceptGeneration(WORKSPACE_ID, 1);
    harness.incus.instances.set(vmName, makeInstance(vmName, 'Stopped'));
    const inst = harness.incus.instances.get(vmName)!;
    inst.expandedConfig['volatile.uuid'] = 'deadbeef-1234';
    inst.expandedConfig['volatile.last_state.ready'] = 'true';
    inst.expandedConfig['volatile.eth0.hwaddr'] = '02:00:00:00:00:07';
    // raw.* is rejected FIRST while the instance is still stopped — a
    // successful start would make the second call early-return on the
    // already-running path without re-attesting.
    inst.expandedConfig['raw.lxc'] = 'evil';
    await expect(call(wsReq('vm.start', { networkProfile: 'network-none' }, { idempotencyKey: 'raw-key-1' })))
      .rejects.toMatchObject({ code: 'VM_ATTESTATION_FAILED' });
    // With raw.* removed the volatile keys alone pass the shape gate; the
    // agent probe then fails on the fake exec transport — anything BUT
    // VM_ATTESTATION_FAILED proves volatile.* was tolerated.
    delete inst.expandedConfig['raw.lxc'];
    await expect(call(wsReq('vm.start', { networkProfile: 'network-none' }, { idempotencyKey: 'vol-key-1' })))
      .rejects.not.toMatchObject({ code: 'VM_ATTESTATION_FAILED' });
  });

  it('a backdated issuedAt cannot smuggle a request past the lease deadline', async () => {
    admitWorkspace('running');
    const past = Math.floor(Date.now() / 1000) - 10;
    harness.journal.setLease({
      workspaceId: WORKSPACE_ID, instanceId: INSTANCE_ID, generation: 1,
      expiresAt: past, hardExpiresAt: past + 100, lastRenewalAt: past, state: 'active'
    });
    // issuedAt claims a time BEFORE the deadline; wall clock is already past it.
    // Live ops stay fenced; lifecycle ops are exempt by policy.
    const backdated = (past - 50) * 1000;
    await expect(call(wsReq('exec.run', {
      opId: 'op-back', argv: ['/bin/true'], environment: {}, timeoutMs: 1000, maxBytes: 1024
    }, { issuedAt: backdated }))).rejects.toMatchObject({ code: 'EXPIRED' });
    const status = await call(wsReq('vm.status', {}, { issuedAt: backdated }));
    expect(status).toMatchObject({ kind: 'result' });
  });

  it('an expired lease fences exec.run even while the journal still says running', async () => {
    admitWorkspace('running');
    // Divergent state the deadline fence cannot see: lease marked 'expired'
    // while its deadline is still in the future (e.g. watchdog raced a
    // renewal). Execution ops must still be fenced; lifecycle stays open.
    const now = Math.floor(Date.now() / 1000);
    harness.journal.setLease({
      workspaceId: WORKSPACE_ID, instanceId: INSTANCE_ID, generation: 1,
      expiresAt: now + 500, hardExpiresAt: now + 700, lastRenewalAt: now, state: 'active'
    });
    harness.journal.setLeaseState(WORKSPACE_ID, 'expired');
    await expect(call(wsReq('exec.run', {
      opId: 'op-exp', argv: ['/bin/true'], environment: {}, timeoutMs: 1000, maxBytes: 1024
    }))).rejects.toMatchObject({ code: 'EXPIRED' });
    // Cleanup/lifecycle ops remain reachable.
    const stop = await call(wsReq('vm.stop', {}));
    expect(stop).toMatchObject({ kind: 'result' });
  });

  it('session controls bind the complete workspace identity (instanceId+generation)', async () => {
    const { IncusExecSession } = await import('../src/incus-exec.js');
    const fakeSession = {
      writeStdin: () => true, stdinEof: () => undefined, waitStdinDrain: async () => undefined,
      signal: () => true, resize: () => true, controlClose: async () => undefined,
      closeAll: () => undefined, hasExited: false, exitInfo: undefined,
      operationPath: '/1.0/operations/fake-exec'
    };
    const spy = vi.spyOn(IncusExecSession, 'open').mockResolvedValue(fakeSession as never);
    try {
      admitWorkspace('running');
      await harness.sessions.openSession({
        sessionId: 'sess-bind-1', workspaceId: WORKSPACE_ID,
        vmName: vmNameForWorkspace(WORKSPACE_ID), instanceId: INSTANCE_ID, generation: 1,
        argv: ['/bin/sh'], environment: {}, channel: fakeChannel, onClosed: () => undefined
      });
      const owner = { workspaceId: WORKSPACE_ID, vmName: vmNameForWorkspace(WORKSPACE_ID), instanceId: INSTANCE_ID, generation: 1 };
      // writeStdin is synchronous — wrap in a thunk for rejection assertions.
      // Wrong generation → NOT_FOUND (never a cross-generation control channel).
      expect(() => harness.sessions.writeStdin('sess-bind-1', 0, 'eA==', undefined, { ...owner, generation: 99 }))
        .toThrowError(/unknown exec session/);
      // Wrong workspace → NOT_FOUND.
      expect(() => harness.sessions.writeStdin('sess-bind-1', 0, 'eA==', undefined, { ...owner, workspaceId: 'ws_otherworkspace000000002' }))
        .toThrowError(/unknown exec session/);
      // Correct complete identity → accepted.
      expect(harness.sessions.writeStdin('sess-bind-1', 0, 'eA==', undefined, owner)).toEqual({ acceptedBytes: 1 });
    } finally {
      spy.mockRestore();
    }
  });

  it('exec.run streams large results as download bytes and journals the full outcome', async () => {
    admitWorkspace('running');
    const big = 'x'.repeat(600 * 1024);
    const spy = vi.spyOn(harness.sessions, 'openAndCapture').mockResolvedValue({
      opId: 'op-big', exitCode: 0, signal: null,
      stdout: big, stderr: 'err-tail', truncated: false, timedOut: false
    });
    try {
      const req = wsReq('exec.run', {
        opId: 'op-big', argv: ['/bin/cat'], environment: {}, timeoutMs: 5000, maxBytes: 1024 * 1024
      });
      const outcome = await call(req);
      expect(outcome.kind).toBe('download');
      const dl = outcome as {
        maxBytes: number;
        streamDigest?: { sha256: string; bytes: number };
        produce: (emit: (c: Buffer) => Promise<void>) => Promise<unknown>;
      };
      expect(dl.maxBytes).toBe(8 + Buffer.byteLength(big, 'utf8') + Buffer.byteLength('err-tail', 'utf8'));
      expect(dl.streamDigest?.bytes).toBe(dl.maxBytes);
      const chunks: Buffer[] = [];
      const trailer = await dl.produce(async (c) => { chunks.push(c); });
      const payload = Buffer.concat(chunks);
      // stream-digest covers the exact wire payload.
      const { createHash } = await import('node:crypto');
      expect(dl.streamDigest?.sha256).toBe(createHash('sha256').update(payload).digest('hex'));
      const stdoutLen = payload.readBigUInt64BE(0);
      expect(Number(stdoutLen)).toBe(Buffer.byteLength(big, 'utf8'));
      expect(payload.subarray(8, 8 + Number(stdoutLen)).toString('utf8')).toBe(big);
      expect(payload.subarray(8 + Number(stdoutLen)).toString('utf8')).toBe('err-tail');
      // Trailer is a schema-valid ExecRunResult with emptied streams.
      expect(trailer).toMatchObject({ opId: 'op-big', exitCode: 0, stdout: '', stderr: '', timedOut: false });
      // Idempotent replay of a LARGE result re-uses the framed download path
      // (never an oversized unary frame) and yields the same payload.
      const replay = await call(req);
      expect(replay.kind).toBe('download');
      const replayDl = replay as typeof dl;
      const replayChunks: Buffer[] = [];
      await replayDl.produce(async (c) => { replayChunks.push(c); });
      expect(Buffer.concat(replayChunks).equals(payload)).toBe(true);
    } finally {
      spy.mockRestore();
    }
  });

  it('exec.run keeps small results on the unary path unchanged', async () => {
    admitWorkspace('running');
    const spy = vi.spyOn(harness.sessions, 'openAndCapture').mockResolvedValue({
      opId: 'op-small', exitCode: 0, signal: null,
      stdout: 'hi', stderr: '', truncated: false, timedOut: false
    });
    try {
      const outcome = await call(wsReq('exec.run', {
        opId: 'op-small', argv: ['/bin/echo'], environment: {}, timeoutMs: 5000, maxBytes: 1024
      }));
      expect(outcome).toMatchObject({ kind: 'result', result: { stdout: 'hi', stderr: '' } });
    } finally {
      spy.mockRestore();
    }
  });

  it('file.list maps native filename arrays into public entries via one guest stat probe', async () => {
    admitWorkspace('running');
    harness.incus.listNames = ['b.txt', 'adir'];
    const spy = vi.spyOn(harness.sessions, 'openAndCapture').mockResolvedValue({
      opId: 'liststat:x', exitCode: 0, signal: null,
      stdout: JSON.stringify([
        { name: 'adir', type: 'directory' },
        { name: 'b.txt', type: 'file', size: 3, mtime: 1700000000000 }
      ]),
      stderr: '', truncated: false, timedOut: false
    });
    try {
      const outcome = await call(wsReq('file.list', { guestPath: '/workspace' }));
      const result = (outcome as { result: { entries: Array<Record<string, unknown>> } }).result;
      expect(result.entries).toEqual([
        { name: 'adir', type: 'directory' },
        { name: 'b.txt', type: 'file', size: 3, mtime: 1700000000000 }
      ]);
      // Sorted by name; the probe ran exactly once for the page.
      expect(spy).toHaveBeenCalledTimes(1);
    } finally {
      spy.mockRestore();
    }
  });

  it('file.list on an empty directory never invokes the guest probe', async () => {
    admitWorkspace('running');
    harness.incus.listNames = [];
    const spy = vi.spyOn(harness.sessions, 'openAndCapture');
    try {
      const outcome = await call(wsReq('file.list', { guestPath: '/workspace' }));
      expect((outcome as { result: { entries: unknown[] } }).result.entries).toEqual([]);
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  it('failed provisioning + failed stop reports UNKNOWN, never a clean retryable failure', async () => {
    admitWorkspace('stopped');
    harness.incus.stopFails = true;
    // Agent probe succeeds; every networkctl step fails → provision throws.
    const spy = vi.spyOn(harness.sessions, 'openAndCapture').mockImplementation(async (input: { argv: string[] }) => {
      const joined = input.argv.join(' ');
      if (joined.includes('networkctl')) {
        return { opId: 'net:x', exitCode: 1, signal: null, stdout: '', stderr: 'netfail', truncated: false, timedOut: false };
      }
      return { opId: 'probe:x', exitCode: 0, signal: null, stdout: '', stderr: '', truncated: false, timedOut: false };
    });
    try {
      await expect(call(wsReq('vm.start', { networkProfile: 'dependency-access' })))
        .rejects.toMatchObject({ unknown: true });
    } finally {
      spy.mockRestore();
    }
  });

  it('failed provisioning with verified stop surfaces the retryable provision error', async () => {
    admitWorkspace('stopped');
    const spy = vi.spyOn(harness.sessions, 'openAndCapture').mockImplementation(async (input: { argv: string[] }) => {
      const joined = input.argv.join(' ');
      if (joined.includes('networkctl')) {
        return { opId: 'net:x', exitCode: 1, signal: null, stdout: '', stderr: 'netfail', truncated: false, timedOut: false };
      }
      return { opId: 'probe:x', exitCode: 0, signal: null, stdout: '', stderr: '', truncated: false, timedOut: false };
    });
    try {
      await expect(call(wsReq('vm.start', { networkProfile: 'dependency-access' })))
        .rejects.toMatchObject({ code: 'VM_SUPERVISOR_UNAVAILABLE', retryable: true });
      // Journal must NOT claim running — the workspace was stopped fail-closed.
      expect(harness.journal.getWorkspace(WORKSPACE_ID)?.state).toBe('stopped');
    } finally {
      spy.mockRestore();
    }
  });
});

describe('late-batch-a: exec.run durability/bounds + file.list paging', () => {
  it('exec.run replay returns the download outcome even when produce never ran', async () => {
    admitWorkspace('running');
    const big = 'y'.repeat(600 * 1024);
    const spy = vi.spyOn(harness.sessions, 'openAndCapture').mockResolvedValue({
      opId: 'op-noproduce', exitCode: 0, signal: null,
      stdout: big, stderr: '', truncated: false, timedOut: false
    });
    try {
      const req = wsReq('exec.run', {
        opId: 'op-noproduce', argv: ['/bin/cat'], environment: {}, timeoutMs: 5000, maxBytes: 1024 * 1024
      });
      const first = await call(req);
      expect(first.kind).toBe('download');
      // Client disconnected before stream-start/produce — the command result
      // is already known, so the durable record must be complete: replay
      // returns the same framed outcome, never pending→UNKNOWN.
      const replay = await call(req);
      expect(replay.kind).toBe('download');
      const chunks: Buffer[] = [];
      const trailer = await (replay as {
        produce: (emit: (c: Buffer) => Promise<void>) => Promise<unknown>;
      }).produce(async (c) => { chunks.push(c); });
      expect(trailer).toMatchObject({ opId: 'op-noproduce', stdout: '', stderr: '' });
      expect(Buffer.concat(chunks).length).toBeGreaterThan(600 * 1024);
    } finally {
      spy.mockRestore();
    }
  });

  it('exec.run bounds UTF-8-expanded output deterministically per request maxBytes', async () => {
    admitWorkspace('running');
    // 5.6M '€' chars → ~16.8MiB UTF-8 per stream; two streams exceed the
    // 32MiB+8 payload bound. Request maxBytes=10MiB → per-stream cap
    // min(3*maxBytes,16MiB)=16MiB → trimmed at a code-point boundary.
    const chunk = '€'.repeat(5_600_000);
    const spy = vi.spyOn(harness.sessions, 'openAndCapture').mockResolvedValue({
      opId: 'op-utf8', exitCode: 0, signal: null,
      stdout: chunk, stderr: chunk, truncated: false, timedOut: false
    });
    try {
      const req = wsReq('exec.run', {
        opId: 'op-utf8', argv: ['/bin/cat'], environment: {}, timeoutMs: 5000, maxBytes: 10_485_760
      });
      const outcome = await call(req);
      expect(outcome.kind).toBe('download');
      const dl = outcome as {
        maxBytes: number;
        produce: (emit: (c: Buffer) => Promise<void>) => Promise<unknown>;
      };
      expect(dl.maxBytes).toBeLessThanOrEqual(2 * 16_777_216 + 8);
      const chunks: Buffer[] = [];
      const trailer = await dl.produce(async (c) => { chunks.push(c); });
      const payload = Buffer.concat(chunks);
      expect(payload.length).toBe(dl.maxBytes);
      const stdoutLen = Number(payload.readBigUInt64BE(0));
      const stdoutBytes = payload.subarray(8, 8 + stdoutLen);
      const stderrBytes = payload.subarray(8 + stdoutLen);
      expect(stdoutBytes.length).toBeLessThanOrEqual(16 * 1024 * 1024);
      expect(stderrBytes.length).toBeLessThanOrEqual(16 * 1024 * 1024);
      // Delivered streams stay valid UTF-8 — truncation never splits a
      // code point into corrupt bytes.
      const stdoutText = stdoutBytes.toString('utf8');
      expect(Buffer.byteLength(stdoutText, 'utf8')).toBe(stdoutBytes.length);
      expect(trailer).toMatchObject({ opId: 'op-utf8', truncated: true, stdout: '', stderr: '' });
      // Deterministic: an idempotent replay yields the identical payload.
      const replay = await call(req);
      const replayChunks: Buffer[] = [];
      await (replay as typeof dl).produce(async (c) => { replayChunks.push(c); });
      expect(Buffer.concat(replayChunks).equals(payload)).toBe(true);
    } finally {
      spy.mockRestore();
    }
  });

  it('file.list stats only the requested page via stdin, never the whole directory', async () => {
    admitWorkspace('running');
    harness.incus.listNames = Array.from({ length: 1001 }, (_, i) => `f${String(i).padStart(4, '0')}`);
    const probed: string[][] = [];
    const spy = vi.spyOn(harness.sessions, 'openAndCapture').mockImplementation(
      async (input: { stdinBase64?: string }) => {
        const names = input.stdinBase64 !== undefined
          ? (JSON.parse(Buffer.from(input.stdinBase64, 'base64').toString('utf8')) as string[])
          : [];
        probed.push(names);
        return {
          opId: 'liststat:x', exitCode: 0, signal: null,
          stdout: JSON.stringify(names.map((n) => ({ name: n, type: 'file', size: 1, mtime: 1 }))),
          stderr: '', truncated: false, timedOut: false
        };
      }
    );
    try {
      await call(wsReq('file.list', { guestPath: '/workspace' }));
      await call(wsReq('file.list', { guestPath: '/workspace', cursor: 'o:1000' }));
      expect(probed).toHaveLength(2);
      expect(probed[0]).toHaveLength(1000);
      // The second page must probe ONLY its single name — the whole-dir
      // scandir is what overflowed the 2MiB capture bound on large dirs.
      expect(probed[1]).toEqual(['f1000']);
    } finally {
      spy.mockRestore();
    }
  });
});

describe('lifecycle admission and identity edge cases (gap regressions)', () => {
  const probeOk = {
    opId: 'probe', exitCode: 0, signal: null, stdout: '', stderr: '',
    truncated: false, timedOut: false
  } as never;

  it('vm.start reconciles its own verified-stopped journal row before admission', async () => {
    // Journal says 'running' but the live instance was stopped out-of-band.
    // maxActive=1: if checkAdmission counted the stale own row, admission
    // would deny — the verified-stopped row must be reconciled first.
    const vmName = vmNameForWorkspace(WORKSPACE_ID);
    harness.journal.recordWorkspaceAdmit({
      workspaceId: WORKSPACE_ID, vmName, instanceId: INSTANCE_ID,
      templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST,
      generation: 1, networkProfile: 'network-none'
    });
    harness.journal.setWorkspaceState(WORKSPACE_ID, 'running');
    harness.journal.acceptGeneration(WORKSPACE_ID, 1);
    const inst = makeInstance(vmName, 'Running');
    harness.incus.instances.set(vmName, inst);
    inst.status = 'Stopped';
    inst._status = 'Stopped';
    vi.spyOn(harness.sessions, 'openAndCapture').mockResolvedValue(probeOk);
    const outcome = await call(wsReq('vm.start', { networkProfile: 'network-none' }));
    expect(outcome).toMatchObject({ kind: 'result', result: { state: 'running' } });
    expect(harness.incus.stateCalls).toContainEqual({ name: vmName, action: 'start' });
    expect(harness.journal.getWorkspace(WORKSPACE_ID)?.state).toBe('running');
  });

  it('vm.start on an already-running instance re-runs guest-network provisioning', async () => {
    // A retry after failed provision+stop lands on the running branch — it
    // must re-verify guest networking, never blind-admit.
    admitWorkspace('running');
    const provisioner = vi.fn(async () => undefined);
    const config = makeConfig(dir);
    const handler2 = createSupervisorHandler({
      config, journal: harness.journal,
      digester: new RequestDigester(join(dir, 'hmac-key3')),
      incus: harness.incus.asClient(), incusSocketPath: config.incusSocketPath,
      lifecycle: new VmLifecycle({ config, journal: harness.journal, incus: harness.incus.asClient(), guard: async () => harness.guard }),
      sessions: harness.sessions,
      guard: async () => harness.guard,
      networkPlan: async () => makePlanner(),
      guestNetworkProvisioner: provisioner,
      execFile: async () => ({ exitCode: 0, stdout: '', stderr: '', timedOut: false, truncated: false })
    });
    const outcome = await handler2(wsReq('vm.start', { networkProfile: 'dependency-access' }), ctx());
    expect(outcome).toMatchObject({ kind: 'result', result: { state: 'running' } });
    expect(provisioner).toHaveBeenCalledOnce();
  });

  it('vm.start fails closed when re-provisioning a running instance fails', async () => {
    admitWorkspace('running');
    const provisioner = vi.fn(async () => { throw new Error('netplan push failed'); });
    const config = makeConfig(dir);
    const handler2 = createSupervisorHandler({
      config, journal: harness.journal,
      digester: new RequestDigester(join(dir, 'hmac-key4')),
      incus: harness.incus.asClient(), incusSocketPath: config.incusSocketPath,
      lifecycle: new VmLifecycle({ config, journal: harness.journal, incus: harness.incus.asClient(), guard: async () => harness.guard }),
      sessions: harness.sessions,
      guard: async () => harness.guard,
      networkPlan: async () => makePlanner(),
      guestNetworkProvisioner: provisioner,
      execFile: async () => ({ exitCode: 0, stdout: '', stderr: '', timedOut: false, truncated: false })
    });
    await expect(handler2(wsReq('vm.start', { networkProfile: 'dependency-access' }), ctx()))
      .rejects.toThrow(/provisioning failed/);
    // Fail-closed: the unverified running instance was stopped, not admitted.
    expect(harness.incus.stateCalls.filter((c) => c.action === 'stop').length).toBeGreaterThan(0);
  });

  it('vm.create refuses when the journaled name now holds a foreign stopped instance', async () => {
    admitWorkspace('stopped');
    const vmName = vmNameForWorkspace(WORKSPACE_ID);
    const before = harness.incus.createCalls.length;
    // The journaled name was replaced while the supervisor was down: a
    // foreign stopped instance squats on it. Identity must be proven.
    harness.incus.instances.set(vmName, makeInstance(vmName, 'Stopped', 'ws_foreign0000000000000000', '99999999-8888-4777-8666-555555555555'));
    await expect(call(wsReq('vm.create', {
      instanceId: INSTANCE_ID, networkProfile: 'network-none',
      templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST
    }))).rejects.toMatchObject({ code: 'VM_IDENTITY_MISMATCH' });
    expect(harness.incus.createCalls).toHaveLength(before);
  });
});

describe('streamGuestTar slow-reader pacing', () => {
  it('pauses guest output above the emit high-water mark and resumes after drain', async () => {
    const { IncusExecSession } = await import('../src/incus-exec.js');
    let capturedEvents: {
      onStdout?: (c: Buffer) => void;
      onStderr?: (c: Buffer) => void;
      onMeta?: (m: unknown) => void;
      onExit?: (i: { exitCode: number | null; signal: string | null; error?: string }) => void;
      onTransportError?: (e: Error) => void;
    } | undefined;
    const fakeSession = {
      pauseOutputChannels: vi.fn(),
      resumeOutputChannels: vi.fn(),
      signal: vi.fn(),
      closeAll: vi.fn(),
      writeStdin: () => true
    };
    const spy = vi.spyOn(IncusExecSession, 'open').mockImplementation(async (_c, _s, _v, _spec, events) => {
      capturedEvents = events as never;
      return fakeSession as never;
    });
    try {
      // Slow consumer: the first emit stays pending until released.
      let releaseEmit!: () => void;
      const emitGate = new Promise<void>((r) => { releaseEmit = r; });
      const emitted: number[] = [];
      const emit = vi.fn(async (chunk: Buffer) => {
        emitted.push(chunk.length);
        await emitGate;
      });
      const pull = harness.sessions.streamGuestTar({
        workspaceId: WORKSPACE_ID,
        vmName: vmNameForWorkspace(WORKSPACE_ID),
        guestPath: '/workspace/big',
        maxBytes: 64 * 1024 * 1024,
        emit
      });
      await new Promise((r) => setTimeout(r, 20));
      expect(capturedEvents).toBeDefined();
      // Flood 6MiB while the consumer is blocked: >4MiB high-water → pause.
      for (let i = 0; i < 6; i += 1) {
        capturedEvents!.onStdout!(Buffer.alloc(1024 * 1024));
      }
      expect(fakeSession.pauseOutputChannels).toHaveBeenCalled();
      // Drain the consumer: pending emits fall below 1MiB → resume.
      releaseEmit();
      await new Promise((r) => setTimeout(r, 30));
      expect(fakeSession.resumeOutputChannels).toHaveBeenCalled();
      // Native exit resolves the pull with the accumulated digest.
      capturedEvents!.onExit!({ exitCode: 0, signal: null });
      const result = await pull;
      expect(result.bytes).toBe(6 * 1024 * 1024);
      expect(result.sha256).toMatch(/^[0-9a-f]{64}$/);
      expect(emitted).toHaveLength(6);
    } finally {
      spy.mockRestore();
    }
  });

  it('rejects LIMIT_EXCEEDED and tears down when the op timeout fires while emit-paused', async () => {
    const { IncusExecSession } = await import('../src/incus-exec.js');
    let capturedEvents: {
      onStdout?: (c: Buffer) => void;
      onStderr?: (c: Buffer) => void;
      onMeta?: (m: unknown) => void;
      onExit?: (i: { exitCode: number | null; signal: string | null; error?: string }) => void;
      onTransportError?: (e: Error) => void;
    } | undefined;
    const fakeSession = {
      pauseOutputChannels: vi.fn(),
      resumeOutputChannels: vi.fn(),
      signal: vi.fn(),
      closeAll: vi.fn(),
      writeStdin: () => true
    };
    const spy = vi.spyOn(IncusExecSession, 'open').mockImplementation(async (_c, _s, _v, _spec, events) => {
      capturedEvents = events as never;
      return fakeSession as never;
    });
    try {
      // Consumer that NEVER drains: every emit stays pending, so
      // pendingEmitBytes stays above the 4MiB high-water and the guest read
      // channels remain paused when the operation-level timeout fires.
      const emit = vi.fn(() => new Promise<void>(() => {}));
      const pull = harness.sessions.streamGuestTar({
        workspaceId: WORKSPACE_ID,
        vmName: vmNameForWorkspace(WORKSPACE_ID),
        guestPath: '/workspace/big',
        maxBytes: 64 * 1024 * 1024,
        timeoutMs: 80,
        emit
      });
      await new Promise((r) => setTimeout(r, 20));
      expect(capturedEvents).toBeDefined();
      for (let i = 0; i < 6; i += 1) {
        capturedEvents!.onStdout!(Buffer.alloc(1024 * 1024));
      }
      // Paused state is real at timeout time: >4MiB pending, never drained.
      expect(fakeSession.pauseOutputChannels).toHaveBeenCalled();
      expect(fakeSession.resumeOutputChannels).not.toHaveBeenCalled();
      const err = await pull.then(
        () => { throw new Error('pull should have rejected'); },
        (e: unknown) => e
      );
      expect(err).toMatchObject({ code: 'LIMIT_EXCEEDED' });
      expect(String((err as Error).message)).toContain('pullTree timed out');
      // Timeout teardown: SIGKILL the guest exec and close every channel.
      expect(fakeSession.signal).toHaveBeenCalledWith('SIGKILL');
      expect(fakeSession.closeAll).toHaveBeenCalledTimes(1);
      // Post-settle events are inert: no orphan emissions or lifecycle calls.
      const pauseCalls = fakeSession.pauseOutputChannels.mock.calls.length;
      const closeCalls = fakeSession.closeAll.mock.calls.length;
      capturedEvents!.onStdout!(Buffer.alloc(1024));
      capturedEvents!.onStderr!(Buffer.alloc(1024));
      capturedEvents!.onExit!({ exitCode: 0, signal: null });
      await new Promise((r) => setTimeout(r, 10));
      expect(fakeSession.pauseOutputChannels.mock.calls.length).toBe(pauseCalls);
      expect(fakeSession.closeAll.mock.calls.length).toBe(closeCalls);
    } finally {
      spy.mockRestore();
    }
  });
});
