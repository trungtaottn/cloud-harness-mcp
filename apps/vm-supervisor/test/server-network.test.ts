import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { VmSupervisorConfig } from '../src/config.js';
import { VmJournal } from '../src/journal.js';
import { RequestDigester } from '../src/request-digest.js';
import type { IncusClient, IncusInstanceInfo } from '../src/incus.js';
import { isManagedInstanceConfig, vmNameForWorkspace } from '../src/identity.js';
import { VmLifecycle } from '../src/lifecycle.js';
import { VmSessionManager } from '../src/sessions.js';
import { createVmNetworkGuard } from '../src/network/ops.js';
import { withGuardLock } from '../src/network/lock.js';
import { makeGuardIncusProbe } from '../src/runtime.js';
import {
  loadVmWorkspaceSubjectPlanner,
  resetVmWorkspaceSubjectPlannerForTests
} from '../src/network-plan.js';
import { VmNetworkGuardNotImplementedError, type VmNetworkGuard, type VmNetworkGuardConfig } from '../src/network-ops.js';
import {
  canonicalNftTable,
  deriveVmName,
  nicDeviceStamp,
  planWorkspaceSubject,
  validateGuardConfig
} from '../src/network/policy.js';
import type { VmNetworkSubject } from '../src/network/policy.js';
import { createSupervisorHandler } from '../src/server.js';
import type { WireHandlerOutcome, WireRequestContext, WireSessionChannel } from '../src/transport.js';
import { createFakeKernel, nftTableDiffs } from './network/fake-kernel.js';
import type { FakeKernel } from './network/fake-kernel.js';

/**
 * REAL integration: the supervisor dispatcher, the canonical subject planner
 * (network-plan.ts → network/policy.ts) and the phase-05 guard
 * (network/ops.ts) run TOGETHER against an injected fake kernel + fake Incus.
 * The stamped NIC at vm.create, the programmed bridge/nft/permits and the
 * attested subject are all derived by the SAME canonical functions — this is
 * the create → program → attest sequence the independent review (B4) proved
 * was previously inconsistent. No live kernel/Incus is touched; real
 * nft/iptables rendering and the guard service's cross-process repair remain
 * phase-11 live gates.
 */

const TEMPLATE_ID = 'cloudharness-vm-debian13';
const TEMPLATE_DIGEST = 'a'.repeat(64);
const WORKSPACE_ID = 'ws_integworkspace00000001';
const INSTANCE_ID = '11111111-2222-4333-8444-555555555555';
const CPUS = 4;
const MEMORY_BYTES = 8 * 1024 ** 3;
const DISK_BYTES = 4 * 1024 ** 3;
const UPLINK = 'enp7s0';

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
    uplink: UPLINK,
    dnsResolvers: ['1.1.1.1', '8.8.8.8'],
    nonpublicCidrs: [],
    poolPath: dir,
    maxTtlSeconds: 3600,
    maxActive: 4,
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

/** Cross-component call order log: tx guard ops and Incus state mutations. */
const eventOrder: string[] = [];

/** Incus fake that persists the create spec — the guard attests what was stamped. */
class FakeIncus {
  instances = new Map<string, FakeInstance>();
  createCalls: Array<{ name: string; config: Record<string, string>; devices: Record<string, Record<string, string>>; profiles: string[] }> = [];
  stateCalls: Array<{ name: string; action: string }> = [];

  asClient(): IncusClient {
    return {
      listInstances: async () => [...this.instances.values()],
      getInstance: async (name: string) => this.instances.get(name) ?? null,
      getInstanceState: async (name: string) => {
        const i = this.instances.get(name);
        return i === undefined ? null : { status: i.status, statusCode: 0 };
      },
      createInstance: async (spec: { name: string; config?: Record<string, string>; devices?: Record<string, Record<string, string>>; profiles?: string[] }) => {
        this.createCalls.push({
          name: spec.name,
          config: spec.config ?? {},
          devices: spec.devices ?? {},
          profiles: spec.profiles ?? []
        });
        this.instances.set(spec.name, {
          name: spec.name,
          status: 'Stopped',
          statusCode: 0,
          expandedConfig: { ...(spec.config ?? {}) },
          expandedDevices: { ...(spec.devices ?? {}) },
          profiles: [...(spec.profiles ?? [])],
          _status: 'Stopped'
        });
        return { synchronous: true };
      },
      setInstanceState: async (name: string, action: string) => {
        this.stateCalls.push({ name, action });
        eventOrder.push(`incus:${action}`);
        const i = this.instances.get(name);
        if (i !== undefined) {
          i.status = action === 'start' ? 'Running' : 'Stopped';
          i._status = i.status;
        }
        return { synchronous: true };
      },
      deleteInstance: async (name: string) => {
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

const fakeChannel: WireSessionChannel = {
  emitData: async () => undefined,
  emitMeta: () => undefined,
  emitEnd: () => undefined,
  open: true
} as unknown as WireSessionChannel;

function ctx(): WireRequestContext {
  return { channel: fakeChannel, signal: new AbortController().signal, closed: new Promise(() => undefined) };
}

let dir: string;
let kernel: FakeKernel;
let incus: FakeIncus;
let journal: VmJournal;
let guardConfig: VmNetworkGuardConfig;
let validated: ReturnType<typeof validateGuardConfig>;
let guard: VmNetworkGuard;
let txProgram: ReturnType<typeof vi.fn>;
let txAttest: ReturnType<typeof vi.fn>;
let txProgramTotal = 0;
let txAttestTotal = 0;
let planner: Awaited<ReturnType<typeof loadVmWorkspaceSubjectPlanner>>;
let handler: ReturnType<typeof createSupervisorHandler>;
let sessions: VmSessionManager;

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

function createParams(networkProfile: 'network-none' | 'dependency-access', instanceId = INSTANCE_ID) {
  return { instanceId, networkProfile, templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST };
}

function subjectFor(workspaceId: string): VmNetworkSubject {
  return planWorkspaceSubject(validated, { workspaceId, vmName: deriveVmName(workspaceId) });
}

async function call(raw: unknown): Promise<WireHandlerOutcome> {
  return handler(raw, ctx());
}

function stubAgentProbe(): void {
  vi.spyOn(sessions, 'openAndCapture').mockResolvedValue({
    opId: 'probe', exitCode: 0, signal: null, stdout: '', stderr: '', truncated: false, timedOut: false
  } as never);
}

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'vmsup-netint-'));
  eventOrder.length = 0;
  txProgramTotal = 0;
  txAttestTotal = 0;
  kernel = await createFakeKernel({
    links: [{ ifname: UPLINK, operstate: 'UP', addrs: [] }],
    routes: [{ dst: 'default', table: 'main', dev: UPLINK }],
    sysctls: { 'net.ipv4.ip_forward': '1' }
  });
  const config = makeConfig(dir);
  journal = new VmJournal(join(dir, 'journal.sqlite'));
  const digester = new RequestDigester(join(dir, 'hmac-key'));
  incus = new FakeIncus();
  guardConfig = {
    bridgePattern: 'chmbr%d',
    subnetPlan: '10.240.0.0/16',
    uplink: UPLINK,
    dnsResolvers: ['1.1.1.1', '8.8.8.8'],
    nonpublicCidrs: [],
    guardStatePath: join(kernel.workDir, 'guard-state.json')
  };
  validated = validateGuardConfig(guardConfig);
  const probe = makeGuardIncusProbe(incus.asClient(), isManagedInstanceConfig);
  const realGuard = createVmNetworkGuard({ config: guardConfig, incus: probe, execFile: kernel.exec });
  // Spy wrappers keep the REAL guard behavior (including the real
  // withStartTransaction → serialize()+withGuardLock) while exposing call
  // order/args. txProgram/txAttest wrap the real unlocked tx ops so tests
  // can assert what ran inside the lock window.
  guard = {
    program: vi.fn(realGuard.program),
    attest: vi.fn(realGuard.attest),
    tearDown: vi.fn(realGuard.tearDown),
    quarantine: vi.fn(realGuard.quarantine),
    withStartTransaction: vi.fn(async (args, fn) => realGuard.withStartTransaction(args, (tx) => {
      txProgram = vi.fn(async () => { txProgramTotal += 1; eventOrder.push('tx-program'); return tx.program(); });
      txAttest = vi.fn(async () => { txAttestTotal += 1; eventOrder.push('tx-attest'); return tx.attest(); });
      return fn({ program: txProgram, attest: txAttest });
    }))
  };
  resetVmWorkspaceSubjectPlannerForTests();
  planner = await loadVmWorkspaceSubjectPlanner(guardConfig);
  const lifecycle = new VmLifecycle({ config, journal, incus: incus.asClient(), guard: async () => guard });
  sessions = new VmSessionManager({
    journal, incus: incus.asClient(), incusSocketPath: config.incusSocketPath, lifecycle
  });
  handler = createSupervisorHandler({
    config, journal, digester, incus: incus.asClient(), incusSocketPath: config.incusSocketPath,
    lifecycle, sessions, guard: async () => guard, networkPlan: async () => planner,
    execFile: kernel.exec
  });
});

afterEach(async () => {
  vi.restoreAllMocks();
  journal.close();
  await kernel.dispose();
  rmSync(dir, { recursive: true, force: true });
});

describe('dependency-access: real create → program → attest → start', () => {
  it('stamps the canonical NIC at create; start programs, attests and starts', async () => {
    const vmName = vmNameForWorkspace(WORKSPACE_ID);
    const subject = subjectFor(WORKSPACE_ID);

    // ---- vm.create: NIC must equal nicDeviceStamp(planWorkspaceSubject(...))
    const created = await call(wsReq('vm.create', createParams('dependency-access')));
    expect(created).toMatchObject({ kind: 'result', result: { state: 'stopped' } });
    expect(incus.createCalls).toHaveLength(1);
    const spec = incus.createCalls[0]!;
    expect(spec.devices.eth0).toEqual(nicDeviceStamp(subject));
    expect(spec.devices.eth0!['host_name']).toBe(subject.tapName);
    expect(spec.devices.eth0!['host_name']!.length).toBeLessThanOrEqual(15);
    expect(spec.devices.eth0!['ipv4.address']).toBe(`${subject.guestIp}/${subject.prefixLength}`);
    // Create does NOT program the network — that is a start-time gate.
    expect(guard.program).not.toHaveBeenCalled();

    // ---- vm.start: program → attest → Incus start, all journaled-profile fenced
    stubAgentProbe();
    const started = await call(wsReq('vm.start', { networkProfile: 'dependency-access' }));
    expect(started).toMatchObject({ kind: 'result', result: { state: 'running' } });

    // Ordering inside ONE withStartTransaction: program BEFORE attest BEFORE
    // Incus start (a failed attest throws and never reaches start, as the
    // fencing tests prove). tx ops take no args — identity/profile ride on
    // the withStartTransaction args asserted below.
    expect(eventOrder.indexOf('tx-program')).toBeGreaterThanOrEqual(0);
    expect(eventOrder.indexOf('tx-program')).toBeLessThan(eventOrder.indexOf('tx-attest'));
    expect(eventOrder.indexOf('tx-attest')).toBeLessThan(eventOrder.indexOf('incus:start'));
    expect(incus.stateCalls).toContainEqual({ name: vmName, action: 'start' });

    // The transaction received the journaled identity + profile.
    const expectedIdentity = {
      workspaceId: WORKSPACE_ID, vmName, instanceId: INSTANCE_ID, generation: 1
    };
    expect(guard.withStartTransaction).toHaveBeenCalledWith(
      { identity: expectedIdentity, networkProfile: 'dependency-access' },
      expect.any(Function)
    );
    expect(txProgram).toHaveBeenCalledTimes(1);
    expect(txAttest).toHaveBeenCalledTimes(1);
    await expect(txAttest.mock.results[0]!.value)
      .resolves.toMatchObject({ ok: true });

    // Kernel reality after program: bridge UP with host /30, canonical nft, permits.
    const link = kernel.links.get(subject.bridgeName);
    expect(link).toBeDefined();
    expect(link!.operstate).toBe('UP');
    expect(link!.infoKind).toBe('bridge');
    expect(link!.addrs).toEqual([{ family: 'inet', local: subject.hostIp, prefixlen: 30 }]);
    expect(kernel.sysctls.get(`net.ipv6.conf.${subject.bridgeName}.disable_ipv6`)).toBe('1');
    // The fake kernel now models real `nft list table` normalization
    // (priority/counter rendering) — compare semantically, never by text.
    expect(nftTableDiffs(kernel.nftTableText, canonicalNftTable([subject], validated, UPLINK))).toEqual([]);
    const dockerUser = (kernel.ipTables.get('filter:DOCKER-USER') ?? '').split('\n').filter((l) => l.startsWith('-A '));
    expect(dockerUser.some((l) => l.includes(subject.bridgeName))).toBe(true);
    expect(journal.getWorkspace(WORKSPACE_ID)?.state).toBe('running');
  });

  it('a guard-service lock hold serializes the whole start transaction', async () => {
    await call(wsReq('vm.create', createParams('dependency-access')));
    stubAgentProbe();
    const workDir = dirname(guardConfig.guardStatePath);
    // Simulate the independent guard-service watcher mid-cycle: it holds the
    // SAME cross-process guard.lock while it would mutate kernel/claims. The
    // start transaction must queue behind that hold — program, attest and
    // Incus start may never run inside the watcher's window.
    const watcher = withGuardLock(workDir, async () => {
      eventOrder.push('watcher-hold');
      await new Promise((resolve) => setTimeout(resolve, 300));
      eventOrder.push('watcher-release');
    }, { timeoutMs: 15_000, pollMs: 10 });
    // Let the watcher win the mkdir race before vm.start queues behind it.
    await new Promise((resolve) => setTimeout(resolve, 50));

    const started = await call(wsReq('vm.start', { networkProfile: 'dependency-access' }));
    expect(started).toMatchObject({ kind: 'result', result: { state: 'running' } });
    await watcher;

    // Everything the transaction did happened strictly AFTER the watcher
    // released the shared lock — zero interleave window.
    const releaseAt = eventOrder.indexOf('watcher-release');
    expect(releaseAt).toBeGreaterThanOrEqual(0);
    for (const marker of ['tx-program', 'tx-attest', 'incus:start']) {
      expect(eventOrder.indexOf(marker)).toBeGreaterThan(releaseAt);
    }
  }, 20_000);

  it('network.program/attest ops agree with the stamped identity (journaled profile)', async () => {
    await call(wsReq('vm.create', createParams('dependency-access')));
    const subject = subjectFor(WORKSPACE_ID);

    const programmed = await call(wsReq('network.program', { networkProfile: 'dependency-access' }));
    expect(programmed).toMatchObject({ kind: 'result' });
    const programResult = (programmed as { result: Record<string, unknown> }).result;
    // The guard derived the SAME subject the supervisor stamped — B4 regression proof.
    expect(programResult['bridgeName']).toBe(subject.bridgeName);
    expect(programResult['guestIp']).toBe(subject.guestIp);

    const attested = await call(wsReq('network.attest', {}));
    expect(attested).toMatchObject({ kind: 'result', result: { ok: true } });
  });
});

describe('network-none', () => {
  it('create stamps no NIC; start runs the empty profile without touching bridges', async () => {
    const vmName = vmNameForWorkspace(WORKSPACE_ID);
    const created = await call(wsReq('vm.create', createParams('network-none')));
    expect(created).toMatchObject({ kind: 'result' });
    expect(incus.createCalls[0]!.devices.eth0).toBeUndefined();
    expect(incus.createCalls[0]!.devices.root).toBeDefined();

    stubAgentProbe();
    const started = await call(wsReq('vm.start', { networkProfile: 'network-none' }));
    expect(started).toMatchObject({ kind: 'result', result: { state: 'running' } });
    expect(guard.withStartTransaction).toHaveBeenCalledWith(
      expect.objectContaining({ networkProfile: 'network-none' }),
      expect.any(Function)
    );
    expect(txProgramTotal).toBe(1);
    expect(txAttestTotal).toBe(1);
    // No chmbr* bridge was created for this workspace.
    expect([...kernel.links.keys()].filter((n) => n.startsWith('chmbr'))).toEqual([]);
    expect(kernel.nftTableText).toBe('');
    expect(incus.stateCalls).toContainEqual({ name: vmName, action: 'start' });
  });
});

describe('collision + fencing', () => {
  it('rejects a second workspace deriving the same bridge slot before Incus mutation', async () => {
    await call(wsReq('vm.create', createParams('dependency-access')));
    const first = subjectFor(WORKSPACE_ID);

    // Find a workspaceId whose canonical slot collides (deterministic scan).
    let collidingId = '';
    let collidingInstance = '';
    for (let i = 0; i < 200_000; i += 1) {
      const candidate = `ws_col_${i.toString().padStart(24, '0')}`;
      const probe = planner.plan({ workspaceId: candidate, vmName: vmNameForWorkspace(candidate) });
      if (probe.bridgeName === first.bridgeName) {
        collidingId = candidate;
        collidingInstance = `33333333-3333-4333-8333-${i.toString().padStart(12, '0')}`;
        break;
      }
    }
    expect(collidingId).not.toBe('');

    await expect(call(wsReq('vm.create', createParams('dependency-access', collidingInstance), {
      workspaceId: collidingId, vmInstanceId: collidingInstance
    }))).rejects.toMatchObject({ code: 'CONFLICT' });
    // Early check fired BEFORE any Incus create for the colliding workspace.
    expect(incus.createCalls).toHaveLength(1);
    expect(journal.getWorkspace(collidingId)).toBeUndefined();
  });

  it('fences mismatched networkProfile on vm.start and network.program', async () => {
    await call(wsReq('vm.create', createParams('dependency-access')));
    await expect(call(wsReq('vm.start', { networkProfile: 'network-none' })))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(call(wsReq('network.program', { networkProfile: 'network-none' })))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(guard.program).not.toHaveBeenCalled();
    expect(guard.withStartTransaction).not.toHaveBeenCalled();
    expect(incus.stateCalls.filter((c) => c.action === 'start')).toHaveLength(0);
  });

  it('refuses network.program while the instance is running; re-start does not re-program', async () => {
    await call(wsReq('vm.create', createParams('dependency-access')));
    stubAgentProbe();
    await call(wsReq('vm.start', { networkProfile: 'dependency-access' }));
    expect(incus.instances.get(vmNameForWorkspace(WORKSPACE_ID))?.status).toBe('Running');
    const programCalls = (guard.program as ReturnType<typeof vi.fn>).mock.calls.length;
    const wstCalls = (guard.withStartTransaction as ReturnType<typeof vi.fn>).mock.calls.length;

    // Program under a live instance is refused before any kernel mutation.
    await expect(call(wsReq('network.program', { networkProfile: 'dependency-access' })))
      .rejects.toMatchObject({ code: 'CONFLICT' });
    expect((guard.program as ReturnType<typeof vi.fn>).mock.calls.length).toBe(programCalls);

    // vm.start on a running instance returns early — no second transaction.
    const again = await call(wsReq('vm.start', { networkProfile: 'dependency-access' }));
    expect(again).toMatchObject({ kind: 'result', result: { state: 'running' } });
    expect((guard.withStartTransaction as ReturnType<typeof vi.fn>).mock.calls.length).toBe(wstCalls);
    expect(txProgramTotal).toBe(1);
    expect(txAttestTotal).toBe(1);
  });
});

describe('fail-closed planner', () => {
  it('vm.create dependency-access fails closed when the policy module is unavailable', async () => {
    const config = makeConfig(dir);
    const failingHandler = createSupervisorHandler({
      config, journal, digester: new RequestDigester(join(dir, 'hmac-key2')),
      incus: incus.asClient(), incusSocketPath: config.incusSocketPath,
      lifecycle: new VmLifecycle({ config, journal, incus: incus.asClient(), guard: async () => guard }),
      sessions,
      guard: async () => guard,
      networkPlan: async () => { throw new VmNetworkGuardNotImplementedError('absent'); },
      execFile: kernel.exec
    });
    await expect(failingHandler(wsReq('vm.create', createParams('dependency-access')), ctx()))
      .rejects.toMatchObject({ code: 'VM_SUPERVISOR_UNAVAILABLE' });
    expect(incus.createCalls).toHaveLength(0);
  });
});
