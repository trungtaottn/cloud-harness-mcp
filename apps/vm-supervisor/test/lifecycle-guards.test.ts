import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { VmJournal } from '../src/journal.js';
import { VmLifecycle } from '../src/lifecycle.js';
import { identityConfigBlock } from '../src/identity.js';
import type { IncusClient, IncusInstanceInfo } from '../src/incus.js';
import type { VmSupervisorConfig } from '../src/config.js';

const dirs: string[] = [];
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'vm-lifecycle-guards-'));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

const WS = 'ws_lifecycle_abcdefghijklmnopqrstuvwxyz';
const INSTANCE = '3f6b2a1c-9d4e-4f5a-8b7c-6d5e4f3a2b1c';
const VM_NAME = 'chm-vm-' + 'a'.repeat(32);

function config(dir: string): VmSupervisorConfig {
  return {
    stateDir: dir, incusSocketPath: '/x', incusProject: 'default',
    guardStatePath: '/x', bridgePattern: 'chmbr%d', subnetPlan: '10.240.0.0/16',
    uplink: '', dnsResolvers: ['10.0.0.2'], nonpublicCidrs: [], poolPath: dir,
    maxTtlSeconds: 3600, maxActive: 1, cpus: 4, memoryBytes: 8 * 1024 ** 3,
    diskBytes: 20 * 1024 ** 3, poolReserveBytes: 1024 ** 3,
    templateId: 'tpl', templateDigest: 'b'.repeat(64)
  } as VmSupervisorConfig;
}

function instance(name: string, status: string, ws = WS, inst = INSTANCE): IncusInstanceInfo {
  return {
    name, status, statusCode: 0,
    expandedConfig: {
      ...identityConfigBlock({ workspaceId: ws, instanceId: inst, templateId: 'tpl', templateDigest: 'b'.repeat(64) }),
      'boot.autostart': 'false'
    },
    expandedDevices: {}, profiles: []
  };
}

function fakeIncus(overrides: Partial<Record<string, unknown>> = {}) {
  const calls = { stops: [] as string[], gets: [] as string[] };
  const client = {
    listInstances: async () => [],
    getInstance: async (name: string) => { calls.gets.push(name); return instance(name, 'Running'); },
    getInstanceState: async () => ({ status: 'Stopped', statusCode: 102 }),
    setInstanceState: async (name: string, action: string) => { calls.stops.push(`${name}:${action}`); return { synchronous: true }; },
    waitOperation: async () => ({ elapsedMs: 1, status: 'Success' }),
    ...overrides
  } as unknown as IncusClient;
  return { client, calls };
}

function makeLifecycle(dir: string, incus: IncusClient, extra: Record<string, unknown> = {}) {
  const journal = new VmJournal(join(dir, 'j.db'));
  journal.recordWorkspaceAdmit({
    workspaceId: WS, vmName: VM_NAME, instanceId: INSTANCE,
    templateId: 'tpl', templateDigest: 'b'.repeat(64), generation: 1, networkProfile: 'network-none'
  });
  journal.setWorkspaceState(WS, 'running');
  const lifecycle = new VmLifecycle({
    config: config(dir), journal, incus,
    guard: async () => { throw new Error('no guard'); },
    ...extra
  });
  return { journal, lifecycle };
}

describe('stopVerified identity gate', () => {
  it('refuses to stop a foreign instance occupying the journaled name', async () => {
    const dir = tempDir();
    const { client, calls } = fakeIncus({
      // Same name, FOREIGN identity — a squatter, not our VM.
      getInstance: async (name: string) => instance(name, 'Running', 'ws_other_abcdefghijklmnopqrstuvwxyz', 'other-inst')
    });
    const { journal, lifecycle } = makeLifecycle(dir, client);
    const result = await lifecycle.stopVerified(VM_NAME, WS, 'test');
    expect(result.outcome).toBe('unknown');
    expect(calls.stops).toEqual([]);
    journal.close();
  });

  it('stops a verified managed instance', async () => {
    const dir = tempDir();
    const { client, calls } = fakeIncus();
    const { journal, lifecycle } = makeLifecycle(dir, client);
    const result = await lifecycle.stopVerified(VM_NAME, WS, 'test');
    expect(result.outcome).toBe('stopped');
    expect(calls.stops).toEqual([`${VM_NAME}:stop`]);
    journal.close();
  });
});

describe('watchdog tick serialization', () => {
  it('concurrent ticks serialize on the lifecycle lock (single stop)', async () => {
    const dir = tempDir();
    let inFlight = 0;
    let maxInFlight = 0;
    const { client, calls } = fakeIncus({
      setInstanceState: async (name: string, action: string) => {
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise((r) => setTimeout(r, 20));
        inFlight -= 1;
        calls.stops.push(`${name}:${action}`);
        return { synchronous: true };
      }
    });
    const { journal, lifecycle } = makeLifecycle(dir, client, { unleasedGraceSeconds: 0 });
    // Force the unleased-grace path: workspace running, no lease, grace=0.
    await Promise.all([lifecycle.tick(), lifecycle.tick(), lifecycle.tick()]);
    expect(calls.stops.filter((s) => s.endsWith(':stop'))).toHaveLength(1);
    expect(maxInFlight).toBe(1);
    journal.close();
  });
});

describe('checkAdmission forStart', () => {
  function poolWithVolumes(dir: string, sizes: Record<string, number>): void {
    for (const [vm, size] of Object.entries(sizes)) {
      const vmDir = join(dir, 'virtual-machines', vm);
      mkdirSync(vmDir, { recursive: true });
      writeFileSync(join(vmDir, 'root.img'), Buffer.alloc(size));
    }
  }

  it('excludes the restarting workspace volume from retained bytes', async () => {
    const dir = tempDir();
    poolWithVolumes(dir, { [VM_NAME]: 1024 * 1024, 'chm-vm-other': 1024 * 1024 });
    const { client } = fakeIncus();
    const { journal } = makeLifecycle(dir, client);
    // Restart admission applies to a STOPPED workspace — a running row would
    // trip the maxActive cap before the disk math under test.
    journal.setWorkspaceState(WS, 'stopped');
    const cfg = config(dir);
    // Measure the OTHER volume's real st_blocks*512; the start requirement
    // must exclude only the workspace's own volume.
    const { statSync } = await import('node:fs');
    const otherBytes = Number(statSync(join(dir, 'virtual-machines', 'chm-vm-other', 'root.img')).blocks) * 512;
    const ownBytes = Number(statSync(join(dir, 'virtual-machines', VM_NAME, 'root.img')).blocks) * 512;
    expect(otherBytes).toBeGreaterThan(0);
    expect(ownBytes).toBeGreaterThan(0);
    // Free sits exactly at the start requirement → start admitted, create denied.
    const free = cfg.diskBytes + otherBytes + cfg.poolReserveBytes;
    const statfsFn = async () => ({ bavail: BigInt(Math.ceil(free / 4096)), bsize: 4096 });
    const lc = new VmLifecycle({
      config: cfg, journal, incus: client,
      guard: async () => { throw new Error('no guard'); },
      statfsFn
    });
    const startAdmission = await lc.checkAdmission({ forStart: true, workspaceId: WS });
    expect(startAdmission.admitted).toBe(true);
    const createAdmission = await lc.checkAdmission({ forStart: false });
    expect(createAdmission.admitted).toBe(false);
    journal.close();
  });
});

describe('checkAdmission running-row scan bound', () => {
  it('counts every running journal row — a live row ordered after stale claims still fences admission', async () => {
    const dir = tempDir();
    const journal = new VmJournal(join(dir, 'j.db'));
    // 256 crashed-stale 'running' claims (Incus reports them absent → they
    // reconcile to stopped) with the genuinely-live row created LAST. Any
    // bounded prefix scan would reconcile the stale rows and never reach
    // the live one, admitting a second VM under maxActive=1.
    for (let i = 0; i < 256; i++) {
      journal.recordWorkspaceAdmit({
        workspaceId: `ws_stale_${String(i).padStart(3, '0')}_abcdefghijklmnop`,
        vmName: `chm-vm-${String(i).padStart(32, '0')}`,
        instanceId: INSTANCE,
        templateId: 'tpl', templateDigest: 'b'.repeat(64),
        generation: 1, networkProfile: 'network-none'
      });
      journal.setWorkspaceState(`ws_stale_${String(i).padStart(3, '0')}_abcdefghijklmnop`, 'running');
    }
    // created_at has seconds precision — cross a second boundary so the live
    // row deterministically sorts AFTER all 256 stale claims.
    await new Promise((r) => setTimeout(r, 1_100));
    journal.recordWorkspaceAdmit({
      workspaceId: WS, vmName: VM_NAME, instanceId: INSTANCE,
      templateId: 'tpl', templateDigest: 'b'.repeat(64),
      generation: 1, networkProfile: 'network-none'
    });
    journal.setWorkspaceState(WS, 'running');
    const client = {
      listInstances: async () => [],
      getInstance: async (name: string) => (name === VM_NAME ? instance(name, 'Running') : null),
      getInstanceState: async () => ({ status: 'Stopped', statusCode: 102 }),
      setInstanceState: async () => ({ synchronous: true }),
      waitOperation: async () => ({ elapsedMs: 1, status: 'Success' })
    } as unknown as IncusClient;
    const lc = new VmLifecycle({
      config: config(dir), journal, incus: client,
      guard: async () => { throw new Error('no guard'); },
      // Isolate the running-row scan: report ample pool space so only the
      // admission count can deny.
      statfsFn: async () => ({ bavail: 1_000_000_000, bsize: 4096 })
    });
    const adm = await lc.checkAdmission({ forStart: false });
    expect(adm.admitted).toBe(false);
    journal.close();
  });

  it('reconciles stale running claims ordered after a verified live row in the same pass', async () => {
    const dir = tempDir();
    const journal = new VmJournal(join(dir, 'j.db'));
    // Live row FIRST, stale claims after it: with maxActive=1 the verdict is
    // already deny once the live row verifies, but the stale rows must still
    // be reconciled to 'stopped' in the same pass — not left 'running' until
    // some later scan happens to reach them.
    journal.recordWorkspaceAdmit({
      workspaceId: WS, vmName: VM_NAME, instanceId: INSTANCE,
      templateId: 'tpl', templateDigest: 'b'.repeat(64),
      generation: 1, networkProfile: 'network-none'
    });
    journal.setWorkspaceState(WS, 'running');
    // created_at has seconds precision — cross a second boundary so the stale
    // rows deterministically sort AFTER the live claim.
    await new Promise((r) => setTimeout(r, 1_100));
    for (const id of ['stale_a', 'stale_b']) {
      const wsid = `ws_${id}_abcdefghijklmnop`;
      journal.recordWorkspaceAdmit({
        workspaceId: wsid,
        vmName: `chm-vm-${id === 'stale_a' ? '1'.repeat(32) : '2'.repeat(32)}`,
        instanceId: INSTANCE,
        templateId: 'tpl', templateDigest: 'b'.repeat(64),
        generation: 1, networkProfile: 'network-none'
      });
      journal.setWorkspaceState(wsid, 'running');
    }
    const client = {
      listInstances: async () => [],
      getInstance: async (name: string) => (name === VM_NAME ? instance(name, 'Running') : null),
      getInstanceState: async () => ({ status: 'Stopped', statusCode: 102 }),
      setInstanceState: async () => ({ synchronous: true }),
      waitOperation: async () => ({ elapsedMs: 1, status: 'Success' })
    } as unknown as IncusClient;
    const lc = new VmLifecycle({
      config: config(dir), journal, incus: client,
      guard: async () => { throw new Error('no guard'); },
      statfsFn: async () => ({ bavail: 1_000_000_000, bsize: 4096 })
    });
    const adm = await lc.checkAdmission({ forStart: false });
    expect(adm.admitted).toBe(false);
    // Pre-fix the early cap break skipped these rows entirely: they stayed
    // 'running' claims even though Incus reports them absent.
    expect(journal.getWorkspace('ws_stale_a_abcdefghijklmnop')?.state).toBe('stopped');
    expect(journal.getWorkspace('ws_stale_b_abcdefghijklmnop')?.state).toBe('stopped');
    expect(journal.getWorkspace(WS)?.state).toBe('running');
    journal.close();
  });
});


describe('watchdog expired lease', () => {
  it('stops a running VM whose lease is already expired — no unleased grace', async () => {
    const dir = tempDir();
    const { client, calls } = fakeIncus();
    // lease.set can record state 'expired' when a renewal lands past the
    // effective deadline. The watchdog must still stop the running VM on its
    // next pass — the unleased grace policy belongs to absent/cleared leases
    // only, so a huge grace must NOT defer this stop.
    const { journal, lifecycle } = makeLifecycle(dir, client, { unleasedGraceSeconds: 86_400 });
    journal.setLease({
      workspaceId: WS, instanceId: INSTANCE, generation: 1,
      expiresAt: 1_000, hardExpiresAt: 2_000, lastRenewalAt: 900, state: 'expired'
    });
    await lifecycle.tick();
    expect(calls.stops).toEqual([`${VM_NAME}:stop`]);
    journal.close();
  });

  it('still applies unleased grace to a cleared lease', async () => {
    const dir = tempDir();
    const { client, calls } = fakeIncus();
    const { journal, lifecycle } = makeLifecycle(dir, client, { unleasedGraceSeconds: 86_400 });
    journal.setLease({
      workspaceId: WS, instanceId: INSTANCE, generation: 1,
      expiresAt: 1_000, hardExpiresAt: 2_000, lastRenewalAt: 900, state: 'cleared'
    });
    await lifecycle.tick();
    expect(calls.stops).toEqual([]);
    journal.close();
  });
});
