import { rm } from 'node:fs/promises';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { WorkspaceId } from '@cloud-harness/contracts';
import { createVmNetworkGuard } from '../../src/network/ops.js';
import { runGuardCycle, createGuardService } from '../../src/network/guard-service.js';
import type { GuardServiceDeps } from '../../src/network/guard-service.js';
import {
  canonicalNftTable,
  deriveVmName,
  expectedNicDevice,
  permitSpecsFor,
  planWorkspaceSubject,
  rulesetDigest,
  validateGuardConfig
} from '../../src/network/policy.js';
import type { VmNetworkSubject } from '../../src/network/policy.js';
import { claimsPathFor, readGuardVerdict } from '../../src/network/state.js';
import type {
  VmGuardCommandRunner,
  VmGuardIncusProbe,
  VmGuardInstanceSnapshot,
  VmNetworkGuardDeps,
  VmNetworkIdentity
} from '../../src/network-ops.js';
import { createFakeKernel, nftTableDiffs } from './fake-kernel.js';
import type { FakeKernel } from './fake-kernel.js';

const CONFIG = {
  bridgePattern: 'chmbr%d',
  subnetPlan: '10.240.0.0/16',
  uplink: 'enp7s0',
  dnsResolvers: ['1.1.1.1', '8.8.8.8'],
  nonpublicCidrs: [] as string[],
  guardStatePath: ''
};
const WS1 = 'ws_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const IID1 = '11111111-1111-4111-8111-111111111111';

class FakeIncus implements VmGuardIncusProbe {
  instances = new Map<string, VmGuardInstanceSnapshot>();
  stopCalls: string[] = [];
  stopResult: 'stopped' | 'unknown' = 'stopped';
  addInstance(identity: VmNetworkIdentity, subject: VmNetworkSubject, status = 'Running'): void {
    this.instances.set(identity.vmName, {
      name: identity.vmName,
      status,
      expandedConfig: {
        'user.cloud-harness.workspace-id': identity.workspaceId,
        'user.cloud-harness.instance-id': identity.instanceId,
        'boot.autostart': 'false'
      },
      expandedDevices: { eth0: { ...expectedNicDevice(subject).expected } },
      profiles: []
    });
  }
  getInstanceExpanded(name: string) {
    return Promise.resolve(this.instances.get(name) ?? null);
  }
  stopInstance(name: string) {
    this.stopCalls.push(name);
    if (this.stopResult === 'stopped') {
      const snap = this.instances.get(name);
      if (snap) this.instances.set(name, { ...snap, status: 'Stopped' });
    }
    return Promise.resolve(this.stopResult);
  }
  listManagedInstances() {
    return Promise.resolve([...this.instances.values()]);
  }
}

let kernel: FakeKernel;
let incus: FakeIncus;
let deps: GuardServiceDeps;
let config: ReturnType<typeof validateGuardConfig>;
let subject: VmNetworkSubject;
let identity: VmNetworkIdentity;
let guardDeps: VmNetworkGuardDeps;

beforeEach(async () => {
  kernel = await createFakeKernel({
    links: [{ ifname: 'enp7s0', operstate: 'UP', addrs: [] }],
    routes: [{ dst: 'default', table: 'main', dev: 'enp7s0' }],
    sysctls: { 'net.ipv4.ip_forward': '1' }
  });
  incus = new FakeIncus();
  config = validateGuardConfig({ ...CONFIG, guardStatePath: join(kernel.workDir, 'guard-state.json') });
  guardDeps = { config: { ...CONFIG, guardStatePath: config.guardStatePath }, incus, execFile: kernel.exec };
  deps = { ...guardDeps, pollIntervalMs: 250 };
  subject = planWorkspaceSubject(config, { workspaceId: WS1, vmName: deriveVmName(WS1) });
  identity = { workspaceId: WS1 as WorkspaceId, vmName: deriveVmName(WS1), instanceId: IID1, generation: 1 };
});

afterEach(async () => {
  await kernel.dispose();
});

async function programmedRunning(): Promise<void> {
  const guard = createVmNetworkGuard(guardDeps);
  incus.addInstance(identity, subject, 'Running');
  await guard.program({ identity, networkProfile: 'dependency-access' });
}

function taggedCount(): number {
  const du = kernel.ipTables.get('filter:DOCKER-USER') ?? '';
  const pr = kernel.ipTables.get('nat:POSTROUTING') ?? '';
  return du.split('\n').filter((l) => l.includes('chm_vm_guard')).length + pr.split('\n').filter((l) => l.includes('chm_vm_guard')).length;
}

/** Semantic nft assertion against the canonical model for `subject`. */
function expectNftTable(): void {
  expect(nftTableDiffs(kernel.nftTableText, canonicalNftTable([subject], config, 'enp7s0'))).toEqual([]);
}

describe('runGuardCycle — healthy', () => {
  it('reports ok and writes the verdict file', async () => {
    await programmedRunning();
    const result = await runGuardCycle(deps);
    expect(result.verdict).toBe('ok');
    expect(result.rulesetHash).toBe(rulesetDigest(canonicalNftTable([subject], config, 'enp7s0')));
    const verdict = await readGuardVerdict(config.guardStatePath);
    expect(verdict?.verdict).toBe('ok');
    expect(verdict?.rulesetHash).toBe(result.rulesetHash);
    expect(verdict?.vms.map((v) => v.vmName)).toContain(identity.vmName);
  });

  it('ok verdict on a completely empty managed set', async () => {
    const result = await runGuardCycle(deps);
    expect(result.verdict).toBe('ok');
  });
});

describe('runGuardCycle — drift repair', () => {
  it('repairs permit loss while the nft guard is intact', async () => {
    await programmedRunning();
    kernel.ipTables.set('filter:DOCKER-USER', '-P DOCKER-USER ACCEPT\n-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1\n');
    kernel.ipTables.set('nat:POSTROUTING', '-P POSTROUTING ACCEPT\n');
    const result = await runGuardCycle(deps);
    expect(result.verdict).toBe('degraded');
    expect(taggedCount()).toBe(3);
    expect(incus.stopCalls).toHaveLength(0);
  });

  it('repairs reorder-only defects (permit ahead of CH jump)', async () => {
    await programmedRunning();
    const specs = permitSpecsFor(subject, config, 'enp7s0');
    kernel.ipTables.set(
      'filter:DOCKER-USER',
      `-P DOCKER-USER ACCEPT\n-A DOCKER-USER ${specs.egress}\n-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1\n-A DOCKER-USER ${specs.ret}\n`
    );
    const result = await runGuardCycle(deps);
    expect(result.verdict).toBe('degraded');
    const rules = (kernel.ipTables.get('filter:DOCKER-USER') ?? '').split('\n').filter((l) => l.startsWith('-A '));
    expect(rules[0]).toBe('-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1');
    expect(rules.filter((l) => l.includes('chm_vm_guard'))).toHaveLength(2);
  });

  it('strips permits, stops exposed VMs, then rebuilds when the nft guard is lost', async () => {
    await programmedRunning();
    kernel.nftTableText = '';
    const result = await runGuardCycle(deps);
    expect(result.verdict).toBe('degraded');
    // Permits were stripped then safely restored after the guard verified.
    expect(taggedCount()).toBe(3);
    // The running instance was stopped during the exposure window.
    expect(incus.stopCalls).toContain(identity.vmName);
    expectNftTable();
    const order = result.actions.join('\n');
    expect(order).toContain('stripped');
    expect(order).toContain('stopped managed instance');
    expect(order).toContain('rebuilt canonical nft guard table');
  });

  it('rebuilds without stopping when guard is lost and no permits exist', async () => {
    await programmedRunning();
    kernel.nftTableText = '';
    kernel.ipTables.set('filter:DOCKER-USER', '-P DOCKER-USER ACCEPT\n-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1\n');
    kernel.ipTables.set('nat:POSTROUTING', '-P POSTROUTING ACCEPT\n');
    const result = await runGuardCycle(deps);
    expect(result.verdict).toBe('degraded');
    expect(incus.stopCalls).toHaveLength(0);
    expectNftTable();
  });

  it('quarantines and stops all managed VMs when drift is unreconcilable', async () => {
    await programmedRunning();
    // Make every nft -f fail → rebuild can never verify.
    const failingExec: VmGuardCommandRunner = async (argv, bounds) => {
      if (argv[0] === 'nft' && argv[1] === '-f') {
        return { exitCode: 1, stdout: '', stderr: 'injected nft failure', timedOut: false, truncated: false };
      }
      return kernel.exec(argv, bounds);
    };
    deps.execFile = failingExec;
    kernel.nftTableText = '';
    const result = await runGuardCycle(deps);
    expect(result.verdict).toBe('quarantined');
    expect(incus.stopCalls).toContain(identity.vmName);
  });

  it('fails closed on transport failure without mutating', async () => {
    await programmedRunning();
    const before = kernel.nftTableText;
    const failingExec: VmGuardCommandRunner = async () => {
      throw new Error('transport down');
    };
    deps.execFile = failingExec;
    const result = await runGuardCycle(deps);
    expect(result.verdict).toBe('failed');
    expect(kernel.nftTableText).toBe(before);
    expect(incus.stopCalls).toHaveLength(0);
  });

  it('strips stale permits left behind after claim release', async () => {
    await programmedRunning();
    // Release the claim but leave kernel resources (unclean teardown).
    await rm(claimsPathFor(config.guardStatePath), { force: true });
    const result = await runGuardCycle(deps);
    // Claims gone → expected set empty → stale tagged rules stripped, table
    // deleted, and the unclaimed running instance stopped.
    expect(['degraded', 'quarantined']).toContain(result.verdict);
    expect(taggedCount()).toBe(0);
    expect(kernel.nftTableText).toBe('');
    expect(incus.stopCalls).toContain(identity.vmName);
  });

  it('stops managed instances that have no claim', async () => {
    // Instance exists but was never programmed/claimed.
    incus.addInstance(identity, subject, 'Running');
    const result = await runGuardCycle(deps);
    expect(incus.stopCalls).toContain(identity.vmName);
    expect(result.drift.join(' ')).toContain('unclaimed-managed-instance');
  });
});

describe('createGuardService', () => {
  it('runs cycles on poll and on monitor wakeups, serialized', async () => {
    await programmedRunning();
    const wakeups: { cbs: (() => void)[] } = { cbs: [] };
    const serviceDeps: GuardServiceDeps = {
      ...deps,
      wakeups: { subscribe: (cb) => { wakeups.cbs.push(cb); return () => undefined; } }
    };
    const service = createGuardService(serviceDeps);
    service.start();
    // Wait for the initial cycle to publish a verdict.
    for (let i = 0; i < 100; i++) {
      const v = await readGuardVerdict(config.guardStatePath);
      if (v !== null) break;
      await new Promise((r) => setTimeout(r, 10));
    }
    const first = await readGuardVerdict(config.guardStatePath);
    expect(first?.verdict).toBe('ok');
    // Wakeup triggers another full cycle (verdict rewritten).
    wakeups.cbs.forEach((cb) => cb());
    await new Promise((r) => setTimeout(r, 60));
    const second = await readGuardVerdict(config.guardStatePath);
    expect(second?.attestedAt).toBeGreaterThanOrEqual(first!.attestedAt);
    await service.stop();
  });

  it('keeps reconciling across cycles (no wedging on prior failure)', async () => {
    await programmedRunning();
    const service = createGuardService({ ...deps, pollIntervalMs: 250 });
    const r1 = await service.runOnce();
    expect(r1.verdict).toBe('ok');
    kernel.nftTableText = '';
    const r2 = await service.runOnce();
    expect(r2.verdict).toBe('degraded');
    const r3 = await service.runOnce();
    expect(r3.verdict).toBe('ok');
    await service.stop();
  });
});

describe('cross-process lock contention', () => {
  it('lock timeout produces a failed verdict, never a silent skip', async () => {
    await programmedRunning();
    // Hold the guard lock with our own live pid so acquisition times out.
    const { guardLockDir } = await import('../../src/network/lock.js');
    const { mkdir, writeFile } = await import('node:fs/promises');
    const lockDir = guardLockDir(kernel.workDir);
    await mkdir(lockDir, { recursive: true });
    await writeFile(join(lockDir, 'owner.json'), JSON.stringify({ pid: process.pid, startedAt: Date.now(), nonce: 'held' }), { mode: 0o600 });
    const result = await runGuardCycle({
      ...deps,
      lockOptions: { timeoutMs: 60, pollMs: 10 }
    });
    expect(result.verdict).toBe('failed');
    expect(result.drift.join(' ')).toMatch(/guard-lock-timeout/);
    // Verdict file records the failure — never stale-ok.
    const verdict = await readGuardVerdict(config.guardStatePath);
    expect(verdict?.verdict).toBe('failed');
  });
});
