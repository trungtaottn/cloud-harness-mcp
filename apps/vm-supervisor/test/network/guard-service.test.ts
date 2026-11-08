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

  it('repairs TWO misplaced permits ahead of the CH jump (interleaved -D/-I must not deadlock)', async () => {
    await programmedRunning();
    const specs = permitSpecsFor(subject, config, 'enp7s0');
    // Both tagged permits precede the marker — the old interleaved
    // delete/reinsert left [E,R,M] unchanged forever.
    kernel.ipTables.set(
      'filter:DOCKER-USER',
      `-P DOCKER-USER ACCEPT\n-A DOCKER-USER ${specs.egress}\n-A DOCKER-USER ${specs.ret}\n-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1\n`
    );
    const result = await runGuardCycle(deps);
    expect(result.verdict).toBe('degraded');
    const rules = (kernel.ipTables.get('filter:DOCKER-USER') ?? '').split('\n').filter((l) => l.startsWith('-A '));
    expect(rules[0]).toBe('-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1');
    const markerIdx = rules.findIndex((l) => l.includes('chm-egress0 -j CHM-EGRESS-v1'));
    const tagged = rules.map((l, i) => ({ l, i })).filter(({ l }) => l.includes('chm_vm_guard'));
    expect(tagged).toHaveLength(2);
    for (const { i } of tagged) expect(i).toBeGreaterThan(markerIdx);
  });

  it('keeps quarantine fail-closed but records the diagnostic when the DOCKER-USER probe read fails', async () => {
    await programmedRunning();
    // Foreign rule first → CH gate fails → reorder probes run. The probe's
    // own DOCKER-USER read (3rd overall: verifyPermits, chGate, probe) throws.
    const valid = kernel.ipTables.get('filter:DOCKER-USER')!;
    kernel.ipTables.set(
      'filter:DOCKER-USER',
      valid.replace('-A DOCKER-USER', '-A DOCKER-USER -p tcp --dport 9999 -j DROP\n-A DOCKER-USER')
    );
    let dockerUserReads = 0;
    const flakyExec: VmGuardCommandRunner = async (argv, bounds) => {
      if (argv[0] === 'iptables' && argv.includes('-S') && argv[argv.length - 1] === 'DOCKER-USER') {
        dockerUserReads += 1;
        if (dockerUserReads > 2) throw new Error('injected transient iptables read failure');
      }
      return kernel.exec(argv, bounds);
    };
    deps.execFile = flakyExec;
    const result = await runGuardCycle(deps);
    // Fail-closed retained: still quarantined, still stops managed VMs —
    // an unreadable chain is never silently treated as repairable.
    expect(result.verdict).toBe('quarantined');
    expect(incus.stopCalls).toContain(identity.vmName);
    expect(result.drift.some((d) => d.includes('docker-user probe read failed'))).toBe(true);
  });

  it('treats a down claimed bridge as unreconciled drift (state.up verified)', async () => {
    await programmedRunning();
    const link = kernel.links.get(subject.bridgeName)!;
    link.operstate = 'DOWN';
    const result = await runGuardCycle(deps);
    // The service never brings bridges up; a down claimed bridge cannot be
    // reconciled this cycle → fail-closed quarantine, not silent 'ok'.
    expect(result.verdict).toBe('quarantined');
    expect(incus.stopCalls).toContain(identity.vmName);
    expect(result.drift.some((d) => d.includes('unreconciled: bridge'))).toBe(true);
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
    // Hold the flock through the REAL lock path — a second acquisition on
    // the same inode blocks in the kernel until timeout.
    const { withGuardLock } = await import('../../src/network/lock.js');
    let releaseHold!: () => void;
    let markAcquired!: () => void;
    const holdGate = new Promise<void>((r) => {
      releaseHold = r;
    });
    const acquired = new Promise<void>((r) => {
      markAcquired = r;
    });
    // The callback runs only AFTER the flock lands — awaiting `acquired`
    // is a real barrier, not a timing guess.
    const holder = withGuardLock(kernel.workDir, async () => {
      markAcquired();
      await holdGate;
    });
    await acquired;
    const result = await runGuardCycle({
      ...deps,
      lockOptions: { timeoutMs: 150 }
    });
    releaseHold();
    await holder;
    expect(result.verdict).toBe('failed');
    expect(result.drift.join(' ')).toMatch(/guard-lock-timeout/);
    // Verdict file records the failure — never stale-ok.
    const verdict = await readGuardVerdict(config.guardStatePath);
    expect(verdict?.verdict).toBe('failed');
  });
});

describe('verified zero-NIC exemption (network-none)', () => {
  function stripNic(vmName: string): void {
    const snap = incus.instances.get(vmName)!;
    incus.instances.set(vmName, { ...snap, expandedDevices: {} });
  }

  it('does not stop a running zero-NIC unclaimed instance', async () => {
    incus.addInstance(identity, subject, 'Running');
    stripNic(identity.vmName);
    const result = await runGuardCycle(deps);
    expect(incus.stopCalls).toHaveLength(0);
    expect(result.drift.join(' ')).not.toContain('unclaimed-managed-instance');
    expect(result.verdict).toBe('ok');
  });

  it('still stops a NIC-bearing unclaimed instance in the same cycle', async () => {
    incus.addInstance(identity, subject, 'Running');
    const result = await runGuardCycle(deps);
    expect(incus.stopCalls).toContain(identity.vmName);
    expect(result.drift.join(' ')).toContain('unclaimed-managed-instance');
  });

  it('quarantine stopAllManaged exempts zero-NIC but stops NIC instances', async () => {
    await programmedRunning();
    // Unreconcilable nft drift → quarantine → stopAllManaged path.
    const failingExec: VmGuardCommandRunner = async (argv, bounds) => {
      if (argv[0] === 'nft' && argv[1] === '-f') {
        return { exitCode: 1, stdout: '', stderr: 'injected nft failure', timedOut: false, truncated: false };
      }
      return kernel.exec(argv, bounds);
    };
    deps.execFile = failingExec;
    kernel.nftTableText = '';
    // Add a second zero-NIC running managed instance.
    const ws2 = 'ws_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    const id2 = '22222222-2222-4222-8222-222222222222';
    const subject2 = planWorkspaceSubject(config, { workspaceId: ws2, vmName: deriveVmName(ws2) });
    const identity2 = { workspaceId: ws2 as WorkspaceId, vmName: deriveVmName(ws2), instanceId: id2, generation: 1 };
    incus.addInstance(identity2, subject2, 'Running');
    stripNic(identity2.vmName);
    const result = await runGuardCycle(deps);
    expect(result.verdict).toBe('quarantined');
    expect(incus.stopCalls).toContain(identity.vmName); // NIC-bearing: stopped
    expect(incus.stopCalls).not.toContain(identity2.vmName); // zero-NIC: exempt
  });
});

describe('failed-stop containment freeze', () => {
  async function unclaimedWithResources(stopResult: 'stopped' | 'unknown'): Promise<void> {
    // Program fully (claim + bridge + permits + nft), then delete the claims
    // file → the running instance is unclaimed but its guard bridge exists.
    await programmedRunning();
    const { rm } = await import('node:fs/promises');
    const { claimsPathFor } = await import('../../src/network/state.js');
    await rm(claimsPathFor(config.guardStatePath), { force: true });
    incus.stopResult = stopResult;
  }

  it('failed unclaimed stop bridge-downs the orphan bridge, freezes repairs, verdict failed', async () => {
    await unclaimedWithResources('unknown');
    const nftBefore = kernel.nftTableText;
    const permitsBefore = taggedCount();
    const result = await runGuardCycle(deps);
    expect(result.verdict).toBe('failed');
    // The freeze reason is recorded on the verdict file; drift carries the
    // unclaimed note + the failed stop confirmation.
    const verdict = await readGuardVerdict(config.guardStatePath);
    expect(verdict?.reason).toContain('unclaimed-instance-stop-failed');
    expect(result.drift.join(' ')).toContain('stop-unknown');
    // Containment: the positively-orphan guard bridge was brought down.
    expect(kernel.links.get(subject.bridgeName)!.operstate).toBe('DOWN');
    // Freeze: shared enforcement untouched — the still-running VM keeps its
    // last effective guard (permits + nft table preserved).
    expect(kernel.nftTableText).toBe(nftBefore);
    expect(taggedCount()).toBe(permitsBefore);
  });

  it('foreign claim on the bridge → NO bridge mutation, repairs frozen, verdict failed', async () => {
    await programmedRunning();
    const { rm, writeFile } = await import('node:fs/promises');
    const { claimsPathFor } = await import('../../src/network/state.js');
    // Replace our claim with a FOREIGN claim occupying the same bridge slot.
    await rm(claimsPathFor(config.guardStatePath), { force: true });
    const ws2 = 'ws_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    await writeFile(
      claimsPathFor(config.guardStatePath),
      JSON.stringify({
        version: 1,
        claims: {
          [subject.bridgeName]: {
            workspaceId: ws2,
            vmName: deriveVmName(ws2),
            bridgeName: subject.bridgeName,
            guestIp: '10.240.0.2',
            claimedAt: Date.now()
          }
        }
      }),
      'utf8'
    );
    incus.stopResult = 'unknown';
    const nftBefore = kernel.nftTableText;
    const permitsBefore = taggedCount();
    const result = await runGuardCycle(deps);
    expect(result.verdict).toBe('failed');
    expect(result.drift.join(' ')).toContain('containment-unverified');
    // Foreign bridge untouched — stays UP; shared rules frozen.
    expect(kernel.links.get(subject.bridgeName)!.operstate).toBe('UP');
    expect(kernel.nftTableText).toBe(nftBefore);
    expect(taggedCount()).toBe(permitsBefore);
  });

  it('unverifiable NIC attachment (two NICs) → no bridge mutation, verdict failed', async () => {
    await programmedRunning();
    const { rm } = await import('node:fs/promises');
    const { claimsPathFor } = await import('../../src/network/state.js');
    await rm(claimsPathFor(config.guardStatePath), { force: true });
    // Give the instance a second NIC → parent cannot be positively resolved.
    const snap = incus.instances.get(identity.vmName)!;
    incus.instances.set(identity.vmName, {
      ...snap,
      expandedDevices: {
        ...snap.expandedDevices,
        eth1: { type: 'nic', nictype: 'bridged', parent: 'otherbr0', name: 'eth1' }
      }
    });
    incus.stopResult = 'unknown';
    const result = await runGuardCycle(deps);
    expect(result.verdict).toBe('failed');
    expect(result.drift.join(' ')).toContain('nic attachment unknown');
    expect(kernel.links.get(subject.bridgeName)!.operstate).toBe('UP');
  });

  it('confirmed stop still proceeds to repairs (no freeze on success)', async () => {
    await programmedRunning();
    const { rm } = await import('node:fs/promises');
    const { claimsPathFor } = await import('../../src/network/state.js');
    await rm(claimsPathFor(config.guardStatePath), { force: true });
    const result = await runGuardCycle(deps);
    expect(incus.stopCalls).toContain(identity.vmName);
    // Stop confirmed → stale permits stripped, table removed, unclaimed gone.
    expect(taggedCount()).toBe(0);
    expect(['degraded', 'quarantined']).toContain(result.verdict);
  });
});

describe('transient kernel-read failures', () => {
  it('ch-gate repair read failure → failed verdict, never a crash', async () => {
    await programmedRunning();
    // Corrupt INPUT's first rule so chGateCheck reports drift (not throw)…
    kernel.ipTables.set('filter:INPUT', '-P INPUT ACCEPT\n-A INPUT -j SOME-FOREIGN-CHAIN\n');
    // …then make the SECOND iptables -S INPUT read (the repair probe) throw.
    let inputReads = 0;
    const flakyExec: VmGuardCommandRunner = async (argv, bounds) => {
      if (argv[0] === 'iptables' && argv.includes('-S') && argv[argv.length - 1] === 'INPUT') {
        inputReads += 1;
        if (inputReads > 1) throw new Error('transient INPUT read failure');
      }
      return kernel.exec(argv, bounds);
    };
    deps.execFile = flakyExec;
    const result = await runGuardCycle(deps);
    expect(result.verdict).toBe('failed');
    expect(result.drift.join(' ')).toContain('ch-gate-read-failure');
  });

  it('nft-repair permit-count read failure → failed verdict, never a crash', async () => {
    await programmedRunning();
    kernel.nftTableText = '';
    // POSTROUTING is read exactly once during verifyKernelState (permit
    // assessment) and re-read inside the nft-repair tagged-count probe —
    // throwing on the SECOND read isolates the new repair-path catch.
    let postroutingReads = 0;
    const flakyExec: VmGuardCommandRunner = async (argv, bounds) => {
      if (argv[0] === 'iptables' && argv.includes('-S') && argv[argv.length - 1] === 'POSTROUTING') {
        postroutingReads += 1;
        if (postroutingReads > 1) throw new Error('transient POSTROUTING read failure');
      }
      return kernel.exec(argv, bounds);
    };
    deps.execFile = flakyExec;
    const result = await runGuardCycle(deps);
    expect(result.verdict).toBe('failed');
    expect(result.drift.join(' ')).toContain('permit-count-read-failure');
  });
});

describe('fresh state directory', () => {
  it('creates a missing guard state dir and still publishes verdict + claims', async () => {
    await programmedRunning();
    // Move the state path into a directory that does not exist yet.
    const freshDir = join(kernel.workDir, 'fresh', 'state');
    const freshPath = join(freshDir, 'guard-state.json');
    deps = { ...deps, config: { ...deps.config, guardStatePath: freshPath } };
    guardDeps = { ...guardDeps, config: { ...guardDeps.config, guardStatePath: freshPath } };
    // Re-derive: claims were written under the OLD path by program(); the
    // fresh dir has no claims → the running instance is unclaimed → it is
    // stopped and stale resources stripped. The point is the CYCLE RUNS.
    const result = await runGuardCycle(deps);
    expect(['ok', 'degraded', 'quarantined']).toContain(result.verdict);
    const verdict = await readGuardVerdict(freshPath);
    expect(verdict).not.toBeNull();
    expect(verdict?.verdict).toBe(result.verdict);
  });
});
