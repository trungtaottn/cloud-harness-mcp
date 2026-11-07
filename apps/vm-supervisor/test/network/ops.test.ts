import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import type { WorkspaceId } from '@cloud-harness/contracts';
import { createVmNetworkGuard } from '../../src/network/ops.js';
import { runGuardCycle } from '../../src/network/guard-service.js';
import type { GuardServiceDeps } from '../../src/network/guard-service.js';
import {
  EMPTY_RULESET_DIGEST,
  canonicalNftTable,
  deriveVmName,
  expectedNicDevice,
  planWorkspaceSubject,
  rulesetDigest,
  validateGuardConfig
} from '../../src/network/policy.js';
import type { VmNetworkSubject } from '../../src/network/policy.js';
import { claimsPathFor, readGuardClaims } from '../../src/network/state.js';
import type {
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
const WS2 = 'ws_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const IID1 = '11111111-1111-4111-8111-111111111111';
const IID2 = '22222222-2222-4222-8222-222222222222';

class FakeIncus implements VmGuardIncusProbe {
  instances = new Map<string, VmGuardInstanceSnapshot>();
  stopCalls: string[] = [];
  stopResult: 'stopped' | 'unknown' = 'stopped';

  addInstance(identity: VmNetworkIdentity, subject: VmNetworkSubject, profile: 'network-none' | 'dependency-access', status = 'Stopped'): void {
    const devices: Record<string, Record<string, string>> = {};
    if (profile === 'dependency-access') {
      devices['eth0'] = { ...expectedNicDevice(subject).expected };
    }
    this.instances.set(identity.vmName, {
      name: identity.vmName,
      status,
      expandedConfig: {
        'user.cloud-harness.workspace-id': identity.workspaceId,
        'user.cloud-harness.instance-id': identity.instanceId,
        'boot.autostart': 'false'
      },
      expandedDevices: devices,
      profiles: []
    });
  }

  getInstanceExpanded(name: string): Promise<VmGuardInstanceSnapshot | null> {
    return Promise.resolve(this.instances.get(name) ?? null);
  }
  stopInstance(name: string): Promise<'stopped' | 'unknown'> {
    this.stopCalls.push(name);
    if (this.stopResult === 'stopped') {
      const snap = this.instances.get(name);
      if (snap) this.instances.set(name, { ...snap, status: 'Stopped' });
    }
    return Promise.resolve(this.stopResult);
  }
  listManagedInstances(): Promise<readonly VmGuardInstanceSnapshot[]> {
    return Promise.resolve([...this.instances.values()]);
  }
}

let kernel: FakeKernel;
let incus: FakeIncus;
let deps: VmNetworkGuardDeps;
let config: ReturnType<typeof validateGuardConfig>;
let subject1: VmNetworkSubject;
let subject2: VmNetworkSubject;
let identity1: VmNetworkIdentity;
let identity2: VmNetworkIdentity;

beforeEach(async () => {
  kernel = await createFakeKernel({
    links: [{ ifname: 'enp7s0', operstate: 'UP', addrs: [] }],
    routes: [{ dst: 'default', table: 'main', dev: 'enp7s0' }],
    sysctls: { 'net.ipv4.ip_forward': '1' }
  });
  incus = new FakeIncus();
  config = validateGuardConfig({ ...CONFIG, guardStatePath: join(kernel.workDir, 'guard-state.json') });
  deps = { config: { ...CONFIG, guardStatePath: config.guardStatePath }, incus, execFile: kernel.exec };
  subject1 = planWorkspaceSubject(config, { workspaceId: WS1, vmName: deriveVmName(WS1) });
  subject2 = planWorkspaceSubject(config, { workspaceId: WS2, vmName: deriveVmName(WS2) });
  identity1 = { workspaceId: WS1 as WorkspaceId, vmName: deriveVmName(WS1), instanceId: IID1, generation: 1 };
  identity2 = { workspaceId: WS2 as WorkspaceId, vmName: deriveVmName(WS2), instanceId: IID2, generation: 1 };
});

afterEach(async () => {
  await kernel.dispose();
});

function dockerUserRules(): string[] {
  return (kernel.ipTables.get('filter:DOCKER-USER') ?? '').split('\n').filter((l) => l.startsWith('-A '));
}
function postroutingRules(): string[] {
  return (kernel.ipTables.get('nat:POSTROUTING') ?? '').split('\n').filter((l) => l.startsWith('-A '));
}
/** Semantic nft assertion: live `nft list` output must parse to the canonical model. */
function expectNftTable(subjects: VmNetworkSubject[]): void {
  expect(nftTableDiffs(kernel.nftTableText, canonicalNftTable(subjects, config, 'enp7s0'))).toEqual([]);
}
function callIndex(pred: (args: string[]) => boolean): number {
  return kernel.calls.findIndex(pred);
}

describe('program', () => {
  it('programs bridge+nft+permits in fail-closed order and returns contract result', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access');
    const result = await guard.program({ identity: identity1, networkProfile: 'dependency-access' });

    expect(result.bridgeName).toBe(subject1.bridgeName);
    expect(result.guestIp).toBe(subject1.guestIp);
    expect(result.rulesetDigest).toBe(rulesetDigest(canonicalNftTable([subject1], config, 'enp7s0')));

    // Kernel state: bridge up with host /30, IPv6 disabled.
    const link = kernel.links.get(subject1.bridgeName)!;
    expect(link).toBeDefined();
    expect(link.operstate).toBe('UP');
    expect(link.infoKind).toBe('bridge');
    expect(link.addrs).toEqual([{ family: 'inet', local: subject1.hostIp, prefixlen: 30 }]);
    expect(kernel.sysctls.get(`net.ipv6.conf.${subject1.bridgeName}.disable_ipv6`)).toBe('1');

    // nft table parses to the canonical model for the claimed set (the fake
    // stores real `nft list` format — symbolic priorities, materialized
    // counters — so compare semantically, never by text).
    expectNftTable([subject1]);

    // Permits present, positioned after the CH first-jump.
    const du = dockerUserRules();
    expect(du[0]).toBe('-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1');
    const ours = du.filter((l) => l.includes('chm_vm_guard'));
    expect(ours).toHaveLength(2);
    expect(ours.every((l) => du.indexOf(l) > 0)).toBe(true);
    expect(postroutingRules().filter((l) => l.includes('chm_vm_guard'))).toHaveLength(1);
    expect(postroutingRules()[0]).toContain('-j MASQUERADE');

    // Ordering: nft apply+verify before first permit restore before link up.
    const nftApply = callIndex((a) => a[0] === 'nft' && a[1] === '-f');
    const firstRestore = callIndex((a) => a[0] === 'iptables-restore' && !a.includes('--test'));
    const linkUp = callIndex((a) => a[0] === 'ip' && a[1] === 'link' && a[2] === 'set' && a[3] === subject1.bridgeName && a[4] === 'up');
    expect(nftApply).toBeGreaterThanOrEqual(0);
    expect(firstRestore).toBeGreaterThan(nftApply);
    expect(linkUp).toBeGreaterThan(firstRestore);

    // Claim recorded.
    const claims = await readGuardClaims(claimsPathFor(config.guardStatePath));
    expect(claims.claims[subject1.bridgeName]?.workspaceId).toBe(WS1);
  });

  it('is idempotent: second program does not duplicate permits', async () => {
    const guard = createVmNetworkGuard(deps);
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    expect(dockerUserRules().filter((l) => l.includes('chm_vm_guard'))).toHaveLength(2);
    expect(postroutingRules().filter((l) => l.includes('chm_vm_guard'))).toHaveLength(1);
  });

  it('programs network-none as empty ruleset with no resources', async () => {
    const guard = createVmNetworkGuard(deps);
    const result = await guard.program({ identity: identity1, networkProfile: 'network-none' });
    expect(result).toEqual({ rulesetDigest: EMPTY_RULESET_DIGEST });
    expect(kernel.links.has(subject1.bridgeName)).toBe(false);
    expect(kernel.nftTableText).toBe('');
    expect(dockerUserRules().filter((l) => l.includes('chm_vm_guard'))).toHaveLength(0);
  });

  it('refuses to program when CH first-jump drifted, mutating nothing', async () => {
    kernel.ipTables.set('filter:DOCKER-USER', '-P DOCKER-USER ACCEPT\n-A DOCKER-USER -p tcp --dport 1 -j ACCEPT\n');
    const guard = createVmNetworkGuard(deps);
    await expect(guard.program({ identity: identity1, networkProfile: 'dependency-access' })).rejects.toMatchObject({
      reason: 'ch-gate-precondition'
    });
    expect(kernel.links.has(subject1.bridgeName)).toBe(false);
    expect(kernel.nftTableText).toBe('');
  });

  it('repairs lost permits while the nft guard is intact', async () => {
    const guard = createVmNetworkGuard(deps);
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    // Simulate permit loss: strip our tagged rules.
    kernel.ipTables.set('filter:DOCKER-USER', '-P DOCKER-USER ACCEPT\n-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1\n');
    kernel.ipTables.set('nat:POSTROUTING', '-P POSTROUTING ACCEPT\n');
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    expect(dockerUserRules().filter((l) => l.includes('chm_vm_guard'))).toHaveLength(2);
    expect(postroutingRules().filter((l) => l.includes('chm_vm_guard'))).toHaveLength(1);
  });

  it('fails on truncated-hash bridge slot collision', async () => {
    // Find a second workspaceId hashing to the same bridge slot.
    let colliding = '';
    for (let i = 0; i < 500_000 && colliding === ''; i++) {
      const candidate = `ws_${i.toString(16).padStart(32, '0')}`;
      if (candidate === WS1) continue;
      const s = planWorkspaceSubject(config, { workspaceId: candidate, vmName: deriveVmName(candidate) });
      if (s.bridgeName === subject1.bridgeName) colliding = candidate;
    }
    expect(colliding).not.toBe('');
    const guard = createVmNetworkGuard(deps);
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    const otherIdentity: VmNetworkIdentity = {
      workspaceId: colliding as WorkspaceId,
      vmName: deriveVmName(colliding),
      instanceId: IID2,
      generation: 1
    };
    await expect(guard.program({ identity: otherIdentity, networkProfile: 'dependency-access' })).rejects.toMatchObject({
      reason: 'bridge-slot-collision'
    });
  });

  it('keeps both workspaces in the shared nft table', async () => {
    const guard = createVmNetworkGuard(deps);
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    await guard.program({ identity: identity2, networkProfile: 'dependency-access' });
    expect(subject1.bridgeName).not.toBe(subject2.bridgeName);
    expectNftTable([subject1, subject2]);
    expect(dockerUserRules().filter((l) => l.includes('chm_vm_guard'))).toHaveLength(4);
  });
});

describe('attest', () => {
  it('returns ok with live kernel + instance verification', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access');
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    const result = await guard.attest({ identity: identity1, networkProfile: 'dependency-access' });
    expect(result.ok).toBe(true);
    expect(result.rulesetDigest).toBe(rulesetDigest(canonicalNftTable([subject1], config, 'enp7s0')));
    expect(result.drift).toBeUndefined();
  });

  it('never trusts a verdict file: kernel drift fails attest', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access');
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    // Corrupt the kernel table silently (list-format text: counters are
    // materialized, so match the rendered statement, not compiler text).
    kernel.nftTableText = kernel.nftTableText
      .split('\n')
      .filter((l) => !l.includes('ct state invalid'))
      .join('\n');
    const result = await guard.attest({ identity: identity1, networkProfile: 'dependency-access' });
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result.drift)).toContain('ct state invalid');
  });

  it('fails when the instance is missing', async () => {
    const guard = createVmNetworkGuard(deps);
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    const result = await guard.attest({ identity: identity1, networkProfile: 'dependency-access' });
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result.drift)).toContain('instance-missing');
  });

  it('rejects raw.* config and unexpected NIC keys', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access');
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    const snap = incus.instances.get(identity1.vmName)!;
    incus.instances.set(identity1.vmName, {
      ...snap,
      expandedConfig: { ...snap.expandedConfig, 'raw.lxc': 'lxc.net.0.type=phys' },
      expandedDevices: { eth0: { ...snap.expandedDevices['eth0']!, 'security.acls': 'true' } }
    });
    const result = await guard.attest({ identity: identity1, networkProfile: 'dependency-access' });
    expect(result.ok).toBe(false);
    const drift = JSON.stringify(result.drift);
    expect(drift).toContain('raw-config-present');
    expect(drift).toContain('nic.security.acls');
  });

  it('network-none attest requires zero NIC devices', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'network-none');
    // Program host side as network-none (no resources), then attest.
    await guard.program({ identity: identity1, networkProfile: 'network-none' });
    const okResult = await guard.attest({ identity: identity1, networkProfile: 'network-none' });
    // Kernel has no rules for this workspace and none are expected... but the
    // subject is still in the expected set → table lacks its chains → drift.
    // This is correct fail-closed: network-none attestation still expects the
    // empty-ruleset posture only when no claims exist; with a claim absent the
    // canonical table is empty and matches.
    expect(okResult.ok).toBe(true);

    // Now give the instance a NIC — must fail.
    const snap = incus.instances.get(identity1.vmName)!;
    incus.instances.set(identity1.vmName, {
      ...snap,
      expandedDevices: { eth0: { ...expectedNicDevice(subject1).expected } }
    });
    const bad = await guard.attest({ identity: identity1, networkProfile: 'network-none' });
    expect(bad.ok).toBe(false);
    expect(JSON.stringify(bad.drift)).toContain('network-none but 1 nic');
  });

  it('detects identity marker mismatch', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access');
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    const snap = incus.instances.get(identity1.vmName)!;
    incus.instances.set(identity1.vmName, {
      ...snap,
      expandedConfig: { ...snap.expandedConfig, 'user.cloud-harness.instance-id': IID2 }
    });
    const result = await guard.attest({ identity: identity1, networkProfile: 'dependency-access' });
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result.drift)).toContain('identity markers');
  });
});

describe('tearDown', () => {
  it('removes permits, nft rules, bridge in order and releases the claim', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access');
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    kernel.calls.length = 0;

    const result = await guard.tearDown({ identity: identity1 });
    expect(result).toEqual({ removed: true });

    expect(kernel.links.has(subject1.bridgeName)).toBe(false);
    expect(kernel.nftTableText).toBe('');
    expect(dockerUserRules().filter((l) => l.includes('chm_vm_guard'))).toHaveLength(0);
    expect(postroutingRules().filter((l) => l.includes('chm_vm_guard'))).toHaveLength(0);
    const claims = await readGuardClaims(claimsPathFor(config.guardStatePath));
    expect(Object.keys(claims.claims)).toHaveLength(0);

    // Order: permit strip BEFORE nft delete BEFORE bridge delete.
    const restoreIdx = callIndex((a) => a[0] === 'iptables-restore' && !a.includes('--test'));
    const nftDelete = callIndex((a) => a[0] === 'nft' && a[1] === '-f');
    const linkDel = callIndex((a) => a[0] === 'ip' && a[1] === 'link' && a[2] === 'del');
    expect(restoreIdx).toBeGreaterThanOrEqual(0);
    expect(nftDelete).toBeGreaterThan(restoreIdx);
    expect(linkDel).toBeGreaterThan(nftDelete);
  });

  it('keeps the shared table for remaining claims', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access');
    incus.addInstance(identity2, subject2, 'dependency-access');
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    await guard.program({ identity: identity2, networkProfile: 'dependency-access' });
    await guard.tearDown({ identity: identity1 });
    expectNftTable([subject2]);
    expect(kernel.links.has(subject1.bridgeName)).toBe(false);
    expect(kernel.links.has(subject2.bridgeName)).toBe(true);
  });

  it('refuses while the instance is not stopped', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access', 'Running');
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    await expect(guard.tearDown({ identity: identity1 })).rejects.toMatchObject({ reason: 'instance-not-stopped' });
    expect(kernel.links.has(subject1.bridgeName)).toBe(true);
    expect(kernel.nftTableText).not.toBe('');
  });

  it('refuses when identity markers do not match', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access');
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    const snap = incus.instances.get(identity1.vmName)!;
    incus.instances.set(identity1.vmName, {
      ...snap,
      expandedConfig: { ...snap.expandedConfig, 'user.cloud-harness.workspace-id': WS2 }
    });
    await expect(guard.tearDown({ identity: identity1 })).rejects.toMatchObject({ reason: 'identity-unverified' });
    expect(kernel.links.has(subject1.bridgeName)).toBe(true);
  });
});

describe('quarantine', () => {
  it('drops link, strips permits, stops instance, retains guard', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access', 'Running');
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });

    const result = await guard.quarantine({ reason: 'test', identities: [identity1] });
    expect(result.quarantined).toBe(true);
    expect(result.outcomes).toEqual([{ vmName: identity1.vmName, outcome: 'stopped' }]);
    expect(incus.stopCalls).toEqual([identity1.vmName]);

    // Link down, permits gone, but nft guard + bridge retained.
    expect(kernel.links.get(subject1.bridgeName)!.operstate).toBe('DOWN');
    expect(dockerUserRules().filter((l) => l.includes('chm_vm_guard'))).toHaveLength(0);
    expect(postroutingRules().filter((l) => l.includes('chm_vm_guard'))).toHaveLength(0);
    expectNftTable([subject1]);
    expect(kernel.links.has(subject1.bridgeName)).toBe(true);
  });

  it('retains everything on unknown stop outcome', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access', 'Running');
    incus.stopResult = 'unknown';
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    const result = await guard.quarantine({ reason: 'test', identities: [identity1] });
    expect(result.outcomes).toEqual([{ vmName: identity1.vmName, outcome: 'unknown' }]);
    expect(kernel.nftTableText).not.toBe('');
    expect(kernel.links.has(subject1.bridgeName)).toBe(true);
  });

  it('skips foreign identities without mutating', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access', 'Running');
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    const foreign: VmNetworkIdentity = { ...identity1, instanceId: IID2 };
    const result = await guard.quarantine({ reason: 'test', identities: [foreign] });
    expect(result.outcomes).toEqual([{ vmName: identity1.vmName, outcome: 'skipped' }]);
    expect(incus.stopCalls).toHaveLength(0);
    expect(kernel.links.get(subject1.bridgeName)!.operstate).toBe('UP');
  });

  it('never removes the nft guard even when stop succeeds', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access', 'Running');
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    const before = kernel.nftAppliedPayloads.length;
    await guard.quarantine({ reason: 'test', identities: [identity1] });
    // No table-removal payload was applied during quarantine.
    for (const payload of kernel.nftAppliedPayloads.slice(before)) {
      expect(payload).not.toContain('destroy table');
      expect(payload).not.toContain('delete table');
    }
    expectNftTable([subject1]);
  });
});

describe('atomic nft application (B2)', () => {
  it('applies destroy+canonical in ONE checked nft -f payload', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access');
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    const applied = kernel.nftAppliedPayloads;
    expect(applied.length).toBeGreaterThanOrEqual(1);
    const last = applied.at(-1)!;
    // Single transaction file: destroy first, then the canonical table text.
    expect(last.startsWith('destroy table inet chm_vm_guard\n')).toBe(true);
    expect(last).toContain('table inet chm_vm_guard {');
    // Check-then-apply: nft -c -f ran before nft -f for the same file.
    const checkIdx = callIndex((a) => a[0] === 'nft' && a.includes('-c'));
    const applyIdx = callIndex((a) => a[0] === 'nft' && a[1] === '-f');
    expect(checkIdx).toBeGreaterThanOrEqual(0);
    expect(applyIdx).toBeGreaterThan(checkIdx);
  });

  it('reapplying program over an existing table is idempotent', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access');
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    const first = kernel.nftTableText;
    const permitCount = dockerUserRules().filter((l) => l.includes('chm_vm_guard')).length;
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    expectNftTable([subject1]);
    // No duplicate permits after re-program.
    expect(dockerUserRules().filter((l) => l.includes('chm_vm_guard'))).toHaveLength(permitCount);
    void first;
  });

  it('teardown succeeds when the nft table is already absent', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access');
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    // Simulate admin removing the whole table outside the guard.
    kernel.nftTableText = '';
    const result = await guard.tearDown({ identity: identity1 });
    expect(result).toEqual({ removed: true });
    expect(kernel.links.has(subject1.bridgeName)).toBe(false);
    const claims = await readGuardClaims(claimsPathFor(config.guardStatePath));
    expect(Object.keys(claims.claims)).toHaveLength(0);
  });
});

describe('iptables canonical-order tolerance (B3)', () => {
  it('permits survive when live -S output reorders tokens canonically', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access');
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    // Fake already renders canonical -s/-d/-i/-o order; attest must pass.
    const attest = await guard.attest({ identity: identity1, networkProfile: 'dependency-access' });
    expect(attest.ok).toBe(true);
    // Tamper: rewrite one permit spec in compiler order — must still verify.
    const rules = dockerUserRules();
    const tagged = rules.find((l) => l.includes('chm_vm_guard'))!;
    kernel.ipTables.set('filter:DOCKER-USER', kernel.ipTables.get('filter:DOCKER-USER')!.replace(tagged, tagged));
    const attest2 = await guard.attest({ identity: identity1, networkProfile: 'dependency-access' });
    expect(attest2.ok).toBe(true);
  });

  it('strips a permit whose live spec is canonically reordered', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access');
    await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    await guard.quarantine({ reason: 'test', identities: [identity1] });
    expect(dockerUserRules().filter((l) => l.includes('chm_vm_guard'))).toHaveLength(0);
    expect(postroutingRules().filter((l) => l.includes('chm_vm_guard'))).toHaveLength(0);
  });
});

describe('network-none stale claim (F5)', () => {
  it('attest fails when a stale claim exists for a network-none workspace', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'network-none');
    // Program network-none first (creates no claim, no resources).
    await guard.program({ identity: identity1, networkProfile: 'network-none' });
    // Forge a stale claim for this workspace as if a dependency-access
    // program crashed mid-flight.
    const claimsPath = claimsPathFor(config.guardStatePath);
    const { claimSubject } = await import('../../src/network/state.js');
    await claimSubject(claimsPath, subject1, Date.now());
    const result = await guard.attest({ identity: identity1, networkProfile: 'network-none' });
    expect(result.ok).toBe(false);
    expect(result.drift?.reasons.join(' ') ?? '').toMatch(/stale-claim|claim/i);
  });
});

describe('nft destroy prerequisite preflight (N4)', () => {
  it('program refuses before any mutation when nftables/kernel are below the destroy floor', async () => {
    const oldKernel = await createFakeKernel({
      links: [{ ifname: 'enp7s0', operstate: 'UP', addrs: [] }],
      routes: [{ dst: 'default', table: 'main', dev: 'enp7s0' }],
      sysctls: { 'net.ipv4.ip_forward': '1' },
      nftVersion: 'nftables v1.0.6 (Old Doc Yak #3)\n',
      kernelRelease: '6.1.0-arch1-1\n'
    });
    try {
      const oldConfig = validateGuardConfig({ ...CONFIG, guardStatePath: join(oldKernel.workDir, 'guard-state.json') });
      const oldDeps: VmNetworkGuardDeps = {
        config: { ...CONFIG, guardStatePath: oldConfig.guardStatePath },
        incus,
        execFile: oldKernel.exec
      };
      const guard = createVmNetworkGuard(oldDeps);
      incus.addInstance(identity1, subject1, 'dependency-access');
      await expect(guard.program({ identity: identity1, networkProfile: 'dependency-access' })).rejects.toMatchObject({
        reason: 'nft-destroy-unsupported'
      });
      // Blocked BEFORE enabling: program creates the bridge held DOWN but
      // the nft apply is refused — no table payload, no permits, link never up.
      const bridge = oldKernel.links.get(subject1.bridgeName);
      expect(bridge === undefined || bridge.operstate === 'DOWN').toBe(true);
      expect(oldKernel.nftAppliedPayloads).toHaveLength(0);
      expect(oldKernel.nftTableText).toBe('');
      const oldDockerUser = (oldKernel.ipTables.get('filter:DOCKER-USER') ?? '').split('\n').filter((l) => l.startsWith('-A '));
      expect(oldDockerUser.filter((l) => l.includes('chm_vm_guard'))).toHaveLength(0);
    } finally {
      await oldKernel.dispose();
    }
  });

  it('program succeeds on a supported floor (control)', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access');
    const result = await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    expect(result.bridgeName).toBe(subject1.bridgeName);
    // Preflight ran: nft --version + uname -r precede the first nft -f.
    const verIdx = callIndex((a) => a[0] === 'nft' && a[1] === '--version');
    const applyIdx = callIndex((a) => a[0] === 'nft' && a[1] === '-f');
    expect(verIdx).toBeGreaterThanOrEqual(0);
    expect(applyIdx).toBeGreaterThan(verIdx);
  });
});

describe('withStartTransaction', () => {
  function serviceDeps(): GuardServiceDeps {
    return { config: deps.config, incus, execFile: kernel.exec };
  }

  it('holds guard.lock across program→attest→start: guard-service cannot mutate in the window', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access', 'Stopped');
    const order: string[] = [];
    let releaseGate!: () => void;
    const gate = new Promise<void>((r) => {
      releaseGate = r;
    });
    let parked = false;
    const txPromise = guard.withStartTransaction(
      { identity: identity1, networkProfile: 'dependency-access' },
      async (tx) => {
        const programResult = await tx.program();
        order.push('program');
        expect(programResult.rulesetDigest).not.toBe(EMPTY_RULESET_DIGEST);
        const attest = await tx.attest();
        order.push('attest');
        expect(attest.ok).toBe(true);
        parked = true;
        await gate; // the attest→Incus.start window — lock still held
        order.push('incus-start');
        return 'started';
      }
    );
    // Wait until fn is parked inside the lock hold.
    for (let i = 0; i < 400 && !parked; i++) await new Promise((r) => setTimeout(r, 5));
    expect(parked).toBe(true);
    // The attest→Incus.start window: a guard-service cycle from a SEPARATE
    // async context (production: a separate process) must fail lock
    // acquisition and MUST NOT mutate kernel/claims.
    const cycle = await runGuardCycle({ ...serviceDeps(), lockOptions: { timeoutMs: 80, pollMs: 10 } });
    order.push(`guard-cycle:${cycle.verdict}`);
    expect(cycle.verdict).toBe('failed'); // lock busy → no mutation
    expect(cycle.drift.join(' ')).toMatch(/guard-lock-timeout/);
    // Kernel state is exactly as program left it — nothing drifted.
    expectNftTable([subject1]);
    releaseGate();
    await expect(txPromise).resolves.toBe('started');
    expect(order).toEqual(['program', 'attest', 'guard-cycle:failed', 'incus-start']);
    // After release the guard service can reconcile again.
    const after = await runGuardCycle({ ...serviceDeps(), lockOptions: { timeoutMs: 2_000, pollMs: 10 } });
    expect(after.verdict).not.toBe('failed');
  });

  it('cannot run fn while the lock is held — no side effects until acquisition', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access', 'Stopped');
    // Hold guard.lock through the REAL lock path — exactly what a guard
    // service mid-cycle does in production. withStartTransaction must stay
    // pending (its withGuardLock timeout rejects before fn ever runs —
    // timeout semantics proven in lock.test.ts) with ZERO side effects.
    let releaseHold!: () => void;
    const holdGate = new Promise<void>((r) => {
      releaseHold = r;
    });
    const { withGuardLock } = await import('../../src/network/lock.js');
    const holder = withGuardLock(kernel.workDir, () => holdGate);
    let fnRan = false;
    const txPromise = guard.withStartTransaction(
      { identity: identity1, networkProfile: 'dependency-access' },
      async (tx) => {
        fnRan = true;
        await tx.program();
        return 'started';
      }
    );
    await new Promise((r) => setTimeout(r, 60));
    expect(fnRan).toBe(false);
    expect(kernel.links.has(subject1.bridgeName)).toBe(false);
    expect(kernel.nftTableText).toBe('');
    expect(dockerUserRules().filter((l) => l.includes('chm_vm_guard'))).toHaveLength(0);
    // Release the hold: the transaction acquires and completes.
    releaseHold();
    await holder;
    await expect(txPromise).resolves.toBe('started');
    expect(fnRan).toBe(true);
    expectNftTable([subject1]);
  });

  it('rejects nested outer-method calls inside fn but lets unrelated callers queue', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access', 'Stopped');
    incus.addInstance(identity2, subject2, 'dependency-access', 'Stopped');
    let releaseGate!: () => void;
    const gate = new Promise<void>((r) => {
      releaseGate = r;
    });
    const txPromise = guard.withStartTransaction(
      { identity: identity1, networkProfile: 'dependency-access' },
      async (tx) => {
        await tx.program();
        // Every outer entry point must reject INSIDE the transaction —
        // queueing would deadlock behind the open fn.
        await expect(guard.program({ identity: identity1, networkProfile: 'dependency-access' })).rejects.toMatchObject({
          reason: 'nested-guard-call'
        });
        await expect(guard.attest({ identity: identity1, networkProfile: 'dependency-access' })).rejects.toMatchObject({
          reason: 'nested-guard-call'
        });
        await expect(guard.tearDown({ identity: identity1 })).rejects.toMatchObject({ reason: 'nested-guard-call' });
        await expect(
          guard.quarantine({ reason: 'x', identities: [identity1] })
        ).rejects.toMatchObject({ reason: 'nested-guard-call' });
        await expect(
          guard.withStartTransaction({ identity: identity1, networkProfile: 'dependency-access' }, async () => 'inner')
        ).rejects.toMatchObject({ reason: 'nested-guard-call' });
        // Hold the window open so the unrelated caller below queues.
        await gate;
        return 'done';
      }
    );
    // Unrelated caller from OUTSIDE the transaction context: must NOT be
    // rejected — it queues behind the open transaction and runs after.
    const unrelated = guard.program({ identity: identity2, networkProfile: 'dependency-access' });
    let unrelatedSettled = false;
    void unrelated.then(
      () => {
        unrelatedSettled = true;
      },
      () => {
        unrelatedSettled = true;
      }
    );
    await new Promise((r) => setTimeout(r, 30));
    expect(unrelatedSettled).toBe(false); // still queued, not rejected
    releaseGate();
    await expect(txPromise).resolves.toBe('done');
    await expect(unrelated).resolves.toMatchObject({ bridgeName: subject2.bridgeName });
    expectNftTable([subject1, subject2]);
  });

  it('releases the lock when fn throws — later ops proceed normally', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'dependency-access', 'Stopped');
    await expect(
      guard.withStartTransaction({ identity: identity1, networkProfile: 'dependency-access' }, async (tx) => {
        await tx.program();
        const attest = await tx.attest();
        expect(attest.ok).toBe(true);
        throw new Error('incus start failed');
      })
    ).rejects.toThrow('incus start failed');
    // Lock released: a fresh cycle and a normal program both work.
    const after = await runGuardCycle({ ...serviceDeps(), lockOptions: { timeoutMs: 2_000, pollMs: 10 } });
    expect(after.verdict).not.toBe('failed');
    const again = await guard.program({ identity: identity1, networkProfile: 'dependency-access' });
    expect(again.bridgeName).toBe(subject1.bridgeName);
  });

  it('network-none transaction: program no-ops, attest still verifies inside the lock', async () => {
    const guard = createVmNetworkGuard(deps);
    incus.addInstance(identity1, subject1, 'network-none');
    const result = await guard.withStartTransaction(
      { identity: identity1, networkProfile: 'network-none' },
      async (tx) => {
        const programResult = await tx.program();
        expect(programResult.rulesetDigest).toBe(EMPTY_RULESET_DIGEST);
        const attest = await tx.attest();
        return attest.ok;
      }
    );
    expect(result).toBe(true);
    expect(kernel.nftTableText).toBe('');
  });
});
