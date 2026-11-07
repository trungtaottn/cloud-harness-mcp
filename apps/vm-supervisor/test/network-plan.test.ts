import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { mkdtempSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  loadVmWorkspaceSubjectPlanner,
  resetVmWorkspaceSubjectPlannerForTests
} from '../src/network-plan.js';
import { VmNetworkGuardNotImplementedError, type VmNetworkGuardConfig } from '../src/network-ops.js';
import { vmNameForWorkspace } from '../src/identity.js';

/**
 * Loader tests for the canonical-subject facade: the planner MUST resolve the
 * real phase-05 policy module and return byte-identical derivations — no
 * local hash may ever substitute. Missing/malformed modules fail closed.
 */

const dir = mkdtempSync(join(tmpdir(), 'chm-netplan-'));

const GUARD_CONFIG: VmNetworkGuardConfig = {
  bridgePattern: 'chmbr%d',
  subnetPlan: '10.240.0.0/16',
  uplink: '',
  dnsResolvers: ['1.1.1.1', '8.8.8.8'],
  nonpublicCidrs: [],
  guardStatePath: join(dir, 'guard-state.json')
};

const WORKSPACE_ID = 'ws_netplan_test_workspace_0001';

async function realPolicy() {
  return import('../src/network/policy.js');
}

afterEach(() => {
  resetVmWorkspaceSubjectPlannerForTests();
  vi.doUnmock('../src/network/policy.js');
  vi.resetModules();
});

describe('loadVmWorkspaceSubjectPlanner (real policy module)', () => {
  it('plan() is identical to policy.planWorkspaceSubject for the same identity', async () => {
    const policy = await realPolicy();
    const planner = await loadVmWorkspaceSubjectPlanner(GUARD_CONFIG);
    const vmName = vmNameForWorkspace(WORKSPACE_ID);
    const subject = planner.plan({ workspaceId: WORKSPACE_ID, vmName });
    const validated = policy.validateGuardConfig(GUARD_CONFIG);
    const expected = policy.planWorkspaceSubject(validated, { workspaceId: WORKSPACE_ID, vmName });
    expect(subject).toEqual(expected);
    expect(subject.vmName).toBe(vmName);
    expect(subject.tapName.length).toBeLessThanOrEqual(15);
    expect(subject.tapName).toMatch(/^chmvt\d+$/);
  });

  it('stamp() is byte-identical to policy.nicDeviceStamp (what attest expects)', async () => {
    const policy = await realPolicy();
    const planner = await loadVmWorkspaceSubjectPlanner(GUARD_CONFIG);
    const vmName = vmNameForWorkspace(WORKSPACE_ID);
    const subject = planner.plan({ workspaceId: WORKSPACE_ID, vmName });
    const stamp = planner.stamp(subject);
    expect(stamp).toEqual(policy.nicDeviceStamp(subject));
    expect(stamp['host_name']).toBe(subject.tapName);
    expect(stamp['host_name']!.length).toBeLessThanOrEqual(15);
    expect(stamp['ipv4.address']).toBe(`${subject.guestIp}/${subject.prefixLength}`);
    expect(stamp.nictype).toBe('bridged');
  });

  it('findCollisions() detects a real slot collision across candidate ids', async () => {
    const planner = await loadVmWorkspaceSubjectPlanner(GUARD_CONFIG);
    const first = planner.plan({ workspaceId: WORKSPACE_ID, vmName: vmNameForWorkspace(WORKSPACE_ID) });
    // Scan deterministic candidates until one derives to the same bridge slot.
    let colliding: string | undefined;
    for (let i = 0; i < 200_000 && colliding === undefined; i += 1) {
      const candidate = `ws_collision_probe_${i.toString().padStart(8, '0')}`;
      const probe = planner.plan({ workspaceId: candidate, vmName: vmNameForWorkspace(candidate) });
      if (probe.bridgeName === first.bridgeName) colliding = candidate;
    }
    expect(colliding).toBeDefined();
    const collisions = planner.findCollisions([WORKSPACE_ID, colliding!]);
    expect(collisions).toHaveLength(1);
    expect(collisions[0]!.bridgeName).toBe(first.bridgeName);
    expect(collisions[0]!.workspaceIds.sort()).toEqual([WORKSPACE_ID, colliding!].sort());
    // No collision for distinct slots.
    expect(planner.findCollisions([WORKSPACE_ID])).toEqual([]);
  });

  it('plan() rejects a vmName that does not match deriveVmName (fail closed)', async () => {
    const planner = await loadVmWorkspaceSubjectPlanner(GUARD_CONFIG);
    expect(() => planner.plan({ workspaceId: WORKSPACE_ID, vmName: 'chm-vm-' + '0'.repeat(32) }))
      .toThrowError(/does not match derived name|identity/i);
  });

  it('invalid guard config propagates VmNetworkGuardError (fail closed, no fallback)', async () => {
    await expect(loadVmWorkspaceSubjectPlanner({ ...GUARD_CONFIG, subnetPlan: '10.240.0.1/16' }))
      .rejects.toThrowError(/host bits|CIDR|invalid/i);
    resetVmWorkspaceSubjectPlannerForTests();
    await expect(loadVmWorkspaceSubjectPlanner({ ...GUARD_CONFIG, bridgePattern: 'chmbr' }))
      .rejects.toThrowError(/%d|bridgePattern/i);
  });
});

describe('loadVmWorkspaceSubjectPlanner (missing/malformed module)', () => {
  it('missing policy module fails closed with VmNetworkGuardNotImplementedError', async () => {
    vi.doMock('../src/network/policy.js', () => {
      throw new Error('Cannot find module');
    });
    resetVmWorkspaceSubjectPlannerForTests();
    await expect(loadVmWorkspaceSubjectPlanner(GUARD_CONFIG))
      .rejects.toBeInstanceOf(VmNetworkGuardNotImplementedError);
  });

  it('module without the required exports fails closed', async () => {
    vi.doMock('../src/network/policy.js', () => ({ unrelated: 42 }));
    resetVmWorkspaceSubjectPlannerForTests();
    await expect(loadVmWorkspaceSubjectPlanner(GUARD_CONFIG))
      .rejects.toBeInstanceOf(VmNetworkGuardNotImplementedError);
  });

  it('planner.plan surfaces guard derivation errors as VmNetworkGuardError', async () => {
    vi.doMock('../src/network/policy.js', async () => {
      const actual = await vi.importActual('../src/network/policy.js') as Record<string, unknown>;
      return {
        ...actual,
        planWorkspaceSubject: () => ({ bogus: true })
      };
    });
    resetVmWorkspaceSubjectPlannerForTests();
    const planner = await loadVmWorkspaceSubjectPlanner(GUARD_CONFIG);
    expect(() => planner.plan({ workspaceId: WORKSPACE_ID, vmName: vmNameForWorkspace(WORKSPACE_ID) }))
      .toThrowError(VmNetworkGuardNotImplementedError);
  });
});
