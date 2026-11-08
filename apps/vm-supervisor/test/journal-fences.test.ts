import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { VmJournal } from '../src/journal.js';

const dirs: string[] = [];
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'vm-journal-fences-'));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

const WS = 'ws_fence_abcdefghijklmnopqrstuvwxyz';
const INSTANCE = '3f6b2a1c-9d4e-4f5a-8b7c-6d5e4f3a2b1c';

function admit(journal: VmJournal, generation = 5): void {
  journal.recordWorkspaceAdmit({
    workspaceId: WS, vmName: 'chm-vm-' + 'a'.repeat(32), instanceId: INSTANCE,
    templateId: 'tpl', templateDigest: 'b'.repeat(64), generation, networkProfile: 'network-none'
  });
}

describe('idempotency pending fences', () => {
  it('never prunes pending rows past the completed-row cap', () => {
    const journal = new VmJournal(join(tempDir(), 'j.db'));
    // 520 completed rows push the cap; then one pending row must survive.
    for (let i = 0; i < 520; i += 1) {
      const begin = journal.beginIdempotent({ workspaceId: WS, op: 'vm.stop', key: `k${i}`, digest: `d${i}` });
      if (begin.kind !== 'proceed') throw new Error('expected proceed');
      journal.completeIdempotent(begin.recordId, { ok: i });
    }
    const pending = journal.beginIdempotent({ workspaceId: WS, op: 'vm.create', key: 'pending-key', digest: 'pd' });
    if (pending.kind !== 'proceed') throw new Error('expected proceed');
    // Trigger pruning with another completed op.
    const trigger = journal.beginIdempotent({ workspaceId: WS, op: 'vm.stop', key: 'trigger', digest: 'dt' });
    if (trigger.kind === 'proceed') journal.completeIdempotent(trigger.recordId, {});
    // The pending row is the retry fence: a retry must report unknown, not proceed.
    const retry = journal.beginIdempotent({ workspaceId: WS, op: 'vm.create', key: 'pending-key', digest: 'pd' });
    expect(retry.kind).toBe('unknown');
    journal.close();
  }, 20_000);
});

describe('recordWorkspaceAdmit generation fencing', () => {
  it('rejects stale-generation re-admit and does not bump updated_at', () => {
    const journal = new VmJournal(join(tempDir(), 'j.db'));
    admit(journal, 5);
    const before = journal.getWorkspace(WS)!;
    expect(() => admit(journal, 3)).toThrow(/stale generation/);
    const after = journal.getWorkspace(WS)!;
    expect(after.updatedAt).toBe(before.updatedAt);
    expect(after.acceptedGeneration).toBe(5);
    journal.close();
  });
});

describe('renewLease policy', () => {
  it('reactivates an expired lease within the hard cutoff', () => {
    const journal = new VmJournal(join(tempDir(), 'j.db'));
    admit(journal);
    const now = Math.floor(Date.now() / 1000);
    journal.setLease({
      workspaceId: WS, instanceId: INSTANCE, generation: 5,
      expiresAt: now - 10, hardExpiresAt: now + 3600, lastRenewalAt: now - 100, state: 'active'
    });
    journal.setLeaseState(WS, 'expired');
    journal.renewLease(WS, { expiresAt: now + 600, lastRenewalAt: now });
    const lease = journal.getLease(WS)!;
    expect(lease.state).toBe('active');
    expect(lease.expiresAt).toBe(now + 600);
    journal.close();
  });

  it('rejects renewal past the hard expiry and on cleared leases', () => {
    const journal = new VmJournal(join(tempDir(), 'j.db'));
    admit(journal);
    const now = Math.floor(Date.now() / 1000);
    journal.setLease({
      workspaceId: WS, instanceId: INSTANCE, generation: 5,
      expiresAt: now + 60, hardExpiresAt: now + 120, lastRenewalAt: now, state: 'active'
    });
    expect(() => journal.renewLease(WS, { expiresAt: now + 300, lastRenewalAt: now })).toThrow(/hard expiry/);
    journal.clearLease(WS);
    expect(() => journal.renewLease(WS, { expiresAt: now + 60, lastRenewalAt: now })).toThrow(/no renewable lease/);
    journal.close();
  });
});
