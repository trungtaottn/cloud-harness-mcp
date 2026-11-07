import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { VmJournal } from '../src/journal.js';

const dirs: string[] = [];
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'vm-journal-'));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

const WS = 'ws_abcdefghijklmnopqrstuvwxyz1234';
const INSTANCE = '3f6b2a1c-9d4e-4f5a-8b7c-6d5e4f3a2b1c';

describe('VmJournal workspace identity and fencing', () => {
  it('persists identity across reopen and fences generation monotonically', () => {
    const dir = tempDir();
    const path = join(dir, 'journal.db');
    {
      const journal = new VmJournal(path);
      journal.recordWorkspaceAdmit({
        workspaceId: WS, vmName: 'chm-vm-' + 'a'.repeat(32), instanceId: INSTANCE,
        templateId: 'tpl', templateDigest: 'b'.repeat(64), generation: 3, networkProfile: 'dependency-access'
      });
      expect(journal.acceptGeneration(WS, 3)).toBe('accepted');
      expect(journal.acceptGeneration(WS, 4)).toBe('accepted');
      expect(journal.acceptGeneration(WS, 3)).toBe('stale');
      expect(journal.acceptGeneration(WS, 2)).toBe('stale');
      journal.close();
    }
    {
      const journal = new VmJournal(path);
      const row = journal.getWorkspace(WS);
      expect(row?.vmName).toBe('chm-vm-' + 'a'.repeat(32));
      expect(row?.instanceId).toBe(INSTANCE);
      expect(row?.acceptedGeneration).toBe(4);
      expect(row?.networkProfile).toBe('dependency-access');
      expect(journal.acceptGeneration(WS, 4)).toBe('accepted');
      expect(journal.acceptGeneration(WS, 5)).toBe('accepted');
      journal.close();
    }
  });

  it('rejects identity mutation for a known workspace', () => {
    const journal = new VmJournal(join(tempDir(), 'j.db'));
    journal.recordWorkspaceAdmit({
      workspaceId: WS, vmName: 'chm-vm-' + 'a'.repeat(32), instanceId: INSTANCE,
      templateId: 'tpl', templateDigest: 'b'.repeat(64), generation: 1, networkProfile: 'network-none'
    });
    expect(() => journal.recordWorkspaceAdmit({
      workspaceId: WS, vmName: 'chm-vm-' + 'c'.repeat(32), instanceId: 'd'.repeat(8) + '-0000-4000-8000-' + 'e'.repeat(12),
      templateId: 'tpl', templateDigest: 'b'.repeat(64), generation: 2, networkProfile: 'network-none'
    })).toThrow(/identity/i);
    journal.close();
  });

  it('tracks workspace lifecycle state', () => {
    const journal = new VmJournal(join(tempDir(), 'j.db'));
    journal.recordWorkspaceAdmit({
      workspaceId: WS, vmName: 'chm-vm-' + 'a'.repeat(32), instanceId: INSTANCE,
      templateId: 'tpl', templateDigest: 'b'.repeat(64), generation: 1, networkProfile: 'dependency-access'
    });
    expect(journal.getWorkspace(WS)?.state).toBe('admitted');
    journal.setWorkspaceState(WS, 'stopped');
    journal.setWorkspaceState(WS, 'running');
    expect(journal.getWorkspace(WS)?.state).toBe('running');
    journal.setWorkspaceState(WS, 'deleted');
    expect(journal.getWorkspace(WS)?.state).toBe('deleted');
    expect(journal.countRunningManaged()).toBe(0);
    journal.close();
  });
});

describe('VmJournal leases', () => {
  it('sets, reads, lists, clears and expires leases with clamped values applied upstream', () => {
    const journal = new VmJournal(join(tempDir(), 'j.db'));
    journal.setLease({
      workspaceId: WS, instanceId: INSTANCE, generation: 2,
      expiresAt: 10_000, hardExpiresAt: 20_000, lastRenewalAt: 5_000, state: 'active'
    });
    const lease = journal.getLease(WS);
    expect(lease).toMatchObject({ expiresAt: 10_000, hardExpiresAt: 20_000, state: 'active', generation: 2 });
    expect(journal.listLeases()).toHaveLength(1);
    journal.setLeaseState(WS, 'expired');
    expect(journal.getLease(WS)?.state).toBe('expired');
    journal.clearLease(WS);
    expect(journal.getLease(WS)?.state).toBe('cleared');
    expect(journal.listLeases().filter((l) => l.state !== 'cleared')).toHaveLength(0);
    journal.close();
  });

  it('renews expiresAt only and never hardExpiresAt', () => {
    const journal = new VmJournal(join(tempDir(), 'j.db'));
    journal.setLease({
      workspaceId: WS, instanceId: INSTANCE, generation: 1,
      expiresAt: 10_000, hardExpiresAt: 50_000, lastRenewalAt: 1_000, state: 'active'
    });
    journal.renewLease(WS, { expiresAt: 30_000, lastRenewalAt: 9_000 });
    const lease = journal.getLease(WS);
    expect(lease?.expiresAt).toBe(30_000);
    expect(lease?.hardExpiresAt).toBe(50_000);
    expect(lease?.lastRenewalAt).toBe(9_000);
    journal.close();
  });
});

describe('VmJournal idempotency', () => {
  const base = { workspaceId: WS, op: 'vm.create', key: 'idem-key-0001', digest: 'd'.repeat(64) };

  it('replays a recorded result for the same key and digest', () => {
    const journal = new VmJournal(join(tempDir(), 'j.db'));
    const first = journal.beginIdempotent(base);
    expect(first.kind).toBe('proceed');
    if (first.kind === 'proceed') journal.completeIdempotent(first.recordId, { vmName: 'chm-vm-x', state: 'stopped' });
    const replay = journal.beginIdempotent(base);
    expect(replay.kind).toBe('replay');
    if (replay.kind === 'replay') expect(replay.result).toEqual({ vmName: 'chm-vm-x', state: 'stopped' });
    journal.close();
  });

  it('conflicts when the same key carries a different digest', () => {
    const journal = new VmJournal(join(tempDir(), 'j.db'));
    const first = journal.beginIdempotent(base);
    if (first.kind === 'proceed') journal.completeIdempotent(first.recordId, { ok: true });
    const conflict = journal.beginIdempotent({ ...base, digest: 'e'.repeat(64) });
    expect(conflict.kind).toBe('conflict');
    journal.close();
  });

  it('scopes keys per workspace and op', () => {
    const journal = new VmJournal(join(tempDir(), 'j.db'));
    const a = journal.beginIdempotent(base);
    if (a.kind === 'proceed') journal.completeIdempotent(a.recordId, { n: 1 });
    expect(journal.beginIdempotent({ ...base, op: 'vm.stop' }).kind).toBe('proceed');
    expect(journal.beginIdempotent({ ...base, workspaceId: 'ws_zyxwvutsrqponmlkjihgfedcba98765432' }).kind).toBe('proceed');
    journal.close();
  });

  it('reports pending records as unknown on replay', () => {
    const journal = new VmJournal(join(tempDir(), 'j.db'));
    journal.beginIdempotent(base); // never completed — simulates crash mid-op
    const replay = journal.beginIdempotent(base);
    expect(replay.kind).toBe('unknown');
    journal.close();
  });
});

describe('VmJournal exec ops, sessions, uploads, events', () => {
  it('records exec lifecycle for inspect', () => {
    const journal = new VmJournal(join(tempDir(), 'j.db'));
    journal.recordExecStart({ opId: 'op-1', workspaceId: WS, sessionId: 'sess-1' });
    expect(journal.getExecOp('op-1')).toMatchObject({ state: 'running', exitCode: null });
    journal.recordExecEnd('op-1', { exitCode: 0, signal: null, returnMetadata: { return: 0 } });
    expect(journal.getExecOp('op-1')).toMatchObject({ state: 'exited', exitCode: 0 });
    journal.close();
  });

  it('manages session registry with ownership fields', () => {
    const journal = new VmJournal(join(tempDir(), 'j.db'));
    journal.registerSession({ sessionId: 'sess-1', workspaceId: WS, instanceId: INSTANCE, generation: 2, pty: true });
    journal.touchSession('sess-1');
    const session = journal.getSession('sess-1');
    expect(session).toMatchObject({ workspaceId: WS, instanceId: INSTANCE, generation: 2, pty: true, state: 'open' });
    journal.setSessionState('sess-1', 'closed');
    expect(journal.getSession('sess-1')?.state).toBe('closed');
    journal.close();
  });

  it('manages one-time bounded uploads', () => {
    const journal = new VmJournal(join(tempDir(), 'j.db'));
    journal.createUpload({ uploadId: 'upl-1', workspaceId: WS, instanceId: INSTANCE, generation: 1, path: '/tmp/x', maxBytes: 1024, expiresAt: 9_999 });
    expect(journal.getUpload('upl-1')).toMatchObject({ consumed: false, maxBytes: 1024 });
    expect(journal.consumeUpload('upl-1')).toBe(true);
    expect(journal.consumeUpload('upl-1')).toBe(false);
    expect(journal.getUpload('upl-1')?.consumed).toBe(true);
    journal.close();
  });

  it('appends bounded events and prunes', () => {
    const journal = new VmJournal(join(tempDir(), 'j.db'));
    for (let i = 0; i < 5; i += 1) journal.appendEvent('watchdog.tick', WS, { i });
    const events = journal.listEvents(3);
    expect(events).toHaveLength(3);
    expect(events[0]?.detail).toEqual({ i: 2 });
    expect(events[2]?.detail).toEqual({ i: 4 });
    journal.close();
  });
});
