import { mkdtempSync, rmSync } from 'node:fs';
import { mkdir, readdir, utimes } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it, vi } from 'vitest';
import type { RunnerConfig } from '@cloud-harness/contracts';
import { StateStore, type WorkspaceRecord } from '../src/state-store.js';
import { ExecutorStore } from '../src/executor-store.js';
import { RemoteWorkspace } from '../src/remote-workspace.js';

const cleanups: Array<() => void> = [];
afterEach(() => { vi.restoreAllMocks(); cleanups.splice(0).forEach(cleanup => cleanup()); });
function setup() {
  const dir = mkdtempSync(join(tmpdir(), 'ch-remote-workspace-'));
  const store = new StateStore(join(dir, 'state.db'));
  cleanups.push(() => { store.close(); rmSync(dir, { recursive: true, force: true }); });
  const allocations = new ExecutorStore(store.database);
  const config = { instabox: { apiKey: 'test-only', machineIds: ['first', 'second'], principalId: 'owner', allowPublicNetwork: true }, maxWorkspaceBytes: 10 * 1024 ** 3, maxOutputBytes: 4096 } as RunnerConfig;
  const remote = new RemoteWorkspace(allocations, config);
  const record = { id: 'ws_retained', ownerId: 'owner', workspacePath: dir } as WorkspaceRecord;
  return { remote, allocations, record };
}

it('retains a failed stop and never reports that its machine can be reused', async () => {
  const { remote, allocations, record } = setup();
  const ref = allocations.reserve(record.id, record.ownerId, ['first'])!;
  allocations.setState(ref, 'ACTIVE');
  vi.spyOn(remote.backend, 'stop').mockRejectedValue(new Error('stop outcome unknown'));
  await expect(remote.stop(record)).rejects.toThrow('unknown');
  expect(allocations.byWorkspace(record.id)?.state).toBe('QUARANTINED');
  expect(allocations.reserve('ws_other', 'owner', ['first'])).toBeUndefined();
});

it('quarantines cleanup uncertainty and releases only after confirmed stop', async () => {
  const { remote, allocations, record } = setup();
  allocations.reserve(record.id, record.ownerId, ['first']);
  vi.spyOn(remote.backend, 'start').mockResolvedValue();
  vi.spyOn(remote.backend, 'run').mockResolvedValue({ exitCode: 0, stdout: '', stderr: '' });
  const stop = vi.spyOn(remote.backend, 'stop').mockRejectedValueOnce(new Error('lost stop receipt')).mockResolvedValue();
  await expect(remote.release(record)).rejects.toThrow('lost stop');
  expect(allocations.byWorkspace(record.id)?.state).toBe('QUARANTINED');
  expect(allocations.reserve('ws_other', 'owner', ['first'])).toBeUndefined();
  await remote.release(record);
  expect(stop).toHaveBeenCalledTimes(3);
  expect(allocations.byWorkspace(record.id)).toBeUndefined();
  expect(allocations.reserve('ws_other', 'owner', ['first'])).toBeDefined();
});

it('selects another available allowlisted machine before local capacity fallback', async () => {
  const { remote, allocations, record } = setup();
  vi.spyOn(remote.backend, 'inspect')
    .mockResolvedValueOnce({ state: 'stopped', ready: false, cooldownUntil: new Date(Date.now() + 60000).toISOString() })
    .mockResolvedValueOnce({ state: 'stopped', ready: false });
  expect(await remote.reserve(record)).toBe(true);
  expect(allocations.byWorkspace(record.id)?.machineId).toBe('second');
  expect(allocations.reserve('ws_other', 'owner', ['first'])).toBeDefined();
  expect(await remote.reserve({ ...record, id: 'ws_third' })).toBe(false);
});

it('rejects a missing retained checkout without allocating a replacement', async () => {
  const { remote, allocations, record } = setup();
  const ref = allocations.reserve(record.id, record.ownerId, ['first'])!;
  allocations.setState(ref, 'STOPPED');
  vi.spyOn(remote.backend, 'start').mockResolvedValue();
  vi.spyOn(remote.backend, 'run').mockResolvedValue({ exitCode: 1, stdout: '', stderr: '' });
  await expect(remote.resume(record)).rejects.toThrow('Retained remote checkout');
  expect(allocations.byWorkspace(record.id)).toMatchObject({ generation: ref.generation, state: 'QUARANTINED', machineId: 'first' });
});

it('uses immutable allocation identity after lifecycle state changes', () => {
  const { remote, allocations, record } = setup();
  const allocation = allocations.reserve(record.id, record.ownerId, ['first'])!;
  const before = remote.ref(record);
  allocations.setState(allocation, 'ACTIVE');
  expect(remote.ref(record)).toEqual(before);
  expect(before).not.toHaveProperty('state');
  expect(() => remote.ref({ ...record, ownerId: 'another-owner' })).toThrow();
});

function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>(done => { resolve = done; });
  return { promise, resolve };
}
it('reclaims abandoned skill transfers without counting unrelated directory entries', async () => {
  const { remote, allocations, record } = setup();
  allocations.reserve(record.id, record.ownerId, ['first']);
  const base = join(record.workspacePath, 'remote-skill-snapshots');
  const old = new Date(Date.now() - 3600001);
  for (let index = 0; index < 32; index++) {
    const incoming = join(base, 'incoming-' + index.toString(16).padStart(24, '0'));
    await mkdir(incoming, { recursive: true });
    await utimes(incoming, old, old);
    await mkdir(join(base, `unrelated-${index}`));
  }
  vi.spyOn(remote, 'exportTree').mockImplementation(async (_record, _guest, destination) => {
    await mkdir(destination);
    return 'a'.repeat(64);
  });
  expect(await remote.snapshotCheckout(record)).toBe(join(base, 'a'.repeat(64)));
  const entries = await readdir(base);
  expect(entries.filter(entry => entry.startsWith('incoming-'))).toEqual([]);
  expect(entries.filter(entry => entry.startsWith('unrelated-'))).toHaveLength(32);
});
it('keeps recent interrupted skill transfers inside the snapshot storage bound', async () => {
  const { remote, allocations, record } = setup();
  allocations.reserve(record.id, record.ownerId, ['first']);
  for (let index = 0; index < 32; index++) {
    await mkdir(join(record.workspacePath, 'remote-skill-snapshots', 'incoming-' + index.toString(16).padStart(24, '0')), { recursive: true });
  }
  const exportTree = vi.spyOn(remote, 'exportTree');
  await expect(remote.snapshotCheckout(record)).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
  expect(exportTree).not.toHaveBeenCalled();
});
it('rejects concurrent stop and release while resume owns the allocation', async () => {
  const { remote, allocations, record } = setup();
  const ref = allocations.reserve(record.id, record.ownerId, ['first'])!;
  allocations.setState(ref, 'STOPPED');
  const gate = deferred();
  vi.spyOn(remote.backend, 'start').mockReturnValue(gate.promise);
  const run = vi.spyOn(remote.backend, 'run').mockResolvedValue({ exitCode: 0, stdout: '', stderr: '' });
  const stop = vi.spyOn(remote.backend, 'stop').mockResolvedValue();
  const resumed = remote.resume(record);
  expect(allocations.byWorkspace(record.id)?.state).toBe('STARTING');
  await expect(remote.release(record)).rejects.toMatchObject({ code: 'CONFLICT' });
  await expect(remote.stop(record)).rejects.toMatchObject({ code: 'CONFLICT' });
  expect(run).not.toHaveBeenCalled(); expect(stop).not.toHaveBeenCalled();
  gate.resolve(); await resumed;
  expect(allocations.byWorkspace(record.id)?.state).toBe('ACTIVE');
});
it('rejects concurrent resume and release while stop owns the allocation', async () => {
  const { remote, allocations, record } = setup();
  const ref = allocations.reserve(record.id, record.ownerId, ['first'])!;
  allocations.setState(ref, 'ACTIVE');
  const gate = deferred();
  vi.spyOn(remote.backend, 'stop').mockReturnValue(gate.promise);
  const start = vi.spyOn(remote.backend, 'start').mockResolvedValue();
  const stopped = remote.stop(record);
  await expect(remote.resume(record)).rejects.toMatchObject({ code: 'CONFLICT' });
  await expect(remote.release(record)).rejects.toMatchObject({ code: 'CONFLICT' });
  expect(start).not.toHaveBeenCalled(); gate.resolve(); await stopped;
  expect(allocations.byWorkspace(record.id)?.state).toBe('STOPPED');
});
it('never starts destructive cleanup after a lost claim or a lost post-start fence', async () => {
  const { remote, allocations, record } = setup();
  allocations.reserve(record.id, record.ownerId, ['first']);
  const start = vi.spyOn(remote.backend, 'start').mockResolvedValue();
  vi.spyOn(remote.backend, 'stop').mockResolvedValue();
  const run = vi.spyOn(remote.backend, 'run').mockResolvedValue({ exitCode: 0, stdout: '', stderr: '' });
  vi.spyOn(allocations, 'setState').mockReturnValueOnce(false);
  await expect(remote.release(record)).rejects.toMatchObject({ code: 'CONFLICT' });
  expect(start).not.toHaveBeenCalled(); expect(run).not.toHaveBeenCalled();
  const gate = deferred(); start.mockReturnValue(gate.promise);
  const released = remote.release(record);
  await vi.waitFor(() => expect(start).toHaveBeenCalledOnce());
  allocations.quarantineInterrupted();
  gate.resolve();
  await expect(released).rejects.toMatchObject({ code: 'CONFLICT' });
  expect(run).not.toHaveBeenCalled();
  expect(allocations.byWorkspace(record.id)?.state).toBe('QUARANTINED');
});
it('ends the old boot before scoped cleanup and confirms final shutdown before reuse', async () => {
  const { remote, allocations, record } = setup();
  allocations.reserve(record.id, record.ownerId, ['first']);
  const order: string[] = [];
  vi.spyOn(remote.backend, 'stop').mockImplementation(async () => { order.push('stop'); });
  vi.spyOn(remote.backend, 'start').mockImplementation(async () => { order.push('start'); });
  vi.spyOn(remote.backend, 'run').mockImplementation(async () => { order.push('cleanup'); return { stdout: '', stderr: '', exitCode: 0 }; });
  await remote.release(record);
  expect(order).toEqual(['stop', 'start', 'cleanup', 'stop']);
  expect(vi.mocked(remote.backend.run).mock.calls[0]?.[1]).toContain("'sudo' '-n' '--' 'python3' '-c'");
  expect(allocations.isReleased(record.id, record.ownerId)).toBe(true);
});
it('keeps cleanup intent pinned when privileged scoped deletion fails', async () => {
  const { remote, allocations, record } = setup();
  allocations.reserve(record.id, record.ownerId, ['first']);
  vi.spyOn(remote.backend, 'start').mockResolvedValue();
  const stop = vi.spyOn(remote.backend, 'stop').mockResolvedValue();
  vi.spyOn(remote.backend, 'run').mockResolvedValue({ stdout: '', stderr: '', exitCode: 1 });
  await expect(remote.release(record)).rejects.toThrow('remote workspace cleanup failed');
  expect(stop).toHaveBeenCalledOnce();
  expect(allocations.byWorkspace(record.id)).toMatchObject({ state: 'QUARANTINED', cleanupRequested: true });
  expect(allocations.isReleased(record.id, record.ownerId)).toBe(false);
});
it('does not report success after a provider effect loses its publication fence', async () => {
  const { remote, allocations, record } = setup();
  const ref = allocations.reserve(record.id, record.ownerId, ['first'])!;
  allocations.setState(ref, 'ACTIVE');
  vi.spyOn(remote.backend, 'stop').mockResolvedValue();
  const original = allocations.setState.bind(allocations);
  vi.spyOn(allocations, 'setState').mockImplementation((identity, state, generation) => state === 'STOPPED' ? false : original(identity, state, generation));
  await expect(remote.stop(record)).rejects.toMatchObject({ code: 'CONFLICT' });
  expect(allocations.byWorkspace(record.id)?.state).toBe('QUARANTINED');
});
it('recovers an uncertain stop by explicit resume without replacing retained work', async () => {
  const { remote, allocations, record } = setup();
  const ref = allocations.reserve(record.id, record.ownerId, ['first'])!;
  allocations.setState(ref, 'ACTIVE');
  vi.spyOn(remote.backend, 'stop').mockRejectedValueOnce(new Error('transport lost'));
  const start = vi.spyOn(remote.backend, 'start').mockResolvedValue();
  const check = vi.spyOn(remote.backend, 'run').mockResolvedValue({ exitCode: 0, stdout: '', stderr: '' });
  await expect(remote.stop(record)).rejects.toThrow('transport lost');
  expect(allocations.byWorkspace(record.id)).toMatchObject({ state: 'QUARANTINED', cleanupRequested: false });
  expect(start).not.toHaveBeenCalled();
  await remote.resume(record);
  expect(check).toHaveBeenCalledOnce();
  expect(allocations.byWorkspace(record.id)).toMatchObject({ state: 'ACTIVE', generation: ref.generation, machineId: ref.machineId, root: ref.root });
});
it('never resumes or stops quarantined partial cleanup, but can retry an uncertain stop explicitly', async () => {
  const { remote, allocations, record } = setup();
  const ref = allocations.reserve(record.id, record.ownerId, ['first'])!;
  allocations.setState(ref, 'QUARANTINED');
  const stop = vi.spyOn(remote.backend, 'stop').mockResolvedValue();
  const start = vi.spyOn(remote.backend, 'start').mockResolvedValue();
  await remote.stop(record);
  expect(allocations.byWorkspace(record.id)?.state).toBe('STOPPED');
  allocations.setState(ref, 'RELEASING'); allocations.setState(ref, 'QUARANTINED');
  stop.mockClear();
  await expect(remote.resume(record)).rejects.toMatchObject({ code: 'CONFLICT' });
  await expect(remote.stop(record)).rejects.toMatchObject({ code: 'CONFLICT' });
  expect(start).not.toHaveBeenCalled(); expect(stop).not.toHaveBeenCalled();
  expect(allocations.byWorkspace(record.id)).toMatchObject({ state: 'QUARANTINED', cleanupRequested: true });
});
