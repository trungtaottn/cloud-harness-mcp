import { DatabaseSync } from 'node:sqlite';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { DependencyStore } from '../src/dependency-store.js';

const databases: DatabaseSync[] = [];
function setup() {
  const db = new DatabaseSync(':memory:'); databases.push(db);
  return { db, store: new DependencyStore(db) };
}
const spec = () => ({ workspaceId: 'ws_abcdefghijklmnopqrst', ecosystem: 'go' as const, directory: '.', snapshots: { 'go.mod': 'module example.com/test', 'go.sum': '' }, imageId: 'sha256:image', profileDigest: 'profile', dependencies: ['example.com/a@v1.0.0'], maxBytes: 1000, timeoutMs: 5000 });
afterEach(() => { databases.splice(0).forEach((db) => db.close()); vi.useRealTimers(); });
describe('DependencyStore', () => {
  it('requires exact owner approval and fences concurrent starts and replay identity', async () => {
    const { store, db } = setup(); const r = store.create('alice', spec()); const { planId, planDigest } = r.view;
    expect(() => store.get('bob', planId)).toThrow('not found');
    expect(store.list('bob')).toEqual([]);
    expect(() => store.start('alice', planId, planDigest, 'ws_abcdefghijklmnopqrst')).toThrow('Approve');
    expect(() => store.approve('alice', { planId, planDigest: 'wrong' })).toThrow('digest');
    store.approve('alice', { planId, planDigest });
    const second = new DependencyStore(db);
    const results = await Promise.all([store, second].map(async (s) => s.start('alice', planId, planDigest, 'ws_abcdefghijklmnopqrst')));
    expect(results.map((r) => r.replayed)).toEqual([false, true]);
    expect(() => store.start('alice', planId, 'wrong', 'ws_abcdefghijklmnopqrst')).toThrow('digest');
    expect(() => store.start('alice', planId, planDigest, 'ws_other')).toThrow('workspace');
    expect(() => store.reject('alice', { planId })).toThrow('cannot');
    expect(store.finish('alice', planId, { sizeBytes: 25 }).state).toBe('SUCCEEDED');
    expect(store.start('alice', planId, planDigest, 'ws_abcdefghijklmnopqrst').replayed).toBe(true);
    expect(store.get('alice', planId).snapshots).toEqual({});
    expect(store.create('alice', spec()).view.changes).toEqual({ added: 0, removed: 0 });
  });
  it('expires approvals and retains rejected states', () => {
    vi.useFakeTimers(); const { store } = setup(); const r = store.create('alice', spec());
    vi.advanceTimersByTime(30 * 60_000);
    expect(() => store.approve('alice', r.view)).toThrow('expired');
    expect(store.list('alice')[0]?.state).toBe('EXPIRED');
    const next = store.create('alice', spec()); store.reject('alice', next.view);
    expect(() => store.approve('alice', next.view)).toThrow('cannot');
  });
  it('recovers interrupted operations without replaying side effects or leaking diagnostics', () => {
    const { store, db } = setup(); const r = store.create('alice', spec());
    store.approve('alice', r.view); store.start('alice', r.view.planId, r.view.planDigest, 'ws_abcdefghijklmnopqrst');
    const restarted = new DependencyStore(db); restarted.recoverInterrupted();
    expect(restarted.get('alice', r.view.planId).view.state).toBe('FAILED');
    expect(restarted.start('alice', r.view.planId, r.view.planDigest, 'ws_abcdefghijklmnopqrst').replayed).toBe(true);
  });
  it('keeps bounded safe failure categories without raw diagnostics and replays failed outcomes', () => {
    const { store } = setup(); const r = store.create('alice', spec());
    store.approve('alice', r.view); store.start('alice', r.view.planId, r.view.planDigest, r.view.workspaceId);
    const result = store.finish('alice', r.view.planId, { error: 'TIMEOUT: private repository token=secret' });
    expect(result.error).toContain('timed out'); expect(result.error).not.toContain('secret');
    expect(store.start('alice', r.view.planId, r.view.planDigest, r.view.workspaceId).record.view).toEqual(result);
    expect(() => store.start('alice', r.view.planId, 'different', r.view.workspaceId)).toThrow('digest');
  });
  it('bounds outstanding plans and terminal history', () => {
    const { store, db } = setup();
    for (let i = 0; i < 32; i++) store.create('alice', spec());
    expect(() => store.create('alice', spec())).toThrow('32');
    for (const plan of store.list('alice')) store.reject('alice', plan);
    for (let i = 0; i < 110; i++) store.reject('alice', store.create('alice', spec()).view);
    expect(store.list('alice')).toHaveLength(100);
    expect((db.prepare('SELECT COUNT(*) n FROM dependency_plans').get() as { n: number }).n).toBeLessThanOrEqual(101);
  });
});
