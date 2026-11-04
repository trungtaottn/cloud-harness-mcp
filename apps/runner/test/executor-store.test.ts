import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, expect, it } from 'vitest';
import { StateStore } from '../src/state-store.js';
import { ExecutorStore } from '../src/executor-store.js';
const dirs: string[] = [];
const stores: StateStore[] = [];
afterEach(() => { stores.splice(0).forEach(s => s.close()); dirs.splice(0).forEach(d => rmSync(d, { recursive: true, force: true })); });
function setup() {
  const dir = mkdtempSync(join(tmpdir(), 'allocations-')); dirs.push(dir);
  const path = join(dir, 'state.db');
  const first = new StateStore(path); const second = new StateStore(path); stores.push(first, second);
  return [new ExecutorStore(first.database), new ExecutorStore(second.database)] as const;
}
it('reserves atomically across connections and retains stopped/quarantined capacity', () => {
  const [a, b] = setup();
  const ref = a.reserve('ws_first', 'canonical-owner', ['machine-a'])!;
  expect(ref).toBeDefined();
  expect(b.reserve('ws_second', 'canonical-owner', ['machine-a'])).toBeUndefined();
  expect(a.setState(ref, 'STOPPED')).toBe(true);
  expect(b.reserve('ws_second', 'canonical-owner', ['machine-a'])).toBeUndefined();
  expect(a.setState(ref, 'QUARANTINED')).toBe(true);
  expect(b.release(ref)).toBe(false);
  expect(b.reserve('ws_second', 'canonical-owner', ['machine-a'])).toBeUndefined();
});
it('fences stale revisions and immutable identities on release and provider access', () => {
  const [a, b] = setup(); const ref = a.reserve('ws_first', 'canonical-owner', ['machine-a'])!;
  expect(a.setState(ref, 'ACTIVE', 0)).toBe(true);
  expect(b.setState(ref, 'STOPPED', 0)).toBe(false);
  expect(() => a.assertRef({ ...ref, ownerId: 'display-name' })).toThrow();
  expect(() => a.assertRef({ ...ref, root: '/data/home' })).toThrow();
  expect(a.reserve('ws_first', 'different-owner', ['machine-a'])).toBeUndefined();
  expect(a.release(ref)).toBe(false);
  expect(a.setState(ref, 'RELEASING')).toBe(true);
  expect(a.release(ref, 1)).toBe(false);
  expect(a.release(ref, 2)).toBe(true);
  expect(a.byWorkspace(ref.workspaceId)).toBeUndefined();
  const next = b.reserve('ws_first', 'canonical-owner', ['machine-a'])!;
  expect(next.generation).toBeGreaterThan(ref.generation);
  expect(a.setState(ref, 'RELEASING')).toBe(false);
  expect(() => a.assertRef(ref)).toThrow();
  expect(() => a.assertRef(next)).not.toThrow();
});
it('rejects unsafe workspace paths and keeps durable identity on reopen', () => {
  const [a, b] = setup();
  expect(() => a.reserve('../escape', 'owner', ['machine-a'])).toThrow();
  const ref = a.reserve('ws_safe', 'owner', ['machine-a'])!;
  expect(b.byWorkspace('ws_safe')).toMatchObject({ ...ref, state: 'RESERVED', stateGeneration: 0 });
  expect(ref.root).toMatch(/^\/data\/home\/\.cloud-harness\/[a-f0-9]{36}\/ws_safe$/);
});
it('fences transient lifecycle ownership and quarantines interrupted effects only on explicit startup reconciliation', () => {
  const [a, b] = setup();
  const ref = a.reserve('ws_starting', 'owner', ['machine-a'])!;
  expect(a.setState(ref, 'STARTING', 0)).toBe(true);
  expect(b.setState(ref, 'RELEASING', 1)).toBe(false);
  expect(b.setState(ref, 'STOPPING', 1)).toBe(false);
  expect(b.quarantineInterrupted()).toBe(1);
  expect(a.setState(ref, 'ACTIVE', 1)).toBe(false);
  expect(a.byWorkspace(ref.workspaceId)?.state).toBe('QUARANTINED');
  expect(a.setState(ref, 'RELEASING', 2)).toBe(true);
  expect(a.release(ref, 3)).toBe(true);
});
it('upgrades the previous allocation constraint without losing retained identity or state revisions', () => {
  const [a] = setup();
  const ref = a.reserve('ws_legacy', 'owner', ['machine-a'])!;
  a.setState(ref, 'STOPPED');
  const db = stores[0]!.database;
  db.exec(`ALTER TABLE executor_allocations ADD COLUMN old_state TEXT NOT NULL DEFAULT 'RESERVED'
      CHECK(old_state IN ('RESERVED','ACTIVE','STOPPED','RELEASING','QUARANTINED'));
    UPDATE executor_allocations SET old_state = state;
    ALTER TABLE executor_allocations DROP COLUMN state;
    ALTER TABLE executor_allocations RENAME COLUMN old_state TO state;`);
  const migrated = new ExecutorStore(db);
  expect(migrated.byWorkspace(ref.workspaceId)).toMatchObject({ generation: ref.generation, state: 'STOPPED', stateGeneration: 1 });
  expect(migrated.setState(ref, 'STARTING', 1)).toBe(true);
  expect(migrated.quarantineInterrupted()).toBe(1);
  expect(migrated.reserve('ws_other', 'owner', ['machine-a'])).toBeUndefined();
});
it('keeps explicit cleanup intent through quarantine and recognizes only the latest owned release receipt', () => {
  const [a] = setup();
  expect(a.isReleased('ws_close', 'owner')).toBe(false);
  const ref = a.reserve('ws_close', 'owner', ['machine-a'])!;
  a.setState(ref, 'RELEASING');
  a.setState(ref, 'QUARANTINED');
  expect(a.byWorkspace('ws_close')?.cleanupRequested).toBe(true);
  expect(a.isReleased('ws_close', 'owner')).toBe(false);
  a.setState(ref, 'RELEASING');
  expect(a.release(ref)).toBe(true);
  expect(a.isReleased('ws_close', 'owner')).toBe(true);
  expect(a.isReleased('ws_close', 'different-owner')).toBe(false);
  a.reserve('ws_close', 'owner', ['machine-a']);
  expect(a.isReleased('ws_close', 'owner')).toBe(false);
});
