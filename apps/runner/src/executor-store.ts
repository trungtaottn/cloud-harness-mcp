import type { DatabaseSync } from 'node:sqlite';
import type { RemoteExecutorRef } from './executors/execution-backend.js';

export type ExecutorAllocationState = 'RESERVED' | 'STARTING' | 'STOPPING' | 'ACTIVE' | 'STOPPED' | 'RELEASING' | 'QUARANTINED';
export type ExecutorAllocation = RemoteExecutorRef & {
  cleanupRequested: boolean; state: ExecutorAllocationState; stateGeneration: number; createdAt: number; updatedAt: number;
};
type Row = { id: number; workspace_id: string; owner_id: string; machine_id: string; root: string;
  cleanup_requested: number; state: ExecutorAllocationState; state_generation: number; created_at: number; updated_at: number };
const allocation = (row: Row): ExecutorAllocation => ({ provider: 'instabox', generation: row.id,
  workspaceId: row.workspace_id, ownerId: row.owner_id, machineId: row.machine_id, root: row.root,
  cleanupRequested: row.cleanup_requested === 1, state: row.state, stateGeneration: row.state_generation, createdAt: row.created_at, updatedAt: row.updated_at });

const ALLOWED_TRANSITIONS: Record<ExecutorAllocationState, readonly ExecutorAllocationState[]> = {
  RESERVED: ['STARTING', 'ACTIVE', 'STOPPED', 'STOPPING', 'RELEASING', 'QUARANTINED'],
  ACTIVE: ['STARTING', 'STOPPING', 'STOPPED', 'RELEASING', 'QUARANTINED'],
  STOPPED: ['STARTING', 'STOPPING', 'ACTIVE', 'RELEASING', 'QUARANTINED'],
  STARTING: ['RESERVED', 'ACTIVE', 'QUARANTINED'],
  STOPPING: ['STOPPED', 'QUARANTINED'],
  RELEASING: ['QUARANTINED'],
  QUARANTINED: ['RELEASING', 'STARTING', 'STOPPING']
};

/** Trusted allocation authority. Released tombstones prevent stale references from becoming valid again. */
export class ExecutorStore {
  constructor(private readonly db: DatabaseSync) {
    db.exec(`CREATE TABLE IF NOT EXISTS executor_allocations (
      id INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id TEXT NOT NULL, owner_id TEXT NOT NULL,
      machine_id TEXT NOT NULL, root TEXT NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('RESERVED','STARTING','STOPPING','ACTIVE','STOPPED','RELEASING','QUARANTINED')),
      state_generation INTEGER NOT NULL DEFAULT 0, released INTEGER NOT NULL DEFAULT 0 CHECK(released IN (0,1)),
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
    );
    CREATE UNIQUE INDEX IF NOT EXISTS executor_live_workspace ON executor_allocations(workspace_id) WHERE released = 0;
    CREATE UNIQUE INDEX IF NOT EXISTS executor_live_machine ON executor_allocations(machine_id) WHERE released = 0;`);
    const columns = db.prepare('PRAGMA table_info(executor_allocations)').all() as { name: string }[];
    if (!columns.some(column => column.name === 'cleanup_requested')) {
      db.exec('ALTER TABLE executor_allocations ADD COLUMN cleanup_requested INTEGER NOT NULL DEFAULT 0 CHECK(cleanup_requested IN (0,1));');
      db.exec("UPDATE executor_allocations SET cleanup_requested = 1 WHERE state = 'RELEASING' OR released = 1;");
    }
    const schema = db.prepare("SELECT sql FROM sqlite_master WHERE name = 'executor_allocations'").get() as { sql: string };
    if (!schema.sql.includes("'STARTING'")) {
      db.exec(`BEGIN IMMEDIATE;
        ALTER TABLE executor_allocations ADD COLUMN state_next TEXT NOT NULL DEFAULT 'RESERVED'
          CHECK(state_next IN ('RESERVED','STARTING','STOPPING','ACTIVE','STOPPED','RELEASING','QUARANTINED'));
        UPDATE executor_allocations SET state_next = state;
        ALTER TABLE executor_allocations DROP COLUMN state;
        ALTER TABLE executor_allocations RENAME COLUMN state_next TO state;
        COMMIT;`);
    }
  }

  reserve(workspaceId: string, ownerId: string, machineIds: readonly string[]): RemoteExecutorRef | undefined {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(workspaceId) || !ownerId || machineIds.some(id => !id)) throw new Error('invalid allocation identity');
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.byWorkspace(workspaceId);
      if (existing) {
        this.db.exec('COMMIT');
        return existing.ownerId === ownerId && machineIds.includes(existing.machineId) ? existing : undefined;
      }
      const instance = this.db.prepare("SELECT value FROM runtime_meta WHERE key = 'runner_instance_id'").get() as { value: string } | undefined;
      if (!instance || !/^[a-f0-9]{36}$/.test(instance.value)) throw new Error('invalid runner instance identity');
      const root = `/data/home/.cloud-harness/${instance.value}/${workspaceId}`;
      const now = Date.now();
      for (const machineId of machineIds) {
        const result = this.db.prepare(`INSERT OR IGNORE INTO executor_allocations
          (workspace_id, owner_id, machine_id, root, state, created_at, updated_at) VALUES (?, ?, ?, ?, 'RESERVED', ?, ?)`)
          .run(workspaceId, ownerId, machineId, root, now, now);
        if (Number(result.changes) === 1) {
          const ref = this.byWorkspace(workspaceId)!;
          this.db.exec('COMMIT');
          return ref;
        }
      }
      this.db.exec('COMMIT');
      return undefined;
    } catch (error) { this.db.exec('ROLLBACK'); throw error; }
  }

  byWorkspace(workspaceId: string): ExecutorAllocation | undefined {
    const row = this.db.prepare('SELECT * FROM executor_allocations WHERE workspace_id = ? AND released = 0').get(workspaceId) as Row | undefined;
    return row ? allocation(row) : undefined;
  }

  /** A missing allocation is not proof of cleanup; only the latest matching-owner tombstone is. */
  isReleased(workspaceId: string, ownerId: string): boolean {
    const row = this.db.prepare('SELECT owner_id, released FROM executor_allocations WHERE workspace_id = ? ORDER BY id DESC LIMIT 1')
      .get(workspaceId) as { owner_id: string; released: number } | undefined;
    return row?.owner_id === ownerId && row.released === 1;
  }

  assertRef(ref: RemoteExecutorRef): void {
    if (!this.matches(ref)) throw new Error('remote allocation identity is stale or invalid');
  }

  private matches(ref: RemoteExecutorRef): ExecutorAllocation | undefined {
    const current = this.byWorkspace(ref.workspaceId);
    return current && ref.provider === 'instabox' && current.generation === ref.generation && current.ownerId === ref.ownerId
      && current.machineId === ref.machineId && current.root === ref.root ? current : undefined;
  }

  setState(ref: RemoteExecutorRef, state: ExecutorAllocationState, expectedStateGeneration?: number): boolean {
    const current = this.matches(ref);
    if (!current || !ALLOWED_TRANSITIONS[current.state].includes(state)) return false;
    if (current.cleanupRequested && (state === 'STARTING' || state === 'STOPPING')) return false;
    return Number(this.db.prepare(`UPDATE executor_allocations SET state = ?, cleanup_requested = CASE WHEN ? = 'RELEASING' THEN 1 ELSE cleanup_requested END, state_generation = state_generation + 1, updated_at = ?
      WHERE id = ? AND released = 0 AND state_generation = ?`)
      .run(state, state, Date.now(), ref.generation, expectedStateGeneration ?? current.stateGeneration).changes) === 1;
  }

  /** Startup only, after the previous runner has stopped: interrupted provider effects are unknown. */
  quarantineInterrupted(): number {
    return Number(this.db.prepare(`UPDATE executor_allocations SET state = 'QUARANTINED',
      state_generation = state_generation + 1, updated_at = ?
      WHERE released = 0 AND state IN ('STARTING', 'STOPPING', 'RELEASING')`).run(Date.now()).changes);
  }

  /** Call only after fresh provider verification of stopped writers and scoped root cleanup. */
  release(ref: RemoteExecutorRef, expectedStateGeneration?: number): boolean {
    const current = this.matches(ref);
    if (!current) return false;
    return Number(this.db.prepare(`UPDATE executor_allocations SET released = 1, state_generation = state_generation + 1, updated_at = ?
      WHERE id = ? AND released = 0 AND state = 'RELEASING' AND state_generation = ?`)
      .run(Date.now(), ref.generation, expectedStateGeneration ?? current.stateGeneration).changes) === 1;
  }
}
