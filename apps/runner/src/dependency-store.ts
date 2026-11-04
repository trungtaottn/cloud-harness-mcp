import { createHash } from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { HarnessError, WorkspaceIdSchema, type DependencyEcosystem, type DependencyPlanView } from '@cloud-harness/contracts';
import { canonicalJson } from './cloudflare-access-oauth-provider.js';
import { opaqueId, transaction } from './metadata-records.js';

export interface DependencyPlanRecord {
  view: DependencyPlanView;
  ownerId: string;
  snapshots: Record<string, string>;
  imageId: string;
  profileDigest: string;
  dependencies: string[];
}
export interface DependencyPlanSpec {
  workspaceId: string;
  ecosystem: DependencyEcosystem;
  directory: string;
  snapshots: Record<string, string>;
  imageId: string;
  profileDigest: string;
  dependencies: string[];
  maxBytes: number;
  timeoutMs: number;
  now?: number;
}
const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const hosts = { go: ['proxy.golang.org', 'sum.golang.org', 'storage.googleapis.com'], pnpm: ['registry.npmjs.org'] };
const terminal = ['SUCCEEDED', 'FAILED', 'REJECTED', 'EXPIRED'];
const safeFailureReasons: Record<string, string> = {
  TIMEOUT: 'Dependency download timed out; create a new plan to retry',
  CANCELLED: 'Dependency download was cancelled; create a new plan to retry',
  LIMIT_EXCEEDED: 'Dependency download exceeded a storage or resource limit; check available space and plan budgets',
  CONFLICT: 'Workspace manifests, image, profile or cache changed; create a new plan',
  INVALID_INPUT: 'Dependency manifests or downloaded cache failed validation; inspect the project and create a new plan',
  UNAVAILABLE: 'Dependency download infrastructure is unavailable; contact the operator and create a new plan'
};

/** Approval and single-use checks share the same SQLite write transaction. */
export class DependencyStore {
  constructor(private readonly database: DatabaseSync) {
    database.exec(`CREATE TABLE IF NOT EXISTS dependency_plans (
      id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, state TEXT NOT NULL,
      created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, record_json TEXT NOT NULL
    ); CREATE INDEX IF NOT EXISTS dependency_plans_owner ON dependency_plans(owner_id, created_at);`);
  }

  create(ownerId: string, spec: DependencyPlanSpec): DependencyPlanRecord {
    return transaction(this.database, () => {
      const now = spec.now ?? Date.now();
      this.prune(ownerId, now);
      const count = this.database.prepare("SELECT COUNT(*) AS n FROM dependency_plans WHERE owner_id = ? AND state IN ('PENDING_APPROVAL','APPROVED','RUNNING')").get(ownerId) as { n: number };
      if (count.n >= 32) throw new HarnessError('LIMIT_EXCEEDED', 'At most 32 unfinished dependency plans are allowed per owner', 429);
      if (Buffer.byteLength(JSON.stringify(spec.snapshots)) > 4 * 1024 * 1024 + 65536) throw new HarnessError('LIMIT_EXCEEDED', 'Dependency manifests exceed 4 MiB', 413);
      const previous = this.rows(ownerId).find((r) => r.view.state === 'SUCCEEDED' && r.view.workspaceId === spec.workspaceId && r.view.ecosystem === spec.ecosystem && r.view.directory === spec.directory);
      const dependencies = [...new Set(spec.dependencies)].sort();
      const before = new Set(previous?.dependencies ?? []);
      const after = new Set(dependencies);
      const manifests = Object.entries(spec.snapshots).sort(([a], [b]) => a.localeCompare(b)).map(([path, text]) => ({ path, sha256: digest(text) }));
      const view: DependencyPlanView = {
        planId: opaqueId('dep'), planDigest: '', workspaceId: WorkspaceIdSchema.parse(spec.workspaceId), ecosystem: spec.ecosystem,
        directory: spec.directory, state: 'PENDING_APPROVAL', manifests, hosts: hosts[spec.ecosystem],
        dependencyCount: dependencies.length, changes: { added: dependencies.filter((d) => !before.has(d)).length, removed: [...before].filter((d) => !after.has(d)).length },
        timeoutMs: spec.timeoutMs, maxBytes: spec.maxBytes, scripts: 'deny', createdAt: now,
        expiresAt: now + 30 * 60_000, completedAt: null, sizeBytes: null, error: null
      };
      view.planDigest = digest(canonicalJson({ ...view, imageId: spec.imageId, profileDigest: spec.profileDigest, dependencies }));
      const record = { view, ownerId, snapshots: spec.snapshots, imageId: spec.imageId, profileDigest: spec.profileDigest, dependencies };
      this.save(record);
      return record;
    });
  }

  get(ownerId: string, planId: string): DependencyPlanRecord {
    const row = this.database.prepare('SELECT record_json FROM dependency_plans WHERE owner_id = ? AND id = ?').get(ownerId, planId) as { record_json: string } | undefined;
    if (!row) throw new HarnessError('NOT_FOUND', 'Dependency plan not found', 404);
    const record = JSON.parse(row.record_json) as DependencyPlanRecord;
    if (['PENDING_APPROVAL', 'APPROVED'].includes(record.view.state) && record.view.expiresAt <= Date.now()) record.view.state = 'EXPIRED';
    return record;
  }

  list(ownerId: string, workspaceId?: string): DependencyPlanView[] {
    return this.rows(ownerId).filter((r) => !workspaceId || r.view.workspaceId === workspaceId).slice(0, 100).map((r) => this.get(ownerId, r.view.planId).view);
  }

  approve(ownerId: string, input: { planId: string; planDigest: string }): DependencyPlanView {
    return transaction(this.database, () => {
      const r = this.get(ownerId, input.planId);
      this.identity(r, input.planDigest);
      this.decidable(r);
      r.view.state = 'APPROVED';
      this.save(r);
      return r.view;
    });
  }

  reject(ownerId: string, input: { planId: string }): DependencyPlanView {
    return transaction(this.database, () => {
      const r = this.get(ownerId, input.planId);
      this.decidable(r);
      r.view.state = 'REJECTED';
      r.view.completedAt = Date.now();
      r.snapshots = {};
      this.save(r);
      return r.view;
    });
  }

  start(ownerId: string, planId: string, planDigest: string, workspaceId: string): { record: DependencyPlanRecord; replayed: boolean } {
    return transaction(this.database, () => {
      const r = this.get(ownerId, planId);
      this.identity(r, planDigest);
      if (r.view.workspaceId !== workspaceId) throw new HarnessError('CONFLICT', 'Dependency plan workspace does not match', 409);
      if (['RUNNING', 'SUCCEEDED', 'FAILED'].includes(r.view.state)) return { record: r, replayed: true };
      this.decidable(r);
      if (r.view.state !== 'APPROVED') throw new HarnessError('OWNER_APPROVAL_REQUIRED', 'Approve this exact dependency plan in the dashboard first', 403);
      r.view.state = 'RUNNING';
      this.save(r);
      return { record: r, replayed: false };
    });
  }

  finish(ownerId: string, planId: string, result: { sizeBytes?: number; error?: string }): DependencyPlanView {
    return transaction(this.database, () => {
      const r = this.get(ownerId, planId);
      if (r.view.state !== 'RUNNING') throw new HarnessError('CONFLICT', 'Dependency plan is not running', 409);
      r.view.state = result.error === undefined ? 'SUCCEEDED' : 'FAILED';
      // Builder diagnostics may contain repository content or credentials; expose a fixed failure only.
      const errorCode = result.error?.split(':', 1)[0] ?? '';
      r.view.error = result.error === undefined ? null : Object.hasOwn(safeFailureReasons, errorCode)
        ? safeFailureReasons[errorCode]! : 'Dependency fetch failed; inspect operator logs and create a new plan to retry';
      r.view.sizeBytes = result.sizeBytes ?? null;
      r.view.completedAt = Date.now();
      r.snapshots = {};
      this.save(r);
      return r.view;
    });
  }

  recoverInterrupted(): void {
    transaction(this.database, () => {
      const rows = this.database.prepare("SELECT record_json FROM dependency_plans WHERE state = 'RUNNING'").all() as { record_json: string }[];
      for (const row of rows) {
        const r = JSON.parse(row.record_json) as DependencyPlanRecord;
        r.view.state = 'FAILED'; r.view.error = 'Runner restarted during dependency fetch; create a new plan';
        r.view.completedAt = Date.now(); r.snapshots = {}; this.save(r);
      }
    });
  }

  private identity(r: DependencyPlanRecord, planDigest: string): void {
    if (r.view.planDigest !== planDigest) throw new HarnessError('CONFLICT', 'Dependency plan digest does not match', 409);
  }
  private decidable(r: DependencyPlanRecord): void {
    if (r.view.state === 'EXPIRED') throw new HarnessError('EXPIRED', 'Dependency plan expired; create a new plan', 410);
    if (!['PENDING_APPROVAL', 'APPROVED'].includes(r.view.state)) throw new HarnessError('CONFLICT', 'Dependency plan cannot be approved or used', 409);
  }
  private rows(ownerId: string): DependencyPlanRecord[] {
    return (this.database.prepare('SELECT record_json FROM dependency_plans WHERE owner_id = ? ORDER BY created_at DESC, rowid DESC').all(ownerId) as { record_json: string }[]).map((r) => JSON.parse(r.record_json) as DependencyPlanRecord);
  }
  private save(r: DependencyPlanRecord): void {
    this.database.prepare(`INSERT INTO dependency_plans VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET state = excluded.state, record_json = excluded.record_json`).run(r.view.planId, r.ownerId, r.view.state, r.view.createdAt, r.view.expiresAt, JSON.stringify(r));
  }
  private prune(ownerId: string, now: number): void {
    let retained = 0;
    for (const r of this.rows(ownerId)) {
      if (['PENDING_APPROVAL', 'APPROVED'].includes(r.view.state) && r.view.expiresAt <= now) { r.view.state = 'EXPIRED'; r.snapshots = {}; this.save(r); }
      if (terminal.includes(r.view.state) && (++retained > 100 || (r.view.completedAt ?? r.view.expiresAt) < now - 7 * 86400_000)) {
        this.database.prepare('DELETE FROM dependency_plans WHERE id = ? AND owner_id = ?').run(r.view.planId, ownerId);
      }
    }
  }
}
