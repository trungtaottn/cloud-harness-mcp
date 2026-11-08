import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

export type VmWorkspaceState = 'admitted' | 'stopped' | 'running' | 'deleted';
export type VmLeaseState = 'active' | 'expired' | 'cleared';

export interface VmWorkspaceIdentityInput {
  workspaceId: string;
  vmName: string;
  instanceId: string;
  templateId: string;
  templateDigest: string;
  generation: number;
  networkProfile: string;
}

export interface VmWorkspaceRow extends VmWorkspaceIdentityInput {
  state: VmWorkspaceState;
  acceptedGeneration: number;
  createdAt: number;
  updatedAt: number;
}

export interface VmLeaseRow {
  workspaceId: string;
  instanceId: string;
  generation: number;
  expiresAt: number;
  hardExpiresAt: number;
  lastRenewalAt: number;
  state: VmLeaseState;
}

export type VmIdempotentBegin =
  | { kind: 'proceed'; recordId: number }
  | { kind: 'replay'; result: unknown }
  | { kind: 'conflict' }
  | { kind: 'unknown' };

export interface VmExecOpRow {
  opId: string;
  workspaceId: string;
  sessionId: string | null;
  state: 'running' | 'exited';
  exitCode: number | null;
  signal: string | null;
  returnMetadata: unknown;
  startedAt: number;
  endedAt: number | null;
}

export interface VmSessionRow {
  sessionId: string;
  workspaceId: string;
  instanceId: string;
  generation: number;
  pty: boolean;
  state: 'open' | 'closed';
  createdAt: number;
  lastSeenAt: number;
}

export interface VmUploadRow {
  uploadId: string;
  workspaceId: string;
  instanceId: string;
  generation: number;
  path: string;
  maxBytes: number;
  expiresAt: number;
  consumed: boolean;
  createdAt: number;
}

export interface VmEventRow {
  id: number;
  ts: number;
  kind: string;
  workspaceId: string | null;
  detail: unknown;
}

const SCHEMA_VERSION = 1;
const EVENT_RETENTION_ROWS = 2_000;
const IDEMPOTENCY_COMPLETED_TTL_SECONDS = 86_400;
const IDEMPOTENCY_MAX_ROWS_PER_WORKSPACE = 512;
const EXEC_OP_RETENTION_SECONDS = 86_400;

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function rowToWorkspace(row: Record<string, unknown>): VmWorkspaceRow {
  return {
    workspaceId: row.workspace_id as string,
    vmName: row.vm_name as string,
    instanceId: row.instance_id as string,
    templateId: row.template_id as string,
    templateDigest: row.template_digest as string,
    networkProfile: row.network_profile as string,
    generation: row.generation as number,
    acceptedGeneration: row.accepted_generation as number,
    state: row.state as VmWorkspaceState,
    createdAt: row.created_at as number,
    updatedAt: row.updated_at as number
  };
}

function rowToLease(row: Record<string, unknown>): VmLeaseRow {
  return {
    workspaceId: row.workspace_id as string,
    instanceId: row.instance_id as string,
    generation: row.generation as number,
    expiresAt: row.expires_at as number,
    hardExpiresAt: row.hard_expires_at as number,
    lastRenewalAt: row.last_renewal_at as number,
    state: row.state as VmLeaseState
  };
}

function rowToExecOp(row: Record<string, unknown>): VmExecOpRow {
  return {
    opId: row.op_id as string,
    workspaceId: row.workspace_id as string,
    sessionId: (row.session_id as string | null) ?? null,
    state: row.state as 'running' | 'exited',
    exitCode: (row.exit_code as number | null) ?? null,
    signal: (row.signal as string | null) ?? null,
    returnMetadata: row.return_metadata_json === null || row.return_metadata_json === undefined
      ? null
      : JSON.parse(row.return_metadata_json as string),
    startedAt: row.started_at as number,
    endedAt: (row.ended_at as number | null) ?? null
  };
}

function rowToSession(row: Record<string, unknown>): VmSessionRow {
  return {
    sessionId: row.session_id as string,
    workspaceId: row.workspace_id as string,
    instanceId: row.instance_id as string,
    generation: row.generation as number,
    pty: row.pty === 1,
    state: row.state as 'open' | 'closed',
    createdAt: row.created_at as number,
    lastSeenAt: row.last_seen_at as number
  };
}

function rowToUpload(row: Record<string, unknown>): VmUploadRow {
  return {
    uploadId: row.upload_id as string,
    workspaceId: row.workspace_id as string,
    instanceId: row.instance_id as string,
    generation: row.generation as number,
    path: row.path as string,
    maxBytes: row.max_bytes as number,
    expiresAt: row.expires_at as number,
    consumed: row.consumed === 1,
    createdAt: row.created_at as number
  };
}

/**
 * Durable supervisor journal: workspace identity + generation fencing,
 * leases, idempotency records, exec-op metadata, session registry, bounded
 * one-time uploads and a bounded event log. Backed by node:sqlite
 * DatabaseSync; synchronous and single-connection, which is sufficient
 * because lifecycle mutations are additionally serialized by the admission
 * queue above this layer.
 *
 * Secret-bearing values (environment maps, streamed payloads) are never
 * written here — idempotency stores only keyed HMAC request digests and the
 * bounded result envelope produced for the caller.
 */
export class VmJournal {
  private readonly db: DatabaseSync;

  constructor(path: string) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA journal_mode = WAL');
    this.db.exec('PRAGMA synchronous = FULL');
    this.db.exec('PRAGMA foreign_keys = ON');
    this.migrate();
  }

  close(): void {
    this.db.close();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS workspaces (
        workspace_id TEXT PRIMARY KEY,
        vm_name TEXT NOT NULL UNIQUE,
        instance_id TEXT NOT NULL,
        template_id TEXT NOT NULL,
        template_digest TEXT NOT NULL,
        generation INTEGER NOT NULL,
        network_profile TEXT NOT NULL,
        accepted_generation INTEGER NOT NULL,
        state TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS leases (
        workspace_id TEXT PRIMARY KEY,
        instance_id TEXT NOT NULL,
        generation INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        hard_expires_at INTEGER NOT NULL,
        last_renewal_at INTEGER NOT NULL,
        state TEXT NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS idempotency (
        workspace_id TEXT NOT NULL,
        op TEXT NOT NULL,
        idempotency_key TEXT NOT NULL,
        request_digest TEXT NOT NULL,
        status TEXT NOT NULL,
        result_json TEXT,
        created_at INTEGER NOT NULL,
        completed_at INTEGER,
        PRIMARY KEY (workspace_id, op, idempotency_key)
      );
      CREATE TABLE IF NOT EXISTS exec_ops (
        op_id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL,
        session_id TEXT,
        state TEXT NOT NULL,
        exit_code INTEGER,
        signal TEXT,
        return_metadata_json TEXT,
        started_at INTEGER NOT NULL,
        ended_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_exec_ops_ws ON exec_ops(workspace_id, started_at);
      CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL,
        instance_id TEXT NOT NULL,
        generation INTEGER NOT NULL,
        pty INTEGER NOT NULL,
        state TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_sessions_state ON sessions(state, last_seen_at);
      CREATE TABLE IF NOT EXISTS uploads (
        upload_id TEXT PRIMARY KEY,
        workspace_id TEXT NOT NULL,
        instance_id TEXT NOT NULL,
        generation INTEGER NOT NULL,
        path TEXT NOT NULL,
        max_bytes INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        consumed INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_uploads_expiry ON uploads(expires_at);
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        kind TEXT NOT NULL,
        workspace_id TEXT,
        detail_json TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
    `);
    this.db
      .prepare("INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)")
      .run(String(SCHEMA_VERSION));
  }

  // ---- workspace identity -------------------------------------------------

  recordWorkspaceAdmit(input: VmWorkspaceIdentityInput): void {
    const now = nowSeconds();
    const existing = this.getWorkspace(input.workspaceId);
    if (existing !== undefined) {
      const same =
        existing.vmName === input.vmName &&
        existing.instanceId === input.instanceId &&
        existing.templateId === input.templateId &&
        existing.templateDigest === input.templateDigest &&
        existing.networkProfile === input.networkProfile;
      if (!same) {
        throw new Error(`workspace ${input.workspaceId} identity conflict: journaled identity differs`);
      }
      // Fencing is mandatory: a stale re-admit must not succeed silently, and
      // updated_at must not move (it anchors the watchdog's unleased grace).
      if (this.acceptGeneration(input.workspaceId, input.generation) === 'stale') {
        throw new Error(`workspace ${input.workspaceId} stale generation ${input.generation}`);
      }
      this.db
        .prepare('UPDATE workspaces SET updated_at = ? WHERE workspace_id = ?')
        .run(now, input.workspaceId);
      return;
    }
    this.db
      .prepare(
        `INSERT INTO workspaces
         (workspace_id, vm_name, instance_id, template_id, template_digest, generation,
          network_profile, accepted_generation, state, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'admitted', ?, ?)`
      )
      .run(
        input.workspaceId, input.vmName, input.instanceId, input.templateId,
        input.templateDigest, input.generation, input.networkProfile,
        input.generation, now, now
      );
  }

  getWorkspace(workspaceId: string): VmWorkspaceRow | undefined {
    const row = this.db
      .prepare('SELECT * FROM workspaces WHERE workspace_id = ?')
      .get(workspaceId) as Record<string, unknown> | undefined;
    return row === undefined ? undefined : rowToWorkspace(row);
  }

  listWorkspaces(state?: VmWorkspaceState): VmWorkspaceRow[] {
    const rows = state === undefined
      ? this.db.prepare('SELECT * FROM workspaces ORDER BY created_at').all()
      : this.db.prepare('SELECT * FROM workspaces WHERE state = ? ORDER BY created_at').all(state);
    return (rows as Record<string, unknown>[]).map(rowToWorkspace);
  }

  setWorkspaceState(workspaceId: string, state: VmWorkspaceState): void {
    const result = this.db
      .prepare('UPDATE workspaces SET state = ?, updated_at = ? WHERE workspace_id = ?')
      .run(state, nowSeconds(), workspaceId);
    if (Number(result.changes) === 0) throw new Error(`unknown workspace ${workspaceId}`);
  }

  countRunningManaged(): number {
    const row = this.db
      .prepare("SELECT COUNT(*) AS n FROM workspaces WHERE state = 'running'")
      .get() as { n: number };
    return row.n;
  }

  /**
   * Generation fencing: accepts generation >= accepted_generation (monotonic,
   * equal is an idempotent retry), rejects anything lower. Returns 'stale' for
   * fenced requests so callers can answer VM_STALE_GENERATION.
   */
  acceptGeneration(workspaceId: string, generation: number): 'accepted' | 'stale' {
    const row = this.getWorkspace(workspaceId);
    if (row === undefined) throw new Error(`unknown workspace ${workspaceId}`);
    if (generation < row.acceptedGeneration) return 'stale';
    if (generation > row.acceptedGeneration) {
      this.db
        .prepare('UPDATE workspaces SET accepted_generation = ?, generation = ?, updated_at = ? WHERE workspace_id = ?')
        .run(generation, generation, nowSeconds(), workspaceId);
    }
    return 'accepted';
  }

  // ---- leases -------------------------------------------------------------

  setLease(input: {
    workspaceId: string;
    instanceId: string;
    generation: number;
    expiresAt: number;
    hardExpiresAt: number;
    lastRenewalAt: number;
    state: VmLeaseState;
  }): void {
    this.db
      .prepare(
        `INSERT INTO leases
         (workspace_id, instance_id, generation, expires_at, hard_expires_at, last_renewal_at, state, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(workspace_id) DO UPDATE SET
           instance_id = excluded.instance_id,
           generation = excluded.generation,
           expires_at = excluded.expires_at,
           hard_expires_at = excluded.hard_expires_at,
           last_renewal_at = excluded.last_renewal_at,
           state = excluded.state,
           updated_at = excluded.updated_at`
      )
      .run(
        input.workspaceId, input.instanceId, input.generation, input.expiresAt,
        input.hardExpiresAt, input.lastRenewalAt, input.state, nowSeconds()
      );
  }

  /**
   * Renewal policy (explicit): a renewal may reactivate an `expired` lease to
   * `active`, but only within the stored hard cutoff — `expiresAt` must be in
   * the future and must not exceed `hardExpiresAt`, which renewals never
   * extend. Cleared leases and cutoff violations are rejected, never silently
   * left in a mismatched state.
   */
  renewLease(workspaceId: string, input: { expiresAt: number; lastRenewalAt: number }): void {
    const lease = this.getLease(workspaceId);
    if (lease === undefined || lease.state === 'cleared') {
      throw new Error(`no renewable lease for ${workspaceId}`);
    }
    const now = nowSeconds();
    if (input.expiresAt <= now || input.expiresAt > lease.hardExpiresAt) {
      throw new Error(`lease renewal for ${workspaceId} violates hard expiry ${lease.hardExpiresAt}`);
    }
    const result = this.db
      .prepare("UPDATE leases SET expires_at = ?, last_renewal_at = ?, state = 'active', updated_at = ? WHERE workspace_id = ? AND state != ?")
      .run(input.expiresAt, input.lastRenewalAt, now, workspaceId, 'cleared');
    if (Number(result.changes) === 0) throw new Error(`no renewable lease for ${workspaceId}`);
  }

  setLeaseState(workspaceId: string, state: VmLeaseState): void {
    this.db
      .prepare('UPDATE leases SET state = ?, updated_at = ? WHERE workspace_id = ?')
      .run(state, nowSeconds(), workspaceId);
  }

  getLease(workspaceId: string): VmLeaseRow | undefined {
    const row = this.db
      .prepare('SELECT * FROM leases WHERE workspace_id = ?')
      .get(workspaceId) as Record<string, unknown> | undefined;
    return row === undefined ? undefined : rowToLease(row);
  }

  listLeases(): VmLeaseRow[] {
    const rows = this.db.prepare('SELECT * FROM leases ORDER BY workspace_id').all() as Record<string, unknown>[];
    return rows.map(rowToLease);
  }

  clearLease(workspaceId: string): void {
    this.setLeaseState(workspaceId, 'cleared');
  }

  // ---- idempotency ----------------------------------------------------------

  beginIdempotent(input: { workspaceId: string; op: string; key: string; digest: string }): VmIdempotentBegin {
    const existing = this.db
      .prepare('SELECT rowid AS rid, request_digest, status, result_json FROM idempotency WHERE workspace_id = ? AND op = ? AND idempotency_key = ?')
      .get(input.workspaceId, input.op, input.key) as
      | { rid: number; request_digest: string; status: string; result_json: string | null }
      | undefined;
    if (existing !== undefined) {
      if (existing.request_digest !== input.digest) return { kind: 'conflict' };
      if (existing.status === 'completed' && existing.result_json !== null) {
        return { kind: 'replay', result: JSON.parse(existing.result_json) };
      }
      return { kind: 'unknown' };
    }
    const result = this.db
      .prepare(
        `INSERT INTO idempotency (workspace_id, op, idempotency_key, request_digest, status, created_at)
         VALUES (?, ?, ?, ?, 'pending', ?)`
      )
      .run(input.workspaceId, input.op, input.key, input.digest, nowSeconds());
    this.pruneIdempotency(input.workspaceId);
    return { kind: 'proceed', recordId: Number(result.lastInsertRowid) };
  }

  completeIdempotent(recordId: number, result: unknown): void {
    this.db
      .prepare("UPDATE idempotency SET status = 'completed', result_json = ?, completed_at = ? WHERE rowid = ?")
      .run(JSON.stringify(result ?? null), nowSeconds(), recordId);
  }

  private pruneIdempotency(workspaceId: string): void {
    const cutoff = nowSeconds() - IDEMPOTENCY_COMPLETED_TTL_SECONDS;
    this.db
      .prepare("DELETE FROM idempotency WHERE workspace_id = ? AND status = 'completed' AND completed_at < ?")
      .run(workspaceId, cutoff);
    // The row cap applies ONLY to completed records. Pending rows are the
    // retry fence for mutations of unknown outcome — pruning one would let a
    // retry re-execute a possibly-applied mutation, so they are never removed
    // here regardless of count.
    this.db
      .prepare(
        `DELETE FROM idempotency WHERE workspace_id = ? AND status = 'completed' AND rowid IN (
           SELECT rowid FROM idempotency WHERE workspace_id = ? AND status = 'completed'
           ORDER BY created_at DESC LIMIT -1 OFFSET ?
         )`
      )
      .run(workspaceId, workspaceId, IDEMPOTENCY_MAX_ROWS_PER_WORKSPACE);
  }

  // ---- exec ops -------------------------------------------------------------

  recordExecStart(input: { opId: string; workspaceId: string; sessionId?: string | null }): void {
    this.db
      .prepare(
        `INSERT INTO exec_ops (op_id, workspace_id, session_id, state, started_at)
         VALUES (?, ?, ?, 'running', ?)`
      )
      .run(input.opId, input.workspaceId, input.sessionId ?? null, nowSeconds());
  }

  recordExecEnd(opId: string, input: { exitCode: number | null; signal: string | null; returnMetadata?: unknown }): void {
    this.db
      .prepare(
        `UPDATE exec_ops SET state = 'exited', exit_code = ?, signal = ?, return_metadata_json = ?, ended_at = ?
         WHERE op_id = ?`
      )
      .run(
        input.exitCode,
        input.signal,
        input.returnMetadata === undefined ? null : JSON.stringify(input.returnMetadata),
        nowSeconds(),
        opId
      );
  }

  getExecOp(opId: string): VmExecOpRow | undefined {
    const row = this.db.prepare('SELECT * FROM exec_ops WHERE op_id = ?').get(opId) as Record<string, unknown> | undefined;
    return row === undefined ? undefined : rowToExecOp(row);
  }

  listExecOps(workspaceId: string, limit = 100): VmExecOpRow[] {
    const rows = this.db
      .prepare('SELECT * FROM exec_ops WHERE workspace_id = ? ORDER BY started_at DESC LIMIT ?')
      .all(workspaceId, limit) as Record<string, unknown>[];
    return rows.map(rowToExecOp);
  }

  pruneExecOps(olderThanSeconds?: number): void {
    const cutoff = nowSeconds() - (olderThanSeconds ?? EXEC_OP_RETENTION_SECONDS);
    this.db.prepare("DELETE FROM exec_ops WHERE state = 'exited' AND ended_at < ?").run(cutoff);
  }

  // ---- sessions ---------------------------------------------------------------

  registerSession(input: {
    sessionId: string;
    workspaceId: string;
    instanceId: string;
    generation: number;
    pty: boolean;
  }): void {
    const now = nowSeconds();
    this.db
      .prepare(
        `INSERT INTO sessions (session_id, workspace_id, instance_id, generation, pty, state, created_at, last_seen_at)
         VALUES (?, ?, ?, ?, ?, 'open', ?, ?)
         ON CONFLICT(session_id) DO UPDATE SET
           workspace_id = excluded.workspace_id,
           instance_id = excluded.instance_id,
           generation = excluded.generation,
           pty = excluded.pty,
           state = 'open',
           last_seen_at = excluded.last_seen_at`
      )
      .run(input.sessionId, input.workspaceId, input.instanceId, input.generation, input.pty ? 1 : 0, now, now);
  }

  touchSession(sessionId: string): void {
    this.db.prepare('UPDATE sessions SET last_seen_at = ? WHERE session_id = ? AND state = ?')
      .run(nowSeconds(), sessionId, 'open');
  }

  getSession(sessionId: string): VmSessionRow | undefined {
    const row = this.db.prepare('SELECT * FROM sessions WHERE session_id = ?').get(sessionId) as Record<string, unknown> | undefined;
    return row === undefined ? undefined : rowToSession(row);
  }

  setSessionState(sessionId: string, state: 'open' | 'closed'): void {
    this.db.prepare('UPDATE sessions SET state = ? WHERE session_id = ?').run(state, sessionId);
  }

  listOpenSessions(): VmSessionRow[] {
    const rows = this.db.prepare("SELECT * FROM sessions WHERE state = 'open' ORDER BY last_seen_at").all() as Record<string, unknown>[];
    return rows.map(rowToSession);
  }

  // ---- uploads ------------------------------------------------------------------

  createUpload(input: {
    uploadId: string;
    workspaceId: string;
    instanceId: string;
    generation: number;
    path: string;
    maxBytes: number;
    expiresAt: number;
  }): void {
    this.db
      .prepare(
        `INSERT INTO uploads (upload_id, workspace_id, instance_id, generation, path, max_bytes, expires_at, consumed, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`
      )
      .run(input.uploadId, input.workspaceId, input.instanceId, input.generation, input.path, input.maxBytes, input.expiresAt, nowSeconds());
  }

  getUpload(uploadId: string): VmUploadRow | undefined {
    const row = this.db.prepare('SELECT * FROM uploads WHERE upload_id = ?').get(uploadId) as Record<string, unknown> | undefined;
    return row === undefined ? undefined : rowToUpload(row);
  }

  /** Atomic one-time consume; returns false when already consumed or missing. */
  consumeUpload(uploadId: string): boolean {
    const result = this.db
      .prepare('UPDATE uploads SET consumed = 1 WHERE upload_id = ? AND consumed = 0')
      .run(uploadId);
    return Number(result.changes) === 1;
  }

  listExpiredUploads(now?: number): VmUploadRow[] {
    const rows = this.db
      .prepare('SELECT * FROM uploads WHERE expires_at <= ? AND consumed = 0')
      .all(now ?? nowSeconds()) as Record<string, unknown>[];
    return rows.map(rowToUpload);
  }

  deleteUpload(uploadId: string): void {
    this.db.prepare('DELETE FROM uploads WHERE upload_id = ?').run(uploadId);
  }

  // ---- events ---------------------------------------------------------------------

  appendEvent(kind: string, workspaceId?: string | null, detail?: unknown): void {
    this.db
      .prepare('INSERT INTO events (ts, kind, workspace_id, detail_json) VALUES (?, ?, ?, ?)')
      .run(nowSeconds(), kind, workspaceId ?? null, detail === undefined ? null : JSON.stringify(detail));
    this.db
      .prepare(
        `DELETE FROM events WHERE id NOT IN (
           SELECT id FROM events ORDER BY id DESC LIMIT ?
         )`
      )
      .run(EVENT_RETENTION_ROWS);
  }

  /** Most recent `limit` events in chronological order. */
  listEvents(limit = 100): VmEventRow[] {
    const rows = this.db
      .prepare('SELECT * FROM events ORDER BY id DESC LIMIT ?')
      .all(limit) as Record<string, unknown>[];
    return rows
      .map((row) => ({
        id: row.id as number,
        ts: row.ts as number,
        kind: row.kind as string,
        workspaceId: (row.workspace_id as string | null) ?? null,
        detail: row.detail_json === null || row.detail_json === undefined ? null : JSON.parse(row.detail_json as string)
      }))
      .reverse();
  }
}
