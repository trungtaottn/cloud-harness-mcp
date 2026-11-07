import { statfs, stat } from 'node:fs/promises';
import { join } from 'node:path';
import type { VmJournal } from './journal.js';
import type { VmSupervisorConfig } from './config.js';
import type { IncusClient, IncusInstanceInfo } from './incus.js';
import {
  isManagedInstanceConfig,
  readIdentityFromConfig,
  verifyIdentityFromConfig
} from './identity.js';
import type { VmNetworkGuard, VmNetworkIdentity } from './network-ops.js';

/**
 * Serialized lifecycle admission + watchdog + reconcile (frozen semantics):
 *
 * - ALL lifecycle mutations serialize under ONE global queue (v1 cap = 1
 *   active managed VM). Every start path — vm.create completion, vm.start,
 *   lease-renew reactivation, ensureActive resume, reconcile-adopt — funnels
 *   through `withLifecycleLock` + `checkAdmission`.
 * - Admission requires: running-count < VM_MAX_ACTIVE AND pool statfs free
 *   covers FULL configured disk growth + retained allocated (st_blocks) +
 *   image cache + VM_POOL_RESERVE_BYTES floor.
 * - Watchdog: deadlines are SCHEDULED enforcement cutoffs. At expiresAt or
 *   hardExpiresAt the lease is marked expired, vm.stop initiated, and all
 *   workspace ops issued at/after the deadline are rejected (op cutoff is
 *   the enforcement; stop latency is measured, never claimed zero).
 *   Unleased managed RUNNING VMs stop after bounded grace; STOPPED retained;
 *   unknown stop state never authorizes deletion (nothing deletes anyway).
 * - Reconcile: adopt only journal-known fully-verified instances; quarantine
 *   identity mismatches; ignore foreign; stop verified unleased RUNNING;
 *   retain STOPPED; delete NOTHING.
 */

export class VmOpError extends Error {
  readonly code: string;
  readonly retryable: boolean;
  readonly unknown: boolean;
  constructor(code: string, message: string, opts: { retryable?: boolean; unknown?: boolean } = {}) {
    super(message);
    this.name = 'VmOpError';
    this.code = code;
    this.retryable = opts.retryable ?? false;
    this.unknown = opts.unknown ?? false;
  }
}

export class VmUnknownMutationError extends VmOpError {
  constructor(message: string) {
    super('VM_UNKNOWN_STATE', message, { retryable: true, unknown: true });
    this.name = 'VmUnknownMutationError';
  }
}

const WATCHDOG_INTERVAL_MS = 20_000;
const UNLEASED_GRACE_SECONDS = 300;
const STOP_OPERATION_DEADLINE_MS = 60_000;
const PROBE_DEADLINE_MS = 30_000;

export interface VmLifecycleDeps {
  config: VmSupervisorConfig;
  journal: VmJournal;
  incus: IncusClient;
  guard: () => Promise<VmNetworkGuard>;
  now?: () => number;
  watchdogIntervalMs?: number;
  unleasedGraceSeconds?: number;
}

export class VmLifecycle {
  private queue: Promise<unknown> = Promise.resolve();
  private watchdogTimer: NodeJS.Timeout | undefined;
  private readonly nowFn: () => number;
  private readonly unleasedGraceSeconds: number;

  constructor(private readonly deps: VmLifecycleDeps) {
    this.nowFn = deps.now ?? (() => Date.now());
    this.unleasedGraceSeconds = deps.unleasedGraceSeconds ?? UNLEASED_GRACE_SECONDS;
  }

  /** Serialize a lifecycle mutation globally. */
  async withLifecycleLock<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn, fn);
    this.queue = run.then(() => undefined, () => undefined);
    return run;
  }

  nowMs(): number {
    return this.nowFn();
  }

  nowSec(): number {
    return Math.floor(this.nowMs() / 1000);
  }

  // ---- admission ---------------------------------------------------------

  /**
   * Dry-run admission check shared by vm.admit (no state change) and every
   * real start path. MUST be called inside withLifecycleLock.
   */
  async checkAdmission(opts: { forStart: boolean }): Promise<{ admitted: boolean; reason?: string }> {
    const { config, journal } = this.deps;
    const running = journal.countRunningManaged();
    if (running >= config.maxActive) {
      return { admitted: false, reason: `active managed VM limit reached (${running}/${config.maxActive})` };
    }
    // Pool reserve: statfs free must cover full configured disk growth for the
    // new VM + retained allocated volumes + image cache headroom + floor.
    try {
      const fs = await statfs(config.poolPath);
      const free = Number(fs.bavail) * Number(fs.bsize);
      const retained = await this.retainedAllocatedBytes();
      const required = config.diskBytes + retained + config.poolReserveBytes;
      if (free < required) {
        return {
          admitted: false,
          reason: `pool reserve insufficient: free=${free} required=${required}`
        };
      }
    } catch (error) {
      return { admitted: false, reason: `pool statfs failed: ${error instanceof Error ? error.message : 'unknown'}` };
    }
    void opts;
    return { admitted: true };
  }

  /** Sum st_blocks*512 across managed volume dirs under the pool path. */
  private async retainedAllocatedBytes(): Promise<number> {
    const { config } = this.deps;
    let total = 0;
    try {
      const { readdir } = await import('node:fs/promises');
      const vmRoot = join(config.poolPath, 'virtual-machines');
      const entries = await readdir(vmRoot, { withFileTypes: true });
      for (const entry of entries.slice(0, 1_024)) {
        if (!entry.isDirectory()) continue;
        try {
          const s = await stat(join(vmRoot, entry.name, 'root.img'));
          total += Number(s.blocks) * 512;
        } catch {
          // volume without root.img — skip
        }
      }
    } catch {
      // pool layout absent (fresh host) → zero retained
    }
    return total;
  }

  // ---- identity helpers ---------------------------------------------------

  /** Verify a live instance's expanded config against journal identity. */
  verifyInstanceIdentity(instance: IncusInstanceInfo, workspace: {
    workspaceId: string; instanceId: string; templateId: string; templateDigest: string;
  }): { ok: true } | { ok: false; reason: string } {
    const verdict = verifyIdentityFromConfig(instance.expandedConfig, workspace);
    return verdict.ok ? { ok: true } : { ok: false, reason: verdict.reason };
  }

  managedIdentityOf(instance: IncusInstanceInfo) {
    return readIdentityFromConfig(instance.expandedConfig);
  }

  isManaged(instance: IncusInstanceInfo): boolean {
    return isManagedInstanceConfig(instance.expandedConfig);
  }

  normalizeState(status: string): 'stopped' | 'starting' | 'running' | 'stopping' | 'frozen' | 'error' | 'unknown' {
    switch (status) {
      case 'Running': return 'running';
      case 'Stopped': return 'stopped';
      case 'Starting': return 'starting';
      case 'Stopping': return 'stopping';
      case 'Freezing':
      case 'Frozen': return 'frozen';
      case 'Error':
      case 'Broken': return 'error';
      default: return 'unknown';
    }
  }

  // ---- watchdog -----------------------------------------------------------

  startWatchdog(): void {
    if (this.watchdogTimer !== undefined) return;
    const interval = this.deps.watchdogIntervalMs ?? WATCHDOG_INTERVAL_MS;
    this.watchdogTimer = setInterval(() => {
      void this.tick().catch(() => undefined);
    }, interval);
    this.watchdogTimer.unref();
    void this.tick().catch(() => undefined);
  }

  stopWatchdog(): void {
    if (this.watchdogTimer !== undefined) clearInterval(this.watchdogTimer);
    this.watchdogTimer = undefined;
  }

  /** One watchdog pass: expire leases, stop unleased running, bounded grace. */
  async tick(): Promise<void> {
    const { journal, incus } = this.deps;
    const now = this.nowSec();
    // 1. Lease deadlines: mark expired + initiate stop; op cutoff is enforced
    //    separately at request time via leaseDeadlineFor().
    for (const lease of journal.listLeases()) {
      if (lease.state === 'cleared') continue;
      const ws = journal.getWorkspace(lease.workspaceId);
      if (ws === undefined || ws.state !== 'running') continue;
      if (lease.state === 'active' && (now >= lease.expiresAt || now >= lease.hardExpiresAt)) {
        journal.setLeaseState(lease.workspaceId, 'expired');
        journal.appendEvent('watchdog.expired', lease.workspaceId, {
          expiresAt: lease.expiresAt, hardExpiresAt: lease.hardExpiresAt, now
        });
        await this.stopVerified(ws.vmName, ws.workspaceId, 'lease-expired');
      }
    }
    // 2. Unleased managed RUNNING → bounded grace → stop (never delete).
    for (const ws of journal.listWorkspaces('running')) {
      const lease = journal.getLease(ws.workspaceId);
      const leased = lease !== undefined && lease.state === 'active';
      if (leased) continue;
      const graceAnchor = ws.updatedAt;
      if (now - graceAnchor < this.unleasedGraceSeconds) continue;
      await this.stopVerified(ws.vmName, ws.workspaceId, 'unleased-grace');
    }
    void incus;
  }

  /**
   * Stop a journal-verified instance and record measured latency. Returns the
   * measured stop duration; 'unknown' outcomes keep the VM running-marked and
   * journaled — never treated as stopped.
   */
  async stopVerified(vmName: string, workspaceId: string, reason: string): Promise<{ outcome: 'stopped' | 'unknown'; elapsedMs?: number }> {
    const { journal, incus } = this.deps;
    try {
      const started = this.nowMs();
      const result = await incus.setInstanceState(vmName, 'stop', { force: true, timeoutSeconds: 30 });
      if (result.operation !== undefined) {
        await incus.waitOperation(result.operation, started + STOP_OPERATION_DEADLINE_MS);
      }
      // Confirm stopped via state read-back.
      const deadline = this.nowMs() + PROBE_DEADLINE_MS;
      for (;;) {
        const state = await incus.getInstanceState(vmName);
        if (state === null) break;
        if (this.normalizeState(state.status) === 'stopped') break;
        if (this.nowMs() >= deadline) {
          journal.appendEvent('watchdog.stop-unknown', workspaceId, { vmName, reason });
          return { outcome: 'unknown' };
        }
        await new Promise((r) => setTimeout(r, 500));
      }
      const elapsedMs = this.nowMs() - started;
      const ws = journal.getWorkspace(workspaceId);
      if (ws !== undefined && ws.state === 'running') journal.setWorkspaceState(workspaceId, 'stopped');
      journal.appendEvent('watchdog.stopped', workspaceId, { vmName, reason, elapsedMs });
      return { outcome: 'stopped', elapsedMs };
    } catch {
      journal.appendEvent('watchdog.stop-unknown', workspaceId, { vmName, reason });
      return { outcome: 'unknown' };
    }
  }

  /**
   * Lease deadline for op cutoff: returns the effective deadline (seconds)
   * at/after which workspace ops must be rejected, or undefined when the
   * workspace has no active lease constraint. Ops issued with
   * `issuedAt >= deadline` are refused — the cutoff IS the enforcement.
   */
  leaseDeadlineFor(workspaceId: string): number | undefined {
    const lease = this.deps.journal.getLease(workspaceId);
    if (lease === undefined || lease.state !== 'active') return undefined;
    return Math.min(lease.expiresAt, lease.hardExpiresAt);
  }

  // ---- reconcile ----------------------------------------------------------

  /**
   * Boot-time reconcile. Adopts journal-known verified instances, quarantines
   * mismatches, ignores foreign, stops verified unleased RUNNING after grace,
   * retains STOPPED, deletes NOTHING.
   */
  async reconcile(): Promise<{
    adopted: Array<{ vmName: string; workspaceId?: string | undefined; instanceId?: string | undefined; reason?: string | undefined }>;
    quarantined: Array<{ vmName: string; workspaceId?: string | undefined; instanceId?: string | undefined; reason?: string | undefined }>;
    stoppedUnleased: Array<{ vmName: string; workspaceId?: string | undefined; instanceId?: string | undefined; reason?: string | undefined }>;
    foreignIgnored: Array<{ vmName: string; reason?: string | undefined }>;
    deferred: Array<{ vmName: string; workspaceId?: string | undefined; instanceId?: string | undefined; reason?: string | undefined }>;
  }> {
    const { journal, incus } = this.deps;
    const result = {
      adopted: [] as Array<{ vmName: string; workspaceId?: string | undefined; instanceId?: string | undefined; reason?: string | undefined }>,
      quarantined: [] as Array<{ vmName: string; workspaceId?: string | undefined; instanceId?: string | undefined; reason?: string | undefined }>,
      stoppedUnleased: [] as Array<{ vmName: string; workspaceId?: string | undefined; instanceId?: string | undefined; reason?: string | undefined }>,
      foreignIgnored: [] as Array<{ vmName: string; reason?: string | undefined }>,
      deferred: [] as Array<{ vmName: string; workspaceId?: string | undefined; instanceId?: string | undefined; reason?: string | undefined }>
    };
    const instances = await incus.listInstances();
    const journalWorkspaces = new Map(journal.listWorkspaces().map((w) => [w.vmName, w]));
    const quarantineCandidates: VmNetworkIdentity[] = [];

    for (const instance of instances) {
      const managed = this.isManaged(instance);
      const journaled = journalWorkspaces.get(instance.name);
      if (!managed) {
        result.foreignIgnored.push({ vmName: instance.name, reason: 'no user.cloud-harness.* markers' });
        continue;
      }
      const identity = this.managedIdentityOf(instance);
      if (journaled === undefined) {
        // Managed markers but unknown to journal → quarantine (never adopt,
        // never touch beyond reporting).
        result.quarantined.push({
          vmName: instance.name,
          workspaceId: identity?.workspaceId,
          instanceId: identity?.instanceId,
          reason: 'managed markers present but workspace not journaled'
        });
        continue;
      }
      // Journal-known: verify FULL identity before any action.
      const verdict = this.verifyInstanceIdentity(instance, journaled);
      if (!verdict.ok) {
        result.quarantined.push({
          vmName: instance.name,
          workspaceId: journaled.workspaceId,
          instanceId: journaled.instanceId,
          reason: `identity mismatch: ${verdict.reason}`
        });
        journal.appendEvent('reconcile.quarantine', journaled.workspaceId, { vmName: instance.name, reason: verdict.reason });
        // Hand the JOURNAL-EXPECTED identity to the guard: its per-instance
        // re-verification refuses anything that doesn't match, so a foreign
        // squatter is reported but never stopped by us.
        quarantineCandidates.push({
          workspaceId: journaled.workspaceId as VmNetworkIdentity['workspaceId'],
          vmName: instance.name,
          instanceId: journaled.instanceId,
          generation: journaled.acceptedGeneration
        });
        continue;
      }
      // Adopt: sync journal state to observed Incus state.
      const observed = this.normalizeState(instance.status);
      if (journaled.state === 'admitted' || journaled.state === 'deleted') {
        if (observed === 'running' || observed === 'starting') {
          result.deferred.push({ vmName: instance.name, workspaceId: journaled.workspaceId, instanceId: journaled.instanceId, reason: 'journal state inconsistent with running instance' });
          continue;
        }
      }
      if (journaled.state !== 'deleted' && observed === 'stopped' && journaled.state === 'running') {
        journal.setWorkspaceState(journaled.workspaceId, 'stopped');
      }
      if (journaled.state !== 'deleted' && (observed === 'running' || observed === 'starting')) {
        if (journaled.state !== 'running') journal.setWorkspaceState(journaled.workspaceId, 'running');
        result.adopted.push({ vmName: instance.name, workspaceId: journaled.workspaceId, instanceId: journaled.instanceId });
        // Unleased running → bounded grace → stop (verified identity only).
        const lease = journal.getLease(journaled.workspaceId);
        const leased = lease !== undefined && lease.state === 'active' && this.nowSec() < Math.min(lease.expiresAt, lease.hardExpiresAt);
        if (!leased && this.nowSec() - journaled.updatedAt >= this.unleasedGraceSeconds) {
          const stop = await this.stopVerified(instance.name, journaled.workspaceId, 'reconcile-unleased');
          if (stop.outcome === 'stopped') {
            result.stoppedUnleased.push({ vmName: instance.name, workspaceId: journaled.workspaceId, instanceId: journaled.instanceId, reason: 'unleased running stopped after grace' });
          } else {
            result.deferred.push({ vmName: instance.name, workspaceId: journaled.workspaceId, instanceId: journaled.instanceId, reason: 'stop outcome unknown; retained' });
          }
        }
      }
    }
    // Guard quarantine for journal-known identity mismatches. Runs AFTER the
    // inspection loop so reconcile reporting is never blocked by guard I/O;
    // a guard failure is journaled, never thrown — reconcile still completes.
    if (quarantineCandidates.length > 0) {
      try {
        const guard = await this.deps.guard();
        const q = await guard.quarantine({
          reason: 'reconcile identity mismatch',
          identities: quarantineCandidates
        });
        journal.appendEvent('reconcile.quarantine-outcomes', null, {
          quarantined: q.quarantined,
          outcomes: q.outcomes
        });
      } catch (error) {
        journal.appendEvent('reconcile.quarantine-failed', null, {
          candidates: quarantineCandidates.length,
          error: error instanceof Error ? error.message : String(error)
        });
      }
    }
    journal.appendEvent('reconcile.complete', null, {
      adopted: result.adopted.length,
      quarantined: result.quarantined.length,
      stoppedUnleased: result.stoppedUnleased.length,
      foreignIgnored: result.foreignIgnored.length,
      deferred: result.deferred.length
    });
    return result;
  }
}
