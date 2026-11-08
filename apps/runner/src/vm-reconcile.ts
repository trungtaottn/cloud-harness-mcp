import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { join } from 'node:path';
import type { VmExportWorkspaceFn } from './backend-factory.js';
import type { VmSupervisorGateway } from './incus-executor-backend.js';
import type { ProvisionContext } from './executor-backend.js';
import type { WorkspaceRecord } from './state-store.js';
import { VmSupervisorCallError, type VmWorkspaceIdentity } from './vm-supervisor-client.js';

/**
 * Runner startup/shutdown reconciliation for incus-vm workspaces.
 *
 * `reconcileVmFleet` compares `vm.list` against persisted records:
 *  - running VMs adopt ONLY for ACTIVE/EXPIRED_RECOVERABLE records on a FULL
 *    `user.cloud-harness.*` identity match (workspaceId + instanceId +
 *    templateId + templateDigest); anything else is reported quarantined and
 *    NEVER touched;
 *  - CREATING records with a verified-identity VM are provision orphans —
 *    reported for the caller's close path; reconcile NEVER deletes;
 *  - EXPIRED_RECOVERABLE records past `hardExpiresAt` get an OFFLINE clean
 *    check: `vm.stop` (lifecycle, not guest exec) → `vm.export` through the
 *    supervisor's libguestfs appliance → injected inspector verdict.
 *    clean → reported `export-clean` and RETAINED — a clean verdict proves
 *    deletability, it does not authorize it; only an explicit user
 *    close/finalize may delete. dirty/unpushed → retained + reported;
 *    unknown or no inspector/export → deferred. Unknown data is never
 *    deleted, and reconcile holds no delete authority at all.
 *  - VMs with no matching record are reported as orphans — never deleted
 *    (the supervisor watchdog owns unleased-VM stops).
 *
 * The module performs only supervisor-side reads/lifecycle actions; record
 * status mutations AND every deletion stay with the service layer, which
 * owns store writes and close/finalize authorization.
 */

export type VmReconcileRecord = Pick<WorkspaceRecord,
  'id' | 'ownerId' | 'status' | 'generation' | 'backendKind' | 'vmName'
  | 'backendInstanceId' | 'templateId' | 'templateDigest'
  | 'expiresAt' | 'hardExpiresAt' | 'recoverableUntil' | 'workspacePath'
>;

export type VmReconcileAction =
  | { type: 'adopted'; workspaceId: string; vmName: string }
  | { type: 'quarantined'; vmName: string; workspaceId?: string; reason: string }
  | { type: 'orphaned'; vmName: string; workspaceId?: string; reason: string }
  /** Offline export proved the checkout clean — RETAINED; only explicit close/finalize may delete. */
  | { type: 'export-clean'; workspaceId: string; vmName: string; reason: string }
  | { type: 'retained-dirty'; workspaceId: string; vmName: string; reason: string }
  | { type: 'deferred'; workspaceId?: string; vmName: string; reason: string }
  | { type: 'stopped'; vmName: string; reason: string };

export type VmReconcileReport = { actions: VmReconcileAction[] };

/** Verdict of the offline-export clean check; 'unknown' always defers. */
export type VmExportCleanVerdict = 'clean' | 'dirty' | 'unknown';

export type VmReconcileDeps = {
  client: Pick<VmSupervisorGateway,
    'vmList' | 'vmStatus' | 'vmStop' | 'vmExport' | 'leaseClear' | 'leaseSet'
  >;
  /**
   * Offline export writer (backend-factory's createVmExportWorkspace). When
   * absent, expired records can never be proven clean → always deferred.
   */
  exportWorkspace?: VmExportWorkspaceFn;
  /**
   * Inspects an exported checkout for unpushed/uncommitted work. Injected by
   * the caller (phase-08 owns checkout inspection); absent → 'unknown' →
   * defer, never delete.
   */
  inspectExport?: (input: {
    record: VmReconcileRecord;
    exportPath: string;
    stagingDir: string;
  }) => Promise<VmExportCleanVerdict>;
  now?: () => number;
};

function wireIdentity(record: VmReconcileRecord): VmWorkspaceIdentity | undefined {
  if (record.backendKind !== 'incus-vm' || !record.backendInstanceId) return undefined;
  return { workspaceId: record.id, generation: record.generation, instanceId: record.backendInstanceId };
}

function fullIdentityMatch(
  observed: { workspaceId: string; instanceId: string; templateId: string; templateDigest: string } | undefined,
  record: VmReconcileRecord
): boolean {
  return observed !== undefined
    && observed.workspaceId === record.id
    && observed.instanceId === record.backendInstanceId
    && observed.templateId === record.templateId
    && observed.templateDigest === record.templateDigest;
}

async function vmStatusSafe(
  deps: VmReconcileDeps,
  identity: VmWorkspaceIdentity,
  signal?: AbortSignal
): Promise<Awaited<ReturnType<VmSupervisorGateway['vmStatus']>> | undefined> {
  try {
    return await deps.client.vmStatus(identity, { timeoutMs: 15_000, ...(signal ? { signal } : {}) });
  } catch {
    return undefined;
  }
}

/**
 * Startup reconcile: adopt verified running VMs, report verified CREATING
 * orphans and fleet orphans, run the offline clean-check on hard-expired
 * records, and report everything else. Reconcile holds NO delete authority —
 * `vm.delete` is reachable only through the explicit close/finalize path.
 * `records` are the runner's persisted workspace rows (any status).
 *
 * `options.signal`/`options.deadlineMs` (absolute epoch ms) bound the sweep:
 * once either expires, no further records are scheduled — each unprocessed
 * VM is reported `deferred` so the caller can retry — and in-flight wire
 * calls (status/stop/export) are aborted through the same signal. An
 * aborted export cleans its exact staging dir and retains the VM; nothing
 * is deleted or mutated after cancellation.
 */
export async function reconcileVmFleet(
  deps: VmReconcileDeps,
  records: readonly VmReconcileRecord[],
  options?: { signal?: AbortSignal; deadlineMs?: number }
): Promise<VmReconcileReport> {
  const actions: VmReconcileAction[] = [];
  const nowFn = deps.now ?? (() => Date.now());
  const signal = options?.signal;
  const deadlineMs = options?.deadlineMs;
  const budgetLeft = (): boolean =>
    signal?.aborted !== true && (deadlineMs === undefined || nowFn() < deadlineMs);
  const exhaustedReason = 'reconcile cancelled or deadline exhausted before this VM was evaluated';
  const vmRecords = records.filter((r) => r.backendKind === 'incus-vm');
  const byWorkspaceId = new Map(vmRecords.map((r) => [r.id, r]));

  let listing;
  try {
    listing = await deps.client.vmList({}, { timeoutMs: 30_000, ...(signal ? { signal } : {}) });
  } catch (error) {
    // Cannot see the fleet → defer everything; never act on partial knowledge.
    for (const record of vmRecords) {
      actions.push({ type: 'deferred', workspaceId: record.id, vmName: record.vmName ?? '', reason: `vm.list unavailable: ${error instanceof Error ? error.message : String(error)}` });
    }
    return { actions };
  }

  const seen = new Set<string>();
  for (const entry of listing) {
    const vmName = entry.vmName;
    seen.add(vmName);
    const record = entry.workspaceId !== undefined ? byWorkspaceId.get(entry.workspaceId) : undefined;

    // M5: once the budget is gone, schedule NOTHING further — every remaining
    // entry is deferred so the caller knows it was never evaluated.
    if (!budgetLeft()) {
      actions.push({
        type: 'deferred',
        vmName,
        ...(record ? { workspaceId: record.id } : {}),
        reason: exhaustedReason
      });
      continue;
    }

    if (!record) {
      actions.push({ type: 'orphaned', vmName, ...(entry.workspaceId ? { workspaceId: entry.workspaceId } : {}), reason: 'no persisted incus-vm record matches this VM' });
      continue;
    }
    const identity = wireIdentity(record);
    if (!identity || (entry.instanceId !== undefined && entry.instanceId !== identity.instanceId)) {
      actions.push({ type: 'quarantined', vmName, workspaceId: record.id, reason: 'VM instance identity does not match the persisted record' });
      continue;
    }

    const status = await vmStatusSafe(deps, identity, signal);
    if (!status) {
      actions.push({ type: 'deferred', workspaceId: record.id, vmName, reason: 'vm.status unavailable; cannot verify identity' });
      continue;
    }
    if (!fullIdentityMatch(status.userCloudHarness, record)) {
      actions.push({ type: 'quarantined', vmName, workspaceId: record.id, reason: 'user.cloud-harness.* identity mismatch or absent' });
      continue;
    }

    if (record.status === 'CREATING') {
      // Provision orphan: identity verified, workspace never activated → no
      // user data can exist. Reported for the caller's close path; reconcile
      // itself never deletes — deletion requires explicit close/finalize.
      actions.push({
        type: 'orphaned',
        vmName,
        workspaceId: record.id,
        reason: 'verified CREATING provision orphan; retained — deletion requires explicit close/finalize'
      });
      continue;
    }

    // M4: EXPIRED_RECOVERABLE past hard expiry is checked BEFORE the running
    // adopt — an expire-before-adopt race must never report 'adopted' for a
    // disk already owned by the offline-export path. The clean-check stops
    // the VM itself, so VM state does not matter here.
    if (record.status === 'EXPIRED_RECOVERABLE' && record.hardExpiresAt <= nowFn()) {
      await expiredCleanCheck(deps, record, identity, vmName, actions, signal);
      continue;
    }

    const adoptable = record.status === 'ACTIVE' || record.status === 'EXPIRED_RECOVERABLE';
    if (status.state === 'running' && adoptable) {
      actions.push({ type: 'adopted', workspaceId: record.id, vmName });
      continue;
    }
    if (status.state === 'running' && !adoptable) {
      actions.push({ type: 'quarantined', vmName, workspaceId: record.id, reason: `running VM belongs to non-adoptable status '${record.status}'` });
      continue;
    }

    // Stopped/frozen/error VMs for live records: nothing to adopt; the next
    // ensureActive start path re-gates through vm.start.
    if (adoptable) {
      actions.push({ type: 'deferred', workspaceId: record.id, vmName, reason: `VM state '${status.state}' needs no reconcile action` });
      continue;
    }
    actions.push({ type: 'deferred', workspaceId: record.id, vmName, reason: `status '${record.status}' with VM state '${status.state}'` });
  }

  // Records whose VM is absent from vm.list entirely.
  for (const record of vmRecords) {
    const vmName = record.vmName ?? '';
    if (vmName !== '' && seen.has(vmName)) continue;
    if (!budgetLeft()) {
      actions.push({ type: 'deferred', workspaceId: record.id, vmName, reason: exhaustedReason });
      continue;
    }
    if (record.status === 'CREATING' || record.status === 'ACTIVE' || record.status === 'EXPIRED_RECOVERABLE') {
      actions.push({ type: 'deferred', workspaceId: record.id, vmName, reason: 'no matching VM in vm.list; record retained — ensureActive re-provisions only on typed supervisor NOT_FOUND' });
    }
  }
  return { actions };
}

/** Offline export clean-check for a hard-expired record. Never deletes on 'unknown'. */
async function expiredCleanCheck(
  deps: VmReconcileDeps,
  record: VmReconcileRecord,
  identity: VmWorkspaceIdentity,
  vmName: string,
  actions: VmReconcileAction[],
  signal?: AbortSignal
): Promise<void> {
  const defer = (reason: string) => actions.push({ type: 'deferred', workspaceId: record.id, vmName, reason });
  if (!deps.exportWorkspace || !deps.inspectExport) {
    defer('no offline export/inspection wired; cannot prove clean — retained');
    return;
  }
  // Lifecycle stop only (never guest exec/probe post-hardTTL); the export
  // itself reads the disk through the supervisor's libguestfs appliance.
  try {
    await deps.client.vmStop(identity, { timeoutMs: 60_000, ...(signal ? { signal } : {}) });
  } catch (error) {
    if (!(error instanceof VmSupervisorCallError && error.code === 'NOT_FOUND')) {
      defer(`vm.stop before export failed: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
  }
  // L11: stage under the record's workspace job dir — the same disk-backed
  // root the backend uses — never os.tmpdir(), which may be tmpfs and would
  // write tens of GiB into RAM on a large-RAM host.
  let staging: string;
  try {
    await mkdir(record.workspacePath, { recursive: true });
    staging = await mkdtemp(join(record.workspacePath, '.reconcile-'));
  } catch (error) {
    defer(`reconcile staging unavailable: ${error instanceof Error ? error.message : String(error)}`);
    return;
  }
  try {
    const exportPath = join(staging, 'checkout.tar');
    // ProvisionContext carries the reconcile signal so the export's wire
    // download aborts mid-stream; staging cleanup below is exact and awaited.
    const ctx = { record, signal } as unknown as ProvisionContext;
    try {
      await deps.exportWorkspace(ctx, { guestPath: '/workspace', destPath: exportPath, maxBytes: 68_719_476_736, ...(signal ? { signal } : {}) });
    } catch (error) {
      defer(signal?.aborted === true
        ? 'reconcile cancelled during offline export; VM retained'
        : `offline export failed: ${error instanceof Error ? error.message : String(error)}`);
      return;
    }
    let verdict: VmExportCleanVerdict;
    try {
      verdict = await deps.inspectExport({ record, exportPath, stagingDir: staging });
    } catch {
      verdict = 'unknown';
    }
    if (verdict === 'clean') {
      // A clean verdict proves deletability, NOT authorization: the VM and
      // its record stay until an explicit user close/finalize runs the
      // destroy path. Reconcile reports the evidence and retains.
      actions.push({
        type: 'export-clean',
        workspaceId: record.id,
        vmName,
        reason: 'offline export verified clean; retained pending explicit close/finalize'
      });
    } else if (verdict === 'dirty') {
      actions.push({ type: 'retained-dirty', workspaceId: record.id, vmName, reason: 'offline export shows uncommitted or unpushed work; retained' });
    } else {
      defer('offline export cleanliness unknown; retained pending audit');
    }
  } finally {
    await rm(staging, { recursive: true, force: true }).catch(() => undefined);
  }
}

/**
 * Shutdown reconcile: `lease.clear` + `vm.stop` best-effort for every
 * incus-vm record. The supervisor watchdog is the hard backstop — errors are
 * collected into the report, never thrown.
 */
export async function reconcileVmShutdown(
  deps: VmReconcileDeps,
  records: readonly VmReconcileRecord[]
): Promise<VmReconcileReport> {
  const actions: VmReconcileAction[] = [];
  for (const record of records) {
    if (record.backendKind !== 'incus-vm') continue;
    const identity = wireIdentity(record);
    const vmName = record.vmName ?? '';
    if (!identity) {
      actions.push({ type: 'deferred', workspaceId: record.id, vmName, reason: 'no persisted VM identity; nothing to stop' });
      continue;
    }
    try {
      await deps.client.leaseClear(identity, { idempotencyKey: `shutdown-lease-${identity.instanceId}-${Date.now()}` });
    } catch {
      // best-effort: watchdog enforces expiry regardless
    }
    try {
      await deps.client.vmStop(identity, { timeoutMs: 60_000 });
      actions.push({ type: 'stopped', vmName, reason: 'runner shutdown stop' });
    } catch (error) {
      actions.push({ type: 'deferred', workspaceId: record.id, vmName, reason: `vm.stop failed: ${error instanceof Error ? error.message : String(error)}` });
    }
  }
  return { actions };
}

