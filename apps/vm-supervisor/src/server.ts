import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { stat, statfs } from 'node:fs/promises';
import {
  VmSupervisorWorkspaceRequestSchema,
  VmSupervisorHostRequestSchema,
  VmSupervisorOpResultSchemas,
  type VmSupervisorWorkspaceRequest,
  type VmSupervisorHostRequest
} from '@cloud-harness/contracts';
import type { VmSupervisorConfig } from './config.js';
import type { VmJournal, VmWorkspaceRow } from './journal.js';
import type { RequestDigester } from './request-digest.js';
import type { IncusClient, IncusInstanceInfo } from './incus.js';
import {
  vmNameForWorkspace,
  identityConfigBlock,
  readIdentityFromConfig
} from './identity.js';
import { VmOpError, VmUnknownMutationError, type VmLifecycle } from './lifecycle.js';
import type { VmSessionManager } from './sessions.js';
import {
  VmNetworkGuardError,
  VmNetworkGuardNotImplementedError,
  type VmNetworkGuard,
  type VmGuardCommandRunner,
  type VmNetworkIdentity
} from './network-ops.js';
import { prepareVmExport } from './export.js';
import type { VmWorkspaceSubjectPlanner } from './network-plan.js';
import { poolVolumeInfos, imageCacheBytes } from './runtime.js';
import { WIRE_LIMITS, type WireHandlerOutcome, type WireRequestContext, type WireRequestHandler } from './transport.js';
import type { DiskReservations } from './disk-reservations.js';

/**
 * Request dispatcher: strict contract validation, workspace fencing,
 * lease-deadline op cutoff, durable idempotency, then per-op handlers.
 * Every result is validated against VmSupervisorOpResultSchemas[op] before
 * it leaves the process — a schema miss is a supervisor bug reported as
 * INTERNAL_ERROR, never a malformed success.
 *
 * Idempotency: mutating ops get a durable record BEFORE execution. Replay of
 * a completed record returns the recorded result; a pending record means the
 * previous attempt's outcome is unknown and surfaces `unknown: true` — the
 * mutation is NEVER blindly re-executed. For upload outcomes the record
 * completes inside the stream `complete()` callback with the real result.
 */

export interface VmSupervisorDeps {
  config: VmSupervisorConfig;
  journal: VmJournal;
  digester: RequestDigester;
  incus: IncusClient;
  incusSocketPath: string;
  lifecycle: VmLifecycle;
  sessions: VmSessionManager;
  guard: () => Promise<VmNetworkGuard>;
  /** Canonical workspace→network-subject planner (lazy; fails closed when absent). */
  networkPlan: () => Promise<VmWorkspaceSubjectPlanner>;
  execFile: VmGuardCommandRunner;
  /**
   * Shared host-disk reservation ledger — MUST be the same instance the wire
   * server uses for upload staging so exports and uploads jointly account
   * for backing-filesystem free space.
   */
  diskReservations?: DiskReservations;
  logger?: (message: string, fields?: Record<string, unknown>) => void;
}

/** Ops that mutate state and therefore carry durable idempotency records. */
const IDEMPOTENT_OPS = new Set<VmSupervisorWorkspaceRequest['op']>([
  'vm.create', 'vm.start', 'vm.stop', 'vm.delete',
  'exec.run', 'exec.open', 'exec.write', 'exec.close', 'exec.resize', 'exec.killSession',
  'file.push', 'pushTree',
  'network.program', 'network.tearDown',
  'lease.set', 'lease.clear'
]);

/**
 * file.pull inline cap: the result rides a kind-0x00 control frame bounded
 * at 1 MiB TOTAL. base64 inflates ~4/3, so 720 KiB raw → ~960 KiB base64 +
 * JSON envelope stays under the cap with headroom; larger files must use
 * pullTree (streamed) — the runner routes on the same threshold.
 */
const FILE_PULL_INLINE_MAX = 720 * 1024;

/**
 * Tar overhead allowance on top of file content. The entry cap (50k, enforced
 * by inspectTarSafety on upload and TarEntryCounter on download) bounds real
 * overhead near ~1 GiB; 8 GiB is the protocol-level allowance so a full
 * diskBytes of content plus worst-case metadata still fits the wire ceiling.
 * It is an OVERHEAD allowance only — never a cap on total transfer size.
 */
const TAR_OVERHEAD_BOUND_BYTES = 8 * 1024 * 1024 * 1024;

/**
 * Per-request transfer bound: configured guest-disk content plus the tar
 * overhead allowance, never above the 72 GiB absolute wire ceiling. Thus a
 * workspace configured for 64 GiB of disk can transfer ~72 GiB total while a
 * default 20 GiB disk bounds requests near 28 GiB. The ceiling itself is
 * never reserved — staging admission (DiskReservations + statfs) enforces
 * actual free space independently of this bound.
 */
function transferMaxBytes(config: VmSupervisorConfig, requested: number): number {
  return Math.min(requested, config.diskBytes + TAR_OVERHEAD_BOUND_BYTES, WIRE_LIMITS.maxStreamBytes);
}
const FILE_STAT_TIMEOUT_MS = 15_000;
const EXEC_PROBE_TIMEOUT_MS = 30_000;
const VM_LIST_PAGE = 1_024;

function sha256Hex(data: Buffer | string): string {
  return createHash('sha256').update(data).digest('hex');
}

function b64(buf: Buffer): string {
  return buf.toString('base64');
}

/**
 * Guest path confinement (phase-04 frozen, extended for phase-07 asset roots):
 * file/export/killSession paths are confined to the approved namespaces below.
 * Absolute paths only (schema-enforced); `..` segments are rejected even inside
 * allowed prefixes.
 *
 * What this bound IS: an API-surface path-shape check for the trusted
 * single-owner caller — it stops accidental out-of-root requests before any
 * guest I/O. What it is NOT: guest filesystem confinement. The check is a
 * pure string-prefix test; it does not resolve guest-side symlinks, and the
 * Incus file transport follows them silently (no readlink exists on that
 * API). That is deliberate, not a gap we pretend away: the guest is trusted
 * single-owner code already running arbitrary repo commands as `harness`
 * with sudo, so a symlink "escape" grants the caller nothing an `exec.run`
 * could not already read — the allowlist exists to bound the API surface,
 * not to contain a hostile guest root (which is not the threat model).
 *
 * The REAL payload boundary is enforced where untrusted bytes cross to the
 * host: pushTree archives are tar-validated before write (tar-safety.ts:
 * traversal, device nodes, link targets), and pullTree consumers validate
 * the extracted stream the same way. Single-file ops move guest bytes
 * verbatim with no host-side interpretation, so no equivalent check exists
 * or is needed there.
 */
const GUEST_PATH_ROOTS = ['/workspace', '/opt/user-tools', '/opt/cloud-harness', '/var/cache/harness', '/tmp', '/var/tmp'] as const;

function assertGuestPathAllowed(guestPath: string): void {
  if (!guestPath.startsWith('/') || guestPath.split('/').includes('..')) {
    throw new VmOpError('INVALID_INPUT', 'guestPath must be absolute and must not contain .. segments');
  }
  const allowed = GUEST_PATH_ROOTS.some(
    (root) => guestPath === root || guestPath.startsWith(`${root}/`)
  );
  if (!allowed) {
    throw new VmOpError('INVALID_INPUT', 'guestPath outside approved roots');
  }
}

function fileOwnerOpts(params: { mode?: number | undefined; uid?: number | undefined; gid?: number | undefined }): { mode?: number; uid?: number; gid?: number } {
  return {
    ...(params.mode !== undefined ? { mode: params.mode } : {}),
    ...(params.uid !== undefined ? { uid: params.uid } : {}),
    ...(params.gid !== undefined ? { gid: params.gid } : {})
  };
}

interface ResolvedWorkspace {
  row: VmWorkspaceRow;
  vmName: string;
}

type OpHandler = (req: never, ctx: WireRequestContext) => unknown;

export function createSupervisorHandler(deps: VmSupervisorDeps): WireRequestHandler {
  const { config, journal, digester, incus, lifecycle, sessions } = deps;
  const log = deps.logger ?? (() => undefined);

  // ---- shared guards ---------------------------------------------------------

  function requireWorkspace(req: VmSupervisorWorkspaceRequest): ResolvedWorkspace {
    const row = journal.getWorkspace(req.workspaceId);
    if (row === undefined) {
      throw new VmOpError('NOT_FOUND', 'unknown workspace');
    }
    if (row.state === 'deleted') {
      throw new VmOpError('CONFLICT', 'workspace is deleted');
    }
    if (row.instanceId !== req.vmInstanceId) {
      throw new VmOpError('VM_IDENTITY_MISMATCH', 'vmInstanceId does not match journal identity');
    }
    if (journal.acceptGeneration(req.workspaceId, req.workspaceGeneration) === 'stale') {
      throw new VmOpError('VM_GENERATION_MISMATCH', 'workspaceGeneration is stale');
    }
    // Lease op cutoff: issuedAt (ms) at/after the effective deadline is refused.
    const deadlineSec = lifecycle.leaseDeadlineFor(req.workspaceId);
    if (deadlineSec !== undefined && req.issuedAt >= deadlineSec * 1000 && req.op !== 'lease.clear') {
      throw new VmOpError('EXPIRED', 'workspace lease deadline reached');
    }
    return { row, vmName: row.vmName };
  }

  /** Verify the live instance against journal identity before acting on it. */
  async function verifiedInstance(ws: ResolvedWorkspace): Promise<IncusInstanceInfo> {
    const instance = await incus.getInstance(ws.vmName);
    if (instance === null) {
      throw new VmOpError('NOT_FOUND', 'managed instance absent from Incus');
    }
    const verdict = lifecycle.verifyInstanceIdentity(instance, ws.row);
    if (!verdict.ok) {
      throw new VmOpError('VM_IDENTITY_MISMATCH', `instance identity verification failed: ${verdict.reason}`);
    }
    return instance;
  }

  /** Assert supervisor-controlled resource/config actuals on expanded view. */
  function assertSupervisorShape(instance: IncusInstanceInfo): void {
    const cfg = instance.expandedConfig;
    const checks: Array<[string, string]> = [
      ['boot.autostart', 'false'],
      ['limits.cpu', String(config.cpus)],
      ['limits.memory', String(config.memoryBytes)]
    ];
    for (const [key, expected] of checks) {
      if (cfg[key] !== expected) {
        throw new VmOpError('VM_ATTESTATION_FAILED', `instance config ${key}=${String(cfg[key])} expected ${expected}`);
      }
    }
    for (const key of Object.keys(cfg)) {
      if (key.startsWith('raw.') || key.startsWith('volatile.')) {
        throw new VmOpError('VM_ATTESTATION_FAILED', `instance carries unsupervised config key ${key}`);
      }
    }
    if (instance.profiles.length > 0) {
      throw new VmOpError('VM_ATTESTATION_FAILED', 'instance carries unexpected profiles');
    }
    const root = instance.expandedDevices['root'];
    if (root === undefined || root.type !== 'disk' || root.path !== '/' || Number(root.size) !== config.diskBytes) {
      throw new VmOpError('VM_ATTESTATION_FAILED', 'root disk device does not match supervisor shape');
    }
  }

  function requireRunning(ws: ResolvedWorkspace): void {
    if (ws.row.state !== 'running') {
      throw new VmOpError('CONFLICT', `workspace VM is ${ws.row.state}, not running`);
    }
  }

  function identityForGuard(ws: ResolvedWorkspace): VmNetworkIdentity {
    return {
      workspaceId: ws.row.workspaceId as VmNetworkIdentity['workspaceId'],
      vmName: ws.vmName,
      instanceId: ws.row.instanceId,
      generation: ws.row.acceptedGeneration
    };
  }

  /** Journaled network profile is authoritative for every guard call. */
  function journaledNetworkProfile(row: VmWorkspaceRow): 'network-none' | 'dependency-access' {
    return row.networkProfile === 'network-none' ? 'network-none' : 'dependency-access';
  }

  // ---- workspace ops ---------------------------------------------------------

  async function opAdmit(): Promise<unknown> {
    const admission = await lifecycle.withLifecycleLock(() => lifecycle.checkAdmission({ forStart: true }));
    return admission.admitted
      ? { decision: 'admitted' as const }
      : { decision: 'denied' as const, reason: admission.reason?.slice(0, 500) };
  }

  async function opCreate(req: Extract<VmSupervisorWorkspaceRequest, { op: 'vm.create' }>): Promise<unknown> {
    const params = req.params;
    if (params.instanceId !== req.vmInstanceId) {
      throw new VmOpError('INVALID_INPUT', 'params.instanceId must equal envelope vmInstanceId');
    }
    if (params.templateId !== config.templateId || params.templateDigest !== config.templateDigest) {
      throw new VmOpError('INVALID_INPUT', 'template is not in the supervisor allowlist');
    }
    return lifecycle.withLifecycleLock(async () => {
      const existing = journal.getWorkspace(req.workspaceId);
      if (existing !== undefined) {
        if (existing.instanceId !== req.vmInstanceId) {
          throw new VmOpError('VM_IDENTITY_MISMATCH', 'workspace already journaled under a different instanceId');
        }
        return { vmName: existing.vmName, state: 'stopped' as const };
      }
      const vmName = vmNameForWorkspace(req.workspaceId);
      const preExisting = await incus.getInstance(vmName);
      if (preExisting !== null) {
        // Name collision or prior partial create: adopt ONLY on full identity match.
        const identity = readIdentityFromConfig(preExisting.expandedConfig);
        if (
          identity === undefined ||
          identity.workspaceId !== req.workspaceId ||
          identity.instanceId !== req.vmInstanceId ||
          identity.templateId !== params.templateId ||
          identity.templateDigest !== params.templateDigest
        ) {
          throw new VmOpError('VM_IDENTITY_MISMATCH', 'existing instance at derived name fails identity verification');
        }
        journal.recordWorkspaceAdmit({
          workspaceId: req.workspaceId, vmName, instanceId: req.vmInstanceId,
          templateId: params.templateId, templateDigest: params.templateDigest,
          generation: req.workspaceGeneration, networkProfile: params.networkProfile
        });
        const observed = lifecycle.normalizeState(preExisting.status);
        journal.setWorkspaceState(req.workspaceId, observed === 'running' ? 'running' : 'stopped');
        return { vmName, state: 'stopped' as const };
      }
      const admission = await lifecycle.checkAdmission({ forStart: false });
      if (!admission.admitted) {
        throw new VmOpError('VM_QUOTA_EXCEEDED', admission.reason ?? 'admission denied');
      }
      const poolName = await incus.findPoolNameBySourcePath(config.poolPath);
      if (poolName === undefined) {
        throw new VmOpError('VM_SUPERVISOR_UNAVAILABLE', 'configured poolPath is not an Incus storage pool', { retryable: true });
      }
      const expandedConfig: Record<string, string> = {
        ...identityConfigBlock({
          workspaceId: req.workspaceId,
          instanceId: req.vmInstanceId,
          templateId: params.templateId,
          templateDigest: params.templateDigest
        }),
        'boot.autostart': 'false',
        'limits.cpu': String(config.cpus),
        'limits.memory': String(config.memoryBytes)
      };
      const devices: Record<string, Record<string, string>> = {
        root: { type: 'disk', path: '/', pool: poolName, size: String(config.diskBytes) }
      };
      if (params.networkProfile === 'dependency-access') {
        // Canonical subject + NIC stamp from the phase-05 policy module — the
        // SAME derivation/record the guard enforces at program/attest time.
        // A missing or invalid policy module fails closed here, before any
        // mutation; there is no fallback hash.
        let planner;
        try {
          planner = await deps.networkPlan();
        } catch (error) {
          if (error instanceof VmNetworkGuardNotImplementedError) {
            throw new VmOpError('VM_SUPERVISOR_UNAVAILABLE', `network identity unavailable: ${error.message}`, { retryable: true });
          }
          if (error instanceof VmNetworkGuardError) {
            throw new VmOpError('VM_ATTESTATION_FAILED', `network identity derivation failed: ${error.message}`);
          }
          throw error;
        }
        // Early slot-conflict check against journaled workspaces (pure hash
        // scan, no kernel access). The guard's claim registry remains the
        // authoritative enforcement at program time — this only fails faster.
        const peers = journal
          .listWorkspaces()
          .filter((w) => w.state !== 'deleted' && w.workspaceId !== req.workspaceId)
          .map((w) => w.workspaceId);
        let stamped: Record<string, string>;
        try {
          const collisions = planner.findCollisions([req.workspaceId, ...peers]);
          if (collisions.some((c) => c.workspaceIds.includes(req.workspaceId))) {
            throw new VmOpError('CONFLICT', 'workspace network slot collides with an existing managed workspace');
          }
          stamped = planner.stamp(planner.plan({ workspaceId: req.workspaceId, vmName }));
        } catch (error) {
          if (error instanceof VmOpError) throw error;
          if (error instanceof VmNetworkGuardNotImplementedError) {
            throw new VmOpError('VM_SUPERVISOR_UNAVAILABLE', `network identity unavailable: ${error.message}`, { retryable: true });
          }
          if (error instanceof VmNetworkGuardError) {
            throw new VmOpError('VM_ATTESTATION_FAILED', `network identity derivation failed: ${error.message}`);
          }
          throw error;
        }
        devices.eth0 = stamped;
      }
      const created = await incus.createInstance({
        name: vmName,
        imageAlias: params.templateId,
        type: 'virtual-machine',
        config: expandedConfig,
        devices,
        profiles: []
      });
      if (created.operation !== undefined) {
        await incus.waitOperation(created.operation, Date.now() + 600_000);
      }
      const readBack = await incus.getInstance(vmName);
      if (readBack === null) {
        throw new VmUnknownMutationError('instance create could not be verified');
      }
      const verdict = lifecycle.verifyInstanceIdentity(readBack, {
        workspaceId: req.workspaceId, instanceId: req.vmInstanceId,
        templateId: params.templateId, templateDigest: params.templateDigest
      });
      if (!verdict.ok) {
        throw new VmUnknownMutationError(`created instance failed identity read-back: ${verdict.reason}`);
      }
      assertSupervisorShape(readBack);
      journal.recordWorkspaceAdmit({
        workspaceId: req.workspaceId, vmName, instanceId: req.vmInstanceId,
        templateId: params.templateId, templateDigest: params.templateDigest,
        generation: req.workspaceGeneration, networkProfile: params.networkProfile
      });
      journal.setWorkspaceState(req.workspaceId, 'stopped');
      journal.appendEvent('vm.created', req.workspaceId, { vmName });
      return { vmName, state: 'stopped' as const };
    });
  }

  async function opStart(req: Extract<VmSupervisorWorkspaceRequest, { op: 'vm.start' }>): Promise<unknown> {
    const ws = requireWorkspace(req);
    // The journaled profile is authoritative — it determined the stamped NIC
    // devices. A mismatched request profile is a fencing violation.
    const journaledProfile = journaledNetworkProfile(ws.row);
    if (req.params.networkProfile !== journaledProfile) {
      throw new VmOpError('INVALID_INPUT', 'networkProfile does not match the admitted workspace profile');
    }
    return lifecycle.withLifecycleLock(async () => {
      const instance = await verifiedInstance(ws);
      const observed = lifecycle.normalizeState(instance.status);
      if (observed === 'running') {
        journal.setWorkspaceState(ws.row.workspaceId, 'running');
        return { state: 'running' as const };
      }
      if (observed !== 'stopped') {
        throw new VmOpError('CONFLICT', `instance state ${instance.status} cannot start`);
      }
      assertSupervisorShape(instance);
      const admission = await lifecycle.checkAdmission({ forStart: true });
      if (!admission.admitted) {
        throw new VmOpError('VM_QUOTA_EXCEEDED', admission.reason ?? 'admission denied');
      }
      // Network gate, serialized inside the lifecycle lock on EVERY start
      // path (open, lease-renew reactivation, recover resume, ensureActive,
      // reaper revive, reconcile-adopt): ONE cross-process guard-lock hold
      // spans program → fresh attest → Incus start (+operation wait), so
      // the independent guard-service watcher cannot strip/rebuild permits
      // anywhere in the attest→start window. Reached only after
      // verified-stopped, so program never reconfigures under a running
      // instance; a cached guard-state.json verdict is never accepted. The
      // probe below stays outside the lock: it reads no guard state. A
      // guard lacking withStartTransaction fails closed — the racy per-call
      // path is never silently used. A start transport error inside the
      // transaction propagates unchanged (UNKNOWN stays UNKNOWN) and the
      // journal/reconcile owns the ambiguous outcome.
      const txArgs = { identity: identityForGuard(ws), networkProfile: journaledProfile };
      try {
        const guard = await deps.guard();
        if (typeof guard.withStartTransaction !== 'function') {
          throw new VmOpError('VM_ATTESTATION_FAILED', 'network guard does not support the atomic start transaction', { retryable: true });
        }
        await guard.withStartTransaction(txArgs, async (tx) => {
          await tx.program();
          const attest = await tx.attest();
          if (!attest.ok) {
            throw new VmOpError('VM_ATTESTATION_FAILED', 'network guard attestation failed');
          }
          const started = await incus.setInstanceState(ws.vmName, 'start', { timeoutSeconds: 120 });
          if (started.operation !== undefined) {
            await incus.waitOperation(started.operation, Date.now() + 300_000);
          }
        });
      } catch (error) {
        guardFailure('start gate', error);
      }
      // Bounded agent probe: exec /bin/true as workspace user.
      try {
        const probe = await sessions.openAndCapture({
          opId: `probe:${ws.row.workspaceId}:${lifecycle.nowMs()}`,
          workspaceId: ws.row.workspaceId,
          vmName: ws.vmName,
          argv: ['/bin/true'],
          environment: {},
          timeoutMs: EXEC_PROBE_TIMEOUT_MS,
          maxBytes: 1024,
          envKeys: [],
          envDigest: ''
        });
        if (probe.exitCode !== 0) {
          throw new VmOpError('VM_SUPERVISOR_UNAVAILABLE', 'guest agent probe failed', { retryable: true });
        }
      } catch (error) {
        if (error instanceof VmOpError) throw error;
        throw new VmOpError('VM_SUPERVISOR_UNAVAILABLE', 'guest agent probe transport failed', { retryable: true });
      }
      journal.setWorkspaceState(ws.row.workspaceId, 'running');
      journal.appendEvent('vm.started', ws.row.workspaceId, { vmName: ws.vmName });
      return { state: 'running' as const };
    });
  }

  async function opStop(req: VmSupervisorWorkspaceRequest & { op: 'vm.stop' }): Promise<unknown> {
    const ws = requireWorkspace(req);
    return lifecycle.withLifecycleLock(async () => {
      const instance = await verifiedInstance(ws);
      const observed = lifecycle.normalizeState(instance.status);
      if (observed === 'stopped') {
        journal.setWorkspaceState(ws.row.workspaceId, 'stopped');
        return { state: 'stopped' as const };
      }
      const stop = await lifecycle.stopVerified(ws.vmName, ws.row.workspaceId, 'vm.stop');
      if (stop.outcome !== 'stopped') {
        throw new VmUnknownMutationError('vm stop outcome could not be verified');
      }
      return { state: 'stopped' as const };
    });
  }

  async function opDelete(req: Extract<VmSupervisorWorkspaceRequest, { op: 'vm.delete' }>): Promise<unknown> {
    const ws = requireWorkspace(req);
    if (req.params.confirmInstanceId !== ws.row.instanceId) {
      throw new VmOpError('VM_IDENTITY_MISMATCH', 'confirmInstanceId does not match journal identity');
    }
    return lifecycle.withLifecycleLock(async () => {
      const instance = await incus.getInstance(ws.vmName);
      if (instance !== null) {
        const verdict = lifecycle.verifyInstanceIdentity(instance, ws.row);
        if (!verdict.ok) {
          throw new VmOpError('VM_IDENTITY_MISMATCH', `refusing delete: ${verdict.reason}`);
        }
        const observed = lifecycle.normalizeState(instance.status);
        if (observed !== 'stopped') {
          throw new VmOpError('CONFLICT', 'vm.delete requires a stopped instance');
        }
        // Guard teardown first: verified-stopped identity only; failure retains.
        const guard = await deps.guard();
        try {
          await guard.tearDown({ identity: identityForGuard(ws) });
        } catch (error) {
          if (error instanceof VmNetworkGuardError) {
            throw new VmOpError('VM_ATTESTATION_FAILED', `network teardown failed: ${error.message}`);
          }
          throw error;
        }
        const deleted = await incus.deleteInstance(ws.vmName);
        if (deleted.operation !== undefined) {
          await incus.waitOperation(deleted.operation, Date.now() + 120_000);
        }
      }
      journal.setWorkspaceState(ws.row.workspaceId, 'deleted');
      journal.clearLease(ws.row.workspaceId);
      journal.appendEvent('vm.deleted', ws.row.workspaceId, { vmName: ws.vmName });
      return { state: 'deleted' as const };
    });
  }

  async function opStatus(req: VmSupervisorWorkspaceRequest & { op: 'vm.status' }): Promise<unknown> {
    const ws = requireWorkspace(req);
    const instance = await incus.getInstance(ws.vmName);
    if (instance === null) {
      return { state: 'unknown' as const };
    }
    const identity = readIdentityFromConfig(instance.expandedConfig);
    return {
      state: lifecycle.normalizeState(instance.status),
      instanceId: ws.row.instanceId,
      ...(identity !== undefined ? { userCloudHarness: identity } : {}),
      expandedDevices: instance.expandedDevices as Record<string, unknown>,
      expandedConfig: instance.expandedConfig as Record<string, unknown>,
      profiles: [...instance.profiles]
    };
  }

  async function opExport(req: Extract<VmSupervisorWorkspaceRequest, { op: 'vm.export' }>): Promise<WireHandlerOutcome> {
    const ws = requireWorkspace(req);
    assertGuestPathAllowed(req.params.guestPath);
    const instance = await verifiedInstance(ws);
    // Offline export requires a STOPPED VM so the appliance reads a consistent
    // image. Journal state may lag; the live status is authoritative here.
    if (lifecycle.normalizeState(instance.status) !== 'stopped') {
      throw new VmOpError('CONFLICT', 'vm.export requires a stopped instance');
    }
    const maxBytes = Math.min(req.params.maxBytes, config.diskBytes);
    // Offline export stages a host tarball in poolPath/.exports BEFORE the
    // download streams — reserve the bound against backing-fs free space
    // (shared ledger with upload staging) for the file's whole lifetime.
    const releaseReservation = deps.diskReservations !== undefined
      ? await deps.diskReservations.acquire(`export:${req.requestId}`, config.poolPath, maxBytes)
      : undefined;
    let prepared: Awaited<ReturnType<typeof prepareVmExport>>;
    try {
      prepared = await prepareVmExport(
        { poolPath: config.poolPath, execFile: deps.execFile },
        { vmName: ws.vmName, guestPath: req.params.guestPath, maxBytes, ...(req.params.sha256 !== undefined ? { expectedSha256: req.params.sha256 } : {}) }
      );
    } catch (error) {
      releaseReservation?.();
      throw error;
    }
    return {
      kind: 'download',
      streamRef: `export:${ws.vmName}`,
      maxBytes,
      produce: async (emit) => {
        try {
          return await prepared.produce(emit);
        } finally {
          releaseReservation?.();
          await prepared.cleanup();
        }
      }
    };
  }

  // ---- exec ops ---------------------------------------------------------------

  async function opExecRun(req: Extract<VmSupervisorWorkspaceRequest, { op: 'exec.run' }>): Promise<unknown> {
    const ws = requireWorkspace(req);
    requireRunning(ws);
    await verifiedInstance(ws);
    const params = req.params;
    const envDigest = digester.digest({ environment: params.environment });
    const outcome = await sessions.openAndCapture({
      opId: params.opId,
      workspaceId: req.workspaceId,
      vmName: ws.vmName,
      argv: params.argv,
      ...(params.cwd !== undefined ? { cwd: params.cwd } : {}),
      environment: params.environment,
      ...(params.stdinBase64 !== undefined ? { stdinBase64: params.stdinBase64 } : {}),
      timeoutMs: params.timeoutMs,
      maxBytes: params.maxBytes,
      ...(params.user !== undefined ? { user: params.user } : {}),
      envKeys: Object.keys(params.environment).sort(),
      envDigest
    });
    return {
      opId: outcome.opId,
      exitCode: outcome.exitCode,
      signal: outcome.signal,
      stdout: outcome.stdout.slice(0, 16_777_216),
      stderr: outcome.stderr.slice(0, 16_777_216),
      truncated: outcome.truncated,
      timedOut: outcome.timedOut
    };
  }

  function opExecInspect(req: Extract<VmSupervisorWorkspaceRequest, { op: 'exec.inspect' }>): unknown {
    const ws = requireWorkspace(req);
    const row = journal.getExecOp(req.params.opId);
    if (row !== undefined && row.workspaceId !== ws.row.workspaceId) {
      throw new VmOpError('NOT_FOUND', 'exec op not found for this workspace');
    }
    const info = sessions.inspectOp(req.params.opId);
    return {
      state: info.state,
      ...(info.exitCode !== undefined ? { exitCode: info.exitCode } : {}),
      ...(info.returnMetadata !== undefined ? { returnMetadata: info.returnMetadata } : {})
    };
  }

  async function opExecOpen(req: Extract<VmSupervisorWorkspaceRequest, { op: 'exec.open' }>, ctx: WireRequestContext): Promise<WireHandlerOutcome> {
    const ws = requireWorkspace(req);
    requireRunning(ws);
    await verifiedInstance(ws);
    const params = req.params;
    const sessionId = params.sessionId;
    const result = await sessions.openSession({
      sessionId,
      workspaceId: req.workspaceId,
      vmName: ws.vmName,
      instanceId: ws.row.instanceId,
      generation: req.workspaceGeneration,
      argv: params.argv,
      ...(params.cwd !== undefined ? { cwd: params.cwd } : {}),
      environment: params.environment,
      ...(params.pty !== undefined ? { pty: params.pty } : {}),
      channel: ctx.channel,
      onClosed: () => undefined
    });
    // Connection drop → verified cleanup ladder; never a silent orphan.
    void ctx.closed.then(() => sessions.onConnectionClosed([sessionId]));
    return { kind: 'session', sessionId, result };
  }

  function opExecWrite(req: Extract<VmSupervisorWorkspaceRequest, { op: 'exec.write' }>): unknown {
    const ws = requireWorkspace(req);
    requireRunning(ws);
    // fd 1|2 are read-only channels: writeStdin rejects them with INVALID_INPUT.
    return sessions.writeStdin(req.params.sessionId, req.params.fd, req.params.dataBase64, req.params.eof);
  }

  async function opExecClose(req: Extract<VmSupervisorWorkspaceRequest, { op: 'exec.close' }>): Promise<unknown> {
    const ws = requireWorkspace(req);
    requireRunning(ws);
    return sessions.closeSession(req.params.sessionId, req.params.fd);
  }

  function opExecResize(req: Extract<VmSupervisorWorkspaceRequest, { op: 'exec.resize' }>): unknown {
    const ws = requireWorkspace(req);
    requireRunning(ws);
    return sessions.resizeSession(req.params.sessionId, req.params.cols, req.params.rows);
  }

  async function opExecKillSession(req: Extract<VmSupervisorWorkspaceRequest, { op: 'exec.killSession' }>): Promise<unknown> {
    const ws = requireWorkspace(req);
    requireRunning(ws);
    assertGuestPathAllowed(req.params.pidFile);
    return sessions.killSession(req.params.sessionId, req.params.pidFile);
  }

  // ---- file ops ---------------------------------------------------------------

  async function opFilePush(req: Extract<VmSupervisorWorkspaceRequest, { op: 'file.push' }>): Promise<WireHandlerOutcome> {
    const ws = requireWorkspace(req);
    requireRunning(ws);
    await verifiedInstance(ws);
    const params = req.params;
    assertGuestPathAllowed(params.guestPath);
    if (params.dataBase64 !== undefined) {
      const data = Buffer.from(params.dataBase64, 'base64');
      if (data.length > params.maxBytes) {
        throw new VmOpError('LIMIT_EXCEEDED', 'inline payload exceeds maxBytes');
      }
      const digest = sha256Hex(data);
      if (digest !== params.sha256) {
        throw new VmOpError('INVALID_INPUT', 'payload sha256 mismatch');
      }
      await incus.writeInstanceFile(ws.vmName, params.guestPath, data, fileOwnerOpts(params));
      return { kind: 'result', result: { sha256: digest, bytes: data.length } };
    }
    // streamRef path: stage upload; complete() streams into the guest.
    const uploadId = params.streamRef ?? `push:${req.requestId}`;
    journal.createUpload({
      uploadId,
      workspaceId: req.workspaceId,
      instanceId: ws.row.instanceId,
      generation: req.workspaceGeneration,
      path: params.guestPath,
      maxBytes: transferMaxBytes(config, params.maxBytes),
      expiresAt: lifecycle.nowSec() + 3600
    });
    return {
      kind: 'upload',
      streamRef: uploadId,
      maxBytes: transferMaxBytes(config, params.maxBytes),
      complete: async (payloadPath, payloadBytes, sha256) => {
        if (!journal.consumeUpload(uploadId)) {
          throw new VmOpError('CONFLICT', 'upload already consumed or unknown');
        }
        if (sha256 !== params.sha256) {
          throw new VmOpError('INVALID_INPUT', 'staged payload sha256 mismatch');
        }
        if (payloadBytes > params.maxBytes) {
          throw new VmOpError('LIMIT_EXCEEDED', 'staged payload exceeds maxBytes');
        }
        const fileStat = await stat(payloadPath);
        await incus.writeInstanceFileStream(ws.vmName, params.guestPath, createReadStream(payloadPath), fileStat.size, fileOwnerOpts(params));
        return { sha256, bytes: payloadBytes };
      }
    };
  }

  async function opFilePull(req: Extract<VmSupervisorWorkspaceRequest, { op: 'file.pull' }>): Promise<unknown> {
    const ws = requireWorkspace(req);
    requireRunning(ws);
    await verifiedInstance(ws);
    const params = req.params;
    assertGuestPathAllowed(params.guestPath);
    if (params.maxBytes > FILE_PULL_INLINE_MAX) {
      throw new VmOpError('INVALID_INPUT', `file.pull is capped at ${FILE_PULL_INLINE_MAX} bytes; use pullTree for larger transfers`);
    }
    const data = await incus.readInstanceFile(ws.vmName, params.guestPath, params.maxBytes);
    const digest = sha256Hex(data);
    if (params.sha256 !== undefined && digest !== params.sha256) {
      throw new VmOpError('VM_UNKNOWN_STATE', 'guest file digest mismatch', { retryable: true });
    }
    return { dataBase64: b64(data), sha256: digest, bytes: data.length };
  }

  async function opFileStat(req: Extract<VmSupervisorWorkspaceRequest, { op: 'file.stat' }>): Promise<unknown> {
    const ws = requireWorkspace(req);
    requireRunning(ws);
    await verifiedInstance(ws);
    assertGuestPathAllowed(req.params.guestPath);
    const out = await sessions.openAndCapture({
      opId: `stat:${req.requestId}`,
      workspaceId: req.workspaceId,
      vmName: ws.vmName,
      argv: ['stat', '-c', '%s|%a|%Y|%F', '--', req.params.guestPath],
      environment: {},
      timeoutMs: FILE_STAT_TIMEOUT_MS,
      maxBytes: 4096,
      envKeys: [],
      envDigest: ''
    });
    if (out.exitCode !== 0) {
      throw new VmOpError('NOT_FOUND', `guest path not found: ${out.stderr.slice(0, 200)}`);
    }
    const [sizeRaw, modeRaw, mtimeRaw, kindRaw] = out.stdout.trim().split('|');
    const size = Number(sizeRaw);
    const mode = Number.parseInt(modeRaw ?? '', 8);
    const mtimeSec = Number(mtimeRaw);
    if (!Number.isFinite(size) || !Number.isFinite(mode) || !Number.isFinite(mtimeSec)) {
      throw new VmOpError('INTERNAL_ERROR', 'unparseable guest stat output');
    }
    return {
      size,
      mode: mode & 0o7777,
      mtime: mtimeSec * 1000,
      isDir: kindRaw === 'directory'
    };
  }

  async function opFileList(req: Extract<VmSupervisorWorkspaceRequest, { op: 'file.list' }>): Promise<unknown> {
    const ws = requireWorkspace(req);
    requireRunning(ws);
    await verifiedInstance(ws);
    const params = req.params;
    assertGuestPathAllowed(params.guestPath);
    const raw = await incus.listInstancePath(ws.vmName, params.guestPath);
    const entries = raw
      .filter((e) => typeof e.name === 'string')
      .map((e) => ({
        name: String(e.name),
        type: (e.type === 'directory' || e.type === 'symlink' ? e.type : e.type === 'file' ? 'file' : 'other') as 'file' | 'directory' | 'symlink' | 'other',
        ...(typeof e.size === 'number' ? { size: e.size } : {}),
        ...(typeof e.mtime === 'number' ? { mtime: e.mtime } : {})
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
    const offset = params.cursor !== undefined && params.cursor.startsWith('o:')
      ? Number.parseInt(params.cursor.slice(2), 10)
      : 0;
    const page = entries.slice(offset, offset + 1000);
    const next = offset + 1000 < entries.length ? `o:${offset + 1000}` : undefined;
    return { entries: page, ...(next !== undefined ? { cursor: next } : {}) };
  }

  async function opPushTree(req: Extract<VmSupervisorWorkspaceRequest, { op: 'pushTree' }>): Promise<WireHandlerOutcome> {
    const ws = requireWorkspace(req);
    requireRunning(ws);
    await verifiedInstance(ws);
    const params = req.params;
    assertGuestPathAllowed(params.guestPath);
    const uploadId = `tree:${req.requestId}`;
    journal.createUpload({
      uploadId,
      workspaceId: req.workspaceId,
      instanceId: ws.row.instanceId,
      generation: req.workspaceGeneration,
      path: params.guestPath,
      maxBytes: transferMaxBytes(config, params.maxBytes),
      expiresAt: lifecycle.nowSec() + 3600
    });
    return {
      kind: 'upload',
      streamRef: uploadId,
      maxBytes: transferMaxBytes(config, params.maxBytes),
      complete: async (payloadPath, payloadBytes, sha256) => {
        if (!journal.consumeUpload(uploadId)) {
          throw new VmOpError('CONFLICT', 'upload already consumed or unknown');
        }
        if (sha256 !== params.sha256) {
          throw new VmOpError('INVALID_INPUT', 'staged tar sha256 mismatch');
        }
        if (payloadBytes > params.maxBytes) {
          throw new VmOpError('LIMIT_EXCEEDED', 'staged tar exceeds maxBytes');
        }
        // Host-side tar safety validation BEFORE guest extraction.
        const { inspectTarSafety } = await import('./tar-safety.js');
        const safety = await inspectTarSafety(payloadPath, params.maxBytes);
        if (!safety.safe) {
          throw new VmOpError('INVALID_INPUT', `unsafe tar archive: ${safety.reason}`);
        }
        const fileStat = await stat(payloadPath);
        const out = await sessions.extractTarStream({
          workspaceId: req.workspaceId,
          vmName: ws.vmName,
          guestPath: params.guestPath,
          tar: createReadStream(payloadPath),
          tarBytes: fileStat.size,
          entryPaths: safety.paths,
          timeoutMs: 30 * 60 * 1000
        });
        if (out.exitCode !== 0) {
          throw new VmOpError('EXECUTION_FAILED', `guest tar extract failed: ${out.stderr.slice(0, 300)}`);
        }
        return { sha256, bytes: payloadBytes, entryCount: safety.entryCount };
      }
    };
  }

  async function opPullTree(req: Extract<VmSupervisorWorkspaceRequest, { op: 'pullTree' }>): Promise<WireHandlerOutcome> {
    const ws = requireWorkspace(req);
    requireRunning(ws);
    await verifiedInstance(ws);
    const params = req.params;
    assertGuestPathAllowed(params.guestPath);
    const maxBytes = transferMaxBytes(config, params.maxBytes);
    return {
      kind: 'download',
      streamRef: `tree:${ws.vmName}`,
      maxBytes,
      produce: async (emit) => {
        const trailer = await sessions.streamGuestTar({
          workspaceId: req.workspaceId,
          vmName: ws.vmName,
          guestPath: params.guestPath,
          maxBytes,
          emit
        });
        if (params.sha256 !== undefined && trailer.sha256 !== params.sha256) {
          throw new VmOpError('VM_UNKNOWN_STATE', 'pullTree digest mismatch', { retryable: true });
        }
        return trailer;
      }
    };
  }

  // ---- network ops -------------------------------------------------------------

  /** Guard transport/kernel failures are fail-closed typed errors, never raw throws. */
  function guardFailure(op: string, error: unknown): never {
    if (error instanceof VmNetworkGuardError) {
      throw new VmOpError('VM_ATTESTATION_FAILED', `network guard ${op} failed: ${error.message}`);
    }
    throw error;
  }

  async function opNetworkProgram(req: Extract<VmSupervisorWorkspaceRequest, { op: 'network.program' }>): Promise<unknown> {
    const ws = requireWorkspace(req);
    const profile = journaledNetworkProfile(ws.row);
    if (req.params.networkProfile !== profile) {
      throw new VmOpError('INVALID_INPUT', 'networkProfile does not match the admitted workspace profile');
    }
    return lifecycle.withLifecycleLock(async () => {
      // Verify state before mutation: program must never reconfigure bridge/
      // nft/permits under a live instance. Only a verified-stopped (or absent)
      // instance may be programmed; anything else fails closed.
      const instance = await incus.getInstance(ws.vmName);
      if (instance !== null) {
        const verdict = lifecycle.verifyInstanceIdentity(instance, ws.row);
        if (!verdict.ok) {
          throw new VmOpError('VM_IDENTITY_MISMATCH', `instance identity verification failed: ${verdict.reason}`);
        }
        if (lifecycle.normalizeState(instance.status) !== 'stopped') {
          throw new VmOpError('CONFLICT', `network.program refused while instance state is ${instance.status}`);
        }
      }
      const guard = await deps.guard();
      try {
        return await guard.program({ identity: identityForGuard(ws), networkProfile: profile });
      } catch (error) {
        guardFailure('program', error);
      }
    });
  }

  async function opNetworkAttest(req: VmSupervisorWorkspaceRequest & { op: 'network.attest' }): Promise<unknown> {
    const ws = requireWorkspace(req);
    const profile = journaledNetworkProfile(ws.row);
    // Serialized with program/tearDown/start so attest never reads kernel
    // state mid-mutation.
    return lifecycle.withLifecycleLock(async () => {
      const guard = await deps.guard();
      try {
        return await guard.attest({ identity: identityForGuard(ws), networkProfile: profile });
      } catch (error) {
        guardFailure('attest', error);
      }
    });
  }

  async function opNetworkTearDown(req: VmSupervisorWorkspaceRequest & { op: 'network.tearDown' }): Promise<unknown> {
    const ws = requireWorkspace(req);
    return lifecycle.withLifecycleLock(async () => {
      const guard = await deps.guard();
      try {
        return await guard.tearDown({ identity: identityForGuard(ws) });
      } catch (error) {
        guardFailure('tearDown', error);
      }
    });
  }

  // ---- lease ops ---------------------------------------------------------------

  function opLeaseSet(req: Extract<VmSupervisorWorkspaceRequest, { op: 'lease.set' }>): unknown {
    const ws = requireWorkspace(req);
    const now = lifecycle.nowSec();
    const ttlCap = now + config.maxTtlSeconds;
    // Renewal semantics (frozen): expiresAt slides forward within the TTL cap;
    // hardExpiresAt is NEVER extended by a renewal — the effective value is the
    // minimum of the stored deadline and the clamped request value.
    const existing = journal.getLease(req.workspaceId);
    const hasLiveLease = existing !== undefined && existing.state !== 'cleared';
    const requestedHard = Math.min(req.params.hardExpiresAt, ttlCap);
    const hardExpiresAt = hasLiveLease
      ? Math.min(existing.hardExpiresAt, requestedHard)
      : requestedHard;
    const expiresAt = Math.min(req.params.expiresAt, hardExpiresAt, ttlCap);
    journal.setLease({
      workspaceId: req.workspaceId,
      instanceId: ws.row.instanceId,
      generation: req.workspaceGeneration,
      expiresAt,
      hardExpiresAt,
      lastRenewalAt: now,
      state: 'active'
    });
    journal.appendEvent('lease.set', req.workspaceId, { expiresAt, hardExpiresAt });
    return { effective: { expiresAt, hardExpiresAt } };
  }

  /** lease.clear: identity+generation fencing WITHOUT the deadline cutoff. */
  function opLeaseClear(req: VmSupervisorWorkspaceRequest & { op: 'lease.clear' }): unknown {
    const row = journal.getWorkspace(req.workspaceId);
    if (row === undefined) throw new VmOpError('NOT_FOUND', 'unknown workspace');
    if (row.state === 'deleted') throw new VmOpError('CONFLICT', 'workspace is deleted');
    if (row.instanceId !== req.vmInstanceId) {
      throw new VmOpError('VM_IDENTITY_MISMATCH', 'vmInstanceId does not match journal identity');
    }
    if (journal.acceptGeneration(req.workspaceId, req.workspaceGeneration) === 'stale') {
      throw new VmOpError('VM_GENERATION_MISMATCH', 'workspaceGeneration is stale');
    }
    journal.clearLease(req.workspaceId);
    journal.appendEvent('lease.clear', req.workspaceId, {});
    return { cleared: true as const };
  }

  // ---- host ops -----------------------------------------------------------------

  async function opVmList(req: VmSupervisorHostRequest & { op: 'vm.list' }): Promise<unknown> {
    const rows = journal.listWorkspaces().slice(0, VM_LIST_PAGE);
    const out = [];
    for (const row of rows) {
      if (req.params.workspaceId !== undefined && row.workspaceId !== req.params.workspaceId) continue;
      let state: string = row.state === 'admitted' ? 'stopped' : row.state === 'deleted' ? 'unknown' : row.state;
      let identity = readIdentityFromConfig({});
      try {
        const inst = await incus.getInstance(row.vmName);
        if (inst !== null) {
          state = lifecycle.normalizeState(inst.status);
          identity = readIdentityFromConfig(inst.expandedConfig);
        } else if (row.state !== 'deleted') {
          state = 'unknown';
        }
      } catch {
        // keep journal-mapped state on probe failure
      }
      out.push({
        vmName: row.vmName,
        workspaceId: row.workspaceId,
        instanceId: row.instanceId,
        state,
        ...(identity !== undefined ? { userCloudHarness: identity } : {})
      });
    }
    return out;
  }

  function opLeaseList(): unknown {
    return journal.listLeases().slice(0, VM_LIST_PAGE).map((l) => ({
      workspaceId: l.workspaceId,
      instanceId: l.instanceId,
      generation: l.generation,
      expiresAt: l.expiresAt,
      hardExpiresAt: l.hardExpiresAt,
      state: l.state
    }));
  }

  async function opPoolInfo(): Promise<unknown> {
    const fs = await statfs(config.poolPath);
    const free = Number(fs.bavail) * Number(fs.bsize);
    const total = Number(fs.blocks) * Number(fs.bsize);
    const journaled = new Map(journal.listWorkspaces().map((w) => [w.vmName, w]));
    const volumes = (await poolVolumeInfos(config.poolPath, (vmName) =>
      journaled.has(vmName) ? config.diskBytes : 0
    )).filter((v) => v.configuredBytes > 0);
    const cache = await imageCacheBytes(config.poolPath);
    return {
      poolPath: config.poolPath,
      statfsFree: free,
      statfsTotal: total,
      volumes: volumes.map((v) => ({
        vmName: v.vmName as never,
        configuredBytes: v.configuredBytes,
        allocatedBytesStBlocks: v.allocatedBytesStBlocks
      })),
      imageCacheBytes: cache,
      managedRunningCount: journal.countRunningManaged()
    };
  }

  function opReconcile(): Promise<unknown> {
    return lifecycle.reconcile();
  }

  async function opGuardState(): Promise<unknown> {
    try {
      const { readFile } = await import('node:fs/promises');
      const raw = JSON.parse(await readFile(config.guardStatePath, 'utf8')) as Record<string, unknown>;
      const verdict = raw.verdict === 'attested' || raw.verdict === 'failed' || raw.verdict === 'unknown'
        ? raw.verdict
        : 'unknown';
      const rulesetHash = typeof raw.rulesetHash === 'string' && /^[0-9a-f]{64}$/.test(raw.rulesetHash)
        ? raw.rulesetHash
        : '0'.repeat(64);
      const attestedAt = typeof raw.attestedAt === 'number' && Number.isFinite(raw.attestedAt)
        ? Math.max(0, Math.floor(raw.attestedAt))
        : 0;
      const vms = Array.isArray(raw.vms)
        ? raw.vms.slice(0, VM_LIST_PAGE).flatMap((v) => {
            if (typeof v !== 'object' || v === null) return [];
            const o = v as Record<string, unknown>;
            const vmName = typeof o.vmName === 'string' ? o.vmName : undefined;
            const vv = o.verdict === 'attested' || o.verdict === 'failed' || o.verdict === 'unknown' ? o.verdict : undefined;
            return vmName !== undefined && vv !== undefined ? [{ vmName: vmName as never, verdict: vv }] : [];
          })
        : [];
      return { verdict, rulesetHash, attestedAt, vms };
    } catch {
      return { verdict: 'unknown' as const, rulesetHash: '0'.repeat(64), attestedAt: 0, vms: [] };
    }
  }

  // ---- result validation ---------------------------------------------------------

  function validateResult(op: string, result: unknown): unknown {
    const schema = (VmSupervisorOpResultSchemas as Record<string, { parse(v: unknown): unknown }>)[op];
    if (schema === undefined) {
      throw new VmOpError('INTERNAL_ERROR', `no result schema for op ${op}`);
    }
    try {
      return schema.parse(result);
    } catch (error) {
      log('result schema validation failed', { op, error: error instanceof Error ? error.message : String(error) });
      throw new VmOpError('INTERNAL_ERROR', 'op result failed contract validation');
    }
  }

  function isWireOutcome(outcome: unknown): outcome is WireHandlerOutcome {
    return typeof outcome === 'object' && outcome !== null && 'kind' in (outcome as Record<string, unknown>);
  }

  /**
   * Normalize a handler return into a transport outcome with contract-
   * validated results. For 'result'/'session' kinds the embedded result is
   * validated now; for 'upload'/'download' the eventual result is validated
   * inside the wrapped complete/produce.
   */
  function normalizeOutcome(op: VmSupervisorWorkspaceRequest['op'] | VmSupervisorHostRequest['op'], outcome: unknown): WireHandlerOutcome {
    if (isWireOutcome(outcome)) {
      switch (outcome.kind) {
        case 'result':
          return { kind: 'result', result: validateResult(op, outcome.result) };
        case 'session':
          return { ...outcome, result: validateResult(op, outcome.result) };
        case 'upload':
          return {
            ...outcome,
            complete: async (p, b, s) => validateResult(op, await outcome.complete(p, b, s))
          };
        case 'download':
          return {
            ...outcome,
            produce: async (emit) => validateResult(op, await outcome.produce(emit))
          };
      }
    }
    return { kind: 'result', result: validateResult(op, outcome) };
  }

  // ---- dispatch ------------------------------------------------------------------

  const workspaceHandlers: Record<VmSupervisorWorkspaceRequest['op'], OpHandler> = {
    'vm.admit': () => opAdmit(),
    'vm.create': (req) => opCreate(req as never),
    'vm.start': (req) => opStart(req as never),
    'vm.stop': (req) => opStop(req as never),
    'vm.delete': (req) => opDelete(req as never),
    'vm.status': (req) => opStatus(req as never),
    'vm.export': (req) => opExport(req as never),
    'exec.run': (req) => opExecRun(req as never),
    'exec.inspect': (req) => opExecInspect(req as never),
    'exec.open': (req, ctx) => opExecOpen(req as never, ctx),
    'exec.write': (req) => opExecWrite(req as never),
    'exec.close': (req) => opExecClose(req as never),
    'exec.resize': (req) => opExecResize(req as never),
    'exec.killSession': (req) => opExecKillSession(req as never),
    'file.push': (req) => opFilePush(req as never),
    'file.pull': (req) => opFilePull(req as never),
    'file.stat': (req) => opFileStat(req as never),
    'file.list': (req) => opFileList(req as never),
    'pushTree': (req) => opPushTree(req as never),
    'pullTree': (req) => opPullTree(req as never),
    'network.program': (req) => opNetworkProgram(req as never),
    'network.attest': (req) => opNetworkAttest(req as never),
    'network.tearDown': (req) => opNetworkTearDown(req as never),
    'lease.set': (req) => opLeaseSet(req as never),
    'lease.clear': (req) => opLeaseClear(req as never)
  };

  const hostHandlers: Record<VmSupervisorHostRequest['op'], (req: never) => unknown> = {
    'vm.list': (req) => opVmList(req as never),
    'lease.list': () => opLeaseList(),
    'pool.info': () => opPoolInfo(),
    'reconcile': () => opReconcile(),
    'guard.state': () => opGuardState()
  };

  return async (raw: unknown, ctx: WireRequestContext): Promise<WireHandlerOutcome> => {
    const wsParsed = VmSupervisorWorkspaceRequestSchema.safeParse(raw);
    if (wsParsed.success) {
      return dispatchWorkspace(wsParsed.data, ctx);
    }
    const hostParsed = VmSupervisorHostRequestSchema.safeParse(raw);
    if (hostParsed.success) {
      const req = hostParsed.data;
      const outcome = await hostHandlers[req.op](req as never);
      return normalizeOutcome(req.op, outcome);
    }
    throw new VmOpError('INVALID_INPUT', 'request does not match the supervisor contract');
  };

  async function dispatchWorkspace(req: VmSupervisorWorkspaceRequest, ctx: WireRequestContext): Promise<WireHandlerOutcome> {
    if (!IDEMPOTENT_OPS.has(req.op)) {
      const outcome = await workspaceHandlers[req.op](req as never, ctx);
      return normalizeOutcome(req.op, outcome);
    }
    // Fence BEFORE recording: identity/generation/deadline failures must not
    // poison the idempotency journal. vm.create may precede any journal row;
    // lease.clear fences inside its own handler without the deadline cutoff.
    if (req.op !== 'vm.create' && req.op !== 'lease.clear') {
      requireWorkspace(req);
    }
    const digest = digester.digest({ op: req.op, params: req.params });
    const begin = journal.beginIdempotent({
      workspaceId: req.workspaceId,
      op: req.op,
      key: req.idempotencyKey,
      digest
    });
    if (begin.kind === 'replay') {
      return { kind: 'result', result: begin.result };
    }
    if (begin.kind === 'conflict') {
      throw new VmOpError('CONFLICT', 'idempotency key reused with different parameters');
    }
    if (begin.kind === 'unknown') {
      throw new VmUnknownMutationError('previous attempt with this idempotency key has unknown outcome');
    }
    const outcome = normalizeOutcome(req.op, await workspaceHandlers[req.op](req as never, ctx));
    // Complete the durable record with the op-level result. For upload
    // outcomes the REAL result arrives later inside complete() — wrap it so
    // the record completes only after the mutation verifiably applied.
    if (outcome.kind === 'upload') {
      const inner = outcome.complete;
      return {
        ...outcome,
        complete: async (p, b, s) => {
          const result = await inner(p, b, s);
          journal.completeIdempotent(begin.recordId, result);
          return result;
        }
      };
    }
    if (outcome.kind === 'result' || outcome.kind === 'session') {
      const result = outcome.kind === 'result' ? outcome.result : outcome.result;
      journal.completeIdempotent(begin.recordId, result);
    }
    return outcome;
  }
}
