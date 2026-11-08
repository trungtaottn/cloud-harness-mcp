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
import { prepareVmExport, type VmApplianceSpawner } from './export.js';
import { GUEST_NETWORK_BUDGET_MS, provisionGuestNetwork } from './guest-network.js';
import type { VmWorkspaceSubjectPlanner } from './network-plan.js';
import { poolVolumeInfos, imageCacheBytes, spawnApplianceProcess } from './runtime.js';
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
   * Appliance spawner for the offline-export tar stream. Production wires
   * spawnApplianceProcess (runtime.ts); tests inject fakes. When unset the
   * real spawner is used — prepareVmExport owns every bound around it.
   */
  spawnAppliance?: VmApplianceSpawner;
  /**
   * Guest-network provisioning override — tests inject a stub; production
   * always runs the real render→push→apply→verify path in guest-network.ts.
   */
  guestNetworkProvisioner?: (input: { workspaceId: string; vmName: string; deadlineMs: number }) => Promise<void>;
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

/**
 * file.list metadata probe: python3 os.scandir over ONE page (≤1000 names).
 * JSON output tolerates every legal filename; argv-passed (no shell quoting).
 * 2 MiB covers 1000 × 255-byte names plus stat fields with wide margin.
 */
const FILE_LIST_STAT_TIMEOUT_MS = 20_000;
const FILE_LIST_STAT_MAX_BYTES = 2 * 1024 * 1024;

/**
 * exec.run result transport: results whose serialized JSON fits under this
 * threshold stay on the unary response path (byte-identical to before);
 * larger results stream as u64be(stdoutLen)+stdout+stderr download bytes
 * followed by an ExecRunResult trailer with emptied streams. 512 KiB keeps
 * the unary envelope far under the ~1 MiB control-frame bound.
 */
const EXEC_RUN_INLINE_RESULT_MAX = 512 * 1024;
/** emit() maps to ONE wire frame; keep chunks well under the frame bound. */
const EXEC_RUN_STREAM_CHUNK = 4 * 1024 * 1024;
/** Worst-case stream payload: 16 MiB stdout + 16 MiB stderr + 8-byte prefix. */
const EXEC_RUN_STREAM_MAX_BYTES = 2 * 16_777_216 + 8;

interface ExecRunFullResult {
  opId: string;
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  timedOut: boolean;
}

/**
 * Largest UTF-8 prefix of `buf` within `maxBytes` that never splits a
 * multi-byte sequence — the truncated text re-encodes to <= maxBytes and
 * stays valid UTF-8 (no corrupt trailing code point).
 */
function utf8Prefix(buf: Buffer, maxBytes: number): Buffer {
  if (buf.length <= maxBytes) return buf;
  let end = maxBytes;
  // Walk back over trailing continuation bytes to the sequence's lead byte.
  let i = end - 1;
  let cont = 0;
  while (i >= 0 && cont < 3 && ((buf[i] as number) & 0xc0) === 0x80) { i -= 1; cont += 1; }
  if (i >= 0) {
    const lead = buf[i] as number;
    const seqlen = lead < 0x80 ? 1 : lead < 0xe0 ? 2 : lead < 0xf0 ? 3 : 4;
    if (seqlen > 1 && i + seqlen > end) end = i;
  }
  return buf.subarray(0, end);
}

/**
 * Bound an exec.run result to what the framed transport can actually
 * deliver. Each stream is captured guest-side at <= `maxBytes` RAW bytes,
 * but the lossy UTF-8 decode expands every invalid byte to a 3-byte
 * U+FFFD, so an encoded stream legitimately reaches 3*maxBytes. The runner
 * bounds the payload at min(8 + 6*maxBytes, EXEC_RUN_STREAM_MAX_BYTES);
 * capping each stream at min(3*maxBytes, 16 MiB) keeps the total inside
 * BOTH bounds for every request maxBytes. Truncation is a pure function
 * of the result strings, so the original op, idempotent replay, and
 * exec.inspect all derive the identical delivered payload.
 */
function boundExecRunResult(full: ExecRunFullResult, maxBytes: number): ExecRunFullResult {
  const perStreamCap = Math.min(3 * maxBytes, 16 * 1024 * 1024);
  const trim = (s: string): { text: string; cut: boolean } => {
    const buf = Buffer.from(s, 'utf8');
    if (buf.length <= perStreamCap) return { text: s, cut: false };
    return { text: utf8Prefix(buf, perStreamCap).toString('utf8'), cut: true };
  };
  const out = trim(full.stdout);
  const err = trim(full.stderr);
  if (!out.cut && !err.cut) return full;
  return { ...full, stdout: out.text, stderr: err.text, truncated: true };
}

/**
 * Framed download encoding for large exec.run results, shared by the
 * original op AND idempotent replays (a replayed >512KiB result must not
 * regress to an oversized unary frame). Wire layout the runner decodes:
 *   stream-start {streamRef:'exec:<opId>', maxBytes:<exact payload bytes>}
 *   WIRE_KIND_BYTES frames: u64be(stdoutUtf8Len) || stdoutUtf8 || stderrUtf8
 *   stream-digest {streamRef, sha256(payload), bytes}
 *   response {ExecRunResult with stdout/stderr emptied}
 * The result MUST already be normalized by boundExecRunResult — journal
 * completion happens eagerly in opExecRun because the mutation verifiably
 * completed; delivery failure surfaces as transport error/unknown, never
 * a clean retryable result.
 */
function execRunDownloadOutcome(
  fullResult: ExecRunFullResult,
  opId: string
): WireHandlerOutcome {
  const stdoutBuf = Buffer.from(fullResult.stdout, 'utf8');
  const stderrBuf = Buffer.from(fullResult.stderr, 'utf8');
  const prefix = Buffer.allocUnsafe(8);
  prefix.writeBigUInt64BE(BigInt(stdoutBuf.length));
  const payload = Buffer.concat([prefix, stdoutBuf, stderrBuf]);
  if (payload.length > EXEC_RUN_STREAM_MAX_BYTES) {
    // Fail closed rather than emit an unbounded declared length — bounded
    // inputs make this unreachable, so a violation is a programming bug.
    throw new VmOpError('LIMIT_EXCEEDED', 'exec.run result exceeds stream bound');
  }
  return {
    kind: 'download',
    streamRef: `exec:${opId}`,
    maxBytes: payload.length,
    streamDigest: { sha256: createHash('sha256').update(payload).digest('hex'), bytes: payload.length },
    produce: async (emit) => {
      for (let off = 0; off < payload.length; off += EXEC_RUN_STREAM_CHUNK) {
        await emit(payload.subarray(off, Math.min(off + EXEC_RUN_STREAM_CHUNK, payload.length)));
      }
      return { ...fullResult, stdout: '', stderr: '' };
    }
  };
}

/**
 * Rebuild a framed download outcome from a JOURNALED exec.run result
 * (idempotent replay). Returns undefined for inline-sized results so the
 * caller falls through to the ordinary {kind:'result'} replay. The journaled
 * record is already complete — no further idempotency write happens here.
 */
function execRunReplayOutcome(journaled: unknown): WireHandlerOutcome | undefined {
  if (journaled === null || typeof journaled !== 'object') return undefined;
  const r = journaled as Record<string, unknown>;
  if (typeof r.opId !== 'string' || typeof r.stdout !== 'string' || typeof r.stderr !== 'string' ||
      typeof r.truncated !== 'boolean' || typeof r.timedOut !== 'boolean') {
    return undefined;
  }
  const full: ExecRunFullResult = {
    opId: r.opId,
    exitCode: typeof r.exitCode === 'number' ? r.exitCode : null,
    signal: typeof r.signal === 'string' ? r.signal : null,
    stdout: r.stdout,
    stderr: r.stderr,
    truncated: r.truncated,
    timedOut: r.timedOut
  };
  if (Buffer.byteLength(JSON.stringify(full), 'utf8') <= EXEC_RUN_INLINE_RESULT_MAX) {
    return undefined;
  }
  return execRunDownloadOutcome(full, full.opId);
}
// Stats ONLY the names handed to it on stdin (a JSON array) — never a
// whole-directory scandir, whose output overflows the capture bound on
// large directories. lstat semantics match the old DirEntry probe:
// symlinks are reported, never followed.
const FILE_LIST_STAT_PY =
  'import os,sys,json,stat as st;d=sys.argv[1]\n' +
  'try: names=json.load(sys.stdin)\n' +
  'except Exception: sys.exit(1)\n' +
  'out=[]\n' +
  'for n in names:\n' +
  " if not isinstance(n,str) or '/' in n or chr(0) in n:\n" +
  "  out.append({'name':n if isinstance(n,str) else '','type':'other'})\n" +
  '  continue\n' +
  ' try:\n' +
  '  s=os.lstat(os.path.join(d,n))\n' +
  "  t='symlink' if st.S_ISLNK(s.st_mode) else ('directory' if st.S_ISDIR(s.st_mode) else 'file')\n" +
  "  out.append({'name':n,'type':t,'size':s.st_size,'mtime':int(s.st_mtime*1000)})\n" +
  ' except OSError:\n' +
  "  out.append({'name':n,'type':'other'})\n" +
  'json.dump(out,sys.stdout,separators=(",",":"))\n';

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

/**
 * Ops allowed past the lease cutoff — BOTH the soft-deadline fence (active
 * lease whose expiresAt/hardExpiresAt has passed but the watchdog has not yet
 * marked 'expired') and the expired-state fence. The set is deliberately
 * narrow: pure lifecycle, cleanup, read-only inspection, lease management,
 * and offline stopped-disk export. Everything that can execute guest code,
 * move live file data, mutate network guard state toward enforcement, or
 * start the VM stays fenced until a fresh lease.set. vm.export re-verifies
 * the live instance is STOPPED inside its handler, so exemption here can
 * never export a running VM.
 */
const CUTOFF_EXEMPT_OPS: ReadonlySet<string> = new Set([
  'vm.create', 'vm.stop', 'vm.delete', 'vm.status',
  'exec.inspect', 'network.attest', 'network.tearDown',
  'lease.set', 'lease.clear',
  'vm.export'
]);

type OpHandler = (req: never, ctx: WireRequestContext, meta?: { idempotentRecordId?: number }) => unknown;

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
    // Lease op cutoff: a request is refused when its EFFECTIVE issue time —
    // the later of the claimed issuedAt and actual arrival — reaches the
    // deadline. A backdated issuedAt cannot smuggle a request past expiry.
    // The same narrow exemption set applies as for the expired-state fence
    // below, so lifecycle/cleanup/inspection ops stay reachable in the
    // pre-watchdog gap while every live op is still fenced.
    const deadlineSec = lifecycle.leaseDeadlineFor(req.workspaceId);
    if (deadlineSec !== undefined && !CUTOFF_EXEMPT_OPS.has(req.op) &&
        Math.max(req.issuedAt, lifecycle.nowMs()) >= deadlineSec * 1000) {
      throw new VmOpError('EXPIRED', 'workspace lease deadline reached');
    }
    // An expired lease fences execution/data-plane ops even while the
    // journaled VM row still reads 'running' (watchdog stop may be in
    // flight). Lifecycle/cleanup/inspection/export ops stay reachable so the
    // workspace can still be stopped, deleted, inspected, exported offline
    // or re-leased.
    const leaseRow = journal.getLease(req.workspaceId);
    if (leaseRow !== undefined && leaseRow.state === 'expired' && !CUTOFF_EXEMPT_OPS.has(req.op)) {
      throw new VmOpError('EXPIRED', 'workspace lease has expired');
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
      // `volatile.*` is Incus-owned RUNTIME state (uuid, last_state.*,
      // apply_template, base_image, idmap.*, per-device hwaddr/host_name) —
      // native Incus writes it unconditionally on every instance, so
      // rejecting it fails every real attestation. It is tolerated as a
      // namespace ONLY: identity is already proven by verifiedInstance
      // (user.cloud-harness.* markers), volatile.* cannot express
      // limits/devices/profiles, and every managed key above is still
      // checked exactly. `raw.*` (arbitrary LXD config injection) and all
      // unexpected keys remain rejected.
      if (key.startsWith('raw.')) {
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
        // Report the VERIFIED live state — never claim 'stopped' for a
        // running (or otherwise non-startable) instance. The journaled name
        // may have been replaced by a foreign instance while we were down:
        // identity must be proven, not assumed from the journal row.
        const live = await incus.getInstance(existing.vmName);
        if (live === null) {
          throw new VmOpError('CONFLICT', 'journaled instance is absent from Incus');
        }
        const verdict = lifecycle.verifyInstanceIdentity(live, existing);
        if (!verdict.ok) {
          throw new VmOpError('VM_IDENTITY_MISMATCH', `journaled instance fails identity verification: ${verdict.reason}`);
        }
        const observed = lifecycle.normalizeState(live.status);
        if (observed === 'running' || observed === 'stopped') {
          journal.setWorkspaceState(req.workspaceId, observed);
        }
        if (observed !== 'stopped') {
          throw new VmOpError('CONFLICT', `workspace instance is ${live.status}; vm.create reports stopped only`);
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
        if (observed !== 'stopped') {
          throw new VmOpError('CONFLICT', `adopted instance is ${preExisting.status}; vm.create reports stopped only`);
        }
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
    /**
     * Guest network provisioning with fail-closed teardown. On ANY failure
     * the verified instance is stopped; if the stop itself cannot be
     * verified, the live instance is re-read (identity + state) and the
     * outcome reported as UNKNOWN — never as a clean provision failure
     * while a possibly-running unprovisioned VM is left behind.
     */
    const provisionFailClosed = async (): Promise<void> => {
      const leaseDeadlineSec = lifecycle.leaseDeadlineFor(ws.row.workspaceId);
      const provisionDeadlineMs = Math.min(
        lifecycle.nowMs() + GUEST_NETWORK_BUDGET_MS,
        leaseDeadlineSec === undefined ? Number.POSITIVE_INFINITY : leaseDeadlineSec * 1000
      );
      const provision = deps.guestNetworkProvisioner ?? ((input: { workspaceId: string; vmName: string; deadlineMs: number }) =>
        provisionGuestNetwork(
          {
            incus,
            sessions,
            networkPlan: deps.networkPlan,
            dnsResolvers: config.dnsResolvers,
            lifecycle
          },
          input
        ));
      try {
        await provision({ workspaceId: ws.row.workspaceId, vmName: ws.vmName, deadlineMs: provisionDeadlineMs });
      } catch (error) {
        const stop = await lifecycle
          .stopVerified(ws.vmName, ws.row.workspaceId, 'guest-network-setup')
          .catch(() => ({ outcome: 'unknown' as const }));
        if (stop.outcome !== 'stopped') {
          // Provisioning failed AND stop is unverified: re-read identity and
          // state before reporting. A still-live (or unverifiable) instance
          // means the outcome is UNKNOWN, not a clean retryable failure.
          let stillLive = true;
          try {
            const live = await verifiedInstance(ws);
            stillLive = lifecycle.normalizeState(live.status) !== 'stopped';
          } catch {
            stillLive = true;
          }
          if (stillLive) {
            throw new VmUnknownMutationError(
              'guest network provisioning failed and instance stop could not be verified'
            );
          }
        }
        if (error instanceof VmOpError) throw error;
        throw new VmOpError(
          'VM_SUPERVISOR_UNAVAILABLE',
          `guest network provisioning failed: ${error instanceof Error ? error.message : 'unknown'}`,
          { retryable: true }
        );
      }
    };
    return lifecycle.withLifecycleLock(async () => {
      const instance = await verifiedInstance(ws);
      const observed = lifecycle.normalizeState(instance.status);
      if (observed === 'running') {
        // A live 'running' instance may predate a failed provision+stop —
        // for dependency-access, re-verify (and repair) guest network
        // readiness before admitting 'running' again. network-none has no
        // guest network to verify.
        if (journaledProfile === 'dependency-access') {
          await provisionFailClosed();
        }
        journal.setWorkspaceState(ws.row.workspaceId, 'running');
        return { state: 'running' as const };
      }
      if (observed !== 'stopped') {
        throw new VmOpError('CONFLICT', `instance state ${instance.status} cannot start`);
      }
      assertSupervisorShape(instance);
      const admission = await lifecycle.checkAdmission({ forStart: true, workspaceId: req.workspaceId });
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
      // Guest network provisioning (dependency-access only): the template
      // ships no .network files, so the per-VM systemd-networkd unit is
      // rendered from the canonical subject, pushed via the native agent,
      // applied, and verified against the exact planned /30 address+route —
      // all BEFORE the workspace is marked running/admitted. Any failure
      // stops the verified instance (fail closed); network-none skips this
      // entirely since no eth0 is stamped for it.
      if (journaledProfile === 'dependency-access') {
        await provisionFailClosed();
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

  async function opExport(req: Extract<VmSupervisorWorkspaceRequest, { op: 'vm.export' }>, ctx: WireRequestContext): Promise<WireHandlerOutcome> {
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
        { poolPath: config.poolPath, spawnAppliance: deps.spawnAppliance ?? spawnApplianceProcess },
        {
          vmName: ws.vmName,
          guestPath: req.params.guestPath,
          maxBytes,
          signal: ctx.signal,
          ...(req.params.sha256 !== undefined ? { expectedSha256: req.params.sha256 } : {})
        }
      );
    } catch (error) {
      releaseReservation?.();
      throw error;
    }
    // Disconnect gap: the transport drops the outcome when the socket dies
    // before completeOutcome runs produce(). Self-clean on close until the
    // produce path claims the staged file; cleanup is idempotent.
    let stageConsumed = false;
    void ctx.closed.then(() => {
      if (stageConsumed) return;
      stageConsumed = true;
      releaseReservation?.();
      void prepared.cleanup();
    });
    return {
      kind: 'download',
      streamRef: `export:${ws.vmName}`,
      maxBytes,
      produce: async (emit) => {
        stageConsumed = true;
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

  async function opExecRun(
    req: Extract<VmSupervisorWorkspaceRequest, { op: 'exec.run' }>,
    _ctx?: WireRequestContext,
    meta?: { idempotentRecordId?: number }
  ): Promise<unknown> {
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
    const rawResult: ExecRunFullResult = {
      opId: outcome.opId,
      exitCode: outcome.exitCode,
      signal: outcome.signal,
      stdout: outcome.stdout.slice(0, 16_777_216),
      stderr: outcome.stderr.slice(0, 16_777_216),
      truncated: outcome.truncated,
      timedOut: outcome.timedOut
    };
    // Bound the DELIVERABLE form once, up front: the journaled record, the
    // inline result, and every replay all carry this normalized result, so
    // a replayed download is byte-identical to the original.
    const fullResult = boundExecRunResult(rawResult, params.maxBytes);
    // Small results stay on the unary path byte-identical to before. Large
    // results cannot fit the ~1 MiB control-frame bound, so they move to the
    // framed download path agreed with the runner (see execRunDownloadOutcome).
    // The mutation has ALREADY completed by this point — a mid-stream failure
    // surfaces as transport error/unknown, never a clean retryable result.
    if (Buffer.byteLength(JSON.stringify(fullResult), 'utf8') <= EXEC_RUN_INLINE_RESULT_MAX) {
      return fullResult;
    }
    // Complete the durable idempotency record EAGERLY: the guest command
    // verifiably exited and its (bounded) result is known, so a client that
    // disconnects before stream-start/produce still replays the true
    // outcome instead of wedging the record in pending→UNKNOWN forever.
    if (meta?.idempotentRecordId !== undefined) {
      journal.completeIdempotent(meta.idempotentRecordId, fullResult);
    }
    return execRunDownloadOutcome(fullResult, params.opId);
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

  /**
   * Complete workspace identity for session-control binding: the resolved
   * workspace row's instanceId plus the request's fenced generation — the
   * same values stamped into the session journal row at exec.open.
   */
  function sessionOwner(
    req: VmSupervisorWorkspaceRequest,
    ws: ResolvedWorkspace
  ): { workspaceId: string; vmName: string; instanceId: string; generation: number } {
    return {
      workspaceId: req.workspaceId,
      vmName: ws.vmName,
      instanceId: ws.row.instanceId,
      generation: req.workspaceGeneration
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
    return sessions.writeStdin(req.params.sessionId, req.params.fd, req.params.dataBase64, req.params.eof, sessionOwner(req, ws));
  }

  async function opExecClose(req: Extract<VmSupervisorWorkspaceRequest, { op: 'exec.close' }>): Promise<unknown> {
    const ws = requireWorkspace(req);
    requireRunning(ws);
    return sessions.closeSession(req.params.sessionId, req.params.fd, sessionOwner(req, ws));
  }

  function opExecResize(req: Extract<VmSupervisorWorkspaceRequest, { op: 'exec.resize' }>): unknown {
    const ws = requireWorkspace(req);
    requireRunning(ws);
    return sessions.resizeSession(req.params.sessionId, req.params.cols, req.params.rows, sessionOwner(req, ws));
  }

  async function opExecKillSession(req: Extract<VmSupervisorWorkspaceRequest, { op: 'exec.killSession' }>): Promise<unknown> {
    const ws = requireWorkspace(req);
    requireRunning(ws);
    assertGuestPathAllowed(req.params.pidFile);
    return sessions.killSession(req.params.sessionId, req.params.pidFile, sessionOwner(req, ws));
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
    // Native Incus answers a directory read with a bare JSON array of
    // filename strings — already validated as single components in
    // incus.listInstancePath. Public entries still need type/size/mtime, so
    // the PAGE (≤1000 names) is stat'ed in ONE guest exec via python3
    // os.lstat — names ride stdin as JSON (never shell-quoted, never a
    // whole-directory scandir whose output could exceed the capture bound).
    const names = await incus.listInstancePath(ws.vmName, params.guestPath);
    names.sort((a, b) => a.localeCompare(b));
    const offset = params.cursor !== undefined && params.cursor.startsWith('o:')
      ? Number.parseInt(params.cursor.slice(2), 10)
      : 0;
    const page = names.slice(offset, offset + 1000);
    const next = offset + 1000 < names.length ? `o:${offset + 1000}` : undefined;
    if (page.length === 0) {
      return { entries: [], ...(next !== undefined ? { cursor: next } : {}) };
    }
    const stat = await sessions.openAndCapture({
      opId: `liststat:${req.requestId}`,
      workspaceId: req.workspaceId,
      vmName: ws.vmName,
      argv: ['python3', '-c', FILE_LIST_STAT_PY, params.guestPath],
      environment: {},
      stdinBase64: Buffer.from(JSON.stringify(page), 'utf8').toString('base64'),
      timeoutMs: FILE_LIST_STAT_TIMEOUT_MS,
      maxBytes: FILE_LIST_STAT_MAX_BYTES,
      envKeys: [],
      envDigest: ''
    });
    if (stat.exitCode !== 0) {
      throw new VmOpError(
        'VM_SUPERVISOR_UNAVAILABLE',
        `guest directory metadata probe failed: ${stat.stderr.slice(0, 200)}`,
        { retryable: true }
      );
    }
    let meta: Record<string, { type: 'file' | 'directory' | 'symlink' | 'other'; size?: number; mtime?: number }>;
    try {
      const parsed = JSON.parse(stat.stdout) as unknown;
      if (!Array.isArray(parsed)) throw new Error('not an array');
      meta = {};
      for (const item of parsed) {
        if (typeof item !== 'object' || item === null) continue;
        const o = item as Record<string, unknown>;
        if (typeof o.name !== 'string') continue;
        const t = o.type === 'directory' || o.type === 'symlink' || o.type === 'file' ? o.type : 'other';
        meta[o.name] = {
          type: t,
          ...(typeof o.size === 'number' && Number.isFinite(o.size) ? { size: o.size } : {}),
          ...(typeof o.mtime === 'number' && Number.isFinite(o.mtime) ? { mtime: o.mtime } : {})
        };
      }
    } catch {
      throw new VmOpError('INTERNAL_ERROR', 'unparseable guest directory metadata');
    }
    const entries = page.map((name) => {
      const m = meta[name];
      // A name listed by the files API but absent from the stat probe
      // (deleted mid-listing) degrades to 'other' — never fabricated stats.
      return m !== undefined ? { name, ...m } : { name, type: 'other' as const };
    });
    return { entries, ...(next !== undefined ? { cursor: next } : {}) };
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
      // A renewal that lands already past its effective deadline must not
      // masquerade as a live lease: keep the truthful expired state so the
      // expired-state fence (not just the deadline fence) applies.
      state: expiresAt <= now ? 'expired' : 'active'
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
    // Filter BEFORE paging: a requested workspaceId beyond the first page
    // must still be found.
    const rows = journal.listWorkspaces()
      .filter((row) => req.params.workspaceId === undefined || row.workspaceId === req.params.workspaceId)
      .slice(0, VM_LIST_PAGE);
    const out = [];
    for (const row of rows) {
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
    'vm.export': (req, ctx) => opExport(req as never, ctx),
    'exec.run': (req, ctx, meta) => opExecRun(req as never, ctx, meta),
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
      // exec.open replay (v1, fail-closed): a duplicate idempotency key means
      // the command already ran — the journaled result proves it. Rebinding
      // the session to this connection is NOT safe: the old connection's
      // closed callback can still kill the session, instance/generation and
      // pre-bind output continuity are unproven, and a replay must never
      // extend a lease. Report UNKNOWN with the fence intact — the command
      // is never re-run and the client gets a typed terminal outcome.
      if (req.op === 'exec.open') {
        throw new VmUnknownMutationError(
          'exec.open replay: session reattachment is unsupported; original command outcome is journaled but not re-bindable'
        );
      }
      // exec.run replay: a large journaled result must go back through the
      // SAME framed download path — returning it unary would recreate the
      // >1MiB control-frame failure the stream exists to avoid.
      if (req.op === 'exec.run') {
        const replayDownload = execRunReplayOutcome(begin.result);
        if (replayDownload !== undefined) return replayDownload;
      }
      return { kind: 'result', result: begin.result };
    }
    if (begin.kind === 'conflict') {
      throw new VmOpError('CONFLICT', 'idempotency key reused with different parameters');
    }
    if (begin.kind === 'unknown') {
      throw new VmUnknownMutationError('previous attempt with this idempotency key has unknown outcome');
    }
    const outcome = normalizeOutcome(req.op, await workspaceHandlers[req.op](req as never, ctx, { idempotentRecordId: begin.recordId }));
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
