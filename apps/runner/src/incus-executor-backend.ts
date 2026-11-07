import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { createReadStream, createWriteStream, type WriteStream } from 'node:fs';
import { cp, lstat, mkdir, mkdtemp, readdir, readFile, realpath, readlink, rm, stat, statfs } from 'node:fs/promises';
import { dirname, join, resolve, sep } from 'node:path';
import { Readable, Writable } from 'node:stream';
import { spawn } from 'node:child_process';
import { EventEmitter } from 'node:events';
import {
  HarnessError,
  validateSecretNameShape,
  type RunnerConfig
} from '@cloud-harness/contracts';
import type { PtyConnection, PtyEnd, PtyOpenRequest, PtyTransport } from './docker-pty.js';
import { TERMINAL_PID_DIR, terminalCommand } from './docker-pty.js';
import type {
  BackendCapabilityMap,
  ExecRequest,
  ExecResult,
  ExecutorBackend,
  ExecutorInspection,
  ExecutorRef,
  ProvisionContext,
  StreamHandle,
  StreamRequest
} from './executor-backend.js';
import { INCUS_VM_BACKEND_CAPABILITIES } from './vm-capabilities.js';
import {
  VmSupervisorCallError,
  type VmExecSession,
  type VmSupervisorClient,
  type VmWorkspaceIdentity
} from './vm-supervisor-client.js';
import type { WorkspaceRecord } from './state-store.js';

/**
 * The incus-vm executor backend: every verb delegates to `vm-supervisor`
 * through the typed wire client — the runner never touches Incus, host
 * mounts, or guest filesystems directly. Identity (`backend_instance_id`,
 * `template_id`, `template_digest`) is persisted at admit; every workspace
 * RPC carries `(workspaceId, generation, instanceId)` plus a per-call
 * idempotency key, and mutation ops that lose their reply surface as
 * VM_UNKNOWN_STATE — never retried blindly.
 *
 * Provision ordering is frozen: `vm.create` (stopped) → `lease.set`
 * (durable, BEFORE start) → `vm.start` (the only gate: supervisor-internal
 * admission + attest + network + agent-ready) → asset pushes → ref.
 * `ensureActive` adopts only on FULL `user.cloud-harness.*` identity match;
 * re-provisioning happens ONLY on a typed supervisor NOT_FOUND (journal has
 * no row — Incus itself still refuses a duplicate name). Every ambiguous
 * status — including the bare `{state:'unknown'}` opStatus returns for an
 * Incus-404 under a live journal row — fails closed and retains, never
 * vm.create, never re-seed.
 */

const WORKSPACE_UID = 10001;
const GUEST_ROOT_USER = 'root';

/** Complete-environment bounds, mirroring the docker adapter's exec env file caps. */
const EXEC_ENV_MAX_ENTRIES = 512;
const EXEC_ENV_MAX_TOTAL_BYTES = 4 * 1_048_576;
const EXEC_ENV_VALUE_MAX_BYTES = 65_536;

/** `exec.run` contract bounds (packages/contracts/src/vm-supervisor-api.ts). */
const EXEC_RUN_MAX_TIMEOUT_MS = 3_600_000;
const EXEC_RUN_MAX_OUTPUT_BYTES = 10_485_760;
/**
 * Wire deadline for `exec.run` = requested guest timeout + bounded cleanup
 * margin. The supervisor's requestDeadlineMs is 4,200,000 ms; worst-case
 * 3,600,000 + 30,000 stays well inside it while a bare 120 s client default
 * would kill long execs mid-flight.
 */
const EXEC_WIRE_DEADLINE_MARGIN_MS = 30_000;
/**
 * `file.pull` inline cap per the frozen wire bounds: 720 KiB keeps the
 * base64 response + JSON envelope under the 1 MiB control-message limit at
 * worst case. `config.vmInlineMaxBytes` can only tighten this, never raise
 * it past the wire bound; larger files route through bounded pullTree.
 */
const FILE_PULL_INLINE_SAFE_MAX_BYTES = 720 * 1_024;
/** Tar framing slack added to maxBytes so the streamed single-file pull is not clipped by headers. */
const FILE_PULL_TAR_SLACK_BYTES = 1_048_576;
/** Wire absolute stream ceiling: 64 GiB content + 8 GiB tar overhead (frozen bounds). */
const PULL_TREE_STREAM_MAX_BYTES = 72 * 1_073_741_824;

const LIFECYCLE_TIMEOUT_MS = 300_000;
const DEFAULT_CALL_TIMEOUT_MS = 120_000;
/** Post-start rollback is best-effort: bounded well under lifecycle so a dead wire cannot stall the error path. */
const ROLLBACK_TIMEOUT_MS = 30_000;
const TAR_TIMEOUT_MS = 30 * 60_000;
/** PTY input: per-slice control bound + total queued-input bound. */
const PTY_WRITE_SLICE_BYTES = 256 * 1_024;
const PTY_MAX_PENDING_INPUT_BYTES = 4 * 1_048_576;

/**
 * Supplementary-group handling is SUPERVISOR-owned: `sessions.ts` wraps every
 * workspace exec/session argv in `runuser -p -u harness --` executed as root,
 * so initgroups applies the `docker` membership while `runuser -p` preserves
 * the injected environment map (nothing secret ever enters argv). The runner
 * therefore sends the caller argv verbatim with `user: 'workspace'` — a
 * second wrap here would double-drop and fail. `user: 'root'` execs bypass
 * the supervisor wrap and stay direct.
 */

/** Deterministic DNS-safe VM name — mirrors the supervisor's identity rule. */
export function incusVmNameForWorkspace(workspaceId: string): string {
  return `chm-vm-${createHash('sha256').update(workspaceId, 'utf8').digest('hex').slice(0, 32)}`;
}

/** The slice of VmSupervisorClient the runner-side VM modules need; fakes implement this surface. */
export type VmSupervisorGateway = Pick<
  VmSupervisorClient,
  | 'vmList' | 'leaseList' | 'poolInfo' | 'reconcile' | 'guardState'
  | 'vmAdmit' | 'vmCreate' | 'vmStart' | 'vmStop' | 'vmDelete' | 'vmStatus' | 'vmExport'
  | 'execRun' | 'execInspect' | 'execOpen' | 'execWrite' | 'execClose' | 'execResize' | 'execKillSession'
  | 'filePush' | 'filePushStream' | 'filePull' | 'fileStat' | 'fileList'
  | 'pushTree' | 'pullTree'
  | 'networkProgram' | 'networkAttest' | 'networkTearDown'
  | 'leaseSet' | 'leaseClear'
>;

export type IncusExecutorBackendDeps = {
  client: VmSupervisorGateway;
  config: RunnerConfig;
  /**
   * Provision-time asset pushes, evaluated AFTER `vm.start` in order. When
   * omitted the backend pushes the real skill tiers itself (builtin catalog +
   * existing owner projection); an override replaces that list entirely.
   */
  provisionAssets?: (record: WorkspaceRecord) => Promise<Array<{ hostDir: string; guestPath: string }>>;
  /**
   * Managed-package profile lookup (same seam the docker adapter uses). A
   * non-empty profile is rejected with VM_CAPABILITY_UNSUPPORTED: package
   * bind-mounts have no VM channel (capability 'packages-bind').
   */
  packages?: {
    profileFor(ownerId: string, workspaceId: string): { mounts: unknown[]; binDirs: unknown[] };
  };
  /** Optional PTY transport override (tests); defaults to IncusPtyTransport over the same client. */
  ptyTransport?: PtyTransport;
};

function isDirectory(path: string): Promise<boolean> {
  return stat(path).then((s) => s.isDirectory()).catch(() => false);
}

/** Guest destinations mirroring the docker executor's read-only skill mounts. */
const GUEST_SKILLS_DIR = '/opt/cloud-harness/skills';
const GUEST_OWNER_SKILLS_DIR = '/opt/cloud-harness/owner-skills';

/**
 * Default provision assets: the skill tiers docker gets via read-only mounts
 * become `pushTree` uploads because a VM has no host mounts.
 *  - `config.builtinSkillsRoot` → `/opt/cloud-harness/skills`. A configured
 *    root that is not a readable directory fails loudly — silently skipping
 *    it would report success on an unverified missing path.
 *  - `<workspacePath>/toolkit-projection/owner-skills` →
 *    `/opt/cloud-harness/owner-skills`, only when the projection already
 *    exists on disk (the toolkit flow materializes it later and the caller
 *    re-pushes on seed; provision must not invent it).
 */
async function defaultProvisionAssets(
  config: RunnerConfig,
  record: WorkspaceRecord
): Promise<Array<{ hostDir: string; guestPath: string }>> {
  const assets: Array<{ hostDir: string; guestPath: string }> = [];
  const builtinRoot = config.builtinSkillsRoot;
  if (builtinRoot) {
    const info = await stat(builtinRoot).catch(() => undefined);
    if (!info?.isDirectory()) {
      throw new HarnessError('UNAVAILABLE', 'builtinSkillsRoot is configured but is not a readable directory', 503, true);
    }
    assets.push({ hostDir: builtinRoot, guestPath: GUEST_SKILLS_DIR });
  }
  const ownerSkills = join(record.workspacePath, 'toolkit-projection', 'owner-skills');
  if (await isDirectory(ownerSkills)) {
    assets.push({ hostDir: ownerSkills, guestPath: GUEST_OWNER_SKILLS_DIR });
  }
  return assets;
}

/** Validates a COMPLETE per-exec environment map (name shape + bounded values). */
function validatedVmExecEnvironment(environment: Record<string, string>): void {
  const entries = Object.entries(environment);
  if (entries.length > EXEC_ENV_MAX_ENTRIES) {
    throw new HarnessError('INVALID_INPUT', 'exec environment has too many entries', 400, false);
  }
  let totalBytes = 0;
  for (const [rawName, value] of entries) {
    const name = validateSecretNameShape(rawName);
    if (!name.ok) {
      throw new HarnessError('INVALID_INPUT', `exec environment variable ${rawName} is invalid: ${name.error}`, 400, false);
    }
    if (typeof value !== 'string' || value.includes('\0') || value.includes('\n') || value.includes('\r')) {
      throw new HarnessError('INVALID_INPUT', `exec environment variable ${name.name} value is invalid`, 400, false);
    }
    const valueBytes = Buffer.byteLength(value, 'utf8');
    if (valueBytes > EXEC_ENV_VALUE_MAX_BYTES) {
      throw new HarnessError('INVALID_INPUT', `exec environment variable ${name.name} value is invalid`, 400, false);
    }
    totalBytes += name.name.length + valueBytes + 2;
    if (totalBytes > EXEC_ENV_MAX_TOTAL_BYTES) {
      throw new HarnessError('INVALID_INPUT', 'exec environment is too large', 400, false);
    }
  }
}

function assertExecArgv(argv: unknown): asserts argv is string[] {
  if (!Array.isArray(argv) || argv.length === 0 || argv.some((arg) => typeof arg !== 'string')) {
    throw new HarnessError('INVALID_INPUT', 'exec argv must be a non-empty string array', 400, false);
  }
}

function clampExecBounds(timeoutMs: number, maxBytes: number): { timeoutMs: number; maxBytes: number } {
  return {
    timeoutMs: Math.min(Math.max(1, Math.floor(timeoutMs)), EXEC_RUN_MAX_TIMEOUT_MS),
    maxBytes: Math.min(Math.max(1, Math.floor(maxBytes)), EXEC_RUN_MAX_OUTPUT_BYTES)
  };
}

/**
 * Canonical guest base environment (H3) — OWNED HERE so exec.run, PTY
 * sessions, spawnStream, and guest Git (via backend.exec's merge) all share
 * one contract. Complete maps, never inherited: callers supply ONLY their
 * extras; this supplies PATH/HOME/GIT_CONFIG_NOSYSTEM/XDG_*. The Git and
 * caller owners must treat this as the single source of truth — do not
 * redefine HOME or PATH for guest execs. No control-plane credentials ever
 * appear here or in caller extras.
 */
export const GUEST_BASE_ENV = {
  PATH: '/opt/user-tools/bin:/opt/user-tools/pnpm/bin:/opt/user-tools/pnpm:/opt/user-tools/bun/bin:/tmp/cloud-harness-home/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
  HOME: '/tmp/cloud-harness-home',
  GIT_CONFIG_NOSYSTEM: '1',
  XDG_CONFIG_HOME: '/tmp/cloud-harness-home/.config',
  XDG_CACHE_HOME: '/var/cache/harness'
} as const;

async function hashFile(path: string): Promise<{ sha256: string; bytes: number }> {
  const hash = createHash('sha256');
  let bytes = 0;
  for await (const chunk of createReadStream(path)) {
    hash.update(chunk as Buffer);
    bytes += (chunk as Buffer).length;
  }
  return { sha256: hash.digest('hex'), bytes };
}

/**
 * Write sink for streamed downloads with three guarantees the bare
 * `createWriteStream` + `once('drain')` pattern lacked:
 *  - 'error' is captured instead of crashing the process (an EventEmitter
 *    'error' with no listener throws);
 *  - a stream error wakes pending drain waiters so the sink rejects on the
 *    next chunk instead of hanging until the wire idle deadline;
 *  - `finish()` surfaces the captured failure as a typed UNAVAILABLE.
 */
export function createGuardedFileWriter(path: string): {
  stream: WriteStream;
  sink: (chunk: Buffer) => void | Promise<void>;
  failure: () => Error | undefined;
  finish: () => Promise<void>;
} {
  const stream = createWriteStream(path);
  let failure: Error | undefined;
  const drainWaiters: Array<() => void> = [];
  stream.on('error', (error: Error) => {
    failure = error;
    for (const wake of drainWaiters.splice(0)) wake();
  });
  const sink = (chunk: Buffer): void | Promise<void> => {
    if (failure) return Promise.reject(failure);
    if (stream.write(chunk)) return;
    return new Promise<void>((resolve) => {
      drainWaiters.push(resolve);
      stream.once('drain', resolve);
    });
  };
  const finish = async (): Promise<void> => {
    await new Promise<void>((resolve, reject) => {
      stream.end((error?: Error | null) => (error ? reject(error) : resolve()));
    });
    if (failure) {
      throw new HarnessError('UNAVAILABLE', 'local transfer staging write failed', 503, true);
    }
  };
  return { stream, sink, failure: () => failure, finish };
}

/**
 * M9 host-side audit of an extracted guest tar: every entry must stay inside
 * `root`. Regular files and directories pass; symlinks pass only when their
 * fully-resolved target (or, for dangling links, the resolved longest
 * existing prefix plus a lexically-contained remainder) stays under root;
 * fifos/sockets/device nodes are rejected outright. Legitimate contained
 * symlinks (e.g. node_modules/.bin) are preserved — host escape is not.
 */
async function assertExtractedTreeContained(root: string): Promise<void> {
  const rootReal = await realpath(root);
  const inside = (candidate: string): boolean =>
    candidate === rootReal || candidate.startsWith(rootReal + sep);
  const assertInside = (candidate: string, what: string): void => {
    if (!inside(candidate)) {
      throw new HarnessError('INVALID_INPUT', `pulled archive contains ${what} escaping the extraction root`, 400, false);
    }
  };
  const auditSymlink = async (linkPath: string): Promise<void> => {
    const target = await readlink(linkPath);
    const lexical = resolve(dirname(linkPath), target);
    assertInside(lexical, 'a symlink');
    // Resolve the longest existing prefix so symlink chains cannot smuggle
    // the target outside root even when the final component is missing.
    let probe = lexical;
    for (;;) {
      try {
        assertInside(await realpath(probe), 'a symlink');
        return;
      } catch (error) {
        if (error instanceof HarnessError) throw error;
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
        const parent = dirname(probe);
        if (parent === probe) throw error;
        probe = parent;
      }
    }
  };
  const walk = async (dir: string): Promise<void> => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isSymbolicLink()) {
        await auditSymlink(path);
      } else if (entry.isDirectory()) {
        await walk(path);
      } else if (!entry.isFile()) {
        throw new HarnessError('INVALID_INPUT', 'pulled archive contains a non-file entry', 400, false);
      }
    }
  };
  await walk(rootReal);
}

/** Free-space margin kept back from staging reservations (matches supervisor). */
const STAGING_DISK_MARGIN_BYTES = 1024 * 1024 * 1024;

/**
 * Process-wide reservation ledger for runner-side staging sinks — the runner
 * counterpart of the supervisor's DiskReservations. Every disk-backed stream
 * sink (pullTree/pullFile staging tars, vm.export tarballs, pushTree staging
 * archives) reserves its worst-case footprint BEFORE the first byte lands, so
 * N concurrent transfers cannot pass the same statfs reading and exhaust the
 * host disk in aggregate. Holds are released in `finally` on every outcome.
 */
export class StagingReservations {
  private readonly held = new Map<string, number>();
  private heldTotal = 0;

  /** Bytes currently reserved across all staging sinks. */
  get reservedBytes(): number {
    return this.heldTotal;
  }

  /**
   * Reserve `bytes` against the filesystem backing `dir`. Throws
   * LIMIT_EXCEEDED when free space minus in-flight reservations minus margin
   * cannot cover the request. When statfs itself is unavailable the transfer
   * is not blocked (same leniency as the previous per-call preflight).
   */
  async acquire(key: string, dir: string, bytes: number): Promise<() => void> {
    if (this.held.has(key)) {
      throw new HarnessError('CONFLICT', `duplicate staging reservation: ${key}`, 409, false);
    }
    const info = await statfs(dir).catch(() => undefined);
    if (info) {
      const free = Number(info.bavail) * Number(info.bsize);
      if (free - this.heldTotal < bytes + STAGING_DISK_MARGIN_BYTES) {
        throw new HarnessError(
          'LIMIT_EXCEEDED',
          `insufficient staging space: ${Math.floor(free)} bytes free minus ${this.heldTotal} reserved, ${bytes} + ${STAGING_DISK_MARGIN_BYTES} margin required`,
          413,
          false
        );
      }
    }
    this.held.set(key, bytes);
    this.heldTotal += bytes;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.heldTotal -= this.held.get(key) ?? 0;
      this.held.delete(key);
    };
  }
}

/** Shared ledger used by every IncusExecutorBackend instance + the export seam. */
export const stagingReservations = new StagingReservations();

/** Cancelled-work error matching the docker adapter's CANCELLED convention. */
function cancelledError(): HarnessError {
  return new HarnessError('CANCELLED', 'tar operation cancelled', 499, false);
}

/** Throw CANCELLED when the signal has fired — used between pipeline phases. */
function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw cancelledError();
}

function runTar(args: string[], timeoutMs: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    throwIfAborted(signal);
    const child = spawn('tar', args, { stdio: ['ignore', 'ignore', 'pipe'] });
    // Cumulative cap — a hostile/verbose tar must not grow stderr without bound.
    let stderr = '';
    child.stderr?.on('data', (chunk: Buffer) => {
      if (stderr.length < 65_536) stderr = (stderr + chunk.toString('utf8')).slice(0, 65_536);
    });
    const timer = setTimeout(() => { child.kill('SIGKILL'); }, timeoutMs);
    timer.unref();
    // M11: abort terminates and reaps the child promptly — cancellation is
    // bounded by the signal, not by TAR_TIMEOUT_MS.
    const onAbort = () => { child.kill('SIGKILL'); };
    signal?.addEventListener('abort', onAbort, { once: true });
    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    };
    child.on('error', (error) => { cleanup(); reject(error); });
    child.on('close', (code) => {
      cleanup();
      if (signal?.aborted) {
        reject(cancelledError());
      } else if (code === 0) {
        resolve();
      } else {
        reject(new HarnessError('UNAVAILABLE', `tar ${args[0]} failed: ${stderr || `exit ${code}`}`.slice(0, 500), 503, true));
      }
    });
  });
}

/**
 * M12: `tar -cf -` pumped through a counting tap into `tarPath`. The byte
 * cap is enforced DURING creation — the moment cumulative output exceeds
 * `byteCap` the child is SIGKILLed and the call rejects LIMIT_EXCEEDED, so
 * staging never holds more than ~cap bytes no matter how large or how fast
 * `hostDir` grows mid-read. Work is O(cap), not O(tree): tar stops emitting
 * once the cap trips. Resolves with the exact archive byte count.
 */
function tarCreateToFile(
  hostDir: string,
  tarPath: string,
  byteCap: number,
  opts: { timeoutMs: number; signal?: AbortSignal }
): Promise<number> {
  return new Promise((resolve, reject) => {
    throwIfAborted(opts.signal);
    const child = spawn('tar', ['-cf', '-', '-C', hostDir, '.'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = '';
    child.stderr?.on('data', (chunk: Buffer) => {
      if (stderr.length < 65_536) stderr = (stderr + chunk.toString('utf8')).slice(0, 65_536);
    });
    const out = createWriteStream(tarPath);
    let bytes = 0;
    let settled = false;
    const cleanup = () => {
      clearTimeout(timer);
      opts.signal?.removeEventListener('abort', onAbort);
    };
    const fail = (error: unknown) => {
      if (settled) return;
      settled = true;
      cleanup();
      child.kill('SIGKILL');
      out.destroy();
      reject(error instanceof Error ? error : new HarnessError('UNAVAILABLE', 'tar create failed', 503, true));
    };
    const timer = setTimeout(() => {
      fail(new HarnessError('UNAVAILABLE', 'tar create timed out', 503, true));
    }, opts.timeoutMs);
    timer.unref();
    const onAbort = () => { fail(cancelledError()); };
    opts.signal?.addEventListener('abort', onAbort, { once: true });
    child.on('error', fail);
    out.on('error', fail);
    child.stdout.on('data', (chunk: Buffer) => {
      bytes += chunk.length;
      if (bytes > byteCap) {
        fail(new HarnessError('LIMIT_EXCEEDED', 'pushTree archive exceeds the workspace byte bound', 413, false));
      }
    });
    child.stdout.pipe(out);
    child.on('close', (code) => {
      if (settled) return;
      // Flush the file stream before reporting: a nonzero exit with a fully
      // written archive still means tar failed (unreadable input, etc.).
      out.end(() => {
        if (settled) return;
        if (code === 0) {
          settled = true;
          cleanup();
          resolve(bytes);
        } else {
          fail(new HarnessError('UNAVAILABLE', `tar create failed: ${stderr || `exit ${code}`}`.slice(0, 500), 503, true));
        }
      });
    });
  });
}

/**
 * Adapts a live `exec.open` session to the `StreamHandle` contract
 * (`OperationManager.track` needs piped stdio + kill + close/error events).
 * stdin writes and control closes ride separate unary `exec.write`/`exec.close`
 * calls; stdout/stderr arrive on the session's fd-tagged data events.
 */
class VmExecStreamHandle extends EventEmitter implements StreamHandle {
  readonly stdin: Writable;
  readonly stdout: Readable;
  readonly stderr: Readable;
  private ended = false;

  constructor(
    private readonly client: VmSupervisorGateway,
    private readonly identity: VmWorkspaceIdentity,
    private readonly session: VmExecSession
  ) {
    super();
    this.stdin = new Writable({
      write: (chunk: Buffer, _encoding, callback) => {
        void this.client.execWrite(this.identity, {
          sessionId: session.sessionId, fd: 0, dataBase64: chunk.toString('base64')
        }).then(() => callback(), (error) => callback(error instanceof Error ? error : new Error(String(error))));
      },
      final: (callback) => {
        void this.client.execWrite(this.identity, {
          sessionId: session.sessionId, fd: 0, dataBase64: '', eof: true
        }).then(() => this.client.execClose(this.identity, { sessionId: session.sessionId, fd: 0 }))
          .then(() => callback(), (error) => callback(error instanceof Error ? error : new Error(String(error))));
      }
    });
    this.stdout = new Readable({ read: () => undefined });
    this.stderr = new Readable({ read: () => undefined });
    session.onData((fd, chunk) => {
      if (fd === 2) this.stderr.push(chunk);
      else this.stdout.push(chunk);
    });
    void session.ended.then(
      (meta) => this.finish(null, meta.exitCode),
      (error) => this.finish(error instanceof Error ? error : new Error(String(error)), null)
    );
  }

  kill(): boolean {
    if (this.ended) return false;
    // fd -1 is the supervisor's control close: it kills the session's
    // process-group leader, matching docker's kill semantics. If the control
    // call itself fails (transport down), detach the session — the supervisor
    // reaps the guest side when the connection drops (L8 best-effort).
    void this.client.execClose(this.identity, { sessionId: this.session.sessionId, fd: -1 })
      .catch(() => { try { this.session.close(); } catch { /* already closed */ } });
    return true;
  }

  private finish(error: Error | null, exitCode: number | null): void {
    if (this.ended) return;
    this.ended = true;
    this.stdout.push(null);
    this.stderr.push(null);
    if (error) this.emit('error', error);
    this.emit('close', exitCode, null);
  }
}

/** PtyConnection over an `exec.open` pty session; output is fd-merged like docker's Tty stream. */
class VmPtyConnection implements PtyConnection {
  private ended = false;
  private readonly dataListeners: Array<(chunk: Buffer) => void> = [];
  private readonly endListeners: Array<(end: PtyEnd) => void> = [];
  private readonly pending: Buffer[] = [];
  /**
   * exec.write calls are unary — each rides its own connection, so issuing
   * them concurrently can reorder keystrokes on the wire. Writes are chained
   * serially (bounded slices keep every control message under the 1 MiB cap)
   * and `pendingBytes` exposes the queue depth for backpressure.
   */
  private writeChain: Promise<void> = Promise.resolve();
  private pendingBytes = 0;

  constructor(
    readonly execId: string,
    private readonly client: VmSupervisorGateway,
    private readonly identity: VmWorkspaceIdentity,
    private readonly session: VmExecSession
  ) {
    session.onData((_fd, chunk) => this.emitData(chunk));
    void session.ended.then(
      () => this.finish({}),
      (error) => this.finish({ error: error instanceof Error ? error : new Error(String(error)) })
    );
  }

  get writableLength(): number {
    return this.pendingBytes;
  }

  write(data: Buffer): void {
    if (this.ended) throw new HarnessError('CONFLICT', 'terminal is not running', 409, false);
    // Bound the queued input: a stalled session must not grow memory without limit.
    if (this.pendingBytes + data.length > PTY_MAX_PENDING_INPUT_BYTES) {
      this.finish({ error: new HarnessError('LIMIT_EXCEEDED', 'terminal input queue exceeded its bound', 413, false) });
      throw new HarnessError('LIMIT_EXCEEDED', 'terminal input queue exceeded its bound', 413, false);
    }
    this.pendingBytes += data.length;
    // exec.write dataBase64 is a control message: keep each slice far under
    // the 1 MiB wire cap (768 KiB raw → ~1 MiB base64 + envelope).
    const slices: Buffer[] = [];
    for (let offset = 0; offset < data.length; offset += PTY_WRITE_SLICE_BYTES) {
      slices.push(data.subarray(offset, offset + PTY_WRITE_SLICE_BYTES));
    }
    this.writeChain = this.writeChain.then(async () => {
      for (const slice of slices) {
        if (this.ended) return;
        await this.client.execWrite(this.identity, {
          sessionId: this.session.sessionId, fd: 0, dataBase64: slice.toString('base64')
        });
      }
    }).catch(() => this.finish({ error: new HarnessError('UNAVAILABLE', 'terminal input could not be delivered', 503, true) }))
      .finally(() => { this.pendingBytes -= data.length; });
  }

  onData(listener: (chunk: Buffer) => void): void {
    this.dataListeners.push(listener);
    if (this.pending.length > 0) {
      const buffered = Buffer.concat(this.pending.splice(0));
      listener(buffered);
    }
  }

  onEnd(listener: (end: PtyEnd) => void): void {
    this.endListeners.push(listener);
  }

  /** Detach only — the guest session survives until killSession, matching docker's close(). */
  close(): void {
    this.session.close();
  }

  private emitData(chunk: Buffer): void {
    if (this.dataListeners.length === 0) {
      this.pending.push(chunk);
      return;
    }
    for (const listener of this.dataListeners) listener(chunk);
  }

  private finish(end: PtyEnd): void {
    if (this.ended) return;
    this.ended = true;
    for (const listener of this.endListeners) listener(end);
  }
}

/** PtyTransport over supervisor `exec.open` pty sessions + `exec.killSession`. */
export class IncusPtyTransport implements PtyTransport {
  /**
   * sessionId → bound workspace identity + settled exit state. `exec.resize`
   * and `inspect` carry only the sessionId, so the identity resolved at
   * `open` is remembered here; `open`/`killSession` resolve identity from the
   * VM name through `identityFor`.
   */
  private readonly sessions = new Map<string, {
    identity: VmWorkspaceIdentity;
    running: boolean;
    exitCode: number | null;
  }>();

  constructor(
    private readonly client: VmSupervisorGateway,
    private readonly identityFor: (container: string) => VmWorkspaceIdentity
  ) {}

  async open(request: PtyOpenRequest): Promise<PtyConnection> {
    const identity = this.identityFor(request.container);
    const sessionId = `pty-${request.terminalId}`.slice(0, 128);
    const session = await this.client.execOpen(identity, {
      sessionId,
      argv: terminalCommand(request.terminalId),
      cwd: request.workingDir,
      environment: {
        // Canonical base env (HOME=/tmp/cloud-harness-home) + terminal vars —
        // the old /home/harness HOME conflicted with GUEST_BASE_ENV.
        ...GUEST_BASE_ENV,
        TERM: 'xterm-256color',
        COLORTERM: 'truecolor'
      },
      pty: { cols: request.cols, rows: request.rows }
    });
    this.sessions.set(sessionId, { identity, running: true, exitCode: null });
    const connection = new VmPtyConnection(sessionId, this.client, identity, session);
    void session.ended.then((meta) => {
      this.sessions.set(sessionId, { identity, running: false, exitCode: meta.exitCode });
    }, () => {
      this.sessions.set(sessionId, { identity, running: false, exitCode: null });
    });
    return connection;
  }

  async resize(execId: string, cols: number, rows: number): Promise<void> {
    const entry = this.sessions.get(execId);
    if (!entry) {
      throw new HarnessError('NOT_FOUND', 'terminal session is not known to this transport', 404, false);
    }
    await this.client.execResize(entry.identity, { sessionId: execId, cols, rows });
  }

  async inspect(execId: string): Promise<{ running: boolean; exitCode: number | null }> {
    const entry = this.sessions.get(execId);
    if (!entry) return { running: false, exitCode: null };
    return { running: entry.running, exitCode: entry.exitCode };
  }

  async killSession(container: string, terminalId: string): Promise<void> {
    const identity = this.identityFor(container);
    const sessionId = `pty-${terminalId}`.slice(0, 128);
    await this.client.execKillSession(identity, {
      sessionId,
      pidFile: `${TERMINAL_PID_DIR}/${terminalId}.pid`
    });
  }
}

export class IncusExecutorBackend implements ExecutorBackend {
  readonly kind = 'incus-vm' as const;
  private ptyClient: PtyTransport | undefined;
  /** vmName → workspace identity, populated by every verb so PtyTransport can resolve per-VM identity. */
  private readonly identities = new Map<string, VmWorkspaceIdentity>();

  constructor(private readonly deps: IncusExecutorBackendDeps) {}

  private get config(): RunnerConfig {
    return this.deps.config;
  }

  private vmName(record: WorkspaceRecord): string {
    return record.vmName ?? incusVmNameForWorkspace(record.id);
  }

  /** Wire identity needs only the persisted instance id; template fields gate create/adopt. */
  private wireIdentity(record: WorkspaceRecord): VmWorkspaceIdentity {
    if (!record.backendInstanceId) {
      throw new HarnessError('UNAVAILABLE', 'workspace VM identity was not persisted at admit', 503, true);
    }
    const identity: VmWorkspaceIdentity = {
      workspaceId: record.id,
      generation: record.generation,
      instanceId: record.backendInstanceId
    };
    this.identities.set(this.vmName(record), identity);
    return identity;
  }

  /** Persisted-at-admit identity incl. template fields; missing means admit never completed. */
  private requireIdentity(record: WorkspaceRecord): { instanceId: string; templateId: string; templateDigest: string } {
    const { backendInstanceId, templateId, templateDigest } = record;
    if (!backendInstanceId || !templateId || !templateDigest) {
      throw new HarnessError('UNAVAILABLE', 'workspace VM identity was not persisted at admit', 503, true);
    }
    return { instanceId: backendInstanceId, templateId, templateDigest };
  }

  private identity(ctx: ProvisionContext): VmWorkspaceIdentity {
    return this.wireIdentity(ctx.record);
  }

  private ref(record: WorkspaceRecord, executorId: string): ExecutorRef {
    return {
      backend: 'incus-vm',
      workspaceId: record.id,
      executorId,
      generation: record.generation,
      ...(record.backendInstanceId ? { instanceId: record.backendInstanceId } : {})
    };
  }

  /* ------------------------------------------------------------------ */
  /* Lifecycle                                                           */
  /* ------------------------------------------------------------------ */

  /**
   * M4/H5 expiry gate. `hardExpiresAt` is an UNCONDITIONAL cutoff — past it
   * nothing runs, no guest probe, no re-provision; reconcile owns the disk.
   * `expiresAt` (soft/idle TTL) is different for `EXPIRED_RECOVERABLE`
   * records: being soft-expired is exactly why they are recoverable, and
   * callers invoke ensureActive BEFORE the store writes the refreshed
   * expiry. Such a record may proceed only inside its recoverable window
   * (`recoverableUntil > now`); every other soft-expired record — including
   * ACTIVE-with-past-expiry (the reaper race) — is refused.
   */
  private assertNotExpired(record: WorkspaceRecord): void {
    const now = Date.now();
    if (record.hardExpiresAt <= now) {
      throw new HarnessError('EXPIRED', 'workspace hard lease limit reached; reconcile owns its VM now', 410, false);
    }
    if (record.expiresAt <= now && !this.isRecoverableResume(record, now)) {
      throw new HarnessError('EXPIRED', 'workspace lease has expired; reconcile owns its VM now', 410, false);
    }
  }

  /**
   * True only for a soft-expired `EXPIRED_RECOVERABLE` record still inside
   * its recoverable window. `recoverableUntil` absent/past → not recoverable.
   */
  private isRecoverableResume(record: WorkspaceRecord, now = Date.now()): boolean {
    return record.expiresAt <= now
      && record.status === 'EXPIRED_RECOVERABLE'
      && record.recoverableUntil != null
      && record.recoverableUntil > now;
  }

  /**
   * H5 recovery lease times. With caller intent (`ctx.leaseExpiresAt`,
   * already clamped to hardTTL by the caller and re-clamped here) the
   * durable lease equals the FINAL post-activation store expiry — the
   * first write is the last write, so a later best-effort leaseSync can
   * never be the only thing standing between a too-long lease and the
   * request. Without intent the record-derived bound
   * `min(hardExpiresAt, recoverableUntil)` applies. `recoverableUntil`
   * bounds recovery ADMISSION only — it never clamps the resulting
   * ACTIVE expiry. Invalid intent (non-finite or not future) is a caller
   * contract violation and throws BEFORE any lease mutation.
   */
  private recoveryLeaseTimes(record: WorkspaceRecord, ctx: ProvisionContext): { expiresAt: number; hardExpiresAt: number } {
    const hard = record.hardExpiresAt;
    const intended = ctx.leaseExpiresAt;
    if (intended === undefined) {
      return { expiresAt: Math.min(hard, record.recoverableUntil ?? hard), hardExpiresAt: hard };
    }
    if (!Number.isFinite(intended) || intended <= Date.now()) {
      throw new HarnessError('INVALID_INPUT', 'leaseExpiresAt must be a finite future timestamp', 400, false);
    }
    return { expiresAt: Math.min(hard, intended), hardExpiresAt: hard };
  }

  /**
   * H5: re-establish the durable supervisor lease BEFORE any status/start
   * call for a recoverable record. The stored lease is soft-expired: while
   * it is still 'active' the request-time deadline cutoff refuses EVERY
   * workspace op (including vm.status and lease.set — only lease.clear is
   * exempt). Clearing first unblocks the channel; the fresh lease.set then
   * restores 'active' state with recovery times so the watchdog keeps the
   * VM and vm.start admission sees a leased workspace. Both ops are
   * identity+generation fenced and idempotency-keyed.
   */
  private async recoverSupervisorLease(ctx: ProvisionContext, record: WorkspaceRecord, instanceId: string): Promise<void> {
    const ident = this.identity(ctx);
    const signal = ctx.signal;
    // Validate intent BEFORE any mutation: an invalid ctx.leaseExpiresAt
    // must fail closed with the stored (expired) lease untouched.
    const times = this.recoveryLeaseTimes(record, ctx);
    // Unique keys per attempt: the supervisor replays a completed
    // idempotency record WITHOUT re-executing, so a fixed key would
    // silently no-op a retry after an intervening lease.clear and leave
    // the workspace permanently unleased.
    const attempt = randomUUID();
    try {
      await this.deps.client.leaseClear(ident, {
        idempotencyKey: `lease-${instanceId}-recover-clear-${attempt}`,
        timeoutMs: LIFECYCLE_TIMEOUT_MS,
        ...(signal ? { signal } : {})
      });
      await this.deps.client.leaseSet(ident, times, {
        idempotencyKey: `lease-${instanceId}-${times.expiresAt}-${times.hardExpiresAt}-${attempt}`,
        timeoutMs: LIFECYCLE_TIMEOUT_MS,
        ...(signal ? { signal } : {})
      });
    } catch (error) {
      // Journal has no row for this workspace → there is no stale lease to
      // recover; fall through so vm.status NOT_FOUND drives the provision path.
      if (error instanceof VmSupervisorCallError && error.code === 'NOT_FOUND') return;
      throw error;
    }
  }

  /**
   * Bounded fail-closed rollback after a confirmed start whose activation
   * then failed — "stop/lease rollback", never passive retention:
   *  - `stop`: Incus stop returns the VM to stopped. Stop preserves the
   *    disk — it is never a delete, so data survives unknown outcomes.
   *  - `unlease`: lease.clear returns the durable lease to unleased so the
   *    supervisor watchdog — not an executing VM — owns the retention
   *    bound until the next recovery re-leases (recoverable records only;
   *    clearing a healthy ACTIVE lease would brick ops until the next sync).
   * Both are best-effort on a fresh deadline with unique idempotency keys:
   * ctx.signal may be the very abort that triggered the failure, and a
   * replayed recorded result must never stand in for a real rollback.
   */
  private async rollbackActivation(
    ident: VmWorkspaceIdentity,
    instanceId: string,
    opts: { stop: boolean; unlease: boolean }
  ): Promise<void> {
    const attempt = randomUUID();
    const ops: Promise<unknown>[] = [];
    if (opts.stop) {
      ops.push(this.deps.client.vmStop(ident, {
        idempotencyKey: `vm-${instanceId}-rollback-stop-${attempt}`,
        timeoutMs: ROLLBACK_TIMEOUT_MS
      }).catch(() => undefined));
    }
    if (opts.unlease) {
      ops.push(this.deps.client.leaseClear(ident, {
        idempotencyKey: `lease-${instanceId}-rollback-clear-${attempt}`,
        timeoutMs: ROLLBACK_TIMEOUT_MS
      }).catch(() => undefined));
    }
    await Promise.all(ops);
  }

  /**
   * Per-asset durable completion sentinel (M3): written under
   * /opt/user-tools IMMEDIATELY after that asset's pushTree lands, so a
   * later adopt can distinguish "this asset completed" from "provision
   * died mid-push". The path is keyed by instanceId AND guestPath so a
   * different instance or a changed asset set never inherits another's
   * completion record.
   *
   * SECURITY: the sentinel lives in the guest filesystem and is therefore
   * guest-root-modifiable — it is a completion HINT only, never an
   * attestation and never authorization to overwrite. It may only ever
   * SKIP a push; it can never cause one. The sole gate that permits a
   * (re-)push is a fileStat NOT_FOUND on the asset's own guestPath —
   * proof the destination is absent, so extraction cannot clobber
   * existing (possibly user-modified) content. An existing-but-unverified
   * destination fails closed instead of being overwritten.
   */
  private provisionSentinelPath(instanceId: string, guestPath: string): string {
    const digest = createHash('sha256').update(guestPath, 'utf8').digest('hex').slice(0, 16);
    return `/opt/user-tools/.cloud-harness-provisioned-${instanceId}-${digest}`;
  }

  /** Write one asset's completion sentinel. Provision/adopt-repair only. */
  private async writeProvisionSentinel(ctx: ProvisionContext, instanceId: string, record: WorkspaceRecord, guestPath: string): Promise<void> {
    const digest = createHash('sha256').update(guestPath, 'utf8').digest('hex').slice(0, 16);
    const content = Buffer.from(`${record.templateDigest ?? ''}\n${guestPath}\n`, 'utf8');
    await this.deps.client.filePush(this.identity(ctx), {
      guestPath: this.provisionSentinelPath(instanceId, guestPath),
      dataBase64: content.toString('base64'),
      sha256: createHash('sha256').update(content).digest('hex'),
      maxBytes: content.length,
      mode: 0o644,
      uid: WORKSPACE_UID,
      gid: WORKSPACE_UID
    }, {
      // Key charset is [A-Za-z0-9._:-] — the guestPath digest stands in for
      // the raw path (which contains '/').
      idempotencyKey: `assets-${instanceId}-${digest}-sentinel`,
      timeoutMs: DEFAULT_CALL_TIMEOUT_MS,
      ...(ctx.signal ? { signal: ctx.signal } : {})
    });
  }

  /** fileStat wrapper: 'file' | 'dir' | 'absent'; other errors propagate. */
  private async guestPathKind(ctx: ProvisionContext, guestPath: string): Promise<'file' | 'dir' | 'absent'> {
    try {
      const stat = await this.deps.client.fileStat(this.identity(ctx), { guestPath }, {
        timeoutMs: DEFAULT_CALL_TIMEOUT_MS,
        ...(ctx.signal ? { signal: ctx.signal } : {})
      });
      return stat.isDir ? 'dir' : 'file';
    } catch (error) {
      if (error instanceof VmSupervisorCallError && error.code === 'NOT_FOUND') return 'absent';
      throw error;
    }
  }

  /** Push every provision asset, then that asset's completion sentinel. Provision-only. */
  private async pushProvisionAssets(ctx: ProvisionContext, record: WorkspaceRecord, instanceId: string): Promise<void> {
    const assets = this.deps.provisionAssets
      ? await this.deps.provisionAssets(record)
      : await defaultProvisionAssets(this.config, record);
    for (const asset of assets) {
      await this.pushTree(ctx, asset.hostDir, asset.guestPath);
      await this.writeProvisionSentinel(ctx, instanceId, record, asset.guestPath);
    }
  }

  /**
   * Adopt-side asset reconciliation (M3). For each asset:
   *  - sentinel present → completion hint says done → skip (a forged or
   *    stale sentinel can only cause a SKIP, i.e. visibly missing files —
   *    never an overwrite).
   *  - sentinel absent + destination fileStat NOT_FOUND → destination is
   *    confirmed empty → safe to pushTree, then write the sentinel.
   *  - sentinel absent + destination EXISTS (file or dir, symlink or not —
   *    file.stat follows links so a resolvable link reads as its target)
   *    → content is unverified: it may be a completed asset whose
   *    sentinel was lost, a partial push, or owner-modified toolkit.
   *    Refuse to overwrite — fail closed and let reconcile/operator
   *    decide. (A dangling symlink stats NOT_FOUND and is the only
   *    residual: guest-side extraction owns containment there.)
   */
  private async ensureProvisionAssets(ctx: ProvisionContext, record: WorkspaceRecord, instanceId: string): Promise<void> {
    const assets = this.deps.provisionAssets
      ? await this.deps.provisionAssets(record)
      : await defaultProvisionAssets(this.config, record);
    for (const asset of assets) {
      const sentinel = await this.guestPathKind(ctx, this.provisionSentinelPath(instanceId, asset.guestPath));
      if (sentinel === 'file') continue;
      const destination = await this.guestPathKind(ctx, asset.guestPath);
      if (destination !== 'absent') {
        throw new HarnessError(
          'UNAVAILABLE',
          `provision asset ${asset.guestPath} exists without a completion record; refusing to overwrite unverified guest content`,
          503,
          true
        );
      }
      await this.pushTree(ctx, asset.hostDir, asset.guestPath);
      await this.writeProvisionSentinel(ctx, instanceId, record, asset.guestPath);
    }
  }

  async provision(ctx: ProvisionContext): Promise<ExecutorRef> {
    const record = ctx.record;
    this.assertNotExpired(record);
    const { instanceId, templateId, templateDigest } = this.requireIdentity(record);
    // packages-bind is unsupported on incus-vm: a bound package profile has
    // no VM mount channel, so provision fails loudly instead of silently
    // dropping the binding (capability map already gates the bind operation).
    if (this.deps.packages) {
      const profile = this.deps.packages.profileFor(record.ownerId, record.id);
      if (profile.mounts.length > 0 || profile.binDirs.length > 0) {
        throw new HarnessError(
          'VM_CAPABILITY_UNSUPPORTED',
          'managed package bindings are not supported by the incus-vm executor backend',
          400,
          false
        );
      }
    }
    const ident = this.identity(ctx);
    const vmName = this.vmName(record);
    const instanceKey = `vm-${instanceId}`;
    const signal = ctx.signal;

    // H5: a recoverable record's stored expiresAt is already past — lease
    // with the recovery/intent times instead or the VM is born expired.
    // Computed BEFORE vm.create so an invalid ctx.leaseExpiresAt fails
    // before any mutation. The key matches createVmLeaseSync's
    // `lease-<iid>-<exp>-<hard>` shape (L6): provision never clears, so a
    // same-value retry replays correctly, and a post-activation leaseSync
    // carrying identical values replays as a no-op.
    const leaseTimes = this.isRecoverableResume(record)
      ? this.recoveryLeaseTimes(record, ctx)
      : { expiresAt: record.expiresAt, hardExpiresAt: record.hardExpiresAt };

    // 1. Create stopped + journaled. Replay-safe: same idempotency key returns
    //    the recorded result instead of a second VM after a lost reply.
    await this.deps.client.vmCreate(ident, {
      instanceId,
      networkProfile: ctx.networkProfile,
      templateId,
      templateDigest
    }, { idempotencyKey: `${instanceKey}-create`, timeoutMs: LIFECYCLE_TIMEOUT_MS, ...(signal ? { signal } : {}) });

    // 2. Durable lease BEFORE any start — the supervisor watchdog stops an
    //    unleased or expired VM, so the lease must exist first. Unique per
    //    attempt like every other lease write: the supervisor replays a
    //    completed idempotency record WITHOUT re-executing, so a
    //    times-derived key could return a stale success after an
    //    intervening lease.clear and leave the VM born unleased.
    await this.deps.client.leaseSet(ident, leaseTimes, {
      idempotencyKey: `lease-${instanceId}-${leaseTimes.expiresAt}-${leaseTimes.hardExpiresAt}-${randomUUID()}`,
      timeoutMs: LIFECYCLE_TIMEOUT_MS,
      ...(signal ? { signal } : {})
    });

    // 3. The ONLY start gate — supervisor re-checks admission, attestation,
    //    network policy, and agent-readiness internally. Unique per attempt:
    //    vm.start is repeatable by design and the supervisor answers
    //    already-running gracefully, so a fresh key always re-executes —
    //    a fixed key would replay a stale 'running' after a rollback stop.
    await this.deps.client.vmStart(ident, {
      networkProfile: ctx.networkProfile
    }, { idempotencyKey: `${instanceKey}-start-${randomUUID()}`, timeoutMs: LIFECYCLE_TIMEOUT_MS, ...(signal ? { signal } : {}) });

    // 4. Guest asset pushes + durable completion marker (M3). A failure
    //    after the CONFIRMED start rolls the VM back to stopped — bounded,
    //    disk-preserving — instead of leaving it executing until lease
    //    expiry on a failed request. The lease itself stays: provision
    //    never clears, so a same-value retry still replays correctly.
    try {
      await this.pushProvisionAssets(ctx, record, instanceId);
    } catch (error) {
      await this.rollbackActivation(ident, instanceId, { stop: true, unlease: false });
      throw error;
    }

    return this.ref(record, vmName);
  }

  async ensureActive(ctx: ProvisionContext): Promise<ExecutorRef> {
    const record = ctx.record;
    this.assertNotExpired(record);
    const { instanceId, templateId, templateDigest } = this.requireIdentity(record);
    const ident = this.identity(ctx);
    const vmName = this.vmName(record);
    const signal = ctx.signal;

    // H5: a recoverable record's stored supervisor lease is soft-expired —
    // while still 'active' the request-time deadline cutoff refuses every
    // workspace op, vm.status included. Re-establish the lease FIRST so the
    // status/start calls below are admissible; hard expiry was already
    // refused unconditionally by assertNotExpired before any RPC.
    const recoverable = this.isRecoverableResume(record);
    if (recoverable) {
      await this.recoverSupervisorLease(ctx, record, instanceId);
    }

    // Rollback scope for failures after the durable lease was (re)written:
    // `started` — this call confirmed vm.start; `adopted` — confirmed
    // running under full identity. A recoverable record always unleases on
    // failure so the watchdog, not an executing VM, owns the retention
    // bound until the next recovery re-leases; a VM this call started —
    // or a recoverable VM confirmed running (already watchdog-doomed under
    // its expired lease) — is stopped. Incus stop preserves the disk,
    // never deletes on unknown outcomes; identity mismatches and transient
    // states unlease only, leaving ambiguous disks untouched.
    let started = false;
    let adopted = false;
    try {
      let status;
      try {
        status = await this.deps.client.vmStatus(ident, { ...(signal ? { signal } : {}) });
      } catch (error) {
        if (error instanceof VmSupervisorCallError && error.code === 'NOT_FOUND') {
          // ONLY a typed NOT_FOUND from the supervisor is trusted absence: it
          // means the supervisor journal has no row for this workspace, so
          // vm.create below registers fresh identity and Incus itself refuses
          // a duplicate name — nothing existing can be overwritten. EVERY
          // other outcome — including a bare {state:'unknown'} result, which
          // is what opStatus returns for an Incus-404 under a live journal row
          // — is ambiguous and must retain: never vm.create, never re-seed.
          return await this.provision(ctx);
        }
        throw error;
      }

      const observed = status.userCloudHarness;
      const identityMatches = observed !== undefined
        && observed.workspaceId === record.id
        && observed.instanceId === instanceId
        && observed.templateId === templateId
        && observed.templateDigest === templateDigest;

      if (status.state === 'running') {
        if (!identityMatches) {
          throw new VmSupervisorCallError('VM_IDENTITY_MISMATCH', 'running VM identity does not match the persisted workspace identity', 409, false, false, 'vm.status');
        }
        adopted = true;
        // Adopt only after the durable asset marker proves provision completed;
        // a partial provision re-pushes missing assets, never the checkout.
        await this.ensureProvisionAssets(ctx, record, instanceId);
        return this.ref(record, vmName);
      }
      if (status.state === 'stopped' || status.state === 'frozen') {
        if (!identityMatches) {
          throw new VmSupervisorCallError('VM_IDENTITY_MISMATCH', 'stopped VM identity does not match the persisted workspace identity', 409, false, false, 'vm.status');
        }
        await this.deps.client.vmStart(ident, {
          networkProfile: ctx.networkProfile
        }, {
          // Unique per attempt: a prior start may have been rolled back to
          // stopped, and the supervisor replays completed idempotency
          // records without re-executing — a fixed key would return the
          // recorded 'running' while the VM is actually still stopped.
          idempotencyKey: `vm-${instanceId}-start-${randomUUID()}`,
          timeoutMs: LIFECYCLE_TIMEOUT_MS,
          ...(signal ? { signal } : {})
        });
        started = true;
        // Assets need a running VM; complete any missing provision phase now.
        await this.ensureProvisionAssets(ctx, record, instanceId);
        return this.ref(record, vmName);
      }
      // starting/stopping/error/unknown are transient or unsafe: never recreate
      // a VM whose disk may hold work — fail closed and let reconcile decide.
      throw new HarnessError('UNAVAILABLE', `workspace VM is in state '${status.state}' and cannot be activated safely`, 503, true);
    } catch (error) {
      if (recoverable || started) {
        await this.rollbackActivation(ident, instanceId, {
          stop: started || (recoverable && adopted),
          unlease: recoverable
        });
      }
      throw error;
    }
  }

  async stop(ctx: ProvisionContext): Promise<void> {
    const record = ctx.record;
    if (!record.backendInstanceId) return;
    try {
      await this.deps.client.leaseClear(this.identity(ctx), {
        timeoutMs: DEFAULT_CALL_TIMEOUT_MS,
        ...(ctx.signal ? { signal: ctx.signal } : {})
      });
    } catch {
      // Lease clear is best-effort at this seam; the watchdog is the hard backstop.
    }
    // Incus stop of a large disk can exceed the 120 s unary default (L5).
    await this.deps.client.vmStop(this.identity(ctx), {
      timeoutMs: LIFECYCLE_TIMEOUT_MS,
      ...(ctx.signal ? { signal: ctx.signal } : {})
    });
  }

  async destroy(ctx: ProvisionContext): Promise<void> {
    const record = ctx.record;
    if (!record.backendInstanceId) return;
    // Explicit close/teardown only — callers gate this on close policy. The
    // wire identity needs only the instance id; template fields are irrelevant
    // to deletion (confirmInstanceId is the authoritative guard).
    await this.deps.client.vmDelete(this.identity(ctx), { confirmInstanceId: record.backendInstanceId }, {
      idempotencyKey: `vm-${record.backendInstanceId}-delete`,
      timeoutMs: LIFECYCLE_TIMEOUT_MS,
      ...(ctx.signal ? { signal: ctx.signal } : {})
    });
    // L1: the vmName→identity binding is per-VM; a destroyed VM must not
    // keep resolving (a recycled name would adopt the wrong identity).
    this.identities.delete(this.vmName(record));
  }

  async inspect(ctx: ProvisionContext): Promise<ExecutorInspection> {
    const record = ctx.record;
    if (!record.backendInstanceId || !record.vmName) return { state: 'missing' };
    try {
      const status = await this.deps.client.vmStatus(this.identity(ctx));
      const observed = status.userCloudHarness;
      const identity = observed === undefined ? undefined : {
        instanceId: observed.instanceId,
        templateId: observed.templateId,
        templateDigest: observed.templateDigest
      };
      switch (status.state) {
        case 'running': return { state: 'running', ...(identity ? { identity } : {}) };
        case 'stopped':
        case 'frozen': return { state: 'stopped', ...(identity ? { identity } : {}) };
        case 'starting':
        case 'stopping':
        case 'error': return { state: 'unknown', ...(identity ? { identity } : {}) };
        case 'unknown': return { state: 'unknown', ...(identity ? { identity } : {}) };
      }
    } catch (error) {
      if (error instanceof VmSupervisorCallError && error.code === 'NOT_FOUND') return { state: 'missing' };
      return { state: 'unknown' };
    }
    return { state: 'unknown' };
  }

  /* ------------------------------------------------------------------ */
  /* Exec + streams                                                      */
  /* ------------------------------------------------------------------ */

  async exec(ctx: ProvisionContext, req: ExecRequest): Promise<ExecResult> {
    assertExecArgv(req.argv);
    const mode = req.executionMode ?? 'executor';
    validatedVmExecEnvironment(req.environment);
    const ident = this.identity(ctx);
    const bounds = clampExecBounds(req.timeoutMs, req.maxBytes);
    const opId = `op-${randomUUID()}`;
    const asRoot = req.user === 'root';
    try {
      const result = await this.deps.client.execRun(ident, {
        opId,
        // argv verbatim — the supervisor wraps workspace execs in runuser.
        argv: req.argv,
        ...(req.cwd !== undefined ? { cwd: req.cwd } : {}),
        // Canonical base env UNDER the caller map: caller wins on conflicts,
        // base guarantees PATH/HOME/tooling for env-poor callers (H3).
        environment: { ...GUEST_BASE_ENV, ...req.environment },
        ...(req.stdin !== undefined
          ? { stdinBase64: (typeof req.stdin === 'string' ? Buffer.from(req.stdin, 'utf8') : req.stdin).toString('base64') }
          : {}),
        timeoutMs: bounds.timeoutMs,
        maxBytes: bounds.maxBytes,
        // 'workspace' → supervisor runuser-wraps (initgroups → docker group);
        // 'root' → direct privileged exec, no wrap.
        user: asRoot ? GUEST_ROOT_USER : 'workspace',
        executionMode: mode
      }, {
        idempotencyKey: opId,
        // Wire deadline = guest timeout + bounded cleanup margin; the 120 s
        // unary default would kill any exec longer than two minutes (H2).
        timeoutMs: bounds.timeoutMs + EXEC_WIRE_DEADLINE_MARGIN_MS,
        ...(req.signal ? { signal: req.signal } : {})
      });
      return {
        exitCode: result.exitCode,
        signal: result.signal,
        stdout: result.stdout,
        stderr: result.stderr,
        truncated: result.truncated,
        timedOut: result.timedOut
      };
    } catch (error) {
      if (error instanceof VmSupervisorCallError && error.unknownOutcome) {
        return await this.reconcileExecOutcome(ctx, opId, error);
      }
      throw error;
    }
  }

  /**
   * Lost-reply reconcile for `exec.run`: `exec.inspect` reports the op's
   * journaled state. 'exited' means the command finished but its output was
   * lost with the reply — reported truncated rather than fabricated;
   * 'running'/'unknown' rethrow the original unknown-state error.
   */
  private async reconcileExecOutcome(ctx: ProvisionContext, opId: string, original: VmSupervisorCallError): Promise<ExecResult> {
    try {
      const inspected = await this.deps.client.execInspect(this.identity(ctx), { opId }, { timeoutMs: 15_000 });
      if (inspected.state === 'exited') {
        return {
          exitCode: inspected.exitCode ?? null,
          signal: null,
          stdout: '',
          stderr: '',
          truncated: true,
          timedOut: false
        };
      }
    } catch {
      // Inspect failure leaves the outcome unknown — fall through to rethrow.
    }
    throw original;
  }

  async spawnStream(ctx: ProvisionContext, req: StreamRequest): Promise<StreamHandle> {
    if (req.pty) {
      const terminalId = `stream-${randomBytes(6).toString('hex')}`;
      const connection = await this.pty(ctx).open({
        container: this.vmName(ctx.record),
        terminalId,
        workingDir: req.cwd ?? '/workspace',
        cols: req.pty.cols,
        rows: req.pty.rows
      });
      return new PtyStreamHandleAdapter(connection, () =>
        this.pty(ctx).killSession(this.vmName(ctx.record), terminalId)
      );
    }
    assertExecArgv(req.argv);
    validatedVmExecEnvironment(req.environment);
    const ident = this.identity(ctx);
    const sessionId = `stream-${randomUUID()}`.slice(0, 128);
    const session = await this.deps.client.execOpen(ident, {
      sessionId,
      argv: req.argv,
      ...(req.cwd !== undefined ? { cwd: req.cwd } : {}),
      // Same canonical merge as exec.run: base env under the caller map.
      environment: { ...GUEST_BASE_ENV, ...req.environment }
    });
    return new VmExecStreamHandle(this.deps.client, ident, session);
  }

  pty(ctx: ProvisionContext): PtyTransport {
    // Bind this workspace's identity up front so pty() callers that never ran
    // another verb still resolve correctly; the transport looks up by vmName.
    this.wireIdentity(ctx.record);
    this.ptyClient ??= this.deps.ptyTransport ?? new IncusPtyTransport(
      this.deps.client,
      (container) => {
        const identity = this.identities.get(container);
        if (!identity) {
          throw new HarnessError('UNAVAILABLE', 'workspace VM identity is not known to this backend', 503, true);
        }
        return identity;
      }
    );
    return this.ptyClient;
  }

  /* ------------------------------------------------------------------ */
  /* Files + trees (bounded, streamed, digest-verified)                  */
  /* ------------------------------------------------------------------ */

  async pullFile(ctx: ProvisionContext, guestPath: string, maxBytes: number): Promise<Buffer> {
    // H4: inline only while the base64 response stays under the 1 MiB control
    // cap — 720 KiB frozen bound, further tightened by vmInlineMaxBytes.
    const inlineMax = Math.min(
      this.config.vmInlineMaxBytes ?? FILE_PULL_INLINE_SAFE_MAX_BYTES,
      FILE_PULL_INLINE_SAFE_MAX_BYTES
    );
    if (maxBytes <= inlineMax) {
      const result = await this.deps.client.filePull(this.identity(ctx), { guestPath, maxBytes }, {
        timeoutMs: DEFAULT_CALL_TIMEOUT_MS,
        ...(ctx.signal ? { signal: ctx.signal } : {})
      });
      return Buffer.from(result.dataBase64, 'base64');
    }
    return this.pullFileStreamed(ctx, guestPath, maxBytes);
  }

  /**
   * `file.pull` is inline-capped, but callers legitimately pull larger files
   * (artifact snapshots, bundle staging). The streamed path reuses the
   * bounded `pullTree` channel: the supervisor tars `-C parent basename` — one
   * member for a regular file — and the host extracts that single member into
   * a scratch dir. `maxBytes` bounds the caller-visible file; the tar stream
   * bound gets framing slack so headers never clip a file that fits.
   * Staging lives under the workspace job dir (disk-backed — never tmpfs).
   */
  private async pullFileStreamed(ctx: ProvisionContext, guestPath: string, maxBytes: number): Promise<Buffer> {
    const base = guestPath.slice(guestPath.lastIndexOf('/') + 1);
    if (base === '' || base === '.' || base === '..' || base.includes('/')) {
      throw new HarnessError('INVALID_INPUT', 'streamed pullFile requires a single file path', 400, false);
    }
    const streamMax = Math.min(maxBytes + FILE_PULL_TAR_SLACK_BYTES, PULL_TREE_STREAM_MAX_BYTES);
    const staging = await this.stagingDir(ctx, 'pull-file');
    const extractDir = join(staging, 'extract');
    const tarPath = join(staging, 'tree.tar');
    const writer = createGuardedFileWriter(tarPath);
    const releaseReservation = await stagingReservations.acquire(tarPath, staging, streamMax + maxBytes);
    try {
      await this.deps.client.pullTree(this.identity(ctx), { guestPath, maxBytes: streamMax }, {
        sink: writer.sink,
        timeoutMs: TAR_TIMEOUT_MS,
        ...(ctx.signal ? { signal: ctx.signal } : {})
      });
      await writer.finish();
      throwIfAborted(ctx.signal);
      await mkdir(extractDir, { recursive: true });
      await runTar(['-xf', tarPath, '-C', extractDir, '--no-same-owner'], TAR_TIMEOUT_MS, ctx.signal);
      throwIfAborted(ctx.signal);
      // M9: the archive must contain EXACTLY the requested member — anything
      // else means the guest tar carried unexpected entries.
      const members = await readdir(extractDir);
      if (members.length !== 1 || members[0] !== base) {
        throw new HarnessError('INVALID_INPUT', 'pulled archive did not contain exactly the requested file', 400, false);
      }
      const filePath = join(extractDir, base);
      // lstat, not stat: a guest symlink must never resolve to a host path.
      const info = await lstat(filePath).catch(() => undefined);
      if (!info?.isFile()) {
        throw new HarnessError('INVALID_INPUT', 'guest path is not a regular file', 400, false);
      }
      if (info.size > maxBytes) {
        throw new HarnessError('LIMIT_EXCEEDED', 'pulled file exceeds maxBytes', 413, false);
      }
      return await readFile(filePath);
    } finally {
      releaseReservation();
      writer.stream.destroy();
      await rm(staging, { recursive: true, force: true }).catch(() => undefined);
    }
  }

  /** Disk-backed staging under the workspace job dir — never tmpfs for big archives. */
  private async stagingDir(ctx: ProvisionContext, prefix: string): Promise<string> {
    const root = ctx.record.workspacePath;
    await mkdir(root, { recursive: true });
    return mkdtemp(join(root, `.${prefix}-`));
  }

  /**
   * Streams `hostDir`'s contents as a tar through `pushTree`. The tar digest
   * is computed BEFORE the request (the supervisor verifies params.sha256
   * against the staged bytes), so the archive is materialized under the
   * workspace job dir first and removed afterwards.
   */
  async pushTree(ctx: ProvisionContext, hostDir: string, guestPath: string): Promise<{ sha256: string; bytes: number; entryCount: number }> {
    if (!(await isDirectory(hostDir))) {
      throw new HarnessError('INVALID_INPUT', 'pushTree source must be a host directory', 400, false);
    }
    if (!guestPath.startsWith('/')) {
      throw new HarnessError('INVALID_INPUT', 'guest path must be executor-absolute', 400, false);
    }
    const record = ctx.record;
    await mkdir(record.workspacePath, { recursive: true });
    const staging = await mkdtemp(join(record.workspacePath, '.push-tree-'));
    const tarPath = join(staging, 'tree.tar');
    // Reserve the wire bound BEFORE tar creation (M12): creation is capped
    // DURING the write — exceeding the bound SIGKILLs tar and rejects, so
    // staging never materializes more than ~bound bytes regardless of the
    // hostDir's true size.
    const releaseReservation = await stagingReservations.acquire(tarPath, staging, this.config.vmMaxWorkspaceBytes);
    try {
      throwIfAborted(ctx.signal);
      await tarCreateToFile(hostDir, tarPath, this.config.vmMaxWorkspaceBytes, {
        timeoutMs: TAR_TIMEOUT_MS,
        ...(ctx.signal ? { signal: ctx.signal } : {})
      });
      throwIfAborted(ctx.signal);
      const { sha256, bytes } = await hashFile(tarPath);
      if (bytes > this.config.vmMaxWorkspaceBytes) {
        throw new HarnessError('LIMIT_EXCEEDED', 'pushTree archive exceeds the workspace byte bound', 413, false);
      }
      const trailer = await this.deps.client.pushTree(this.identity(ctx), {
        guestPath,
        maxBytes: this.config.vmMaxWorkspaceBytes,
        sha256,
        mode: 0o755,
        uid: WORKSPACE_UID,
        gid: WORKSPACE_UID
      }, createReadStream(tarPath), {
        idempotencyKey: `push-${randomUUID()}`,
        timeoutMs: TAR_TIMEOUT_MS,
        ...(ctx.signal ? { signal: ctx.signal } : {})
      });
      return { sha256: trailer.sha256, bytes: trailer.bytes, entryCount: trailer.entryCount };
    } finally {
      releaseReservation();
      await rm(staging, { recursive: true, force: true }).catch(() => undefined);
    }
  }

  /**
   * Streams the guest tar into a disk-backed staging file, extracts CONTENTS
   * into a scratch dir (`--strip-components=1` drops the guest dir's own
   * name), audits every materialized entry for host containment, and only
   * then copies into `hostDir` — a hostile guest tar can never plant a
   * symlink or exotic node that escapes the destination (M9).
   */
  async pullTree(ctx: ProvisionContext, guestPath: string, hostDir: string): Promise<{ sha256: string; bytes: number; entryCount: number }> {
    if (!guestPath.startsWith('/')) {
      throw new HarnessError('INVALID_INPUT', 'guest path must be executor-absolute', 400, false);
    }
    // pullTree tars a directory tree; a non-directory guestPath would produce
    // a single-member archive that silently violates the tree contract.
    const guestStat = await this.deps.client.fileStat(this.identity(ctx), { guestPath }, {
      timeoutMs: DEFAULT_CALL_TIMEOUT_MS,
      ...(ctx.signal ? { signal: ctx.signal } : {})
    });
    if (!guestStat.isDir) {
      throw new HarnessError('INVALID_INPUT', 'pullTree guest path is not a directory', 400, false);
    }
    const maxBytes = this.config.vmMaxWorkspaceBytes;
    const staging = await this.stagingDir(ctx, 'pull-tree');
    const extractDir = join(staging, 'extract');
    const tarPath = join(staging, 'tree.tar');
    const writer = createGuardedFileWriter(tarPath);
    const releaseReservation = await stagingReservations.acquire(tarPath, staging, maxBytes * 2);
    try {
      const trailer = await this.deps.client.pullTree(this.identity(ctx), {
        guestPath,
        maxBytes
      }, {
        sink: writer.sink,
        timeoutMs: TAR_TIMEOUT_MS,
        ...(ctx.signal ? { signal: ctx.signal } : {})
      });
      await writer.finish();
      throwIfAborted(ctx.signal);
      await mkdir(extractDir, { recursive: true });
      await runTar(['-xf', tarPath, '-C', extractDir, '--strip-components=1', '--no-same-owner'], TAR_TIMEOUT_MS, ctx.signal);
      throwIfAborted(ctx.signal);
      await assertExtractedTreeContained(extractDir);
      throwIfAborted(ctx.signal);
      await mkdir(hostDir, { recursive: true });
      for (const entry of await readdir(extractDir)) {
        await cp(join(extractDir, entry), join(hostDir, entry), { recursive: true, force: true });
      }
      return { sha256: trailer.sha256, bytes: trailer.bytes, entryCount: trailer.entryCount };
    } finally {
      releaseReservation();
      writer.stream.destroy();
      await rm(staging, { recursive: true, force: true }).catch(() => undefined);
    }
  }

  /* ------------------------------------------------------------------ */
  /* Measurement + process control                                       */
  /* ------------------------------------------------------------------ */

  /** guest-df.sh keeps the docker `du -sb --apparent-size` 3-path contract. */
  async measureWorkspaceBytes(ctx: ProvisionContext): Promise<number> {
    const result = await this.exec(ctx, {
      argv: ['/usr/local/bin/guest-df.sh'],
      cwd: '/',
      environment: { ...GUEST_BASE_ENV },
      timeoutMs: 30_000,
      maxBytes: 8_192,
      user: 'workspace',
      ...(ctx.signal ? { signal: ctx.signal } : {})
    });
    if (result.exitCode !== 0) {
      throw new HarnessError('UNAVAILABLE', 'workspace size could not be measured safely', 503, true);
    }
    let totalBytes = 0;
    for (const line of result.stdout.trim().split('\n')) {
      const bytes = Number(line.trim().split(/\s+/, 1)[0]);
      if (Number.isSafeInteger(bytes) && bytes >= 0) totalBytes += bytes;
    }
    return totalBytes;
  }

  /** Guest kill-session.sh mirrors the docker process-group TERM→KILL ladder. */
  async killProcessGroup(ctx: ProvisionContext, pidFile: string): Promise<void> {
    const result = await this.exec(ctx, {
      argv: ['/usr/local/bin/kill-session.sh', pidFile],
      cwd: '/',
      environment: { ...GUEST_BASE_ENV },
      timeoutMs: 15_000,
      maxBytes: 8_192,
      user: 'workspace',
      ...(ctx.signal ? { signal: ctx.signal } : {})
    });
    if (result.exitCode !== 0) {
      throw new HarnessError('UNAVAILABLE', 'workspace process group could not be terminated', 503, true);
    }
  }

  capabilities(): BackendCapabilityMap {
    return { ...INCUS_VM_BACKEND_CAPABILITIES };
  }
}

/** PtyStreamHandle parity with the docker adapter: stderr is inert under a PTY. */
class PtyStreamHandleAdapter extends EventEmitter implements StreamHandle {
  readonly stdin: Writable;
  readonly stdout: Readable;
  readonly stderr: Readable;
  private closed = false;

  constructor(
    private readonly connection: PtyConnection,
    private readonly endSession: () => Promise<void>
  ) {
    super();
    this.stdin = new Writable({
      write: (chunk: Buffer, _encoding, callback) => {
        try {
          this.connection.write(chunk);
          callback();
        } catch (error) {
          callback(error instanceof Error ? error : new Error(String(error)));
        }
      }
    });
    this.stdout = new Readable({ read: () => undefined });
    this.stderr = new Readable({ read: () => undefined });
    this.connection.onData((chunk) => this.stdout.push(chunk));
    this.connection.onEnd((end) => {
      this.stdout.push(null);
      this.stderr.push(null);
      this.finish(end.error ?? null);
    });
  }

  kill(): boolean {
    if (this.closed) return false;
    try { this.connection.close(); } catch { /* already closed */ }
    void this.endSession().catch(() => undefined);
    return true;
  }

  private finish(error: Error | null): void {
    if (this.closed) return;
    this.closed = true;
    if (error) this.emit('error', error);
    this.emit('close', null, null);
  }
}
