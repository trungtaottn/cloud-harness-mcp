import { AsyncLocalStorage } from 'node:async_hooks';
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { constants } from 'node:fs';
import { access, lstat, mkdir, open, realpath, stat } from 'node:fs/promises';
import type { FileHandle } from 'node:fs/promises';
import { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { VmNetworkGuardError } from '../network-ops.js';

/**
 * Cross-process mutual exclusion for guard mutations.
 *
 * The supervisor's in-process `serialize()` queue cannot order mutations
 * against the independent guard service (separate process, same host). Both
 * sides take THIS lock around every kernel/claim mutation so a guard cycle
 * can never act on an assessment that a concurrent program/tearDown/
 * quarantine has already invalidated — convergence-after-the-fact is not
 * sufficient during managed transitions.
 *
 * Primitive: kernel `flock(2)` on a STABLE, never-unlinked inode.
 * `<workDir>/guard.flock` is a regular file created once and NEVER removed
 * or renamed by this code — there is no owner metadata, no publication
 * protocol, no stale-breaking, no PID liveness question. Acquisition opens
 * the file, passes the parent-owned descriptor to `/usr/bin/flock` (trusted
 * absolute path — util-linux flock; availability is verified per-acquire
 * and surfaces as typed 'guard-lock-helper-missing', never assumed), which
 * `flock(LOCK_EX)`s the SHARED open file description and exits. The lock is
 * held by the description, which stays open through the parent's FileHandle
 * for the entire callback; the kernel releases it automatically when the
 * last fd closes — process exit, crash or SIGKILL included. There is no
 * grace period, no ownerless window, no rename gap: a live critical section
 * can never be displaced, and a dead one frees the lock instantly.
 *
 * Why the fd form and not `flock <path>`: a path argument makes the helper
 * open its OWN description, so its lock would die with the helper. Passing
 * the descriptor binds the lock to the parent's description — the holder
 * is this process for exactly the callback's duration.
 *
 * Legacy protocol refusal: the pre-flock implementation used a DIRECTORY
 * `<workDir>/guard.lock` with owner.json. It is NEVER unlinked, renamed or
 * replaced automatically — an old worker may still hold it. Any presence of
 * that name fails closed with 'guard-lock-legacy-present' and explicit
 * manual migration instructions; the two protocols never run as parallel
 * mutexes. Migration is operational: stop BOTH units, confirm no holder
 * remains, preserve the directory aside for review (mv, never rm -rf), then
 * start the upgraded units.
 *
 * Residuals (documented, single-owner host):
 *  - The post-acquire lstat inode/mode check detects replacement DURING
 *    acquire. It cannot prevent an arbitrary later host-root unlink/
 *    recreate — a root actor owns the host anyway and is outside the guard
 *    threat model.
 *  - A flock helper orphaned by parent death mid-wait lives at most the
 *    remaining `-w` budget (≤ timeoutMs), then exits; it runs no user code
 *    and its transient hold is bounded and harmless.
 *  - flock(2) requires a local filesystem; the state dir is `/run`
 *    (tmpfs), never NFS.
 *  - If the helper cannot be proven dead within REAP_TIMEOUT_MS after a
 *    kill, the acquire fails 'guard-lock-reap-failed' and the parent fd is
 *    DELIBERATELY left open — the lock stays held (fail-closed) rather than
 *    risk an orphaned helper acquiring later with no owner. The leak
 *    resolves on process exit; it is the safe direction.
 */

export interface GuardLockOptions {
  /**
   * Max time for the WHOLE acquire — canonicalization, helper preflight,
   * spawn and kernel wait measured on a monotonic clock. Default 120s. A
   * timeout NEVER revokes a live holder: contenders fail closed with
   * 'guard-lock-timeout' and a wedged holder requires the holder's
   * process to exit (the kernel then releases instantly) or operator
   * recovery.
   */
  readonly timeoutMs?: number;
  /**
   * Test-only override for the flock helper path. Production never sets
   * this — the trusted absolute default is used so PATH hijacking cannot
   * substitute a helper.
   */
  readonly helperPath?: string;
  /**
   * Test-only probe invoked AFTER the flock wait succeeds and BEFORE the
   * post-acquire inode/legacy verification — it marks the exact window a
   * test needs to swap the lock inode deterministically. Production never
   * sets this; it performs no I/O and changes no decision.
   */
  readonly afterFlockAcquire?: () => void | Promise<void>;
}

/** Trusted absolute helper — never PATH-resolved. */
export const FLOCK_HELPER_PATH = '/usr/bin/flock';
const FLOCK_LOCK_NAME = 'guard.flock';
const LEGACY_LOCK_NAME = 'guard.lock';
const DEFAULT_TIMEOUT_MS = 120_000;
const REAP_TIMEOUT_MS = 2_000;
const MAX_HELPER_STDERR = 4096;

export function guardFlockPath(workDir: string): string {
  return join(workDir, FLOCK_LOCK_NAME);
}

/** Path of the retired directory-protocol lock — presence means REFUSE. */
export function legacyGuardLockPath(workDir: string): string {
  return join(workDir, LEGACY_LOCK_NAME);
}

/**
 * In-process reentrancy guard. The ALS store is a MAP from canonical lock
 * path to a shared active-token, INHERITED down the async context — so a
 * nested withGuardLock sees EVERY ancestor hold, not just the innermost:
 * withGuardLock(A) → withGuardLock(B) → withGuardLock(A) still rejects
 * 'guard-lock-reentrant' instead of self-deadlocking on the kernel lock
 * this process already holds (A-B-A). Each level adds its own token to the
 * shared map; release sets `active=false` then deletes the key, so a
 * detached timer/task created inside the callback sees an inactive/absent
 * token after release — it neither false-rejects nor bypasses: it proceeds
 * to a REAL flock acquisition, kernel-serialized against any holder.
 * Sibling same-process contenders see no store and contend through flock(2).
 * Paths are canonicalized via realpath so alias spellings of the same
 * directory cannot evade the check.
 */
interface HeldScope {
  active: boolean;
}
const heldContext = new AsyncLocalStorage<Map<string, HeldScope>>();

/**
 * FileHandles deliberately retained after an unproven reap. The fd MUST
 * stay referenced for the process lifetime: an unreferenced FileHandle is
 * GC-closed (error + lock release), which would silently undo the
 * fail-closed retain. The kernel closes every fd at process exit anyway,
 * so this set can never outlive the holder — it only prevents premature
 * collection. Entries are never removed by design.
 */
const retainedFds = new Set<FileHandle>();

function lockError(reason: string, message: string): VmNetworkGuardError {
  return new VmNetworkGuardError(reason, message);
}

/**
 * The retired directory-protocol lock must be ABSENT before we take the
 * flock mutex — running both protocols in parallel would admit concurrent
 * mutations. lstat (not stat) so a symlink also counts as presence. An
 * unverifiable check fails closed: we cannot prove the legacy lock is gone,
 * so we must not run.
 */
async function assertNoLegacyLock(workDir: string): Promise<void> {
  const legacy = join(workDir, LEGACY_LOCK_NAME);
  try {
    await lstat(legacy);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw lockError(
      'guard-lock-legacy-check',
      `cannot verify absence of legacy guard lock '${legacy}': ${error instanceof Error ? error.message : String(error)}`
    );
  }
  throw lockError(
    'guard-lock-legacy-present',
    `legacy protocol lock '${legacy}' still exists — refusing to start a second mutex protocol. ` +
      `Migrate manually: stop cloudharness-vm-supervisor and cloud-harness-vm-guard, ` +
      `confirm no holder process remains, preserve the directory aside for operator review ` +
      `(mv '${LEGACY_LOCK_NAME}' '${LEGACY_LOCK_NAME}.retired-<timestamp>'), then start the upgraded units.`
  );
}

/** Preflight the trusted helper — absence is a typed fail-closed error, never an assumption. */
async function assertFlockHelper(helperPath: string): Promise<void> {
  try {
    const s = await stat(helperPath);
    if (!s.isFile()) throw new Error('not a regular file');
    await access(helperPath, constants.X_OK);
  } catch (error) {
    throw lockError(
      'guard-lock-helper-missing',
      `flock helper '${helperPath}' unavailable: ${error instanceof Error ? error.message : String(error)} — util-linux flock is required`
    );
  }
}

/**
 * Open the stable lock inode. O_NOFOLLOW rejects a symlink at open; the
 * file is created 0600 if absent and NEVER unlinked by this code — inode
 * stability is the lock's identity.
 */
async function openFlockFile(lockPath: string): Promise<FileHandle> {
  try {
    return await open(lockPath, constants.O_RDWR | constants.O_CREAT | constants.O_NOFOLLOW, 0o600);
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ELOOP' || code === 'EMLINK') {
      throw lockError('guard-lock-symlink', `guard lock '${lockPath}' is a symlink — refusing`);
    }
    throw lockError('guard-lock-open', `cannot open guard lock '${lockPath}': ${error instanceof Error ? error.message : String(error)}`);
  }
}

interface FlockWaitResult {
  acquired: boolean;
  /** 'deadline' | 'reap-failed' | 'timeout' | 'spawn' | exit detail */
  detail?: string;
  stderr?: string;
}

/**
 * SIGKILL and PROVE the flock waiter dead before returning. The helper
 * shares our open file description — if it outlived us it could acquire
 * the lock later with no parent awareness. Returns false when exit cannot
 * be confirmed inside REAP_TIMEOUT_MS: callers must then retain the parent
 * fd (fail-closed — the lock stays held rather than risk an orphaned
 * acquirer). The reap timer is always cleared so no dangling handle
 * survives a won race.
 */
async function terminateAndReap(child: ChildProcess): Promise<boolean> {
  if (child.exitCode !== null || child.signalCode !== null) return true;
  // A late 'error' (kill failure, spawn fallout) must never crash the
  // process as an unhandled event while we are proving death.
  child.on('error', () => undefined);
  child.kill('SIGKILL');
  let timer: NodeJS.Timeout | undefined;
  const reaped = await new Promise<boolean>((resolve) => {
    timer = setTimeout(() => resolve(false), REAP_TIMEOUT_MS);
    // 'exit' covers the normal kill path; 'close' additionally covers
    // spawn-failed children, which never emit 'exit' but always close
    // their (empty) stdio — without it a failed spawn would look like an
    // unproven reap and wedge the fd forever.
    child.once('exit', () => resolve(true));
    child.once('close', () => resolve(true));
  });
  if (timer !== undefined) clearTimeout(timer);
  return reaped;
}

/**
 * Spawn `/usr/bin/flock -x -w <ceil(waitMs/1000)> 3` with the lock fd passed
 * as child fd 3 (stdio index 3 → same fd number in the child). The helper
 * blocks up to the kernel wait, exits 0 on acquire, 1 on timeout. The Node
 * deadline (monotonic, includes spawn time) is enforced independently: on
 * expiry we kill+reap BEFORE reporting — the helper can never be left
 * running to acquire after we return.
 */
async function waitFlockChild(child: ChildProcess, deadlineAt: number): Promise<FlockWaitResult> {
  let stderr = '';
  child.stderr?.on('data', (chunk: Buffer | string) => {
    if (stderr.length < MAX_HELPER_STDERR) stderr += String(chunk);
  });
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null; spawnError: boolean }>((resolve) => {
    let done = false;
    const fin = (r: { code: number | null; signal: NodeJS.Signals | null; spawnError: boolean }) => {
      if (!done) {
        done = true;
        resolve(r);
      }
    };
    child.once('error', () => fin({ code: null, signal: null, spawnError: true }));
    child.once('exit', (code, signal) => fin({ code, signal, spawnError: false }));
  });
  const leftMs = deadlineAt - performance.now();
  let timer: NodeJS.Timeout | undefined;
  const deadlineHit = new Promise<{ kind: 'deadline' }>((resolve) => {
    timer = setTimeout(() => resolve({ kind: 'deadline' }), Math.max(1, leftMs));
    timer.unref?.();
  });
  const winner = await Promise.race([exited.then((r) => ({ kind: 'exit' as const, ...r })), deadlineHit]);
  if (timer !== undefined) clearTimeout(timer);
  if (winner.kind === 'deadline') {
    const reaped = await terminateAndReap(child);
    return reaped ? { acquired: false, detail: 'deadline' } : { acquired: false, detail: 'reap-failed' };
  }
  if (winner.spawnError) return { acquired: false, detail: 'spawn', stderr };
  if (winner.code === 0) return { acquired: true };
  return {
    acquired: false,
    detail: winner.code === 1 ? 'timeout' : `exit:${winner.code ?? winner.signal ?? 'unknown'}`,
    stderr
  };
}

function spawnFlockWaiter(helperPath: string, fd: number, waitMs: number): ChildProcess {
  // Integer-second ceiling: flock -w accepts whole seconds on all
  // util-linux versions; the precise bound is the Node monotonic deadline,
  // which kills+reaps the helper if it outlives the budget.
  const waitSec = Math.max(1, Math.ceil(waitMs / 1000));
  return spawn(helperPath, ['-x', '-w', String(waitSec), '3'], {
    stdio: ['ignore', 'ignore', 'pipe', fd]
  });
}

/**
 * Post-acquire verification, run BEFORE fn: the legacy dir must still be
 * absent (it could have appeared during the wait) and the path must still
 * lstat-resolve to the exact inode+mode we hold — a swapped lock file means
 * our flock guards an orphan inode while a replacement admits a second
 * holder. lstat (never stat) so a symlink planted at the path is rejected
 * rather than followed onto a different inode.
 */
async function assertFlockIdentity(fh: FileHandle, lockPath: string, workDir: string): Promise<void> {
  await assertNoLegacyLock(workDir);
  let fdStat;
  let pathStat;
  try {
    [fdStat, pathStat] = await Promise.all([fh.stat(), lstat(lockPath)]);
  } catch (error) {
    throw lockError(
      'guard-lock-replaced',
      `guard lock '${lockPath}' vanished during acquire: ${error instanceof Error ? error.message : String(error)}`
    );
  }
  if (
    !fdStat.isFile() ||
    !pathStat.isFile() ||
    pathStat.isSymbolicLink() ||
    fdStat.dev !== pathStat.dev ||
    fdStat.ino !== pathStat.ino ||
    fdStat.mode !== pathStat.mode
  ) {
    throw lockError('guard-lock-replaced', `guard lock '${lockPath}' was replaced during acquire — refusing to run on an orphan inode`);
  }
}

/**
 * Run `fn` while holding the cross-process guard lock for `workDir`.
 *
 * Throws VmNetworkGuardError:
 *  - 'guard-lock-reentrant'   — same canonical lock already held in THIS
 *    async context (any ancestor level — A-B-A included)
 *  - 'guard-lock-legacy-present' / 'guard-lock-legacy-check' — retired
 *    directory protocol detected; manual migration required (fail closed,
 *    never auto-removed, never run as a parallel mutex)
 *  - 'guard-lock-helper-missing' — flock helper absent or not executable
 *  - 'guard-lock-symlink' / 'guard-lock-open' — lock path unusable
 *  - 'guard-lock-replaced'    — inode/mode changed during acquire
 *  - 'guard-lock-timeout'     — bounded wait expired; a live holder is
 *    NEVER stolen — the kernel releases only when its process dies
 *  - 'guard-lock-reap-failed' — helper kill could not be proven; the lock
 *    fd is retained (fail-closed) rather than risk an orphaned acquirer
 * `fn` never runs in any failure case.
 */
export async function withGuardLock<T>(workDir: string, fn: () => Promise<T>, options: GuardLockOptions = {}): Promise<T> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const helperPath = options.helperPath ?? FLOCK_HELPER_PATH;
  // Monotonic deadline covers canonicalization + preflight + spawn + kernel
  // wait — clock jumps cannot extend or shrink the admission bound.
  const deadlineAt = performance.now() + timeoutMs;

  // The state dir may not exist yet (fresh /run tmpfs after reboot).
  await mkdir(workDir, { recursive: true });
  // Canonicalize so alias spellings (symlinked/relative workDir) share ONE
  // reentrancy key and ONE inode identity.
  let canonDir: string;
  try {
    canonDir = await realpath(workDir);
  } catch (error) {
    throw lockError('guard-lock-open', `cannot canonicalize guard state dir '${workDir}': ${error instanceof Error ? error.message : String(error)}`);
  }
  const lockPath = join(canonDir, FLOCK_LOCK_NAME);

  const scopes = heldContext.getStore();
  if (scopes?.get(lockPath)?.active === true) {
    throw lockError('guard-lock-reentrant', `guard lock '${lockPath}' is already held by this async context`);
  }

  await assertNoLegacyLock(canonDir);
  await assertFlockHelper(helperPath);

  const fh = await openFlockFile(lockPath);
  let fdClosed = false;
  const releaseFd = async (): Promise<void> => {
    if (fdClosed) return;
    fdClosed = true;
    // Last close of the description drops the kernel lock. close() on a
    // valid FileHandle cannot meaningfully fail; a leaked fd would hold
    // the lock until process exit anyway — the safe direction.
    await fh.close().catch(() => undefined);
  };

  let child: ChildProcess | undefined;
  // Reap-failure is fail-closed: the helper's liveness is unproven, so the
  // parent fd is deliberately retained — the lock stays held (contenders
  // time out) rather than risk an orphaned acquirer with no owner.
  let retainFd = false;
  try {
    const remainingMs = deadlineAt - performance.now();
    if (remainingMs <= 0) {
      throw lockError('guard-lock-timeout', `timed out after ${timeoutMs}ms waiting for guard lock '${lockPath}'`);
    }
    child = spawnFlockWaiter(helperPath, fh.fd, remainingMs);
    const outcome = await waitFlockChild(child, deadlineAt);
    if (!outcome.acquired) {
      if (outcome.detail === 'reap-failed') {
        retainFd = true;
        throw lockError(
          'guard-lock-reap-failed',
          `flock helper for '${lockPath}' could not be proven dead — retaining the lock fd fail-closed`
        );
      }
      const detail = outcome.stderr !== undefined && outcome.stderr.trim() !== '' ? `: ${outcome.stderr.trim().slice(0, 200)}` : '';
      if (outcome.detail === 'spawn') {
        throw lockError('guard-lock-helper-missing', `flock helper '${helperPath}' failed to spawn${detail}`);
      }
      throw lockError('guard-lock-timeout', `timed out after ${timeoutMs}ms waiting for guard lock '${lockPath}'${detail}`);
    }
    // The waiter exited 0 — it is already reaped; nothing left to kill.
    child = undefined;

    await options.afterFlockAcquire?.();
    await assertFlockIdentity(fh, lockPath, canonDir);

    const scope: HeldScope = { active: true };
    // Copy-on-write: ALS propagates the SAME store object to every async
    // branch descended from `fn`, so mutating `scopes` in place would leak
    // this hold into sibling contexts — a parallel sibling requesting the
    // same lock would false-'guard-lock-reentrant' instead of waiting on
    // the kernel flock. A fresh map keeps reentrancy ancestor-scoped: this
    // context and its descendants see the hold; siblings do not.
    const childScopes = scopes === undefined ? new Map<string, HeldScope>() : new Map(scopes);
    childScopes.set(lockPath, scope);
    try {
      return await heldContext.run(childScopes, fn);
    } finally {
      // Deactivate + remove BEFORE releasing the fd: a detached task waking
      // in this window sees no active token and takes the real flock path
      // rather than false-rejecting — and can never bypass an active hold.
      scope.active = false;
      childScopes.delete(lockPath);
      await releaseFd();
    }
  } finally {
    // Ordering is the safety property: the helper must be dead+reaped
    // BEFORE the parent fd closes, or it could acquire later and retain a
    // lock nobody owns. An unproven reap retains the fd fail-closed.
    if (child !== undefined && !(await terminateAndReap(child))) {
      retainFd = true;
    }
    if (retainFd) {
      retainedFds.add(fh);
    } else {
      await releaseFd();
    }
  }
}
