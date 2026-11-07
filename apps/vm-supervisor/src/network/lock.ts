import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { mkdir, readdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
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
 * Primitive: `mkdir` is atomic on POSIX, so the lock is a directory
 * `<workDir>/guard.lock` containing `owner.json` {pid, startedAt, nonce}.
 * Ownership is established atomically: `owner.json` is created with
 * `flag:'wx'` (O_EXCL) so exactly ONE acquirer can ever publish metadata in
 * a given directory — a stale-broken-then-recreated dir fails the second
 * publisher closed instead of double-owning. The publishing process also
 * records the directory inode before/after the write and read-back verifies
 * the owner token, so a dir swapped mid-acquire is detected, never run.
 *
 * Release is ownership-verified by rename-aside: `guard.lock` is moved to a
 * unique trash name (atomic capture of whatever sits at the path), the
 * moved owner is compared against THIS holder's token, and only a match is
 * removed — a replacement live lock is restored untouched. This closes the
 * check-then-rm TOCTOU: release can never delete another process's lock.
 *
 * Stale-breaking is deliberately conservative (P1): a held lock is broken
 * ONLY when its owner is conclusively gone —
 *   - owner.json ABSENT past ownerlessGraceMs: an orphaned mkdir from a
 *     crashed acquirer, or a holder stalled mid-publish. Proven safe: the
 *     displaced acquirer's O_EXCL publish/verify fails closed and fn never
 *     runs (S3 probe), so no live holder is ever displaced this way.
 *   - owner.json VALID with a DEAD pid (kill(pid,0) → ESRCH): the holder
 *     process cannot be running fn.
 * A lock with a LIVE pid is NEVER broken — not on age, not on wall-clock
 * `startedAt`, not on any max-hold heuristic. Clock jumps (NTP slew, VM
 * snapshot/resume) and legitimately long callbacks (withStartTransaction
 * holds through incus.waitOperation) cannot steal it; waiters simply hit
 * `guard-lock-timeout` and a wedged holder requires OPERATOR recovery —
 * and recovery is ONLY valid once the holder is verified gone: kill the
 * holder process and confirm it has exited (the dead-pid break then
 * applies), or for the managed guard service stop the unit first so no
 * in-flight mutation can still be running and its state is controlled.
 * Removing `guard.lock` by hand while any holder process is alive — or
 * while the managed service state is uncontrolled — can admit a second
 * concurrent mutation; NEVER remove a live lock.
 * PID reuse reads as alive → retained (fail-closed availability loss,
 * never a safety breach). A corrupt/unparseable owner.json is UNVERIFIABLE
 * → also retained forever; it cannot be distinguished from a live holder
 * whose metadata was damaged, so it is never auto-broken.
 *
 * Residuals (documented, single-owner host):
 *  - If OUR lock was reclaimed while fn() still ran (only possible via the
 *    ownerless-grace path before publish completed — fn cannot have
 *    started — or dead-pid misdetection, which requires our pid to have
 *    died, i.e. fn is not running), release moves the replacement aside,
 *    sees the foreign owner and restores it. Should a new acquirer grab
 *    `guard.lock` inside that ~ms restore gap, the restore rename fails
 *    and the foreign lock is stranded at `guard.lock.release-*` — it is
 *    NEVER deleted by the releaser; the bounded trash sweep removes such
 *    dirs only after trashMaxAgeMs (default 24h), by which point the
 *    creating operation has certainly finished.
 *  - The release rename-aside leaves `guard.lock` absent for the
 *    read-owner-then-decide window. While live holders are never
 *    displaced, the foreign-restore path that gap protects is
 *    unreachable; it remains as defense-in-depth.
 */

export interface GuardLockIo {
  writeFile: typeof writeFile;
}

export interface GuardLockOptions {
  /** Max time to wait for the lock before failing closed. Default 120s. */
  timeoutMs?: number;
  /** Poll interval while waiting. Default 50ms. */
  pollMs?: number;
  /** Grace period before an ownerless lock dir may be broken. Default 2s. */
  ownerlessGraceMs?: number;
  /**
   * Age after which stranded `guard.lock.stale-*`/`guard.lock.release-*`
   * trash dirs are swept. Default 24h. These dirs are never lock targets;
   * sweeping is best-effort cosmetic cleanup of abandoned renames.
   */
  trashMaxAgeMs?: number;
  /**
   * Test-only filesystem override for the owner-metadata write. Production
   * callers never set this; it exists so tests can force the N2 failure
   * (ENOSPC/EACCES) deterministically.
   */
  io?: Partial<GuardLockIo>;
}

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_POLL_MS = 50;
const DEFAULT_OWNERLESS_GRACE_MS = 2_000;
const DEFAULT_TRASH_MAX_AGE_MS = 24 * 60 * 60_000;
const TRASH_PREFIXES = ['guard.lock.stale-', 'guard.lock.release-'];

export function guardLockDir(workDir: string): string {
  return join(workDir, 'guard.lock');
}

interface LockOwner {
  pid: number;
  startedAt: number;
  nonce: string;
}

interface LockDirId {
  dev: number;
  ino: number;
}

/**
 * Tri-state classification of whatever sits at the lock path:
 *  - absent:  no owner.json — ownerless (mid-acquire or orphaned mkdir)
 *  - corrupt: owner.json exists but is unreadable/invalid — UNVERIFIABLE,
 *             treated exactly like a live holder (never auto-broken)
 *  - owner:   a syntactically valid owner record
 */
type OwnerRead =
  | { kind: 'absent' }
  | { kind: 'corrupt' }
  | { kind: 'owner'; owner: LockOwner };

/**
 * In-process reentrancy guard (N5): only calls made FROM WITHIN a held
 * callback's async context see the store — a nested withGuardLock on the
 * same dir throws immediately instead of self-deadlocking into the full
 * timeout. Sibling contenders in the same process (e.g. a supervisor and
 * an in-process guard service sharing one PID) see no store and contend
 * normally through mkdir/EEXIST — the mutex still orders them.
 */
const heldContext = new AsyncLocalStorage<string>();

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'EPERM';
  }
}

async function readOwnerState(dir: string): Promise<OwnerRead> {
  let raw: string;
  try {
    raw = await readFile(join(dir, 'owner.json'), 'utf8');
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === 'ENOENT' ? { kind: 'absent' } : { kind: 'corrupt' };
  }
  try {
    const parsed = JSON.parse(raw) as Partial<LockOwner>;
    // pid must be a positive integer: kill(<=0)/kill(-pgid) has group
    // semantics and must never decide staleness for a lock record.
    if (
      typeof parsed.pid === 'number' &&
      Number.isInteger(parsed.pid) &&
      parsed.pid > 0 &&
      typeof parsed.startedAt === 'number' &&
      Number.isFinite(parsed.startedAt)
    ) {
      return {
        kind: 'owner',
        owner: { pid: parsed.pid, startedAt: parsed.startedAt, nonce: typeof parsed.nonce === 'string' ? parsed.nonce : '' }
      };
    }
  } catch {
    // fall through — unparseable JSON is unverifiable
  }
  return { kind: 'corrupt' };
}

async function lockDirAgeMs(dir: string): Promise<number> {
  try {
    return Date.now() - (await stat(dir)).mtimeMs;
  } catch {
    return 0;
  }
}

async function lockDirId(dir: string): Promise<LockDirId | null> {
  try {
    const s = await stat(dir);
    return { dev: s.dev, ino: s.ino };
  } catch {
    return null;
  }
}

function sameDirId(a: LockDirId | null, b: LockDirId | null): boolean {
  return a !== null && b !== null && a.dev === b.dev && a.ino === b.ino;
}

function sameOwner(a: LockOwner | null, b: LockOwner | null): boolean {
  if (a === null || b === null) return a === b;
  return a.pid === b.pid && a.startedAt === b.startedAt && a.nonce === b.nonce;
}

/**
 * Attempt to break a stale lock: rename the directory aside (atomic), verify
 * the moved contents still match the stale snapshot's classification, then
 * remove it — or restore it untouched when anything differs (a fresh owner,
 * a corrupt file, or a valid owner where we expected ownerless).
 */
async function breakStaleLock(dir: string, expected: OwnerRead): Promise<boolean> {
  const trash = `${dir}.stale-${process.pid}-${Date.now()}-${randomUUID().slice(0, 8)}`;
  try {
    await rename(dir, trash);
  } catch {
    return false; // vanished or already moved by another breaker
  }
  const moved = await readOwnerState(trash);
  const matches =
    expected.kind === 'absent'
      ? moved.kind === 'absent'
      : expected.kind === 'owner'
        ? moved.kind === 'owner' && sameOwner(moved.owner, expected.owner)
        : false; // 'corrupt' is never classified stale — unreachable
  if (!matches) {
    // A different state appeared — restore it; the displaced acquirer (if
    // any) fails closed at its own owner-publish verify.
    await rename(trash, dir).catch(() => undefined);
    return false;
  }
  await rm(trash, { recursive: true, force: true }).catch(() => undefined);
  return true;
}

/**
 * Ownership-verified release: move whatever sits at `dir` aside, keep it
 * only when its owner token is THIS holder's, restore it untouched when it
 * is a replacement. Never deletes a lock this process does not own.
 */
async function releaseGuardLock(dir: string, owner: LockOwner): Promise<void> {
  const trash = `${dir}.release-${owner.nonce}`;
  try {
    await rename(dir, trash);
  } catch {
    return; // already gone — nothing of ours remains to release
  }
  const moved = await readOwnerState(trash);
  if (moved.kind !== 'owner' || !sameOwner(moved.owner, owner)) {
    // The path held a REPLACEMENT lock (ours was reclaimed while fn ran —
    // only reachable via paths that cannot displace a live holder, kept as
    // defense-in-depth). Restore it; if a newer acquirer took `dir` in the
    // gap the restore fails and the foreign lock stays stranded-but-alive
    // at `trash` until the bounded sweep removes it (documented residual —
    // never deleted by us).
    await rename(trash, dir).catch(() => undefined);
    return;
  }
  await rm(trash, { recursive: true, force: true }).catch(() => undefined);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function lockError(reason: string, message: string): VmNetworkGuardError {
  return new VmNetworkGuardError(reason, message);
}

/**
 * Publish ownership into an already-mkdir'd lock dir. Fails closed: any
 * write/verify/identity problem removes the dir (only when it is still
 * ownerless-or-ours) and throws — `fn` must NEVER run on an ownerless or
 * unverifiable lock.
 */
async function establishLockOwner(
  dir: string,
  owner: LockOwner,
  writeOwnerFile: GuardLockIo['writeFile']
): Promise<void> {
  const ownerPath = join(dir, 'owner.json');
  const idBefore = await lockDirId(dir);
  try {
    // O_EXCL publish: exactly one writer can create owner.json in this
    // dir — a recreated/replacement dir fails the second publisher closed.
    await writeOwnerFile(ownerPath, JSON.stringify(owner), { mode: 0o600, flag: 'wx' });
  } catch (error) {
    await releaseIfOwnerlessOrOurs(dir, owner);
    throw lockError('guard-lock-owner-write', `failed to publish lock owner: ${error instanceof Error ? error.message : String(error)}`);
  }
  const [idAfter, verify] = await Promise.all([lockDirId(dir), readOwnerState(dir)]);
  if (!sameDirId(idBefore, idAfter) || verify.kind !== 'owner' || !sameOwner(verify.owner, owner)) {
    // The directory was swapped between mkdir and publish (stale-broken
    // and recreated in the gap): whatever owner.json we may have written
    // belongs to a dir that is not ours to run under.
    await releaseIfOwnerlessOrOurs(dir, owner);
    throw lockError('guard-lock-owner-write', 'lock directory identity changed during owner publish');
  }
}

/**
 * Best-effort removal of a just-acquired dir that failed owner
 * establishment: removes it ONLY while it is still ownerless (absent or
 * corrupt owner.json — neither can be a completed foreign ownership,
 * since completion requires a verified valid read-back) or carries OUR
 * token — never a foreign owner's valid live lock.
 */
async function releaseIfOwnerlessOrOurs(dir: string, owner: LockOwner): Promise<void> {
  const current = await readOwnerState(dir);
  if (current.kind === 'owner' && !sameOwner(current.owner, owner)) return; // foreign live lock — leave it
  await rm(dir, { recursive: true, force: true }).catch(() => undefined);
}

/**
 * Best-effort sweep of stranded `guard.lock.stale-*`/`guard.lock.release-*`
 * trash dirs older than `maxAgeMs`. These names are only ever created by
 * rename-aside break/release and are never lock targets; a dir older than
 * the threshold belongs to an operation that finished (or died) long ago.
 * Failure to sweep must never block acquisition — all errors are ignored.
 */
async function sweepGuardTrash(workDir: string, maxAgeMs: number): Promise<void> {
  const cutoff = Date.now() - maxAgeMs;
  let entries: string[];
  try {
    entries = await readdir(workDir);
  } catch {
    return;
  }
  await Promise.all(
    entries
      .filter((name) => TRASH_PREFIXES.some((p) => name.startsWith(p)))
      .map(async (name) => {
        const path = join(workDir, name);
        try {
          if ((await stat(path)).mtimeMs < cutoff) {
            await rm(path, { recursive: true, force: true });
          }
        } catch {
          // vanished or busy — leave it for a later sweep
        }
      })
  );
}

/**
 * Run `fn` while holding the cross-process guard lock for `workDir`.
 * Throws VmNetworkGuardError('guard-lock-timeout') when the lock cannot be
 * acquired within timeoutMs — callers fail closed and may retry. A timeout
 * NEVER revokes a live holder: held locks are broken only on conclusively
 * dead pids or ownerless dirs past grace; everything else is retained until
 * its owner finishes or dies (operator recovery for a wedged holder).
 * Throws 'guard-lock-reentrant' when the same workDir is already held in
 * THIS process, and 'guard-lock-owner-write' when ownership cannot be
 * established — `fn` never runs in either case.
 */
export async function withGuardLock<T>(workDir: string, fn: () => Promise<T>, options: GuardLockOptions = {}): Promise<T> {
  const dir = guardLockDir(workDir);
  if (heldContext.getStore() === dir) {
    throw lockError('guard-lock-reentrant', `guard lock '${dir}' is already held by this async context`);
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const pollMs = options.pollMs ?? DEFAULT_POLL_MS;
  const ownerlessGraceMs = options.ownerlessGraceMs ?? DEFAULT_OWNERLESS_GRACE_MS;
  const trashMaxAgeMs = options.trashMaxAgeMs ?? DEFAULT_TRASH_MAX_AGE_MS;
  const writeOwnerFile = options.io?.writeFile ?? writeFile;
  const deadline = Date.now() + timeoutMs;

  await sweepGuardTrash(workDir, trashMaxAgeMs);

  for (;;) {
    try {
      await mkdir(dir);
      break; // acquired
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
    }

    const state = await readOwnerState(dir);
    let stale = false;
    if (state.kind === 'absent') {
      // Owner file absent: either a holder mid-acquire (grace covers it) or
      // an orphaned lock dir from a crashed acquirer. Safe to break past
      // grace — the displaced acquirer fails closed at owner publish.
      stale = (await lockDirAgeMs(dir)) > ownerlessGraceMs;
    } else if (state.kind === 'owner') {
      // ONLY conclusively dead pids are broken. A live pid is retained
      // regardless of age, startedAt, or clock jumps — waiters time out
      // and a wedged holder is an operator problem, never a license to
      // mutate concurrently (P1).
      stale = !pidAlive(state.owner.pid);
    }
    // 'corrupt' → stale stays false: unverifiable holder, retained.
    if (stale && (await breakStaleLock(dir, state))) continue;

    if (Date.now() >= deadline) {
      throw lockError('guard-lock-timeout', `timed out after ${timeoutMs}ms waiting for guard lock '${dir}'`);
    }
    await sleep(pollMs);
  }

  const owner: LockOwner = { pid: process.pid, startedAt: Date.now(), nonce: randomUUID() };
  await establishLockOwner(dir, owner, writeOwnerFile);
  try {
    return await heldContext.run(dir, fn);
  } finally {
    await releaseGuardLock(dir, owner);
  }
}
