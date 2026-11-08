import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { guardFlockPath, legacyGuardLockPath, withGuardLock } from '../../src/network/lock.js';

/**
 * In-process guard-lock tests for the flock(2) backend: kernel exclusion on
 * a stable never-unlinked inode, legacy directory-protocol refusal, ALS
 * reentrancy/detach semantics, and fail-closed typed errors. Cross-process
 * contention/death scenarios live in lock-multi.test.ts. All scenarios use
 * real filesystem state + the real /usr/bin/flock helper — no mocks.
 */

const dirs: string[] = [];

async function tmpWorkDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'chm-lock-test-'));
  dirs.push(dir);
  return dir;
}

/** Deterministic barrier: poll until `pred` holds. */
async function waitForEvent(pred: () => boolean, timeoutMs = 3_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!pred()) {
    if (Date.now() > deadline) throw new Error('waitForEvent timed out');
    await new Promise((r) => setTimeout(r, 5));
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

describe('withGuardLock (flock backend)', () => {
  it('runs fn while holding the lock on a stable regular-file inode, then releases', async () => {
    const workDir = await tmpWorkDir();
    const result = await withGuardLock(workDir, async () => {
      const st = await stat(guardFlockPath(workDir));
      expect(st.isFile()).toBe(true);
      // No owner metadata protocol survives — the inode IS the lock.
      await expect(readFile(join(workDir, 'owner.json'), 'utf8')).rejects.toThrow();
      return 'done';
    });
    expect(result).toBe('done');
    // Sequential re-acquire succeeds — the kernel released on fd close.
    await expect(withGuardLock(workDir, async () => 'again')).resolves.toBe('again');
  });

  it('mutual exclusion: a held lock makes a sibling acquisition time out, never steals', async () => {
    const workDir = await tmpWorkDir();
    let release!: () => void;
    const gate = new Promise<void>((r) => {
      release = r;
    });
    const holder = withGuardLock(workDir, () => gate);
    // Let the holder's flock land before contending.
    await sleep(80);
    // There is no age/staleness input at all — the ONLY outcomes are
    // acquire-after-release or timeout while held.
    await expect(withGuardLock(workDir, async () => 'never', { timeoutMs: 150 })).rejects.toMatchObject({
      reason: 'guard-lock-timeout'
    });
    release();
    await holder;
    await expect(withGuardLock(workDir, async () => 'after')).resolves.toBe('after');
  });

  it('A-B-A nesting rejects reentrantly; the outer hold still completes', async () => {
    const workDir = await tmpWorkDir();
    const order: string[] = [];
    await withGuardLock(workDir, async () => {
      order.push('outer');
      await expect(withGuardLock(workDir, async () => 'inner')).rejects.toMatchObject({
        reason: 'guard-lock-reentrant'
      });
      // A-B-A: the rejected inner never ran and never released the outer.
      await expect(withGuardLock(workDir, async () => 'inner2')).rejects.toMatchObject({
        reason: 'guard-lock-reentrant'
      });
      order.push('outer-done');
    });
    expect(order).toEqual(['outer', 'outer-done']);
  });

  it('a DIFFERENT workDir nests freely — but A-B-A across dirs still rejects every ancestor hold', async () => {
    const a = await tmpWorkDir();
    const b = await tmpWorkDir();
    await withGuardLock(a, async () => {
      await withGuardLock(b, async () => {
        // B inside A is fine; A again inside B must see the ANCESTOR hold —
        // a single-scope ALS would miss it and self-deadlock on the kernel.
        await expect(withGuardLock(a, async () => 'inner-A', { timeoutMs: 300 })).rejects.toMatchObject({
          reason: 'guard-lock-reentrant'
        });
        await expect(withGuardLock(b, async () => 'inner-B', { timeoutMs: 300 })).rejects.toMatchObject({
          reason: 'guard-lock-reentrant'
        });
      });
    });
  });

  it('sibling async branches under one hold do NOT share tokens — a parallel request waits on the flock', async () => {
    const a = await tmpWorkDir();
    const b = await tmpWorkDir();
    const order: string[] = [];
    await withGuardLock(a, async () => {
      let releaseB!: () => void;
      let markBHeld!: () => void;
      const bGate = new Promise<void>((r) => {
        releaseB = r;
      });
      const bHeld = new Promise<void>((r) => {
        markBHeld = r;
      });
      // Branch 1 (sibling under A): acquire and hold B.
      const holder = withGuardLock(b, async () => {
        markBHeld();
        order.push('b-held');
        await bGate;
        order.push('b-released');
      });
      await bHeld; // barrier: B's flock + active token are live
      // Branch 2 is a SIBLING of branch 1, not a descendant — it must not
      // see B's token. With a shared ALS map it would false-'reentrant';
      // correct behaviour is to wait on the kernel flock until B releases.
      const contender = withGuardLock(
        b,
        async () => {
          order.push('b-contended');
          return 'contended-ok';
        },
        { timeoutMs: 5_000 }
      );
      await sleep(50); // let the contender reach the kernel wait
      releaseB();
      await expect(contender).resolves.toBe('contended-ok');
      await holder;
    });
    expect(order).toEqual(['b-held', 'b-released', 'b-contended']);
  });

  it('detached task created inside the hold acquires normally AFTER release', async () => {
    const workDir = await tmpWorkDir();
    let detachedRan = false;
    await withGuardLock(workDir, async () => {
      // Scheduled inside the held async context but fires after fn returns —
      // the deactivated token must neither false-reject nor bypass.
      setTimeout(() => {
        void withGuardLock(workDir, async () => {
          detachedRan = true;
        }).catch(() => undefined);
      }, 30).unref();
      await sleep(5);
    });
    await waitForEvent(() => detachedRan);
  });

  it('detached task firing DURING the hold still rejects — active token is not bypassed', async () => {
    const workDir = await tmpWorkDir();
    let sawReentrant = false;
    await withGuardLock(workDir, async () => {
      setTimeout(() => {
        void withGuardLock(workDir, async () => 'x')
          .then(() => undefined)
          .catch((e: unknown) => {
            if ((e as { reason?: string }).reason === 'guard-lock-reentrant') sawReentrant = true;
          });
      }, 10).unref();
      await sleep(80); // timer fires while the hold is active
    });
    await waitForEvent(() => sawReentrant);
  });

  it('refuses the retired directory protocol: legacy guard.lock → typed fail-closed, dir preserved', async () => {
    const workDir = await tmpWorkDir();
    const legacy = legacyGuardLockPath(workDir);
    await mkdir(legacy, { recursive: true });
    await writeFile(join(legacy, 'owner.json'), JSON.stringify({ pid: process.pid, startedAt: Date.now() }), {
      mode: 0o600
    });
    await expect(withGuardLock(workDir, async () => 'never')).rejects.toMatchObject({
      reason: 'guard-lock-legacy-present'
    });
    // The legacy dir is NEVER auto-removed — migration is manual.
    expect(existsSync(legacy)).toBe(true);
    // A regular file under the legacy name refuses identically.
    const workDir2 = await tmpWorkDir();
    await writeFile(legacyGuardLockPath(workDir2), 'junk');
    await expect(withGuardLock(workDir2, async () => 'never')).rejects.toMatchObject({
      reason: 'guard-lock-legacy-present'
    });
  });

  it('rejects a symlinked guard.flock at open', async () => {
    const workDir = await tmpWorkDir();
    await symlink('/etc/hostname', guardFlockPath(workDir));
    await expect(withGuardLock(workDir, async () => 'never')).rejects.toMatchObject({
      reason: 'guard-lock-symlink'
    });
  });

  it('detects inode replacement during acquire — never runs fn on an orphan inode', async () => {
    const workDir = await tmpWorkDir();
    await expect(
      withGuardLock(workDir, async () => 'never', {
        afterFlockAcquire: async () => {
          // Swap the lock inode inside the post-acquire/pre-callback window.
          await rm(guardFlockPath(workDir));
          await writeFile(guardFlockPath(workDir), 'replacement');
        }
      })
    ).rejects.toMatchObject({ reason: 'guard-lock-replaced' });
    // The replacement file is untouched — we never delete what we do not own.
    expect(await readFile(guardFlockPath(workDir), 'utf8')).toBe('replacement');
  });

  it('fails closed with a typed error when the flock helper is missing', async () => {
    const workDir = await tmpWorkDir();
    await expect(
      withGuardLock(workDir, async () => 'never', { helperPath: '/nonexistent/chm-flock' })
    ).rejects.toMatchObject({ reason: 'guard-lock-helper-missing' });
  });
});

/**
 * Resolves once the holder's callback proves the kernel flock is held;
 * rejects with the holder's own error when `withGuardLock` fails BEFORE
 * invoking `fn` (missing helper, spawn failure, identity check, …), so the
 * real lock error surfaces instead of `acquired` stalling until the test
 * timeout. `held` resolving is ignored — the holder keeps the lock until the
 * test's `finally` releases it, long after this barrier has settled.
 */
function holderBarrier(held: Promise<unknown>, acquired: Promise<void>): Promise<void> {
  return Promise.race([
    acquired,
    new Promise<never>((_resolve, reject) => {
      void held.catch(reject);
    })
  ]);
}

describe('withGuardLock state-dir and clock-edge cases (gap regressions)', () => {
  it('creates a missing state directory on first use (fresh host)', async () => {
    const base = await tmpWorkDir();
    const fresh = join(base, 'no-such-parent', 'guard-state');
    const result = await withGuardLock(fresh, async () => 'first-cycle');
    expect(result).toBe('first-cycle');
    expect(existsSync(guardFlockPath(fresh))).toBe(true);
  });

  it('enforces the acquire deadline on the monotonic clock, not wall time', async () => {
    const workDir = await tmpWorkDir();
    let release: (() => void) | undefined;
    let markAcquired!: () => void;
    const acquired = new Promise<void>((resolve) => { markAcquired = resolve; });
    const held = withGuardLock(workDir, () => {
      // Entering the callback proves the kernel flock is already held —
      // an explicit barrier, not a fixed sleep that could fire while the
      // holder is still spawning/waiting on the flock helper.
      markAcquired();
      return new Promise<void>((resolve) => { release = resolve; });
    });
    // Pre-handle so an early holder failure cannot surface as an unhandled
    // rejection; the barrier below still observes it via `held`.
    held.catch(() => undefined);
    await holderBarrier(held, acquired);
    // Freeze the WALL clock: any Date.now()-based deadline math would hang
    // (deadline never reached) or fire instantly. performance.now() is
    // monotonic — the ~80ms timeout must still elapse in real time.
    const dateSpy = vi.spyOn(Date, 'now').mockImplementation(() => 1_000_000);
    const t0 = performance.now();
    try {
      await expect(withGuardLock(workDir, async () => 'never', { timeoutMs: 80 }))
        .rejects.toMatchObject({ reason: 'guard-lock-timeout' });
    } finally {
      dateSpy.mockRestore();
      release?.();
      await held;
    }
    const elapsed = performance.now() - t0;
    expect(elapsed).toBeGreaterThanOrEqual(50);
    expect(elapsed).toBeLessThan(3_000);
  });

  it('surfaces a pre-callback holder failure instead of stalling on the barrier', { timeout: 1_500 }, async () => {
    const workDir = await tmpWorkDir();
    let markAcquired!: () => void;
    const acquired = new Promise<void>((resolve) => { markAcquired = resolve; });
    // Bogus helper path: withGuardLock rejects 'guard-lock-helper-missing'
    // before fn can run, so `acquired` can never settle — the barrier must
    // propagate the real error, not hang until the test timeout.
    const held = withGuardLock(workDir, () => {
      markAcquired();
      return Promise.resolve();
    }, { helperPath: '/nonexistent/chm-flock' });
    held.catch(() => undefined);
    const started = Date.now();
    await expect(holderBarrier(held, acquired))
      .rejects.toMatchObject({ reason: 'guard-lock-helper-missing' });
    expect(Date.now() - started).toBeLessThan(1_000);
  });
});
