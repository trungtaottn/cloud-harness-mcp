import { mkdtemp, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { withGuardLock } from '../../src/network/lock.js';

/**
 * API-COMPATIBLE lock behavior suite — deliberately imports ONLY
 * `withGuardLock` and passes ONLY `timeoutMs`, the intersection of the old
 * directory-protocol and new flock-protocol option surfaces. It therefore
 * compiles and runs against BOTH trees:
 *
 *   - on the published 9fb2dec baseline (old protocol) the marked
 *     DISCRIMINATING tests must FAIL, proving the original defects;
 *   - on the fixed tree every test must PASS.
 *
 * New-protocol-only guarantees (guard.flock inode, legacy refusal, helper
 * lifecycle, inode replacement, symlink reject) live in lock.test.ts /
 * lock-multi.test.ts and are NOT re-proven here — module-load failure on
 * the old tree is not evidence of the original bug.
 */

const dirs: string[] = [];

async function tmpWorkDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'chm-lock-compat-'));
  dirs.push(dir);
  return dir;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

afterEach(async () => {
  while (dirs.length > 0) await rm(dirs.pop()!, { recursive: true, force: true });
});

describe('withGuardLock — cross-protocol behavior contract', () => {
  it('direct same-dir nesting rejects reentrantly (contract guard — both protocols)', async () => {
    const workDir = await tmpWorkDir();
    await withGuardLock(workDir, async () => {
      await expect(withGuardLock(workDir, async () => 'inner', { timeoutMs: 300 })).rejects.toMatchObject({
        reason: 'guard-lock-reentrant'
      });
    });
  });

  it('DISCRIMINATING: A-B-A across different dirs rejects every ancestor hold', async () => {
    const a = await tmpWorkDir();
    const b = await tmpWorkDir();
    await withGuardLock(a, async () => {
      await withGuardLock(b, async () => {
        // Old protocol: single-string ALS store sees only dirB → inner-A
        // proceeds, finds OUR live pid as owner, and times out with the
        // WRONG reason — never 'guard-lock-reentrant'.
        await expect(withGuardLock(a, async () => 'inner-A', { timeoutMs: 300 })).rejects.toMatchObject({
          reason: 'guard-lock-reentrant'
        });
        await expect(withGuardLock(b, async () => 'inner-B', { timeoutMs: 300 })).rejects.toMatchObject({
          reason: 'guard-lock-reentrant'
        });
      });
    });
  });

  it('DISCRIMINATING: detached task created inside the hold acquires AFTER release', async () => {
    const workDir = await tmpWorkDir();
    let settled: { ok: boolean; reason?: string } | undefined;
    await withGuardLock(workDir, async () => {
      // Timer async-resource captures the held ALS context at creation;
      // it fires after fn returns. Old protocol: the captured store still
      // equals the lock dir → false 'guard-lock-reentrant' forever. New:
      // the token was deactivated+deleted at release → real acquisition.
      setTimeout(() => {
        void withGuardLock(workDir, async () => 'detached-ok', { timeoutMs: 2_000 })
          .then(() => {
            settled = { ok: true };
          })
          .catch((e: unknown) => {
            settled = { ok: false, reason: (e as { reason?: string }).reason };
          });
      }, 30).unref();
      await sleep(5);
    });
    const deadline = Date.now() + 4_000;
    while (settled === undefined && Date.now() < deadline) await sleep(10);
    expect(settled).toEqual({ ok: true });
  });

  it('DISCRIMINATING: a symlinked alias of the held dir still rejects reentrantly', async () => {
    const workDir = await tmpWorkDir();
    const aliasDir = join(await tmpWorkDir(), 'alias');
    await symlink(workDir, aliasDir, 'dir');
    await withGuardLock(workDir, async () => {
      // Old protocol keys the store on the UNCANONICALIZED dir string:
      // aliasDir/guard.lock !== workDir/guard.lock → proceeds → same
      // physical lock dir → our own live pid → 'guard-lock-timeout',
      // never reentrant. New protocol canonicalizes via realpath → same
      // lock path → 'guard-lock-reentrant'.
      await expect(withGuardLock(aliasDir, async () => 'alias', { timeoutMs: 300 })).rejects.toMatchObject({
        reason: 'guard-lock-reentrant'
      });
    });
  });

  it('sibling same-process contenders serialize through the real mutex (contract guard — both)', async () => {
    const workDir = await tmpWorkDir();
    const order: string[] = [];
    let releaseFirst!: () => void;
    const gate = new Promise<void>((r) => {
      releaseFirst = r;
    });
    const first = withGuardLock(workDir, async () => {
      order.push('first-in');
      await gate;
      order.push('first-out');
    });
    // 'first-in' is pushed INSIDE the held callback — proof of acquisition
    // on either protocol; spawning the sibling earlier would race the
    // mutex and could invert the expected order.
    const deadline = Date.now() + 5_000;
    while (!order.includes('first-in') && Date.now() < deadline) await sleep(5);
    expect(order).toContain('first-in');
    const second = withGuardLock(workDir, async () => {
      order.push('second-in');
    }, { timeoutMs: 5_000 });
    releaseFirst();
    await Promise.all([first, second]);
    expect(order).toEqual(['first-in', 'first-out', 'second-in']);
  });

  it('a live foreign hold yields typed guard-lock-timeout, never a steal (contract guard — both)', async () => {
    const workDir = await tmpWorkDir();
    let releaseHold!: () => void;
    const gate = new Promise<void>((r) => {
      releaseHold = r;
    });
    let markAcquired!: () => void;
    const acquired = new Promise<void>((r) => {
      markAcquired = r;
    });
    const holder = withGuardLock(workDir, async () => {
      markAcquired();
      await gate;
    });
    await acquired; // holder provably inside its critical section on BOTH protocols
    await expect(withGuardLock(workDir, async () => 'contender', { timeoutMs: 300 })).rejects.toMatchObject({
      reason: 'guard-lock-timeout'
    });
    releaseHold();
    await holder;
    // After release a fresh contender proceeds on BOTH protocols.
    await expect(withGuardLock(workDir, async () => 'late', { timeoutMs: 2_000 })).resolves.toBe('late');
  });
});
