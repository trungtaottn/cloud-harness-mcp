import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { guardLockDir, withGuardLock } from '../../src/network/lock.js';
import { VmNetworkGuardError } from '../../src/network-ops.js';

/**
 * Cross-process guard-lock tests. The lock is a mkdir mutex with pid-liveness
 * stale-breaking; these tests exercise mutual exclusion, stale-break on a
 * dead owner pid, ownerless-orphan grace, and fail-closed timeout — all with
 * real filesystem state, no kernel commands.
 */

const dirs: string[] = [];

async function tmpWorkDir(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'chm-lock-test-'));
  dirs.push(dir);
  return dir;
}

async function writeOwner(dir: string, pid: number, startedAt = Date.now()): Promise<void> {
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, 'owner.json'), JSON.stringify({ pid, startedAt, nonce: 'test' }), { mode: 0o600 });
}

/** Deterministic barrier: poll until `pred` holds — used to order contenders. */
async function waitForEvent(pred: () => boolean, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!pred()) {
    if (Date.now() > deadline) throw new Error('waitForEvent timed out');
    await new Promise((r) => setTimeout(r, 5));
  }
}

afterEach(async () => {
  await Promise.all(dirs.splice(0).map((d) => rm(d, { recursive: true, force: true })));
});

describe('withGuardLock', () => {
  it('runs fn while holding the lock and releases it afterwards', async () => {
    const workDir = await tmpWorkDir();
    let heldDuring = false;
    const result = await withGuardLock(workDir, async () => {
      // The lock dir must exist with our owner metadata while fn runs.
      const owner = JSON.parse(await readFile(join(guardLockDir(workDir), 'owner.json'), 'utf8')) as { pid: number };
      heldDuring = owner.pid === process.pid;
      return 'done';
    });
    expect(result).toBe('done');
    expect(heldDuring).toBe(true);
    // Lock dir is gone after release.
    await expect(readFile(join(guardLockDir(workDir), 'owner.json'), 'utf8')).rejects.toThrow();
  });

  it('serializes a second acquirer until the first releases', async () => {
    const workDir = await tmpWorkDir();
    const order: string[] = [];
    let releaseFirst!: () => void;
    const firstGate = new Promise<void>((r) => {
      releaseFirst = r;
    });
    const first = withGuardLock(workDir, async () => {
      order.push('first-in');
      await firstGate;
      order.push('first-out');
    });
    // Deterministic barrier: `second` must not exist until `first` has
    // actually acquired and entered fn — otherwise mkdir order between the
    // two contenders is racy and the asserted order is not guaranteed.
    await waitForEvent(() => order.includes('first-in'));
    const second = withGuardLock(workDir, async () => {
      order.push('second-in');
    });
    // Give the second acquirer a moment to hit EEXIST and start polling.
    await new Promise((r) => setTimeout(r, 30));
    expect(order).toEqual(['first-in']);
    releaseFirst();
    await Promise.all([first, second]);
    // Mutual exclusion is the assertion: second-in can only follow
    // first-out because acquisition requires the released lock dir.
    expect(order).toEqual(['first-in', 'first-out', 'second-in']);
  });

  it('times out fail-closed while a live foreign pid holds the lock', async () => {
    const workDir = await tmpWorkDir();
    // Simulate another process holding the lock: our own pid is alive.
    await writeOwner(guardLockDir(workDir), process.pid);
    await expect(
      withGuardLock(workDir, async () => 'never', { timeoutMs: 60, pollMs: 10 })
    ).rejects.toMatchObject({ reason: 'guard-lock-timeout' });
    await expect(
      withGuardLock(workDir, async () => 'never', { timeoutMs: 60, pollMs: 10 })
    ).rejects.toBeInstanceOf(VmNetworkGuardError);
  });

  it('breaks a stale lock owned by a dead pid', async () => {
    const workDir = await tmpWorkDir();
    // Spawn a child, let it exit, then use its (now dead) pid as owner.
    const deadPid = await new Promise<number>((resolve, reject) => {
      const child = spawn(process.execPath, ['-e', 'process.exit(0)']);
      child.on('exit', () => resolve(child.pid!));
      child.on('error', reject);
    });
    await writeOwner(guardLockDir(workDir), deadPid, Date.now() - 60_000);
    const result = await withGuardLock(workDir, async () => 'acquired', { timeoutMs: 2_000, pollMs: 10 });
    expect(result).toBe('acquired');
  });

  it('breaks an ownerless orphan lock dir past the grace period', async () => {
    const workDir = await tmpWorkDir();
    const dir = guardLockDir(workDir);
    await mkdir(dir, { recursive: true });
    // No owner.json — orphaned acquisition. Age it past the grace window.
    const old = new Date(Date.now() - 10_000);
    const { utimes } = await import('node:fs/promises');
    await utimes(dir, old, old);
    const result = await withGuardLock(workDir, async () => 'acquired', {
      timeoutMs: 2_000,
      pollMs: 10,
      ownerlessGraceMs: 100
    });
    expect(result).toBe('acquired');
  });

  it('does not break a fresh ownerless lock dir inside the grace window', async () => {
    const workDir = await tmpWorkDir();
    await mkdir(guardLockDir(workDir), { recursive: true });
    // Fresh orphan (just created) — inside grace → treated as held → timeout.
    await expect(
      withGuardLock(workDir, async () => 'never', { timeoutMs: 60, pollMs: 10, ownerlessGraceMs: 60_000 })
    ).rejects.toMatchObject({ reason: 'guard-lock-timeout' });
  });
});

describe('N1/N2 defect fixes', () => {
  async function waitForOwner(dir: string, timeoutMs = 2_000): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      try {
        await readFile(join(dir, 'owner.json'), 'utf8');
        return;
      } catch {
        if (Date.now() > deadline) throw new Error('owner.json never appeared');
        await new Promise((r) => setTimeout(r, 5));
      }
    }
  }

  it('N2: owner.json write failure fails closed — fn never runs, dir removed', async () => {
    const workDir = await tmpWorkDir();
    let fnRan = false;
    await expect(
      withGuardLock(
        workDir,
        async () => {
          fnRan = true;
        },
        {
          io: {
            writeFile: () => Promise.reject(Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' }))
          }
        }
      )
    ).rejects.toMatchObject({ reason: 'guard-lock-owner-write' });
    expect(fnRan).toBe(false);
    // The ownerless dir must not be left behind for a waiter to break.
    await expect(readFile(join(guardLockDir(workDir), 'owner.json'), 'utf8')).rejects.toThrow();
  });

  it('N2: a squatter publishing in the mkdir→publish gap wins; we fail closed and delete nothing', async () => {
    const workDir = await tmpWorkDir();
    const dir = guardLockDir(workDir);
    // Deterministic swap: inside our owner-write hook, a "replacement"
    // acquirer publishes ITS owner.json first — our flag:'wx' write must
    // then fail EEXIST, fail closed, and leave the foreign lock untouched.
    const squatter = { pid: process.pid, startedAt: Date.now(), nonce: 'squatter' };
    let fnRan = false;
    await expect(
      withGuardLock(
        workDir,
        async () => {
          fnRan = true;
        },
        {
          io: {
            writeFile: async (path, data, opts) => {
              await writeFile(join(dir, 'owner.json'), JSON.stringify(squatter), { mode: 0o600 });
              return writeFile(path, data, opts);
            }
          }
        }
      )
    ).rejects.toMatchObject({ reason: 'guard-lock-owner-write' });
    expect(fnRan).toBe(false);
    // The squatter's lock survives intact — we must not delete a foreign lock.
    const owner = JSON.parse(await readFile(join(dir, 'owner.json'), 'utf8')) as { nonce: string };
    expect(owner.nonce).toBe('squatter');
  });

  it('N1: late release after stale reclaim never deletes the replacement lock', async () => {
    const workDir = await tmpWorkDir();
    const dir = guardLockDir(workDir);
    let releaseA!: () => void;
    const gateA = new Promise<void>((r) => {
      releaseA = r;
    });
    // A acquires and holds fn open.
    const aPromise = withGuardLock(workDir, async () => {
      await gateA;
      return 'A';
    });
    await waitForOwner(dir);
    // Simulate stale reclaim: break A's dir aside exactly like breakStaleLock,
    // then B acquires a FRESH lock dir.
    const trashA = `${dir}.test-reclaim`;
    await rename(dir, trashA);
    await rm(trashA, { recursive: true, force: true });
    let releaseB!: () => void;
    const gateB = new Promise<void>((r) => {
      releaseB = r;
    });
    const bPromise = withGuardLock(workDir, async () => {
      await gateB;
      return 'B';
    });
    await waitForOwner(dir);
    // A's fn finishes NOW — its release must NOT delete B's live lock.
    releaseA();
    await expect(aPromise).resolves.toBe('A');
    // B's lock must still be present and held: a third contender times out.
    await expect(withGuardLock(workDir, async () => 'C', { timeoutMs: 80, pollMs: 10 })).rejects.toMatchObject({
      reason: 'guard-lock-timeout'
    });
    const ownerB = JSON.parse(await readFile(join(dir, 'owner.json'), 'utf8')) as { nonce: string };
    expect(ownerB.nonce).not.toBe('');
    // B finishes and releases cleanly; C can then acquire.
    releaseB();
    await expect(bPromise).resolves.toBe('B');
    await expect(withGuardLock(workDir, async () => 'C', { timeoutMs: 2_000, pollMs: 10 })).resolves.toBe('C');
  });

  it('P1: live pid is retained regardless of age — clock jumps cannot steal the lock', async () => {
    const workDir = await tmpWorkDir();
    const dir = guardLockDir(workDir);
    // PID-reuse / forward-clock-jump shape: owner pid is ALIVE (our own)
    // but startedAt is ancient (epoch). The old maxHoldMs rule broke this;
    // the lock must now be retained and the waiter must time out.
    await mkdir(dir, { recursive: true });
    await writeFile(
      join(dir, 'owner.json'),
      JSON.stringify({ pid: process.pid, startedAt: 0, nonce: 'reused' }),
      { mode: 0o600 }
    );
    await expect(withGuardLock(workDir, async () => 'x', { timeoutMs: 80, pollMs: 10 })).rejects.toMatchObject({
      reason: 'guard-lock-timeout'
    });
    // The lock must be untouched — no break, no replacement.
    const owner = JSON.parse(await readFile(join(dir, 'owner.json'), 'utf8')) as { nonce: string };
    expect(owner.nonce).toBe('reused');
  });

  it('P1: a long-held live lock is never stolen — waiter times out, holder completes alone', async () => {
    const workDir = await tmpWorkDir();
    let releaseHolder!: () => void;
    const gate = new Promise<void>((r) => {
      releaseHolder = r;
    });
    let concurrent = 0;
    let maxConcurrent = 0;
    const holder = withGuardLock(workDir, async () => {
      concurrent += 1;
      maxConcurrent = Math.max(maxConcurrent, concurrent);
      await gate; // holder "runs long" — far beyond any waiter's patience
      concurrent -= 1;
      return 'holder-done';
    });
    // Waiter arrives mid-hold with a short timeout: must fail closed, and
    // must NOT have broken the holder's lock to get in.
    await new Promise((r) => setTimeout(r, 30));
    await expect(withGuardLock(workDir, async () => 'waiter', { timeoutMs: 80, pollMs: 10 })).rejects.toMatchObject({
      reason: 'guard-lock-timeout'
    });
    // Second waiter also fails while holder still runs.
    await expect(withGuardLock(workDir, async () => 'waiter2', { timeoutMs: 60, pollMs: 10 })).rejects.toMatchObject({
      reason: 'guard-lock-timeout'
    });
    releaseHolder();
    await expect(holder).resolves.toBe('holder-done');
    expect(maxConcurrent).toBe(1);
    // After release a fresh acquirer succeeds — the lock was never stolen.
    await expect(withGuardLock(workDir, async () => 'next', { timeoutMs: 2_000, pollMs: 10 })).resolves.toBe('next');
  });

  it('P1: corrupt owner.json is unverifiable — retained, never auto-broken', async () => {
    const workDir = await tmpWorkDir();
    const dir = guardLockDir(workDir);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, 'owner.json'), '{"pid": 123, "startedAt":', { mode: 0o600 }); // truncated JSON
    await expect(withGuardLock(workDir, async () => 'x', { timeoutMs: 80, pollMs: 10 })).rejects.toMatchObject({
      reason: 'guard-lock-timeout'
    });
    // Still present and untouched — operator recovery required, not a break.
    await expect(readFile(join(dir, 'owner.json'), 'utf8')).resolves.toContain('"startedAt"');
  });

  it('P1: owner.json with a non-positive pid is corrupt — retained, never broken', async () => {
    const workDir = await tmpWorkDir();
    const dir = guardLockDir(workDir);
    await mkdir(dir, { recursive: true });
    // pid:-1 would give kill(-1,0) process-GROUP semantics — must never
    // decide staleness. Invalid record → unverifiable → retained.
    await writeFile(join(dir, 'owner.json'), JSON.stringify({ pid: -1, startedAt: 0, nonce: 'bad' }), { mode: 0o600 });
    await expect(withGuardLock(workDir, async () => 'x', { timeoutMs: 80, pollMs: 10 })).rejects.toMatchObject({
      reason: 'guard-lock-timeout'
    });
    await expect(readFile(join(dir, 'owner.json'), 'utf8')).resolves.toContain('"pid":-1');
  });

  it('P3: sweeps stranded trash dirs older than trashMaxAgeMs, keeps fresh ones', async () => {
    const workDir = await tmpWorkDir();
    const oldTrash = join(workDir, 'guard.lock.stale-1-old');
    const freshTrash = join(workDir, 'guard.lock.release-2-fresh');
    await mkdir(oldTrash, { recursive: true });
    await mkdir(freshTrash, { recursive: true });
    await writeFile(join(oldTrash, 'owner.json'), '{}', { mode: 0o600 });
    await writeFile(join(freshTrash, 'owner.json'), '{}', { mode: 0o600 });
    // Age only the stale trash dir beyond the sweep threshold.
    const { utimes } = await import('node:fs/promises');
    const past = new Date(Date.now() - 3_600_000);
    await utimes(oldTrash, past, past);
    await utimes(join(oldTrash, 'owner.json'), past, past);
    const result = await withGuardLock(workDir, async () => 'ok', { timeoutMs: 2_000, pollMs: 10, trashMaxAgeMs: 1_800_000 });
    expect(result).toBe('ok');
    await expect(readFile(join(oldTrash, 'owner.json'), 'utf8')).rejects.toThrow(); // swept
    await expect(readFile(join(freshTrash, 'owner.json'), 'utf8')).resolves.toBe('{}'); // fresh kept
  });

  it('N5: nested withGuardLock on the same dir throws immediately, no self-deadlock', async () => {
    const workDir = await tmpWorkDir();
    const started = Date.now();
    await expect(
      withGuardLock(workDir, async () => {
        await expect(withGuardLock(workDir, async () => 'inner', { timeoutMs: 5_000 })).rejects.toMatchObject({
          reason: 'guard-lock-reentrant'
        });
        return 'outer';
      })
    ).resolves.toBe('outer');
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it('two contenders serialize: loser waits, neither overlaps', async () => {
    const workDir = await tmpWorkDir();
    const events: string[] = [];
    let releaseFirst!: () => void;
    const gate = new Promise<void>((r) => {
      releaseFirst = r;
    });
    const first = withGuardLock(workDir, async () => {
      events.push('first-in');
      await gate;
      events.push('first-out');
    });
    // Same deterministic barrier as above: second starts only after first
    // holds the lock, so the serialized order is guaranteed, not raced.
    await waitForEvent(() => events.includes('first-in'));
    const second = withGuardLock(workDir, async () => {
      events.push('second-in');
    });
    await new Promise((r) => setTimeout(r, 40));
    expect(events).toEqual(['first-in']);
    releaseFirst();
    await Promise.all([first, second]);
    expect(events).toEqual(['first-in', 'first-out', 'second-in']);
  });
});
