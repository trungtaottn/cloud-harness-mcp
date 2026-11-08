import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSync } from 'esbuild';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { guardFlockPath, legacyGuardLockPath } from '../../src/network/lock.js';

/**
 * TRUE multiprocess regression for the flock(2) guard lock: real child
 * processes, real kernel flock on a stable inode, filesystem barriers.
 * Covers the windows the retired mkdir/owner.json protocol could not:
 *   - mutual exclusion with zero callback overlap;
 *   - SIGKILL'd holder → instant kernel release (no grace, no stale scan);
 *   - live holder is NEVER stolen (no age input exists at all);
 *   - legacy directory protocol → typed refusal, dir preserved;
 *   - cross-process inode replacement detected before fn runs.
 */

let bundlePath: string;
let driverPath: string;
let workRoot: string;

const DRIVER = `
import { appendFileSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
const { withGuardLock, guardFlockPath } = await import(process.env.LOCK_BUNDLE_PATH);
const [workDir, role, eventsFile, holdMsRaw, timeoutMsRaw, mode] = process.argv.slice(2);
const holdMs = Number(holdMsRaw || '60');
const timeoutMs = Number(timeoutMsRaw || '15000');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const opts = { timeoutMs };
if (mode === 'swap-inode') {
  opts.afterFlockAcquire = async () => {
    rmSync(guardFlockPath(workDir));
    writeFileSync(guardFlockPath(workDir), 'replacement');
  };
}
try {
  await withGuardLock(workDir, async () => {
    appendFileSync(eventsFile, role + '-fn:' + Date.now() + '\\n');
    if (mode === 'hang') await new Promise(() => {});
    await sleep(holdMs);
  }, opts);
  appendFileSync(eventsFile, role + '-ok:' + Date.now() + '\\n');
} catch (error) {
  const reason = error && error.reason ? error.reason : (error && error.message ? error.message : 'unknown');
  appendFileSync(eventsFile, role + '-err:' + reason + '\\n');
  process.exitCode = 3;
}
`;

function waitExit(child: ReturnType<typeof spawn>): Promise<number | null> {
  return new Promise((resolve, reject) => {
    child.on('exit', (code) => resolve(code));
    child.on('error', reject);
  });
}

function spawnChild(
  workDir: string,
  role: string,
  eventsFile: string,
  opts: { holdMs?: number; timeoutMs?: number; mode?: string } = {}
) {
  return spawn(
    process.execPath,
    [
      driverPath,
      workDir,
      role,
      eventsFile,
      String(opts.holdMs ?? 60),
      String(opts.timeoutMs ?? 15_000),
      opts.mode ?? 'normal'
    ],
    { env: { ...process.env, LOCK_BUNDLE_PATH: bundlePath }, stdio: ['ignore', 'pipe', 'pipe'] }
  );
}

async function readEvents(path: string): Promise<string> {
  try {
    return await readFile(path, 'utf8');
  } catch {
    return '';
  }
}

async function waitForContent(path: string, needle: string, timeoutMs = 10_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if ((await readEvents(path)).includes(needle)) return;
    if (Date.now() > deadline) throw new Error(`waitForContent timed out: '${needle}' in ${path}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

beforeAll(async () => {
  workRoot = await mkdtemp(join(tmpdir(), 'ch-lock-multi-'));
  bundlePath = join(workRoot, 'lock.bundle.mjs');
  driverPath = join(workRoot, 'driver.mjs');
  buildSync({
    entryPoints: [fileURLToPath(new URL('../../src/network/lock.ts', import.meta.url))],
    bundle: true,
    format: 'esm',
    platform: 'node',
    outfile: bundlePath,
    logLevel: 'silent'
  });
  await writeFile(driverPath, DRIVER, 'utf8');
});

afterAll(async () => {
  await rm(workRoot, { recursive: true, force: true });
});

describe('multiprocess flock exclusion', () => {
  it('serializes two real processes: exactly fn→ok→fn→ok, zero overlap', async () => {
    const workDir = join(workRoot, 'case-serialize');
    const eventsFile = join(workDir, 'events.log');
    await mkdir(workDir, { recursive: true });
    const child1 = spawnChild(workDir, 'P1', eventsFile, { holdMs: 120 });
    const child2 = spawnChild(workDir, 'P2', eventsFile, { holdMs: 120 });
    const [c1, c2] = await Promise.all([waitExit(child1), waitExit(child2)]);
    expect([c1, c2]).toEqual([0, 0]);
    const events = await readEvents(eventsFile);
    const kinds = events
      .trim()
      .split('\n')
      .map((l) => (l.includes('-fn:') ? 'fn' : l.includes('-ok:') ? 'ok' : 'err'));
    expect(kinds).toEqual(['fn', 'ok', 'fn', 'ok']);
  }, 30_000);

  it('SIGKILLed holder releases instantly — contender acquires with no grace period', async () => {
    const workDir = join(workRoot, 'case-death');
    const eventsFile = join(workDir, 'events.log');
    await mkdir(workDir, { recursive: true });
    const holder = spawnChild(workDir, 'A', eventsFile, { mode: 'hang' });
    const exitA = waitExit(holder);
    await waitForContent(eventsFile, 'A-fn');
    // Kill mid-callback: the kernel closes the fd → lock is free NOW.
    holder.kill('SIGKILL');
    expect(await exitA).not.toBe(0);
    const started = Date.now();
    const contender = spawnChild(workDir, 'B', eventsFile, { holdMs: 30 });
    expect(await waitExit(contender)).toBe(0);
    // Kernel release is synchronous — generous bound proves no grace/stale
    // scan delay (the retired protocol needed ownerlessGraceMs + polling).
    expect(Date.now() - started).toBeLessThan(5_000);
    const events = await readEvents(eventsFile);
    expect(events).toContain('B-ok');
  }, 30_000);

  it('live holder is NEVER stolen — contender times out, then acquires after release', async () => {
    const workDir = join(workRoot, 'case-live');
    const eventsFile = join(workDir, 'events.log');
    await mkdir(workDir, { recursive: true });
    const holder = spawnChild(workDir, 'A', eventsFile, { holdMs: 900 });
    await waitForContent(eventsFile, 'A-fn');
    // B contends while A is alive and well inside its callback — no age,
    // no startedAt, no max-hold input exists to steal with.
    const contender = spawnChild(workDir, 'B', eventsFile, { holdMs: 30, timeoutMs: 300 });
    expect(await waitExit(contender)).toBe(3);
    expect(await waitExit(holder)).toBe(0);
    const events = await readEvents(eventsFile);
    expect(events).toContain('B-err:guard-lock-timeout');
    expect(events).toContain('A-ok');
    // After the holder released, a fresh contender proceeds.
    const late = spawnChild(workDir, 'C', eventsFile, { holdMs: 20 });
    expect(await waitExit(late)).toBe(0);
    expect(await readEvents(eventsFile)).toContain('C-ok');
  }, 30_000);

  it('retired directory protocol refuses cross-process — legacy dir preserved', async () => {
    const workDir = join(workRoot, 'case-legacy');
    const eventsFile = join(workDir, 'events.log');
    const legacy = legacyGuardLockPath(workDir);
    await mkdir(legacy, { recursive: true });
    await writeFile(join(legacy, 'owner.json'), JSON.stringify({ pid: process.pid, startedAt: Date.now() }));
    const child = spawnChild(workDir, 'D', eventsFile);
    expect(await waitExit(child)).toBe(3);
    const events = await readEvents(eventsFile);
    expect(events).toContain('D-err:guard-lock-legacy-present');
    // Never auto-removed — even across process boundaries.
    expect(existsSync(legacy)).toBe(true);
  }, 30_000);

  it('cross-process inode replacement is detected — fn never runs on an orphan inode', async () => {
    const workDir = join(workRoot, 'case-replaced');
    const eventsFile = join(workDir, 'events.log');
    await mkdir(workDir, { recursive: true });
    // A must hold FIRST or the scenario is meaningless: if B won the
    // initial race it would swap the inode before A ever opened it, and A
    // would (correctly) refuse the orphan — the test would fail for the
    // wrong reason. waitForContent proves A is inside its callback before
    // B is spawned, so B deterministically waits on the original inode.
    const a = spawnChild(workDir, 'A', eventsFile, { holdMs: 200 });
    await waitForContent(eventsFile, 'A-fn');
    const b = spawnChild(workDir, 'B', eventsFile, { holdMs: 20, mode: 'swap-inode', timeoutMs: 15_000 });
    expect(await waitExit(a)).toBe(0);
    expect(await waitExit(b)).toBe(3);
    const events = await readEvents(eventsFile);
    expect(events).toContain('A-ok');
    expect(events).toContain('B-err:guard-lock-replaced');
    // The swapped-in replacement survives untouched.
    expect(await readFile(guardFlockPath(workDir), 'utf8')).toBe('replacement');
    // A fresh contender acquires on the canonical (replacement) inode.
    const c = spawnChild(workDir, 'C', eventsFile, { holdMs: 20 });
    expect(await waitExit(c)).toBe(0);
    expect(await readEvents(eventsFile)).toContain('C-ok');
  }, 30_000);
});
