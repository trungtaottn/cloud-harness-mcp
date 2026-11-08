import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildSync } from 'esbuild';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

/**
 * Fresh-process liveness regression (PR#6 finding #6): the guard service
 * must survive monitor-child death because the poll interval — not the
 * monitor — is the event-loop anchor. Runs the REAL createGuardService +
 * createNftMonitorWakeups in a spawned node process against the fake
 * kernel; no live nft/monitor/systemd involved.
 */

let workRoot: string;
let runnerPath: string;

beforeAll(async () => {
  workRoot = await mkdtemp(join(tmpdir(), 'ch-svc-liveness-'));
  // The child bundle contains live.ts's invokedAsScript CLI guard, which
  // compares import.meta.url to argv[1]. Running the bundle directly would
  // fire main() and exit(1) on missing VM_* env. A two-file split keeps
  // argv[1] pointed at a neutral runner so the guard stays inert.
  const bundlePath = join(workRoot, 'liveness-child.lib.mjs');
  runnerPath = join(workRoot, 'liveness-runner.mjs');
  buildSync({
    entryPoints: [fileURLToPath(new URL('./fixtures/liveness-child.ts', import.meta.url))],
    bundle: true,
    format: 'esm',
    platform: 'node',
    outfile: bundlePath,
    logLevel: 'silent'
  });
  await writeFile(runnerPath, `await import(${JSON.stringify(new URL(`file://${bundlePath}`).href)});\n`, 'utf8');
});

afterAll(async () => {
  await rm(workRoot, { recursive: true, force: true });
});

describe('guard service liveness across monitor death', () => {
  it('stays alive after the nft monitor child exits — poll interval is the anchor', async () => {
    const stateDir = join(workRoot, 'state');
    const markerPath = join(workRoot, 'alive.marker');
    await mkdir(stateDir, { recursive: true });
    const started = Date.now();
    const child = spawn(process.execPath, [runnerPath, stateDir, markerPath], {
      stdio: ['ignore', 'pipe', 'pipe']
    });
    let stderr = '';
    child.stderr.on('data', (d: Buffer) => {
      stderr += d.toString('utf8');
    });
    const code = await new Promise<number | null>((resolve, reject) => {
      const timer = setTimeout(() => {
        child.kill('SIGKILL');
        reject(new Error(`liveness child did not exit within 20s; stderr: ${stderr}`));
      }, 20_000);
      child.on('exit', (c) => {
        clearTimeout(timer);
        resolve(c);
      });
      child.on('error', reject);
    });
    const elapsed = Date.now() - started;
    expect(code).toBe(0);
    // The marker is written ~600ms in via an UNREF'd timer, after monitor
    // death at ~150ms — it can only exist if the referenced poll interval
    // kept the event loop alive. An unref'd interval drains the loop at
    // ~150ms: exit(0) with no marker and elapsed ~160ms.
    expect(existsSync(markerPath)).toBe(true);
    expect(await readFile(markerPath, 'utf8')).toBe('alive');
    expect(elapsed).toBeGreaterThanOrEqual(400);
  }, 30_000);
});
