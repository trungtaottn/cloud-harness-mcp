import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';

/**
 * Direct tests for appliance-shim.mjs — the sentinel process-group leader
 * used by spawnApplianceProcess. These spawn the shim itself (not through
 * export.ts) to prove its three watchdogs and its exit-status fidelity:
 * control-pipe EOF (parent death), the deadline backstop, and faithful
 * propagation of the appliance's exit code / fatal signal.
 */

const SHIM = fileURLToPath(new URL('../appliance-shim.mjs', import.meta.url));

const dirs: string[] = [];
const children: ChildProcess[] = [];

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'vm-shim-'));
  dirs.push(dir);
  return dir;
}

afterEach(() => {
  while (children.length) {
    const child = children.pop() as ChildProcess;
    try {
      (child.stdio[3] as { destroy?: () => void } | null)?.destroy?.();
    } catch {
      // already closed
    }
    try {
      child.kill('SIGKILL');
    } catch {
      // already gone
    }
  }
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

function spawnShim(args: string[]): ChildProcess {
  const child = spawn(process.execPath, [SHIM, ...args], {
    stdio: ['ignore', 'pipe', 'pipe', 'pipe'],
    detached: true
  });
  children.push(child);
  child.stderr?.resume(); // drain diagnostics; never assert on them here
  return child;
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitForPidGone(pid: number, timeoutMs = 5_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (pidAlive(pid)) {
    if (Date.now() >= deadline) return false;
    await new Promise((r) => setTimeout(r, 25));
  }
  return true;
}

async function waitForFile(path: string, timeoutMs = 5_000): Promise<string> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      return readFileSync(path, 'utf8').trim();
    } catch {
      if (Date.now() >= deadline) throw new Error(`timed out waiting for ${path}`);
      await new Promise((r) => setTimeout(r, 25));
    }
  }
}

describe('appliance-shim', () => {
  it('exits with the appliance exit code after the group drains', async () => {
    const child = spawnShim(['--', 'sh', '-c', 'exit 3']);
    const [code, signal] = (await once(child, 'close')) as [number | null, string | null];
    expect(code).toBe(3);
    expect(signal).toBeNull();
  });

  it('re-raises the appliance fatal signal so close reports it', async () => {
    const child = spawnShim(['--', 'sh', '-c', 'kill -KILL $$']);
    const [code, signal] = (await once(child, 'close')) as [number | null, string | null];
    expect(signal).toBe('SIGKILL');
    expect(code).toBeNull();
  });

  it('reports the EXACT trapped signal (SIGTERM) instead of degrading to exit 1', async () => {
    // Regression: finish() re-raises the appliance's fatal signal, but the
    // installed SIGTERM/SIGINT traps used to still be active — terminateGroup
    // saw finished=true, swallowed the signal, and the 500ms fallback reported
    // exit code 1. The traps must be removed BEFORE the re-raise so 'close'
    // reports signal 'SIGTERM' with a null code.
    const child = spawnShim(['--', 'sh', '-c', 'kill -TERM $$']);
    const [code, signal] = (await once(child, 'close')) as [number | null, string | null];
    expect(signal).toBe('SIGTERM');
    expect(code).toBeNull();
  });

  it('reports the EXACT trapped signal (SIGINT) instead of degrading to exit 1', async () => {
    const child = spawnShim(['--', 'sh', '-c', 'kill -INT $$']);
    const [code, signal] = (await once(child, 'close')) as [number | null, string | null];
    expect(signal).toBe('SIGINT');
    expect(code).toBeNull();
  });

  it('self-kills the group when the /proc readdir scan is unverifiable', async () => {
    // --scan-fail=readdir makes readdirSync('/proc') throw EIO on the first
    // drain tick. An unverifiable scan must fail CLOSED — self-kill — never
    // fabricate an empty group and report the appliance's exit 0.
    const child = spawnShim(['--scan-fail=readdir', '--', 'sh', '-c', 'exit 0']);
    const [code, signal] = (await once(child, 'close')) as [number | null, string | null];
    expect(signal).toBe('SIGKILL');
    expect(code).toBeNull();
  });

  it('self-kills the group on a PARTIAL per-pid stat failure, not just readdir', async () => {
    // Injects EACCES for ONE live /proc entry (this test process) while every
    // other stat reads normally: a single unverifiable member is enough to
    // make "group drained" unprovable, so the shim must self-kill rather than
    // count it as exited and finish with code 0.
    const child = spawnShim(['--scan-fail=stat:' + process.pid + ':EACCES', '--', 'sh', '-c', 'exit 0']);
    const [code, signal] = (await once(child, 'close')) as [number | null, string | null];
    expect(signal).toBe('SIGKILL');
    expect(code).toBeNull();
  });

  it('treats an ENOENT stat failure as disappearance and still drains cleanly', async () => {
    // The counterpart guard: ENOENT/ESRCH prove the pid exited between
    // readdir and read, so they must NOT trigger the fail-closed kill — the
    // appliance's genuine exit code is preserved.
    const child = spawnShim(['--scan-fail=stat:' + process.pid + ':ENOENT', '--', 'sh', '-c', 'exit 0']);
    const [code, signal] = (await once(child, 'close')) as [number | null, string | null];
    expect(code).toBe(0);
    expect(signal).toBeNull();
  });

  it('self-kills the whole group when the control pipe reaches EOF (parent death)', async () => {
    const dir = tempDir();
    const pidfile = join(dir, 'apid');
    // Appliance records its pid then sleeps; the shim is the group leader.
    const child = spawnShim(['--', 'sh', '-c', `echo $$ > '${pidfile}'; exec sleep 300`]);
    const apid = Number(await waitForFile(pidfile));
    expect(apid).toBeGreaterThan(0);
    expect(pidAlive(apid)).toBe(true);
    // Supervisor "dies": close our write end. No kill() call is made — the
    // shim's EOF watchdog must terminate the group on its own.
    (child.stdio[3] as { end: () => void }).end();
    expect(await waitForPidGone(apid)).toBe(true);
    expect(await waitForPidGone(child.pid as number)).toBe(true);
  });

  it('self-kills the group at the deadline backstop without any cancel', async () => {
    const dir = tempDir();
    const pidfile = join(dir, 'apid');
    const child = spawnShim(['--deadline-ms=300', '--', 'sh', '-c', `echo $$ > '${pidfile}'; exec sleep 300`]);
    const apid = Number(await waitForFile(pidfile));
    expect(pidAlive(apid)).toBe(true);
    // Control pipe stays OPEN — only the deadline may fire.
    expect(await waitForPidGone(apid, 5_000)).toBe(true);
    expect(await waitForPidGone(child.pid as number)).toBe(true);
  });

  it('waits for a lingering group member before exiting (no premature close)', async () => {
    const dir = tempDir();
    const pidfile = join(dir, 'gcpid');
    // Appliance parent exits immediately; grandchild holds the group for ~400ms.
    const child = spawnShim([
      '--',
      'sh',
      '-c',
      `sleep 0.4 & echo $! > '${pidfile}'; exit 0`
    ]);
    const gcpid = Number(await waitForFile(pidfile));
    const started = Date.now();
    const [code] = (await once(child, 'close')) as [number | null, string | null];
    const elapsed = Date.now() - started;
    expect(code).toBe(0);
    // The shim must not exit while the grandchild still lives: close can
    // only arrive after the ~400ms drain, proving 'close' attests group death.
    expect(elapsed).toBeGreaterThanOrEqual(300);
    expect(pidAlive(gcpid)).toBe(false);
  });
});
