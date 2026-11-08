import { EventEmitter } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { OperationManager } from '../src/operation-manager.js';
import { StateStore } from '../src/state-store.js';
import type { ExecutorBackend, ProvisionContext, StreamHandle } from '../src/executor-backend.js';
import type { WorkspaceRecord } from '../src/state-store.js';

/**
 * Regression coverage for the VM executor-stream path in OperationManager:
 * spawn failures must settle the record exactly once without touching a lock
 * owned by another task, stream 'error' events must settle rather than crash,
 * and CH_COMMAND may carry multiline commands through the named env channel.
 */

const WS = 'ws_0123456789abcdef0123456789abcdef';

function ctx(): ProvisionContext {
  return {
    record: { id: WS, workspacePath: '/tmp/ws' } as WorkspaceRecord,
    environment: { BASE: '1' },
    networkProfile: 'network-none',
    stagingDir: '/tmp/staging'
  };
}

function fakeHandle(overrides: Partial<StreamHandle> = {}): StreamHandle {
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const stderr = new PassThrough();
  const child = Object.assign(new EventEmitter(), {
    stdin,
    stdout,
    stderr,
    kill: vi.fn(),
    pid: 4242
  });
  return Object.assign(child, overrides) as unknown as StreamHandle;
}

function backendWith(spawnStream: ExecutorBackend['spawnStream']): ExecutorBackend {
  return { spawnStream } as unknown as ExecutorBackend;
}

function managerWith(backend: ExecutorBackend) {
  const manager = new OperationManager();
  manager.executorAccessProvider = () => ({ backend, ctx: ctx() });
  return manager;
}

const flush = () => new Promise((resolve) => setImmediate(resolve));

const tempDirs: string[] = [];
afterEach(() => {
  while (tempDirs.length) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

describe('OperationManager executor streams', () => {
  // Task logs are written under <workspacePath>/.chm/tasks — give every
  // runTask a per-suite mkdtemp workspace so logs are removed by afterEach
  // instead of accumulating in the shared /tmp/ws or os tmpdir.
  const wsDir = mkdtempSync(join(tmpdir(), 'ch-ops-ws-'));
  tempDirs.push(wsDir);
  it('multiline CH_COMMAND reaches spawnStream with multilineEnvNames and no argv leak', async () => {
    const spawnStream = vi.fn(async () => fakeHandle());
    const manager = managerWith(backendWith(spawnStream));
    const command = 'echo one\necho two\n# comment';
    manager.runTask(WS, 'ctr', '.', command, 'key-1', 60_000, 4096, [], undefined, wsDir);
    await flush();
    await flush();
    expect(spawnStream).toHaveBeenCalledTimes(1);
    const [calledCtx, request] = spawnStream.mock.calls[0]!;
    expect(calledCtx.record.id).toBe(WS);
    expect(request.environment.CH_COMMAND).toBe(command);
    expect(request.multilineEnvNames).toEqual(['CH_COMMAND']);
    // The command must never appear in argv — only the runner script path.
    expect(request.argv.join(' ')).not.toContain('echo one');
    expect(request.argv[0]).toBe('/opt/harness/task-runner.sh');
  });

  it("a shell record's spawn failure does not settle a running task's mutation lock", async () => {
    const settle = vi.fn();
    const start = vi.fn();
    // First call (the task) returns a live handle; second call (the shell)
    // rejects, exercising the spawn-failure path for a non-task record.
    const spawnStream = vi.fn()
      .mockImplementationOnce(async () => fakeHandle())
      .mockRejectedValueOnce(new Error('vm exec.open refused'));
    const manager = managerWith(backendWith(spawnStream));
    manager.onTaskStart = start;
    manager.onTaskSettle = settle;

    const task = manager.runTask(WS, 'ctr', '.', 'sleep 5', 'task-key', 60_000, 4096, [], undefined, wsDir);
    await flush();
    await flush();
    expect(start).toHaveBeenCalledTimes(1);
    expect(settle).not.toHaveBeenCalled();

    const shell = manager.openShell(WS, 'ctr', '.', 'shell-key', 4096);
    await flush();
    await flush();
    // The shell failed and is marked failed…
    expect(shell.status).toBe('failed');
    // …but the TASK's lock must not be released by the shell's failure.
    expect(settle).not.toHaveBeenCalled();
    expect(task.status).toBe('running');
  });

  it("a task record's own spawn failure still settles its lock exactly once", async () => {
    const settle = vi.fn();
    const spawnStream = vi.fn().mockRejectedValue(new Error('spawn refused'));
    const manager = managerWith(backendWith(spawnStream));
    manager.onTaskSettle = settle;
    const task = manager.runTask(WS, 'ctr', '.', 'echo hi', 'task-key-2', 60_000, 4096, [], undefined, wsDir);
    await flush();
    await flush();
    expect(task.status).toBe('failed');
    expect(settle).toHaveBeenCalledTimes(1);
    expect(settle).toHaveBeenCalledWith(WS, task.id);
  });

  it("stream 'error' settles the record as failed instead of crashing, exactly once with 'close'", async () => {
    const handle = fakeHandle();
    const spawnStream = vi.fn(async () => handle);
    const manager = managerWith(backendWith(spawnStream));
    const settle = vi.fn();
    manager.onTaskSettle = settle;
    const task = manager.runTask(WS, 'ctr', '.', 'echo hi', 'task-key-3', 60_000, 4096, [], undefined, wsDir);
    await flush();
    await flush();
    expect(task.status).toBe('running');

    // VmExecStreamHandle emits 'error' then 'close'; the record must settle
    // on whichever arrives first and exactly once overall.
    const child = handle as unknown as EventEmitter;
    child.emit('error', new Error('session overflow'));
    child.emit('close', 1);
    await flush();
    expect(task.status).toBe('failed');
    expect(task.errorCode).toBe('INTERNAL_ERROR');
    expect(settle).toHaveBeenCalledTimes(1);
  });

  it("stream 'close' after 'error' does not double-settle or overwrite the error", async () => {
    const handle = fakeHandle();
    const spawnStream = vi.fn(async () => handle);
    const manager = managerWith(backendWith(spawnStream));
    const task = manager.runTask(WS, 'ctr', '.', 'echo hi', 'task-key-4', 60_000, 4096, [], undefined, wsDir);
    await flush();
    await flush();
    const child = handle as unknown as EventEmitter;
    child.emit('error', new Error('first failure'));
    child.emit('close', 0);
    await flush();
    expect(task.status).toBe('failed');
    expect(task.errorMessage).toBe('first failure');
    expect(task.exitCode).toBe(1);
  });

  it('stream error persists errorCode/errorMessage to the durable record across restart', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'ch-ops-durable-'));
    tempDirs.push(dir);
    const dbPath = join(dir, 'state.sqlite');
    const store = new StateStore(dbPath);
    let ownerId = '';
    let taskId = '';
    try {
      ownerId = store.resolvePrincipal({ kind: 'external', issuer: 'https://issuer.com', subject: 'user-ops-err' });
      store.create({
        id: WS,
        ownerId,
        idempotencyKey: 'ik_ws_ops_err',
        repositoryUrl: 'https://github.com/org/repo',
        repositoryRef: null,
        containerName: null,
        workspacePath: wsDir,
        status: 'ACTIVE',
        networkProfile: 'network-none',
        createdAt: Date.now(),
        lastActivityAt: Date.now(),
        expiresAt: Date.now() + 3600_000,
        hardExpiresAt: Date.now() + 7200_000,
        gitAuthorName: null,
        gitAuthorEmail: null,
        mutationLockedUntil: null,
        generation: 1,
        error: null
      });
      const handle = fakeHandle();
      const spawnStream = vi.fn(async () => handle);
      const manager = new OperationManager(store, 'boot_a');
      manager.executorAccessProvider = () => ({ backend: backendWith(spawnStream), ctx: ctx() });
      const task = manager.runTask(WS, 'ctr', '.', 'echo hi', 'durable-err-key', 60_000, 4096, [], ownerId, wsDir);
      await flush();
      await flush();
      expect(task.status).toBe('running');

      const child = handle as unknown as EventEmitter;
      child.emit('error', new Error('stream blew up'));
      child.emit('close', 1);
      await flush();
      await flush();
      expect(task.status).toBe('failed');

      // The durable write on the finish path must carry the error fields —
      // pre-fix it persisted FAILED status but dropped code/message.
      const persisted = store.getDurableTask(ownerId, WS, task.id);
      taskId = task.id;
      expect(persisted?.status).toBe('FAILED');
      expect(persisted?.errorCode).toBe('INTERNAL_ERROR');
      expect(persisted?.errorMessage).toContain('stream blew up');
    } finally {
      store.close();
    }

    // Post-restart inspection (fresh store on the same sqlite file) sees the
    // same error — the fields were durably written, not just in-memory.
    const store2 = new StateStore(dbPath);
    try {
      const reloaded = store2.getDurableTask(ownerId, WS, taskId);
      expect(reloaded?.status).toBe('FAILED');
      expect(reloaded?.errorCode).toBe('INTERNAL_ERROR');
      expect(reloaded?.errorMessage).toContain('stream blew up');
    } finally {
      store2.close();
    }
  });
});
