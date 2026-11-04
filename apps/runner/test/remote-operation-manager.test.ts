import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SecretSnapshotRedactor } from '../src/output-redactor.js';
import { StateStore } from '../src/state-store.js';
import type { PtyTransport } from '../src/docker-pty.js';
import { OperationManager } from '../src/operation-manager.js';
import type { RemoteExecutionBackend, RemoteExecutorRef } from '../src/executors/execution-backend.js';
vi.mock('../src/docker-engine.js', () => ({ spawnDocker: vi.fn(() => { throw new Error('unexpected Docker'); }), terminateContainerProcessGroup: vi.fn() }));
const ref: RemoteExecutorRef = { provider: 'instabox', workspaceId: 'remote', ownerId: 'owner', machineId: 'machine', generation: 1, root: '/workspace' };
function setup(store?: StateStore) {
  const backend = {
    startJob: vi.fn().mockResolvedValue(undefined),
    readJob: vi.fn().mockResolvedValue({ status: 'running', output: Buffer.alloc(0), nextOffset: 0, outputBytes: 0, truncated: false }),
    cancelJob: vi.fn().mockResolvedValue(undefined), writeJob: vi.fn().mockResolvedValue(undefined), activity: vi.fn().mockResolvedValue(undefined),
    pty: vi.fn()
  } as unknown as RemoteExecutionBackend;
  const manager = new OperationManager(store, 'boot', { remoteExecution: { backend, resolve: (ws) => ws === 'remote' ? ref : undefined } });
  return { backend, manager };
}
describe('remote operations', () => {
  afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); });
  it('keeps an ambiguous dispatch running and reconciles without redispatch', async () => {
    vi.useFakeTimers();
    const { backend, manager } = setup();
    vi.mocked(backend.startJob).mockRejectedValue(new Error('lost response'));
    const task = manager.runTask('remote', '', '.', 'echo hi', 'key', 60_000, 100);
    await vi.advanceTimersByTimeAsync(1);
    expect(task.status).toBe('running');
    vi.mocked(backend.readJob).mockImplementation(async (_ref, _id, offset) => ({ status: 'exited', exitCode: 0, output: Buffer.from('hi').subarray(offset), nextOffset: 2, outputBytes: 2, truncated: false }));
    await vi.advanceTimersByTimeAsync(1000);
    expect(task.status).toBe('succeeded');
    expect(task.output.toString()).toBe('hi');
    expect(backend.startJob).toHaveBeenCalledTimes(1);
    rmSync(task.logPath!);
  });
  it('does not publish cancellation until remote termination succeeds', async () => {
    vi.useFakeTimers();
    const { backend, manager } = setup();
    const task = manager.runTask('remote', '', '.', 'sleep 10', 'key', 60_000, 100);
    await vi.advanceTimersByTimeAsync(1);
    vi.mocked(backend.cancelJob).mockRejectedValueOnce(new Error('unavailable'));
    await expect(manager.cancelTask('remote', task.id)).rejects.toThrow('unavailable');
    expect(task.status).toBe('running');
    await manager.cancelTask('remote', task.id);
    expect(task.status).toBe('cancelled');
    rmSync(task.logPath!);
  });
  it('writes input to the same persistent shell and confirms close', async () => {
    vi.useFakeTimers();
    const { backend, manager } = setup();
    const shell = manager.openShell('remote', '', '.', 'key', 100);
    manager.shellIo('remote', shell.id, 'cd /tmp\n');
    await vi.advanceTimersByTimeAsync(1);
    expect(backend.startJob).toHaveBeenCalledWith(ref, expect.objectContaining({ id: shell.id, kind: 'shell' }));
    expect(backend.writeJob).toHaveBeenCalledWith(ref, shell.id, 'cd /tmp\n');
    await manager.closeShell('remote', shell.id);
    expect(backend.cancelJob).toHaveBeenCalledWith(ref, shell.id);
  });
  it('rehydrates dependencies and replays already spooled output without duplicating it', async () => {
    vi.useFakeTimers();
    const dir = mkdtempSync(join(tmpdir(), 'remote-operations-'));
    const store = new StateStore(join(dir, 'state.sqlite'));
    const owner = store.resolvePrincipal({ kind: 'external', issuer: 'https://issuer.test', subject: 'remote' });
    store.create({ id: 'remote', ownerId: owner, idempotencyKey: 'ws', repositoryUrl: 'https://github.com/org/repo', repositoryRef: null,
      containerName: null, workspacePath: dir, status: 'ACTIVE', networkProfile: 'network-none', createdAt: Date.now(), lastActivityAt: Date.now(),
      expiresAt: Date.now() + 3600000, hardExpiresAt: Date.now() + 7200000, gitAuthorName: null, gitAuthorEmail: null,
      mutationLockedUntil: null, generation: 1, error: null });
    try {
      const persisted = vi.spyOn(store, 'updateDurableTaskStatus');
      const first = setup(store);
      vi.mocked(first.backend.readJob).mockImplementation(async (_ref, _id, offset) => ({ status: 'running', output: Buffer.from('first').subarray(offset), nextOffset: 5, outputBytes: 5, truncated: false }));
      const task = first.manager.runTask('remote', '', '.', 'echo first', 'first', 60000, 100, [], owner, dir);
      const dependent = first.manager.runTask('remote', '', '.', 'echo second', 'second', 60000, 100, [task.id], owner, dir);
      await vi.advanceTimersByTimeAsync(1);
      expect(readFileSync(task.logPath!, 'utf8')).toBe('first');
      const writes = persisted.mock.calls.length;
      await vi.advanceTimersByTimeAsync(2000);
      expect(persisted).toHaveBeenCalledTimes(writes);
      vi.clearAllTimers(); // Simulate runner loss without a lifecycle cancellation.
      const recovered = setup(store);
      vi.mocked(recovered.backend.readJob).mockImplementation(async (_ref, job, offset) => ({ status: job === task.id ? 'exited' : 'running', exitCode: 0,
        output: Buffer.from(job === task.id ? 'first-last' : '').subarray(offset), nextOffset: job === task.id ? 10 : 0, outputBytes: 10, truncated: false }));
      persisted.mockClear();
      persisted.mockReturnValueOnce(false);
      await recovered.manager.reconcileRemoteTasks('remote', owner);
      await vi.advanceTimersByTimeAsync(600);
      expect(readFileSync(task.logPath!, 'utf8')).toBe('first-last');
      expect(recovered.manager.task('remote', task.id).status).toBe('succeeded');
      expect(store.getDurableTask(owner, 'remote', task.id)?.status).toBe('SUCCEEDED');
      const parentWrites = persisted.mock.calls.filter(([id]) => id === task.id);
      expect(parentWrites[0]![1]).toBe(parentWrites[1]![1]);
      expect(recovered.backend.startJob).toHaveBeenCalledTimes(1);
      expect(recovered.backend.startJob).toHaveBeenCalledWith(ref, expect.objectContaining({ id: dependent.id }));
      await recovered.manager.stopWorkspace('remote', owner);
    } finally { store.close(); rmSync(dir, { recursive: true, force: true }); }
  });

  it('pins each terminal to its workspace transport across mixed local and remote opens', async () => {
    const connection = () => ({ execId: 'exec', writableLength: 0, write: vi.fn(), close: vi.fn(), onData: vi.fn(), onEnd: vi.fn() });
    const transport = (): PtyTransport => ({ open: vi.fn().mockResolvedValue(connection()), resize: vi.fn().mockResolvedValue(undefined),
      inspect: vi.fn().mockResolvedValue({ running: false, exitCode: 0 }), killSession: vi.fn().mockResolvedValue(undefined) });
    const local = transport(); const remote = transport(); const { backend } = setup();
    vi.mocked(backend.pty).mockReturnValue(remote);
    const manager = new OperationManager(undefined, 'boot', { transport: local, remoteExecution: { backend, resolve: (ws) => ws === 'remote' ? ref : undefined } });
    const a = await manager.openTerminal({ ownerId: 'owner', workspaceId: 'remote', container: '', cwd: '.', cols: 80, rows: 24 });
    const b = await manager.openTerminal({ ownerId: 'owner', workspaceId: 'local', container: 'docker', cwd: '.', cols: 80, rows: 24 });
    await manager.resizeTerminal('owner', 'remote', a.terminalId, 100, 30);
    expect(remote.resize).toHaveBeenCalledOnce(); expect(local.resize).not.toHaveBeenCalled();
    await manager.closeTerminal('owner', 'remote', a.terminalId);
    await manager.closeTerminal('owner', 'local', b.terminalId);
    expect(remote.killSession).toHaveBeenCalledWith('', a.terminalId);
    expect(local.killSession).toHaveBeenCalledWith('docker', b.terminalId);
  });

  it('redacts split secrets and caps the host spool while draining remote output', async () => {
    vi.useFakeTimers();
    const { backend, manager } = setup();
    manager.redactorProvider = () => new SecretSnapshotRedactor({ TOKEN: 'secret-value' });
    const chunks = [Buffer.from('secret-'), Buffer.from('value\nmore output than the budget')];
    let cursor = 0;
    vi.mocked(backend.readJob).mockImplementation(async () => {
      const output = chunks.shift() ?? Buffer.alloc(0); cursor += output.length;
      return { status: 'exited', exitCode: 0, output, nextOffset: cursor, outputBytes: cursor, truncated: false };
    });
    const task = manager.runTask('remote', '', '.', 'echo', 'key', 60000, 16);
    await vi.advanceTimersByTimeAsync(1000);
    expect(task.status).toBe('succeeded');
    const log = readFileSync(task.logPath!);
    expect(log.length).toBe(16);
    expect(log.toString()).not.toContain('secret');
    expect(task.output.length).toBeLessThanOrEqual(16);
    expect(backend.activity).toHaveBeenLastCalledWith(ref, task.id, false);
    rmSync(task.logPath!);
  });

  it('enforces the host deadline and keeps unknown outcomes active without false events', async () => {
    vi.useFakeTimers();
    const { backend, manager } = setup();
    vi.mocked(backend.readJob).mockResolvedValue({ status: 'unknown', output: Buffer.alloc(0), nextOffset: 0, outputBytes: 0, truncated: false });
    manager.onTaskSettle = vi.fn();
    const task = manager.runTask('remote', '', '.', 'sleep 999', 'key', 1000, 100);
    await vi.advanceTimersByTimeAsync(2000);
    expect(backend.cancelJob).toHaveBeenCalledWith(ref, task.id);
    expect(task.status).toBe('running');
    expect(manager.onTaskSettle).not.toHaveBeenCalled();
    expect(backend.activity).not.toHaveBeenCalledWith(ref, task.id, true);
    await manager.cancelTask('remote', task.id);
    rmSync(task.logPath!);
  });

  it('waits for an in-flight start before confirming cancellation and ignores a late exit', async () => {
    vi.useFakeTimers();
    const { backend, manager } = setup();
    let started!: () => void;
    vi.mocked(backend.startJob).mockReturnValue(new Promise<void>((resolve) => { started = resolve; }));
    let observed!: (value: Awaited<ReturnType<RemoteExecutionBackend['readJob']>>) => void;
    vi.mocked(backend.readJob).mockReturnValue(new Promise((resolve) => { observed = resolve; }));
    manager.onTaskSettle = vi.fn();
    const task = manager.runTask('remote', '', '.', 'sleep 1', 'key', 60000, 100);
    const cancellation = manager.cancelTask('remote', task.id);
    expect(backend.cancelJob).not.toHaveBeenCalled();
    started();
    await cancellation;
    observed({ status: 'exited', exitCode: 0, output: Buffer.alloc(0), nextOffset: 0, outputBytes: 0, truncated: false });
    await vi.advanceTimersByTimeAsync(1000);
    expect(task.status).toBe('cancelled');
    expect(manager.onTaskSettle).toHaveBeenCalledTimes(1);
    expect(backend.startJob).toHaveBeenCalledTimes(1);
    rmSync(task.logPath!);
  });

  it('surfaces unconfirmed shell input through the awaited operation boundary', async () => {
    vi.useFakeTimers();
    const { backend, manager } = setup();
    const shell = manager.openShell('remote', '', '.', 'key', 100);
    await manager.awaitRemoteOperation('remote', shell.id);
    vi.mocked(backend.writeJob).mockRejectedValue(new Error('input response lost'));
    manager.shellIo('remote', shell.id, 'echo hi\n');
    await expect(manager.awaitRemoteOperation('remote', shell.id)).rejects.toThrow('input response lost');
    expect(shell.status).toBe('running');
    await manager.closeShell('remote', shell.id);
  });

  it('detaches runner observation without cancelling a durable guest task', async () => {
    vi.useFakeTimers();
    const { backend, manager } = setup();
    const task = manager.runTask('remote', '', '.', 'sleep 1', 'key', 60000, 100);
    await vi.advanceTimersByTimeAsync(1);
    const reads = vi.mocked(backend.readJob).mock.calls.length;
    await manager.detachRemoteOperations();
    await vi.advanceTimersByTimeAsync(2000);
    expect(backend.readJob).toHaveBeenCalledTimes(reads);
    expect(backend.cancelJob).not.toHaveBeenCalled();
    expect(task.status).toBe('running');
    rmSync(task.logPath!);
  });

  it('keeps generic remote work active when termination cannot be confirmed', async () => {
    const manager = new OperationManager();
    const operation = manager.registerGenericOperation({ id: 'op_remote', workspaceId: 'remote', kind: 'files_read' });
    operation.cancelRemote = vi.fn().mockRejectedValue(new Error('unconfirmed'));
    await expect(manager.cancelGenericOperation(operation.id)).rejects.toThrow('unconfirmed');
    expect(operation.status).toBe('running');
    operation.cancelRemote = vi.fn().mockResolvedValue(undefined);
    await manager.cancelGenericOperation(operation.id);
    expect(operation.status).toBe('cancelled');
  });

  it('fences completion and dependency scheduling while cancellation awaits confirmation', async () => {
    vi.useFakeTimers();
    const { backend, manager } = setup();
    let observe!: (value: Awaited<ReturnType<RemoteExecutionBackend['readJob']>>) => void;
    vi.mocked(backend.readJob).mockReturnValue(new Promise(resolve => { observe = resolve; }));
    const parent = manager.runTask('remote', '', '.', 'sleep 1', 'parent', 60000, 100);
    const child = manager.runTask('remote', '', '.', 'echo child', 'child', 60000, 100, [parent.id]);
    await vi.advanceTimersByTimeAsync(1);
    let confirm!: () => void;
    vi.mocked(backend.cancelJob).mockReturnValue(new Promise<void>(resolve => { confirm = resolve; }));
    const cancellation = manager.cancelTask('remote', parent.id);
    await Promise.resolve();
    observe({ status: 'exited', exitCode: 0, output: Buffer.alloc(0), nextOffset: 0, outputBytes: 0, truncated: false });
    await vi.advanceTimersByTimeAsync(1000);
    expect(parent.status).toBe('running');
    expect(child.status).toBe('queued');
    expect(backend.startJob).toHaveBeenCalledTimes(1);
    confirm(); await cancellation;
    expect(parent.status).toBe('cancelled'); expect(child.status).toBe('blocked');
    expect(backend.startJob).toHaveBeenCalledTimes(1);
    rmSync(parent.logPath!); rmSync(child.logPath!);
  });

});
