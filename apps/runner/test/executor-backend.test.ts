import { EventEmitter } from 'node:events';
import { rmSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { BACKEND_CAPABILITY_IDS } from '@cloud-harness/contracts';
import { DockerExecutorBackend } from '../src/docker-executor-backend.js';
import { DockerGitDataPlane } from '../src/git-data-plane.js';
import type { PtyTransport } from '../src/docker-pty.js';
import type {
  BackendCapabilityMap,
  ExecRequest,
  ExecutorBackend,
  ExecutorInspection,
  ExecutorRef,
  ProvisionContext,
  StreamHandle,
  StreamRequest
} from '../src/executor-backend.js';
import { makeConfig, makeCtx, makeDeps, testDirectories } from './backend-test-utils.js';

const directories = testDirectories;

afterEach(() => {
  vi.clearAllMocks();
  for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true });
});

/** A stream handle backed by a real EventEmitter so close/error semantics behave like a child process. */
class FakeStreamHandle extends EventEmitter implements StreamHandle {
  stdin = null;
  stdout = new EventEmitter() as unknown as NodeJS.ReadableStream;
  stderr = new EventEmitter() as unknown as NodeJS.ReadableStream;
  killed = false;
  kill(): boolean {
    this.killed = true;
    return true;
  }
}

/** Records every verb invocation so tests can assert the full call surface. */
class RecordingBackend implements ExecutorBackend {
  readonly kind = 'docker' as const;
  calls: Array<{ verb: string; args: unknown[] }> = [];
  private record(verb: string, ...args: unknown[]) {
    this.calls.push({ verb, args });
  }
  async provision(ctx: ProvisionContext): Promise<ExecutorRef> {
    this.record('provision', ctx);
    return { backend: 'docker', workspaceId: ctx.record.id, executorId: 'exec-1', generation: ctx.record.generation };
  }
  async ensureActive(ctx: ProvisionContext): Promise<ExecutorRef> {
    this.record('ensureActive', ctx);
    return { backend: 'docker', workspaceId: ctx.record.id, executorId: 'exec-1', generation: ctx.record.generation };
  }
  async exec(_ctx: ProvisionContext, req: ExecRequest) {
    this.record('exec', req);
    return { exitCode: 0, signal: null, stdout: '', stderr: '', truncated: false, timedOut: false };
  }
  async spawnStream(_ctx: ProvisionContext, req: StreamRequest): Promise<StreamHandle> {
    this.record('spawnStream', req);
    return new FakeStreamHandle();
  }
  pty(): PtyTransport {
    this.record('pty');
    return {
      open: vi.fn(),
      resize: vi.fn(),
      inspect: vi.fn(),
      killSession: vi.fn()
    } as unknown as PtyTransport;
  }
  async pullFile(_ctx: ProvisionContext, guestPath: string, maxBytes: number) {
    this.record('pullFile', guestPath, maxBytes);
    return Buffer.from('data');
  }
  async pushTree(_ctx: ProvisionContext, hostDir: string, guestPath: string) {
    this.record('pushTree', hostDir, guestPath);
    return { sha256: 'a'.repeat(64), bytes: 1, entryCount: 1 };
  }
  async pullTree(_ctx: ProvisionContext, guestPath: string, hostDir: string) {
    this.record('pullTree', guestPath, hostDir);
    return { sha256: 'b'.repeat(64), bytes: 1, entryCount: 1 };
  }
  async measureWorkspaceBytes(ctx: ProvisionContext) {
    this.record('measureWorkspaceBytes', ctx);
    return 42;
  }
  async killProcessGroup(_ctx: ProvisionContext, pidFile: string) {
    this.record('killProcessGroup', pidFile);
  }
  async stop(ctx: ProvisionContext) {
    this.record('stop', ctx);
  }
  async destroy(ctx: ProvisionContext) {
    this.record('destroy', ctx);
  }
  async inspect(ctx: ProvisionContext): Promise<ExecutorInspection> {
    this.record('inspect', ctx);
    return { state: 'running' };
  }
  capabilities(): BackendCapabilityMap {
    this.record('capabilities');
    return Object.fromEntries(BACKEND_CAPABILITY_IDS.map((id) => [id, 'supported'])) as BackendCapabilityMap;
  }
}

describe('ExecutorBackend interface conformance', () => {
  it('exercises every verb against a recording fake backend', async () => {
    const backend: ExecutorBackend = new RecordingBackend();
    const ctx = makeCtx();
    const ref = await backend.provision(ctx);
    expect(ref).toMatchObject({ backend: 'docker', workspaceId: ctx.record.id, generation: ctx.record.generation });
    await backend.ensureActive(ctx);
    await backend.exec(ctx, { argv: ['true'], environment: {}, timeoutMs: 1_000, maxBytes: 1_024 });
    const stream = await backend.spawnStream(ctx, { argv: ['cat'], environment: {} });
    expect(stream).toBeInstanceOf(FakeStreamHandle);
    backend.pty(ctx);
    await backend.pullFile(ctx, '/workspace/file.txt', 1_024);
    await backend.pushTree(ctx, '/tmp/src', '/workspace/dst');
    await backend.pullTree(ctx, '/workspace/src', '/tmp/dst');
    await expect(backend.measureWorkspaceBytes(ctx)).resolves.toBe(42);
    await backend.killProcessGroup(ctx, '/tmp/pids');
    await backend.stop(ctx);
    await backend.destroy(ctx);
    await expect(backend.inspect(ctx)).resolves.toEqual({ state: 'running' });
    const caps = backend.capabilities();
    expect(Object.keys(caps).sort()).toEqual([...BACKEND_CAPABILITY_IDS].sort());

    const fake = backend as RecordingBackend;
    expect(fake.calls.map((call) => call.verb)).toEqual([
      'provision', 'ensureActive', 'exec', 'spawnStream', 'pty', 'pullFile', 'pushTree',
      'pullTree', 'measureWorkspaceBytes', 'killProcessGroup', 'stop', 'destroy', 'inspect', 'capabilities'
    ]);
  });

  it('DockerExecutorBackend satisfies the ExecutorBackend interface', () => {
    const backend: ExecutorBackend = new DockerExecutorBackend(makeDeps());
    expect(backend.kind).toBe('docker');
    const caps = backend.capabilities();
    expect(Object.keys(caps).sort()).toEqual([...BACKEND_CAPABILITY_IDS].sort());
    for (const id of BACKEND_CAPABILITY_IDS) expect(caps[id]).toBe('supported');
  });

  it('DockerGitDataPlane satisfies the GitDataPlane interface', () => {
    const backend = new DockerExecutorBackend(makeDeps());
    const plane = new DockerGitDataPlane({ backend, config: makeConfig(), instanceId: 'instance-test' });
    expect(plane.backend).toBe('docker');
    expect(typeof plane.seedCheckout).toBe('function');
    expect(typeof plane.exportObjects).toBe('function');
    expect(typeof plane.importObjects).toBe('function');
    expect(typeof plane.guestGit).toBe('function');
    expect(typeof plane.stagingDir).toBe('function');
  });
});
