import { createHash } from 'node:crypto';
import { readFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { WorkspaceRecord } from '../src/state-store.js';
import { DockerGitDataPlane, bundleHeadsToRefspecs } from '../src/git-data-plane.js';
import type { ExecutorBackend, ExecResult, ProvisionContext } from '../src/executor-backend.js';
import { makeConfig, makeDeps, makeRecord, testDirectories, trackDir } from './backend-test-utils.js';
import { DockerExecutorBackend } from '../src/docker-executor-backend.js';

const docker = vi.hoisted(() => ({
  runDocker: vi.fn(),
  removeContainer: vi.fn(async () => undefined)
}));

vi.mock('../src/docker-engine.js', () => docker);

const directories = testDirectories;

afterEach(() => {
  vi.clearAllMocks();
  for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true });
});

function workspaceDir(): string {
  const dir = trackDir(mkdtempSync(join(tmpdir(), 'cloud-harness-git-plane-')));
  mkdirSync(join(dir, 'repo'), { recursive: true });
  mkdirSync(join(dir, 'git-staging'), { recursive: true });
  return dir;
}

function ctxFor(record: WorkspaceRecord, overrides: Partial<ProvisionContext> = {}): ProvisionContext {
  mkdirSync(record.workspacePath, { recursive: true });
  return {
    record,
    environment: { GH_TOKEN: 'never-in-guest' },
    networkProfile: record.networkProfile,
    stagingDir: join(record.workspacePath, 'git-staging'),
    ...overrides
  };
}

function plane(backend?: ExecutorBackend): DockerGitDataPlane {
  return new DockerGitDataPlane({
    backend: backend ?? new DockerExecutorBackend(makeDeps()),
    config: makeConfig(),
    instanceId: 'instance-test'
  });
}

function ok(stdout = '', stderr = '', exitCode = 0) {
  return { stdout, stderr, exitCode, truncated: false };
}

function dockerCalls(): string[][] {
  return docker.runDocker.mock.calls.map((call) => call[0] as string[]);
}

describe('bundleHeadsToRefspecs', () => {
  it('maps heads to origin remote-tracking refs like today\'s import', () => {
    const out = bundleHeadsToRefspecs('abc123\trefs/heads/main\ndef456 refs/heads/feature/x\n');
    expect(out).toEqual(['+refs/heads/main:refs/remotes/origin/main', '+refs/heads/feature/x:refs/remotes/origin/feature/x']);
  });

  it('maps tags to their own names and HEAD/other refs to FETCH_HEAD', () => {
    const out = bundleHeadsToRefspecs('aaa refs/tags/v1.0\nbbb HEAD\nccc refs/pull/1/head\n');
    expect(out).toEqual(['+refs/tags/v1.0:refs/tags/v1.0', 'HEAD', 'refs/pull/1/head']);
  });

  it('rejects option-injection and malformed refs from untrusted bundle metadata', () => {
    expect(() => bundleHeadsToRefspecs('abc --upload-pack=evil\n')).toThrow();
    expect(() => bundleHeadsToRefspecs('abc refs/heads/../escape\n')).toThrow();
    expect(() => bundleHeadsToRefspecs('abc refs/heads//double\n')).toThrow();
    expect(() => bundleHeadsToRefspecs('abc refs/heads/trail/\n')).toThrow();
    expect(() => bundleHeadsToRefspecs('abc not-a-ref\n')).toThrow();
    expect(() => bundleHeadsToRefspecs(`abc refs/heads/${'x'.repeat(300)}\n`)).toThrow();
  });

  it('caps the number of advertised refs', () => {
    const many = Array.from({ length: 1_100 }, (_, i) => `abc refs/heads/b${i}`).join('\n');
    expect(() => bundleHeadsToRefspecs(many)).toThrow();
  });
});

describe('DockerGitDataPlane.guestGit', () => {
  it('runs git -C /workspace through the backend exec with the ctx environment', async () => {
    const exec = vi.fn(async (): Promise<ExecResult> => ({ exitCode: 0, signal: null, stdout: 'main\n', stderr: '', truncated: false, timedOut: false }));
    const backend = { exec } as unknown as ExecutorBackend;
    const record = makeRecord({ containerName: 'chm-git' });
    const ctx = ctxFor(record);
    const result = await plane(backend).guestGit(ctx, ['-c', 'core.pager=cat', 'branch', '--show-current'], { timeoutMs: 5_000, maxBytes: 8_192 });
    expect(result.stdout).toBe('main\n');
    expect(exec).toHaveBeenCalledWith(ctx, expect.objectContaining({
      argv: ['git', '-C', '/workspace', '-c', 'core.pager=cat', 'branch', '--show-current'],
      environment: ctx.environment,
      timeoutMs: 5_000,
      maxBytes: 8_192
    }));
    const argv = (exec.mock.calls[0]![1] as { argv: string[] }).argv;
    expect(argv.join(' ')).not.toContain('/workspace/repo');
    expect(argv.join(' ')).not.toContain('GH_TOKEN');
  });

  it('uses the read-only host-mount helper when no executor container exists', async () => {
    docker.runDocker.mockResolvedValue(ok('feature-branch\n'));
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: null });
    const result = await plane().guestGit(ctxFor(record), ['-c', 'core.hooksPath=/dev/null', 'branch', '--show-current']);
    expect(result.stdout).toBe('feature-branch\n');
    const args = dockerCalls()[0]!;
    expect(args[0]).toBe('run');
    expect(args).toContain('--entrypoint');
    expect(args[args.indexOf('--entrypoint') + 1]).toBe('git');
    expect(args).toContain('--workdir');
    expect(args[args.indexOf('--workdir') + 1]).toBe('/workspace');
    expect(args).toContain(`${workspacePath}/repo:/workspace:ro`);
    expect(args).toContain('--read-only');
    expect(args).toContain('--network');
    expect(args[args.indexOf('--network') + 1]).toBe('none');
    expect(args.slice(-4)).toEqual(['-c', 'core.hooksPath=/dev/null', 'branch', '--show-current']);
    // The helper env stays the fixed credential-free set — workspace secrets never leak in.
    const envArgs = args.filter((_, i) => args[i - 1] === '--env');
    expect(envArgs).toEqual([]);
    expect(args.join(' ')).not.toContain('GH_TOKEN');
    expect(args.join(' ')).not.toContain('never-in-guest');
  });

  it('rejects non-string args', async () => {
    const backend = { exec: vi.fn() } as unknown as ExecutorBackend;
    const record = makeRecord({ containerName: 'chm-git' });
    await expect(plane(backend).guestGit(ctxFor(record), [1 as never])).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect((backend.exec as ReturnType<typeof vi.fn>)).not.toHaveBeenCalled();
  });
});

describe('DockerGitDataPlane.exportObjects', () => {
  it('creates a bundle through the hardened helper and returns its digest', async () => {
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: 'chm-x' });
    const bundlePath = join(workspacePath, 'git-staging', 'out.bundle');
    const bundleBytes = Buffer.from('FAKE-BUNDLE-CONTENT');
    docker.runDocker.mockImplementation(async (args: string[]) => {
      const createIndex = args.indexOf('create');
      if (createIndex >= 0 && args.includes('bundle')) {
        const bundleArg = args[createIndex + 1]!;
        const hostPath = join(workspacePath, bundleArg.slice('/job/'.length));
        mkdirSync(join(hostPath, '..'), { recursive: true });
        writeFileSync(hostPath, bundleBytes);
      }
      return ok();
    });
    const result = await plane().exportObjects(ctxFor(record), 'main feature', bundlePath);
    expect(result.bytes).toBe(bundleBytes.length);
    expect(result.sha256).toBe(createHash('sha256').update(bundleBytes).digest('hex'));
    const args = dockerCalls()[0]!;
    expect(args).toContain('--network');
    expect(args[args.indexOf('--network') + 1]).toBe('none');
    expect(args).toContain('--user');
    expect(args[args.indexOf('--user') + 1]).toBe('10001:10001');
    expect(args).toContain('--read-only');
    expect(args).toContain('--cap-drop');
    expect(args).toContain('ALL');
    const gitArgs = args.slice(args.indexOf('/usr/bin/git') + 2);
    expect(gitArgs.slice(0, 7)).toEqual(['-c', 'core.hooksPath=/dev/null', '-c', 'core.pager=cat', '-C', '/job/repo', 'bundle']);
    expect(gitArgs).toContain('create');
    expect(gitArgs).toContain('/job/git-staging/out.bundle');
    expect(gitArgs.slice(-2)).toEqual(['main', 'feature']);
  });

  it('rejects option-bearing revision specs before any docker call', async () => {
    const record = makeRecord({ workspacePath: workspaceDir(), containerName: 'chm-x' });
    await expect(plane().exportObjects(ctxFor(record), '--upload-pack=evil', join(record.workspacePath, 'git-staging', 'x.bundle')))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(plane().exportObjects(ctxFor(record), '   ', join(record.workspacePath, 'git-staging', 'x.bundle')))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(docker.runDocker).not.toHaveBeenCalled();
  });

  it('rejects bundle paths outside the workspace job path', async () => {
    const record = makeRecord({ workspacePath: workspaceDir(), containerName: 'chm-x' });
    await expect(plane().exportObjects(ctxFor(record), 'main', '/tmp/elsewhere/x.bundle'))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(docker.runDocker).not.toHaveBeenCalled();
  });
});

describe('DockerGitDataPlane.importObjects', () => {
  function bundleFile(workspacePath: string, content = 'bundle-bytes'): string {
    const path = join(workspacePath, 'git-staging', 'in.bundle');
    mkdirSync(join(workspacePath, 'git-staging'), { recursive: true });
    writeFileSync(path, content);
    return path;
  }
  function sha256(path: string): string {
    return createHash('sha256').update(readFileSync(path)).digest('hex');
  }

  it('verifies the digest, pauses, discovers refs, fetches, and unpauses in order', async () => {
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: 'chm-imp' });
    const bundlePath = bundleFile(workspacePath);
    const digest = sha256(bundlePath);
    const sequence: string[] = [];
    docker.runDocker.mockImplementation(async (args: string[]) => {
      sequence.push(args[0]!);
      if (args.includes('list-heads')) return ok('abc123\trefs/heads/main\n');
      return ok();
    });
    await plane().importObjects(ctxFor(record), bundlePath, digest);
    // Order: list-heads helper, pause, fetch helper, unpause.
    expect(sequence).toEqual(['run', 'pause', 'run', 'unpause']);
    const fetchArgs = dockerCalls()[2]!;
    expect(fetchArgs).toContain('-C');
    expect(fetchArgs).toContain('/job/repo');
    expect(fetchArgs).toContain('fetch');
    expect(fetchArgs).toContain('--no-tags');
    expect(fetchArgs).toContain('/job/git-staging/in.bundle');
    expect(fetchArgs).toContain('+refs/heads/main:refs/remotes/origin/main');
    expect(fetchArgs.join(' ')).not.toContain('/workspace/repo');
  });

  it('rejects a digest mismatch before touching docker', async () => {
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: 'chm-imp' });
    const bundlePath = bundleFile(workspacePath);
    await expect(plane().importObjects(ctxFor(record), bundlePath, 'f'.repeat(64)))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(docker.runDocker).not.toHaveBeenCalled();
  });

  it('rejects malformed expectedSha256 and missing bundles', async () => {
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: 'chm-imp' });
    const bundlePath = bundleFile(workspacePath);
    await expect(plane().importObjects(ctxFor(record), bundlePath, 'not-hex'))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(plane().importObjects(ctxFor(record), join(workspacePath, 'git-staging', 'missing.bundle'), 'a'.repeat(64)))
      .rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(docker.runDocker).not.toHaveBeenCalled();
  });

  it('unpauses and rethrows when the fetch fails', async () => {
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: 'chm-imp' });
    const bundlePath = bundleFile(workspacePath);
    docker.runDocker.mockImplementation(async (args: string[]) => {
      if (args.includes('list-heads')) return ok('abc refs/heads/main\n');
      if (args.includes('fetch')) return ok('', 'fetch blew up', 1);
      return ok();
    });
    await expect(plane().importObjects(ctxFor(record), bundlePath, sha256(bundlePath)))
      .rejects.toMatchObject({ code: 'UNAVAILABLE' });
    const verbs = dockerCalls().map((args) => args[0]);
    expect(verbs).toEqual(['run', 'pause', 'run', 'unpause']);
  });

  it('unpauses with a signal independent of an aborted caller signal', async () => {
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: 'chm-unpause-abort' });
    const bundlePath = bundleFile(workspacePath);
    const controller = new AbortController();
    controller.abort();
    docker.runDocker.mockImplementation(async (args: string[]) => {
      if (args.includes('list-heads')) return ok('abc refs/heads/main\n');
      return ok();
    });
    // Caller cancellation mid-transfer must not skip or cancel the unpause —
    // the old code passed ctx.signal through and could leave Docker paused.
    await plane().importObjects(ctxFor(record, { signal: controller.signal }), bundlePath, sha256(bundlePath)).catch(() => undefined);
    const verbs = dockerCalls().map((args) => args[0]);
    expect(verbs).toContain('unpause');
    const unpauseCall = docker.runDocker.mock.calls[dockerCalls().findIndex((args) => args[0] === 'unpause')];
    const unpauseSignal = (unpauseCall?.[1] as { signal?: AbortSignal } | undefined)?.signal;
    expect(unpauseSignal === undefined || !unpauseSignal.aborted).toBe(true);
  });

  it('throws UNAVAILABLE when the executor cannot be paused', async () => {
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: 'chm-imp' });
    const bundlePath = bundleFile(workspacePath);
    docker.runDocker.mockImplementation(async (args: string[]) => {
      if (args[0] === 'pause') return ok('', 'cannot pause', 1);
      if (args.includes('list-heads')) return ok('abc refs/heads/main\n');
      return ok();
    });
    await expect(plane().importObjects(ctxFor(record), bundlePath, sha256(bundlePath)))
      .rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(dockerCalls().map((args) => args[0])).toEqual(['run', 'pause']);
  });

  it('throws UNAVAILABLE without a container after ref discovery', async () => {
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: null });
    const bundlePath = bundleFile(workspacePath);
    docker.runDocker.mockResolvedValue(ok('abc refs/heads/main\n'));
    await expect(plane().importObjects(ctxFor(record), bundlePath, sha256(bundlePath)))
      .rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(dockerCalls().map((args) => args[0])).toEqual(['run']);
  });
});

describe('DockerGitDataPlane misc', () => {
  it('seedCheckout is a docker no-op and stagingDir returns the ctx staging dir', async () => {
    const record = makeRecord({ workspacePath: workspaceDir(), containerName: 'chm-x' });
    const ctx = ctxFor(record);
    await expect(plane().seedCheckout(ctx, '/nonexistent')).resolves.toBeUndefined();
    expect(plane().stagingDir(ctx)).toBe(ctx.stagingDir);
    expect(docker.runDocker).not.toHaveBeenCalled();
  });
});
