import { EventEmitter } from 'node:events';
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, readlinkSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable, Writable } from 'node:stream';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { HarnessError } from '@cloud-harness/contracts';
import { EXECUTOR_HARDENING_ARGS } from '../src/toolbox-runner.js';
import type { WorkspaceRecord } from '../src/state-store.js';
import { DockerExecutorBackend, envFileContent, type DockerExecutorBackendDeps } from '../src/docker-executor-backend.js';
import type { ProvisionContext } from '../src/executor-backend.js';
import type { PtyConnection, PtyTransport } from '../src/docker-pty.js';
import { makeConfig, makeDeps, makeRecord, testDirectories, trackDir } from './backend-test-utils.js';

const docker = vi.hoisted(() => ({
  runDocker: vi.fn(),
  spawnDocker: vi.fn(),
  removeContainer: vi.fn(async () => undefined),
  inspectContainer: vi.fn(async () => undefined),
  terminateContainerProcessGroup: vi.fn(async () => undefined)
}));

vi.mock('../src/docker-engine.js', () => docker);

const directories = testDirectories;

afterEach(() => {
  vi.clearAllMocks();
  for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true });
});

const EXECUTOR_PATH = '/workspace/node_modules/.bin:/opt/user-tools/bin:/opt/user-tools/pnpm/bin:/opt/user-tools/pnpm:/opt/user-tools/bun/bin:/tmp/cloud-harness-home/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';
const IMAGE = 'cloud-harness-executor:test';

function workspaceDir(): string {
  const dir = trackDir(mkdtempSync(join(tmpdir(), 'cloud-harness-docker-backend-')));
  mkdirSync(join(dir, 'repo'), { recursive: true });
  return dir;
}

function ctxFor(record: WorkspaceRecord, overrides: Partial<ProvisionContext> = {}): ProvisionContext {
  mkdirSync(record.workspacePath, { recursive: true });
  return { record, environment: {}, networkProfile: record.networkProfile, stagingDir: join(record.workspacePath, 'git-staging'), ...overrides };
}

function ok(stdout = '', stderr = '', exitCode = 0) {
  return { stdout, stderr, exitCode, truncated: false };
}

function dockerCalls(): string[][] {
  return docker.runDocker.mock.calls.map((call) => call[0] as string[]);
}

function findCall(predicate: (args: string[]) => boolean): string[] | undefined {
  return dockerCalls().find(predicate);
}

function backend(overrides: Partial<DockerExecutorBackendDeps> = {}): DockerExecutorBackend {
  return new DockerExecutorBackend(makeDeps(overrides));
}

describe('DockerExecutorBackend.provision', () => {
  it('issues create+start argv identical to the current createExecutor shape', async () => {
    docker.runDocker.mockResolvedValue(ok());
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: null });
    const name = `cloud-harness-ws-${record.id.slice(3, 19).toLowerCase()}`;
    const repositoryPath = join(workspacePath, 'repo');
    const toolsPath = join(workspacePath, 'tools');
    const cachePath = join(workspacePath, 'cache');
    const ownerSkillsPath = join(workspacePath, 'toolkit-projection', 'owner-skills');

    const ref = await backend().provision(ctxFor(record));

    expect(ref).toEqual({ backend: 'docker', workspaceId: record.id, executorId: name, generation: record.generation });
    const create = findCall((args) => args[0] === 'create');
    expect(create).toEqual([
      'create', '--name', name,
      '--label', 'cloud-harness.managed=true', '--label', 'cloud-harness.instance=instance-test',
      '--label', `cloud-harness.workspace=${record.id}`,
      ...EXECUTOR_HARDENING_ARGS, '--workdir', '/workspace',
      '--network', 'none',
      '--volume', `${repositoryPath}:/workspace:rw`,
      '--volume', `${toolsPath}:/opt/user-tools:rw`,
      '--volume', `${cachePath}:/var/cache/harness:rw`,
      '--volume', `${ownerSkillsPath}:/opt/cloud-harness/owner-skills:ro`,
      '--env', 'HOME=/tmp/cloud-harness-home',
      '--env', 'GIT_CONFIG_NOSYSTEM=1',
      '--env', 'XDG_CONFIG_HOME=/tmp/cloud-harness-home/.config',
      '--env', 'XDG_CACHE_HOME=/var/cache/harness',
      '--env', 'XDG_DATA_HOME=/opt/user-tools/data',
      '--env', 'NPM_CONFIG_PREFIX=/opt/user-tools',
      '--env', 'NPM_CONFIG_CACHE=/var/cache/harness/npm',
      '--env', 'UV_CACHE_DIR=/var/cache/harness/uv',
      '--env', 'BUN_INSTALL=/opt/user-tools/bun',
      '--env', 'PNPM_HOME=/opt/user-tools/pnpm',
      '--env', 'UV_TOOL_BIN_DIR=/opt/user-tools/bin',
      '--env', `PATH=${EXECUTOR_PATH}`,
      IMAGE
    ]);
    expect(findCall((args) => args[0] === 'start')).toEqual(['start', name]);
  });

  it('writes the provision environment to a mode-0600 env file outside the repo mount and removes it', async () => {
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: null });
    const seen: Array<{ path: string; mode: number; content: string }> = [];
    docker.runDocker.mockImplementation(async (args: string[]) => {
      const envIndex = args.indexOf('--env-file');
      if (envIndex >= 0 && args[0] === 'create') {
        const path = args[envIndex + 1]!;
        const { statSync } = await import('node:fs');
        seen.push({ path, mode: statSync(path).mode & 0o777, content: readFileSync(path, 'utf8') });
      }
      return ok();
    });

    await backend().provision(ctxFor(record, { environment: { MY_SECRET: 's3cr3t-value', PLAIN: 'x' } }));

    expect(seen).toHaveLength(1);
    expect(seen[0]!.path.startsWith(workspacePath)).toBe(true);
    expect(seen[0]!.path).not.toContain('/repo/');
    expect(seen[0]!.mode).toBe(0o600);
    expect(seen[0]!.content).toBe('MY_SECRET=s3cr3t-value\nPLAIN=x\n');
    const create = findCall((args) => args[0] === 'create')!;
    expect(create).toContain('--env-file');
    expect(create.join(' ')).not.toContain('s3cr3t-value');
    expect(create.join(' ')).not.toContain('MY_SECRET=');
    expect(readdirSync(workspacePath).filter((name) => name.startsWith('.env.injected-'))).toEqual([]);
  });

  it('omits --env-file entirely when the environment is empty', async () => {
    docker.runDocker.mockResolvedValue(ok());
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: null });
    await backend().provision(ctxFor(record));
    const create = findCall((args) => args[0] === 'create')!;
    expect(create).not.toContain('--env-file');
  });

  it('mounts builtin skills and package releases read-only when configured', async () => {
    docker.runDocker.mockResolvedValue(ok());
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: null });
    const skillsRoot = join(workspacePath, 'builtin-skills');
    mkdirSync(skillsRoot, { recursive: true });
    const release = { source: '/packages/rel-1', target: '/opt/chm-packages/rel-1' };
    const binDir = '/opt/chm-packages/rel-1/bin';
    const deps = makeDeps({
      config: makeConfig({ packagesEnabled: true, builtinSkillsRoot: skillsRoot }),
      packages: { profileFor: vi.fn(() => ({ mounts: [release], binDirs: [binDir] })) }
    });
    await new DockerExecutorBackend(deps).provision(ctxFor(record));
    const create = findCall((args) => args[0] === 'create')!;
    expect(create).toContain(`${skillsRoot}:/opt/cloud-harness/skills:ro`);
    expect(create).toContain(`${release.source}:${release.target}:ro`);
    const pathArg = create.find((arg) => arg.startsWith('PATH=/workspace/node_modules/.bin:'))!;
    expect(pathArg).toContain(binDir);
    expect(create).toContain(`CLOUD_HARNESS_MANAGED_PATH=${binDir}`);
  });
});

describe('DockerExecutorBackend.ensureActive', () => {
  it('adopts a running container without recreating it', async () => {
    docker.inspectContainer.mockResolvedValue({ State: { Running: true } });
    const record = makeRecord({ containerName: 'chm-live' });
    const ref = await backend().ensureActive(ctxFor(record));
    expect(ref.executorId).toBe('chm-live');
    expect(docker.inspectContainer).toHaveBeenCalledWith('chm-live');
    expect(findCall((args) => args[0] === 'create')).toBeUndefined();
  });

  it('starts a stopped container', async () => {
    docker.inspectContainer.mockResolvedValue({ State: { Running: false } });
    docker.runDocker.mockResolvedValue(ok());
    const record = makeRecord({ containerName: 'chm-stopped' });
    const ref = await backend().ensureActive(ctxFor(record));
    expect(ref.executorId).toBe('chm-stopped');
    expect(findCall((args) => args[0] === 'start' && args[1] === 'chm-stopped')).toBeDefined();
    expect(findCall((args) => args[0] === 'create')).toBeUndefined();
  });

  it('rebuilds dependency-access and quarantined records instead of reusing containers', async () => {
    docker.runDocker.mockResolvedValue(ok());
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: 'chm-old', networkProfile: 'dependency-access' });
    await backend().ensureActive(ctxFor(record));
    expect(docker.removeContainer).toHaveBeenCalledWith('chm-old');
    expect(findCall((args) => args[0] === 'create')).toBeDefined();
  });

  it('throws EXPIRED when the on-disk repository is gone', async () => {
    docker.inspectContainer.mockResolvedValue(undefined);
    const workspacePath = workspaceDir();
    rmSync(join(workspacePath, 'repo'), { recursive: true, force: true });
    const record = makeRecord({ workspacePath, containerName: 'chm-gone' });
    await expect(backend().ensureActive(ctxFor(record))).rejects.toMatchObject({ code: 'EXPIRED' });
  });
});

describe('DockerExecutorBackend.exec', () => {
  it('produces byte-identical docker exec argv for a minimal request', async () => {
    docker.runDocker.mockResolvedValue(ok('out', '', 0));
    const record = makeRecord({ containerName: 'chm-exec' });
    const result = await backend().exec(ctxFor(record), {
      argv: ['git', '-c', 'core.pager=cat', 'status'],
      environment: {},
      timeoutMs: 30_000,
      maxBytes: 8_192
    });
    expect(result).toEqual({ exitCode: 0, signal: null, stdout: 'out', stderr: '', truncated: false, timedOut: false });
    expect(docker.runDocker).toHaveBeenCalledWith(
      ['exec', 'chm-exec', 'git', '-c', 'core.pager=cat', 'status'],
      expect.objectContaining({ timeoutMs: 30_000, maxBytes: 8_192 })
    );
  });

  it('maps stdin/cwd/root user/env overrides onto docker exec flags', async () => {
    docker.runDocker.mockResolvedValue(ok());
    const record = makeRecord({ containerName: 'chm-exec' });
    const ctx = ctxFor(record);
    await backend().exec(ctx, {
      argv: ['id'],
      cwd: '/workspace/sub',
      environment: { TOKEN: 'abc' },
      stdin: 'payload',
      user: 'root',
      timeoutMs: 5_000,
      maxBytes: 1_024
    });
    const args = dockerCalls()[0]!;
    expect(args.slice(0, 7)).toEqual(['exec', '-i', '-w', '/workspace/sub', '--user', '0:0', '--env-file']);
    expect(args[7]).toMatch(/\.env\.exec-[0-9a-f]+$/);
    expect(args[8]).toBe('chm-exec');
    expect(args.slice(9)).toEqual(['id']);
    expect(args.join(' ')).not.toContain('abc');
    expect(args.join(' ')).not.toContain('TOKEN=');
    const options = docker.runDocker.mock.calls[0]![1] as { stdin?: string };
    expect(options.stdin).toBe('payload');
    expect(readdirSync(record.workspacePath).filter((name) => name.startsWith('.env.exec-'))).toEqual([]);
  });

  it('rejects malformed argv and invalid environment keys', async () => {
    const record = makeRecord({ containerName: 'chm-exec' });
    const ctx = ctxFor(record);
    await expect(backend().exec(ctx, { argv: [], environment: {}, timeoutMs: 1, maxBytes: 1 })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(backend().exec(ctx, { argv: ['ok'], environment: { 'BAD NAME': 'x' }, timeoutMs: 1, maxBytes: 1 })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(backend().exec(ctx, { argv: ['ok'], environment: { GOOD: 'has\nnewline' }, timeoutMs: 1, maxBytes: 1 })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(docker.runDocker).not.toHaveBeenCalled();
  });

  it('ephemeral-helper root mode matches the privileged helper shape', async () => {
    docker.runDocker.mockResolvedValue(ok('uid=0'));
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: null, networkProfile: 'network-none' });
    await backend().exec(ctxFor(record), {
      argv: ['/bin/bash', '-c', 'id'],
      cwd: '/workspace',
      executionMode: 'ephemeral-helper',
      user: 'root',
      environment: {},
      timeoutMs: 60_000,
      maxBytes: 262_144
    });
    const args = dockerCalls()[0]!;
    expect(args.slice(0, 2)).toEqual(['run', '-i']);
    expect(args).toContain('--rm');
    expect(args).toContain('cloud-harness.role=priv-exec');
    expect(args).toContain('cloud-harness.ephemeral=true');
    expect(args).toContain(`cloud-harness.workspace=${record.id}`);
    expect(args).toContain('--network');
    expect(args[args.indexOf('--user') + 1]).toBe('0:0');
    expect(args).not.toContain('--cap-drop');
    expect(args).toContain('--workdir');
    expect(args[args.indexOf('--workdir') + 1]).toBe('/workspace');
    expect(args).toContain(`${workspacePath}/repo:/workspace:rw`);
    expect(args).toContain(`${workspacePath}/tools:/opt/user-tools:rw`);
    expect(args).toContain(`${workspacePath}/cache:/var/cache/harness:rw`);
    expect(args).toContain(`PATH=${EXECUTOR_PATH}`);
    expect(args[args.length - 4]).toBe(IMAGE);
    expect(args.slice(-3)).toEqual(['/bin/bash', '-c', 'id']);
  });

  it('ephemeral-helper workspace mode drops all caps like skills_run', async () => {
    docker.runDocker.mockResolvedValue(ok());
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: null });
    await backend().exec(ctxFor(record), {
      argv: ['/bin/bash', '-c', 'node /opt/harness/harness-worker.mjs'],
      executionMode: 'ephemeral-helper',
      user: 'workspace',
      environment: {},
      timeoutMs: 60_000,
      maxBytes: 1_024
    });
    const args = dockerCalls()[0]!;
    expect(args[args.indexOf('--user') + 1]).toBe('10001:10001');
    expect(args).toContain('--cap-drop');
    expect(args).toContain('ALL');
    expect(args).toContain('no-new-privileges:true');
  });
});

describe('DockerExecutorBackend.spawnStream', () => {
  function fakeChild() {
    const child = new EventEmitter() as EventEmitter & {
      stdin: Writable; stdout: Readable; stderr: Readable; kill: ReturnType<typeof vi.fn>;
    };
    child.stdin = new Writable({ write: (_c, _e, cb) => cb() });
    child.stdout = new Readable({ read: () => undefined });
    child.stderr = new Readable({ read: () => undefined });
    child.kill = vi.fn(() => true);
    return child;
  }

  it('spawns docker exec -i and keeps the env file until close', async () => {
    const child = fakeChild();
    docker.spawnDocker.mockReturnValue(child as never);
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: 'chm-stream' });
    const handle = await backend().spawnStream(ctxFor(record), {
      argv: ['/usr/bin/setsid', '--wait', '/opt/harness/worker-runner.sh', 'op_1'],
      environment: { RUN_TOKEN: 'sekret' }
    });
    expect(docker.spawnDocker).toHaveBeenCalledWith(
      expect.arrayContaining(['exec', '-i', 'chm-stream', '/usr/bin/setsid', '--wait', '/opt/harness/worker-runner.sh', 'op_1'])
    );
    const spawnArgs = docker.spawnDocker.mock.calls[0]![0] as string[];
    expect(spawnArgs.join(' ')).not.toContain('sekret');
    expect(spawnArgs.join(' ')).not.toContain('RUN_TOKEN=');
    const envFiles = readdirSync(workspacePath).filter((name) => name.startsWith('.env.stream-'));
    expect(envFiles).toHaveLength(1);
    expect(readFileSync(join(workspacePath, envFiles[0]!), 'utf8')).toBe('RUN_TOKEN=sekret\n');
    child.emit('close', 0, null);
    await vi.waitFor(() => {
      expect(readdirSync(workspacePath).filter((name) => name.startsWith('.env.stream-'))).toEqual([]);
    });
    expect(handle.stdout).toBe(child.stdout);
    expect(handle.stdin).toBe(child.stdin);
  });

  it('routes pty streams through the PtyTransport with a stream- terminal id', async () => {
    const connection = {
      execId: 'exec-1', writableLength: 0,
      write: vi.fn(), onData: vi.fn(), onEnd: vi.fn(), close: vi.fn()
    } as unknown as PtyConnection;
    const transport: PtyTransport = {
      open: vi.fn(async () => connection),
      resize: vi.fn(async () => undefined),
      inspect: vi.fn(async () => ({ running: true, exitCode: null })),
      killSession: vi.fn(async () => undefined)
    };
    const record = makeRecord({ containerName: 'chm-pty' });
    const handle = await backend({ ptyTransport: transport }).spawnStream(ctxFor(record), {
      argv: ['ignored'],
      cwd: '/workspace/src',
      environment: {},
      pty: { cols: 120, rows: 40 }
    });
    expect(transport.open).toHaveBeenCalledWith(expect.objectContaining({
      container: 'chm-pty',
      workingDir: '/workspace/src',
      cols: 120,
      rows: 40
    }));
    const openArg = (transport.open as ReturnType<typeof vi.fn>).mock.calls[0]![0] as { terminalId: string };
    expect(openArg.terminalId).toMatch(/^stream-[0-9a-f]+$/);
    handle.kill();
    expect(connection.close).toHaveBeenCalled();
    expect(transport.killSession).toHaveBeenCalledWith('chm-pty', openArg.terminalId);
  });

  it('forwards argv and environment to the PTY transport verbatim', async () => {
    const connection = {
      execId: 'exec-argv', writableLength: 0,
      write: vi.fn(), onData: vi.fn(), onEnd: vi.fn(), close: vi.fn()
    } as unknown as PtyConnection;
    const transport: PtyTransport = {
      open: vi.fn(async () => connection),
      resize: vi.fn(async () => undefined),
      inspect: vi.fn(async () => ({ running: true, exitCode: null })),
      killSession: vi.fn(async () => undefined)
    };
    const record = makeRecord({ containerName: 'chm-pty-argv' });
    await backend({ ptyTransport: transport }).spawnStream(ctxFor(record), {
      argv: ['/bin/bash', '-lc', 'echo hi'],
      cwd: '/workspace/src',
      environment: { FOO: 'bar', TERM: 'xterm-256color' },
      pty: { cols: 80, rows: 24 }
    });
    expect(transport.open).toHaveBeenCalledWith(expect.objectContaining({
      argv: ['/bin/bash', '-lc', 'echo hi'],
      environment: { FOO: 'bar', TERM: 'xterm-256color' }
    }));
  });

  it('PTY stream close emits the real exit code resolved via inspect', async () => {
    let endListener: ((end: { error?: Error }) => void) | undefined;
    const connection = {
      execId: 'exec-exit', writableLength: 0,
      write: vi.fn(),
      onData: vi.fn(),
      onEnd: vi.fn((listener: (end: { error?: Error }) => void) => { endListener = listener; }),
      close: vi.fn()
    } as unknown as PtyConnection;
    const transport: PtyTransport = {
      open: vi.fn(async () => connection),
      resize: vi.fn(async () => undefined),
      inspect: vi.fn(async () => ({ running: false, exitCode: 3 })),
      killSession: vi.fn(async () => undefined)
    };
    const record = makeRecord({ containerName: 'chm-pty-exit' });
    const handle = await backend({ ptyTransport: transport }).spawnStream(ctxFor(record), {
      argv: ['true'], environment: {}, pty: { cols: 80, rows: 24 }
    });
    const closed = new Promise<[number | null, string | null]>((resolve) => {
      handle.on('close', (code, signal) => resolve([code, signal]));
    });
    endListener!({});
    await expect(closed).resolves.toEqual([3, null]);
    expect(transport.inspect).toHaveBeenCalledWith('exec-exit');
  });
});

describe('DockerExecutorBackend file/tree verbs', () => {
  it('pullFile reads through the /workspace mount with bounded verification', async () => {
    const workspacePath = workspaceDir();
    writeFileSync(join(workspacePath, 'repo', 'hello.txt'), 'hello');
    const record = makeRecord({ workspacePath });
    const data = await backend().pullFile(ctxFor(record), '/workspace/hello.txt', 100);
    expect(data.toString()).toBe('hello');
    await expect(backend().pullFile(ctxFor(record), '/etc/passwd', 100)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(backend().pullFile(ctxFor(record), '/workspace/../escape', 100)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(backend().pullFile(ctxFor(record), '/opt/cloud-harness/owner-skills/x', 100)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('pullFile can read writable mounts beyond /workspace', async () => {
    const workspacePath = workspaceDir();
    mkdirSync(join(workspacePath, 'tools', 'bin'), { recursive: true });
    writeFileSync(join(workspacePath, 'tools', 'bin', 'tool'), '#!/bin/sh\n');
    const record = makeRecord({ workspacePath });
    const data = await backend().pullFile(ctxFor(record), '/opt/user-tools/bin/tool', 100);
    expect(data.toString()).toContain('#!/bin/sh');
  });

  it('pushTree copies a host tree into the guest mount and returns a manifest digest', async () => {
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath });
    const hostDir = mkdtempSync(join(tmpdir(), 'cloud-harness-push-'));
    trackDir(hostDir);
    writeFileSync(join(hostDir, 'a.txt'), 'alpha');
    mkdirSync(join(hostDir, 'sub'));
    writeFileSync(join(hostDir, 'sub', 'b.txt'), 'beta');
    symlinkSync('a.txt', join(hostDir, 'link'));

    const result = await backend().pushTree(ctxFor(record), hostDir, '/workspace/imported');
    expect(result.entryCount).toBe(4);
    expect(result.bytes).toBe('alpha'.length + 'beta'.length);
    expect(readFileSync(join(workspacePath, 'repo', 'imported', 'a.txt'), 'utf8')).toBe('alpha');
    expect(readFileSync(join(workspacePath, 'repo', 'imported', 'sub', 'b.txt'), 'utf8')).toBe('beta');
    const { lstatSync, readlinkSync } = await import('node:fs');
    expect(lstatSync(join(workspacePath, 'repo', 'imported', 'link')).isSymbolicLink()).toBe(true);
    expect(readlinkSync(join(workspacePath, 'repo', 'imported', 'link'))).toBe('a.txt');
    expect(result.sha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it.runIf(typeof process.getuid !== 'function' || process.getuid() !== 0)(
    'pushTree does not leak fds when a source directory cannot be opened',
    async () => {
      const workspacePath = workspaceDir();
      const record = makeRecord({ workspacePath });
      const hostDir = mkdtempSync(join(tmpdir(), 'cloud-harness-push-fd-'));
      trackDir(hostDir);
      mkdirSync(join(hostDir, 'blocked'));
      writeFileSync(join(hostDir, 'ok.txt'), 'x');
      // lstat reports a directory but open(O_RDONLY|O_DIRECTORY|O_NOFOLLOW)
      // fails EACCES — exactly the vanish/swap failure shape the fix covers.
      chmodSync(join(hostDir, 'blocked'), 0o000);
      const fdCount = () => readdirSync('/proc/self/fd').length;
      try {
        // Warm-up: settle any lazy one-time fds before measuring.
        await expect(backend().pushTree(ctxFor(record), hostDir, '/workspace/warm')).rejects.toThrow();
        const before = fdCount();
        for (let i = 0; i < 25; i += 1) {
          await expect(backend().pushTree(ctxFor(record), hostDir, `/workspace/leak-${i}`)).rejects.toThrow();
        }
        // Pre-fix each failure leaked the already-open targetChild fd (+25).
        expect(fdCount()).toBeLessThanOrEqual(before + 2);
      } finally {
        // Restore traversal so afterEach rmSync can clean the fixture.
        chmodSync(join(hostDir, 'blocked'), 0o755);
      }
    }
  );

  it('pushTree rejects read-only mounts and non-directory sources', async () => {
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath });
    const ctx = ctxFor(record);
    await expect(backend().pushTree(ctx, workspacePath, '/opt/cloud-harness/owner-skills/x')).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(backend().pushTree(ctx, join(workspacePath, 'missing'), '/workspace/x')).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(backend().pushTree(ctx, workspacePath, '/not-mounted/x')).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('pushTree rejects source/destination overlap before any mutation', async () => {
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath });
    const ctx = ctxFor(record);
    // Equal paths: hostDir IS the resolved destination.
    const inner = join(workspacePath, 'repo', 'inner');
    mkdirSync(inner, { recursive: true });
    writeFileSync(join(inner, 'keep.txt'), 'keep');
    await expect(backend().pushTree(ctx, inner, '/workspace/inner'))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(readFileSync(join(inner, 'keep.txt'), 'utf8')).toBe('keep');
    // Destination nested INSIDE the source — the old recursive copy would
    // descend into its own output.
    await expect(backend().pushTree(ctx, join(workspacePath, 'repo'), '/workspace/inner/deeper'))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Source nested inside the destination — copying would overwrite the
    // source tree's own parent directories mid-read.
    mkdirSync(join(workspacePath, 'repo', 'inner', 'deep'), { recursive: true });
    writeFileSync(join(workspacePath, 'repo', 'inner', 'deep', 'keep2.txt'), 'keep2');
    await expect(backend().pushTree(ctx, join(workspacePath, 'repo', 'inner', 'deep'), '/workspace/inner'))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(readFileSync(join(workspacePath, 'repo', 'inner', 'deep', 'keep2.txt'), 'utf8')).toBe('keep2');
    // Symlink alias: hostDir is a symlink whose target nests inside the
    // destination — lexical paths differ, canonical paths overlap.
    const alias = join(workspacePath, 'repo', 'alias');
    symlinkSync(join(workspacePath, 'repo', 'inner'), alias, 'dir');
    await expect(backend().pushTree(ctx, alias, '/workspace/inner/deeper'))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(readFileSync(join(inner, 'keep.txt'), 'utf8')).toBe('keep');
  });

  it('pullTree rejects a host destination overlapping the mounted source', async () => {
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath });
    writeFileSync(join(workspacePath, 'repo', 'one.txt'), 'one');
    // Destination nested inside the source tree.
    await expect(backend().pullTree(ctxFor(record), '/workspace', join(workspacePath, 'repo', 'pulled')))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Source nested inside the destination — the mirror direction.
    mkdirSync(join(workspacePath, 'repo', 'inner'), { recursive: true });
    await expect(backend().pullTree(ctxFor(record), '/workspace/inner', workspacePath))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Equal canonical paths through a symlinked destination.
    const alias = join(workspacePath, 'repo-alias');
    symlinkSync(join(workspacePath, 'repo'), alias, 'dir');
    await expect(backend().pullTree(ctxFor(record), '/workspace', alias))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('pushTree chowns the destination root even for an empty source tree', async () => {
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath });
    const hostDir = trackDir(mkdtempSync(join(tmpdir(), 'cloud-harness-push-empty-')));
    await backend().pushTree(ctxFor(record), hostDir, '/workspace/empty-import');
    const hostPath = join(workspacePath, 'repo', 'empty-import');
    // Non-root runners cannot chown directly, so the fallback helper must run
    // — its 'chown -R' covers the destination root that afterCreate never saw.
    const helperRan = dockerCalls().some((args) => args.some((a) => typeof a === 'string' && a.includes('chown -R')));
    const owned = statSync(hostPath).uid === 10001;
    expect(helperRan || owned).toBe(true);
  });

  it('pullTree round-trips content with an identical manifest digest', async () => {
    const workspacePath = workspaceDir();
    writeFileSync(join(workspacePath, 'repo', 'one.txt'), 'one');
    mkdirSync(join(workspacePath, 'repo', 'deep'));
    writeFileSync(join(workspacePath, 'repo', 'deep', 'two.txt'), 'two');
    const record = makeRecord({ workspacePath });
    const hostDir = mkdtempSync(join(tmpdir(), 'cloud-harness-pull-'));
    trackDir(hostDir);
    const result = await backend().pullTree(ctxFor(record), '/workspace', hostDir);
    expect(readFileSync(join(hostDir, 'one.txt'), 'utf8')).toBe('one');
    expect(readFileSync(join(hostDir, 'deep', 'two.txt'), 'utf8')).toBe('two');
    expect(result.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(result.entryCount).toBe(3);
    await expect(backend().pullTree(ctxFor(record), '/workspace/missing', hostDir)).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
});

describe('DockerExecutorBackend.measureWorkspaceBytes / killProcessGroup / lifecycle', () => {
  it('measures the three workspace roots via docker exec du', async () => {
    docker.runDocker.mockResolvedValue(ok('100\t/workspace\n200\t/opt/user-tools\n300\t/var/cache/harness\n'));
    const record = makeRecord({ containerName: 'chm-size' });
    const total = await backend().measureWorkspaceBytes(ctxFor(record));
    expect(total).toBe(600);
    expect(docker.runDocker).toHaveBeenCalledWith(
      ['exec', 'chm-size', '/usr/bin/du', '-sb', '--apparent-size', '/workspace', '/opt/user-tools', '/var/cache/harness'],
      expect.objectContaining({ timeoutMs: 30_000, maxBytes: 8_192 })
    );
  });

  it('falls back to the read-only size helper when exec du fails', async () => {
    docker.runDocker
      .mockResolvedValueOnce(ok('', 'exec failed', 1))
      .mockResolvedValueOnce(ok('42\t/target\n'));
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath, containerName: 'chm-size' });
    const total = await backend().measureWorkspaceBytes(ctxFor(record));
    expect(total).toBe(42);
    const helper = dockerCalls().find((args) => args[0] === 'run')!;
    expect(helper).toContain('--entrypoint');
    expect(helper[helper.indexOf('--entrypoint') + 1]).toBe('/usr/bin/du');
    expect(helper).toContain(`${workspacePath}:/target:ro`);
    expect(helper).toContain('--read-only');
    expect(helper).toContain('--user');
    expect(helper[helper.indexOf('--user') + 1]).toBe('0:0');
  });

  it('throws UNAVAILABLE when both measurement paths fail', async () => {
    docker.runDocker.mockResolvedValue(ok('', 'nope', 1));
    const record = makeRecord({ workspacePath: workspaceDir(), containerName: 'chm-size' });
    await expect(backend().measureWorkspaceBytes(ctxFor(record))).rejects.toMatchObject({ code: 'UNAVAILABLE' });
  });

  it('killProcessGroup delegates to terminateContainerProcessGroup', async () => {
    const record = makeRecord({ containerName: 'chm-kill' });
    await backend().killProcessGroup(ctxFor(record), '/tmp/pids.json');
    expect(docker.terminateContainerProcessGroup).toHaveBeenCalledWith('chm-kill', '/tmp/pids.json');
  });

  it('stop issues docker stop and tolerates missing containers', async () => {
    docker.runDocker.mockResolvedValue(ok());
    const record = makeRecord({ containerName: 'chm-stop' });
    await backend().stop(ctxFor(record));
    expect(findCall((args) => args[0] === 'stop')).toEqual(['stop', 'chm-stop']);
    docker.runDocker.mockResolvedValue(ok('', 'Error: No such container: chm-stop', 1));
    await expect(backend().stop(ctxFor(record))).resolves.toBeUndefined();
    docker.runDocker.mockResolvedValue(ok('', 'daemon exploded', 1));
    await expect(backend().stop(ctxFor(record))).rejects.toMatchObject({ code: 'UNAVAILABLE' });
  });

  it('destroy removes the container and inspect maps docker state', async () => {
    const record = makeRecord({ containerName: 'chm-inspect' });
    await backend().destroy(ctxFor(record));
    expect(docker.removeContainer).toHaveBeenCalledWith('chm-inspect');
    docker.inspectContainer.mockResolvedValue({ State: { Running: true } });
    await expect(backend().inspect(ctxFor(record))).resolves.toEqual({ state: 'running' });
    docker.inspectContainer.mockResolvedValue({ State: { Running: false } });
    await expect(backend().inspect(ctxFor(record))).resolves.toEqual({ state: 'stopped' });
    docker.inspectContainer.mockResolvedValue(undefined);
    await expect(backend().inspect(ctxFor(record))).resolves.toEqual({ state: 'missing' });
    docker.inspectContainer.mockRejectedValue(new Error('socket gone'));
    await expect(backend().inspect(ctxFor(record))).resolves.toEqual({ state: 'unknown' });
    const noName = makeRecord({ containerName: null });
    await expect(backend().inspect(ctxFor(noName))).resolves.toEqual({ state: 'missing' });
  });

  it('destroy propagates removal failure so callers keep state recoverable', async () => {
    // closeRecord semantics depend on this: an unconfirmed removal must reject,
    // never resolve — the workspace record stays REAPING and files survive.
    docker.removeContainer.mockRejectedValueOnce(new HarnessError('UNAVAILABLE', 'Docker unavailable', 503, true));
    const record = makeRecord({ containerName: 'chm-stuck' });
    await expect(backend().destroy(ctxFor(record))).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    const noName = makeRecord({ containerName: null });
    await expect(backend().destroy(ctxFor(noName))).resolves.toBeUndefined();
    expect(docker.removeContainer).toHaveBeenCalledTimes(1);
  });
});

describe('envFileContent', () => {
  it('serializes KEY=VALUE lines and rejects invalid entries', () => {
    expect(envFileContent({ A: '1', B: 'two' })).toBe('A=1\nB=two\n');
    expect(() => envFileContent({ '9BAD': 'x' })).toThrow(HarnessError);
    expect(() => envFileContent({ GOOD: 'a\nb' })).toThrow(HarnessError);
  });
});

// ---------------------------------------------------------------------------
// Round-2 review: mount containment + safe tree overwrite (SEC findings)
// ---------------------------------------------------------------------------

describe('DockerExecutorBackend tree containment', () => {
  function hostTree(files: Record<string, string>): string {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'cloud-harness-push-')));
    for (const [rel, data] of Object.entries(files)) {
      const target = join(dir, rel);
      mkdirSync(join(target, '..'), { recursive: true });
      writeFileSync(target, data);
    }
    return dir;
  }

  it('pushTree rejects a guest-planted symlink in the destination ancestry', async () => {
    docker.runDocker.mockResolvedValue(ok());
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath });
    const outside = trackDir(mkdtempSync(join(tmpdir(), 'cloud-harness-outside-')));
    // The guest controls the mounted tree: 'escape' is a symlink to a host
    // dir outside the mount. Lexical resolution alone would happily write
    // through it — the no-follow ancestry check must refuse first.
    symlinkSync(outside, join(workspacePath, 'repo', 'escape'));
    const hostDir = hostTree({ 'a.txt': 'alpha' });
    await expect(backend().pushTree(ctxFor(record), hostDir, '/workspace/escape/sub'))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(readdirSync(outside)).toEqual([]);
  });

  it('pullTree rejects a symlinked guest source root instead of reading outside the mount', async () => {
    docker.runDocker.mockResolvedValue(ok());
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath });
    const outside = trackDir(mkdtempSync(join(tmpdir(), 'cloud-harness-secret-')));
    writeFileSync(join(outside, 'secret.txt'), 'host-secret');
    symlinkSync(outside, join(workspacePath, 'repo', 'evil'));
    const hostDir = trackDir(mkdtempSync(join(tmpdir(), 'cloud-harness-pull-')));
    await expect(backend().pullTree(ctxFor(record), '/workspace/evil', hostDir))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(readdirSync(hostDir)).toEqual([]);
  });

  it('pullTree preserves guest symlinks verbatim without reading through them', async () => {
    docker.runDocker.mockResolvedValue(ok());
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath });
    const guestTree = join(workspacePath, 'repo', 'export');
    mkdirSync(join(guestTree, 'sub'), { recursive: true });
    writeFileSync(join(guestTree, 'sub', 'target.txt'), 'payload');
    // A relative link must survive as a RELATIVE link — rewriting it to an
    // absolute mount path changes semantics once the tree moves.
    symlinkSync('sub/target.txt', join(guestTree, 'rel-link'));
    // An absolute escape link is copied as a link only — never followed, so
    // no host bytes are read through it during the copy.
    symlinkSync('/etc/passwd', join(guestTree, 'abs-link'));
    const hostDir = trackDir(mkdtempSync(join(tmpdir(), 'cloud-harness-pull-')));
    await backend().pullTree(ctxFor(record), '/workspace/export', hostDir);
    expect(lstatSync(join(hostDir, 'rel-link')).isSymbolicLink()).toBe(true);
    expect(readlinkSync(join(hostDir, 'rel-link'))).toBe('sub/target.txt');
    expect(readlinkSync(join(hostDir, 'abs-link'))).toBe('/etc/passwd');
    expect(readFileSync(join(hostDir, 'sub', 'target.txt'), 'utf8')).toBe('payload');
    // Nothing may have materialized the link TARGETS' contents.
    expect(readdirSync(hostDir).sort()).toEqual(['abs-link', 'rel-link', 'sub']);
  });

  it('pushTree overwrites file↔symlink conflicts without recursive-deleting unknown dirs', async () => {
    docker.runDocker.mockResolvedValue(ok());
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath });
    const outside = trackDir(mkdtempSync(join(tmpdir(), 'cloud-harness-unknown-')));
    writeFileSync(join(outside, 'precious.txt'), 'do-not-touch');
    const imported = join(workspacePath, 'repo', 'imported');
    mkdirSync(imported, { recursive: true });
    // Guest-side pre-existing state the source must overwrite safely:
    //  - 'was-link' is a symlink at a path where the source has a directory
    //  - 'was-file' is a regular file where the source has a different file
    //  - 'was-symlink' is a symlink where the source has a file
    //  - 'keep-dir' is a real directory the source does NOT describe — it
    //    must survive untouched (no rm -rf of unknown targets).
    symlinkSync(outside, join(imported, 'was-link'));
    writeFileSync(join(imported, 'was-file'), 'old-content');
    symlinkSync('was-file', join(imported, 'was-symlink'));
    mkdirSync(join(imported, 'keep-dir'));
    writeFileSync(join(imported, 'keep-dir', 'precious.txt'), 'guest-data');

    const hostDir = hostTree({
      'was-link/inner.txt': 'new-inner',
      'was-file': 'new-content',
      'was-symlink': 'now-a-file',
      'fresh.txt': 'fresh'
    });
    await backend().pushTree(ctxFor(record), hostDir, '/workspace/imported');

    // The directory-over-symlink was UNLINKED (never followed): outside dir
    // is untouched and 'was-link' is now a real directory with the content.
    expect(readdirSync(outside)).toEqual(['precious.txt']);
    expect(lstatSync(join(imported, 'was-link')).isDirectory()).toBe(true);
    expect(readFileSync(join(imported, 'was-link', 'inner.txt'), 'utf8')).toBe('new-inner');
    // File-over-file truncates in place; file-over-symlink unlinks the link
    // first so the write can never land through it.
    expect(readFileSync(join(imported, 'was-file'), 'utf8')).toBe('new-content');
    expect(lstatSync(join(imported, 'was-symlink')).isFile()).toBe(true);
    expect(readFileSync(join(imported, 'was-symlink'), 'utf8')).toBe('now-a-file');
    // Undescribed guest directory survives byte-for-byte.
    expect(readFileSync(join(imported, 'keep-dir', 'precious.txt'), 'utf8')).toBe('guest-data');
    expect(readFileSync(join(imported, 'fresh.txt'), 'utf8')).toBe('fresh');
  });

  it('pushTree refuses file-over-real-directory rather than recursively deleting it', async () => {
    docker.runDocker.mockResolvedValue(ok());
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath });
    const imported = join(workspacePath, 'repo', 'imported');
    mkdirSync(join(imported, 'blocker'), { recursive: true });
    writeFileSync(join(imported, 'blocker', 'guest-data.txt'), 'keep-me');
    const hostDir = hostTree({ 'blocker': 'now-a-file' });
    await expect(backend().pushTree(ctxFor(record), hostDir, '/workspace/imported'))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // The unknown directory and its contents are preserved exactly.
    expect(readFileSync(join(imported, 'blocker', 'guest-data.txt'), 'utf8')).toBe('keep-me');
    expect(lstatSync(join(imported, 'blocker')).isDirectory()).toBe(true);
  });

  it('pushTree preserves source directory modes on the destination', async () => {
    docker.runDocker.mockResolvedValue(ok());
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath });
    const hostDir = trackDir(mkdtempSync(join(tmpdir(), 'cloud-harness-modes-')));
    mkdirSync(join(hostDir, 'sub'), { mode: 0o750 });
    writeFileSync(join(hostDir, 'sub', 'f.txt'), 'x');
    const { chmodSync } = await import('node:fs');
    chmodSync(join(hostDir, 'sub'), 0o750);
    await backend().pushTree(ctxFor(record), hostDir, '/workspace/modes');
    const dest = join(workspacePath, 'repo', 'modes', 'sub');
    expect(statSync(dest).mode & 0o7777).toBe(0o750);
  });

  it('pushTree: intermediate dir swapped for a symlink mid-copy never writes outside the mount', async () => {
    docker.runDocker.mockResolvedValue(ok());
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath });
    const outside = trackDir(mkdtempSync(join(tmpdir(), 'cloud-harness-swap-out-')));
    // Pre-existing guest dir that ensureRealDestinationDir will REUSE: the
    // swap below replaces it mid-recursion, after its fd is already pinned.
    const guestSub = join(workspacePath, 'repo', 'imported', 'sub');
    mkdirSync(guestSub, { recursive: true });
    const hostDir = hostTree({
      // 'aaa-big' sorts first inside sub and takes long enough to copy that
      // the swap deterministically lands while later entries are pending.
      'sub/aaa-big': 'x'.repeat(96 * 1024 * 1024),
      'sub/zzz-late.txt': 'must-stay-inside'
    });
    const pending = backend().pushTree(ctxFor(record), hostDir, '/workspace/imported');
    // Wait until the big file's destination exists — proof the recursion is
    // inside 'sub' — then swap the intermediate dir for a symlink to the
    // outside dir, exactly like a hostile guest racing the copy.
    const destBig = join(guestSub, 'aaa-big');
    const deadline = Date.now() + 15_000;
    for (;;) {
      if (existsSync(destBig)) break;
      if (Date.now() > deadline) throw new Error('copy never reached sub/aaa-big');
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    // Rename-swap, not unlink: the real directory stays reachable as
    // 'sub.old', which is what a hostile guest actually does (mv + ln -s).
    // An rm-unlink swap makes even the vulnerable baseline fail loudly
    // before any escape, so it cannot discriminate the fix.
    const guestSubOld = join(workspacePath, 'repo', 'imported', 'sub.old');
    renameSync(guestSub, guestSubOld);
    symlinkSync(outside, guestSub, 'dir');
    // The copy must COMPLETE and the late entry must land inside the pinned
    // real directory (now reachable as sub.old) — never through the link.
    await expect(pending).resolves.toBeDefined();
    expect(existsSync(join(guestSubOld, 'zzz-late.txt'))).toBe(true);
    expect(readdirSync(outside)).toEqual([]);
    expect(lstatSync(guestSub).isSymbolicLink()).toBe(true);
    expect(readlinkSync(guestSub)).toBe(outside);
  });

  it('pullTree: intermediate dir swapped for a symlink mid-copy never reads outside the mount', async () => {
    docker.runDocker.mockResolvedValue(ok());
    const workspacePath = workspaceDir();
    const record = makeRecord({ workspacePath });
    const guestSub = join(workspacePath, 'repo', 'export', 'sub');
    mkdirSync(guestSub, { recursive: true });
    writeFileSync(join(guestSub, 'aaa-big'), 'g'.repeat(96 * 1024 * 1024));
    writeFileSync(join(guestSub, 'zzz-late.txt'), 'guest-data');
    const outside = trackDir(mkdtempSync(join(tmpdir(), 'cloud-harness-secret-out-')));
    // The sentinel sits at the exact entry name the recursion still expects:
    // a path-based reader resolves the swapped link and copies host bytes in.
    writeFileSync(join(outside, 'zzz-late.txt'), 'HOST-SECRET-SENTINEL');
    writeFileSync(join(outside, 'secret.txt'), 'HOST-SECRET-SENTINEL');
    const hostDir = trackDir(mkdtempSync(join(tmpdir(), 'cloud-harness-pull-swap-')));
    const pending = backend().pullTree(ctxFor(record), '/workspace/export', hostDir).then(
      (value) => ({ ok: true as const, value }),
      (error: unknown) => ({ ok: false as const, error })
    );
    // Same gate: wait for the big file to land in the destination, then swap
    // the guest-side intermediate dir for a link at the host secret dir.
    const destBig = join(hostDir, 'sub', 'aaa-big');
    const deadline = Date.now() + 15_000;
    for (;;) {
      if (existsSync(destBig)) break;
      if (Date.now() > deadline) throw new Error('pull never reached sub/aaa-big');
      await new Promise((resolve) => setTimeout(resolve, 1));
    }
    // Rename-swap like the push side: the real dir stays reachable as
    // 'sub.old', matching a hostile guest's mv + ln -s.
    const guestSubOld = join(workspacePath, 'repo', 'export', 'sub.old');
    renameSync(guestSub, guestSubOld);
    symlinkSync(outside, guestSub, 'dir');
    // The pinned source dirfd lets the pull COMPLETE from the real directory;
    // a path-based reader resolves the link and leaks the sentinel instead.
    const settled = await pending;
    expect(settled.ok).toBe(true);
    expect(readFileSync(join(hostDir, 'sub', 'zzz-late.txt'), 'utf8')).toBe('guest-data');
    // No matter where the swap landed, host bytes must not leak: the pull
    // either fails loudly or completes having read only the pinned real dir.
    const leaked = (dir: string): boolean => {
      for (const name of readdirSync(dir)) {
        const full = join(dir, name);
        const info = lstatSync(full);
        if (info.isDirectory()) { if (leaked(full)) return true; }
        else if (info.isFile() && readFileSync(full, 'utf8').includes('HOST-SECRET-SENTINEL')) return true;
      }
      return false;
    };
    expect(leaked(hostDir)).toBe(false);
  });
});
