import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { PassThrough, Readable } from 'node:stream';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { RunnerConfig } from '@cloud-harness/contracts';
import {
  VM_HELPER_GID,
  VM_HELPER_UID,
  VmGitStaging,
  dockerVmHelperRunner,
  extractTarSafe,
  findCheckoutRoot,
  findCheckoutRoots,
  inspectVmCheckout,
  neutralizeGitObjectRedirects,
  sanitizeGitConfig,
  secureVmStagingDir,
  validateVmShallowBoundary,
  vmShallowSidecarPath,
  writeVmExportTar,
  type VmHelperRunner,
  type VmHelperSpec,
  type VmStagingDirOps
} from '../src/git-vm-staging.js';
import { makeConfig, makeRecord, testDirectories, trackDir } from './backend-test-utils.js';
import type { ProvisionContext } from '../src/executor-backend.js';

const docker = vi.hoisted(() => ({
  runDocker: vi.fn(),
  removeContainer: vi.fn(async () => undefined)
}));
vi.mock('../src/docker-engine.js', () => docker);

const REPO_ROOT = join(__dirname, '..', '..', '..');
const TRANSFER_HELPER = join(REPO_ROOT, 'worker', 'git-transfer-helper.sh');

const directories = testDirectories;
afterEach(() => {
  vi.clearAllMocks();
  for (const path of directories.splice(0)) rmSync(path, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Fixtures: real disposable git repositories, fully offline (local-path remotes)
// ---------------------------------------------------------------------------

function sh(bin: string, args: string[], opts: { cwd?: string; input?: string; env?: NodeJS.ProcessEnv } = {}) {
  const result = spawnSync(bin, args, {
    cwd: opts.cwd,
    input: opts.input,
    encoding: 'utf8',
    env: { PATH: process.env.PATH, HOME: opts.env?.HOME ?? '/tmp', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0', ...opts.env },
    maxBuffer: 16 * 1024 * 1024
  });
  return { status: result.status, stdout: result.stdout ?? '', stderr: result.stderr ?? '' };
}

function git(cwd: string, args: string[]): string {
  const result = sh('git', args, { cwd });
  if (result.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${result.stderr}`);
  return result.stdout.trim();
}

function makeRemote(): { remoteDir: string; bareDir: string } {
  const base = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-remote-')));
  const work = join(base, 'work');
  const bareDir = join(base, 'remote.git');
  mkdirSync(work, { recursive: true });
  git(work, ['init', '-q', '-b', 'main']);
  git(work, ['config', 'user.email', 't@example.com']);
  git(work, ['config', 'user.name', 'tester']);
  writeFileSync(join(work, 'f.txt'), 'v1\n');
  git(work, ['add', 'f.txt']);
  git(work, ['commit', '-qm', 'c1']);
  git(work, ['branch', 'dev']);
  git(work, ['tag', 'v1.0']);
  sh('git', ['init', '-q', '--bare', '-b', 'main', bareDir]);
  git(work, ['push', '-q', bareDir, 'HEAD:refs/heads/main', 'dev:refs/heads/dev', 'v1.0:refs/tags/v1.0']);
  return { remoteDir: bareDir, bareDir };
}

function advanceRemote(remoteDir: string, content: string, message: string): string {
  const base = dirname(remoteDir);
  const work = join(base, 'adv');
  if (!existsSync(work)) {
    sh('git', ['clone', '-q', remoteDir, work]);
    git(work, ['config', 'user.email', 't@example.com']);
    git(work, ['config', 'user.name', 'tester']);
  }
  writeFileSync(join(work, 'f.txt'), content);
  git(work, ['commit', '-qam', message]);
  git(work, ['push', '-q', remoteDir, 'HEAD:refs/heads/main']);
  return git(work, ['rev-parse', 'HEAD']);
}

function workspaceCtx(overrides: { workspacePath?: string; stagingDir?: string } = {}): { ctx: ProvisionContext; workspacePath: string } {
  const workspacePath = overrides.workspacePath ?? trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-ws-')));
  mkdirSync(join(workspacePath, 'git-staging'), { recursive: true });
  const record = makeRecord({ workspacePath, backendKind: 'incus-vm', containerName: 'chm-vm-test' });
  return {
    workspacePath,
    ctx: {
      record,
      environment: { GH_TOKEN: 'must-not-leak' },
      networkProfile: 'network-none',
      stagingDir: overrides.stagingDir ?? join(workspacePath, 'git-staging')
    }
  };
}

function stagingWith(runner?: VmHelperRunner, config: RunnerConfig = makeConfig()): VmGitStaging {
  return new VmGitStaging({ config, instanceId: 'instance-test', ...(runner ? { runner } : {}) });
}

// Local runner: real git for kind:'git' (cwd=mountDir, containerPath→mountDir argv
// translation), real worker/git-transfer-helper.sh for kind:'transfer' (local-path
// "remote" — the same script the docker helper container runs).
function localRunner(extraEnv: NodeJS.ProcessEnv = {}): VmHelperRunner {
  return async (spec: VmHelperSpec) => {
    // Env values may reference the container mount spelling (e.g.
    // GIT_SHALLOW_FILE=/job/shallow.txt) — translate them like argv.
    const translateEnv = (env: Record<string, string> | undefined, containerPath: string): NodeJS.ProcessEnv =>
      Object.fromEntries(Object.entries(env ?? {}).map(([key, value]) => [
        key,
        value === containerPath ? spec.mountDir : value.startsWith(`${containerPath}/`) ? join(spec.mountDir, value.slice(containerPath.length + 1)) : value
      ]));
    if (spec.kind === 'git') {
      const containerPath = spec.containerPath ?? '/job';
      const args = spec.args.map((arg) =>
        arg === containerPath ? spec.mountDir : arg.startsWith(`${containerPath}/`) ? join(spec.mountDir, arg.slice(containerPath.length + 1)) : arg
      );
      const result = spawnSync('git', args, {
        cwd: spec.mountDir,
        encoding: 'utf8',
        ...(spec.stdin !== undefined ? { input: spec.stdin } : {}),
        env: {
          PATH: process.env.PATH,
          HOME: '/tmp',
          GIT_CONFIG_NOSYSTEM: '1',
          GIT_CONFIG_GLOBAL: '/dev/null',
          GIT_CONFIG_SYSTEM: '/dev/null',
          GIT_TERMINAL_PROMPT: '0',
          GIT_PAGER: 'cat',
          PAGER: 'cat',
          ...extraEnv,
          ...translateEnv(spec.env, containerPath)
        },
        maxBuffer: 16 * 1024 * 1024
      });
      return {
        exitCode: result.status,
        stdout: result.stdout ?? '',
        stderr: result.stderr ?? '',
        truncated: false,
        timedOut: false
      };
    }
    const result = spawnSync('bash', [
      TRANSFER_HELPER,
      spec.mode,
      spec.repositoryUrl,
      join(spec.mountDir, 'unused'),
      join(spec.mountDir, 'bare.git'),
      spec.argument,
      spec.expectedRemoteOid,
      spec.historySpec
    ], {
      input: `${spec.stdin ?? ''}\n`,
      encoding: 'utf8',
      env: { PATH: process.env.PATH, HOME: '/tmp', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0', ...extraEnv, ...translateEnv(spec.env, '/job') },
      maxBuffer: 16 * 1024 * 1024
    });
    return {
      exitCode: result.status,
      stdout: result.stdout ?? '',
      stderr: result.stderr ?? '',
      truncated: false,
      timedOut: false
    };
  };
}

function listRefs(gitDir: string): Record<string, string> {
  const out = git(gitDir, ['--git-dir', gitDir, 'for-each-ref', '--format=%(refname) %(objectname)']);
  const refs: Record<string, string> = {};
  for (const line of out.split('\n')) {
    const [name, oid] = line.split(' ');
    if (name && oid) refs[name] = oid;
  }
  return refs;
}

// ---------------------------------------------------------------------------
// VmGitStaging — op dirs, fetch/bundle/push primitives
// ---------------------------------------------------------------------------

describe('VmGitStaging op dirs', () => {
  it('creates op dirs under the ctx staging root and removes them', async () => {
    const { ctx } = workspaceCtx();
    const staging = stagingWith(localRunner());
    const opDir = await staging.createOpDir(ctx);
    expect(opDir.startsWith(ctx.stagingDir)).toBe(true);
    expect(existsSync(opDir)).toBe(true);
    await staging.removeOpDir(opDir);
    expect(existsSync(opDir)).toBe(false);
  });

  it('refuses to remove directories outside the staging root', async () => {
    workspaceCtx();
    const staging = stagingWith(localRunner());
    const outside = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-outside-')));
    await expect(staging.removeOpDir(outside)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(existsSync(outside)).toBe(true);
  });
});

describe('VmGitStaging.fetchRemoteBare', () => {
  it('fetches all branches into bare.git with cloud-harness refs then renormalizes to refs/heads/*', async () => {
    const { remoteDir } = makeRemote();
    const { ctx } = workspaceCtx();
    const staging = stagingWith(localRunner());
    const opDir = await staging.createOpDir(ctx);
    try {
      const result = await staging.fetchRemoteBare(opDir, { repositoryUrl: remoteDir, remoteRef: '', historySpec: '', token: undefined });
      expect(result.exitCode).toBe(0);
      const refs = listRefs(join(opDir, 'bare.git'));
      expect(refs['refs/heads/main']).toBeTruthy();
      expect(refs['refs/heads/dev']).toBeTruthy();
      expect(Object.keys(refs).some((r) => r.includes('cloud-harness'))).toBe(false);
      expect(refs['refs/tags/v1.0']).toBeUndefined(); // --no-tags parity with the helper
    } finally {
      await staging.removeOpDir(opDir);
    }
  });

  it('single refs/heads/* fetch renormalizes to the branch name for origin tracking', async () => {
    const { remoteDir } = makeRemote();
    const { ctx } = workspaceCtx();
    const staging = stagingWith(localRunner());
    const opDir = await staging.createOpDir(ctx);
    try {
      const result = await staging.fetchRemoteBare(opDir, { repositoryUrl: remoteDir, remoteRef: 'refs/heads/dev', historySpec: '', token: undefined });
      expect(result.exitCode).toBe(0);
      const refs = listRefs(join(opDir, 'bare.git'));
      expect(Object.keys(refs)).toEqual(['refs/heads/dev']);
    } finally {
      await staging.removeOpDir(opDir);
    }
  });

  it('non-branch single refs land on a FETCH_HEAD-only staging ref', async () => {
    const { remoteDir } = makeRemote();
    const { ctx } = workspaceCtx();
    const staging = stagingWith(localRunner());
    const opDir = await staging.createOpDir(ctx);
    try {
      const result = await staging.fetchRemoteBare(opDir, { repositoryUrl: remoteDir, remoteRef: 'refs/tags/v1.0', historySpec: '', token: undefined });
      expect(result.exitCode).toBe(0);
      const refs = listRefs(join(opDir, 'bare.git'));
      // Not under refs/heads/ or refs/tags/ → bundleHeadsToRefspecs maps to FETCH_HEAD only.
      const names = Object.keys(refs);
      expect(names).toHaveLength(1);
      expect(names[0]).toMatch(/^refs\//);
      expect(names[0]).not.toMatch(/^refs\/(heads|tags)\//);
    } finally {
      await staging.removeOpDir(opDir);
    }
  });

  it('applies depth history spec through the helper', async () => {
    const { remoteDir } = makeRemote();
    const { ctx } = workspaceCtx();
    const staging = stagingWith(localRunner());
    const opDir = await staging.createOpDir(ctx);
    try {
      const result = await staging.fetchRemoteBare(opDir, { repositoryUrl: remoteDir, remoteRef: '', historySpec: 'depth:1', token: undefined });
      expect(result.exitCode).toBe(0);
      const shallow = git(join(opDir, 'bare.git'), ['--git-dir', join(opDir, 'bare.git'), 'rev-parse', '--is-shallow-repository']);
      expect(shallow).toBe('true');
    } finally {
      await staging.removeOpDir(opDir);
    }
  });

  it('surfaces helper failure with stderr', async () => {
    const { ctx } = workspaceCtx();
    const staging = stagingWith(localRunner());
    const opDir = await staging.createOpDir(ctx);
    try {
      const result = await staging.fetchRemoteBare(opDir, { repositoryUrl: '/nonexistent/remote.git', remoteRef: '', historySpec: '', token: undefined });
      expect(result.exitCode).not.toBe(0);
    } finally {
      await staging.removeOpDir(opDir);
    }
  });
});

describe('VmGitStaging bundle create/list/stage/push', () => {
  async function fetchedBare(ctx: ProvisionContext, staging: VmGitStaging, remoteDir: string): Promise<string> {
    const opDir = await staging.createOpDir(ctx);
    const result = await staging.fetchRemoteBare(opDir, { repositoryUrl: remoteDir, remoteRef: '', historySpec: '', token: undefined });
    expect(result.exitCode).toBe(0);
    return opDir;
  }

  it('creates a bundle from the staging bare and lists its heads', async () => {
    const { remoteDir } = makeRemote();
    const { ctx } = workspaceCtx();
    const staging = stagingWith(localRunner());
    const opDir = await fetchedBare(ctx, staging, remoteDir);
    try {
      const bundle = await staging.createBundle(opDir, { revs: ['--branches'] });
      expect(bundle.bytes).toBeGreaterThan(0);
      expect(bundle.sha256).toBe(createHash('sha256').update(readFileSync(bundle.hostPath)).digest('hex'));
      const heads = await staging.listHeads(opDir, 'transfer.bundle');
      expect(heads.exitCode).toBe(0);
      expect(heads.stdout).toContain('refs/heads/main');
      expect(heads.stdout).toContain('refs/heads/dev');
    } finally {
      await staging.removeOpDir(opDir);
    }
  });

  it('bundle fetches into a real checkout and preserves unpushed local commits', async () => {
    const { remoteDir } = makeRemote();
    const { ctx, workspacePath } = workspaceCtx();
    const staging = stagingWith(localRunner());
    // Guest-side checkout (real repo simulating /workspace contents).
    const guest = join(workspacePath, 'guest-checkout');
    sh('git', ['clone', '-q', remoteDir, guest]);
    git(guest, ['config', 'user.email', 't@example.com']);
    git(guest, ['config', 'user.name', 'tester']);
    git(guest, ['checkout', '-q', '-B', 'main', 'origin/main']);
    writeFileSync(join(guest, 'local.txt'), 'unpushed\n');
    git(guest, ['add', 'local.txt']);
    git(guest, ['commit', '-qm', 'local-work']);
    const localHead = git(guest, ['rev-parse', 'HEAD']);

    const opDir = await staging.createOpDir(ctx);
    try {
      await staging.fetchRemoteBare(opDir, { repositoryUrl: remoteDir, remoteRef: '', historySpec: '', token: undefined });
      const bundle = await staging.createBundle(opDir, { revs: ['--branches'] });
      const refspecs = await staging.bundleRefspecs(opDir, 'transfer.bundle');
      // Guest-side import: fetch the bundle with the derived refspecs.
      const fetch = sh('git', ['-C', guest, 'fetch', '--no-tags', '--no-recurse-submodules', '--', bundle.hostPath, ...refspecs]);
      expect(fetch.status).toBe(0);
      expect(git(guest, ['rev-parse', 'HEAD'])).toBe(localHead);
      expect(git(guest, ['rev-parse', 'refs/remotes/origin/main'])).toBe(git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main']));
    } finally {
      await staging.removeOpDir(opDir);
    }
  });

  it('stages a guest bundle as a bare repo and pushes with force-with-lease CAS', async () => {
    const { remoteDir } = makeRemote();
    const { ctx } = workspaceCtx();
    const staging = stagingWith(localRunner());
    // Simulate the guest side: a checkout with a new commit on main.
    const guestBase = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-guest-')));
    const guest = join(guestBase, 'checkout');
    sh('git', ['clone', '-q', remoteDir, guest]);
    git(guest, ['config', 'user.email', 't@example.com']);
    git(guest, ['config', 'user.name', 'tester']);
    git(guest, ['checkout', '-q', '-B', 'main', 'origin/main']);
    writeFileSync(join(guest, 'push.txt'), 'new\n');
    git(guest, ['add', 'push.txt']);
    git(guest, ['commit', '-qm', 'guest-work']);
    const guestHead = git(guest, ['rev-parse', 'HEAD']);
    const remoteBefore = git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main']);

    const opDir = await staging.createOpDir(ctx);
    try {
      // Guest export: bundle of all refs.
      const bundlePath = join(guestBase, 'guest.bundle');
      git(guest, ['bundle', 'create', bundlePath, '--branches', '--tags', 'HEAD']);
      // Stage into the op dir and clone --bare.
      const staged = join(opDir, 'push.bundle');
      linkSync(bundlePath, staged);
      await staging.stagePushBare(opDir, 'push.bundle');
      const stagedRefs = listRefs(join(opDir, 'bare.git'));
      expect(stagedRefs['refs/heads/main']).toBe(guestHead);
      // Push with correct lease.
      const pushed = await staging.pushBare(opDir, {
        repositoryUrl: remoteDir,
        refspec: 'refs/heads/main:refs/heads/main',
        expectedRemoteOid: remoteBefore,
        token: undefined
      });
      expect(pushed.exitCode).toBe(0);
      expect(git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main'])).toBe(guestHead);
    } finally {
      await staging.removeOpDir(opDir);
    }
  });

  it('rejects a stale lease and leaves the remote untouched', async () => {
    const { remoteDir } = makeRemote();
    const { ctx } = workspaceCtx();
    const staging = stagingWith(localRunner());
    const guestBase = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-guest-')));
    const guest = join(guestBase, 'checkout');
    sh('git', ['clone', '-q', remoteDir, guest]);
    git(guest, ['config', 'user.email', 't@example.com']);
    git(guest, ['config', 'user.name', 'tester']);
    git(guest, ['checkout', '-q', '-B', 'main', 'origin/main']);
    writeFileSync(join(guest, 'x.txt'), 'x\n');
    git(guest, ['add', 'x.txt']);
    git(guest, ['commit', '-qm', 'guest-work']);
    const remoteHead = git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main']);
    // Advance the remote so the lease goes stale.
    advanceRemote(remoteDir, 'remote-v2\n', 'remote-advance');
    const afterAdvance = git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main']);
    expect(afterAdvance).not.toBe(remoteHead);

    const opDir = await staging.createOpDir(ctx);
    try {
      const bundlePath = join(guestBase, 'guest.bundle');
      git(guest, ['bundle', 'create', bundlePath, '--branches', '--tags', 'HEAD']);
      linkSync(bundlePath, join(opDir, 'push.bundle'));
      await staging.stagePushBare(opDir, 'push.bundle');
      const pushed = await staging.pushBare(opDir, {
        repositoryUrl: remoteDir,
        refspec: 'refs/heads/main:refs/heads/main',
        expectedRemoteOid: remoteHead, // stale
        token: undefined
      });
      expect(pushed.exitCode).not.toBe(0);
      expect(pushed.stderr + pushed.stdout).toMatch(/stale info|rejected|lease/i);
      expect(git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main'])).toBe(afterAdvance);
    } finally {
      await staging.removeOpDir(opDir);
    }
  });

  it('rejects option-injection refspecs before any helper call', async () => {
    const runner = vi.fn(localRunner());
    const staging = stagingWith(runner as unknown as VmHelperRunner);
    const { ctx } = workspaceCtx();
    const opDir = await staging.createOpDir(ctx);
    try {
      await expect(staging.pushBare(opDir, { repositoryUrl: '/tmp/x', refspec: '--upload-pack=evil', expectedRemoteOid: '', token: undefined }))
        .rejects.toMatchObject({ code: 'INVALID_INPUT' });
      expect(runner).not.toHaveBeenCalled();
    } finally {
      await staging.removeOpDir(opDir);
    }
  });

  it('detects corrupt bundles at list-heads and refuses staging', async () => {
    const { ctx } = workspaceCtx();
    const staging = stagingWith(localRunner());
    const opDir = await staging.createOpDir(ctx);
    try {
      writeFileSync(join(opDir, 'bad.bundle'), 'not a git bundle at all');
      const heads = await staging.listHeads(opDir, 'bad.bundle');
      expect(heads.exitCode).not.toBe(0);
      await expect(staging.stagePushBare(opDir, 'bad.bundle')).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    } finally {
      await staging.removeOpDir(opDir);
    }
  });
});

// ---------------------------------------------------------------------------
// Docker helper runner — argv/env contract (runDocker mocked)
// ---------------------------------------------------------------------------

describe('dockerVmHelperRunner', () => {
  function dockerResult(stdout = '', stderr = '', exitCode = 0) {
    return { exitCode, signal: null, stdout, stderr, truncated: false, timedOut: false };
  }
  function calls(): string[][] {
    return docker.runDocker.mock.calls.map((call) => call[0] as string[]);
  }

  it('runs git helpers with the hardened offline envelope', async () => {
    docker.runDocker.mockResolvedValue(dockerResult('ok\n'));
    const runner = dockerVmHelperRunner({ config: makeConfig(), instanceId: 'inst-1' });
    const result = await runner({ kind: 'git', mountDir: '/tmp/op', args: ['--git-dir=bare.git', 'for-each-ref'], readOnly: true });
    expect(result.stdout).toBe('ok\n');
    const args = calls()[0]!;
    expect(args[0]).toBe('run');
    expect(args).toContain('--network');
    expect(args[args.indexOf('--network') + 1]).toBe('none');
    expect(args).toContain('--read-only');
    expect(args).toContain('/tmp/op:/job:ro');
    expect(args).toContain('--workdir');
    expect(args[args.indexOf('--workdir') + 1]).toBe('/job');
    expect(args[args.indexOf('--entrypoint') + 1]).toBe('/usr/bin/git');
    // Hardened -c flags precede argv; safe.directory is scoped to the mount.
    const cFlags = args.filter((_, i) => args[i - 1] === '-c');
    expect(cFlags).toEqual(expect.arrayContaining([
      'core.hooksPath=/dev/null', 'core.fsmonitor=false', 'core.pager=cat',
      'credential.helper=', 'http.followRedirects=false',
      'safe.directory=/job', 'safe.directory=/job/*'
    ]));
    expect(args.slice(-2)).toEqual(['--git-dir=bare.git', 'for-each-ref']);
    const envFlags = args.filter((_, i) => args[i - 1] === '--env').map((v) => v);
    expect(envFlags).toContain('GIT_CONFIG_NOSYSTEM=1');
    expect(envFlags).toContain('GIT_CONFIG_GLOBAL=/dev/null');
    expect(envFlags).toContain('GIT_TERMINAL_PROMPT=0');
    expect(docker.removeContainer).toHaveBeenCalled();
  });

  it('passes validated spec.env through --env and rejects bad entries', async () => {
    docker.runDocker.mockResolvedValue(dockerResult('ok\n'));
    const runner = dockerVmHelperRunner({ config: makeConfig(), instanceId: 'inst-1' });
    await runner({ kind: 'git', mountDir: '/tmp/op', args: ['status'], env: { GIT_SHALLOW_FILE: '/job/shallow.txt' } });
    const args = calls()[0]!;
    const envFlags = args.filter((_, i) => args[i - 1] === '--env').map((v) => v);
    expect(envFlags).toContain('GIT_SHALLOW_FILE=/job/shallow.txt');
    await expect(runner({ kind: 'git', mountDir: '/tmp/op', args: ['status'], env: { 'BAD KEY': 'x' } })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(runner({ kind: 'git', mountDir: '/tmp/op', args: ['status'], env: { GIT_SHALLOW_FILE: 'has\nnewline' } })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('keeps stdin attached for git helpers so update-ref --stdin can read it', async () => {
    docker.runDocker.mockResolvedValue(dockerResult('ok\n'));
    const runner = dockerVmHelperRunner({ config: makeConfig(), instanceId: 'inst-1' });
    const stdin = 'update refs/heads/main\n';
    await runner({ kind: 'git', mountDir: '/tmp/op', args: ['--git-dir=bare.git', 'update-ref', '--stdin'], stdin });
    const args = calls()[0]!;
    // -i attaches container stdin; without it `update-ref --stdin` sees EOF
    // immediately and every ref update silently no-ops.
    expect(args.slice(0, 2)).toEqual(['run', '-i']);
    const runOpts = docker.runDocker.mock.calls[0]![1] as { stdin?: string };
    expect(runOpts.stdin).toBe(stdin);
  });

  it('runs transfer helpers on bridge with the token only on stdin', async () => {
    docker.runDocker.mockResolvedValue(dockerResult('', '', 0));
    const runner = dockerVmHelperRunner({ config: makeConfig(), instanceId: 'inst-1' });
    const secret = 'SECRET-TOKEN-123';
    await runner({
      kind: 'transfer',
      mountDir: '/tmp/op',
      mode: 'fetch',
      repositoryUrl: 'https://github.com/o/r.git',
      argument: 'refs/heads/main',
      expectedRemoteOid: '',
      historySpec: '',
      stdin: secret
    });
    const args = calls()[0]!;
    expect(args).toContain('--network');
    expect(args[args.indexOf('--network') + 1]).toBe('bridge');
    expect(args[args.indexOf('--entrypoint') + 1]).toBe('/opt/harness/git-transfer-helper.sh');
    expect(args).toContain('/tmp/op:/job:rw');
    const tail = args.slice(args.indexOf('cloud-harness-executor:test') + 1);
    expect(tail).toEqual(['fetch', 'https://github.com/o/r.git', '/job/unused', '/job/bare.git', 'refs/heads/main', '', '']);
    // Token appears ONLY in stdin, never argv/env.
    expect(args.join(' ')).not.toContain(secret);
    const runOpts = docker.runDocker.mock.calls[0]![1] as { stdin?: string };
    expect(runOpts.stdin).toBe(`${secret}\n`);
  });
});

// ---------------------------------------------------------------------------
// Tar export: bounded write + hostile-entry-safe extraction
// ---------------------------------------------------------------------------

function tarHeader(name: string, opts: { type?: string; size?: number; linkname?: string; mode?: number } = {}): Buffer {
  const header = Buffer.alloc(512);
  header.write(name.slice(0, 100), 0, 'utf8');
  header.write((opts.mode ?? 0o644).toString(8).padStart(7, '0') + '\0', 100, 'utf8');
  header.write('0000000\0', 108, 'utf8');
  header.write('0000000\0', 116, 'utf8');
  header.write((opts.size ?? 0).toString(8).padStart(11, '0') + '\0', 124, 'utf8');
  header.write('00000000000\0', 136, 'utf8');
  header.fill(0x20, 148, 156);
  header.write(opts.type ?? '0', 156, 'utf8');
  header.write((opts.linkname ?? '').slice(0, 100), 157, 'utf8');
  header.write('ustar\0', 257, 'utf8');
  header.write('00', 263, 'utf8');
  let sum = 0;
  for (const b of header) sum += b;
  header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 'utf8');
  return header;
}

function tarFile(entries: Array<{ name: string; data?: string | Buffer; type?: string; linkname?: string; mode?: number }>): Buffer {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    const data = entry.data === undefined ? Buffer.alloc(0) : Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data, 'utf8');
    parts.push(tarHeader(entry.name, { type: entry.type, size: data.length, linkname: entry.linkname, mode: entry.mode }));
    if (data.length > 0) {
      parts.push(data);
      const pad = (512 - (data.length % 512)) % 512;
      if (pad) parts.push(Buffer.alloc(pad));
    }
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

async function streamOf(buffer: Buffer): Promise<Readable> {
  return Readable.from([buffer]);
}

describe('writeVmExportTar', () => {
  it('streams tar bytes to disk with sha256 + byte count, bounded by maxBytes', async () => {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-tar-')));
    const payload = tarFile([{ name: 'workspace/f.txt', data: 'hello\n' }]);
    const dest = join(dir, 'export.tar');
    const result = await writeVmExportTar(await streamOf(payload), dest, payload.length + 1024);
    expect(result.bytes).toBe(payload.length);
    expect(result.sha256).toBe(createHash('sha256').update(payload).digest('hex'));
    expect(readFileSync(dest).equals(payload)).toBe(true);
  });

  it('rejects streams exceeding maxBytes mid-flight', async () => {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-tar-')));
    const payload = tarFile([{ name: 'big.bin', data: Buffer.alloc(4096, 1) }]);
    const dest = join(dir, 'export.tar');
    await expect(writeVmExportTar(await streamOf(payload), dest, 1024)).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    // Partial file is removed.
    expect(existsSync(dest)).toBe(false);
  });

  it('creates the destination before the source is consumed', async () => {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-tar-')));
    const dest = join(dir, 'export.tar');
    let existedAtFirstRead: boolean | undefined;
    let pushed = false;
    const source = new Readable({
      read() {
        if (existedAtFirstRead === undefined) existedAtFirstRead = existsSync(dest);
        if (!pushed) {
          pushed = true;
          this.push(Buffer.alloc(64, 3));
          this.push(null);
        }
      }
    });
    await writeVmExportTar(source, dest, 1024);
    // The open must be awaited before the first pull: with createWriteStream the
    // async open could still be in flight here, which is the window that let a
    // failed export recreate export.tar after cleanup removed it.
    expect(existedAtFirstRead).toBe(true);
  });

  it('removes the destination when the source fails before its first chunk', async () => {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-tar-')));
    const dest = join(dir, 'export.tar');
    const source = new Readable({
      read() {
        this.destroy(new Error('source failed before first chunk'));
      }
    });
    await expect(writeVmExportTar(source, dest, 1024)).rejects.toThrow('source failed before first chunk');
    expect(existsSync(dest)).toBe(false);
  });

  it('removes a partially written export when the stream fails mid-flight', async () => {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-tar-')));
    const dest = join(dir, 'export.tar');
    const source = new PassThrough();
    // The 'error' event is asserted through the writeVmExportTar rejection; the
    // listener only keeps an early destroy from surfacing as an uncaught error.
    source.on('error', () => undefined);
    const writing = writeVmExportTar(source, dest, 1024 * 1024);
    source.write(Buffer.alloc(4096, 9));
    // Wait until the first chunk has actually landed so the failure is
    // genuinely mid-flight rather than pre-open.
    await vi.waitFor(() => expect(statSync(dest).size).toBe(4096));
    source.destroy(new Error('mid-flight failure'));
    await expect(writing).rejects.toThrow('mid-flight failure');
    expect(existsSync(dest)).toBe(false);
  });
});

describe('extractTarSafe', () => {
  async function extract(entries: Parameters<typeof tarFile>[0], limits = {}) {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-ext-')));
    const tarPath = join(dir, 'in.tar');
    writeFileSync(tarPath, tarFile(entries));
    const dest = join(dir, 'out');
    mkdirSync(dest, { recursive: true });
    const result = await extractTarSafe(tarPath, dest, { maxEntries: 10_000, maxBytes: 64 * 1024 * 1024, ...limits });
    return { dir, dest, result };
  }

  it('extracts regular files and directories with safe modes', async () => {
    const { dest } = await extract([
      { name: 'workspace/', type: '5', mode: 0o755 },
      { name: 'workspace/.git/', type: '5' },
      { name: 'workspace/.git/HEAD', data: 'ref: refs/heads/main\n' },
      { name: 'workspace/f.txt', data: 'content\n', mode: 0o755 }
    ]);
    expect(readFileSync(join(dest, 'workspace', '.git', 'HEAD'), 'utf8')).toBe('ref: refs/heads/main\n');
    expect(readFileSync(join(dest, 'workspace', 'f.txt'), 'utf8')).toBe('content\n');
    expect(statSync(join(dest, 'workspace', 'f.txt')).mode & 0o111).toBeTruthy();
  });

  it('rejects absolute paths and .. traversal', async () => {
    await expect(extract([{ name: '../escape.txt', data: 'x' }])).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(extract([{ name: '/etc/passwd', data: 'x' }])).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(extract([{ name: 'a/../../b', data: 'x' }])).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(extract([{ name: 'workspace/./ok.txt', data: 'x' }])).resolves.toBeTruthy();
  });

  it('rejects escaping symlinks/hardlinks, devices, and fifos', async () => {
    await expect(extract([{ name: 'link', type: '2', linkname: '/etc/passwd' }])).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(extract([{ name: 'link', type: '2', linkname: '../escape' }])).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(extract([{ name: 'hard', type: '1', linkname: 'missing-target' }])).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(extract([{ name: 'dev', type: '3', linkname: '', mode: 0o666 }])).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(extract([{ name: 'fifo', type: '6' }])).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('accepts contained symlinks and hardlinks, materialized after files', async () => {
    const { dest } = await extract([
      { name: 'workspace/f.txt', data: 'payload\n' },
      { name: 'workspace/link', type: '2', linkname: 'f.txt' },
      { name: 'workspace/hard', type: '1', linkname: 'workspace/f.txt' }
    ]);
    const ws = join(dest, 'workspace');
    expect(readlinkSync(join(ws, 'link'))).toBe('f.txt');
    expect(readFileSync(join(ws, 'link'), 'utf8')).toBe('payload\n');
    expect(lstatSync(join(ws, 'hard')).isFile()).toBe(true);
    expect(statSync(join(ws, 'hard')).ino).toBe(statSync(join(ws, 'f.txt')).ino);
  });

  it('rejects write-through: a file path under a pending symlink cannot be created', async () => {
    // The symlink materializes last, so 'link/' is a real dir during file
    // extraction; the link then collides and the whole extraction fails —
    // no bytes can ever be written through a link.
    await expect(extract([
      { name: 'sub/real.txt', data: 'x' },
      { name: 'link', type: '2', linkname: 'sub' },
      { name: 'link/evil.txt', data: 'pwned' }
    ])).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('rejects links whose parents are files and hardlinks to symlinks', async () => {
    await expect(extract([
      { name: 'blocker', data: 'x' },
      { name: 'blocker/x', type: '2', linkname: 'f.txt' }
    ])).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(extract([
      { name: 'target.txt', data: 'x' },
      { name: 'slink', type: '2', linkname: 'target.txt' },
      { name: 'hard', type: '1', linkname: 'slink' }
    ])).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('rejects pax path overrides that smuggle traversal', async () => {
    // pax extended header 'x' with path=../evil, then a file entry.
    // pax record length counts its own digits: '20 path=../evil.txt\n' is 20 bytes.
    const paxData = Buffer.from('20 path=../evil.txt\n');
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-pax-')));
    const tarPath = join(dir, 'pax.tar');
    const parts: Buffer[] = [];
    parts.push(tarHeader('paxhdr', { type: 'x', size: paxData.length }));
    parts.push(paxData);
    parts.push(Buffer.alloc((512 - (paxData.length % 512)) % 512));
    parts.push(tarHeader('innocent.txt', { type: '0', size: 1 }));
    parts.push(Buffer.from('x'));
    parts.push(Buffer.alloc(511));
    parts.push(Buffer.alloc(1024));
    writeFileSync(tarPath, Buffer.concat(parts));
    const dest = join(dir, 'out');
    mkdirSync(dest, { recursive: true });
    await expect(extractTarSafe(tarPath, dest, { maxEntries: 100, maxBytes: 1024 * 1024 })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(existsSync(join(dir, 'evil.txt'))).toBe(false);
  });

  it('rejects oversized entry counts and declared content', async () => {
    await expect(extract([{ name: 'a', data: 'x' }, { name: 'b', data: 'y' }], { maxEntries: 1 })).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    await expect(extract([{ name: 'big', data: Buffer.alloc(8192, 7) }], { maxBytes: 4096 })).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
  });

  it('accumulates consecutive L/K/x metadata headers until a real entry consumes them', async () => {
    // GNU tar emits several metadata headers in a row (long name, then long
    // link). Resetting meta per header dropped whichever came first — here the
    // K longlink must survive the following L longname header so the hardlink
    // resolves to the real target instead of the truncated placeholder.
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-meta-')));
    const tarPath = join(dir, 'meta.tar');
    const longTarget = `workspace/${'a'.repeat(105)}`;
    const longLink = `workspace/${'a'.repeat(105)}`;
    const longName = `workspace/${'b'.repeat(105)}`;
    const metaRecord = (type: string, value: string): Buffer[] => {
      const data = Buffer.from(`${value}\0`, 'utf8');
      return [
        tarHeader('LongLink', { type, size: data.length }),
        data,
        Buffer.alloc((512 - (data.length % 512)) % 512)
      ];
    };
    const parts: Buffer[] = [];
    // File whose NAME exceeds the 100-byte header field (via L), carrying data.
    parts.push(...metaRecord('L', longTarget));
    parts.push(tarHeader('short', { type: '0', size: 1 }));
    parts.push(Buffer.from('x'));
    parts.push(Buffer.alloc(511));
    // Hardlink whose NAME and LINKNAME both exceed header fields: K then L.
    parts.push(...metaRecord('K', longLink));
    parts.push(...metaRecord('L', longName));
    parts.push(tarHeader('h', { type: '1', size: 0, linkname: 'placeholder' }));
    parts.push(Buffer.alloc(1024));
    writeFileSync(tarPath, Buffer.concat(parts));
    const dest = join(dir, 'out');
    mkdirSync(dest, { recursive: true });
    await extractTarSafe(tarPath, dest, { maxEntries: 100, maxBytes: 1024 * 1024 });
    const ws = join(dest, 'workspace');
    expect(readFileSync(join(ws, `${'a'.repeat(105)}`), 'utf8')).toBe('x');
    expect(statSync(join(ws, `${'b'.repeat(105)}`)).ino).toBe(statSync(join(ws, `${'a'.repeat(105)}`)).ino);
  });

  it('rejects malformed/truncated archives', async () => {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-bad-')));
    const tarPath = join(dir, 'bad.tar');
    writeFileSync(tarPath, Buffer.from('definitely not a tar file, just text'));
    const dest = join(dir, 'out');
    mkdirSync(dest, { recursive: true });
    await expect(extractTarSafe(tarPath, dest, { maxEntries: 100, maxBytes: 1024 * 1024 })).rejects.toThrow();
  });
});

describe('findCheckoutRoot', () => {
  it('finds .git at the root and one level down', async () => {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-root-')));
    mkdirSync(join(dir, '.git'), { recursive: true });
    expect(await findCheckoutRoot(dir)).toBe('');
    const dir2 = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-root-')));
    mkdirSync(join(dir2, 'workspace', '.git'), { recursive: true });
    expect(await findCheckoutRoot(dir2)).toBe('workspace');
    const dir3 = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-root-')));
    expect(await findCheckoutRoot(dir3)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Offline checkout inspection (close_check parity)
// ---------------------------------------------------------------------------

/** Build an export-like checkout dir whose worktree pointers reference the checkout dir itself (the /workspace role). */
function buildExportFixture(opts: { dirty?: boolean; unpushed?: boolean; stash?: boolean; worktree?: boolean } = {}): { exportDir: string; checkoutDir: string } {
  const base = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-fixture-')));
  const repo = join(base, 'src-repo');
  mkdirSync(repo, { recursive: true });
  git(repo, ['init', '-q', '-b', 'main']);
  git(repo, ['config', 'user.email', 't@example.com']);
  git(repo, ['config', 'user.name', 'tester']);
  writeFileSync(join(repo, 'f.txt'), 'v1\n');
  git(repo, ['add', 'f.txt']);
  git(repo, ['commit', '-qm', 'c1']);
  // A local "remote" so unpushed math has a --remotes exclusion.
  const remoteDir = join(base, 'remote.git');
  sh('git', ['init', '-q', '--bare', '-b', 'main', remoteDir]);
  git(repo, ['remote', 'add', 'origin', remoteDir]);
  git(repo, ['push', '-q', 'origin', 'HEAD:refs/heads/main']);
  git(repo, ['fetch', '-q', 'origin']);
  if (opts.worktree) {
    git(repo, ['worktree', 'add', '-q', '.worktrees/feat', '-b', 'feat']);
    const wt = join(repo, '.worktrees', 'feat');
    writeFileSync(join(wt, 'wt.txt'), 'wt\n');
    git(wt, ['add', 'wt.txt']);
    git(wt, ['commit', '-qm', 'wt-c1']);
  }
  if (opts.unpushed) {
    writeFileSync(join(repo, 'unpushed.txt'), 'u\n');
    git(repo, ['add', 'unpushed.txt']);
    git(repo, ['commit', '-qm', 'unpushed-work']);
  }
  if (opts.dirty) writeFileSync(join(repo, 'f.txt'), 'dirty\n');
  if (opts.stash) {
    writeFileSync(join(repo, 'stash.txt'), 's\n');
    git(repo, ['add', 'stash.txt']);
    git(repo, ['stash', 'push', '-qm', 'stash-entry']);
  }
  // "Export": copy the checkout to exportDir/workspace, then rewrite all
  // absolute worktree pointers from the source path to the checkout path —
  // exactly what a guest export looks like when /workspace is the checkout.
  const exportDir = join(base, 'export');
  const checkoutDir = join(exportDir, 'workspace');
  mkdirSync(exportDir, { recursive: true });
  sh('cp', ['-a', repo, checkoutDir]);
  rewritePointers(checkoutDir, repo, checkoutDir);
  return { exportDir, checkoutDir };
}

/** Replace absolute path pointers `from`→`to` inside .git/worktrees metadata and worktree .git files. */
function rewritePointers(checkoutDir: string, from: string, to: string) {
  const gitdir = join(checkoutDir, '.git');
  const worktreesMeta = join(gitdir, 'worktrees');
  if (existsSync(worktreesMeta)) {
    for (const id of readdirSync(worktreesMeta)) {
      const gitdirFile = join(worktreesMeta, id, 'gitdir');
      if (existsSync(gitdirFile)) {
        writeFileSync(gitdirFile, readFileSync(gitdirFile, 'utf8').replaceAll(from, to));
      }
    }
  }
  const walk = (dir: string): string[] => {
    const out: string[] = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, entry.name);
      if (entry.isDirectory()) out.push(...walk(p));
      else if (entry.name === '.git' && entry.isFile()) out.push(p);
    }
    return out;
  };
  for (const file of walk(checkoutDir)) {
    const content = readFileSync(file, 'utf8');
    if (content.includes('gitdir:')) writeFileSync(file, content.replaceAll(from, to));
  }
}

describe('inspectVmCheckout', () => {
  const localStaging = () => stagingWith(localRunner());

  it('reports clean for a pristine synced checkout', async () => {
    const { checkoutDir } = buildExportFixture();
    const result = await inspectVmCheckout(localStaging(), checkoutDir, { containerPath: checkoutDir });
    expect(result.verdict).toBe('clean');
    expect(result.uncommittedPaths).toBe(0);
    expect(result.stashes).toBe(0);
    expect(result.unpushedCommits).toBe(0);
  });

  it('reports retain for dirty working tree, unpushed commits, and stashes', async () => {
    const dirty = buildExportFixture({ dirty: true });
    const r1 = await inspectVmCheckout(localStaging(), dirty.checkoutDir, { containerPath: dirty.checkoutDir });
    expect(r1.verdict).toBe('retain');
    expect(r1.uncommittedPaths).toBeGreaterThan(0);

    const unpushed = buildExportFixture({ unpushed: true });
    const r2 = await inspectVmCheckout(localStaging(), unpushed.checkoutDir, { containerPath: unpushed.checkoutDir });
    expect(r2.verdict).toBe('retain');
    expect(r2.unpushedCommits).toBe(1);

    const stash = buildExportFixture({ stash: true });
    const r3 = await inspectVmCheckout(localStaging(), stash.checkoutDir, { containerPath: stash.checkoutDir });
    expect(r3.verdict).toBe('retain');
    expect(r3.stashes).toBe(1);
  });

  it('counts dirty files inside linked worktrees separately', async () => {
    const { checkoutDir } = buildExportFixture({ worktree: true });
    // Dirty the linked worktree after export-copy.
    writeFileSync(join(checkoutDir, '.worktrees', 'feat', 'wt.txt'), 'dirty-wt\n');
    const result = await inspectVmCheckout(localStaging(), checkoutDir, { containerPath: checkoutDir });
    expect(result.verdict).toBe('retain');
    expect(result.uncommittedPaths).toBeGreaterThan(0);
  });

  it('returns unknown when the checkout has no .git', async () => {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-nogit-')));
    mkdirSync(join(dir, 'workspace'), { recursive: true });
    writeFileSync(join(dir, 'workspace', 'f.txt'), 'x');
    const result = await inspectVmCheckout(localStaging(), join(dir, 'workspace'), { containerPath: '/workspace' });
    expect(result.verdict).toBe('unknown');
  });

  it('returns unknown on git failure rather than guessing clean', async () => {
    const { checkoutDir } = buildExportFixture();
    // Corrupt .git so git commands fail.
    rmSync(join(checkoutDir, '.git', 'HEAD'));
    const result = await inspectVmCheckout(localStaging(), checkoutDir, { containerPath: checkoutDir });
    expect(result.verdict).toBe('unknown');
  });

  it('neutralizes objects/info alternates before host git inspection', async () => {
    const { checkoutDir } = buildExportFixture({ dirty: true });
    const info = join(checkoutDir, '.git', 'objects', 'info');
    mkdirSync(info, { recursive: true });
    const outside = join(checkoutDir, '..', 'host-object-store');
    mkdirSync(outside, { recursive: true });
    writeFileSync(join(info, 'alternates'), `${outside}\n`);
    writeFileSync(join(info, 'http-alternates'), 'https://objects.example/info\n');
    const result = await inspectVmCheckout(localStaging(), checkoutDir, { containerPath: checkoutDir });
    expect(result.verdict).toBe('retain'); // dirty file still seen — no host store consulted
    expect(existsSync(join(info, 'alternates'))).toBe(false);
    expect(existsSync(join(info, 'http-alternates'))).toBe(false);
  });

  it('returns unknown when a worktree commondir escapes the checkout', async () => {
    const { checkoutDir } = buildExportFixture({ worktree: true });
    const wtGitdir = join(checkoutDir, '.git', 'worktrees');
    const id = readdirSync(wtGitdir)[0]!;
    writeFileSync(join(wtGitdir, id, 'commondir'), '/etc\n');
    const result = await inspectVmCheckout(localStaging(), checkoutDir, { containerPath: checkoutDir });
    expect(result.verdict).toBe('unknown');
  });

  it('returns unknown when a linked worktree gitfile points outside .git/worktrees', async () => {
    const { checkoutDir } = buildExportFixture({ worktree: true });
    // Forward pointer escape: the worktree path stays inside the root (the
    // reverse gitdir pointer is intact) but `git -C` would follow this
    // gitfile to an unvalidated gitdir.
    const wtGitfile = join(checkoutDir, '.worktrees', 'feat', '.git');
    writeFileSync(wtGitfile, `gitdir: ${join(checkoutDir, 'evil-gitdir')}\n`);
    mkdirSync(join(checkoutDir, 'evil-gitdir'), { recursive: true });
    const result = await inspectVmCheckout(localStaging(), checkoutDir, { containerPath: checkoutDir });
    expect(result.verdict).toBe('unknown');
  });

  it('returns unknown when a linked worktree .git is a directory, not a gitfile', async () => {
    const { checkoutDir } = buildExportFixture({ worktree: true });
    const wtGitfile = join(checkoutDir, '.worktrees', 'feat', '.git');
    rmSync(wtGitfile);
    mkdirSync(wtGitfile, { recursive: true }); // nested repo dir — never a valid gitfile
    const result = await inspectVmCheckout(localStaging(), checkoutDir, { containerPath: checkoutDir });
    expect(result.verdict).toBe('unknown');
  });

  it('cannot be evaded by core.worktree pointing at a clean decoy', async () => {
    const { checkoutDir } = buildExportFixture({ dirty: true });
    // A decoy clean checkout of the same repo — if core.worktree survived
    // sanitization, `git status` would inspect it and report clean.
    const decoy = join(checkoutDir, '..', 'decoy');
    sh('git', ['clone', '-q', checkoutDir, decoy]);
    writeFileSync(join(checkoutDir, '.git', 'config'), `${readFileSync(join(checkoutDir, '.git', 'config'), 'utf8')}\n[core]\n\tworktree = ${decoy}\n`);
    const result = await inspectVmCheckout(localStaging(), checkoutDir, { containerPath: checkoutDir });
    expect(result.verdict).toBe('retain');
    expect(result.uncommittedPaths).toBeGreaterThan(0);
  });

  it('inspects a real sha256-objectFormat checkout as clean', async () => {
    const base = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-sha256-')));
    const repo = join(base, 'repo');
    mkdirSync(repo, { recursive: true });
    const init = sh('git', ['init', '-q', '-b', 'main', '--object-format=sha256'], { cwd: repo });
    if (init.status !== 0) return; // host git without sha256 — nothing to verify
    git(repo, ['config', 'user.email', 't@example.com']);
    git(repo, ['config', 'user.name', 'tester']);
    writeFileSync(join(repo, 'f.txt'), 'sha256\n');
    git(repo, ['add', 'f.txt']);
    git(repo, ['commit', '-qm', 'c1']);
    // A synced remote ref keeps unpushedCommits at 0 so 'clean' is reachable.
    const remoteDir = join(base, 'remote.git');
    sh('git', ['init', '-q', '--bare', '-b', 'main', '--object-format=sha256', remoteDir]);
    git(repo, ['remote', 'add', 'origin', remoteDir]);
    git(repo, ['push', '-q', 'origin', 'HEAD:refs/heads/main']);
    git(repo, ['fetch', '-q', 'origin']);
    const checkoutDir = join(base, 'export', 'workspace');
    mkdirSync(join(base, 'export'), { recursive: true });
    sh('cp', ['-a', repo, checkoutDir]);
    const config = readFileSync(join(checkoutDir, '.git', 'config'), 'utf8');
    expect(config).toContain('objectformat = sha256'); // the extension under test
    const result = await inspectVmCheckout(localStaging(), checkoutDir, { containerPath: checkoutDir });
    expect(result.verdict).toBe('clean');
  });
});

// ---------------------------------------------------------------------------
// secureVmStagingDir — scoped ownership/perms (injected ops, no privileges)
// ---------------------------------------------------------------------------

describe('secureVmStagingDir', () => {
  function ops(overrides: Partial<VmStagingDirOps> = {}): { ops: VmStagingDirOps; calls: string[] } {
    const calls: string[] = [];
    return {
      calls,
      ops: {
        getuid: () => 0,
        chown: async (path, uid, gid) => { calls.push(`chown ${uid}:${gid} ${path}`); },
        chmod: async (path, mode) => { calls.push(`chmod ${mode.toString(8)} ${path}`); },
        ...overrides
      }
    };
  }

  it('root runner chowns to the helper uid and tightens to 0700', async () => {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-sec-')));
    const { ops: o, calls } = ops();
    await secureVmStagingDir(dir, o);
    expect(calls).toEqual([`chown ${VM_HELPER_UID}:${VM_HELPER_GID} ${dir}`, 'chmod 700 ' + dir]);
  });

  it('falls back to 0777 on the staging dir only when chown fails', async () => {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-sec-')));
    const { ops: o, calls } = ops({
      chown: async () => { throw Object.assign(new Error('EPERM'), { code: 'EPERM' }); }
    });
    await secureVmStagingDir(dir, o);
    expect(calls).toEqual([`chmod 777 ${dir}`]);
  });

  it('unprivileged runner skips chown entirely and uses 0777', async () => {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-sec-')));
    const { ops: o, calls } = ops({ getuid: () => 1000 });
    await secureVmStagingDir(dir, o);
    expect(calls).toEqual([`chmod 777 ${dir}`]);
    expect(calls.some((c) => c.startsWith('chown'))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// findCheckoutRoots — all shallowest candidates, deeper .git are decoys
// ---------------------------------------------------------------------------

describe('findCheckoutRoots', () => {
  it('returns every same-depth candidate and ignores deeper decoys', async () => {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-roots-')));
    mkdirSync(join(dir, 'a', '.git'), { recursive: true });
    mkdirSync(join(dir, 'b', '.git'), { recursive: true });
    mkdirSync(join(dir, 'a', 'nested', '.git'), { recursive: true }); // deeper decoy
    mkdirSync(join(dir, 'c', 'd', '.git'), { recursive: true });       // deeper
    const roots = await findCheckoutRoots(dir);
    expect(roots).toEqual(['a', 'b']);
  });

  it('prefers the shallowest depth over deeper candidates', async () => {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-roots-')));
    mkdirSync(join(dir, '.git'), { recursive: true });
    mkdirSync(join(dir, 'sub', '.git'), { recursive: true });
    expect(await findCheckoutRoots(dir)).toEqual(['']);
  });
});

// ---------------------------------------------------------------------------
// sanitizeGitConfig — hostile .git/config must not reach host git
// ---------------------------------------------------------------------------

describe('sanitizeGitConfig', () => {
  async function fixture(config: string): Promise<string> {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-cfg-')));
    mkdirSync(join(dir, '.git'), { recursive: true });
    writeFileSync(join(dir, '.git', 'config'), config);
    await sanitizeGitConfig(dir);
    return readFileSync(join(dir, '.git', 'config'), 'utf8');
  }

  it('strips include/filter/fsmonitor/credential sections and dangerous keys', async () => {
    const out = await fixture([
      '[core]',
      '\trepositoryformatversion = 0',
      '\tfsmonitor = /tmp/evil.sh',
      '[include]',
      '\tpath = /tmp/evil.inc',
      '[includeIf "gitdir:/x"]',
      '\tpath = /tmp/evil2.inc',
      '[filter "lfs"]',
      '\tclean = /tmp/evil.sh',
      '[credential "https://x"]',
      '\thelper = /tmp/evil.sh',
      '[remote "origin"]',
      '\turl = /tmp/repo.git',
      ''
    ].join('\n'));
    expect(out).not.toContain('fsmonitor');
    expect(out).not.toContain('include');
    expect(out).not.toContain('filter');
    expect(out).not.toContain('credential');
    expect(out).toContain('repositoryformatversion');
    expect(out).toContain('url = /tmp/repo.git');
  });

  it('keeps benign config and handles missing config', async () => {
    const out = await fixture('[core]\n\tbare = false\n[branch "main"]\n\tremote = origin\n');
    expect(out).toContain('bare = false');
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-cfg-')));
    mkdirSync(join(dir, '.git'), { recursive: true });
    await expect(sanitizeGitConfig(dir)).resolves.toBeUndefined();
  });

  it('preserves validated extensions.objectFormat but drops every other extension', async () => {
    const out = await fixture([
      '[core]',
      '\trepositoryformatversion = 1',
      '[extensions]',
      '\tobjectformat = sha256',
      '\tpartialclone = origin',
      '\trefstorage = reftable',
      '\tworktreeconfig = true',
      '[extensions "noop"]',
      '\tobjectformat = sha1',
      '[branch "main"]',
      '\tremote = origin',
      ''
    ].join('\n'));
    expect(out).toContain('objectformat = sha256');
    expect(out).toContain('repositoryformatversion = 1');
    expect(out).not.toContain('partialclone');
    expect(out).not.toContain('refstorage');
    expect(out).not.toContain('worktreeconfig');
    // Subsectioned extensions are dropped wholesale — even a lookalike key.
    expect(out).not.toContain('noop');
    expect(out).toContain('remote = origin');
  });

  it('keeps sha1 objectFormat and drops unknown objectFormat values', async () => {
    const out = await fixture([
      '[extensions]',
      '\tobjectformat = sha1',
      '\tcompatobjectformat = sha256',
      '[extensions.foo]',
      '\tobjectformat = sha256',
      ''
    ].join('\n'));
    expect(out).toContain('objectformat = sha1');
    expect(out).not.toContain('compatobjectformat');
    // Deprecated subsection spelling is denied wholesale like [extensions "x"].
    expect(out).not.toContain('extensions.foo');
    const bogus = await fixture('[extensions]\n\tobjectformat = md5\n');
    expect(bogus).not.toContain('objectformat');
  });

  it('drops boolean-form denied keys and space-separated values (L1)', async () => {
    const out = await fixture([
      '[core]',
      '\tfsmonitor',
      '\thookspath /tmp/hooks',
      '\tbare false',
      '\tworktree = /tmp/decoy',
      '\tbare = true',
      '[include]',
      '\tpath = /tmp/a.inc',
      '\tpath = /tmp/b.inc',
      '[branch "main"]',
      '\tremote = origin',
      ''
    ].join('\n'));
    expect(out).not.toContain('fsmonitor');
    expect(out).not.toContain('hookspath');
    expect(out).not.toContain('worktree');
    // `bare false` (space form) and `bare = true` are both dropped; the
    // include section's SECOND key must not leak into the next allowed section.
    expect(out).not.toContain('/tmp/a.inc');
    expect(out).not.toContain('/tmp/b.inc');
    expect(out).toContain('remote = origin');
    const benign = await fixture('[core]\n\tbare = false\n\tbare = no\n\tbare = off\n\tbare = 0\n\tbare =\n');
    expect(benign.match(/bare\s*=/g)).toHaveLength(5);
  });
});

// ---------------------------------------------------------------------------
// neutralizeGitObjectRedirects — alternates/http-alternates/commondir containment
// ---------------------------------------------------------------------------

describe('neutralizeGitObjectRedirects', () => {
  function gitCheckout(): string {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-alt-')));
    const repo = join(dir, 'repo');
    mkdirSync(repo, { recursive: true });
    git(repo, ['init', '-q', '-b', 'main']);
    git(repo, ['config', 'user.email', 't@example.com']);
    git(repo, ['config', 'user.name', 'tester']);
    writeFileSync(join(repo, 'f.txt'), 'x\n');
    git(repo, ['add', 'f.txt']);
    git(repo, ['commit', '-qm', 'c1']);
    return repo;
  }

  it('removes alternates and http-alternates without following symlinks', async () => {
    const repo = gitCheckout();
    const info = join(repo, '.git', 'objects', 'info');
    mkdirSync(info, { recursive: true });
    const outside = join(repo, '..', 'outside-objects');
    mkdirSync(outside, { recursive: true });
    writeFileSync(join(info, 'alternates'), `${outside}\n/tmp/other-store\n`);
    writeFileSync(join(info, 'http-alternates'), 'https://evil.example/objects\n');
    symlinkSync(outside, join(info, 'alternates-link'));
    await neutralizeGitObjectRedirects(repo);
    expect(existsSync(join(info, 'alternates'))).toBe(false);
    expect(existsSync(join(info, 'http-alternates'))).toBe(false);
    // Only git-recognized redirect names are stripped; inert siblings stay.
    expect(lstatSync(join(info, 'alternates-link')).isSymbolicLink()).toBe(true);
    expect(existsSync(outside)).toBe(true); // target untouched — we never followed it
  });

  it('handles commondir inside the checkout and neutralizes its objects/info', async () => {
    const repo = gitCheckout();
    // Simulate a linked worktree layout: .git/commondir → real gitdir inside root.
    const common = join(repo, '.git', 'common');
    mkdirSync(join(common, 'objects', 'info'), { recursive: true });
    writeFileSync(join(common, 'objects', 'info', 'alternates'), '/etc/passwd-store\n');
    writeFileSync(join(repo, '.git', 'commondir'), 'common\n');
    await neutralizeGitObjectRedirects(repo);
    expect(existsSync(join(common, 'objects', 'info', 'alternates'))).toBe(false);
  });

  it('throws when commondir escapes the checkout root', async () => {
    const repo = gitCheckout();
    writeFileSync(join(repo, '.git', 'commondir'), '../outside-gitdir\n');
    await expect(neutralizeGitObjectRedirects(repo)).rejects.toThrow();
    const abs = gitCheckout();
    writeFileSync(join(abs, '.git', 'commondir'), '/etc\n');
    await expect(neutralizeGitObjectRedirects(abs)).rejects.toThrow();
  });

  it('throws when objects/info is a symlink (no-follow invariant)', async () => {
    const repo = gitCheckout();
    const info = join(repo, '.git', 'objects', 'info');
    rmSync(info, { recursive: true });
    const real = join(repo, '..', 'real-info');
    mkdirSync(real, { recursive: true });
    symlinkSync(real, info);
    await expect(neutralizeGitObjectRedirects(repo)).rejects.toThrow();
    expect(existsSync(join(real, 'alternates'))).toBe(false);
  });

  it('is a no-op for checkouts without .git', async () => {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-nogit-')));
    await expect(neutralizeGitObjectRedirects(dir)).resolves.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// validateVmShallowBoundary / vmShallowSidecarPath — sidecar contract
// ---------------------------------------------------------------------------

describe('validateVmShallowBoundary', () => {
  const oid = 'a'.repeat(40);
  const oid256 = 'b'.repeat(64);

  it('accepts absent files and well-formed boundaries, rejects malformed ones', async () => {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-sidecar-')));
    const missing = join(dir, 'missing.shallow');
    await expect(validateVmShallowBoundary(missing)).resolves.toBe(false);

    const good = join(dir, 'good.shallow');
    writeFileSync(good, `${oid}\n${oid256}\n\n`);
    await expect(validateVmShallowBoundary(good)).resolves.toBe(true);

    for (const [name, content] of [
      ['bad-oid', 'not-an-oid\n'],
      ['short-oid', 'abc123\n'],
      ['uppercase', 'A'.repeat(40) + '\n'],
      ['empty', ''],
      ['dir', null] as const
    ]) {
      const p = join(dir, `${name}.shallow`);
      if (content === null) mkdirSync(p);
      else writeFileSync(p, content);
      await expect(validateVmShallowBoundary(p), name).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    }
  });

  it('derives the deterministic <bundle>.shallow sibling path', () => {
    expect(vmShallowSidecarPath('/job/x/bundle.git')).toBe('/job/x/bundle.git.shallow');
  });
});

// ---------------------------------------------------------------------------
// Bounded-RSS: large streamed entry in a fresh process
// ---------------------------------------------------------------------------

describe('extractTarSafe memory bound', () => {
  it('streams a ~256MiB entry without buffering it whole (fresh process RSS)', async () => {
    const dir = trackDir(mkdtempSync(join(tmpdir(), 'ch-vm-rss-')));
    const entryBytes = 256 * 1024 * 1024;
    // Build the tar on disk without holding it in this test's heap.
    const srcDir = join(dir, 'src');
    mkdirSync(srcDir, { recursive: true });
    const big = join(srcDir, 'big.bin');
    const out = spawnSync('dd', ['if=/dev/zero', `of=${big}`, 'bs=1M', `count=${entryBytes / (1024 * 1024)}`], { encoding: 'utf8' });
    expect(out.status).toBe(0);
    const smallDir = join(dir, 'srcsmall');
    mkdirSync(smallDir, { recursive: true });
    writeFileSync(join(smallDir, 'small.bin'), 'x'.repeat(1024));
    const tarPath = join(dir, 'big.tar');
    const smallTarPath = join(dir, 'small.tar');
    expect(spawnSync('tar', ['-cf', tarPath, '-C', srcDir, 'big.bin'], { encoding: 'utf8' }).status).toBe(0);
    expect(spawnSync('tar', ['-cf', smallTarPath, '-C', smallDir, 'small.bin'], { encoding: 'utf8' }).status).toBe(0);

    // Bundle the module once so the child needs no TS loader.
    const bundlePath = join(dir, 'gvs.mjs');
    const esbuilt = spawnSync('npx', ['esbuild', join(REPO_ROOT, 'apps/runner/src/git-vm-staging.ts'), '--bundle', '--format=esm', '--platform=node', `--outfile=${bundlePath}`], { encoding: 'utf8', cwd: REPO_ROOT });
    expect(esbuilt.status).toBe(0);

    const probePath = join(dir, 'probe.mjs');
    writeFileSync(probePath, `
      import { extractTarSafe } from ${JSON.stringify(bundlePath)};
      const { statSync } = await import('node:fs');
      const small = await extractTarSafe(${JSON.stringify(smallTarPath)}, ${JSON.stringify(join(dir, 'out-small'))}, { maxEntries: 100, maxBytes: 1048576 });
      globalThis.gc?.();
      const rss0 = process.memoryUsage().rss;
      const big = await extractTarSafe(${JSON.stringify(tarPath)}, ${JSON.stringify(join(dir, 'out'))}, { maxEntries: 100, maxBytes: ${entryBytes + 1024 * 1024} });
      const size = statSync(${JSON.stringify(join(dir, 'out'))} + '/big.bin').size;
      console.log(JSON.stringify({ rss0, rss1: process.memoryUsage().rss, delta: process.memoryUsage().rss - rss0, bytes: big.bytes, size }));
    `);
    const probe = spawnSync('node', ['--expose-gc', probePath], { encoding: 'utf8', timeout: 120_000 });
    expect(probe.status).toBe(0);
    const report = JSON.parse(probe.stdout.trim().split('\n').at(-1)!);
    expect(report.size).toBe(entryBytes);
    // Whole-buffering would add ≥ entry size plus concat overhead (>512MiB
    // delta for a 256MiB entry). Streaming stays far below the entry size.
    expect(report.delta).toBeLessThan(entryBytes);
  }, 180_000);
});
