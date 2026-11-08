import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, writeFileSync, cpSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import type { RunnerConfig } from '@cloud-harness/contracts';
import type { ExecRequest, ExecResult, ExecutorBackend, ExecutorInspection, ProvisionContext, StreamHandle } from '../src/executor-backend.js';
import type { PtyTransport } from '../src/docker-pty.js';
import { VmGitStaging, type VmHelperRunner, type VmHelperSpec, type VmHelperResult } from '../src/git-vm-staging.js';
import { VmGitTransport } from '../src/git-vm-transport.js';
import { makeConfig, makeCtx, trackDir } from './backend-test-utils.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, '../../..');
const GUEST_SCRIPT = join(REPO_ROOT, 'deploy/vm-template/guest/usr/local/bin/git-vm.sh');
const TRANSFER_HELPER = join(REPO_ROOT, 'worker/git-transfer-helper.sh');

const tempDirs: string[] = [];
afterEach(() => {
  while (tempDirs.length) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});
function tmp(prefix: string): string {
  const dir = trackDir(mkdtempSync(join(tmpdir(), prefix)));
  tempDirs.push(dir);
  return dir;
}

function sh(bin: string, args: string[], opts: { cwd?: string; env?: NodeJS.ProcessEnv; input?: string } = {}) {
  return spawnSync(bin, args, { cwd: opts.cwd, env: opts.env ?? { PATH: process.env.PATH, HOME: '/tmp' }, input: opts.input, encoding: 'utf8' });
}
function git(cwd: string, args: string[]): string {
  const r = sh('git', args, { cwd });
  if (r.status !== 0) throw new Error(`git ${args.join(' ')} failed: ${r.stderr}`);
  return r.stdout.trim();
}

// ---------------------------------------------------------------------------
// Real-git fixtures
// ---------------------------------------------------------------------------

function makeRemote(): { remoteDir: string; workDir: string } {
  const base = tmp('ch-vm-remote-');
  const remoteDir = join(base, 'remote.git');
  const workDir = join(base, 'work');
  sh('git', ['init', '-q', '--bare', '-b', 'main', remoteDir]);
  sh('git', ['init', '-q', '-b', 'main', workDir]);
  git(workDir, ['config', 'user.email', 't@example.com']);
  git(workDir, ['config', 'user.name', 'tester']);
  writeFileSync(join(workDir, 'f.txt'), 'one\n');
  git(workDir, ['add', 'f.txt']);
  git(workDir, ['commit', '-qm', 'c1']);
  git(workDir, ['branch', 'dev']);
  git(workDir, ['push', '-q', remoteDir, 'HEAD:main', 'dev:dev']);
  return { remoteDir, workDir };
}

/** Staging clone fixture: a credential-free clone with an uncommitted toolkit patch. Must live under the workspace job path. */
function makeStagingClone(remoteDir: string, jobDir: string): string {
  const dir = join(jobDir, 'staging', 'clone');
  mkdirSync(join(jobDir, 'staging'), { recursive: true });
  sh('git', ['clone', '-q', remoteDir, dir]);
  git(dir, ['config', 'user.email', 't@example.com']);
  git(dir, ['config', 'user.name', 'tester']);
  // Uncommitted toolkit patch — must survive seedCheckout (phase-09 evidence).
  mkdirSync(join(dir, '.cloud-harness', 'skills', 'demo'), { recursive: true });
  writeFileSync(join(dir, '.cloud-harness', 'skills', 'demo', 'SKILL.md'), '---\nname: demo\n---\nbody\n');
  writeFileSync(join(dir, 'dirty.txt'), 'uncommitted\n');
  return dir;
}

// ---------------------------------------------------------------------------
// Fake guest backend: guest fs = local dir; exec runs real git/git-vm.sh.
// ---------------------------------------------------------------------------

class FakeGuestBackend implements ExecutorBackend {
  readonly kind = 'incus-vm' as const;
  readonly root = tmp('ch-vm-guestfs-');
  readonly execCalls: { argv: string[]; environment: Record<string, string>; cwd?: string }[] = [];

  private gpath(p: string): string {
    return join(this.root, p.replace(/^\/+/, ''));
  }
  private translate(arg: string): string {
    return arg.startsWith('/') ? this.gpath(arg) : arg;
  }

  async provision(): Promise<never> { throw new Error('not used'); }
  async ensureActive(): Promise<never> { throw new Error('not used'); }
  async spawnStream(): Promise<StreamHandle> { throw new Error('not used'); }
  pty(): PtyTransport { throw new Error('not used'); }
  async measureWorkspaceBytes(): Promise<number> { return 0; }
  async killProcessGroup(): Promise<void> {}
  async stop(): Promise<void> {}
  async destroy(): Promise<void> {}
  async inspect(): Promise<ExecutorInspection> { return { state: 'running' }; }
  capabilities() { return {} as never; }

  async exec(_ctx: ProvisionContext, req: ExecRequest): Promise<ExecResult> {
    this.execCalls.push({ argv: [...req.argv], environment: { ...req.environment }, ...(req.cwd ? { cwd: req.cwd } : {}) });
    const [bin, ...args] = req.argv;
    const translated = args.map((a) => this.translate(a));
    let cmd: string;
    let cmdArgs: string[];
    if (bin === '/usr/local/bin/git-vm.sh' || bin === 'git-vm.sh') {
      cmd = 'bash';
      cmdArgs = [GUEST_SCRIPT, ...translated];
    } else {
      cmd = bin;
      cmdArgs = translated;
    }
    const cwd = req.cwd ? this.translate(req.cwd) : this.gpath('/workspace');
    const result = spawnSync(cmd, cmdArgs, {
      cwd,
      env: {
        PATH: process.env.PATH,
        HOME: '/tmp',
        LANG: 'C.UTF-8',
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: '/dev/null',
        GIT_CONFIG_SYSTEM: '/dev/null',
        GIT_TERMINAL_PROMPT: '0',
        GIT_PAGER: 'cat',
        PAGER: 'cat',
        ...req.environment
      },
      input: typeof req.stdin === 'string' ? req.stdin : req.stdin,
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
      timeout: req.timeoutMs
    });
    return {
      exitCode: result.status,
      signal: result.signal,
      stdout: result.stdout ?? '',
      stderr: result.stderr ?? '',
      truncated: false,
      timedOut: result.error?.code === 'ETIMEDOUT' || result.signal === 'SIGTERM'
    };
  }

  /** Deterministic manifest digest — same contract shape as the docker backend. */
  private async digestDir(root: string): Promise<{ sha256: string; bytes: number; entryCount: number }> {
    const hash = createHash('sha256');
    let bytes = 0;
    let entryCount = 0;
    const walk = (dir: string, prefix: string) => {
      for (const name of readdirSync(dir).sort()) {
        const full = join(dir, name);
        const rel = prefix ? `${prefix}/${name}` : name;
        const st = statSync(full);
        entryCount += 1;
        if (st.isDirectory()) { hash.update(`d\0${rel}\0`); walk(full, rel); }
        else if (st.isFile()) {
          const content = createHash('sha256').update(readFileSync(full)).digest('hex');
          hash.update(`f\0${rel}\0${content}\0`);
          bytes += st.size;
        } else if (st.isSymbolicLink()) hash.update(`l\0${rel}\0`);
      }
    };
    walk(root, '');
    return { sha256: hash.digest('hex'), bytes, entryCount };
  }

  async pushTree(_ctx: ProvisionContext, hostDir: string, guestPath: string) {
    const dst = this.gpath(guestPath);
    mkdirSync(dst, { recursive: true });
    cpSync(hostDir, dst, { recursive: true });
    return this.digestDir(hostDir);
  }

  async pullTree(_ctx: ProvisionContext, guestPath: string, hostDir: string) {
    const src = this.gpath(guestPath);
    mkdirSync(hostDir, { recursive: true });
    cpSync(src, hostDir, { recursive: true });
    return this.digestDir(src);
  }

  async pullFile(_ctx: ProvisionContext, guestPath: string, maxBytes: number): Promise<Buffer> {
    const buf = readFileSync(this.gpath(guestPath));
    if (buf.length > maxBytes) throw new Error('pullFile exceeds maxBytes');
    return buf;
  }
}

// ---------------------------------------------------------------------------
// Host-side runner: real git for kind:'git', real helpers for transfer/probe.
// ---------------------------------------------------------------------------

function localRunner(): VmHelperRunner {
  return async (spec: VmHelperSpec) => {
    const run = (bin: string, args: string[], opts: { cwd?: string; input?: string; env?: NodeJS.ProcessEnv } = {}): VmHelperResult => {
      const r = spawnSync(bin, args, {
        cwd: opts.cwd,
        input: opts.input,
        encoding: 'utf8',
        env: { PATH: process.env.PATH, HOME: '/tmp', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_SYSTEM: '/dev/null', GIT_TERMINAL_PROMPT: '0', GIT_PAGER: 'cat', PAGER: 'cat', ...opts.env },
        maxBuffer: 16 * 1024 * 1024
      });
      return { exitCode: r.status, signal: r.signal, stdout: r.stdout ?? '', stderr: r.stderr ?? '', truncated: false, timedOut: false };
    };
    // Env values may reference the container mount spelling — translate like argv.
    const translateEnv = (env: Record<string, string> | undefined, containerPath: string): NodeJS.ProcessEnv =>
      Object.fromEntries(Object.entries(env ?? {}).map(([key, value]) => [
        key,
        value === containerPath ? spec.mountDir : value.startsWith(`${containerPath}/`) ? join(spec.mountDir, value.slice(containerPath.length + 1)) : value
      ]));
    if (spec.kind === 'git') {
      const containerPath = spec.containerPath ?? '/job';
      const args = spec.args.map((a) => (a === containerPath ? spec.mountDir : a.startsWith(`${containerPath}/`) ? join(spec.mountDir, a.slice(containerPath.length + 1)) : a));
      return run('git', args, { cwd: spec.mountDir, input: spec.stdin, env: translateEnv(spec.env, containerPath) });
    }
    if (spec.kind === 'transfer') {
      return run('bash', [TRANSFER_HELPER, spec.mode, spec.repositoryUrl, join(spec.mountDir, 'unused'), join(spec.mountDir, 'bare.git'), spec.argument, spec.expectedRemoteOid, spec.historySpec], { input: `${spec.stdin ?? ''}\n`, env: translateEnv(spec.env, '/job') });
    }
    throw new Error(`unexpected helper kind in test runner: ${(spec as { kind: string }).kind}`);
  };
}

/** ProvisionContext whose stagingDir lives under the workspace job path (staging confinement rule). */
function makeVmCtx(overrides: Partial<ProvisionContext> = {}): ProvisionContext {
  const ctx = makeCtx(overrides);
  ctx.stagingDir = join(ctx.record.workspacePath, 'staging', 'git');
  return ctx;
}

function makeTransport(opts: { backend?: FakeGuestBackend; runner?: VmHelperRunner; config?: RunnerConfig; exportWorkspace?: ConstructorParameters<typeof VmGitTransport>[0]['exportWorkspace'] } = {}) {
  const backend = opts.backend ?? new FakeGuestBackend();
  const config = opts.config ?? makeConfig();
  const transport = new VmGitTransport({
    backend,
    config,
    instanceId: 'instance-test',
    runner: opts.runner ?? localRunner(),
    // Local-path remotes are the offline test fixture; production uses the
    // real validateRepositoryUrl (https/443/allowlist/public-DNS).
    validateUrl: async (raw: string) => raw,
    ...(opts.exportWorkspace ? { exportWorkspace: opts.exportWorkspace } : {})
  });
  return { transport, backend, config };
}

function guestGitDir(backend: FakeGuestBackend): string {
  return join(backend.root, 'workspace');
}

// ---------------------------------------------------------------------------
// guestGit
// ---------------------------------------------------------------------------

describe('VmGitTransport.guestGit', () => {
  it('runs git -C /workspace inside the guest with the ctx environment', async () => {
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx({ environment: { CLOUD_HARNESS_TEST_ENV: 'present' } });
    const result = await transport.guestGit(ctx, ['rev-parse', '--is-inside-work-tree']);
    // No repo seeded yet → nonzero exit, but the exec itself must have run.
    expect(result.exitCode).not.toBe(0);
    const call = backend.execCalls.at(-1)!;
    expect(call.argv.slice(0, 3)).toEqual(['git', '-C', '/workspace']);
    expect(call.environment.CLOUD_HARNESS_TEST_ENV).toBe('present');
  });

  it('rejects non-string argv', async () => {
    const { transport } = makeTransport();
    await expect(transport.guestGit(makeVmCtx(), ['status', 1 as never])).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});

// ---------------------------------------------------------------------------
// seedCheckout — carries uncommitted toolkit files (phase-09 evidence)
// ---------------------------------------------------------------------------

describe('VmGitTransport.seedCheckout', () => {
  it('pushes the whole staging tree (incl .git and uncommitted files) to /workspace', async () => {
    const { remoteDir } = makeRemote();
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    await transport.seedCheckout(ctx, makeStagingClone(remoteDir, ctx.record.workspacePath));
    const guest = guestGitDir(backend);
    // Uncommitted toolkit patch + dirty file survived.
    expect(readFileSync(join(guest, '.cloud-harness', 'skills', 'demo', 'SKILL.md'), 'utf8')).toContain('name: demo');
    expect(readFileSync(join(guest, 'dirty.txt'), 'utf8')).toBe('uncommitted\n');
    expect(existsSync(join(guest, '.git'))).toBe(true);
    // Real repo sanity: guest git resolves HEAD.
    const head = git(guest, ['rev-parse', 'HEAD']);
    expect(head).toMatch(/^[0-9a-f]{40}$/);
    // Remote URL stays credential-free.
    const origin = git(guest, ['remote', 'get-url', 'origin']);
    expect(origin).not.toContain('token');
    expect(origin).not.toContain('x-access-token');
  });

  it('fails loudly when the staged tree is not a git checkout', async () => {
    const { transport } = makeTransport();
    const ctx = makeVmCtx();
    const notARepo = join(ctx.record.workspacePath, 'notrepo');
    mkdirSync(notARepo, { recursive: true });
    writeFileSync(join(notARepo, 'readme.txt'), 'hi\n');
    await expect(transport.seedCheckout(ctx, notARepo)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// importObjects / exportObjects
// ---------------------------------------------------------------------------

describe('VmGitTransport.importObjects', () => {
  it('verifies the digest then imports bundle objects+refs into the guest checkout', async () => {
    const { remoteDir, workDir } = makeRemote();
    // Advance remote so the bundle carries new objects.
    writeFileSync(join(workDir, 'new.txt'), 'new\n');
    git(workDir, ['add', 'new.txt']);
    git(workDir, ['commit', '-qm', 'c2']);
    git(workDir, ['push', '-q', remoteDir, 'HEAD:main']);
    const remoteMain = git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main']);

    // Host staging: fetch remote → bundle.
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    await transport.seedCheckout(ctx, makeStagingClone(remoteDir, ctx.record.workspacePath));
    // Rewind guest origin/main to c1 so the import is meaningful.
    const guest = guestGitDir(backend);
    const c1 = git(guest, ['rev-parse', 'HEAD~0']);
    git(guest, ['update-ref', 'refs/remotes/origin/main', git(guest, ['rev-list', '--max-parents=0', 'HEAD'])]);

    // Build the import bundle through the real staging path.
    const staging = new VmGitStaging({ config: makeConfig(), instanceId: 'instance-test', runner: localRunner() });
    const opDir = await staging.createOpDir(ctx);
    const bundlePath = join(ctx.record.workspacePath, 'incoming.bundle');
    try {
      const fetched = await staging.fetchRemoteBare(opDir, { repositoryUrl: remoteDir, remoteRef: '', historySpec: '', token: undefined });
      expect(fetched.exitCode).toBe(0);
      const bundle = await staging.createBundle(opDir, { revs: ['--branches'] });
      cpSync(bundle.hostPath, bundlePath);
      await transport.importObjects(ctx, bundlePath, bundle.sha256);
      // Guest now sees origin/main at the remote tip.
      expect(git(guest, ['rev-parse', 'refs/remotes/origin/main'])).toBe(remoteMain);
      expect(c1).toMatch(/^[0-9a-f]{40}$/);
    } finally {
      await staging.removeOpDir(opDir);
    }
  });

  it('rejects digest mismatch and missing bundles', async () => {
    const { transport } = makeTransport();
    const ctx = makeVmCtx();
    const dir = join(ctx.record.workspacePath, 'bundles');
    mkdirSync(dir, { recursive: true });
    const bundle = join(dir, 'b.bundle');
    writeFileSync(bundle, 'not a bundle');
    await expect(transport.importObjects(ctx, bundle, 'a'.repeat(64))).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(transport.importObjects(ctx, join(dir, 'missing.bundle'), 'a'.repeat(64))).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(transport.importObjects(ctx, bundle, 'not-hex')).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('rejects bundle host paths outside the workspace job path', async () => {
    const { transport } = makeTransport();
    const ctx = makeVmCtx();
    const outside = join(tmp('ch-vm-outside-'), 'b.bundle');
    writeFileSync(outside, 'x');
    await expect(transport.importObjects(ctx, outside, 'a'.repeat(64))).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('imports an incremental bundle (prerequisite lines) without the shallow-sidecar rejection', async () => {
    const { remoteDir, workDir } = makeRemote();
    // Advance remote to c3 so the guest checkout holds c1..c3.
    writeFileSync(join(workDir, 'n2.txt'), 'n2\n');
    git(workDir, ['add', 'n2.txt']);
    git(workDir, ['commit', '-qm', 'c2']);
    git(workDir, ['push', '-q', remoteDir, 'HEAD:main']);
    writeFileSync(join(workDir, 'n3.txt'), 'n3\n');
    git(workDir, ['add', 'n3.txt']);
    git(workDir, ['commit', '-qm', 'c3']);
    git(workDir, ['push', '-q', remoteDir, 'HEAD:main']);

    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    await transport.seedCheckout(ctx, makeStagingClone(remoteDir, ctx.record.workspacePath));
    const guest = guestGitDir(backend);

    // Incremental bundle: advertises inc-main (c2) with c1 as a '-' prerequisite.
    // The old clone-into-empty probe rejected this as unimportable even though
    // the prerequisite is present in the checkout.
    git(workDir, ['branch', '-f', 'inc-main', 'HEAD~1']);
    const bundlePath = join(ctx.record.workspacePath, 'incoming-inc.bundle');
    git(workDir, ['bundle', 'create', bundlePath, 'inc-main', '^inc-main~1']);
    const digest = createHash('sha256').update(readFileSync(bundlePath)).digest('hex');
    await transport.importObjects(ctx, bundlePath, digest);
    expect(git(guest, ['rev-parse', 'refs/remotes/origin/inc-main'])).toBe(git(workDir, ['rev-parse', 'inc-main']));
  });

  it('successful import into a shallow checkout leaves no shallow-boundary backup behind', async () => {
    const { remoteDir, workDir } = makeRemote();
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    // Seed the guest checkout from a SHALLOW staging clone: .git/shallow is
    // the only condition that makes git-vm.sh create the
    // git-vm-shallow-bak.* mktemp backup during import.
    const shallowStaging = join(ctx.record.workspacePath, 'staging', 'clone');
    mkdirSync(join(ctx.record.workspacePath, 'staging'), { recursive: true });
    sh('git', ['clone', '-q', '--depth', '1', `file://${remoteDir}`, shallowStaging]);
    await transport.seedCheckout(ctx, shallowStaging);
    const guest = guestGitDir(backend);
    expect(git(guest, ['rev-parse', '--is-shallow-repository'])).toBe('true');

    // Advance the remote so the import bundle carries new objects.
    writeFileSync(join(workDir, 'new.txt'), 'new\n');
    git(workDir, ['add', 'new.txt']);
    git(workDir, ['commit', '-qm', 'c2']);
    git(workDir, ['push', '-q', remoteDir, 'HEAD:main']);
    const remoteMain = git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main']);

    // Build the import bundle through the real staging path (same as the
    // first importObjects test).
    const staging = new VmGitStaging({ config: makeConfig(), instanceId: 'instance-test', runner: localRunner() });
    const opDir = await staging.createOpDir(ctx);
    const bundlePath = join(ctx.record.workspacePath, 'incoming.bundle');
    const bakGlob = () => readdirSync('/tmp').filter((f) => f.startsWith('git-vm-shallow-bak.'));
    const before = new Set(bakGlob());
    try {
      const fetched = await staging.fetchRemoteBare(opDir, { repositoryUrl: remoteDir, remoteRef: '', historySpec: '', token: undefined });
      expect(fetched.exitCode).toBe(0);
      const bundle = await staging.createBundle(opDir, { revs: ['--branches'] });
      cpSync(bundle.hostPath, bundlePath);
      await transport.importObjects(ctx, bundlePath, bundle.sha256);
      expect(git(guest, ['rev-parse', 'refs/remotes/origin/main'])).toBe(remoteMain);
      // The reconciled shallow boundary is the desired state — kept, not rolled back.
      expect(git(guest, ['rev-parse', '--is-shallow-repository'])).toBe('true');
      // Regression: pre-fix the success path disarmed the EXIT trap before it
      // could rm the backup, leaking git-vm-shallow-bak.* into TMPDIR.
      expect(bakGlob().filter((f) => !before.has(f))).toEqual([]);
    } finally {
      await staging.removeOpDir(opDir);
    }
  });

  it('rejects a crafted prerequisite+shallow bundle before any ref is published', async () => {
    const { remoteDir, workDir } = makeRemote();
    // The remote needs >1 commit so a depth-1 bundle truncates a parent.
    writeFileSync(join(workDir, 'n1.txt'), 'n1\n');
    git(workDir, ['add', 'n1.txt']);
    git(workDir, ['commit', '-qm', 'c2']);
    git(workDir, ['push', '-q', remoteDir, 'HEAD:main']);
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    // Seed the guest checkout with the object the crafted '-' line names as
    // its prerequisite, so `bundle unbundle` succeeds and the connectivity
    // gate is the only thing between the pack and ref publication.
    const guestWs = join(backend.root, 'workspace');
    mkdirSync(guestWs, { recursive: true });
    git(guestWs, ['init', '-q', '-b', 'main']);
    git(guestWs, ['config', 'user.email', 't@example.com']);
    git(guestWs, ['config', 'user.name', 'tester']);
    writeFileSync(join(guestWs, 'prereq.txt'), 'prereq\n');
    git(guestWs, ['add', 'prereq.txt']);
    git(guestWs, ['commit', '-qm', 'prereq']);
    const prereq = git(guestWs, ['rev-parse', 'HEAD']);

    // A real shallow bundle: the boundary commit's parent is absent and no
    // .shallow sidecar exists — the silent-corruption shape from the review.
    const shallowDir = tmp('ch-vm-shallow-');
    sh('git', ['clone', '-q', '--depth', '1', `file://${remoteDir}`, shallowDir]);
    const bundlePath = join(ctx.record.workspacePath, 'git-staging', 'crafted.bundle');
    mkdirSync(dirname(bundlePath), { recursive: true });
    git(shallowDir, ['bundle', 'create', bundlePath, '--branches']);
    // Inject a SATISFIED prerequisite line: bundleHasPrerequisites then skips
    // the host-side connectivity probe exactly like the reported bypass.
    const raw = readFileSync(bundlePath);
    const headerEnd = raw.indexOf('\n', raw.indexOf('# v2')) + 1;
    const injected = Buffer.concat([
      raw.subarray(0, headerEnd),
      Buffer.from(`-${prereq} crafted-prerequisite\n`),
      raw.subarray(headerEnd)
    ]);
    writeFileSync(bundlePath, injected);
    const digest = createHash('sha256').update(injected).digest('hex');

    const failure = await transport.importObjects(ctx, bundlePath, digest).then(
      () => {
        throw new Error('importObjects unexpectedly succeeded on a crafted bundle');
      },
      (error: unknown) => error
    );
    expect(failure).toMatchObject({ code: 'UNAVAILABLE' });
    expect((failure as Error).message).toMatch(/connectivity/);
    // No partial refs: the bundle advertises both main and dev, so a
    // per-ref publish loop could have left one behind — none may exist, and
    // the checked-out branch must still resolve to the pre-import commit.
    const refs = git(guestWs, ['for-each-ref', '--format=%(refname)']);
    expect(refs).not.toContain('refs/remotes/origin/');
    expect(git(guestWs, ['rev-parse', 'refs/heads/main'])).toBe(prereq);
  });

  it('rejects a shallow bundle that lacks its .shallow sidecar', async () => {
    const { remoteDir, workDir } = makeRemote();
    // The remote needs >1 commit: a depth-1 clone of a single-commit repo is
    // a root commit with nothing to truncate, so its bundle is complete.
    writeFileSync(join(workDir, 'n1.txt'), 'n1\n');
    git(workDir, ['add', 'n1.txt']);
    git(workDir, ['commit', '-qm', 'c2']);
    git(workDir, ['push', '-q', remoteDir, 'HEAD:main']);
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    // A real depth-1 clone produces a bundle whose boundary commit has a
    // dangling parent and NO '-' prerequisite lines. clone --bare succeeds on
    // it, so only the rev-list connectivity probe can detect the truncation.
    const shallowDir = tmp('ch-vm-shallow-');
    sh('git', ['clone', '-q', '--depth', '1', `file://${remoteDir}`, shallowDir]);
    const bundlePath = join(ctx.record.workspacePath, 'git-staging', 'shallow.bundle');
    mkdirSync(dirname(bundlePath), { recursive: true });
    git(shallowDir, ['bundle', 'create', bundlePath, '--branches']);
    const digest = createHash('sha256').update(readFileSync(bundlePath)).digest('hex');
    await expect(transport.importObjects(ctx, bundlePath, digest))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // The probe fails host-side before any guest execution.
    expect(backend.execCalls.filter((c) => c.argv[0] === '/usr/local/bin/git-vm.sh')).toHaveLength(0);
  });

  it('probes bundle connectivity with bounded fsck, never unbounded rev-list', async () => {
    const { workDir } = makeRemote();
    const { backend } = makeTransport();
    const gitArgs: string[][] = [];
    const recording = localRunner();
    const { transport } = makeTransport({
      backend,
      runner: async (spec) => {
        if (spec.kind === 'git') gitArgs.push([...spec.args]);
        return recording(spec);
      }
    });
    const ctx = makeVmCtx();
    // The fake guest's exec cwd is <root>/workspace and bundle-fetch needs a
    // real git repo there; seedCheckout normally creates both via pushTree.
    const guestWs = join(backend.root, 'workspace');
    mkdirSync(guestWs, { recursive: true });
    git(guestWs, ['init', '-q', '-b', 'main']);
    // A COMPLETE self-contained bundle (no '-' prereq lines, no sidecar)
    // reaches the connectivity probe; fsck must be the detector so a large
    // repo's object listing can never truncate into a false shallow rejection.
    const bundlePath = join(ctx.record.workspacePath, 'git-staging', 'full.bundle');
    mkdirSync(dirname(bundlePath), { recursive: true });
    git(workDir, ['bundle', 'create', bundlePath, '--branches']);
    const digest = createHash('sha256').update(readFileSync(bundlePath)).digest('hex');
    await transport.importObjects(ctx, bundlePath, digest);
    const flat = gitArgs.map((a) => a.join(' '));
    expect(flat.some((a) => a.includes('fsck') && a.includes('--connectivity-only'))).toBe(true);
    expect(flat.some((a) => a.includes('rev-list'))).toBe(false);
  });

  it('bounds guest cleanup by lease/hard TTL and makes it caller-cancellation independent', async () => {
    const { remoteDir, workDir } = makeRemote();
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    await transport.seedCheckout(ctx, makeStagingClone(remoteDir, ctx.record.workspacePath));
    // Self-contained bundle so the import reaches the finally-block cleanup.
    const bundlePath = join(ctx.record.workspacePath, 'self.bundle');
    git(workDir, ['bundle', 'create', bundlePath, '--branches']);
    const digest = createHash('sha256').update(readFileSync(bundlePath)).digest('hex');
    const rmCalls = () => backend.execCalls.filter((c) => c.argv[0] === 'rm');
    const seenRm: Array<{ signal: AbortSignal | undefined; timeoutMs: number | undefined }> = [];
    const originalExec = backend.exec.bind(backend);
    backend.exec = (execCtx: ProvisionContext, req: ExecRequest) => {
      if (req.argv[0] === 'rm') seenRm.push({ signal: req.signal, timeoutMs: req.timeoutMs });
      return originalExec(execCtx, req);
    };

    // Past the hard TTL the guest rm must not execute at all.
    ctx.record.hardExpiresAt = Date.now() - 1_000;
    await transport.importObjects(ctx, bundlePath, digest);
    expect(rmCalls()).toHaveLength(0);

    // Past the SOFT lease but before hard TTL — cleanup still must not run
    // guest work: the deadline is min(expiresAt, hardExpiresAt).
    ctx.record.hardExpiresAt = Date.now() + 60_000;
    ctx.record.expiresAt = Date.now() - 1_000;
    await transport.importObjects(ctx, bundlePath, digest);
    expect(rmCalls()).toHaveLength(0);

    // Live lease: the import's finally-block cleanup does run the guest rm.
    ctx.record.expiresAt = Date.now() + 60_000;
    await transport.importObjects(ctx, bundlePath, digest);
    expect(rmCalls().length).toBeGreaterThan(0);

    // Cleanup invoked just before the lease deadline is bounded by the
    // REMAINING time, not a fresh 30 s — direct invocation keeps the timing
    // deterministic (an importObjects round-trip would expire the lease first).
    const guestRm = (c: ProvisionContext, p: string) =>
      (transport as unknown as { guestRm(ctx: ProvisionContext, guestPath: string): Promise<void> }).guestRm(c, p);
    ctx.record.expiresAt = Date.now() + 400;
    await guestRm(ctx, '/tmp/xfer-bounded');
    const bounded = seenRm.at(-1)!;
    expect(bounded.timeoutMs).toBeGreaterThan(0);
    expect(bounded.timeoutMs!).toBeLessThanOrEqual(500);

    // With ample lease but an aborted caller signal, cleanup still runs —
    // and the exec request carries no caller signal and the full 30 s bound.
    ctx.record.expiresAt = Date.now() + 60_000;
    const controller = new AbortController();
    controller.abort();
    await guestRm({ ...ctx, signal: controller.signal }, '/tmp/xfer-aborted');
    const last = seenRm.at(-1)!;
    expect(last.signal).toBeUndefined();
    expect(last.timeoutMs).toBe(30_000);
    for (const call of seenRm) expect(call.signal).toBeUndefined();
  });
});

describe('VmGitTransport.exportObjects', () => {
  it('creates a guest bundle and returns it at the host path with a verified digest', async () => {
    const { remoteDir } = makeRemote();
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    await transport.seedCheckout(ctx, makeStagingClone(remoteDir, ctx.record.workspacePath));
    const outPath = join(ctx.record.workspacePath, 'git-staging', 'export.bundle');
    const result = await transport.exportObjects(ctx, 'main', outPath);
    expect(result.bytes).toBeGreaterThan(0);
    expect(result.sha256).toBe(createHash('sha256').update(readFileSync(outPath)).digest('hex'));
    // The bundle is a real git bundle containing the checkout's refs.
    const heads = git(ctx.record.workspacePath, ['bundle', 'list-heads', outPath]);
    expect(heads).toContain('refs/heads/main');
    expect(backend.execCalls.some((c) => c.argv[0] === '/usr/local/bin/git-vm.sh')).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// remoteFetch — host credentialed fetch → bundle → guest import
// ---------------------------------------------------------------------------

describe('VmGitTransport.remoteFetch', () => {
  it('fetches from the remote host-side and imports into the guest without credentials in the guest', async () => {
    const { remoteDir, workDir } = makeRemote();
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx({ environment: {} });
    // Seed at c1, THEN advance the remote so the fetch has something to move.
    await transport.seedCheckout(ctx, makeStagingClone(remoteDir, ctx.record.workspacePath));
    writeFileSync(join(workDir, 'fetched.txt'), 'from-remote\n');
    git(workDir, ['add', 'fetched.txt']);
    git(workDir, ['commit', '-qm', 'remote-c2']);
    git(workDir, ['push', '-q', remoteDir, 'HEAD:main']);
    const remoteMain = git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main']);
    const guest = guestGitDir(backend);
    // Guest origin/main is at c1; after fetch it must reach the remote tip.
    const before = git(guest, ['rev-parse', 'refs/remotes/origin/main']);
    expect(before).not.toBe(remoteMain);

    const token = 'ghp_secretTokenValue123';
    const result = await transport.remoteFetch(ctx, { repositoryUrl: remoteDir, remoteRef: '', historySpec: '', token });
    expect(result.fetched.exitCode).toBe(0);
    expect(result.imported.exitCode).toBe(0);
    expect(git(guest, ['rev-parse', 'refs/remotes/origin/main'])).toBe(remoteMain);

    // Secret non-disclosure: token appears in NO guest file, env, or argv.
    const guestEnv = backend.execCalls.filter((c) => c.argv[0] === '/usr/local/bin/git-vm.sh').map((c) => JSON.stringify(c.environment));
    for (const env of guestEnv) expect(env).not.toContain(token);
    for (const call of backend.execCalls) expect(JSON.stringify(call.argv)).not.toContain(token);
    const grep = sh('grep', ['-r', token, backend.root]);
    expect(grep.status).not.toBe(0);
    // Staging op dirs are cleaned up.
    const stagingRoot = join(ctx.record.workspacePath, 'git-staging');
    const leftovers = existsSync(stagingRoot) ? readdirSync(stagingRoot).filter((n) => n.startsWith('vm-git-')) : [];
    expect(leftovers).toEqual([]);
  });

  it('maps helper failure to UNAVAILABLE for fetch', async () => {
    const { transport } = makeTransport({
      runner: async (spec) => {
        if (spec.kind === 'transfer') return { exitCode: 128, stdout: '', stderr: 'fatal: repository not found', truncated: false };
        return localRunner()(spec);
      }
    });
    await expect(transport.remoteFetch(makeVmCtx(), { repositoryUrl: '/nonexistent', remoteRef: '', historySpec: '', token: undefined })).rejects.toMatchObject({ code: 'UNAVAILABLE' });
  });
});

// ---------------------------------------------------------------------------
// remotePush — guest bundle → staging bare → credentialed push + CAS
// ---------------------------------------------------------------------------

describe('VmGitTransport.remotePush', () => {
  async function seededGuest() {
    const { remoteDir, workDir } = makeRemote();
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    await transport.seedCheckout(ctx, makeStagingClone(remoteDir, ctx.record.workspacePath));
    const guest = guestGitDir(backend);
    git(guest, ['config', 'user.email', 't@example.com']);
    git(guest, ['config', 'user.name', 'tester']);
    return { remoteDir, workDir, transport, backend, ctx, guest };
  }

  it('pushes a guest commit to the remote with the expected-oid lease', async () => {
    const { remoteDir, transport, ctx, guest } = await seededGuest();
    writeFileSync(join(guest, 'pushed.txt'), 'guest-work\n');
    git(guest, ['add', 'pushed.txt']);
    git(guest, ['commit', '-qm', 'guest-work']);
    const guestHead = git(guest, ['rev-parse', 'HEAD']);
    const remoteBefore = git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main']);

    const pushed = await transport.remotePush(ctx, {
      repositoryUrl: remoteDir,
      refspec: 'refs/heads/main:refs/heads/main',
      expectedRemoteOid: remoteBefore,
      token: undefined
    });
    expect(pushed.exitCode).toBe(0);
    expect(git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main'])).toBe(guestHead);
  });

  it('rejects a stale lease with CONFLICT and leaves the remote untouched', async () => {
    const { remoteDir, workDir, transport, ctx, guest } = await seededGuest();
    writeFileSync(join(guest, 'x.txt'), 'x\n');
    git(guest, ['add', 'x.txt']);
    git(guest, ['commit', '-qm', 'guest-work']);
    const staleOid = git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main']);
    // Advance the remote so the lease is stale.
    writeFileSync(join(workDir, 'adv.txt'), 'adv\n');
    git(workDir, ['add', 'adv.txt']);
    git(workDir, ['commit', '-qm', 'remote-advance']);
    git(workDir, ['push', '-q', remoteDir, 'HEAD:main']);
    const afterAdvance = git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main']);

    await expect(transport.remotePush(ctx, {
      repositoryUrl: remoteDir,
      refspec: 'refs/heads/main:refs/heads/main',
      expectedRemoteOid: staleOid,
      token: undefined
    })).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main'])).toBe(afterAdvance);
  });

  it('maps network-failure push output to UNKNOWN_REMOTE_STATE', async () => {
    const { remoteDir } = makeRemote();
    const failing: VmHelperRunner = async (spec) => {
      if (spec.kind === 'transfer' && spec.mode === 'push') {
        return { exitCode: 128, stdout: '', stderr: 'fatal: unable to access: Connection timed out', truncated: false };
      }
      return localRunner()(spec);
    };
    const { transport: t3, backend: b3 } = makeTransport({ runner: failing });
    const ctx3 = makeVmCtx();
    await t3.seedCheckout(ctx3, makeStagingClone(remoteDir, ctx3.record.workspacePath));
    const g3 = guestGitDir(b3);
    git(g3, ['config', 'user.email', 't@example.com']);
    git(g3, ['config', 'user.name', 'tester']);
    writeFileSync(join(g3, 'z.txt'), 'z\n');
    git(g3, ['add', 'z.txt']);
    git(g3, ['commit', '-qm', 'w']);
    await expect(t3.remotePush(ctx3, { repositoryUrl: remoteDir, refspec: 'refs/heads/main:refs/heads/main', expectedRemoteOid: undefined, token: undefined }))
      .rejects.toMatchObject({ code: 'UNKNOWN_REMOTE_STATE' });
  });

  it('rejects option-injection refspecs before any guest or helper work', async () => {
    const { transport, backend } = makeTransport();
    await expect(transport.remotePush(makeVmCtx(), { repositoryUrl: '/tmp/x', refspec: '--upload-pack=evil', expectedRemoteOid: undefined, token: undefined }))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(backend.execCalls.filter((c) => c.argv[0] === '/usr/local/bin/git-vm.sh')).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// probeRemoteRefOid
// ---------------------------------------------------------------------------

describe('VmGitTransport.probeRemoteRefOid', () => {
  it('returns the remote branch oid, null for absent, undefined on failure', async () => {
    const { remoteDir } = makeRemote();
    const { transport } = makeTransport();
    const ctx = makeVmCtx();
    const oid = await transport.probeRemoteRefOid(ctx, { repositoryUrl: remoteDir, branch: 'main', token: undefined });
    expect(oid).toBe(git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main']));
    expect(await transport.probeRemoteRefOid(ctx, { repositoryUrl: remoteDir, branch: 'no-such-branch', token: undefined })).toBeNull();
    expect(await transport.probeRemoteRefOid(ctx, { repositoryUrl: '/nonexistent-repo', branch: 'main', token: undefined })).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// exportCheckoutOffline — stopped-VM export → safe extract → inspection
// ---------------------------------------------------------------------------

describe('VmGitTransport.exportCheckoutOffline', () => {
  function makeExportTar(dir: string): { tarPath: string; sha256: string; bytes: number } {
    const tarPath = join(dir, 'export.tar');
    const r = sh('tar', ['-cf', tarPath, '-C', dir, 'workspace']);
    expect(r.status).toBe(0);
    const buf = readFileSync(tarPath);
    return { tarPath, sha256: createHash('sha256').update(buf).digest('hex'), bytes: buf.length };
  }

  function exportWorkspaceFrom(tarPath: string) {
    // Landed VmExportWorkspaceFn shape: writes the tar to opts.destPath,
    // resolves {sha256, bytes} — same contract as createVmExportWorkspace.
    return async (_ctx: ProvisionContext, opts: { guestPath: string; destPath: string; maxBytes: number }) => {
      const buf = readFileSync(tarPath);
      writeFileSync(opts.destPath, buf);
      return { sha256: createHash('sha256').update(buf).digest('hex'), bytes: buf.length };
    };
  }

  function buildCheckout(dir: string, opts: { dirty?: boolean; unpushed?: boolean; stash?: boolean } = {}): string {
    const repo = join(dir, 'src');
    sh('git', ['init', '-q', '-b', 'main', repo]);
    git(repo, ['config', 'user.email', 't@example.com']);
    git(repo, ['config', 'user.name', 'tester']);
    writeFileSync(join(repo, 'f.txt'), 'one\n');
    git(repo, ['add', 'f.txt']);
    git(repo, ['commit', '-qm', 'c1']);
    const remote = join(dir, 'remote.git');
    sh('git', ['init', '-q', '--bare', '-b', 'main', remote]);
    git(repo, ['remote', 'add', 'origin', remote]);
    git(repo, ['push', '-q', 'origin', 'HEAD:main']);
    git(repo, ['fetch', '-q', 'origin']);
    if (opts.unpushed) {
      writeFileSync(join(repo, 'u.txt'), 'unpushed\n');
      git(repo, ['add', 'u.txt']);
      git(repo, ['commit', '-qm', 'unpushed-work']);
    }
    if (opts.dirty) writeFileSync(join(repo, 'dirty.txt'), 'dirty\n');
    if (opts.stash) {
      writeFileSync(join(repo, 'stash.txt'), 'stash-me\n');
      git(repo, ['add', 'stash.txt']);
      git(repo, ['stash', 'push', '-qm', 'wip']);
    }
    return repo;
  }

  it('reports clean for a fully-pushed checkout', async () => {
    const dir = tmp('ch-vm-exp-');
    const repo = buildCheckout(dir);
    const ws = join(dir, 'workspace');
    cpSync(repo, ws, { recursive: true });
    const tar = makeExportTar(dir);
    const { transport } = makeTransport({ exportWorkspace: exportWorkspaceFrom(tar.tarPath) });
    const result = await transport.exportCheckoutOffline(makeVmCtx(), { maxBytes: 64 * 1024 * 1024, cloneRef: 'main' });
    expect(result.verdict).toBe('clean');
  });

  it('preserves .git/shallow into workDir/shallow.txt for offline push staging', async () => {
    const dir = tmp('ch-vm-exp-');
    // Remote with enough history for a meaningful shallow boundary.
    const base = join(dir, 'base');
    sh('git', ['init', '-q', '-b', 'main', base]);
    git(base, ['config', 'user.email', 't@example.com']);
    git(base, ['config', 'user.name', 'tester']);
    for (let i = 1; i <= 4; i++) {
      writeFileSync(join(base, 'f.txt'), `v${i}\n`);
      git(base, ['add', 'f.txt']);
      git(base, ['commit', '-qm', `c${i}`]);
    }
    const remote = join(dir, 'remote.git');
    sh('git', ['init', '-q', '--bare', '-b', 'main', remote]);
    git(base, ['remote', 'add', 'origin', remote]);
    git(base, ['push', '-q', 'origin', 'HEAD:main']);
    const ws = join(dir, 'workspace');
    const clone = sh('git', ['clone', '-q', '--depth', '2', `file://${remote}`, ws]);
    expect(clone.status).toBe(0);
    const shallowFile = join(ws, '.git', 'shallow');
    expect(existsSync(shallowFile)).toBe(true);
    const tar = makeExportTar(dir);
    const { transport } = makeTransport({ exportWorkspace: exportWorkspaceFrom(tar.tarPath) });
    const result = await transport.exportCheckoutOffline(makeVmCtx(), { maxBytes: 64 * 1024 * 1024, cloneRef: 'main' });
    expect(result.verdict).toBe('clean');
    // The boundary must reach the op dir under the name stagePushBare/pushBare
    // consume — this is the offline snapshot sidecar the caller stages from.
    const sidecar = join(result.workDir, 'shallow.txt');
    expect(existsSync(sidecar)).toBe(true);
    expect(readFileSync(sidecar, 'utf8').trim()).toBe(readFileSync(shallowFile, 'utf8').trim());
  });

  it('reports retain for dirty, unpushed, and stashed checkouts', async () => {
    for (const opts of [{ dirty: true }, { unpushed: true }, { stash: true }]) {
      const dir = tmp('ch-vm-exp-');
      const repo = buildCheckout(dir, opts);
      cpSync(repo, join(dir, 'workspace'), { recursive: true });
      const tar = makeExportTar(dir);
      const { transport } = makeTransport({ exportWorkspace: exportWorkspaceFrom(tar.tarPath) });
      const result = await transport.exportCheckoutOffline(makeVmCtx(), { maxBytes: 64 * 1024 * 1024, cloneRef: 'main' });
      expect(result.verdict).toBe('retain');
    }
  });

  it('reports unknown when no checkout root exists in the export', async () => {
    const dir = tmp('ch-vm-exp-');
    mkdirSync(join(dir, 'workspace', 'random'), { recursive: true });
    writeFileSync(join(dir, 'workspace', 'random', 'f.txt'), 'x');
    const tar = makeExportTar(dir);
    const { transport } = makeTransport({ exportWorkspace: exportWorkspaceFrom(tar.tarPath) });
    const result = await transport.exportCheckoutOffline(makeVmCtx(), { maxBytes: 64 * 1024 * 1024 });
    expect(result.verdict).toBe('unknown');
  });

  it('rejects when no export seam is configured', async () => {
    const { transport } = makeTransport();
    await expect(transport.exportCheckoutOffline(makeVmCtx(), { maxBytes: 1024 })).rejects.toMatchObject({ code: 'VM_CAPABILITY_UNSUPPORTED' });
  });
});

// ---------------------------------------------------------------------------
// Shallow boundaries — real repos, independent oracle (docker import_history parity)
// ---------------------------------------------------------------------------

describe('VmGitTransport shallow semantics', () => {
  /** Remote with `count` linear commits on main. */
  function makeShallowRemote(count: number): { remoteDir: string; workDir: string } {
    const base = tmp('ch-vm-shallow-');
    const remoteDir = join(base, 'remote.git');
    const workDir = join(base, 'work');
    sh('git', ['init', '-q', '--bare', '-b', 'main', remoteDir]);
    sh('git', ['init', '-q', '-b', 'main', workDir]);
    git(workDir, ['config', 'user.email', 't@example.com']);
    git(workDir, ['config', 'user.name', 'tester']);
    for (let i = 1; i <= count; i++) {
      writeFileSync(join(workDir, 'f.txt'), `v${i}\n`);
      git(workDir, ['add', 'f.txt']);
      git(workDir, ['commit', '-qm', `c${i}`]);
    }
    git(workDir, ['push', '-q', remoteDir, 'HEAD:main']);
    return { remoteDir, workDir };
  }

  function advance(workDir: string, remoteDir: string, tag: string): string {
    writeFileSync(join(workDir, 'f.txt'), `${tag}\n`);
    git(workDir, ['add', 'f.txt']);
    git(workDir, ['commit', '-qm', tag]);
    git(workDir, ['push', '-q', remoteDir, 'HEAD:main']);
    return git(workDir, ['rev-parse', 'HEAD']);
  }

  /** Shallow staging clone (file:// required for --depth over local transport). */
  function makeShallowClone(remoteDir: string, jobDir: string, depth: number): string {
    const dir = join(jobDir, 'staging', `clone-d${depth}`);
    mkdirSync(join(jobDir, 'staging'), { recursive: true });
    const r = sh('git', ['clone', '-q', `--depth`, String(depth), `file://${remoteDir}`, dir]);
    if (r.status !== 0) throw new Error(`shallow clone failed: ${r.stderr}`);
    git(dir, ['config', 'user.email', 't@example.com']);
    git(dir, ['config', 'user.name', 'tester']);
    return dir;
  }

  function shallowMarks(guestDir: string): string[] {
    const file = join(guestDir, '.git', 'shallow');
    if (!existsSync(file)) return [];
    return readFileSync(file, 'utf8').split('\n').map((l) => l.trim()).filter(Boolean).sort();
  }

  it('divergent boundary keeps old marks with missing parents plus the transferred tip', async () => {
    const { remoteDir, workDir } = makeShallowRemote(6);
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    // Guest at depth:3 → boundary = c4 (keeps c4,c5,c6).
    await transport.seedCheckout(ctx, makeShallowClone(remoteDir, ctx.record.workspacePath, 3));
    const guest = guestGitDir(backend);
    const oldMark = shallowMarks(guest);
    expect(oldMark).toHaveLength(1);
    expect(git(guest, ['rev-list', '--count', 'refs/remotes/origin/main'])).toBe('3');

    // Remote advances two commits; host fetches depth:1 → boundary = new tip.
    advance(workDir, remoteDir, 'c7');
    const tip = advance(workDir, remoteDir, 'c8');
    await transport.remoteFetch(ctx, { repositoryUrl: remoteDir, remoteRef: '', historySpec: 'depth:1', token: undefined });

    // Oracle (real `git fetch --depth 1`): old mark survives (its parent is
    // still absent) AND the new tip is marked — count collapses to 1.
    const marks = shallowMarks(guest);
    expect(marks).toEqual([oldMark[0]!, tip].sort());
    expect(git(guest, ['rev-list', '--count', 'refs/remotes/origin/main'])).toBe('1');
    expect(git(guest, ['rev-parse', 'refs/remotes/origin/main'])).toBe(tip);
  });

  it('deepening recomputes the boundary and drops marks whose parents arrived', async () => {
    const { remoteDir, workDir } = makeShallowRemote(6);
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    await transport.seedCheckout(ctx, makeShallowClone(remoteDir, ctx.record.workspacePath, 3));
    const guest = guestGitDir(backend);
    advance(workDir, remoteDir, 'c7');
    const tip8 = advance(workDir, remoteDir, 'c8');
    await transport.remoteFetch(ctx, { repositoryUrl: remoteDir, remoteRef: '', historySpec: 'depth:1', token: undefined });
    expect(shallowMarks(guest)).toHaveLength(2);

    // depth:4 over the 8-commit remote → boundary = c5; the c8 mark's parent
    // c7 is now present so it drops; the orphaned c4 mark keeps its missing
    // parent c3 and survives alongside c5.
    const linear = git(remoteDir, ['--git-dir', remoteDir, 'rev-list', '--reverse', 'refs/heads/main']).split('\n');
    const c4 = linear[3]!;
    const c5 = linear[4]!;
    await transport.remoteFetch(ctx, { repositoryUrl: remoteDir, remoteRef: '', historySpec: 'depth:4', token: undefined });
    expect(shallowMarks(guest)).toEqual([c4, c5].sort());
    expect(git(guest, ['rev-list', '--count', 'refs/remotes/origin/main'])).toBe('4');
    expect(tip8).toMatch(/^[0-9a-f]{40}$/);
  });

  it('full unshallows a shallow checkout once history is complete', async () => {
    const { remoteDir, workDir } = makeShallowRemote(6);
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    await transport.seedCheckout(ctx, makeShallowClone(remoteDir, ctx.record.workspacePath, 3));
    const guest = guestGitDir(backend);
    advance(workDir, remoteDir, 'c7');
    await transport.remoteFetch(ctx, { repositoryUrl: remoteDir, remoteRef: '', historySpec: 'depth:2', token: undefined });
    expect(shallowMarks(guest).length).toBeGreaterThan(0);

    await transport.remoteFetch(ctx, { repositoryUrl: remoteDir, remoteRef: '', historySpec: 'full', token: undefined });
    expect(shallowMarks(guest)).toEqual([]);
    expect(git(guest, ['rev-list', '--count', 'refs/remotes/origin/main'])).toBe('7');
  });

  it('a complete checkout is never cut back by a depth request', async () => {
    const { remoteDir, workDir } = makeRemote();
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    await transport.seedCheckout(ctx, makeStagingClone(remoteDir, ctx.record.workspacePath));
    const guest = guestGitDir(backend);
    writeFileSync(join(workDir, 'd.txt'), 'd\n');
    git(workDir, ['add', 'd.txt']);
    git(workDir, ['commit', '-qm', 'c2']);
    git(workDir, ['push', '-q', remoteDir, 'HEAD:main']);
    await transport.remoteFetch(ctx, { repositoryUrl: remoteDir, remoteRef: '', historySpec: 'depth:1', token: undefined });
    expect(shallowMarks(guest)).toEqual([]);
    expect(existsSync(join(guest, '.git', 'shallow'))).toBe(false);
  });

  it('empty history spec leaves the shallow file untouched', async () => {
    const { remoteDir, workDir } = makeShallowRemote(6);
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    await transport.seedCheckout(ctx, makeShallowClone(remoteDir, ctx.record.workspacePath, 3));
    const guest = guestGitDir(backend);
    const before = shallowMarks(guest);
    advance(workDir, remoteDir, 'c7');
    await transport.remoteFetch(ctx, { repositoryUrl: remoteDir, remoteRef: '', historySpec: '', token: undefined });
    expect(shallowMarks(guest)).toEqual(before);
  });

  it('pushes from a shallow checkout through the boundary-aware staging path', async () => {
    const { remoteDir, workDir } = makeShallowRemote(6);
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    await transport.seedCheckout(ctx, makeShallowClone(remoteDir, ctx.record.workspacePath, 4));
    const guest = guestGitDir(backend);
    expect(shallowMarks(guest).length).toBeGreaterThan(0);
    git(guest, ['config', 'user.email', 't@example.com']);
    git(guest, ['config', 'user.name', 'tester']);
    writeFileSync(join(guest, 'pushed.txt'), 'shallow-work\n');
    git(guest, ['add', 'pushed.txt']);
    git(guest, ['commit', '-qm', 'shallow-work']);
    const guestHead = git(guest, ['rev-parse', 'HEAD']);
    const remoteBefore = git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main']);

    const pushed = await transport.remotePush(ctx, {
      repositoryUrl: remoteDir,
      refspec: 'refs/heads/main:refs/heads/main',
      expectedRemoteOid: remoteBefore,
      token: undefined
    });
    expect(pushed.exitCode).toBe(0);
    expect(git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main'])).toBe(guestHead);
    void workDir;
  });

  it('strips a leading + force marker from the bundle source rev (M4)', async () => {
    const { remoteDir } = makeRemote();
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    await transport.seedCheckout(ctx, makeStagingClone(remoteDir, ctx.record.workspacePath));
    const guest = guestGitDir(backend);
    git(guest, ['config', 'user.email', 't@example.com']);
    git(guest, ['config', 'user.name', 'tester']);
    // Diverge so the push is meaningful (an up-to-date push is rejected).
    writeFileSync(join(guest, 'force.txt'), 'force\n');
    git(guest, ['add', 'force.txt']);
    git(guest, ['commit', '-qm', 'force-work']);
    const remoteBefore = git(remoteDir, ['--git-dir', remoteDir, 'rev-parse', 'refs/heads/main']);
    // '+refs/heads/main:...' must reach git bundle create as 'refs/heads/main'.
    const pushed = await transport.remotePush(ctx, {
      repositoryUrl: remoteDir,
      refspec: '+refs/heads/main:refs/heads/main',
      expectedRemoteOid: remoteBefore,
      token: undefined
    });
    expect(pushed.exitCode).toBe(0);
    expect(backend.execCalls.some((c) => c.argv.includes('+refs/heads/main'))).toBe(false);
  });

  // exportObjects/importObjects — the generic GitDataPlane object transfer
  // must carry the shallow boundary end-to-end, not just remoteFetch/Push.

  it('exportObjects persists the guest shallow boundary as a <bundle>.shallow sibling', async () => {
    const { remoteDir } = makeShallowRemote(8);
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    await transport.seedCheckout(ctx, makeShallowClone(remoteDir, ctx.record.workspacePath, 3));
    const guest = guestGitDir(backend);
    const marks = shallowMarks(guest);
    expect(marks).toHaveLength(1);
    const outPath = join(ctx.record.workspacePath, 'git-staging', 'exported.bundle');
    const result = await transport.exportObjects(ctx, 'main', outPath);
    expect(result.bytes).toBeGreaterThan(0);
    expect(result.sha256).toBe(createHash('sha256').update(readFileSync(outPath)).digest('hex'));
    const sidecar = `${outPath}.shallow`;
    expect(existsSync(sidecar)).toBe(true);
    expect(readFileSync(sidecar, 'utf8').trim().split('\n').sort()).toEqual(marks);
  });

  it('exportObjects writes no sidecar for a complete checkout', async () => {
    const { remoteDir } = makeRemote();
    const { transport } = makeTransport();
    const ctx = makeVmCtx();
    await transport.seedCheckout(ctx, makeStagingClone(remoteDir, ctx.record.workspacePath));
    const outPath = join(ctx.record.workspacePath, 'git-staging', 'full.bundle');
    await transport.exportObjects(ctx, 'main', outPath);
    expect(existsSync(`${outPath}.shallow`)).toBe(false);
  });

  it('importObjects applies a carried .shallow sidecar to a different-boundary checkout', async () => {
    const { remoteDir } = makeShallowRemote(8);
    const { transport, backend } = makeTransport();
    const ctx = makeVmCtx();
    // Export from a depth:3 checkout (boundary = c6).
    await transport.seedCheckout(ctx, makeShallowClone(remoteDir, ctx.record.workspacePath, 3));
    const guest = guestGitDir(backend);
    const exported = await transport.exportObjects(ctx, 'main', join(ctx.record.workspacePath, 'git-staging', 'xfer.bundle'));
    const bundlePath = join(ctx.record.workspacePath, 'git-staging', 'xfer.bundle');
    expect(existsSync(`${bundlePath}.shallow`)).toBe(true);

    // Re-seed at depth:2 (boundary = c7) — the import must union the
    // transferred boundary with the surviving old mark, never unmark.
    rmSync(guest, { recursive: true, force: true });
    await transport.seedCheckout(ctx, makeShallowClone(remoteDir, ctx.record.workspacePath, 2));
    const linear = git(remoteDir, ['--git-dir', remoteDir, 'rev-list', '--reverse', 'refs/heads/main']).split('\n');
    const c6 = linear[5]!;
    const c7 = linear[6]!;
    await transport.importObjects(ctx, bundlePath, exported.sha256);
    expect(shallowMarks(guest)).toEqual([c6, c7].sort());
    // The imported tip is reachable and history stays consistent (no
    // missing-object corruption from unmarked truncated parents). Boundary
    // commits still count in rev-list — {c7 marked, c8} → 2.
    expect(git(guest, ['rev-parse', 'refs/remotes/origin/main'])).toBe(linear[7]);
    expect(git(guest, ['rev-list', '--count', 'refs/remotes/origin/main'])).toBe('2');
  });

  it('importObjects rejects a shallow bundle whose .shallow sidecar is missing', async () => {
    const { remoteDir } = makeShallowRemote(8);
    const { transport } = makeTransport();
    const ctx = makeVmCtx();
    await transport.seedCheckout(ctx, makeShallowClone(remoteDir, ctx.record.workspacePath, 3));
    const bundlePath = join(ctx.record.workspacePath, 'git-staging', 'orphan.bundle');
    const exported = await transport.exportObjects(ctx, 'main', bundlePath);
    rmSync(`${bundlePath}.shallow`); // caller dropped the sidecar — must fail loudly
    await expect(transport.importObjects(ctx, bundlePath, exported.sha256)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('importObjects rejects a malformed .shallow sidecar instead of dropping it', async () => {
    const { remoteDir } = makeRemote();
    const { transport } = makeTransport();
    const ctx = makeVmCtx();
    await transport.seedCheckout(ctx, makeStagingClone(remoteDir, ctx.record.workspacePath));
    const bundlePath = join(ctx.record.workspacePath, 'git-staging', 'bad.sidecar.bundle');
    const exported = await transport.exportObjects(ctx, 'main', bundlePath);
    writeFileSync(`${bundlePath}.shallow`, 'not-a-valid-oid\n');
    await expect(transport.importObjects(ctx, bundlePath, exported.sha256)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});
