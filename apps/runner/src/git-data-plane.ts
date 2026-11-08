import { createHash, randomBytes } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdir, stat } from 'node:fs/promises';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { HarnessError, type ExecutorBackendKind, type RunnerConfig } from '@cloud-harness/contracts';
import { removeContainer, runDocker } from './docker-engine.js';
import type { ExecRequest, ExecResult, ExecutorBackend, ProvisionContext } from './executor-backend.js';

/**
 * Brokered git data plane. The checkout root inside the executor is
 * `/workspace` — NOT `/workspace/repo` (that host path is the docker mount
 * source only). Objects cross backends as digest-verified bundles through
 * host staging; credentials never enter the executor.
 */
export interface GitDataPlane {
  readonly backend: ExecutorBackendKind;
  /** Seed the guest `/workspace` root from host staging (docker: checkout already mounted — no-op). */
  seedCheckout(ctx: ProvisionContext, stagingRepoDir: string): Promise<void>;
  /** Export objects matching `refspec` into a bundle file at `outBundleHostPath`; returns its digest. */
  exportObjects(ctx: ProvisionContext, refspec: string, outBundleHostPath: string): Promise<{ sha256: string; bytes: number }>;
  /** Verify `expectedSha256` and import the bundle's objects+refs into the checkout at `/workspace`. */
  importObjects(ctx: ProvisionContext, bundleHostPath: string, expectedSha256: string): Promise<void>;
  /** Credential-free `git -C /workspace …` inside the executor; env comes from `ctx`. */
  guestGit(ctx: ProvisionContext, args: string[], opts?: { timeoutMs?: number; maxBytes?: number; signal?: AbortSignal }): Promise<ExecResult>;
  /** Host bare/bundle staging directory under the job path. */
  stagingDir(ctx: ProvisionContext): string;
}

export type DockerGitDataPlaneDeps = {
  backend: ExecutorBackend;
  config: RunnerConfig;
  instanceId: string;
};

const GUEST_GIT_TIMEOUT_MS = 30_000;
const GUEST_GIT_MAX_BYTES = 65_536;
const BUNDLE_HELPER_TIMEOUT_MS = 120_000;
const MAX_BUNDLE_HEADS = 1_024;
const BUNDLE_REF_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$/;

async function sha256File(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

/**
 * Splits a caller-supplied revision spec into `git bundle create` rev-list
 * arguments. Revisions never contain whitespace, and any `-`-leading token is
 * rejected outright rather than silently dropped — it would be a git option,
 * not a revision.
 */
function revisionArgs(spec: string): string[] {
  const trimmed = spec.trim();
  if (!trimmed || trimmed.length > 4_096 || /[\0\n\r]/.test(trimmed)) {
    throw new HarnessError('INVALID_INPUT', 'git revision spec is invalid', 400, false);
  }
  const args = trimmed.split(/\s+/);
  if (args.some((arg) => arg.startsWith('-'))) {
    throw new HarnessError('INVALID_INPUT', 'git revision spec cannot contain options', 400, false);
  }
  return args;
}

/**
 * Maps `git bundle list-heads` output (`<oid> <ref>` lines) to fetch
 * refspecs that preserve today's import outcome: bundle heads land on
 * `refs/remotes/origin/*`, tags on their own names, and anything else
 * (HEAD, exotic refs) lands in FETCH_HEAD only — objects always transfer.
 * Bundle metadata is guest-influenced untrusted input: every ref is
 * shape-checked so no argv element can be option-parsed by git.
 */
export function bundleHeadsToRefspecs(listHeads: string): string[] {
  const refspecs = new Set<string>();
  for (const line of listHeads.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const ref = trimmed.split(/\s+/)[1] ?? '';
    const isHead = ref.startsWith('refs/heads/');
    const isTag = ref.startsWith('refs/tags/');
    const fetchable = ref === 'HEAD' || isHead || isTag || ref.startsWith('refs/');
    if (!fetchable || !BUNDLE_REF_PATTERN.test(ref) || ref.includes('..') || ref.endsWith('/') || ref.includes('//')) {
      throw new HarnessError('INVALID_INPUT', 'git bundle advertises an invalid ref name', 400, false);
    }
    if (isHead) {
      refspecs.add(`+${ref}:refs/remotes/origin/${ref.slice('refs/heads/'.length)}`);
    } else if (isTag) {
      refspecs.add(`+${ref}:${ref}`);
    } else {
      refspecs.add(ref);
    }
    if (refspecs.size > MAX_BUNDLE_HEADS) {
      throw new HarnessError('LIMIT_EXCEEDED', 'git bundle advertises too many refs', 413, false);
    }
  }
  return [...refspecs];
}

/**
 * The docker `GitDataPlane`: object transfer rides the same hardened ephemeral
 * helper shape `git-transfer-helper.sh` uses (workspace job dir mounted at
 * `/job`, uid 10001, read-only rootfs, no network, cap-drop ALL), and the
 * import's pause semantics stay inside this class where they already lived.
 * `guestGit` is `docker exec git -C /workspace` with the read-only host-mount
 * helper fallback today's `currentBranch`/`currentHead` carry.
 */
export class DockerGitDataPlane implements GitDataPlane {
  readonly backend: ExecutorBackendKind = 'docker';

  constructor(private readonly deps: DockerGitDataPlaneDeps) {}

  stagingDir(ctx: ProvisionContext): string {
    return ctx.stagingDir;
  }

  /** The checkout is already bind-mounted at `/workspace`; there is nothing to seed. */
  async seedCheckout(): Promise<void> {}

  /**
   * Maps a host path under `record.workspacePath` to its `/job/...` path
   * inside helper containers. Paths outside the job dir are unreachable —
   * callers must keep bundles/bare staging under the workspace job path.
   */
  private jobRelative(ctx: ProvisionContext, hostPath: string): string {
    const jobPath = ctx.record.workspacePath;
    const abs = resolve(hostPath);
    const rel = relative(jobPath, abs);
    if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) {
      throw new HarnessError('INVALID_INPUT', 'git data-plane host path must live under the workspace job path', 400, false);
    }
    return rel.split(sep).join('/');
  }

  /**
   * One credential-free git invocation inside the transfer-helper hardening
   * envelope. `gitArgs` are the full argv after the `git` binary; callers add
   * `-C /job/repo` when the command needs the checkout. No stdin, no token —
   * bundle transport never carries credentials.
   */
  private async runGitHelper(
    ctx: ProvisionContext,
    gitArgs: string[],
    options: { timeoutMs?: number; signal?: AbortSignal } = {}
  ): Promise<{ exitCode: number; stdout: string; stderr: string; truncated: boolean }> {
    const helperName = `chm-git-${randomBytes(6).toString('hex')}`;
    try {
      const result = await runDocker([
        'run', '--rm', '--pull', 'never', '--name', helperName,
        '--label', 'cloud-harness.role=git-transfer-helper', '--label', 'cloud-harness.ephemeral=true',
        '--label', `cloud-harness.instance=${this.deps.instanceId}`, '--label', `cloud-harness.workspace=${ctx.record.id}`,
        '--network', 'none', '--user', '10001:10001', '--read-only',
        '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=64m', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--pids-limit', '128', '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
        '--env', 'HOME=/tmp/cloud-harness-home', '--env', 'GIT_CONFIG_NOSYSTEM=1', '--env', 'GIT_TERMINAL_PROMPT=0',
        '--volume', `${ctx.record.workspacePath}:/job:rw`,
        '--entrypoint', '/usr/bin/git',
        this.deps.config.executorImage,
        '-c', 'core.hooksPath=/dev/null', '-c', 'core.pager=cat', ...gitArgs
      ], {
        timeoutMs: options.timeoutMs ?? BUNDLE_HELPER_TIMEOUT_MS,
        maxBytes: this.deps.config.maxOutputBytes,
        ...(options.signal ? { signal: options.signal } : {})
      });
      return result;
    } finally {
      await removeContainer(helperName).catch(() => undefined);
    }
  }

  async exportObjects(ctx: ProvisionContext, refspec: string, outBundleHostPath: string): Promise<{ sha256: string; bytes: number }> {
    const revisions = revisionArgs(refspec);
    if (revisions.length === 0) {
      throw new HarnessError('INVALID_INPUT', 'exportObjects requires at least one revision', 400, false);
    }
    const bundleRel = this.jobRelative(ctx, outBundleHostPath);
    await mkdir(dirname(outBundleHostPath), { recursive: true });
    // `git bundle create` only reads the checkout — no pause needed, matching
    // today's read-only helper operations.
    const result = await this.runGitHelper(ctx, [
      '-C', '/job/repo', 'bundle', 'create', `/job/${bundleRel}`, ...revisions
    ], { ...(ctx.signal ? { signal: ctx.signal } : {}) });
    if (result.exitCode !== 0) {
      throw new HarnessError('UNAVAILABLE', `git bundle export failed: ${result.stderr || result.stdout}`.slice(0, 2_000), 502, true);
    }
    const info = await stat(outBundleHostPath).catch(() => undefined);
    if (!info?.isFile() || info.size === 0) {
      throw new HarnessError('UNAVAILABLE', 'git bundle export produced no bundle file', 502, true);
    }
    return { sha256: await sha256File(outBundleHostPath), bytes: info.size };
  }

  /**
   * Pause → import → unpause, byte-identical to the service's
   * `withPausedExecutor`: it throws UNAVAILABLE without a container, the pause
   * wraps only the import, an unpause failure is itself UNAVAILABLE, and the
   * action's error is rethrown after resume.
   */
  private async withPausedExecutor<T>(ctx: ProvisionContext, action: () => Promise<T>): Promise<T> {
    const containerName = ctx.record.containerName;
    if (!containerName) throw new HarnessError('UNAVAILABLE', 'workspace executor is unavailable', 503, true);
    const paused = await runDocker(['pause', containerName], { timeoutMs: 30_000, maxBytes: 8_192, ...(ctx.signal ? { signal: ctx.signal } : {}) });
    if (paused.exitCode !== 0) throw new HarnessError('UNAVAILABLE', 'executor could not be paused for an atomic Git transfer', 503, true);
    let value: T | undefined;
    let actionError: unknown;
    try {
      value = await action();
    } catch (error) { actionError = error; }
    // The unpause MUST outlive caller cancellation: an aborted ctx.signal here
    // would leave the executor frozen forever. The 30s timeout still bounds it.
    const resumed = await runDocker(['unpause', containerName], { timeoutMs: 30_000, maxBytes: 8_192 });
    if (resumed.exitCode !== 0) throw new HarnessError('UNAVAILABLE', 'executor could not be resumed after Git transfer', 503, true);
    if (actionError) throw actionError;
    return value!;
  }

  async importObjects(ctx: ProvisionContext, bundleHostPath: string, expectedSha256: string): Promise<void> {
    if (!/^[0-9a-f]{64}$/i.test(expectedSha256)) {
      throw new HarnessError('INVALID_INPUT', 'expectedSha256 must be a SHA-256 hex digest', 400, false);
    }
    const info = await stat(bundleHostPath).catch(() => undefined);
    if (!info?.isFile() || info.size === 0) {
      throw new HarnessError('NOT_FOUND', 'git bundle file not found', 404, false);
    }
    const actual = (await sha256File(bundleHostPath)).toLowerCase();
    if (actual !== expectedSha256.toLowerCase()) {
      throw new HarnessError('INVALID_INPUT', 'git bundle digest does not match the expected SHA-256', 400, false);
    }
    const bundleRel = this.jobRelative(ctx, bundleHostPath);
    // Ref discovery is read-only bundle inspection — it runs before the pause
    // so the frozen window covers only the checkout mutation.
    const heads = await this.runGitHelper(ctx, ['bundle', 'list-heads', `/job/${bundleRel}`], { ...(ctx.signal ? { signal: ctx.signal } : {}) });
    if (heads.exitCode !== 0) {
      throw new HarnessError('INVALID_INPUT', `git bundle could not be inspected: ${heads.stderr || heads.stdout}`.slice(0, 2_000), 400, false);
    }
    const refspecs = bundleHeadsToRefspecs(heads.stdout);
    if (refspecs.length === 0) {
      throw new HarnessError('INVALID_INPUT', 'git bundle advertises no refs', 400, false);
    }
    await this.withPausedExecutor(ctx, async () => {
      const result = await this.runGitHelper(ctx, [
        '-C', '/job/repo', 'fetch', '--no-tags', '--no-recurse-submodules',
        `/job/${bundleRel}`, ...refspecs
      ], { ...(ctx.signal ? { signal: ctx.signal } : {}) });
      if (result.exitCode !== 0) {
        throw new HarnessError('UNAVAILABLE', `git bundle import failed: ${result.stderr || result.stdout}`.slice(0, 2_000), 502, true);
      }
    });
  }

  async guestGit(ctx: ProvisionContext, args: string[], opts: { timeoutMs?: number; maxBytes?: number; signal?: AbortSignal } = {}): Promise<ExecResult> {
    if (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string')) {
      throw new HarnessError('INVALID_INPUT', 'guestGit args must be a string array', 400, false);
    }
    const timeoutMs = opts.timeoutMs ?? GUEST_GIT_TIMEOUT_MS;
    const maxBytes = opts.maxBytes ?? GUEST_GIT_MAX_BYTES;
    if (ctx.record.containerName) {
      const request: ExecRequest = {
        argv: ['git', '-C', '/workspace', ...args],
        environment: ctx.environment,
        timeoutMs,
        maxBytes,
        ...(opts.signal ? { signal: opts.signal } : {})
      };
      return await this.deps.backend.exec(ctx, request);
    }
    return await this.guestGitHelper(ctx, args, timeoutMs, maxBytes, opts.signal);
  }

  /**
   * The read-only host-mount fallback today's `currentBranch`/`currentHead`
   * helpers use when no executor container exists. The argv is byte-identical
   * to those helpers — workdir `/workspace` stands in for `-C /workspace` —
   * and the environment stays the fixed credential-free helper set: workspace
   * secrets must never leak into a helper that only needed a read-only peek.
   */
  private async guestGitHelper(ctx: ProvisionContext, args: string[], timeoutMs: number, maxBytes: number, signal?: AbortSignal): Promise<ExecResult> {
    const helperName = `chm-git-${randomBytes(6).toString('hex')}`;
    try {
      const result = await runDocker([
        'run', '--rm', '--name', helperName,
        '--label', 'cloud-harness.ephemeral=true',
        '--network', 'none', '--user', '10001:10001', '--read-only',
        '--volume', `${ctx.record.workspacePath}/repo:/workspace:ro`,
        '--workdir', '/workspace',
        '--entrypoint', 'git',
        this.deps.config.executorImage,
        ...args
      ], { timeoutMs, maxBytes, ...(signal ? { signal } : {}) });
      return { exitCode: result.exitCode, signal: null, stdout: result.stdout, stderr: result.stderr, truncated: result.truncated, timedOut: false };
    } finally {
      await removeContainer(helperName).catch(() => undefined);
    }
  }
}
