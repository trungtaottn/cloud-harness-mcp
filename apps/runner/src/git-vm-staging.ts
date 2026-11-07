import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { chmod, chown, lstat, lchown, link as fsLink, mkdir, open, readdir, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import type { Readable } from 'node:stream';
import { once } from 'node:events';
import { finished } from 'node:stream/promises';
import { HarnessError, type RunnerConfig } from '@cloud-harness/contracts';
import { removeContainer, runDocker } from './docker-engine.js';
import { bundleHeadsToRefspecs } from './git-data-plane.js';
import type { ProvisionContext } from './executor-backend.js';

/**
 * Host-side git staging for the incus-vm data plane. Everything here runs on
 * the RUNNER host inside the same hardened ephemeral-helper envelope the
 * docker git path uses: host helpers are docker containers that never see the
 * guest checkout, credentials travel only on helper stdin (never argv, never
 * guest files, never transferred archives), and every path stays confined to
 * the workspace job staging dir.
 *
 * Object flow (phase-08, git-native — no quiesce):
 *   fetch:  git-transfer-helper fetch → staging bare → renormalize refs →
 *           `git bundle create` → digest-verified pushTree → guest fetch
 *   push:   guest `git bundle create` → pullTree → `git clone --bare` staging
 *           → git-transfer-helper push (force-with-lease CAS unchanged)
 *   export: supervisor vm.export tar → bounded write → safe extract →
 *           credential-free git inspection of the untrusted checkout copy
 */

export interface VmHelperResult {
  exitCode: number | null;
  signal?: string | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  timedOut?: boolean;
}

export type VmHelperSpec =
  | {
      kind: 'git';
      /** Host directory mounted at `containerPath` inside the helper. */
      mountDir: string;
      /** Container-side mount/workdir path. Default `/job`. */
      containerPath?: string;
      /** Mount read-only (inspection). Default read-write. */
      readOnly?: boolean;
      /** Extra process env (e.g. GIT_SHALLOW_FILE); validated, never secrets. */
      env?: Record<string, string>;
      /** git argv after the `-c` hardening flags; may use containerPath-absolute or workdir-relative paths. */
      args: string[];
      stdin?: string;
      timeoutMs?: number;
      signal?: AbortSignal;
      workspaceId?: string;
    }
  | {
      kind: 'transfer';
      /** Op dir mounted at `/job`; must contain `bare.git`. */
      mountDir: string;
      mode: 'fetch' | 'push';
      repositoryUrl: string;
      /** fetch: remote ref ('' = all heads); push: normalized refspec. */
      argument: string;
      /** push lease value: '', 'absent', or a hex object id. */
      expectedRemoteOid: string;
      historySpec: string;
      /** Token material — stdin only, NEVER argv/env/files. */
      stdin?: string;
      /** Extra process env for the helper script (e.g. GIT_SHALLOW_FILE); validated, never secrets. */
      env?: Record<string, string>;
      timeoutMs?: number;
      signal?: AbortSignal;
      workspaceId?: string;
    };

export type VmHelperRunner = (spec: VmHelperSpec) => Promise<VmHelperResult>;

const HELPER_TIMEOUT_MS = 120_000;
const GIT_HELPER_MAX_BYTES_FALLBACK = 1_048_576;
/** uid/gid every helper-visible staging path is owned by inside the container. */
export const VM_HELPER_UID = 10001;
export const VM_HELPER_GID = 10001;

const ENV_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** Extra helper env is a small fixed surface (e.g. GIT_SHALLOW_FILE) — never secrets. */
function assertHelperEnv(env: Record<string, string> | undefined): void {
  if (env === undefined) return;
  for (const [key, value] of Object.entries(env)) {
    if (!ENV_KEY.test(key) || value.length > 8192 || /[\0\n\r]/.test(value)) {
      throw new HarnessError('INVALID_INPUT', 'helper env entry is invalid', 400, false);
    }
  }
}

function helperEnvArgs(env: Record<string, string> | undefined): string[] {
  assertHelperEnv(env);
  return Object.entries(env ?? {}).flatMap(([key, value]) => ['--env', `${key}=${value}`]);
}

/** Container path spellings safe to embed in a `-c safe.directory=` value. */
function assertContainerPath(containerPath: string): void {
  if (!containerPath.startsWith('/') || !/^[A-Za-z0-9/_.-]+$/.test(containerPath) || containerPath.includes('..')) {
    throw new HarnessError('INVALID_INPUT', 'helper containerPath is invalid', 400, false);
  }
}

/**
 * Ephemeral docker helpers — the only production runner. `kind:'git'` is a
 * credential-free `/usr/bin/git` invocation (network none, read-only rootfs,
 * cap-drop ALL, uid 10001); `kind:'transfer'` is `/opt/harness/git-transfer-helper.sh`
 * on bridge for the two credentialed modes this plane uses (fetch, push).
 * The token rides stdin exactly like `runGitTransferHelper` today.
 */
export function dockerVmHelperRunner(deps: { config: RunnerConfig; instanceId: string }): VmHelperRunner {
  return async (spec) => {
    const helperName = `chm-vmg-${randomBytes(6).toString('hex')}`;
    const workspaceLabel = spec.workspaceId ? [`--label`, `cloud-harness.workspace=${spec.workspaceId}`] : [];
    try {
      if (spec.kind === 'git') {
        const containerPath = spec.containerPath ?? '/job';
        assertContainerPath(containerPath);
        const result = await runDocker([
          'run', '--rm', '--pull', 'never', '--name', helperName,
          '--label', 'cloud-harness.role=git-vm-helper', '--label', 'cloud-harness.ephemeral=true',
          '--label', `cloud-harness.instance=${deps.instanceId}`, ...workspaceLabel,
          '--network', 'none', '--user', '10001:10001', '--read-only',
          '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=64m', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
          '--pids-limit', '128', '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
          '--env', 'HOME=/tmp/cloud-harness-home', '--env', 'GIT_CONFIG_NOSYSTEM=1', '--env', 'GIT_CONFIG_GLOBAL=/dev/null',
          '--env', 'GIT_CONFIG_SYSTEM=/dev/null', '--env', 'GIT_TERMINAL_PROMPT=0', '--env', 'GIT_PAGER=cat', '--env', 'PAGER=cat',
          ...helperEnvArgs(spec.env),
          '--volume', `${spec.mountDir}:${containerPath}:${spec.readOnly ? 'ro' : 'rw'}`,
          '--workdir', containerPath,
          '--entrypoint', '/usr/bin/git',
          deps.config.executorImage,
          '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false', '-c', 'core.pager=cat',
          '-c', 'credential.helper=', '-c', 'http.followRedirects=false',
          // safe.directory is protected-scope only; command -c qualifies. The
          // mount root itself plus everything beneath it covers worktree and
          // gitdir spellings without trusting arbitrary host paths.
          '-c', `safe.directory=${containerPath}`, '-c', `safe.directory=${containerPath}/*`,
          ...spec.args
        ], {
          ...(spec.stdin !== undefined ? { stdin: spec.stdin } : {}),
          timeoutMs: spec.timeoutMs ?? HELPER_TIMEOUT_MS,
          maxBytes: deps.config.maxOutputBytes ?? GIT_HELPER_MAX_BYTES_FALLBACK,
          ...(spec.signal ? { signal: spec.signal } : {})
        });
        return { exitCode: result.exitCode, stdout: result.stdout, stderr: result.stderr, truncated: result.truncated };
      }
      const result = await runDocker([
        'run', '-i', '--rm', '--pull', 'never', '--name', helperName,
        '--label', 'cloud-harness.role=git-transfer-helper', '--label', 'cloud-harness.ephemeral=true',
        '--label', `cloud-harness.instance=${deps.instanceId}`, ...workspaceLabel,
        '--network', 'bridge', '--user', '10001:10001', '--read-only',
        '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=64m', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--pids-limit', '128', '--memory', '512m', '--memory-swap', '512m', '--cpus', '1',
        '--env', 'HOME=/tmp/cloud-harness-home', '--env', 'GIT_CONFIG_NOSYSTEM=1', '--env', 'GIT_TERMINAL_PROMPT=0',
        ...helperEnvArgs(spec.env),
        '--volume', `${spec.mountDir}:/job:rw`,
        '--entrypoint', '/opt/harness/git-transfer-helper.sh',
        deps.config.executorImage,
        spec.mode, spec.repositoryUrl, '/job/unused', '/job/bare.git', spec.argument, spec.expectedRemoteOid, spec.historySpec
      ], {
        stdin: `${spec.stdin ?? ''}\n`,
        timeoutMs: spec.timeoutMs ?? HELPER_TIMEOUT_MS,
        maxBytes: deps.config.maxOutputBytes ?? GIT_HELPER_MAX_BYTES_FALLBACK,
        ...(spec.signal ? { signal: spec.signal } : {})
      });
      return { exitCode: result.exitCode, stdout: result.stdout, stderr: result.stderr, truncated: result.truncated };
    } finally {
      await removeContainer(helperName).catch(() => undefined);
    }
  };
}

/** Upper bound for a single git bundle crossing the boundary (fetch or push direction). */
export const VM_MAX_BUNDLE_BYTES = 1024 * 1024 * 1024;
const MAX_REF_LIST_BYTES = 65_536;
/** Staging bare repository directory name inside every op dir. */
export const BARE_DIR_NAME = 'bare.git';
const STAGING_REF_FETCH = 'refs/vm-import/fetch';
const OP_DIR_PATTERN = /^vm-git-[0-9a-f]{16}$/;
/** Shallow-boundary sidecar carried next to push bundles (guest .git/shallow content). */
export const VM_SHALLOW_BOUNDARY_NAME = 'shallow.txt';
/**
 * Sidecar byte ceiling shared by every layer: 8 MiB covers the 100k-line
 * mark bound for sha256 object ids (~6.6 MB). The guest helper enforces the
 * same constant on emit and reconcile.
 */
export const VM_MAX_SHALLOW_BOUNDARY_BYTES = 8 * 1024 * 1024;
const MAX_SHALLOW_BOUNDARY_LINES = 100_000;
const SHALLOW_OID = /^[0-9a-f]{40}$|^[0-9a-f]{64}$/;

/** Host-side sibling path carrying a bundle's shallow boundary (`<bundle>.shallow`). */
export const vmShallowSidecarPath = (bundlePath: string): string => `${bundlePath}.shallow`;

/**
 * Validates a shallow-boundary sidecar as a bounded regular file of hex
 * object ids. Returns true when the file exists; throws INVALID_INPUT on
 * anything present-but-malformed — a corrupt sidecar must never be
 * silently ignored (it is the only record of a shallow bundle's boundary).
 */
export async function validateVmShallowBoundary(path: string): Promise<boolean> {
  const info = await lstat(path).catch(() => undefined);
  if (info === undefined) return false;
  if (!info.isFile() || info.size === 0 || info.size > VM_MAX_SHALLOW_BOUNDARY_BYTES) {
    throw new HarnessError('INVALID_INPUT', 'shallow boundary sidecar is not a bounded regular file', 400, false);
  }
  const content = await readFile(path, 'utf8');
  const lines = content.split('\n').map((line) => line.trim()).filter((line) => line !== '');
  if (lines.length > MAX_SHALLOW_BOUNDARY_LINES || lines.some((line) => !SHALLOW_OID.test(line))) {
    throw new HarnessError('INVALID_INPUT', 'shallow boundary sidecar contains malformed entries', 400, false);
  }
  return true;
}

/**
 * Filesystem ops {@link secureVmStagingDir} needs — injectable so ownership
 * semantics are testable without privileged execution.
 */
export interface VmStagingDirOps {
  getuid?: () => number | undefined;
  chown?: (path: string, uid: number, gid: number) => Promise<void>;
  lchown?: (path: string, uid: number, gid: number) => Promise<void>;
  chmod?: (path: string, mode: number) => Promise<void>;
}

const defaultDirOps: Required<VmStagingDirOps> = {
  getuid: () => (typeof process.getuid === 'function' ? process.getuid() : undefined),
  chown: (path, uid, gid) => chown(path, uid, gid),
  lchown: (path, uid, gid) => lchown(path, uid, gid),
  chmod: (path, mode) => chmod(path, mode)
};

/**
 * Makes a staging directory writable by the uid-10001 helper containers with
 * scoped, private permissions — never a blind world-writable tree:
 *   - privileged runner (root): chown to the helper uid and chmod 0700, so
 *     only the helper uid (and root) can enter — tighter than the jobPath
 *     0777 precedent;
 *   - unprivileged runner (dev/tests): chown is impossible, so fall back to
 *     0777 on THIS directory only — the same exposure class workspacePath
 *     already accepts, required for dev-docker helpers to write.
 */
export async function secureVmStagingDir(dir: string, ops: VmStagingDirOps = {}): Promise<void> {
  const o = { ...defaultDirOps, ...ops };
  if (o.getuid() === 0) {
    try {
      await o.chown(dir, VM_HELPER_UID, VM_HELPER_GID);
      await o.chmod(dir, 0o700);
      return;
    } catch {
      // Fall through to the permissive mode — a root runner that cannot
      // chown still needs helper-writable staging.
    }
  }
  await o.chmod(dir, 0o777);
}

/**
 * Splits a caller-supplied revision spec into `git bundle create` rev-list
 * arguments — same contract as the docker plane: whitespace-separated,
 * `-`-leading tokens rejected as option injection.
 */
export function vmRevisionArgs(spec: string): string[] {
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

async function sha256File(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return hash.digest('hex');
}

export interface VmGitStagingDeps {
  config: RunnerConfig;
  instanceId: string;
  /** Injectable for tests; defaults to {@link dockerVmHelperRunner}. */
  runner?: VmHelperRunner;
}

export class VmGitStaging {
  private readonly runner: VmHelperRunner;
  /** Op dirs this instance created — the ONLY paths removeOpDir will delete. */
  private readonly opDirs = new Set<string>();

  constructor(private readonly deps: VmGitStagingDeps) {
    this.runner = deps.runner ?? dockerVmHelperRunner({ config: deps.config, instanceId: deps.instanceId });
  }

  /** ctx.stagingDir verified to live under the workspace job path, created if needed. */
  async stagingRoot(ctx: ProvisionContext): Promise<string> {
    const root = resolve(ctx.stagingDir);
    const job = resolve(ctx.record.workspacePath);
    const rel = relative(job, root);
    if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) {
      throw new HarnessError('INVALID_INPUT', 'git staging dir must live under the workspace job path', 400, false);
    }
    await mkdir(root, { recursive: true });
    await secureVmStagingDir(root);
    return root;
  }

  async createOpDir(ctx: ProvisionContext): Promise<string> {
    const root = await this.stagingRoot(ctx);
    const dir = join(root, `vm-git-${randomBytes(8).toString('hex')}`);
    await mkdir(dir, { recursive: true });
    await secureVmStagingDir(dir);
    this.opDirs.add(dir);
    return dir;
  }

  /** Removes an op dir created by {@link createOpDir}; refuses anything else. */
  async removeOpDir(opDir: string): Promise<void> {
    const abs = resolve(opDir);
    if (!this.opDirs.has(abs) || !OP_DIR_PATTERN.test(basename(abs))) {
      throw new HarnessError('INVALID_INPUT', 'refusing to remove a path that is not a staging op dir', 400, false);
    }
    await rm(abs, { recursive: true, force: true });
    this.opDirs.delete(abs);
  }

  /**
   * Credential-free git invocation inside the hardened helper envelope.
   * `mountDir` is a host path mounted at `containerPath` (default `/job`);
   * args may reference either spelling. Public so checkout inspection and the
   * transport can share the same hardened path.
   */
  git(mountDir: string, args: string[], opts: { containerPath?: string; readOnly?: boolean; env?: Record<string, string>; stdin?: string; timeoutMs?: number; signal?: AbortSignal; workspaceId?: string } = {}): Promise<VmHelperResult> {
    return this.runner({
      kind: 'git',
      mountDir,
      args,
      ...(opts.containerPath !== undefined ? { containerPath: opts.containerPath } : {}),
      ...(opts.readOnly !== undefined ? { readOnly: opts.readOnly } : {}),
      ...(opts.env !== undefined ? { env: opts.env } : {}),
      ...(opts.stdin !== undefined ? { stdin: opts.stdin } : {}),
      ...(opts.timeoutMs !== undefined ? { timeoutMs: opts.timeoutMs } : {}),
      ...(opts.signal !== undefined ? { signal: opts.signal } : {}),
      ...(opts.workspaceId !== undefined ? { workspaceId: opts.workspaceId } : {})
    });
  }

  private transfer(opDir: string, mode: 'fetch' | 'push', params: {
    repositoryUrl: string;
    argument: string;
    expectedRemoteOid?: string;
    historySpec?: string;
    token?: string;
    env?: Record<string, string>;
    timeoutMs?: number;
    signal?: AbortSignal;
    workspaceId?: string;
  }): Promise<VmHelperResult> {
    return this.runner({
      kind: 'transfer',
      mountDir: opDir,
      mode,
      repositoryUrl: params.repositoryUrl,
      argument: params.argument,
      expectedRemoteOid: params.expectedRemoteOid ?? '',
      historySpec: params.historySpec ?? '',
      ...(params.token !== undefined ? { stdin: params.token } : {}),
      ...(params.env !== undefined ? { env: params.env } : {}),
      ...(params.timeoutMs !== undefined ? { timeoutMs: params.timeoutMs } : {}),
      ...(params.signal !== undefined ? { signal: params.signal } : {}),
      ...(params.workspaceId !== undefined ? { workspaceId: params.workspaceId } : {})
    });
  }

  /**
   * Validates and returns the GIT_SHALLOW_FILE env for ops touching a
   * shallow-staged bare, or undefined for complete repos. The sidecar is
   * guest-supplied bytes — strict shape check before it reaches git.
   */
  private async shallowBoundaryEnv(opDir: string): Promise<Record<string, string> | undefined> {
    const present = await validateVmShallowBoundary(join(opDir, VM_SHALLOW_BOUNDARY_NAME));
    if (!present) return undefined;
    return { GIT_SHALLOW_FILE: `/job/${VM_SHALLOW_BOUNDARY_NAME}` };
  }

  /**
   * Credentialed remote fetch into `opDir/bare.git` via the unchanged
   * `git-transfer-helper.sh fetch` mode, then renormalizes the helper's
   * `refs/heads/cloud-harness/*` staging refs into the names the bundle
   * mapper expects:
   *   - full fetch (remoteRef ''): `cloud-harness/<b>` → `refs/heads/<b>`
   *   - `refs/heads/X`: `cloud-harness-fetch` → `refs/heads/X` (origin tracking parity)
   *   - anything else: `cloud-harness-fetch` → `refs/vm-import/fetch`
   *     (maps to a FETCH_HEAD-only refspec — objects land, no ref created,
   *     matching the docker import outcome for tags/HEAD/raw revisions).
   */
  async fetchRemoteBare(opDir: string, params: {
    repositoryUrl: string;
    remoteRef: string;
    historySpec?: string;
    token?: string;
    timeoutMs?: number;
    signal?: AbortSignal;
    workspaceId?: string;
  }): Promise<VmHelperResult> {
    const remoteRef = params.remoteRef ?? '';
    if (remoteRef.length > 255 || remoteRef.startsWith('-') || /[\0\n\r]/.test(remoteRef)) {
      throw new HarnessError('INVALID_INPUT', 'git fetch ref is invalid', 400, false);
    }
    const fetched = await this.transfer(opDir, 'fetch', {
      repositoryUrl: params.repositoryUrl,
      argument: remoteRef,
      ...(params.historySpec !== undefined ? { historySpec: params.historySpec } : {}),
      ...(params.token !== undefined ? { token: params.token } : {}),
      ...(params.timeoutMs !== undefined ? { timeoutMs: params.timeoutMs } : {}),
      ...(params.signal !== undefined ? { signal: params.signal } : {}),
      ...(params.workspaceId !== undefined ? { workspaceId: params.workspaceId } : {})
    });
    if (fetched.exitCode !== 0) return fetched;
    await this.renormalizeFetchRefs(opDir, remoteRef, params);
    return fetched;
  }

  private async renormalizeFetchRefs(opDir: string, remoteRef: string, params: { signal?: AbortSignal; workspaceId?: string }): Promise<void> {
    const listed = await this.git(opDir, ['--git-dir=' + BARE_DIR_NAME, 'for-each-ref', '--format=%(refname) %(objectname)', 'refs/heads/'], {
      readOnly: true,
      ...(params.signal !== undefined ? { signal: params.signal } : {}),
      ...(params.workspaceId !== undefined ? { workspaceId: params.workspaceId } : {})
    });
    if (listed.exitCode !== 0 || listed.truncated) {
      throw new HarnessError('UNAVAILABLE', `staged ref listing failed: ${listed.stderr || listed.stdout}`.slice(0, 2_000), 502, true);
    }
    const lines = listed.stdout.split('\n').map((line) => line.trim()).filter(Boolean);
    if (lines.length === 0) return;
    const updates: string[] = [];
    for (const line of lines) {
      const [name, oid] = line.split(/\s+/);
      if (!name || !/^[0-9a-f]{40,64}$/.test(oid ?? '')) {
        throw new HarnessError('UNAVAILABLE', 'staged bare repository returned a malformed ref listing', 502, true);
      }
      let target: string;
      if (remoteRef === '') {
        const match = /^refs\/heads\/cloud-harness\/(.+)$/.exec(name);
        if (!match) throw new HarnessError('UNAVAILABLE', `unexpected staged ref ${name}`, 502, true);
        target = `refs/heads/${match[1]}`;
      } else {
        if (name !== 'refs/heads/cloud-harness-fetch') {
          throw new HarnessError('UNAVAILABLE', `unexpected staged ref ${name}`, 502, true);
        }
        target = remoteRef.startsWith('refs/heads/')
          ? `refs/heads/${remoteRef.slice('refs/heads/'.length)}`
          : STAGING_REF_FETCH;
      }
      const format = await this.git(opDir, ['--git-dir=' + BARE_DIR_NAME, 'check-ref-format', target], {
        readOnly: true,
        ...(params.signal !== undefined ? { signal: params.signal } : {}),
        ...(params.workspaceId !== undefined ? { workspaceId: params.workspaceId } : {})
      });
      if (format.exitCode !== 0) {
        throw new HarnessError('INVALID_INPUT', `fetched ref ${remoteRef} cannot be staged under ${target}`, 400, false);
      }
      updates.push(`update ${target} ${oid}`, `delete ${name}`);
    }
    const applied = await this.git(opDir, ['--git-dir=' + BARE_DIR_NAME, 'update-ref', '--stdin'], {
      stdin: `${updates.join('\n')}\n`,
      ...(params.signal !== undefined ? { signal: params.signal } : {}),
      ...(params.workspaceId !== undefined ? { workspaceId: params.workspaceId } : {})
    });
    if (applied.exitCode !== 0) {
      throw new HarnessError('UNAVAILABLE', `staged ref renormalization failed: ${applied.stderr || applied.stdout}`.slice(0, 2_000), 502, true);
    }
  }

  /** `git bundle create` inside the staging bare; returns the verified host file. */
  async createBundle(opDir: string, opts: { revs: string[]; outName?: string; signal?: AbortSignal; workspaceId?: string }): Promise<{ hostPath: string; sha256: string; bytes: number }> {
    const outName = opts.outName ?? 'transfer.bundle';
    if (!/^[A-Za-z0-9._-]+$/.test(outName)) {
      throw new HarnessError('INVALID_INPUT', 'bundle output name is invalid', 400, false);
    }
    const created = await this.git(opDir, ['--git-dir=' + BARE_DIR_NAME, 'bundle', 'create', outName, ...opts.revs], {
      ...(opts.signal !== undefined ? { signal: opts.signal } : {}),
      ...(opts.workspaceId !== undefined ? { workspaceId: opts.workspaceId } : {})
    });
    if (created.exitCode !== 0) {
      throw new HarnessError('UNAVAILABLE', `git bundle create failed: ${created.stderr || created.stdout}`.slice(0, 2_000), 502, true);
    }
    const hostPath = join(opDir, outName);
    const info = await lstat(hostPath).catch(() => undefined);
    if (!info?.isFile() || info.size === 0) {
      throw new HarnessError('UNAVAILABLE', 'git bundle create produced no bundle file', 502, true);
    }
    if (info.size > VM_MAX_BUNDLE_BYTES) {
      throw new HarnessError('LIMIT_EXCEEDED', 'git bundle exceeds the maximum transfer size', 413, false);
    }
    return { hostPath, sha256: await sha256File(hostPath), bytes: info.size };
  }

  /** Raw `git bundle list-heads` output for a bundle file inside the op dir. */
  async listHeads(opDir: string, bundleName: string, opts: { signal?: AbortSignal; workspaceId?: string } = {}): Promise<VmHelperResult> {
    if (!/^[A-Za-z0-9._-]+$/.test(bundleName)) {
      throw new HarnessError('INVALID_INPUT', 'bundle name is invalid', 400, false);
    }
    return this.git(opDir, ['bundle', 'list-heads', bundleName], {
      readOnly: true,
      ...(opts.signal !== undefined ? { signal: opts.signal } : {}),
      ...(opts.workspaceId !== undefined ? { workspaceId: opts.workspaceId } : {})
    });
  }

  /** `bundleHeadsToRefspecs` over a bundle inside the op dir; throws on uninspectable/empty bundles. */
  async bundleRefspecs(opDir: string, bundleName: string, opts: { signal?: AbortSignal; workspaceId?: string } = {}): Promise<string[]> {
    const heads = await this.listHeads(opDir, bundleName, opts);
    if (heads.exitCode !== 0 || heads.truncated) {
      throw new HarnessError('INVALID_INPUT', `git bundle could not be inspected: ${heads.stderr || heads.stdout}`.slice(0, 2_000), 400, false);
    }
    if (Buffer.byteLength(heads.stdout) > MAX_REF_LIST_BYTES) {
      throw new HarnessError('LIMIT_EXCEEDED', 'git bundle advertises too much ref metadata', 413, false);
    }
    const refspecs = bundleHeadsToRefspecs(heads.stdout);
    if (refspecs.length === 0) {
      throw new HarnessError('INVALID_INPUT', 'git bundle advertises no refs', 400, false);
    }
    return refspecs;
  }

  /**
   * `git clone --bare <bundle> bare.git` — materializes every bundle head as a
   * same-name ref plus HEAD, giving the push helper a normal bare repository.
   * Corrupt bundles fail here with INVALID_INPUT. When the op dir carries a
   * `shallow.txt` boundary sidecar (guest shallow checkout), GIT_SHALLOW_FILE
   * points git at it so the shallow bundle's truncated parents verify —
   * the same shallow state docker's `clone --bare` propagates natively.
   */
  async stagePushBare(opDir: string, bundleName: string, opts: { signal?: AbortSignal; workspaceId?: string } = {}): Promise<void> {
    if (!/^[A-Za-z0-9._-]+$/.test(bundleName)) {
      throw new HarnessError('INVALID_INPUT', 'bundle name is invalid', 400, false);
    }
    const env = await this.shallowBoundaryEnv(opDir);
    const staged = await this.git(opDir, ['clone', '--bare', bundleName, BARE_DIR_NAME], {
      ...(env !== undefined ? { env } : {}),
      ...(opts.signal !== undefined ? { signal: opts.signal } : {}),
      ...(opts.workspaceId !== undefined ? { workspaceId: opts.workspaceId } : {})
    });
    if (staged.exitCode !== 0) {
      throw new HarnessError('INVALID_INPUT', `git bundle could not be staged: ${staged.stderr || staged.stdout}`.slice(0, 2_000), 400, false);
    }
  }

  /** Credentialed push from `opDir/bare.git` via `git-transfer-helper.sh push` (lease CAS unchanged). */
  async pushBare(opDir: string, params: {
    repositoryUrl: string;
    refspec: string;
    expectedRemoteOid?: string;
    token?: string;
    timeoutMs?: number;
    signal?: AbortSignal;
    workspaceId?: string;
  }): Promise<VmHelperResult> {
    const refspec = params.refspec ?? '';
    // Delete refspecs legitimately start with ':' (`:refs/heads/x`); option
    // injection is a leading '-', and the schema allows at most one colon.
    if (
      refspec.length === 0 || refspec.length > 512 || refspec.startsWith('-')
      || /[\0\n\r]/.test(refspec) || refspec.split(':').length > 2
    ) {
      throw new HarnessError('INVALID_INPUT', 'git push refspec is invalid', 400, false);
    }
    const env = await this.shallowBoundaryEnv(opDir);
    return this.transfer(opDir, 'push', {
      repositoryUrl: params.repositoryUrl,
      argument: refspec,
      ...(params.expectedRemoteOid !== undefined ? { expectedRemoteOid: params.expectedRemoteOid } : {}),
      ...(params.token !== undefined ? { token: params.token } : {}),
      ...(env !== undefined ? { env } : {}),
      ...(params.timeoutMs !== undefined ? { timeoutMs: params.timeoutMs } : {}),
      ...(params.signal !== undefined ? { signal: params.signal } : {}),
      ...(params.workspaceId !== undefined ? { workspaceId: params.workspaceId } : {})
    });
  }
}

/**
 * Maps a non-zero transfer-helper result to the same HarnessError contract
 * `runGitTransferHelper` produces for the docker path — push gets the
 * remote-rejected/lease/network classification; fetch collapses to UNAVAILABLE.
 */
export function assertVmTransferOk(mode: 'fetch' | 'push', result: VmHelperResult, opts: { expectedRemoteOid?: string } = {}): void {
  if (result.exitCode === 0) return;
  const action = mode;
  const errText = mode === 'push' ? [result.stderr, result.stdout].filter(Boolean).join('\n') : result.stderr || result.stdout;
  if (mode === 'push') {
    if (/\[remote rejected\]|^remote: error: GH0\d\d:/m.test(errText)) {
      const missingWorkflowsPermission = /without [`'"]?workflows[`'"]? permission|create or update workflow/i.test(errText);
      throw new HarnessError(
        missingWorkflowsPermission ? 'GITHUB_PERMISSION_MISSING' : 'FORBIDDEN',
        (missingWorkflowsPermission
          ? `Git push rejected: the credential lacks the GitHub workflows permission needed to change .github/workflows (${errText})`
          : `Git push rejected by the remote's branch protection, ruleset, or hook (${errText})`).slice(0, 2_000),
        403,
        false,
        { expectedRemoteOid: opts.expectedRemoteOid }
      );
    }
    if (/src refspec .* does not match any/.test(errText)) {
      throw new HarnessError('INVALID_INPUT', `Git push source does not name a local branch, tag, or HEAD (${errText})`.slice(0, 2_000), 400, false);
    }
    if (/\[rejected\]|\(stale info\)|lease rejected:|non-fast-forward|fetch first/.test(errText)) {
      throw new HarnessError('CONFLICT', `Git push rejected: remote ref has diverged or force-with-lease failed (${errText})`.slice(0, 2_000), 409, false, {
        expectedRemoteOid: opts.expectedRemoteOid,
        resumeAction: 'reconcile_push'
      });
    }
    if (errText.includes('Connection timed out') || errText.includes('Connection reset') || errText.includes('timed out') || errText.includes('Could not resolve host')) {
      throw new HarnessError('UNKNOWN_REMOTE_STATE', `Git push was interrupted by network failure (${errText})`.slice(0, 2_000), 504, true, {
        expectedRemoteOid: opts.expectedRemoteOid,
        resumeAction: 'reconcile_push'
      });
    }
  }
  throw new HarnessError('UNAVAILABLE', `Git ${action} failed: ${errText}`.slice(0, 2_000), 502, true);
}

// ---------------------------------------------------------------------------
// Offline export: bounded tar write + hostile-entry-safe extraction + inspection
// ---------------------------------------------------------------------------

/**
 * Streams supervisor `vm.export` tar bytes to `destPath`, enforcing `maxBytes`
 * mid-flight. Any failure removes the partial file. Returns the digest the
 * caller compares against the supervisor trailer.
 */
export async function writeVmExportTar(source: Readable, destPath: string, maxBytes: number): Promise<{ sha256: string; bytes: number }> {
  if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0) {
    throw new HarnessError('INVALID_INPUT', 'export maxBytes must be a positive integer', 400, false);
  }
  await mkdir(dirname(destPath), { recursive: true });
  const hash = createHash('sha256');
  let bytes = 0;
  const out = createWriteStream(destPath);
  try {
    for await (const chunk of source) {
      const buf = chunk as Buffer;
      bytes += buf.length;
      if (bytes > maxBytes) {
        throw new HarnessError('LIMIT_EXCEEDED', 'VM export stream exceeds maxBytes', 413, false);
      }
      hash.update(buf);
      if (!out.write(buf)) await once(out, 'drain');
    }
    out.end();
    await finished(out);
  } catch (error) {
    out.destroy();
    await rm(destPath, { force: true }).catch(() => undefined);
    throw error;
  }
  return { sha256: hash.digest('hex'), bytes };
}

export interface VmTarExtractLimits {
  maxEntries: number;
  /** Total regular-file content bound; the tar file itself is already bounded. */
  maxBytes: number;
  /** Aggregate pax/longname metadata payload bytes. Default 16 MiB. */
  maxMetadataBytes?: number;
  /** Single metadata-entry payload bound (pax record, gnu longname). Default 1 MiB. */
  maxMetadataEntryBytes?: number;
  /** Pending link entries (symlinks/hardlinks) materialized after all files. Default 50_000. */
  maxLinks?: number;
}

export interface VmTarExtractOptions {
  /**
   * When set, every extracted entry is `lchown`ed to this uid:gid (never
   * follows links). EPERM/ENOSYS are ignored so unprivileged dev runners
   * still extract; other errors propagate.
   */
  owner?: { uid: number; gid: number };
}

const TAR_HEADER = 512;
const TAR_PAYLOAD_CHUNK = 4 * 1024 * 1024;
const DEFAULT_MAX_METADATA_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_METADATA_ENTRY_BYTES = 1024 * 1024;
const DEFAULT_MAX_LINKS = 50_000;

function tarOctal(field: Buffer): number {
  const text = field.toString('utf8').replace(/\0.*$/s, '').trim();
  if (text === '') return 0;
  // base-256 (binary) size encoding used by large-file tars
  if ((field[0] ?? 0) & 0x80) {
    let value = 0;
    for (let i = 1; i < field.length; i++) value = value * 256 + (field[i] ?? 0);
    return value;
  }
  const value = Number.parseInt(text, 8);
  return Number.isFinite(value) ? value : -1;
}

function tarCstr(field: Buffer): string {
  const idx = field.indexOf(0);
  return field.subarray(0, idx === -1 ? field.length : idx).toString('utf8');
}

/** Reject names that escape the extraction root (same rules as the supervisor's pushTree check). */
function tarPathSafe(name: string): boolean {
  if (name === '' || name.length > 4096 || name.includes('\0')) return false;
  if (name.startsWith('/') || name.startsWith('\\')) return false;
  return !name.split('/').includes('..');
}

/** PAX extended-header 'path'/'linkpath' overrides. */
function parsePaxOverrides(data: Buffer): { path?: string; linkpath?: string } {
  const out: { path?: string; linkpath?: string } = {};
  let offset = 0;
  while (offset < data.length) {
    const spaceIdx = data.indexOf(0x20, offset);
    if (spaceIdx === -1) break;
    const len = Number.parseInt(data.subarray(offset, spaceIdx).toString('utf8'), 10);
    if (!Number.isFinite(len) || len <= 0 || offset + len > data.length) break;
    const record = data.subarray(spaceIdx + 1, offset + len).toString('utf8');
    const eq = record.indexOf('=');
    if (eq !== -1) {
      const key = record.slice(0, eq);
      const value = record.slice(eq + 1).replace(/\n$/, '');
      if (key === 'path') out.path = value;
      else if (key === 'linkpath') out.linkpath = value;
    }
    offset += len;
  }
  return out;
}

/**
 * Exact-size reader over the tar stream. At most one stream chunk plus the
 * requested buffer is ever held, so a multi-GiB entry streams to disk with
 * bounded RSS instead of being buffered whole.
 */
class TarBlockReader {
  private readonly iterator: AsyncIterator<Buffer>;
  private pending: Buffer[] = [];
  private pendingLen = 0;
  private exhausted = false;

  constructor(stream: Readable) {
    this.iterator = stream[Symbol.asyncIterator]();
  }

  private async fill(): Promise<boolean> {
    while (this.pendingLen === 0 && !this.exhausted) {
      const next = await this.iterator.next();
      if (next.done === true) {
        this.exhausted = true;
        return false;
      }
      const chunk = next.value as Buffer;
      this.pending.push(chunk);
      this.pendingLen += chunk.length;
    }
    return this.pendingLen > 0;
  }

  private consume(amount: number): Buffer[] {
    const out: Buffer[] = [];
    let left = amount;
    while (left > 0 && this.pendingLen > 0) {
      const head = this.pending[0]!;
      const take = Math.min(left, head.length);
      out.push(take === head.length ? head : head.subarray(0, take));
      if (take === head.length) {
        this.pending.shift();
        this.pendingLen -= head.length;
      } else {
        this.pending[0] = head.subarray(take);
        this.pendingLen -= take;
      }
      left -= take;
    }
    return out;
  }

  /** Exactly `n` bytes; throws INVALID_INPUT on early EOF. */
  async read(n: number): Promise<Buffer> {
    const parts: Buffer[] = [];
    let got = 0;
    while (got < n) {
      if (!(await this.fill())) {
        throw new HarnessError('INVALID_INPUT', 'tar archive truncated mid-entry', 400, false);
      }
      const taken = this.consume(n - got);
      for (const part of taken) {
        parts.push(part);
        got += part.length;
      }
      if (taken.length === 0) {
        throw new HarnessError('INVALID_INPUT', 'tar archive truncated mid-entry', 400, false);
      }
    }
    return parts.length === 1 ? parts[0]! : Buffer.concat(parts);
  }

  /** Discards exactly `n` bytes; throws INVALID_INPUT on early EOF. */
  async discard(n: number): Promise<void> {
    let left = n;
    while (left > 0) {
      if (!(await this.fill())) {
        throw new HarnessError('INVALID_INPUT', 'tar archive truncated mid-entry', 400, false);
      }
      const head = this.pending[0]!;
      const amount = Math.min(left, head.length);
      if (amount === head.length) {
        this.pending.shift();
        this.pendingLen -= head.length;
      } else {
        this.pending[0] = head.subarray(amount);
        this.pendingLen -= amount;
      }
      left -= amount;
    }
  }
}

interface PendingMeta {
  longName: string | undefined;
  longLink: string | undefined;
  paxPath: string | undefined;
  paxLink: string | undefined;
}

interface PendingLink {
  /** Absolute extraction path the link is materialized at. */
  abs: string;
  type: '1' | '2';
  /**
   * '2': raw symlink target text (validated root-contained relative to the
   * link's directory). '1': absolute path of the already-extracted regular
   * file the hardlink aliases.
   */
  target: string;
}

/**
 * Symlink targets stay inside the extraction root: absolute paths, drive
 * roots, control characters, and `..` escapes are rejected. Resolution is
 * lexical against the link's own directory — sound because every ancestor
 * is a real directory we created (links materialize last, parents are
 * lstat-verified), so kernel resolution cannot detour through a link.
 */
function tarSymlinkTargetSafe(linkAbs: string, destRoot: string, target: string): boolean {
  if (target === '' || target.length > 4096 || [...target].some((ch) => ch < ' ')) return false;
  if (target.startsWith('/') || target.startsWith('\\\\')) return false;
  const resolved = resolve(dirname(linkAbs), target);
  return resolved === destRoot || resolved.startsWith(destRoot + sep);
}

/**
 * Extracts a supervisor `vm.export` tar into `destDir` with hostile-entry
 * rejection and bounded memory:
 *
 * - entry names: absolute paths, `..` traversal, NULs, overlong names rejected
 *   (pax path / gnu longname overrides included);
 * - types: regular files, directories, and contained symlinks/hardlinks only —
 *   devices, fifos, sparse, and every other typeflag rejected;
 * - links: validated root-contained, then materialized AFTER all regular
 *   entries so no write can ever pass through a link; hardlink targets must
 *   already exist as regular files; link parents are lstat-verified to be
 *   real directories (never links);
 * - bounds: entry count, total file bytes, per-entry stream (never buffered
 *   whole), aggregate + per-entry metadata bytes, pending-link count, and a
 *   required zero-block terminator;
 * - `destDir` must be empty on entry — a pre-existing symlink can never be
 *   written through;
 * - `opts.owner` lchowns every entry (files, dirs, links) to the helper uid.
 */
export async function extractTarSafe(
  tarPath: string,
  destDir: string,
  limits: VmTarExtractLimits,
  opts: VmTarExtractOptions = {}
): Promise<{ entries: number; bytes: number; links: number }> {
  const destRoot = resolve(destDir);
  await mkdir(destRoot, { recursive: true });
  // Extraction only ever targets a fresh directory: a pre-existing entry
  // (especially a symlink) must never be followed for writes.
  const preExisting = await readdir(destRoot);
  if (preExisting.length > 0) {
    throw new HarnessError('INVALID_INPUT', 'tar extraction destination is not empty', 400, false);
  }

  const maxMetadataBytes = limits.maxMetadataBytes ?? DEFAULT_MAX_METADATA_BYTES;
  const maxMetadataEntryBytes = limits.maxMetadataEntryBytes ?? DEFAULT_MAX_METADATA_ENTRY_BYTES;
  const maxLinks = limits.maxLinks ?? DEFAULT_MAX_LINKS;

  const stream = createReadStream(tarPath, { highWaterMark: TAR_PAYLOAD_CHUNK });
  const reader = new TarBlockReader(stream);
  const knownDirs = new Set<string>([destRoot]);
  const pendingLinks: PendingLink[] = [];
  let meta: PendingMeta = { longName: undefined, longLink: undefined, paxPath: undefined, paxLink: undefined };
  let entries = 0;
  let links = 0;
  let declaredBytes = 0;
  let metadataBytes = 0;
  let sawZeroBlock = false;

  const invalid = (message: string): never => {
    throw new HarnessError('INVALID_INPUT', message, 400, false);
  };
  const limit = (message: string): never => {
    throw new HarnessError('LIMIT_EXCEEDED', message, 413, false);
  };

  /** tar name → absolute path inside destRoot; throws on any escape. */
  const resolveEntry = (name: string): string => {
    let normalized = name;
    while (normalized.startsWith('./')) normalized = normalized.slice(2);
    if (!tarPathSafe(normalized)) invalid(`unsafe tar entry path '${name.slice(0, 120)}'`);
    const target = resolve(destRoot, normalized);
    if (target !== destRoot && !target.startsWith(destRoot + sep)) {
      invalid(`tar entry escapes extraction root '${name.slice(0, 120)}'`);
    }
    return target;
  };

  /** Creates every missing directory component as a REAL directory (lstat-verified). */
  const ensureDir = async (abs: string): Promise<void> => {
    const rel = relative(destRoot, abs);
    if (rel === '') return;
    let cur = destRoot;
    for (const part of rel.split(sep)) {
      cur = join(cur, part);
      if (knownDirs.has(cur)) continue;
      try {
        await mkdir(cur);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      }
      const info = await lstat(cur);
      if (!info.isDirectory()) invalid('tar path crosses a non-directory entry');
      knownDirs.add(cur);
      await applyOwner(cur);
    }
  };

  const applyOwner = async (path: string): Promise<void> => {
    if (opts.owner === undefined) return;
    try {
      await lchown(path, opts.owner.uid, opts.owner.gid);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== 'EPERM' && code !== 'ENOSYS' && code !== 'EOPNOTSUPP') throw error;
    }
  };

  /** Reads and bounds a metadata payload (pax record / gnu longname). */
  const readMetadata = async (size: number): Promise<Buffer> => {
    if (size > maxMetadataEntryBytes) limit('tar metadata entry exceeds maxMetadataEntryBytes');
    metadataBytes += size;
    if (metadataBytes > maxMetadataBytes) limit('tar metadata exceeds maxMetadataBytes');
    const data = await reader.read(size);
    await reader.discard(padding(size));
    return data;
  };

  const padding = (size: number): number => (TAR_HEADER - (size % TAR_HEADER)) % TAR_HEADER;

  const countEntry = (): void => {
    entries += 1;
    if (entries > limits.maxEntries) limit(`tar entry count exceeds ${limits.maxEntries}`);
  };

  const extractFile = async (target: string, size: number, mode: number): Promise<void> => {
    await ensureDir(dirname(target));
    const handle = await open(target, 'w', 0o600);
    try {
      let remaining = size;
      while (remaining > 0) {
        const chunk = await reader.read(Math.min(remaining, TAR_PAYLOAD_CHUNK));
        await handle.write(chunk);
        declaredBytes += chunk.length;
        if (declaredBytes > limits.maxBytes) limit('tar declared content exceeds maxBytes');
        remaining -= chunk.length;
      }
      const wanted = mode >= 0 && (mode & 0o111) !== 0 ? 0o755 : 0o644;
      await handle.chmod(wanted);
    } finally {
      await handle.close();
    }
    await applyOwner(target);
    await reader.discard(padding(size));
  };

  const stageLink = (abs: string, typeflag: string, size: number, linkname: string): void => {
    if (size !== 0) invalid('tar link entry carries unexpected payload');
    if (typeflag === '2') {
      if (!tarSymlinkTargetSafe(abs, destRoot, linkname)) {
        invalid(`tar symlink target escapes extraction root '${linkname.slice(0, 120)}'`);
      }
      pendingLinks.push({ abs, type: '2', target: linkname });
    } else {
      // Hardlink names are archive-root-relative, never relative to the link.
      let normalized = linkname;
      while (normalized.startsWith('./')) normalized = normalized.slice(2);
      if (!tarPathSafe(normalized)) invalid(`unsafe tar hardlink target '${linkname.slice(0, 120)}'`);
      const targetAbs = resolve(destRoot, normalized);
      if (targetAbs !== destRoot && !targetAbs.startsWith(destRoot + sep)) {
        invalid(`tar hardlink target escapes extraction root '${linkname.slice(0, 120)}'`);
      }
      pendingLinks.push({ abs, type: '1', target: targetAbs });
    }
    links += 1;
    if (links > maxLinks) limit(`tar link count exceeds ${maxLinks}`);
  };

  const consumeEntry = async (header: Buffer): Promise<void> => {
    const typeflag = String.fromCharCode(header[156] ?? 0);
    const prefix = tarCstr(header.subarray(345, 500));
    const rawName = tarCstr(header.subarray(0, 100));
    const headerName = prefix !== '' ? `${prefix}/${rawName}` : rawName;
    const name = meta.paxPath ?? meta.longName ?? headerName;
    const linkname = meta.paxLink ?? meta.longLink ?? tarCstr(header.subarray(157, 257));
    meta = { longName: undefined, longLink: undefined, paxPath: undefined, paxLink: undefined };
    const size = tarOctal(header.subarray(124, 136));
    if (size < 0) invalid('malformed tar size field');

    switch (typeflag) {
      case 'L': {
        const data = await readMetadata(size);
        meta.longName = tarCstr(data.subarray(0, data.indexOf(0) === -1 ? data.length : data.indexOf(0)));
        return;
      }
      case 'K': {
        const data = await readMetadata(size);
        meta.longLink = tarCstr(data.subarray(0, data.indexOf(0) === -1 ? data.length : data.indexOf(0)));
        return;
      }
      case 'x': {
        const pax = parsePaxOverrides(await readMetadata(size));
        if (pax.path !== undefined) meta.paxPath = pax.path;
        if (pax.linkpath !== undefined) meta.paxLink = pax.linkpath;
        return;
      }
      case 'g':
        await readMetadata(size);
        return;
      case '0':
      case '\0':
      case '7': {
        countEntry();
        const target = resolveEntry(name.endsWith('/') ? name.slice(0, -1) : name);
        if (target === destRoot) invalid('tar file entry targets the extraction root');
        const mode = tarOctal(header.subarray(100, 108));
        await extractFile(target, size, mode);
        return;
      }
      case '5': {
        if (size !== 0) invalid('tar directory entry carries unexpected payload');
        countEntry();
        const dirName = name.endsWith('/') ? name.slice(0, -1) : name;
        if (dirName === '') return; // archive root
        const target = resolveEntry(dirName);
        if (target === destRoot) return;
        await ensureDir(target);
        await applyOwner(target);
        return;
      }
      case '1':
      case '2': {
        countEntry();
        const abs = resolveEntry(name.endsWith('/') ? name.slice(0, -1) : name);
        if (abs === destRoot) invalid('tar link entry targets the extraction root');
        stageLink(abs, typeflag, size, linkname);
        return;
      }
      default:
        invalid(`tar entry type '${typeflag}' is not allowed`);
    }
  };

  try {
    for (;;) {
      const header = await reader.read(TAR_HEADER);
      if (header.every((byte) => byte === 0)) {
        sawZeroBlock = true;
        break;
      }
      await consumeEntry(header);
    }
  } finally {
    stream.destroy();
  }
  if (!sawZeroBlock) invalid('tar archive missing terminator blocks');

  // Links materialize last: regular files/dirs already exist, so no link can
  // ever redirect a write. Parents are lstat-verified real directories.
  for (const link of pendingLinks) {
    const rel = relative(destRoot, link.abs);
    let cur = destRoot;
    const parts = rel.split(sep);
    for (const part of parts.slice(0, -1)) {
      cur = join(cur, part);
      const info = await lstat(cur).catch(() => undefined);
      if (info === undefined) {
        await mkdir(cur, { recursive: true });
        const made = await lstat(cur);
        if (!made.isDirectory()) invalid('tar link path crosses a non-directory entry');
        knownDirs.add(cur);
      } else if (!info.isDirectory()) {
        invalid('tar link path crosses a symlink or non-directory entry');
      }
    }
    try {
      if (link.type === '2') {
        await symlink(link.target, link.abs);
      } else {
        const targetInfo = await lstat(link.target).catch(() => undefined);
        if (!targetInfo?.isFile()) invalid('tar hardlink target is not an extracted regular file');
        await fsLink(link.target, link.abs);
      }
    } catch (error) {
      if (error instanceof HarnessError) throw error;
      invalid(`tar link conflicts with an existing entry (${(error as NodeJS.ErrnoException).code ?? 'error'})`);
    }
    await applyOwner(link.abs);
  }

  return { entries, bytes: declaredBytes, links };
}

/**
 * All checkout-root candidates at the SHALLOWEST depth containing a `.git`
 * entry (directory or gitfile), sorted by path. Deeper `.git` directories
 * are decoys/sub-repos and never returned; same-depth siblings are all
 * returned so the caller can conservatively inspect each instead of
 * trusting an arbitrary pick.
 */
export async function findCheckoutRoots(dir: string, opts: { maxDepth?: number; maxEntries?: number } = {}): Promise<string[]> {
  const maxDepth = opts.maxDepth ?? 2;
  const maxEntries = opts.maxEntries ?? 50_000;
  let visited = 0;
  let frontier: string[] = [''];
  for (let depth = 0; depth <= maxDepth && frontier.length > 0; depth++) {
    const next: string[] = [];
    const found: string[] = [];
    for (const rel of frontier) {
      const abs = rel === '' ? dir : join(dir, rel);
      try {
        const info = await lstat(join(abs, '.git'));
        if (info.isDirectory() || info.isFile()) found.push(rel);
      } catch { /* no .git here */ }
      let children;
      try {
        children = await readdir(abs, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const child of children) {
        if (++visited > maxEntries) return found.length > 0 ? found.sort() : [];
        if (child.isDirectory() && child.name !== '.git' && !child.isSymbolicLink()) {
          next.push(rel === '' ? child.name : `${rel}/${child.name}`);
        }
      }
    }
    if (found.length > 0) return found.sort();
    frontier = next;
  }
  return [];
}

/** First shallowest checkout root, or undefined — kept for single-root callers. */
export async function findCheckoutRoot(dir: string, opts: { maxDepth?: number; maxEntries?: number } = {}): Promise<string | undefined> {
  const roots = await findCheckoutRoots(dir, opts);
  return roots[0];
}

// ---------------------------------------------------------------------------
// Untrusted .git/config sanitization (host-side, before any git inspection)
// ---------------------------------------------------------------------------

/**
 * Config sections that can execute code, redirect object stores, or pull in
 * further config when git reads a repository — always stripped from an
 * extracted (guest-controlled) checkout before host-side inspection.
 */
const GIT_CONFIG_DENIED_SECTIONS = new Set([
  'include', 'includeif', 'filter', 'diff', 'merge', 'protocol',
  'credential', 'http', 'url', 'gpg', 'instaweb', 'browser', 'mergetool',
  'difftool', 'interactive', 'sendemail', 'imap', 'svn', 'p4', 'uploadpack',
  'receive', 'uploadarchive', 'sequence', 'rebase', 'lfs', 'annex', 'gitcvs',
  'web--browse', 'man', 'help', 'interpret-trailers'
]);

/**
 * `extensions` is filtered per-key instead of denied wholesale: only
 * `objectformat` (validated sha1/sha256) is legitimate repo metadata needed
 * for sha256 checkouts to inspect at all. Every other extension —
 * partialclone/promisor (lazy network fetch), refstorage, worktreeconfig,
 * compatobjectformat — stays denied. Any non-plain extensions section
 * (`[extensions.foo]`, `[extensions "sub"]`) is denied entirely.
 */
const GIT_CONFIG_PLAIN_EXTENSIONS_SECTION = 'extensions';
const GIT_CONFIG_EXTENSIONS_ALLOWED_VALUE = /^\s*objectformat\s*=\s*(?:sha1|sha256)\s*(?:[#;].*)?$/i;
/** `bare = false` (and git's other false spellings/empty) is the init default — only truthy forms are denied. */
const GIT_CONFIG_BARE_FALSE_VALUE = /^\s*bare\s*=\s*(?:false|no|off|0)?\s*(?:[#;].*)?$/i;

/** Keys inside otherwise-allowed sections that can execute or redirect. */
const GIT_CONFIG_DENIED_KEYS = new Set([
  'core.fsmonitor', 'core.sshcommand', 'core.attributesfile', 'core.hookspath',
  'core.askpass', 'core.editor', 'core.pager', 'core.browser', 'core.sshvariant',
  // core.worktree/core.bare relocate or reclassify the worktree — a crafted
  // value makes `git status` inspect a decoy directory and report clean.
  'core.worktree', 'core.bare', 'core.gitdir',
  'commit.gpgsign', 'tag.gpgsign', 'push.gpgsign', 'merge.gpgsign',
  'gpg.program', 'gpg.ssh.program', 'gpg.openpgp.program', 'gpg.x509.program'
]);

const GIT_CONFIG_MAX_BYTES = 1024 * 1024;

function gitConfigSectionToken(line: string): string | undefined {
  const match = /^\s*\[\s*([^\s\]]+)/.exec(line);
  return match === null ? undefined : match[1]!.toLowerCase();
}

/** Full `[...]` inner text — distinguishes plain `[extensions]` from subsectioned forms. */
function gitConfigSectionInner(line: string): string | undefined {
  const match = /^\s*\[\s*([^\]\n]+?)\s*\]/.exec(line);
  return match === null ? undefined : match[1];
}

/**
 * Section classification for the sanitizer: 'denied' drops the whole section,
 * 'extensions' keeps only a validated `objectformat` key, 'allowed' keeps the
 * section with per-key deny checks. `undefined` means the line is not a
 * section header.
 */
function gitConfigSectionMode(line: string): 'denied' | 'extensions' | 'allowed' | undefined {
  const token = gitConfigSectionToken(line);
  if (token === undefined) return undefined;
  // Deprecated `[section.subsection]` spelling: the real section is the
  // first dot-segment, so check both spellings against the deny list.
  const firstSegment = token.split('.')[0]!;
  if (GIT_CONFIG_DENIED_SECTIONS.has(token) || GIT_CONFIG_DENIED_SECTIONS.has(firstSegment)) return 'denied';
  if (firstSegment === GIT_CONFIG_PLAIN_EXTENSIONS_SECTION) {
    const inner = (gitConfigSectionInner(line) ?? '').trim().toLowerCase();
    // Only the bare `[extensions]` header gets per-key filtering; any
    // subsectioned spelling is denied wholesale.
    return inner === GIT_CONFIG_PLAIN_EXTENSIONS_SECTION ? 'extensions' : 'denied';
  }
  return 'allowed';
}

/**
 * Key-name match for deny checks. Matches `key`, `key =`, `key = value`, and
 * the deprecated `key value` form — anything key-shaped followed by `=`,
 * whitespace, or end-of-line, so boolean/trailing forms cannot bypass the
 * denied-key list.
 */
function gitConfigKeyName(line: string): string | undefined {
  const match = /^\s*([A-Za-z][A-Za-z0-9]*)\s*(?==|\s|$)/.exec(line);
  return match === null ? undefined : match[1]!.toLowerCase();
}

/** A trailing unescaped backslash continues the value onto the next line. */
function gitConfigContinues(line: string): boolean {
  const trimmed = line.replace(/\s+$/, '');
  let backslashes = 0;
  for (let i = trimmed.length - 1; i >= 0 && trimmed[i] === '\\'; i--) backslashes += 1;
  return backslashes % 2 === 1;
}

/**
 * Rewrites an extracted checkout's `.git/config` (and `config.worktree`)
 * in place, dropping every denied section and denied key. Guest-controlled
 * config must never reach host git with `include.*`, `filter.*`,
 * `core.fsmonitor`, `core.sshCommand`, protocol allowances, extensions, or
 * credential/http/url/gpg machinery intact — those are the repository-
 * controlled execution and exfiltration surfaces. Anything unreadable,
 * oversized, or non-regular is refused so the caller degrades to `unknown`.
 */
export async function sanitizeGitConfig(checkoutDir: string): Promise<void> {
  const gitDir = join(checkoutDir, '.git');
  const dotGit = await lstat(gitDir).catch(() => undefined);
  if (dotGit === undefined || !dotGit.isDirectory()) return; // inspection reports unknown
  for (const name of ['config', 'config.worktree']) {
    const path = join(gitDir, name);
    const info = await lstat(path).catch(() => undefined);
    if (info === undefined) continue;
    if (!info.isFile() || info.size > GIT_CONFIG_MAX_BYTES) {
      throw new HarnessError('INVALID_INPUT', `checkout ${name} is not a bounded regular file`, 400, false);
    }
    const original = await readFile(path, 'utf8');
    const lines = original.split('\n');
    const out: string[] = [];
    let sectionName = '';
    let sectionMode: 'denied' | 'extensions' | 'allowed' | undefined;
    let skippingKey = false;
    let changed = false;
    for (const line of lines) {
      const mode = gitConfigSectionMode(line);
      if (mode !== undefined) {
        sectionMode = mode;
        skippingKey = false;
        if (mode === 'denied') {
          changed = true;
          continue; // drop the whole denied section header
        }
        sectionName = gitConfigSectionToken(line) ?? '';
        out.push(line);
        continue;
      }
      // Denied/extensions modes run until the next section header — every
      // line in between belongs to the section, continuation or not.
      if (sectionMode === 'denied') {
        changed = true;
        continue;
      }
      if (skippingKey) {
        changed = true;
        if (!gitConfigContinues(line)) skippingKey = false;
        continue;
      }
      if (sectionMode === 'extensions') {
        const key = gitConfigKeyName(line);
        if (key === undefined) {
          out.push(line); // comment/blank/continuation of a kept value
          continue;
        }
        if (key === 'objectformat' && GIT_CONFIG_EXTENSIONS_ALLOWED_VALUE.test(line)) {
          out.push(line);
          continue;
        }
        changed = true;
        skippingKey = gitConfigContinues(line);
        continue;
      }
      const key = gitConfigKeyName(line);
      if (key !== undefined) {
        const fullKey = `${sectionName}.${key}`;
        const bareFalse = fullKey === 'core.bare' && GIT_CONFIG_BARE_FALSE_VALUE.test(line);
        if (GIT_CONFIG_DENIED_KEYS.has(fullKey) && !bareFalse) {
          changed = true;
          skippingKey = gitConfigContinues(line);
          continue;
        }
      }
      out.push(line);
    }
    if (changed) await writeFile(path, out.join('\n'), { mode: 0o644 });
  }
}

const GIT_COMMONDIR_MAX_BYTES = 4096;
/** Object-store redirect files git follows silently during inspection. */
const GIT_OBJECT_REDIRECT_NAMES = ['alternates', 'http-alternates'] as const;

/**
 * Neutralizes object-store redirects in an extracted checkout before any
 * host git invocation. `.git/objects/info/alternates` (and
 * `http-alternates`) let object lookup escape the extraction root — an
 * existence/content oracle and a way to make an incomplete checkout look
 * inspectable through a host object store. `commondir` files (`.git/` and
 * every `.git/worktrees/<id>/`) relocate the object store for linked
 * worktrees and must resolve inside the checkout. Redirect entries are
 * unlinked — the runner owns the extracted copy — and anything unsafe
 * throws so the caller reports `unknown` (retain) rather than inspecting
 * mixed guest/host state.
 */
export async function neutralizeGitObjectRedirects(checkoutDir: string): Promise<void> {
  const invalid = (message: string): never => {
    throw new HarnessError('INVALID_INPUT', message, 400, false);
  };
  const gitDir = join(checkoutDir, '.git');
  const dotGit = await lstat(gitDir).catch(() => undefined);
  if (dotGit === undefined || !dotGit.isDirectory()) return; // inspection reports unknown
  // Containment must hold after symlink resolution — a contained symlink can
  // point outside the export, so every pointer target is realpath-checked
  // against the realpath'd checkout root.
  const rootReal = await realpath(checkoutDir).catch(() => resolve(checkoutDir));
  const gitDirs = new Set<string>([gitDir]);

  const readPointer = async (path: string, what: string): Promise<string | undefined> => {
    const info = await lstat(path).catch(() => undefined);
    if (info === undefined) return undefined;
    if (!info.isFile() || info.size === 0 || info.size > GIT_COMMONDIR_MAX_BYTES) {
      invalid(`${what} is not a bounded regular file`);
    }
    const raw = (await readFile(path, 'utf8')).trim();
    if (raw === '' || /[\0\r\n]/.test(raw)) invalid(`${what} is malformed`);
    return raw;
  };
  const resolveContained = async (baseDir: string, raw: string, what: string): Promise<string> => {
    const resolved = resolve(isAbsolute(raw) ? raw : join(baseDir, raw));
    const real = await realpath(resolved).catch(() => undefined);
    if (real === undefined) return invalid(`${what} target does not resolve`);
    const rel = relative(rootReal, real);
    if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) return invalid(`${what} escapes the export root`);
    return real;
  };

  // `.git/commondir` relocates the whole object store — a planted file turns
  // every git invocation into a read of an outside directory.
  const mainCommon = await readPointer(join(gitDir, 'commondir'), 'checkout commondir');
  if (mainCommon !== undefined) {
    gitDirs.add(await resolveContained(gitDir, mainCommon, 'checkout commondir'));
  }

  // Linked worktrees: each `.git/worktrees/<id>/commondir` relocates that
  // worktree's object store the same way. `<id>` must be a real directory —
  // a symlink would move the scan itself outside the export.
  const worktreesDir = join(gitDir, 'worktrees');
  const worktreesInfo = await lstat(worktreesDir).catch(() => undefined);
  if (worktreesInfo !== undefined) {
    if (!worktreesInfo.isDirectory()) invalid('checkout worktrees dir is not a real directory');
    for (const id of await readdir(worktreesDir)) {
      const wtGitdir = join(worktreesDir, id);
      const wtInfo = await lstat(wtGitdir).catch(() => undefined);
      if (wtInfo === undefined) continue;
      if (!wtInfo.isDirectory()) invalid(`checkout worktree entry ${id} is not a real directory`);
      gitDirs.add(wtGitdir);
      const common = await readPointer(join(wtGitdir, 'commondir'), `worktree ${id} commondir`);
      if (common !== undefined) {
        gitDirs.add(await resolveContained(wtGitdir, common, `worktree ${id} commondir`));
      }
    }
  }

  for (const dir of gitDirs) {
    const objectsDir = join(dir, 'objects');
    const objectsInfo = await lstat(objectsDir).catch(() => undefined);
    if (objectsInfo === undefined) continue; // no object store — git fails closed
    if (!objectsInfo.isDirectory()) invalid('checkout objects dir is not a real directory');
    const infoDir = join(objectsDir, 'info');
    const infoInfo = await lstat(infoDir).catch(() => undefined);
    if (infoInfo === undefined) continue;
    if (!infoInfo.isDirectory()) invalid('checkout objects/info is not a real directory');
    for (const name of GIT_OBJECT_REDIRECT_NAMES) {
      const target = join(infoDir, name);
      const info = await lstat(target).catch(() => undefined);
      if (info === undefined) continue;
      try {
        // rm removes the directory entry itself — a symlink is unlinked, never followed.
        await rm(target, { force: true });
      } catch {
        invalid(`checkout objects/info/${name} could not be removed`);
      }
    }
  }
}

export interface VmCheckoutInspection {
  verdict: 'clean' | 'retain' | 'unknown';
  uncommittedPaths?: number;
  stashes?: number;
  unpushedCommits?: number;
  reason?: string;
}

const countLines = (output: string): number => output.split('\n').filter((line) => line.trim()).length;

/**
 * Offline close-check parity with the worker's `close_check` mode, run against
 * an extracted (untrusted) checkout copy through credential-free git helpers.
 * The checkout dir is mounted at `containerPath` (default `/workspace`, the
 * guest spelling) so worktree pointer files resolve natively. ANY git failure
 * or uninspectable state returns `unknown` — callers must defer auto-close and
 * never delete on unknown.
 */
export async function inspectVmCheckout(
  staging: VmGitStaging,
  checkoutDir: string,
  opts: { containerPath?: string; cloneRef?: string; signal?: AbortSignal; workspaceId?: string } = {}
): Promise<VmCheckoutInspection> {
  const containerPath = opts.containerPath ?? '/workspace';
  const git = (args: string[]) => staging.git(checkoutDir, args, {
    containerPath,
    readOnly: true,
    ...(opts.signal !== undefined ? { signal: opts.signal } : {}),
    ...(opts.workspaceId !== undefined ? { workspaceId: opts.workspaceId } : {})
  });
  const unknown = (reason: string): VmCheckoutInspection => ({ verdict: 'unknown', reason });

  // Strip guest-controlled execution surfaces and object-store redirects
  // from .git before any git invocation — include/filter/fsmonitor/
  // sshCommand/protocol/extensions/credential/http/url/gpg machinery and
  // objects/info/alternates must never reach host git intact. Uninspectable
  // state → unknown.
  try {
    await sanitizeGitConfig(checkoutDir);
    await neutralizeGitObjectRedirects(checkoutDir);
  } catch {
    return unknown('checkout git metadata could not be sanitized');
  }

  // .git must be a real directory — lstat so a symlink/gitfile pointing
  // outside the export is never followed into host git execution.
  const dotGit = await lstat(join(checkoutDir, '.git')).catch(() => undefined);
  if (!dotGit?.isDirectory()) return unknown('checkout .git is not a directory');

  // worktree list --porcelain -z (NUL-separated records)
  const worktreeRes = await git(['worktree', 'list', '--porcelain', '-z']);
  if (worktreeRes.exitCode !== 0 || worktreeRes.truncated) return unknown('git worktree list failed');
  const worktreeBlocks = worktreeRes.stdout.split('\0\0').filter(Boolean);
  const mainPath = worktreeBlocks[0]?.split('\0').find((line) => line.startsWith('worktree '))?.slice('worktree '.length);
  if (!mainPath || !isAbsolute(mainPath)) return unknown('git worktree list returned no usable main worktree');
  const linkedWorktrees = worktreeBlocks.slice(1).map((block) => {
    const lines = block.split('\0');
    const path = lines.find((line) => line.startsWith('worktree '))?.slice('worktree '.length);
    const head = lines.find((line) => line.startsWith('HEAD '))?.slice('HEAD '.length);
    return { path, head, prunable: lines.some((line) => line === 'prunable' || line.startsWith('prunable ')) };
  }).filter((worktree) => worktree.path);

  const statusArgs = ['--no-optional-locks', 'status', '--porcelain', '--untracked-files=all', '--ignore-submodules=none'];
  const worktreeExclusions = linkedWorktrees
    .filter((worktree) => !worktree.prunable)
    .map((worktree) => relative(mainPath, worktree.path!))
    .filter((path) => path !== '' && !path.startsWith('..') && !isAbsolute(path))
    .map((path) => `:(exclude,literal)${path}`);

  const statusRes = await git([...statusArgs, '--', '.', ...worktreeExclusions]);
  if (statusRes.exitCode !== 0 || statusRes.truncated) return unknown('git status failed');
  // Linked-worktree paths come from guest-controlled gitdir files — `git -C`
  // must never leave the exported checkout root. Anything escaping (or not
  // absolute) is unsafe → unknown → retain.
  const mainRoot = resolve(mainPath);
  // Git reports worktree paths in the HELPER's spelling (container path under
  // docker, host mountDir under a local runner) — but relative(mainPath, wt)
  // is spelling-independent, so the host path is always checkoutDir + rel.
  const worktreeGitRoot = join(checkoutDir, '.git', 'worktrees');
  const worktreeGitRootReal = await realpath(worktreeGitRoot).catch(() => undefined);
  const worktreeStatuses: string[] = [];
  for (const worktree of linkedWorktrees.filter((candidate) => !candidate.prunable)) {
    const wtPath = worktree.path!;
    if (!isAbsolute(wtPath)) return unknown('linked worktree path is not absolute');
    const rel = relative(mainRoot, resolve(wtPath));
    if (rel === '' || rel.startsWith('..') || isAbsolute(rel)) {
      return unknown('linked worktree escapes the checkout root');
    }
    // `git -C <wt>` follows the worktree's `.git` gitfile to a gitdir whose
    // commondir picks the object store — every hop is guest-controlled. The
    // gitfile must be a real bounded file whose gitdir stays a single entry
    // under `<main>/.git/worktrees/` — checked in the helper's path spelling
    // (where the pointer is meaningful) AND after host realpath resolution
    // (where symlinks could still relocate it). neutralizeGitObjectRedirects
    // already scanned every `.git/worktrees/<id>/commondir` for escapes.
    const hostWt = join(checkoutDir, rel);
    const gitfilePath = join(hostWt, '.git');
    const gitfileInfo = await lstat(gitfilePath).catch(() => undefined);
    if (gitfileInfo === undefined || !gitfileInfo.isFile() || gitfileInfo.size === 0 || gitfileInfo.size > GIT_COMMONDIR_MAX_BYTES) {
      return unknown('linked worktree .git is not a bounded gitfile');
    }
    const gitfileContent = (await readFile(gitfilePath, 'utf8')).trim();
    const gitdirRaw = gitfileContent.startsWith('gitdir:') ? gitfileContent.slice('gitdir:'.length).trim() : '';
    if (gitdirRaw === '' || /[\0\r\n]/.test(gitdirRaw)) return unknown('linked worktree gitfile is malformed');
    const helperGitRoot = join(mainRoot, '.git', 'worktrees');
    const helperGitdir = resolve(isAbsolute(gitdirRaw) ? gitdirRaw : join(wtPath, gitdirRaw));
    const helperRel = relative(helperGitRoot, helperGitdir);
    if (helperRel === '' || helperRel.startsWith('..') || isAbsolute(helperRel) || helperRel.includes('/') || helperRel.includes('\\')) {
      return unknown('linked worktree gitdir escapes .git/worktrees');
    }
    const hostGitdir = join(worktreeGitRoot, helperRel);
    const gitdirReal = await realpath(hostGitdir).catch(() => undefined);
    if (worktreeGitRootReal === undefined || gitdirReal === undefined) {
      return unknown('linked worktree gitdir is not resolvable inside the checkout');
    }
    const gitRel = relative(worktreeGitRootReal, gitdirReal);
    if (gitRel.startsWith('..') || isAbsolute(gitRel)) {
      return unknown('linked worktree gitdir escapes .git/worktrees');
    }
    const result = await git(['-C', resolve(wtPath), ...statusArgs]);
    if (result.exitCode !== 0 || result.truncated) return unknown('git status failed in a linked worktree');
    worktreeStatuses.push(result.stdout);
  }
  const stashRes = await git(['--no-optional-locks', 'stash', 'list']);
  if (stashRes.exitCode !== 0 || stashRes.truncated) return unknown('git stash list failed');

  const tips = ['--branches'];
  const headRes = await git(['rev-parse', '--verify', '--quiet', 'HEAD^{commit}']);
  if (headRes.exitCode === 0) tips.push('HEAD');
  for (const worktree of linkedWorktrees) {
    if (/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(worktree.head ?? '') && !/^0+$/.test(worktree.head!)) tips.push(worktree.head!);
  }
  const exclusions = ['--remotes'];
  const cloneRef = typeof opts.cloneRef === 'string' ? opts.cloneRef : '';
  if (/^[A-Za-z0-9._/-]{1,255}$/.test(cloneRef) && !cloneRef.includes('..') && !cloneRef.startsWith('-')) {
    const candidates = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(cloneRef) ? [cloneRef] : [`refs/tags/${cloneRef}`];
    for (const candidate of candidates) {
      const baseRes = await git(['rev-parse', '--verify', '--quiet', `${candidate}^{commit}`]);
      if (baseRes.exitCode === 0 && /^[0-9a-f]{40,64}$/.test(baseRes.stdout.trim())) exclusions.push(baseRes.stdout.trim());
    }
  }
  const unpushedRes = await git(['rev-list', '--count', ...tips, '--not', ...exclusions]);
  if (unpushedRes.exitCode !== 0) return unknown('git rev-list failed');
  const unpushedCommits = Number(unpushedRes.stdout.trim());
  if (!Number.isSafeInteger(unpushedCommits) || unpushedCommits < 0) return unknown('git rev-list returned an unexpected count');

  const uncommittedPaths = [statusRes.stdout, ...worktreeStatuses].reduce((total, output) => total + countLines(output), 0);
  const stashes = countLines(stashRes.stdout);
  const verdict = uncommittedPaths === 0 && stashes === 0 && unpushedCommits === 0 ? 'clean' : 'retain';
  return { verdict, uncommittedPaths, stashes, unpushedCommits };
}
