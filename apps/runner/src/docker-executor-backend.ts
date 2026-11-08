import { createHash, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { chmod, chown, lchown, lstat, mkdir, open, readdir, readlink, realpath, rm, stat, symlink, writeFile, type FileHandle } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { EventEmitter } from 'node:events';
import { Readable, Writable } from 'node:stream';
import {
  BACKEND_CAPABILITY_IDS,
  HarnessError,
  validateSecretNameShape,
  type ExecutorNetworkProfile,
  type RunnerConfig
} from '@cloud-harness/contracts';
import {
  inspectContainer,
  removeContainer,
  runDocker,
  spawnDocker,
  terminateContainerProcessGroup
} from './docker-engine.js';
import { DockerPtyClient, type PtyConnection, type PtyExecState, type PtyTransport } from './docker-pty.js';
import { EXECUTOR_HARDENING_ARGS, managedPathEnvArgs, withManagedBins } from './toolbox-runner.js';
import { validatedWorkspaceEnvironment } from './workspace-environment.js';
import { readVerifiedWorkspaceFile } from './bounded-workspace-file-reader.js';
import type { PackageProfile } from './package-service.js';
import type {
  BackendCapabilityMap,
  ExecRequest,
  ExecResult,
  ExecutorBackend,
  ExecutorInspection,
  ExecutorRef,
  ProvisionContext,
  StreamHandle,
  StreamRequest
} from './executor-backend.js';

/**
 * The executor PATH before managed package `bin` directories are inserted.
 * Keep in sync with `EXECUTOR_PATH` in workspace-service.ts until phase-03
 * routes executor creation through this adapter and the service copy dies.
 */
const EXECUTOR_PATH = '/workspace/node_modules/.bin:/opt/user-tools/bin:/opt/user-tools/pnpm/bin:/opt/user-tools/pnpm:/opt/user-tools/bun/bin:/tmp/cloud-harness-home/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';

/**
 * Operator-provided skills mounted read-only at the worker's `built-in` tier.
 * Keep in sync with `builtinSkillsMountArgs` in workspace-service.ts.
 */
function builtinSkillsMountArgs(builtinSkillsRoot: string | undefined): string[] {
  if (!builtinSkillsRoot) return [];
  return ['--volume', `${builtinSkillsRoot}:/opt/cloud-harness/skills:ro`];
}

const WORKSPACE_UID = '10001:10001';
/**
 * Open flags that refuse a symlinked FINAL component (ELOOP). Intermediate
 * components are covered by the mount-ancestry check plus per-entry lstat;
 * the guest can still race a swap, so every file open/write below carries
 * O_NOFOLLOW as the atomic last line — a swapped link fails loudly instead
 * of redirecting the read or write outside the mount.
 */
const READ_NOFOLLOW_FLAGS = constants.O_RDONLY | constants.O_NOFOLLOW;
const WRITE_NOFOLLOW_FLAGS = constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC | constants.O_NOFOLLOW;
/**
 * Directory opens for the tree verbs. O_NOFOLLOW rejects a symlinked FINAL
 * component atomically (ELOOP) and O_DIRECTORY rejects non-directories
 * (ENOTDIR); combined with /proc/self/fd-relative child addressing, an
 * intermediate directory swapped for a symlink mid-copy cannot redirect
 * reads, writes, chmods, or chowns outside the mount — the open fd pins the
 * inode the path check verified.
 */
const DIR_NOFOLLOW_FLAGS = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;
/** Same without O_NOFOLLOW for trusted runner-owned roots (staging dirs). */
const DIR_OPEN_FLAGS = constants.O_RDONLY | constants.O_DIRECTORY;
const PROC_SELF_FD = '/proc/self/fd';
/** `/proc/self/fd/<fd>` — path of the directory an open fd pins. */
function fdDirPath(dir: FileHandle): string {
  return `${PROC_SELF_FD}/${dir.fd}`;
}
/** `/proc/self/fd/<fd>/<name>` — child entry resolved under the pinned dir. */
function fdChildPath(dir: FileHandle, name: string): string {
  return `${fdDirPath(dir)}/${name}`;
}
const ENV_FILE_MAX_ENTRIES = 512;
const ENV_FILE_MAX_TOTAL_BYTES = 4 * 1_048_576;
const ENV_VALUE_MAX_BYTES = 65_536;
/**
 * Failsafe lifetime for a spawned stream's env file. The docker CLI reads
 * `--env-file` during flag parsing — milliseconds after spawn — so a file
 * still present after this bound belongs to a hung CLI, not a live session.
 */
const STREAM_ENV_FILE_MAX_AGE_MS = 10 * 60_000;

export type DockerExecutorBackendDeps = {
  config: RunnerConfig;
  instanceId: string;
  network: {
    ensureProfileReady(profile: ExecutorNetworkProfile): Promise<void>;
    dockerLaunchArgs(profile: ExecutorNetworkProfile): string[];
  };
  packages: {
    profileFor(ownerId: string, workspaceId: string): Pick<PackageProfile, 'mounts' | 'binDirs'>;
  };
  /** Optional PTY transport override (tests); defaults to a lazily created DockerPtyClient. */
  ptyTransport?: PtyTransport;
};

type MountEntry = { guest: string; host: string; writable: boolean };

type TreeManifestEntry = {
  type: 'd' | 'f' | 'l';
  mode: string;
  size: number;
  path: string;
  sha256?: string;
  target?: string;
};

function isInside(root: string, candidate: string): boolean {
  return candidate === root || candidate.startsWith(`${root}${sep}`);
}

function envStdin(stdin: string | Buffer): string {
  return typeof stdin === 'string' ? stdin : stdin.toString('utf8');
}

/**
 * Validates an operation-scoped exec environment override map. Keys use the
 * secret-name SHAPE only — reserved control-plane names like `CH_COMMAND` are
 * legitimate per-exec overrides — while values reject the characters that
 * would let one env-file line escape into another.
 */
function validatedExecEnvironment(environment: Record<string, string>): Array<[string, string]> {
  const entries = Object.entries(environment);
  if (entries.length > ENV_FILE_MAX_ENTRIES) {
    throw new HarnessError('INVALID_INPUT', 'exec environment has too many entries', 400, false);
  }
  const validated: Array<[string, string]> = [];
  let totalBytes = 0;
  for (const [rawName, value] of entries) {
    const name = validateSecretNameShape(rawName);
    if (!name.ok) {
      throw new HarnessError('INVALID_INPUT', `exec environment variable ${rawName} is invalid: ${name.error}`, 400, false);
    }
    if (typeof value !== 'string' || value.includes('\0') || value.includes('\n') || value.includes('\r')) {
      throw new HarnessError('INVALID_INPUT', `exec environment variable ${name.name} value is invalid`, 400, false);
    }
    const valueBytes = Buffer.byteLength(value, 'utf8');
    if (valueBytes > ENV_VALUE_MAX_BYTES) {
      throw new HarnessError('INVALID_INPUT', `exec environment variable ${name.name} value is invalid`, 400, false);
    }
    totalBytes += name.name.length + valueBytes + 2;
    if (totalBytes > ENV_FILE_MAX_TOTAL_BYTES) {
      throw new HarnessError('INVALID_INPUT', 'exec environment is too large', 400, false);
    }
    validated.push([name.name, value]);
  }
  return validated;
}

/** Serializes an env map as a docker `--env-file` body (`KEY=VALUE` lines). */
export function envFileContent(environment: Record<string, string>): string {
  return validatedExecEnvironment(environment).map(([key, value]) => `${key}=${value}`).join('\n') + '\n';
}

/**
 * Adapts a hijacked Engine-API PTY connection to the `StreamHandle` contract so
 * `spawnStream({pty})` and `backend.pty(ctx)` share one transport. The PTY
 * merges stderr into stdout, so `stderr` is an inert stream; `kill` detaches
 * and then ends the terminal's recorded session best-effort.
 */
class PtyStreamHandle extends EventEmitter implements StreamHandle {
  readonly stdin: Writable;
  readonly stdout: Readable;
  readonly stderr: Readable;
  private closed = false;

  constructor(
    private readonly connection: PtyConnection,
    private readonly transport: PtyTransport,
    private readonly endSession: () => Promise<void>
  ) {
    super();
    this.stdin = new Writable({
      write: (chunk: Buffer, _encoding, callback) => {
        try {
          this.connection.write(chunk);
          callback();
        } catch (error) {
          callback(error instanceof Error ? error : new Error(String(error)));
        }
      }
    });
    this.stdout = new Readable({ read: () => undefined });
    this.stderr = new Readable({ read: () => undefined });
    this.connection.onData((chunk) => this.stdout.push(chunk));
    this.connection.onEnd((end) => {
      this.stdout.push(null);
      this.stderr.push(null);
      void this.finish(end.error ?? null);
    });
  }

  kill(): boolean {
    if (this.closed) return false;
    try { this.connection.close(); } catch { /* already closed */ }
    void this.endSession().catch(() => undefined);
    return true;
  }

  /**
   * The hijacked exec stream carries no exit status, so the real code comes
   * from `inspect` after the stream ends. The exec can still report running
   * for a beat (and killSession may still be terminating it), so poll briefly
   * rather than emit a fabricated failure. An inspect failure is surfaced as
   * an error event, never a silent exit 1.
   */
  private async finish(error: Error | null): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    if (error) {
      this.emit('error', error);
      this.emit('close', null, null);
      return;
    }
    try {
      const state = await this.inspectExit();
      this.emit('close', state.exitCode, null);
    } catch (inspectError) {
      this.emit('error', inspectError instanceof Error ? inspectError : new Error(String(inspectError)));
      this.emit('close', null, null);
    }
  }

  private async inspectExit(): Promise<PtyExecState> {
    const deadline = Date.now() + 5_000;
    for (;;) {
      const state = await this.transport.inspect(this.connection.execId);
      if (!state.running || state.exitCode !== null || Date.now() >= deadline) return state;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
}

/**
 * The docker executor backend: every verb delegates to the same
 * `docker-engine`/`docker-pty`/`toolbox-runner` primitives
 * `workspace-service.ts` calls today, relocated without behavior change.
 * Environment overrides travel via mode-0600 env files — never argv — so
 * provision-baked secrets stay baked and per-exec values stay off the command
 * line.
 */
export class DockerExecutorBackend implements ExecutorBackend {
  readonly kind = 'docker' as const;
  private ptyClient: PtyTransport | undefined;

  constructor(private readonly deps: DockerExecutorBackendDeps) {}

  private get config(): RunnerConfig {
    return this.deps.config;
  }

  private ref(record: ProvisionContext['record'], executorId: string): ExecutorRef {
    return { backend: 'docker', workspaceId: record.id, executorId, generation: record.generation };
  }

  private containerName(ctx: ProvisionContext): string {
    if (!ctx.record.containerName) {
      throw new HarnessError('UNAVAILABLE', 'workspace executor is unavailable', 503, true);
    }
    return ctx.record.containerName;
  }

  /* ------------------------------------------------------------------ */
  /* Lifecycle                                                           */
  /* ------------------------------------------------------------------ */

  private async provisionMountDirectories(record: ProvisionContext['record'], signal?: AbortSignal): Promise<{ toolsPath: string; cachePath: string; ownerSkillsPath: string }> {
    const jobPath = record.workspacePath;
    const toolsPath = join(jobPath, 'tools');
    const cachePath = join(jobPath, 'cache');
    const ownerSkillsPath = join(jobPath, 'toolkit-projection', 'owner-skills');
    await mkdir(toolsPath, { recursive: true, mode: 0o755 });
    await mkdir(cachePath, { recursive: true, mode: 0o755 });
    await mkdir(ownerSkillsPath, { recursive: true, mode: 0o755 });
    try {
      await chown(toolsPath, 10001, 10001);
      await chown(cachePath, 10001, 10001);
      await chown(ownerSkillsPath, 10001, 10001);
      await chmod(toolsPath, 0o755);
      await chmod(cachePath, 0o755);
      await chmod(ownerSkillsPath, 0o755);
    } catch {
      const helperName = `chm-chown-${record.id.slice(3, 15)}-${randomBytes(4).toString('hex')}`;
      try {
        const result = await runDocker([
          'run', '--rm', '--pull', 'never', '--name', helperName,
          '--label', 'cloud-harness.role=chown-helper', '--label', 'cloud-harness.ephemeral=true',
          '--label', `cloud-harness.instance=${this.deps.instanceId}`, '--label', `cloud-harness.workspace=${record.id}`,
          '--network', 'none', '--user', '0:0',
          '--volume', `${jobPath}:/job`,
          '--entrypoint', '/bin/sh', this.config.executorImage,
          '-c', 'mkdir -p /job/tools /job/cache /job/toolkit-projection/owner-skills && chown -R 10001:10001 /job/tools /job/cache /job/toolkit-projection/owner-skills && chmod -R 0755 /job/tools /job/cache /job/toolkit-projection/owner-skills'
        ], { timeoutMs: 30_000, maxBytes: 8_192, ...(signal ? { signal } : {}) });
        if (result.exitCode !== 0) {
          throw new HarnessError('UNAVAILABLE', `mount directory provisioning failed: ${result.stderr || result.stdout}`.slice(0, 2_000), 502, true);
        }
      } finally {
        await removeContainer(helperName);
      }
    }
    return { toolsPath, cachePath, ownerSkillsPath };
  }

  async provision(ctx: ProvisionContext): Promise<ExecutorRef> {
    const record = ctx.record;
    const name = `cloud-harness-ws-${record.id.slice(3, 19).toLowerCase()}`;
    await removeContainer(name).catch(() => undefined);
    const { toolsPath, cachePath, ownerSkillsPath } = await this.provisionMountDirectories(record, ctx.signal);
    // Recorded as the workspace's profile; later binding changes apply only when the executor is recreated.
    const packageProfile = this.config.packagesEnabled === true
      ? this.deps.packages.profileFor(record.ownerId, record.id)
      : { mounts: [], binDirs: [] };
    const environment = validatedWorkspaceEnvironment(ctx.environment);
    const envEntries = Object.entries(environment);
    const envFilePath = join(record.workspacePath, `.env.injected-${randomBytes(6).toString('hex')}`);
    let useEnvFile = false;
    if (envEntries.length > 0) {
      const content = envEntries.map(([k, v]) => `${k}=${v}`).join('\n') + '\n';
      await writeFile(envFilePath, content, { mode: 0o600, encoding: 'utf8' });
      useEnvFile = true;
    }
    try {
      await this.deps.network.ensureProfileReady(ctx.networkProfile);
      const networkArgs = this.deps.network.dockerLaunchArgs(ctx.networkProfile);
      const repositoryPath = join(record.workspacePath, 'repo');
      const args = [
        'create', '--name', name,
        '--label', 'cloud-harness.managed=true', '--label', `cloud-harness.instance=${this.deps.instanceId}`,
        '--label', `cloud-harness.workspace=${record.id}`,
        ...EXECUTOR_HARDENING_ARGS, '--workdir', '/workspace',
        ...networkArgs,
        '--volume', `${repositoryPath}:/workspace:rw`,
        '--volume', `${toolsPath}:/opt/user-tools:rw`,
        '--volume', `${cachePath}:/var/cache/harness:rw`,
        '--volume', `${ownerSkillsPath}:/opt/cloud-harness/owner-skills:ro`,
        ...builtinSkillsMountArgs(this.config.builtinSkillsRoot),
        ...packageProfile.mounts.flatMap((mount) => ['--volume', `${mount.source}:${mount.target}:ro`]),
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
        '--env', `PATH=${withManagedBins(EXECUTOR_PATH, packageProfile.binDirs)}`,
        ...managedPathEnvArgs(packageProfile.binDirs),
        ...(useEnvFile ? ['--env-file', envFilePath] : []),
        this.config.executorImage
      ];
      const created = await runDocker(args, { timeoutMs: 30_000, ...(ctx.signal ? { signal: ctx.signal } : {}) });
      if (created.exitCode !== 0) throw new HarnessError('UNAVAILABLE', `executor creation failed: ${created.stderr}`.slice(0, 2_000), 502, true);
      const started = await runDocker(['start', name], { timeoutMs: 30_000, ...(ctx.signal ? { signal: ctx.signal } : {}) });
      if (started.exitCode !== 0) {
        await removeContainer(name);
        throw new HarnessError('UNAVAILABLE', `executor start failed: ${started.stderr}`.slice(0, 2_000), 502, true);
      }
      return this.ref(record, name);
    } finally {
      if (useEnvFile) {
        await rm(envFilePath, { force: true }).catch(() => undefined);
      }
    }
  }

  async ensureActive(ctx: ProvisionContext): Promise<ExecutorRef> {
    const record = ctx.record;
    // Dependency-access requires a fresh attestation before reuse; a quarantined
    // record must never resume its existing container. Force removal and rebuild
    // through provision (which re-attests) instead of reusing a container
    // that may sit behind a drifted firewall.
    const mustRebuild = record.networkProfile === 'dependency-access' || record.status === 'NETWORK_QUARANTINED';
    if (record.containerName && mustRebuild) {
      await removeContainer(record.containerName).catch(() => undefined);
    } else if (record.containerName) {
      const inspected = await inspectContainer(record.containerName);
      if (inspected) {
        const state = inspected.State as { Running?: boolean } | undefined;
        if (state?.Running) {
          return this.ref(record, record.containerName);
        }
        const started = await runDocker(['start', record.containerName], { timeoutMs: 30_000, ...(ctx.signal ? { signal: ctx.signal } : {}) });
        if (started.exitCode === 0) {
          return this.ref(record, record.containerName);
        }
      }
      await removeContainer(record.containerName).catch(() => undefined);
    }
    const repositoryPath = join(record.workspacePath, 'repo');
    const repoExists = await stat(repositoryPath).then(() => true).catch(() => false);
    if (!repoExists) {
      throw new HarnessError('EXPIRED', 'workspace repository data is no longer retained on disk and cannot be recovered', 410);
    }
    // The caller persists the returned executorId/status (activateWithLimit and
    // its CONFLICT handling stay in the service layer).
    return await this.provision(ctx);
  }

  async stop(ctx: ProvisionContext): Promise<void> {
    const name = ctx.record.containerName;
    if (!name) return;
    const result = await runDocker(['stop', name], { timeoutMs: 30_000, ...(ctx.signal ? { signal: ctx.signal } : {}) });
    if (result.exitCode !== 0 && !/no such (container|object)/i.test(result.stderr)) {
      throw new HarnessError('UNAVAILABLE', 'workspace executor could not be stopped', 503, true);
    }
  }

  async destroy(ctx: ProvisionContext): Promise<void> {
    if (ctx.record.containerName) await removeContainer(ctx.record.containerName);
  }

  async inspect(ctx: ProvisionContext): Promise<ExecutorInspection> {
    const name = ctx.record.containerName;
    if (!name) return { state: 'missing' };
    let inspected: Record<string, unknown> | undefined;
    try {
      inspected = await inspectContainer(name);
    } catch {
      return { state: 'unknown' };
    }
    if (!inspected) return { state: 'missing' };
    const state = inspected.State as { Running?: boolean } | undefined;
    return { state: state?.Running === true ? 'running' : 'stopped' };
  }

  /* ------------------------------------------------------------------ */
  /* Exec + streams                                                      */
  /* ------------------------------------------------------------------ */

  /**
   * Writes the operation-scoped environment to a mode-0600 env file under the
   * workspace job dir (trusted runner staging) and returns its path, or
   * `undefined` when the map is empty so argv stays byte-identical to today.
   */
  private async writeExecEnvFile(ctx: ProvisionContext, environment: Record<string, string>, prefix: string): Promise<string | undefined> {
    const entries = validatedExecEnvironment(environment);
    if (entries.length === 0) return undefined;
    const envFilePath = join(ctx.record.workspacePath, `${prefix}-${randomBytes(6).toString('hex')}`);
    await writeFile(envFilePath, entries.map(([k, v]) => `${k}=${v}`).join('\n') + '\n', { mode: 0o600, encoding: 'utf8' });
    return envFilePath;
  }

  private async removeExecEnvFile(envFilePath: string | undefined): Promise<void> {
    if (envFilePath) await rm(envFilePath, { force: true }).catch(() => undefined);
  }

  async exec(ctx: ProvisionContext, req: ExecRequest): Promise<ExecResult> {
    if (!Array.isArray(req.argv) || req.argv.length === 0 || req.argv.some((arg) => typeof arg !== 'string')) {
      throw new HarnessError('INVALID_INPUT', 'exec argv must be a non-empty string array', 400, false);
    }
    const mode = req.executionMode ?? 'executor';
    if (mode === 'ephemeral-helper') return await this.execEphemeralHelper(ctx, req);
    const containerName = this.containerName(ctx);
    const envFilePath = await this.writeExecEnvFile(ctx, req.environment, '.env.exec');
    const args = ['exec'];
    if (req.stdin !== undefined) args.push('-i');
    if (req.cwd !== undefined) args.push('-w', req.cwd);
    if (req.user === 'root') args.push('--user', '0:0');
    if (envFilePath) args.push('--env-file', envFilePath);
    args.push(containerName, ...req.argv);
    try {
      const result = await runDocker(args, {
        ...(req.stdin !== undefined ? { stdin: envStdin(req.stdin) } : {}),
        timeoutMs: req.timeoutMs,
        maxBytes: req.maxBytes,
        ...(req.signal ? { signal: req.signal } : {}),
        ...(req.abortKillGraceMs !== undefined ? { abortKillGraceMs: req.abortKillGraceMs } : {})
      });
      return {
        exitCode: result.exitCode,
        signal: null,
        stdout: result.stdout,
        stderr: result.stderr,
        truncated: result.truncated,
        timedOut: false
      };
    } finally {
      await this.removeExecEnvFile(envFilePath);
    }
  }

  /**
   * The `runPrivilegedEphemeralExec` shape relocated: a disposable helper
   * container with the workspace's network profile and the fixed helper
   * environment. `user` selects the uid WITHIN this mode — `'root'` keeps
   * today's privileged variant, anything else the cap-dropped unprivileged
   * variant; root is never granted by omission.
   */
  private async execEphemeralHelper(ctx: ProvisionContext, req: ExecRequest): Promise<ExecResult> {
    const record = ctx.record;
    const helperName = `chm-priv-${record.id.slice(3, 15)}-${randomBytes(4).toString('hex')}`;
    const toolsPath = join(record.workspacePath, 'tools');
    const cachePath = join(record.workspacePath, 'cache');
    const asRoot = req.user === 'root';
    const envFilePath = await this.writeExecEnvFile(ctx, req.environment, '.env.exec');
    try {
      await this.deps.network.ensureProfileReady(record.networkProfile);
      const args = [
        'run', '-i', '--rm', '--name', helperName,
        '--label', 'cloud-harness.managed=true',
        '--label', `cloud-harness.instance=${this.deps.instanceId}`,
        '--label', `cloud-harness.workspace=${record.id}`,
        '--label', 'cloud-harness.role=priv-exec',
        '--label', 'cloud-harness.ephemeral=true',
        ...this.deps.network.dockerLaunchArgs(record.networkProfile),
        '--user', asRoot ? '0:0' : WORKSPACE_UID,
        ...(asRoot ? [] : ['--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true']),
        '--workdir', req.cwd ?? '/workspace',
        '--pids-limit', '256',
        '--memory', '1g', '--memory-swap', '1g', '--cpus', '1',
        '--tmpfs', '/tmp:rw,exec,nosuid,nodev,size=128m',
        '--tmpfs', '/run:rw,nosuid,nodev,size=8m',
        '--volume', `${record.workspacePath}/repo:/workspace:rw`,
        '--volume', `${toolsPath}:/opt/user-tools:rw`,
        '--volume', `${cachePath}:/var/cache/harness:rw`,
        '--env', 'HOME=/tmp/cloud-harness-home',
        '--env', 'BUN_INSTALL=/opt/user-tools/bun',
        '--env', 'PNPM_HOME=/opt/user-tools/pnpm',
        '--env', 'UV_TOOL_BIN_DIR=/opt/user-tools/bin',
        '--env', `PATH=${EXECUTOR_PATH}`,
        ...(envFilePath ? ['--env-file', envFilePath] : []),
        this.config.executorImage,
        ...req.argv
      ];
      const result = await runDocker(args, {
        ...(req.stdin !== undefined ? { stdin: envStdin(req.stdin) } : {}),
        timeoutMs: req.timeoutMs,
        maxBytes: req.maxBytes,
        ...(req.signal ? { signal: req.signal } : {}),
        ...(req.abortKillGraceMs !== undefined ? { abortKillGraceMs: req.abortKillGraceMs } : {})
      });
      return {
        exitCode: result.exitCode,
        signal: null,
        stdout: result.stdout,
        stderr: result.stderr,
        truncated: result.truncated,
        timedOut: false
      };
    } finally {
      await this.removeExecEnvFile(envFilePath);
      await removeContainer(helperName);
    }
  }

  async spawnStream(ctx: ProvisionContext, req: StreamRequest): Promise<StreamHandle> {
    if (req.pty) return await this.spawnPtyStream(ctx, req as StreamRequest & { pty: { cols: number; rows: number } });
    if (!Array.isArray(req.argv) || req.argv.length === 0 || req.argv.some((arg) => typeof arg !== 'string')) {
      throw new HarnessError('INVALID_INPUT', 'stream argv must be a non-empty string array', 400, false);
    }
    const containerName = this.containerName(ctx);
    // The env file must outlive the docker CLI's own read of it: it is removed
    // when the spawned process closes (or errors), never synchronously after
    // spawn returns.
    const envFilePath = await this.writeExecEnvFile(ctx, req.environment, '.env.stream');
    const args = ['exec', '-i'];
    if (req.cwd !== undefined) args.push('-w', req.cwd);
    if (envFilePath) args.push('--env-file', envFilePath);
    args.push(containerName, ...req.argv);
    let child;
    try {
      child = spawnDocker(args);
    } catch (error) {
      await this.removeExecEnvFile(envFilePath);
      throw error;
    }
    // The env file must outlive the docker CLI's own read of it: removal waits
    // for close/error, never fires on spawn. A failsafe timer bounds the leak
    // when the CLI hangs without either event — by then flag parsing has long
    // since consumed the file, so deleting it cannot break a live session.
    const cleanup = () => { void this.removeExecEnvFile(envFilePath); };
    const failsafe = setTimeout(cleanup, STREAM_ENV_FILE_MAX_AGE_MS);
    failsafe.unref();
    child.once('close', () => { clearTimeout(failsafe); cleanup(); });
    child.once('error', () => { clearTimeout(failsafe); cleanup(); });
    return child as unknown as StreamHandle;
  }

  private async spawnPtyStream(ctx: ProvisionContext, req: StreamRequest & { pty: { cols: number; rows: number } }): Promise<StreamHandle> {
    if (!Array.isArray(req.argv) || req.argv.length === 0 || req.argv.some((arg) => typeof arg !== 'string')) {
      throw new HarnessError('INVALID_INPUT', 'stream argv must be a non-empty string array', 400, false);
    }
    validatedExecEnvironment(req.environment);
    const containerName = this.containerName(ctx);
    const terminalId = `stream-${randomBytes(6).toString('hex')}`;
    const transport = this.pty(ctx);
    const connection = await transport.open({
      container: containerName,
      terminalId,
      workingDir: req.cwd ?? '/workspace',
      cols: req.pty.cols,
      rows: req.pty.rows,
      argv: req.argv,
      environment: req.environment
    });
    return new PtyStreamHandle(connection, transport, () => transport.killSession(containerName, terminalId));
  }

  pty(ctx: ProvisionContext): PtyTransport {
    void ctx;
    this.ptyClient ??= this.deps.ptyTransport ?? new DockerPtyClient();
    return this.ptyClient;
  }

  /* ------------------------------------------------------------------ */
  /* Workspace file/tree transfer (host-side through the executor mounts) */
  /* ------------------------------------------------------------------ */

  /**
   * The executor's writable host-visible mounts. The docker executor has no
   * generic guest-fs channel: workspace data reaches the host through these
   * bind mounts, so file verbs resolve guest paths through this table and are
   * confined to writable mounts — read-only managed mounts (owner/builtin
   * skills, package releases) are never file-verb targets in either
   * direction.
   */
  private mountEntries(ctx: ProvisionContext): MountEntry[] {
    const jobPath = ctx.record.workspacePath;
    const entries: MountEntry[] = [
      { guest: '/workspace', host: join(jobPath, 'repo'), writable: true },
      { guest: '/opt/user-tools', host: join(jobPath, 'tools'), writable: true },
      { guest: '/var/cache/harness', host: join(jobPath, 'cache'), writable: true },
      { guest: '/opt/cloud-harness/owner-skills', host: join(jobPath, 'toolkit-projection', 'owner-skills'), writable: false }
    ];
    if (this.config.builtinSkillsRoot) {
      entries.push({ guest: '/opt/cloud-harness/skills', host: this.config.builtinSkillsRoot, writable: false });
    }
    return entries;
  }

  private resolveGuestPath(ctx: ProvisionContext, guestPath: string, options: { writable?: boolean } = {}): { root: string; hostPath: string; rel: string; writable: boolean } {
    if (typeof guestPath !== 'string' || !guestPath.startsWith('/')) {
      throw new HarnessError('INVALID_INPUT', 'guest path must be executor-absolute', 400, false);
    }
    const normalized = resolve(guestPath);
    let best: MountEntry | undefined;
    for (const entry of this.mountEntries(ctx)) {
      if (normalized === entry.guest || normalized.startsWith(`${entry.guest}/`)) {
        if (!best || entry.guest.length > best.guest.length) best = entry;
      }
    }
    if (!best) {
      throw new HarnessError('INVALID_INPUT', `guest path ${guestPath} is not reachable through the Docker executor mounts`, 400, false);
    }
    if (options.writable && !best.writable) {
      throw new HarnessError('INVALID_INPUT', `guest path ${guestPath} is mounted read-only`, 400, false);
    }
    const rel = normalized === best.guest ? '' : normalized.slice(best.guest.length + 1);
    const hostPath = resolve(best.host, rel);
    if (!isInside(resolve(best.host), hostPath)) {
      throw new HarnessError('INVALID_INPUT', `guest path ${guestPath} escapes its mount`, 400, false);
    }
    return { root: best.host, hostPath, rel, writable: best.writable };
  }

  /**
   * Opens `root/rel` as a pinned directory fd for the tree verbs. Each
   * component is opened O_NOFOLLOW|O_DIRECTORY through /proc/self/fd, so a
   * guest-swapped intermediate symlink fails atomically (ELOOP) instead of
   * being followed after a separate path check — closing the
   * check-then-use race a canonical-ancestor + leaf-O_NOFOLLOW scheme leaves
   * open. With `createMissing`, absent components are created one level at
   * a time (pushTree semantics); without it a missing component is NOT_FOUND
   * (pullTree semantics). The returned handle MUST be closed by the caller.
   */
  private async openPinnedGuestDir(root: string, rel: string, createMissing: boolean): Promise<FileHandle> {
    const openChild = async (dir: FileHandle, name: string): Promise<FileHandle | undefined> => {
      try {
        return await open(fdChildPath(dir, name), DIR_NOFOLLOW_FLAGS);
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === 'ENOENT') return undefined;
        if (code === 'ELOOP') {
          throw new HarnessError('INVALID_INPUT', 'executor path resolves through a symlink', 400, false);
        }
        if (code === 'ENOTDIR') {
          throw new HarnessError('INVALID_INPUT', 'executor path crosses a non-directory', 400, false);
        }
        throw error;
      }
    };
    let dir = await open(root, DIR_NOFOLLOW_FLAGS);
    const parts = rel === '' ? [] : rel.split(sep).filter((part) => part.length > 0);
    try {
      for (const part of parts) {
        let next = await openChild(dir, part);
        if (next === undefined && createMissing) {
          const child = fdChildPath(dir, part);
          await mkdir(child).catch((error: unknown) => {
            if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
          });
          next = await openChild(dir, part);
          if (next === undefined) {
            throw new HarnessError('INVALID_INPUT', 'tree destination changed during creation', 400, false);
          }
        }
        if (next === undefined) {
          throw new HarnessError('NOT_FOUND', 'tree source not found in the executor mounts', 404, false);
        }
        const previous = dir;
        dir = next;
        await previous.close();
      }
      return dir;
    } catch (error) {
      await dir.close().catch(() => undefined);
      throw error;
    }
  }

  async pullFile(ctx: ProvisionContext, guestPath: string, maxBytes: number): Promise<Buffer> {
    const { root, rel } = this.resolveGuestPath(ctx, guestPath, { writable: true });
    return await readVerifiedWorkspaceFile(root, rel, maxBytes);
  }

  /**
   * Copies `hostDir`'s entries into the guest path (contents semantics, like
   * `tar -C hostDir -cf - . | tar -C guestPath -xf -`). Only regular files,
   * directories, and symlinks are transferred; anything else fails rather
   * than silently dropping data. New files are chowned to the workspace uid;
   * when the runner lacks CAP_CHOWN the same chown-helper container shape
   * `provisionMountDirectories` uses fixes ownership recursively.
   */
  async pushTree(ctx: ProvisionContext, hostDir: string, guestPath: string): Promise<{ sha256: string; bytes: number; entryCount: number }> {
    const { root, hostPath, rel } = this.resolveGuestPath(ctx, guestPath, { writable: true });
    const sourceStat = await stat(hostDir).catch(() => undefined);
    if (!sourceStat?.isDirectory()) {
      throw new HarnessError('INVALID_INPUT', 'pushTree source must be a host directory', 400, false);
    }
    const targetStat = await lstat(hostPath).catch(() => undefined);
    if (targetStat && !targetStat.isDirectory()) {
      throw new HarnessError('INVALID_INPUT', 'pushTree target exists and is not a directory', 400, false);
    }
    // copyTree reads the source while writing the destination: if the two
    // resolve to the same directory — or either nests inside the other — the
    // copy truncates source files mid-read and can recurse into itself.
    // Compare canonical paths (symlinks resolved) BEFORE any mutation.
    const [sourceReal, targetReal] = await Promise.all([
      this.canonicalPath(hostDir),
      this.canonicalPath(hostPath)
    ]);
    if (
      sourceReal === targetReal ||
      sourceReal.startsWith(targetReal + sep) ||
      targetReal.startsWith(sourceReal + sep)
    ) {
      throw new HarnessError('INVALID_INPUT', 'pushTree source and destination must not overlap', 400, false);
    }
    // The guest owns the mounted tree: descend to the target through pinned
    // directory fds so an intermediate dir swapped for a symlink mid-copy
    // fails ELOOP instead of redirecting writes outside the mount. Missing
    // components are created level by level — never recursively through an
    // unverified path.
    const targetDir = await this.openPinnedGuestDir(root, rel, true);
    const sourceDir = await open(hostDir, DIR_OPEN_FLAGS);
    try {
      let needsChown = false;
      const onChownFailure = () => { needsChown = true; };
      // afterCreate only covers entries INSIDE the tree; the destination
      // root itself must be workspace-owned too or the guest cannot write
      // into it. fchown on the pinned fd cannot be redirected by a swap.
      await targetDir.chown(10001, 10001).catch(onChownFailure);
      await this.copyTree(sourceDir, targetDir, true, onChownFailure);
      if (needsChown) await this.chownTreeToWorkspace(ctx, hostPath);
      // The digest identifies the tree that crossed, computed on the source
      // so a pre-existing destination never pollutes it.
      return await this.treeDigest(sourceDir);
    } finally {
      await sourceDir.close();
      await targetDir.close();
    }
  }

  /**
   * Recursive chown of a pushed tree to the workspace uid through the same
   * ephemeral helper shape `provisionMountDirectories` falls back to. The
   * target is passed as a positional parameter — never interpolated into the
   * shell command — and must live under `record.workspacePath` (all writable
   * mounts do).
   */
  private async chownTreeToWorkspace(ctx: ProvisionContext, hostPath: string): Promise<void> {
    const jobPath = ctx.record.workspacePath;
    const jobRel = relative(jobPath, hostPath);
    if (jobRel === '' || jobRel.startsWith('..') || isAbsolute(jobRel)) {
      throw new HarnessError('INTERNAL_ERROR', 'pushed tree target is outside the workspace job path', 500, false);
    }
    const helperName = `chm-chown-${ctx.record.id.slice(3, 15)}-${randomBytes(4).toString('hex')}`;
    try {
      const result = await runDocker([
        'run', '--rm', '--pull', 'never', '--name', helperName,
        '--label', 'cloud-harness.role=chown-helper', '--label', 'cloud-harness.ephemeral=true',
        '--label', `cloud-harness.instance=${this.deps.instanceId}`, '--label', `cloud-harness.workspace=${ctx.record.id}`,
        '--network', 'none', '--user', '0:0',
        '--volume', `${jobPath}:/job`,
        '--entrypoint', '/bin/sh', this.config.executorImage,
        '-c', 'chown -R 10001:10001 "$1"', 'chown-helper', `/job/${jobRel}`
      ], { timeoutMs: 120_000, maxBytes: 8_192, ...(ctx.signal ? { signal: ctx.signal } : {}) });
      if (result.exitCode !== 0) {
        throw new HarnessError('UNAVAILABLE', `pushed tree ownership could not be normalized: ${result.stderr || result.stdout}`.slice(0, 2_000), 502, true);
      }
    } finally {
      await removeContainer(helperName);
    }
  }

  async pullTree(ctx: ProvisionContext, guestPath: string, hostDir: string): Promise<{ sha256: string; bytes: number; entryCount: number }> {
    const { root, hostPath, rel } = this.resolveGuestPath(ctx, guestPath, { writable: true });
    const sourceStat = await lstat(hostPath).catch(() => undefined);
    // A symlink at the source root is a containment refusal, not a missing
    // tree — keep the INVALID_INPUT the ancestry check used to produce.
    if (sourceStat?.isSymbolicLink()) {
      throw new HarnessError('INVALID_INPUT', 'executor path resolves through a symlink', 400, false);
    }
    if (!sourceStat?.isDirectory()) {
      throw new HarnessError('NOT_FOUND', 'tree source not found in the executor mounts', 404, false);
    }
    const targetStat = await stat(hostDir).catch(() => undefined);
    if (targetStat && !targetStat.isDirectory()) {
      throw new HarnessError('INVALID_INPUT', 'pullTree destination exists and is not a directory', 400, false);
    }
    // Same overlap hazard as pushTree, mirrored: the destination must not
    // alias or nest inside the mounted source before copyTree mutates it.
    const [sourceReal, targetReal] = await Promise.all([
      this.canonicalPath(hostPath),
      this.canonicalPath(hostDir)
    ]);
    if (
      sourceReal === targetReal ||
      sourceReal.startsWith(targetReal + sep) ||
      targetReal.startsWith(sourceReal + sep)
    ) {
      throw new HarnessError('INVALID_INPUT', 'pullTree source and destination must not overlap', 400, false);
    }
    await mkdir(hostDir, { recursive: true });
    // Mirror of pushTree: the guest-controlled source is pinned fd-relative
    // so a swapped intermediate dir cannot turn the copy into a host file
    // disclosure; the trusted destination root is opened once.
    const sourceDir = await this.openPinnedGuestDir(root, rel, false);
    const targetDir = await open(hostDir, DIR_OPEN_FLAGS);
    try {
      await this.copyTree(sourceDir, targetDir, false, () => undefined);
      return await this.treeDigest(sourceDir);
    } finally {
      await sourceDir.close();
      await targetDir.close();
    }
  }

  /**
   * Canonical path for overlap checks: realpath the deepest existing ancestor
   * and re-append the not-yet-created tail, so a destination that does not
   * exist yet still compares correctly against symlinked sources.
   */
  private async canonicalPath(path: string): Promise<string> {
    const missing: string[] = [];
    let cursor = resolve(path);
    for (;;) {
      const info = await stat(cursor).catch(() => undefined);
      if (info) {
        const real = await realpath(cursor);
        return missing.length === 0 ? real : join(real, ...missing);
      }
      const parent = dirname(cursor);
      if (parent === cursor) return cursor;
      missing.unshift(basename(cursor));
      cursor = parent;
    }
  }

  /**
   * Copies the CONTENTS of `source` into `target` (both pinned directory
   * fds). Every level descends through /proc/self/fd child paths, so an
   * intermediate directory swapped for a symlink mid-copy fails ELOOP at
   * the next open instead of redirecting the copy outside the mount —
   * closing the race a path-based ancestry check + leaf O_NOFOLLOW leaves
   * open. `chownToWorkspace` normalizes new entries to the workspace uid;
   * failures are reported through `onChownFailure` so the caller can fall
   * back to the chown-helper container.
   *
   * The destination tree is guest-writable on the push side, so every
   * create first `lstat`s the fd-relative child path and never follows it:
   * files/symlinks are unlinked (never recursively removed — an unverified
   * directory target is a hard error, not an overwrite), directories are
   * reused or recreated after the link is unlinked, and file opens carry
   * O_NOFOLLOW so a symlink swapped in mid-copy fails ELOOP instead of
   * escaping the mount. Source reads carry the same flag for the pull
   * direction.
   */
  private async copyTree(source: FileHandle, target: FileHandle, chownToWorkspace: boolean, onChownFailure: () => void): Promise<void> {
    const entries = await readdir(fdDirPath(source), { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const from = fdChildPath(source, entry.name);
      const info = await lstat(from);
      if (info.isDirectory()) {
        const targetChild = await this.ensureRealDestinationDir(target, entry.name);
        // O_NOFOLLOW|O_DIRECTORY: a source dir swapped for a symlink between
        // the entry lstat and this open fails ELOOP rather than being read
        // through the link. The target fd is already open here — close it on
        // source-open failure or every swapped-source retry leaks a handle.
        let sourceChild: FileHandle;
        try {
          sourceChild = await open(from, DIR_NOFOLLOW_FLAGS);
        } catch (error) {
          await targetChild.close().catch(() => undefined);
          throw error;
        }
        try {
          if (chownToWorkspace) {
            // fchown on the pinned fd: immune to post-open path swaps.
            await targetChild.chown(10001, 10001).catch(onChownFailure);
          }
          await this.copyTree(sourceChild, targetChild, chownToWorkspace, onChownFailure);
          // Directory modes are applied AFTER children so a read-only source
          // mode cannot block the copy; treeDigest records modes, so skipping
          // this made pushed trees digest differently than their source.
          // fchmod on the pinned fd cannot be redirected by a swap either.
          await targetChild.chmod(info.mode & 0o7777);
        } finally {
          await sourceChild.close();
          await targetChild.close();
        }
      } else if (info.isSymbolicLink()) {
        const linkTarget = await readlink(from);
        await this.replaceDestinationEntry(target, entry.name, async () => {
          await symlink(linkTarget, fdChildPath(target, entry.name));
        });
        if (chownToWorkspace) {
          // lchown never follows: it acts on the link inode inside the
          // pinned parent even if the entry was swapped mid-copy.
          await lchown(fdChildPath(target, entry.name), 10001, 10001).catch(onChownFailure);
        }
      } else if (info.isFile()) {
        await this.copyFileNoFollow(
          from,
          fdChildPath(target, entry.name),
          info.mode & 0o7777,
          chownToWorkspace
            ? async (handle) => {
                // fchown while the O_NOFOLLOW write fd is still open: the
                // ownership change is pinned to the created inode.
                await handle.chown(10001, 10001).catch(onChownFailure);
              }
            : undefined
        );
      } else {
        throw new HarnessError('INVALID_INPUT', `tree entry ${entry.name} is not a regular file, directory, or symlink`, 400, false);
      }
    }
  }

  /**
   * Ensures `name` under the pinned `parent` is a real directory for a 'd'
   * source entry, and returns its pinned fd for the recursion. An existing
   * file or symlink is unlinked first — `rm` without recursion can never
   * reach through a link — and the final O_NOFOLLOW open re-verifies the
   * result so a mid-copy swap fails loudly instead of being copied into.
   */
  private async ensureRealDestinationDir(parent: FileHandle, name: string): Promise<FileHandle> {
    const to = fdChildPath(parent, name);
    const existing = await lstat(to).catch(() => undefined);
    if (existing === undefined) {
      // EEXIST means something appeared mid-check — the verify below decides.
      await mkdir(to).catch((error: unknown) => {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      });
    } else if (!existing.isDirectory()) {
      await rm(to, { force: true });
      await mkdir(to);
    }
    const verify = await lstat(to).catch(() => undefined);
    if (!verify?.isDirectory()) {
      throw new HarnessError('INVALID_INPUT', 'tree destination changed during copy', 400, false);
    }
    try {
      return await open(to, DIR_NOFOLLOW_FLAGS);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'ELOOP' || code === 'ENOTDIR') {
        throw new HarnessError('INVALID_INPUT', 'tree destination changed during copy', 400, false);
      }
      throw error;
    }
  }

  /**
   * Replaces whatever non-directory sits at `name` under the pinned `parent`
   * (file or symlink — unlinked, never followed) then runs `create`. A real
   * directory is a hard error: removing it recursively could destroy guest
   * data the source never described. One EEXIST retry covers a file/symlink
   * swapped in mid-copy.
   */
  private async replaceDestinationEntry(parent: FileHandle, name: string, create: () => Promise<void>): Promise<void> {
    const to = fdChildPath(parent, name);
    const existing = await lstat(to).catch(() => undefined);
    if (existing?.isDirectory()) {
      throw new HarnessError('INVALID_INPUT', 'tree destination is a directory', 400, false);
    }
    if (existing) await rm(to, { force: true });
    try {
      await create();
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
      const swapped = await lstat(to).catch(() => undefined);
      if (swapped?.isDirectory()) {
        throw new HarnessError('INVALID_INPUT', 'tree destination is a directory', 400, false);
      }
      await rm(to, { force: true });
      await create();
    }
  }

  /**
   * Copies one regular file with O_NOFOLLOW on both ends. An ELOOP on the
   * destination means a symlink appeared after the lstat — unlink and retry
   * once; anything else is a real failure. ELOOP on the source means the
   * guest swapped the file for a link mid-read: fail, never follow.
   * `onOpenHandle` runs while the destination fd is still open so callers
   * can pin metadata changes (fchown) to the created inode.
   */
  private async copyFileNoFollow(from: string, to: string, mode: number, onOpenHandle?: (handle: FileHandle) => Promise<void>): Promise<void> {
    const write = async (): Promise<void> => {
      // fs.promises.open with numeric flags + FileHandle: the O_NOFOLLOW open
      // and the fchmod/fchown below are all pinned to the created inode, so
      // none can be redirected by a symlink swapped in mid-copy.
      const handle = await open(to, WRITE_NOFOLLOW_FLAGS, mode);
      // The source open carries the same O_NOFOLLOW pin: a leaf swapped for
      // a symlink between the entry lstat and this open fails ELOOP. The
      // copy uses FileHandle.read/write rather than createReadStream/
      // createWriteStream because those close the fd when the stream ends —
      // fchmod/fchown below must still find it open and pinned.
      const source = await open(from, READ_NOFOLLOW_FLAGS);
      const buffer = Buffer.allocUnsafe(1024 * 1024);
      try {
        for (;;) {
          const { bytesRead } = await source.read(buffer, 0, buffer.length, null);
          if (bytesRead === 0) break;
          let offset = 0;
          while (offset < bytesRead) {
            const { bytesWritten } = await handle.write(buffer, offset, bytesRead - offset, null);
            offset += bytesWritten;
          }
        }
        await handle.chmod(mode);
        if (onOpenHandle !== undefined) await onOpenHandle(handle);
      } finally {
        await source.close();
        await handle.close();
      }
    };
    try {
      await write();
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      // ELOOP: a symlink appeared after the entry lstat — unlink and retry
      // once. EISDIR: the destination is a real directory — a hard error,
      // never recursively removed.
      if (code !== 'ELOOP' && code !== 'EISDIR') throw error;
      const target = await lstat(to).catch(() => undefined);
      if (target?.isDirectory()) {
        throw new HarnessError('INVALID_INPUT', 'tree destination is a directory', 400, false);
      }
      if (code === 'EISDIR') throw error;
      await rm(to, { force: true });
      await write();
    }
  }

  /**
   * Deterministic content manifest digest shared by pushTree/pullTree: sorted
   * JSON entries of type, mode, size, path, and per-file SHA-256 (or symlink
   * target), so identical trees digest identically in either direction. File
   * contents are hashed as a stream — trees can be large. The walk is
   * fd-relative like copyTree: `root` is an open directory fd and every
   * level descends through /proc/self/fd, so a guest-swapped intermediate
   * dir cannot redirect digest reads outside the mount on the pull side.
   * The caller retains ownership of `root` and closes it.
   */
  private async treeDigest(root: FileHandle): Promise<{ sha256: string; bytes: number; entryCount: number }> {
    const manifest: TreeManifestEntry[] = [];
    let bytes = 0;
    const hashFile = async (path: string): Promise<string> => {
      const hash = createHash('sha256');
      const file = await open(path, READ_NOFOLLOW_FLAGS);
      const buffer = Buffer.allocUnsafe(1024 * 1024);
      try {
        for (;;) {
          const { bytesRead } = await file.read(buffer, 0, buffer.length, null);
          if (bytesRead === 0) break;
          hash.update(buffer.subarray(0, bytesRead));
        }
      } finally {
        await file.close();
      }
      return hash.digest('hex');
    };
    const walk = async (dir: FileHandle, prefix: string): Promise<void> => {
      const entries = await readdir(fdDirPath(dir), { withFileTypes: true });
      entries.sort((a, b) => a.name.localeCompare(b.name));
      for (const entry of entries) {
        const full = fdChildPath(dir, entry.name);
        const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
        const info = await lstat(full);
        if (info.isDirectory()) {
          manifest.push({ type: 'd', mode: (info.mode & 0o7777).toString(8), size: 0, path: rel });
          const child = await open(full, DIR_NOFOLLOW_FLAGS);
          try {
            await walk(child, rel);
          } finally {
            await child.close();
          }
        } else if (info.isSymbolicLink()) {
          manifest.push({ type: 'l', mode: (info.mode & 0o7777).toString(8), size: 0, path: rel, target: await readlink(full) });
        } else if (info.isFile()) {
          manifest.push({ type: 'f', mode: (info.mode & 0o7777).toString(8), size: info.size, path: rel, sha256: await hashFile(full) });
          bytes += info.size;
        } else {
          throw new HarnessError('INVALID_INPUT', `tree entry ${rel} is not a regular file, directory, or symlink`, 400, false);
        }
      }
    };
    await walk(root, '');
    return { sha256: createHash('sha256').update(JSON.stringify(manifest)).digest('hex'), bytes, entryCount: manifest.length };
  }

  /* ------------------------------------------------------------------ */
  /* Measurement + process control                                       */
  /* ------------------------------------------------------------------ */

  /**
   * The `workspaceBytes` relocation: `du` over the three mounted workspace
   * roots inside the executor, falling back to the read-only size helper when
   * the exec path cannot answer. A thrown docker error propagates exactly as
   * it does today; only a non-zero exit selects the helper.
   */
  async measureWorkspaceBytes(ctx: ProvisionContext): Promise<number> {
    const record = ctx.record;
    let result;
    if (record.containerName) {
      result = await runDocker(
        ['exec', record.containerName, '/usr/bin/du', '-sb', '--apparent-size', '/workspace', '/opt/user-tools', '/var/cache/harness'],
        { timeoutMs: 30_000, maxBytes: 8_192, ...(ctx.signal ? { signal: ctx.signal } : {}) }
      );
    }
    if (!result || result.exitCode !== 0) {
      const helperName = `chm-size-${record.id.slice(3, 15)}-${randomBytes(4).toString('hex')}`;
      try {
        result = await runDocker([
          'run', '--rm', '--pull', 'never', '--name', helperName,
          '--label', 'cloud-harness.role=size-helper', '--label', 'cloud-harness.ephemeral=true',
          '--label', `cloud-harness.instance=${this.deps.instanceId}`, '--label', `cloud-harness.workspace=${record.id}`,
          '--network', 'none', '--user', '0:0', '--read-only',
          '--pids-limit', '32', '--memory', '128m', '--memory-swap', '128m', '--cpus', '0.25',
          '--volume', `${record.workspacePath}:/target:ro`, '--entrypoint', '/usr/bin/du', this.config.executorImage,
          '-sb', '--apparent-size', '/target'
        ], { timeoutMs: 30_000, maxBytes: 8_192, ...(ctx.signal ? { signal: ctx.signal } : {}) });
      } finally {
        await removeContainer(helperName);
      }
    }
    if (result.exitCode !== 0) {
      throw new HarnessError('UNAVAILABLE', 'workspace size could not be measured safely', 503, true);
    }
    const lines = result.stdout.trim().split('\n');
    let totalBytes = 0;
    for (const line of lines) {
      const bytes = Number(line.trim().split(/\s+/, 1)[0]);
      if (Number.isSafeInteger(bytes) && bytes >= 0) {
        totalBytes += bytes;
      }
    }
    return totalBytes;
  }

  async killProcessGroup(ctx: ProvisionContext, pidFile: string): Promise<void> {
    await terminateContainerProcessGroup(this.containerName(ctx), pidFile);
  }

  capabilities(): BackendCapabilityMap {
    return Object.fromEntries(BACKEND_CAPABILITY_IDS.map((id) => [id, 'supported'])) as BackendCapabilityMap;
  }
}
