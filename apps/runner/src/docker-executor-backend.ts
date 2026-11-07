import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, createWriteStream } from 'node:fs';
import { chmod, chown, lchown, lstat, mkdir, readdir, readlink, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { pipeline } from 'node:stream/promises';
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
import { DockerPtyClient, type PtyConnection, type PtyTransport } from './docker-pty.js';
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
      this.finish(end.error ?? null);
    });
  }

  kill(): boolean {
    if (this.closed) return false;
    try { this.connection.close(); } catch { /* already closed */ }
    void this.endSession().catch(() => undefined);
    return true;
  }

  private finish(error: Error | null): void {
    if (this.closed) return;
    this.closed = true;
    if (error) this.emit('error', error);
    this.emit('close', null, null);
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
    const containerName = this.containerName(ctx);
    const terminalId = `stream-${randomBytes(6).toString('hex')}`;
    const connection = await this.pty(ctx).open({
      container: containerName,
      terminalId,
      workingDir: req.cwd ?? '/workspace',
      cols: req.pty.cols,
      rows: req.pty.rows
    });
    return new PtyStreamHandle(connection, () => this.pty(ctx).killSession(containerName, terminalId));
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
    const { hostPath } = this.resolveGuestPath(ctx, guestPath, { writable: true });
    const sourceStat = await stat(hostDir).catch(() => undefined);
    if (!sourceStat?.isDirectory()) {
      throw new HarnessError('INVALID_INPUT', 'pushTree source must be a host directory', 400, false);
    }
    const targetStat = await stat(hostPath).catch(() => undefined);
    if (targetStat && !targetStat.isDirectory()) {
      throw new HarnessError('INVALID_INPUT', 'pushTree target exists and is not a directory', 400, false);
    }
    await mkdir(hostPath, { recursive: true });
    let needsChown = false;
    await this.copyTree(hostDir, hostPath, async (target, kind) => {
      try {
        if (kind === 'l') await lchown(target, 10001, 10001);
        else await chown(target, 10001, 10001);
      } catch {
        needsChown = true;
      }
    });
    if (needsChown) await this.chownTreeToWorkspace(ctx, hostPath);
    // The digest identifies the tree that crossed, computed on the source so a
    // pre-existing destination never pollutes it.
    return await this.treeDigest(hostDir);
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
    const { hostPath } = this.resolveGuestPath(ctx, guestPath, { writable: true });
    const sourceStat = await stat(hostPath).catch(() => undefined);
    if (!sourceStat?.isDirectory()) {
      throw new HarnessError('NOT_FOUND', 'tree source not found in the executor mounts', 404, false);
    }
    const targetStat = await stat(hostDir).catch(() => undefined);
    if (targetStat && !targetStat.isDirectory()) {
      throw new HarnessError('INVALID_INPUT', 'pullTree destination exists and is not a directory', 400, false);
    }
    await mkdir(hostDir, { recursive: true });
    await this.copyTree(hostPath, hostDir, async () => undefined);
    return await this.treeDigest(hostPath);
  }

  /**
   * Copies the CONTENTS of `source` into `target` (both must be directories).
   * `afterCreate` runs per created entry for ownership fixups; `kind` is
   * 'd' | 'f' | 'l' so symlink ownership uses lchown semantics.
   */
  private async copyTree(source: string, target: string, afterCreate: (path: string, kind: 'd' | 'f' | 'l') => Promise<void>): Promise<void> {
    const entries = await readdir(source, { withFileTypes: true });
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const from = join(source, entry.name);
      const to = join(target, entry.name);
      const info = await lstat(from);
      if (info.isDirectory()) {
        await mkdir(to, { recursive: true });
        await afterCreate(to, 'd');
        await this.copyTree(from, to, afterCreate);
      } else if (info.isSymbolicLink()) {
        const linkTarget = await readlink(from);
        await symlink(linkTarget, to);
        await afterCreate(to, 'l');
      } else if (info.isFile()) {
        await mkdir(dirname(to), { recursive: true });
        await pipeline(createReadStream(from), createWriteStream(to));
        await chmod(to, info.mode & 0o7777);
        await afterCreate(to, 'f');
      } else {
        throw new HarnessError('INVALID_INPUT', `tree entry ${entry.name} is not a regular file, directory, or symlink`, 400, false);
      }
    }
  }

  /**
   * Deterministic content manifest digest shared by pushTree/pullTree: sorted
   * JSON entries of type, mode, size, path, and per-file SHA-256 (or symlink
   * target), so identical trees digest identically in either direction. File
   * contents are hashed as a stream — trees can be large.
   */
  private async treeDigest(root: string): Promise<{ sha256: string; bytes: number; entryCount: number }> {
    const manifest: TreeManifestEntry[] = [];
    let bytes = 0;
    const hashFile = async (path: string): Promise<string> => {
      const hash = createHash('sha256');
      for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
      return hash.digest('hex');
    };
    const walk = async (dir: string, prefix: string): Promise<void> => {
      const entries = await readdir(dir, { withFileTypes: true });
      entries.sort((a, b) => a.name.localeCompare(b.name));
      for (const entry of entries) {
        const full = join(dir, entry.name);
        const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
        const info = await lstat(full);
        if (info.isDirectory()) {
          manifest.push({ type: 'd', mode: (info.mode & 0o7777).toString(8), size: 0, path: rel });
          await walk(full, rel);
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
