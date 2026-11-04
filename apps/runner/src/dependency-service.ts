import { createHash } from 'node:crypto';
import { chmod, chown, lstat, mkdir, open, readFile, readdir, realpath, rename, rm, statfs } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { HarnessError, type DependenciesApplyInput, type DependenciesPlanInput, type DependencyPlanView } from '@cloud-harness/contracts';
import { readVerifiedWorkspaceFile } from './bounded-workspace-file-reader.js';
import { DependencyCleanupError } from './dependency-builder-port.js';
import type { DependencyBuilderPort } from './dependency-builder-port.js';
import { validateDependencyManifests } from './dependency-manifests.js';
import type { DependencyStore } from './dependency-store.js';

export type DependencyWorkspace = {
  repositoryRoot: string;
  workspacePath: string;
  toolsPath: string;
  cachePath: string;
  maxWorkspaceBytes: number;
  minFreeBytes: number;
  toolMounts: Array<{ source: string; target: string }>;
  binDirs: string[];
  profileDigest: string;
  /** Execute only while the existing executor is paused; resume in finally. */
  paused<T>(action: () => Promise<T>): Promise<T>;
  /** Fails if the workspace was closed, expired or changed generation. */
  assertCurrent(): void;
};
export type DependencyServiceOptions = {
  store: DependencyStore;
  builder: DependencyBuilderPort;
  enabled: boolean;
  approvalAvailable: boolean;
  timeoutMs: number;
  maxBytes: number;
  withWorkspace<T>(ownerId: string, workspaceId: string, action: (workspace: DependencyWorkspace) => Promise<T>, planning?: boolean): Promise<T>;
  prepareDirectory?: (path: string) => Promise<void>;
  audit?: (ownerId: string, action: string, plan: DependencyPlanView) => void;
};
const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const sameSnapshot = (a: Record<string, string>, b: Record<string, string>) => JSON.stringify(a) === JSON.stringify(b);

/** Plans never fetch; only a consumed Dashboard approval can start an isolated downloader. */
export class DependencyService {
  private readonly jobs = new Map<string, { controller: AbortController; promise: Promise<void>; started: Promise<DependencyPlanView> }>();
  constructor(private readonly options: DependencyServiceOptions) {
    options.store.recoverInterrupted();
  }
  list(ownerId: string): DependencyPlanView[] { return this.options.store.list(ownerId); }
  status(ownerId: string, workspaceId: string, planId?: string): { plans: DependencyPlanView[] } {
    if (!planId) return { plans: this.options.store.list(ownerId, workspaceId) };
    const record = this.options.store.get(ownerId, planId);
    if (record.view.workspaceId !== workspaceId) throw new HarnessError('NOT_FOUND', 'Dependency plan not found', 404);
    return { plans: [record.view] };
  }
  approve(ownerId: string, input: { planId: string; planDigest: string }): DependencyPlanView {
    this.requireEnabled();
    const plan = this.options.store.approve(ownerId, input);
    this.audit(ownerId, 'dependency_plan.approved', plan);
    return plan;
  }
  reject(ownerId: string, input: { planId: string }): DependencyPlanView {
    const plan = this.options.store.reject(ownerId, input);
    this.audit(ownerId, 'dependency_plan.rejected', plan);
    return plan;
  }
  async plan(ownerId: string, input: DependenciesPlanInput): Promise<DependencyPlanView> {
    this.requireEnabled();
    return this.options.withWorkspace(ownerId, input.workspaceId, async (workspace) => {
      const snapshots = await workspace.paused(() => this.snapshot(workspace, input.ecosystem, input.directory));
      const { dependencies } = validateDependencyManifests(input.ecosystem, snapshots);
      const imageId = await this.options.builder.imageId();
      workspace.assertCurrent();
      const plan = this.options.store.create(ownerId, {
        ...input, snapshots, imageId, dependencies, profileDigest: workspace.profileDigest,
        maxBytes: Math.min(this.options.maxBytes, workspace.maxWorkspaceBytes), timeoutMs: this.options.timeoutMs
      }).view;
      this.audit(ownerId, 'dependency_plan.created', plan);
      return plan;
    }, true);
  }
  async apply(ownerId: string, input: DependenciesApplyInput): Promise<DependencyPlanView> {
    this.requireEnabled();
    const record = this.options.store.get(ownerId, input.planId);
    if (record.view.workspaceId !== input.workspaceId) throw new HarnessError('NOT_FOUND', 'Dependency plan not found', 404);
    if (record.view.planDigest !== input.planDigest) throw new HarnessError('CONFLICT', 'Dependency plan digest changed', 409);
    const current = this.jobs.get(input.planId);
    if (current) return current.started;
    if (['SUCCEEDED', 'FAILED', 'RUNNING'].includes(record.view.state)) return record.view;
    if (record.view.state === 'EXPIRED' || record.view.expiresAt <= Date.now()) throw new HarnessError('EXPIRED', 'Dependency approval expired', 410);
    if (record.view.state !== 'APPROVED') throw new HarnessError('OWNER_APPROVAL_REQUIRED', 'Approve this dependency plan in Dashboard before downloading', 403);
    if (this.jobs.size >= 2) throw new HarnessError('LIMIT_EXCEEDED', 'Two dependency downloads are already active; retry later', 429, true);
    const controller = new AbortController();
    let resolveStarted!: (plan: DependencyPlanView) => void;
    let rejectStarted!: (error: unknown) => void;
    const started = new Promise<DependencyPlanView>((resolve, reject) => { resolveStarted = resolve; rejectStarted = reject; });
    let consumed = false;
    const promise = this.options.withWorkspace(ownerId, input.workspaceId, async (workspace) => {
      const snapshots = await workspace.paused(() => this.snapshot(workspace, record.view.ecosystem, record.view.directory));
      if (!sameSnapshot(record.snapshots, snapshots) || record.profileDigest !== workspace.profileDigest
        || record.imageId !== await this.options.builder.imageId()) {
        throw new HarnessError('CONFLICT', 'Manifests, package profile or executor image changed; create a new dependency plan', 409);
      }
      validateDependencyManifests(record.view.ecosystem, snapshots);
      workspace.assertCurrent();
      const result = this.options.store.start(ownerId, input.planId, input.planDigest, input.workspaceId);
      if (result.replayed) { resolveStarted(result.record.view); return; }
      consumed = true;
      resolveStarted(result.record.view);
      const staging = join(workspace.workspacePath, `dependency-${input.planId}`);
      let cleanupSafe = true;
      try {
        await mkdir(staging, { mode: 0o700 });
        if (this.options.prepareDirectory) await this.options.prepareDirectory(staging);
        else { await chown(staging, 10001, 10001); await chmod(staging, 0o700); }
        const free = await statfs(staging);
        if (Number(free.bavail) * Number(free.bsize) < record.view.maxBytes + workspace.minFreeBytes) {
          throw new HarnessError('LIMIT_EXCEEDED', 'Insufficient free disk for approved dependency cache', 413);
        }
        try { await this.options.builder.download({
          id: input.planId, imageId: record.imageId, ecosystem: record.view.ecosystem,
          manifests: record.snapshots, stagingDir: staging, timeoutMs: record.view.timeoutMs,
          maxBytes: record.view.maxBytes, toolMounts: workspace.toolMounts,
          binDirs: workspace.binDirs, signal: controller.signal
        }); } catch (error) {
          if (error instanceof DependencyCleanupError) cleanupSafe = false;
          throw error;
        }
        workspace.assertCurrent();
        const sizeBytes = await workspace.paused(async () => {
          if (!sameSnapshot(record.snapshots, await this.snapshot(workspace, record.view.ecosystem, record.view.directory))) {
            throw new HarnessError('CONFLICT', 'Dependency manifests changed during download; cache was not installed', 409);
          }
          const source = join(staging, 'cache', record.view.ecosystem === 'go' ? 'go-mod' : 'pnpm-store');
          const size = await measureCache(source, record.view.maxBytes, true);
          const currentBytes = await measureCache(workspace.repositoryRoot, workspace.maxWorkspaceBytes, false)
            + await measureCache(workspace.toolsPath, workspace.maxWorkspaceBytes, false)
            + await measureCache(workspace.cachePath, workspace.maxWorkspaceBytes, false);
          if (currentBytes + size > workspace.maxWorkspaceBytes) throw new HarnessError('LIMIT_EXCEEDED', 'Dependency cache would exceed the workspace storage ceiling', 413);
          const root = record.view.ecosystem === 'go' ? workspace.cachePath : workspace.toolsPath;
          const target = record.view.ecosystem === 'go' ? join(root, 'go-mod') : join(root, 'pnpm', 'store');
          const marker = await open(join(staging, 'publication.json'), 'wx', 0o600);
          try { await marker.writeFile(JSON.stringify({ ecosystem: record.view.ecosystem })); await marker.sync(); }
          finally { await marker.close(); }
          try { await installCache(root, target, source, join(staging, 'previous-cache')); }
          catch (error) {
            if (error instanceof DependencyPublicationError) cleanupSafe = false;
            throw error;
          }
          return size;
        });
        const completed = this.options.store.finish(ownerId, input.planId, { sizeBytes });
        this.audit(ownerId, 'dependency_download.succeeded', completed);
      } finally {
        if (cleanupSafe) await removeDependencyStaging(staging).catch(() => {
          this.audit(ownerId, 'dependency_cache.cleanup_pending', this.options.store.get(ownerId, input.planId).view);
        });
      }
    }).catch((error: unknown) => {
      if (consumed && this.options.store.get(ownerId, input.planId).view.state === 'RUNNING') {
        const message = error instanceof HarnessError ? `${error.code}: ${error.message}` : 'Dependency download failed; inspect operator logs and request a new plan';
        const failed = this.options.store.finish(ownerId, input.planId, { error: message });
        this.audit(ownerId, 'dependency_download.failed', failed);
      }
      rejectStarted(error);
    }).finally(() => { this.jobs.delete(input.planId); });
    this.jobs.set(input.planId, { controller, promise, started });
    return started;
  }
  async shutdown(): Promise<void> {
    for (const job of this.jobs.values()) job.controller.abort();
    await Promise.allSettled([...this.jobs.values()].map((job) => job.promise));
  }
  private requireEnabled(): void {
    if (!this.options.enabled) throw new HarnessError('UNAVAILABLE', 'Project dependency downloads are off; operator enables DEPENDENCIES_ENABLED=true', 503);
    if (!this.options.approvalAvailable) throw new HarnessError('UNAVAILABLE', 'Project dependency downloads require Dashboard approval', 503);
  }
  private audit(ownerId: string, action: string, plan: DependencyPlanView): void {
    try { this.options.audit?.(ownerId, action, plan); } catch { /* Audit failures do not repeat downloads. */ }
  }
  private async snapshot(workspace: DependencyWorkspace, ecosystem: 'go' | 'pnpm', directory: string): Promise<Record<string, string>> {
    const names = ecosystem === 'go' ? ['go.mod', 'go.sum'] : ['package.json', 'pnpm-lock.yaml'];
    const snapshots: Record<string, string> = {};
    for (const name of names) {
      const bytes = await readVerifiedWorkspaceFile(workspace.repositoryRoot, join(directory, name), 4 * 1024 * 1024);
      const text = bytes.toString('utf8');
      if (!Buffer.from(text, 'utf8').equals(bytes)) throw new HarnessError('INVALID_INPUT', 'Dependency manifests must be valid UTF-8', 400);
      snapshots[name] = text;
    }
    return snapshots;
  }
}

/** Refuse symlink/special-file cache output before importing it into the executor. */
export async function measureCache(root: string, maxBytes: number, strict: boolean): Promise<number> {
  let bytes = 0;
  let entries = 0;
  const visit = async (path: string): Promise<void> => {
    const entry = await lstat(path);
    if (++entries > 500_000) throw new HarnessError('LIMIT_EXCEEDED', 'Dependency cache contains too many entries', 413);
    if (strict && (entry.isSymbolicLink() || (!entry.isDirectory() && !entry.isFile()))) throw new HarnessError('INVALID_INPUT', 'Dependency cache contains an unsafe entry', 400);
    bytes += entry.size;
    if (bytes > maxBytes) throw new HarnessError('LIMIT_EXCEEDED', 'Dependency cache exceeds disk budget', 413);
    if (entry.isDirectory()) for (const child of await readdir(path)) await visit(join(path, child));
  };
  await visit(root);
  return bytes;
}

class DependencyPublicationError extends HarnessError {
  constructor() { super('CONFLICT', 'Dependency cache publication needs recovery; the previous cache is retained', 409); }
}

async function installCache(root: string, target: string, source: string, previous: string): Promise<void> {
  if (await realpath(root) !== resolve(root) || !resolve(target).startsWith(`${resolve(root)}${sep}`)) throw new HarnessError('CONFLICT', 'Workspace cache root changed', 409);
  const parent = join(target, '..');
  await mkdir(parent, { recursive: true });
  if (await realpath(parent) !== resolve(parent)) throw new HarnessError('CONFLICT', 'Workspace cache path must not use symlinks', 409);
  const existing = await lstat(target).catch((error: NodeJS.ErrnoException) => { if (error.code === 'ENOENT') return undefined; throw error; });
  if (existing && !existing.isDirectory()) throw new HarnessError('CONFLICT', 'Workspace cache destination is not a directory', 409);
  if (existing) await rename(target, previous);
  try { await rename(source, target); }
  catch (error) {
    if (existing) {
      try { await rename(previous, target); }
      catch { throw new DependencyPublicationError(); }
    }
    throw error;
  }
}

export const dependencyProfileDigest = (releaseIds: string[]) => hash(JSON.stringify([...releaseIds].sort()));

/** Called only after helper cleanup, while the executor cannot write these paths. */
export async function removeDependencyStaging(path: string): Promise<void> {
  const makeWritable = async (entry: string): Promise<void> => {
    const info = await lstat(entry).catch((error: NodeJS.ErrnoException) => { if (error.code === 'ENOENT') return undefined; throw error; });
    if (!info?.isDirectory() || info.isSymbolicLink()) return;
    await chmod(entry, 0o700);
    for (const name of await readdir(entry)) await makeWritable(join(entry, name));
  };
  await makeWritable(path);
  await rm(path, { recursive: true, force: true });
}

/** Restore a displaced cache after a crash between the two publication renames. */
export async function reconcileDependencyStaging(workspacePath: string): Promise<void> {
  for (const name of await readdir(workspacePath)) {
    if (!/^dependency-dep_[A-Za-z0-9_-]{20,80}$/.test(name)) continue;
    const staging = join(workspacePath, name);
    if (!(await lstat(staging)).isDirectory() || await realpath(staging) !== resolve(staging)) throw new HarnessError('CONFLICT', 'Dependency staging path changed', 409);
    const markerPath = join(staging, 'publication.json');
    const markerInfo = await lstat(markerPath).catch((error: NodeJS.ErrnoException) => { if (error.code === 'ENOENT') return undefined; throw error; });
    if (markerInfo && (!markerInfo.isFile() || markerInfo.size > 1024)) throw new HarnessError('CONFLICT', 'Invalid dependency publication marker', 409);
    const marker = markerInfo ? await readFile(markerPath, 'utf8') : undefined;
    if (marker) {
      const value: unknown = JSON.parse(marker);
      const ecosystem = (value as { ecosystem?: unknown })?.ecosystem;
      if (ecosystem !== 'go' && ecosystem !== 'pnpm') throw new HarnessError('CONFLICT', 'Invalid dependency publication marker', 409);
      const root = join(workspacePath, ecosystem === 'go' ? 'cache' : 'tools');
      const target = ecosystem === 'go' ? join(root, 'go-mod') : join(root, 'pnpm', 'store');
      const parent = join(target, '..');
      if (await realpath(root) !== resolve(root)) throw new HarnessError('CONFLICT', 'Dependency recovery path changed', 409);
      const previous = join(staging, 'previous-cache');
      const old = await lstat(previous).catch((error: NodeJS.ErrnoException) => { if (error.code === 'ENOENT') return undefined; throw error; });
      const current = await lstat(target).catch((error: NodeJS.ErrnoException) => { if (error.code === 'ENOENT') return undefined; throw error; });
      if (old && !old.isDirectory() || current && !current.isDirectory()) throw new HarnessError('CONFLICT', 'Invalid dependency cache recovery entry', 409);
      // The marker precedes parent creation. A crash here is safe to clean when
      // nothing was displaced; if an old cache exists, reconstruct only its verified parent.
      let parentPath = await realpath(parent).catch((error: NodeJS.ErrnoException) => { if (error.code === 'ENOENT') return undefined; throw error; });
      if (!parentPath && old) {
        await mkdir(parent, { recursive: true });
        parentPath = await realpath(parent);
      }
      if (parentPath !== undefined && parentPath !== resolve(parent)) throw new HarnessError('CONFLICT', 'Dependency recovery path changed', 409);
      if (old && !current) await rename(previous, target);
    }
    await removeDependencyStaging(staging);
  }
}
