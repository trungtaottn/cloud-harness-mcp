import type * as FsPromises from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink, chmod, lstat, rename } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { DependenciesPlanInput } from '@cloud-harness/contracts';
import { DependencyService, measureCache, reconcileDependencyStaging, removeDependencyStaging } from '../src/dependency-service.js';
import { DependencyStore } from '../src/dependency-store.js';
import { DependencyCleanupError, type DependencyDownloadSpec } from '../src/dependency-builder-port.js';

vi.mock('node:fs/promises', async (importOriginal) => {
  const original = await importOriginal<typeof FsPromises>();
  return { ...original, rename: vi.fn(original.rename) };
});

const cleanup: Array<() => Promise<void>> = [];
afterEach(async () => { for (const close of cleanup.splice(0)) await close(); });
const workspaceId = 'ws_abcdefghijklmnopqrst' as DependenciesPlanInput['workspaceId'];
async function setup() {
  const root = await mkdtemp(join(tmpdir(), 'chm-dependency-service-'));
  const database = new DatabaseSync(':memory:');
  const paths = { repositoryRoot: join(root, 'repo'), toolsPath: join(root, 'tools'), cachePath: join(root, 'cache') };
  for (const path of Object.values(paths)) await mkdir(path);
  await writeFile(join(paths.repositoryRoot, 'go.mod'), 'module example.com/test\n\ngo 1.26.0\n');
  await writeFile(join(paths.repositoryRoot, 'go.sum'), '');
  const builder = {
    imageId: vi.fn(async () => `sha256:${'a'.repeat(64)}`),
    download: vi.fn(async (spec: DependencyDownloadSpec) => {
      await mkdir(join(spec.stagingDir, 'cache', 'go-mod'), { recursive: true });
      await writeFile(join(spec.stagingDir, 'cache', 'go-mod', 'downloaded'), 'verified');
      return { sizeBytes: 8 };
    })
  };
  const store = new DependencyStore(database);
  let maxWorkspaceBytes = 100_000;
  const service = new DependencyService({ store, builder, enabled: true, approvalAvailable: true,
    timeoutMs: 10000, maxBytes: 10000, prepareDirectory: async () => {},
    withWorkspace: async (_owner, id, action) => {
      expect(id).toBe(workspaceId);
      return action({ ...paths, workspacePath: root, maxWorkspaceBytes, minFreeBytes: 0,
        toolMounts: [], binDirs: [], profileDigest: 'profile', paused: async (fn) => fn(), assertCurrent: () => {} });
    }
  });
  cleanup.push(async () => { await service.shutdown(); database.close(); await rm(root, { recursive: true, force: true }); });
  const plan = () => service.plan('owner', { workspaceId, ecosystem: 'go', directory: '.' });
  return { root, paths, builder, store, service, plan, quota: (n: number) => { maxWorkspaceBytes = n; } };
}
describe('approved dependency cache service', () => {
  it('performs no network until approval, imports cache and replays without another download', async () => {
    const f = await setup(); const plan = await f.plan();
    expect(f.builder.download).not.toHaveBeenCalled();
    const input = { workspaceId, planId: plan.planId, planDigest: plan.planDigest };
    await expect(f.service.apply('owner', input)).rejects.toThrow('Approve');
    f.service.approve('owner', input);
    await f.service.apply('owner', input);
    await vi.waitFor(() => expect(f.service.status('owner', workspaceId, plan.planId).plans[0]?.state).toBe('SUCCEEDED'));
    expect(await readFile(join(f.paths.cachePath, 'go-mod', 'downloaded'), 'utf8')).toBe('verified');
    await f.service.apply('owner', input);
    expect(f.builder.download).toHaveBeenCalledTimes(1);
    await expect(f.service.apply('other', input)).rejects.toThrow('not found');
  });
  it('rejects changed manifests before consuming approval or downloading', async () => {
    const f = await setup(); const plan = await f.plan(); f.service.approve('owner', plan);
    await writeFile(join(f.paths.repositoryRoot, 'go.mod'), 'module example.com/changed\n\ngo 1.26.0\n');
    await expect(f.service.apply('owner', { workspaceId, planId: plan.planId, planDigest: plan.planDigest })).rejects.toThrow('changed');
    expect(f.builder.download).not.toHaveBeenCalled();
    expect(f.store.get('owner', plan.planId).view.state).toBe('APPROVED');
  });
  it('leaves prior cache intact when downloads fail and never retries a consumed approval', async () => {
    const f = await setup(); await mkdir(join(f.paths.cachePath, 'go-mod')); await writeFile(join(f.paths.cachePath, 'go-mod', 'old'), 'retained');
    f.builder.download.mockRejectedValue(new Error('download unavailable'));
    const plan = await f.plan(); f.service.approve('owner', plan); const input = { workspaceId, planId: plan.planId, planDigest: plan.planDigest };
    await f.service.apply('owner', input);
    await vi.waitFor(() => expect(f.store.get('owner', plan.planId).view.state).toBe('FAILED'));
    expect(await readFile(join(f.paths.cachePath, 'go-mod', 'old'), 'utf8')).toBe('retained');
    await f.service.apply('owner', input); expect(f.builder.download).toHaveBeenCalledTimes(1);
  });
  it('refuses symlink cache output', async () => {
    const f = await setup(); const dir = join(f.root, 'unsafe'); await mkdir(dir); await symlink('/etc/passwd', join(dir, 'link'));
    await expect(measureCache(dir, 10000, true)).rejects.toThrow('unsafe');
  });
});


describe('dependency publication and recovery', () => {
  const stagingName = 'dependency-dep_abcdefghijklmnopqrst';
  async function recoveryFixture(ecosystem: 'go' | 'pnpm' = 'go') {
    const f = await setup();
    const staging = join(f.root, stagingName);
    await mkdir(staging);
    await writeFile(join(staging, 'publication.json'), JSON.stringify({ ecosystem }));
    const target = ecosystem === 'go' ? join(f.paths.cachePath, 'go-mod') : join(f.paths.toolsPath, 'pnpm', 'store');
    return { ...f, staging, target };
  }
  it('removes owned read-only cache directories without following symlinks', async () => {
    const f = await setup(); const staging = join(f.root, stagingName); const nested = join(staging, 'cache', 'module');
    await mkdir(nested, { recursive: true }); await writeFile(join(nested, 'go.mod'), 'cached');
    await symlink(f.paths.repositoryRoot, join(nested, 'outside'));
    await chmod(nested, 0o555); await chmod(join(staging, 'cache'), 0o555);
    await removeDependencyStaging(staging);
    await expect(lstat(staging)).rejects.toMatchObject({ code: 'ENOENT' });
    expect(await readFile(join(f.paths.repositoryRoot, 'go.mod'), 'utf8')).toContain('module');
  });
  it('restores the old cache after a crash between publication renames', async () => {
    const f = await recoveryFixture(); const previous = join(f.staging, 'previous-cache');
    await mkdir(previous); await writeFile(join(previous, 'old'), 'retained');
    await mkdir(join(f.staging, 'cache', 'go-mod'), { recursive: true });
    await reconcileDependencyStaging(f.root);
    expect(await readFile(join(f.target, 'old'), 'utf8')).toBe('retained');
    await expect(lstat(f.staging)).rejects.toMatchObject({ code: 'ENOENT' });
  });
  it('preserves the published cache after a crash following both renames', async () => {
    const f = await recoveryFixture(); await mkdir(join(f.staging, 'previous-cache'));
    await writeFile(join(f.staging, 'previous-cache', 'old'), 'old');
    await mkdir(f.target); await writeFile(join(f.target, 'new'), 'published');
    await reconcileDependencyStaging(f.root);
    expect(await readFile(join(f.target, 'new'), 'utf8')).toBe('published');
    await expect(lstat(f.staging)).rejects.toMatchObject({ code: 'ENOENT' });
  });
  it('cleans a marker written before pnpm parent creation without losing a displaced cache', async () => {
    const f = await recoveryFixture('pnpm');
    await reconcileDependencyStaging(f.root);
    await expect(lstat(f.staging)).rejects.toMatchObject({ code: 'ENOENT' });
    await mkdir(f.staging); await writeFile(join(f.staging, 'publication.json'), '{"ecosystem":"pnpm"}');
    await mkdir(join(f.staging, 'previous-cache')); await writeFile(join(f.staging, 'previous-cache', 'old'), 'retained');
    await reconcileDependencyStaging(f.root);
    expect(await readFile(join(f.target, 'old'), 'utf8')).toBe('retained');
  });
  it('retains staging when publication and rollback both fail, then recovers the prior cache', async () => {
    const f = await setup(); const old = join(f.paths.cachePath, 'go-mod');
    await mkdir(old); await writeFile(join(old, 'old'), 'retained');
    const actual = await vi.importActual<typeof FsPromises>('node:fs/promises');
    vi.mocked(rename).mockImplementationOnce(actual.rename)
      .mockRejectedValueOnce(new Error('publication failed'))
      .mockRejectedValueOnce(new Error('rollback failed'));
    const plan = await f.plan(); f.service.approve('owner', plan);
    await f.service.apply('owner', { workspaceId, planId: plan.planId, planDigest: plan.planDigest });
    await vi.waitFor(() => expect(f.store.get('owner', plan.planId).view.state).toBe('FAILED'));
    const staging = join(f.root, `dependency-${plan.planId}`);
    expect(await readFile(join(staging, 'previous-cache', 'old'), 'utf8')).toBe('retained');
    await reconcileDependencyStaging(f.root);
    expect(await readFile(join(old, 'old'), 'utf8')).toBe('retained');
  });
  it('refuses recovery through a symlink parent and retains the previous cache', async () => {
    const f = await recoveryFixture('pnpm');
    await mkdir(join(f.staging, 'previous-cache')); await writeFile(join(f.staging, 'previous-cache', 'old'), 'retained');
    await symlink(f.paths.repositoryRoot, join(f.paths.toolsPath, 'pnpm'));
    await expect(reconcileDependencyStaging(f.root)).rejects.toThrow('path changed');
    expect(await readFile(join(f.staging, 'previous-cache', 'old'), 'utf8')).toBe('retained');
  });
  it('retains staging when helper termination cannot be confirmed', async () => {
    const f = await setup(); f.builder.download.mockRejectedValue(new DependencyCleanupError());
    const plan = await f.plan(); f.service.approve('owner', plan);
    await f.service.apply('owner', { workspaceId, planId: plan.planId, planDigest: plan.planDigest });
    await vi.waitFor(() => expect(f.store.get('owner', plan.planId).view.state).toBe('FAILED'));
    expect((await lstat(join(f.root, `dependency-${plan.planId}`))).isDirectory()).toBe(true);
  });
  it('rejects invalid UTF-8 before creating a plan', async () => {
    const f = await setup(); await writeFile(join(f.paths.repositoryRoot, 'go.mod'), Buffer.from([0xc3, 0x28]));
    await expect(f.plan()).rejects.toThrow('valid UTF-8');
    expect(f.store.list('owner')).toEqual([]); expect(f.builder.download).not.toHaveBeenCalled();
  });
  it('refuses an expired approval before starting a download', async () => {
    const f = await setup(); const plan = await f.plan(); f.service.approve('owner', plan);
    const clock = vi.spyOn(Date, 'now').mockReturnValue(plan.expiresAt + 1);
    try {
      await expect(f.service.apply('owner', { workspaceId, planId: plan.planId, planDigest: plan.planDigest })).rejects.toMatchObject({ code: 'EXPIRED' });
      expect(f.builder.download).not.toHaveBeenCalled();
    } finally { clock.mockRestore(); }
  });
  it('keeps the previous cache when importing would exceed the workspace quota', async () => {
    const f = await setup(); await mkdir(join(f.paths.cachePath, 'go-mod')); await writeFile(join(f.paths.cachePath, 'go-mod', 'old'), 'retained');
    const plan = await f.plan(); f.service.approve('owner', plan);
    const currentBytes = (await Promise.all(Object.values(f.paths).map((path) => measureCache(path, 100_000, false)))).reduce((a, b) => a + b, 0);
    f.quota(currentBytes + 1);
    await f.service.apply('owner', { workspaceId, planId: plan.planId, planDigest: plan.planDigest });
    await vi.waitFor(() => expect(f.store.get('owner', plan.planId).view.state).toBe('FAILED'));
    expect(f.store.get('owner', plan.planId).view.error).toContain('limit');
    expect(await readFile(join(f.paths.cachePath, 'go-mod', 'old'), 'utf8')).toBe('retained');
  });
  it('preserves prior cache when manifests change during download', async () => {
    const f = await setup(); await mkdir(join(f.paths.cachePath, 'go-mod')); await writeFile(join(f.paths.cachePath, 'go-mod', 'old'), 'retained');
    f.builder.download.mockImplementation(async (spec) => {
      await mkdir(join(spec.stagingDir, 'cache', 'go-mod'), { recursive: true });
      await writeFile(join(f.paths.repositoryRoot, 'go.mod'), 'module example.org/changed\n');
      return { sizeBytes: 0 };
    });
    const plan = await f.plan(); f.service.approve('owner', plan);
    await f.service.apply('owner', { workspaceId, planId: plan.planId, planDigest: plan.planDigest });
    await vi.waitFor(() => expect(f.store.get('owner', plan.planId).view.state).toBe('FAILED'));
    expect(await readFile(join(f.paths.cachePath, 'go-mod', 'old'), 'utf8')).toBe('retained');
  });
});
