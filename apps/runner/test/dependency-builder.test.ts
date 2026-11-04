import { afterEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runDocker } from '../src/docker-engine.js';
import type * as ToolboxRunner from '../src/toolbox-runner.js';
import { removeContainerUntilGone } from '../src/toolbox-runner.js';
import { DependencyBuilder, dependencyHelperArgs, DEPENDENCY_DOWNLOAD_SCRIPT } from '../src/dependency-builder.js';
import { DependencyCleanupError, type DependencyDownloadSpec } from '../src/dependency-builder-port.js';
const spec: DependencyDownloadSpec = { id: 'job', imageId: `sha256:${'a'.repeat(64)}`, ecosystem: 'go', manifests: {}, stagingDir: '/staging/job', timeoutMs: 1000, maxBytes: 1000, toolMounts: [], binDirs: [] };
describe('dependency helper boundary', () => {
  it('mounts staging only, pins the image, and restricts Go resolution', () => {
    const args = dependencyHelperArgs(spec, 'helper', 'internal-job', 'proxy', 'instance');
    expect(args).toContain('GOPROXY=https://proxy.golang.org');
    expect(args).toContain('GOTOOLCHAIN=local');
    expect(args).toContain('GOWORK=off');
    expect(args).toContain('10001:10001');
    expect(args).toContain('--read-only');
    expect(args).toContain('internal-job');
    expect(args.filter((_, i) => args[i - 1] === '--mount')).toEqual(['type=bind,source=/staging/job,target=/job', 'type=bind,source=/staging/job/input,target=/input,readonly']);
    expect(args).not.toContain('--env-file');
    expect(DEPENDENCY_DOWNLOAD_SCRIPT).toContain('cmp /input/go.sum go.sum');
  });
  it('disables package scripts, hooks, and automatic package-manager downloads', () => {
    expect(DEPENDENCY_DOWNLOAD_SCRIPT).toContain('pnpm fetch --frozen-lockfile --ignore-scripts --ignore-pnpmfile');
    expect(DEPENDENCY_DOWNLOAD_SCRIPT).toContain('manage-package-manager-versions=false');
    expect(DEPENDENCY_DOWNLOAD_SCRIPT).toContain('10.30.1');
    expect(DEPENDENCY_DOWNLOAD_SCRIPT).toContain('process.kill(-child.pid');
  });
  it('rejects mount and PATH injection', () => {
    expect(() => dependencyHelperArgs({ ...spec, stagingDir: '/tmp/a,readonly' }, 'h', 'n', 'p', 'i')).toThrow();
    expect(() => dependencyHelperArgs({ ...spec, toolMounts: [{ source: '/tools', target: '/usr/bin' }] }, 'h', 'n', 'p', 'i')).toThrow();
    expect(() => dependencyHelperArgs({ ...spec, binDirs: ['/workspace/bin'] }, 'h', 'n', 'p', 'i')).toThrow();
  });
});

vi.mock('../src/docker-engine.js', () => ({ runDocker: vi.fn() }));
vi.mock('../src/toolbox-runner.js', async importOriginal => ({ ...(await importOriginal<typeof ToolboxRunner>()), removeContainerUntilGone: vi.fn() }));
const directories: string[] = [];
afterEach(async () => { vi.resetAllMocks(); for (const directory of directories.splice(0)) await rm(directory, { recursive: true, force: true }); });
it.each(['failed', 'timeout'])('removes exact helper, proxy and internal network after %s download', async failure => {
  const stagingDir = await mkdtemp(join(tmpdir(), 'dependency-test-')); directories.push(stagingDir);
  vi.mocked(removeContainerUntilGone).mockResolvedValue(true);
  vi.mocked(runDocker).mockImplementation(async args => {
    if (args[0] === 'start' && args[1] === '--attach') {
      if (failure === 'timeout') throw new Error('timeout');
      return { stdout: '', stderr: '', exitCode: 1, truncated: false };
    }
    return { stdout: '', stderr: '', exitCode: 0, truncated: false };
  });
  const builder = new DependencyBuilder({ executorImage: 'executor', instanceId: 'instance', network: 'provisioning', proxy: 'http://proxy:3128' });
  await expect(builder.download({ ...spec, stagingDir, manifests: { 'go.mod': 'module test', 'go.sum': '' } })).rejects.toThrow();
  const removed = vi.mocked(removeContainerUntilGone).mock.calls.map(call => call[0]);
  expect(removed).toHaveLength(2);
  expect(removed[0]).toMatch(/^chm-depbuild-[a-f0-9]{16}$/);
  expect(removed[1]).toMatch(/^chm-depproxy-[a-f0-9]{16}$/);
  const calls = vi.mocked(runDocker).mock.calls.map(call => call[0]);
  expect(calls.find(args => args[0] === 'network' && args[1] === 'create')).toContain('--internal');
  expect(calls.at(-1)?.slice(0, 2)).toEqual(['network', 'rm']);
  expect(calls.at(-1)?.[2]).toMatch(/^chm-depnet-[a-f0-9]{16}$/);
});

it.each(['unconfirmed', 'rejected'])('signals staging retention when cleanup is %s', async failure => {
  const stagingDir = await mkdtemp(join(tmpdir(), 'dependency-test-')); directories.push(stagingDir);
  if (failure === 'rejected') vi.mocked(removeContainerUntilGone).mockRejectedValue(new Error('daemon unavailable'));
  else vi.mocked(removeContainerUntilGone).mockResolvedValue(false);
  vi.mocked(runDocker).mockResolvedValue({ stdout: '', stderr: '', exitCode: 0, truncated: false });
  const builder = new DependencyBuilder({ executorImage: 'executor', instanceId: 'instance', network: 'provisioning', proxy: 'http://proxy:3128' });
  await expect(builder.download({ ...spec, stagingDir, manifests: { 'go.mod': 'module test', 'go.sum': '' } })).rejects.toBeInstanceOf(DependencyCleanupError);
});
