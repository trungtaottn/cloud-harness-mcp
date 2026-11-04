import { randomBytes } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { DependencyBuilder } from '../../apps/runner/src/dependency-builder.js';
import type { DependencyDownloadSpec } from '../../apps/runner/src/dependency-builder-port.js';
import { removeContainer, runDocker } from '../../apps/runner/src/docker-engine.js';
import { EXECUTOR_HARDENING_ARGS } from '../../apps/runner/src/toolbox-runner.js';
import { dockerPrerequisiteIssue, requireDockerPrerequisites } from '../agent-docker-test-support.js';

// Opt-in real public-registry smoke test. Supply a verified pnpm 10.30.1 release mount;
// no workspace, user-tool tree, runtime credentials, or production network is used.
const image = process.env.EXECUTOR_IMAGE ?? 'cloud-harness-executor:local';
const toolSource = process.env.DEPENDENCY_TEST_PNPM_SOURCE;
const toolTarget = process.env.DEPENDENCY_TEST_PNPM_TARGET;
const issue = process.env.DEPENDENCY_TEST_PUBLIC_REGISTRIES !== '1' ? 'public registry smoke test is not enabled'
  : !toolSource || !toolTarget ? 'verified pnpm release mount is required' : dockerPrerequisiteIssue([image]);
// The registry smoke fixture is an explicit operator opt-in, including in the
// general required-Docker gate; once selected, missing prerequisites are fatal.
if (process.env.DEPENDENCY_TEST_PUBLIC_REGISTRIES === '1') requireDockerPrerequisites(issue);
const instanceId = `deptest-${randomBytes(6).toString('hex')}`;
const provisionNetwork = `${instanceId}-internal`, egressNetwork = `${instanceId}-egress`, upstream = `${instanceId}-proxy`;
const names = new Set<string>();
let root = '', imageId = '';
let builder: DependencyBuilder;
let goManifests: Record<string, string>, pnpmManifests: Record<string, string>;
const toolMounts = toolSource && toolTarget ? [{ source: toolSource, target: toolTarget }] : [];
const binDirs = toolTarget ? [`${toolTarget}/bin`] : [];

async function docker(args: string[], timeoutMs = 30_000) {
  const result = await runDocker(args, { timeoutMs, maxBytes: 65_536 });
  if (result.exitCode !== 0 || result.truncated) throw new Error(`Docker fixture failed (${args[0]}): ${result.stderr || result.stdout}`);
  return result;
}
async function fixtureCommand(command: string, mounts: string[] = [], env: string[] = []) {
  const name = `${instanceId}-${randomBytes(4).toString('hex')}`; names.add(name);
  try {
    return await docker(['run', '--rm', '--pull', 'never', '--name', name, ...EXECUTOR_HARDENING_ARGS,
      '--network', 'none', ...mounts.flatMap(value => ['--mount', value]), ...env.flatMap(value => ['--env', value]),
      '--entrypoint', '/bin/sh', imageId, '-eu', '-c', command], 120_000);
  } finally { await removeContainer(name); names.delete(name); }
}
async function staging(ecosystem: 'go' | 'pnpm', overrides: Partial<DependencyDownloadSpec> = {}): Promise<DependencyDownloadSpec> {
  const stagingDir = join(root, randomBytes(4).toString('hex'));
  await mkdir(stagingDir); await chmod(stagingDir, 0o777);
  // The host test runner is unprivileged; allow it to write the manifest snapshot while
  // preserving the downloader's actual UID ownership and no-root execution contract.
  const name = `${instanceId}-own-${randomBytes(4).toString('hex')}`; names.add(name);
  try { await docker(['run', '--rm', '--pull', 'never', '--name', name, '--network', 'none', '--user', '0:0', '--read-only', '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--mount', `type=bind,source=${stagingDir},target=/fixture`, '--entrypoint', 'chown', imageId, '10001:10001', '/fixture']); }
  finally { await removeContainer(name); names.delete(name); }
  return { id: randomBytes(8).toString('hex'), imageId, ecosystem, manifests: ecosystem === 'go' ? goManifests : pnpmManifests,
    stagingDir, timeoutMs: 90_000, maxBytes: 20 * 1024 * 1024, toolMounts: ecosystem === 'pnpm' ? toolMounts : [], binDirs: ecosystem === 'pnpm' ? binDirs : [], ...overrides };
}
async function assertNoJobs() {
  const filters = ['--filter', `label=cloud-harness.instance=${instanceId}`, '--format', '{{.Names}}'];
  expect((await docker(['ps', '-a', ...filters])).stdout.trim()).toBe('');
  expect((await docker(['network', 'ls', '--filter', `label=cloud-harness.instance=${instanceId}`, '--format', '{{.Name}}'])).stdout.trim()).toBe('');
}
beforeAll(async () => {
  if (issue) return;
  root = await mkdtemp(join(tmpdir(), 'chm-dependencies-')); await chmod(root, 0o755);
  imageId = (await docker(['image', 'inspect', '--format', '{{.Id}}', image])).stdout.trim();
  expect(imageId).toMatch(/^sha256:[a-f0-9]{64}$/);
  const proxyCode = await readFile(new URL('../../deploy/provisioning-proxy.mjs', import.meta.url), 'utf8');
  await docker(['network', 'create', '--internal', provisionNetwork]);
  await docker(['network', 'create', egressNetwork]);
  names.add(upstream);
  await docker(['create', '--pull', 'never', '--name', upstream, ...EXECUTOR_HARDENING_ARGS, '--network', provisionNetwork,
    '--env', 'ALLOWED_HOSTS=proxy.golang.org,sum.golang.org,storage.googleapis.com,registry.npmjs.org',
    '--entrypoint', 'node', imageId, '--input-type=module', '-e', proxyCode]);
  await docker(['network', 'connect', egressNetwork, upstream]); await docker(['start', upstream]);
  await docker(['exec', upstream, 'node', '-e', "let n=0;function check(){const s=require('net').connect(3128,'127.0.0.1',()=>{s.destroy();process.exit(0)});s.on('error',()=>{if(++n>50)process.exit(1);setTimeout(check,100)})}check()"]);
  builder = new DependencyBuilder({ executorImage: image, instanceId, network: provisionNetwork, proxy: `http://${upstream}:3128` });
  const sumResponse = await fetch('https://sum.golang.org/lookup/github.com/google/uuid@v1.6.0', { signal: AbortSignal.timeout(15_000) });
  expect(sumResponse.ok).toBe(true);
  const sums = (await sumResponse.text()).split('\n').filter(line => /^github.com\/google\/uuid v1\.6\.0(?:\/go.mod)? h1:/.test(line));
  expect(sums).toHaveLength(2);
  goManifests = { 'go.mod': 'module fixture.test/offline\n\ngo 1.23.0\n\nrequire github.com/google/uuid v1.6.0\n', 'go.sum': `${sums.join('\n')}\n` };
  const metadataResponse = await fetch('https://registry.npmjs.org/is-number/7.0.0', { signal: AbortSignal.timeout(15_000) });
  expect(metadataResponse.ok).toBe(true);
  const metadata = await metadataResponse.json() as { dist: { integrity: string } };
  expect(metadata.dist.integrity).toMatch(/^sha512-[A-Za-z0-9+/=]+$/);
  pnpmManifests = { 'package.json': JSON.stringify({ name: 'offline-fixture', version: '1.0.0', packageManager: 'pnpm@10.30.1', scripts: { preinstall: 'touch /job/lifecycle-ran' }, dependencies: { 'is-number': '7.0.0' } }),
    'pnpm-lock.yaml': `lockfileVersion: '9.0'\nsettings:\n  autoInstallPeers: true\n  excludeLinksFromLockfile: false\nimporters:\n  .:\n    dependencies:\n      is-number:\n        specifier: 7.0.0\n        version: 7.0.0\npackages:\n  is-number@7.0.0:\n    resolution: {integrity: ${metadata.dist.integrity}}\n    engines: {node: '>=0.12.0'}\nsnapshots:\n  is-number@7.0.0: {}\n` };
}, 90_000);
afterAll(async () => {
  if (issue) return;
  if (builder) await builder.cleanupStale();
  for (const name of names) await removeContainer(name);
  await runDocker(['network', 'rm', provisionNetwork, egressNetwork], { timeoutMs: 30_000 });
  if (root) {
    const name = `${instanceId}-cleanup`;
    try { await docker(['run', '--rm', '--pull', 'never', '--name', name, '--network', 'none', '--user', '0:0', '--read-only', '--cap-drop', 'ALL', '--cap-add', 'DAC_OVERRIDE', '--mount', `type=bind,source=${root},target=/fixture`, '--entrypoint', '/bin/sh', imageId, '-eu', '-c', 'rm -rf -- /fixture/*']); }
    finally { await removeContainer(name); }
    await rm(root, { recursive: true, force: true });
  }
}, 90_000);

describe.skipIf(issue !== undefined)('approved dependency downloads in Docker', { timeout: 180_000 }, () => {
  it('downloads Go modules and compiles their importer with network none', async () => {
    const spec = await staging('go');
    const result = await builder.download(spec);
    expect(result.sizeBytes).toBeGreaterThan(0); expect(result.sizeBytes).toBeLessThan(spec.maxBytes);
    expect(await readFile(join(spec.stagingDir, 'input/go.mod'), 'utf8')).toBe(goManifests['go.mod']);
    expect(await readFile(join(spec.stagingDir, 'input/go.sum'), 'utf8')).toBe(goManifests['go.sum']);
    const output = await fixtureCommand("mkdir /tmp/project; cp /input/* /tmp/project/; printf '%s\\n' 'package main' 'import (\"fmt\"; \"github.com/google/uuid\")' 'func main(){fmt.Print(uuid.Nil.String())}' > /tmp/project/main.go; cd /tmp/project; go run .", [
      `type=bind,source=${join(spec.stagingDir, 'input')},target=/input,readonly`, `type=bind,source=${join(spec.stagingDir, 'cache/go-mod')},target=/go-mod`
    ], ['GOMODCACHE=/go-mod', 'GOCACHE=/tmp/go-build', 'GOPROXY=off', 'GOSUMDB=off', 'GOTOOLCHAIN=local', 'GOWORK=off', 'GOENV=off']);
    expect(output.stdout).toContain('00000000-0000-0000-0000-000000000000'); await assertNoJobs();
  });
  it('fetches pnpm dependencies without scripts and installs from the cache offline', async () => {
    const spec = await staging('pnpm');
    const result = await builder.download(spec);
    expect(result.sizeBytes).toBeGreaterThan(0); expect(result.sizeBytes).toBeLessThan(spec.maxBytes);
    await expect(readFile(join(spec.stagingDir, 'cache/pnpm-store/v10/projects'))).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(readFile(join(spec.stagingDir, 'lifecycle-ran'))).rejects.toMatchObject({ code: 'ENOENT' });
    const output = await fixtureCommand('mkdir /tmp/project; cp /input/* /tmp/project/; cd /tmp/project; pnpm install --offline --frozen-lockfile --ignore-scripts --ignore-pnpmfile --config.manage-package-manager-versions=false --store-dir=/store; node -e "if (!require(\'is-number\')(42)) process.exit(1); console.log(\'offline-pnpm-ok\')"', [
      `type=bind,source=${join(spec.stagingDir, 'input')},target=/input,readonly`, `type=bind,source=${join(spec.stagingDir, 'cache/pnpm-store')},target=/store`, ...toolMounts.map(mount => `type=bind,source=${mount.source},target=${mount.target},readonly`)
    ], [`PATH=${binDirs.join(':')}:/usr/local/bin:/usr/bin:/bin`, 'HOME=/tmp/home', 'npm_config_userconfig=/dev/null', 'npm_config_manage_package_manager_versions=false']);
    expect(output.stdout).toContain('offline-pnpm-ok'); await assertNoJobs();
  });
  it('rejects a transfer over its byte budget and removes all job resources', async () => {
    await expect(builder.download(await staging('go', { maxBytes: 64 }))).rejects.toThrow(); await assertNoJobs();
  });
  it('cleans up after a deadline expires', async () => {
    await expect(builder.download(await staging('go', { timeoutMs: 250 }))).rejects.toThrow(); await assertNoJobs();
  });
});
