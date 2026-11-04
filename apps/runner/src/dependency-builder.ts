import { randomBytes } from 'node:crypto';
import { mkdir, readdir, lstat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { HarnessError } from '@cloud-harness/contracts';
import { runDocker } from './docker-engine.js';
import { EXECUTOR_HARDENING_ARGS, isSafeBindPath, removeContainerUntilGone } from './toolbox-runner.js';
import { DependencyCleanupError, type DependencyBuilderPort, type DependencyDownloadSpec } from './dependency-builder-port.js';
import { DEPENDENCY_PROXY_SCRIPT } from './dependency-proxy.js';

const IMAGE = /^sha256:[a-f0-9]{64}$/;
const NAME = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/;
const fail = (message: string) => new HarnessError('UNAVAILABLE', message, 503, false);
export const DEPENDENCY_DOWNLOAD_SCRIPT = String.raw`
const {spawn} = require('node:child_process');
const fs = require('node:fs');
const [ecosystem, maxText, timeoutText] = process.argv.slice(1);
const max = Number(maxText);
fs.mkdirSync('/job/cache', {recursive:true});
fs.mkdirSync('/tmp/input');
for (const name of fs.readdirSync('/input')) fs.copyFileSync('/input/' + name, '/tmp/input/' + name);
const command = ecosystem === 'go'
  ? 'go mod download all && cmp /input/go.mod go.mod && cmp /input/go.sum go.sum'
  : 'test "$(pnpm --version)" = 10.30.1 && pnpm fetch --frozen-lockfile --ignore-scripts --ignore-pnpmfile --config.manage-package-manager-versions=false --config.package-manager-strict=false --registry=https://registry.npmjs.org/ --store-dir=/job/cache/pnpm-store';
const child = spawn('/bin/sh', ['-eu', '-c', command], {cwd:'/tmp/input', stdio:'inherit', detached:true});
let stopped = false;
const stop = () => { stopped = true; try { process.kill(-child.pid, 'SIGKILL'); } catch {} };
// pnpm registers the temporary project with a symlink. Never follow it or publish it.
const projectRegistry = '/job/cache/pnpm-store/v10/projects';
function size(path) {
  let bytes = 0;
  for (const name of fs.readdirSync(path)) {
    const p = path+'/'+name, stat = fs.lstatSync(p);
    if (stat.isSymbolicLink()) {
      const target = require('node:path').resolve(path, fs.readlinkSync(p));
      if (ecosystem !== 'pnpm' || path !== projectRegistry || !/^[a-f0-9]+$/.test(name) || target !== '/tmp/input') throw Error('unsafe cache');
      bytes += stat.size;
    } else {
      if (!stat.isDirectory() && !stat.isFile()) throw Error('unsafe cache');
      bytes += stat.isDirectory() ? size(p) : stat.size;
    }
    if (bytes > max) throw Error('cache budget');
  }
  return bytes;
}
const interval = setInterval(() => {
  try { size('/job/cache'); } catch (error) {
    // Atomic cache writes may rename a file between readdir and lstat. The final scan is strict.
    if (error.code !== 'ENOENT') stop();
  }
}, 200);
const timer = setTimeout(stop, Number(timeoutText));
child.on('error', () => { stop(); clearInterval(interval); clearTimeout(timer); process.exitCode=1; });
child.on('exit', code => {
  clearInterval(interval); clearTimeout(timer);
  try {
    size('/job/cache');
    if (ecosystem === 'pnpm') fs.rmSync(projectRegistry, {recursive:true, force:true});
  } catch { stopped=true; }
  process.exitCode = stopped || code !== 0 ? 1 : 0;
});
`;

/** Arguments are exported so the no-workspace/no-credentials boundary is directly testable. */
export function dependencyHelperArgs(spec: DependencyDownloadSpec, name: string, network: string, proxyName: string, instanceId: string): string[] {
  if (!IMAGE.test(spec.imageId) || !isSafeBindPath(spec.stagingDir)) throw fail('invalid dependency staging or image');
  for (const mount of spec.toolMounts) {
    if (!isSafeBindPath(mount.source) || !/^\/opt\/chm-packages\/[A-Za-z0-9_-]+$/.test(mount.target)) throw fail('invalid dependency tool mount');
  }
  if (spec.binDirs.some(dir => !spec.toolMounts.some(mount => dir === `${mount.target}/bin`))) throw fail('invalid dependency tool PATH');
  const env = {
    HOME: '/tmp/home', XDG_CONFIG_HOME: '/tmp/home/.config',
    PATH: [...spec.binDirs, '/usr/local/go/bin', '/opt/go/bin', '/usr/local/bin', '/usr/bin', '/bin'].join(':'),
    HTTPS_PROXY: `http://${proxyName}:3128`, HTTP_PROXY: `http://${proxyName}:3128`, NO_PROXY: '',
    https_proxy: `http://${proxyName}:3128`, http_proxy: `http://${proxyName}:3128`, no_proxy: '',
    GOPROXY: 'https://proxy.golang.org', GOSUMDB: 'sum.golang.org', GOTOOLCHAIN: 'local', GOWORK: 'off',
    GOMODCACHE: '/job/cache/go-mod', GOCACHE: '/tmp/go-build', GOENV: 'off', GOPRIVATE: '', GONOPROXY: 'none', GONOSUMDB: 'none',
    npm_config_userconfig: '/dev/null', npm_config_globalconfig: '/dev/null', npm_config_registry: 'https://registry.npmjs.org/',
    npm_config_ignore_scripts: 'true', npm_config_ignore_pnpmfile: 'true', npm_config_manage_package_manager_versions: 'false',
    COREPACK_ENABLE_NETWORK: '0', COREPACK_ENABLE_PROJECT_SPEC: '0'
  };
  return ['create', '--pull', 'never', '--name', name, ...labels(instanceId), ...EXECUTOR_HARDENING_ARGS,
    '--network', network, '--workdir', '/tmp',
    '--mount', `type=bind,source=${spec.stagingDir},target=/job`,
    '--mount', `type=bind,source=${join(spec.stagingDir, 'input')},target=/input,readonly`,
    ...spec.toolMounts.flatMap(mount => ['--mount', `type=bind,source=${mount.source},target=${mount.target},readonly`]),
    ...Object.entries(env).flatMap(([key, value]) => ['--env', `${key}=${value}`]),
    '--entrypoint', 'node', spec.imageId, '-e', DEPENDENCY_DOWNLOAD_SCRIPT, spec.ecosystem, String(spec.maxBytes), String(spec.timeoutMs)];
}
function labels(instanceId: string): string[] {
  return ['--label', 'cloud-harness.role=dependency-download', '--label', 'cloud-harness.ephemeral=true', '--label', `cloud-harness.instance=${instanceId}`];
}
async function cacheSize(path: string, max: number): Promise<number> {
  let bytes = 0;
  for (const entry of await readdir(path)) {
    const child = join(path, entry), stat = await lstat(child);
    if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) throw fail('dependency cache contains unsupported files');
    bytes += stat.isDirectory() ? await cacheSize(child, max - bytes) : stat.size;
    if (bytes > max) throw fail('dependency cache exceeds byte budget');
  }
  return bytes;
}
export class DependencyBuilder implements DependencyBuilderPort {
  constructor(private readonly options: { executorImage: string; instanceId: string; network: string; proxy: string }) {
    const url = new URL(options.proxy);
    if (!NAME.test(options.instanceId) || !NAME.test(options.network) || url.protocol !== 'http:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) throw fail('invalid dependency downloader configuration');
  }
  /** Startup-only reconciliation, before this instance accepts new downloads. */
  async cleanupStale(): Promise<void> {
    const filters = ['--filter', 'label=cloud-harness.role=dependency-download', '--filter', 'label=cloud-harness.ephemeral=true', '--filter', `label=cloud-harness.instance=${this.options.instanceId}`];
    const containers = await runDocker(['ps', '-a', ...filters, '--format', '{{.Names}}'], { maxBytes: 65_536 });
    if (containers.exitCode !== 0 || containers.truncated) throw fail('dependency container inventory failed');
    for (const name of containers.stdout.trim().split('\n').filter(Boolean)) {
      if (!/^chm-dep(build|proxy)-[a-f0-9]{16}$/.test(name)) throw fail('unexpected managed dependency container');
      if (!(await removeContainerUntilGone(name))) throw fail('stale dependency container cleanup failed');
    }
    const networks = await runDocker(['network', 'ls', ...filters, '--format', '{{.Name}}'], { maxBytes: 65_536 });
    if (networks.exitCode !== 0 || networks.truncated) throw fail('dependency network inventory failed');
    for (const name of networks.stdout.trim().split('\n').filter(Boolean)) {
      if (!/^chm-depnet-[a-f0-9]{16}$/.test(name)) throw fail('unexpected managed dependency network');
      const result = await runDocker(['network', 'rm', name], { maxBytes: 4096 });
      if (result.exitCode !== 0) throw fail('stale dependency network cleanup failed');
    }
  }
  async imageId(): Promise<string> {
    const result = await runDocker(['image', 'inspect', '--format', '{{.Id}}', this.options.executorImage], { timeoutMs: 10_000, maxBytes: 1024 });
    const id = result.stdout.trim();
    if (result.exitCode !== 0 || !IMAGE.test(id)) throw fail('dependency executor image is unavailable');
    return id;
  }
  async download(spec: DependencyDownloadSpec): Promise<{ sizeBytes: number }> {
    if (!Number.isSafeInteger(spec.timeoutMs) || spec.timeoutMs < 1 || !Number.isSafeInteger(spec.maxBytes) || spec.maxBytes < 1) throw fail('invalid dependency download budget');
    const suffix = randomBytes(8).toString('hex'), network = `chm-depnet-${suffix}`, helper = `chm-depbuild-${suffix}`, proxy = `chm-depproxy-${suffix}`;
    const args = dependencyHelperArgs(spec, helper, network, proxy, this.options.instanceId);
    const allowed = spec.ecosystem === 'go' ? ['go.mod', 'go.sum'] : ['package.json', 'pnpm-lock.yaml', 'pnpm-workspace.yaml'];
    if (Object.keys(spec.manifests).some(name => !allowed.includes(name)) || !allowed.slice(0, 2).every(name => Object.hasOwn(spec.manifests, name))) throw fail('invalid dependency manifests');
    if (spec.signal?.aborted) throw new HarnessError('CANCELLED', 'dependency download cancelled', 499, false);
    await mkdir(join(spec.stagingDir, 'input'), { mode: 0o755 });
    for (const [name, content] of Object.entries(spec.manifests)) await writeFile(join(spec.stagingDir, 'input', name), content, { mode: 0o644, flag: 'wx' });
    const deadline = Date.now() + spec.timeoutMs;
    let uncertainCreation = false;
    const docker = async (argv: string[], interruptible = true) => {
      const remaining = deadline - Date.now();
      if (remaining <= 0) throw new HarnessError('TIMEOUT', 'dependency download timed out', 504, true);
      // A job deadline must not interrupt Docker create: the daemon may finish after its CLI dies.
      // If the independent creation bound itself expires, retain staging for startup reconciliation.
      const result = await runDocker(argv, { timeoutMs: interruptible ? Math.min(remaining, 30_000) : 30_000, maxBytes: 65_536, ...(interruptible && spec.signal ? { signal: spec.signal } : {}) }).catch((error: unknown) => {
        if (!interruptible) uncertainCreation = true;
        throw error;
      });
      if (result.exitCode !== 0 || result.truncated) throw fail('dependency download container operation failed');
      return result;
    };
    try {
      await docker(['network', 'create', '--internal', ...labels(this.options.instanceId), network], false);
      await docker(['create', '--pull', 'never', '--name', proxy, ...labels(this.options.instanceId), ...EXECUTOR_HARDENING_ARGS,
        '--network', this.options.network, '--entrypoint', 'node', spec.imageId, '-e', DEPENDENCY_PROXY_SCRIPT,
        spec.ecosystem, this.options.proxy, String(spec.maxBytes), String(Math.max(1, deadline - Date.now()))], false);
      await docker(['network', 'connect', '--alias', proxy, network, proxy], false);
      await docker(['start', proxy]);
      // Probe the listener inside its own network namespace; never publish a host port.
      await docker(['exec', proxy, 'node', '-e', "const net=require('net');let n=0;function check(){const s=net.connect(3128,'127.0.0.1',()=>{s.destroy();process.exit(0)});s.on('error',()=>{if(++n>50)process.exit(1);setTimeout(check,100)})}check()"]);
      await docker(args, false);
      if (spec.signal?.aborted) throw new HarnessError('CANCELLED', 'dependency download cancelled', 499, false);
      const result = await runDocker(['start', '--attach', helper], { timeoutMs: Math.max(1, deadline - Date.now()), maxBytes: 65_536, ...(spec.signal ? { signal: spec.signal } : {}) });
      if (result.exitCode !== 0 || result.truncated) throw fail('dependency download failed');
    } finally {
      await cleanupDownload(helper, proxy, network, uncertainCreation);
    }
    return { sizeBytes: await cacheSize(join(spec.stagingDir, 'cache'), spec.maxBytes) };
  }
}

async function cleanupDownload(helper: string, proxy: string, network: string, uncertainCreation: boolean): Promise<void> {
  try {
    const removed = await Promise.all([removeContainerUntilGone(helper), removeContainerUntilGone(proxy)]);
    const net = await runDocker(['network', 'rm', network], { timeoutMs: 30_000, maxBytes: 4096 });
    if (uncertainCreation || removed.some(value => !value) || (net.exitCode !== 0 && !/not found|No such network/i.test(net.stderr))) throw new DependencyCleanupError();
  } catch {
    throw new DependencyCleanupError();
  }
}
