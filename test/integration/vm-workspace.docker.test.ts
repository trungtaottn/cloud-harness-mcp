import { mkdirSync, mkdtempSync, writeFileSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { TerminalReadResultSchema, type RunnerConfig } from '@cloud-harness/contracts';
import { StateStore, type WorkspaceRecord } from '../../apps/runner/src/state-store.js';
import { WorkspaceService } from '../../apps/runner/src/workspace-service.js';
import { inspectContainer, removeContainer, runDocker } from '../../apps/runner/src/docker-engine.js';
import { removeTreeAsRoot } from './package-registry-fixture.js';

const image = process.env.EXECUTOR_IMAGE ?? 'cloud-harness-executor:local';
const enabled = process.env.TEST_KATA === '1';
let directory: string;
let store: StateStore;
let service: WorkspaceService;
let record: WorkspaceRecord;
let container: string | undefined;

async function command(command: string) {
  const result = await service.execute(record.ownerId, 'exec_run', { workspaceId: record.id, command, timeoutMs: 120_000 });
  expect(result.ok, JSON.stringify(result)).toBe(true);
  expect((result.data as { exitCode: number }).exitCode, JSON.stringify(result)).toBe(0);
  return result;
}

beforeAll(async () => {
  if (!enabled) return;
  directory = mkdtempSync(join(tmpdir(), 'ch-vm-workspace-'));
  const jobsRoot = join(directory, 'jobs');
  mkdirSync(jobsRoot);
  const config = {
    jobsRoot, stateDb: join(directory, 'state.db'), executorImage: image, executorKind: 'kata',
    vmMemoryMiB: 2048, vmCpus: 2, networkProfile: 'dependency-access',
    idleTtlSeconds: 3600, wallTtlSeconds: 14400, reaperIntervalSeconds: 60,
    maxWorkspaceBytes: 10 * 1024 ** 3, minFreeBytes: 0, maxOutputBytes: 262144,
    allowedGitHosts: ['github.com'], maxActiveWorkspacesPerOwner: 1
  } as RunnerConfig;
  store = new StateStore(config.stateDb);
  service = new WorkspaceService(config, store);
  const ownerId = store.resolvePrincipal({ kind: 'owner', ownerId: 'vm-test-owner' });
  const id = 'ws_vmfixture123456789012345678';
  const workspacePath = join(jobsRoot, id);
  const repo = join(workspacePath, 'repo');
  mkdirSync(repo, { recursive: true });
  chmodSync(repo, 0o777);
  writeFileSync(join(repo, 'fixture.txt'), 'retain this source');
  const now = Date.now();
  record = {
    id, ownerId, workspacePath, idempotencyKey: 'vm-test', executorKind: 'kata',
    repositoryUrl: 'https://github.com/example/fixture.git', repositoryRef: null,
    containerName: null, status: 'CREATING', networkProfile: 'dependency-access',
    createdAt: now, lastActivityAt: now, expiresAt: now + 3600_000, hardExpiresAt: now + 14400_000,
    environmentId: null, gitAuthorName: null, gitAuthorEmail: null, mutationLockedUntil: null,
    generation: 1, error: null
  };
  store.create(record);
  container = await service['createExecutor'](record, repo);
  record = store.update(id, { containerName: container, status: 'ACTIVE' });
}, 120_000);

afterAll(async () => {
  await service?.stop();
  if (container) await removeContainer(container);
  store?.close();
  if (directory) removeTreeAsRoot(image, directory);
}, 60_000);

describe.skipIf(!enabled)('persistent Kata workspace', { timeout: 180_000 }, () => {
  it('installs a system package and Go, pnpm and Rust dependencies inside its VM', async () => {
    const result = await command(`set -eu
sudo -n chown 10001:10001 /workspace
sudo -n apt-get update -qq
sudo -n apt-get install -y --no-install-recommends hello >/dev/null
sudo -n npm install -g pnpm@10.30.1 >/dev/null
mkdir -p /workspace/go-fixture /workspace/ui-fixture /workspace/rust-fixture
cd /workspace/go-fixture
printf 'module fixture\n\ngo 1.26.0\n\nrequire github.com/google/uuid v1.6.0\n' > go.mod
go mod download
cd /workspace/ui-fixture
printf '{"dependencies":{"is-number":"7.0.0"}}' > package.json
pnpm install --ignore-scripts
node -e 'if(!require("is-number")(42))process.exit(1)'
cd /workspace/rust-fixture
cargo init --bin --name vm_fixture --vcs none --quiet
cargo run --quiet
cd /workspace
git init -q
git -c user.name=Fixture -c user.email=fixture@example.invalid add .
git -c user.name=Fixture -c user.email=fixture@example.invalid commit -qm retained
hello
pnpm --version`);
    expect(JSON.stringify(result)).toContain('10.30.1');
    expect(JSON.stringify(result)).toContain('Hello, world!');
  });

  it('retains root installs and unpushed work after stop, expiry and resume', async () => {
    await service.execute(record.ownerId, 'workspace_recover', { workspaceId: record.id, mode: 'stop' });
    expect(store.byId(record.id)).toMatchObject({ status: 'EXPIRED_RECOVERABLE', containerName: container, executorKind: 'kata' });
    expect((await inspectContainer(container!))?.State).toMatchObject({ Running: false });
    await service.start();
    expect((await inspectContainer(container!))?.State).toMatchObject({ Running: false });
    store.update(record.id, { hardExpiresAt: Date.now() - 1 });
    expect(store.listAutoCloseDue(Date.now() + 365 * 86400_000)).toEqual([]);
    await service.execute(record.ownerId, 'workspace_recover', { workspaceId: record.id, mode: 'resume' });
    const result = await command('set -eu; hello; pnpm --version; git log -1 --format=%s; test -f fixture.txt');
    expect(JSON.stringify(result)).toContain('10.30.1');
    expect(JSON.stringify(result)).toContain('retained');
    expect(store.byId(record.id)!.hardExpiresAt).toBeGreaterThan(Date.now());
    expect(store.byId(record.id)!.containerName).toBe(container);
  });

  it('blocks host and metadata access while allowing public package HTTPS', async () => {
    const result = await runDocker(['exec', container!, 'bash', '-c',
      'set -eu; curl -fsS --max-time 15 https://registry.npmjs.org/is-number/7.0.0 >/dev/null; for addr in 172.30.240.1 169.254.169.254 192.168.1.1; do if curl -fsS --max-time 2 "http://$addr/" >/dev/null 2>&1; then exit 1; fi; done'], { timeoutMs: 30_000 });
    expect(result.exitCode).toBe(0);
  });

  it('runs an interactive terminal through the existing Docker PTY transport and refuses a busy stop', async () => {
    const operations = service['operations'];
    const terminal = await operations.openTerminal({ ownerId: record.ownerId, workspaceId: record.id, container: container!, cwd: '.', cols: 80, rows: 24 });
    try {
      await expect(service.execute(record.ownerId, 'workspace_recover', { workspaceId: record.id, mode: 'stop' })).rejects.toMatchObject({ code: 'CONFLICT' });
      operations.writeTerminal(record.ownerId, record.id, terminal.terminalId, Buffer.from("printf 'pty-%s\\n' 'vm-ok'; exit\n"));
      let cursor = '0';
      let output = '';
      for (let attempt = 0; attempt < 20; attempt++) {
        const page = TerminalReadResultSchema.parse(await operations.readTerminal(record.ownerId, record.id, terminal.terminalId, cursor, 1000));
        output += Buffer.from(page.data, 'base64').toString('utf8');
        cursor = page.nextCursor;
        if (page.terminal.status !== 'running') break;
      }
      expect(output).toMatch(/\rpty-vm-ok\r?\n/);
    } finally {
      await operations.closeTerminal(record.ownerId, record.id, terminal.terminalId);
    }
  });

  it('refuses destructive recreate and retains state on quota violation', async () => {
    await expect(service.execute(record.ownerId, 'workspace_recover', { workspaceId: record.id, mode: 'recreate' })).rejects.toMatchObject({ code: 'NOT_SUPPORTED' });
    service['config'].maxWorkspaceBytes = 1;
    await expect(service['enforceActiveLimits'](store.byId(record.id)!)).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    expect(store.byId(record.id)).toMatchObject({ status: 'EXPIRED_RECOVERABLE', containerName: container });
    expect((await inspectContainer(container!))?.State).toMatchObject({ Running: false });
  });
});
