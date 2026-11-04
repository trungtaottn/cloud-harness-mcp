import { createHash, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, rmSync, mkdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createServer, type Server } from 'node:http';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { Client, StreamableHTTPClientTransport, type CallToolResult } from '@modelcontextprotocol/client';
import { Sandbox } from '@insforge/instabox-sdk';
import { ApiConfigSchema, RunnerConfigSchema, TOOL_SCHEMA_BY_NAME, InternalRunnerRequestSchema, type RunnerConfig } from '@cloud-harness/contracts';
import { createApiApp, type ApiRuntime } from '../../apps/api/src/app.js';
import { createRunnerApp } from '../../apps/runner/src/app.js';
import { ArtifactStore } from '../../apps/runner/src/artifact-store.js';
import { MetadataStore } from '../../apps/runner/src/metadata-store.js';
import { SqliteGitHubInstallationStore } from '../../apps/runner/src/github-installation-sqlite-store.js';
import { StateStore } from '../../apps/runner/src/state-store.js';
import { ExecutorStore } from '../../apps/runner/src/executor-store.js';
import { InstaBoxBackend } from '../../apps/runner/src/executors/instabox-backend.js';
import { WorkspaceService } from '../../apps/runner/src/workspace-service.js';

/**
 * Explicitly opt in with CH_INSTABOX_CANARY=true, INSTABOX_API_KEY_FILE and exactly three
 * comma-separated INSTABOX_MACHINE_IDS. All three must be stopped, dedicated test machines.
 * CH_CANARY_EXECUTOR_IMAGE selects an already-built helper/executor image. Docker must support Kata.
 * No credentials, IDs or local recovery state are stored in the checkout. No remote Git push is made.
 */
const enabled = process.env.CH_INSTABOX_CANARY === 'true';
const pause = (ms: number) => new Promise<void>(resolve => setTimeout(resolve, ms));
const repositoryUrl = 'https://github.com/bestagentkits/cloud-harness-mcp.git';
const fixtureRef = 'test-fixture-v1';

// Software and caches stay inside the disposable allocation, outside its Git checkout.
const installDependencies = `set -eu
tools="$HARNESS_WORKSPACE_ROOT/../canary-tools"
mkdir -p "$tools/ui" "$tools/go-project"
npm install --prefix "$tools" --cache "$tools/npm-cache" --no-audit --no-fund --ignore-scripts --package-lock=false --registry=https://registry.npmjs.org pnpm@10.30.1
test "$("$tools/node_modules/.bin/pnpm" --version)" = 10.30.1
printf '%s\\n' '{"private":true,"dependencies":{"is-number":"7.0.0"}}' > "$tools/ui/package.json"
"$tools/node_modules/.bin/pnpm" --dir "$tools/ui" install --ignore-scripts --store-dir "$tools/pnpm-store" --registry=https://registry.npmjs.org
node -e 'if(require(process.argv[1])("42") !== true) process.exit(1)' "$tools/ui/node_modules/is-number"
cd "$tools/go-project"
printf 'module canary.invalid/dependencies\\n\\ngo 1.22\\n\\nrequire github.com/google/uuid v1.6.0\\n' > go.mod
cat > dependencies_test.go <<'GO_TEST'
package dependencies
import ("testing"; "github.com/google/uuid")
func TestDependency(t *testing.T) {
  if uuid.Nil.String() != "00000000-0000-0000-0000-000000000000" { t.Fatal("dependency could not be used") }
}
GO_TEST
export GOPATH="$tools/go" GOCACHE="$tools/go-build" GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOTOOLCHAIN=local
go mod tidy
go test -count=1 -mod=readonly ./...
sudo -n install -d -m 500 "$tools/root-owned-cache"
printf 'retained root-owned cache\\n' | sudo -n tee "$tools/root-owned-cache/receipt" >/dev/null
sudo -n chmod 400 "$tools/root-owned-cache/receipt"
printf 'dependency-install-online-ok\\n'`;

const verifyRetainedDependencies = `set -eu
tools="$HARNESS_WORKSPACE_ROOT/../canary-tools"
test "$("$tools/node_modules/.bin/pnpm" --version)" = 10.30.1
test "$(sudo -n cat "$tools/root-owned-cache/receipt")" = 'retained root-owned cache'
rm -rf -- "$tools/ui/node_modules"
"$tools/node_modules/.bin/pnpm" --dir "$tools/ui" install --offline --frozen-lockfile --ignore-scripts --store-dir "$tools/pnpm-store"
node -e 'if(require(process.argv[1])("42") !== true) process.exit(1)' "$tools/ui/node_modules/is-number"
cd "$tools/go-project"
export GOPATH="$tools/go" GOCACHE="$tools/go-offline-build" GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local
go test -count=1 -mod=readonly ./...
printf 'dependency-cache-offline-after-resume-ok\\n'`;

function validateCanaryRequests(): void {
  const workspaceId = 'ws_' + 'a'.repeat(24), taskId = 'task_' + 'a'.repeat(24), shellId = 'sh_' + 'a'.repeat(24), sessionId = 'sess_' + 'a'.repeat(24), artifactId = 'art_' + 'a'.repeat(24);
  const requests: Array<[keyof typeof TOOL_SCHEMA_BY_NAME, Record<string, unknown>]> = [
    ...['remote-primary', 'remote-second', 'remote-third', 'local-overflow', 'explicit-network', 'large-worker-payload'].map(idempotencyKey => ['workspace_open', { repositoryUrl, ref: fixtureRef, idempotencyKey, ...(idempotencyKey === 'explicit-network' ? { networkProfile: 'network-none' } : {}) }] as [keyof typeof TOOL_SCHEMA_BY_NAME, Record<string, unknown>]),
    ['workspace_status', { workspaceId }], ['workspace_close', { workspaceId }],
    ['workspace_recover', { workspaceId, mode: 'stop' }], ['workspace_recover', { workspaceId, mode: 'resume' }],
    ['files_write', { workspaceId, path: 'large-payload.txt', content: 'payload-'.repeat(20480) }],
    ['files_read', { workspaceId, path: 'large-payload.txt', offset: 123, limit: 4096 }],
    ['files_write', { workspaceId, path: 'canary.txt', content: 'retained\n' }], ['files_read', { workspaceId, path: 'canary.txt', offset: 0, limit: 100 }],
    ['exec_run', { workspaceId, command: 'printf canary', cwd: '.', timeoutMs: 30000, maxOutputBytes: 65536 }],
    ['artifacts_snapshot', { workspaceId, path: 'binary.dat', logicalName: 'binary-canary' }], ['artifacts_read', { artifactId, offset: 0, limit: 100 }], ['artifacts_restore', { workspaceId, artifactId, path: 'restored.dat', overwrite: false }], ['artifacts_delete', { artifactId }],
    ...['task-idempotent', 'dependent', 'canary-cancel', 'canary-restart'].map(idempotencyKey => ['tasks_run', { workspaceId, command: 'printf task', cwd: '.', idempotencyKey, timeoutMs: 120000, ...(idempotencyKey === 'dependent' ? { dependsOn: [taskId] } : {}) }] as [keyof typeof TOOL_SCHEMA_BY_NAME, Record<string, unknown>]),
    ['tasks_status', { workspaceId, taskId }], ['tasks_cancel', { workspaceId, taskId }], ['tasks_graph', { workspaceId }],
    ['shell_open', { workspaceId, cwd: '.', idempotencyKey: 'canary-shell' }], ['shell_io', { workspaceId, shellId, input: 'printf shell\n', cursor: '0', waitMs: 500 }], ['shell_close', { workspaceId, shellId }],
    ['sessions_open', { workspaceId, cwd: '.', name: 'canary', idempotencyKey: 'canary-session' }], ['sessions_io', { workspaceId, sessionId, input: 'printf session\n', cursor: '0', waitMs: 500 }], ['sessions_close', { workspaceId, sessionId }],
    ['git_add', { workspaceId, all: true, paths: [] }], ['git_commit', { workspaceId, message: 'test: isolated InstaBox canary', authorName: 'Harness Canary', authorEmail: 'canary@example.invalid', all: false }], ['git_log', { workspaceId, limit: 2 }], ['git_fetch', { workspaceId, remote: 'origin' }],
    ['git_push', { workspaceId, remote: 'origin', refspec: 'HEAD:refs/heads/unauthorized-canary', idempotencyKey: 'deny-push' }]
  ];
  for (const [name, input] of requests) TOOL_SCHEMA_BY_NAME[name].parse(input);
  const terminalId = 'term_' + 'a'.repeat(24);
  for (const [operation, input] of [
    ['terminal_open', { workspaceId, cwd: '.', cols: 80, rows: 24 }],
    ['terminal_input', { workspaceId, terminalId, data: Buffer.from('printf terminal\n').toString('base64') }],
    ['terminal_resize', { workspaceId, terminalId, cols: 101, rows: 33 }],
    ['terminal_read', { workspaceId, terminalId, cursor: '0', waitMs: 1000 }],
    ['terminal_close', { workspaceId, terminalId }]
  ]) InternalRunnerRequestSchema.parse({ version: 2, principal: { kind: 'owner', ownerId: 'canary' }, operation, input });
}
it('validates the complete canary request shapes before any live setup', validateCanaryRequests);

describe.skipIf(!enabled)('real InstaBox MCP workflow and Kata overflow', () => {
  const owner = `instabox-canary-${randomUUID()}`;
  const bearer = randomUUID() + randomUUID();
  const serviceToken = randomUUID() + randomUUID();
  let directory: string | undefined;
  let store: StateStore | undefined;
  let service: WorkspaceService | undefined;
  let metadata: MetadataStore | undefined;
  let config: RunnerConfig;
  let runnerServer: Server | undefined;
  let runnerPort: number;
  let apiServer: Server | undefined;
  let apiRuntime: ApiRuntime | undefined;
  let client: Client | undefined;
  let apiKey: string;
  let machineIds: string[] = [];
  let ownsMachines = false;
  let principalId: string;
  const stages: string[] = [];
  let scenarioFailed = false;
  afterEach(context => { if (context.task.result?.state === 'fail') scenarioFailed = true; });

  async function listen(server: Server): Promise<number> {
    await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Canary server did not bind');
    return address.port;
  }
  function envelope(result: CallToolResult): Record<string, any> {
    const body = result.structuredContent as Record<string, any> | undefined;
    // Error codes suffice for debugging; never dump a complete authenticated tool response.
    expect(result.isError, `${body?.error?.code ?? 'missing envelope'}: ${body?.error?.message ?? ''}`).toBe(false);
    expect(body?.ok).not.toBe(false);
    return body!;
  }
  async function call(name: string, args: Record<string, unknown> = {}) {
    const schema = TOOL_SCHEMA_BY_NAME[name as keyof typeof TOOL_SCHEMA_BY_NAME];
    schema?.parse(args);
    try { return envelope(await client!.callTool({ name, arguments: args }, { timeout: 300_000 })); }
    catch (error) { throw new Error(`${name}: ${error instanceof Error ? error.message : 'tool failed'}`); }
  }
  async function internal(operation: string, input: Record<string, unknown>) {
    const response = await fetch(`http://127.0.0.1:${runnerPort}/v1/internal/dashboard-operations`, {
      method: 'POST', headers: { authorization: `Bearer ${serviceToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ version: 2, principal: { kind: 'owner', ownerId: owner }, operation, input }), signal: AbortSignal.timeout(120_000)
    });
    const body = await response.json() as Record<string, any>;
    expect(body.ok, `${operation}: ${body.error?.code ?? response.status}`).toBe(true);
    return body;
  }
  function evidence(stage: string): void {
    stages.push(stage);
    console.info(`InstaBox canary: ${stage}`);
    writeFileSync(join(directory!, 'evidence.json'), JSON.stringify({ stages }, null, 2), { mode: 0o600 });
  }
  async function finished(workspaceId: string, taskId: string) {
    const deadline = Date.now() + 180_000;
    while (Date.now() < deadline) {
      const result = await call('tasks_status', { workspaceId, taskId });
      if (!['running', 'queued'].includes(result.data.status)) return result;
      await pause(300);
    }
    throw new Error('Canary task did not settle within deadline');
  }
  async function output(workspaceId: string, command: string, timeoutMs = 30_000): Promise<string> {
    const result = await call('exec_run', { workspaceId, command, cwd: '.', timeoutMs, maxOutputBytes: 65_536 });
    expect(result.data.exitCode).toBe(0);
    return String(result.data.output);
  }
  async function shellOutput(operation: 'shell_io' | 'sessions_io', input: Record<string, unknown>, marker: string): Promise<void> {
    let text = ''; let cursor: string | undefined;
    for (let attempt = 0; attempt < 30; attempt++) {
      const result = await call(operation, { ...input, ...(attempt ? { input: undefined } : {}), ...(cursor ? { cursor } : {}), waitMs: 500 });
      text += result.data.output; cursor = result.cursor;
      if (text.includes(marker)) return;
    }
    throw new Error(`${operation} did not return its marker`);
  }
  function constructService(): WorkspaceService {
    metadata = new MetadataStore(config.stateDb);
    const artifacts = new ArtifactStore(store!.database, { root: config.artifactRoot, maxArtifactBytes: config.maxArtifactBytes, maxPrincipalBytes: config.maxPrincipalArtifactBytes, defaultRetentionMs: config.artifactRetentionSeconds * 1000, maxRetentionMs: 2592000000 });
    return new WorkspaceService(config, store!, metadata, new SqliteGitHubInstallationStore(store!.database), undefined, artifacts);
  }
  async function reopenService(): Promise<void> {
    await service!.stop();
    metadata!.close();
    store!.close();
    store = new StateStore(config.stateDb);
    service = constructService();
    await service.start();
    runnerServer!.removeAllListeners('request');
    runnerServer!.on('request', createRunnerApp(config, service));
  }

  beforeAll(async () => {
    validateCanaryRequests();
    const keyFile = process.env.INSTABOX_API_KEY_FILE;
    if (!keyFile) throw new Error('Opt-in canary requires INSTABOX_API_KEY_FILE');
    apiKey = readFileSync(keyFile, 'utf8').trim();
    machineIds = (process.env.INSTABOX_MACHINE_IDS ?? '').split(',').map(value => value.trim()).filter(Boolean);
    if (machineIds.length !== 3 || new Set(machineIds).size !== 3 || machineIds.some(id => !/^[A-Za-z0-9_-]{1,128}$/.test(id))) throw new Error('Canary requires exactly three unique allowlisted test machines');
    // Deliberately outside Vitest's TMPDIR: global teardown otherwise deletes recovery evidence on failure.
    const recoveryParent = resolve(process.env.CH_INSTABOX_CANARY_STATE_ROOT ?? '/tmp');
    mkdirSync(recoveryParent, { recursive: true });
    directory = mkdtempSync(join(recoveryParent, 'ch-instabox-e2e-'));
    store = new StateStore(join(directory, 'state', 'state.db'));
    principalId = store.resolvePrincipal({ kind: 'owner', ownerId: owner });
    writeFileSync(join(directory, 'recovery.json'), JSON.stringify({ owner, principalId, machineIds, stateDb: join(directory, 'state', 'state.db'), keyFile, instructions: 'Retain this directory until every workspace closes and each allowlisted machine is confirmed stopped.' }, null, 2), { mode: 0o600 });
    for (const id of machineIds) {
      const sandbox = await Sandbox.connect(id, { apiKey, resume: false });
      if ((await sandbox.getInfo()).state !== 'stopped') throw new Error('Canary refuses to claim a machine that is not stopped');
    }
    ownsMachines = true;
    config = RunnerConfigSchema.parse({
      host: '127.0.0.1', port: 3001, serviceToken, jobsRoot: join(directory, 'jobs'), stateDb: join(directory, 'state', 'state.db'),
      executorImage: process.env.CH_CANARY_EXECUTOR_IMAGE ?? 'cloud-harness-executor:local', executorKind: 'kata', vmMemoryMiB: 2048, vmCpus: 1,
      instabox: { apiKey, machineIds, principalId, allowPublicNetwork: true },
      allowedGitHosts: ['github.com'], networkProfile: 'network-none', wallTtlSeconds: 7200, idleTtlSeconds: 3600,
      maxActiveWorkspacesPerOwner: 6, maxOutputBytes: 262144, minFreeBytes: 104857600, maxWorkspaceBytes: 1073741824,
      reaperIntervalSeconds: 30, artifactRoot: join(directory, 'artifacts'), maxArtifactBytes: 16777216,
      maxPrincipalArtifactBytes: 134217728, artifactRetentionSeconds: 86400, enableRepoCache: false, repoCacheRoot: join(directory, 'cache')
    });
    service = constructService(); await service.start();
    runnerServer = createServer(createRunnerApp(config, service)); runnerPort = await listen(runnerServer);
    const apiConfig = ApiConfigSchema.parse({
      host: '127.0.0.1', port: 3000, ownerId: owner, bearerToken: bearer, runnerUrl: `http://127.0.0.1:${runnerPort}`, runnerToken: serviceToken,
      publicHosts: ['127.0.0.1'], allowedOrigins: [], requestTimeoutMs: 300000, maxBodyBytes: 262144,
      mcpGatewayTimeoutMs: 30000, mcpGatewayMaxResponseBytes: 262144, mcpGatewayMaxToolsPerServer: 500, mcpGatewayMaxSchemaBytes: 65536,
      mcpGatewayMaxCatalogBytes: 2097152, mcpGatewayMaxTraceRows: 20000, mcpGatewayMaxConnections: 32,
      mcpGatewayAllowInsecureHttp: false, mcpGatewayAllowPrivateEndpoints: false
    });
    apiRuntime = createApiApp(apiConfig); apiServer = createServer(apiRuntime.app); const apiPort = await listen(apiServer);
    client = new Client({ name: 'instabox-e2e', version: '1.0.0' }, { versionNegotiation: { mode: { pin: '2026-07-28' } } });
    await client.connect(new StreamableHTTPClientTransport(new URL(`http://127.0.0.1:${apiPort}/mcp`), { requestInit: { headers: { authorization: `Bearer ${bearer}` } } }));
    evidence('isolated-api-runner-ready');
  }, 180000);

  afterAll(async () => {
    let clean = true;
    const cleanup: Array<Record<string, unknown>> = [];
    const describeError = (error: unknown) => ({ code: (error as { code?: string; providerCode?: string })?.providerCode ?? (error as { code?: string })?.code ?? 'unknown', message: error instanceof Error ? error.message.replaceAll(apiKey ?? '', '[REDACTED]').slice(0, 300) : 'unknown' });
    if (service && store) {
      // Also find workspaces whose open failed before returning an ID.
      for (const record of store.list(principalId)) {
        if (record.status === 'CLOSED') continue;
        let closed = false;
        for (let attempt = 0; attempt < 5; attempt++) {
          try {
            const result = await service.execute(owner, 'workspace_close', { workspaceId: record.id });
            if (!result.ok) cleanup.push({ phase: 'workspace-close', workspaceId: record.id, error: result.error });
            closed = result.ok && store.byId(record.id)?.status === 'CLOSED';
            break;
          } catch (error) {
            const detail = describeError(error);
            cleanup.push({ phase: 'workspace-close', workspaceId: record.id, attempt, ...detail });
            // Retry only this same durable cleanup intent, never workspace creation or user commands.
            if (!['rate_limited', 'quota_exceeded', 'cooldown'].some(code => detail.code.includes(code) || detail.message.includes(code))) break;
            const retryAfter = (error as { retryAfterMs?: number }).retryAfterMs ?? 60000;
            await pause(Math.min(60000, Math.max(1000, retryAfter)));
          }
        }
        if (!closed) clean = false;
      }
    }
    if (ownsMachines) {
      for (const id of machineIds) {
        let stopped = false;
        for (let attempt = 0; attempt < 5; attempt++) {
          try { const sandbox = await Sandbox.connect(id, { apiKey, resume: false }); if ((await sandbox.getInfo()).state !== 'stopped') await sandbox.stop(); stopped = (await sandbox.getInfo()).state === 'stopped'; if (stopped) break; }
          catch { /* Suspended->stop may consume provider's limited start quota. */ }
          await pause(20000);
        }
        cleanup.push({ phase: 'machine-stop', allowlistIndex: machineIds.indexOf(id), stopped });
        if (!stopped) clean = false;
      }
    }
    await client?.close().catch(() => {});
    await apiRuntime?.close().catch(() => { clean = false; });
    await service?.stop().catch(() => { clean = false; });
    metadata?.close();
    store?.close();
    for (const server of [apiServer, runnerServer]) if (server?.listening) {
      server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()));
    }
    if (directory) {
      writeFileSync(join(directory, 'cleanup.json'), JSON.stringify({ clean, cleanup }, null, 2), { mode: 0o600 });
      if (clean && !scenarioFailed && stages.includes('complete')) rmSync(directory, { recursive: true, force: true });
      else console.warn(`InstaBox canary recovery/evidence retained at ${directory}; cleanupConfirmed=${clean}`);
    }
    expect(clean, 'Canary cleanup could not be confirmed; retain recovery directory').toBe(true);
  }, 600000);

  it('large worker payload and paused compute status use current RPC safely', async () => {
    const opened = await call('workspace_open', { repositoryUrl, ref: fixtureRef, idempotencyKey: 'large-worker-payload' });
    const workspaceId = opened.data.workspaceId as string;
    expect(store!.byId(workspaceId)?.executorKind).toBe('instabox');
    const content = 'payload-'.repeat(20480);
    expect(Buffer.byteLength(content)).toBe(160 * 1024);
    await call('files_write', { workspaceId, path: 'large-payload.txt', content });
    const expectedHash = createHash('sha256').update(content).digest('hex');
    expect((await output(workspaceId, 'sha256sum large-payload.txt')).split(/\s+/)[0]).toBe(expectedHash);
    const read = await call('files_read', { workspaceId, path: 'large-payload.txt', offset: 123, limit: 4096 });
    expect(read.data.content).toBe(content.slice(123, 123 + 4096));
    evidence('large-worker-payload-160KiB-hash-and-chunk');
    const allocation = new ExecutorStore(store!.database).byWorkspace(workspaceId)!;
    const sandbox = await Sandbox.connect(allocation.machineId, { apiKey, resume: false });
    await sandbox.pause();
    const status = await call('workspace_status', { workspaceId });
    expect(status.data.compute).toMatchObject({ state: 'suspended', ready: false });
    expect((await sandbox.getInfo()).state).toBe('suspended');
    await call('workspace_recover', { workspaceId, mode: 'resume' });
    expect((await call('workspace_status', { workspaceId })).data.compute).toMatchObject({ state: 'running', ready: true });
    evidence('compute-status-paused-read-does-not-wake');
    await call('workspace_close', { workspaceId });
    evidence('complete');
  }, 600000);

  it('preserves public coding workflows, durable work and explicit network policy', async () => {
    const openInput = { repositoryUrl, ref: fixtureRef, idempotencyKey: 'remote-primary' };
    const primary = await call('workspace_open', openInput); const workspaceId = primary.data.workspaceId as string;
    expect(store!.byId(workspaceId)?.executorKind).toBe('instabox');
    expect(primary.data.networkProfile).toBe('provider-managed');
    expect((await call('workspace_open', openInput)).data.workspaceId).toBe(workspaceId);
    expect((await call('workspace_status', { workspaceId })).data.status).toBe('ACTIVE');
    evidence('remote-open-idempotent');

    await call('files_write', { workspaceId, path: 'canary.txt', content: 'retained\n' });
    expect(JSON.stringify((await call('files_read', { workspaceId, path: 'canary.txt', offset: 0, limit: 100 })).data)).toContain('retained');
    await output(workspaceId, `node -e "require('fs').writeFileSync('binary.dat',Buffer.from([0,255,1,2,99]))"`);
    const artifact = await call('artifacts_snapshot', { workspaceId, path: 'binary.dat', logicalName: 'binary-canary' });
    const artifactId = artifact.data.artifactId;
    const bytes = await call('artifacts_read', { artifactId, offset: 0, limit: 100 });
    expect(Buffer.from(bytes.data.content, 'base64')).toEqual(Buffer.from([0,255,1,2,99]));
    await call('artifacts_restore', { workspaceId, artifactId, path: 'restored.dat', overwrite: false });
    expect((await output(workspaceId, 'cmp binary.dat restored.dat && printf binary-ok')).trim()).toBe('binary-ok');
    await call('artifacts_delete', { artifactId });
    evidence('worker-files-binary-artifact-exec');

    const taskInput = { workspaceId, command: 'printf once >> task-once; printf task-ok', cwd: '.', idempotencyKey: 'task-idempotent', timeoutMs: 30000 };
    const task = await call('tasks_run', taskInput); expect((await call('tasks_run', taskInput)).data.id).toBe(task.data.id);
    expect((await finished(workspaceId, task.data.id)).data.status).toBe('succeeded');
    expect((await output(workspaceId, 'cat task-once')).trim()).toBe('once');
    const dependent = await call('tasks_run', { workspaceId, command: 'printf dependent-ok', cwd: '.', idempotencyKey: 'dependent', timeoutMs: 30000, dependsOn: [task.data.id] });
    expect(JSON.stringify((await finished(workspaceId, dependent.data.id)).data)).toContain('dependent-ok');
    expect((await call('tasks_graph', { workspaceId })).data.edges).toContainEqual({ from: task.data.id, to: dependent.data.id });
    const cancellable = await call('tasks_run', { workspaceId, command: 'sleep 30; touch cancelled-leak', cwd: '.', idempotencyKey: 'canary-cancel', timeoutMs: 60000 });
    await call('tasks_cancel', { workspaceId, taskId: cancellable.data.id });
    expect((await call('tasks_status', { workspaceId, taskId: cancellable.data.id })).data.status).toBe('cancelled');
    await output(workspaceId, 'test ! -e cancelled-leak');
    evidence('tasks-idempotency-dag-cancel');

    const allocations = new ExecutorStore(store!.database);
    const allocated = allocations.byWorkspace(workspaceId)!;
    const observer = new InstaBoxBackend({ apiKey, allowedMachineIds: machineIds, principalId, validateRef: ref => allocations.assertRef(ref) });
    const sandbox = await Sandbox.connect(allocated.machineId, { apiKey, resume: false });
    await sandbox.pause();
    expect((await sandbox.getInfo()).state).toBe('suspended');
    await expect(observer.readJob(allocated, task.data.id, 0, 100)).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    const pausedStatus = await client!.callTool({ name: 'tasks_status', arguments: { workspaceId, taskId: task.data.id } });
    expect(pausedStatus.isError).toBe(true);
    expect((await sandbox.getInfo()).state).toBe('suspended');
    await call('workspace_recover', { workspaceId, mode: 'resume' });
    expect((await sandbox.getInfo()).state).toBe('running');
    evidence('paused-job-observation-does-not-wake-before-explicit-resume');

    const shell = await call('shell_open', { workspaceId, cwd: '.', idempotencyKey: 'canary-shell' });
    await shellOutput('shell_io', { workspaceId, shellId: shell.data.id, input: 'export CANARY_STATE=kept; printf initialized\n' }, 'initialized');
    await shellOutput('shell_io', { workspaceId, shellId: shell.data.id, input: 'printf "STATE_%s" "$CANARY_STATE"\n' }, 'STATE_kept');
    await call('shell_close', { workspaceId, shellId: shell.data.id });
    const session = await call('sessions_open', { workspaceId, name: 'canary', cwd: '.', idempotencyKey: 'canary-session' });
    await shellOutput('sessions_io', { workspaceId, sessionId: session.data.id, input: 'printf session-ok\n' }, 'session-ok');
    await call('sessions_close', { workspaceId, sessionId: session.data.id });
    evidence('shell-session-persistent-io-close');

    const terminal = await internal('terminal_open', { workspaceId, cwd: '.', cols: 80, rows: 24 }); const terminalId = terminal.data.terminalId;
    await internal('terminal_input', { workspaceId, terminalId, data: Buffer.from('printf "\\nTERMINAL_%s\\n" yes\n').toString('base64') });
    await internal('terminal_resize', { workspaceId, terminalId, cols: 101, rows: 33 });
    let terminalText = '', terminalCursor = '0';
    for (let n = 0; n < 20 && !terminalText.includes('TERMINAL_yes'); n++) { const page = await internal('terminal_read', { workspaceId, terminalId, cursor: terminalCursor, waitMs: 1000 }); terminalText += Buffer.from(page.data.data, 'base64').toString(); terminalCursor = page.data.nextCursor; }
    expect(terminalText).toContain('TERMINAL_yes');
    const delta = await internal('terminal_read', { workspaceId, terminalId, cursor: terminalCursor, waitMs: 0 });
    expect(Buffer.from(delta.data.data, 'base64').toString()).not.toContain('TERMINAL_yes');
    await internal('terminal_close', { workspaceId, terminalId });
    evidence('authenticated-terminal-raw-resize-cursor-close');

    const restartTask = await call('tasks_run', { workspaceId, command: 'printf once >> restart-once; sleep 15; printf after-restart', cwd: '.', idempotencyKey: 'canary-restart', timeoutMs: 120000 });
    await output(workspaceId, 'test -f restart-once');
    await reopenService();
    const reconciled = await finished(workspaceId, restartTask.data.id);
    expect(reconciled.data.status).toBe('succeeded'); expect(JSON.stringify(reconciled.data)).toContain('after-restart');
    expect((await output(workspaceId, 'cat restart-once')).trim()).toBe('once');
    evidence('service-restart-reconciles-durable-task');

    await call('git_add', { workspaceId, all: true, paths: [] });
    await call('git_commit', { workspaceId, message: 'test: isolated InstaBox canary', authorName: 'Harness Canary', authorEmail: 'canary@example.invalid', all: false });
    expect(JSON.stringify((await call('git_log', { workspaceId, limit: 2 })).data)).toContain('isolated InstaBox canary');
    await call('git_fetch', { workspaceId, remote: 'origin' });
    const push = await client!.callTool({ name: 'git_push', arguments: { workspaceId, remote: 'origin', refspec: 'HEAD:refs/heads/unauthorized-canary', idempotencyKey: 'deny-push' } });
    expect(push.isError).toBe(true);
    expect((push.structuredContent as any).error.code).toBe('REPOSITORY_OPERATION_NOT_AUTHORIZED');
    await call('files_write', { workspaceId, path: 'canary.txt', content: 'dirty retained\n' });
    await call('files_write', { workspaceId, path: 'untracked.txt', content: 'untracked retained\n' });
    expect(await output(workspaceId, installDependencies, 240000)).toContain('dependency-install-online-ok');
    evidence('pinned-pnpm-and-real-ui-go-dependencies-installed');
    const before = await output(workspaceId, 'git rev-parse HEAD; git status --porcelain; sha256sum canary.txt untracked.txt');
    await call('workspace_recover', { workspaceId, mode: 'stop' });
    await call('workspace_recover', { workspaceId, mode: 'resume' });
    expect(await output(workspaceId, 'git rev-parse HEAD; git status --porcelain; sha256sum canary.txt untracked.txt')).toBe(before);
    expect(await output(workspaceId, verifyRetainedDependencies, 240000)).toContain('dependency-cache-offline-after-resume-ok');
    evidence('pnpm-version-and-ui-go-offline-caches-survive-stop-resume');
    evidence('git-local-commit-broker-fetch-denied-push-stop-resume-retention');

    const second = await call('workspace_open', { repositoryUrl, ref: fixtureRef, idempotencyKey: 'remote-second' });
    const third = await call('workspace_open', { repositoryUrl, ref: fixtureRef, idempotencyKey: 'remote-third' });
    expect(store!.byId(second.data.workspaceId)?.executorKind).toBe('instabox'); expect(store!.byId(third.data.workspaceId)?.executorKind).toBe('instabox');
    const fourth = await call('workspace_open', { repositoryUrl, ref: fixtureRef, idempotencyKey: 'local-overflow' });
    expect(store!.byId(fourth.data.workspaceId)?.executorKind).toBe('kata');
    expect((await output(fourth.data.workspaceId, 'printf local-kata-ok')).trim()).toBe('local-kata-ok');
    const restricted = await call('workspace_open', { repositoryUrl, ref: fixtureRef, idempotencyKey: 'explicit-network', networkProfile: 'network-none' });
    expect(store!.byId(restricted.data.workspaceId)?.executorKind).toBe('kata');
    expect(restricted.data.networkProfile).toBe('network-none');
    evidence('three-remote-fourth-kata-explicit-network-local');
    evidence('complete');
  }, 1800000);
});
