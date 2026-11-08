import { execFile, spawnSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { mkdtemp, mkdir, writeFile, readFile, rm, readdir, cp, chmod, symlink, readlink, lstat, statfs } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { IncusExecutorBackend, incusVmNameForWorkspace, stagingReservations, type VmSupervisorGateway } from '../src/incus-executor-backend.js';
import { INCUS_VM_BACKEND_CAPABILITIES } from '../src/vm-capabilities.js';
import { VmSupervisorCallError } from '../src/vm-supervisor-client.js';
import type { ProvisionContext } from '../src/executor-backend.js';
import type { WorkspaceRecord } from '../src/state-store.js';
import type { RunnerConfig } from '@cloud-harness/contracts';

const INSTANCE_ID = '123e4567-e89b-42d3-a456-426614174000';
const TEMPLATE_ID = 'chm-ubuntu-2404';
const TEMPLATE_DIGEST = 'a'.repeat(64);

// Real staging IO (pullFile/pullTree/pushTree) lands under record.workspacePath,
// so every fixture record/ctx gets a test-owned mkdtemp under os.tmpdir()
// (honors TMPDIR) instead of a shared hardcoded path, drained after each test.
const fixtureDirs: string[] = [];

function fixtureDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  fixtureDirs.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(fixtureDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

function record(overrides: Partial<WorkspaceRecord> = {}): WorkspaceRecord {
  return {
    id: 'ws_0123456789abcdef0123456789abcdef',
    ownerId: 'owner-1',
    idempotencyKey: 'key-1',
    repositoryUrl: 'https://example.com/repo.git',
    repositoryRef: null,
    containerName: null,
    workspacePath: fixtureDir('ch-incus-ws-'),
    environmentId: null,
    status: 'ACTIVE',
    networkProfile: 'network-none',
    createdAt: 1,
    lastActivityAt: 1,
    expiresAt: 9_999_999_999_999,
    hardExpiresAt: 10_000_000_000_000,
    gitAuthorName: null,
    gitAuthorEmail: null,
    mutationLockedUntil: null,
    generation: 7,
    error: null,
    backendKind: 'incus-vm',
    vmName: incusVmNameForWorkspace('ws_0123456789abcdef0123456789abcdef'),
    backendInstanceId: INSTANCE_ID,
    templateId: TEMPLATE_ID,
    templateDigest: TEMPLATE_DIGEST,
    ...overrides
  } as WorkspaceRecord;
}

function ctx(overrides: Partial<ProvisionContext> = {}): ProvisionContext {
  return {
    record: record(),
    environment: { BASE: '1' },
    networkProfile: 'network-none',
    stagingDir: join(fixtureDir('ch-incus-staging-'), 'git-staging'),
    ...overrides
  };
}

const config = {
  vmBackendEnabled: true,
  // Kept small so pullTree staging-capacity checks (2× bound) stay cheap in CI.
  vmMaxWorkspaceBytes: 256 * 1024 * 1024,
  vmInlineMaxBytes: 8_388_608
} as unknown as RunnerConfig;

function fakeClient() {
  const calls: Array<{ method: string; args: unknown[] }> = [];
  const record = (method: string) => (...args: unknown[]) => {
    calls.push({ method, args });
    return undefined;
  };
  const client = {
    vmCreate: vi.fn(async () => ({ vmName: 'chm-vm-x', state: 'stopped' as const })),
    vmStart: vi.fn(async () => ({ state: 'running' as const })),
    vmStop: vi.fn(async () => ({ state: 'stopped' as const })),
    vmDelete: vi.fn(async () => ({ state: 'deleted' as const })),
    vmStatus: vi.fn(async () => ({ state: 'running' as const })),
    execRun: vi.fn(async () => ({ opId: 'op', exitCode: 0, signal: null, stdout: '', stderr: '', truncated: false, timedOut: false })),
    execInspect: vi.fn(async () => ({ state: 'unknown' as const })),
    execOpen: vi.fn(),
    execWrite: vi.fn(async () => ({ acceptedBytes: 0 })),
    execClose: vi.fn(async () => ({ closed: true as const })),
    execResize: vi.fn(async () => ({})),
    execKillSession: vi.fn(async () => ({ killed: true as const })),
    filePull: vi.fn(async () => ({ dataBase64: Buffer.from('hi').toString('base64'), sha256: 'b'.repeat(64), bytes: 2 })),
    // Marker paths (.cloud-harness-provisioned) report as files; everything
    // else as directories so pullTree's isDir pre-check passes by default.
    fileStat: vi.fn(async (_id: unknown, params: { guestPath: string }) => ({
      size: 1, mode: 0o644, mtime: 1,
      isDir: !params.guestPath.includes('.cloud-harness-provisioned')
    })),
    filePush: vi.fn(async () => ({ sha256: 'e'.repeat(64), bytes: 1 })),
    pushTree: vi.fn(async () => ({ sha256: 'c'.repeat(64), bytes: 10, entryCount: 1 })),
    pullTree: vi.fn(async () => ({ sha256: 'd'.repeat(64), bytes: 10, entryCount: 1 })),
    leaseSet: vi.fn(async () => ({ effective: { expiresAt: 1, hardExpiresAt: 2 } })),
    leaseClear: vi.fn(async () => ({ cleared: true as const }))
  };
  void record;
  return { client: client as unknown as VmSupervisorGateway & typeof client, calls: client };
}

const runTar = promisify(execFile);

const __dirname = dirname(fileURLToPath(import.meta.url));
/** User+mount namespaces let the test bind a fixture over /opt without root. */
const UNSHARE_USERNS = spawnSync('unshare', ['-rm', 'true']).status === 0;

const IDENT = { workspaceId: 'ws_0123456789abcdef0123456789abcdef', generation: 7, instanceId: INSTANCE_ID };

describe('IncusExecutorBackend provision ordering', () => {
  it('runs create → lease.set → vm.start → assets, with fenced identity + idempotency keys', async () => {
    const { client, calls } = fakeClient();
    const order: string[] = [];
    for (const m of ['vmCreate', 'leaseSet', 'vmStart'] as const) {
      const orig = calls[m].getMockImplementation();
      void orig;
    }
    calls.vmCreate.mockImplementation(async () => { order.push('create'); return { vmName: 'x', state: 'stopped' as const }; });
    calls.leaseSet.mockImplementation(async () => { order.push('lease'); return { effective: { expiresAt: 1, hardExpiresAt: 2 } }; });
    calls.vmStart.mockImplementation(async () => { order.push('start'); return { state: 'running' as const }; });
    const backend = new IncusExecutorBackend({ client, config });
    const ref = await backend.provision(ctx());
    expect(order).toEqual(['create', 'lease', 'start']);
    expect(ref.backend).toBe('incus-vm');
    expect(ref.executorId).toBe(incusVmNameForWorkspace(IDENT.workspaceId));
    expect(ref.instanceId).toBe(INSTANCE_ID);
    // Every workspace call carries the full fenced identity.
    for (const [method, fn] of Object.entries(calls)) {
      if (method === 'execInspect') continue;
      for (const call of fn.mock.calls) {
        expect(call[0]).toEqual(IDENT);
      }
    }
    expect(calls.vmCreate.mock.calls[0]![1]).toMatchObject({ instanceId: INSTANCE_ID, templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST });
    expect(calls.leaseSet.mock.calls[0]![1]).toMatchObject({ expiresAt: 9_999_999_999_999, hardExpiresAt: 10_000_000_000_000 });
    const keys = [calls.vmCreate, calls.leaseSet, calls.vmStart].map((f) => (f.mock.calls[0]![2] as { idempotencyKey: string }).idempotencyKey);
    expect(new Set(keys).size).toBe(3);
    expect(keys[0]).toContain(INSTANCE_ID);
  });

  it('pushes provision assets after start when configured', async () => {
    const { client, calls } = fakeClient();
    const dir = await mkdtemp(join(tmpdir(), 'ch-asset-'));
    await mkdir(join(dir, 'skills'), { recursive: true });
    await writeFile(join(dir, 'skills', 'SKILL.md'), 'x');
    const backend = new IncusExecutorBackend({
      client,
      config,
      provisionAssets: async () => [{ hostDir: dir, guestPath: '/workspace/skills' }]
    });
    await backend.provision(ctx());
    expect(calls.pushTree).toHaveBeenCalledTimes(1);
    const params = calls.pushTree.mock.calls[0]![1] as { guestPath: string; sha256: string };
    expect(params.guestPath).toBe('/workspace/skills');
    expect(params.sha256).toMatch(/^[0-9a-f]{64}$/);
    await rm(dir, { recursive: true, force: true });
  });

  it('default provision assets push builtin skills + existing owner projection only', async () => {
    const { client, calls } = fakeClient();
    const builtin = await mkdtemp(join(tmpdir(), 'ch-builtin-'));
    await mkdir(join(builtin, 'skill-a'), { recursive: true });
    const jobDir = await mkdtemp(join(tmpdir(), 'ch-job-'));
    const ownerSkills = join(jobDir, 'toolkit-projection', 'owner-skills');
    await mkdir(ownerSkills, { recursive: true });
    const backend = new IncusExecutorBackend({
      client,
      config: { ...config, builtinSkillsRoot: builtin } as RunnerConfig
    });
    await backend.provision(ctx({ record: record({ workspacePath: jobDir }) }));
    const guestPaths = calls.pushTree.mock.calls.map((c) => (c[1] as { guestPath: string }).guestPath);
    expect(guestPaths).toEqual(['/opt/cloud-harness/skills', '/opt/cloud-harness/owner-skills']);
    await rm(builtin, { recursive: true, force: true });
    await rm(jobDir, { recursive: true, force: true });
  });

  it('default provision assets fail loudly when builtinSkillsRoot is configured but missing', async () => {
    const { client, calls } = fakeClient();
    const backend = new IncusExecutorBackend({
      client,
      config: { ...config, builtinSkillsRoot: '/nonexistent/skills-root' } as RunnerConfig
    });
    await expect(backend.provision(ctx())).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(calls.pushTree).not.toHaveBeenCalled();
  });

  it('opens the VM for owner-scope packages and reports the unsupported host bindings', async () => {
    const { client, calls } = fakeClient();
    const onUnsupportedPackages = vi.fn();
    const backend = new IncusExecutorBackend({
      client,
      config,
      packages: { profileFor: () => ({ mounts: [{ source: '/x', target: '/y' }], binDirs: [], releaseIds: ['rel-1'] }) },
      onUnsupportedPackages
    });
    // packages-bind has no VM mount channel, but the binding must not block
    // the opt-in VM: no mounts are injected and the gap is reported honestly.
    await backend.provision(ctx());
    expect(calls.vmCreate).toHaveBeenCalledTimes(1);
    expect(onUnsupportedPackages).toHaveBeenCalledWith({
      ownerId: 'owner-1', workspaceId: 'ws_0123456789abcdef0123456789abcdef', releaseIds: ['rel-1']
    });
    // No package mount may leak into the VM create/push calls.
    const createArgs = JSON.stringify(calls.vmCreate.mock.calls);
    expect(createArgs).not.toContain('/x');
  });

  it('stays silent on unsupported-package reporting when the profile is empty', async () => {
    const { client } = fakeClient();
    const onUnsupportedPackages = vi.fn();
    const backend = new IncusExecutorBackend({
      client,
      config,
      packages: { profileFor: () => ({ mounts: [], binDirs: [] }) },
      onUnsupportedPackages
    });
    await backend.provision(ctx());
    expect(onUnsupportedPackages).not.toHaveBeenCalled();
  });

  it('fails before any supervisor call when admit identity is missing', async () => {
    const { client, calls } = fakeClient();
    const backend = new IncusExecutorBackend({ client, config });
    await expect(backend.provision(ctx({ record: record({ backendInstanceId: null }) }))).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(calls.vmCreate).not.toHaveBeenCalled();
  });
});

describe('IncusExecutorBackend ensureActive', () => {
  it('adopts a running VM only on full identity match', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue({
      state: 'running',
      userCloudHarness: { workspaceId: IDENT.workspaceId, instanceId: INSTANCE_ID, templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST, generationPolicy: 'external' }
    });
    const backend = new IncusExecutorBackend({ client, config });
    const ref = await backend.ensureActive(ctx());
    expect(ref.executorId).toBe(incusVmNameForWorkspace(IDENT.workspaceId));
    expect(calls.vmStart).not.toHaveBeenCalled();
  });

  it('refuses to adopt on identity mismatch', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue({
      state: 'running',
      userCloudHarness: { workspaceId: 'ws_other', instanceId: INSTANCE_ID, templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST, generationPolicy: 'external' }
    });
    const backend = new IncusExecutorBackend({ client, config });
    await expect(backend.ensureActive(ctx())).rejects.toMatchObject({ code: 'VM_IDENTITY_MISMATCH' });
  });

  it('gated-starts a verified stopped VM', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue({
      state: 'stopped',
      userCloudHarness: { workspaceId: IDENT.workspaceId, instanceId: INSTANCE_ID, templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST, generationPolicy: 'external' }
    });
    const backend = new IncusExecutorBackend({ client, config });
    await backend.ensureActive(ctx());
    expect(calls.vmStart).toHaveBeenCalledTimes(1);
    expect(calls.vmCreate).not.toHaveBeenCalled();
  });

  it('re-provisions ONLY on typed NOT_FOUND; every ambiguous status retains with zero mutations', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockRejectedValueOnce(new VmSupervisorCallError('NOT_FOUND', 'gone', 404, false));
    const backend = new IncusExecutorBackend({ client, config });
    const first = backend.ensureActive(ctx());
    // provision path: vmCreate→lease→vmStart all succeed with fakes
    await expect(first).resolves.toMatchObject({ backend: 'incus-vm' });
    expect(calls.vmCreate).toHaveBeenCalledTimes(1);

    // M2 correction: a BARE {state:'unknown'} — even with no identity and no
    // expandedConfig — is what opStatus returns for an Incus-404 under a
    // live journal row. It is NOT proof of absence and must NEVER trigger
    // vm.create/re-seed: retain and fail closed.
    const mutations = () => {
      expect(calls.vmCreate).not.toHaveBeenCalled();
      expect(calls.leaseSet).not.toHaveBeenCalled();
      expect(calls.vmStart).not.toHaveBeenCalled();
      expect(calls.pushTree).not.toHaveBeenCalled();
      expect(calls.filePush).not.toHaveBeenCalled();
    };
    calls.vmCreate.mockClear(); calls.leaseSet.mockClear(); calls.vmStart.mockClear();
    calls.pushTree.mockClear(); calls.filePush.mockClear();

    calls.vmStatus.mockResolvedValueOnce({ state: 'unknown' });
    await expect(backend.ensureActive(ctx())).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    mutations();

    // 'unknown' carrying full instance fields is equally ambiguous.
    calls.vmStatus.mockResolvedValueOnce({
      state: 'unknown',
      expandedConfig: { 'user.cloud-harness.workspace': IDENT.workspaceId },
      expandedDevices: {}, profiles: []
    });
    await expect(backend.ensureActive(ctx())).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    mutations();

    calls.vmStatus.mockRejectedValueOnce(new VmSupervisorCallError('UNAVAILABLE', 'down', 503, true));
    await expect(backend.ensureActive(ctx())).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    calls.vmStatus.mockResolvedValueOnce({ state: 'error' });
    await expect(backend.ensureActive(ctx())).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    mutations();
    expect(calls.vmCreate).toHaveBeenCalledTimes(0); // never recreated on unknown/error
  });
});

describe('IncusExecutorBackend exec/streams/files', () => {
  it('sends the COMPLETE canonical env map, merged over GUEST_BASE_ENV; clamps bounds', async () => {
    const { client, calls } = fakeClient();
    const backend = new IncusExecutorBackend({ client, config });
    const env = { SECRET_TOKEN: 's3cr3t' };
    const result = await backend.exec(ctx(), {
      argv: ['echo', 'hi'], cwd: '/workspace', environment: env,
      stdin: 'input', timeoutMs: 99_999_999, maxBytes: 99_999_999, user: 'root'
    });
    expect(result.exitCode).toBe(0);
    const params = calls.execRun.mock.calls[0]![1] as Record<string, unknown>;
    // H3: the wire env is the complete canonical base + caller env (caller wins).
    expect(params.environment).toMatchObject({
      ...env,
      HOME: '/tmp/cloud-harness-home',
      GIT_CONFIG_NOSYSTEM: '1',
      XDG_CONFIG_HOME: '/tmp/cloud-harness-home/.config',
      XDG_CACHE_HOME: '/var/cache/harness'
    });
    expect((params.environment as Record<string, string>).PATH).toContain('/opt/user-tools/bin');
    // PR17 (comment 4504671885): /opt/harness/bin must LEAD PATH — VM execs are
    // non-login so profile.d/harness.sh never runs; without it the baked
    // npx/skills/skillx dispatchers are unreachable.
    expect((params.environment as Record<string, string>).PATH!.split(':')[0]).toBe('/opt/harness/bin');
    expect(params.user).toBe('root');
    expect(params.timeoutMs).toBe(3_600_000);
    expect(params.maxBytes).toBe(10_485_760);
    expect(params.stdinBase64).toBe(Buffer.from('input').toString('base64'));
    expect(params.executionMode).toBe('executor');
    // env values never appear in argv
    expect(JSON.stringify(params.argv)).not.toContain('s3cr3t');
    // H2: the wire deadline covers requested duration + bounded kill grace.
    const wireOpts = calls.execRun.mock.calls[0]![2] as { timeoutMs?: number };
    expect(wireOpts.timeoutMs).toBe(3_600_000 + 30_000);
  });

  it.skipIf(!UNSHARE_USERNS)('resolves the shipped npx dispatcher first through the real exec-env PATH', async () => {
    // Behavior proof for PR17 (comment 4504671885), not a string-prefix
    // assumption: capture the EXACT environment the exec path puts on the
    // wire, bind a fixture /opt containing the shipped dispatcher inside a
    // user+mount namespace, and let a real shell resolve `npx` through it.
    const { client, calls } = fakeClient();
    const backend = new IncusExecutorBackend({ client, config });
    await backend.exec(ctx(), {
      argv: ['true'], cwd: '/workspace', environment: {},
      timeoutMs: 5_000, maxBytes: 4_096
    });
    const wireEnv = (calls.execRun.mock.calls[0]![1] as { environment: Record<string, string> }).environment;
    const pathEnv = wireEnv.PATH!;
    expect(pathEnv.split(':')[0]).toBe('/opt/harness/bin');

    // Fixture /opt: the three dispatcher targets worker-manifest.txt installs.
    const root = await mkdtemp(join(tmpdir(), 'ch-vm-path-'));
    try {
      const binDir = join(root, 'opt', 'harness', 'bin');
      await mkdir(binDir, { recursive: true });
      const workerBin = resolve(__dirname, '../../../worker/bin');
      for (const [src, dst] of [['npx-dispatcher', 'npx'], ['skills', 'skills'], ['skillx', 'skillx']] as const) {
        await cp(join(workerBin, src), join(binDir, dst));
        await chmod(join(binDir, dst), 0o755);
      }
      const script = `mount --bind ${join(root, 'opt')} /opt && env -i PATH='${pathEnv}' bash -c 'command -v npx && head -20 "$(command -v npx)"'`;
      const { stdout } = await runTar('unshare', ['-rm', 'bash', '-c', script]);
      const lines = stdout.trim().split('\n');
      // The FIRST PATH hit is the shipped dispatcher at /opt/harness/bin/npx,
      // and its content is the narrow offline dispatcher — not a foreign npx.
      expect(lines[0]).toBe('/opt/harness/bin/npx');
      expect(lines.slice(1).join('\n')).toContain('Narrow `npx` dispatcher');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('sends workspace execs verbatim — the supervisor owns the runuser drop', async () => {
    const { client, calls } = fakeClient();
    const backend = new IncusExecutorBackend({ client, config });
    const env = { SECRET_TOKEN: 's3cr3t', PATH: '/usr/bin' };
    await backend.exec(ctx(), {
      argv: ['docker', 'ps'], cwd: '/workspace', environment: env,
      timeoutMs: 5000, maxBytes: 4096, user: 'workspace'
    });
    const params = calls.execRun.mock.calls[0]![1] as { argv: string[]; user: string; environment: Record<string, string> };
    // No double-wrap: sessions.ts wraps argv itself; the backend sends the
    // workspace identity and lets the supervisor apply runuser/initgroups.
    expect(params.user).toBe('workspace');
    expect(params.argv).toEqual(['docker', 'ps']);
    expect(params.environment).toMatchObject(env);
    expect(JSON.stringify(params.argv)).not.toContain('s3cr3t');
  });

  it('reconciles a lost exec reply via exec.inspect (exited → truncated result)', async () => {
    const { client, calls } = fakeClient();
    calls.execRun.mockRejectedValueOnce(new VmSupervisorCallError('VM_UNKNOWN_STATE', 'lost', 503, true, true));
    calls.execInspect.mockResolvedValueOnce({ state: 'exited', exitCode: 0 });
    const backend = new IncusExecutorBackend({ client, config });
    const result = await backend.exec(ctx(), { argv: ['true'], environment: {}, timeoutMs: 1000, maxBytes: 100 });
    expect(result.truncated).toBe(true);
    expect(result.exitCode).toBe(0);
    expect(calls.execInspect).toHaveBeenCalledTimes(1);
  });

  it('rethrows unknown outcome when inspect cannot resolve it', async () => {
    const { client, calls } = fakeClient();
    calls.execRun.mockRejectedValueOnce(new VmSupervisorCallError('VM_UNKNOWN_STATE', 'lost', 503, true, true));
    calls.execInspect.mockResolvedValueOnce({ state: 'running' });
    const backend = new IncusExecutorBackend({ client, config });
    await expect(backend.exec(ctx(), { argv: ['true'], environment: {}, timeoutMs: 1000, maxBytes: 100 }))
      .rejects.toMatchObject({ code: 'VM_UNKNOWN_STATE', unknownOutcome: true });
  });

  it('pullFile decodes inline base64 under the 4 MiB bound', async () => {
    const { client, calls } = fakeClient();
    const backend = new IncusExecutorBackend({ client, config });
    const buf = await backend.pullFile(ctx(), '/workspace/a.txt', 1024);
    expect(buf.toString()).toBe('hi');
    expect(calls.filePull).toHaveBeenCalledTimes(1);
    expect(calls.pullTree).not.toHaveBeenCalled();
  });

  it('pullFile streams files over the inline cap through a bounded pullTree + single-member extract', async () => {
    const src = await mkdtemp(join(tmpdir(), 'ch-pull-src-'));
    const payload = Buffer.alloc(5 * 1024 * 1024 + 7, 0x61); // > 4 MiB inline cap
    await writeFile(join(src, 'big.bin'), payload);
    const tarPath = join(src, 'tree.tar');
    await runTar('tar', ['-cf', tarPath, '-C', src, 'big.bin']);
    const tarBytes = await readFile(tarPath);

    const { client, calls } = fakeClient();
    calls.pullTree.mockImplementationOnce(async (_id: unknown, _p: unknown, opts: { sink: (c: Buffer) => void | Promise<void> }) => {
      for (let i = 0; i < tarBytes.length; i += 65536) await opts.sink(tarBytes.subarray(i, i + 65536));
      return { sha256: 'd'.repeat(64), bytes: tarBytes.length, entryCount: 1 };
    });
    const backend = new IncusExecutorBackend({ client, config });
    const buf = await backend.pullFile(ctx(), '/workspace/big.bin', 6 * 1024 * 1024);
    expect(buf.equals(payload)).toBe(true);
    expect(calls.filePull).not.toHaveBeenCalled();
    const params = calls.pullTree.mock.calls[0]![1] as { guestPath: string; maxBytes: number };
    expect(params.guestPath).toBe('/workspace/big.bin');
    expect(params.maxBytes).toBeGreaterThanOrEqual(payload.length);
    await rm(src, { recursive: true, force: true });
  });

  it('streamed pullFile enforces maxBytes on the extracted file', async () => {
    const src = await mkdtemp(join(tmpdir(), 'ch-pull-src2-'));
    // > inline cap so the request routes through the streamed pullTree path,
    // and larger than the caller bound so the extracted file trips LIMIT_EXCEEDED.
    await writeFile(join(src, 'big.bin'), Buffer.alloc(800 * 1024, 0x62));
    const tarPath = join(src, 'tree.tar');
    await runTar('tar', ['-cf', tarPath, '-C', src, 'big.bin']);
    const tarBytes = await readFile(tarPath);

    const { client, calls } = fakeClient();
    calls.pullTree.mockImplementationOnce(async (_id: unknown, _p: unknown, opts: { sink: (c: Buffer) => void }) => {
      opts.sink(tarBytes);
      return { sha256: 'd'.repeat(64), bytes: tarBytes.length, entryCount: 1 };
    });
    const backend = new IncusExecutorBackend({ client, config });
    const overCap = 700 * 1024; // > 720KiB? no — just under inline cap? see below
    // maxBytes must exceed the 720KiB inline bound to route streamed AND be
    // smaller than the 800KiB file to trip LIMIT_EXCEEDED.
    await expect(backend.pullFile(ctx(), '/workspace/big.bin', 750 * 1024)).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    void overCap;
    await rm(src, { recursive: true, force: true });
  });

  it('streamed pullFile rejects non-regular files (directory member)', async () => {
    const src = await mkdtemp(join(tmpdir(), 'ch-pull-src3-'));
    await mkdir(join(src, 'adir'));
    const tarPath = join(src, 'tree.tar');
    await runTar('tar', ['-cf', tarPath, '-C', src, 'adir']);
    const tarBytes = await readFile(tarPath);

    const { client, calls } = fakeClient();
    calls.pullTree.mockImplementationOnce(async (_id: unknown, _p: unknown, opts: { sink: (c: Buffer) => void }) => {
      opts.sink(tarBytes);
      return { sha256: 'd'.repeat(64), bytes: tarBytes.length, entryCount: 1 };
    });
    const backend = new IncusExecutorBackend({ client, config });
    await expect(backend.pullFile(ctx(), '/workspace/adir', 1024 * 1024)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await rm(src, { recursive: true, force: true });
  });

  it('routes pullFile inline under the 720KiB supervisor bound, streamed above it', async () => {
    const { client, calls } = fakeClient();
    const backend = new IncusExecutorBackend({ client, config });
    await backend.pullFile(ctx(), '/workspace/small.txt', 700 * 1024);
    expect(calls.filePull).toHaveBeenCalledTimes(1);
    expect(calls.pullTree).not.toHaveBeenCalled();
    // Above the frozen 720KiB inline bound → streamed pullTree path.
    calls.pullTree.mockImplementationOnce(async (_id: unknown, _p: unknown, opts: { sink: (c: Buffer) => void }) => {
      // Empty tar (all-zero blocks) extracts to nothing → INVALID_INPUT, but
      // the routing assertion is what matters: pullTree was invoked.
      opts.sink(Buffer.alloc(1024));
      return { sha256: 'd'.repeat(64), bytes: 1024, entryCount: 0 };
    });
    await expect(backend.pullFile(ctx(), '/workspace/big.bin', 800 * 1024)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(calls.pullTree).toHaveBeenCalledTimes(1);
  });

  it('pushTree/pullTree return the supervisor trailer and stage through tar', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ch-tree-'));
    await writeFile(join(dir, 'f.txt'), 'data');
    const { client, calls } = fakeClient();
    const rec = record({ workspacePath: dir });
    const backend = new IncusExecutorBackend({ client, config });
    const pushed = await backend.pushTree(ctx({ record: rec }), dir, '/workspace/in');
    expect(pushed).toEqual({ sha256: 'c'.repeat(64), bytes: 10, entryCount: 1 });
    const params = calls.pushTree.mock.calls[0]![1] as { sha256: string; maxBytes: number };
    expect(params.sha256).toMatch(/^[0-9a-f]{64}$/);
    // pullTree writes tar bytes then extracts; fake emits no sink data → empty tar extract would fail,
    // so feed one valid empty tar (1024 zero bytes) via sink.
    calls.pullTree.mockImplementationOnce(async (_id: unknown, _p: unknown, opts: { sink: (c: Buffer) => void }) => {
      opts.sink(Buffer.alloc(1024));
      return { sha256: 'd'.repeat(64), bytes: 1024, entryCount: 0 };
    });
    const out = await mkdtemp(join(tmpdir(), 'ch-out-'));
    const pulled = await backend.pullTree(ctx({ record: rec }), '/workspace/out', out);
    expect(pulled.entryCount).toBe(0);
    await rm(dir, { recursive: true, force: true });
    await rm(out, { recursive: true, force: true });
  });

  it('measureWorkspaceBytes parses guest-df output; killProcessGroup uses kill-session.sh', async () => {
    const { client, calls } = fakeClient();
    calls.execRun.mockResolvedValue({ opId: 'o', exitCode: 0, signal: null, stdout: '100 /workspace\n200 /opt/user-tools\n50 /var/cache/harness\n', stderr: '', truncated: false, timedOut: false });
    const backend = new IncusExecutorBackend({ client, config });
    expect(await backend.measureWorkspaceBytes(ctx())).toBe(350);
    await backend.killProcessGroup(ctx(), '/tmp/pids/task.pid');
    const killArgs = calls.execRun.mock.calls.at(-1)![1] as { argv: string[]; user: string };
    // workspace exec → verbatim argv + workspace identity; supervisor wraps.
    expect(killArgs.user).toBe('workspace');
    expect(killArgs.argv).toEqual(['/usr/local/bin/kill-session.sh', '/tmp/pids/task.pid']);
  });
});

describe('IncusExecutorBackend lifecycle verbs', () => {
  it('stop clears lease then stops; destroy requires confirmInstanceId', async () => {
    const { client, calls } = fakeClient();
    const backend = new IncusExecutorBackend({ client, config });
    await backend.stop(ctx());
    expect(calls.leaseClear).toHaveBeenCalledTimes(1);
    expect(calls.vmStop).toHaveBeenCalledTimes(1);
    await backend.destroy(ctx());
    expect((calls.vmDelete.mock.calls[0]![1] as { confirmInstanceId: string }).confirmInstanceId).toBe(INSTANCE_ID);
  });

  it('inspect maps states and reports missing on NOT_FOUND', async () => {
    const { client, calls } = fakeClient();
    const backend = new IncusExecutorBackend({ client, config });
    calls.vmStatus.mockResolvedValueOnce({ state: 'running' });
    expect((await backend.inspect(ctx())).state).toBe('running');
    calls.vmStatus.mockRejectedValueOnce(new VmSupervisorCallError('NOT_FOUND', 'gone', 404, false));
    expect((await backend.inspect(ctx())).state).toBe('missing');
  });

  it('capabilities returns the shared incus-vm map', () => {
    const { client } = fakeClient();
    const backend = new IncusExecutorBackend({ client, config });
    const caps = backend.capabilities();
    expect(caps).toEqual(INCUS_VM_BACKEND_CAPABILITIES);
    expect(caps['packages-bind']).toBe('unsupported');
    expect(caps['dashboard-repo-skills']).toBe('unsupported');
  });
});

// ---------------------------------------------------------------------------
// Review-hardening: durable provision marker (M3), expiry gate (M4),
// pullTree guards (M9), ordered bounded PTY writes (M8)
// ---------------------------------------------------------------------------

describe('IncusExecutorBackend provision sentinels (M3)', () => {
  it('provision pushes each asset then writes its completion sentinel', async () => {
    const { client, calls } = fakeClient();
    const order: string[] = [];
    calls.pushTree.mockImplementation(async () => { order.push('pushTree'); return { sha256: 'c'.repeat(64), bytes: 1, entryCount: 0 }; });
    calls.filePush.mockImplementation(async () => { order.push('filePush'); return { sha256: 'e'.repeat(64), bytes: 1 }; });
    const dir = await mkdtemp(join(tmpdir(), 'ch-m3-'));
    await mkdir(join(dir, 'skills'), { recursive: true });
    const backend = new IncusExecutorBackend({
      client, config,
      provisionAssets: async () => [{ hostDir: dir, guestPath: '/workspace/skills' }]
    });
    await backend.provision(ctx());
    expect(order).toEqual(['pushTree', 'filePush']);
    const sentinelParams = calls.filePush.mock.calls.at(-1)![1] as { guestPath: string; dataBase64: string };
    expect(sentinelParams.guestPath).toContain('/opt/user-tools/.cloud-harness-provisioned-');
    expect(sentinelParams.guestPath).toContain(INSTANCE_ID);
    await rm(dir, { recursive: true, force: true });
  });

  it('adopt skips assets whose sentinel exists; repairs only confirmed-absent destinations', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue({
      state: 'running',
      userCloudHarness: { workspaceId: IDENT.workspaceId, instanceId: INSTANCE_ID, templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST, generationPolicy: 'external' }
    });
    const dir = await mkdtemp(join(tmpdir(), 'ch-m3b-'));
    await mkdir(join(dir, 's'), { recursive: true });
    const backend = new IncusExecutorBackend({
      client, config,
      provisionAssets: async () => [{ hostDir: dir, guestPath: '/workspace/s' }]
    });

    // Sentinel present (fileStat isDir:false on .cloud-harness-provisioned*)
    // → completion hint honored → zero pushes.
    await backend.ensureActive(ctx());
    expect(calls.pushTree).not.toHaveBeenCalled();
    expect(calls.filePush).not.toHaveBeenCalled();

    // Sentinel absent (NOT_FOUND) AND destination absent (NOT_FOUND) → the
    // only safe repair: pushTree into confirmed-empty guestPath + sentinel.
    calls.fileStat.mockImplementation(async (_id: unknown, params: { guestPath: string }) => {
      if (params.guestPath === '/workspace/s' || params.guestPath.includes('.cloud-harness-provisioned')) {
        throw new VmSupervisorCallError('NOT_FOUND', 'absent', 404, false);
      }
      return { size: 1, mode: 0o755, mtime: 1, isDir: true };
    });
    await backend.ensureActive(ctx());
    expect(calls.pushTree).toHaveBeenCalledTimes(1);
    expect(calls.filePush).toHaveBeenCalledTimes(1);
    const pushed = calls.pushTree.mock.calls.at(-1)![1] as { guestPath: string };
    expect(pushed.guestPath).toBe('/workspace/s');
    await rm(dir, { recursive: true, force: true });
  });

  it('adopt NEVER overwrites an existing destination without a sentinel — fails closed (M3)', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue({
      state: 'running',
      userCloudHarness: { workspaceId: IDENT.workspaceId, instanceId: INSTANCE_ID, templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST, generationPolicy: 'external' }
    });
    const dir = await mkdtemp(join(tmpdir(), 'ch-m3c-'));
    await mkdir(join(dir, 's'), { recursive: true });
    const backend = new IncusExecutorBackend({
      client, config,
      provisionAssets: async () => [{ hostDir: dir, guestPath: '/workspace/s' }]
    });

    // Sentinel absent BUT destination exists (dir, file, or symlink target —
    // file.stat follows links): content is unverified → refuse to overwrite.
    calls.fileStat.mockImplementation(async (_id: unknown, params: { guestPath: string }) => {
      if (params.guestPath.includes('.cloud-harness-provisioned')) {
        throw new VmSupervisorCallError('NOT_FOUND', 'no sentinel', 404, false);
      }
      return { size: 1, mode: 0o755, mtime: 1, isDir: params.guestPath === '/workspace/s' };
    });
    await expect(backend.ensureActive(ctx())).rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(calls.pushTree).not.toHaveBeenCalled();
    expect(calls.filePush).not.toHaveBeenCalled();
    await rm(dir, { recursive: true, force: true });
  });
});

describe('IncusExecutorBackend expiry gate (M4)', () => {
  it('refuses provision/ensureActive on an expired record before any supervisor call', async () => {
    const { client, calls } = fakeClient();
    const backend = new IncusExecutorBackend({ client, config });
    const expired = record({ expiresAt: 1, hardExpiresAt: 2 });
    await expect(backend.provision(ctx({ record: expired }))).rejects.toMatchObject({ code: 'EXPIRED' });
    await expect(backend.ensureActive(ctx({ record: expired }))).rejects.toMatchObject({ code: 'EXPIRED' });
    expect(calls.vmCreate).not.toHaveBeenCalled();
    expect(calls.vmStatus).not.toHaveBeenCalled();
  });
});

describe('IncusExecutorBackend pullTree guards (M9)', () => {
  it('rejects a non-directory guestPath before streaming', async () => {
    const { client, calls } = fakeClient();
    calls.fileStat.mockResolvedValueOnce({ size: 1, mode: 0o644, mtime: 1, isDir: false });
    const backend = new IncusExecutorBackend({ client, config });
    const out = await mkdtemp(join(tmpdir(), 'ch-pt-out-'));
    await expect(backend.pullTree(ctx(), '/workspace/file.txt', out)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(calls.pullTree).not.toHaveBeenCalled();
    await rm(out, { recursive: true, force: true });
  });

  it('rejects a tar whose entries escape the destination via symlink (M9)', async () => {
    const src = await mkdtemp(join(tmpdir(), 'ch-evil-'));
    const outside = await mkdtemp(join(tmpdir(), 'ch-outside-'));
    await writeFile(join(outside, 'secret.txt'), 'host-secret');
    // Guest tars `-C guestPath .` → members './x'; strip-components=1 leaves 'x'.
    await mkdir(join(src, 'tree'));
    await execFile('ln', ['-s', outside, join(src, 'tree', 'evil')]);
    const tarPath = join(src, 'packed.tar');
    await runTar('tar', ['-cf', tarPath, '-C', src, 'tree']);
    const tarBytes = await readFile(tarPath);

    const { client, calls } = fakeClient();
    calls.pullTree.mockImplementationOnce(async (_id: unknown, _p: unknown, opts: { sink: (c: Buffer) => void }) => {
      opts.sink(tarBytes);
      return { sha256: 'd'.repeat(64), bytes: tarBytes.length, entryCount: 1 };
    });
    const backend = new IncusExecutorBackend({ client, config });
    const hostDir = join(src, 'host-out');
    await expect(backend.pullTree(ctx({ record: record({ workspacePath: src }) }), '/workspace/evil', hostDir))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Host dir must not contain a planted symlink.
    const { readdir, lstat } = await import('node:fs/promises');
    const entries = await readdir(hostDir).catch(() => [] as string[]);
    for (const e of entries) {
      expect((await lstat(join(hostDir, e))).isSymbolicLink()).toBe(false);
    }
    await rm(src, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  });
});

describe('IncusPtyTransport ordered bounded writes (M8)', () => {
  it('serializes exec.write calls in order and bounds the pending queue', async () => {
    const { client, calls } = fakeClient();
    // Session fake: never ends; execWrite deferred so ordering is observable.
    const session = {
      sessionId: 'pty-t1',
      onData: () => () => undefined,
      onMeta: () => () => undefined,
      ended: new Promise(() => undefined),
      closed: false,
      resume: () => undefined,
      close: () => undefined
    };
    calls.execOpen.mockResolvedValue(session);
    const writeOrder: string[] = [];
    let releaseFirst: (() => void) | undefined;
    calls.execWrite
      .mockImplementationOnce(async (_id: unknown, params: { dataBase64: string }) => {
        writeOrder.push(Buffer.from(params.dataBase64, 'base64').toString());
        await new Promise<void>((r) => { releaseFirst = r; });
        return { acceptedBytes: 1 };
      })
      .mockImplementation(async (_id: unknown, params: { dataBase64: string }) => {
        writeOrder.push(Buffer.from(params.dataBase64, 'base64').toString());
        return { acceptedBytes: 1 };
      });

    const { IncusPtyTransport } = await import('../src/incus-executor-backend.js');
    const transport = new IncusPtyTransport(client, () => IDENT);
    const conn = await transport.open({ container: 'chm-vm-x', terminalId: 't1', workingDir: '/workspace', cols: 80, rows: 24 });
    conn.write(Buffer.from('first'));
    conn.write(Buffer.from('second'));
    // Second write must NOT reach the wire until the first resolves.
    await new Promise((r) => setTimeout(r, 20));
    expect(writeOrder).toEqual(['first']);
    expect(conn.writableLength).toBeGreaterThan(0);
    releaseFirst!();
    await new Promise((r) => setTimeout(r, 20));
    expect(writeOrder).toEqual(['first', 'second']);
    expect(conn.writableLength).toBe(0);
    conn.close();
  });
});

// ---------------------------------------------------------------------------
// Round-2 review: recoverable resume (H5), tar abort/bounds (M11/M12)
// ---------------------------------------------------------------------------

describe('IncusExecutorBackend recoverable resume (H5)', () => {
  const RUNNING = {
    state: 'running' as const,
    userCloudHarness: {
      workspaceId: IDENT.workspaceId, instanceId: INSTANCE_ID,
      templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST, generationPolicy: 'external' as const
    }
  };
  const STOPPED = { ...RUNNING, state: 'stopped' as const };
  const recoverable = (overrides: Partial<WorkspaceRecord> = {}) => record({
    status: 'EXPIRED_RECOVERABLE',
    expiresAt: Date.now() - 60_000,
    recoverableUntil: Date.now() + 600_000,
    hardExpiresAt: Date.now() + 3_600_000,
    ...overrides
  });

  it('running VM: lease.clear+lease.set(recovery) run BEFORE vm.status, then adopt', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue(RUNNING);
    const backend = new IncusExecutorBackend({ client, config });
    const rec = recoverable();
    await expect(backend.ensureActive(ctx({ record: rec }))).resolves.toMatchObject({ backend: 'incus-vm' });
    expect(calls.leaseClear).toHaveBeenCalledTimes(1);
    expect(calls.leaseSet).toHaveBeenCalledTimes(1);
    const setParams = calls.leaseSet.mock.calls[0]![1] as { expiresAt: number; hardExpiresAt: number };
    expect(setParams.hardExpiresAt).toBe(rec.hardExpiresAt);
    expect(setParams.expiresAt).toBe(Math.min(rec.hardExpiresAt, rec.recoverableUntil!));
    // The expired stored lease would refuse every workspace op — recovery
    // must precede the status probe.
    expect(calls.leaseClear.mock.invocationCallOrder[0]!).toBeLessThan(calls.vmStatus.mock.invocationCallOrder[0]!);
    expect(calls.leaseSet.mock.invocationCallOrder[0]!).toBeLessThan(calls.vmStatus.mock.invocationCallOrder[0]!);
    expect(calls.vmStart).not.toHaveBeenCalled();
    expect(calls.vmCreate).not.toHaveBeenCalled();
  });

  it('stopped VM: recovery lease then the normal vm.start admission path', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue(STOPPED);
    const backend = new IncusExecutorBackend({ client, config });
    await expect(backend.ensureActive(ctx({ record: recoverable() }))).resolves.toMatchObject({ backend: 'incus-vm' });
    expect(calls.vmStart).toHaveBeenCalledTimes(1);
    expect(calls.leaseSet.mock.invocationCallOrder[0]!).toBeLessThan(calls.vmStart.mock.invocationCallOrder[0]!);
  });

  it('NOT_FOUND journal row: recovery lease tolerates absence, provision uses recovery times', async () => {
    const { client, calls } = fakeClient();
    calls.leaseClear.mockRejectedValueOnce(new VmSupervisorCallError('NOT_FOUND', 'no row', 404, false));
    calls.vmStatus.mockRejectedValueOnce(new VmSupervisorCallError('NOT_FOUND', 'no row', 404, false));
    const backend = new IncusExecutorBackend({ client, config });
    const rec = recoverable();
    await expect(backend.ensureActive(ctx({ record: rec }))).resolves.toMatchObject({ backend: 'incus-vm' });
    expect(calls.vmCreate).toHaveBeenCalledTimes(1);
    // provision's own lease.set carried recovery times, not the stale expiry.
    const provisionSet = calls.leaseSet.mock.calls.at(-1)![1] as { expiresAt: number; hardExpiresAt: number };
    expect(provisionSet.expiresAt).toBe(Math.min(rec.hardExpiresAt, rec.recoverableUntil!));
    expect(provisionSet.hardExpiresAt).toBe(rec.hardExpiresAt);
  });

  it('hard expiry is an unconditional zero-call cutoff even for recoverable records', async () => {
    const { client, calls } = fakeClient();
    const backend = new IncusExecutorBackend({ client, config });
    const rec = recoverable({ hardExpiresAt: Date.now() - 1 });
    await expect(backend.ensureActive(ctx({ record: rec }))).rejects.toMatchObject({ code: 'EXPIRED' });
    await expect(backend.provision(ctx({ record: rec }))).rejects.toMatchObject({ code: 'EXPIRED' });
    for (const m of ['vmStatus', 'leaseClear', 'leaseSet', 'vmCreate', 'vmStart'] as const) {
      expect(calls[m]).not.toHaveBeenCalled();
    }
  });

  it('closed recoverable window and ACTIVE-with-past-expiry are both refused', async () => {
    const { client, calls } = fakeClient();
    const backend = new IncusExecutorBackend({ client, config });
    await expect(backend.ensureActive(ctx({ record: recoverable({ recoverableUntil: Date.now() - 1 }) })))
      .rejects.toMatchObject({ code: 'EXPIRED' });
    await expect(backend.ensureActive(ctx({ record: record({ expiresAt: Date.now() - 1 }) })))
      .rejects.toMatchObject({ code: 'EXPIRED' });
    expect(calls.vmStatus).not.toHaveBeenCalled();
    expect(calls.leaseClear).not.toHaveBeenCalled();
  });

  it('recovery expiresAt never exceeds the exact hard cutoff', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue(RUNNING);
    const backend = new IncusExecutorBackend({ client, config });
    const hard = Date.now() + 60_000;
    const rec = recoverable({ hardExpiresAt: hard, recoverableUntil: hard + 600_000 });
    await backend.ensureActive(ctx({ record: rec }));
    const setParams = calls.leaseSet.mock.calls[0]![1] as { expiresAt: number; hardExpiresAt: number };
    expect(setParams.expiresAt).toBe(hard);
    expect(setParams.hardExpiresAt).toBe(hard);
  });

  it('a healthy ACTIVE record skips the lease-recovery round-trip entirely', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue(RUNNING);
    const backend = new IncusExecutorBackend({ client, config });
    await backend.ensureActive(ctx());
    expect(calls.leaseClear).not.toHaveBeenCalled();
    expect(calls.leaseSet).not.toHaveBeenCalled();
  });
});

describe('IncusExecutorBackend leaseExpiresAt intent (H5 seam)', () => {
  const RUNNING = {
    state: 'running' as const,
    userCloudHarness: {
      workspaceId: IDENT.workspaceId, instanceId: INSTANCE_ID,
      templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST, generationPolicy: 'external' as const
    }
  };
  const recoverable = (overrides: Partial<WorkspaceRecord> = {}) => record({
    status: 'EXPIRED_RECOVERABLE',
    expiresAt: Date.now() - 60_000,
    recoverableUntil: Date.now() + 600_000,
    hardExpiresAt: Date.now() + 3_600_000,
    ...overrides
  });
  const leaseSetParams = (calls: ReturnType<typeof fakeClient>['calls']) =>
    calls.leaseSet.mock.calls[0]![1] as { expiresAt: number; hardExpiresAt: number };

  it('caller intent wins over the recoverable window: durable lease equals the requested renewal', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue(RUNNING);
    const backend = new IncusExecutorBackend({ client, config });
    const rec = recoverable();
    // Short renewal (60s) inside a 10-minute recoverable window: the OLD
    // record-derived bound would have leased ~10min — longer than asked.
    const intent = Date.now() + 60_000;
    await backend.ensureActive(ctx({ record: rec, leaseExpiresAt: intent }));
    const set = leaseSetParams(calls);
    expect(set.expiresAt).toBe(intent);
    expect(set.hardExpiresAt).toBe(rec.hardExpiresAt);
    expect(set.expiresAt).toBeLessThan(rec.recoverableUntil!);
  });

  it('intent may exceed recoverableUntil — it bounds admission, never the ACTIVE expiry', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue(RUNNING);
    const backend = new IncusExecutorBackend({ client, config });
    const rec = recoverable();
    const intent = Date.now() + 1_800_000; // > recoverableUntil(+600s), < hard(+3600s)
    await backend.ensureActive(ctx({ record: rec, leaseExpiresAt: intent }));
    expect(leaseSetParams(calls).expiresAt).toBe(intent);
  });

  it('intent equal to hardExpiresAt is the exact cutoff; beyond it clamps to hard', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue(RUNNING);
    const backend = new IncusExecutorBackend({ client, config });
    const hard = Date.now() + 3_600_000;
    const rec = recoverable({ hardExpiresAt: hard });
    await backend.ensureActive(ctx({ record: rec, leaseExpiresAt: hard }));
    expect(leaseSetParams(calls)).toEqual({ expiresAt: hard, hardExpiresAt: hard });

    calls.leaseSet.mockClear();
    calls.leaseClear.mockClear();
    calls.vmStatus.mockClear();
    await backend.ensureActive(ctx({ record: rec, leaseExpiresAt: hard + 60_000 }));
    expect(leaseSetParams(calls).expiresAt).toBe(hard);
  });

  it('invalid intent fails BEFORE any lease mutation — stored lease untouched', async () => {
    const { client, calls } = fakeClient();
    const backend = new IncusExecutorBackend({ client, config });
    const rec = recoverable();
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Date.now() - 1, Date.now()]) {
      calls.leaseClear.mockClear(); calls.leaseSet.mockClear(); calls.vmStatus.mockClear();
      await expect(backend.ensureActive(ctx({ record: rec, leaseExpiresAt: bad })))
        .rejects.toMatchObject({ code: 'INVALID_INPUT' });
      for (const m of ['leaseClear', 'leaseSet', 'vmStatus', 'vmCreate', 'vmStart'] as const) {
        expect(calls[m]).not.toHaveBeenCalled();
      }
    }
  });

  it('absent intent keeps the record-derived recoverable-window bound', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue(RUNNING);
    const backend = new IncusExecutorBackend({ client, config });
    const rec = recoverable();
    await backend.ensureActive(ctx({ record: rec }));
    expect(leaseSetParams(calls).expiresAt).toBe(Math.min(rec.hardExpiresAt, rec.recoverableUntil!));
  });

  it('NOT_FOUND → provision leases at the caller intent, not the recoverable window', async () => {
    const { client, calls } = fakeClient();
    calls.leaseClear.mockRejectedValueOnce(new VmSupervisorCallError('NOT_FOUND', 'no row', 404, false));
    calls.vmStatus.mockRejectedValueOnce(new VmSupervisorCallError('NOT_FOUND', 'no row', 404, false));
    const backend = new IncusExecutorBackend({ client, config });
    const rec = recoverable();
    const intent = Date.now() + 60_000;
    await expect(backend.ensureActive(ctx({ record: rec, leaseExpiresAt: intent })))
      .resolves.toMatchObject({ backend: 'incus-vm' });
    const provisionSet = calls.leaseSet.mock.calls.at(-1)![1] as { expiresAt: number; hardExpiresAt: number };
    expect(provisionSet.expiresAt).toBe(intent);
    expect(provisionSet.hardExpiresAt).toBe(rec.hardExpiresAt);
  });

  it('recovery lease keys are unique per attempt — a retry after clear cannot replay a stale record', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue(RUNNING);
    const backend = new IncusExecutorBackend({ client, config });
    const rec = recoverable();
    await backend.ensureActive(ctx({ record: rec }));
    await backend.ensureActive(ctx({ record: rec }));
    const clearKeys = calls.leaseClear.mock.calls.map((c) => (c[1] as { idempotencyKey: string }).idempotencyKey);
    const setKeys = calls.leaseSet.mock.calls.map((c) => (c[2] as { idempotencyKey: string }).idempotencyKey);
    expect(new Set(clearKeys).size).toBe(2);
    expect(new Set(setKeys).size).toBe(2);
  });
});

describe('IncusExecutorBackend post-start activation rollback', () => {
  const RUNNING = {
    state: 'running' as const,
    userCloudHarness: {
      workspaceId: IDENT.workspaceId, instanceId: INSTANCE_ID,
      templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST, generationPolicy: 'external' as const
    }
  };
  const STOPPED = { ...RUNNING, state: 'stopped' as const };
  const recoverable = (overrides: Partial<WorkspaceRecord> = {}) => record({
    status: 'EXPIRED_RECOVERABLE',
    expiresAt: Date.now() - 60_000,
    recoverableUntil: Date.now() + 600_000,
    hardExpiresAt: Date.now() + 3_600_000,
    ...overrides
  });
  // Forces ensureProvisionAssets to hit the M3 fail-closed path: sentinel
  // absent (NOT_FOUND) + destination exists (dir) → refuses to overwrite.
  const failingAssets = () => ({
    provisionAssets: async () => [{ hostDir: '/tmp/skills', guestPath: '/opt/cloud-harness/skills' }]
  });
  const sabotageAssets = (calls: ReturnType<typeof fakeClient>['calls']) => {
    calls.fileStat.mockImplementation(async (_id: unknown, params: { guestPath: string }) => {
      if (params.guestPath.includes('.cloud-harness-provisioned')) {
        throw new VmSupervisorCallError('NOT_FOUND', 'absent', 404, false);
      }
      return { size: 1, mode: 0o755, mtime: 1, isDir: true };
    });
  };

  it('recoverable + stopped: confirmed start then asset failure → vmStop AND leaseClear', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue(STOPPED);
    sabotageAssets(calls);
    const backend = new IncusExecutorBackend({ client, config, ...failingAssets() });
    await expect(backend.ensureActive(ctx({ record: recoverable() })))
      .rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(calls.vmStart).toHaveBeenCalledTimes(1);
    expect(calls.vmStop).toHaveBeenCalledTimes(1);
    // leaseClear: one recovery clear + one rollback clear.
    expect(calls.leaseClear).toHaveBeenCalledTimes(2);
    expect(calls.vmDelete).not.toHaveBeenCalled();
  });

  it('recoverable + running adopt: asset failure → vmStop AND leaseClear (lease was extended by us)', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue(RUNNING);
    sabotageAssets(calls);
    const backend = new IncusExecutorBackend({ client, config, ...failingAssets() });
    await expect(backend.ensureActive(ctx({ record: recoverable() })))
      .rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(calls.vmStop).toHaveBeenCalledTimes(1);
    expect(calls.leaseClear).toHaveBeenCalledTimes(2);
  });

  it('non-recoverable + started: asset failure → vmStop but lease KEPT (healthy ACTIVE lease must not be cleared)', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue(STOPPED);
    sabotageAssets(calls);
    const backend = new IncusExecutorBackend({ client, config, ...failingAssets() });
    await expect(backend.ensureActive(ctx()))
      .rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(calls.vmStop).toHaveBeenCalledTimes(1);
    expect(calls.leaseClear).not.toHaveBeenCalled();
    expect(calls.leaseSet).not.toHaveBeenCalled();
  });

  it('non-recoverable + running adopt: asset failure → NO rollback (VM was legitimately running)', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue(RUNNING);
    sabotageAssets(calls);
    const backend = new IncusExecutorBackend({ client, config, ...failingAssets() });
    await expect(backend.ensureActive(ctx()))
      .rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(calls.vmStop).not.toHaveBeenCalled();
    expect(calls.leaseClear).not.toHaveBeenCalled();
  });

  it('recoverable + transient VM state: unlease only, never stop an unknown-state disk', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue({ ...RUNNING, state: 'starting' as const });
    const backend = new IncusExecutorBackend({ client, config });
    await expect(backend.ensureActive(ctx({ record: recoverable() })))
      .rejects.toMatchObject({ code: 'UNAVAILABLE' });
    expect(calls.vmStop).not.toHaveBeenCalled();
    expect(calls.leaseClear).toHaveBeenCalledTimes(2); // recovery clear + rollback unlease
  });

  it('recoverable + identity mismatch: unlease only — ambiguous disk left running untouched', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue({
      state: 'running' as const,
      userCloudHarness: { ...RUNNING.userCloudHarness, instanceId: '00000000-0000-4000-8000-000000000000' }
    });
    const backend = new IncusExecutorBackend({ client, config });
    await expect(backend.ensureActive(ctx({ record: recoverable() })))
      .rejects.toMatchObject({ code: 'VM_IDENTITY_MISMATCH' });
    expect(calls.vmStop).not.toHaveBeenCalled();
    expect(calls.leaseClear).toHaveBeenCalledTimes(2);
  });

  it('provision: asset failure after confirmed vm.create+start → vmStop, lease retained for replay-safe retry', async () => {
    const { client, calls } = fakeClient();
    const src = await mkdtemp(join(tmpdir(), 'ch-h5-assets-'));
    calls.pushTree.mockRejectedValueOnce(new Error('wire lost mid-push'));
    const backend = new IncusExecutorBackend({
      client, config,
      provisionAssets: async () => [{ hostDir: src, guestPath: '/opt/cloud-harness/skills' }]
    });
    await expect(backend.provision(ctx()))
      .rejects.toThrow('wire lost mid-push');
    expect(calls.vmCreate).toHaveBeenCalledTimes(1);
    expect(calls.vmStart).toHaveBeenCalledTimes(1);
    expect(calls.vmStop).toHaveBeenCalledTimes(1);
    expect(calls.leaseClear).not.toHaveBeenCalled();
    expect(calls.vmDelete).not.toHaveBeenCalled();
  });

  it('repeatable mutation keys are unique per attempt — a post-rollback retry cannot replay a stale success', async () => {
    const { client, calls } = fakeClient();
    calls.vmStatus.mockResolvedValue(STOPPED);
    const backend = new IncusExecutorBackend({ client, config });
    const rec = recoverable();
    // Two full activate cycles in the SAME recoverable window: recovery
    // lease clear/set, provision-path lease.set, and every vm.start must
    // carry fresh keys — the supervisor replays completed records without
    // re-executing, so any repeated key would return a stale success while
    // the real VM sits stopped/unleased.
    await backend.ensureActive(ctx({ record: rec }));
    await backend.ensureActive(ctx({ record: rec }));
    const keyOf = (fn: { mock: { calls: unknown[][] } }, idx: number) =>
      (fn.mock.calls.map((c) => (c[idx] as { idempotencyKey?: string })?.idempotencyKey).filter(Boolean)) as string[];
    for (const [fn, idx] of [
      [calls.vmStart, 2], [calls.leaseSet, 2], [calls.leaseClear, 1]
    ] as const) {
      const keys = keyOf(fn, idx);
      expect(keys.length).toBeGreaterThanOrEqual(2);
      expect(new Set(keys).size).toBe(keys.length);
    }
    // vm.create/vm.delete stay fixed-key: they are terminal dedup ops where
    // replay IS the correct semantics (create-once, delete-once).
  });
});

describe('IncusExecutorBackend tar abort + creation bound (M11/M12)', () => {
  it('pushTree aborts tar creation promptly on signal — never waits out the timeout', async () => {
    const { open } = await import('node:fs/promises');
    const src = await mkdtemp(join(tmpdir(), 'ch-m11-src-'));
    const jobDir = await mkdtemp(join(tmpdir(), 'ch-m11-job-'));
    // Sparse 2 GiB: tar emits output long enough for the abort to land mid-write.
    const fh = await open(join(src, 'huge.bin'), 'w');
    await fh.truncate(2 * 1024 ** 3);
    await fh.close();
    const { client, calls } = fakeClient();
    const backend = new IncusExecutorBackend({ client, config });
    const controller = new AbortController();
    const started = Date.now();
    const pending = backend.pushTree(
      ctx({ record: record({ workspacePath: jobDir }), signal: controller.signal }),
      src,
      '/workspace/big'
    );
    setTimeout(() => controller.abort(), 30);
    await expect(pending).rejects.toMatchObject({ code: 'CANCELLED' });
    // Promptness proof: bounded by the signal, not TAR_TIMEOUT_MS (30 min).
    expect(Date.now() - started).toBeLessThan(15_000);
    expect(calls.pushTree).not.toHaveBeenCalled();
    expect((await readdir(jobDir)).filter((n) => n.startsWith('.push-tree-'))).toHaveLength(0);
    await rm(src, { recursive: true, force: true });
    await rm(jobDir, { recursive: true, force: true });
  });

  it('pushTree caps tar creation at the bound — an oversized tree never materializes', async () => {
    const { open } = await import('node:fs/promises');
    const src = await mkdtemp(join(tmpdir(), 'ch-m12-src-'));
    const jobDir = await mkdtemp(join(tmpdir(), 'ch-m12-job-'));
    // Sparse 4 GiB vs an 8 MiB bound: pre-fix this wrote ~4 GiB to staging
    // before the post-hoc compare; now creation is killed at ~8 MiB.
    const fh = await open(join(src, 'huge.bin'), 'w');
    await fh.truncate(4 * 1024 ** 3);
    await fh.close();
    const { client, calls } = fakeClient();
    const backend = new IncusExecutorBackend({
      client,
      config: { ...config, vmMaxWorkspaceBytes: 8 * 1024 * 1024 } as RunnerConfig
    });
    const started = Date.now();
    await expect(backend.pushTree(ctx({ record: record({ workspacePath: jobDir }) }), src, '/workspace/big'))
      .rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    expect(Date.now() - started).toBeLessThan(15_000);
    expect(calls.pushTree).not.toHaveBeenCalled();
    expect((await readdir(jobDir)).filter((n) => n.startsWith('.push-tree-'))).toHaveLength(0);
    await rm(src, { recursive: true, force: true });
    await rm(jobDir, { recursive: true, force: true });
  });

  it('pullTree extract honors AbortSignal — tar child is killed, staging removed', async () => {
    const src = await mkdtemp(join(tmpdir(), 'ch-m11x-src-'));
    const jobDir = await mkdtemp(join(tmpdir(), 'ch-m11x-job-'));
    // Many small members → extraction takes measurable time so the abort
    // lands inside runTar rather than in the wire phase.
    const treeDir = join(src, 'tree');
    await mkdir(treeDir);
    for (let i = 0; i < 6000; i += 1) {
      await writeFile(join(treeDir, `f${i}.txt`), 'x');
    }
    const tarPath = join(src, 'in.tar');
    await runTar('tar', ['-cf', tarPath, '-C', src, 'tree']);
    const tarBytes = await readFile(tarPath);

    const { client } = fakeClient();
    client.pullTree.mockImplementationOnce(async (_id: unknown, _p: unknown, opts: { sink: (c: Buffer) => void }) => {
      opts.sink(tarBytes);
      return { sha256: 'd'.repeat(64), bytes: tarBytes.length, entryCount: 6000 };
    });
    const backend = new IncusExecutorBackend({ client, config });
    const controller = new AbortController();
    const started = Date.now();
    const pending = backend.pullTree(
      ctx({ record: record({ workspacePath: jobDir }), signal: controller.signal }),
      '/workspace/tree',
      join(src, 'out')
    );
    setTimeout(() => controller.abort(), 60);
    await expect(pending).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(Date.now() - started).toBeLessThan(20_000);
    expect((await readdir(jobDir)).filter((n) => n.startsWith('.pull-tree-'))).toHaveLength(0);
    await rm(src, { recursive: true, force: true });
    await rm(jobDir, { recursive: true, force: true });
  });
});

// ---------------------------------------------------------------------------
// Round-2 review: staging reservation ordering, verbatim symlinks, stream IO
// ---------------------------------------------------------------------------

describe('IncusExecutorBackend staging reservation ordering', () => {
  it('a refused pushTree reservation creates no staging dir or tar file', async () => {
    const src = await mkdtemp(join(tmpdir(), 'ch-push-'));
    const jobDir = await mkdtemp(join(tmpdir(), 'ch-job-'));
    try {
      await mkdir(join(src, 'tree'), { recursive: true });
      await writeFile(join(src, 'tree', 'a.txt'), 'x');
      const { client } = fakeClient();
      const backend = new IncusExecutorBackend({ client, config });
      // Saturate the shared ledger: a reservation of (free - margin) passes
      // the statfs check, after which ANY positive acquire fails LIMIT_EXCEEDED.
      const info = await statfs(jobDir);
      const free = Number(info.bavail) * Number(info.bsize);
      const blockerBytes = Math.max(0, free - 1024 * 1024 * 1024);
      const baseline = stagingReservations.reservedBytes;
      let blocker: (() => void) | undefined;
      if (blockerBytes > 0) {
        blocker = await stagingReservations.acquire('round2-blocker', jobDir, blockerBytes);
      }
      const before = await readdir(jobDir);
      try {
        await expect(
          backend.pushTree(ctx({ record: record({ workspacePath: jobDir }) }), join(src, 'tree'), '/workspace/in')
        ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
      } finally {
        blocker?.();
      }
      // No staging dir, no tar, and the ledger returned to its prior total —
      // the acquire must precede mkdir/writer creation and release on refusal.
      expect(await readdir(jobDir)).toEqual(before);
      expect(stagingReservations.reservedBytes).toBe(baseline);
    } finally {
      await rm(src, { recursive: true, force: true });
      await rm(jobDir, { recursive: true, force: true });
    }
  });

  it('concurrent staging acquires cannot approve against the same statfs snapshot', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'ch-statfs-'));
    try {
      const info = await statfs(dir);
      const free = Number(info.bavail) * Number(info.bsize);
      const margin = 1024 * 1024 * 1024;
      // Two acquires each sized to fit alone must not BOTH pass: the second
      // sees the first's hold in heldTotal before its own statfs await.
      const half = Math.floor((free - margin) / 2);
      if (half <= 0) return; // filesystem too small to discriminate; skip
      const first = await stagingReservations.acquire('race-a', dir, half);
      try {
        await expect(stagingReservations.acquire('race-b', dir, half + margin / 2))
          .rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
      } finally {
        first();
      }
      expect(stagingReservations.reservedBytes).toBe(0);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});

describe('IncusExecutorBackend pullTree verbatim symlinks', () => {
  it('preserves relative symlink targets instead of rewriting them to staging paths', async () => {
    const src = await mkdtemp(join(tmpdir(), 'ch-vsym-'));
    const jobDir = await mkdtemp(join(tmpdir(), 'ch-vjob-'));
    const out = join(src, 'out');
    try {
      await mkdir(join(src, 'tree', 'sub'), { recursive: true });
      await writeFile(join(src, 'tree', 'sub', 'target.txt'), 'data');
      await symlink('sub/target.txt', join(src, 'tree', 'link'));
      const tarPath = join(src, 'in.tar');
      await runTar('tar', ['-cf', tarPath, '-C', src, 'tree']);
      const tarBytes = await readFile(tarPath);
      const { client } = fakeClient();
      client.pullTree.mockImplementationOnce(async (_id: unknown, _p: unknown, opts: { sink: (c: Buffer) => void }) => {
        opts.sink(tarBytes);
        return { sha256: 'd'.repeat(64), bytes: tarBytes.length, entryCount: 2 };
      });
      const backend = new IncusExecutorBackend({ client, config });
      await backend.pullTree(ctx({ record: record({ workspacePath: jobDir }) }), '/workspace/tree', out);
      const linkPath = join(out, 'link');
      expect((await lstat(linkPath)).isSymbolicLink()).toBe(true);
      // The RELATIVE target must survive verbatim — cp's default rewrites it
      // to an absolute staging path that dangles after staging cleanup.
      expect(await readlink(linkPath)).toBe('sub/target.txt');
      expect(await readFile(join(out, 'link'), 'utf8')).toBe('data');
    } finally {
      await rm(src, { recursive: true, force: true });
      await rm(jobDir, { recursive: true, force: true });
    }
  });
});

describe('VmExecStreamHandle stdin slicing and backpressure', () => {
  function streamSession() {
    let dataListener: ((fd: number, chunk: Buffer) => boolean | void) | undefined;
    const session = {
      sessionId: 'stream-s1',
      onData: (listener: (fd: number, chunk: Buffer) => boolean | void) => {
        dataListener = listener;
        return () => undefined;
      },
      onMeta: () => () => undefined,
      ended: new Promise(() => undefined),
      closed: false,
      resume: vi.fn(),
      close: () => undefined
    };
    return { session, emit: (fd: number, chunk: Buffer) => dataListener?.(fd, chunk) };
  }

  it('slices exec.write stdin chunks below the 1 MiB control-frame bound, in order', async () => {
    const { client, calls } = fakeClient();
    const { session } = streamSession();
    calls.execOpen.mockResolvedValue(session);
    calls.execWrite.mockResolvedValue({ acceptedBytes: 0 });
    const backend = new IncusExecutorBackend({ client, config });
    const handle = await backend.spawnStream(ctx(), {
      argv: ['cat'], cwd: '/workspace', environment: {}
    });
    // 600 KiB in ONE write() must become three ordered exec.write calls, each
    // far below the ~1 MiB dataBase64 control cap.
    const payload = Buffer.alloc(600 * 1024, 0x61);
    await new Promise<void>((resolve, reject) => {
      handle.stdin.write(payload, (error) => (error ? reject(error) : resolve()));
    });
    const writes = calls.execWrite.mock.calls.map((c) => Buffer.from((c[1] as { dataBase64: string }).dataBase64, 'base64'));
    expect(writes.length).toBe(3);
    for (const w of writes) expect(w.length).toBeLessThanOrEqual(256 * 1024);
    expect(Buffer.concat(writes)).toEqual(payload);
    handle.kill();
  });

  it('pauses session delivery when push() reports a full buffer and resumes on _read', async () => {
    const { client, calls } = fakeClient();
    const { session, emit } = streamSession();
    calls.execOpen.mockResolvedValue(session);
    const backend = new IncusExecutorBackend({ client, config });
    const handle = await backend.spawnStream(ctx(), {
      argv: ['cat'], cwd: '/workspace', environment: {}
    });
    // Feed until the readable's high-water mark is exceeded: onData must
    // return false exactly then (an inverted check would resume instead).
    let last: boolean | void = undefined;
    for (let i = 0; i < 200 && last !== false; i += 1) {
      last = emit(1, Buffer.alloc(64 * 1024));
    }
    expect(last).toBe(false);
    expect(session.resume).not.toHaveBeenCalled();
    // Draining the stream fires _read → session.resume() restarts delivery.
    // Flowing mode guarantees the buffered chunks are consumed and _read runs.
    handle.stdout.on('data', () => undefined);
    handle.stdout.resume();
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(session.resume).toHaveBeenCalled();
    handle.kill();
  });
});

describe('VmExecStreamHandle multiline env channel boundary', () => {
  it('permits line breaks only in CH_COMMAND and rejects the channel for any other name', async () => {
    const { client, calls } = fakeClient();
    calls.execOpen.mockResolvedValue({
      sessionId: 'ml-s1',
      onData: () => () => undefined,
      onMeta: () => () => undefined,
      ended: new Promise(() => undefined),
      closed: false,
      resume: () => undefined,
      close: () => undefined
    });
    const backend = new IncusExecutorBackend({ client, config });
    // CH_COMMAND may carry the public multiline command contract.
    const ok = await backend.spawnStream(ctx(), {
      argv: ['runner'], cwd: '/workspace',
      environment: { CH_COMMAND: 'echo one\necho two' },
      multilineEnvNames: ['CH_COMMAND']
    });
    ok.kill();
    // A secret-bearing name can NEVER opt into the multiline channel — the
    // request is rejected before any supervisor call.
    calls.execOpen.mockClear();
    await expect(backend.spawnStream(ctx(), {
      argv: ['runner'], cwd: '/workspace',
      environment: { SECRET_TOKEN: 'line1\nline2' },
      multilineEnvNames: ['SECRET_TOKEN']
    })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(backend.spawnStream(ctx(), {
      argv: ['runner'], cwd: '/workspace',
      environment: { SECRET_TOKEN: 'line1\nline2' },
      multilineEnvNames: ['CH_COMMAND', 'SECRET_TOKEN']
    })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // And without the channel opt-in, a newline in any env value still fails.
    await expect(backend.spawnStream(ctx(), {
      argv: ['runner'], cwd: '/workspace',
      environment: { CH_COMMAND: 'echo one\necho two' }
    })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(calls.execOpen).not.toHaveBeenCalled();
  });
});
