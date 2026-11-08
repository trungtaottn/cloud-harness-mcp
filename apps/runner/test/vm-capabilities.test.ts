import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  BACKEND_CAPABILITY_IDS,
  InternalRunnerOperationSchema,
  RunnerOperationSchema,
  SkillsExtReadDataSchema,
  type MetadataRunnerRequest,
  type RunnerConfig,
  type SkillEntry
} from '@cloud-harness/contracts';

vi.mock('../src/docker-engine.js', () => ({
  runDocker: vi.fn(async () => ({ stdout: '', stderr: '', exitCode: 0, truncated: false })),
  removeContainer: vi.fn(async () => undefined),
  inspectContainer: vi.fn(async () => undefined),
  terminateContainerProcessGroup: vi.fn(async () => undefined),
  spawnDocker: vi.fn()
}));

import { ArtifactStore } from '../src/artifact-store.js';
import { DashboardControlService } from '../src/dashboard-control-service.js';
import { MetadataStore } from '../src/metadata-store.js';
import type { PackageBuildJob, PackageBuildResult, PackageBuilderPort, ResolvePackagePlanSpec, ResolvedPackagePlan } from '../src/package-builder-port.js';
import { PackageService, type PackageServiceConfig } from '../src/package-service.js';
import { PackageStore } from '../src/package-store.js';
import { StateStore } from '../src/state-store.js';
import { WorkspaceService } from '../src/workspace-service.js';
import {
  DOCKER_BACKEND_CAPABILITIES,
  EXECUTOR_OPERATION_CLASS,
  INCUS_VM_BACKEND_CAPABILITIES,
  INTERNAL_EXECUTOR_OPERATION_CLASS,
  assertExecutorOperationSupported,
  assertVmCapability,
  backendCapabilityMap,
  executorCapabilityForOperation,
  executorCapabilityUnsupported,
  executorOperationClass
} from '../src/vm-capabilities.js';

const roots: string[] = [];
const cleanups: (() => void | Promise<void>)[] = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

const owner = { kind: 'external' as const, issuer: 'https://access.example.com', subject: 'owner' };
const document = (name: string) => `---\nname: ${name}\ndescription: ${name} skill\n---\n# ${name}\n`;

describe('capability maps', () => {
  it('declares every capability id for both backends', () => {
    for (const map of [DOCKER_BACKEND_CAPABILITIES, INCUS_VM_BACKEND_CAPABILITIES]) {
      expect(Object.keys(map).sort()).toEqual([...BACKEND_CAPABILITY_IDS].sort());
    }
  });

  it('marks every docker capability supported — the phase-09 regression baseline', () => {
    for (const id of BACKEND_CAPABILITY_IDS) {
      expect(DOCKER_BACKEND_CAPABILITIES[id], id).toBe('supported');
    }
    expect(backendCapabilityMap('docker')).toBe(DOCKER_BACKEND_CAPABILITIES);
    expect(backendCapabilityMap('incus-vm')).toBe(INCUS_VM_BACKEND_CAPABILITIES);
  });

  it('marks exactly packages-bind and dashboard-repo-skills unsupported for incus-vm', () => {
    const unsupported = BACKEND_CAPABILITY_IDS.filter((id) => INCUS_VM_BACKEND_CAPABILITIES[id] === 'unsupported');
    expect(unsupported.sort()).toEqual(['dashboard-repo-skills', 'packages-bind']);
  });
});

describe('operation classification', () => {
  it('classifies every RunnerOperation and InternalRunnerOperation explicitly', () => {
    for (const operation of RunnerOperationSchema.options) {
      const cls = executorOperationClass(operation);
      expect(cls, operation).not.toBeUndefined();
      if (cls !== 'host-only') expect(BACKEND_CAPABILITY_IDS).toContain(cls);
    }
    for (const operation of InternalRunnerOperationSchema.options) {
      expect(executorOperationClass(operation), operation).not.toBeUndefined();
    }
    // The exported records are the same source the gate consults.
    for (const operation of RunnerOperationSchema.options) {
      expect(EXECUTOR_OPERATION_CLASS[operation as keyof typeof EXECUTOR_OPERATION_CLASS]).toBe(executorOperationClass(operation));
    }
    for (const operation of InternalRunnerOperationSchema.options) {
      expect(INTERNAL_EXECUTOR_OPERATION_CLASS[operation]).toBe(executorOperationClass(operation));
    }
  });

  it('returns a capability only for executor-bound operations', () => {
    expect(executorCapabilityForOperation('exec_run')).toBe('exec');
    expect(executorCapabilityForOperation('files_read')).toBe('files');
    expect(executorCapabilityForOperation('git_push')).toBe('git-remote');
    expect(executorCapabilityForOperation('terminal_open')).toBe('terminal');
    expect(executorCapabilityForOperation('workspace_open')).toBeUndefined();
    expect(executorCapabilityForOperation('packages_apply')).toBeUndefined();
    expect(executorCapabilityForOperation('not-an-operation')).toBeUndefined();
  });
});

describe('gate helpers', () => {
  const incusBackend = { kind: 'incus-vm' as const, capabilities: () => INCUS_VM_BACKEND_CAPABILITIES };
  const dockerBackend = { kind: 'docker' as const, capabilities: () => DOCKER_BACKEND_CAPABILITIES };

  it('assertVmCapability throws the named error only for unsupported capabilities', () => {
    expect(() => assertVmCapability(INCUS_VM_BACKEND_CAPABILITIES, 'packages-bind')).toThrowError(
      expect.objectContaining({ code: 'VM_CAPABILITY_UNSUPPORTED' })
    );
    expect(() => assertVmCapability(INCUS_VM_BACKEND_CAPABILITIES, 'exec')).not.toThrow();
    expect(() => assertVmCapability(DOCKER_BACKEND_CAPABILITIES, 'packages-bind')).not.toThrow();
  });

  it('executorCapabilityUnsupported reflects the backend map for executor-bound operations', () => {
    // incus-vm v1 supports every executor-bound operation; the unsupported rows are reached through
    // the package-binding and dashboard skill paths, not the dispatch gate.
    expect(executorCapabilityUnsupported(incusBackend, 'exec_run')).toBe(false);
    expect(executorCapabilityUnsupported(incusBackend, 'terminal_open')).toBe(false);
    expect(executorCapabilityUnsupported(incusBackend, 'workspace_open')).toBe(false);
    expect(executorCapabilityUnsupported(dockerBackend, 'exec_run')).toBe(false);
    const noExec = { capabilities: () => ({ ...INCUS_VM_BACKEND_CAPABILITIES, exec: 'unsupported' as const }) };
    expect(executorCapabilityUnsupported(noExec, 'exec_run')).toBe(true);
    expect(executorCapabilityUnsupported(noExec, 'workspace_open')).toBe(false);
  });

  it('assertExecutorOperationSupported names the operation and backend', () => {
    const noExec = { kind: 'incus-vm' as const, capabilities: () => ({ ...INCUS_VM_BACKEND_CAPABILITIES, exec: 'unsupported' as const }) };
    expect(() => assertExecutorOperationSupported(noExec, 'exec_run')).toThrowError(
      expect.objectContaining({ code: 'VM_CAPABILITY_UNSUPPORTED', message: expect.stringContaining('exec_run') })
    );
    expect(() => assertExecutorOperationSupported(incusBackend, 'exec_run')).not.toThrow();
    expect(() => assertExecutorOperationSupported(incusBackend, 'workspace_open')).not.toThrow();
  });
});

/* Package binding rejection through the real PackageService.execute entrypoint. */

const NOW = 1_800_000_000_000;
const IMAGE = 'sha256:executor-image-one';

class CountingBuilder implements PackageBuilderPort {
  calls = { imageId: 0, probe: 0, resolve: 0, build: 0 };
  imageId(): Promise<string> { this.calls.imageId += 1; return Promise.resolve(IMAGE); }
  probeRegistries(): Promise<void> { this.calls.probe += 1; return Promise.resolve(); }
  async resolvePlan(spec: ResolvePackagePlanSpec): Promise<ResolvedPackagePlan> {
    this.calls.resolve += 1;
    const lockText = JSON.stringify({ name: spec.name, version: '1.0.0' });
    return {
      version: '1.0.0',
      source: { registry: 'https://registry.npmjs.org/', resolved: `https://registry.npmjs.org/${spec.name}/-/${spec.name}-1.0.0.tgz` },
      integrity: 'sha512-abc',
      lockText,
      lockSha256: createHash('sha256').update(lockText).digest('hex'),
      dependencyCount: 1,
      sizeEstimateBytes: 2_048,
      binaries: [spec.name],
      runtime: { imageId: IMAGE, node: 'v24.11.0', npm: '11.6.0', uv: null, python: null }
    };
  }
  async build(job: PackageBuildJob): Promise<PackageBuildResult> {
    this.calls.build += 1;
    mkdirSync(join(job.stagingDir, 'bin'), { recursive: true });
    for (const binary of job.binaries) writeFileSync(join(job.stagingDir, 'bin', binary), '#!/bin/sh\necho ok\n', { mode: 0o755 });
    await job.onPhase?.('VERIFYING');
    return {
      treeDigest: createHash('sha256').update(job.releaseId).digest('hex'),
      sizeBytes: 1_024,
      fileCount: job.binaries.length + 1,
      sbom: [{ name: job.name, version: job.version, integrity: 'sha512-abc' }],
      runtime: { imageId: IMAGE, node: 'v24.11.0', npm: '11.6.0', uv: null, python: null },
      provenance: { registry: 'https://registry.npmjs.org/' },
      launchChecks: Object.fromEntries(job.binaries.map((binary) => [binary, '--version']))
    };
  }
}

function packageFixture() {
  const directory = mkdtempSync(join(tmpdir(), 'cloud-harness-vm-caps-pkg-')); roots.push(directory);
  const state = new StateStore(join(directory, 'state.db'));
  const metadata = new MetadataStore(join(directory, 'state.db'));
  cleanups.push(() => { metadata.close(); state.close(); });
  const ownerId = state.resolvePrincipal(owner);
  const config: PackageServiceConfig = {
    authMode: 'cloudflare-access',
    executorImage: 'cloud-harness-executor:test',
    minFreeBytes: 0,
    packagesEnabled: true,
    packagesRoot: join(directory, 'packages'),
    packagesEcosystems: ['npm', 'uv'],
    packagesApprovalMode: 'none',
    packagesNpmLifecycleScripts: 'deny',
    packagesMaxReleaseBytes: 16_777_216,
    packagesMaxOwnerBytes: 4_294_967_296,
    packagesMaxBindings: 32,
    packagesBuildTimeoutMs: 600_000
  };
  const builder = new CountingBuilder();
  const packages = new PackageService({
    database: state.database, config, builder, instanceId: 'instance-test',
    clock: () => NOW, setExecutorOwnership: () => Promise.resolve()
  });
  cleanups.push(() => packages.shutdown());
  const store = new PackageStore(state.database);
  const workspace = (backendKind: 'docker' | 'incus-vm' = 'docker') => {
    const id = `ws_${createHash('sha256').update(`${ownerId}-${Math.random()}`).digest('hex').slice(0, 24)}`;
    const now = Date.now();
    state.database.prepare(`
      INSERT INTO workspaces (id, owner_id, idempotency_key, repository_url, repository_ref, container_name, workspace_path, status, network_profile, created_at, last_activity_at, expires_at, hard_expires_at, generation, backend_kind)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 'network-none', ?, ?, ?, ?, 1, ?)
    `).run(id, ownerId, `request-${id}`, 'https://github.com/example/repo.git', 'main', null, join(directory, id), now, now, now + 60_000, now + 14_400_000, backendKind);
    return id;
  };
  const install = async (input: Record<string, unknown>) => {
    const planned = await packages.execute(ownerId, 'packages_plan', { ecosystem: 'npm', name: 'chm-hello', ...input });
    const plan = (planned as { planId: string; planDigest: string });
    await packages.execute(ownerId, 'packages_apply', { planId: plan.planId, planDigest: plan.planDigest });
    await packages.drain();
    return plan;
  };
  return { state, ownerId, builder, packages, store, workspace, install };
}

describe('package binding capability gate', () => {
  it('rejects packages_plan for an incus-vm workspace before any builder dispatch', async () => {
    const f = packageFixture();
    const ws = f.workspace('incus-vm');
    await expect(f.packages.execute(f.ownerId, 'packages_plan', {
      ecosystem: 'npm', name: 'chm-hello', scope: 'workspace', workspaceId: ws
    })).rejects.toMatchObject({ code: 'VM_CAPABILITY_UNSUPPORTED', status: 400, retryable: false });
    expect(f.builder.calls.resolve).toBe(0);
    expect(f.builder.calls.build).toBe(0);
  });

  it('rejects packages_apply for a plan that targets an incus-vm workspace', async () => {
    const f = packageFixture();
    const ws = f.workspace('docker');
    const plan = await f.install({ scope: 'workspace', workspaceId: ws });
    // A plan recorded while the workspace was docker must still refuse once the workspace is incus-vm.
    f.state.database.prepare('UPDATE workspaces SET backend_kind = ? WHERE id = ?').run('incus-vm', ws);
    const buildsBefore = f.builder.calls.build;
    await expect(f.packages.execute(f.ownerId, 'packages_apply', {
      planId: (plan as { planId: string }).planId, planDigest: (plan as { planDigest: string }).planDigest
    })).rejects.toMatchObject({ code: 'VM_CAPABILITY_UNSUPPORTED' });
    expect(f.builder.calls.build).toBe(buildsBefore);
  });

  it('rejects packages_rollback that would keep an incus-vm workspace binding alive', async () => {
    const f = packageFixture();
    const ws = f.workspace('docker');
    await f.install({ scope: 'workspace', workspaceId: ws, name: 'chm-other' });
    const binding = f.store.listBindings(f.ownerId).find((entry) => entry.scope === 'workspace')!;
    expect(binding).toBeDefined();
    f.state.database.prepare('UPDATE workspaces SET backend_kind = ? WHERE id = ?').run('incus-vm', ws);
    await expect(f.packages.execute(f.ownerId, 'packages_rollback', {
      bindingId: binding.id, releaseId: binding.releaseId!, expectedGeneration: binding.generation
    })).rejects.toMatchObject({ code: 'VM_CAPABILITY_UNSUPPORTED' });
    // The store was never reached: the binding generation is unchanged.
    expect(f.store.getBinding(f.ownerId, binding.id)?.generation).toBe(binding.generation);
  });

  it('keeps docker workspace bindings and owner-scope plans working', async () => {
    const f = packageFixture();
    const ws = f.workspace('docker');
    await f.install({ scope: 'workspace', workspaceId: ws, name: 'chm-other' });
    await f.install({ scope: 'owner', name: 'chm-hello' });
    const overview = await f.packages.execute(f.ownerId, 'packages_list', {});
    expect((overview as { bindings: unknown[] }).bindings.length).toBeGreaterThan(0);
  });
});

/* Dashboard workspace-repository skill reads: explicit unsupported for incus-vm. */

const WS_VM = 'ws_vmcapability000000000001';
const WS_DOCKER = 'ws_vmcapability000000000002';

function skillFixture() {
  const root = mkdtempSync(join(tmpdir(), 'cloud-harness-vm-caps-skills-')); roots.push(root);
  const jobsRoot = join(root, 'jobs');
  const builtinRoot = join(root, 'builtin');
  mkdirSync(jobsRoot);
  mkdirSync(builtinRoot);
  const config = {
    jobsRoot,
    stateDb: join(root, 'state.db'),
    artifactRoot: join(root, 'artifacts'),
    maxArtifactBytes: 1024,
    maxPrincipalArtifactBytes: 4096,
    artifactRetentionSeconds: 60,
    idleTtlSeconds: 1800,
    wallTtlSeconds: 7200,
    maxExecutionTimeSeconds: 7200,
    executorImage: 'cloud-harness-executor:local',
    reaperIntervalSeconds: 30,
    builtinSkillsRoot: builtinRoot
  } as RunnerConfig;
  const store = new StateStore(config.stateDb);
  const metadata = new MetadataStore(config.stateDb);
  cleanups.push(() => {
    try { metadata.database.close(); } catch { /* ignore */ }
    try { store.close(); } catch { /* ignore */ }
  });
  const artifacts = new ArtifactStore(store.database, { root: config.artifactRoot, maxArtifactBytes: 1024, maxPrincipalBytes: 4096, defaultRetentionMs: 60_000, maxRetentionMs: 120_000 });
  const workspaces = new WorkspaceService(config, store, metadata, undefined, undefined, artifacts);
  const controls = new DashboardControlService(config, store, metadata, artifacts, workspaces);

  const openWorkspace = (id: string, backendKind: 'docker' | 'incus-vm') => {
    const ownerId = store.resolvePrincipal(owner);
    const workspacePath = join(jobsRoot, id);
    mkdirSync(join(workspacePath, 'repo'), { recursive: true });
    const now = Date.now();
    store.database.prepare(`
      INSERT INTO workspaces (id, owner_id, idempotency_key, repository_url, repository_ref, container_name, workspace_path, status, network_profile, created_at, last_activity_at, expires_at, hard_expires_at, generation, backend_kind)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', 'network-none', ?, ?, ?, ?, 1, ?)
    `).run(id, ownerId, `idem-${id}`, 'https://github.com/example/repo.git', 'main', `container-${id}`, workspacePath, now, now, now + 1_800_000, now + 7_200_000, backendKind);
    return join(workspacePath, 'repo');
  };
  const write = (dir: string, files: Record<string, string>) => {
    for (const [relative, content] of Object.entries(files)) {
      const path = join(dir, relative);
      mkdirSync(join(path, '..'), { recursive: true });
      writeFileSync(path, content);
    }
    return dir;
  };
  const call = (operation: MetadataRunnerRequest['operation'], input: Record<string, unknown>) =>
    controls.execute({ version: 2 as const, principal: owner, operation, input } as MetadataRunnerRequest);
  const list = async (input: Record<string, unknown> = {}) =>
    (await call('skills_ext_list', input)).data as { skills: SkillEntry[] };
  return { store, controls, openWorkspace, write, call, list, builtinRoot };
}

describe('dashboard repository skill reads on incus-vm', () => {
  it('rejects workspace-bound skill list/get/read with VM_CAPABILITY_UNSUPPORTED and never reads host staging', async () => {
    const f = skillFixture();
    // The trap this gate exists for: a host `repo/` staging tree exists, but a VM workspace's real
    // checkout lives in the guest. Serving it would be a silent host-filesystem fallback.
    const repo = f.openWorkspace(WS_VM, 'incus-vm');
    f.write(join(repo, '.agents/skills/vm-skill'), { 'SKILL.md': document('vm-skill') });
    const uri = `skill://cloud-harness/repository/${WS_VM}/vm-skill/SKILL.md`;

    await expect(f.call('skills_ext_list', { workspaceId: WS_VM })).rejects.toMatchObject({ code: 'VM_CAPABILITY_UNSUPPORTED' });
    await expect(f.call('skills_ext_get', { uri, workspaceId: WS_VM })).rejects.toMatchObject({ code: 'VM_CAPABILITY_UNSUPPORTED' });
    await expect(f.call('skills_ext_read', { uri, workspaceId: WS_VM })).rejects.toMatchObject({ code: 'VM_CAPABILITY_UNSUPPORTED' });
  });

  it('keeps built-in and owner skill reads working for unbound and docker-bound requests', async () => {
    const f = skillFixture();
    f.write(join(f.builtinRoot, 'builtin-skill'), { 'SKILL.md': document('builtin-skill') });
    const dockerRepo = f.openWorkspace(WS_DOCKER, 'docker');
    f.write(join(dockerRepo, '.agents/skills/docker-skill'), { 'SKILL.md': document('docker-skill') });

    const unbound = await f.list();
    expect(unbound.skills.some((skill) => skill.frontmatter.name === 'builtin-skill')).toBe(true);

    const dockerBound = await f.list({ workspaceId: WS_DOCKER });
    expect(dockerBound.skills.some((skill) => skill.frontmatter.name === 'docker-skill')).toBe(true);
    expect(dockerBound.skills.some((skill) => skill.frontmatter.name === 'builtin-skill')).toBe(true);

    const uri = `skill://cloud-harness/repository/${WS_DOCKER}/docker-skill/SKILL.md`;
    const got = await f.call('skills_ext_get', { uri, workspaceId: WS_DOCKER });
    expect((got.data as { skill: SkillEntry }).skill.frontmatter.name).toBe('docker-skill');
    const read = SkillsExtReadDataSchema.parse((await f.call('skills_ext_read', { uri, workspaceId: WS_DOCKER })).data);
    expect(read.contents[0]?.text).toContain('docker-skill');
  });

  it('answers an unavailable incus-vm workspace with NOT_FOUND, not the capability error', async () => {
    const f = skillFixture();
    const repo = f.openWorkspace(WS_VM, 'incus-vm');
    f.write(join(repo, '.agents/skills/vm-skill'), { 'SKILL.md': document('vm-skill') });
    f.store.database.prepare('UPDATE workspaces SET status = ? WHERE id = ?').run('CLOSED', WS_VM);
    await expect(f.call('skills_ext_list', { workspaceId: WS_VM })).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
});
