import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { vi } from 'vitest';
import type { RunnerConfig } from '@cloud-harness/contracts';
import type { WorkspaceRecord } from '../src/state-store.js';
import type { DockerExecutorBackendDeps } from '../src/docker-executor-backend.js';
import type { ProvisionContext } from '../src/executor-backend.js';

/** Shared fixture builders for the phase-02 executor-backend test files. */

export const testDirectories: string[] = [];

export function trackDir(path: string): string {
  testDirectories.push(path);
  return path;
}

export function makeRecord(overrides: Partial<WorkspaceRecord> = {}): WorkspaceRecord {
  const directory = trackDir(mkdtempSync(join(tmpdir(), 'cloud-harness-backend-')));
  const now = Date.now();
  return {
    id: `ws_${'a'.repeat(24)}`,
    ownerId: 'owner-1',
    idempotencyKey: 'backend-key-1',
    repositoryUrl: 'https://github.com/example/repo.git',
    repositoryRef: 'main',
    containerName: 'cloud-harness-ws-testcontainer',
    workspacePath: join(directory, 'ws'),
    environmentId: null,
    status: 'ACTIVE',
    networkProfile: 'network-none',
    createdAt: now,
    lastActivityAt: now,
    expiresAt: now + 3_600_000,
    hardExpiresAt: now + 14_400_000,
    gitAuthorName: null,
    gitAuthorEmail: null,
    mutationLockedUntil: null,
    generation: 7,
    error: null,
    ...overrides
  };
}

export function makeCtx(overrides: Partial<ProvisionContext> = {}): ProvisionContext {
  const staging = trackDir(mkdtempSync(join(tmpdir(), 'cloud-harness-staging-')));
  return {
    record: makeRecord(),
    environment: {},
    networkProfile: 'network-none',
    stagingDir: join(staging, 'git-staging'),
    ...overrides
  };
}

export function makeConfig(overrides: Partial<RunnerConfig> = {}): RunnerConfig {
  return {
    executorImage: 'cloud-harness-executor:test',
    maxOutputBytes: 262_144,
    packagesEnabled: false,
    ...overrides
  } as RunnerConfig;
}

export function makeDeps(overrides: Partial<DockerExecutorBackendDeps> = {}): DockerExecutorBackendDeps {
  return {
    config: makeConfig(),
    instanceId: 'instance-test',
    network: {
      ensureProfileReady: vi.fn(async () => undefined),
      dockerLaunchArgs: vi.fn(() => ['--network', 'none'])
    },
    packages: {
      profileFor: vi.fn(() => ({ mounts: [], binDirs: [] }))
    },
    ...overrides
  };
}
