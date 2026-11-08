import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { loadRunnerConfigWithReadiness } from '../src/config.js';

afterEach(() => vi.unstubAllEnvs());

function requiredEnvironment() {
  vi.stubEnv('RUNNER_TOKEN', 'r'.repeat(32));
}

function enableVmBackend() {
  vi.stubEnv('VM_BACKEND_ENABLED', 'true');
  vi.stubEnv('VM_SUPERVISOR_TOKEN', 'v'.repeat(32));
  vi.stubEnv('VM_TEMPLATE_ID', 'cloud-harness/ubuntu-vm:24.04');
  vi.stubEnv('VM_TEMPLATE_DIGEST', 'c'.repeat(64));
}

describe('VM runner configuration', () => {
  it('leaves the backend disabled with documented defaults when nothing is set', () => {
    requiredEnvironment();
    const { config } = loadRunnerConfigWithReadiness();
    expect(config.vmBackendEnabled).toBe(false);
    expect(config.vmSupervisorSocket).toBe('/run/cloud-harness-vm/supervisor.sock');
    expect(config.vmSupervisorToken).toBeUndefined();
    expect(config.vmTemplateId).toBeUndefined();
    expect(config.vmTemplateDigest).toBeUndefined();
    expect(config.vmMaxActive).toBe(1);
    expect(config.vmCpus).toBe(4);
    expect(config.vmMemoryBytes).toBe(8_589_934_592);
    expect(config.vmDiskBytes).toBe(21_474_836_480);
    expect(config.vmPoolReserveBytes).toBe(10_737_418_240);
    expect(config.vmMaxWorkspaceBytes).toBe(12_884_901_888);
    expect(config.vmInlineMaxBytes).toBe(8_388_608);
  });

  it('parses every runner-side VM environment variable', () => {
    requiredEnvironment();
    vi.stubEnv('VM_BACKEND_ENABLED', 'true');
    vi.stubEnv('VM_SUPERVISOR_SOCKET', '/run/custom/vm-supervisor.sock');
    vi.stubEnv('VM_SUPERVISOR_TOKEN', 'v'.repeat(32));
    vi.stubEnv('VM_TEMPLATE_ID', 'cloud-harness/ubuntu-vm:24.04');
    vi.stubEnv('VM_TEMPLATE_DIGEST', 'd'.repeat(64));
    vi.stubEnv('VM_MAX_ACTIVE', '1');
    vi.stubEnv('VM_CPUS', '4');
    vi.stubEnv('VM_MEMORY_BYTES', '8589934592');
    vi.stubEnv('VM_DISK_BYTES', '21474836480');
    vi.stubEnv('VM_POOL_RESERVE_BYTES', '5368709120');
    vi.stubEnv('VM_MAX_WORKSPACE_BYTES', '25769803776');
    vi.stubEnv('VM_INLINE_MAX_BYTES', '16777216');
    const { config } = loadRunnerConfigWithReadiness();
    expect(config.vmBackendEnabled).toBe(true);
    expect(config.vmSupervisorSocket).toBe('/run/custom/vm-supervisor.sock');
    expect(config.vmSupervisorToken).toBe('v'.repeat(32));
    expect(config.vmTemplateId).toBe('cloud-harness/ubuntu-vm:24.04');
    expect(config.vmTemplateDigest).toBe('d'.repeat(64));
    expect(config.vmMaxActive).toBe(1);
    expect(config.vmCpus).toBe(4);
    expect(config.vmMemoryBytes).toBe(8_589_934_592);
    expect(config.vmDiskBytes).toBe(21_474_836_480);
    expect(config.vmPoolReserveBytes).toBe(5_368_709_120);
    expect(config.vmMaxWorkspaceBytes).toBe(25_769_803_776);
    expect(config.vmInlineMaxBytes).toBe(16_777_216);
  });

  it('rejects any deviation from the pinned approved shape', () => {
    requiredEnvironment();
    enableVmBackend();
    // CH-VM-SCOPE-2026-11-07: one active VM globally at EXACTLY 4 vCPU /
    // 8 GiB / 20 GiB — deviation in EITHER direction is rejected through
    // the real env loader. Zod issues name the schema field.
    for (const bad of ['0', '2']) {
      vi.stubEnv('VM_MAX_ACTIVE', bad);
      expect(() => loadRunnerConfigWithReadiness()).toThrow(/vmMaxActive/);
    }
    vi.stubEnv('VM_MAX_ACTIVE', '1');
    for (const bad of ['3', '5']) {
      vi.stubEnv('VM_CPUS', bad);
      expect(() => loadRunnerConfigWithReadiness()).toThrow(/vmCpus/);
    }
    vi.stubEnv('VM_CPUS', '4');
    for (const bad of ['8589934591', '8589934593']) {
      vi.stubEnv('VM_MEMORY_BYTES', bad);
      expect(() => loadRunnerConfigWithReadiness()).toThrow(/vmMemoryBytes/);
    }
    vi.stubEnv('VM_MEMORY_BYTES', '8589934592');
    for (const bad of ['21474836479', '21474836481']) {
      vi.stubEnv('VM_DISK_BYTES', bad);
      expect(() => loadRunnerConfigWithReadiness()).toThrow(/vmDiskBytes/);
    }
    vi.stubEnv('VM_DISK_BYTES', '21474836480');
    expect(loadRunnerConfigWithReadiness().config.vmCpus).toBe(4);
  });

  it('reads VM_SUPERVISOR_TOKEN from a _FILE secret like other runner secrets', () => {
    requiredEnvironment();
    const directory = mkdtempSync(join(tmpdir(), 'vm-config-'));
    try {
      const tokenFile = join(directory, 'vm-token');
      writeFileSync(tokenFile, `${'f'.repeat(32)}\n`, { mode: 0o600 });
      enableVmBackend();
      vi.stubEnv('VM_SUPERVISOR_TOKEN', '');
      vi.stubEnv('VM_SUPERVISOR_TOKEN_FILE', tokenFile);
      const { config } = loadRunnerConfigWithReadiness();
      expect(config.vmSupervisorToken).toBe('f'.repeat(32));
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('refuses to start an enabled backend without the token, template id, and digest', () => {
    requiredEnvironment();
    vi.stubEnv('VM_BACKEND_ENABLED', 'true');
    expect(() => loadRunnerConfigWithReadiness()).toThrow(/VM_SUPERVISOR_TOKEN/);
  });

  it('refuses an enabled backend missing only the template digest', () => {
    requiredEnvironment();
    vi.stubEnv('VM_BACKEND_ENABLED', 'true');
    vi.stubEnv('VM_SUPERVISOR_TOKEN', 'v'.repeat(32));
    vi.stubEnv('VM_TEMPLATE_ID', 'cloud-harness/ubuntu-vm:24.04');
    expect(() => loadRunnerConfigWithReadiness()).toThrow(/VM_TEMPLATE_DIGEST/);
  });

  it('keeps supervisor-only keys out of the runner config surface', () => {
    requiredEnvironment();
    enableVmBackend();
    vi.stubEnv('VM_BRIDGE_PATTERN', 'chmbr%d');
    vi.stubEnv('VM_SUBNET_PLAN', '10.240.0.0/16');
    vi.stubEnv('VM_POOL_PATH', '/var/lib/incus-pool');
    const { config } = loadRunnerConfigWithReadiness();
    expect(config).not.toHaveProperty('vmBridgePattern');
    expect(config).not.toHaveProperty('vmSubnetPlan');
    expect(config).not.toHaveProperty('vmPoolPath');
    expect(config).not.toHaveProperty('vmUplink');
    expect(config).not.toHaveProperty('vmDnsResolvers');
    expect(config).not.toHaveProperty('vmNonpublicCidrs');
    expect(config).not.toHaveProperty('vmMaxTtlSeconds');
    expect(config).not.toHaveProperty('vmProbeMaxSeconds');
  });
});
