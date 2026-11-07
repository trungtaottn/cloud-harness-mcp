import { describe, expect, it } from 'vitest';
import { loadVmSupervisorConfig, VmSupervisorConfigError } from '../src/config.js';

const VALID_ENV = {
  VM_SUPERVISOR_TOKEN: 'a'.repeat(48),
  VM_INCUS_PROJECT: 'cloud-harness',
  VM_TEMPLATE_ID: 'cloudharness-vm-template',
  VM_TEMPLATE_DIGEST: 'b'.repeat(64)
} as const;

function env(overrides: Record<string, string | undefined> = {}): Record<string, string | undefined> {
  return { ...VALID_ENV, ...overrides };
}

describe('loadVmSupervisorConfig', () => {
  it('applies documented defaults for optional keys', () => {
    const config = loadVmSupervisorConfig(env());
    expect(config.socketPath).toBe('/run/cloud-harness-vm/supervisor.sock');
    expect(config.stateDir).toBe('/var/lib/cloud-harness-vm');
    expect(config.incusSocketPath).toBe('/var/lib/incus/unix.socket');
    expect(config.guardStatePath).toBe('/run/cloud-harness-vm/guard-state.json');
    expect(config.bridgePattern).toBe('chmbr%d');
    expect(config.subnetPlan).toBe('10.240.0.0/16');
    expect(config.uplink).toBe('');
    expect(config.dnsResolvers).toEqual(['1.1.1.1', '8.8.8.8']);
    expect(config.nonpublicCidrs).toEqual([]);
    expect(config.poolPath).toBe('/var/lib/incus-pool');
    expect(config.maxTtlSeconds).toBe(86_400);
    expect(config.maxActive).toBe(1);
    expect(config.cpus).toBe(4);
    expect(config.memoryBytes).toBe(8_589_934_592);
    expect(config.diskBytes).toBe(21_474_836_480);
    expect(config.poolReserveBytes).toBe(10_737_418_240);
    expect(config.token).toBe('a'.repeat(48));
    expect(config.incusProject).toBe('cloud-harness');
    expect(config.templateId).toBe('cloudharness-vm-template');
    expect(config.templateDigest).toBe('b'.repeat(64));
  });

  it('honours explicit overrides', () => {
    const config = loadVmSupervisorConfig(env({
      VM_SUPERVISOR_SOCKET: '/tmp/vm.sock',
      VM_SUPERVISOR_STATE_DIR: '/tmp/vm-state',
      VM_INCUS_SOCKET: '/tmp/incus.sock',
      VM_INCUS_PROJECT: 'pilot',
      VM_GUARD_STATE_PATH: '/tmp/guard.json',
      VM_BRIDGE_PATTERN: 'br%d',
      VM_SUBNET_PLAN: '10.9.0.0/16',
      VM_UPLINK: 'enp7s0',
      VM_DNS_RESOLVERS: '9.9.9.9, 149.112.112.112',
      VM_NONPUBLIC_CIDRS: '10.0.0.0/8, 192.168.0.0/16',
      VM_POOL_PATH: '/mnt/pool',
      VM_MAX_TTL_SECONDS: '7200',
      VM_MAX_ACTIVE: '2',
      VM_CPUS: '8',
      VM_MEMORY_BYTES: '17179869184',
      VM_DISK_BYTES: '42949672960',
      VM_POOL_RESERVE_BYTES: '5368709120'
    }));
    expect(config.socketPath).toBe('/tmp/vm.sock');
    expect(config.stateDir).toBe('/tmp/vm-state');
    expect(config.incusSocketPath).toBe('/tmp/incus.sock');
    expect(config.incusProject).toBe('pilot');
    expect(config.guardStatePath).toBe('/tmp/guard.json');
    expect(config.bridgePattern).toBe('br%d');
    expect(config.subnetPlan).toBe('10.9.0.0/16');
    expect(config.uplink).toBe('enp7s0');
    expect(config.dnsResolvers).toEqual(['9.9.9.9', '149.112.112.112']);
    expect(config.nonpublicCidrs).toEqual(['10.0.0.0/8', '192.168.0.0/16']);
    expect(config.poolPath).toBe('/mnt/pool');
    expect(config.maxTtlSeconds).toBe(7200);
    expect(config.maxActive).toBe(2);
    expect(config.cpus).toBe(8);
    expect(config.memoryBytes).toBe(17_179_869_184);
    expect(config.diskBytes).toBe(42_949_672_960);
    expect(config.poolReserveBytes).toBe(5_368_709_120);
  });

  it('requires the supervisor token', () => {
    expect(() => loadVmSupervisorConfig(env({ VM_SUPERVISOR_TOKEN: undefined })))
      .toThrow(VmSupervisorConfigError);
    expect(() => loadVmSupervisorConfig(env({ VM_SUPERVISOR_TOKEN: 'short' })))
      .toThrow(/VM_SUPERVISOR_TOKEN/);
  });

  it('reads the token from VM_SUPERVISOR_TOKEN_FILE', () => {
    const config = loadVmSupervisorConfig(env({
      VM_SUPERVISOR_TOKEN: undefined,
      VM_SUPERVISOR_TOKEN_FILE: '/run/secrets/vm-token'
    }), {
      readSecretFile: (path) => {
        expect(path).toBe('/run/secrets/vm-token');
        return `${'f'.repeat(48)}\n`;
      }
    });
    expect(config.token).toBe('f'.repeat(48));
  });

  it('requires a dedicated explicit Incus project and rejects the default project', () => {
    expect(() => loadVmSupervisorConfig(env({ VM_INCUS_PROJECT: undefined })))
      .toThrow(/VM_INCUS_PROJECT/);
    expect(() => loadVmSupervisorConfig(env({ VM_INCUS_PROJECT: '' })))
      .toThrow(/VM_INCUS_PROJECT/);
    expect(() => loadVmSupervisorConfig(env({ VM_INCUS_PROJECT: 'default' })))
      .toThrow(/VM_INCUS_PROJECT/);
    // Any other explicit dedicated project name is accepted; existence is verified at startup.
    expect(loadVmSupervisorConfig(env({ VM_INCUS_PROJECT: 'ch-vms' })).incusProject).toBe('ch-vms');
  });

  it('requires the trusted template allowlist', () => {
    expect(() => loadVmSupervisorConfig(env({ VM_TEMPLATE_ID: undefined })))
      .toThrow(/VM_TEMPLATE_ID/);
    expect(() => loadVmSupervisorConfig(env({ VM_TEMPLATE_DIGEST: undefined })))
      .toThrow(/VM_TEMPLATE_DIGEST/);
    expect(() => loadVmSupervisorConfig(env({ VM_TEMPLATE_DIGEST: 'not-hex' })))
      .toThrow(/VM_TEMPLATE_DIGEST/);
    expect(() => loadVmSupervisorConfig(env({ VM_TEMPLATE_ID: 'has space' })))
      .toThrow(/VM_TEMPLATE_ID/);
  });

  it('rejects malformed socket/state/pool paths', () => {
    expect(() => loadVmSupervisorConfig(env({ VM_SUPERVISOR_SOCKET: 'relative.sock' })))
      .toThrow(/VM_SUPERVISOR_SOCKET/);
    expect(() => loadVmSupervisorConfig(env({ VM_SUPERVISOR_SOCKET: '/tmp/a\0b' })))
      .toThrow(/VM_SUPERVISOR_SOCKET/);
    expect(() => loadVmSupervisorConfig(env({ VM_SUPERVISOR_STATE_DIR: 'relative' })))
      .toThrow(/VM_SUPERVISOR_STATE_DIR/);
    expect(() => loadVmSupervisorConfig(env({ VM_POOL_PATH: 'relative' })))
      .toThrow(/VM_POOL_PATH/);
    expect(() => loadVmSupervisorConfig(env({ VM_INCUS_SOCKET: 'relative' })))
      .toThrow(/VM_INCUS_SOCKET/);
  });

  it('rejects out-of-range numeric knobs', () => {
    expect(() => loadVmSupervisorConfig(env({ VM_MAX_ACTIVE: '0' }))).toThrow(/VM_MAX_ACTIVE/);
    expect(() => loadVmSupervisorConfig(env({ VM_MAX_ACTIVE: '17' }))).toThrow(/VM_MAX_ACTIVE/);
    expect(() => loadVmSupervisorConfig(env({ VM_MAX_TTL_SECONDS: '0' }))).toThrow(/VM_MAX_TTL_SECONDS/);
    expect(() => loadVmSupervisorConfig(env({ VM_CPUS: '0' }))).toThrow(/VM_CPUS/);
    expect(() => loadVmSupervisorConfig(env({ VM_MEMORY_BYTES: '1' }))).toThrow(/VM_MEMORY_BYTES/);
    expect(() => loadVmSupervisorConfig(env({ VM_DISK_BYTES: '1' }))).toThrow(/VM_DISK_BYTES/);
    expect(() => loadVmSupervisorConfig(env({ VM_POOL_RESERVE_BYTES: '-1' }))).toThrow(/VM_POOL_RESERVE_BYTES/);
  });

  it('rejects malformed DNS resolver and CIDR lists', () => {
    expect(() => loadVmSupervisorConfig(env({ VM_DNS_RESOLVERS: 'not-an-ip' })))
      .toThrow(/VM_DNS_RESOLVERS/);
    expect(() => loadVmSupervisorConfig(env({ VM_DNS_RESOLVERS: '1.1.1.1,,8.8.8.8' })))
      .toThrow(/VM_DNS_RESOLVERS/);
    expect(() => loadVmSupervisorConfig(env({ VM_NONPUBLIC_CIDRS: '10.0.0.0/33' })))
      .toThrow(/VM_NONPUBLIC_CIDRS/);
    expect(() => loadVmSupervisorConfig(env({ VM_NONPUBLIC_CIDRS: 'not-a-cidr' })))
      .toThrow(/VM_NONPUBLIC_CIDRS/);
  });

  it('rejects a subnet plan that is not a valid IPv4 CIDR', () => {
    expect(() => loadVmSupervisorConfig(env({ VM_SUBNET_PLAN: '10.240.0.0/33' })))
      .toThrow(/VM_SUBNET_PLAN/);
    expect(() => loadVmSupervisorConfig(env({ VM_SUBNET_PLAN: 'nope' })))
      .toThrow(/VM_SUBNET_PLAN/);
  });
});
