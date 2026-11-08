import { lstatSync, readFileSync } from 'node:fs';

export class VmSupervisorConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'VmSupervisorConfigError';
  }
}

function fail(name: string, message: string): never {
  throw new VmSupervisorConfigError(`${name}: ${message}`);
}

function required(env: Record<string, string | undefined>, name: string): string {
  const value = env[name];
  if (value === undefined || value === '') fail(name, 'is required');
  return value as string;
}

function optional(env: Record<string, string | undefined>, name: string, fallback: string): string {
  const value = env[name];
  return value === undefined || value === '' ? fallback : value;
}

function absolutePath(env: Record<string, string | undefined>, name: string, fallback?: string): string {
  const value = fallback === undefined ? required(env, name) : optional(env, name, fallback);
  if (!value.startsWith('/') || value.includes('\0')) fail(name, 'must be an absolute path without NUL bytes');
  return value;
}

const DECIMAL = /^\d+$/;

function integer(env: Record<string, string | undefined>, name: string, fallback: number, min: number, max: number): number {
  const raw = optional(env, name, String(fallback));
  if (!DECIMAL.test(raw)) fail(name, 'must be a non-negative integer');
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    fail(name, `must be an integer between ${min} and ${max}`);
  }
  return value;
}

function ipv4(value: string): boolean {
  const parts = value.split('.');
  if (parts.length !== 4) return false;
  return parts.every((part) => DECIMAL.test(part) && Number(part) <= 255 && (part === '0' || !part.startsWith('0')));
}

function cidr(value: string): boolean {
  const [address, prefix, extra] = value.split('/');
  if (extra !== undefined || address === undefined || prefix === undefined) return false;
  if (!DECIMAL.test(prefix)) return false;
  const bits = Number(prefix);
  return bits <= 32 && ipv4(address);
}

function csvValidated(env: Record<string, string | undefined>, name: string, fallback: string, validate: (entry: string) => boolean, what: string, allowEmpty = false): string[] {
  const raw = optional(env, name, fallback);
  if (raw.trim() === '') {
    if (allowEmpty) return [];
    fail(name, `must be a comma-separated list of ${what}`);
  }
  const parts = raw.split(',').map((entry) => entry.trim());
  const entries = parts.filter((entry) => entry !== '');
  if (parts.some((entry) => entry === '') || entries.length === 0 || entries.some((entry) => !validate(entry))) {
    fail(name, `must be a comma-separated list of ${what}`);
  }
  return entries;
}

export interface VmSupervisorSecretFileReader {
  (path: string): string;
}

export interface VmSupervisorConfigDeps {
  readSecretFile?: VmSupervisorSecretFileReader;
}

export interface VmSupervisorConfig {
  /** Unix socket the supervisor binds and the runner dials. */
  socketPath: string;
  /** Shared bearer token; compared constant-time on every request. */
  token: string;
  /** Durable state root: journal DB, upload staging, HMAC key file. */
  stateDir: string;
  incusSocketPath: string;
  /**
   * Dedicated Incus project, explicitly configured — never `default` and never
   * auto-created. Verified to exist at startup; admission fails when absent.
   */
  incusProject: string;
  guardStatePath: string;
  bridgePattern: string;
  subnetPlan: string;
  /** Empty string = auto-detect the single IPv4 default route. */
  uplink: string;
  dnsResolvers: string[];
  nonpublicCidrs: string[];
  poolPath: string;
  /** Lease TTL clamp: supervisor never accepts a deadline beyond now + this. */
  maxTtlSeconds: number;
  /** Global serialized-admission cap on running managed VMs. */
  maxActive: number;
  /** Supervisor-owned resource ACTUALS stamped at create and asserted on read-back. */
  cpus: number;
  memoryBytes: number;
  diskBytes: number;
  /** Host statfs floor admission must preserve. */
  poolReserveBytes: number;
  /** Trusted template allowlist: vm.create params must match these exactly. */
  templateId: string;
  templateDigest: string;
}

const TEMPLATE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$/;
const SHA256_HEX = /^[0-9a-f]{64}$/;
const INCUS_PROJECT_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$/;

/**
 * Parse supervisor configuration from the process environment. Only the
 * documented VM_* keys are read; everything else in the environment is
 * ignored. Fails closed with VmSupervisorConfigError naming the offending key.
 */
export function loadVmSupervisorConfig(
  env: Record<string, string | undefined>,
  deps: VmSupervisorConfigDeps = {}
): VmSupervisorConfig {
  const readSecretFile = deps.readSecretFile ?? defaultSecretFileReader;

  const tokenFile = env.VM_SUPERVISOR_TOKEN_FILE;
  const tokenValue = env.VM_SUPERVISOR_TOKEN;
  let token: string;
  if (tokenFile !== undefined && tokenFile !== '') {
    if (tokenValue !== undefined && tokenValue !== '') {
      fail('VM_SUPERVISOR_TOKEN', 'conflicts with VM_SUPERVISOR_TOKEN_FILE; set only one');
    }
    token = readSecretFile(tokenFile).trim();
  } else {
    token = required(env, 'VM_SUPERVISOR_TOKEN');
  }
  if (token.length < 32 || /\s/.test(token)) {
    fail('VM_SUPERVISOR_TOKEN', 'must be at least 32 characters without whitespace');
  }

  const incusProject = required(env, 'VM_INCUS_PROJECT');
  if (incusProject === 'default' || !INCUS_PROJECT_PATTERN.test(incusProject)) {
    fail('VM_INCUS_PROJECT', 'must name a dedicated managed Incus project (never "default")');
  }

  const templateId = required(env, 'VM_TEMPLATE_ID');
  if (!TEMPLATE_ID_PATTERN.test(templateId)) {
    fail('VM_TEMPLATE_ID', 'invalid template identifier');
  }
  const templateDigest = required(env, 'VM_TEMPLATE_DIGEST');
  if (!SHA256_HEX.test(templateDigest)) {
    fail('VM_TEMPLATE_DIGEST', 'expected lowercase SHA-256 hex digest');
  }

  const subnetPlan = optional(env, 'VM_SUBNET_PLAN', '10.240.0.0/16');
  if (!cidr(subnetPlan)) fail('VM_SUBNET_PLAN', 'must be an IPv4 CIDR such as 10.240.0.0/16');

  const dnsResolvers = csvValidated(env, 'VM_DNS_RESOLVERS', '1.1.1.1,8.8.8.8', ipv4, 'IPv4 resolver addresses');
  // Empty means "use the guard module's built-in non-public set" (phase-05
  // owns it); the parsed list stays empty rather than inventing the set here.
  const nonpublicCidrs = csvValidated(env, 'VM_NONPUBLIC_CIDRS', '', (entry) => cidr(entry), 'IPv4 CIDRs', true);

  const uplink = optional(env, 'VM_UPLINK', '');
  if (uplink !== '' && !/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$/.test(uplink)) {
    fail('VM_UPLINK', 'must be a Linux interface name or empty for auto-detect');
  }

  return {
    socketPath: absolutePath(env, 'VM_SUPERVISOR_SOCKET', '/run/cloud-harness-vm/supervisor.sock'),
    token,
    stateDir: absolutePath(env, 'VM_SUPERVISOR_STATE_DIR', '/var/lib/cloud-harness-vm'),
    incusSocketPath: absolutePath(env, 'VM_INCUS_SOCKET', '/var/lib/incus/unix.socket'),
    incusProject,
    guardStatePath: absolutePath(env, 'VM_GUARD_STATE_PATH', '/run/cloud-harness-vm/guard-state.json'),
    bridgePattern: optional(env, 'VM_BRIDGE_PATTERN', 'chmbr%d'),
    subnetPlan,
    uplink,
    dnsResolvers,
    nonpublicCidrs,
    poolPath: absolutePath(env, 'VM_POOL_PATH', '/var/lib/incus-pool'),
    maxTtlSeconds: integer(env, 'VM_MAX_TTL_SECONDS', 86_400, 60, 31_536_000),
    // CH-VM-SCOPE-2026-11-07 approved initial envelope: one active VM
    // globally at EXACTLY 4 vCPU / 8 GiB / 20 GiB disk. Pinned values —
    // deviation in either direction is rejected until a measured capacity
    // review changes the approved shape.
    maxActive: integer(env, 'VM_MAX_ACTIVE', 1, 1, 1),
    cpus: integer(env, 'VM_CPUS', 4, 4, 4),
    memoryBytes: integer(env, 'VM_MEMORY_BYTES', 8_589_934_592, 8_589_934_592, 8_589_934_592),
    diskBytes: integer(env, 'VM_DISK_BYTES', 21_474_836_480, 21_474_836_480, 21_474_836_480),
    poolReserveBytes: integer(env, 'VM_POOL_RESERVE_BYTES', 10_737_418_240, 0, 1_099_511_627_776),
    templateId,
    templateDigest
  };
}

/**
 * Read a secret file with restrictive-safeguard checks: regular file (never a
 * symlink), owned by the effective uid or root, and no group/other permission
 * bits. Returns the trimmed contents; callers validate shape/length.
 */
export function defaultSecretFileReader(path: string): string {
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new VmSupervisorConfigError(`secret file ${path} must be a regular file, not a symlink`);
  }
  const euid = typeof process.geteuid === 'function' ? process.geteuid() : 0;
  if (stat.uid !== 0 && stat.uid !== euid) {
    throw new VmSupervisorConfigError(`secret file ${path} must be owned by root or the service user`);
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new VmSupervisorConfigError(`secret file ${path} must not grant group/other permissions`);
  }
  return readFileSync(path, 'utf8');
}
