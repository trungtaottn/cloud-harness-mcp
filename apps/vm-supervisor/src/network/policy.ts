import { createHash } from 'node:crypto';
import { VmNetworkGuardError } from '../network-ops.js';
import type { VmNetworkGuardConfig } from '../network-ops.js';

/**
 * Pure network-guard policy: canonical per-workspace resource derivation and
 * the nft/iptables rule compilers. Everything here is deterministic and
 * side-effect free — all kernel/incus access lives in kernel.ts/ops.ts.
 *
 * Verified shape (phase-05 + vm-pilot-network.py + the 2026-11-07 guard
 * verification): one `inet` nft table at base-chain priority -20 whose drops
 * are FINAL, spec-fixed iptables-nft DOCKER-USER permits plus a guest-/32
 * scoped MASQUERADE that carry the ALLOW path past UFW/Docker FORWARD-DROP,
 * and per-workspace unmanaged bridges with pinned /30 + MAC + tap identity.
 */

export const VM_GUARD_TABLE = 'chm_vm_guard';
/** iptables comment tag identifying rules this guard owns (never foreign). */
export const VM_GUARD_TAG = VM_GUARD_TABLE;

/** CH first-jump invariants asserted before AND after every mutation (pilot ch_gate). */
export const CH_INPUT_FIRST_RULE = '-A INPUT -i chm-egress0 -j CHM-INPUT-v1';
export const CH_FORWARD_FIRST_RULE = '-A FORWARD -j DOCKER-USER';
export const CH_DOCKER_USER_FIRST_RULE = '-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1';

/** The pilot's verified 15-CIDR nonpublic set, used when config leaves the list empty. */
export const DEFAULT_NONPUBLIC_CIDRS: readonly string[] = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.0.0.0/24',
  '192.0.2.0/24',
  '192.88.99.0/24',
  '192.168.0.0/16',
  '198.18.0.0/15',
  '198.51.100.0/24',
  '203.0.113.0/24',
  '224.0.0.0/4',
  '240.0.0.0/4'
];

const IFNAME_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/;
const HEX32_RE = /^[0-9a-f]{32}$/;
/** Linux IFNAMSIZ is 16 including NUL — every derived interface name must fit 15 chars. */
export const IFNAME_MAX_LENGTH = 15;

export interface VmNetworkSubject {
  workspaceId: string;
  vmName: string;
  /** Subnet/bridge slot index rendered into bridgePattern `%d` and tapName. */
  slotIndex: number;
  bridgeName: string;
  hostIp: string;
  guestIp: string;
  prefixLength: number;
  mac: string;
  tapName: string;
}

export interface ValidatedGuardConfig {
  bridgePattern: string;
  subnetPlanBase: number;
  subnetPlanPrefix: number;
  subnetPlanText: string;
  slotCount: number;
  /** '' means auto-detect the single IPv4 default route at use time. */
  uplink: string;
  dnsResolvers: readonly string[];
  nonpublicCidrs: readonly string[];
  guardStatePath: string;
}

function configError(message: string): never {
  throw new VmNetworkGuardError('guard-config-invalid', message);
}

function ipv4ToInt(ip: string): number {
  const parts = ip.split('.');
  if (parts.length !== 4) configError(`invalid IPv4 address '${ip}'`);
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) configError(`invalid IPv4 address '${ip}'`);
    const octet = Number(part);
    if (octet > 255) configError(`invalid IPv4 address '${ip}'`);
    value = value * 256 + octet;
  }
  return value >>> 0;
}

function intToIpv4(value: number): string {
  return [24, 16, 8, 0].map((shift) => (value >>> shift) & 0xff).join('.');
}

export function parseIpv4Cidr(text: string): { base: number; prefix: number; text: string } {
  const match = /^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/.exec(text.trim());
  if (!match) configError(`invalid IPv4 CIDR '${text}'`);
  const prefix = Number(match[2]);
  if (prefix > 32) configError(`invalid IPv4 CIDR '${text}'`);
  const base = ipv4ToInt(match[1]!);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const network = (base & mask) >>> 0;
  if (network !== base) configError(`IPv4 CIDR '${text}' has host bits set`);
  return { base: network, prefix, text: `${intToIpv4(network)}/${prefix}` };
}

function parseIpv4Address(text: string): string {
  const value = ipv4ToInt(text.trim());
  return intToIpv4(value);
}

function canonicalCidrSort(a: string, b: string): number {
  const ca = parseIpv4Cidr(a);
  const cb = parseIpv4Cidr(b);
  return ca.base - cb.base || ca.prefix - cb.prefix;
}

/**
 * Validate and normalize the supervisor-supplied guard config. Throws
 * VmNetworkGuardError on any unusable value — the guard fails closed rather
 * than programming an ambiguous ruleset.
 */
export function validateGuardConfig(config: VmNetworkGuardConfig): ValidatedGuardConfig {
  const bridgeVerbs = config.bridgePattern.split('%d').length - 1;
  if (bridgeVerbs !== 1) {
    configError(`bridgePattern '${config.bridgePattern}' must contain exactly one %d slot verb`);
  }
  const subnet = parseIpv4Cidr(config.subnetPlan);
  if (subnet.prefix > 30) {
    configError(`subnetPlan '${config.subnetPlan}' must be /30 or larger to carve per-workspace /30s`);
  }
  if (config.dnsResolvers.length === 0) {
    configError('dnsResolvers must contain at least one approved resolver');
  }
  const dnsResolvers = [...new Set(config.dnsResolvers.map(parseIpv4Address))].sort((a, b) => ipv4ToInt(a) - ipv4ToInt(b));
  const nonpublicInput = config.nonpublicCidrs.length > 0 ? config.nonpublicCidrs : DEFAULT_NONPUBLIC_CIDRS;
  const nonpublicCidrs = [...new Set(nonpublicInput.map((c) => parseIpv4Cidr(c).text))].sort(canonicalCidrSort);
  if (config.guardStatePath.trim().length === 0 || config.guardStatePath.includes('\0')) {
    configError('guardStatePath must be a non-empty path without NUL bytes');
  }
  if (config.uplink !== '' && !IFNAME_RE.test(config.uplink)) {
    configError(`uplink '${config.uplink}' is not a valid interface name`);
  }
  return {
    bridgePattern: config.bridgePattern,
    subnetPlanBase: subnet.base,
    subnetPlanPrefix: subnet.prefix,
    subnetPlanText: subnet.text,
    slotCount: 2 ** (30 - subnet.prefix),
    uplink: config.uplink,
    dnsResolvers,
    nonpublicCidrs,
    guardStatePath: config.guardStatePath
  };
}

/** `chm-vm-<sha256(workspaceId)[:32]>` — the contract VM name (executor-backend.ts). */
export function deriveVmName(workspaceId: string): string {
  return `chm-vm-${createHash('sha256').update(workspaceId, 'utf8').digest('hex').slice(0, 32)}`;
}

function workspaceHash(workspaceId: string): Buffer {
  return createHash('sha256').update(workspaceId, 'utf8').digest();
}

function expandBridgePattern(pattern: string, slotIndex: number): string {
  const name = pattern.replace('%d', String(slotIndex));
  if (!IFNAME_RE.test(name) || name.length > IFNAME_MAX_LENGTH) {
    configError(`bridgePattern '${pattern}' rendered invalid interface name '${name}'`);
  }
  return name;
}

/**
 * Deterministic per-workspace network identity: bridge name, host/guest /30
 * addresses, MAC and pinned tap name all derive from the workspaceId hash, so
 * they are stable across generations, supervisor restarts and reboots. A
 * truncated-hash slot collision is detected by the guard's claim registry and
 * managed-instance cross-check, never silently shared.
 */
export function planWorkspaceSubject(
  config: ValidatedGuardConfig,
  identity: { workspaceId: string; vmName: string }
): VmNetworkSubject {
  const expectedVmName = deriveVmName(identity.workspaceId);
  if (identity.vmName !== expectedVmName || !HEX32_RE.test(identity.vmName.slice(7))) {
    throw new VmNetworkGuardError(
      'vm-identity-mismatch',
      `vmName '${identity.vmName}' does not match derived name for workspace '${identity.workspaceId}'`
    );
  }
  const hash = workspaceHash(identity.workspaceId);
  // bytes 16..19 seed the subnet slot; bytes 20..24 seed the MAC. The vmName
  // consumes hex chars 0..31 (bytes 0..15), so these are disjoint material.
  const slotIndex = hash.readUInt32BE(16) % config.slotCount;
  const slotBase = (config.subnetPlanBase + slotIndex * 4) >>> 0;
  const hostIp = intToIpv4((slotBase + 1) >>> 0);
  const guestIp = intToIpv4((slotBase + 2) >>> 0);
  const macBytes = hash.subarray(20, 25);
  const mac = `02:${[...macBytes].map((b) => b.toString(16).padStart(2, '0')).join(':')}`;
  const bridgeName = expandBridgePattern(config.bridgePattern, slotIndex);
  const tapName = `chmvt${slotIndex}`;
  if (!IFNAME_RE.test(tapName) || tapName.length > IFNAME_MAX_LENGTH) {
    configError(`derived tap name '${tapName}' is not a valid interface name`);
  }
  return {
    workspaceId: identity.workspaceId,
    vmName: identity.vmName,
    slotIndex,
    bridgeName,
    hostIp,
    guestIp,
    prefixLength: 30,
    mac,
    tapName
  };
}

/** nft chain name for a subject's egress policy; bridge names are sanitized. */
export function nftChainNameFor(subject: VmNetworkSubject): string {
  return `egress_${subject.bridgeName.replace(/[^A-Za-z0-9_]/g, '_')}`;
}

export interface VmSubjectCollision {
  bridgeName: string;
  bridgeIndex: number;
  guestIp: string;
  /** The workspaces that derive to this same bridge//30 slot, sorted. */
  workspaceIds: string[];
}

/**
 * Pure cross-workspace collision detection over the canonical derivation:
 * groups `workspaceIds` by derived bridge slot and returns every slot claimed
 * by two or more distinct workspaces. The guard's claim registry enforces
 * this at program time; callers (e.g. the supervisor's vm.create path) can
 * run it earlier for a friendlier failure. Deterministic: output sorted by
 * bridgeName, workspaceIds sorted inside each group.
 */
export function findWorkspaceSubjectCollisions(
  config: ValidatedGuardConfig,
  workspaceIds: readonly string[]
): VmSubjectCollision[] {
  const byBridge = new Map<string, { bridgeIndex: number; guestIp: string; workspaceIds: Set<string> }>();
  for (const workspaceId of workspaceIds) {
    const subject = planWorkspaceSubject(config, { workspaceId, vmName: deriveVmName(workspaceId) });
    const entry = byBridge.get(subject.bridgeName) ?? { bridgeIndex: subject.slotIndex, guestIp: subject.guestIp, workspaceIds: new Set<string>() };
    entry.workspaceIds.add(workspaceId);
    byBridge.set(subject.bridgeName, entry);
  }
  return [...byBridge.entries()]
    .filter(([, entry]) => entry.workspaceIds.size > 1)
    .map(([bridgeName, entry]) => ({
      bridgeName,
      bridgeIndex: entry.bridgeIndex,
      guestIp: entry.guestIp,
      workspaceIds: [...entry.workspaceIds].sort()
    }))
    .sort((a, b) => a.bridgeName.localeCompare(b.bridgeName));
}

function cidrList(text: readonly string[]): string {
  return text.join(', ');
}

/**
 * Compile the canonical `inet chm_vm_guard` table text for the given subject
 * set. Returns '' for an empty set — callers translate that into a bare
 * `delete table` (the guard table is removed LAST, after reachability is
 * gone). Subjects are sorted by bridge name so output is deterministic.
 */
export function canonicalNftTable(
  subjects: readonly VmNetworkSubject[],
  config: ValidatedGuardConfig,
  uplink: string = config.uplink
): string {
  const ordered = [...subjects].sort((a, b) => a.bridgeName.localeCompare(b.bridgeName));
  if (ordered.length > 0 && uplink === '') {
    throw new VmNetworkGuardError('uplink-unresolved', 'nft table compilation requires a resolved uplink interface');
  }
  const chainNames = ordered.map(nftChainNameFor);
  if (new Set(chainNames).size !== chainNames.length) {
    configError('two workspace subjects collapse to the same nft chain name');
  }
  const bridges = ordered.map((s) => `"${s.bridgeName}"`).join(', ');
  const resolvers = `{ ${config.dnsResolvers.join(', ')} }`;
  const lines: string[] = [
    `table inet ${VM_GUARD_TABLE} {`,
    `\tset nonpublic {`,
    `\t\ttype ipv4_addr`,
    `\t\tflags interval`,
    `\t\telements = { ${cidrList(config.nonpublicCidrs)} }`,
    `\t}`,
    `\tset vm_bridges {`,
    `\t\ttype ifname`,
    `\t\telements = { ${bridges} }`,
    `\t}`,
    `\tchain input {`,
    `\t\ttype filter hook input priority -20; policy accept;`,
    `\t\tiifname @vm_bridges counter drop`,
    `\t}`,
    `\tchain forward {`,
    `\t\ttype filter hook forward priority -20; policy accept;`
  ];
  for (const subject of ordered) {
    lines.push(`\t\tiifname "${subject.bridgeName}" jump ${nftChainNameFor(subject)}`);
  }
  for (const subject of ordered) {
    lines.push(
      `\t\toifname "${subject.bridgeName}" ip daddr ${subject.guestIp} ct state established,related counter accept`,
      `\t\toifname "${subject.bridgeName}" counter drop`
    );
  }
  lines.push(`\t}`);
  for (const subject of ordered) {
    lines.push(
      `\tchain ${nftChainNameFor(subject)} {`,
      `\t\tmeta nfproto != ipv4 counter drop`,
      `\t\tip saddr != ${subject.guestIp} counter drop`,
      // F2 (independent review): `ether saddr` matching at the inet forward
      // hook depends on L2-header availability for routed tap→bridge frames —
      // UNVERIFIED until the phase-11 live gate. If `nft -c -f` rejects it the
      // apply fails closed; if accepted but inert it is dead weight. The L3
      // `ip saddr` check plus Incus security.mac_filtering/ipv4_filtering
      // already bound spoofing, so dropping this clause is the fallback.
      `\t\tether saddr != ${subject.mac} counter drop`,
      // F6 (independent review): ARP is NOT filtered — the `inet` family sees
      // only IPv4/IPv6; ARP traverses `arp`/`bridge` families. A guest can ARP
      // on its own /30 (required for gateway resolution); spoofing is bounded
      // to its isolated segment — no other guests share the bridge and Incus
      // mac_filtering constrains L2 identity. Accepted residual; an
      // `arp`/`bridge`-family drop for non-vm_bridges sources is the
      // defense-in-depth option if the owner wants it.
      `\t\tip daddr @nonpublic counter drop`,
      `\t\toifname != "${uplink}" counter drop`,
      `\t\tct state invalid counter drop`,
      `\t\tip daddr ${resolvers} udp dport 53 counter accept`,
      `\t\tip daddr ${resolvers} tcp dport 53 counter accept`,
      `\t\ttcp dport { 80, 443 } counter accept`,
      `\t\tcounter drop`,
      `\t}`
    );
  }
  lines.push('}');
  return ordered.length === 0 ? '' : `${lines.join('\n')}\n`;
}

/** sha256 hex digest of canonical ruleset text — the contract rulesetDigest. */
export function rulesetDigest(canonicalText: string): string {
  return createHash('sha256').update(canonicalText, 'utf8').digest('hex');
}

/** The canonical empty-ruleset digest returned by `network-none` program. */
export const EMPTY_RULESET_DIGEST = rulesetDigest('');

export interface VmPermitSpecs {
  /** DOCKER-USER rule spec (text after `-A DOCKER-USER `). */
  egress: string;
  /** DOCKER-USER established-return rule spec. */
  ret: string;
  /** nat POSTROUTING MASQUERADE rule spec (text after `-A POSTROUTING `). */
  nat: string;
}

/**
 * The three load-bearing iptables-nft permit specs for one subject, tagged
 * with VM_GUARD_TAG so ownership is identifiable and foreign rules are never
 * touched. `uplink` must already be resolved (never the empty auto marker).
 */
export function permitSpecsFor(subject: VmNetworkSubject, config: ValidatedGuardConfig, uplink: string = config.uplink): VmPermitSpecs {
  if (uplink === '') {
    throw new VmNetworkGuardError('uplink-unresolved', 'permit specs require a resolved uplink interface');
  }
  const tag = `-m comment --comment ${VM_GUARD_TAG}`;
  return {
    egress: `-i ${subject.bridgeName} -s ${subject.guestIp}/32 -o ${uplink} ${tag} -j ACCEPT`,
    ret: `-o ${subject.bridgeName} -d ${subject.guestIp}/32 -m conntrack --ctstate ESTABLISHED,RELATED ${tag} -j ACCEPT`,
    nat: `-s ${subject.guestIp}/32 -o ${uplink} ${tag} -j MASQUERADE`
  };
}

/** Expected expanded_devices slice for the attested network profile. */
export interface VmExpectedNicDevice {
  /** Exact allowed key set for the single NIC device (type included). */
  allowedKeys: readonly string[];
  expected: Readonly<Record<string, string>>;
}

const NIC_ALLOWED_KEYS = [
  'type',
  'nictype',
  'parent',
  'name',
  'hwaddr',
  'host_name',
  'ipv4.address',
  'security.mac_filtering',
  'security.ipv4_filtering',
  'security.ipv6_filtering'
] as const;

/**
 * The pinned device template (phase-05): nictype=bridged on the dedicated
 * unmanaged parent, deterministic hwaddr/host_name/ipv4.address and all three
 * Incus security.*_filtering layers as SUPPLEMENTARY L2 anti-spoof. The key
 * set is exact — `security.acls`, `ipv6.address`, `vlan`, `mtu` and any other
 * key are drift.
 */
export function expectedNicDevice(subject: VmNetworkSubject): VmExpectedNicDevice {
  return {
    allowedKeys: NIC_ALLOWED_KEYS,
    expected: nicDeviceStamp(subject)
  };
}

/**
 * The exact `expanded_devices.eth0` record the supervisor MUST stamp at
 * vm.create — identical to what `expectedNicDevice` attests, so stamping and
 * attestation can never diverge. `host_name` is the pinned tap (<=15 chars,
 * IFNAMSIZ); `ipv4.address` carries the /30 prefix explicitly.
 */
export function nicDeviceStamp(subject: VmNetworkSubject): Record<string, string> {
  return {
    type: 'nic',
    nictype: 'bridged',
    parent: subject.bridgeName,
    name: 'eth0',
    hwaddr: subject.mac,
    host_name: subject.tapName,
    'ipv4.address': `${subject.guestIp}/${subject.prefixLength}`,
    'security.mac_filtering': 'true',
    'security.ipv4_filtering': 'true',
    'security.ipv6_filtering': 'true'
  };
}
