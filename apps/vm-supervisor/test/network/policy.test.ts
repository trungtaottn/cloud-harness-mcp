import { describe, expect, it } from 'vitest';
import {
  CH_DOCKER_USER_FIRST_RULE,
  CH_FORWARD_FIRST_RULE,
  CH_INPUT_FIRST_RULE,
  EMPTY_RULESET_DIGEST,
  IFNAME_MAX_LENGTH,
  VM_GUARD_TABLE,
  canonicalNftTable,
  deriveVmName,
  expectedNicDevice,
  findWorkspaceSubjectCollisions,
  nicDeviceStamp,
  nftChainNameFor,
  permitSpecsFor,
  planWorkspaceSubject,
  rulesetDigest,
  validateGuardConfig
} from '../../src/network/policy.js';
import { VmNetworkGuardError } from '../../src/network-ops.js';
import type { VmNetworkGuardConfig } from '../../src/network-ops.js';

const baseConfig: VmNetworkGuardConfig = {
  bridgePattern: 'chmbr%d',
  subnetPlan: '10.240.0.0/16',
  uplink: '',
  dnsResolvers: ['1.1.1.1', '8.8.8.8'],
  nonpublicCidrs: [],
  guardStatePath: '/run/cloud-harness-vm/guard-state.json'
};

const WS = 'ws_0123456789abcdef0123456789abcdef';

describe('validateGuardConfig', () => {
  it('accepts the documented supervisor config shape', () => {
    const config = validateGuardConfig(baseConfig);
    expect(config.bridgePattern).toBe('chmbr%d');
    expect(config.uplink).toBe('');
    expect(config.dnsResolvers).toEqual(['1.1.1.1', '8.8.8.8']);
    expect(config.slotCount).toBe(16_384);
  });

  it('rejects a bridge pattern without exactly one %d slot verb', () => {
    expect(() => validateGuardConfig({ ...baseConfig, bridgePattern: 'chmbr' })).toThrowError(VmNetworkGuardError);
    expect(() => validateGuardConfig({ ...baseConfig, bridgePattern: 'chmbr%d%d' })).toThrowError(VmNetworkGuardError);
  });

  it('rejects non-IPv4 or too-small subnet plans', () => {
    expect(() => validateGuardConfig({ ...baseConfig, subnetPlan: 'fd00::/64' })).toThrowError(VmNetworkGuardError);
    expect(() => validateGuardConfig({ ...baseConfig, subnetPlan: '10.240.0.0/31' })).toThrowError(VmNetworkGuardError);
    expect(() => validateGuardConfig({ ...baseConfig, subnetPlan: 'not-a-cidr' })).toThrowError(VmNetworkGuardError);
  });

  it('rejects invalid DNS resolvers and non-CIDR nonpublic entries', () => {
    expect(() => validateGuardConfig({ ...baseConfig, dnsResolvers: ['999.1.1.1'] })).toThrowError(VmNetworkGuardError);
    expect(() => validateGuardConfig({ ...baseConfig, dnsResolvers: ['10.0.0.1/24'] })).toThrowError(VmNetworkGuardError);
    expect(() => validateGuardConfig({ ...baseConfig, nonpublicCidrs: ['not-a-cidr'] })).toThrowError(VmNetworkGuardError);
  });

  it('sorts and dedupes resolvers and CIDRs canonically', () => {
    const config = validateGuardConfig({
      ...baseConfig,
      dnsResolvers: ['8.8.8.8', '1.1.1.1', '8.8.8.8'],
      nonpublicCidrs: ['192.168.0.0/16', '10.0.0.0/8', '10.0.0.0/8']
    });
    expect(config.dnsResolvers).toEqual(['1.1.1.1', '8.8.8.8']);
    expect(config.nonpublicCidrs).toEqual(['10.0.0.0/8', '192.168.0.0/16']);
  });

  it('falls back to the verified pilot nonpublic set when the config list is empty', () => {
    const config = validateGuardConfig(baseConfig);
    expect(config.nonpublicCidrs).toContain('169.254.0.0/16');
    expect(config.nonpublicCidrs).toContain('100.64.0.0/10');
    expect(config.nonpublicCidrs.length).toBe(15);
  });
});

describe('deriveVmName / planWorkspaceSubject', () => {
  it('derives the contract vm name from the workspace id', () => {
    const name = deriveVmName(WS);
    expect(name).toMatch(/^chm-vm-[0-9a-f]{32}$/);
    expect(deriveVmName(WS)).toBe(name);
    expect(deriveVmName('ws_other')).not.toBe(name);
  });

  it('derives a canonical /30, bridge, MAC and tap deterministically', () => {
    const config = validateGuardConfig(baseConfig);
    const vmName = deriveVmName(WS);
    const subject = planWorkspaceSubject(config, { workspaceId: WS, vmName });
    expect(subject.vmName).toBe(vmName);
    expect(subject.bridgeName).toMatch(/^chmbr\d+$/);
    expect(subject.guestIp).toMatch(/^10\.240\./);
    expect(subject.hostIp).toMatch(/^10\.240\./);
    expect(subject.prefixLength).toBe(30);
    // host .1 guest .2 inside the same /30
    const host = subject.hostIp.split('.').map(Number);
    const guest = subject.guestIp.split('.').map(Number);
    expect(guest[3]! - host[3]!).toBe(1);
    expect(host[3]! % 4).toBe(1);
    expect(guest[3]! % 4).toBe(2);
    // locally-administered unicast MAC, deterministic
    expect(subject.mac).toMatch(/^02(:[0-9a-f]{2}){5}$/);
    expect(planWorkspaceSubject(config, { workspaceId: WS, vmName }).mac).toBe(subject.mac);
    expect(subject.tapName).toMatch(/^chmvt\d+$/);
  });

  it('is stable across generations (identity carries no generation input)', () => {
    const config = validateGuardConfig(baseConfig);
    const vmName = deriveVmName(WS);
    const a = planWorkspaceSubject(config, { workspaceId: WS, vmName });
    const b = planWorkspaceSubject(config, { workspaceId: WS, vmName });
    expect(a).toEqual(b);
  });

  it('fails closed when the supplied vmName does not match the workspace hash', () => {
    const config = validateGuardConfig(baseConfig);
    expect(() => planWorkspaceSubject(config, { workspaceId: WS, vmName: 'chm-vm-' + '0'.repeat(32) }))
      .toThrowError(VmNetworkGuardError);
  });

  it('produces distinct subjects for distinct workspaces', () => {
    const config = validateGuardConfig(baseConfig);
    const a = planWorkspaceSubject(config, { workspaceId: WS, vmName: deriveVmName(WS) });
    const b = planWorkspaceSubject(config, { workspaceId: 'ws_ffffffffffffffffffffffffffffffff', vmName: deriveVmName('ws_ffffffffffffffffffffffffffffffff') });
    expect(a.bridgeName).not.toBe(b.bridgeName);
    expect(a.guestIp).not.toBe(b.guestIp);
    expect(a.mac).not.toBe(b.mac);
  });

  it('exposes slotIndex and keeps every derived interface name within IFNAMSIZ', () => {
    const config = validateGuardConfig(baseConfig);
    const subject = planWorkspaceSubject(config, { workspaceId: WS, vmName: deriveVmName(WS) });
    expect(subject.slotIndex).toBeGreaterThanOrEqual(0);
    expect(subject.slotIndex).toBeLessThan(config.slotCount);
    for (const name of [subject.bridgeName, subject.tapName]) {
      expect(name.length).toBeLessThanOrEqual(IFNAME_MAX_LENGTH);
      expect(name.length).toBeLessThanOrEqual(15); // IFNAMSIZ-1
    }
    // tapName embeds the slot so supervisor stamping can recover it.
    expect(subject.tapName).toBe(`chmvt${subject.slotIndex}`);
  });

  it('rejects bridge patterns that render names over IFNAMSIZ', () => {
    const config = validateGuardConfig({ ...baseConfig, bridgePattern: 'chm-bridge-with-a-very-long-name-%d' });
    expect(() => planWorkspaceSubject(config, { workspaceId: WS, vmName: deriveVmName(WS) })).toThrowError(VmNetworkGuardError);
  });
});

describe('findWorkspaceSubjectCollisions (B4 seam)', () => {
  const config = validateGuardConfig(baseConfig);

  it('returns no collisions for distinct workspaces', () => {
    const ids = [WS, 'ws_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'ws_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'];
    expect(findWorkspaceSubjectCollisions(config, ids)).toEqual([]);
  });

  it('detects a truncated-hash bridge slot collision deterministically', () => {
    // Reuse the ops-test approach: scan for a second id on subject1's slot.
    const first = planWorkspaceSubject(config, { workspaceId: WS, vmName: deriveVmName(WS) });
    let other = '';
    for (let i = 0; i < 500_000 && other === ''; i++) {
      const candidate = `ws_${i.toString(16).padStart(32, '0')}`;
      if (candidate === WS) continue;
      const s = planWorkspaceSubject(config, { workspaceId: candidate, vmName: deriveVmName(candidate) });
      if (s.bridgeName === first.bridgeName) other = candidate;
    }
    expect(other).not.toBe('');
    const collisions = findWorkspaceSubjectCollisions(config, [WS, other]);
    expect(collisions).toHaveLength(1);
    expect(collisions[0]!.bridgeName).toBe(first.bridgeName);
    expect(collisions[0]!.workspaceIds).toEqual([WS, other].sort());
    expect(collisions[0]!.guestIp).toBe(first.guestIp);
    // Order-independent: reversed input yields identical output.
    expect(findWorkspaceSubjectCollisions(config, [other, WS])).toEqual(collisions);
  });
});

describe('nicDeviceStamp / expectedNicDevice (B4 stamping seam)', () => {
  const config = validateGuardConfig({ ...baseConfig, uplink: 'enp7s0' });
  const subject = planWorkspaceSubject(config, { workspaceId: WS, vmName: deriveVmName(WS) });

  it('stamp equals the attested expected record exactly', () => {
    const expected = expectedNicDevice(subject);
    expect(nicDeviceStamp(subject)).toEqual(expected.expected);
    // host_name is the pinned tap — always <=15 chars (IFNAMSIZ), never
    // `chm-<workspaceId>` which overflowed the old supervisor derivation.
    expect(subject.tapName.length).toBeLessThanOrEqual(IFNAME_MAX_LENGTH);
    expect(nicDeviceStamp(subject)['host_name']).toBe(subject.tapName);
    expect(nicDeviceStamp(subject)['parent']).toBe(subject.bridgeName);
    expect(nicDeviceStamp(subject)['ipv4.address']).toBe(`${subject.guestIp}/30`);
    expect(nicDeviceStamp(subject)['hwaddr']).toBe(subject.mac);
  });
});

describe('canonicalNftTable', () => {
  const config = validateGuardConfig({ ...baseConfig, uplink: 'enp7s0' });
  const subject = planWorkspaceSubject(config, { workspaceId: WS, vmName: deriveVmName(WS) });

  it('returns the canonical empty ruleset for zero subjects', () => {
    expect(canonicalNftTable([], config)).toBe('');
    expect(EMPTY_RULESET_DIGEST).toBe(rulesetDigest(''));
  });

  it('compiles the verified pilot-shaped deny table generalized per workspace', () => {
    const text = canonicalNftTable([subject], config);
    expect(text).toContain(`table inet ${VM_GUARD_TABLE} {`);
    expect(text).toContain('type filter hook input priority -20; policy accept;');
    expect(text).toContain('type filter hook forward priority -20; policy accept;');
    expect(text).toContain('iifname @vm_bridges counter drop');
    expect(text).toContain(`ip saddr != ${subject.guestIp} counter drop`);
    expect(text).toContain(`ether saddr != ${subject.mac} counter drop`);
    expect(text).toContain('ip daddr @nonpublic counter drop');
    expect(text).toContain('oifname != "enp7s0" counter drop');
    expect(text).toContain('ct state invalid counter drop');
    expect(text).toContain('udp dport 53 counter accept');
    expect(text).toContain('tcp dport 53 counter accept');
    expect(text).toContain('tcp dport { 80, 443 } counter accept');
    expect(text).toContain('meta nfproto != ipv4 counter drop');
    expect(text).toContain(`oifname "${subject.bridgeName}" ip daddr ${subject.guestIp} ct state established,related counter accept`);
    expect(text).toContain(`oifname "${subject.bridgeName}" counter drop`);
    expect(text).toContain(`iifname "${subject.bridgeName}" jump ${nftChainNameFor(subject)}`);
    // terminal drop is the last statement of the (last) egress chain
    expect(text).toMatch(/\t\tcounter drop\n\t\}\n\}\n$/);
  });

  it('sorts subjects and set elements deterministically', () => {
    const other = planWorkspaceSubject(config, { workspaceId: 'ws_ffffffffffffffffffffffffffffffff', vmName: deriveVmName('ws_ffffffffffffffffffffffffffffffff') });
    const t1 = canonicalNftTable([subject, other], config);
    const t2 = canonicalNftTable([other, subject], config);
    expect(t1).toBe(t2);
    expect(rulesetDigest(t1)).toBe(rulesetDigest(t2));
  });

  it('emits no IPv6-permitting constructs and pins DNS to configured resolvers only', () => {
    const text = canonicalNftTable([subject], config);
    expect(text).not.toContain('ip6 ');
    expect(text).not.toContain('udp dport { 53,');
    expect(text).toContain('ip daddr { 1.1.1.1, 8.8.8.8 } udp dport 53 counter accept');
  });

  it('admits approved DNS resolvers before the nonpublic drop, after iface/spoof constraints', () => {
    // Private resolvers must be reachable on dport 53 only — every other
    // port/destination to a nonpublic address still hits the drop.
    const privateCfg = validateGuardConfig({ ...baseConfig, uplink: 'enp7s0', dnsResolvers: ['10.0.0.53'] });
    const privSubject = planWorkspaceSubject(privateCfg, { workspaceId: WS, vmName: deriveVmName(WS) });
    const text = canonicalNftTable([privSubject], privateCfg);
    const idx = (needle: string) => {
      const i = text.indexOf(needle);
      expect(i, `missing rule: ${needle}`).toBeGreaterThanOrEqual(0);
      return i;
    };
    const oif = idx('oifname != "enp7s0" counter drop');
    const invalid = idx('ct state invalid counter drop');
    const dnsUdp = idx('ip daddr { 10.0.0.53 } udp dport 53 counter accept');
    const dnsTcp = idx('ip daddr { 10.0.0.53 } tcp dport 53 counter accept');
    const nonpublic = idx('ip daddr @nonpublic counter drop');
    const web = idx('tcp dport { 80, 443 } counter accept');
    // iface binding + conntrack sanity precede the DNS admits
    expect(oif).toBeLessThan(dnsUdp);
    expect(invalid).toBeLessThan(dnsUdp);
    // DNS admits precede the nonpublic drop — the private-resolver fix
    expect(dnsUdp).toBeLessThan(nonpublic);
    expect(dnsTcp).toBeLessThan(nonpublic);
    // …but the nonpublic drop still precedes the web accepts, so private
    // SSH/HTTP to the same resolver IP remains dropped.
    expect(nonpublic).toBeLessThan(web);
    // Spoof constraints still precede everything accept-shaped.
    expect(idx(`ip saddr != ${privSubject.guestIp} counter drop`)).toBeLessThan(dnsUdp);
    expect(idx(`ether saddr != ${privSubject.mac} counter drop`)).toBeLessThan(dnsUdp);
  });
});

describe('permitSpecsFor', () => {
  const config = validateGuardConfig({ ...baseConfig, uplink: 'enp7s0' });
  const subject = planWorkspaceSubject(config, { workspaceId: WS, vmName: deriveVmName(WS) });

  it('produces the pilot-shaped DOCKER-USER accepts and scoped MASQUERADE', () => {
    const specs = permitSpecsFor(subject, config);
    expect(specs.egress).toBe(
      `-i ${subject.bridgeName} -s ${subject.guestIp}/32 -o enp7s0 -m comment --comment ${VM_GUARD_TABLE} -j ACCEPT`
    );
    expect(specs.ret).toBe(
      `-o ${subject.bridgeName} -d ${subject.guestIp}/32 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment ${VM_GUARD_TABLE} -j ACCEPT`
    );
    expect(specs.nat).toBe(
      `-s ${subject.guestIp}/32 -o enp7s0 -m comment --comment ${VM_GUARD_TABLE} -j MASQUERADE`
    );
  });
});

describe('CH gate constants', () => {
  it('pins the verified Cloud Harness first-jump rules', () => {
    expect(CH_INPUT_FIRST_RULE).toBe('-A INPUT -i chm-egress0 -j CHM-INPUT-v1');
    expect(CH_FORWARD_FIRST_RULE).toBe('-A FORWARD -j DOCKER-USER');
    expect(CH_DOCKER_USER_FIRST_RULE).toBe('-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1');
  });
});
