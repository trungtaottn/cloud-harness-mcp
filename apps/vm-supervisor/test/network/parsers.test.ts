import { describe, expect, it } from 'vitest';
import {
  canonicalNftText,
  diffNftTables,
  firstChainRule,
  ipRuleLineKey,
  normalizeNftStatement,
  ipRuleSpecKey,
  normalizeIpRule,
  parseIpJson,
  parseIpRuleSpec,
  parseIpTablesChain,
  parseIpTablesRuleLine,
  parseNftPriority,
  parseNftTableText,
  rulePositions,
  singleDefaultRouteDev
} from '../../src/network/parsers.js';
import { CH_DOCKER_USER_FIRST_RULE } from '../../src/network/policy.js';
import { canonicalNftTable, planWorkspaceSubject, validateGuardConfig, deriveVmName } from '../../src/network/policy.js';
import type { VmNetworkSubject } from '../../src/network/policy.js';

const config = validateGuardConfig({
  bridgePattern: 'chmbr%d',
  subnetPlan: '10.240.0.0/16',
  uplink: 'enp7s0',
  dnsResolvers: ['1.1.1.1', '8.8.8.8'],
  nonpublicCidrs: [],
  guardStatePath: '/run/cloud-harness-vm/guard-state.json'
});
const WS = 'ws_0123456789abcdef0123456789abcdef';
const subject: VmNetworkSubject = planWorkspaceSubject(config, { workspaceId: WS, vmName: deriveVmName(WS) });

/** What `nft list table inet chm_vm_guard` prints after our canonical apply (counters materialized). */
function listedNftText(): string {
  const base = canonicalNftTable([subject], config);
  return base
    .replaceAll('counter drop', 'counter packets 12 bytes 3456 drop')
    .replaceAll('counter accept', 'counter packets 7 bytes 890 accept');
}

describe('parseNftTableText', () => {
  it('parses the canonical compiler output into a model', () => {
    const model = parseNftTableText(canonicalNftTable([subject], config));
    expect(model.family).toBe('inet');
    expect(model.name).toBe('chm_vm_guard');
    const setNames = model.sets.map((s) => s.name).sort();
    expect(setNames).toEqual(['nonpublic', 'vm_bridges']);
    const nonpublic = model.sets.find((s) => s.name === 'nonpublic')!;
    expect(nonpublic.elements).toContain('169.254.0.0/16');
    const input = model.chains.find((c) => c.name === 'input')!;
    expect(input.hook).toBe('input');
    expect(input.priority).toBe(-20);
    expect(input.policy).toBe('accept');
    expect(input.rules).toEqual(['iifname @vm_bridges drop']);
    const egress = model.chains.find((c) => c.name.startsWith('egress_'))!;
    expect(egress.rules[0]).toBe('meta nfproto != ipv4 drop');
    expect(egress.rules.at(-1)).toBe('drop');
  });

  it('tolerates counter materialization, quoting and wrapped set elements', () => {
    const listed = listedNftText();
    const model = parseNftTableText(listed);
    const input = model.chains.find((c) => c.name === 'input')!;
    expect(input.rules).toEqual(['iifname @vm_bridges drop']);
    const canonical = parseNftTableText(canonicalNftTable([subject], config));
    expect(canonicalNftText(model)).toBe(canonicalNftText(canonical));
    expect(diffNftTables(canonical, model)).toEqual([]);
  });

  it('detects drift: missing rule, foreign insert, reordered deny', () => {
    const canonical = parseNftTableText(canonicalNftTable([subject], config));
    const drifted = canonicalNftTable([subject], config)
      .replace('ct state invalid counter drop\n', '')
      .replace('oifname != "enp7s0" counter drop', 'oifname != "enp7s0" counter drop\n\t\ttcp dport 22 counter accept');
    const actual = parseNftTableText(drifted);
    const diffs = diffNftTables(canonical, actual);
    // Ordered compare reports ONE sequence diff per drifted chain; both the
    // removed deny and the foreign insert surface inside it.
    expect(diffs).toHaveLength(1);
    expect(diffs.join('\n')).toContain('ct state invalid');
    expect(diffs.join('\n')).toContain('tcp dport 22');
  });

  it('detects a missing table as empty model', () => {
    const model = parseNftTableText('');
    expect(model.sets).toEqual([]);
    expect(model.chains).toEqual([]);
  });

  it('parses REAL `nft list` output: symbolic priorities + materialized counters', () => {
    // Captured-format fixture: `nft list table inet chm_vm_guard` never prints
    // `priority -20` — it resolves the integer to the nearest named base plus
    // a spaced signed offset, and bare `counter` becomes packet/byte counters.
    const br = subject.bridgeName;
    const egressChain = `egress_${br.replace(/[^A-Za-z0-9_]/g, '_')}`;
    const listed = [
      'table inet chm_vm_guard {',
      '\tset nonpublic {',
      '\t\ttype ipv4_addr',
      '\t\tflags interval',
      `\t\telements = { ${config.nonpublicCidrs.join(', ')} }`,
      '\t}',
      '\tset vm_bridges {',
      '\t\ttype ifname',
      `\t\telements = { "${br}" }`,
      '\t}',
      '\tchain input {',
      '\t\ttype filter hook input priority filter - 20; policy accept;',
      '\t\tiifname @vm_bridges counter packets 41 bytes 3443 drop',
      '\t}',
      '\tchain forward {',
      '\t\ttype filter hook forward priority filter - 20; policy accept;',
      `\t\tiifname "${br}" jump ${egressChain}`,
      `\t\toifname "${br}" ip daddr ${subject.guestIp} ct state { established, related } counter packets 9 bytes 900 accept`,
      `\t\toifname "${br}" counter packets 3 bytes 180 drop`,
      '\t}',
      `\tchain ${egressChain} {`,
      '\t\tmeta nfproto != ipv4 counter packets 0 bytes 0 drop',
      `\t\tip saddr != ${subject.guestIp} counter packets 0 bytes 0 drop`,
      `\t\tether saddr != ${subject.mac} counter packets 0 bytes 0 drop`,
      '\t\toifname != "enp7s0" counter packets 0 bytes 0 drop',
      '\t\tct state invalid counter packets 0 bytes 0 drop',
      '\t\tip daddr { 1.1.1.1, 8.8.8.8 } udp dport 53 counter packets 0 bytes 0 accept',
      '\t\tip daddr { 1.1.1.1, 8.8.8.8 } tcp dport 53 counter packets 0 bytes 0 accept',
      '\t\tip daddr @nonpublic counter packets 0 bytes 0 drop',
      '\t\ttcp dport { 80, 443 } counter packets 0 bytes 0 accept',
      '\t\tcounter packets 0 bytes 0 drop',
      '\t}',
      '}'
    ].join('\n');
    const model = parseNftTableText(listed);
    const input = model.chains.find((c) => c.name === 'input')!;
    expect(input.priority).toBe(-20);
    expect(input.policy).toBe('accept');
    const egress = model.chains.find((c) => c.name === egressChain)!;
    expect(egress.rules).toContain('ct state invalid drop');
    expect(egress.rules.at(-1)).toBe('drop');
    // And it parses to the SAME model as the compiler text for this subject.
    const canonical = parseNftTableText(canonicalNftTable([subject], config));
    expect(canonicalNftText(model)).toBe(canonicalNftText(canonical));
    expect(diffNftTables(canonical, model)).toEqual([]);
  });

  it('collapses singleton anonymous sets: `{ x }` and `x` normalize identically', () => {
    // nftables v1.1.7 prints `ip daddr { 1.1.1.1 }` back as `ip daddr 1.1.1.1`
    // (verified in an isolated netns) — without collapse a single-resolver
    // config drifts forever.
    expect(normalizeNftStatement('ip daddr { 1.1.1.1 } udp dport 53 counter accept')).toBe(
      normalizeNftStatement('ip daddr 1.1.1.1 udp dport 53 counter accept')
    );
    expect(normalizeNftStatement('tcp dport { 443 } accept')).toBe(normalizeNftStatement('tcp dport 443 accept'));
    // Multi-element sets keep their braces.
    expect(normalizeNftStatement('ip daddr { 8.8.8.8, 1.1.1.1 } accept')).toContain('{ 1.1.1.1, 8.8.8.8 }');
  });

  it('single-resolver canonical table produces zero drift against nft print form', () => {
    const single = validateGuardConfig({
      bridgePattern: 'chmbr%d',
      subnetPlan: '10.240.0.0/16',
      uplink: 'enp7s0',
      dnsResolvers: ['10.0.0.53'],
      nonpublicCidrs: [],
      guardStatePath: '/run/cloud-harness-vm/guard-state.json'
    });
    const subj = planWorkspaceSubject(single, { workspaceId: WS, vmName: deriveVmName(WS) });
    const canonical = parseNftTableText(canonicalNftTable([subj], single));
    // Simulate `nft list` output: singleton set prints WITHOUT braces.
    const listed = canonicalNftTable([subj], single).replaceAll('ip daddr { 10.0.0.53 }', 'ip daddr 10.0.0.53');
    const actual = parseNftTableText(listed);
    expect(diffNftTables(canonical, actual)).toEqual([]);
  });

  it('ordered rule comparison flags a pure reorder as drift (F1)', () => {
    const expected = parseNftTableText(canonicalNftTable([subject], config));
    const actual = parseNftTableText(canonicalNftTable([subject], config));
    const egress = actual.chains.find((c) => c.name.startsWith('egress_'))!;
    const reordered = [...egress.rules];
    // Swap the DNS-accept pair — semantically different evaluation order.
    const i1 = reordered.findIndex((r) => r.includes('udp dport 53'));
    const i2 = reordered.findIndex((r) => r.includes('tcp dport {'));
    [reordered[i1], reordered[i2]] = [reordered[i2]!, reordered[i1]!];
    egress.rules = reordered;
    const diffs = diffNftTables(expected, actual);
    expect(diffs.join('\n')).toContain('rule sequence differs');
  });
});

describe('parseNftPriority', () => {
  it('resolves every form real `nft list` prints', () => {
    expect(parseNftPriority('filter - 20')).toBe(-20);
    expect(parseNftPriority('filter - 1')).toBe(-1);
    expect(parseNftPriority('filter + 20')).toBe(20);
    expect(parseNftPriority('raw - 1')).toBe(-301);
    expect(parseNftPriority('filter')).toBe(0);
    expect(parseNftPriority('-20')).toBe(-20);
    expect(parseNftPriority('+5')).toBe(5);
  });

  it('fails closed on unrecognized priority syntax', () => {
    expect(parseNftPriority('filter -x')).toBeUndefined();
    expect(parseNftPriority('bogus - 5')).toBeUndefined();
    expect(parseNftPriority('')).toBeUndefined();
    expect(parseNftPriority('filter - 20 extra')).toBeUndefined();
  });
});

describe('parseIpTablesChain / rulePositions / normalizeIpRule', () => {
  const chainText = [
    '-P DOCKER-USER ACCEPT',
    '-N CHM-EGRESS-v1',
    '-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1',
    `-A DOCKER-USER -i ${subject.bridgeName} -s ${subject.guestIp}/32 -o enp7s0 -m comment --comment chm_vm_guard -j ACCEPT`,
    '-A DOCKER-USER -p tcp -m tcp --dport 8080 -j DROP',
    `-A DOCKER-USER -o ${subject.bridgeName} -d ${subject.guestIp}/32 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment chm_vm_guard -j ACCEPT`
  ].join('\n');

  it('extracts -A rules and the first rule position', () => {
    const rules = parseIpTablesChain(chainText);
    expect(rules).toHaveLength(4);
    expect(firstChainRule(chainText)).toBe('-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1');
  });

  it('normalizes whitespace for canonical compare', () => {
    expect(normalizeIpRule('-A  DOCKER-USER   -i   chmbr1')).toBe('-A DOCKER-USER -i chmbr1');
  });

  it('reports positions of our tagged permits relative to the CH jump', () => {
    const positions = rulePositions(chainText, [
      `-A DOCKER-USER -i ${subject.bridgeName} -s ${subject.guestIp}/32 -o enp7s0 -m comment --comment chm_vm_guard -j ACCEPT`,
      `-A DOCKER-USER -o ${subject.bridgeName} -d ${subject.guestIp}/32 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment chm_vm_guard -j ACCEPT`
    ], CH_DOCKER_USER_FIRST_RULE);
    expect(positions.found).toHaveLength(2);
    expect(positions.missing).toEqual([]);
    expect(positions.afterMarker).toBe(true);
  });

  it('flags permits that precede the CH first jump as out of position', () => {
    const bad = [
      `-A DOCKER-USER -i ${subject.bridgeName} -s ${subject.guestIp}/32 -o enp7s0 -m comment --comment chm_vm_guard -j ACCEPT`,
      '-A DOCKER-USER -i chm-egress0 -j CHM-EGRESS-v1',
      `-A DOCKER-USER -o ${subject.bridgeName} -d ${subject.guestIp}/32 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment chm_vm_guard -j ACCEPT`
    ].join('\n');
    const positions = rulePositions(bad, [
      `-A DOCKER-USER -i ${subject.bridgeName} -s ${subject.guestIp}/32 -o enp7s0 -m comment --comment chm_vm_guard -j ACCEPT`
    ], CH_DOCKER_USER_FIRST_RULE);
    expect(positions.afterMarker).toBe(false);
  });
});

describe('iptables semantic rule model (B3)', () => {
  // Real `iptables -S` (iptables-nft) prints addresses before interfaces,
  // protocol after interfaces, ctstate in kernel order, and match modules in
  // creation order — NEVER the order the rule was supplied in.
  const canonicalLine =
    '-A DOCKER-USER -s 10.240.7.2/32 -i chmbr7 -o enp7s0 -m comment --comment chm_vm_guard -j ACCEPT';
  const retCanonical =
    '-A DOCKER-USER -d 10.240.7.2/32 -o chmbr7 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment chm_vm_guard -j ACCEPT';

  it('treats compiler-order and canonical-order specs as the same rule', () => {
    const compiler = `-i chmbr7 -s 10.240.7.2/32 -o enp7s0 -m comment --comment chm_vm_guard -j ACCEPT`;
    const keyCompiler = ipRuleSpecKey('DOCKER-USER', compiler);
    const keyCanonical = ipRuleSpecKey('DOCKER-USER', canonicalLine.slice('-A DOCKER-USER '.length));
    expect(keyCompiler).not.toBeNull();
    expect(keyCompiler).toBe(keyCanonical);
    expect(ipRuleLineKey(canonicalLine)).toBe(keyCompiler);
  });

  it('normalizes ctstate set order (ESTABLISHED,RELATED == RELATED,ESTABLISHED)', () => {
    const a = ipRuleSpecKey(
      'DOCKER-USER',
      '-o chmbr7 -d 10.240.7.2/32 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment chm_vm_guard -j ACCEPT'
    );
    const b = ipRuleSpecKey('DOCKER-USER', retCanonical.slice('-A DOCKER-USER '.length));
    expect(a).toBe(b);
  });

  it('preserves negation: `! -i x` never equals `-i x`', () => {
    const pos = ipRuleSpecKey('FORWARD', '-i eth0 -j ACCEPT');
    const neg = ipRuleSpecKey('FORWARD', '! -i eth0 -j ACCEPT');
    expect(pos).not.toBe(neg);
    const model = parseIpRuleSpec('FORWARD', '! -i eth0 -j ACCEPT')!;
    expect(model.inInterface).toEqual({ value: 'eth0', negated: true });
  });

  it('distinguishes different targets, interfaces and comment values', () => {
    const base = ipRuleSpecKey('DOCKER-USER', '-s 10.0.0.2/32 -i br0 -o eth0 -m comment --comment chm_vm_guard -j ACCEPT')!;
    expect(ipRuleSpecKey('DOCKER-USER', '-s 10.0.0.2/32 -i br0 -o eth0 -m comment --comment chm_vm_guard -j DROP')).not.toBe(base);
    expect(ipRuleSpecKey('DOCKER-USER', '-s 10.0.0.3/32 -i br0 -o eth0 -m comment --comment chm_vm_guard -j ACCEPT')).not.toBe(base);
    expect(ipRuleSpecKey('DOCKER-USER', '-s 10.0.0.2/32 -i br1 -o eth0 -m comment --comment chm_vm_guard -j ACCEPT')).not.toBe(base);
    expect(ipRuleSpecKey('DOCKER-USER', '-s 10.0.0.2/32 -i br0 -o eth0 -m comment --comment other -j ACCEPT')).not.toBe(base);
  });

  it('treats match-module order as irrelevant but keeps match semantics', () => {
    const connFirst = ipRuleSpecKey(
      'DOCKER-USER',
      '-d 10.0.0.2/32 -o br0 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment chm_vm_guard -j ACCEPT'
    );
    const commentFirst = ipRuleSpecKey(
      'DOCKER-USER',
      '-d 10.0.0.2/32 -o br0 -m comment --comment chm_vm_guard -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT'
    );
    expect(connFirst).toBe(commentFirst);
    // But a DIFFERENT match arg is a different rule.
    const other = ipRuleSpecKey(
      'DOCKER-USER',
      '-d 10.0.0.2/32 -o br0 -m conntrack --ctstate NEW -m comment --comment chm_vm_guard -j ACCEPT'
    );
    expect(other).not.toBe(connFirst);
  });

  it('preserves negation inside match modules: `! --ctstate` never equals `--ctstate`', () => {
    const pos = ipRuleSpecKey(
      'DOCKER-USER',
      '-o br0 -d 10.0.0.2/32 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment chm_vm_guard -j ACCEPT'
    );
    const negSpace = ipRuleSpecKey(
      'DOCKER-USER',
      '-o br0 -d 10.0.0.2/32 -m conntrack ! --ctstate ESTABLISHED,RELATED -m comment --comment chm_vm_guard -j ACCEPT'
    );
    const negJoined = ipRuleSpecKey(
      'DOCKER-USER',
      '-o br0 -d 10.0.0.2/32 -m conntrack !--ctstate ESTABLISHED,RELATED -m comment --comment chm_vm_guard -j ACCEPT'
    );
    expect(pos).not.toBe(negSpace);
    expect(pos).not.toBe(negJoined);
    expect(negSpace).toBe(negJoined);
    // Negated set-valued options still normalize member order.
    const negReordered = ipRuleSpecKey(
      'DOCKER-USER',
      '-o br0 -d 10.0.0.2/32 -m conntrack ! --ctstate RELATED,ESTABLISHED -m comment --comment chm_vm_guard -j ACCEPT'
    );
    expect(negReordered).toBe(negSpace);
  });

  it('handles quoted comment values and bare -A line parsing', () => {
    const model = parseIpTablesRuleLine('-A DOCKER-USER -s 10.0.0.2/32 -m comment --comment "two words" -j ACCEPT')!;
    expect(model.matches[0]!.args).toContain('two words');
    expect(parseIpTablesRuleLine('-P DOCKER-USER ACCEPT')).toBeNull();
  });
});

describe('ip -j JSON helpers', () => {
  it('parses link/addr/route JSON arrays', () => {
    const links = parseIpJson('[{"ifname":"chmbr1","linkinfo":{"info_kind":"bridge"},"operstate":"UP"}]');
    expect(links).toHaveLength(1);
    const routes = parseIpJson('[{"dst":"default","table":"main","dev":"enp7s0"},{"dst":"10.0.0.0/8","table":"main","dev":"tailscale0"}]');
    expect(singleDefaultRouteDev(routes)).toBe('enp7s0');
  });

  it('rejects ambiguous or absent default routes', () => {
    expect(singleDefaultRouteDev(parseIpJson('[]'))).toBeNull();
    expect(singleDefaultRouteDev(parseIpJson('[{"dst":"default","table":"main","dev":"a"},{"dst":"default","table":"main","dev":"b"}]'))).toBeNull();
    expect(singleDefaultRouteDev(parseIpJson('[{"dst":"default","table":"local","dev":"a"}]'))).toBeNull();
  });
});
