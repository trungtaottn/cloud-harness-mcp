import { mkdir, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { VmNetworkGuardError } from '../network-ops.js';
import type { VmGuardCommandRunner } from '../network-ops.js';
import {
  CH_DOCKER_USER_FIRST_RULE,
  CH_FORWARD_FIRST_RULE,
  CH_INPUT_FIRST_RULE,
  VM_GUARD_TABLE,
  VM_GUARD_TAG,
  canonicalNftTable,
  permitSpecsFor,
  rulesetDigest
} from './policy.js';
import type { ValidatedGuardConfig, VmNetworkSubject } from './policy.js';
import {
  diffNftTables,
  firstChainRule,
  ipRuleLineKey,
  parseIpJson,
  parseIpTablesChain,
  parseIpTablesRuleLine,
  parseNftTableText,
  singleDefaultRouteDev
} from './parsers.js';
import type { NftTableModel } from './parsers.js';

/**
 * Kernel-side operations for the guard: every nft/iptables/ip/sysctl call goes
 * through the injected bounded CommandRunner as an argv array (never a shell
 * string). Mutations are atomic per subsystem — one `nft -c -f` + one
 * `nft -f` file for the whole table, one `iptables-restore --test` + one
 * `iptables-restore --noflush` per table — matching the verified pilot and
 * CH's own transactional firewall pattern.
 */

export const GUARD_COMMAND_BOUNDS = { timeoutMs: 15_000, maxOutputBytes: 4_194_304 } as const;

let tempCounter = 0;

async function withTempFile<T>(dir: string, prefix: string, content: string, fn: (path: string) => Promise<T>): Promise<T> {
  await mkdir(dir, { recursive: true });
  const path = join(dir, `${prefix}-${process.pid}-${Date.now()}-${tempCounter++}.tmp`);
  await writeFile(path, content, { mode: 0o600 });
  try {
    return await fn(path);
  } finally {
    await rm(path, { force: true }).catch(() => undefined);
  }
}

async function runChecked(
  exec: VmGuardCommandRunner,
  argv: readonly string[],
  what: string
): Promise<{ exitCode: number; stdout: string; stderr: string }> {
  const result = await exec(argv, GUARD_COMMAND_BOUNDS);
  if (result.timedOut) {
    throw new VmNetworkGuardError('command-timeout', `${what} timed out: ${argv.join(' ')}`);
  }
  if (result.truncated) {
    throw new VmNetworkGuardError('command-output-truncated', `${what} output exceeded bound: ${argv.join(' ')}`);
  }
  if (result.exitCode !== 0) {
    throw new VmNetworkGuardError('command-failed', `${what} failed (exit ${result.exitCode}): ${argv.join(' ')}: ${(result.stderr || result.stdout).slice(0, 400)}`);
  }
  return result;
}

// ---------------------------------------------------------------------------
// nft table
// ---------------------------------------------------------------------------

export interface NftTableRead {
  present: boolean;
  text: string;
}

/** Read the guard table text; `present:false` only when the table is absent. */
export async function readNftTable(exec: VmGuardCommandRunner): Promise<NftTableRead> {
  const tables = await runChecked(exec, ['nft', 'list', 'tables'], 'nft list tables');
  const present = tables.stdout.split('\n').some((l) => l.trim() === `table inet ${VM_GUARD_TABLE}`);
  if (!present) return { present: false, text: '' };
  const listed = await runChecked(exec, ['nft', 'list', 'table', 'inet', VM_GUARD_TABLE], 'nft list table');
  return { present: true, text: listed.stdout };
}

/**
 * Explicit prerequisite probe for `destroy table`: nftables >= 1.0.7 AND
 * kernel >= 6.3 (the kernel nf_tables `destroy` command landed in 6.3).
 * Bounded: two short read-only exec calls. Callers MUST treat `ok:false`
 * as blocking — an unsupported host can never safely apply the guard.
 */
export async function nftDestroySupport(exec: VmGuardCommandRunner): Promise<{ ok: boolean; detail: string }> {
  const ver = await runChecked(exec, ['nft', '--version'], 'nft --version');
  const nftMatch = /nftables v(\d+)\.(\d+)\.(\d+)/.exec(ver.stdout);
  const un = await runChecked(exec, ['uname', '-r'], 'uname -r');
  const kernelMatch = /^(\d+)\.(\d+)/.exec(un.stdout.trim());
  if (nftMatch === null || kernelMatch === null) {
    return { ok: false, detail: `unparseable versions: nft='${ver.stdout.trim().slice(0, 80)}' kernel='${un.stdout.trim().slice(0, 80)}'` };
  }
  const [nMaj, nMin, nPat] = [Number(nftMatch[1]), Number(nftMatch[2]), Number(nftMatch[3])];
  const [kMaj, kMin] = [Number(kernelMatch[1]), Number(kernelMatch[2])];
  const nftOk = nMaj > 1 || (nMaj === 1 && (nMin > 0 || (nMin === 0 && nPat >= 7)));
  const kernelOk = kMaj > 6 || (kMaj === 6 && kMin >= 3);
  if (!nftOk || !kernelOk) {
    return { ok: false, detail: `nft ${nMaj}.${nMin}.${nPat} / kernel ${kMaj}.${kMin} below destroy floor (nftables>=1.0.7, kernel>=6.3)` };
  }
  return { ok: true, detail: `nftables ${nMaj}.${nMin}.${nPat}, kernel ${kMaj}.${kMin}` };
}

/**
 * Atomically replace the whole guard table with the canonical ruleset: a
 * single `nft -c -f` syntax check followed by a single `nft -f` file — the
 * destroy+rules commit has no fail-open window (verified nft atomicity).
 *
 * Idempotency requires `destroy`, NOT `delete`: `delete table` fails when the
 * table is absent and a bare `table { ... }` block fails `File exists` on
 * re-apply over live chains/sets. `destroy table` (nftables >= 1.0.7,
 * kernel >= 6.3) removes the table when present and is a no-op when absent,
 * so `destroy` + the canonical block in ONE file is the only correct
 * replace-or-create primitive — re-apply, rebuild and last-claim teardown
 * all converge. The version floor is probed explicitly BEFORE any payload
 * is written: an unsupported host fails with 'nft-destroy-unsupported'
 * instead of a late `command-failed` at `nft -c`.
 */
export async function applyNftTable(exec: VmGuardCommandRunner, workDir: string, canonicalText: string): Promise<void> {
  const support = await nftDestroySupport(exec);
  if (!support.ok) {
    throw new VmNetworkGuardError('nft-destroy-unsupported', `refusing nft apply: ${support.detail}`);
  }
  const payload = `destroy table inet ${VM_GUARD_TABLE}\n${canonicalText}`;
  await withTempFile(workDir, 'chm-nft', payload, async (path) => {
    await runChecked(exec, ['nft', '-c', '-f', path], 'nft check');
    await runChecked(exec, ['nft', '-f', path], 'nft apply');
  });
}

export interface NftVerifyResult {
  ok: boolean;
  diffs: string[];
  digest: string;
  model: NftTableModel | null;
}

/**
 * Verify live kernel nft state equals the canonical ruleset for `subjects`
 * (counter-free compare). `present:false` on a non-empty expectation is
 * drift, never success.
 */
export async function verifyNftTable(
  exec: VmGuardCommandRunner,
  subjects: readonly VmNetworkSubject[],
  config: ValidatedGuardConfig,
  uplink: string
): Promise<NftVerifyResult> {
  const canonicalText = canonicalNftTable(subjects, config, uplink);
  const digest = rulesetDigest(canonicalText);
  const expectedModel = parseNftTableText(canonicalText);
  const read = await readNftTable(exec);
  if (!read.present) {
    return { ok: subjects.length === 0, diffs: subjects.length === 0 ? [] : ['guard table missing'], digest, model: null };
  }
  const actualModel = parseNftTableText(read.text);
  const diffs = diffNftTables(expectedModel, actualModel);
  return { ok: diffs.length === 0, diffs, digest, model: actualModel };
}

// ---------------------------------------------------------------------------
// iptables-nft permits (DOCKER-USER filter + POSTROUTING nat)
// ---------------------------------------------------------------------------

export async function readIpChain(exec: VmGuardCommandRunner, table: 'filter' | 'nat', chain: string): Promise<string> {
  const argv = table === 'nat'
    ? ['iptables', '-w', '10', '-t', 'nat', '-S', chain]
    : ['iptables', '-w', '10', '-S', chain];
  const result = await runChecked(exec, argv, `iptables -S ${chain}`);
  return result.stdout;
}

/** CH first-jump gate: the three invariants the pilot asserted before/after mutation. */
export async function chGateCheck(exec: VmGuardCommandRunner): Promise<{ ok: boolean; reason?: string }> {
  const [input, forward, dockerUser] = await Promise.all([
    readIpChain(exec, 'filter', 'INPUT'),
    readIpChain(exec, 'filter', 'FORWARD'),
    readIpChain(exec, 'filter', 'DOCKER-USER')
  ]);
  if (firstChainRule(input) !== CH_INPUT_FIRST_RULE) {
    return { ok: false, reason: `CH INPUT first rule changed: ${firstChainRule(input) ?? '(none)'}` };
  }
  if (firstChainRule(forward) !== CH_FORWARD_FIRST_RULE) {
    return { ok: false, reason: `CH FORWARD first rule changed: ${firstChainRule(forward) ?? '(none)'}` };
  }
  if (firstChainRule(dockerUser) !== CH_DOCKER_USER_FIRST_RULE) {
    return { ok: false, reason: `CH DOCKER-USER first rule changed: ${firstChainRule(dockerUser) ?? '(none)'}` };
  }
  return { ok: true };
}

/**
 * Apply one iptables-restore transaction per table: `--test` syntax check,
 * then `--noflush` commit. Lines are iptables-restore directives
 * (`-D`/`-I`/`-A`/`-F` scoped to our specs only — never a flush).
 */
export async function applyIpTablesRestore(
  exec: VmGuardCommandRunner,
  workDir: string,
  table: 'filter' | 'nat',
  lines: readonly string[]
): Promise<void> {
  if (lines.length === 0) return;
  const payload = `*${table}\n${lines.join('\n')}\nCOMMIT\n`;
  await withTempFile(workDir, `chm-iptables-${table}`, payload, async (path) => {
    await runChecked(exec, ['iptables-restore', '-w', '10', '--test', path], `iptables-restore --test ${table}`);
    await runChecked(exec, ['iptables-restore', '-w', '10', '--noflush', path], `iptables-restore ${table}`);
  });
}

export interface PermitDrift {
  missing: string[];
  /** Our tagged rules found before the CH first-jump (must be repaired). */
  misplaced: string[];
  /** Our tagged rules absent from desired set (stale — strip, fail-closed). */
  stale: string[];
}

interface LiveTaggedRule {
  line: string;
  index: number;
  key: string;
}

/**
 * Semantic drift for one chain: desired `-A` lines vs live tagged `-A` lines,
 * compared by canonicalIpRuleKey (iptables -S print order is NOT the order
 * rules were supplied in). `markerIndex` is the position of the CH
 * first-jump; desired-kind rules before it are `misplaced`, never `missing`.
 * Duplicate live copies beyond the desired multiplicity are `stale`.
 */
function computeChainPermitDrift(
  liveLines: readonly string[],
  desiredLines: readonly string[],
  markerIndex: number
): { missing: string[]; misplaced: string[]; stale: string[] } {
  const desiredByKey = new Map<string, string[]>();
  for (const line of desiredLines) {
    const key = ipRuleLineKey(line) ?? `unparsed:${line}`;
    const list = desiredByKey.get(key) ?? [];
    list.push(line);
    desiredByKey.set(key, list);
  }
  const liveTagged: LiveTaggedRule[] = [];
  liveLines.forEach((line, index) => {
    if (!isGuardTaggedRule(line)) return;
    liveTagged.push({ line, index, key: ipRuleLineKey(line) ?? `unparsed:${line}` });
  });
  const liveByKey = new Map<string, LiveTaggedRule[]>();
  for (const entry of liveTagged) {
    const list = liveByKey.get(entry.key) ?? [];
    list.push(entry);
    liveByKey.set(entry.key, list);
  }
  for (const list of liveByKey.values()) list.sort((a, b) => a.index - b.index);

  const missing: string[] = [];
  const misplaced: string[] = [];
  const stale: string[] = [];
  for (const [key, desired] of desiredByKey) {
    const live = liveByKey.get(key) ?? [];
    const matched = live.slice(0, desired.length);
    for (const extra of live.slice(desired.length)) stale.push(extra.line);
    for (let j = live.length; j < desired.length; j++) missing.push(desired[j]!);
    for (const entry of matched) {
      if (markerIndex !== -1 && entry.index < markerIndex) misplaced.push(entry.line);
    }
  }
  for (const [key, entries] of liveByKey) {
    if (!desiredByKey.has(key)) for (const entry of entries) stale.push(entry.line);
  }
  return { missing, misplaced, stale };
}

/**
 * Compare live DOCKER-USER/POSTROUTING against the desired permit specs for
 * `subjects` — semantically, never by literal `-A` text (see
 * canonicalIpRuleKey). Only rules carrying VM_GUARD_TAG count as ours;
 * foreign rules are never drift.
 */
export async function verifyPermits(
  exec: VmGuardCommandRunner,
  subjects: readonly VmNetworkSubject[],
  config: ValidatedGuardConfig,
  uplink: string
): Promise<{ ok: boolean; drift: PermitDrift; desired: { dockerUser: string[]; postrouting: string[] } }> {
  const desiredDockerUser: string[] = [];
  const desiredPostrouting: string[] = [];
  for (const subject of subjects) {
    const specs = permitSpecsFor(subject, config, uplink);
    desiredDockerUser.push(`-A DOCKER-USER ${specs.egress}`, `-A DOCKER-USER ${specs.ret}`);
    desiredPostrouting.push(`-A POSTROUTING ${specs.nat}`);
  }

  const [dockerUserText, postroutingText] = await Promise.all([
    readIpChain(exec, 'filter', 'DOCKER-USER'),
    readIpChain(exec, 'nat', 'POSTROUTING')
  ]);
  const dockerUserRules = parseIpTablesChain(dockerUserText);
  const postroutingRules = parseIpTablesChain(postroutingText);
  const markerIndex = dockerUserRules.indexOf(CH_DOCKER_USER_FIRST_RULE);

  const filterDrift = computeChainPermitDrift(dockerUserRules, desiredDockerUser, markerIndex);
  const natDrift = computeChainPermitDrift(postroutingRules, desiredPostrouting, -1);
  const drift: PermitDrift = {
    missing: [...filterDrift.missing, ...natDrift.missing],
    misplaced: filterDrift.misplaced,
    stale: [...filterDrift.stale, ...natDrift.stale]
  };
  return {
    ok: drift.missing.length === 0 && drift.misplaced.length === 0 && drift.stale.length === 0,
    drift,
    desired: { dockerUser: desiredDockerUser, postrouting: desiredPostrouting }
  };
}

/**
 * True for any iptables -A line carrying our ownership tag — decided
 * semantically (a `comment` match whose `--comment` value is EXACTLY the
 * tag), with an exact-token fallback for lines the parser cannot model.
 */
export function isGuardTaggedRule(line: string): boolean {
  const model = parseIpTablesRuleLine(line);
  if (model !== null) {
    return model.matches.some(
      (m) =>
        m.module === 'comment' &&
        m.args.some((arg, idx) => arg === '--comment' && m.args[idx + 1] === VM_GUARD_TAG)
    );
  }
  return new RegExp(`--comment\\s+(?:"${VM_GUARD_TAG}"|${VM_GUARD_TAG})(?=\\s|$)`).test(line);
}

/**
 * Remove EVERY tagged permit rule (desired, stale, misplaced — all of them).
 * This is the fail-safe direction used when the nft guard cannot be verified:
 * permits without the verified drop-layer must not survive. Returns the
 * number of rules deleted.
 */
export async function stripAllTaggedPermits(exec: VmGuardCommandRunner, workDir: string): Promise<number> {
  const [dockerUserText, postroutingText] = await Promise.all([
    readIpChain(exec, 'filter', 'DOCKER-USER'),
    readIpChain(exec, 'nat', 'POSTROUTING')
  ]);
  const filterLines = parseIpTablesChain(dockerUserText)
    .filter(isGuardTaggedRule)
    .map((l) => `-D DOCKER-USER ${l.slice('-A DOCKER-USER '.length)}`);
  const natLines = parseIpTablesChain(postroutingText)
    .filter(isGuardTaggedRule)
    .map((l) => `-D POSTROUTING ${l.slice('-A POSTROUTING '.length)}`);
  await applyIpTablesRestore(exec, workDir, 'filter', filterLines);
  await applyIpTablesRestore(exec, workDir, 'nat', natLines);
  return filterLines.length + natLines.length;
}

// ---------------------------------------------------------------------------
// ip link / address / route / sysctl
// ---------------------------------------------------------------------------

interface IpLinkLike {
  ifname?: string;
  operstate?: string;
  linkinfo?: { info_kind?: string };
  flags?: string[];
}

export async function listLinks(exec: VmGuardCommandRunner): Promise<IpLinkLike[]> {
  const result = await runChecked(exec, ['ip', '-j', 'link', 'show'], 'ip -j link show');
  return parseIpJson(result.stdout) as IpLinkLike[];
}

export async function linkExists(exec: VmGuardCommandRunner, name: string): Promise<boolean> {
  const links = await listLinks(exec);
  return links.some((l) => l.ifname === name);
}

export async function isBridgeUp(exec: VmGuardCommandRunner, name: string): Promise<{ exists: boolean; isBridge: boolean; up: boolean }> {
  const links = await listLinks(exec);
  const link = links.find((l) => l.ifname === name);
  if (!link) return { exists: false, isBridge: false, up: false };
  return {
    exists: true,
    isBridge: link.linkinfo?.info_kind === 'bridge',
    up: link.operstate === 'UP' || (link.flags ?? []).includes('UP')
  };
}

interface IpAddrInfo {
  family?: string;
  local?: string;
  prefixlen?: number;
}

export async function linkAddresses(exec: VmGuardCommandRunner, name: string, family: 4 | 6): Promise<IpAddrInfo[]> {
  const result = await runChecked(exec, ['ip', '-j', `-${family}`, 'addr', 'show', 'dev', name], `ip -j -${family} addr show ${name}`);
  const parsed = parseIpJson(result.stdout) as { addr_info?: IpAddrInfo[] }[];
  return parsed.flatMap((entry) => entry.addr_info ?? []);
}

export async function resolveUplink(exec: VmGuardCommandRunner, configured: string): Promise<string> {
  if (configured !== '') {
    if (!(await linkExists(exec, configured))) {
      throw new VmNetworkGuardError('uplink-missing', `configured uplink '${configured}' does not exist`);
    }
    return configured;
  }
  const result = await runChecked(exec, ['ip', '-j', '-4', 'route', 'show', 'table', 'all'], 'ip -j -4 route show table all');
  const dev = singleDefaultRouteDev(parseIpJson(result.stdout));
  if (!dev) {
    throw new VmNetworkGuardError('uplink-ambiguous', 'cannot resolve uplink: expected exactly one IPv4 default route in main table');
  }
  return dev;
}

export async function setBridgeIpv6(exec: VmGuardCommandRunner, bridge: string, disable: boolean): Promise<void> {
  const key = `net.ipv6.conf.${bridge}.disable_ipv6`;
  if (disable) {
    await runChecked(exec, ['sysctl', '-w', `${key}=1`], `sysctl -w ${key}`);
  } else {
    await runChecked(exec, ['sysctl', '-w', `${key}=0`], `sysctl -w ${key}`);
  }
}

export async function bridgeIpv6Disabled(exec: VmGuardCommandRunner, bridge: string): Promise<boolean> {
  const result = await runChecked(exec, ['sysctl', '-n', `net.ipv6.conf.${bridge}.disable_ipv6`], 'sysctl -n disable_ipv6');
  return result.stdout.trim() === '1';
}

export async function ipForwardingEnabled(exec: VmGuardCommandRunner): Promise<boolean> {
  const result = await runChecked(exec, ['sysctl', '-n', 'net.ipv4.ip_forward'], 'sysctl -n ip_forward');
  return result.stdout.trim() === '1';
}

// ---------------------------------------------------------------------------
// Bridge lifecycle (link stays DOWN until the caller verifies the guard)
// ---------------------------------------------------------------------------

export async function ensureBridge(exec: VmGuardCommandRunner, subject: VmNetworkSubject): Promise<'created' | 'existing'> {
  const state = await isBridgeUp(exec, subject.bridgeName);
  if (state.exists) {
    if (!state.isBridge) {
      throw new VmNetworkGuardError('bridge-conflict', `'${subject.bridgeName}' exists but is not a bridge`);
    }
    return 'existing';
  }
  await runChecked(exec, ['ip', 'link', 'add', subject.bridgeName, 'type', 'bridge'], `ip link add ${subject.bridgeName}`);
  return 'created';
}

export async function ensureHostAddress(exec: VmGuardCommandRunner, subject: VmNetworkSubject): Promise<void> {
  const want = `${subject.hostIp}/${subject.prefixLength}`;
  const addrs = await linkAddresses(exec, subject.bridgeName, 4);
  const present = addrs.some((a) => a.family === 'inet' && a.local === subject.hostIp && a.prefixlen === subject.prefixLength);
  if (present) return;
  const foreign = addrs.filter((a) => a.family === 'inet');
  if (foreign.length > 0) {
    throw new VmNetworkGuardError('bridge-address-conflict', `bridge '${subject.bridgeName}' has unexpected IPv4 address(es): ${foreign.map((a) => `${a.local}/${a.prefixlen}`).join(',')}`);
  }
  await runChecked(exec, ['ip', 'address', 'add', want, 'dev', subject.bridgeName], `ip address add ${want}`);
}

export async function setBridgeUp(exec: VmGuardCommandRunner, bridge: string, up: boolean): Promise<void> {
  await runChecked(exec, ['ip', 'link', 'set', bridge, up ? 'up' : 'down'], `ip link set ${bridge} ${up ? 'up' : 'down'}`);
}

export async function deleteBridge(exec: VmGuardCommandRunner, bridge: string): Promise<void> {
  const state = await isBridgeUp(exec, bridge);
  if (!state.exists) return;
  await runChecked(exec, ['ip', 'link', 'del', bridge], `ip link del ${bridge}`);
}

// ---------------------------------------------------------------------------
// Permit reconciliation (fail-closed direction only)
// ---------------------------------------------------------------------------

export interface PermitPlan {
  filterLines: string[];
  natLines: string[];
}

/**
 * Plan the iptables-restore lines that move live permits to the desired set:
 * stale/misplaced tagged rules are deleted by exact spec, missing desired
 * specs are inserted right after the CH DOCKER-USER first-jump (position 2).
 * Only VM_GUARD_TAG-tagged rules are ever touched — the inputs are already
 * filtered to ours by verifyPermits.
 */
export function planPermitRestore(drift: PermitDrift): PermitPlan {
  const filterLines: string[] = [];
  const natLines: string[] = [];
  // Stale rules are deleted outright. Misplaced rules ARE desired specs in the
  // wrong position — delete AND re-insert after the CH first-jump.
  for (const line of drift.stale) {
    if (line.startsWith('-A DOCKER-USER ')) {
      filterLines.push(`-D DOCKER-USER ${line.slice('-A DOCKER-USER '.length)}`);
    } else if (line.startsWith('-A POSTROUTING ')) {
      natLines.push(`-D POSTROUTING ${line.slice('-A POSTROUTING '.length)}`);
    }
  }
  for (const line of drift.misplaced) {
    if (!line.startsWith('-A DOCKER-USER ')) continue;
    const spec = line.slice('-A DOCKER-USER '.length);
    filterLines.push(`-D DOCKER-USER ${spec}`, `-I DOCKER-USER 2 ${spec}`);
  }
  for (const line of drift.missing) {
    if (line.startsWith('-A DOCKER-USER ')) {
      filterLines.push(`-I DOCKER-USER 2 ${line.slice('-A DOCKER-USER '.length)}`);
    } else if (line.startsWith('-A POSTROUTING ')) {
      natLines.push(`-A POSTROUTING ${line.slice('-A POSTROUTING '.length)}`);
    }
  }
  return { filterLines, natLines };
}

// ---------------------------------------------------------------------------
// Convenience: full kernel verify bundle used by ops + guard service
// ---------------------------------------------------------------------------

export interface KernelVerifyInput {
  exec: VmGuardCommandRunner;
  workDir: string;
  subjects: readonly VmNetworkSubject[];
  config: ValidatedGuardConfig;
  uplink: string;
}

export interface KernelVerifyResult {
  nft: NftVerifyResult;
  permits: { ok: boolean; drift: PermitDrift };
  chGate: { ok: boolean; reason?: string };
  bridges: { name: string; ok: boolean; reason?: string }[];
  uplinkOk: boolean;
  forwarding: boolean;
}

/** Read-only kernel verification bundle — never mutates. */
export async function verifyKernelState(input: KernelVerifyInput): Promise<KernelVerifyResult> {
  const { exec, subjects, config, uplink } = input;
  const [nft, permits, chGate, forwarding] = await Promise.all([
    verifyNftTable(exec, subjects, config, uplink),
    verifyPermits(exec, subjects, config, uplink),
    chGateCheck(exec),
    ipForwardingEnabled(exec)
  ]);
  const bridges: KernelVerifyResult['bridges'] = [];
  for (const subject of subjects) {
    const state = await isBridgeUp(exec, subject.bridgeName);
    if (!state.exists || !state.isBridge) {
      bridges.push({ name: subject.bridgeName, ok: false, reason: 'missing or not a bridge' });
      continue;
    }
    const ipv6Off = await bridgeIpv6Disabled(exec, subject.bridgeName);
    const addrs = await linkAddresses(exec, subject.bridgeName, 4);
    const hasHost = addrs.some((a) => a.family === 'inet' && a.local === subject.hostIp && a.prefixlen === subject.prefixLength);
    const inet6 = await linkAddresses(exec, subject.bridgeName, 6);
    const hasInet6 = inet6.some((a) => a.family === 'inet6');
    if (!ipv6Off || !hasHost || hasInet6) {
      bridges.push({
        name: subject.bridgeName,
        ok: false,
        reason: `ipv6Disabled=${ipv6Off} hostAddr=${hasHost} inet6Present=${hasInet6}`
      });
    } else {
      bridges.push({ name: subject.bridgeName, ok: true });
    }
  }
  return { nft, permits, chGate, bridges, uplinkOk: uplink !== '', forwarding };
}
