import { VmNetworkGuardError } from '../network-ops.js';

/**
 * Pure parsers for kernel/Incus text the guard reads back: `nft list table`
 * output, `iptables -S <chain>` output and `ip -j` JSON. Everything returns
 * normalized models so canonical comparison ignores counters, quoting and
 * formatting — the same "ruleset minus counters" semantics the verified
 * pilot used (`policy_text()`).
 */

export interface NftSetModel {
  name: string;
  keyType?: string;
  flags: string[];
  elements: string[];
}

export interface NftChainModel {
  name: string;
  type?: string;
  hook?: string;
  priority?: number;
  policy?: string;
  /** Normalized rule statements in kernel order (counter-free). */
  rules: string[];
}

export interface NftTableModel {
  family: string;
  name: string;
  sets: NftSetModel[];
  chains: NftChainModel[];
}

function unquote(text: string): string {
  return text.replace(/"([^"]*)"/g, '$1');
}

/** Normalize one nft rule statement: drop counters, unquote, sort set literals. */
export function normalizeNftStatement(raw: string): string {
  let text = raw.trim().replace(/\s+/g, ' ');
  // `counter` and `counter packets N bytes N` are observability, not policy.
  text = text.replace(/\bcounter\b( packets \d+ bytes \d+)?/g, ' ');
  text = unquote(text);
  // `ct state { a, b }` and `ct state a,b` are the same unordered state set.
  text = text.replace(/\bct state\s*\{([^}]*)\}/g, (_m, inner: string) =>
    `ct state ${inner.split(',').map((s) => s.trim()).filter(Boolean).join(',')}`
  );
  // Sort anonymous set literals `{ a, b }` — membership is unordered.
  text = text.replace(/\{([^{}]*)\}/g, (_m, inner: string) => {
    const items = inner.split(',').map((s) => s.trim()).filter((s) => s.length > 0).sort();
    return `{ ${items.join(', ')} }`;
  });
  // `ct state a,b` lists are unordered state sets.
  text = text.replace(/\bct state ((?:[a-z_]+,?)+)/g, (_m, list: string) => {
    const states = list.split(',').map((s) => s.trim()).filter(Boolean).sort();
    return `ct state ${states.join(',')}`;
  });
  return text.replace(/\s+/g, ' ').trim();
}

function parseSetBlock(name: string, lines: string[]): NftSetModel {
  const set: NftSetModel = { name, flags: [], elements: [] };
  const body = lines.join(' ');
  const typeMatch = /\btype\s+([A-Za-z0-9_]+)/.exec(body);
  if (typeMatch?.[1]) set.keyType = typeMatch[1];
  const flagsMatch = /\bflags\s+([A-Za-z0-9_,\s]+?)(?=\belements\b|$)/.exec(body);
  if (flagsMatch?.[1]) set.flags = flagsMatch[1].trim().split(/[\s,]+/).filter(Boolean).sort();
  const elemMatch = /\belements\s*=\s*\{([\s\S]*?)\}/.exec(body);
  if (elemMatch) {
    set.elements = elemMatch[1]!
      .split(',')
      .map((s) => unquote(s.trim()))
      .filter((s) => s.length > 0)
      .sort();
  }
  return set;
}

/**
 * nftables symbolic base-chain priority names → netfilter hook values
 * (NF_IP_PRI_*). `nft list` NEVER prints a bare custom priority: it resolves
 * the stored integer to the closest named priority plus a signed offset,
 * e.g. priority -20 prints as `priority filter - 20` and -1 as
 * `priority filter - 1` (verified against real `nft list` output).
 */
const NFT_PRIORITY_NAMES: Readonly<Record<string, number>> = {
  raw: -300,
  mangle: -150,
  dstnat: -100,
  filter: 0,
  security: 50,
  srcnat: 100
};

/**
 * Resolve a `priority` clause to its integer value. Accepts every form nft
 * prints or accepts: `filter`, `filter - 20`, `filter + 20`, `-20`, `+5`.
 * Returns undefined for anything unrecognized — the chain header then diffs
 * as "priority missing", which fails closed.
 */
export function parseNftPriority(spec: string): number | undefined {
  const named = /^([A-Za-z]+)\s*(?:([+-])\s*(\d+))?$/.exec(spec);
  if (named) {
    const base = NFT_PRIORITY_NAMES[named[1]!];
    if (base === undefined) return undefined;
    if (named[3] === undefined) return base;
    const offset = Number(named[3]);
    return named[2] === '-' ? base - offset : base + offset;
  }
  const numeric = /^([+-]?\d+)$/.exec(spec);
  return numeric ? Number(numeric[1]) : undefined;
}

function parseChainHeader(line: string): Pick<NftChainModel, 'type' | 'hook' | 'priority' | 'policy'> {
  const out: Pick<NftChainModel, 'type' | 'hook' | 'priority' | 'policy'> = {};
  const typeMatch = /\btype\s+([A-Za-z0-9_]+)/.exec(line);
  if (typeMatch?.[1]) out.type = typeMatch[1];
  const hookMatch = /\bhook\s+([A-Za-z0-9_]+)/.exec(line);
  if (hookMatch?.[1]) out.hook = hookMatch[1];
  const prioMatch = /\bpriority\s+([^;]+)/.exec(line);
  if (prioMatch?.[1] !== undefined) {
    const priority = parseNftPriority(prioMatch[1].trim());
    if (priority !== undefined) out.priority = priority;
  }
  const policyMatch = /\bpolicy\s+([A-Za-z]+)/.exec(line);
  if (policyMatch?.[1]) out.policy = policyMatch[1];
  return out;
}

/**
 * Parse `nft list table <family> <name>` text (or compiler output in the same
 * format). An empty/absent table yields the empty model. Malformed input
 * throws — the caller fails closed rather than attesting garbage.
 */
export function parseNftTableText(text: string): NftTableModel {
  const lines = text.split('\n');
  const tableStart = lines.findIndex((l) => /^table\s+\S+\s+\S+\s*\{/.test(l.trim()));
  if (tableStart === -1) {
    if (text.trim().length === 0) return { family: '', name: '', sets: [], chains: [] };
    throw new VmNetworkGuardError('nft-parse', 'nft output does not contain a table block');
  }
  const header = lines[tableStart]!.trim();
  const [, family, name] = /^table\s+(\S+)\s+(\S+)\s*\{/.exec(header)!;
  const model: NftTableModel = { family: family!, name: name!, sets: [], chains: [] };

  // Walk the table body tracking brace depth; `set`/`chain` blocks are
  // collected verbatim then parsed.
  let i = tableStart + 1;
  let depth = 1;
  const body: string[] = [];
  for (; i < lines.length; i++) {
    const line = lines[i]!;
    for (const ch of line) {
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
    }
    body.push(line);
    if (depth === 0) break;
  }
  // Re-parse body blocks: join wrapped lines per top-level block.
  let block: string[] = [];
  let blockDepth = 0;
  const blocks: string[][] = [];
  for (const line of body) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    if (block.length === 0 && !/^(set|chain)\s/.test(trimmed)) {
      // stray content outside blocks — ignore (comments etc.)
      continue;
    }
    block.push(line);
    for (const ch of line) {
      if (ch === '{') blockDepth++;
      else if (ch === '}') blockDepth--;
    }
    if (blockDepth === 0 && block.length > 0) {
      blocks.push(block);
      block = [];
    }
  }
  if (block.length > 0) blocks.push(block);

  for (const blk of blocks) {
    const first = blk[0]!.trim();
    const setMatch = /^set\s+(\S+)\s*\{/.exec(first);
    const chainMatch = /^chain\s+(\S+)\s*\{/.exec(first);
    if (setMatch) {
      model.sets.push(parseSetBlock(setMatch[1]!, blk.slice(1)));
    } else if (chainMatch) {
      const chain: NftChainModel = { name: chainMatch[1]!, rules: [] };
      for (const raw of blk.slice(1)) {
        const trimmed = raw.trim();
        if (trimmed.length === 0) continue;
        if (/\btype\s+\S+\s+hook\b/.test(trimmed) || (/\btype\s+\S+\b/.test(trimmed) && /\bpolicy\b/.test(trimmed))) {
          Object.assign(chain, parseChainHeader(trimmed));
        } else if (!trimmed.startsWith('}')) {
          const stmt = normalizeNftStatement(trimmed);
          if (stmt.length > 0) chain.rules.push(stmt);
        }
      }
      model.chains.push(chain);
    }
  }
  return model;
}

/** Deterministic serialization of a parsed model — the canonical compare key. */
export function canonicalNftText(model: NftTableModel): string {
  const parts: string[] = [`table ${model.family} ${model.name}`];
  for (const set of [...model.sets].sort((a, b) => a.name.localeCompare(b.name))) {
    parts.push(`set ${set.name} type=${set.keyType ?? ''} flags=${[...set.flags].sort().join(',')} elements=${[...set.elements].sort().join(',')}`);
  }
  for (const chain of [...model.chains].sort((a, b) => a.name.localeCompare(b.name))) {
    const head = [chain.type, chain.hook, chain.priority, chain.policy].filter((v) => v !== undefined).join('/');
    parts.push(`chain ${chain.name} ${head} rules=${chain.rules.join(' ;; ')}`);
  }
  return parts.join('\n');
}

/** Human-readable drift list between expected and actual table models. */
export function diffNftTables(expected: NftTableModel, actual: NftTableModel): string[] {
  const diffs: string[] = [];
  if (expected.family !== actual.family || expected.name !== actual.name) {
    diffs.push(`table identity differs: expected ${expected.family} ${expected.name}, found ${actual.family} ${actual.name}`);
    return diffs;
  }
  const expectedSets = new Map(expected.sets.map((s) => [s.name, s]));
  const actualSets = new Map(actual.sets.map((s) => [s.name, s]));
  for (const [name, set] of expectedSets) {
    const found = actualSets.get(name);
    if (!found) {
      diffs.push(`set ${name} missing`);
      continue;
    }
    const missing = set.elements.filter((e) => !found.elements.includes(e));
    const extra = found.elements.filter((e) => !set.elements.includes(e));
    if (missing.length > 0 || extra.length > 0 || set.keyType !== found.keyType) {
      diffs.push(`set ${name} elements differ (missing: ${missing.join(',') || '-'}; extra: ${extra.join(',') || '-'})`);
    }
  }
  for (const name of actualSets.keys()) {
    if (!expectedSets.has(name)) diffs.push(`unexpected set ${name} present`);
  }
  const expectedChains = new Map(expected.chains.map((c) => [c.name, c]));
  const actualChains = new Map(actual.chains.map((c) => [c.name, c]));
  for (const [name, chain] of expectedChains) {
    const found = actualChains.get(name);
    if (!found) {
      diffs.push(`chain ${name} missing`);
      continue;
    }
    const headDiff =
      chain.hook !== found.hook || chain.priority !== found.priority || chain.policy !== found.policy || chain.type !== found.type;
    if (headDiff) {
      diffs.push(`chain ${name} header differs: expected ${chain.type}/${chain.hook}/${chain.priority}/${chain.policy}, found ${found.type}/${found.hook}/${found.priority}/${found.policy}`);
    }
    // Rule ORDER is semantic (first-match evaluation): compare the sequence
    // positionally, never as a set — a pure reorder must surface as drift.
    const mismatches: string[] = [];
    const ruleCount = Math.max(chain.rules.length, found.rules.length);
    for (let i = 0; i < ruleCount && mismatches.length < 3; i++) {
      if (chain.rules[i] !== found.rules[i]) {
        mismatches.push(`@${i} want='${chain.rules[i] ?? '<none>'}' got='${found.rules[i] ?? '<none>'}'`);
      }
    }
    if (mismatches.length > 0) {
      diffs.push(`chain ${name} rule sequence differs (${chain.rules.length} expected vs ${found.rules.length} found): ${mismatches.join(' ; ')}`);
    }
  }
  for (const name of actualChains.keys()) {
    if (!expectedChains.has(name)) diffs.push(`unexpected chain ${name} present`);
  }
  return diffs;
}

// ---------------------------------------------------------------------------
// iptables -S <chain> parsing
// ---------------------------------------------------------------------------

/** Collapse whitespace in an iptables rule line for canonical compare. */
export function normalizeIpRule(line: string): string {
  return line.trim().replace(/\s+/g, ' ');
}

/** All `-A` rule lines of an `iptables -S <chain>` dump, normalized. */
export function parseIpTablesChain(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.startsWith('-A '))
    .map(normalizeIpRule);
}

/** First `-A` rule line of a chain dump (the CH first-jump check). */
export function firstChainRule(text: string): string | undefined {
  return parseIpTablesChain(text)[0];
}

/** Rule spec for `iptables -D <chain> <spec>` — the -S line minus `-A <chain>`. */
export function ipRuleSpec(fullLine: string, chain: string): string {
  const prefix = `-A ${chain} `;
  if (!fullLine.startsWith(prefix)) {
    throw new VmNetworkGuardError('iptables-parse', `rule '${fullLine}' is not in chain '${chain}'`);
  }
  return fullLine.slice(prefix.length);
}

// ---------------------------------------------------------------------------
// iptables rule SEMANTIC model
//
// `iptables -S` (iptables-nft backend) does NOT print options in the order
// they were supplied: addresses precede interfaces, `-p` follows interfaces,
// match modules keep creation order, and set-valued options such as
// `--ctstate` print in the kernel's own state order (e.g. RELATED,ESTABLISHED).
// Literal `-A` text comparison therefore cannot work — rules are compared
// through this parsed model instead. Negations (`!`) are preserved per field;
// only genuinely unordered value sets are canonicalized.
// ---------------------------------------------------------------------------

export interface IpRuleField {
  value: string;
  negated: boolean;
}

export interface IpRuleMatch {
  module: string;
  /** Match arguments in printed order; set-valued options are sorted. */
  args: string[];
}

export interface IpRuleModel {
  chain: string;
  protocol?: IpRuleField;
  source?: IpRuleField;
  dest?: IpRuleField;
  inInterface?: IpRuleField;
  outInterface?: IpRuleField;
  fragment: boolean;
  /** Match modules in printed order (kept for fidelity; compared as a set). */
  matches: IpRuleMatch[];
  jump?: string;
  goto?: string;
  /** Tokens not attributable to a known option — preserved for determinism. */
  misc: string[];
}

/** Match options whose comma-separated values form an unordered set. */
const IP_SET_VALUED_OPTIONS = new Set(['--ctstate', '--state']);

function unquoteToken(token: string): string {
  if (token.length >= 2 && token.startsWith('"') && token.endsWith('"')) return token.slice(1, -1);
  return token;
}

function tokenizeIpSpec(spec: string): string[] {
  return spec.match(/"[^"]*"|\S+/g) ?? [];
}

const IP_TOP_LEVEL_OPTIONS = new Set([
  '-p', '--protocol',
  '-s', '--source',
  '-d', '--destination',
  '-i', '--in-interface',
  '-o', '--out-interface',
  '-f', '--fragment',
  '-m', '--match',
  '-j', '--jump',
  '-g', '--goto'
]);

/**
 * Parse an iptables rule specification (the text after `-A <chain> `) into
 * the semantic model. Returns null only when the spec is empty — individual
 * unrecognized tokens are preserved in `misc` so comparison stays
 * deterministic and fail-closed.
 */
export function parseIpRuleSpec(chain: string, spec: string): IpRuleModel | null {
  const tokens = tokenizeIpSpec(spec);
  if (tokens.length === 0) return null;
  const model: IpRuleModel = { chain, fragment: false, matches: [], misc: [] };
  let i = 0;
  let negateNext = false;
  let currentMatch: IpRuleMatch | null = null;
  const field = (value: string, negated: boolean): IpRuleField => ({ value: unquoteToken(value), negated });
  const closeMatch = () => {
    currentMatch = null;
  };
  while (i < tokens.length) {
    let token = tokens[i++]!;
    if (token === '!') {
      negateNext = true;
      continue;
    }
    if (token.startsWith('!') && token.length > 1 && IP_TOP_LEVEL_OPTIONS.has(token.slice(1))) {
      negateNext = true;
      token = token.slice(1);
    }
    const negated = negateNext;
    negateNext = false;
    if (token === '-f' || token === '--fragment') {
      closeMatch();
      model.fragment = true;
      continue;
    }
    if (token === '-p' || token === '--protocol') {
      closeMatch();
      if (i < tokens.length) model.protocol = field(tokens[i++]!, negated);
      continue;
    }
    if (token === '-s' || token === '--source') {
      closeMatch();
      if (i < tokens.length) model.source = field(tokens[i++]!, negated);
      continue;
    }
    if (token === '-d' || token === '--destination') {
      closeMatch();
      if (i < tokens.length) model.dest = field(tokens[i++]!, negated);
      continue;
    }
    if (token === '-i' || token === '--in-interface') {
      closeMatch();
      if (i < tokens.length) model.inInterface = field(tokens[i++]!, negated);
      continue;
    }
    if (token === '-o' || token === '--out-interface') {
      closeMatch();
      if (i < tokens.length) model.outInterface = field(tokens[i++]!, negated);
      continue;
    }
    if (token === '-m' || token === '--match') {
      if (i < tokens.length) {
        currentMatch = { module: unquoteToken(tokens[i++]!), args: [] };
        model.matches.push(currentMatch);
      }
      continue;
    }
    if (token === '-j' || token === '--jump') {
      closeMatch();
      if (i < tokens.length) model.jump = unquoteToken(tokens[i++]!);
      continue;
    }
    if (token === '-g' || token === '--goto') {
      closeMatch();
      if (i < tokens.length) model.goto = unquoteToken(tokens[i++]!);
      continue;
    }
    if (IP_TOP_LEVEL_OPTIONS.has(token)) {
      // Known option missing its value — keep the token itself for
      // determinism rather than dropping it.
      closeMatch();
      model.misc.push(token);
      continue;
    }
    if (currentMatch !== null) {
      currentMatch.args.push(unquoteToken(token));
    } else {
      model.misc.push(token);
    }
  }
  // Normalize set-valued match options: `--ctstate RELATED,ESTABLISHED` and
  // `--ctstate ESTABLISHED,RELATED` are the same rule.
  for (const match of model.matches) {
    for (let j = 0; j < match.args.length - 1; j++) {
      if (IP_SET_VALUED_OPTIONS.has(match.args[j]!)) {
        match.args[j + 1] = match.args[j + 1]!.split(',').map((s) => s.trim()).filter(Boolean).sort().join(',');
      }
    }
  }
  return model;
}

/** Parse a full `-A <chain> <spec>` line from `iptables -S` output. */
export function parseIpTablesRuleLine(line: string): IpRuleModel | null {
  const m = /^-A\s+(\S+)\s+(.*)$/.exec(line.trim());
  if (!m) return null;
  return parseIpRuleSpec(m[1]!, m[2]!);
}

function fieldKey(name: string, f: IpRuleField | undefined): string | null {
  if (f === undefined) return null;
  return `${f.negated ? '! ' : ''}${name} ${f.value}`;
}

function matchKey(match: IpRuleMatch): string {
  return `-m ${match.module}${match.args.length > 0 ? ` ${match.args.join(' ')}` : ''}`;
}

/**
 * Deterministic semantic key for a parsed rule. Field order is fixed;
 * match modules compare as a multiset of normalized `-m module args` strings
 * — sound for the guard's permit specs because every module it emits
 * (conntrack ctstate set, comment string) is an order-insensitive predicate,
 * and any tagged rule outside the desired set is stale → stripped anyway.
 * Negations are part of the key, so `! -i x` never equals `-i x`.
 */
export function canonicalIpRuleKey(model: IpRuleModel): string {
  const parts: string[] = [];
  const proto = fieldKey('-p', model.protocol);
  if (proto !== null) parts.push(proto);
  const src = fieldKey('-s', model.source);
  if (src !== null) parts.push(src);
  const dst = fieldKey('-d', model.dest);
  if (dst !== null) parts.push(dst);
  const inIf = fieldKey('-i', model.inInterface);
  if (inIf !== null) parts.push(inIf);
  const outIf = fieldKey('-o', model.outInterface);
  if (outIf !== null) parts.push(outIf);
  if (model.fragment) parts.push('-f');
  parts.push(...model.matches.map(matchKey).sort());
  if (model.jump !== undefined) parts.push(`-j ${model.jump}`);
  if (model.goto !== undefined) parts.push(`-g ${model.goto}`);
  if (model.misc.length > 0) parts.push(...[...model.misc].sort());
  return parts.join(' ');
}

/** Semantic key for a bare rule spec (text after `-A <chain> `). */
export function ipRuleSpecKey(chain: string, spec: string): string | null {
  const model = parseIpRuleSpec(chain, spec);
  return model === null ? null : canonicalIpRuleKey(model);
}

/** Semantic key for a full `-A <chain> <spec>` line; null when unparsable. */
export function ipRuleLineKey(line: string): string | null {
  const model = parseIpTablesRuleLine(line);
  return model === null ? null : canonicalIpRuleKey(model);
}

export interface IpRulePositions {
  /** Expected lines found, with their index among -A rules. */
  found: { line: string; index: number }[];
  /** Expected lines absent from the chain. */
  missing: string[];
  /** True when the marker rule exists and every found rule sits after it. */
  afterMarker: boolean;
}

/**
 * Locate expected `-A` lines in a chain dump relative to a marker rule (the
 * CH first-jump). Permits are only valid positioned AFTER the marker — a
 * permit ahead of it would bypass the CH egress chain.
 */
export function rulePositions(text: string, expectedLines: readonly string[], markerLine: string): IpRulePositions {
  const rules = parseIpTablesChain(text);
  const markerIndex = rules.indexOf(normalizeIpRule(markerLine));
  const found: { line: string; index: number }[] = [];
  const missing: string[] = [];
  for (const expected of expectedLines) {
    const needle = normalizeIpRule(expected);
    const index = rules.indexOf(needle);
    if (index === -1) missing.push(expected);
    else found.push({ line: expected, index });
  }
  const afterMarker = markerIndex !== -1 && found.every((f) => f.index > markerIndex);
  return { found, missing, afterMarker };
}

// ---------------------------------------------------------------------------
// ip -j JSON helpers
// ---------------------------------------------------------------------------

export function parseIpJson(text: string): unknown[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new VmNetworkGuardError('ip-json-parse', 'ip -j output is not valid JSON');
  }
  if (!Array.isArray(parsed)) {
    throw new VmNetworkGuardError('ip-json-parse', 'ip -j output is not a JSON array');
  }
  return parsed;
}

interface IpRouteLike {
  dst?: string;
  table?: string;
  dev?: string;
}

/**
 * The single IPv4 default-route device, or null when absent/ambiguous.
 * Mirrors the pilot's "uplink unambiguous" check.
 */
export function singleDefaultRouteDev(routes: readonly unknown[]): string | null {
  const defaults = (routes as readonly IpRouteLike[]).filter(
    (r) => r && r.dst === 'default' && (r.table === undefined || r.table === 'main') && typeof r.dev === 'string' && r.dev.length > 0
  );
  if (defaults.length !== 1) return null;
  return defaults[0]!.dev!;
}
