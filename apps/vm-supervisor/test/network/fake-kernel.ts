import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { VmGuardCommandResult, VmGuardCommandRunner } from '../../src/network-ops.js';
import {
  diffNftTables,
  ipRuleSpecKey,
  parseIpRuleSpec,
  parseIpTablesChain,
  parseNftTableText
} from '../../src/network/parsers.js';
import type { IpRuleField } from '../../src/network/parsers.js';

/**
 * In-memory kernel simulator behind the bounded CommandRunner seam. It
 * understands exactly the argv shapes kernel.ts emits — nothing else — and
 * mutates fake nft/iptables/ip/sysctl state accordingly. No live commands
 * are ever executed; this is the ONLY command path tests may use.
 *
 * Fidelity notes (independent-review fix): the fake does NOT echo compiler
 * text back. `nft -f` payloads are interpreted and `nft list table`
 * re-renders in real canonical form — symbolic priorities
 * (`priority filter - 20`), materialized counters
 * (`counter packets 0 bytes 0`), brace-form ct state — and `destroy`/
 * `delete`/bare `table {}` obey real existence semantics (destroy is
 * idempotent, delete fails when absent, a bare table block fails
 * `File exists` over a live table). `iptables -S` re-renders rules in
 * canonical print order (addresses → interfaces → protocol → matches →
 * target, ctstate in kernel order) and `-D` matches semantically, exactly
 * like iptables' structural rule comparison.
 */

export interface FakeLink {
  ifname: string;
  operstate: 'UP' | 'DOWN' | 'LOWERLAYERDOWN';
  infoKind?: string;
  addrs: { family: 'inet' | 'inet6'; local: string; prefixlen: number }[];
}

export interface FakeKernel {
  exec: VmGuardCommandRunner;
  /** `nft list table` canonical text for chm_vm_guard ('' = absent). */
  nftTableText: string;
  /** Every payload passed to `nft -f` (for delete-vs-apply assertions). */
  nftAppliedPayloads: string[];
  /** iptables chain dumps keyed 'filter:CHAIN' / 'nat:CHAIN' (-S format). */
  ipTables: Map<string, string>;
  links: Map<string, FakeLink>;
  routes: { dst: string; table: string; dev: string }[];
  sysctls: Map<string, string>;
  /** Ordered argv log for ordering assertions. */
  calls: string[][];
  workDir: string;
  dispose(): Promise<void>;
}

const ok = (stdout = ''): VmGuardCommandResult => ({ exitCode: 0, stdout, stderr: '', timedOut: false, truncated: false });
const fail = (stderr: string, exitCode = 1): VmGuardCommandResult => ({ exitCode, stdout: '', stderr, timedOut: false, truncated: false });

// ---------------------------------------------------------------------------
// nft canonical list rendering
// ---------------------------------------------------------------------------

/** nftables symbolic base priorities (same table as parsers.ts). */
const NFT_BASE_PRIORITIES: ReadonlyArray<readonly [string, number]> = [
  ['raw', -300],
  ['mangle', -150],
  ['dstnat', -100],
  ['filter', 0],
  ['security', 50],
  ['srcnat', 100]
];

/** Render an integer priority the way `nft list` does: nearest named base + offset. */
function renderNftPriority(value: number): string {
  let name = 'filter';
  let base = 0;
  let bestDelta = Infinity;
  for (const [n, b] of NFT_BASE_PRIORITIES) {
    const delta = Math.abs(value - b);
    if (delta < bestDelta) {
      bestDelta = delta;
      name = n;
      base = b;
    }
  }
  const offset = value - base;
  if (offset === 0) return name;
  return `${name} ${offset < 0 ? '-' : '+'} ${Math.abs(offset)}`;
}

/** Transform one compiler-style statement into `nft list` canonical form. */
function renderNftStatement(line: string): string {
  return line
    .replace(/\bpriority\s+([+-]?\d+)\b/g, (_m, n: string) => `priority ${renderNftPriority(Number(n))}`)
    .replace(/\bcounter\b(?!\s+packets)/g, 'counter packets 0 bytes 0')
    .replace(/\bct state ((?:[a-z_]+,){1,}[a-z_]+)\b/g, (_m, list: string) => `ct state { ${list.split(',').join(', ')} }`);
}

/**
 * Interpret an `nft -f` payload: `destroy table`, `delete table` and bare
 * `table { ... }` blocks. Returns the rendered list text for a created
 * table, or an error string matching real nft failure modes.
 */
function nftApplyPayload(
  text: string,
  tables: Map<string, string>
): { ok: true } | { ok: false; error: string } {
  const lines = text.split('\n').map((l) => l.trim()).filter((l) => l.length > 0);
  let i = 0;
  while (i < lines.length) {
    const line = lines[i++]!;
    let m = /^(destroy|delete)\s+table\s+(\S+)\s+(\S+)$/.exec(line);
    if (m) {
      const key = `${m[2]} ${m[3]}`;
      if (m[1] === 'delete' && !tables.has(key)) {
        return { ok: false, error: 'Could not process rule: No such file or directory' };
      }
      tables.delete(key);
      continue;
    }
    m = /^table\s+(\S+)\s+(\S+)\s*\{/.exec(line);
    if (m) {
      const key = `${m[1]} ${m[2]}`;
      if (tables.has(key)) {
        return { ok: false, error: 'Could not process rule: File exists' };
      }
      const block: string[] = [line];
      let depth = (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
      while (i < lines.length && depth > 0) {
        const inner = lines[i++]!;
        block.push(inner);
        depth += (inner.match(/\{/g) ?? []).length - (inner.match(/\}/g) ?? []).length;
      }
      if (depth !== 0) return { ok: false, error: 'syntax error: unbalanced braces' };
      const rendered = [`table ${m[1]} ${m[2]} {`];
      for (const inner of block.slice(1, -1)) {
        const t = inner.trim();
        if (t.length === 0) continue;
        rendered.push(`\t${renderNftStatement(t)}`);
      }
      rendered.push('}');
      tables.set(key, `${rendered.join('\n')}\n`);
      continue;
    }
    return { ok: false, error: `syntax error near '${line}'` };
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// iptables canonical -S rendering + semantic -D
// ---------------------------------------------------------------------------

/** Kernel conntrack-state print order (differs from compiler/alpha order). */
const CTSTATE_KERNEL_ORDER = [
  'UNTRACKED', 'INVALID', 'NEW', 'RELATED', 'ESTABLISHED',
  'CLOSE', 'CLOSE_WAIT', 'LAST_ACK', 'FIN_WAIT',
  'SYN_RECV', 'SYN_SENT', 'TIME_WAIT'
];

function kernelOrderStates(value: string): string {
  const states = value.split(',').map((s) => s.trim()).filter(Boolean);
  if (states.length < 2) return value;
  const rank = (s: string) => {
    const idx = CTSTATE_KERNEL_ORDER.indexOf(s.toUpperCase());
    return idx === -1 ? CTSTATE_KERNEL_ORDER.length : idx;
  };
  return [...states].sort((a, b) => rank(a) - rank(b) || a.localeCompare(b)).join(',');
}

function fieldText(name: string, f: IpRuleField | undefined, parts: string[]): void {
  if (f !== undefined) parts.push(`${f.negated ? '! ' : ''}${name} ${f.value}`);
}

/**
 * Render a stored rule spec the way `iptables -S` prints it: addresses,
 * interfaces, protocol, matches (creation order, ctstate in kernel order),
 * target — never the order the spec was supplied in.
 */
function renderCanonicalIpSpec(chain: string, spec: string): string {
  const model = parseIpRuleSpec(chain, spec);
  if (model === null) return spec;
  const parts: string[] = [];
  fieldText('-s', model.source, parts);
  fieldText('-d', model.dest, parts);
  fieldText('-i', model.inInterface, parts);
  fieldText('-o', model.outInterface, parts);
  fieldText('-p', model.protocol, parts);
  parts.push(...model.misc);
  for (const match of model.matches) {
    const args = [...match.args];
    for (let j = 0; j < args.length - 1; j++) {
      if (args[j] === '--ctstate' || args[j] === '--state') args[j + 1] = kernelOrderStates(args[j + 1]!);
    }
    parts.push(`-m ${match.module}${args.length > 0 ? ` ${args.join(' ')}` : ''}`);
  }
  if (model.jump !== undefined) parts.push(`-j ${model.jump}`);
  if (model.goto !== undefined) parts.push(`-g ${model.goto}`);
  return parts.join(' ');
}

function chainDump(chain: string, rules: string[]): string {
  return [`-P ${chain} ACCEPT`, ...rules.map((r) => `-A ${chain} ${renderCanonicalIpSpec(chain, r)}`)].join('\n') + '\n';
}

function specsFromDump(dump: string): string[] {
  return parseIpTablesChain(dump).map((l) => l.replace(/^-A \S+ /, ''));
}

/** Parse an iptables-restore file body into per-table rule ops. */
function applyRestore(text: string, tables: Map<string, string[]>) {
  let table: string | null = null;
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (line === '') continue;
    if (line.startsWith('*')) {
      table = line.slice(1);
      if (!tables.has(table)) tables.set(table, []);
      continue;
    }
    if (line === 'COMMIT') {
      table = null;
      continue;
    }
    if (table === null) continue;
    tables.get(table)!.push(line);
  }
}

/** Drift between live `nft list` text and compiler-canonical text (tests). */
export function nftTableDiffs(actualText: string, canonicalText: string): string[] {
  return diffNftTables(parseNftTableText(canonicalText), parseNftTableText(actualText));
}

export async function createFakeKernel(seed?: {
  nftTableText?: string;
  ipTables?: Record<string, string>;
  links?: FakeLink[];
  routes?: { dst: string; table: string; dev: string }[];
  sysctls?: Record<string, string>;
  /** `nft --version` stdout override (default: supported 1.1.x). */
  nftVersion?: string;
  /** `uname -r` stdout override (default: supported 6.x+). */
  kernelRelease?: string;
}): Promise<FakeKernel> {
  const workDir = await mkdtemp(join(tmpdir(), 'chm-fake-kernel-'));
  const nftVersion = seed?.nftVersion ?? 'nftables v1.1.0 (Old Doc Yak #3)\n';
  const kernelRelease = seed?.kernelRelease ?? '7.2.15-arch1-1\n';
  const nftTables = new Map<string, string>();
  if (seed?.nftTableText) nftTables.set('inet chm_vm_guard', seed.nftTableText);
  const state = {
    ipTables: new Map<string, string>(Object.entries(seed?.ipTables ?? {})),
    links: new Map<string, FakeLink>((seed?.links ?? []).map((l) => [l.ifname, { ...l, addrs: [...l.addrs] }])),
    routes: [...(seed?.routes ?? [])],
    sysctls: new Map<string, string>(Object.entries(seed?.sysctls ?? {}))
  };
  const calls: string[][] = [];
  const nftAppliedPayloads: string[] = [];

  const ensureChains = () => {
    for (const chain of ['INPUT', 'FORWARD', 'DOCKER-USER']) {
      const key = `filter:${chain}`;
      if (!state.ipTables.has(key)) state.ipTables.set(key, chainDump(chain, []));
    }
    const natKey = 'nat:POSTROUTING';
    if (!state.ipTables.has(natKey)) state.ipTables.set(natKey, chainDump('POSTROUTING', []));
  };
  ensureChains();

  // Default CH first-jump fixtures unless caller overrode the chains.
  const dockerUser = state.ipTables.get('filter:DOCKER-USER')!;
  if (!dockerUser.includes('chm-egress0')) {
    state.ipTables.set('filter:DOCKER-USER', chainDump('DOCKER-USER', ['-i chm-egress0 -j CHM-EGRESS-v1']));
  }
  const forward = state.ipTables.get('filter:FORWARD')!;
  if (!forward.includes('DOCKER-USER')) {
    state.ipTables.set('filter:FORWARD', chainDump('FORWARD', ['-j DOCKER-USER']));
  }
  const input = state.ipTables.get('filter:INPUT')!;
  if (!input.includes('CHM-INPUT-v1')) {
    state.ipTables.set('filter:INPUT', chainDump('INPUT', ['-i chm-egress0 -j CHM-INPUT-v1']));
  }

  const exec: VmGuardCommandRunner = async (argv) => {
    const args = [...argv];
    calls.push(args);
    const cmd = args[0];

    if (cmd === 'nft') {
      if (args[1] === '--version') return ok(nftVersion);
      if (args[1] === 'list' && args[2] === 'tables') {
        const out = [...nftTables.keys()].map((key) => `table ${key}`).join('\n');
        return ok(out === '' ? '' : `${out}\n`);
      }
      if (args[1] === 'list' && args[2] === 'table') {
        const key = `${args[3]} ${args[4]}`;
        return ok(nftTables.get(key) ?? '');
      }
      if (args[1] === '-c' && args[2] === '-f') {
        // Syntax+semantic check against live state WITHOUT committing —
        // `nft -c` catches the same existence errors a real apply would.
        const text = await readFile(args[3]!, 'utf8');
        const probe = nftApplyPayload(text, new Map(nftTables));
        return probe.ok ? ok() : fail(probe.error);
      }
      if (args[1] === '-f') {
        const text = await readFile(args[2]!, 'utf8');
        nftAppliedPayloads.push(text);
        // Apply on a scratch copy first so a mid-payload failure leaves the
        // live table untouched, like a real atomic nft transaction.
        const scratch = new Map(nftTables);
        const result = nftApplyPayload(text, scratch);
        if (!result.ok) return fail(result.error);
        nftTables.clear();
        for (const [k, v] of scratch) nftTables.set(k, v);
        return ok();
      }
      return fail(`unsupported nft argv: ${args.join(' ')}`);
    }

    if (cmd === 'iptables-restore') {
      const path = args[args.length - 1]!;
      const text = await readFile(path, 'utf8');
      // --test parses only; --noflush commits. Both parse identically here.
      const ops = new Map<string, string[]>();
      applyRestore(text, ops);
      if (args.includes('--test')) return ok();
      for (const [tableName, lines] of ops) {
        for (const line of lines) {
          const m = /^-(A|I|D)\s+(\S+)\s+(.*)$/.exec(line);
          if (!m) continue;
          const [, verb, chain, spec] = m;
          const key = `${tableName}:${chain}`;
          if (!state.ipTables.has(key)) {
            state.ipTables.set(key, chainDump(chain!, []));
          }
          const rules = specsFromDump(state.ipTables.get(key)!);
          if (verb === 'A') {
            rules.push(spec!);
          } else if (verb === 'I') {
            const posMatch = /^(\d+)\s+(.*)$/.exec(spec!);
            if (posMatch) {
              // iptables -I CHAIN <n> is 1-based: insert before rule n.
              const pos = Math.max(0, Math.min(Number(posMatch[1]) - 1, rules.length));
              rules.splice(pos, 0, posMatch[2]!);
            } else {
              rules.unshift(spec!);
            }
          } else if (verb === 'D') {
            // iptables -D matches the rule STRUCTURALLY — semantic key
            // equality, never literal text (print order is canonicalized).
            const want = ipRuleSpecKey(chain!, spec!);
            const idx = want === null ? -1 : rules.findIndex((r) => ipRuleSpecKey(chain!, r) === want);
            if (idx !== -1) rules.splice(idx, 1);
          }
          state.ipTables.set(key, chainDump(chain!, rules));
        }
      }
      return ok();
    }

    if (cmd === 'iptables') {
      const tableIdx = args.indexOf('-t');
      const table = tableIdx !== -1 ? args[tableIdx + 1]! : 'filter';
      const chain = args[args.length - 1]!;
      const key = `${table}:${chain}`;
      if (args.includes('-S')) {
        const dump = state.ipTables.get(key);
        if (dump === undefined) return ok(chainDump(chain, []));
        // `iptables -S` prints canonical order, never insertion order.
        return ok(chainDump(chain, specsFromDump(dump)));
      }
      return fail(`unsupported iptables argv: ${args.join(' ')}`);
    }

    if (cmd === 'ip') {
      if (args[1] === '-j' && args[2] === 'link' && args[3] === 'show') {
        const out = [...state.links.values()].map((l) => ({
          ifname: l.ifname,
          operstate: l.operstate,
          flags: l.operstate === 'UP' ? ['UP'] : ['BROADCAST', 'MULTICAST'],
          ...(l.infoKind ? { linkinfo: { info_kind: l.infoKind } } : {})
        }));
        return ok(JSON.stringify(out));
      }
      if (args[1] === '-j' && args[2] === '-4' && args[3] === 'addr' && args[4] === 'show') {
        const devIdx = args.indexOf('dev');
        const dev = devIdx !== -1 ? args[devIdx + 1]! : '';
        const link = state.links.get(dev);
        const out = link ? [{ ifname: dev, addr_info: link.addrs.filter((a) => a.family === 'inet').map((a) => ({ family: 'inet', local: a.local, prefixlen: a.prefixlen })) }] : [];
        return ok(JSON.stringify(out));
      }
      if (args[1] === '-j' && args[2] === '-6' && args[3] === 'addr' && args[4] === 'show') {
        const devIdx = args.indexOf('dev');
        const dev = devIdx !== -1 ? args[devIdx + 1]! : '';
        const link = state.links.get(dev);
        const out = link ? [{ ifname: dev, addr_info: link.addrs.filter((a) => a.family === 'inet6').map((a) => ({ family: 'inet6', local: a.local, prefixlen: a.prefixlen })) }] : [];
        return ok(JSON.stringify(out));
      }
      if (args[1] === '-j' && args[2] === '-4' && args[3] === 'route') {
        return ok(JSON.stringify(state.routes));
      }
      if (args[1] === 'link' && args[2] === 'add') {
        const name = args[3]!;
        state.links.set(name, { ifname: name, operstate: 'DOWN', infoKind: 'bridge', addrs: [] });
        return ok();
      }
      if (args[1] === 'link' && args[2] === 'del') {
        state.links.delete(args[3]!);
        return ok();
      }
      if (args[1] === 'link' && args[2] === 'set') {
        const link = state.links.get(args[3]!);
        if (!link) return fail(`Cannot find device "${args[3]}"`);
        link.operstate = args[4] === 'up' ? 'UP' : 'DOWN';
        return ok();
      }
      if (args[1] === 'address' && args[2] === 'add') {
        const addr = args[3]!;
        const devIdx = args.indexOf('dev');
        const dev = devIdx !== -1 ? args[devIdx + 1]! : '';
        const link = state.links.get(dev);
        if (!link) return fail(`Cannot find device "${dev}"`);
        const [local, prefix] = addr.split('/');
        link.addrs.push({ family: 'inet', local: local!, prefixlen: Number(prefix) });
        return ok();
      }
      return fail(`unsupported ip argv: ${args.join(' ')}`);
    }

    if (cmd === 'uname') {
      if (args[1] === '-r') return ok(kernelRelease);
      return fail(`unsupported uname argv: ${args.join(' ')}`);
    }

    if (cmd === 'sysctl') {
      if (args[1] === '-n') {
        const key = args[2]!;
        const value = state.sysctls.get(key);
        return value === undefined ? fail(`sysctl: cannot stat /proc/sys/${key.replace(/\./g, '/')}`, 255) : ok(`${value}\n`);
      }
      if (args[1] === '-w') {
        const eq = args[2]!.indexOf('=');
        const key = args[2]!.slice(0, eq);
        const value = args[2]!.slice(eq + 1);
        state.sysctls.set(key, value);
        return ok(`${key} = ${value}\n`);
      }
      return fail(`unsupported sysctl argv: ${args.join(' ')}`);
    }

    return fail(`unsupported command: ${args.join(' ')}`);
  };

  return {
    exec,
    get nftTableText() {
      return nftTables.get('inet chm_vm_guard') ?? '';
    },
    set nftTableText(v: string) {
      nftTables.clear();
      if (v !== '') nftTables.set('inet chm_vm_guard', v);
    },
    nftAppliedPayloads,
    // Live map so tests can inject drift via .set(); `iptables -S` reads
    // canonicalize on the way out and restore ops canonicalize on write.
    get ipTables() {
      return state.ipTables;
    },
    get links() {
      return state.links;
    },
    get routes() {
      return state.routes;
    },
    get sysctls() {
      return state.sysctls;
    },
    calls,
    workDir,
    dispose: () => rm(workDir, { recursive: true, force: true })
  };
}
