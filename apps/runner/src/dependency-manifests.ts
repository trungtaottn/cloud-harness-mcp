import { HarnessError, type DependencyEcosystem } from '@cloud-harness/contracts';
import { parseDocument } from 'yaml';

const deny = (message: string): never => { throw new HarnessError('INVALID_INPUT', message, 400); };
const object = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return deny('Expected a manifest mapping');
  return value as Record<string, unknown>;
};
const npmName = /^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/i;
const version = /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?$/;
const integrity = /^(?:sha256|sha384|sha512)-[A-Za-z0-9+/]+={0,2}(?: (?:sha256|sha384|sha512)-[A-Za-z0-9+/]+={0,2})*$/;

function safeRegistryUrl(value: unknown): void {
  if (typeof value !== 'string') deny('Tarball URL must be a public npm registry HTTPS URL');
  let url: URL;
  try { url = new URL(value as string); } catch { return deny('Invalid tarball URL'); }
  if (url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.username || url.password || url.port || url.hash || url.search || /%2f|%5c|%2e/i.test(url.pathname)) deny('Only credential-free https://registry.npmjs.org tarballs are supported');
}

function validateGo(snapshots: Record<string, string>): string[] {
  const mod = snapshots['go.mod']!;
  const sum = snapshots['go.sum']!;
  const requirements: string[] = [];
  let block = false;
  let moduleFound = false;
  const modulePath = (text: string) => /^[A-Za-z0-9][A-Za-z0-9._~-]*(?:\/[A-Za-z0-9_~][A-Za-z0-9._~-]*)*$/.test(text) && !text.split('/').some((p) => p === '..' || p === '.');
  for (const raw of mod.split(/\r?\n/)) {
    const line = raw.replace(/\s*\/\/.*$/, '').trim();
    if (!line) continue;
    if (line === ')') { if (!block) deny('Malformed go.mod require block'); block = false; continue; }
    if (/^require\s*\($/.test(line)) { if (block) deny('Malformed go.mod require block'); block = true; continue; }
    const parts = line.split(/\s+/);
    if (!block && parts[0] === 'module' && parts.length === 2 && modulePath(parts[1]!)) { moduleFound = true; continue; }
    if (!block && parts[0] === 'go' && parts.length === 2 && /^1\.\d+(?:\.\d+)?$/.test(parts[1]!)) continue;
    if (!block && parts[0] === 'require') parts.shift();
    else if (!block) deny('Only module, go and require directives are supported; remove replace, exclude, toolchain and tool directives');
    if (parts.length !== 2 || !modulePath(parts[0]!) || !parts[0]!.split('/')[0]!.includes('.') || !/^v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+incompatible)?$/.test(parts[1]!)) deny('Go requirements must use public module paths and exact versions');
    requirements.push(`${parts[0]}@${parts[1]}`);
  }
  if (block || !moduleFound) deny('Malformed go.mod: a module directive and closed require blocks are required');
  const sums = new Set<string>();
  for (const line of sum.split(/\r?\n/).filter((s) => s.trim())) {
    const parts = line.trim().split(/\s+/);
    if (parts.length !== 3 || !modulePath(parts[0]!) || !/^v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?(?:\+incompatible)?(?:\/go.mod)?$/.test(parts[1]!) || !/^h1:[A-Za-z0-9+/]{43}=$/.test(parts[2]!)) deny('go.sum must contain valid h1 integrity entries');
    sums.add(`${parts[0]}@${parts[1]}`);
  }
  for (const dep of requirements) if (!sums.has(dep) || !sums.has(`${dep}/go.mod`)) deny('Every required Go module needs both module and go.mod integrity entries; update go.sum before planning');
  return [...new Set(requirements)].sort();
}

function validatePnpm(snapshots: Record<string, string>): string[] {
  let manifest: Record<string, unknown>;
  let lock: Record<string, unknown>;
  try {
    manifest = object(JSON.parse(snapshots['package.json']!));
    const document = parseDocument(snapshots['pnpm-lock.yaml']!, { uniqueKeys: true });
    if (document.errors.length) return deny('Invalid pnpm lock YAML');
    lock = object(document.toJS({ maxAliasCount: 0 }));
  } catch { return deny('Invalid JSON or YAML; YAML aliases are not supported'); }
  if (typeof manifest.packageManager !== 'string' || !/^pnpm@10\.30\.1(?:\+sha(?:224|256|384|512)\.[a-f0-9]+)?$/.test(manifest.packageManager)) deny('Pin packageManager to pnpm@10.30.1');
  if (String(lock.lockfileVersion) !== '9.0') deny('Use pnpm lockfile version 9.0');
  for (const key of ['workspaces', 'resolutions', 'overrides', 'publishConfig']) if (key in manifest) deny('Workspace, registry and pnpm overrides are unsupported; use a standalone public-registry lock');
  for (const key of Object.keys(lock)) if (!['lockfileVersion', 'settings', 'importers', 'packages', 'snapshots', 'overrides'].includes(key)) deny('Unsupported pnpm lock configuration; remove catalogs, patches and overrides');
  const pnpm = object(manifest.pnpm ?? {});
  if (Object.keys(pnpm).some((key) => key !== 'overrides')) deny('Only public-registry pnpm overrides are supported; remove hooks, patches and custom configuration');
  const overrides = object(pnpm.overrides ?? {});
  const lockedOverrides = object(lock.overrides ?? {});
  if (Object.keys(overrides).length !== Object.keys(lockedOverrides).length) deny('Manifest and lockfile overrides disagree; regenerate the lock');
  for (const [name, spec] of Object.entries(overrides)) {
    if (!npmName.test(name) || typeof spec !== 'string' || !/^[0-9v*^~<>=| .+xX-]+$/.test(spec) || spec.length > 200) deny('Overrides must name public registry packages with semver ranges; local, URL and git sources are unsupported');
    if (lockedOverrides[name] !== spec) deny('Manifest and lockfile overrides disagree; regenerate the lock');
  }
  const settings = object(lock.settings ?? {});
  if (Object.keys(settings).some((k) => !['autoInstallPeers', 'excludeLinksFromLockfile'].includes(k))) deny('Unsupported pnpm settings');
  const importers = object(lock.importers);
  if (Object.keys(importers).length !== 1 || !('.' in importers)) deny('Only standalone pnpm projects with one root importer are supported');
  const packages = object(lock.packages ?? {});
  const snapshotsMap = object(lock.snapshots ?? {});
  const packageKey = (key: string): boolean => {
    const at = key.lastIndexOf('@');
    return at > 0 && npmName.test(key.slice(0, at)) && version.test(key.slice(at + 1));
  };
  const baseKey = (key: string) => key.split('(')[0]!;
  const reference = (name: string, value: unknown): void => {
    if (!npmName.test(name) || typeof value !== 'string' || /[\\\s:]|\.\.\//.test(value)) deny('Only public registry dependency references are supported');
    const ref = value as string;
    // Peer suffixes contain other package versions, and do not change the tarball identity.
    if (!/^[A-Za-z0-9@/_.+()=-]+$/.test(ref)) deny('Unsafe pnpm dependency reference');
    const base = baseKey(ref);
    const key = version.test(base) ? `${name}@${base}` : base;
    if (!packageKey(key) || !(key in packages)) deny('Every dependency must reference an integrity-pinned public registry package');
  };
  for (const [key, value] of Object.entries(packages)) {
    if (!packageKey(key)) deny('Only exact public registry package keys are supported');
    const pkg = object(value);
    const resolution = object(pkg.resolution);
    if (typeof resolution.integrity !== 'string' || !integrity.test(resolution.integrity)) deny('Every package requires integrity');
    if (Object.keys(resolution).some((k) => !['integrity', 'tarball'].includes(k))) deny('Unsupported package resolution source');
    if (resolution.tarball !== undefined) safeRegistryUrl(resolution.tarball);
  }
  const importer = object(importers['.']);
  if (Object.keys(importer).some((k) => !['dependencies', 'devDependencies', 'optionalDependencies'].includes(k))) deny('Unsupported importer configuration');
  for (const group of ['dependencies', 'devDependencies', 'optionalDependencies'] as const) {
    const requested = object(manifest[group] ?? {});
    const locked = object(importer[group] ?? {});
    if (Object.keys(requested).length !== Object.keys(locked).length) deny('package.json and lockfile disagree; regenerate the lock');
    for (const [name, spec] of Object.entries(requested)) {
      if (!npmName.test(name) || typeof spec !== 'string' || !/^[0-9v*^~<>=| .+xX-]+$/.test(spec) || spec.length > 200) deny('Use public registry semver dependencies; local, git, URL and catalog sources are unsupported');
      const entry = object(locked[name]);
      if (entry.specifier !== spec) deny('package.json and lockfile disagree; regenerate the lock');
      reference(name, entry.version);
    }
  }
  const snapshotPackages = new Set<string>();
  for (const [key, value] of Object.entries(snapshotsMap)) {
    if (!packageKey(baseKey(key)) || !(baseKey(key) in packages) || !/^[A-Za-z0-9@/_.+()=-]+$/.test(key)) deny('Unsafe snapshot package key');
    snapshotPackages.add(baseKey(key));
    const snapshot = object(value);
    for (const group of ['dependencies', 'optionalDependencies']) for (const [name, ref] of Object.entries(object(snapshot[group] ?? {}))) reference(name, ref);
  }
  if (Object.keys(packages).some((key) => !snapshotPackages.has(key))) deny('Every package must have a lock snapshot');
  return Object.keys(packages).sort();
}

/** Checks only immutable supplied text; never reads project config or executes package code. */
export function validateDependencyManifests(ecosystem: DependencyEcosystem, snapshots: Record<string, string>): { dependencies: string[] } {
  const expected = ecosystem === 'go' ? ['go.mod', 'go.sum'] : ['package.json', 'pnpm-lock.yaml'];
  if (Object.keys(snapshots).length !== 2 || expected.some((key) => typeof snapshots[key] !== 'string')) deny(`Supply exactly ${expected.join(' and ')}`);
  if (Object.values(snapshots).reduce((n, text) => n + Buffer.byteLength(text), 0) > 4 * 1024 * 1024) throw new HarnessError('LIMIT_EXCEEDED', 'Dependency manifests exceed 4 MiB', 413);
  if (Object.values(snapshots).some((text) => text.includes('\0'))) deny('Manifest contains NUL bytes');
  return { dependencies: ecosystem === 'go' ? validateGo(snapshots) : validatePnpm(snapshots) };
}
