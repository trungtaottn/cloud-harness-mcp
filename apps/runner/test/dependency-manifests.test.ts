import { describe, expect, it } from 'vitest';
import { validateDependencyManifests as validate } from '../src/dependency-manifests.js';
const hash = 'A'.repeat(43) + '=';
const go = () => ({ 'go.mod': 'module example.com/app\n\ngo 1.24\nrequire (\n github.com/a/b v1.2.3 // indirect\n)\n', 'go.sum': `github.com/a/b v1.2.3 h1:${hash}\ngithub.com/a/b v1.2.3/go.mod h1:${hash}\n` });
const pnpm = () => ({ 'package.json': JSON.stringify({ name: 'app', packageManager: 'pnpm@10.30.1', dependencies: { react: '^19.0.0' } }), 'pnpm-lock.yaml': `lockfileVersion: '9.0'
settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false
importers:
  .:
    dependencies:
      react:
        specifier: ^19.0.0
        version: 19.0.0
packages:
  react@19.0.0:
    resolution: {integrity: sha512-${hash}}
    engines: {node: '>=0.10.0'}
snapshots:
  react@19.0.0: {}
` });
describe('dependency manifests', () => {
  it('accepts complete Go sums and standalone pnpm v9 registry locks', () => {
    expect(validate('go', go()).dependencies).toEqual(['github.com/a/b@v1.2.3']);
    expect(validate('pnpm', pnpm()).dependencies).toEqual(['react@19.0.0']);
  });
  it('accepts peer suffixes without treating them as source URLs', () => {
    const input = pnpm(); input['pnpm-lock.yaml'] = input['pnpm-lock.yaml'].replace('version: 19.0.0', 'version: 19.0.0(@types/react@19.0.0)').replace('  react@19.0.0: {}', '  react@19.0.0(@types/react@19.0.0): {}');
    expect(validate('pnpm', input).dependencies).toHaveLength(1);
  });
  it.each(['replace github.com/a/b => ../local', 'toolchain go1.99.0', 'exclude github.com/a/b v1.2.3'])('rejects unsupported Go directive %s', (directive) => {
    const input = go(); input['go.mod'] += directive; expect(() => validate('go', input)).toThrow();
  });
  it('accepts public host-only and SourceHut module paths', () => {
    for (const path of ['example.org', 'git.example.org/~author/module/v2']) {
      const input = go();
      input['go.mod'] = input['go.mod'].replaceAll('github.com/a/b', path);
      input['go.sum'] = input['go.sum'].replaceAll('github.com/a/b', path);
      expect(validate('go', input).dependencies).toEqual([`${path}@v1.2.3`]);
    }
  });
  it('accepts matching registry overrides and rejects source overrides, drift and pnpm hooks', () => {
    const input = pnpm();
    const manifest = JSON.parse(input['package.json']);
    manifest.pnpm = { overrides: { react: '^19.0.0' } };
    input['package.json'] = JSON.stringify(manifest);
    input['pnpm-lock.yaml'] += '\noverrides:\n  react: ^19.0.0\n';
    expect(validate('pnpm', input).dependencies).toHaveLength(1);
    expect(() => validate('pnpm', { ...input, 'pnpm-lock.yaml': input['pnpm-lock.yaml'].replace('react: ^19.0.0', 'react: ^18.0.0') })).toThrow('overrides disagree');
    for (const source of ['file:../react', 'git+https://example.org/react', 'https://example.org/react.tgz']) {
      manifest.pnpm.overrides.react = source;
      expect(() => validate('pnpm', { ...input, 'package.json': JSON.stringify(manifest) })).toThrow('Overrides must');
    }
    manifest.pnpm = { overrides: {}, hooks: {} };
    expect(() => validate('pnpm', { ...input, 'package.json': JSON.stringify(manifest) })).toThrow('hooks');
  });
  it('requires exact Go version integrity', () => {
    const input = go(); input['go.sum'] = input['go.sum'].replaceAll('v1.2.3', 'v1.2.4'); expect(() => validate('go', input)).toThrow('integrity');
  });
  it.each(['file:../local', 'git+https://example.com/a', 'https://example.com/a.tgz', 'workspace:*', 'catalog:'])('denies source %s', (source) => {
    const input = pnpm(); input['package.json'] = input['package.json'].replace('^19.0.0', source); expect(() => validate('pnpm', input)).toThrow();
  });
  it.each(['https://evil.test/a.tgz', 'https://user:pass@registry.npmjs.org/a', 'http://registry.npmjs.org/a', 'https://registry.npmjs.org:8443/a', 'https://registry.npmjs.org/a#fragment'])('denies tarball %s', (url) => {
    const input = pnpm(); input['pnpm-lock.yaml'] = input['pnpm-lock.yaml'].replace(`integrity: sha512-${hash}`, `integrity: sha512-${hash}, tarball: '${url}'`); expect(() => validate('pnpm', input)).toThrow();
  });
  it('rejects aliases, missing integrity and manifest drift', () => {
    const input = pnpm(); expect(() => validate('pnpm', { ...input, 'pnpm-lock.yaml': 'a: &a [1]\nb: *a' })).toThrow();
    expect(() => validate('pnpm', { ...input, 'pnpm-lock.yaml': input['pnpm-lock.yaml'].replace(`integrity: sha512-${hash}`, '') })).toThrow();
    expect(() => validate('pnpm', { ...input, 'package.json': input['package.json'].replace('^19.0.0', '^18.0.0') })).toThrow();
  });
  it('bounds snapshots and rejects extraneous configuration', () => {
    expect(() => validate('go', { ...go(), '.npmrc': 'token' })).toThrow();
    expect(() => validate('go', { ...go(), 'go.sum': 'a'.repeat(4 * 1024 * 1024) })).toThrow('4 MiB');
  });
});
