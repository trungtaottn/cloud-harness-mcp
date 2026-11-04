import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { loadRunnerConfig } from '../src/config.js';
const dirs: string[] = [];
beforeEach(() => {
  vi.stubEnv('RUNNER_TOKEN', 'r'.repeat(32));
  for (const key of ['ENABLED', 'API_KEY', 'API_KEY_FILE', 'MACHINE_IDS', 'PRINCIPAL_ID', 'ALLOW_PUBLIC_NETWORK']) vi.stubEnv(`INSTABOX_${key}`, undefined);
});
afterEach(() => { vi.unstubAllEnvs(); dirs.splice(0).forEach(d => rmSync(d, { recursive: true, force: true })); });
function enabled() {
  const dir = mkdtempSync(join(tmpdir(), 'instabox-config-')); dirs.push(dir);
  const file = join(dir, 'key'); writeFileSync(file, 'test-provider-credential\n');
  vi.stubEnv('INSTABOX_ENABLED', 'true'); vi.stubEnv('INSTABOX_API_KEY_FILE', file);
  vi.stubEnv('INSTABOX_MACHINE_IDS', 'machine-a, machine-b, machine-c');
  vi.stubEnv('INSTABOX_PRINCIPAL_ID', 'canonical-principal'); vi.stubEnv('INSTABOX_ALLOW_PUBLIC_NETWORK', 'true');
  return file;
}
it('keeps disabled behavior and quotas unchanged', () => {
  const initial = loadRunnerConfig();
  expect(initial.instabox).toBeUndefined(); enabled();
  const configured = loadRunnerConfig();
  expect(configured.instabox).toMatchObject({ machineIds: ['machine-a', 'machine-b', 'machine-c'], principalId: 'canonical-principal', allowPublicNetwork: true });
  expect(configured.maxActiveWorkspacesPerOwner).toBe(initial.maxActiveWorkspacesPerOwner);
  expect(configured.networkProfile).toBe(initial.networkProfile);
});
it.each(['INSTABOX_MACHINE_IDS', 'INSTABOX_PRINCIPAL_ID', 'INSTABOX_ALLOW_PUBLIC_NETWORK', 'INSTABOX_API_KEY_FILE'])('fails closed without %s', key => {
  enabled(); vi.stubEnv(key, undefined); expect(() => loadRunnerConfig()).toThrow();
});
it('rejects inline keys, empty files and duplicate machine IDs', () => {
  const file = enabled(); vi.stubEnv('INSTABOX_API_KEY', 'do-not-disclose-sentinel');
  expect(() => loadRunnerConfig()).toThrow('INSTABOX_API_KEY is forbidden');
  vi.stubEnv('INSTABOX_API_KEY', undefined); writeFileSync(file, ' \n');
  expect(() => loadRunnerConfig()).toThrow(); writeFileSync(file, 'test-provider-credential');
  vi.stubEnv('INSTABOX_MACHINE_IDS', 'machine-a,machine-a'); expect(() => loadRunnerConfig()).toThrow();
});
