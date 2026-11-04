import { chmod, lstat, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mkdtempSync } from 'node:fs';
import { execFile, spawnSync } from 'node:child_process';
import { promisify } from 'node:util';
import { afterEach, expect, it } from 'vitest';
import { REMOTE_CLEANUP_SCRIPT, remoteCleanupCommand } from '../src/remote-cleanup.js';

const execute = promisify(execFile);
const roots: string[] = [];
const instance = 'a'.repeat(36);
const workspace = 'ws_cleanup';
const isolatedMounts = spawnSync('unshare', ['--user', '--map-root-user', '--mount', 'true']).status === 0;

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'remote-cleanup-'));
  roots.push(root);
  return { root, base: join(root, 'data', 'home') };
}

async function cleanup(base: string, workspaceId = workspace) {
  return execute('python3', ['-c', REMOTE_CLEANUP_SCRIPT, base, instance, workspaceId]);
}

afterEach(async () => {
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

it('removes a partial readonly allocation without following contained links', async () => {
  const { root, base } = fixture();
  const allocation = join(base, '.cloud-harness', instance, workspace);
  const readonly = join(allocation, 'canary-tools', 'go', 'pkg', 'mod', 'github.com', 'google', 'uuid@v1.6.0', '.github', 'workflows');
  const outside = join(root, 'outside');
  await mkdir(readonly, { recursive: true });
  await mkdir(outside);
  await writeFile(join(readonly, 'test.yml'), 'retained');
  await writeFile(join(outside, 'sentinel'), 'outside');
  await symlink(outside, join(allocation, 'outside-link'));
  await chmod(join(readonly, 'test.yml'), 0o444);
  for (const directory of [readonly, join(readonly, '..'), join(readonly, '..', '..')]) await chmod(directory, 0o555);

  await cleanup(base);

  await expect(readFile(join(outside, 'sentinel'), 'utf8')).resolves.toBe('outside');
  await expect(lstat(allocation)).rejects.toMatchObject({ code: 'ENOENT' });
});

it('treats an already missing allocation as a successful cleanup retry', async () => {
  const { base } = fixture();
  await mkdir(join(base, '.cloud-harness', instance), { recursive: true });
  await expect(cleanup(base)).resolves.toBeDefined();
});

it('refuses symlinked ancestors and workspace roots without touching their targets', async () => {
  const first = fixture();
  const outside = join(first.root, 'outside');
  await mkdir(outside);
  await writeFile(join(outside, 'sentinel'), 'safe');
  await mkdir(first.base, { recursive: true });
  await symlink(outside, join(first.base, '.cloud-harness'));
  await expect(cleanup(first.base)).rejects.toThrow();
  await expect(readFile(join(outside, 'sentinel'), 'utf8')).resolves.toBe('safe');

  const second = fixture();
  const parent = join(second.base, '.cloud-harness', instance);
  await mkdir(parent, { recursive: true });
  await symlink(outside, join(parent, workspace));
  await expect(cleanup(second.base)).rejects.toThrow();
  await expect(readFile(join(outside, 'sentinel'), 'utf8')).resolves.toBe('safe');
});

it.skipIf(!isolatedMounts)('refuses a bind-mounted allocation ancestor in an isolated mount namespace', async () => {
  const { root, base } = fixture();
  const boundary = join(base, '.cloud-harness');
  const redirected = join(root, 'redirected');
  await mkdir(boundary, { recursive: true });
  await mkdir(join(redirected, instance, workspace), { recursive: true });
  await writeFile(join(redirected, instance, workspace, 'sentinel'), 'safe');
  const command = 'mount --bind "$1" "$2"; exec python3 -c "$3" "$4" "$5" "$6"';
  await expect(execute('unshare', ['--user', '--map-root-user', '--mount', 'sh', '-c', command, 'sh',
    redirected, boundary, REMOTE_CLEANUP_SCRIPT, base, instance, workspace])).rejects.toMatchObject({
      stderr: expect.stringContaining('cleanup refuses an ancestor mount')
    });
  await expect(readFile(join(redirected, instance, workspace, 'sentinel'), 'utf8')).resolves.toBe('safe');
});

it('builds a noninteractive privileged command only for the exact allocation path', () => {
  const ref = { provider: 'instabox' as const, workspaceId: workspace, ownerId: 'owner', machineId: 'machine', generation: 1,
    root: `/data/home/.cloud-harness/${instance}/${workspace}` };
  const command = remoteCleanupCommand(ref);
  expect(command).toContain("'sudo' '-n' '--' 'python3' '-c'");
  expect(command).toContain(`'/data/home' '${instance}' '${workspace}'`);
  expect(() => remoteCleanupCommand({ ...ref, root: `/data/home/.cloud-harness/${instance}/other` })).toThrow('path is invalid');
  expect(() => remoteCleanupCommand({ ...ref, root: `/data/home/.cloud-harness/${instance}/${workspace}/nested` })).toThrow('path is invalid');
});
