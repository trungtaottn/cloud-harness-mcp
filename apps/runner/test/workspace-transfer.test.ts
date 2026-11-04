import { mkdtemp, mkdir, readFile, writeFile, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { afterEach, describe, expect, it } from 'vitest';
const roots: string[] = [];
const script = resolve('worker/workspace-transfer.mjs');
const run = (...args: string[]) => execFileSync(process.execPath, [script, ...args], { stdio: 'pipe' });
afterEach(async () => { for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true }); });
async function fixture() { const root = await mkdtemp(join(tmpdir(), 'ch-transfer-')); roots.push(root); return root; }
describe('bounded workspace transfer', () => {
  it('round trips binary files, hidden Git state and safe relative symlinks', async () => {
    const root = await fixture(); const source = join(root, 'source');
    await mkdir(join(source, '.git'), { recursive: true });
    await writeFile(join(source, '.git', 'index'), Buffer.from([0, 255, 13, 10]));
    await writeFile(join(source, 'unfinished'), 'not committed');
    await symlink('unfinished', join(source, 'link'));
    run('pack', source, join(root, 'archive'), '1024');
    run('unpack', join(root, 'archive'), join(root, 'restored'), '1024');
    expect(await readFile(join(root, 'restored', '.git', 'index'))).toEqual(Buffer.from([0, 255, 13, 10]));
    expect(await readFile(join(root, 'restored', 'link'), 'utf8')).toBe('not committed');
  });
  it('refuses outside links and does not follow them into a checkpoint', async () => {
    const root = await fixture(); await mkdir(join(root, 'source')); await symlink('/etc/passwd', join(root, 'source', 'outside'));
    expect(() => run('pack', join(root, 'source'), join(root, 'archive'), '1024')).toThrow();
  });
  it('refuses traversal, oversized entries and partial archives without publishing a destination', async () => {
    const root = await fixture();
    for (const header of [{ path: '../escape', type: 'file', size: 1 }, { path: 'file', type: 'file', size: 2048 }, { path: 'file', type: 'file', size: 2 }]) {
      await writeFile(join(root, 'archive'), 'CHWORK1\n'+JSON.stringify(header)+'\n'+'x');
      expect(() => run('unpack', join(root, 'archive'), join(root, 'dest'), '1024')).toThrow();
    }
    await expect(readFile(join(root, 'escape'))).rejects.toThrow();
  });
  it('never overwrites an existing destination', async () => {
    const root = await fixture(); await mkdir(join(root, 'source')); await writeFile(join(root, 'source', 'file'), 'new');
    await mkdir(join(root, 'dest')); await writeFile(join(root, 'dest', 'file'), 'old');
    run('pack', join(root, 'source'), join(root, 'archive'), '1024');
    expect(() => run('unpack', join(root, 'archive'), join(root, 'dest'), '1024')).toThrow();
    expect(await readFile(join(root, 'dest', 'file'), 'utf8')).toBe('old');
  });
  it('projects only selected skill trees without copying unrelated checkout files', async () => {
    const root = await fixture(); const source = join(root, 'source');
    await mkdir(join(source, '.agents', 'skills', 'example'), { recursive: true });
    await writeFile(join(source, '.agents', 'skills', 'example', 'SKILL.md'), 'example');
    await writeFile(join(source, 'large-unrelated'), Buffer.alloc(100000));
    run('pack', source, join(root, 'archive'), '2048', JSON.stringify(['.agents/skills']));
    run('unpack', join(root, 'archive'), join(root, 'restored'), '2048');
    expect(await readFile(join(root, 'restored', '.agents', 'skills', 'example', 'SKILL.md'), 'utf8')).toBe('example');
    await expect(readFile(join(root, 'restored', 'large-unrelated'))).rejects.toThrow();
  });
  it('refuses a directory swapped to an outside symlink after its metadata check', async () => {
    const root = await fixture();
    await mkdir(join(root, 'source', 'nested'), { recursive: true });
    await mkdir(join(root, 'outside'));
    await writeFile(join(root, 'outside', 'private-file'), 'must not be exported');
    const hook = join(root, 'swap.mjs');
    await writeFile(hook, `import fs from 'node:fs'; import {syncBuiltinESMExports} from 'node:module';
const original=fs.lstatSync; let swapped=false;
fs.lstatSync=(path,...args)=>{const value=original(path,...args);if(!swapped&&String(path).endsWith('/nested')){swapped=true;fs.renameSync(${JSON.stringify(join(root, 'source', 'nested'))},${JSON.stringify(join(root, 'source', 'moved'))});fs.symlinkSync(${JSON.stringify(join(root, 'outside'))},${JSON.stringify(join(root, 'source', 'nested'))});}return value;};syncBuiltinESMExports();`);
    expect(() => execFileSync(process.execPath, ['--import', hook, script, 'pack', join(root, 'source'), join(root, 'archive'), '4096'], { stdio: 'pipe' })).toThrow();
    await expect(readFile(join(root, 'archive'))).rejects.toThrow();
  });
});
