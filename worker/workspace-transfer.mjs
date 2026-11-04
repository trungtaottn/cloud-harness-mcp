import { constants, openSync, closeSync, readSync, writeSync, fstatSync, lstatSync, mkdirSync, readdirSync, readlinkSync, symlinkSync, renameSync, rmSync, existsSync, chmodSync } from 'node:fs';
import { resolve, dirname, join, isAbsolute, posix } from 'node:path';
import { randomUUID } from 'node:crypto';

// An intentionally small, length-delimited format. No archive engine, device nodes,
// ownership restoration, hard links or extraction through symlink parents.
const [mode, source, destination, limitArg, pathsArg] = process.argv.slice(2);
const limit = Number(limitArg);
if (!['pack', 'unpack'].includes(mode) || !source || !destination || !Number.isSafeInteger(limit) || limit < 1) throw new Error('invalid transfer arguments');
const maxEntries = 100_000;
const magic = 'CHWORK1\n';
function safeName(name) {
  if (typeof name !== 'string' || !name || name.length > 8192 || isAbsolute(name) || name.includes('\\') || name.includes('\0') || name.split('/').some(x => !x || x === '.' || x === '..')) throw new Error('unsafe transfer path');
  return name;
}
function safeLink(name, target) {
  if (typeof target !== 'string' || !target || isAbsolute(target) || target.includes('\\') || target.includes('\0')) throw new Error('unsafe link');
  const resolved = posix.normalize(posix.join(posix.dirname(name), target));
  if (resolved === '..' || resolved.startsWith('../') || name.split('/').includes('.git') || /(^|\/)objects\//.test(name)) throw new Error('link escapes transfer or Git metadata');
}
function metadataPath(name, stat) {
  if ((name === '.git' || name.endsWith('/.git')) && !stat.isDirectory()) throw new Error('external Git directory is not transferable');
  if (name.endsWith('objects/info/alternates') && stat.size > 0) throw new Error('Git alternates must be materialized before transfer');
}
function pack() {
  const root = resolve(source), target = resolve(destination);
  const paths = pathsArg === undefined ? undefined : JSON.parse(pathsArg);
  if (paths !== undefined && (!Array.isArray(paths) || paths.length > 32 || paths.some(path => safeName(path) !== path))) throw new Error('invalid transfer selection');
  if (target === root || target.startsWith(root + '/')) throw new Error('archive cannot be inside source');
  const rootFd = openSync(root, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  if (readlinkSync(`/proc/self/fd/${rootFd}`) !== root) { closeSync(rootFd); throw new Error('source must be a canonical directory'); }
  const fd = openSync(target, 'wx', 0o600);
  let bytes = 0, entries = 0;
  const output = data => { const b = Buffer.isBuffer(data) ? data : Buffer.from(data); bytes += b.length; if (bytes > limit) throw new Error('transfer exceeds byte limit'); let off = 0; while (off < b.length) off += writeSync(fd, b, off); };
  try {
    output(magic);
    function walk(directoryFd, prefix = '') {
      // Anchor every child lookup to its opened parent. Checking a path and then
      // recursively following that path permits a concurrent directory->symlink
      // swap to escape the snapshot, even when individual files use O_NOFOLLOW.
      const parent = `/proc/self/fd/${directoryFd}`;
      for (const name of readdirSync(parent).sort()) {
        const rel = safeName(prefix + name);
        if (paths && !paths.some(path => rel === path || rel.startsWith(path + '/') || path.startsWith(rel + '/'))) continue;
        const path = join(parent, name), st = lstatSync(path);
        if (++entries > maxEntries) throw new Error('too many transfer entries');
        metadataPath(rel, st);
        if (st.isDirectory()) {
          const child = openSync(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
          try {
            const opened = fstatSync(child);
            if (opened.ino !== st.ino || opened.dev !== st.dev) throw new Error('directory changed during transfer');
            output(JSON.stringify({ path: rel, type: 'dir' }) + '\n'); walk(child, rel + '/');
          } finally { closeSync(child); }
        }
        else if (st.isSymbolicLink()) { const target = readlinkSync(path); safeLink(rel, target); output(JSON.stringify({ path: rel, type: 'link', target }) + '\n'); }
        else if (st.isFile()) {
          output(JSON.stringify({ path: rel, type: 'file', size: st.size, mode: st.mode & 0o111 ? 0o755 : 0o644 }) + '\n');
          const input = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
          try {
            const before = fstatSync(input);
            if (before.ino !== st.ino || before.dev !== st.dev || before.size !== st.size) throw new Error('source changed during transfer');
            const buf = Buffer.alloc(65536); let left = st.size;
            while (left > 0) { const n = readSync(input, buf, 0, Math.min(left, buf.length), null); if (!n) throw new Error('source truncated'); output(buf.subarray(0, n)); left -= n; }
            const after = fstatSync(input);
            if (after.size !== before.size || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) throw new Error('source changed during transfer');
          } finally { closeSync(input); }
          output('\n');
        } else throw new Error('unsupported special file');
      }
    }
    walk(rootFd); output(JSON.stringify({ end: true, entries }) + '\n');
  } catch (e) { rmSync(target, { force: true }); throw e; }
  finally { closeSync(fd); closeSync(rootFd); }
}
function unpack() {
  const target = resolve(destination);
  if (existsSync(target)) throw new Error('destination already exists');
  const fd = openSync(source, constants.O_RDONLY | constants.O_NOFOLLOW);
  const stage = target + '.incoming-' + randomUUID();
  let buffered = Buffer.alloc(0), consumed = 0, entries = 0;
  const names = new Set(), links = [];
  function more() { const b = Buffer.alloc(65536); const n = readSync(fd, b, 0, b.length, null); buffered = Buffer.concat([buffered, b.subarray(0, n)]); return n; }
  function take(n) {
    while (buffered.length < n) if (!more()) throw new Error('truncated transfer');
    consumed += n; if (consumed > limit) throw new Error('transfer exceeds byte limit');
    const out = buffered.subarray(0, n); buffered = buffered.subarray(n); return out;
  }
  function line() {
    while (!buffered.includes(10)) { if (buffered.length > 16384) throw new Error('oversized transfer header'); if (!more()) throw new Error('missing transfer footer'); }
    const end = buffered.indexOf(10); if (end > 16384) throw new Error('oversized transfer header');
    return take(end + 1).subarray(0, end).toString('utf8');
  }
  try {
    if (!fstatSync(fd).isFile() || fstatSync(fd).size > limit) throw new Error('invalid archive size');
    if (take(Buffer.byteLength(magic)).toString() !== magic) throw new Error('invalid archive magic');
    mkdirSync(stage, { mode: 0o700 });
    for (;;) {
      const entry = JSON.parse(line());
      if (entry.end === true) { if (entry.entries !== entries || buffered.length || more()) throw new Error('invalid transfer footer'); break; }
      const name = safeName(entry.path), path = join(stage, name);
      if (names.has(name) || ++entries > maxEntries) throw new Error('duplicate or excessive entries');
      names.add(name);
      if (name.split('/').includes('.git') && entry.type === 'link') throw new Error('linked Git metadata');
      if ((name === '.git' || name.endsWith('/.git')) && entry.type !== 'dir') throw new Error('external Git directory');
      mkdirSync(dirname(path), { recursive: true, mode: 0o755 });
      if (entry.type === 'dir') mkdirSync(path, { recursive: true, mode: 0o755 });
      else if (entry.type === 'link') { safeLink(name, entry.target); links.push([path, entry.target]); }
      else if (entry.type === 'file') {
        if (!Number.isSafeInteger(entry.size) || entry.size < 0 || entry.size + consumed > limit || (name.endsWith('objects/info/alternates') && entry.size > 0)) throw new Error('invalid file size or external Git alternates');
        const output = openSync(path, 'wx', 0o600);
        try { let left = entry.size; while (left) { const b = take(Math.min(left, 65536)); let off = 0; while (off < b.length) off += writeSync(output, b, off); left -= b.length; } } finally { closeSync(output); }
        if (take(1)[0] !== 10) throw new Error('missing file delimiter');
        chmodSync(path, entry.mode === 0o755 ? 0o755 : 0o644);
      } else throw new Error('unsupported entry type');
    }
    for (const [path, value] of links) symlinkSync(value, path);
    if (existsSync(target)) throw new Error('destination appeared during transfer');
    renameSync(stage, target);
  } catch (e) { rmSync(stage, { recursive: true, force: true }); throw e; }
  finally { closeSync(fd); }
}
if (mode === 'pack') pack(); else unpack();
