// Durable allocation-scoped jobs. Python sets Linux subreaper ownership before execing Node.
import { mkdirSync, readFileSync, writeFileSync, linkSync, unlinkSync, existsSync, openSync, closeSync, readSync, appendFileSync, renameSync, readdirSync, fstatSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createServer, createConnection } from 'node:net';
import { createHash, randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { setInterval, clearInterval } from 'node:timers';

const [root, action, payload] = process.argv.slice(2);
const args = JSON.parse(payload === '-' ? readFileSync(0, 'utf8') : Buffer.from(payload || '', 'base64').toString());
if (!root?.startsWith('/') || !/^[A-Za-z0-9_-]{1,128}$/.test(args.id)) throw Error('invalid job identity');
const dir = join(root, '.ch-jobs', args.id);
mkdirSync(dir, { recursive: true, mode: 0o700 });
const boot = readFileSync('/proc/sys/kernel/random/boot_id', 'utf8').trim();
const json = name => JSON.parse(readFileSync(join(dir, name), 'utf8'));
const exists = name => existsSync(join(dir, name));
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const save = (name, value) => {
  const temporary = join(dir, `${name}.${randomUUID()}`);
  writeFileSync(temporary, JSON.stringify(value), { mode: 0o600 });
  renameSync(temporary, join(dir, name));
};
function identity(pid) {
  try {
    const fields = readFileSync(`/proc/${pid}/stat`, 'utf8').split(') ').at(-1).split(' ');
    return { pid, boot, start: fields[19], state: fields[0], parent: Number(fields[1]) };
  } catch { return undefined; }
}
function same(record) {
  const current = identity(record?.pid);
  return current && record.boot === boot && current.start === record.start && !['Z', 'X'].includes(current.state);
}
const socketPath = '/tmp/ch-' + createHash('sha256').update(dir).digest('hex').slice(0, 32) + '.sock';
function claim(spec) {
  const temporary = join(dir, 'claim.' + randomUUID());
  writeFileSync(temporary, JSON.stringify({ ...spec, claimedAt: Date.now() }), { mode: 0o600 });
  try { linkSync(temporary, join(dir, 'claim')); return true; }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    if (json('claim').fingerprint !== spec.fingerprint) throw Error('job fingerprint conflict');
    return false;
  } finally { unlinkSync(temporary); }
}
// PR_SET_CHILD_SUBREAPER survives execve. Orphans cannot escape this ownership boundary by setsid/double-fork.
const trampoline = "import ctypes,os,sys; lib=ctypes.CDLL(None,use_errno=True); result=lib.prctl(36,1,0,0,0); result==0 or sys.exit(125); os.environ['CH_REMOTE_SUBREAPER']='1'; os.execv(sys.argv[1],sys.argv[1:])";
function supervisor(mode, value, terminal = false) {
  return spawn('python3', ['-c', trampoline, process.execPath, fileURLToPath(import.meta.url), root, mode, Buffer.from(JSON.stringify(value)).toString('base64')], { detached: !terminal, stdio: terminal ? 'inherit' : 'ignore' });
}
function descendants(owner) {
  if (!same(owner)) throw Error('supervisor identity lost');
  const all = readdirSync('/proc').filter(value => /^\d+$/.test(value)).map(value => identity(Number(value))).filter(Boolean);
  const selected = new Map([[owner.pid, owner]]);
  for (let changed = true; changed;) {
    changed = false;
    for (const item of all) if (!selected.has(item.pid) && selected.has(item.parent)) { selected.set(item.pid, item); changed = true; }
  }
  selected.delete(owner.pid);
  return [...selected.values()].filter(same);
}
function signalIdentity(record, signal) {
  if (!same(record)) return;
  try { process.kill(record.pid, signal); } catch (error) { if (error.code !== 'ESRCH') throw error; }
}
async function quiesce(owner) {
  // Freeze fork-capable parents, kill the verified tree, then rescan kernel-adopted orphans.
  // An empty live tree is the completion condition, never merely the original shell's death.
  for (let attempt = 0; attempt < 250; attempt++) {
    const children = descendants(owner);
    if (!children.length) return;
    for (const item of children) signalIdentity(item, 'SIGSTOP');
    for (const item of descendants(owner).reverse()) signalIdentity(item, 'SIGKILL');
    await wait(20);
  }
  throw Error('descendant cleanup unconfirmed');
}

let result = {};
if (action === 'start') {
  if (claim(args)) {
    const child = supervisor('supervise', { id: args.id });
    child.on('error', () => {}); // The absent receipt remains an unknown dispatch, never a retry.
    child.unref();
  }
  for (let attempt = 0; !exists('process') && !exists('exit') && attempt < 100; attempt++) await wait(20);
  if (!exists('process') && !exists('exit')) throw Error('launch unconfirmed');
} else if (action === 'terminal') {
  const child = supervisor('terminal-supervise', args, true);
  child.on('error', () => { process.exitCode = 125; });
  child.on('exit', code => { process.exitCode = code ?? 125; });
} else if (action === 'supervise' || action === 'terminal-supervise') {
  if (process.env.CH_REMOTE_SUBREAPER !== '1') throw Error('kernel subreaper is required');
  const terminal = action === 'terminal-supervise';
  if (terminal && !claim(args)) throw Error('terminal already claimed');
  const spec = json('claim');
  if (exists('cancel')) { save('exit', { exitCode: 143, truncated: false }); process.exit(0); }
  const owner = identity(process.pid);
  let environment = {};
  try { environment = JSON.parse(readFileSync(join(root, 'runtime', 'environment.json'), 'utf8')); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }
  const child = spawn('/bin/bash', terminal ? ['--noprofile', '--norc', '-i'] : spec.kind === 'shell' ? ['--noprofile', '--norc'] : ['-c', spec.command], {
    cwd: spec.cwd, detached: !terminal, stdio: terminal ? 'inherit' : ['pipe', 'pipe', 'pipe'],
    env: { ...process.env, ...environment, HARNESS_WORKSPACE_ROOT: join(root, 'repo'), CH_OWNER_SKILLS_ROOT: join(root, 'owner-skills'), BUILTIN_SKILLS_ROOT: join(root, 'builtin-skills') }
  });
  let bytes = 0, truncated = false, finishing;
  const closed = new Promise(resolve => child.once('close', resolve));
  const append = chunk => {
    const remaining = Math.max(0, spec.maxBytes - bytes);
    if (chunk.length > remaining) truncated = true;
    const data = chunk.subarray(0, remaining);
    if (data.length) { appendFileSync(join(dir, 'output'), data); bytes += data.length; }
    if (truncated && !exists('truncated')) writeFileSync(join(dir, 'truncated'), '1');
  };
  child.stdout?.on('data', append); child.stderr?.on('data', append); child.stdin?.on('error', () => {});
  if (spec.kind === 'task' && !terminal) child.stdin.end();
  const server = createServer(socket => {
    let size = 0;
    socket.on('data', data => {
      size += data.length;
      if (finishing || size > 1048576 || !child.stdin || child.stdin.writableLength + data.length > 1048576) { socket.destroy(); return; }
      if (!child.stdin.write(data)) { socket.pause(); child.stdin.once('drain', () => socket.resume()); }
    });
    socket.on('end', () => socket.end()); socket.on('error', () => {});
  });
  try { unlinkSync(socketPath); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  server.listen(socketPath, () => {
    save('process', { ...identity(child.pid), supervisor: owner, containment: 'subreaper-v1' });
    if (terminal) process.stdout.write(`\x1eCH_READY_${args.id}\x1f`);
  });
  const timer = setTimeout(() => { save('timeout', {}); void finish(124); }, spec.timeoutMs);
  const poll = setInterval(() => { if (exists('cancel')) void finish(143); }, 50);
  function finish(code) {
    if (finishing) return finishing;
    clearTimeout(timer); clearInterval(poll);
    finishing = (async () => {
      // Failed cleanup retains the live subreaper and an unknown result. Never orphan children or claim success.
      for (;;) { try { await quiesce(owner); break; } catch { await wait(200); } }
      await closed;
      save('exit', { exitCode: exists('timeout') ? 124 : exists('cancel') ? 143 : code, truncated });
      server.close();
      try { unlinkSync(socketPath); } catch { /* already removed */ }
    })();
    return finishing;
  }
  child.on('error', () => { void finish(127); });
  child.on('exit', (code, signal) => { void finish(code ?? (signal === 'SIGKILL' ? 137 : 143)); });
  process.on('SIGTERM', () => { writeFileSync(join(dir, 'cancel'), '1'); void finish(143); });
} else if (action === 'read') {
  if (!Number.isSafeInteger(args.offset) || args.offset < 0 || !Number.isSafeInteger(args.maxBytes) || args.maxBytes < 0 || args.maxBytes > 1048576) throw Error('invalid read bound');
  const output = Buffer.alloc(args.maxBytes); let length = 0, total = 0;
  try {
    const fd = openSync(join(dir, 'output'), 'r');
    try { total = fstatSync(fd).size; length = readSync(fd, output, 0, output.length, args.offset); } finally { closeSync(fd); }
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const exit = exists('exit') ? json('exit') : undefined;
  const proc = exists('process') ? json('process') : undefined;
  result = {
    errorCode: !exit && !proc && !exists('claim') ? 'JOB_NOT_FOUND' : !exit && proc && !same(proc.supervisor) ? 'PROCESS_IDENTITY_LOST' : undefined,
    status: exit ? 'exited' : proc ? (same(proc.supervisor) ? 'running' : 'unknown') : exists('claim') && Date.now() - json('claim').claimedAt < 10000 ? 'starting' : 'unknown',
    ...exit, output: output.subarray(0, length).toString('base64'), nextOffset: args.offset + length, outputBytes: total, truncated: exists('truncated') || exit?.truncated === true
  };
} else if (action === 'cancel') {
  writeFileSync(join(dir, 'cancel'), '1');
  if (!exists('claim')) save('exit', { exitCode: 143, truncated: false });
  for (let attempt = 0; !exists('exit') && attempt < 500; attempt++) {
    if (exists('process')) {
      const record = json('process');
      if (record.containment !== 'subreaper-v1' || !same(record.supervisor)) throw Error('cancellation unconfirmed: supervisor identity lost');
    }
    await wait(20);
  }
  if (!exists('exit')) throw Error('cancellation unconfirmed');
} else if (action === 'write') {
  if (Buffer.byteLength(args.input) > 1048576) throw Error('input exceeds limit');
  const record = json('process');
  if (!same(record) || !same(record.supervisor) || exists('cancel')) throw Error('shell not running');
  await new Promise((resolve, reject) => {
    const socket = createConnection(socketPath, () => socket.end(args.input));
    socket.setTimeout(5000, () => socket.destroy(Error('stdin timeout')));
    socket.on('error', reject); socket.on('close', resolve);
  });
} else throw Error('invalid action');
if (!['supervise', 'terminal', 'terminal-supervise'].includes(action)) process.stdout.write(JSON.stringify(result));
