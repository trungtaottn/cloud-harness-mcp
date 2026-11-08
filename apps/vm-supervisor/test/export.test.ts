import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { prepareVmExport, TarEntryCounter, type VmApplianceProcess, type VmApplianceSpawner } from '../src/export.js';
import { inspectTarSafety, tarSizeField } from '../src/tar-safety.js';
import { spawnApplianceProcess } from '../src/runtime.js';

const dirs: string[] = [];
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'vm-export-'));
  dirs.push(dir);
  return dir;
}
afterEach(() => {
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

// -- tar helpers ---------------------------------------------------------------

function tarHeader(name: string, type: string, size: bigint, link = ''): Buffer {
  const h = Buffer.alloc(512);
  h.write(name.slice(0, 100), 0, 'utf8');
  h.write('0000644\0', 100);
  h.write('0000000\0', 108);
  h.write('0000000\0', 116);
  const field = Buffer.alloc(12);
  if (size < 8n * 1024n ** 3n) {
    // octal ASCII (11 digits + NUL holds up to 8 GiB - 1)
    field.write(size.toString(8).padStart(11, '0') + '\0', 0, 'ascii');
  } else {
    // GNU base-256: 12-byte big-endian with marker bit in byte 0
    let v = size;
    for (let i = 11; i >= 0; i -= 1) { field[i] = Number(v & 0xffn); v >>= 8n; }
    field[0] = field[0]! | 0x80;
  }
  field.copy(h, 124);
  h.write(type, 156);
  h.write(link.slice(0, 100), 157, 'utf8');
  h.write('ustar\0', 257);
  h.write('00', 263);
  return h;
}

function tarOfMembers(...members: { name: string; body?: Buffer; type?: string; link?: string; base256?: boolean }[]): Buffer {
  const parts: Buffer[] = [];
  for (const m of members) {
    const body = m.body ?? Buffer.alloc(0);
    const size = BigInt(body.length);
    let header: Buffer;
    if (m.base256) {
      header = tarHeader(m.name, m.type ?? '0', size, m.link ?? '');
      // force base-256 even for small sizes
      const field = Buffer.alloc(12);
      let v = size;
      for (let i = 11; i >= 0; i -= 1) { field[i] = Number(v & 0xffn); v >>= 8n; }
      field[0] = field[0]! | 0x80;
      field.copy(header, 124);
    } else {
      header = tarHeader(m.name, m.type ?? '0', size, m.link ?? '');
    }
    const pad = Number(((size + 511n) / 512n) * 512n - size);
    parts.push(header, body, Buffer.alloc(pad));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

// -- fake appliance ------------------------------------------------------------

function chunksOf(buf: Buffer, size: number): Buffer[] {
  const out: Buffer[] = [];
  for (let i = 0; i < buf.length; i += size) out.push(buf.subarray(i, Math.min(i + size, buf.length)));
  return out.length === 0 ? [Buffer.alloc(0)] : out;
}

class FakeAppliance extends EventEmitter implements VmApplianceProcess {
  readonly stdout: Readable | null;
  readonly stderr: Readable | null;
  killedWith: NodeJS.Signals | number | undefined;
  closeEmitted = false;
  private hang: boolean;
  private emitClose: () => void;

  constructor(
    chunks: Buffer[],
    opts: { exitCode?: number | null; signal?: NodeJS.Signals | null; stderr?: string; hang?: boolean } = {}
  ) {
    super();
    this.hang = opts.hang === true;
    const code = opts.exitCode === undefined ? 0 : opts.exitCode;
    const sig = opts.signal ?? null;
    this.stdout = this.hang ? new Readable({ read() { /* never produces until killed */ } }) : Readable.from(chunks);
    this.stderr = Readable.from(opts.stderr === undefined || opts.stderr === '' ? [] : [Buffer.from(opts.stderr)]);
    this.emitClose = () => {
      if (this.closeEmitted) return;
      this.closeEmitted = true;
      this.emit('close', code, sig);
    };
    // A live child reports exit asynchronously; 'close' is what runAppliance
    // awaits. A hung child only closes once killed — like a real SIGKILL.
    if (!this.hang) setImmediate(this.emitClose);
  }

  kill(signal?: NodeJS.Signals | number): boolean {
    this.killedWith = signal;
    // SIGKILL ends the process: stdout reaches EOF so the sink loop exits,
    // then 'close' reports the reap — mirroring real child semantics.
    if (this.hang) {
      try { this.stdout?.push(null); } catch { /* already ended */ }
      try { this.stderr?.push(null); } catch { /* already ended */ }
    }
    setImmediate(this.emitClose);
    return true;
  }
}

interface FakeSpawnerOpts {
  exitCode?: number | null;
  signal?: NodeJS.Signals | null;
  stderr?: string;
  hang?: boolean;
  chunkSize?: number;
  throwSpawn?: Error;
  emitError?: Error;
}

function fakeSpawner(
  tar: Buffer | null,
  opts: FakeSpawnerOpts = {}
): { spawner: VmApplianceSpawner; calls: string[][]; procs: FakeAppliance[] } {
  const calls: string[][] = [];
  const procs: FakeAppliance[] = [];
  const spawner: VmApplianceSpawner = (argv) => {
    calls.push([...argv]);
    if (opts.throwSpawn !== undefined) throw opts.throwSpawn;
    const proc = new FakeAppliance(tar === null ? [] : chunksOf(tar, opts.chunkSize ?? 700), opts);
    if (opts.emitError !== undefined) setImmediate(() => proc.emit('error', opts.emitError));
    procs.push(proc);
    return proc;
  };
  return { spawner, calls, procs };
}

function stagedFiles(dir: string): string[] {
  try {
    return readdirSync(join(dir, '.exports')).map((f) => join(dir, '.exports', f));
  } catch {
    return [];
  }
}

// -- tarSizeField ---------------------------------------------------------------

describe('tarSizeField base-256', () => {
  it('decodes octal ASCII fields', () => {
    const f = Buffer.alloc(12);
    f.write('000000010644\0', 0, 'ascii'); // 0o10644 = 4516
    expect(tarSizeField(f)).toBe(4516n);
  });

  it('decodes GNU base-256 fields', () => {
    const f = Buffer.alloc(12);
    // 5 GiB in base-256
    let v = 5n * 1024n ** 3n;
    for (let i = 11; i >= 0; i -= 1) { f[i] = Number(v & 0xffn); v >>= 8n; }
    f[0] = f[0]! | 0x80;
    expect(tarSizeField(f)).toBe(5n * 1024n ** 3n);
  });

  it('rejects malformed fields', () => {
    expect(tarSizeField(Buffer.alloc(11))).toBeUndefined();
    const bad = Buffer.alloc(12);
    bad.write('not-octal!!', 0, 'ascii');
    expect(tarSizeField(bad)).toBeUndefined();
  });
});

// -- TarEntryCounter ------------------------------------------------------------

describe('TarEntryCounter', () => {
  it('counts entries and skips bodies incrementally', () => {
    const tar = tarOfMembers(
      { name: 'a.txt', body: Buffer.alloc(100) },
      { name: 'dir/', type: '5' },
      { name: 'dir/b.bin', body: Buffer.alloc(5000) }
    );
    const c = new TarEntryCounter();
    // Feed in awkward 700-byte slices to prove streaming, not whole-buffer parse.
    for (let i = 0; i < tar.length; i += 700) c.push(tar.subarray(i, i + 700));
    expect(c.entryCount).toBe(3);
    expect(c.complete).toBe(true);
  });

  it('skips base-256 sized bodies without buffering them', () => {
    const body = Buffer.alloc(4096, 0x61);
    const tar = tarOfMembers({ name: 'big', body, base256: true });
    const c = new TarEntryCounter();
    for (let i = 0; i < tar.length; i += 997) c.push(tar.subarray(i, i + 997));
    expect(c.entryCount).toBe(1);
    expect(c.complete).toBe(true);
  });

  it('reports incomplete until the end-of-archive marker is seen', () => {
    const tar = tarOfMembers({ name: 'f', body: Buffer.from('x') });
    const c = new TarEntryCounter();
    // Feed everything except the trailing zero blocks.
    for (let i = 0; i < tar.length - 1024; i += 700) c.push(tar.subarray(i, Math.min(i + 700, tar.length - 1024)));
    expect(c.complete).toBe(false);
    c.push(tar.subarray(tar.length - 1024));
    expect(c.complete).toBe(true);
  });

  it('reports incomplete when the stream ends mid-entry-body', () => {
    const tar = tarOfMembers({ name: 'big', body: Buffer.alloc(4096) });
    const c = new TarEntryCounter();
    c.push(tar.subarray(0, 512 + 100)); // header + partial body, no trailer
    expect(c.entryCount).toBe(1);
    expect(c.complete).toBe(false);
  });

  it('throws past the 50k entry bound', () => {
    const c = new TarEntryCounter();
    const header = tarHeader('f', '0', 0n);
    // 50_001 tiny entries: header-only, no body.
    const chunk = Buffer.concat(Array.from({ length: 1000 }, () => header));
    expect(() => {
      for (let i = 0; i < 51; i += 1) c.push(chunk);
    }).toThrow(/too many tar entries/);
  });
});

// -- inspectTarSafety base-256 ---------------------------------------------------

describe('inspectTarSafety base-256 sizes', () => {
  it('accepts an archive whose member uses a base-256 size field', async () => {
    const dir = tempDir();
    const p = join(dir, 'big.tar');
    const body = Buffer.alloc(8192, 0x62);
    writeFileSync(p, tarOfMembers({ name: 'big.bin', body, base256: true }, { name: 'small.txt', body: Buffer.from('hi') }));
    const r = await inspectTarSafety(p, 1024 * 1024);
    expect(r.safe).toBe(true);
    expect(r.paths).toEqual(['big.bin', 'small.txt']);
  });
});

// -- prepareVmExport -------------------------------------------------------------

describe('prepareVmExport', () => {
  const input = { vmName: 'chm-vm-' + 'a'.repeat(32), guestPath: '/workspace', maxBytes: 1024 * 1024 };

  it('keeps --ro, emits the tar on stdout (`-`), and stages under .exports', async () => {
    const dir = tempDir();
    const tar = tarOfMembers({ name: 'f.txt', body: Buffer.from('hello') });
    const { spawner, calls } = fakeSpawner(tar);
    const prod = await prepareVmExport({ poolPath: dir, spawnAppliance: spawner }, input);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toContain('--ro');
    expect(calls[0]![0]).toBe('virt-tar-out');
    expect(calls[0]![calls[0]!.length - 1]).toBe('-');
    const staged = stagedFiles(dir);
    expect(staged).toHaveLength(1);
    expect(staged[0]!.startsWith(join(dir, '.exports'))).toBe(true);
    expect(staged[0]!.endsWith('.tar')).toBe(true);
    const chunks: Buffer[] = [];
    const trailer = await prod.produce(async (c) => { chunks.push(c); });
    expect(Buffer.concat(chunks).equals(tar)).toBe(true);
    expect(trailer.bytes).toBe(tar.length);
    expect(trailer.entryCount).toBe(1);
    expect(trailer.sha256).toBe(createHash('sha256').update(tar).digest('hex'));
    await prod.cleanup();
    expect(stagedFiles(dir)).toHaveLength(0);
  });

  it('gives concurrent exports of the same VM distinct staging paths', async () => {
    const dir = tempDir();
    const tar = tarOfMembers({ name: 'f', body: Buffer.from('x') });
    const { spawner } = fakeSpawner(tar);
    const [a, b] = await Promise.all([
      prepareVmExport({ poolPath: dir, spawnAppliance: spawner }, input),
      prepareVmExport({ poolPath: dir, spawnAppliance: spawner }, input)
    ]);
    expect(stagedFiles(dir)).toHaveLength(2);
    await a.cleanup();
    await b.cleanup();
    expect(stagedFiles(dir)).toHaveLength(0);
  });

  it('removes the staging file when the appliance exits non-zero', async () => {
    const dir = tempDir();
    const { spawner } = fakeSpawner(null, { exitCode: 1, stderr: 'appliance exploded' });
    await expect(prepareVmExport({ poolPath: dir, spawnAppliance: spawner }, input)).rejects.toThrow(/appliance failed: appliance exploded/);
    expect(stagedFiles(dir)).toHaveLength(0);
  });

  it('removes the staging file when the spawner throws', async () => {
    const dir = tempDir();
    const { spawner } = fakeSpawner(null, { throwSpawn: new Error('spawn ENOENT') });
    await expect(prepareVmExport({ poolPath: dir, spawnAppliance: spawner }, input)).rejects.toThrow(/spawn ENOENT/);
    expect(stagedFiles(dir)).toHaveLength(0);
  });

  it('removes the staging file when the child reports a spawn error', async () => {
    const dir = tempDir();
    const { spawner } = fakeSpawner(tarOfMembers({ name: 'f', body: Buffer.from('x') }), { emitError: new Error('spawn ENOENT virt-tar-out') });
    await expect(prepareVmExport({ poolPath: dir, spawnAppliance: spawner }, input)).rejects.toThrow(/ENOENT/);
    expect(stagedFiles(dir)).toHaveLength(0);
  });

  it('kills and reaps the appliance when stdout exceeds maxBytes during production', async () => {
    const dir = tempDir();
    // 8 KiB of tar against a 1 KiB cap: the sink must stop the child mid-run,
    // not discover the oversize only after virt-tar-out exits.
    const tar = tarOfMembers({ name: 'big', body: Buffer.alloc(8192) });
    const { spawner, procs } = fakeSpawner(tar, { chunkSize: 1024 });
    await expect(
      prepareVmExport({ poolPath: dir, spawnAppliance: spawner }, { ...input, maxBytes: 1024 })
    ).rejects.toThrow(/exceeds maxBytes/);
    expect(procs).toHaveLength(1);
    expect(procs[0]!.killedWith).toBe('SIGKILL');
    // 'close' was awaited before rejection — the child is really reaped.
    expect(procs[0]!.closeEmitted).toBe(true);
    expect(stagedFiles(dir)).toHaveLength(0);
  });

  it('enforces maxBytes mid-stream when the staged file grows after prepare', async () => {
    const dir = tempDir();
    const tar = tarOfMembers({ name: 'big', body: Buffer.alloc(3000) });
    const { spawner } = fakeSpawner(tar);
    const maxBytes = 768 * 1024;
    const prod = await prepareVmExport({ poolPath: dir, spawnAppliance: spawner }, { ...input, maxBytes });
    // The production cap passed on the small tar; grow the staged file so
    // the streaming bound — not the sink — is what must reject.
    const staged = stagedFiles(dir)[0]!;
    const { appendFileSync } = await import('node:fs');
    appendFileSync(staged, Buffer.alloc(1024 * 1024));
    await expect(prod.produce(async () => undefined)).rejects.toThrow(/stream exceeded maxBytes/);
    await prod.cleanup();
    expect(stagedFiles(dir)).toHaveLength(0);
  });

  it('rejects a truncated staged archive at produce time', async () => {
    const dir = tempDir();
    const tar = tarOfMembers({ name: 'f', body: Buffer.from('data') });
    // Drop the end-of-archive zero blocks: entries parse, but the archive
    // is cut short — must not attest as a successful export.
    const truncated = tar.subarray(0, tar.length - 1024);
    const { spawner } = fakeSpawner(truncated);
    const prod = await prepareVmExport({ poolPath: dir, spawnAppliance: spawner }, input);
    await expect(prod.produce(async () => undefined)).rejects.toThrow(/truncated/);
    await prod.cleanup();
    expect(stagedFiles(dir)).toHaveLength(0);
  });

  it('propagates emit errors and leaves cleanup to the caller', async () => {
    const dir = tempDir();
    const tar = tarOfMembers({ name: 'f', body: Buffer.from('x') });
    const { spawner } = fakeSpawner(tar);
    const prod = await prepareVmExport({ poolPath: dir, spawnAppliance: spawner }, input);
    await expect(prod.produce(async () => { throw new Error('client disconnected'); })).rejects.toThrow(/disconnected/);
    await prod.cleanup();
    expect(stagedFiles(dir)).toHaveLength(0);
  });

  it('verifies expectedSha256 trailer', async () => {
    const dir = tempDir();
    const tar = tarOfMembers({ name: 'f', body: Buffer.from('data') });
    const { spawner } = fakeSpawner(tar);
    const good = await prepareVmExport({ poolPath: dir, spawnAppliance: spawner }, { ...input, expectedSha256: createHash('sha256').update(tar).digest('hex') });
    const trailer = await good.produce(async () => undefined);
    expect(trailer.sha256).toBe(createHash('sha256').update(tar).digest('hex'));
    await good.cleanup();
    const bad = await prepareVmExport({ poolPath: dir, spawnAppliance: spawner }, { ...input, expectedSha256: '0'.repeat(64) });
    await expect(bad.produce(async () => undefined)).rejects.toThrow(/digest mismatch/);
    await bad.cleanup();
  });

  it('kills the appliance at the wall-clock timeout and reaps it', async () => {
    const dir = tempDir();
    const { spawner, procs } = fakeSpawner(null, { hang: true });
    await expect(
      prepareVmExport({ poolPath: dir, spawnAppliance: spawner, applianceTimeoutMs: 50 }, input)
    ).rejects.toThrow(/timed out/);
    expect(procs[0]!.killedWith).toBe('SIGKILL');
    expect(procs[0]!.closeEmitted).toBe(true);
    expect(stagedFiles(dir)).toHaveLength(0);
  });

  it('kills the appliance when the caller aborts (disconnect)', async () => {
    const dir = tempDir();
    const { spawner, procs } = fakeSpawner(null, { hang: true });
    const abort = new AbortController();
    const run = prepareVmExport(
      { poolPath: dir, spawnAppliance: spawner },
      { ...input, signal: abort.signal }
    );
    setTimeout(() => abort.abort(), 30);
    await expect(run).rejects.toThrow(/aborted/);
    expect(procs[0]!.killedWith).toBe('SIGKILL');
    expect(procs[0]!.closeEmitted).toBe(true);
    expect(stagedFiles(dir)).toHaveLength(0);
  });

  it('rejects a pre-aborted signal without ever spawning the appliance', async () => {
    const dir = tempDir();
    const { spawner, calls } = fakeSpawner(tarOfMembers({ name: 'f', body: Buffer.from('x') }));
    const abort = new AbortController();
    abort.abort();
    await expect(
      prepareVmExport({ poolPath: dir, spawnAppliance: spawner }, { ...input, signal: abort.signal })
    ).rejects.toThrow(/aborted/);
    expect(calls).toHaveLength(0);
    expect(stagedFiles(dir)).toHaveLength(0);
  });

  it('fails closed when the appliance exits 0 but produces no tar output', async () => {
    const dir = tempDir();
    const { spawner } = fakeSpawner(Buffer.alloc(0));
    await expect(prepareVmExport({ poolPath: dir, spawnAppliance: spawner }, input)).rejects.toThrow(/no tar output/);
    expect(stagedFiles(dir)).toHaveLength(0);
  });
});

// -- real subprocess appliance ----------------------------------------------------
//
// End-to-end proof that the production cap is enforced while the appliance
// runs — not discovered by a post-exit stat. A stub `virt-tar-out` on PATH
// stands in for libguestfs; the real spawnApplianceProcess + bounded sink do
// the rest.

describe('prepareVmExport with a real appliance subprocess', () => {
  const input = { vmName: 'chm-vm-' + 'b'.repeat(32), guestPath: '/workspace', maxBytes: 256 * 1024 };
  let binDir = '';
  let savedPath = '';
  const savedEnv = new Map<string, string | undefined>();

  function installStub(body: string): string {
    binDir = mkdtempSync(join(tmpdir(), 'vm-appliance-bin-'));
    dirs.push(binDir);
    const stub = join(binDir, 'virt-tar-out');
    writeFileSync(stub, `#!/bin/sh\n${body}\n`, { mode: 0o755 });
    chmodSync(stub, 0o755);
    savedPath = process.env.PATH ?? '';
    process.env.PATH = `${binDir}:${savedPath}`;
    return stub;
  }

  function setEnv(key: string, value: string): void {
    if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
    process.env[key] = value;
  }

  afterEach(() => {
    if (savedPath !== '') process.env.PATH = savedPath;
    savedPath = '';
    for (const [key, value] of savedEnv) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
    savedEnv.clear();
  });

  /** Exact liveness for a recorded pid — no process-name matching. */
  function pidAlive(pid: number): boolean {
    try {
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  }

  async function waitForPidGone(pid: number, timeoutMs = 5_000): Promise<boolean> {
    const deadline = Date.now() + timeoutMs;
    while (pidAlive(pid)) {
      if (Date.now() >= deadline) return false;
      await new Promise((r) => setTimeout(r, 50));
    }
    return true;
  }

  /** Poll staged sizes until `done` flips; returns the max observed size. */
  async function observeMaxStaged(dir: string, done: () => boolean): Promise<number> {
    let max = 0;
    while (!done()) {
      for (const f of stagedFiles(dir)) {
        try {
          max = Math.max(max, statSync(f).size);
        } catch {
          // file may be mid-delete
        }
      }
      await new Promise((r) => setTimeout(r, 5));
    }
    return max;
  }

  function readPid(dir: string, name: string): number {
    return Number(readFileSync(join(dir, name), 'utf8').trim());
  }

  it('keeps staged bytes <= maxBytes and kills the whole process group on overflow', async () => {
    const dir = tempDir();
    // A grandchild (backgrounded sleep) inherits the stdout pipe and would
    // keep 'close' pending and the "appliance" alive if only the direct
    // child were killed. It records its own pid; the parent records its pid.
    const stub = installStub(
      `sleep 300 &\n` +
      `echo $! > '${dir}/gcpid'\n` +
      `echo $$ > '${dir}/ppid'\n` +
      `i=0\nwhile [ "$i" -lt 64 ]; do head -c 131072 /dev/zero; i=$((i+1)); sleep 0.05; done`
    );
    expect(stub).toContain('virt-tar-out');
    let settled = false;
    const run = prepareVmExport(
      { poolPath: dir, spawnAppliance: spawnApplianceProcess },
      input
    ).finally(() => { settled = true; });
    const observed = observeMaxStaged(dir, () => settled);
    await expect(run).rejects.toThrow(/exceeds maxBytes/);
    const maxObserved = await observed;
    // The file existed and was written — and never exceeded the reservation.
    expect(maxObserved).toBeGreaterThan(0);
    expect(maxObserved).toBeLessThanOrEqual(input.maxBytes);
    expect(stagedFiles(dir)).toHaveLength(0);
    // BOTH the direct child and the pipe-holding grandchild are gone —
    // exact pid liveness, not name matching.
    const gcpid = readPid(dir, 'gcpid');
    const ppid = readPid(dir, 'ppid');
    expect(gcpid).toBeGreaterThan(0);
    expect(ppid).toBeGreaterThan(0);
    expect(await waitForPidGone(gcpid)).toBe(true);
    expect(await waitForPidGone(ppid)).toBe(true);
  });

  it('streams a valid tar through stdout into the staging file intact', async () => {
    const dir = tempDir();
    const tar = tarOfMembers(
      { name: 'a.txt', body: Buffer.from('hello') },
      { name: 'dir/b.bin', body: Buffer.alloc(5000, 0x63) }
    );
    const fixture = join(dir, 'fixture.tar');
    writeFileSync(fixture, tar);
    installStub(`cat '${fixture}'`);
    const prod = await prepareVmExport(
      { poolPath: dir, spawnAppliance: spawnApplianceProcess },
      { ...input, maxBytes: 1024 * 1024 }
    );
    const chunks: Buffer[] = [];
    const trailer = await prod.produce(async (c) => { chunks.push(c); });
    expect(Buffer.concat(chunks).equals(tar)).toBe(true);
    expect(trailer.bytes).toBe(tar.length);
    expect(trailer.entryCount).toBe(2);
    await prod.cleanup();
    expect(stagedFiles(dir)).toHaveLength(0);
  });

  it('runs the appliance with a minimal allowlisted env — no supervisor secrets', async () => {
    const dir = tempDir();
    const tar = tarOfMembers({ name: 'f', body: Buffer.from('x') });
    const fixture = join(dir, 'fixture.tar');
    writeFileSync(fixture, tar);
    // Hostile inherited values that must NOT survive into the appliance:
    // the supervisor bearer token and a libvirt backend override.
    setEnv('VM_SUPERVISOR_TOKEN', 'super-secret-token');
    setEnv('LIBGUESTFS_BACKEND', 'libvirt');
    installStub(`env > '${dir}/child.env'\ncat '${fixture}'`);
    const prod = await prepareVmExport(
      { poolPath: dir, spawnAppliance: spawnApplianceProcess },
      { ...input, maxBytes: 1024 * 1024 }
    );
    const trailer = await prod.produce(async () => undefined);
    expect(trailer.bytes).toBe(tar.length);
    await prod.cleanup();
    const envTxt = readFileSync(join(dir, 'child.env'), 'utf8');
    expect(envTxt).not.toContain('super-secret-token');
    expect(envTxt).not.toContain('LIBGUESTFS_BACKEND=libvirt');
    expect(envTxt).toContain('LIBGUESTFS_BACKEND=direct');
    expect(envTxt).toContain('HOME=/tmp');
    expect(envTxt).toMatch(/^PATH=/m);
  });

  it('kills a pipe-holding descendant after the appliance parent has already exited', async () => {
    const dir = tempDir();
    // The stub parent spawns a grandchild inheriting stdout/stderr, records
    // both pids, then EXITS immediately — the exact gap where signaling only
    // the leader (or nothing, once exitCode is set) leaves the descendant
    // alive holding the pipes and disk image. The sentinel shim must still
    // be alive (drain-waiting) when the abort lands.
    installStub(
      `sleep 300 &\n` +
      `echo $! > '${dir}/gcpid'\n` +
      `echo $$ > '${dir}/ppid'\n` +
      `exit 0\n`
    );
    const abort = new AbortController();
    const run = prepareVmExport(
      { poolPath: dir, spawnAppliance: spawnApplianceProcess },
      { ...input, signal: abort.signal }
    );
    // Wait until the stub parent is reaped AND the grandchild is confirmed
    // alive — descendant outlived its leader before any cancellation.
    const deadline = Date.now() + 5_000;
    let ppid = 0;
    let gcpid = 0;
    while (Date.now() < deadline) {
      try {
        ppid = readPid(dir, 'ppid');
        gcpid = readPid(dir, 'gcpid');
      } catch {
        // pidfiles not written yet
      }
      if (ppid > 0 && gcpid > 0 && !pidAlive(ppid)) break;
      await new Promise((r) => setTimeout(r, 25));
    }
    expect(ppid).toBeGreaterThan(0);
    expect(gcpid).toBeGreaterThan(0);
    expect(pidAlive(gcpid)).toBe(true);
    abort.abort();
    await expect(run).rejects.toThrow(/aborted/);
    expect(await waitForPidGone(gcpid)).toBe(true);
    expect(stagedFiles(dir)).toHaveLength(0);
  });

  it('kills a hung appliance and its pipe-holding grandchild when the caller aborts', async () => {
    const dir = tempDir();
    // Produces nothing (cannot trip the byte cap before the abort lands);
    // parent and grandchild both idle in the same process group.
    const stub = installStub(
      `sleep 300 &\n` +
      `echo $! > '${dir}/gcpid'\n` +
      `echo $$ > '${dir}/ppid'\n` +
      `exec sleep 300`
    );
    expect(stub).toContain('virt-tar-out');
    const abort = new AbortController();
    const run = prepareVmExport(
      { poolPath: dir, spawnAppliance: spawnApplianceProcess },
      { ...input, signal: abort.signal }
    );
    setTimeout(() => abort.abort(), 200);
    await expect(run).rejects.toThrow(/aborted/);
    expect(stagedFiles(dir)).toHaveLength(0);
    const gcpid = readPid(dir, 'gcpid');
    const ppid = readPid(dir, 'ppid');
    expect(gcpid).toBeGreaterThan(0);
    expect(ppid).toBeGreaterThan(0);
    expect(await waitForPidGone(gcpid)).toBe(true);
    expect(await waitForPidGone(ppid)).toBe(true);
  });
});

// -- round-2 native regressions -------------------------------------------------

describe('TarEntryCounter metadata-header parity', () => {
  it('does not count GNU longname/longlink or PAX headers as entries', () => {
    // 'L' header carrying a >100-byte name, 'K' longlink, 'x' pax — none are
    // members; inspectTarSafety applies the same rule so counts stay equal.
    const longName = 'd/'.repeat(80) + 'file.txt'; // >100 bytes → GNU 'L' in real tars
    const lBody = Buffer.from(longName + '\0');
    const kBody = Buffer.from('some/link/target\0');
    const xBody = Buffer.from('27 path=real-name.txt\n');
    const fileBody = Buffer.from('data');
    const tar = Buffer.concat([
      tarHeader('L', 'L', BigInt(lBody.length)), lBody, Buffer.alloc(((lBody.length + 511) / 512 | 0) * 512 - lBody.length),
      tarHeader('K', 'K', BigInt(kBody.length)), kBody, Buffer.alloc(((kBody.length + 511) / 512 | 0) * 512 - kBody.length),
      tarHeader('x', 'x', BigInt(xBody.length)), xBody, Buffer.alloc(((xBody.length + 511) / 512 | 0) * 512 - xBody.length),
      tarHeader('real-name.txt', '0', BigInt(fileBody.length)), fileBody, Buffer.alloc(512 - fileBody.length),
      Buffer.alloc(1024)
    ]);
    const c = new TarEntryCounter();
    for (let i = 0; i < tar.length; i += 700) c.push(tar.subarray(i, i + 700));
    expect(c.entryCount).toBe(1);
    expect(c.complete).toBe(true);
  });
});

describe('inspectTarSafety global PAX rejection', () => {
  it('rejects an archive carrying a global extended header', async () => {
    const dir = tempDir();
    const p = join(dir, 'global-pax.tar');
    // 'g' header smuggling an escaping path keyword + one normal member.
    const gBody = Buffer.from('30 path=../escape.txt\n');
    const member = Buffer.from('x');
    const tar = Buffer.concat([
      tarHeader('g', 'g', BigInt(gBody.length)), gBody, Buffer.alloc(((gBody.length + 511) / 512 | 0) * 512 - gBody.length),
      tarHeader('ok.txt', '0', BigInt(member.length)), member, Buffer.alloc(512 - member.length),
      Buffer.alloc(1024)
    ]);
    writeFileSync(p, tar);
    const r = await inspectTarSafety(p, 1024 * 1024);
    expect(r.safe).toBe(false);
    expect(r.reason).toMatch(/global PAX/i);
  });
});

describe('prepareVmExport produce abort', () => {
  it('stops emitting and never reports success when the caller aborts mid-stream', async () => {
    const dir = tempDir();
    const tar = tarOfMembers({ name: 'f.txt', body: Buffer.alloc(64 * 1024, 0x61) });
    const { spawner } = fakeSpawner(tar);
    const ac = new AbortController();
    const prod = await prepareVmExport(
      { poolPath: dir, spawnAppliance: spawner },
      { vmName: 'chm-vm-' + 'b'.repeat(32), guestPath: '/workspace', maxBytes: 1024 * 1024, signal: ac.signal }
    );
    let emitted = 0;
    await expect(prod.produce(async () => {
      emitted += 1;
      // The staged archive fits one stream chunk, so the abort lands on the
      // final emit — the post-loop guard must still fail the export.
      if (emitted === 1) ac.abort();
    })).rejects.toThrow(/export aborted/i);
    await prod.cleanup();
  });
});

describe('staging sink failure and reap-timer hygiene (gap regressions)', () => {
  const input = { vmName: 'chm-vm-' + 'c'.repeat(32), guestPath: '/workspace', maxBytes: 1024 * 1024 };

  it('fails promptly when the staging file is unwritable — dead sink kills the producer', async () => {
    const dir = tempDir();
    const tar = tarOfMembers({ name: 'f', body: Buffer.alloc(256 * 1024) });
    const { spawner, procs } = fakeSpawner(tar, { chunkSize: 64 * 1024 });
    // .exports -> /sys: read-only for EVERY uid (even root gets EROFS), so
    // the staging open/write fails deterministically mid-run.
    symlinkSync('/sys', join(dir, '.exports'));
    const started = Date.now();
    await expect(prepareVmExport({ poolPath: dir, spawnAppliance: spawner }, input))
      .rejects.toThrow(/export appliance failed/);
    // Prompt fileError — NOT a ride to the appliance timeout.
    expect(Date.now() - started).toBeLessThan(15_000);
    expect(procs[0]!.killedWith).toBeDefined();
  });

  it('leaves no lingering reap timer after a fast clean close', async () => {
    const dir = tempDir();
    const tar = tarOfMembers({ name: 'f', body: Buffer.from('x') });
    const { spawner } = fakeSpawner(tar);
    // process._getActiveHandles() cannot see ordinary setTimeout timers.
    // Fake ONLY the timer functions — setImmediate stays real so the fake
    // appliance's 'close' still fires — and count what the export actually
    // leaves armed. A leaked REAP_TIMEOUT_MS timer would stay counted.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      const before = vi.getTimerCount();
      const prod = await prepareVmExport({ poolPath: dir, spawnAppliance: spawner }, input);
      await prod.produce(async () => undefined);
      await prod.cleanup();
      // 'close' wins the awaitClose race; its 5s reap timer must be cleared
      // in finally — a retained timer per export would accumulate here.
      expect(vi.getTimerCount()).toBe(before);
    } finally {
      vi.useRealTimers();
    }
  });
});
