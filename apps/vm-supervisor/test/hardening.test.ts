import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Readable } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { IncusClient, IncusExecSessionRequest } from '../src/incus.js';
import { IncusExecSession } from '../src/incus-exec.js';
import { VmJournal } from '../src/journal.js';
import { VmLifecycle } from '../src/lifecycle.js';
import { VmSessionManager } from '../src/sessions.js';
import { vmNameForWorkspace } from '../src/identity.js';
import { inspectTarSafety } from '../src/tar-safety.js';
import { WIRE_LIMITS } from '../src/transport.js';
import type { VmSupervisorConfig } from '../src/config.js';
import { writeFileSync } from 'node:fs';

/**
 * Hardening coverage for the independent-review findings: tar cross-entry
 * link canonicalization, guest-side destination link-ancestor rejection,
 * pushTree mkdir-before-extract, and the file.pull inline envelope proof.
 */

const WORKSPACE_ID = 'ws_hardening_workspace_01';
const INSTANCE_ID = '11111111-2222-4333-8444-555555555555';
const VM_NAME = vmNameForWorkspace(WORKSPACE_ID);

function makeConfig(dir: string): VmSupervisorConfig {
  return {
    socketPath: join(dir, 'supervisor.sock'),
    token: 't'.repeat(48),
    stateDir: dir,
    incusSocketPath: '/nonexistent/incus.sock',
    incusProject: 'cloud-harness',
    guardStatePath: join(dir, 'guard-state.json'),
    bridgePattern: 'chmbr%d',
    subnetPlan: '10.240.0.0/16',
    uplink: '',
    dnsResolvers: ['10.0.0.2'],
    nonpublicCidrs: [],
    poolPath: dir,
    maxTtlSeconds: 3600,
    maxActive: 4,
    cpus: 4,
    memoryBytes: 8 * 1024 ** 3,
    diskBytes: 20 * 1024 ** 3,
    poolReserveBytes: 1024 ** 3,
    templateId: 'cloudharness-vm-debian13',
    templateDigest: 'a'.repeat(64)
  };
}

// -- minimal tar writer (parser does not verify checksums) --------------------

function tarEntry(name: string, type: string, link = '', body = ''): Buffer {
  const h = Buffer.alloc(512);
  h.write(name.slice(0, 100), 0, 'utf8');
  h.write('0000644\0', 100);
  h.write('0000000\0', 108);
  h.write('0000000\0', 116);
  const size = Buffer.byteLength(body);
  h.write(size.toString(8).padStart(11, '0') + '\0', 124);
  h.write(type, 156);
  h.write(link.slice(0, 100), 157, 'utf8');
  h.write('ustar\0', 257);
  h.write('00', 263);
  const pad = (512 - (size % 512)) % 512;
  return Buffer.concat([h, Buffer.from(body), Buffer.alloc(pad)]);
}

function tarOf(...entries: Buffer[]): Buffer {
  return Buffer.concat([...entries, Buffer.alloc(1024)]);
}

async function inspect(entries: Buffer[]) {
  const dir = mkdtempSync(join(tmpdir(), 'vmtar-'));
  try {
    const p = join(dir, 'a.tar');
    writeFileSync(p, tarOf(...entries));
    return await inspectTarSafety(p, 64 * 1024 * 1024);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe('tar-safety cross-entry link canonicalization', () => {
  it('rejects a member nested beneath an earlier symlink entry', async () => {
    const r = await inspect([
      tarEntry('a', '2', 'b'),
      tarEntry('a/x', '0', '', 'data')
    ]);
    expect(r.safe).toBe(false);
    expect(r.reason).toContain('nests beneath link');
  });

  it('rejects hardlink targets that are not regular archive members', async () => {
    const r = await inspect([
      tarEntry('h', '1', 'missing')
    ]);
    expect(r.safe).toBe(false);
    expect(r.reason).toContain('hardlink');
  });

  it('rejects hardlinks to symlink members and members under link paths', async () => {
    const r = await inspect([
      tarEntry('l', '2', 'real'),
      tarEntry('h', '1', 'l')
    ]);
    expect(r.safe).toBe(false);
  });

  it('accepts confined symlinks and hardlinks to regular members, returns paths', async () => {
    const r = await inspect([
      tarEntry('dir/', '5'),
      tarEntry('dir/f', '0', '', 'x'),
      tarEntry('l', '2', 'dir/f'),
      tarEntry('h', '1', 'dir/f')
    ]);
    expect(r.safe).toBe(true);
    expect(r.paths).toEqual(['dir/', 'dir/f', 'l', 'h']);
  });
});

// -- extractTarStream: mkdir + guest link-ancestor scan -----------------------

interface CapturedSpec {
  spec: IncusExecSessionRequest;
  events: {
    onStdout(chunk: Buffer): void;
    onStderr(chunk: Buffer): void;
    onMeta?(message: unknown): void;
    onExit(result: { exitCode: number | null; signal: string | null; metadata?: unknown }): void;
    onTransportError(error: Error): void;
  };
  session: {
    exitInfo: { exitCode: number | null; signal: string | null } | undefined;
    writeStdin: ReturnType<typeof vi.fn>;
    stdinEof: ReturnType<typeof vi.fn>;
    signal: ReturnType<typeof vi.fn>;
    resize: ReturnType<typeof vi.fn>;
    closeAll: ReturnType<typeof vi.fn>;
  };
}

const fakeIncus = {
  openExecFds: async () => ({ channels: {}, operation: '/1.0/operations/fake' }),
  waitExecExit: async () => ({ exitCode: 0, signal: null })
} as unknown as IncusClient;
let dir: string;
let journal: VmJournal;
let sessions: VmSessionManager;
let captured: CapturedSpec[];

function stubFor(spec: IncusExecSessionRequest): CapturedSpec['session'] {
  const s: CapturedSpec['session'] = {
    exitInfo: undefined,
    writeStdin: vi.fn(() => true),
    stdinEof: vi.fn(() => { s.exitInfo = { exitCode: 0, signal: null }; }),
    signal: vi.fn(() => true),
    resize: vi.fn(() => true),
    closeAll: vi.fn(),
    waitStdinDrain: vi.fn(async () => undefined)
  };
  // mkdir + tar sessions resolve via exitInfo polling; find resolves via events.
  // Guest commands arrive runuser-wrapped: [..., '--', 'mkdir', '-p', path].
  if (spec.command.includes('mkdir')) s.exitInfo = { exitCode: 0, signal: null };
  return s;
}

async function waitFor(cond: () => boolean, ms = 5_000): Promise<void> {
  const start = Date.now();
  while (!cond()) {
    if (Date.now() - start > ms) throw new Error('waitFor timeout');
    await new Promise((r) => setTimeout(r, 10));
  }
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'vmsup-hardening-'));
  const config = makeConfig(dir);
  journal = new VmJournal(join(dir, 'journal.sqlite'));
  journal.recordWorkspaceAdmit({
    workspaceId: WORKSPACE_ID, vmName: VM_NAME, instanceId: INSTANCE_ID,
    templateId: config.templateId, templateDigest: config.templateDigest,
    generation: 1, networkProfile: 'network-none'
  });
  journal.setWorkspaceState(WORKSPACE_ID, 'running');
  journal.acceptGeneration(WORKSPACE_ID, 1);
  const lifecycle = new VmLifecycle({
    config, journal, incus: fakeIncus, guard: async () => { throw new Error('unused'); }
  });
  sessions = new VmSessionManager({
    journal, incus: fakeIncus, incusSocketPath: config.incusSocketPath, lifecycle
  });
  captured = [];
  vi.spyOn(IncusExecSession, 'open').mockImplementation(async (_c, _s, _n, spec, events) => {
    const session = stubFor(spec);
    captured.push({ spec, events: events as CapturedSpec['events'], session });
    return session as unknown as IncusExecSession;
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  journal.close();
  rmSync(dir, { recursive: true, force: true });
});

describe('extractTarStream guest safety', () => {
  it('runs mkdir -p as guest user, link-scans, then extracts with exact argv', async () => {
    const p = extract(['sub/file']);
    await waitFor(() => captured.length >= 2);
    // find session: report no symlinks, exit 0
    captured[1]!.events.onStdout(Buffer.from(''));
    captured[1]!.events.onExit({ exitCode: 0, signal: null });
    await waitFor(() => captured.length >= 3);
    const out = await p;
    expect(out.exitCode).toBe(0);
    expect(captured[0]!.spec.command).toEqual(['/usr/sbin/runuser', '-p', '-u', 'harness', '--', 'mkdir', '-p', '/workspace/dest']);
    // openAndCapture wraps workspace argv in the runuser drop.
    expect(captured[1]!.spec.command).toEqual([
      '/usr/sbin/runuser', '-p', '-u', 'harness', '--',
      'find', '-H', '/workspace/dest', '-type', 'l', '-printf', '%P\n'
    ]);
    expect(captured[2]!.spec.command).toEqual(['/usr/sbin/runuser', '-p', '-u', 'harness', '--', 'tar', '-xf', '-', '-C', '/workspace/dest', '--no-same-owner', '--no-same-permissions']);
  });

  it('rejects when a pre-existing guest symlink is an ancestor of an entry', async () => {
    const p = extract(['sub/file']);
    await waitFor(() => captured.length >= 2);
    captured[1]!.events.onStdout(Buffer.from('sub\nother/link\n'));
    captured[1]!.events.onExit({ exitCode: 0, signal: null });
    await expect(p).rejects.toThrow(/existing symlink/);
    // tar session must never open
    expect(captured).toHaveLength(2);
  });

  it('skips the link scan when no entry paths are supplied', async () => {
    const p = extract(undefined, undefined);
    await waitFor(() => captured.length >= 2);
    const out = await p;
    expect(out.exitCode).toBe(0);
    expect(captured).toHaveLength(2); // mkdir + tar only
    expect(captured[1]!.spec.command).toEqual([
      '/usr/sbin/runuser', '-p', '-u', 'harness', '--',
      'tar', '-xf', '-', '-C', '/workspace/dest', '--no-same-owner', '--no-same-permissions'
    ]);
  });
});

function extract(entryPaths?: string[]) {
  return sessions.extractTarStream({
    workspaceId: WORKSPACE_ID,
    vmName: VM_NAME,
    guestPath: '/workspace/dest',
    tar: Readable.from([Buffer.from('tar-bytes')]),
    tarBytes: 9,
    ...(entryPaths !== undefined ? { entryPaths } : {})
  });
}

// -- file.pull inline envelope proof ------------------------------------------

describe('file.pull inline envelope', () => {
  it('720KiB raw fits the 1MiB control frame as base64 JSON', () => {
    // Mirror server.ts FILE_PULL_INLINE_MAX = 720 * 1024.
    const raw = 720 * 1024;
    const b64 = Buffer.alloc(raw).toString('base64');
    const frame = JSON.stringify({
      type: 'response',
      response: { ok: true, result: { op: 'file.pull', dataBase64: b64 } }
    });
    expect(Buffer.byteLength(frame, 'utf8')).toBeLessThan(WIRE_LIMITS.maxControlBytes);
    // And the previous 4MiB cap would NOT have fit — proving the fix mattered.
    const oversized = Buffer.alloc(4 * 1024 * 1024).toString('base64');
    const bad = JSON.stringify({ type: 'response', response: { ok: true, result: { dataBase64: oversized } } });
    expect(Buffer.byteLength(bad, 'utf8')).toBeGreaterThan(WIRE_LIMITS.maxControlBytes);
  });
});
