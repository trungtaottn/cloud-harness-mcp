import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { IncusClient } from '../src/incus.js';
import type { IncusExecSessionRequest } from '../src/incus.js';
import { IncusExecSession } from '../src/incus-exec.js';
import { VmJournal } from '../src/journal.js';
import { VmLifecycle } from '../src/lifecycle.js';
import { VmSessionManager } from '../src/sessions.js';
import { RequestDigester } from '../src/request-digest.js';
import { createSupervisorHandler } from '../src/server.js';
import { VmSupervisorWireServer } from '../src/transport.js';
import { identityConfigBlock } from '../src/identity.js';
import type { VmNetworkGuard } from '../src/network-ops.js';
import type { VmWorkspaceSubjectPlanner } from '../src/network-plan.js';
import type { VmSupervisorConfig } from '../src/config.js';
import { VmSupervisorClient } from '../../runner/src/vm-supervisor-client.js';

/**
 * REAL end-to-end: the published runner VmSupervisorClient talks the actual
 * wire protocol to the actual supervisor handler over a real unix socket,
 * with only Incus/kernel seams faked. Covers the review's demand for
 * client->handler integration rather than incompatible fake twins:
 * admit -> create -> start -> file.push/pull -> pushTree/pullTree streams
 * -> exec.open session output.
 */

const WORKSPACE_ID = 'ws_clientint_workspace_01';
const INSTANCE_ID = '11111111-2222-4333-8444-555555555555';
const TOKEN = 't'.repeat(48);
const TEMPLATE_ID = 'cloudharness-vm-debian13';
const TEMPLATE_DIGEST = 'a'.repeat(64);

function makeConfig(dir: string): VmSupervisorConfig {
  return {
    socketPath: join(dir, 'supervisor.sock'),
    token: TOKEN,
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
    diskBytes: 4 * 1024 ** 3,
    poolReserveBytes: 1024 ** 3,
    templateId: TEMPLATE_ID,
    templateDigest: TEMPLATE_DIGEST
  };
}

interface FakeInstance {
  name: string; status: string; statusCode: number;
  expandedConfig: Record<string, string>;
  expandedDevices: Record<string, unknown>;
  profiles: string[];
}

function managedConfig(): Record<string, string> {
  return {
    ...identityConfigBlock({
      workspaceId: WORKSPACE_ID, instanceId: INSTANCE_ID,
      templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST
    }),
    'boot.autostart': 'false',
    'limits.cpu': '4',
    'limits.memory': String(8 * 1024 ** 3)
  };
}

class FakeIncus {
  instances = new Map<string, FakeInstance>();
  writtenFiles = new Map<string, Buffer>();
  asClient(): IncusClient {
    const mk = (name: string, status: string): FakeInstance => ({
      name, status, statusCode: 0,
      expandedConfig: managedConfig(),
      expandedDevices: { root: { type: 'disk', path: '/', pool: 'default', size: String(4 * 1024 ** 3) } },
      profiles: []
    });
    return {
      listInstances: async () => [...this.instances.values()],
      getInstance: async (n: string) => this.instances.get(n) ?? null,
      getInstanceState: async (n: string) => {
        const i = this.instances.get(n);
        return i === undefined ? null : { status: i.status, statusCode: 0 };
      },
      createInstance: async (spec: { name: string }) => {
        this.instances.set(spec.name, mk(spec.name, 'Stopped'));
        return { synchronous: true };
      },
      setInstanceState: async (n: string, action: string) => {
        const i = this.instances.get(n);
        if (i !== undefined) i.status = action === 'start' ? 'Running' : 'Stopped';
        return { synchronous: true };
      },
      deleteInstance: async (n: string) => { this.instances.delete(n); return { synchronous: true }; },
      waitOperation: async () => ({ elapsedMs: 1, status: 'Success' }),
      findPoolNameBySourcePath: async () => 'default',
      openExecFds: async () => ({ fds: [] }),
      readInstanceFile: async (n: string, p: string) => this.writtenFiles.get(`${n}:${p}`) ?? Buffer.from(''),
      writeInstanceFile: async (n: string, p: string, data: Buffer) => { this.writtenFiles.set(`${n}:${p}`, data); },
      writeInstanceFileStream: async (n: string, p: string, data: Buffer) => { this.writtenFiles.set(`${n}:${p}`, data); },
      deleteInstanceFile: async () => undefined,
      listInstancePath: async () => []
    } as unknown as IncusClient;
  }
}

function makeGuard(): VmNetworkGuard {
  return {
    program: async () => ({ rulesetDigest: 'b'.repeat(64) }),
    attest: async () => ({ ok: true, rulesetDigest: 'b'.repeat(64) }),
    tearDown: async () => ({ removed: true as const }),
    quarantine: async () => ({ quarantined: true, outcomes: [] }),
    withStartTransaction: async (_args, fn) => fn({
      program: async () => ({ rulesetDigest: 'b'.repeat(64) }),
      attest: async () => ({ ok: true, rulesetDigest: 'b'.repeat(64) })
    })
  };
}

function makePlanner(): VmWorkspaceSubjectPlanner {
  return {
    plan: ({ workspaceId, vmName }) => ({
      workspaceId, vmName, slotIndex: 3, bridgeName: 'chmbr3',
      hostIp: '10.240.0.13', guestIp: '10.240.0.14', prefixLength: 30,
      mac: '02:00:00:00:00:03', tapName: 'chmvt3'
    }),
    stamp: () => ({
      type: 'nic', nictype: 'bridged', parent: 'chmbr3', name: 'eth0',
      hwaddr: '02:00:00:00:00:03', host_name: 'chmvt3',
      'ipv4.address': '10.240.0.14/30',
      'security.mac_filtering': 'true', 'security.ipv4_filtering': 'true', 'security.ipv6_filtering': 'true'
    }),
    findCollisions: () => []
  };
}

// -- tiny tar writer for the pushTree payload ---------------------------------
function tarEntry(name: string, body: string): Buffer {
  const h = Buffer.alloc(512);
  h.write(name.slice(0, 100), 0, 'utf8');
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  const size = Buffer.byteLength(body);
  h.write(size.toString(8).padStart(11, '0') + '\0', 124);
  h.write('0', 156);
  h.write('ustar\0', 257); h.write('00', 263);
  const pad = (512 - (size % 512)) % 512;
  return Buffer.concat([h, Buffer.from(body), Buffer.alloc(pad)]);
}
const TAR_PAYLOAD = Buffer.concat([
  tarEntry('hello.txt', 'hello from runner'),
  Buffer.alloc(1024)
]);
const TAR_SHA = createHash('sha256').update(TAR_PAYLOAD).digest('hex');

let dir: string;
let server: VmSupervisorWireServer;
let client: VmSupervisorClient;
let incus: FakeIncus;
let journal: VmJournal;
let sessions: VmSessionManager;

const IDENTITY = { workspaceId: WORKSPACE_ID, generation: 1, instanceId: INSTANCE_ID };

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), 'vmsup-clientint-'));
  const config = makeConfig(dir);
  journal = new VmJournal(join(dir, 'journal.sqlite'));
  const digester = new RequestDigester(join(dir, 'hmac-key'));
  incus = new FakeIncus();
  const incusClient = incus.asClient();
  const lifecycle = new VmLifecycle({
    config, journal, incus: incusClient, guard: async () => makeGuard()
  });
  sessions = new VmSessionManager({
    journal, incus: incusClient, incusSocketPath: config.incusSocketPath, lifecycle
  });
  // Incus exec transport is a WebSocket seam — stub the manager methods that
  // need it; everything else (wire, staging, tar validation, idempotency)
  // runs for real.
  vi.spyOn(sessions, 'extractTarStream').mockResolvedValue({ exitCode: 0, signal: null, stderr: '' });
  vi.spyOn(sessions, 'streamGuestTar').mockImplementation(async ({ emit }) => {
    await emit(TAR_PAYLOAD.subarray(0, 2048));
    return { sha256: TAR_SHA, bytes: TAR_PAYLOAD.length, entryCount: 1 };
  });
  vi.spyOn(sessions, 'openAndCapture').mockResolvedValue({
    opId: 'stub', exitCode: 0, signal: null, stdout: '', stderr: '', truncated: false, timedOut: false
  });
  const handler = createSupervisorHandler({
    config, journal, digester, incus: incusClient, incusSocketPath: config.incusSocketPath,
    lifecycle, sessions, guard: async () => makeGuard(), networkPlan: async () => makePlanner(),
    execFile: async () => ({ exitCode: 0, stdout: '', stderr: '', timedOut: false, truncated: false })
  });
  server = new VmSupervisorWireServer({
    socketPath: config.socketPath, token: TOKEN, handler, streamDir: join(dir, 'streams')
  });
  await server.listen();
  client = new VmSupervisorClient({ socketPath: config.socketPath, token: TOKEN });
});

afterEach(async () => {
  client?.close();
  await server?.close();
  vi.restoreAllMocks();
  journal?.close();
  rmSync(dir, { recursive: true, force: true });
});

describe('runner client -> real supervisor handler (FakeIncus)', () => {
  it('runs admit->create->start->file.push->file.pull over the real wire', async () => {
    const admit = await client.vmAdmit(IDENTITY, { networkProfile: 'network-none' });
    expect(admit.decision).toBe('admitted');
    const created = await client.vmCreate(IDENTITY, {
      instanceId: INSTANCE_ID, networkProfile: 'network-none',
      templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST
    });
    expect(created.state).toBe('stopped');
    const started = await client.vmStart(IDENTITY, { networkProfile: 'network-none' });
    expect(started.state).toBe('running');
    const payload = Buffer.from('wire payload');
    const sha = createHash('sha256').update(payload).digest('hex');
    const pushed = await client.filePush(IDENTITY, {
      guestPath: '/workspace/pushed.bin',
      dataBase64: payload.toString('base64'),
      sha256: sha, maxBytes: 1024 * 1024
    });
    expect(pushed.sha256).toBe(sha);
    const pulled = await client.filePull(IDENTITY, { guestPath: '/workspace/pushed.bin', maxBytes: 700 * 1024 });
    expect(Buffer.from(pulled.dataBase64, 'base64').toString()).toBe('wire payload');
    expect(pulled.sha256).toBe(sha);
  });

  it('streams pushTree upload and pullTree download through the real protocol', async () => {
    await client.vmAdmit(IDENTITY, { networkProfile: 'network-none' });
    await client.vmCreate(IDENTITY, {
      instanceId: INSTANCE_ID, networkProfile: 'network-none',
      templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST
    });
    await client.vmStart(IDENTITY, { networkProfile: 'network-none' });
    const pushed = await client.pushTree(
      IDENTITY,
      { guestPath: '/workspace/tree', maxBytes: 64 * 1024 * 1024, sha256: TAR_SHA },
      [TAR_PAYLOAD]
    );
    expect(pushed.sha256).toBe(TAR_SHA);
    const chunks: Buffer[] = [];
    const trailer = await client.pullTree(
      IDENTITY,
      { guestPath: '/workspace/tree', maxBytes: 64 * 1024 * 1024 },
      { sink: (c) => { chunks.push(c); } }
    );
    expect(trailer.sha256).toBe(TAR_SHA);
    expect(Buffer.concat(chunks).equals(TAR_PAYLOAD.subarray(0, 2048))).toBe(true);
  });

  it('delivers exec.open session output end-to-end over the socket', async () => {
    await client.vmAdmit(IDENTITY, { networkProfile: 'network-none' });
    await client.vmCreate(IDENTITY, {
      instanceId: INSTANCE_ID, networkProfile: 'network-none',
      templateId: TEMPLATE_ID, templateDigest: TEMPLATE_DIGEST
    });
    await client.vmStart(IDENTITY, { networkProfile: 'network-none' });
    const session = await client.execOpen(IDENTITY, {
      sessionId: 'sess-e2e',
      argv: ['/bin/echo', 'hi'],
      cwd: '/workspace',
      environment: { PATH: '/usr/bin' }
    });
    const got: Buffer[] = [];
    session.onData((_fd, chunk) => { got.push(chunk); });
    const ended = session.ended;
    // Drive the fake guest exec: emit stdout then exit through the captured handlers.
    await vi.waitFor(() => { expect(capturedExecs.length).toBeGreaterThan(0); });
    capturedExecs[0]!.events.onStdout(Buffer.from('hello-guest'));
    capturedExecs[0]!.events.onExit({ exitCode: 0, signal: null, metadata: { return: 0 } });
    const meta = await ended;
    expect(meta.exitCode).toBe(0);
    expect(Buffer.concat(got).toString()).toBe('hello-guest');
    session.close();
  });
});

// Captured IncusExecSession.open invocations for the session test.
interface CapturedExec {
  spec: IncusExecSessionRequest;
  events: {
    onStdout(chunk: Buffer): void;
    onStderr(chunk: Buffer): void;
    onMeta?(message: unknown): void;
    onExit(result: { exitCode: number | null; signal: string | null; metadata?: unknown }): void;
    onTransportError(error: Error): void;
  };
}
const capturedExecs: CapturedExec[] = [];

beforeEach(() => {
  capturedExecs.length = 0;
  vi.spyOn(IncusExecSession, 'open').mockImplementation(async (_c, _s, _n, spec, events) => {
    capturedExecs.push({ spec, events: events as CapturedExec['events'] });
    return {
      writeStdin: () => true, stdinEof: () => undefined, signal: () => true,
      resize: () => true, closeAll: () => undefined,
      pauseOutputChannels: () => undefined, resumeOutputChannels: () => undefined,
      get exitInfo() { return undefined; }
    } as unknown as IncusExecSession;
  });
});
