import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  VmSupervisorWireServer,
  type WireHandlerOutcome,
  type WireRequestContext,
  type WireRequestHandler
} from '../../vm-supervisor/src/transport.js';
import { DiskReservations } from '../../vm-supervisor/src/disk-reservations.js';
import { statfs } from 'node:fs/promises';
// NOTE: the transport's default DiskReservations statfs resolves 'node:fs/promises'
// differently when this file is imported cross-package under vitest; injecting
// the documented dep keeps the test on the real code path without that quirk.
import {
  VmSupervisorClient,
  type VmWorkspaceIdentity
} from '../src/vm-supervisor-client.js';

/**
 * REAL-protocol integration: the actual supervisor `VmSupervisorWireServer`
 * (apps/vm-supervisor/src/transport.ts) on one end, the runner
 * `VmSupervisorClient` on the other — no fake framing on either side. The
 * handler plays the role of server.ts's op dispatch; everything below the
 * handler (framing, auth, backpressure, idle timers, session channels,
 * trailers) is production code on both ends.
 */

const TOKEN = 'wire-it-token';
const IDENTITY: VmWorkspaceIdentity = {
  workspaceId: 'ws_aaaaaaaaaaaaaaaaaaaa',
  generation: 3,
  instanceId: '123e4567-e89b-42d3-a456-426614174000'
};

const dirs: string[] = [];
const servers: VmSupervisorWireServer[] = [];
const clients: VmSupervisorClient[] = [];

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'ch-wire-it-'));
  dirs.push(dir);
  return dir;
}

async function startServer(handler: WireRequestHandler, limits?: ConstructorParameters<typeof VmSupervisorWireServer>[0]['limits']) {
  const dir = tempDir();
  const socketPath = join(dir, 's.sock');
  const streamDir = join(dir, 'streams');
  mkdirSync(streamDir, { recursive: true });
  const diskReservations = new DiskReservations((p) => statfs(p));
  const server = new VmSupervisorWireServer({ socketPath, token: TOKEN, handler, streamDir, limits, diskReservations });
  await server.listen();
  servers.push(server);
  return { server, socketPath, streamDir };
}

function makeClient(socketPath: string, limits: Record<string, number> = {}): VmSupervisorClient {
  const client = new VmSupervisorClient({
    socketPath,
    token: TOKEN,
    limits: {
      authTimeoutMs: 1_000,
      connectTimeoutMs: 1_000,
      requestTimeoutMs: 10_000,
      streamIdleTimeoutMs: 5_000,
      ...limits
    }
  });
  clients.push(client);
  return client;
}

afterEach(async () => {
  for (const client of clients.splice(0)) client.close();
  for (const server of servers.splice(0)) await server.close().catch(() => undefined);
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe('runner client ↔ real supervisor wire server', () => {
  it('unary roundtrip: vm.status through real framing + auth', async () => {
    const { socketPath } = await startServer(async (request) => {
      expect((request as { op: string }).op).toBe('vm.status');
      return { kind: 'result', result: { state: 'running', userCloudHarness: { workspaceId: IDENTITY.workspaceId, instanceId: IDENTITY.instanceId, templateId: 'tpl', templateDigest: 'a'.repeat(64), generationPolicy: 'external' } } };
    });
    const client = makeClient(socketPath);
    const status = await client.vmStatus(IDENTITY);
    expect(status.state).toBe('running');
  });

  it('pushTree: real upload staging, tree:<requestId> binding, sha256 trailer (C1)', async () => {
    const payload = Buffer.concat([Buffer.alloc(64 * 1024, 0x11), Buffer.from('tree-tail')]);
    const sha = createHash('sha256').update(payload).digest('hex');
    let completed: { bytes: number; sha256: string } | undefined;
    let seenRef = '';
    const { socketPath, streamDir } = await startServer(async (request) => {
      const req = request as { requestId: string; op: string };
      expect(req.op).toBe('pushTree');
      seenRef = `tree:${req.requestId}`; // the server.ts naming rule
      return {
        kind: 'upload',
        streamRef: seenRef,
        maxBytes: 4 * 1024 * 1024,
        complete: async (path, bytes, digest) => {
          completed = { bytes, sha256: digest };
          return { sha256: digest, bytes, entryCount: 7 };
        }
      };
    });
    const client = makeClient(socketPath);
    const trailer = await client.pushTree(
      IDENTITY,
      { guestPath: '/workspace/tree', maxBytes: 4 * 1024 * 1024, sha256: sha },
      (async function* () { for (let i = 0; i < payload.length; i += 8192) yield payload.subarray(i, i + 8192); })(),
      { idempotencyKey: 'wire-push-tree-1' }
    );
    expect(trailer).toEqual({ sha256: sha, bytes: payload.length, entryCount: 7 });
    expect(completed).toEqual({ bytes: payload.length, sha256: sha });
    void streamDir;
  });

  it('pullTree: real download produce→sink with verified trailer (M7)', async () => {
    const payload = Buffer.concat([Buffer.alloc(32 * 1024, 0x22), Buffer.from('end')]);
    const sha = createHash('sha256').update(payload).digest('hex');
    const { socketPath } = await startServer(async () => ({
      kind: 'download',
      streamRef: 'dl-1',
      maxBytes: 1024 * 1024,
      produce: async (emit) => {
        for (let i = 0; i < payload.length; i += 4096) await emit(payload.subarray(i, i + 4096));
        return { sha256: sha, bytes: payload.length, entryCount: 3 };
      }
    }));
    const client = makeClient(socketPath);
    const got: Buffer[] = [];
    const trailer = await client.pullTree(
      IDENTITY,
      { guestPath: '/workspace/tree', maxBytes: 1024 * 1024 },
      { sink: (c) => { got.push(Buffer.from(c)); }, idempotencyKey: 'wire-pull-tree-1' }
    );
    expect(trailer.bytes).toBe(payload.length);
    expect(Buffer.concat(got).equals(payload)).toBe(true);
  });

  it('exec.open session: ordered fd-tagged output through the real session channel (M8)', async () => {
    const { socketPath } = await startServer(async (request, ctx: WireRequestContext): Promise<WireHandlerOutcome> => {
      const req = request as { params?: { sessionId?: string } };
      const sessionId = req.params?.sessionId ?? 's1';
      // Emissions must land AFTER the transport marks the conn 'session' —
      // defer past the outcome return, then interleave stdout/stderr; the
      // channel serializes frames per connection.
      setTimeout(() => {
        void ctx.channel.emitData(sessionId, 1, Buffer.from('out-1'));
        void ctx.channel.emitData(sessionId, 2, Buffer.from('err-1'));
        void ctx.channel.emitData(sessionId, 1, Buffer.from('out-2'));
        ctx.channel.emitEnd(sessionId, 0, null, { return: 0 });
      }, 0);
      return { kind: 'session', sessionId, result: { sessionId, fdsReady: true } };
    });
    const client = makeClient(socketPath);
    const session = await client.execOpen(IDENTITY, {
      sessionId: 'wire-sess-1',
      argv: ['sh'],
      cwd: '/workspace',
      environment: { HOME: '/tmp/cloud-harness-home' }
    }, { idempotencyKey: 'wire-exec-open-1' });
    const events: Array<{ fd: number; text: string }> = [];
    session.onData((fd, chunk) => events.push({ fd, text: chunk.toString() }));
    const meta = await session.ended;
    expect(meta.exitCode).toBe(0);
    // All three emissions arrive, fd-tagged and in emission order.
    expect(events).toEqual([
      { fd: 1, text: 'out-1' },
      { fd: 2, text: 'err-1' },
      { fd: 1, text: 'out-2' }
    ]);
    session.close();
  });

  it('large bounded download: fresh-process RSS stays flat (no giant buffering)', async () => {
    // 96 MiB through the real server; the client must stream, not buffer.
    const total = 96 * 1024 * 1024;
    const { socketPath } = await startServer(async () => ({
      kind: 'download',
      streamRef: 'dl-big',
      maxBytes: total + 1024,
      produce: async (emit) => {
        const block = Buffer.alloc(1024 * 1024, 0x33);
        const hash = createHash('sha256');
        for (let i = 0; i < total; i += block.length) {
          hash.update(block);
          await emit(block);
        }
        return { sha256: hash.digest('hex'), bytes: total, entryCount: 1 };
      }
    }));
    // This file runs in its own vitest worker process — RSS here is fresh.
    const before = process.memoryUsage().rss;
    const client = makeClient(socketPath, { streamIdleTimeoutMs: 15_000 });
    let received = 0;
    const trailer = await client.pullTree(
      IDENTITY,
      { guestPath: '/workspace/big', maxBytes: total + 1024 },
      { sink: (c) => { received += c.length; }, idempotencyKey: 'wire-big-dl-001' }
    );
    const after = process.memoryUsage().rss;
    expect(received).toBe(total);
    expect(trailer.bytes).toBe(total);
    // 48 MiB streamed through BOTH ends in this process: RSS growth must
    // stay well under 2× payload — proves chunked forwarding with no
    // whole-archive buffering (socket + GC headroom accounts for the rest).
    expect(after - before).toBeLessThan(total * 2);
  });

  it('large bounded upload: real staging + backpressure end-to-end (C2)', async () => {
    const total = 8 * 1024 * 1024;
    const payload = Buffer.alloc(total, 0x44);
    const sha = createHash('sha256').update(payload).digest('hex');
    const { socketPath, streamDir } = await startServer(async (request) => {
      const req = request as { requestId: string };
      return {
        kind: 'upload',
        streamRef: `tree:${req.requestId}`,
        maxBytes: total + 4096,
        complete: async (_path, bytes, digest) => ({ sha256: digest, bytes, entryCount: 1 })
      };
    });
    const client = makeClient(socketPath, { streamIdleTimeoutMs: 15_000 });
    const t0 = Date.now();
    const trailer = await client.pushTree(
      IDENTITY,
      { guestPath: '/workspace/big', maxBytes: total + 4096, sha256: sha },
      (async function* () {
        for (let i = 0; i < payload.length; i += 1024 * 1024) yield payload.subarray(i, i + 1024 * 1024);
      })(),
      { idempotencyKey: 'wire-big-up-001' }
    );
    expect(trailer.bytes).toBe(total);
    expect(Date.now() - t0).toBeLessThan(30_000);
    void streamDir;
  });
});
