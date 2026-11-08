import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  VmInstanceListResultSchema,
  VmPoolInfoResultSchema,
  VmTarTrailerSchema
} from '@cloud-harness/contracts';
import {
  VmSupervisorCallError,
  VmSupervisorClient,
  WIRE_KIND_BYTES,
  WIRE_KIND_JSON,
  WireFrameDecoder,
  encodeWireFrame,
  encodeWireJson,
  type VmWorkspaceIdentity
} from '../src/vm-supervisor-client.js';

/**
 * Conformance tests for the runner-side vm-supervisor wire client. The fake
 * server below re-implements the APPROVED wire protocol v1
 * (apps/vm-supervisor/src/transport.ts) independently: uint32be payloadLen
 * (includes the kind byte) || uint8 kind || payload; kind 0x00 JSON control,
 * kind 0x01 raw stream bytes. It is deliberately NOT an import of the
 * supervisor transport so codec drift on either side fails here.
 */

const TOKEN = 'test-supervisor-token';
const IDENTITY: VmWorkspaceIdentity = {
  workspaceId: 'ws_aaaaaaaaaaaaaaaaaaaa',
  generation: 3,
  instanceId: '123e4567-e89b-42d3-a456-426614174000'
};

// ---------------------------------------------------------------------------
// Frame codec (client-side, mirrors the wire spec)
// ---------------------------------------------------------------------------

describe('wire frame codec', () => {
  it('encodes the 5-byte header with payloadLen including the kind byte', () => {
    const frame = encodeWireFrame(WIRE_KIND_JSON, '{"a":1}');
    expect(frame.readUInt32BE(0)).toBe(1 + 7);
    expect(frame.readUInt8(4)).toBe(WIRE_KIND_JSON);
    expect(frame.subarray(5).toString('utf8')).toBe('{"a":1}');
  });

  it('decodes frames split across arbitrary push boundaries', () => {
    const decoder = new WireFrameDecoder();
    const f1 = encodeWireJson({ type: 'auth', token: 'x' });
    const f2 = encodeWireFrame(WIRE_KIND_BYTES, Buffer.from([1, 2, 3, 4]));
    const blob = Buffer.concat([f1, f2]);
    const out: Array<{ kind: number; payload: Buffer }> = [];
    for (let i = 0; i < blob.length; i += 3) out.push(...decoder.push(blob.subarray(i, i + 3)));
    expect(out).toHaveLength(2);
    expect(out[0]!.kind).toBe(WIRE_KIND_JSON);
    expect(JSON.parse(out[0]!.payload.toString('utf8'))).toEqual({ type: 'auth', token: 'x' });
    expect(out[1]!.kind).toBe(WIRE_KIND_BYTES);
    expect([...out[1]!.payload]).toEqual([1, 2, 3, 4]);
    expect(decoder.bufferedBytes).toBe(0);
  });

  it('rejects out-of-bounds frame lengths', () => {
    const decoder = new WireFrameDecoder();
    const bad = Buffer.alloc(5);
    bad.writeUInt32BE(0, 0); // len 0 < 1
    expect(() => decoder.push(bad)).toThrow(/frame length/);
    const huge = Buffer.alloc(5);
    huge.writeUInt32BE(64 * 1024 * 1024, 0);
    expect(() => new WireFrameDecoder().push(huge)).toThrow(/frame length/);
  });
});

// ---------------------------------------------------------------------------
// Fake wire-protocol server (independent implementation of transport.ts spec)
// ---------------------------------------------------------------------------

type FakeRequest = Record<string, unknown> & { op?: string; requestId?: string };

interface FakeSessionCtl {
  data(fd: number, chunk: Buffer | string): void;
  /** Sends one session-data header followed by `parts` kind-0x01 frames. */
  dataParts(fd: number, chunk: Buffer | string, parts: number[]): void;
  /** Sends a session-data header declaring `bytes` with NO payload (protocol probe). */
  badDataHeader(fd: number, bytes: number): void;
  meta(exitCode: number | null, signal: string | null, returnMetadata?: unknown): void;
  end(exitCode?: number | null, signal?: string | null): void;
}

type FakeOutcome =
  | { type: 'result'; result: unknown }
  | { type: 'error'; code: string; message?: string; retryable?: boolean; unknown?: boolean }
  | { type: 'hang' }
  | { type: 'destroy' }
  | { type: 'stall-download'; streamRef?: string; maxBytes?: number }
  | { type: 'upload-then-destroy'; streamRef: string }
  | {
      type: 'upload-pause';
      streamRef: string;
      pauseMs: number;
      maxBytes?: number;
      complete: (payload: Buffer, sha256: string) => FakeOutcome | Promise<FakeOutcome>;
    }
  | {
      type: 'upload';
      streamRef: string;
      maxBytes?: number;
      complete: (payload: Buffer, sha256: string) => FakeOutcome | Promise<FakeOutcome>;
    }
  | {
      type: 'download';
      streamRef?: string;
      maxBytes?: number;
      chunks: Buffer[];
      trailer: unknown;
    }
  | { type: 'session'; sessionId: string; result?: unknown };

type FakeHandler = (request: FakeRequest, io: { session: (ctl: FakeSessionCtl) => void }) => FakeOutcome | Promise<FakeOutcome>;

class FakeWireServer {
  readonly socketPath: string;
  private server!: Server;
  private sockets = new Set<Socket>();
  handler: FakeHandler = () => ({ type: 'result', result: {} });
  /** Every decoded client→server control message, for assertions. */
  readonly received: Array<Record<string, unknown>> = [];
  auths = 0;
  /** Most recent session controller handed to a 'session' outcome. */
  lastSession: FakeSessionCtl | undefined;
  private readonly token: string;
  private readonly dir: string;

  constructor(opts: { token?: string; handler?: FakeHandler } = {}) {
    this.dir = mkdtempSync(join(tmpdir(), 'vm-wire-fake-'));
    this.socketPath = join(this.dir, 'supervisor.sock');
    this.token = opts.token ?? TOKEN;
    if (opts.handler) this.handler = opts.handler;
  }

  async listen(): Promise<void> {
    this.server = createServer((socket) => this.accept(socket));
    await new Promise<void>((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.socketPath, () => resolve());
    });
  }

  async close(): Promise<void> {
    for (const socket of this.sockets) socket.destroy();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
    rmSync(this.dir, { recursive: true, force: true });
  }

  private sendJson(socket: Socket, message: Record<string, unknown>): void {
    if (!socket.destroyed) socket.write(encodeWireJson(message));
  }

  private sendFrame(socket: Socket, kind: number, payload: Buffer | string): void {
    if (!socket.destroyed) socket.write(encodeWireFrame(kind, payload));
  }

  private accept(socket: Socket): void {
    this.sockets.add(socket);
    socket.on('close', () => this.sockets.delete(socket));
    socket.on('error', () => this.sockets.delete(socket));
    let buffer = Buffer.alloc(0);
    let authenticated = false;
    let pendingRequestId: string | undefined;
    let upload: { streamRef: string; chunks: Buffer[]; maxBytes: number; complete: (payload: Buffer, sha256: string) => FakeOutcome | Promise<FakeOutcome> } | undefined;
    let sessionCtl: FakeSessionCtl | undefined;

    const sessionCtlFor = (sessionId: string): FakeSessionCtl => {
      const sendData = (fd: number, payload: Buffer) => {
        this.sendJson(socket, { type: 'session-data', sessionId, fd, bytes: payload.length });
        this.sendFrame(socket, WIRE_KIND_BYTES, payload);
      };
      return {
        data: (fd, chunk) => {
          sendData(fd, typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk);
        },
        dataParts: (fd, chunk, parts) => {
          const payload = typeof chunk === 'string' ? Buffer.from(chunk, 'utf8') : chunk;
          this.sendJson(socket, { type: 'session-data', sessionId, fd, bytes: payload.length });
          let offset = 0;
          for (const size of parts) {
            this.sendFrame(socket, WIRE_KIND_BYTES, payload.subarray(offset, offset + size));
            offset += size;
          }
          if (offset < payload.length) this.sendFrame(socket, WIRE_KIND_BYTES, payload.subarray(offset));
        },
        badDataHeader: (fd, bytes) => {
          this.sendJson(socket, { type: 'session-data', sessionId, fd, bytes });
        },
        meta: (exitCode, signal, returnMetadata) => {
          this.sendJson(socket, { type: 'session-meta', sessionId, exitCode, signal, ...(returnMetadata !== undefined ? { returnMetadata } : {}) });
        },
        end: (exitCode = null, signal = null) => {
          this.sendJson(socket, { type: 'session-meta', sessionId, exitCode, signal });
          this.sendJson(socket, { type: 'session-end', sessionId });
        }
      };
    };

    const sendResponse = (requestId: string | undefined, ok: boolean, body: unknown, unknownFlag?: boolean) => {
      this.sendJson(socket, {
        type: 'response',
        response: ok
          ? { version: 1, requestId: requestId ?? '', ok: true, result: body }
          : { version: 1, requestId: requestId ?? '', ok: false, error: body, ...(unknownFlag ? { unknown: true } : {}) }
      });
    };

    const respond = async (rawRequest: unknown) => {
      const envelope = rawRequest as { requestId?: string };
      pendingRequestId = typeof envelope.requestId === 'string' ? envelope.requestId : undefined;
      try {
        const outcome = await this.handler(envelope as FakeRequest, { session: (ctl) => { sessionCtl = ctl; } });
        if (socket.destroyed) return;
        switch (outcome.type) {
          case 'result':
            sendResponse(pendingRequestId, true, outcome.result);
            return;
          case 'error':
            sendResponse(pendingRequestId, false, { code: outcome.code, message: outcome.message ?? 'failed', retryable: outcome.retryable === true }, outcome.unknown === true);
            return;
          case 'hang':
            return;
          case 'destroy':
            socket.destroy();
            return;
          case 'upload-then-destroy':
            this.sendJson(socket, { type: 'stream-ready', streamRef: outcome.streamRef });
            socket.destroy();
            return;
          case 'upload': {
            this.sendJson(socket, { type: 'stream-ready', streamRef: outcome.streamRef });
            upload = { streamRef: outcome.streamRef, chunks: [], maxBytes: outcome.maxBytes ?? 64 * 1024 * 1024, complete: outcome.complete };
            return;
          }
          case 'stall-download':
            this.sendJson(socket, { type: 'stream-start', streamRef: outcome.streamRef ?? 'dl-stall', maxBytes: outcome.maxBytes ?? 64 * 1024 * 1024 });
            return;
          case 'upload-pause':
            this.sendJson(socket, { type: 'stream-ready', streamRef: outcome.streamRef });
            upload = { streamRef: outcome.streamRef, chunks: [], maxBytes: outcome.maxBytes ?? 64 * 1024 * 1024, complete: outcome.complete };
            // Stop reading so the client's kernel buffers fill and write()
            // returns false — exercises the drain-waiter path (C2).
            socket.pause();
            setTimeout(() => { if (!socket.destroyed) socket.resume(); }, outcome.pauseMs).unref();
            return;
          case 'download': {
            this.sendJson(socket, { type: 'stream-start', streamRef: outcome.streamRef ?? pendingRequestId ?? 'dl', maxBytes: outcome.maxBytes ?? 64 * 1024 * 1024 });
            for (const chunk of outcome.chunks) {
              if (socket.destroyed) return;
              this.sendFrame(socket, WIRE_KIND_BYTES, chunk);
            }
            sendResponse(pendingRequestId, true, outcome.trailer);
            return;
          }
          case 'session': {
            sendResponse(pendingRequestId, true, outcome.result ?? { sessionId: outcome.sessionId, fdsReady: true });
            sessionCtl = sessionCtlFor(outcome.sessionId);
            this.lastSession = sessionCtl;
            return;
          }
        }
      } catch (error) {
        if (!socket.destroyed) {
          sendResponse(pendingRequestId, false, {
            code: 'INTERNAL_ERROR',
            message: error instanceof Error ? error.message : String(error),
            retryable: false
          });
        }
      }
    };

    socket.on('data', (chunk: Buffer) => {
      buffer = buffer.length === 0 ? chunk : Buffer.concat([buffer, chunk]);
      for (;;) {
        if (buffer.length < 5) return;
        const len = buffer.readUInt32BE(0);
        if (len < 1 || len > 8 * 1024 * 1024 + 1) { socket.destroy(); return; }
        if (buffer.length < 4 + len) return;
        const kind = buffer.readUInt8(4);
        const payload = buffer.subarray(5, 4 + len);
        buffer = buffer.subarray(4 + len);
        if (kind === WIRE_KIND_BYTES) {
          if (upload) {
            upload.chunks.push(Buffer.from(payload));
            const total = upload.chunks.reduce((n, c) => n + c.length, 0);
            if (total > upload.maxBytes) { socket.destroy(); return; }
          } else {
            socket.destroy();
            return;
          }
          continue;
        }
        let message: Record<string, unknown>;
        try {
          message = JSON.parse(payload.toString('utf8')) as Record<string, unknown>;
        } catch {
          socket.destroy();
          return;
        }
        this.received.push(message);
        if (!authenticated) {
          if (message.type === 'auth' && message.token === this.token) {
            authenticated = true;
            this.auths += 1;
            this.sendJson(socket, { type: 'auth-ok' });
          } else {
            this.sendJson(socket, { type: 'error', error: { code: 'AUTHENTICATION_FAILED', message: 'authentication failed', retryable: false } });
            socket.destroy();
          }
          continue;
        }
        if (message.type === 'stream-end' && upload) {
          const finished = upload;
          upload = undefined;
          const bytes = Buffer.concat(finished.chunks);
          const sha256 = createHash('sha256').update(bytes).digest('hex');
          void (async () => {
            const outcome = await finished.complete(bytes, sha256);
            if (socket.destroyed) return;
            if (outcome.type === 'result') sendResponse(pendingRequestId, true, outcome.result);
            else if (outcome.type === 'error') sendResponse(pendingRequestId, false, { code: outcome.code, message: outcome.message ?? 'failed', retryable: outcome.retryable === true }, outcome.unknown === true);
            else socket.destroy();
          })();
          continue;
        }
        if (message.type === 'request') {
          void respond(message.request);
          continue;
        }
        if (message.type === 'ping') {
          this.sendJson(socket, { type: 'pong' });
          continue;
        }
        this.sendJson(socket, { type: 'error', error: { code: 'INVALID_INPUT', message: 'unknown message type', retryable: false } });
      }
    });
    socket.on('close', () => { upload = undefined; sessionCtl = undefined; });
  }
}

const servers: FakeWireServer[] = [];
const extraServers: Array<{ close: () => Promise<void> }> = [];

async function makeServer(opts: ConstructorParameters<typeof FakeWireServer>[0] = {}): Promise<FakeWireServer> {
  const server = new FakeWireServer(opts);
  servers.push(server);
  await server.listen();
  return server;
}

/** A bare unix socket that accepts and then does whatever `onConnection` says. */
async function makeRawServer(onConnection: (socket: Socket) => void): Promise<{ socketPath: string; close: () => Promise<void> }> {
  const dir = mkdtempSync(join(tmpdir(), 'vm-wire-raw-'));
  const socketPath = join(dir, 'raw.sock');
  const server = createServer(onConnection);
  await new Promise<void>((resolve) => server.listen(socketPath, resolve));
  const handle = {
    socketPath,
    close: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      rmSync(dir, { recursive: true, force: true });
    }
  };
  extraServers.push(handle);
  return handle;
}

function makeClient(server: { socketPath: string }, overrides: { token?: string; limits?: Record<string, number> } = {}): VmSupervisorClient {
  const { token = TOKEN, limits = {} } = overrides;
  return new VmSupervisorClient({
    socketPath: server.socketPath,
    token,
    limits: {
      authTimeoutMs: 300,
      connectTimeoutMs: 500,
      requestTimeoutMs: 1_000,
      streamIdleTimeoutMs: 400,
      ...limits
    }
  });
}

function fakePoolInfo() {
  return {
    poolPath: '/var/lib/incus-pool',
    statfsFree: 500 * 1024 ** 3,
    statfsTotal: 1024 * 1024 ** 3,
    volumes: [],
    imageCacheBytes: 1024 ** 3,
    managedRunningCount: 0
  };
}

afterEach(async () => {
  for (const server of servers.splice(0)) await server.close();
  for (const server of extraServers.splice(0)) await server.close();
});

// ---------------------------------------------------------------------------
// Auth + envelopes
// ---------------------------------------------------------------------------

describe('VmSupervisorClient auth and envelopes', () => {
  it('authenticates with the bearer token before any request', async () => {
    const server = await makeServer({
      handler: (request) => ({ type: 'result', result: request.op === 'pool.info' ? fakePoolInfo() : {} })
    });
    const client = makeClient(server);
    const info = await client.poolInfo();
    expect(info.managedRunningCount).toBe(0);
    expect(server.auths).toBe(1);
    const auth = server.received.find((m) => m.type === 'auth');
    expect(auth?.token).toBe(TOKEN);
  });

  it('rejects a wrong token with AUTHENTICATION_FAILED', async () => {
    const server = await makeServer();
    const client = makeClient(server, { token: 'wrong-token' });
    await expect(client.poolInfo()).rejects.toMatchObject({ code: 'AUTHENTICATION_FAILED', retryable: false });
  });

  it('fails closed when auth-ok never arrives', async () => {
    const server = await makeRawServer((socket) => {
      socket.on('data', () => undefined); // swallow everything, never auth-ok
    });
    const client = makeClient(server, { limits: { authTimeoutMs: 120, connectTimeoutMs: 400 } });
    await expect(client.poolInfo()).rejects.toMatchObject({ code: 'VM_SUPERVISOR_UNAVAILABLE', retryable: true });
  });

  it('sends the full workspace envelope on workspace ops', async () => {
    const server = await makeServer({
      handler: (request) => ({
        type: 'result',
        result: request.op === 'pool.info' ? fakePoolInfo() : { state: 'running' }
      })
    });
    const client = makeClient(server);
    await client.vmStart(IDENTITY, { networkProfile: 'network-none' }, { idempotencyKey: 'start-key-12345678' });
    const request = server.received.find((m) => m.type === 'request')?.request as Record<string, unknown>;
    expect(request).toMatchObject({
      version: 1,
      workspaceId: IDENTITY.workspaceId,
      workspaceGeneration: IDENTITY.generation,
      vmInstanceId: IDENTITY.instanceId,
      idempotencyKey: 'start-key-12345678',
      op: 'vm.start',
      params: { networkProfile: 'network-none' }
    });
    expect(typeof request.requestId).toBe('string');
    expect(typeof request.issuedAt).toBe('number');
    // Host ops carry no workspace fence.
    await client.poolInfo();
    const hostRequest = server.received.filter((m) => m.type === 'request').map((m) => m.request as Record<string, unknown>).at(-1);
    expect(hostRequest).not.toHaveProperty('workspaceId');
    expect(hostRequest).not.toHaveProperty('vmInstanceId');
    expect(hostRequest).not.toHaveProperty('idempotencyKey');
  });

  it('validates the result against the per-op schema', async () => {
    const server = await makeServer({
      handler: (request) => ({
        type: 'result',
        // vm.status is a read: a malformed result is a supervisor failure.
        // vm.start is a mutation: the same violation leaves the outcome
        // unknown, so it must surface as VM_UNKNOWN_STATE for reconcile.
        result: request.op === 'vm.status' ? { state: 'running', bogus: true } : { state: 'running', bogus: true }
      })
    });
    const client = makeClient(server);
    await expect(client.vmStatus(IDENTITY, { idempotencyKey: 'k-12345678' }))
      .rejects.toMatchObject({ code: 'VM_SUPERVISOR_UNAVAILABLE' });
    await expect(client.vmStart(IDENTITY, { networkProfile: 'network-none' }, { idempotencyKey: 'k-12345678' }))
      .rejects.toMatchObject({ code: 'VM_UNKNOWN_STATE', retryable: true });
  });

  it('maps typed error responses to HarnessError and preserves unknown', async () => {
    const server = await makeServer({
      handler: (request) => request.op === 'vm.create'
        ? { type: 'error', code: 'VM_UNKNOWN_STATE', message: 'lost reply', retryable: true, unknown: true }
        : { type: 'result', result: {} }
    });
    const client = makeClient(server);
    const failure = await client.vmCreate(IDENTITY, {
      instanceId: IDENTITY.instanceId,
      networkProfile: 'network-none',
      templateId: 'cloud-harness/ubuntu-vm:24.04',
      templateDigest: 'a'.repeat(64)
    }, { idempotencyKey: 'create-key-12345678' }).catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(VmSupervisorCallError);
    expect(failure).toMatchObject({ code: 'VM_UNKNOWN_STATE', retryable: true });
    expect((failure as VmSupervisorCallError).unknownOutcome).toBe(true);
  });

  it('rejects malformed envelopes locally before touching the socket', async () => {
    const server = await makeServer();
    const client = makeClient(server);
    await expect(client.filePull(IDENTITY, { guestPath: 'relative/path', maxBytes: 1024 }, { idempotencyKey: 'k-12345678' }))
      .rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(server.received.filter((m) => m.type === 'request')).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Unary calls: ok/error/EOF/timeout/abort
// ---------------------------------------------------------------------------

describe('VmSupervisorClient unary calls', () => {
  it('round-trips pool.info with schema-validated results', async () => {
    const server = await makeServer({ handler: () => ({ type: 'result', result: fakePoolInfo() }) });
    const client = makeClient(server);
    const info = await client.poolInfo();
    expect(VmPoolInfoResultSchema.safeParse(info).success).toBe(true);
    expect(info.statfsFree).toBe(500 * 1024 ** 3);
  });

  it('returns vm.list entries validated by the contract schema', async () => {
    const server = await makeServer({
      handler: () => ({
        type: 'result',
        result: [{
          vmName: `chm-vm-${'a'.repeat(32)}`,
          workspaceId: IDENTITY.workspaceId,
          instanceId: IDENTITY.instanceId,
          state: 'running',
          userCloudHarness: {
            workspaceId: IDENTITY.workspaceId,
            instanceId: IDENTITY.instanceId,
            templateId: 'cloud-harness/ubuntu-vm:24.04',
            templateDigest: 'b'.repeat(64),
            generationPolicy: 'external'
          }
        }]
      })
    });
    const client = makeClient(server);
    const list = await client.vmList({ workspaceId: IDENTITY.workspaceId });
    expect(VmInstanceListResultSchema.safeParse(list).success).toBe(true);
    expect(list).toHaveLength(1);
  });

  it('EOF before the response is UNKNOWN for mutations, UNAVAILABLE for reads', async () => {
    const server = await makeServer({ handler: () => ({ type: 'destroy' }) });
    const client = makeClient(server);
    await expect(client.vmStart(IDENTITY, { networkProfile: 'network-none' }, { idempotencyKey: 'k-12345678' }))
      .rejects.toMatchObject({ code: 'VM_UNKNOWN_STATE', retryable: true });
    await expect(client.vmStatus(IDENTITY, { idempotencyKey: 'k-12345678' }))
      .rejects.toMatchObject({ code: 'VM_SUPERVISOR_UNAVAILABLE', retryable: true });
  });

  it('times out a request that never gets a response', async () => {
    const server = await makeServer({ handler: () => ({ type: 'hang' }) });
    const client = makeClient(server, { limits: { requestTimeoutMs: 120 } });
    await expect(client.poolInfo()).rejects.toMatchObject({ code: 'VM_SUPERVISOR_UNAVAILABLE', retryable: true });
  });

  it('honors the caller abort signal', async () => {
    const server = await makeServer({ handler: () => ({ type: 'hang' }) });
    const client = makeClient(server);
    const controller = new AbortController();
    const pending = client.poolInfo({ signal: controller.signal });
    controller.abort();
    await expect(pending).rejects.toMatchObject({ code: 'CANCELLED' });
  });

  it('maps a post-dispatch mutation abort to VM_UNKNOWN_STATE, never CANCELLED', async () => {
    const server = await makeServer({ handler: (request) => (request.op === 'pool.info' ? { type: 'result', result: fakePoolInfo() } : { type: 'hang' }) });
    const client = makeClient(server);
    // Warm the connection so the lease.set frame is on the wire well before
    // the abort fires — the mutation outcome is genuinely unknown.
    await client.poolInfo();
    const controller = new AbortController();
    const pending = client.leaseSet(IDENTITY, { expiresAt: 1_000, hardExpiresAt: 2_000 }, { signal: controller.signal });
    await new Promise((resolve) => setTimeout(resolve, 25));
    controller.abort();
    await expect(pending).rejects.toMatchObject({ code: 'VM_UNKNOWN_STATE', retryable: true, unknownOutcome: true });
  });

  it('a pre-aborted mutation throws CANCELLED without dispatching a request frame', async () => {
    const server = await makeServer({ handler: () => ({ type: 'result', result: {} }) });
    const client = makeClient(server);
    const controller = new AbortController();
    controller.abort();
    await expect(client.leaseSet(IDENTITY, { expiresAt: 1_000, hardExpiresAt: 2_000 }, { signal: controller.signal }))
      .rejects.toMatchObject({ code: 'CANCELLED' });
    // Only the transport auth handshake may appear; no request envelope.
    expect(server.received.filter((request) => typeof request.op === 'string')).toHaveLength(0);
  });

  it('a pre-aborted read throws CANCELLED without dispatching a request frame', async () => {
    const server = await makeServer({ handler: () => ({ type: 'result', result: fakePoolInfo() }) });
    const client = makeClient(server);
    const controller = new AbortController();
    controller.abort();
    await expect(client.poolInfo({ signal: controller.signal })).rejects.toMatchObject({ code: 'CANCELLED' });
    expect(server.received.filter((request) => typeof request.op === 'string')).toHaveLength(0);
  });

  it('maps a server protocol error frame to a retryable supervisor failure', async () => {
    const server = await makeRawServer((socket) => {
      socket.on('data', () => {
        socket.write(encodeWireJson({ type: 'auth-ok' }));
        socket.write(encodeWireJson({ type: 'error', error: { code: 'INTERNAL_ERROR', message: 'boom', retryable: true } }));
        socket.destroy();
      });
    });
    const client = makeClient(server, { limits: { requestTimeoutMs: 500 } });
    await expect(client.poolInfo()).rejects.toMatchObject({ code: 'VM_SUPERVISOR_UNAVAILABLE', retryable: true });
  });
});

// ---------------------------------------------------------------------------
// Upload flow (file.push stream / pushTree)
// ---------------------------------------------------------------------------

describe('VmSupervisorClient upload flow', () => {
  it('streams pushTree payload frames then stream-end then validates the trailer', async () => {
    const tarBytes = Buffer.concat([Buffer.alloc(1024, 7), Buffer.from('tail')]);
    const sha256 = createHash('sha256').update(tarBytes).digest('hex');
    let completed: { bytes: number; sha256: string } | undefined;
    const server = await makeServer({
      handler: (request) => {
        expect(request.op).toBe('pushTree');
        return {
          type: 'upload',
          // Real server.ts names pushTree uploads `tree:<requestId>` — the
          // client must bind to THIS ref, not the bare requestId (C1).
          streamRef: `tree:${request.requestId as string}`,
          complete: (payload, digest) => {
            completed = { bytes: payload.length, sha256: digest };
            return { type: 'result', result: { sha256: digest, bytes: payload.length, entryCount: 3 } };
          }
        };
      }
    });
    const client = makeClient(server);
    const trailer = await client.pushTree(
      IDENTITY,
      { guestPath: '/workspace/tree', maxBytes: 1_048_576, sha256 },
      (async function* () {
        yield tarBytes.subarray(0, 500);
        yield tarBytes.subarray(500);
      })(),
      { idempotencyKey: 'push-tree-key-1' }
    );
    expect(VmTarTrailerSchema.safeParse(trailer).success).toBe(true);
    expect(trailer).toEqual({ sha256, bytes: tarBytes.length, entryCount: 3 });
    expect(completed).toEqual({ bytes: tarBytes.length, sha256 });
    const types = server.received.map((m) => m.type);
    expect(types).toContain('stream-end');
  });

  it('file.push with streamRef uses the client-chosen stream token', async () => {
    const payload = Buffer.from('file-bytes');
    const sha256 = createHash('sha256').update(payload).digest('hex');
    const server = await makeServer({
      handler: () => ({
        type: 'upload',
        streamRef: 'client-stream-ref-1',
        complete: () => ({ type: 'result', result: { sha256, bytes: payload.length } })
      })
    });
    const client = makeClient(server);
    const result = await client.filePushStream(
      IDENTITY,
      { guestPath: '/opt/harness/file.txt', streamRef: 'client-stream-ref-1', sha256, maxBytes: 4096 },
      (async function* () { yield payload; })(),
      { idempotencyKey: 'file-push-key-1' }
    );
    expect(result).toEqual({ sha256, bytes: payload.length });
  });

  it('EOF mid-upload is UNKNOWN, never success', async () => {
    const server = await makeServer({
      handler: (request) => ({ type: 'upload-then-destroy', streamRef: `tree:${request.requestId as string}` })
    });
    const client = makeClient(server);
    await expect(client.pushTree(
      IDENTITY,
      { guestPath: '/workspace/t', maxBytes: 1_048_576, sha256: 'a'.repeat(64) },
      (async function* () {
        for (let i = 0; i < 100; i++) yield Buffer.alloc(1024, i & 0xff);
      })(),
      { idempotencyKey: 'push-tree-key-2' }
    )).rejects.toMatchObject({ code: 'VM_UNKNOWN_STATE', retryable: true });
  });

  it('surfaces a server-side rejection (quota) as a typed error before streaming', async () => {
    const server = await makeServer({
      handler: () => ({ type: 'error', code: 'VM_QUOTA_EXCEEDED', message: 'pool reserve', retryable: true })
    });
    const client = makeClient(server);
    await expect(client.pushTree(
      IDENTITY,
      { guestPath: '/workspace/t', maxBytes: 1_048_576, sha256: 'a'.repeat(64) },
      (async function* () { yield Buffer.alloc(8); })(),
      { idempotencyKey: 'push-tree-key-3' }
    )).rejects.toMatchObject({ code: 'VM_QUOTA_EXCEEDED', retryable: true });
  });
});

// ---------------------------------------------------------------------------
// Download flow (vm.export / pullTree)
// ---------------------------------------------------------------------------

describe('VmSupervisorClient download flow', () => {
  it('streams pullTree bytes to the sink and returns the typed trailer', async () => {
    const chunks = [Buffer.from('chunk-one-'), Buffer.from('chunk-two')];
    // M7: the trailer must match the bytes actually received — compute it.
    const payload = Buffer.concat(chunks);
    const trailer = { sha256: createHash('sha256').update(payload).digest('hex'), bytes: payload.length, entryCount: 2 };
    const server = await makeServer({
      handler: () => ({ type: 'download', streamRef: 'dl-1', maxBytes: 1_048_576, chunks, trailer })
    });
    const client = makeClient(server);
    const received: Buffer[] = [];
    const result = await client.pullTree(
      IDENTITY,
      { guestPath: '/workspace/tree', maxBytes: 1_048_576 },
      { sink: (chunk) => { received.push(Buffer.from(chunk)); }, idempotencyKey: 'pull-tree-key-1' }
    );
    expect(result).toEqual(trailer);
    expect(Buffer.concat(received).toString()).toBe('chunk-one-chunk-two');
  });

  it('enforces the stream byte bound mid-download', async () => {
    const server = await makeServer({
      handler: () => ({
        type: 'download',
        maxBytes: 8,
        chunks: [Buffer.alloc(4, 1), Buffer.alloc(8, 2)],
        trailer: { sha256: 'd'.repeat(64), bytes: 12, entryCount: 1 }
      })
    });
    const client = makeClient(server);
    await expect(client.pullTree(
      IDENTITY,
      { guestPath: '/workspace/tree', maxBytes: 8 },
      { sink: () => undefined, idempotencyKey: 'pull-tree-key-2' }
    )).rejects.toMatchObject({ code: 'VM_SUPERVISOR_UNAVAILABLE' });
  });

  it('vm.export uses the same download path with an expected sha256 trailer', async () => {
    const payload = Buffer.alloc(100, 9);
    const trailer = { sha256: createHash('sha256').update(payload).digest('hex'), bytes: 100, entryCount: 5 };
    const server = await makeServer({
      handler: () => ({ type: 'download', chunks: [payload], trailer })
    });
    const client = makeClient(server);
    const received: Buffer[] = [];
    const result = await client.vmExport(
      IDENTITY,
      { guestPath: '/workspace', maxBytes: 1_048_576, sha256: 'e'.repeat(64) },
      { sink: (chunk) => { received.push(Buffer.from(chunk)); }, idempotencyKey: 'export-key-1' }
    );
    expect(result).toEqual(trailer);
    expect(received.reduce((n, c) => n + c.length, 0)).toBe(100);
  });

  it('a hung download times out as supervisor unavailable (read op)', async () => {
    const server = await makeServer({ handler: () => ({ type: 'hang' }) });
    const client = makeClient(server, { limits: { requestTimeoutMs: 150 } });
    await expect(client.pullTree(
      IDENTITY,
      { guestPath: '/workspace/tree', maxBytes: 1_048_576 },
      { sink: () => undefined, idempotencyKey: 'pull-tree-key-3' }
    )).rejects.toMatchObject({ code: 'VM_SUPERVISOR_UNAVAILABLE' });
  });
});

// ---------------------------------------------------------------------------
// Exec sessions (exec.open + session-data/meta/end)
// ---------------------------------------------------------------------------

describe('VmSupervisorClient exec sessions', () => {
  it('opens a session, delivers fd-tagged data, meta and end in order', async () => {
    const server = await makeServer({
      handler: (request) => {
        expect(request.op).toBe('exec.open');
        return { type: 'session', sessionId: 'sess-1', result: { sessionId: 'sess-1', fdsReady: true } };
      }
    });
    const client = makeClient(server);
    const session = await client.execOpen(IDENTITY, {
      sessionId: 'sess-1',
      argv: ['/opt/harness/worker-runner.sh', 'op-1'],
      cwd: '/workspace',
      environment: { PATH: '/usr/bin' }
    }, { idempotencyKey: 'open-key-1' });
    expect(session.sessionId).toBe('sess-1');

    const data: Array<{ fd: number; text: string }> = [];
    session.onData((fd, chunk) => { data.push({ fd, text: chunk.toString('utf8') }); });
    const ended = session.ended;

    await new Promise((resolve) => setTimeout(resolve, 10));
    server.lastSession!.data(1, 'hello-out');
    server.lastSession!.data(2, 'hello-err');
    server.lastSession!.meta(0, null);
    server.lastSession!.end(0, null);

    const end = await ended;
    expect(end.exitCode).toBe(0);
    expect(data).toEqual([
      { fd: 1, text: 'hello-out' },
      { fd: 2, text: 'hello-err' }
    ]);
    expect(session.closed).toBe(true);
  });

  it('reassembles session-data payloads split across byte frames', async () => {
    const server = await makeServer({ handler: () => ({ type: 'session', sessionId: 'sess-2' }) });
    const client = makeClient(server);
    const session = await client.execOpen(IDENTITY, {
      sessionId: 'sess-2', argv: ['cat'], environment: {}
    }, { idempotencyKey: 'open-key-2' });
    const chunks: Buffer[] = [];
    session.onData((_fd, chunk) => { chunks.push(Buffer.from(chunk)); });
    const ended = session.ended;
    await new Promise((resolve) => setTimeout(resolve, 10));
    server.lastSession!.dataParts(1, 'abcdef', [2, 4]);
    server.lastSession!.end(0, null);
    await ended;
    expect(Buffer.concat(chunks).toString()).toBe('abcdef');
  });

  it('retains pre-listener session output past the soft cap and replays it on attach', async () => {
    const server = await makeServer({ handler: () => ({ type: 'session', sessionId: 'sess-prebuf' }) });
    const client = makeClient(server, {
      limits: { preListenerBufferMaxBytes: 1024 * 1024, preListenerHardMaxBytes: 8 * 1024 * 1024 }
    });
    const session = await client.execOpen(IDENTITY, {
      sessionId: 'sess-prebuf', argv: ['cat'], environment: {}
    }, { idempotencyKey: 'open-key-prebuf' });
    const ended = session.ended;
    await new Promise((resolve) => setTimeout(resolve, 10));
    // 3 MiB of output lands before any onData listener — past the 1 MiB soft
    // cap (socket pauses) but under the 8 MiB hard bound. Every byte must be
    // held and replayed; the old code silently dropped the overflow.
    const parts: Buffer[] = [];
    for (let i = 0; i < 6; i += 1) {
      const part = Buffer.alloc(512 * 1024, 0x61 + (i % 26));
      parts.push(part);
      server.lastSession!.data(1, part);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
    const chunks: Buffer[] = [];
    session.onData((_fd, chunk) => { chunks.push(Buffer.from(chunk)); });
    server.lastSession!.end(0, null);
    await ended;
    // Buffer.equals is a native memcmp — vitest toEqual on multi-MiB buffers
    // is pathologically slow and would blow the test timeout on its own.
    const received = Buffer.concat(chunks);
    const expected = Buffer.concat(parts);
    expect(received.length).toBe(expected.length);
    expect(received.equals(expected)).toBe(true);
    expect(session.closed).toBe(true);
  });

  it('replays ALL pre-listener output past the default 4 MiB soft cap', async () => {
    const server = await makeServer({ handler: () => ({ type: 'session', sessionId: 'sess-defaultcap' }) });
    // Default limits: 4 MiB soft pause / 64 MiB hard bound — the production
    // shape, not an injected small cap.
    const client = makeClient(server);
    const session = await client.execOpen(IDENTITY, {
      sessionId: 'sess-defaultcap', argv: ['cat'], environment: {}
    }, { idempotencyKey: 'open-key-defaultcap' });
    const ended = session.ended;
    await new Promise((resolve) => setTimeout(resolve, 10));
    // 6 MiB in <=1 MiB session-data messages, all before any listener.
    const parts: Buffer[] = [];
    for (let i = 0; i < 12; i += 1) {
      const part = Buffer.alloc(512 * 1024, 0x61 + (i % 26));
      parts.push(part);
      server.lastSession!.data(1, part);
    }
    await new Promise((resolve) => setTimeout(resolve, 150));
    const chunks: Buffer[] = [];
    session.onData((_fd, chunk) => { chunks.push(Buffer.from(chunk)); });
    server.lastSession!.end(0, null);
    await ended;
    const received = Buffer.concat(chunks);
    const expected = Buffer.concat(parts);
    expect(received.length).toBe(expected.length);
    expect(received.equals(expected)).toBe(true);
    expect(session.closed).toBe(true);
  });

  it('fails the session loudly when pre-listener output exceeds the hard bound', async () => {
    const server = await makeServer({ handler: () => ({ type: 'session', sessionId: 'sess-hardcap' }) });
    const client = makeClient(server, {
      // hard < soft on purpose: the hard bound must reject BEFORE the soft
      // cap pauses the socket, otherwise in-flight bytes can never arrive to
      // cross it. This exercises the loud-failure path deterministically.
      limits: { preListenerBufferMaxBytes: 8 * 1024 * 1024, preListenerHardMaxBytes: 2 * 1024 * 1024 }
    });
    const session = await client.execOpen(IDENTITY, {
      sessionId: 'sess-hardcap', argv: ['cat'], environment: {}
    }, { idempotencyKey: 'open-key-hardcap' });
    const ended = session.ended.catch((error: unknown) => error);
    await new Promise((resolve) => setTimeout(resolve, 10));
    // 3 MiB total against a 2 MiB hard bound — the session must terminate
    // loudly instead of buffering or dropping bytes. exec.open already ran
    // the guest command, so the outcome is unobservable once we close: this
    // is VM_UNKNOWN_STATE (retryable, reconcile-first), NOT a protocol
    // violation — nothing malformed arrived, a client bound was hit.
    for (let i = 0; i < 6; i += 1) {
      server.lastSession!.data(1, Buffer.alloc(512 * 1024, 0x62));
    }
    const end = await ended;
    expect(end).toMatchObject({ code: 'VM_UNKNOWN_STATE', retryable: true });
    expect((end as VmSupervisorCallError).unknownOutcome).toBe(true);
    expect(session.closed).toBe(true);
  });

  it('EOF during an open session ends it with an unknown-state error', async () => {
    const server = await makeServer({ handler: () => ({ type: 'session', sessionId: 'sess-3' }) });
    const client = makeClient(server);
    const session = await client.execOpen(IDENTITY, {
      sessionId: 'sess-3', argv: ['sleep', '60'], environment: {}
    }, { idempotencyKey: 'open-key-3' });
    // Simulate supervisor restart: the whole server (and its sockets) dies.
    await server.close();
    servers.splice(servers.indexOf(server), 1);
    const end = await session.ended.catch((error: unknown) => error);
    expect(end).toMatchObject({ code: 'VM_UNKNOWN_STATE' });
    expect(session.closed).toBe(true);
  });

  it('local session close resolves ended without an error', async () => {
    const server = await makeServer({ handler: () => ({ type: 'session', sessionId: 'sess-4' }) });
    const client = makeClient(server);
    const session = await client.execOpen(IDENTITY, {
      sessionId: 'sess-4', argv: ['cat'], environment: {}
    }, { idempotencyKey: 'open-key-4' });
    session.close();
    const end = await session.ended;
    expect(end.exitCode).toBeNull();
    expect(session.closed).toBe(true);
  });

  it('exec.write/close/resize/killSession are ordinary fenced unary calls', async () => {
    const server = await makeServer({
      handler: (request) => {
        const op = request.op as string;
        if (op === 'exec.write') return { type: 'result', result: { acceptedBytes: 5 } };
        if (op === 'exec.close') return { type: 'result', result: { closed: true } };
        if (op === 'exec.resize') return { type: 'result', result: {} };
        if (op === 'exec.killSession') return { type: 'result', result: { killed: true } };
        return { type: 'result', result: {} };
      }
    });
    const client = makeClient(server);
    const written = await client.execWrite(IDENTITY, { sessionId: 's-1', fd: 0, dataBase64: Buffer.from('hello').toString('base64') }, { idempotencyKey: 'write-key-1' });
    expect(written.acceptedBytes).toBe(5);
    await client.execClose(IDENTITY, { sessionId: 's-1', fd: -1 }, { idempotencyKey: 'close-key-1' });
    await client.execResize(IDENTITY, { sessionId: 's-1', cols: 120, rows: 40 }, { idempotencyKey: 'resize-key-1' });
    await client.execKillSession(IDENTITY, { sessionId: 's-1', pidFile: '/tmp/pid' }, { idempotencyKey: 'killsess-key-1' });
    const ops = server.received.filter((m) => m.type === 'request').map((m) => (m.request as { op: string }).op);
    expect(ops).toEqual(['exec.write', 'exec.close', 'exec.resize', 'exec.killSession']);
  });
});

// ---------------------------------------------------------------------------
// Review-hardening: trailer verification, mutation classification, bounds
// ---------------------------------------------------------------------------

describe('VmSupervisorClient review hardening', () => {
  it('rejects a download whose trailer sha256/bytes do not match received data (M7)', async () => {
    const payload = Buffer.from('real-bytes');
    const server = await makeServer({
      handler: () => ({
        type: 'download',
        chunks: [payload],
        trailer: { sha256: 'f'.repeat(64), bytes: 999, entryCount: 1 }
      })
    });
    const client = makeClient(server);
    const received: Buffer[] = [];
    await expect(client.pullTree(
      IDENTITY,
      { guestPath: '/workspace/tree', maxBytes: 1_048_576 },
      { sink: (c) => { received.push(Buffer.from(c)); }, idempotencyKey: 'pull-mismatch-1' }
    )).rejects.toMatchObject({ code: 'VM_SUPERVISOR_UNAVAILABLE' });
    // Bytes were delivered before the trailer check failed — the sink saw them.
    expect(Buffer.concat(received).equals(payload)).toBe(true);
  });

  it('treats reconcile as a mutation: transport loss is VM_UNKNOWN_STATE (M10)', async () => {
    const server = await makeServer({ handler: () => ({ type: 'destroy' }) });
    const client = makeClient(server);
    await expect(client.reconcile()).rejects.toMatchObject({ code: 'VM_UNKNOWN_STATE', retryable: true });
  });

  it('rejects a session-data header declaring more than the 1 MiB message bound (L4)', async () => {
    const server = await makeServer({ handler: () => ({ type: 'session', sessionId: 'sess-big' }) });
    const client = makeClient(server);
    const session = await client.execOpen(IDENTITY, {
      sessionId: 'sess-big', argv: ['cat'], environment: {}
    }, { idempotencyKey: 'open-big-1' });
    const ended = session.ended.catch((e: unknown) => e);
    await new Promise((r) => setTimeout(r, 10));
    server.lastSession!.badDataHeader(1, 2 * 1024 * 1024);
    // Session transport failures surface as supervisor-unavailable; the
    // contract under test is that the session TERMINATES, never hangs.
    await expect(ended).resolves.toMatchObject({ code: 'VM_SUPERVISOR_UNAVAILABLE' });
  });

  it('re-arms the stream idle deadline on progress: trickled download outlives one idle window (H1)', async () => {
    const payload = Buffer.concat([Buffer.alloc(64, 1), Buffer.alloc(64, 2)]);
    const sha = createHash('sha256').update(payload).digest('hex');
    // Raw server for precise timing control: chunk, ~250ms gap (< 400ms idle),
    // chunk, trailer — total > one idle window, so only a re-arming timer passes.
    const dir = mkdtempSync(join(tmpdir(), 'vm-wire-trickle-'));
    const sockPath = join(dir, 's.sock');
    const { createServer } = await import('node:net');
    const srv = createServer((socket) => {
      const decoder = new WireFrameDecoder();
      let authed = false;
      let sent = false;
      socket.on('data', (chunk) => {
        for (const frame of decoder.push(chunk)) {
          if (frame.kind !== WIRE_KIND_JSON) continue;
          const msg = JSON.parse(frame.payload.toString('utf8')) as { type?: string; request?: { requestId?: string } };
          if (!authed) {
            if (msg.type === 'auth') { authed = true; socket.write(encodeWireJson({ type: 'auth-ok' })); }
            continue;
          }
          if (msg.type === 'request' && !sent && typeof msg.request?.requestId === 'string') {
            sent = true;
            const rid = msg.request.requestId;
            socket.write(encodeWireJson({ type: 'stream-start', streamRef: 'dl-x', maxBytes: 1 << 20 }));
            socket.write(encodeWireFrame(WIRE_KIND_BYTES, payload.subarray(0, 64)));
            setTimeout(() => {
              if (socket.destroyed) return;
              socket.write(encodeWireFrame(WIRE_KIND_BYTES, payload.subarray(64)));
              socket.write(encodeWireJson({ type: 'response', response: { version: 1, requestId: rid, ok: true, result: { sha256: sha, bytes: 128, entryCount: 1 } } }));
            }, 250);
          }
        }
      });
    });
    await new Promise<void>((r) => srv.listen(sockPath, r));
    extraServers.push({ close: async () => { await new Promise<void>((r) => srv.close(() => r())); rmSync(dir, { recursive: true, force: true }); } });
    const client = new VmSupervisorClient({ socketPath: sockPath, token: TOKEN, limits: { requestTimeoutMs: 2_000, streamIdleTimeoutMs: 400, authTimeoutMs: 500, connectTimeoutMs: 500 } });
    const got: Buffer[] = [];
    const result = await client.pullTree(IDENTITY, { guestPath: '/w/t', maxBytes: 1 << 20 }, {
      sink: (c) => { got.push(Buffer.from(c)); }, idempotencyKey: 'trickle-1'
    });
    expect(result.bytes).toBe(128);
    expect(Buffer.concat(got).equals(payload)).toBe(true);
    await client.close();
  });

  it('aborts a stalled download at the idle deadline (H1 bound)', async () => {
    const server = await makeServer({ handler: () => ({ type: 'stall-download' }) });
    const client = makeClient(server, { limits: { streamIdleTimeoutMs: 200 } });
    await expect(client.pullTree(
      IDENTITY,
      { guestPath: '/workspace/tree', maxBytes: 1_048_576 },
      { sink: () => undefined, idempotencyKey: 'stall-key-01' }
    )).rejects.toMatchObject({ code: 'VM_SUPERVISOR_UNAVAILABLE' });
  });

  it('large upload survives socket backpressure via drain (C2)', async () => {
    const total = 6 * 1024 * 1024; // > socket buffers → write() returns false
    const payload = Buffer.alloc(total, 0x5a);
    const sha = createHash('sha256').update(payload).digest('hex');
    let completedBytes = 0;
    const server = await makeServer({
      handler: (request) => ({
        type: 'upload-pause',
        streamRef: `tree:${request.requestId as string}`,
        pauseMs: 200,
        complete: (body) => {
          completedBytes = body.length;
          return { type: 'result', result: { sha256: sha, bytes: body.length, entryCount: 1 } };
        }
      })
    });
    const client = makeClient(server, { limits: { streamIdleTimeoutMs: 2_000 } });
    const trailer = await client.pushTree(
      IDENTITY,
      { guestPath: '/workspace/big', maxBytes: total + 1024, sha256: sha },
      (async function* () { yield payload; })(),
      { idempotencyKey: 'big-upload-1' }
    );
    expect(completedBytes).toBe(total);
    expect(trailer.bytes).toBe(total);
  });
});
