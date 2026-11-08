import { mkdtempSync, rmSync } from 'node:fs';
import { connect, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  encodeWireFrame,
  encodeWireJson,
  VmSupervisorWireServer,
  WIRE_KIND_BYTES,
  WIRE_KIND_JSON,
  type WIRE_LIMITS,
  type WireFrame,
  type WireHandlerOutcome,
  type WireRequestContext,
  type WireServerMessage
} from '../src/transport.js';
import { WireFrameDecoder } from '../src/transport.js';
import type { DiskReservations } from '../src/disk-reservations.js';

const dirs: string[] = [];
const servers: VmSupervisorWireServer[] = [];
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'vm-wire-'));
  dirs.push(dir);
  return dir;
}
afterEach(async () => {
  while (servers.length) await servers.pop()!.close();
  while (dirs.length) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

const TOKEN = 't'.repeat(48);

/** Minimal test client implementing the published wire protocol. */
class TestClient {
  socket!: Socket;
  private decoder = new WireFrameDecoder();
  private buffer: WireFrame[] = [];
  private waiters: Array<(frame: WireFrame) => void> = [];
  private closed = false;

  static async connect(socketPath: string): Promise<TestClient> {
    const client = new TestClient();
    await new Promise<void>((resolve, reject) => {
      client.socket = connect({ path: socketPath });
      client.socket.once('connect', resolve);
      client.socket.once('error', reject);
      client.socket.on('data', (chunk: Buffer) => {
        for (const frame of client.decoder.push(chunk)) client.deliver(frame);
      });
      client.socket.on('close', () => { client.closed = true; });
    });
    return client;
  }

  private deliver(frame: WireFrame): void {
    const waiter = this.waiters.shift();
    if (waiter !== undefined) waiter(frame);
    else this.buffer.push(frame);
  }

  private nextFrame(timeoutMs = 5_000): Promise<WireFrame> {
    const buffered = this.buffer.shift();
    if (buffered !== undefined) return Promise.resolve(buffered);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('frame timeout')), timeoutMs);
      this.waiters.push((frame) => { clearTimeout(timer); resolve(frame); });
    });
  }

  private async nextJson(timeoutMs?: number): Promise<Record<string, unknown>> {
    const frame = await this.nextFrame(timeoutMs);
    expect(frame.kind).toBe(WIRE_KIND_JSON);
    return JSON.parse(frame.payload.toString('utf8')) as Record<string, unknown>;
  }

  sendJson(message: unknown): void {
    this.socket.write(encodeWireJson(message));
  }

  sendBytes(payload: Buffer): void {
    this.socket.write(encodeWireFrame(WIRE_KIND_BYTES, payload));
  }

  async auth(token = TOKEN): Promise<Record<string, unknown>> {
    this.sendJson({ type: 'auth', token });
    return this.nextJson();
  }

  async request(request: unknown): Promise<{ type: string; response?: { ok: boolean; result?: unknown; error?: { code: string } }; [k: string]: unknown }> {
    this.sendJson({ type: 'request', request });
    // Responses may be preceded by stream/session control messages.
    for (;;) {
      const msg = await this.nextJson();
      if (msg.type === 'response') return msg as never;
      // stash non-response messages is not needed for these tests
      throw new Error(`unexpected pre-response message: ${msg.type}`);
    }
  }

  async expectError(): Promise<Record<string, unknown>> {
    const msg = await this.nextJson();
    expect(msg.type).toBe('error');
    return msg;
  }

  close(): void {
    this.socket.destroy();
  }
}

async function startServer(
  handler: (req: unknown, ctx: WireRequestContext) => Promise<WireHandlerOutcome>,
  token = TOKEN,
  limits?: Partial<typeof WIRE_LIMITS>,
  diskReservations?: DiskReservations
) {
  const dir = tempDir();
  const socketPath = join(dir, 's.sock');
  const streamDir = join(dir, 'streams');
  const server = new VmSupervisorWireServer({ socketPath, token, handler, streamDir, limits, ...(diskReservations !== undefined ? { diskReservations } : {}) });
  await server.listen();
  servers.push(server);
  return { server, socketPath, streamDir };
}

describe('wire framing codec', () => {
  it('round-trips frames across arbitrary chunk boundaries', () => {
    const decoder = new WireFrameDecoder();
    const payload = Buffer.from('{"type":"ping"}');
    const frame = encodeWireFrame(WIRE_KIND_JSON, payload);
    const frames = [
      ...decoder.push(frame.subarray(0, 2)),
      ...decoder.push(frame.subarray(2, 5)),
      ...decoder.push(frame.subarray(5))
    ];
    expect(frames).toHaveLength(1);
    expect(frames[0]?.kind).toBe(WIRE_KIND_JSON);
    expect(frames[0]?.payload.toString()).toBe('{"type":"ping"}');
  });

  it('rejects out-of-bounds frame lengths', () => {
    const decoder = new WireFrameDecoder();
    const bad = Buffer.alloc(5);
    bad.writeUInt32BE(64 * 1024 * 1024, 0);
    bad.writeUInt8(WIRE_KIND_JSON, 4);
    expect(() => decoder.push(bad)).toThrow(/bounds/);
  });
});

describe('auth and request dispatch', () => {
  it('rejects missing/wrong token and accepts the right one', async () => {
    const { socketPath } = await startServer(async () => ({ kind: 'result', result: { ok: 1 } }));
    const bad = await TestClient.connect(socketPath);
    bad.sendJson({ type: 'auth', token: 'wrong' });
    const err = await bad.expectError();
    expect((err.error as { code: string }).code).toBe('AUTHENTICATION_FAILED');
    bad.close();

    const noAuth = await TestClient.connect(socketPath);
    noAuth.sendJson({ type: 'request', request: {} });
    const err2 = await noAuth.expectError();
    expect((err2.error as { code: string }).code).toBe('AUTHENTICATION_FAILED');
    noAuth.close();

    const good = await TestClient.connect(socketPath);
    const authOk = await good.auth();
    expect(authOk.type).toBe('auth-ok');
    const res = await good.request({ op: 'vm.status' });
    expect(res.type).toBe('response');
    expect((res.response as { ok: boolean }).ok).toBe(true);
    good.close();
  });

  it('destroys unauthenticated connections after the auth deadline (slowloris)', async () => {
    const { socketPath } = await startServer(async () => ({ kind: 'result', result: {} }), TOKEN, { authTimeoutMs: 150 });
    const client = await TestClient.connect(socketPath);
    // Send nothing; the server must drop the connection.
    await new Promise<void>((resolve) => client.socket.once('close', resolve));
    client.close();
  });

  it('enforces sequential requests per connection', async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const { socketPath } = await startServer(async () => {
      await gate;
      return { kind: 'result', result: { done: true } };
    });
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: { op: 'a', requestId: 'ra' } });
    // Second request while first is in flight → CONFLICT error response.
    client.sendJson({ type: 'request', request: { op: 'b', requestId: 'rb' } });
    const busy = await client.nextJson();
    expect(busy.type).toBe('response');
    const busyRes = busy.response as { ok: boolean; error?: { code: string } };
    expect(busyRes.ok).toBe(false);
    expect(busyRes.error?.code).toBe('CONFLICT');
    release();
    const done = await client.nextJson();
    expect((done.response as { ok: boolean }).ok).toBe(true);
    client.close();
  });
});

describe('upload flow', () => {
  it('streams bytes then completes with sha256', async () => {
    const { createHash } = await import('node:crypto');
    const payload = Buffer.from('hello-upload');
    const expectedSha = createHash('sha256').update(payload).digest('hex');
    let completedWith: { path: string; bytes: number; sha256: string } | undefined;
    const { socketPath } = await startServer(async () => ({
      kind: 'upload',
      streamRef: 'upl-1',
      maxBytes: 1024,
      complete: async (path, bytes, sha256) => {
        completedWith = { path, bytes, sha256 };
        return { sha256, bytes };
      }
    }));
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: { op: 'file.push', params: {} } });
    const ready = await client.nextJson();
    expect(ready.type).toBe('stream-ready');
    expect(ready.streamRef).toBe('upl-1');
    // split payload across frames
    client.sendBytes(payload.subarray(0, 5));
    client.sendBytes(payload.subarray(5));
    client.sendJson({ type: 'stream-end', streamRef: 'upl-1' });
    const res = await client.nextJson();
    expect(res.type).toBe('response');
    expect((res.response as { result: { sha256: string; bytes: number } }).result).toEqual({ sha256: expectedSha, bytes: payload.length });
    expect(completedWith?.sha256).toBe(expectedSha);
    expect(completedWith?.bytes).toBe(payload.length);
    client.close();
  });

  it('disconnect before stream-end never produces success', async () => {
    let completed = false;
    const { socketPath } = await startServer(async () => ({
      kind: 'upload',
      streamRef: 'upl-2',
      maxBytes: 4096,
      complete: async () => { completed = true; return {}; }
    }));
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: {} });
    await client.nextJson(); // stream-ready
    client.sendBytes(Buffer.from('partial'));
    client.close(); // EOF without stream-end
    await new Promise((r) => setTimeout(r, 100));
    expect(completed).toBe(false);
  });

  it('rejects uploads exceeding maxBytes', async () => {
    const { socketPath } = await startServer(async () => ({
      kind: 'upload',
      streamRef: 'upl-3',
      maxBytes: 4,
      complete: async () => ({})
    }));
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: {} });
    await client.nextJson();
    client.sendBytes(Buffer.alloc(8));
    // connection should be destroyed
    await new Promise<void>((resolve) => client.socket.once('close', resolve));
    client.close();
  });
});

describe('download flow', () => {
  it('streams chunks then trailer response', async () => {
    const chunks = [Buffer.from('chunk-one-'), Buffer.from('chunk-two')];
    const { socketPath } = await startServer(async () => ({
      kind: 'download',
      streamRef: 'req-1',
      maxBytes: 1024,
      produce: async (emit) => {
        for (const c of chunks) await emit(c);
        return { sha256: 'a'.repeat(64), bytes: 17, entryCount: 2 };
      }
    }));
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: { op: 'vm.export' } });
    const start = await client.nextJson();
    expect(start.type).toBe('stream-start');
    const received: Buffer[] = [];
    // read byte frames until response
    for (;;) {
      const frame = await client.nextFrame();
      if (frame.kind === WIRE_KIND_BYTES) received.push(frame.payload);
      else {
        const msg = JSON.parse(frame.payload.toString('utf8')) as WireServerMessage;
        expect(msg.type).toBe('response');
        const result = (msg as { response: { result: { bytes: number } } }).response.result;
        expect(result.bytes).toBe(17);
        break;
      }
    }
    expect(Buffer.concat(received).toString()).toBe('chunk-one-chunk-two');
    client.close();
  });
});

describe('session flow', () => {
  it('emits session-data then meta+end and returns conn to idle', async () => {
    const { socketPath } = await startServer(async (_req, ctx) => {
      const sessionId = 'sess-1';
      // simulate async output after response
      setTimeout(() => {
        void ctx.channel.emitData(sessionId, 1, Buffer.from('out-1'));
        void ctx.channel.emitData(sessionId, 2, Buffer.from('err-1'));
        ctx.channel.emitEnd(sessionId, 0, null, { return: 0 });
      }, 20);
      return { kind: 'session', sessionId, result: { sessionId, fdsReady: true } };
    });
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: { op: 'exec.open' } });
    const res = await client.nextJson();
    expect(res.type).toBe('response');
    const seen: Array<{ type: string; fd?: number; text?: string }> = [];
    for (;;) {
      const frame = await client.nextFrame();
      if (frame.kind === WIRE_KIND_BYTES) {
        // associate with previous session-data header
        const last = seen[seen.length - 1];
        if (last !== undefined) last.text = (last.text ?? '') + frame.payload.toString();
        continue;
      }
      const msg = JSON.parse(frame.payload.toString('utf8')) as Record<string, unknown>;
      seen.push({ type: String(msg.type), fd: msg.fd as number | undefined });
      if (msg.type === 'session-end') break;
    }
    const dataMsgs = seen.filter((m) => m.type === 'session-data');
    expect(dataMsgs).toHaveLength(2);
    expect(dataMsgs.map((m) => m.text).join('')).toContain('out-1');
    expect(dataMsgs.map((m) => m.text).join('')).toContain('err-1');
    expect(seen.some((m) => m.type === 'session-meta')).toBe(true);
    // connection reusable after session-end
    client.sendJson({ type: 'request', request: { op: 'vm.status' } });
    const res2 = await client.nextJson();
    expect(res2.type).toBe('response');
    client.close();
  });
});

describe('session emission serialization (review fix)', () => {
  it('never interleaves session-data headers, payloads, meta or end under drain', async () => {
    const { socketPath } = await startServer(async (_req, ctx) => {
      const sessionId = 'sess-ordered';
      setTimeout(() => {
        // Fire all emissions concurrently — without per-connection
        // serialization their header/payload frames interleave on the wire.
        const emits: Promise<void>[] = [];
        for (let i = 0; i < 60; i += 1) {
          emits.push(ctx.channel.emitData(sessionId, i % 2 === 0 ? 1 : 2, Buffer.from(`chunk-${i}`)));
        }
        emits.push(Promise.resolve(ctx.channel.emitMeta(sessionId, { note: 'mid' })));
        emits.push(Promise.resolve(ctx.channel.emitEnd(sessionId, 0, null, { return: 0 })));
        void Promise.all(emits);
      }, 20);
      return { kind: 'session', sessionId, result: { sessionId, fdsReady: true } };
    });
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: { op: 'exec.open' } });
    await client.nextJson(); // response
    // Tag every frame: 'J:<type>' for JSON control, 'B' for binary payload.
    const tags: string[] = [];
    for (;;) {
      const frame = await client.nextFrame();
      if (frame.kind === WIRE_KIND_BYTES) { tags.push('B'); continue; }
      const msg = JSON.parse(frame.payload.toString('utf8')) as { type?: string };
      tags.push(`J:${msg.type}`);
      if (msg.type === 'session-end') break;
    }
    // Invariant: every session-data JSON header is IMMEDIATELY followed by
    // its binary payload — no other frame may land between them.
    for (let i = 0; i < tags.length; i += 1) {
      if (tags[i] === 'J:session-data') {
        expect(tags[i + 1], `frame after session-data at ${i}`).toBe('B');
      }
      if (tags[i] === 'J:session-meta' || tags[i] === 'J:session-end') {
        // meta/end must be the LAST emissions: nothing may follow except end.
        for (let j = i + 1; j < tags.length; j += 1) {
          expect(tags[j]).not.toBe('J:session-data');
        }
      }
    }
    // All 60 payloads arrived, meta before end.
    expect(tags.filter((t) => t === 'B')).toHaveLength(60);
    expect(tags.indexOf('J:session-meta')).toBeLessThan(tags.indexOf('J:session-end'));
    client.close();
  });
});

describe('stream idle semantics (review fix)', () => {
  it('outbound download progress resets the idle timer — no inbound needed', async () => {
    // Idle timeout 120ms; produce emits every 30ms for ~450ms while the
    // client sends NOTHING. Pre-fix the inbound-only timer killed the conn.
    const { socketPath } = await startServer(async () => ({
      kind: 'download',
      streamRef: 'req-idle',
      maxBytes: 1 << 20,
      produce: async (emit) => {
        for (let i = 0; i < 15; i += 1) {
          await emit(Buffer.alloc(1024, i));
          await new Promise((r) => setTimeout(r, 30));
        }
        return { sha256: 'b'.repeat(64), bytes: 15 * 1024, entryCount: 0 };
      }
    }), TOKEN, { streamIdleTimeoutMs: 120 });
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: { op: 'vm.export' } });
    const start = await client.nextJson();
    expect(start.type).toBe('stream-start');
    let bytes = 0;
    for (;;) {
      const frame = await client.nextFrame(10_000);
      if (frame.kind === WIRE_KIND_BYTES) bytes += frame.payload.length;
      else {
        const msg = JSON.parse(frame.payload.toString('utf8')) as { type?: string };
        expect(msg.type).toBe('response');
        break;
      }
    }
    expect(bytes).toBe(15 * 1024);
    client.close();
  });
});

describe('upload disk reservations (injected statfs)', () => {
  const GIB = 1024 ** 3;
  const uploadOutcome = {
    kind: 'upload' as const,
    streamRef: 'upl-r',
    maxBytes: 8 * GIB,
    complete: async () => ({ done: true })
  };

  it('rejects before stream-ready when backing fs cannot cover the reservation', async () => {
    const { DiskReservations } = await import("../src/disk-reservations.js");
    // 6GiB free, 1GiB margin → 5GiB usable < 8GiB request.
    const reservations = new DiskReservations(async () => ({ bavail: 6 * GIB, bsize: 1 }), GIB);
    const { socketPath } = await startServer(async () => uploadOutcome, TOKEN, undefined, reservations);
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: { op: 'file.pushStream' } });
    const res = await client.nextJson();
    expect(res.type).toBe('response');
    expect((res.response as { ok: boolean; error?: { code: string } }).ok).toBe(false);
    expect((res.response as { error?: { code: string } }).error?.code).toBe('VM_QUOTA_EXCEEDED');
    client.close();
  });

  it('concurrent uploads share one ledger: second rejects on combined demand', async () => {
    const { DiskReservations } = await import("../src/disk-reservations.js");
    // 10GiB free, 1GiB margin → 9GiB usable; two 8GiB uploads cannot both hold.
    const reservations = new DiskReservations(async () => ({ bavail: 10 * GIB, bsize: 1 }), GIB);
    const { socketPath } = await startServer(async () => ({ ...uploadOutcome, streamRef: `upl-${Math.random()}` }), TOKEN, undefined, reservations);
    const c1 = await TestClient.connect(socketPath);
    const c2 = await TestClient.connect(socketPath);
    await c1.auth(); await c2.auth();
    c1.sendJson({ type: 'request', request: { op: 'a' } });
    const r1 = await c1.nextJson();
    expect(r1.type).toBe('stream-ready'); // first holds 8GiB of 9GiB
    c2.sendJson({ type: 'request', request: { op: 'b' } });
    const r2 = await c2.nextJson();
    expect(r2.type).toBe('response');
    expect((r2.response as { ok: boolean }).ok).toBe(false);
    expect((r2.response as { error?: { code: string } }).error?.code).toBe('VM_QUOTA_EXCEEDED');
    c1.close(); c2.close();
  });

  it('releases the reservation on abort so a later upload is admitted', async () => {
    const { DiskReservations } = await import("../src/disk-reservations.js");
    const reservations = new DiskReservations(async () => ({ bavail: 10 * GIB, bsize: 1 }), GIB);
    const { socketPath } = await startServer(async () => ({ ...uploadOutcome, streamRef: 'upl-x' }), TOKEN, undefined, reservations);
    const c1 = await TestClient.connect(socketPath);
    await c1.auth();
    c1.sendJson({ type: 'request', request: { op: 'a' } });
    await c1.nextJson(); // stream-ready — 8GiB held
    c1.close(); // abort mid-upload
    await new Promise((r) => setTimeout(r, 100));
    expect(reservations.reservedBytes).toBe(0);
    const c2 = await TestClient.connect(socketPath);
    await c2.auth();
    c2.sendJson({ type: 'request', request: { op: 'b' } });
    const r2 = await c2.nextJson();
    expect(r2.type).toBe('stream-ready'); // admitted after release
    c2.close();
  });
});

describe('session open ordering', () => {
  it('never lets session frames precede the opening response', async () => {
    const { socketPath } = await startServer(async (_req, ctx) => {
      const sessionId = 'sess-early';
      // Guest output + exit landing during the open handshake must queue
      // behind the {kind:'session'} response, not beat it to the wire.
      void ctx.channel.emitData(sessionId, 1, Buffer.from('early-out'));
      ctx.channel.emitEnd(sessionId, 0, null, { return: 0 });
      return { kind: 'session', sessionId, result: { sessionId, fdsReady: true } };
    });
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: { op: 'exec.open' } });
    const res = await client.nextJson();
    expect(res.type).toBe('response');
    const rest: string[] = [];
    for (;;) {
      const frame = await client.nextFrame(2_000);
      if (frame.kind === WIRE_KIND_BYTES) continue;
      const msg = JSON.parse(frame.payload.toString('utf8')) as { type?: string };
      rest.push(String(msg.type));
      if (msg.type === 'session-end') break;
    }
    expect(rest[0]).toBe('session-data');
    expect(rest).toContain('session-meta');
    expect(rest[rest.length - 1]).toBe('session-end');
    client.close();
  });
});

describe('failed session open cleanup', () => {
  it('discards queued session frames and accounted bytes when exec.open fails', async () => {
    let attempt = 0;
    let pendingAtSecondOpen = -1;
    let strandedEmit: Promise<void> | undefined;
    const { socketPath } = await startServer(async (_req, ctx) => {
      attempt += 1;
      if (attempt === 1) {
        const sid = 'sess-fail';
        // Guest output racing the handshake queues per-session and accounts
        // bytes immediately; a later handshake failure must discard both.
        strandedEmit = ctx.channel.emitData(sid, 1, Buffer.alloc(128 * 1024));
        ctx.channel.emitEnd(sid, null, null);
        throw new Error('downstream handshake failed');
      }
      pendingAtSecondOpen = ctx.channel.pendingOutputBytes();
      const sid = 'sess-ok';
      return { kind: 'session', sessionId: sid, result: { sessionId: sid, fdsReady: true } };
    });
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: { op: 'exec.open' } });
    const err = await client.nextJson();
    expect(err.type).toBe('response');
    expect((err.response as { ok?: boolean } | undefined)?.ok).toBe(false);
    // The failed session's queued emitData promise must be resolved by the
    // discard — pre-fix it pends forever and its bytes stay accounted.
    await Promise.race([
      strandedEmit,
      new Promise((_, reject) => setTimeout(() => reject(new Error('stranded emitData never resolved')), 1_000))
    ]);
    client.sendJson({ type: 'request', request: { op: 'exec.open' } });
    const res = await client.nextJson();
    expect(res.type).toBe('response');
    expect(pendingAtSecondOpen).toBe(0);
    client.close();
  });
});

describe('decoder buffered-bytes bound (lifetime vs resident)', () => {
  it('streams >32MiB of well-formed frames without tripping the resident bound', async () => {
    const { socketPath } = await startServer(async () => ({ kind: 'result', result: { ok: true } }));
    const client = await TestClient.connect(socketPath);
    await client.auth();
    // ~36MiB cumulative across 40 sequential requests — every frame decodes
    // promptly so resident bufferedBytes stays near zero. The pre-fix
    // lifetime counter destroyed the connection at ~32MiB.
    const pad = 'x'.repeat(900 * 1024);
    for (let i = 0; i < 40; i++) {
      client.sendJson({ type: 'request', request: { op: 'pad', i, pad } });
      const res = await client.nextJson();
      expect(res.type).toBe('response');
      expect((res.response as { ok: boolean }).ok).toBe(true);
    }
    client.sendJson({ type: 'request', request: { op: 'still-alive' } });
    expect((await client.nextJson()).type).toBe('response');
    client.close();
  });

  it('destroys the connection when UNDECODED bytes exceed maxBufferedBytes', async () => {
    // Tight resident bound: a partial frame whose buffered tail exceeds it
    // must fail closed — distinct from cumulative lifetime traffic.
    const { socketPath } = await startServer(
      async () => ({ kind: 'result', result: {} }),
      TOKEN,
      { maxBufferedBytes: 256 }
    );
    const client = await TestClient.connect(socketPath);
    await client.auth();
    // Valid 4-byte length + kind, payload dribbled past the 256B bound.
    const head = Buffer.alloc(5);
    head.writeUInt32BE(4096, 0);
    head.writeUInt8(WIRE_KIND_JSON, 4);
    client.socket.write(head);
    client.socket.write(Buffer.alloc(300, 0x61)); // 300 undecoded bytes > 256
    await new Promise<void>((resolve) => client.socket.once('close', resolve));
    client.close();
  });
});

describe('upload admission disconnect race', () => {
  it('releases the disk reservation when the client disconnects during acquire', async () => {
    const { DiskReservations } = await import("../src/disk-reservations.js");
    const GIB = 1024 ** 3;
    const reservations = new DiskReservations(async () => ({ bavail: 10 * GIB, bsize: 1 }), GIB);
    // Widen the mkdir/acquire await window so the disconnect lands inside it.
    const orig = reservations.acquire.bind(reservations);
    vi.spyOn(reservations, 'acquire').mockImplementation(async (...args: Parameters<typeof orig>) => {
      await new Promise((r) => setTimeout(r, 120));
      return orig(...args);
    });
    const { socketPath, streamDir } = await startServer(
      async () => ({
        kind: 'upload' as const,
        streamRef: 'upl-disc',
        maxBytes: 1024,
        complete: async () => ({ done: true })
      }),
      TOKEN,
      undefined,
      reservations
    );
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: { op: 'file.push', params: {} } });
    // Disconnect while completeOutcome is still inside acquire().
    await new Promise((r) => setTimeout(r, 30));
    client.close();
    await new Promise((r) => setTimeout(r, 400));
    expect(reservations.reservedBytes).toBe(0);
    const { readdirSync } = await import('node:fs');
    expect(readdirSync(streamDir)).toHaveLength(0);
  });
});

describe('per-request close-waiter lifecycle', () => {
  function serverSideCloseListeners(server: VmSupervisorWireServer): number {
    const conns = (server as unknown as { connections: Set<{ socket: Socket }> }).connections;
    let total = 0;
    for (const conn of conns) total += conn.socket.listenerCount('close');
    return total;
  }

  it('keeps socket close-listener count flat across sequential requests on one connection', async () => {
    const { server, socketPath } = await startServer(async () => ({ kind: 'result', result: { ok: true } }));
    const client = await TestClient.connect(socketPath);
    await client.auth();
    const baseline = serverSideCloseListeners(server);
    expect(baseline).toBeGreaterThan(0);
    for (let i = 0; i < 15; i += 1) {
      const res = await client.request({ op: 'vm.status', requestId: `seq-${i}` });
      expect((res.response as { ok: boolean }).ok).toBe(true);
    }
    // Settled requests must not retain close waiters: the count returns to
    // the per-connection baseline instead of growing by 2 listeners/request.
    expect(serverSideCloseListeners(server)).toBe(baseline);
    client.close();
  });

  it('resolves ctx.closed on disconnect while a session is still bound', async () => {
    let sawClosed = false;
    const { socketPath } = await startServer(async (_req, ctx) => {
      void ctx.closed.then(() => { sawClosed = true; });
      return { kind: 'session', sessionId: 'sess-live', result: { sessionId: 'sess-live' } };
    });
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: { op: 'exec.open' } });
    const res = await client.nextJson();
    expect(res.type).toBe('response');
    client.close();
    await new Promise((r) => setTimeout(r, 60));
    expect(sawClosed).toBe(true);
  });

  it('aborts ctx.signal and resolves ctx.closed when the client disconnects mid-request', async () => {
    let sawSignal = false;
    let sawClosed = false;
    const { socketPath } = await startServer(async (_req, ctx) => {
      ctx.signal.addEventListener('abort', () => { sawSignal = true; });
      void ctx.closed.then(() => { sawClosed = true; });
      // Never settles on its own: only the disconnect path can end this.
      await new Promise<void>(() => {});
      return { kind: 'result', result: {} };
    });
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: { op: 'slow.op' } });
    await new Promise((r) => setTimeout(r, 30));
    client.close();
    await new Promise((r) => setTimeout(r, 60));
    expect(sawSignal).toBe(true);
    expect(sawClosed).toBe(true);
  });

  it('disarms the session waiter at session end and settled request waiters at request end', async () => {
    const events: string[] = [];
    let sessionCtx: WireRequestContext | undefined;
    const { server, socketPath } = await startServer(async (req, ctx) => {
      const op = (req as { op?: string }).op;
      if (op === 'exec.open') {
        sessionCtx = ctx;
        void ctx.closed.then(() => { events.push('session-ctx-closed'); });
        return { kind: 'session', sessionId: 'sess-w', result: { sessionId: 'sess-w' } };
      }
      void ctx.closed.then(() => { events.push(`result-ctx-${String(op)}-closed`); });
      return { kind: 'result', result: { ok: true } };
    });
    const client = await TestClient.connect(socketPath);
    await client.auth();
    const baseline = serverSideCloseListeners(server);

    client.sendJson({ type: 'request', request: { op: 'exec.open' } });
    const openRes = await client.nextJson();
    expect(openRes.type).toBe('response');
    expect(sessionCtx).toBeDefined();
    // End the session through the real channel path; the conn returns to idle.
    sessionCtx!.channel.emitEnd('sess-w', 0, null);
    for (;;) {
      const frame = await client.nextFrame();
      if (frame.kind !== WIRE_KIND_JSON) continue;
      const msg = JSON.parse(frame.payload.toString('utf8')) as { type?: string };
      if (msg.type === 'session-end') break;
    }
    // A settled result request must leave no retained waiter either.
    const res = await client.request({ op: 'vm.status' });
    expect((res.response as { ok: boolean }).ok).toBe(true);
    expect(serverSideCloseListeners(server)).toBe(baseline);

    // Disconnect now: the ended session's waiter was disarmed WITHOUT
    // resolving (session already ended cleanly) and the settled request's
    // waiter was removed — neither ctx.closed may fire.
    client.close();
    await new Promise((r) => setTimeout(r, 60));
    expect(events).toEqual([]);
  });
});

describe('upload ctx.closed/ctx.signal lifecycle (review fix)', () => {
  interface ConnRegs { closed: number; aborts: number }
  function ctxRegistries(server: VmSupervisorWireServer): ConnRegs {
    const conns = (server as unknown as {
      connections: Set<{ closedWaiters: Set<unknown>; requestAborts: Set<unknown> }>;
    }).connections;
    let closed = 0;
    let aborts = 0;
    for (const conn of conns) {
      closed += conn.closedWaiters.size;
      aborts += conn.requestAborts.size;
    }
    return { closed, aborts };
  }
  const flush = () => new Promise((r) => setTimeout(r, 60));

  it('notifies the handler and cleans up when the client disconnects mid-upload', async () => {
    let sawClosed = false;
    let sawAbort = false;
    let completed = false;
    const { server, socketPath, streamDir } = await startServer(async (_req, ctx) => {
      void ctx.closed.then(() => { sawClosed = true; });
      ctx.signal.addEventListener('abort', () => { sawAbort = true; });
      return {
        kind: 'upload' as const,
        streamRef: 'upl-mid',
        maxBytes: 4096,
        complete: async () => { completed = true; return { done: true }; }
      };
    });
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: { op: 'file.push' } });
    const ready = await client.nextJson();
    expect(ready.type).toBe('stream-ready');
    client.sendBytes(Buffer.from('partial-payload'));
    // Disconnect BEFORE stream-end: the upload is still in flight, so the
    // handler's ctx.closed/ctx.signal must still be armed to observe it.
    client.close();
    await vi.waitFor(() => {
      expect(sawClosed).toBe(true);
      expect(sawAbort).toBe(true);
    }, { timeout: 2_000 });
    expect(completed).toBe(false);
    expect(ctxRegistries(server)).toEqual({ closed: 0, aborts: 0 });
    const { readdirSync } = await import('node:fs');
    expect(readdirSync(streamDir)).toHaveLength(0);
  });

  it('keeps ctx armed through complete() and disarms after a clean stream-end', async () => {
    let sawClosed = false;
    let sawAbort = false;
    let armedInsideComplete = -1;
    let abortsInsideComplete = -1;
    const { server, socketPath } = await startServer(async (_req, ctx) => {
      void ctx.closed.then(() => { sawClosed = true; });
      ctx.signal.addEventListener('abort', () => { sawAbort = true; });
      return {
        kind: 'upload' as const,
        streamRef: 'upl-ok',
        maxBytes: 1024,
        complete: async () => {
          const regs = ctxRegistries(server);
          armedInsideComplete = regs.closed;
          abortsInsideComplete = regs.aborts;
          return { ok: true };
        }
      };
    });
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: { op: 'file.push' } });
    await client.nextJson(); // stream-ready
    client.sendBytes(Buffer.from('payload'));
    client.sendJson({ type: 'stream-end', streamRef: 'upl-ok' });
    const res = await client.nextJson();
    expect(res.type).toBe('response');
    expect((res.response as { ok: boolean }).ok).toBe(true);
    // The upload only settles once complete() returns — the notifications
    // must still be armed inside it, then disarm without firing.
    expect(armedInsideComplete).toBe(1);
    expect(abortsInsideComplete).toBe(1);
    await flush();
    expect(sawClosed).toBe(false);
    expect(sawAbort).toBe(false);
    expect(ctxRegistries(server)).toEqual({ closed: 0, aborts: 0 });
    client.close();
  });

  it('keeps waiter/abort registries flat across sequential uploads on one connection', async () => {
    const { server, socketPath } = await startServer(async () => ({
      kind: 'upload' as const,
      streamRef: 'upl-seq',
      maxBytes: 1024,
      complete: async () => ({ ok: true })
    }));
    const client = await TestClient.connect(socketPath);
    await client.auth();
    for (let i = 0; i < 6; i += 1) {
      client.sendJson({ type: 'request', request: { op: 'file.push', i } });
      const ready = await client.nextJson();
      expect(ready.type).toBe('stream-ready');
      client.sendBytes(Buffer.from(`seq-${i}`));
      client.sendJson({ type: 'stream-end', streamRef: 'upl-seq' });
      const res = await client.nextJson();
      expect(res.type).toBe('response');
      expect((res.response as { ok: boolean }).ok).toBe(true);
      expect(ctxRegistries(server)).toEqual({ closed: 0, aborts: 0 });
    }
    client.close();
  });

  it('disarms ctx and stays usable when upload complete() fails', async () => {
    let sawClosed = false;
    let sawAbort = false;
    const { server, socketPath } = await startServer(async (req, ctx) => {
      const op = (req as { op?: string }).op;
      if (op === 'bad.upload') {
        void ctx.closed.then(() => { sawClosed = true; });
        ctx.signal.addEventListener('abort', () => { sawAbort = true; });
        return {
          kind: 'upload' as const,
          streamRef: 'upl-bad',
          maxBytes: 1024,
          complete: async () => { throw new Error('completion exploded'); }
        };
      }
      return { kind: 'result' as const, result: { ok: true } };
    });
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: { op: 'bad.upload' } });
    await client.nextJson(); // stream-ready
    client.sendBytes(Buffer.from('x'));
    client.sendJson({ type: 'stream-end', streamRef: 'upl-bad' });
    const res = await client.nextJson();
    expect(res.type).toBe('response');
    expect((res.response as { ok: boolean }).ok).toBe(false);
    await flush();
    expect(sawClosed).toBe(false);
    expect(sawAbort).toBe(false);
    expect(ctxRegistries(server)).toEqual({ closed: 0, aborts: 0 });
    // The connection returned to idle: a plain request still works.
    const after = await client.request({ op: 'vm.status' });
    expect((after.response as { ok: boolean }).ok).toBe(true);
    client.close();
  });

  it('keeps ctx armed across a mismatched stream-end, then disarms at real settle', async () => {
    const { server, socketPath } = await startServer(async () => ({
      kind: 'upload' as const,
      streamRef: 'upl-real',
      maxBytes: 1024,
      complete: async () => ({ ok: true })
    }));
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: { op: 'file.push' } });
    await client.nextJson(); // stream-ready
    client.sendBytes(Buffer.from('data'));
    // Wrong streamRef: protocol error, but the upload itself stays live.
    client.sendJson({ type: 'stream-end', streamRef: 'upl-WRONG' });
    const err = await client.nextJson();
    expect(err.type).toBe('error');
    // Still mid-upload: notifications must remain armed.
    expect(ctxRegistries(server)).toEqual({ closed: 1, aborts: 1 });
    client.sendJson({ type: 'stream-end', streamRef: 'upl-real' });
    const res = await client.nextJson();
    expect(res.type).toBe('response');
    expect((res.response as { ok: boolean }).ok).toBe(true);
    expect(ctxRegistries(server)).toEqual({ closed: 0, aborts: 0 });
    client.close();
  });

  it('notifies ctx.closed/ctx.signal when an oversized upload destroys the connection', async () => {
    let sawClosed = false;
    let sawAbort = false;
    const { socketPath } = await startServer(async (_req, ctx) => {
      void ctx.closed.then(() => { sawClosed = true; });
      ctx.signal.addEventListener('abort', () => { sawAbort = true; });
      return {
        kind: 'upload' as const,
        streamRef: 'upl-big',
        maxBytes: 4,
        complete: async () => ({})
      };
    });
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: {} });
    await client.nextJson(); // stream-ready
    client.sendBytes(Buffer.alloc(8)); // exceeds maxBytes → destroyConnection
    await vi.waitFor(() => {
      expect(sawClosed).toBe(true);
      expect(sawAbort).toBe(true);
    }, { timeout: 2_000 });
    client.close();
  });

  it('notifies ctx.closed/ctx.signal when the client disconnects during complete()', async () => {
    let releaseComplete!: () => void;
    const gate = new Promise<void>((resolve) => { releaseComplete = resolve; });
    let sawClosed = false;
    let sawAbort = false;
    const { socketPath } = await startServer(async (_req, ctx) => {
      void ctx.closed.then(() => { sawClosed = true; });
      ctx.signal.addEventListener('abort', () => { sawAbort = true; });
      return {
        kind: 'upload' as const,
        streamRef: 'upl-gate',
        maxBytes: 1024,
        complete: async () => { await gate; return { ok: true }; }
      };
    });
    const client = await TestClient.connect(socketPath);
    await client.auth();
    try {
      client.sendJson({ type: 'request', request: {} });
      await client.nextJson(); // stream-ready
      client.sendBytes(Buffer.from('data'));
      client.sendJson({ type: 'stream-end', streamRef: 'upl-gate' });
      await flush(); // server is now inside the gated complete()
      client.close();
      await vi.waitFor(() => {
        expect(sawClosed).toBe(true);
        expect(sawAbort).toBe(true);
      }, { timeout: 2_000 });
    } finally {
      releaseComplete();
      client.close();
    }
  });

  it('disarms ctx when upload admission is rejected — connection stays usable', async () => {
    const { DiskReservations } = await import('../src/disk-reservations.js');
    const GIB = 1024 ** 3;
    // 6GiB free, 1GiB margin → 5GiB usable < 8GiB request: admission fails
    // BEFORE stream-ready, so ctx must disarm at request settle, not hang.
    const reservations = new DiskReservations(async () => ({ bavail: 6 * GIB, bsize: 1 }), GIB);
    let sawClosed = false;
    let sawAbort = false;
    const { server, socketPath } = await startServer(async (req, ctx) => {
      const op = (req as { op?: string }).op;
      if (op === 'file.pushStream') {
        void ctx.closed.then(() => { sawClosed = true; });
        ctx.signal.addEventListener('abort', () => { sawAbort = true; });
        return {
          kind: 'upload' as const,
          streamRef: 'upl-denied',
          maxBytes: 8 * GIB,
          complete: async () => ({})
        };
      }
      return { kind: 'result' as const, result: { ok: true } };
    }, TOKEN, undefined, reservations);
    const client = await TestClient.connect(socketPath);
    await client.auth();
    client.sendJson({ type: 'request', request: { op: 'file.pushStream' } });
    const res = await client.nextJson();
    expect(res.type).toBe('response');
    expect((res.response as { ok: boolean }).ok).toBe(false);
    await flush();
    expect(sawClosed).toBe(false);
    expect(sawAbort).toBe(false);
    expect(ctxRegistries(server)).toEqual({ closed: 0, aborts: 0 });
    const after = await client.request({ op: 'vm.status' });
    expect((after.response as { ok: boolean }).ok).toBe(true);
    client.close();
  });
});
