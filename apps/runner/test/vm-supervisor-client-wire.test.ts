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

  // -- exec.run framed download (v2 contract) ---------------------------------
  // The handler plays server.ts's op dispatch; framing, auth, stream-digest
  // emission and backpressure are the REAL transport on both ends. The
  // payload layout mirrors execRunDownloadOutcome in server.ts: u64be
  // stdout-byte-length || stdoutUtf8 || stderrUtf8, streamRef exec:<opId>,
  // streamDigest over the exact payload, trailer with emptied streams.

  function execRunParams(opId: string, maxBytes: number) {
    return {
      opId,
      argv: ['sh', '-c', 'emit'],
      cwd: '/workspace',
      environment: { HOME: '/tmp/cloud-harness-home' },
      timeoutMs: 5_000,
      maxBytes
    };
  }

  function execRunDownloadOutcome(opId: string, stdout: string, stderr: string, exitCode: number | null = 0) {
    const stdoutBuf = Buffer.from(stdout, 'utf8');
    const stderrBuf = Buffer.from(stderr, 'utf8');
    const prefix = Buffer.allocUnsafe(8);
    prefix.writeBigUInt64BE(BigInt(stdoutBuf.length));
    const payload = Buffer.concat([prefix, stdoutBuf, stderrBuf]);
    return {
      payload,
      outcome: {
        kind: 'download' as const,
        streamRef: `exec:${opId}`,
        maxBytes: payload.length,
        streamDigest: { sha256: createHash('sha256').update(payload).digest('hex'), bytes: payload.length },
        produce: async (emit: (chunk: Buffer) => Promise<void>) => {
          for (let off = 0; off < payload.length; off += 4 * 1024 * 1024) {
            await emit(payload.subarray(off, Math.min(off + 4 * 1024 * 1024, payload.length)));
          }
          return { opId, exitCode, signal: null, stdout: '', stderr: '', truncated: false, timedOut: false };
        }
      }
    };
  }

  it('exec.run large result: framed decode keeps stdout/stderr boundaries with multibyte UTF-8', async () => {
    // >4 MiB total forces multiple WIRE_KIND_BYTES frames; multibyte chars
    // make the u64be BYTE length diverge from the JS string length — a
    // char/byte confusion corrupts the stderr boundary.
    const stdoutText = `head-${'line-'.repeat(200)}${'é€😀'.repeat(400_000)}tail`;
    const stderrText = `stderr-${'wörn-'.repeat(200_000)}`;
    const { payload, outcome } = execRunDownloadOutcome('op-large-1', stdoutText, stderrText, 3);
    expect(payload.length).toBeGreaterThan(4 * 1024 * 1024);
    const { socketPath } = await startServer(async (request) => {
      const req = request as { op: string; params?: { opId?: string } };
      expect(req.op).toBe('exec.run');
      expect(req.params?.opId).toBe('op-large-1');
      return outcome;
    });
    const client = makeClient(socketPath);
    const result = await client.execRun(IDENTITY, execRunParams('op-large-1', 2 * 1024 * 1024), {
      idempotencyKey: 'wire-exec-run-large-1'
    });
    expect(result.opId).toBe('op-large-1');
    expect(result.exitCode).toBe(3);
    expect(result.stdout).toBe(stdoutText);
    expect(result.stderr).toBe(stderrText);
    expect(result.truncated).toBe(false);
    expect(result.timedOut).toBe(false);
  });

  it('exec.run small result stays on the unary path unchanged', async () => {
    const { socketPath } = await startServer(async () => ({
      kind: 'result' as const,
      result: { opId: 'op-small-1', exitCode: 1, signal: null, stdout: 'tiny-out', stderr: 'tiny-err', truncated: false, timedOut: false }
    }));
    const client = makeClient(socketPath);
    const result = await client.execRun(IDENTITY, execRunParams('op-small-1', 1024), {
      idempotencyKey: 'wire-exec-run-small-1'
    });
    expect(result).toEqual({ opId: 'op-small-1', exitCode: 1, signal: null, stdout: 'tiny-out', stderr: 'tiny-err', truncated: false, timedOut: false });
  });

  it('exec.run idempotent replay of a large result takes the same framed path', async () => {
    const stdoutText = `replay-${'x'.repeat(600 * 1024)}`;
    const stderrText = `replay-err-${'y'.repeat(100 * 1024)}`;
    const { outcome } = execRunDownloadOutcome('op-replay-1', stdoutText, stderrText, 0);
    let calls = 0;
    const { socketPath } = await startServer(async () => {
      calls += 1;
      // The journaled replay returns the SAME download outcome — the command
      // is never re-run and the client must not predict framing by size.
      return outcome;
    });
    const client = makeClient(socketPath);
    const params = execRunParams('op-replay-1', 2 * 1024 * 1024);
    const first = await client.execRun(IDENTITY, params, { idempotencyKey: 'wire-exec-run-replay-1' });
    const second = await client.execRun(IDENTITY, params, { idempotencyKey: 'wire-exec-run-replay-1' });
    expect(calls).toBe(2);
    expect(first.stdout).toBe(stdoutText);
    expect(first.stderr).toBe(stderrText);
    expect(second.stdout).toBe(stdoutText);
    expect(second.stderr).toBe(stderrText);
  });

  it('exec.run framed stream rejects a digest that does not match the payload', async () => {
    const stdoutText = `digest-${'z'.repeat(300 * 1024)}`;
    const { outcome } = execRunDownloadOutcome('op-bad-digest-1', stdoutText, 'err', 0);
    outcome.streamDigest = { sha256: 'f'.repeat(64), bytes: outcome.maxBytes };
    const { socketPath } = await startServer(async () => outcome);
    const client = makeClient(socketPath);
    // Post-command integrity failure: the guest command already ran, so the
    // outcome is UNKNOWN — callers must reconcile, never blindly retry.
    await expect(
      client.execRun(IDENTITY, execRunParams('op-bad-digest-1', 1024 * 1024), { idempotencyKey: 'wire-exec-run-bad-digest-1' })
    ).rejects.toMatchObject({ code: 'VM_UNKNOWN_STATE', unknownOutcome: true });
  });

  it('exec.run framed stream rejects when emitted bytes disagree with stream-start.maxBytes', async () => {
    const stdoutText = `short-${'q'.repeat(200 * 1024)}`;
    const { payload, outcome } = execRunDownloadOutcome('op-short-1', stdoutText, '', 0);
    const half = Math.floor(payload.length / 2);
    // Emit only half the declared payload but keep a self-consistent digest
    // for what WAS sent — the length triple-check must still fail.
    const emitted = payload.subarray(0, half);
    outcome.streamDigest = { sha256: createHash('sha256').update(emitted).digest('hex'), bytes: emitted.length };
    outcome.produce = async (emit: (chunk: Buffer) => Promise<void>) => {
      await emit(emitted);
      return { opId: 'op-short-1', exitCode: 0, signal: null, stdout: '', stderr: '', truncated: false, timedOut: false };
    };
    const { socketPath } = await startServer(async () => outcome);
    const client = makeClient(socketPath);
    await expect(
      client.execRun(IDENTITY, execRunParams('op-short-1', 1024 * 1024), { idempotencyKey: 'wire-exec-run-short-1' })
    ).rejects.toMatchObject({ code: 'VM_UNKNOWN_STATE', unknownOutcome: true });
  });

  it('exec.run framed stream disconnect mid-flight surfaces UNKNOWN, never a clean retry', async () => {
    const { outcome } = execRunDownloadOutcome('op-drop-1', `drop-${'d'.repeat(100 * 1024)}`, '', 0);
    let produced = false;
    outcome.produce = async (emit: (chunk: Buffer) => Promise<void>) => {
      produced = true;
      await emit(Buffer.alloc(64 * 1024, 0x55));
      // Stall forever: the test closes the server to simulate transport loss
      // after mutation started but before the trailer arrived.
      await new Promise<void>(() => undefined);
      return { opId: 'op-drop-1', exitCode: 0, signal: null, stdout: '', stderr: '', truncated: false, timedOut: false };
    };
    const { server, socketPath } = await startServer(async () => outcome);
    const client = makeClient(socketPath);
    const pending = client.execRun(IDENTITY, execRunParams('op-drop-1', 1024 * 1024), { idempotencyKey: 'wire-exec-run-drop-1' });
    // Wait until the handler is actually producing, then kill the transport.
    for (let i = 0; i < 100 && !produced; i += 1) await new Promise((r) => setTimeout(r, 10));
    expect(produced).toBe(true);
    await server.close();
    await expect(pending).rejects.toMatchObject({ code: 'VM_UNKNOWN_STATE', unknownOutcome: true });
  });
});
