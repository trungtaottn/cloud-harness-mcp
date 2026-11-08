import { createHash } from 'node:crypto';
import { createServer, type Server, type Socket } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { WsClient, type WsMessage } from '../src/ws-client.js';

/**
 * Parser-level EOF regressions over a REAL unix socket: a stub server
 * completes the RFC6455 upgrade then drives arbitrary byte sequences +
 * TCP FIN. Proves a clean FIN carrying a partial frame or unterminated
 * fragment is reported as abnormal (1006), never as clean EOF (1000).
 */

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const cleanups: Array<() => void> = [];

function startStubServer(): Promise<{ socketPath: string; server: Server; lastSocket: () => Socket | undefined }> {
  const dir = mkdtempSync(join(tmpdir(), 'wsclient-'));
  const socketPath = join(dir, 'w.sock');
  let accepted: Socket | undefined;
  const server = createServer((socket) => {
    accepted = socket;
    let buf = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const idx = buf.indexOf('\r\n\r\n');
      if (idx === -1) return;
      socket.removeAllListeners('data');
      const head = buf.subarray(0, idx).toString('latin1');
      const key = head.split('\r\n')
        .map((l) => l.split(':', 2))
        .find(([n]) => n?.trim().toLowerCase() === 'sec-websocket-key')?.[1]?.trim() ?? '';
      const accept = createHash('sha1').update(`${key}${WS_GUID}`).digest('base64');
      socket.write(
        'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\nConnection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
      );
    });
  });
  return new Promise((resolve) => {
    server.listen(socketPath, () => {
      cleanups.push(() => { server.close(); rmSync(dir, { recursive: true, force: true }); });
      resolve({ socketPath, server, lastSocket: () => accepted });
    });
  });
}

/** Connect, then hand the accepted socket to `drive` for byte-level control. */
async function connectAndDrive(
  drive: (socket: Socket) => void
): Promise<{ code: number; reason: string }> {
  const { socketPath, lastSocket } = await startStubServer();
  const client = await WsClient.connect({ socketPath, path: '/x', handshakeTimeoutMs: 2_000 });
  const closed = new Promise<{ code: number; reason: string }>((resolve) => {
    client.onClose((code, reason) => resolve({ code, reason }));
  });
  // Real consumers attach a message listener immediately (IncusExecSession
  // does); without one, complete frames queue as pendingMessages and the
  // EOF check rightly treats undelivered messages as abnormal.
  client.onMessage(() => undefined);
  // The stub accepts on 'connection'; wait a tick for the socket reference.
  await new Promise((r) => setTimeout(r, 10));
  const sock = lastSocket();
  if (sock === undefined) throw new Error('stub server never accepted');
  drive(sock);
  const result = await closed;
  client.close(1000, 'test-done');
  return result;
}

afterEach(() => {
  while (cleanups.length > 0) cleanups.pop()!();
});

describe('WsClient EOF frame-integrity', () => {
  it('reports clean EOF (1000) when FIN follows only complete frames', async () => {
    const { code } = await connectAndDrive((sock) => {
      // One complete binary frame "hi", then TCP FIN — no close frame.
      sock.write(Buffer.from([0x82, 0x02, 0x68, 0x69]));
      sock.end();
    });
    expect(code).toBe(1000);
  });

  it('reports abnormal close (1006) when FIN truncates a frame header', async () => {
    const { code } = await connectAndDrive((sock) => {
      // Binary frame declaring 5-byte payload, header says len=126 ext —
      // only 2 of the 4 header bytes arrive before FIN.
      sock.write(Buffer.from([0x82, 0x7e, 0x00]));
      sock.end();
    });
    expect(code).toBe(1006);
  });

  it('reports abnormal close (1006) when FIN truncates a frame payload', async () => {
    const { code } = await connectAndDrive((sock) => {
      // Complete-looking header for 5 payload bytes; only 3 arrive pre-FIN.
      sock.write(Buffer.from([0x82, 0x05, 0x68, 0x69, 0x21]));
      sock.end();
    });
    expect(code).toBe(1006);
  });

  it('reports abnormal close (1006) when FIN leaves a fragmented message unfinished', async () => {
    const { code } = await connectAndDrive((sock) => {
      // fin=0 binary fragment, then FIN before the continuation frame.
      sock.write(Buffer.from([0x02, 0x02, 0x68, 0x69]));
      sock.end();
    });
    expect(code).toBe(1006);
  });

  it('reports abnormal close (1006) when FIN leaves a lone continuation frame', async () => {
    const { code } = await connectAndDrive((sock) => {
      // fin=0 continuation opcode with no started fragment — residual
      // fragment state at FIN must not pass as clean EOF.
      sock.write(Buffer.from([0x00, 0x02, 0x68, 0x69]));
      sock.end();
    });
    expect(code).toBe(1006);
  });
});

describe('WsClient send backpressure and pre-listener queue', () => {
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  it('returns true when socket.write() applies backpressure and paces via waitForDrain', async () => {
    const { socketPath, lastSocket } = await startStubServer();
    const client = await WsClient.connect({ socketPath, path: '/x', handshakeTimeoutMs: 2_000 });
    client.onMessage(() => undefined);
    await sleep(10);
    const sock = lastSocket();
    if (sock === undefined) throw new Error('stub server never accepted');
    // Stop reading: the peer kernel buffer fills, so client write() returns
    // false — accepted data under backpressure, NOT a send failure.
    sock.pause();
    const chunk = Buffer.alloc(4 * 1024 * 1024);
    for (let i = 0; i < 8; i += 1) {
      expect(client.sendBinary(chunk)).toBe(true);
    }
    const drained = client.waitForDrain();
    let resolved = false;
    void drained.then(() => { resolved = true; });
    await sleep(60);
    // Real backpressure engaged: the kernel buffer is still full.
    expect(resolved).toBe(false);
    sock.on('data', () => undefined); // discard once flowing
    sock.resume();
    await drained;
    expect(resolved).toBe(true);
    client.close(1000, 'done');
  });

  it('delivers a complete frame that arrives before the first onMessage listener', async () => {
    const { socketPath, lastSocket } = await startStubServer();
    const client = await WsClient.connect({ socketPath, path: '/x', handshakeTimeoutMs: 2_000 });
    await sleep(10);
    const sock = lastSocket();
    if (sock === undefined) throw new Error('stub server never accepted');
    // Server pushes output while the exec channel is still handshaking —
    // no listener attached yet. It must queue, not vanish.
    sock.write(Buffer.from([0x82, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f]));
    const got: WsMessage[] = [];
    client.onMessage((m) => got.push(m));
    await sleep(60);
    expect(got).toHaveLength(1);
    expect(got[0]!.opcode).toBe(0x2);
    expect(got[0]!.payload.toString()).toBe('hello');
    client.close(1000, 'done');
  });
});
