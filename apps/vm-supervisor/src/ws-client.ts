import { connect, type Socket } from 'node:net';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Minimal RFC 6455 WebSocket client over a Unix-domain socket. Just enough
 * for the Incus exec/file channels: HTTP upgrade handshake, masked client
 * frames, unmasked server frames, ping→pong, close handshake, bounded
 * buffering with backpressure via 'drain'. No extensions, no permessage-deflate.
 */

export interface WsClientOptions {
  socketPath: string;
  /** HTTP path including query, e.g. `/1.0/instances/x/exec/0?secret=...`. */
  path: string;
  /** Optional extra handshake headers (Incus may want none beyond standard). */
  headers?: Record<string, string>;
  /** Handshake deadline; default 5s per the supervisor's ws-connect deadline. */
  handshakeTimeoutMs?: number;
}

export interface WsMessage {
  opcode: number; // 0x1 text, 0x2 binary, 0x8 close, 0x9 ping, 0xA pong
  payload: Buffer;
}

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_FRAME_PAYLOAD = 16 * 1024 * 1024;
const MAX_BUFFERED_BYTES = 64 * 1024 * 1024;

export class WsClient {
  private socket!: Socket;
  private buffer = Buffer.alloc(0);
  private fragments: Buffer[] = [];
  private fragmentOpcode = 0;
  private closed = false;
  private handshakeResolve!: () => void;
  private handshakeReject!: (error: Error) => void;
  private readonly messageListeners = new Set<(message: WsMessage) => void>();
  private readonly closeListeners = new Set<(code: number, reason: string) => void>();
  private readonly errorListeners = new Set<(error: Error) => void>();
  private closeCode = 1000;
  private closeReason = '';

  static async connect(options: WsClientOptions): Promise<WsClient> {
    const client = new WsClient();
    await client.open(options);
    return client;
  }

  private open(options: WsClientOptions): Promise<void> {
    return new Promise((resolve, reject) => {
      this.handshakeResolve = resolve;
      this.handshakeReject = reject;
      const key = randomBytes(16).toString('base64');
      const lines = [
        `GET ${options.path} HTTP/1.1`,
        `Host: localhost`,
        `Upgrade: websocket`,
        `Connection: Upgrade`,
        `Sec-WebSocket-Key: ${key}`,
        `Sec-WebSocket-Version: 13`
      ];
      for (const [name, value] of Object.entries(options.headers ?? {})) {
        lines.push(`${name}: ${value}`);
      }
      const request = lines.join('\r\n') + '\r\n\r\n';

      this.socket = connect({ path: options.socketPath });
      let handshakeDone = false;
      let headerBuffer = Buffer.alloc(0);

      const handshakeTimeout = setTimeout(() => {
        if (!handshakeDone) {
          this.socket.destroy();
          reject(new Error('websocket handshake timed out'));
        }
      }, options.handshakeTimeoutMs ?? 5_000);

      this.socket.on('connect', () => {
        this.socket.write(request);
      });
      this.socket.on('data', (chunk: Buffer) => {
        if (!handshakeDone) {
          headerBuffer = Buffer.concat([headerBuffer, chunk]);
          const idx = headerBuffer.indexOf('\r\n\r\n');
          if (idx === -1) {
            if (headerBuffer.length > 64 * 1024) {
              this.socket.destroy();
              reject(new Error('websocket handshake headers exceeded bound'));
            }
            return;
          }
          const head = headerBuffer.subarray(0, idx).toString('latin1');
          const rest = headerBuffer.subarray(idx + 4);
          const statusLine = head.split('\r\n')[0] ?? '';
          if (!statusLine.includes('101')) {
            this.socket.destroy();
            reject(new Error(`websocket upgrade refused: ${statusLine}`));
            return;
          }
          // RFC 6455: the accept key must be SHA-1(key + GUID), base64. Verify
          // it so a non-Incus peer on the socket cannot complete the upgrade.
          const acceptHeader = head.split('\r\n')
            .map((line) => line.split(':', 2))
            .find(([name]) => name?.trim().toLowerCase() === 'sec-websocket-accept')?.[1]
            ?.trim();
          const expectedAccept = createHash('sha1').update(`${key}${WS_GUID}`).digest('base64');
          const acceptBytes = Buffer.from(acceptHeader ?? '', 'utf8');
          const expectedBytes = Buffer.from(expectedAccept, 'utf8');
          if (acceptBytes.length !== expectedBytes.length || !timingSafeEqual(acceptBytes, expectedBytes)) {
            this.socket.destroy();
            reject(new Error('websocket accept key mismatch'));
            return;
          }
          handshakeDone = true;
          clearTimeout(handshakeTimeout);
          this.buffer = rest;
          resolve();
          this.drainFrames();
          return;
        }
        this.buffer = Buffer.concat([this.buffer, chunk]);
        if (this.buffer.length > MAX_BUFFERED_BYTES + MAX_FRAME_PAYLOAD) {
          this.fail(new Error('websocket receive buffer exceeded bound'));
          return;
        }
        this.drainFrames();
      });
      this.socket.on('error', (error) => {
        if (!handshakeDone) {
          clearTimeout(handshakeTimeout);
          reject(error);
        } else {
          this.fail(error);
        }
      });
      this.socket.on('close', () => {
        if (!handshakeDone) {
          clearTimeout(handshakeTimeout);
          reject(new Error('websocket closed during handshake'));
        } else {
          this.emitClose(this.closeCode, this.closeReason);
        }
      });
    });
  }

  onMessage(listener: (message: WsMessage) => void): () => void {
    this.messageListeners.add(listener);
    return () => this.messageListeners.delete(listener);
  }

  onClose(listener: (code: number, reason: string) => void): () => void {
    this.closeListeners.add(listener);
    return () => this.closeListeners.delete(listener);
  }

  onError(listener: (error: Error) => void): () => void {
    this.errorListeners.add(listener);
    return () => this.errorListeners.delete(listener);
  }

  /** Send a frame; resolves false when the socket is closing/closed. */
  send(opcode: number, payload: Buffer | string): boolean {
    if (this.closed) return false;
    const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
    if (data.length > MAX_FRAME_PAYLOAD) {
      this.fail(new Error('websocket send payload exceeded bound'));
      return false;
    }
    const header: number[] = [0x80 | opcode];
    const len = data.length;
    if (len < 126) {
      header.push(0x80 | len);
    } else if (len < 65_536) {
      header.push(0x80 | 126, (len >> 8) & 0xff, len & 0xff);
    } else {
      header.push(0x80 | 127);
      for (let i = 7; i >= 0; i -= 1) header.push(Math.floor(len / 2 ** (8 * i)) & 0xff);
    }
    const mask = randomBytes(4);
    header.push(...mask);
    const masked = Buffer.allocUnsafe(len);
    for (let i = 0; i < len; i += 1) masked[i] = data[i]! ^ mask[i % 4]!;
    try {
      return this.socket.write(Buffer.concat([Buffer.from(header), masked]));
    } catch {
      return false;
    }
  }

  sendText(text: string): boolean {
    return this.send(0x1, text);
  }

  sendBinary(data: Buffer): boolean {
    return this.send(0x2, data);
  }

  ping(payload: Buffer = Buffer.alloc(0)): boolean {
    return this.send(0x9, payload);
  }

  /** Stop 'data' events — TCP backpressure propagates to the peer. */
  pause(): void {
    this.socket.pause();
  }

  resume(): void {
    this.socket.resume();
  }

  close(code = 1000, reason = ''): void {
    if (this.closed) return;
    const reasonBytes = Buffer.from(reason.slice(0, 120), 'utf8');
    const payload = Buffer.alloc(2 + reasonBytes.length);
    payload.writeUInt16BE(code, 0);
    reasonBytes.copy(payload, 2);
    this.send(0x8, payload);
    this.socket.end();
    this.markClosed(code, reason);
  }

  get isClosed(): boolean {
    return this.closed;
  }

  private markClosed(code: number, reason: string): void {
    if (this.closed) return;
    this.closed = true;
    this.closeCode = code;
    this.closeReason = reason;
  }

  private drainFrames(): void {
    for (;;) {
      if (this.buffer.length < 2) return;
      const b0 = this.buffer[0]!;
      const b1 = this.buffer[1]!;
      const fin = (b0 & 0x80) !== 0;
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let offset = 2;
      if (len === 126) {
        if (this.buffer.length < 4) return;
        len = this.buffer.readUInt16BE(2);
        offset = 4;
      } else if (len === 127) {
        if (this.buffer.length < 10) return;
        const big = this.buffer.readBigUInt64BE(2);
        if (big > BigInt(MAX_FRAME_PAYLOAD)) {
          this.fail(new Error('websocket frame exceeded bound'));
          return;
        }
        len = Number(big);
        offset = 10;
      }
      if (len > MAX_FRAME_PAYLOAD) {
        this.fail(new Error('websocket frame exceeded bound'));
        return;
      }
      let mask: Buffer | undefined;
      if (masked) {
        if (this.buffer.length < offset + 4) return;
        mask = this.buffer.subarray(offset, offset + 4);
        offset += 4;
      }
      if (this.buffer.length < offset + len) return;
      let payload = this.buffer.subarray(offset, offset + len);
      if (mask !== undefined) {
        const unmasked = Buffer.allocUnsafe(len);
        for (let i = 0; i < len; i += 1) unmasked[i] = payload[i]! ^ mask[i % 4]!;
        payload = unmasked;
      }
      this.buffer = this.buffer.subarray(offset + len);
      this.handleFrame(fin, opcode, payload);
      if (this.closed) return;
    }
  }

  private handleFrame(fin: boolean, opcode: number, payload: Buffer): void {
    if (opcode === 0x8) {
      const code = payload.length >= 2 ? payload.readUInt16BE(0) : 1000;
      const reason = payload.length > 2 ? payload.subarray(2).toString('utf8') : '';
      this.markClosed(code, reason);
      this.socket.end();
      this.emitClose(code, reason);
      return;
    }
    if (opcode === 0x9) {
      this.send(0xA, payload);
      return;
    }
    if (opcode === 0xA) return;
    if (opcode === 0x0) {
      this.fragments.push(payload);
      if (!fin) return;
      const full = Buffer.concat(this.fragments);
      this.fragments = [];
      this.dispatch(this.fragmentOpcode, full);
      this.fragmentOpcode = 0;
      return;
    }
    if (opcode === 0x1 || opcode === 0x2) {
      if (!fin) {
        this.fragmentOpcode = opcode;
        this.fragments = [payload];
        return;
      }
      this.dispatch(opcode, payload);
    }
  }

  private dispatch(opcode: number, payload: Buffer): void {
    for (const listener of this.messageListeners) {
      try {
        listener({ opcode, payload });
      } catch {
        // Listener errors must not kill the socket loop.
      }
    }
  }

  private emitClose(code: number, reason: string): void {
    for (const listener of this.closeListeners) {
      try {
        listener(code, reason);
      } catch {
        // ignore
      }
    }
  }

  private fail(error: Error): void {
    for (const listener of this.errorListeners) {
      try {
        listener(error);
      } catch {
        // ignore
      }
    }
    this.socket.destroy();
    this.markClosed(1011, error.message.slice(0, 120));
    this.emitClose(1011, error.message.slice(0, 120));
  }
}
