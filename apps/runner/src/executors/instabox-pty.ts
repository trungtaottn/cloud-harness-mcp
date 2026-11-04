import WebSocket from 'ws';
import { HarnessError } from '@cloud-harness/contracts';
import { createHash } from 'node:crypto';
import { posix } from 'node:path';
import type { PtyConnection, PtyEnd, PtyExecState, PtyOpenRequest, PtyTransport } from '../docker-pty.js';
import type { RemoteExecutorRef } from './execution-backend.js';
import { InstaBoxProviderError, shellQuote, type InstaBoxBackend } from './instabox-backend.js';

class SocketConnection implements PtyConnection {
  private dataListeners: Array<(chunk: Buffer) => void> = [];
  private endListeners: Array<(end: PtyEnd) => void> = [];
  private pending: Buffer[] = [];
  private pendingBytes = 0;
  private end: PtyEnd | undefined;
  private initializing = true;
  private initialization = Buffer.alloc(0);
  constructor(readonly execId: string, readonly socket: WebSocket, private readonly validate: () => void) {
    socket.on('message', (data, binary) => {
      if (this.end) return;
      if (binary) {
        let chunk = Buffer.isBuffer(data) ? data : Buffer.from(data as ArrayBuffer);
        if (this.initializing) {
          this.initialization = Buffer.concat([this.initialization, chunk]);
          if (this.initialization.length > 1048576) return this.finish({ error: new InstaBoxProviderError('terminal_bootstrap_too_large') });
          const marker = Buffer.from(`\x1eCH_READY_${this.execId}\x1f`);
          const index = this.initialization.indexOf(marker);
          if (index < 0) return;
          chunk = this.initialization.subarray(index + marker.length);
          this.initialization = Buffer.alloc(0);
          this.initializing = false;
        }
        if (this.dataListeners.length) for (const listener of this.dataListeners) listener(chunk);
        else { this.pendingBytes += chunk.length; if (this.pendingBytes > 1048576) return this.finish({ error: new InstaBoxProviderError('terminal_backpressure') }); this.pending.push(chunk); }
      } else {
        try { const control = JSON.parse(data.toString()) as { type: string };
          if (control.type === 'taken') this.finish({ error: new InstaBoxProviderError('terminal_taken') });
          else if (control.type === 'error') this.finish({ error: new InstaBoxProviderError('terminal_error') });
          else if (control.type === 'exit') this.finish({});
        } catch { this.finish({ error: new InstaBoxProviderError('terminal_protocol_error') }); }
      }
    });
    socket.on('close', () => this.finish({}));
    socket.on('error', () => this.finish({ error: new InstaBoxProviderError('terminal_transport_error') }));
  }
  get writableLength(): number { return this.socket.bufferedAmount; }
  get initialized(): boolean { return !this.initializing; }
  write(data: Buffer): void {
    this.validate();
    if (this.end || this.socket.readyState !== WebSocket.OPEN) throw new InstaBoxProviderError('terminal_closed');
    if (this.socket.bufferedAmount + data.length > 1048576) throw new InstaBoxProviderError('terminal_backpressure');
    this.socket.send(data, { binary: true });
  }
  onData(listener: (chunk: Buffer) => void): void { this.dataListeners.push(listener); for (const chunk of this.pending.splice(0)) listener(chunk); this.pendingBytes = 0; }
  onEnd(listener: (end: PtyEnd) => void): void { this.endListeners.push(listener); if (this.end) listener(this.end); }
  close(): void { this.socket.close(); setTimeout(() => this.socket.terminate(), 250).unref(); }
  private finish(end: PtyEnd): void { if (this.end) return; this.end = end; for (const listener of this.endListeners) listener(end); this.close(); }
}
/** Provider replay has no byte cursor: reject re-opening an ID instead of silently duplicating output. */
export class InstaBoxPty implements PtyTransport {
  private sessions = new Map<string, SocketConnection>();
  constructor(private readonly ref: RemoteExecutorRef, private readonly apiKey: string, private readonly backend: InstaBoxBackend) {}
  private id(terminalId: string): string { return 'ch-' + createHash('sha256').update(`${this.ref.workspaceId}:${this.ref.generation}:${terminalId}`).digest('hex').slice(0, 28); }
  private dimensions(cols: number, rows: number): void { if (!Number.isInteger(cols) || cols < 10 || cols > 1000 || !Number.isInteger(rows) || rows < 4 || rows > 500) throw new HarnessError('INVALID_INPUT', 'InstaBox terminals require 10–1000 columns and 4–500 rows'); }
  async open(request: PtyOpenRequest): Promise<PtyConnection> {
    this.backend.validate(this.ref); this.dimensions(request.cols, request.rows);
    const id = this.id(request.terminalId);
    if (this.sessions.has(id)) throw new InstaBoxProviderError('terminal_already_opened');
    const before = await this.backend.readJob(this.ref, id, 0, 0);
    if (before.status !== 'unknown' || before.errorCode !== 'JOB_NOT_FOUND') throw new InstaBoxProviderError('terminal_replay_unavailable');
    const cwd = request.workingDir === '/workspace' ? `${this.ref.root}/repo` : request.workingDir.startsWith('/workspace/') ? `${this.ref.root}/repo/${request.workingDir.slice(11)}` : request.workingDir;
    if (!cwd.startsWith(`${this.ref.root}/`) || posix.normalize(cwd) !== cwd) throw new InstaBoxProviderError('terminal_invalid_cwd');
    this.backend.validate(this.ref);
    const socket = new WebSocket(`wss://api.instabox.sh/v1/machines/${encodeURIComponent(this.ref.machineId)}/terminal?session=${id}&cols=${request.cols}&rows=${request.rows}&wake=0`, { headers: { Authorization: `Bearer ${this.apiKey}` }, handshakeTimeout: 10000, maxPayload: 1048576, followRedirects: false });
    const connection = new SocketConnection(id, socket, () => this.backend.validate(this.ref));
    // Record immediately, including failed opens. An uncertain handshake must never take over its session.
    this.sessions.set(id, connection);
    try {
      await new Promise<void>((resolve, reject) => { socket.once('open', resolve); socket.once('error', () => reject(new InstaBoxProviderError('terminal_connect_failed'))); socket.once('close', () => reject(new InstaBoxProviderError('terminal_connect_closed'))); });
      const spec = { id, kind: 'shell', cwd, fingerprint: id, timeoutMs: 8 * 60 * 60 * 1000, maxBytes: 0 };
      const payload = Buffer.from(JSON.stringify(spec)).toString('base64');
      connection.write(Buffer.from(`exec node ${shellQuote(`${this.ref.root}/runtime/remote-executor.mjs`)} ${shellQuote(this.ref.root)} terminal ${shellQuote(payload)}\n`));
      let ready = false;
      for (let i = 0; i < 40; i++) { const state = await this.backend.readJob(this.ref, id, 0, 0); if (state.status === 'running' && connection.initialized) { ready = true; break; } if (state.status === 'exited') break; await new Promise(resolve => setTimeout(resolve, 50)); }
      if (!ready) throw new InstaBoxProviderError('terminal_start_unconfirmed');
      connection.write(Buffer.from('\n'));
      return connection;
    } catch (error) { connection.close(); throw error instanceof InstaBoxProviderError ? error : new InstaBoxProviderError('terminal_start_unconfirmed'); }
  }
  async resize(execId: string, cols: number, rows: number): Promise<void> { this.backend.validate(this.ref); this.dimensions(cols, rows); const connection = this.sessions.get(execId); if (!connection || connection.socket.readyState !== WebSocket.OPEN) throw new InstaBoxProviderError('terminal_closed'); connection.socket.send(JSON.stringify({ type: 'resize', cols, rows })); }
  async inspect(execId: string): Promise<PtyExecState> { this.backend.validate(this.ref); if (!/^ch-[a-f0-9]{28}$/.test(execId)) throw new InstaBoxProviderError('terminal_unknown'); const state = await this.backend.readJob(this.ref, execId, 0, 0); return { running: state.status === 'running' || state.status === 'starting', exitCode: state.exitCode ?? null }; }
  async killSession(_container: string, terminalId: string): Promise<void> { this.backend.validate(this.ref); const id = this.id(terminalId); await this.backend.cancelJob(this.ref, id); this.sessions.get(id)?.close(); }
}
