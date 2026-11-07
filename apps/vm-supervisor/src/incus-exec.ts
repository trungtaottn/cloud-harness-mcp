import type { IncusClient, IncusExecSessionRequest } from './incus.js';
import { WsClient, type WsMessage } from './ws-client.js';

/**
 * Interactive exec session over Incus exec websockets. Opens the fd set via
 * `IncusClient.openExecFds`, connects one WsClient per channel, and proxies
 * bounded byte streams. Channel layout (non-PTY): fds[0]=stdin (write),
 * fds[1]=stdout, fds[2]=stderr, optional control channel for signals,
 * window-change and exit metadata. PTY mode merges stdio on fds[0].
 *
 * Exit status arrives as a JSON control message; the exact Incus message
 * shape is normalized defensively in `parseExecExitMessage` and verified at
 * the phase-11 live gate.
 */

export interface ExecExitInfo {
  exitCode: number | null;
  signal: string | null;
  metadata?: unknown;
}

export interface IncusExecSessionEvents {
  onStdout(chunk: Buffer): void;
  onStderr(chunk: Buffer): void;
  /** JSON control-channel messages that are not exit notifications. */
  onMeta?(message: unknown): void;
  onExit(result: ExecExitInfo): void;
  onTransportError(error: Error): void;
}

interface Channel {
  ws: WsClient;
  role: 'stdin' | 'stdout' | 'stderr' | 'control' | 'pty';
}

const CONTROL_CLOSE_TIMEOUT_MS = 2_000;

function parseExecExitMessage(text: string): ExecExitInfo | undefined {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (typeof parsed !== 'object' || parsed === null) return undefined;
  const msg = parsed as Record<string, unknown>;
  const type = msg.type;
  if (type !== 'exit' && type !== 'exit-status' && type !== 'metadata') return undefined;
  const exitCode = typeof msg.exitCode === 'number' ? msg.exitCode
    : typeof msg.exit_code === 'number' ? msg.exit_code
    : typeof msg.return === 'number' ? msg.return
    : null;
  const signal = typeof msg.signal === 'string' ? msg.signal : null;
  return { exitCode, signal, metadata: msg };
}

export class IncusExecSession {
  private readonly channels: Channel[] = [];
  private exited = false;
  private closed = false;
  private lastResult?: ExecExitInfo;

  private constructor(
    private readonly events: IncusExecSessionEvents,
    private readonly operation?: string
  ) {}

  static async open(
    client: Pick<IncusClient, 'openExecFds'>,
    socketPath: string,
    instanceName: string,
    spec: IncusExecSessionRequest,
    events: IncusExecSessionEvents,
    wsHandshakeTimeoutMs = 5_000
  ): Promise<IncusExecSession> {
    const fdSet = await client.openExecFds(instanceName, spec);
    if (fdSet.fds.length === 0) {
      throw new Error(`incus exec returned no websocket fds (operation=${fdSet.operation ?? 'none'})`);
    }
    const session = new IncusExecSession(events, fdSet.operation);
    const isPty = spec.pty !== undefined;
    const connect = async (path: string, role: Channel['role']): Promise<Channel> => {
      const ws = await WsClient.connect({ socketPath, path, handshakeTimeoutMs: wsHandshakeTimeoutMs });
      return { ws, role };
    };
    try {
      if (isPty) {
        const ch = await connect(fdSet.fds[0]!, 'pty');
        session.attach(ch);
        session.channels.push(ch);
      } else {
        const stdin = await connect(fdSet.fds[0]!, 'stdin');
        const stdout = await connect(fdSet.fds[1] ?? fdSet.fds[0]!, 'stdout');
        const stderr = fdSet.fds.length > 2 ? await connect(fdSet.fds[2]!, 'stderr') : undefined;
        const controlPath = fdSet.control ?? (fdSet.fds.length > 3 ? fdSet.fds[3] : undefined);
        const control = controlPath !== undefined ? await connect(controlPath, 'control') : undefined;
        for (const ch of [stdin, stdout, stderr, control]) {
          if (ch !== undefined) {
            session.attach(ch);
            session.channels.push(ch);
          }
        }
      }
    } catch (error) {
      session.closeAll();
      throw error;
    }
    return session;
  }

  private attach(ch: Channel): void {
    ch.ws.onMessage((message: WsMessage) => this.handleMessage(ch, message));
    ch.ws.onClose(() => {
      if (!this.exited && !this.closed) {
        this.events.onTransportError(new Error(`incus exec ${ch.role} channel closed`));
      }
    });
    ch.ws.onError((error) => this.events.onTransportError(error));
  }

  private handleMessage(ch: Channel, message: WsMessage): void {
    if (this.exited) return;
    if (message.opcode === 0x1) {
      const text = message.payload.toString('utf8');
      const exit = parseExecExitMessage(text);
      if (exit !== undefined) {
        this.finish(exit);
        return;
      }
      if (ch.role === 'control') {
        try {
          this.events.onMeta?.(JSON.parse(text));
        } catch {
          // non-JSON control chatter is ignored
        }
        return;
      }
      // JSON-looking text on data channels is still guest output.
      this.events.onStdout(message.payload);
      return;
    }
    if (message.opcode === 0x2 || message.opcode === 0x0) {
      if (ch.role === 'pty' || ch.role === 'stdout') this.events.onStdout(message.payload);
      else if (ch.role === 'stderr') this.events.onStderr(message.payload);
      // stdin channel is write-only; inbound data ignored.
    }
  }

  writeStdin(data: Buffer): boolean {
    const ch = this.channels.find((c) => c.role === 'stdin' || c.role === 'pty');
    return ch !== undefined && ch.ws.sendBinary(data);
  }

  stdinEof(): void {
    const ch = this.channels.find((c) => c.role === 'stdin');
    ch?.ws.close(1000, 'eof');
  }

  resize(cols: number, rows: number): boolean {
    const control = this.channels.find((c) => c.role === 'control');
    if (control !== undefined) {
      return control.ws.sendText(JSON.stringify({ type: 'window-change', width: cols, height: rows }));
    }
    return false;
  }

  signal(name: string): boolean {
    const control = this.channels.find((c) => c.role === 'control');
    if (control !== undefined) {
      return control.ws.sendText(JSON.stringify({ type: 'signal', signal: name }));
    }
    return false;
  }

  /**
   * Pause/resume guest->supervisor output reads. Only DATA channels pause —
   * stdin stays writable and control (signals/exit/window-change) stays live
   * so a flooded session can still be killed or report exit while paused.
   */
  pauseOutputChannels(): void {
    for (const ch of this.channels) {
      if (ch.role === 'stdout' || ch.role === 'stderr' || ch.role === 'pty') ch.ws.pause();
    }
  }

  resumeOutputChannels(): void {
    for (const ch of this.channels) {
      if (ch.role === 'stdout' || ch.role === 'stderr' || ch.role === 'pty') ch.ws.resume();
    }
  }

  /** Control-close: ends the session politely before hard teardown. */
  async controlClose(): Promise<void> {
    const stdin = this.channels.find((c) => c.role === 'stdin');
    stdin?.ws.close(1000, 'control-close');
    await new Promise((resolve) => setTimeout(resolve, CONTROL_CLOSE_TIMEOUT_MS));
    this.closeAll();
  }

  closeAll(): void {
    if (this.closed) return;
    this.closed = true;
    for (const ch of this.channels) {
      try {
        ch.ws.close(1001, 'supervisor-close');
      } catch {
        // already closed
      }
    }
    this.channels.length = 0;
  }

  private finish(result: ExecExitInfo): void {
    if (this.exited) return;
    this.exited = true;
    this.lastResult = result;
    this.events.onExit(result);
    this.closeAll();
  }

  get hasExited(): boolean {
    return this.exited;
  }

  /** Exit metadata once the session has finished; undefined while running. */
  get exitInfo(): ExecExitInfo | undefined {
    return this.lastResult;
  }

  get operationPath(): string | undefined {
    return this.operation;
  }
}
