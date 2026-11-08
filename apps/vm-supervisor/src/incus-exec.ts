import type { IncusClient, IncusExecSessionRequest } from './incus.js';
import { WsClient, type WsMessage } from './ws-client.js';

/**
 * Interactive exec session over Incus exec websockets.
 *
 * Native Incus exec protocol (verified against
 * `cmd/incusd/instance_exec.go` @ 1f0ce8eabe435d04d5840df0155237c234d67a54):
 * the POST always returns 202 with an async operation whose
 * `metadata.fds` maps fd names to connect secrets. Each secret dials
 * `{operation}/websocket?secret=…`. Non-interactive exec uses "0"=stdin,
 * "1"=stdout, "2"=stderr plus an optional "control" channel; interactive
 * (`interactive: true`) exec merges stdio on a single bidirectional "0"
 * PTY. Exit status is NOT a websocket frame — it is the operation's
 * `metadata.return`, polled via `IncusClient.waitExecExit`. Control-channel
 * client messages are `{"command":"window-resize","args":{…}}` and
 * `{"command":"signal","signal":<signum>}`.
 *
 * Channel EOF is proven by the NATIVE barrier, not by close alone: Incus's
 * `shared/ws` MirrorRead ends every fd stream with an empty TEXT "barrier"
 * frame, then the operation teardown raw-closes the TCP conn (gorilla
 * Close() sends no WS close frame). Atomic frame writes do NOT guarantee
 * delivery across a transport failure, so a clean FIN WITHOUT the barrier —
 * or with any non-normal close code — means the tail may be cut and is a
 * transport error, never silent success. The operation poll remains the
 * exit-CODE authority; the barrier+close pair is the output-COMPLETENESS
 * authority.
 */

export interface ExecExitInfo {
  exitCode: number | null;
  signal: string | null;
  metadata?: unknown;
}

export interface IncusExecSessionEvents {
  onStdout(chunk: Buffer): void;
  onStderr(chunk: Buffer): void;
  /** JSON control-channel messages that are not commands (rare/never on native Incus). */
  onMeta?(message: unknown): void;
  onExit(result: ExecExitInfo): void;
  onTransportError(error: Error): void;
}

interface Channel {
  ws: WsClient;
  role: 'stdin' | 'stdout' | 'stderr' | 'control' | 'pty';
  /** Native EOF marker seen: empty TEXT barrier frame on a data channel. */
  sawEofBarrier: boolean;
}

const CONTROL_CLOSE_TIMEOUT_MS = 2_000;
/**
 * Fail-safe bound for the post-exit fd drain: once the operation poll
 * reports a terminal state, Incus has finished writing guest output and
 * ends the fd websockets — channel close is the native EOF, ordered after
 * every data frame on the same TCP connection. This deadline only guards
 * a wedged peer; expiry is an honest transport error, never a silent
 * success over possibly-lost tail bytes.
 */
const EXIT_DRAIN_TIMEOUT_MS = 10_000;

const SIGNAL_NUMBERS: Record<string, number> = {
  SIGHUP: 1, SIGINT: 2, SIGQUIT: 3, SIGILL: 4, SIGTRAP: 5, SIGABRT: 6,
  SIGBUS: 7, SIGFPE: 8, SIGKILL: 9, SIGUSR1: 10, SIGSEGV: 11, SIGUSR2: 12,
  SIGPIPE: 13, SIGALRM: 14, SIGTERM: 15, SIGSTKFLT: 16, SIGCHLD: 17,
  SIGCONT: 18, SIGSTOP: 19, SIGTSTP: 20, SIGTTIN: 21, SIGTTOU: 22,
  SIGURG: 23, SIGXCPU: 24, SIGXFSZ: 25, SIGVTALRM: 26, SIGPROF: 27,
  SIGWINCH: 28, SIGIO: 29, SIGPWR: 30, SIGSYS: 31
};

function signalNumber(name: string): number | undefined {
  if (/^\d+$/.test(name)) {
    const n = Number(name);
    return n > 0 && n <= 64 ? n : undefined;
  }
  const upper = name.toUpperCase();
  const bare = upper.startsWith('SIG') ? upper : `SIG${upper}`;
  return SIGNAL_NUMBERS[bare];
}

function channelRole(fd: string, isPty: boolean): Channel['role'] | undefined {
  // The control channel exists for PTY sessions too — window-resize and
  // signal commands ride it regardless of the data-channel layout.
  if (fd === 'control') return 'control';
  if (isPty) return fd === '0' ? 'pty' : undefined;
  if (fd === '0') return 'stdin';
  if (fd === '1') return 'stdout';
  if (fd === '2') return 'stderr';
  return undefined;
}

export class IncusExecSession {
  private readonly channels = new Map<string, Channel>();
  private exited = false;
  private closed = false;
  private lastResult?: ExecExitInfo;
  private readonly exitAbort = new AbortController();
  /** Set between op-terminal and fd-drain completion; data still flows. */
  private exitPending: ExecExitInfo | undefined;
  /** Data channels still awaiting their native close after exit. */
  private readonly drainingChannels = new Set<Channel>();
  private exitDrainTimer: ReturnType<typeof setTimeout> | undefined;
  /** True while pauseOutputChannels has guest reads suspended. */
  private outputChannelsPausedFlag = false;

  private constructor(
    private readonly events: IncusExecSessionEvents,
    private readonly operation: string,
    private readonly client: Pick<IncusClient, 'waitExecExit'>,
    private readonly exitDrainTimeoutMs: number
  ) {}

  static async open(
    client: Pick<IncusClient, 'openExecFds' | 'waitExecExit'>,
    socketPath: string,
    instanceName: string,
    spec: IncusExecSessionRequest,
    events: IncusExecSessionEvents,
    wsHandshakeTimeoutMs = 5_000,
    exitDrainTimeoutMs = EXIT_DRAIN_TIMEOUT_MS,
    holdOutputPaused = false
  ): Promise<IncusExecSession> {
    const fdSet = await client.openExecFds(instanceName, spec);
    const session = new IncusExecSession(events, fdSet.operation, client, exitDrainTimeoutMs);
    const isPty = spec.pty !== undefined;
    // Dial order: data channels first, control last. "control" is optional —
    // Incus may omit it; every other required fd must be present or the exec
    // can never complete observably, so its absence fails closed.
    const order = isPty ? ['0', 'control'] : ['0', '1', '2', 'control'];
    try {
      for (const fd of order) {
        const path = fdSet.channels[fd];
        if (path === undefined) {
          if (fd === 'control') continue;
          throw new Error(`incus exec operation provided no '${fd}' channel`);
        }
        const ws = await WsClient.connect({ socketPath, path, handshakeTimeoutMs: wsHandshakeTimeoutMs });
        if (session.isClosedFlag) {
          // The command already exited and tore the session down mid-handshake.
          ws.close(1000, 'session-closed');
          break;
        }
        const role = channelRole(fd, isPty);
        if (role === undefined) {
          ws.close(1000, 'unused-channel');
          continue;
        }
        // Track + attach immediately: a later channel failure must close
        // every socket already connected, and listeners must be live before
        // the next connect so no early frame is dropped.
        const ch: Channel = { ws, role, sawEofBarrier: false };
        session.channels.set(fd, ch);
        // holdOutputPaused: session consumers (exec.open) bind the wire
        // response only after open() returns — pause data channels during
        // the handshake so fast guest output applies TCP backpressure
        // instead of growing an unbounded pre-bind queue. Resumed below
        // once every channel is connected.
        if (holdOutputPaused && (role === 'stdout' || role === 'stderr' || role === 'pty')) {
          ch.ws.pause();
        }
        session.attach(ch);
      }
      if (!session.isClosedFlag && !isPty) {
        for (const fd of ['0', '1', '2']) {
          if (!session.channels.has(fd)) {
            throw new Error(`incus exec session missing required fd '${fd}'`);
          }
        }
      }
      if (!session.isClosedFlag && isPty && !session.channels.has('0')) {
        throw new Error('incus exec session missing required pty channel');
      }
      if (holdOutputPaused) session.resumeOutputChannels();
    } catch (error) {
      session.closeAll();
      throw error;
    }
    session.startExitPoll();
    return session;
  }

  private attach(ch: Channel): void {
    ch.ws.onMessage((message: WsMessage) => this.handleMessage(ch, message));
    ch.ws.onClose((code) => {
      this.channels.forEach((c, fd) => { if (c === ch) this.channels.delete(fd); });
      if (this.exited || this.closed) return;
      const isOutput = ch.role === 'stdout' || ch.role === 'stderr' || ch.role === 'pty';
      if (isOutput) {
        // Output completeness is proven by the NATIVE sequence — empty TEXT
        // barrier then clean close (1000). A clean FIN without the barrier,
        // or ANY non-normal close code (1001/1006/1011/...), means the frame
        // boundary may have cut the tail: honest transport failure whether
        // the exit poll already reported terminal or not.
        if (code !== 1000 || !ch.sawEofBarrier) {
          const error = new Error(
            code === 1000
              ? 'incus exec fd stream closed without native EOF barrier'
              : 'incus exec fd stream closed abnormally'
          );
          if (this.exitPending !== undefined) this.failExitDrain(error);
          else this.events.onTransportError(error);
          return;
        }
        // Clean native EOF: post-exit this IS the drain signal — every data
        // frame is TCP-ordered before barrier+FIN on the same connection.
        if (this.exitPending !== undefined &&
            this.drainingChannels.delete(ch) && this.drainingChannels.size === 0) {
          this.completeExitDrain();
        }
        return;
      }
      // stdin/control are not output channels: closes are informational
      // mid-run. During the post-exit drain an abnormal close still fails
      // honestly — the transport layer is degraded.
      if (this.exitPending !== undefined && code === 1006) {
        this.failExitDrain(new Error('incus exec channel closed abnormally after command exit'));
      }
    });
    ch.ws.onError((error) => {
      if (!this.exited && !this.closed) {
        this.events.onTransportError(error);
      }
    });
  }

  private handleMessage(ch: Channel, message: WsMessage): void {
    if (this.exited) return;
    // Post-exit drain: any frame on an output channel is progress — restart
    // the deadline so steady output is never mistaken for a wedged peer.
    if (this.exitPending !== undefined &&
        (ch.role === 'stdout' || ch.role === 'stderr' || ch.role === 'pty') &&
        this.exitDrainTimer !== undefined) {
      this.armExitDrainTimer();
    }
    if (message.opcode === 0x1) {
      const text = message.payload.toString('utf8');
      if (ch.role === 'control') {
        try {
          this.events.onMeta?.(JSON.parse(text));
        } catch {
          // non-JSON control chatter is ignored
        }
        return;
      }
      // TEXT on a data channel is the native EOF barrier (Incus writes
      // guest output as BINARY frames only) — mark it; the empty payload
      // is still forwarded harmlessly below.
      ch.sawEofBarrier = true;
      this.events.onStdout(message.payload);
      return;
    }
    if (message.opcode === 0x2 || message.opcode === 0x0) {
      if (ch.role === 'pty' || ch.role === 'stdout') this.events.onStdout(message.payload);
      else if (ch.role === 'stderr') this.events.onStderr(message.payload);
      // stdin channel is write-only; inbound data ignored.
    }
  }

  /**
   * The operation poll is the ONLY exit authority: Incus exec websockets
   * carry process I/O but never an exit frame. Poll failures are retried by
   * waitExecExit; aborting here (closeAll) resolves nothing — teardown is
   * already underway.
   */
  private startExitPoll(): void {
    void this.client.waitExecExit(this.operation, { signal: this.exitAbort.signal })
      .then((res) => {
        if (this.exited || this.closed) return;
        this.beginExitDrain({
          exitCode: res.exitCode,
          signal: res.signal,
          ...(res.error !== undefined ? { metadata: { operationError: res.error } } : {})
        });
      })
      .catch((error: unknown) => {
        if (this.exited || this.closed) return;
        this.events.onTransportError(error instanceof Error ? error : new Error(String(error)));
      });
  }

  /**
   * Op-terminal does NOT mean output-complete: Incus ends each fd stream
   * with the native barrier+close sequence, and every data frame is
   * TCP-ordered before it. Wait for each data channel's proven EOF (bounded
   * by exitDrainTimeoutMs) so trailing output is never silently dropped.
   */
  private beginExitDrain(info: ExecExitInfo): void {
    this.exitPending = info;
    for (const ch of this.channels.values()) {
      if (ch.role === 'stdout' || ch.role === 'stderr' || ch.role === 'pty') {
        this.drainingChannels.add(ch);
      }
    }
    if (this.drainingChannels.size === 0) {
      this.completeExitDrain();
      return;
    }
    // The deadline measures time WITHOUT progress, not time since exit:
    // each received frame restarts it (see handleMessage), and it is
    // suspended entirely while output channels are paused for backpressure —
    // a paused socket cannot deliver its EOF barrier until the consumer
    // drains, so a slow-but-alive consumer must never false-fail the drain.
    if (!this.outputChannelsPausedFlag) this.armExitDrainTimer();
  }

  private armExitDrainTimer(): void {
    if (this.exitDrainTimer !== undefined) clearTimeout(this.exitDrainTimer);
    this.exitDrainTimer = setTimeout(() => {
      this.exitDrainTimer = undefined;
      if (this.exited || this.closed || this.exitPending === undefined) return;
      this.failExitDrain(new Error('incus exec fd streams did not close after command exit'));
    }, this.exitDrainTimeoutMs);
    this.exitDrainTimer.unref();
  }

  private completeExitDrain(): void {
    if (this.exitDrainTimer !== undefined) {
      clearTimeout(this.exitDrainTimer);
      this.exitDrainTimer = undefined;
    }
    const info = this.exitPending;
    this.exitPending = undefined;
    this.drainingChannels.clear();
    if (info !== undefined && !this.exited && !this.closed) {
      this.finish(info);
    }
  }

  private failExitDrain(error: Error): void {
    if (this.exitDrainTimer !== undefined) {
      clearTimeout(this.exitDrainTimer);
      this.exitDrainTimer = undefined;
    }
    this.exitPending = undefined;
    this.drainingChannels.clear();
    if (!this.exited && !this.closed) {
      this.events.onTransportError(error);
    }
  }

  writeStdin(data: Buffer): boolean {
    const ch = this.channels.get('0');
    return ch !== undefined && (ch.role === 'stdin' || ch.role === 'pty') && ch.ws.sendBinary(data);
  }

  /** Resolve once the stdin/pty socket's kernel buffer has drained. */
  waitStdinDrain(): Promise<void> {
    const ch = this.channels.get('0');
    if (ch === undefined || (ch.role !== 'stdin' && ch.role !== 'pty')) return Promise.resolve();
    return ch.ws.waitForDrain();
  }

  stdinEof(): void {
    const ch = this.channels.get('0');
    if (ch !== undefined && ch.role === 'stdin') {
      // Intentional EOF: close the write side politely. This is NOT a
      // transport error — the command keeps running until it exits.
      ch.ws.close(1000, 'eof');
    }
  }

  resize(cols: number, rows: number): boolean {
    const control = this.channels.get('control');
    if (control === undefined) return false;
    // Native control protocol: window-resize args are strings.
    return control.ws.sendText(JSON.stringify({
      command: 'window-resize',
      args: { width: String(cols), height: String(rows) }
    }));
  }

  signal(name: string): boolean {
    const control = this.channels.get('control');
    if (control === undefined) return false;
    const signum = signalNumber(name);
    if (signum === undefined) return false;
    // Native control protocol: signal is a numeric signum.
    return control.ws.sendText(JSON.stringify({ command: 'signal', signal: signum }));
  }

  /**
   * Pause/resume guest->supervisor output reads. Only DATA channels pause —
   * stdin stays writable and control (signals) stays live so a flooded
   * session can still be killed while paused.
   */
  pauseOutputChannels(): void {
    for (const ch of this.channels.values()) {
      if (ch.role === 'stdout' || ch.role === 'stderr' || ch.role === 'pty') ch.ws.pause();
    }
    if (!this.outputChannelsPausedFlag) {
      this.outputChannelsPausedFlag = true;
      // Suspend the drain deadline while reads are held: no EOF can arrive.
      if (this.exitPending !== undefined && this.exitDrainTimer !== undefined) {
        clearTimeout(this.exitDrainTimer);
        this.exitDrainTimer = undefined;
      }
    }
  }

  resumeOutputChannels(): void {
    for (const ch of this.channels.values()) {
      if (ch.role === 'stdout' || ch.role === 'stderr' || ch.role === 'pty') ch.ws.resume();
    }
    if (this.outputChannelsPausedFlag) {
      this.outputChannelsPausedFlag = false;
      // Reads are live again: the drain deadline restarts fresh — resume is
      // itself progress, and a peer that then goes silent still fails bounded.
      if (this.exitPending !== undefined && this.exitDrainTimer === undefined) {
        this.armExitDrainTimer();
      }
    }
  }

  /** Control-close: ends stdin politely before hard teardown. */
  async controlClose(): Promise<void> {
    const stdin = this.channels.get('0');
    if (stdin !== undefined && stdin.role === 'stdin') {
      stdin.ws.close(1000, 'control-close');
    }
    await new Promise((resolve) => setTimeout(resolve, CONTROL_CLOSE_TIMEOUT_MS));
    this.closeAll();
  }

  closeAll(): void {
    if (this.closed) return;
    this.closed = true;
    this.exitAbort.abort();
    if (this.exitDrainTimer !== undefined) {
      clearTimeout(this.exitDrainTimer);
      this.exitDrainTimer = undefined;
    }
    this.exitPending = undefined;
    this.drainingChannels.clear();
    this.outputChannelsPausedFlag = false;
    for (const ch of this.channels.values()) {
      try {
        ch.ws.close(1001, 'supervisor-close');
      } catch {
        // already closed
      }
    }
    this.channels.clear();
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

  get operationPath(): string {
    return this.operation;
  }

  private get isClosedFlag(): boolean {
    return this.closed;
  }
}
