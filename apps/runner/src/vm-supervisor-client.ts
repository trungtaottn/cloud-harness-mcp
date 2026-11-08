import { createHash, randomUUID } from 'node:crypto';
import { connect as netConnect, type Socket } from 'node:net';
import {
  ErrorCodeSchema,
  HarnessError,
  VmSupervisorHostRequestSchema,
  VmSupervisorOpResultSchemas,
  VmSupervisorResponseSchema,
  VmSupervisorWorkspaceRequestSchema,
  type ErrorCode,
  type VmAdmitResult,
  type VmCreateResult,
  type VmDeleteResult,
  type VmExecCloseResult,
  type VmExecInspectResult,
  type VmExecKillSessionResult,
  type VmExecResizeResult,
  type VmExecRunResult,
  type VmExecWriteResult,
  type VmFileListResult,
  type VmFilePullResult,
  type VmFilePushResult,
  type VmFileStatResult,
  type VmGuardStateResult,
  type VmHostOperation,
  type VmInstanceListResult,
  type VmLeaseClearResult,
  type VmLeaseListResult,
  type VmLeaseSetResult,
  type VmNetworkAttestResult,
  type VmNetworkProgramResult,
  type VmNetworkTearDownResult,
  type VmPoolInfoResult,
  type VmReconcileResult,
  type VmStartResult,
  type VmStatusResult,
  type VmStopResult,
  type VmSupervisorHostRequest,
  type VmSupervisorOperation,
  type VmSupervisorRequest,
  type VmSupervisorResponse,
  type VmSupervisorWorkspaceRequest,
  type VmTarTrailer,
  type VmWorkspaceOperation
} from '@cloud-harness/contracts';

/**
 * Runner-side client for the vm-supervisor raw framed Unix-socket protocol
 * (wire protocol v1, owned by apps/vm-supervisor/src/transport.ts).
 *
 * Frame layout: uint32be payloadLen (includes the kind byte) || uint8 kind ||
 * payload. kind 0x00 carries a UTF-8 JSON control message (<=1 MiB), kind
 * 0x01 carries raw stream bytes. The first frame on every connection must be
 * {type:'auth', token}; the server answers {type:'auth-ok'} or an error and
 * closes. Requests are strictly sequential per connection; the client opens
 * one connection per call (and per exec session).
 *
 * This module deliberately re-implements the codec rather than importing the
 * supervisor package: apps/runner must not depend on apps/vm-supervisor, and
 * test/vm-supervisor-client.test.ts proves conformance against an independent
 * fake server.
 *
 * Secret discipline: the supervisor token, environment maps, exec payloads
 * and file bytes are never logged or included in error messages here.
 */

export const WIRE_KIND_JSON = 0x00;
export const WIRE_KIND_BYTES = 0x01;

/**
 * exec.run framed-download payload ceiling: 8-byte u64be stdout-length prefix
 * plus two streams each capped at 16 MiB of UTF-8 (the exec.run result
 * schema's per-stream bound). Mirrors the supervisor's own construction
 * bound; the decoder additionally derives a tighter request-scoped limit.
 */
export const EXEC_RUN_STREAM_MAX_BYTES = 2 * 16_777_216 + 8;

export const VM_WIRE_LIMITS = {
  /** Largest single frame payload (kind byte excluded). */
  maxFramePayloadBytes: 8 * 1024 * 1024,
  /** Largest JSON control message payload. */
  maxControlPayloadBytes: 1024 * 1024,
  /** Unprocessed inbound bytes before the connection is declared broken. */
  maxBufferedPayloadBytes: 32 * 1024 * 1024,
  /** Wire absolute stream ceiling: 64 GiB content + 8 GiB tar overhead (frozen bounds). */
  maxStreamBytes: 72 * 1024 * 1024 * 1024,
  authTimeoutMs: 5_000,
  connectTimeoutMs: 10_000,
  requestTimeoutMs: 120_000,
  /** Max gap with no progress during upload/download phases. */
  streamIdleTimeoutMs: 300_000,
  /** Largest declared session-data payload (mirrors server WIRE_LIMITS). */
  maxSessionDataMessageBytes: 1024 * 1024,
  /** Socket pause threshold while a consumer drains the event queue. */
  pauseBufferedBytes: 4 * 1024 * 1024,
  resumeBufferedBytes: 1024 * 1024,
  /** Outbound upload chunk size per kind-0x01 frame. */
  uploadChunkBytes: 4 * 1024 * 1024,
  /**
   * Soft bound for session output held before the first onData() listener:
   * past it the socket pauses until a listener attaches. Chunks are HELD,
   * never dropped — discarding session output is silent data loss.
   */
  preListenerBufferMaxBytes: 4 * 1024 * 1024,
  /**
   * Hard bound for pre-listener session output. Frames already decoded into
   * the connection queue keep arriving while the socket is paused, so the
   * hold needs its own ceiling — beyond it the session fails loudly instead
   * of buffering without limit.
   */
  preListenerHardMaxBytes: 64 * 1024 * 1024
} as const;

export type VmSupervisorClientLimits = { [K in keyof typeof VM_WIRE_LIMITS]?: number };

// ---------------------------------------------------------------------------
// Frame codec
// ---------------------------------------------------------------------------

export function encodeWireFrame(kind: number, payload: Buffer | string): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const frame = Buffer.allocUnsafe(5 + body.length);
  frame.writeUInt32BE(1 + body.length, 0);
  frame.writeUInt8(kind, 4);
  body.copy(frame, 5);
  return frame;
}

export function encodeWireJson(message: Record<string, unknown>): Buffer {
  return encodeWireFrame(WIRE_KIND_JSON, JSON.stringify(message));
}

export interface WireFrame {
  kind: number;
  payload: Buffer;
}

/** Incremental frame decoder; throws on out-of-bounds frame lengths. */
export class WireFrameDecoder {
  private buffer: Buffer = Buffer.alloc(0);

  constructor(private readonly maxFramePayloadBytes: number = VM_WIRE_LIMITS.maxFramePayloadBytes) {}

  get bufferedBytes(): number {
    return this.buffer.length;
  }

  push(chunk: Buffer): WireFrame[] {
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    const frames: WireFrame[] = [];
    for (;;) {
      if (this.buffer.length < 5) return frames;
      const len = this.buffer.readUInt32BE(0);
      if (len < 1 || len > this.maxFramePayloadBytes + 1) {
        throw new Error(`vm-supervisor frame length ${len} out of bounds`);
      }
      if (this.buffer.length < 4 + len) return frames;
      const kind = this.buffer.readUInt8(4);
      const payload = this.buffer.subarray(5, 4 + len);
      this.buffer = this.buffer.subarray(4 + len);
      frames.push({ kind, payload });
    }
  }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/**
 * Typed failure surfaced by the supervisor client. `unknownOutcome` is true
 * when a mutation may have applied but the reply was lost — callers must
 * reconcile via reads, never blind-retry.
 */
export class VmSupervisorCallError extends HarnessError {
  public readonly unknownOutcome: boolean;

  constructor(
    code: ErrorCode,
    message: string,
    status: number,
    retryable: boolean,
    unknownOutcome = false,
    operation?: string
  ) {
    super(code, message, status, retryable, { operation });
    this.name = 'VmSupervisorCallError';
    this.unknownOutcome = unknownOutcome;
  }
}

function statusForSupervisorError(code: ErrorCode, retryable: boolean): number {
  switch (code) {
    case 'AUTHENTICATION_FAILED': return 401;
    case 'FORBIDDEN': return 403;
    case 'INVALID_INPUT': return 400;
    case 'NOT_FOUND': return 404;
    case 'CONFLICT': return 409;
    case 'EXPIRED': return 410;
    case 'VM_GENERATION_MISMATCH':
    case 'VM_IDENTITY_MISMATCH': return 409;
    case 'VM_CAPABILITY_UNSUPPORTED': return 400;
    case 'VM_QUOTA_EXCEEDED':
    case 'LIMIT_EXCEEDED': return 429;
    case 'VM_BACKEND_DISABLED':
    case 'VM_UNKNOWN_STATE':
    case 'VM_ATTESTATION_FAILED':
    case 'VM_SUPERVISOR_UNAVAILABLE':
    case 'UNAVAILABLE':
    case 'TIMEOUT': return 503;
    case 'CANCELLED': return 499;
    default: return retryable ? 503 : 400;
  }
}

function callError(
  code: ErrorCode,
  message: string,
  retryable: boolean,
  unknownOutcome: boolean,
  operation?: string
): VmSupervisorCallError {
  return new VmSupervisorCallError(code, message, statusForSupervisorError(code, retryable), retryable, unknownOutcome, operation);
}

function transportFailure(mutation: boolean, operation?: string): VmSupervisorCallError {
  return mutation
    ? callError('VM_UNKNOWN_STATE', `vm-supervisor connection lost during ${operation ?? 'request'}; mutation outcome unknown`, true, true, operation)
    : callError('VM_SUPERVISOR_UNAVAILABLE', `vm-supervisor connection lost during ${operation ?? 'request'}`, true, false, operation);
}

function protocolFailure(message: string, operation?: string): VmSupervisorCallError {
  return callError('VM_SUPERVISOR_UNAVAILABLE', `vm-supervisor protocol violation: ${message}`, false, false, operation);
}

/**
 * Stream-phase integrity failure AFTER stream-start: the supervisor already
 * executed the command and is streaming its result, so a mutation's outcome
 * is UNKNOWN — the bytes cannot be trusted and blind retry is unsafe.
 * Mirrors fatalControl's mutation branch (VM_UNKNOWN_STATE, retryable,
 * unknownOutcome) so callers reconcile instead of resending.
 */
function postCommandFailure(message: string, operation?: string): VmSupervisorCallError {
  return callError('VM_UNKNOWN_STATE', `vm-supervisor protocol violation after command dispatch: ${message}`, true, true, operation);
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** Full workspace identity fence carried by every workspace-scoped request. */
export interface VmWorkspaceIdentity {
  workspaceId: string;
  /** External generation fence; must match the persisted workspace generation. */
  generation: number;
  /** backend_instance_id UUID persisted before the first supervisor call. */
  instanceId: string;
}

export type VmWorkspaceOpParams<Op extends VmWorkspaceOperation> =
  Extract<VmSupervisorWorkspaceRequest, { op: Op }>['params'];

export type VmHostOpParams<Op extends VmHostOperation> =
  Extract<VmSupervisorHostRequest, { op: Op }>['params'];

export type VmOpResult<Op extends VmSupervisorOperation> =
  (typeof VmSupervisorOpResultSchemas)[Op] extends { parse: (value: unknown) => infer R } ? R : never;

export interface VmCallOptions {
  /**
   * Stable idempotency key. Mutating ops replay safely only when the caller
   * reuses the same key; when omitted a fresh key is generated per call.
   */
  idempotencyKey?: string;
  /** Bounds the request phase (until stream-ready/stream-start/response). */
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface VmDownloadOptions extends VmCallOptions {
  /** Receives each inbound byte chunk in order; may be async for backpressure. */
  sink: (chunk: Buffer) => void | Promise<void>;
}

export type VmFilePushInlineParams = Omit<VmWorkspaceOpParams<'file.push'>, 'dataBase64' | 'streamRef'> & {
  dataBase64: string;
};
export type VmFilePushStreamParams = Omit<VmWorkspaceOpParams<'file.push'>, 'dataBase64' | 'streamRef'> & {
  streamRef: string;
};

export interface VmSessionMeta {
  exitCode: number | null;
  signal: string | null;
  returnMetadata?: Record<string, unknown> | undefined;
}

/**
 * Live exec session bound to one supervisor connection. `ended` resolves with
 * the terminal meta on session-end, rejects when the transport dies first
 * (VM_UNKNOWN_STATE — the guest-side outcome is then unknown).
 */
export interface VmExecSession {
  readonly sessionId: string;
  /** Register an output listener; returning false pauses the socket. */
  onData(listener: (fd: number, chunk: Buffer) => boolean | void): () => void;
  onMeta(listener: (meta: VmSessionMeta) => void): () => void;
  readonly ended: Promise<VmSessionMeta>;
  readonly closed: boolean;
  resume(): void;
  /** Detach: destroys the connection; the supervisor reaps the guest session. */
  close(): void;
}

export interface VmSupervisorClientDeps {
  socketPath: string;
  token: string;
  limits?: VmSupervisorClientLimits;
  /** Test seam: socket factory; defaults to a unix net.connect. */
  connect?: (socketPath: string) => Promise<Socket>;
  now?: () => number;
  newId?: () => string;
}

// ---------------------------------------------------------------------------
// Read-only op set — EOF/timeout on these is a read failure, not unknown state.
// ---------------------------------------------------------------------------

const READ_ONLY_OPS = new Set<string>([
  'vm.admit',
  'vm.status',
  'vm.list',
  'vm.export',
  'exec.inspect',
  'file.pull',
  'file.stat',
  'file.list',
  'pullTree',
  'network.attest',
  'lease.list',
  'pool.info',
  'guard.state'
]);

function isMutation(op: VmSupervisorOperation): boolean {
  return !READ_ONLY_OPS.has(op);
}

// ---------------------------------------------------------------------------
// Connection: one authenticated socket, sequential requests, event pump.
// ---------------------------------------------------------------------------

type TerminalReason = 'eof' | 'abort' | 'timeout' | 'protocol';

interface TerminalEvent {
  type: 'terminal';
  reason: TerminalReason;
  error?: VmSupervisorCallError;
}

type ConnEvent =
  | { type: 'control'; message: Record<string, unknown> }
  | { type: 'bytes'; payload: Buffer }
  | TerminalEvent;

class WireConn {
  private readonly socket: Socket;
  private readonly decoder: WireFrameDecoder;
  private readonly limits: Required<VmSupervisorClientLimits>;
  private op: VmSupervisorOperation = 'pool.info';

  private queue: ConnEvent[] = [];
  private queuedPayloadBytes = 0;
  private waiter: ((event: ConnEvent) => void) | null = null;
  private terminal: TerminalEvent | null = null;
  private closing = false;
  private idleTimer: NodeJS.Timeout | null = null;
  private abortSignal: AbortSignal | null = null;
  private abortHandler: (() => void) | null = null;
  private drainWaiters: Array<{ resolve: () => void; reject: (error: Error) => void }> = [];

  private constructor(socket: Socket, limits: Required<VmSupervisorClientLimits>) {
    this.socket = socket;
    this.limits = limits;
    this.decoder = new WireFrameDecoder(limits.maxFramePayloadBytes);
  }

  /** Perform the auth handshake on an already-connected socket. */
  static async openAuthenticated(
    socket: Socket,
    token: string,
    limits: Required<VmSupervisorClientLimits>
  ): Promise<WireConn> {
    const conn = new WireConn(socket, limits);
    conn.installPump();
    conn.sendJson({ type: 'auth', token });
    const deadline = setTimeout(() => {
      conn.terminate({ type: 'terminal', reason: 'timeout' });
    }, limits.authTimeoutMs);
    deadline.unref?.();
    try {
      for (;;) {
        const event = await conn.nextEvent();
        if (event.type === 'terminal') {
          throw conn.mapTerminal(event, false, 'auth');
        }
        if (event.type === 'bytes') {
          const error = protocolFailure('byte frame during auth');
          conn.terminate({ type: 'terminal', reason: 'protocol', error });
          throw error;
        }
        const type = event.message.type;
        if (type === 'auth-ok') return conn;
        if (type === 'error') {
          const wire = parseWireError(event.message.error);
          throw callError(wire.code, wire.message, wire.retryable, false, 'auth');
        }
        const error = protocolFailure(`unexpected ${String(type)} during auth`);
        conn.terminate({ type: 'terminal', reason: 'protocol', error });
        throw error;
      }
    } finally {
      clearTimeout(deadline);
    }
  }

  private get mutation(): boolean {
    return isMutation(this.op);
  }

  // -- pump -----------------------------------------------------------------

  private installPump(): void {
    this.socket.on('data', (chunk: Buffer) => {
      let frames: WireFrame[];
      try {
        frames = this.decoder.push(chunk);
      } catch {
        this.terminate({ type: 'terminal', reason: 'protocol', error: protocolFailure('undecodable frame', this.op) });
        return;
      }
      for (const frame of frames) {
        if (frame.kind === WIRE_KIND_BYTES) {
          this.enqueue({ type: 'bytes', payload: frame.payload });
          if (this.terminal) return;
          continue;
        }
        if (frame.kind !== WIRE_KIND_JSON) {
          this.terminate({ type: 'terminal', reason: 'protocol', error: protocolFailure(`unknown frame kind ${frame.kind}`, this.op) });
          return;
        }
        if (frame.payload.length > this.limits.maxControlPayloadBytes) {
          this.terminate({ type: 'terminal', reason: 'protocol', error: protocolFailure('control message too large', this.op) });
          return;
        }
        let message: unknown;
        try {
          message = JSON.parse(frame.payload.toString('utf8'));
        } catch {
          this.terminate({ type: 'terminal', reason: 'protocol', error: protocolFailure('invalid JSON control message', this.op) });
          return;
        }
        if (typeof message !== 'object' || message === null || Array.isArray(message)) {
          this.terminate({ type: 'terminal', reason: 'protocol', error: protocolFailure('control message is not an object', this.op) });
          return;
        }
        this.enqueue({ type: 'control', message: message as Record<string, unknown> });
        if (this.terminal) return;
      }
    });
    const onEnd = () => this.terminate({ type: 'terminal', reason: 'eof' });
    this.socket.on('close', onEnd);
    this.socket.on('end', onEnd);
    this.socket.on('error', () => this.terminate({ type: 'terminal', reason: 'eof' }));
    // sendBytes() queues waiters when write() returns false; without this the
    // upload phase stalls forever once the kernel buffer fills.
    this.socket.on('drain', () => this.wakeDrainWaiters());
  }

  private enqueue(event: ConnEvent): void {
    if (this.terminal) return;
    if (event.type === 'bytes') this.queuedPayloadBytes += event.payload.length;
    this.applyPauseState();
    if (this.waiter) {
      const waiter = this.waiter;
      this.waiter = null;
      this.accountDelivery(event);
      waiter(event);
      return;
    }
    this.queue.push(event);
    if (this.queuedPayloadBytes > this.limits.maxBufferedPayloadBytes) {
      this.terminate({ type: 'terminal', reason: 'protocol', error: protocolFailure('inbound buffer bound exceeded', this.op) });
    }
  }

  /** Account for a consumed event so queued-byte backpressure stays accurate. */
  private accountDelivery(event: ConnEvent): void {
    if (event.type === 'bytes') {
      this.queuedPayloadBytes = Math.max(0, this.queuedPayloadBytes - event.payload.length);
    }
    this.applyPauseState();
  }

  private consumerPaused = false;

  private applyPauseState(): void {
    const shouldPause =
      this.consumerPaused ||
      this.queuedPayloadBytes > this.limits.pauseBufferedBytes;
    if (shouldPause && !this.socket.isPaused()) this.socket.pause();
    if (!shouldPause && this.socket.isPaused()) this.socket.resume();
  }

  /** Session consumer backpressure: pause inbound delivery. */
  pauseSocket(): void {
    this.consumerPaused = true;
    this.applyPauseState();
  }

  resumeSocket(): void {
    this.consumerPaused = false;
    this.applyPauseState();
  }

  private nextEvent(): Promise<ConnEvent> {
    if (this.terminal) return Promise.resolve(this.terminal);
    if (this.queue.length > 0) {
      const event = this.queue.shift()!;
      this.accountDelivery(event);
      return Promise.resolve(event);
    }
    return new Promise<ConnEvent>((resolve) => {
      this.waiter = resolve;
    });
  }

  // -- send -----------------------------------------------------------------

  private sendJson(message: Record<string, unknown>): void {
    if (this.terminal) throw this.mapTerminal(this.terminal, this.mutation, this.op);
    if (this.closing || this.socket.destroyed) {
      throw transportFailure(this.mutation, this.op);
    }
    const frame = encodeWireJson(message);
    const payloadLength = frame.length - 5;
    if (payloadLength > this.limits.maxControlPayloadBytes) {
      throw callError('INVALID_INPUT', `vm-supervisor control message exceeds ${this.limits.maxControlPayloadBytes} bytes`, false, false, this.op);
    }
    this.socket.write(frame);
  }

  private async sendBytes(payload: Buffer): Promise<void> {
    if (this.terminal) throw this.mapTerminal(this.terminal, this.mutation, this.op);
    if (this.closing || this.socket.destroyed) {
      throw transportFailure(this.mutation, this.op);
    }
    const ok = this.socket.write(encodeWireFrame(WIRE_KIND_BYTES, payload));
    this.noteActivity();
    if (!ok) await this.waitDrain();
  }

  private waitDrain(): Promise<void> {
    if (this.terminal || this.socket.destroyed) {
      return Promise.reject(this.mapTerminal({ type: 'terminal', reason: 'eof' }, this.mutation, this.op));
    }
    return new Promise<void>((resolve, reject) => {
      this.drainWaiters.push({ resolve, reject });
    });
  }

  private wakeDrainWaiters(error?: Error): void {
    const waiters = this.drainWaiters.splice(0);
    for (const waiter of waiters) {
      if (error) waiter.reject(error);
      else waiter.resolve();
    }
  }

  // -- timers / abort --------------------------------------------------------

  /**
   * Progress resets the stream-idle deadline: the timer is armed for the whole
   * upload/download phase and every chunk/event re-arms it, so a mid-stream
   * stall is still bounded by streamIdleTimeoutMs.
   */
  private noteActivity(): void {
    if (!this.idleArmed) return;
    this.armIdleTimer();
  }

  private idleArmed = false;

  private armIdleTimer(): void {
    this.idleArmed = true;
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => {
      this.terminate({ type: 'terminal', reason: 'timeout' });
    }, this.limits.streamIdleTimeoutMs);
    this.idleTimer.unref?.();
  }

  private clearIdleTimer(): void {
    this.idleArmed = false;
    if (this.idleTimer) {
      clearTimeout(this.idleTimer);
      this.idleTimer = null;
    }
  }

  private armAbort(signal: AbortSignal | undefined): void {
    if (!signal) return;
    if (signal.aborted) {
      this.terminate({ type: 'terminal', reason: 'abort' });
      return;
    }
    this.abortSignal = signal;
    this.abortHandler = () => this.terminate({ type: 'terminal', reason: 'abort' });
    signal.addEventListener('abort', this.abortHandler, { once: true });
  }

  private disarmAbort(): void {
    if (this.abortSignal && this.abortHandler) {
      this.abortSignal.removeEventListener('abort', this.abortHandler);
    }
    this.abortSignal = null;
    this.abortHandler = null;
  }

  // -- terminal handling -----------------------------------------------------

  private terminate(event: TerminalEvent): void {
    if (this.terminal) return;
    this.terminal = event;
    this.closing = true;
    this.clearIdleTimer();
    this.disarmAbort();
    const mapped = this.mapTerminal(event, this.mutation, this.op);
    this.wakeDrainWaiters(event.error ?? mapped);
    if (this.waiter) {
      const waiter = this.waiter;
      this.waiter = null;
      waiter(event);
    }
    this.socket.destroy();
  }

  private mapTerminal(event: TerminalEvent, mutation: boolean, operation: string): VmSupervisorCallError {
    if (event.error) return event.error;
    switch (event.reason) {
      case 'abort':
        // A mutation whose request frame may already be on the wire has an
        // UNKNOWN outcome — the supervisor may have applied it. Callers must
        // reconcile (exec.inspect / journal probe) before any retry; this is
        // never a license to blindly resend. Reads that never dispatched are
        // a clean CANCELLED.
        return mutation
          ? callError('VM_UNKNOWN_STATE', `${operation} aborted by caller; outcome unknown`, true, true, operation)
          : callError('CANCELLED', `${operation} aborted by caller`, false, false, operation);
      case 'protocol':
        return protocolFailure('connection terminated', operation);
      case 'timeout':
      case 'eof':
      default:
        return transportFailure(mutation, operation);
    }
  }

  close(): void {
    if (this.terminal) {
      this.socket.destroy();
      return;
    }
    this.terminal = { type: 'terminal', reason: 'eof' };
    this.closing = true;
    this.clearIdleTimer();
    this.disarmAbort();
    this.wakeDrainWaiters();
    if (this.waiter) {
      const waiter = this.waiter;
      this.waiter = null;
      waiter(this.terminal);
    }
    this.socket.destroy();
  }

  // -- shared response handling ----------------------------------------------

  private parseResponseMessage(
    value: unknown,
    request: VmSupervisorRequest,
    mutation: boolean
  ): VmSupervisorResponse {
    const parsed = VmSupervisorResponseSchema.safeParse(value);
    if (!parsed.success || parsed.data.requestId !== request.requestId) {
      const error = mutation
        ? transportFailure(true, request.op)
        : protocolFailure('malformed or mismatched response envelope', request.op);
      this.terminate({ type: 'terminal', reason: 'protocol', error });
      throw error;
    }
    return parsed.data;
  }

  /**
   * A post-auth {type:'error'} frame is connection-fatal, not a typed
   * per-request response (those arrive as response{ok:false}). For a pending
   * mutation the outcome is unknown; for a read it is a supervisor failure.
   */
  private fatalControl(value: unknown, mutation: boolean, op: VmSupervisorOperation): never {
    const wire = parseWireError(value);
    const error = mutation
      ? callError('VM_UNKNOWN_STATE', wire.message, true, true, op)
      : callError('VM_SUPERVISOR_UNAVAILABLE', wire.message, wire.retryable, false, op);
    this.terminate({ type: 'terminal', reason: 'protocol', error });
    throw error;
  }

  private unexpectedControl(type: unknown, context: string, request: VmSupervisorRequest, postCommand = false): never {
    const message = `unexpected ${String(type)} ${context}`;
    const error = postCommand ? postCommandFailure(message, request.op) : protocolFailure(message, request.op);
    this.terminate({ type: 'terminal', reason: 'protocol', error });
    throw error;
  }

  // -- flows -----------------------------------------------------------------

  /**
   * Unary request/response. Returns the validated response envelope; the
   * caller maps ok/error and validates `result` per op.
   */
  async call(request: VmSupervisorRequest, options: { timeoutMs?: number | undefined; signal?: AbortSignal | undefined } = {}): Promise<VmSupervisorResponse> {
    this.op = request.op;
    const mutation = this.mutation;
    // A pre-aborted request must never dispatch a frame. Nothing was sent,
    // so the outcome is KNOWN — CANCELLED even for mutations (contrast the
    // post-send abort in mapTerminal, which is UNKNOWN for mutations).
    if (options.signal?.aborted) {
      throw callError('CANCELLED', `${request.op} aborted before dispatch`, false, false, request.op);
    }
    this.sendJson({ type: 'request', request });
    this.armAbort(options.signal);
    const deadline = setTimeout(() => {
      this.terminate({ type: 'terminal', reason: 'timeout' });
    }, options.timeoutMs ?? this.limits.requestTimeoutMs);
    deadline.unref?.();
    try {
      for (;;) {
        const event = await this.nextEvent();
        if (event.type === 'terminal') throw this.mapTerminal(event, mutation, request.op);
        if (event.type === 'bytes') {
          this.unexpectedControl('byte-frame', 'during request', request);
        }
        const type = event.message.type;
        if (type === 'response') {
          return this.parseResponseMessage(event.message.response, request, mutation);
        }
        if (type === 'error') this.fatalControl(event.message.error, mutation, request.op);
        this.unexpectedControl(type, 'during request', request);
      }
    } finally {
      clearTimeout(deadline);
      this.clearIdleTimer();
      this.disarmAbort();
    }
  }

  /**
   * Upload flow: request → stream-ready → kind-0x01 payload frames →
   * stream-end → typed response. EOF before stream-end is UNKNOWN for
   * mutations per the wire spec.
   */
  async upload(
    request: VmSupervisorRequest,
    expectedStreamRef: string,
    payload: AsyncIterable<Buffer> | Iterable<Buffer>,
    options: { timeoutMs?: number | undefined; signal?: AbortSignal | undefined } = {}
  ): Promise<VmSupervisorResponse> {
    this.op = request.op;
    const mutation = this.mutation;
    if (
      typeof (payload as AsyncIterable<Buffer>)[Symbol.asyncIterator] !== 'function' &&
      typeof (payload as Iterable<Buffer>)[Symbol.iterator] !== 'function'
    ) {
      throw callError('INVALID_INPUT', `${request.op} payload must be an async or sync iterable of Buffers`, false, false, request.op);
    }
    if (options.signal?.aborted) {
      throw callError('CANCELLED', `${request.op} aborted before dispatch`, false, false, request.op);
    }
    this.sendJson({ type: 'request', request });
    this.armAbort(options.signal);
    const requestTimeout = options.timeoutMs ?? this.limits.requestTimeoutMs;
    const startDeadline = setTimeout(() => {
      this.terminate({ type: 'terminal', reason: 'timeout' });
    }, requestTimeout);
    startDeadline.unref?.();
    try {
      const start = await this.awaitFlowStart(request, 'stream-ready', mutation);
      clearTimeout(startDeadline);
      if (start.kind === 'response') return start.response;
      if (start.streamRef !== expectedStreamRef) {
        const error = protocolFailure('stream-ready streamRef mismatch', request.op);
        this.terminate({ type: 'terminal', reason: 'protocol', error });
        throw error;
      }
      // Phase 2: stream payload frames under the idle deadline.
      this.armIdleTimer();
      const iterator = toAsyncIterator(payload);
      try {
        for (;;) {
          const next = await iterator.next();
          if (next.done) break;
          const chunk = Buffer.isBuffer(next.value) ? next.value : Buffer.from(next.value);
          for (let offset = 0; offset < chunk.length; offset += this.limits.uploadChunkBytes) {
            await this.sendBytes(chunk.subarray(offset, offset + this.limits.uploadChunkBytes));
            this.noteActivity();
          }
        }
      } catch (error) {
        // Local payload failure: stream-end is never sent and the server
        // discards the partial upload, so propagate the original error.
        // Transport failures are already mapped VmSupervisorCallErrors.
        this.terminate({ type: 'terminal', reason: 'eof' });
        throw error;
      } finally {
        await iterator.return(undefined).catch(() => undefined);
      }
      // The server-issued ref is authoritative — echo it verbatim.
      this.sendJson({ type: 'stream-end', streamRef: start.streamRef });
      this.clearIdleTimer();
      // Phase 3: await the typed response under a fresh request deadline.
      return await this.awaitResponse(request, mutation, requestTimeout);
    } finally {
      clearTimeout(startDeadline);
      this.clearIdleTimer();
      this.disarmAbort();
    }
  }

  /**
   * Download flow: request → stream-start → kind-0x01 byte frames → typed
   * trailer response. `maxBytesBound` is the caller-declared cap; the
   * stream-start maxBytes can only tighten it.
   */
  async download(
    request: VmSupervisorRequest,
    maxBytesBound: number,
    sink: (chunk: Buffer) => void | Promise<void>,
    options: { timeoutMs?: number | undefined; signal?: AbortSignal | undefined } = {}
  ): Promise<VmSupervisorResponse> {
    this.op = request.op;
    const mutation = this.mutation;
    if (options.signal?.aborted) {
      throw callError('CANCELLED', `${request.op} aborted before dispatch`, false, false, request.op);
    }
    this.sendJson({ type: 'request', request });
    this.armAbort(options.signal);
    const requestTimeout = options.timeoutMs ?? this.limits.requestTimeoutMs;
    const startDeadline = setTimeout(() => {
      this.terminate({ type: 'terminal', reason: 'timeout' });
    }, requestTimeout);
    startDeadline.unref?.();
    try {
      const start = await this.awaitFlowStart(request, 'stream-start', mutation);
      clearTimeout(startDeadline);
      if (start.kind === 'response') return start.response;
      const bound = Math.min(maxBytesBound, start.maxBytes, this.limits.maxStreamBytes);
      this.armIdleTimer();
      const hash = createHash('sha256');
      let received = 0;
      for (;;) {
        const event = await this.nextEvent();
        if (event.type === 'terminal') throw this.mapTerminal(event, mutation, request.op);
        this.noteActivity();
        if (event.type === 'bytes') {
          received += event.payload.length;
          if (received > bound) {
            const error = protocolFailure('download exceeded byte bound', request.op);
            this.terminate({ type: 'terminal', reason: 'protocol', error });
            throw error;
          }
          hash.update(event.payload);
          await sink(event.payload);
          continue;
        }
        const type = event.message.type;
        if (type === 'response') {
          const response = this.parseResponseMessage(event.message.response, request, mutation);
          this.verifyStreamTrailer(response, request, received, hash);
          return response;
        }
        if (type === 'error') this.fatalControl(event.message.error, mutation, request.op);
        this.unexpectedControl(type, 'during download', request);
      }
    } finally {
      clearTimeout(startDeadline);
      this.clearIdleTimer();
      this.disarmAbort();
    }
  }

  /**
   * exec.run answers either inline ({kind:'result'}) or framed: stream-start
   * → WIRE_KIND_BYTES(u64be(stdoutUtf8Len) || stdoutUtf8 || stderrUtf8) →
   * stream-digest{streamRef, sha256, bytes} → response trailer whose
   * stdout/stderr are emptied. Idempotent replays of large journaled results
   * take the same framed path, so both forms are handled here. The returned
   * envelope carries the decoded streams spliced into `result`; per-op schema
   * validation still happens in the caller's unwrap().
   */
  async execRunResult(
    request: VmSupervisorRequest,
    opId: string,
    maxBytes: number,
    options: { timeoutMs?: number | undefined; signal?: AbortSignal | undefined } = {}
  ): Promise<VmSupervisorResponse> {
    this.op = request.op;
    const mutation = this.mutation;
    if (options.signal?.aborted) {
      throw callError('CANCELLED', `${request.op} aborted before dispatch`, false, false, request.op);
    }
    this.sendJson({ type: 'request', request });
    this.armAbort(options.signal);
    const requestTimeout = options.timeoutMs ?? this.limits.requestTimeoutMs;
    const startDeadline = setTimeout(() => {
      this.terminate({ type: 'terminal', reason: 'timeout' });
    }, requestTimeout);
    startDeadline.unref?.();
    try {
      const start = await this.awaitFlowStart(request, 'stream-start', mutation);
      clearTimeout(startDeadline);
      if (start.kind === 'response') return start.response;
      const expectedRef = `exec:${opId}`;
      if (start.streamRef !== expectedRef) {
        const error = postCommandFailure('exec.run streamRef does not match request opId', request.op);
        this.terminate({ type: 'terminal', reason: 'protocol', error });
        throw error;
      }
      // Bound the payload from the REQUEST, not just the global cap: each
      // stream is capped at `maxBytes` raw bytes server-side, and the lossy
      // UTF-8 decode can expand every invalid byte to a 3-byte U+FFFD, so a
      // legitimate payload is at most 8 + 6*maxBytes. The protocol hard cap
      // (2*16MiB streams + 8-byte prefix) applies on top — stream-start's
      // declared maxBytes is never trusted on its own.
      const bound = Math.min(
        start.maxBytes,
        EXEC_RUN_STREAM_MAX_BYTES,
        8 + 6 * maxBytes,
        this.limits.maxStreamBytes
      );
      this.armIdleTimer();
      const hash = createHash('sha256');
      const chunks: Buffer[] = [];
      let received = 0;
      let digestBytes: number | undefined;
      let digestSeen = false;
      for (;;) {
        const event = await this.nextEvent();
        if (event.type === 'terminal') throw this.mapTerminal(event, mutation, request.op);
        this.noteActivity();
        if (event.type === 'bytes') {
          if (digestSeen) {
            const error = postCommandFailure('byte frame after stream-digest', request.op);
            this.terminate({ type: 'terminal', reason: 'protocol', error });
            throw error;
          }
          received += event.payload.length;
          if (received > bound) {
            const error = postCommandFailure('exec.run stream exceeded byte bound', request.op);
            this.terminate({ type: 'terminal', reason: 'protocol', error });
            throw error;
          }
          hash.update(event.payload);
          chunks.push(event.payload);
          continue;
        }
        const type = event.message.type;
        if (type === 'stream-digest') {
          const message = event.message as { streamRef?: unknown; sha256?: unknown; bytes?: unknown };
          if (
            digestSeen ||
            message.streamRef !== start.streamRef ||
            typeof message.sha256 !== 'string' ||
            typeof message.bytes !== 'number' ||
            message.bytes !== received ||
            message.sha256 !== hash.digest('hex')
          ) {
            const error = postCommandFailure('exec.run stream-digest mismatch', request.op);
            this.terminate({ type: 'terminal', reason: 'protocol', error });
            throw error;
          }
          digestSeen = true;
          digestBytes = message.bytes;
          continue;
        }
        if (type === 'response') {
          const response = this.parseResponseMessage(event.message.response, request, mutation);
          if (!response.ok) return response;
          if (!digestSeen || digestBytes !== received || received !== start.maxBytes) {
            const error = postCommandFailure('exec.run stream length/digest incomplete', request.op);
            this.terminate({ type: 'terminal', reason: 'protocol', error });
            throw error;
          }
          const payload = Buffer.concat(chunks, received);
          if (payload.length < 8) {
            const error = postCommandFailure('exec.run stream payload too short', request.op);
            this.terminate({ type: 'terminal', reason: 'protocol', error });
            throw error;
          }
          const stdoutLength = Number(payload.readBigUInt64BE(0));
          if (stdoutLength > payload.length - 8) {
            const error = postCommandFailure('exec.run stdout length exceeds payload', request.op);
            this.terminate({ type: 'terminal', reason: 'protocol', error });
            throw error;
          }
          const result = response.result;
          if (typeof result !== 'object' || result === null) {
            const error = postCommandFailure('exec.run trailer result is not an object', request.op);
            this.terminate({ type: 'terminal', reason: 'protocol', error });
            throw error;
          }
          const trailer = result as Record<string, unknown>;
          if (trailer.stdout !== '' || trailer.stderr !== '') {
            const error = postCommandFailure('exec.run trailer streams must be empty', request.op);
            this.terminate({ type: 'terminal', reason: 'protocol', error });
            throw error;
          }
          return {
            ...response,
            result: {
              ...trailer,
              stdout: payload.subarray(8, 8 + stdoutLength).toString('utf8'),
              stderr: payload.subarray(8 + stdoutLength).toString('utf8')
            }
          };
        }
        if (type === 'error') this.fatalControl(event.message.error, mutation, request.op);
        this.unexpectedControl(type, 'during exec.run download', request, mutation);
      }
    } finally {
      clearTimeout(startDeadline);
      this.clearIdleTimer();
      this.disarmAbort();
    }
  }

  /**
   * M7: the typed trailer is only trusted after it matches the bytes that
   * actually crossed the socket. `sha256`/`bytes` are verified whenever the
   * op's result carries them (pullTree, vm.export); results without a
   * trailer shape are left to per-op schema validation.
   */
  private verifyStreamTrailer(
    response: VmSupervisorResponse,
    request: VmSupervisorRequest,
    received: number,
    hash: ReturnType<typeof createHash>
  ): void {
    if (!response.ok) return;
    const result = response.result;
    if (typeof result !== 'object' || result === null) return;
    const trailer = result as Record<string, unknown>;
    if (typeof trailer.sha256 !== 'string' || typeof trailer.bytes !== 'number') return;
    if (trailer.bytes !== received || trailer.sha256 !== hash.digest('hex')) {
      const error = protocolFailure('stream trailer does not match received bytes', request.op);
      this.terminate({ type: 'terminal', reason: 'protocol', error });
      throw error;
    }
  }

  /**
   * exec.open: unary request whose ok-result opens a session phase on this
   * connection. Returns the live session handle.
   */
  async openSession(
    request: VmSupervisorRequest,
    sessionId: string,
    options: { timeoutMs?: number | undefined; signal?: AbortSignal | undefined } = {}
  ): Promise<VmExecSessionImpl> {
    this.op = request.op;
    const response = await this.call(request, options);
    if (!response.ok) {
      const wire = response.error;
      const code = ErrorCodeSchema.safeParse(wire.code);
      throw callError(
        code.success ? code.data : 'VM_SUPERVISOR_UNAVAILABLE',
        wire.message,
        wire.retryable,
        response.unknown === true,
        request.op
      );
    }
    const parsed = VmSupervisorOpResultSchemas['exec.open'].safeParse(response.result);
    if (!parsed.success || parsed.data.sessionId !== sessionId || parsed.data.fdsReady !== true) {
      const error = transportFailure(true, request.op);
      this.terminate({ type: 'terminal', reason: 'protocol', error });
      throw error;
    }
    const session = new VmExecSessionImpl(sessionId, this, this.limits);
    void this.pumpSession(session);
    return session;
  }

  private async pumpSession(session: VmExecSessionImpl): Promise<void> {
    try {
      for (;;) {
        const event = await this.nextEvent();
        if (event.type === 'terminal') {
          if (session.localClose) {
            session.end();
          } else {
            session.fail(this.mapTerminal(event, true, 'exec.open'));
          }
          this.close();
          return;
        }
        if (event.type === 'bytes') {
          session.pushBytes(event.payload);
          continue;
        }
        const message = event.message;
        const type = message.type;
        if (type === 'session-data') {
          const data = message as { sessionId?: unknown; fd?: unknown; bytes?: unknown };
          if (
            data.sessionId !== session.sessionId ||
            typeof data.fd !== 'number' ||
            typeof data.bytes !== 'number' ||
            data.bytes < 0 ||
            data.bytes > this.limits.maxSessionDataMessageBytes
          ) {
            throw protocolFailure('malformed session-data header', 'exec.open');
          }
          session.expectData(data.fd, data.bytes);
          continue;
        }
        if (type === 'session-meta') {
          const meta = message as { sessionId?: unknown; exitCode?: unknown; signal?: unknown; returnMetadata?: unknown };
          if (meta.sessionId !== session.sessionId) {
            throw protocolFailure('session-meta for unknown session', 'exec.open');
          }
          session.deliverMeta({
            exitCode: typeof meta.exitCode === 'number' ? meta.exitCode : null,
            signal: typeof meta.signal === 'string' ? meta.signal : null,
            returnMetadata: typeof meta.returnMetadata === 'object' && meta.returnMetadata !== null
              ? meta.returnMetadata as Record<string, unknown>
              : undefined
          });
          continue;
        }
        if (type === 'session-end') {
          const end = message as { sessionId?: unknown };
          if (end.sessionId !== session.sessionId) {
            throw protocolFailure('session-end for unknown session', 'exec.open');
          }
          session.end();
          this.close();
          return;
        }
        throw protocolFailure(`unexpected ${String(type)} during session`, 'exec.open');
      }
    } catch (error) {
      session.fail(error instanceof VmSupervisorCallError ? error : protocolFailure('session pump failure', 'exec.open'));
      this.close();
    }
  }

  /** Phase 1 of upload/download: await stream-ready/stream-start. */
  private async awaitFlowStart(
    request: VmSupervisorRequest,
    expected: 'stream-ready' | 'stream-start',
    mutation: boolean
  ): Promise<
    | { kind: 'start'; streamRef: string; maxBytes: number }
    | { kind: 'response'; response: VmSupervisorResponse }
  > {
    for (;;) {
      const event = await this.nextEvent();
      if (event.type === 'terminal') throw this.mapTerminal(event, mutation, request.op);
      if (event.type === 'bytes') {
        this.unexpectedControl('byte-frame', 'before stream start', request);
      }
      const type = event.message.type;
      if (type === expected) {
        const message = event.message as { streamRef?: unknown; maxBytes?: unknown };
        if (typeof message.streamRef !== 'string' || message.streamRef.length === 0) {
          const error = protocolFailure(`${expected} missing streamRef`, request.op);
          this.terminate({ type: 'terminal', reason: 'protocol', error });
          throw error;
        }
        const maxBytes = typeof message.maxBytes === 'number' && Number.isFinite(message.maxBytes)
          ? message.maxBytes
          : this.limits.maxStreamBytes;
        return { kind: 'start', streamRef: message.streamRef, maxBytes };
      }
      if (type === 'response') {
        return { kind: 'response', response: this.parseResponseMessage(event.message.response, request, mutation) };
      }
      if (type === 'error') this.fatalControl(event.message.error, mutation, request.op);
      this.unexpectedControl(type, `awaiting ${expected}`, request);
    }
  }

  /** Shared tail: await the typed response after a flow start. */
  private async awaitResponse(
    request: VmSupervisorRequest,
    mutation: boolean,
    timeoutMs: number
  ): Promise<VmSupervisorResponse> {
    const deadline = setTimeout(() => {
      this.terminate({ type: 'terminal', reason: 'timeout' });
    }, timeoutMs);
    deadline.unref?.();
    try {
      for (;;) {
        const event = await this.nextEvent();
        if (event.type === 'terminal') throw this.mapTerminal(event, mutation, request.op);
        if (event.type === 'bytes') {
          this.unexpectedControl('byte-frame', 'awaiting response', request);
        }
        const type = event.message.type;
        if (type === 'response') {
          return this.parseResponseMessage(event.message.response, request, mutation);
        }
        if (type === 'error') this.fatalControl(event.message.error, mutation, request.op);
        this.unexpectedControl(type, 'awaiting response', request);
      }
    } finally {
      clearTimeout(deadline);
    }
  }
}

// ---------------------------------------------------------------------------
// Session implementation
// ---------------------------------------------------------------------------

class VmExecSessionImpl implements VmExecSession {
  readonly sessionId: string;
  readonly ended: Promise<VmSessionMeta>;
  closed = false;
  localClose = false;

  private readonly conn: WireConn;
  private readonly dataListeners = new Set<(fd: number, chunk: Buffer) => boolean | void>();
  private readonly metaListeners = new Set<(meta: VmSessionMeta) => void>();
  private meta: VmSessionMeta = { exitCode: null, signal: null };
  private pending: { fd: number; remaining: number; chunks: Buffer[] } | null = null;
  /**
   * session-data can legally arrive in the same socket flush as the exec.open
   * response — before the caller's first onData() registration. Those chunks
   * are buffered (bounded) and replayed on registration instead of dropped.
   */
  private preListener: Array<{ fd: number; chunk: Buffer }> = [];
  private preListenerBytes = 0;
  private preListenerPaused = false;
  private paused = false;
  private endedResolve!: (meta: VmSessionMeta) => void;
  private endedReject!: (error: Error) => void;
  private settled = false;

  private readonly limits: Required<VmSupervisorClientLimits>;

  constructor(sessionId: string, conn: WireConn, limits: Required<VmSupervisorClientLimits>) {
    this.sessionId = sessionId;
    this.conn = conn;
    this.limits = limits;
    this.ended = new Promise<VmSessionMeta>((resolve, reject) => {
      this.endedResolve = resolve;
      this.endedReject = reject;
    });
    // Avoid unhandled rejection noise when callers never await `ended`.
    this.ended.catch(() => undefined);
  }

  onData(listener: (fd: number, chunk: Buffer) => boolean | void): () => void {
    this.dataListeners.add(listener);
    if (this.dataListeners.size === 1 && this.preListener.length > 0) {
      const buffered = this.preListener;
      this.preListener = [];
      this.preListenerBytes = 0;
      for (const item of buffered) this.deliverData(item.fd, item.chunk);
    }
    if (this.preListenerPaused) {
      this.preListenerPaused = false;
      this.conn.resumeSocket();
    }
    return () => this.dataListeners.delete(listener);
  }

  onMeta(listener: (meta: VmSessionMeta) => void): () => void {
    this.metaListeners.add(listener);
    return () => this.metaListeners.delete(listener);
  }

  /** Called by the connection pump on a session-data header. */
  expectData(fd: number, bytes: number): void {
    if (this.pending !== null) {
      throw protocolFailure('session-data header while payload incomplete', 'exec.open');
    }
    this.pending = { fd, remaining: bytes, chunks: [] };
    if (bytes === 0) this.flushPending();
  }

  /** Called by the connection pump on a kind-0x01 frame during a session. */
  pushBytes(payload: Buffer): void {
    if (this.pending === null) {
      throw protocolFailure('byte frame outside session-data', 'exec.open');
    }
    if (payload.length > this.pending.remaining) {
      throw protocolFailure('session-data payload exceeds declared length', 'exec.open');
    }
    this.pending.chunks.push(Buffer.from(payload));
    this.pending.remaining -= payload.length;
    if (this.pending.remaining === 0) this.flushPending();
  }

  private flushPending(): void {
    const pending = this.pending;
    if (!pending) return;
    this.pending = null;
    const chunk = pending.chunks.length === 1 ? pending.chunks[0]! : Buffer.concat(pending.chunks);
    if (this.dataListeners.size === 0) {
      // No listener yet: buffer pre-open output. Past the soft cap pause the
      // socket — but NEVER drop the chunk: session output is data, and
      // discarding it is silent corruption. Frames already decoded into the
      // connection queue still arrive while paused, so they are held too;
      // the hard cap bounds total held bytes and fails the session loudly.
      if (this.preListenerBytes + chunk.length > this.limits.preListenerHardMaxBytes) {
        // exec.open already succeeded — the guest command is running and its
        // outcome is unobservable once we close. Nothing malformed arrived;
        // this is a client resource bound, so the session reports UNKNOWN
        // (retryable, reconcile-first) rather than a protocol violation.
        this.fail(transportFailure(true, 'exec.open'));
        this.conn.close();
        return;
      }
      this.preListener.push({ fd: pending.fd, chunk });
      this.preListenerBytes += chunk.length;
      if (!this.preListenerPaused && this.preListenerBytes > this.limits.preListenerBufferMaxBytes) {
        this.preListenerPaused = true;
        this.conn.pauseSocket();
      }
      return;
    }
    this.deliverData(pending.fd, chunk);
  }

  private deliverData(fd: number, chunk: Buffer): void {
    let pause = false;
    for (const listener of this.dataListeners) {
      try {
        if (listener(fd, chunk) === false) pause = true;
      } catch {
        // Listener errors must not kill the session pump.
      }
    }
    if (pause && !this.paused) {
      this.paused = true;
      this.conn.pauseSocket();
    }
  }

  resume(): void {
    if (!this.paused) return;
    this.paused = false;
    this.conn.resumeSocket();
  }

  deliverMeta(meta: VmSessionMeta): void {
    this.meta = meta;
    for (const listener of this.metaListeners) {
      try {
        listener(meta);
      } catch {
        // ignore listener errors
      }
    }
  }

  end(): void {
    if (this.settled) return;
    this.settled = true;
    this.closed = true;
    this.endedResolve(this.meta);
  }

  fail(error: Error): void {
    if (this.settled) return;
    this.settled = true;
    this.closed = true;
    this.endedReject(error);
  }

  close(): void {
    if (this.closed) return;
    this.localClose = true;
    this.conn.close();
    // The pump observes the terminal event and resolves `ended`.
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function parseWireError(value: unknown): { code: ErrorCode; message: string; retryable: boolean } {
  if (typeof value === 'object' && value !== null) {
    const record = value as { code?: unknown; message?: unknown; retryable?: unknown };
    const code = ErrorCodeSchema.safeParse(record.code);
    return {
      code: code.success ? code.data : 'VM_SUPERVISOR_UNAVAILABLE',
      message: typeof record.message === 'string' && record.message.length > 0
        ? record.message.slice(0, 2_000)
        : 'vm-supervisor request failed',
      retryable: record.retryable === true
    };
  }
  return { code: 'VM_SUPERVISOR_UNAVAILABLE', message: 'vm-supervisor request failed', retryable: true };
}

function invalidInput(op: string, detail: string): VmSupervisorCallError {
  return callError('INVALID_INPUT', `invalid ${op} request: ${detail}`, false, false, op);
}

function zodIssueDetail(error: unknown): string {
  // Never include issue values — params may carry environment secrets.
  const issues = (error as { issues?: Array<{ path?: unknown[]; code?: string }> }).issues;
  if (!Array.isArray(issues) || issues.length === 0) return 'invalid parameters';
  const first = issues[0]!;
  const path = Array.isArray(first.path)
    ? first.path.filter((part) => typeof part === 'string' || typeof part === 'number').join('.')
    : '';
  return path ? `invalid ${path}` : 'invalid parameters';
}

async function* toAsyncIterator<T>(source: AsyncIterable<T> | Iterable<T>): AsyncGenerator<T> {
  if (typeof (source as AsyncIterable<T>)[Symbol.asyncIterator] === 'function') {
    yield* source as AsyncIterable<T>;
    return;
  }
  yield* source as Iterable<T>;
}

const defaultConnect = (socketPath: string): Promise<Socket> =>
  new Promise<Socket>((resolve, reject) => {
    const socket = netConnect({ path: socketPath });
    socket.once('connect', () => resolve(socket));
    socket.once('error', reject);
  });

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

export class VmSupervisorClient {
  private readonly socketPath: string;
  private readonly token: string;
  private readonly limits: Required<VmSupervisorClientLimits>;
  private readonly connect: (socketPath: string) => Promise<Socket>;
  private readonly now: () => number;
  private readonly newId: () => string;
  private readonly sessions = new Set<VmExecSessionImpl>();

  constructor(deps: VmSupervisorClientDeps) {
    this.socketPath = deps.socketPath;
    this.token = deps.token;
    this.limits = { ...VM_WIRE_LIMITS, ...(deps.limits ?? {}) } as Required<VmSupervisorClientLimits>;
    this.connect = deps.connect ?? defaultConnect;
    this.now = deps.now ?? (() => Date.now());
    this.newId = deps.newId ?? (() => randomUUID());
  }

  /** Close every live exec session (runner shutdown path). */
  close(): void {
    for (const session of this.sessions) session.close();
    this.sessions.clear();
  }

  // -- envelope builders -----------------------------------------------------

  private workspaceRequest<Op extends VmWorkspaceOperation>(
    identity: VmWorkspaceIdentity,
    op: Op,
    params: unknown,
    options?: VmCallOptions
  ): VmSupervisorWorkspaceRequest {
    try {
      return VmSupervisorWorkspaceRequestSchema.parse({
        version: 1,
        requestId: this.newId(),
        workspaceId: identity.workspaceId,
        workspaceGeneration: identity.generation,
        vmInstanceId: identity.instanceId,
        idempotencyKey: options?.idempotencyKey ?? `idem-${this.newId()}`,
        issuedAt: this.now(),
        op,
        params
      });
    } catch (error) {
      throw invalidInput(op, zodIssueDetail(error));
    }
  }

  private hostRequest<Op extends VmHostOperation>(
    op: Op,
    params: unknown
  ): VmSupervisorHostRequest {
    try {
      return VmSupervisorHostRequestSchema.parse({
        version: 1,
        requestId: this.newId(),
        issuedAt: this.now(),
        op,
        params
      });
    } catch (error) {
      throw invalidInput(op, zodIssueDetail(error));
    }
  }

  // -- connection plumbing ----------------------------------------------------

  private async openConn(): Promise<WireConn> {
    // Promise.resolve().then() also captures synchronous connect() throws.
    const pending = Promise.resolve().then(() => this.connect(this.socketPath));
    let timer: NodeJS.Timeout | undefined;
    let socket: Socket;
    try {
      socket = await Promise.race([
        pending,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => {
            reject(callError('VM_SUPERVISOR_UNAVAILABLE', 'vm-supervisor connect timed out', true, false));
          }, this.limits.connectTimeoutMs);
          timer.unref?.();
        })
      ]);
    } catch (error) {
      // A late-arriving socket must not leak.
      void pending.then((late) => late.destroy()).catch(() => undefined);
      if (error instanceof VmSupervisorCallError) throw error;
      throw callError('VM_SUPERVISOR_UNAVAILABLE', 'cannot reach vm-supervisor socket', true, false);
    } finally {
      if (timer) clearTimeout(timer);
    }
    try {
      return await WireConn.openAuthenticated(socket, this.token, this.limits);
    } catch (error) {
      socket.destroy();
      throw error;
    }
  }

  private async unwrap<T>(response: VmSupervisorResponse, op: VmSupervisorOperation, mutation: boolean): Promise<T> {
    if (!response.ok) {
      const wire = response.error;
      const code = ErrorCodeSchema.safeParse(wire.code);
      const resolved = code.success ? code.data : 'VM_SUPERVISOR_UNAVAILABLE';
      throw callError(resolved, wire.message, wire.retryable, response.unknown === true, op);
    }
    const schema = VmSupervisorOpResultSchemas[op];
    const parsed = schema.safeParse(response.result);
    if (!parsed.success) {
      throw mutation
        ? transportFailure(true, op)
        : protocolFailure(`${op} returned a malformed result`, op);
    }
    return parsed.data as T;
  }

  private async unary<Op extends VmSupervisorOperation>(
    op: Op,
    request: VmSupervisorRequest,
    options?: VmCallOptions
  ): Promise<VmOpResult<Op>> {
    const conn = await this.openConn();
    try {
      const response = await conn.call(request, { timeoutMs: options?.timeoutMs, signal: options?.signal });
      return await this.unwrap<VmOpResult<Op>>(response, op, isMutation(op));
    } finally {
      conn.close();
    }
  }

  private async upload<Op extends VmSupervisorOperation>(
    op: Op,
    request: VmSupervisorRequest,
    expectedStreamRef: string,
    payload: AsyncIterable<Buffer> | Iterable<Buffer>,
    options?: VmCallOptions
  ): Promise<VmOpResult<Op>> {
    const conn = await this.openConn();
    try {
      const response = await conn.upload(request, expectedStreamRef, payload, { timeoutMs: options?.timeoutMs, signal: options?.signal });
      return await this.unwrap<VmOpResult<Op>>(response, op, isMutation(op));
    } finally {
      conn.close();
    }
  }

  private async download<Op extends VmSupervisorOperation>(
    op: Op,
    request: VmSupervisorRequest,
    maxBytesBound: number,
    sink: (chunk: Buffer) => void | Promise<void>,
    options?: VmCallOptions
  ): Promise<VmOpResult<Op>> {
    const conn = await this.openConn();
    try {
      const response = await conn.download(request, maxBytesBound, sink, { timeoutMs: options?.timeoutMs, signal: options?.signal });
      return await this.unwrap<VmOpResult<Op>>(response, op, isMutation(op));
    } finally {
      conn.close();
    }
  }

  // -- host ops ---------------------------------------------------------------

  async vmList(params: VmHostOpParams<'vm.list'> = {}, options?: VmCallOptions): Promise<VmInstanceListResult> {
    return this.unary('vm.list', this.hostRequest('vm.list', params), options);
  }

  async leaseList(options?: VmCallOptions): Promise<VmLeaseListResult> {
    return this.unary('lease.list', this.hostRequest('lease.list', {}), options);
  }

  async poolInfo(options?: VmCallOptions): Promise<VmPoolInfoResult> {
    return this.unary('pool.info', this.hostRequest('pool.info', {}), options);
  }

  async reconcile(options?: VmCallOptions): Promise<VmReconcileResult> {
    return this.unary('reconcile', this.hostRequest('reconcile', {}), options);
  }

  async guardState(options?: VmCallOptions): Promise<VmGuardStateResult> {
    return this.unary('guard.state', this.hostRequest('guard.state', {}), options);
  }

  // -- workspace lifecycle ----------------------------------------------------

  async vmAdmit(identity: VmWorkspaceIdentity, params: VmWorkspaceOpParams<'vm.admit'>, options?: VmCallOptions): Promise<VmAdmitResult> {
    return this.unary('vm.admit', this.workspaceRequest(identity, 'vm.admit', params, options), options);
  }

  async vmCreate(identity: VmWorkspaceIdentity, params: VmWorkspaceOpParams<'vm.create'>, options?: VmCallOptions): Promise<VmCreateResult> {
    return this.unary('vm.create', this.workspaceRequest(identity, 'vm.create', params, options), options);
  }

  async vmStart(identity: VmWorkspaceIdentity, params: VmWorkspaceOpParams<'vm.start'>, options?: VmCallOptions): Promise<VmStartResult> {
    return this.unary('vm.start', this.workspaceRequest(identity, 'vm.start', params, options), options);
  }

  async vmStop(identity: VmWorkspaceIdentity, options?: VmCallOptions): Promise<VmStopResult> {
    return this.unary('vm.stop', this.workspaceRequest(identity, 'vm.stop', {}, options), options);
  }

  async vmDelete(identity: VmWorkspaceIdentity, params: VmWorkspaceOpParams<'vm.delete'>, options?: VmCallOptions): Promise<VmDeleteResult> {
    return this.unary('vm.delete', this.workspaceRequest(identity, 'vm.delete', params, options), options);
  }

  async vmStatus(identity: VmWorkspaceIdentity, options?: VmCallOptions): Promise<VmStatusResult> {
    return this.unary('vm.status', this.workspaceRequest(identity, 'vm.status', {}, options), options);
  }

  async vmExport(
    identity: VmWorkspaceIdentity,
    params: VmWorkspaceOpParams<'vm.export'>,
    options: VmDownloadOptions
  ): Promise<VmTarTrailer> {
    return this.download(
      'vm.export',
      this.workspaceRequest(identity, 'vm.export', params, options),
      params.maxBytes,
      options.sink,
      options
    );
  }

  // -- exec -------------------------------------------------------------------

  async execRun(identity: VmWorkspaceIdentity, params: VmWorkspaceOpParams<'exec.run'>, options?: VmCallOptions): Promise<VmExecRunResult> {
    const request = this.workspaceRequest(identity, 'exec.run', params, options);
    const conn = await this.openConn();
    try {
      // exec.run may answer inline or via the framed download path (large
      // results, including idempotent replays of journaled ones). The
      // decoder splices decoded stdout/stderr into the trailer result.
      const response = await conn.execRunResult(request, params.opId, params.maxBytes, {
        timeoutMs: options?.timeoutMs,
        signal: options?.signal
      });
      return await this.unwrap<VmExecRunResult>(response, 'exec.run', isMutation('exec.run'));
    } finally {
      conn.close();
    }
  }

  async execInspect(identity: VmWorkspaceIdentity, params: VmWorkspaceOpParams<'exec.inspect'>, options?: VmCallOptions): Promise<VmExecInspectResult> {
    return this.unary('exec.inspect', this.workspaceRequest(identity, 'exec.inspect', params, options), options);
  }

  async execOpen(identity: VmWorkspaceIdentity, params: VmWorkspaceOpParams<'exec.open'>, options?: VmCallOptions): Promise<VmExecSession> {
    const request = this.workspaceRequest(identity, 'exec.open', params, options);
    const conn = await this.openConn();
    let session: VmExecSessionImpl;
    try {
      session = await conn.openSession(request, params.sessionId, { timeoutMs: options?.timeoutMs, signal: options?.signal });
    } catch (error) {
      conn.close();
      throw error;
    }
    this.sessions.add(session);
    void session.ended.finally(() => this.sessions.delete(session)).catch(() => undefined);
    return session;
  }

  async execWrite(identity: VmWorkspaceIdentity, params: VmWorkspaceOpParams<'exec.write'>, options?: VmCallOptions): Promise<VmExecWriteResult> {
    return this.unary('exec.write', this.workspaceRequest(identity, 'exec.write', params, options), options);
  }

  async execClose(identity: VmWorkspaceIdentity, params: VmWorkspaceOpParams<'exec.close'>, options?: VmCallOptions): Promise<VmExecCloseResult> {
    return this.unary('exec.close', this.workspaceRequest(identity, 'exec.close', params, options), options);
  }

  async execResize(identity: VmWorkspaceIdentity, params: VmWorkspaceOpParams<'exec.resize'>, options?: VmCallOptions): Promise<VmExecResizeResult> {
    return this.unary('exec.resize', this.workspaceRequest(identity, 'exec.resize', params, options), options);
  }

  async execKillSession(identity: VmWorkspaceIdentity, params: VmWorkspaceOpParams<'exec.killSession'>, options?: VmCallOptions): Promise<VmExecKillSessionResult> {
    return this.unary('exec.killSession', this.workspaceRequest(identity, 'exec.killSession', params, options), options);
  }

  // -- files ------------------------------------------------------------------

  async filePush(identity: VmWorkspaceIdentity, params: VmFilePushInlineParams, options?: VmCallOptions): Promise<VmFilePushResult> {
    return this.unary('file.push', this.workspaceRequest(identity, 'file.push', params, options), options);
  }

  async filePushStream(
    identity: VmWorkspaceIdentity,
    params: VmFilePushStreamParams,
    payload: AsyncIterable<Buffer> | Iterable<Buffer>,
    options?: VmCallOptions
  ): Promise<VmFilePushResult> {
    return this.upload(
      'file.push',
      this.workspaceRequest(identity, 'file.push', params, options),
      params.streamRef,
      payload,
      options
    );
  }

  async filePull(identity: VmWorkspaceIdentity, params: VmWorkspaceOpParams<'file.pull'>, options?: VmCallOptions): Promise<VmFilePullResult> {
    return this.unary('file.pull', this.workspaceRequest(identity, 'file.pull', params, options), options);
  }

  async fileStat(identity: VmWorkspaceIdentity, params: VmWorkspaceOpParams<'file.stat'>, options?: VmCallOptions): Promise<VmFileStatResult> {
    return this.unary('file.stat', this.workspaceRequest(identity, 'file.stat', params, options), options);
  }

  async fileList(identity: VmWorkspaceIdentity, params: VmWorkspaceOpParams<'file.list'>, options?: VmCallOptions): Promise<VmFileListResult> {
    return this.unary('file.list', this.workspaceRequest(identity, 'file.list', params, options), options);
  }

  async pushTree(
    identity: VmWorkspaceIdentity,
    params: VmWorkspaceOpParams<'pushTree'>,
    payload: AsyncIterable<Buffer> | Iterable<Buffer>,
    options?: VmCallOptions
  ): Promise<VmTarTrailer> {
    const request = this.workspaceRequest(identity, 'pushTree', params, options);
    // The supervisor names pushTree uploads `tree:<requestId>`; file.push uses
    // the caller-supplied params.streamRef instead. Bind to the server-issued
    // ref inside upload() — never predict it.
    return this.upload('pushTree', request, `tree:${request.requestId}`, payload, options);
  }

  async pullTree(
    identity: VmWorkspaceIdentity,
    params: VmWorkspaceOpParams<'pullTree'>,
    options: VmDownloadOptions
  ): Promise<VmTarTrailer> {
    return this.download(
      'pullTree',
      this.workspaceRequest(identity, 'pullTree', params, options),
      params.maxBytes,
      options.sink,
      options
    );
  }

  // -- network ----------------------------------------------------------------

  async networkProgram(identity: VmWorkspaceIdentity, params: VmWorkspaceOpParams<'network.program'>, options?: VmCallOptions): Promise<VmNetworkProgramResult> {
    return this.unary('network.program', this.workspaceRequest(identity, 'network.program', params, options), options);
  }

  async networkAttest(identity: VmWorkspaceIdentity, options?: VmCallOptions): Promise<VmNetworkAttestResult> {
    return this.unary('network.attest', this.workspaceRequest(identity, 'network.attest', {}, options), options);
  }

  async networkTearDown(identity: VmWorkspaceIdentity, options?: VmCallOptions): Promise<VmNetworkTearDownResult> {
    return this.unary('network.tearDown', this.workspaceRequest(identity, 'network.tearDown', {}, options), options);
  }

  // -- lease ------------------------------------------------------------------

  async leaseSet(identity: VmWorkspaceIdentity, params: VmWorkspaceOpParams<'lease.set'>, options?: VmCallOptions): Promise<VmLeaseSetResult> {
    return this.unary('lease.set', this.workspaceRequest(identity, 'lease.set', params, options), options);
  }

  async leaseClear(identity: VmWorkspaceIdentity, options?: VmCallOptions): Promise<VmLeaseClearResult> {
    return this.unary('lease.clear', this.workspaceRequest(identity, 'lease.clear', {}, options), options);
  }
}
