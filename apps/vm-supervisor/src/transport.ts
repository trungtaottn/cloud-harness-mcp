import { createHash, randomUUID } from 'node:crypto';
import { createServer, type Server, type Socket } from 'node:net';
import { createWriteStream, type WriteStream } from 'node:fs';
import { mkdir, rm } from 'node:fs/promises';
import { DiskReservations } from './disk-reservations.js';
import { join } from 'node:path';
import { ErrorCodeSchema } from '@cloud-harness/contracts';
import { constantTimeEqual } from './security.js';

/**
 * vm-supervisor wire protocol v1 — the ONLY transport the runner-side client
 * implements (phase-07 worker consumes this spec, never this file).
 *
 * DESIGN DEVIATION (coordinator-approved): the phase plan sketched an
 * HTTP/1.1 unix-socket RPC; the implemented transport is a raw length-prefixed
 * framed protocol on net.Socket instead, chosen for bounded streaming,
 * session push and backpressure without HTTP overhead. Approved explicitly
 * by the coordinator; both sides implement THIS file's spec.
 *
 * FRAMING
 *   Every frame: `uint32be payloadLen || uint8 kind || payload` where
 *   payloadLen includes the kind byte (payloadLen = 1 + bodyLen).
 *   kind 0x00 → body is UTF-8 JSON control message.
 *   kind 0x01 → body is raw stream bytes belonging to the stream declared
 *               by the most recent control header in that direction.
 *   A JSON control message never exceeds 1 MiB; a single frame never
 *   exceeds 8 MiB; a connection never buffers more than 32 MiB unprocessed.
 *
 * DEADLINES (all absolute unless noted; WIRE_LIMITS owns the values)
 *   auth:        first frame must authenticate within authTimeoutMs (5s).
 *   frame:       a partial frame must complete within frameDeadlineMs (120s),
 *                reset only when a frame completes — kills byte-trickle
 *                slowloris that idle timers cannot catch.
 *   request:     mode='request' is bounded by requestDeadlineMs (70min,
 *                covers exec.run's 1h cap + margin).
 *   stream:      upload/download bounded by streamIdleTimeoutMs (300s no
 *                progress) AND streamDeadlineMs (4h absolute), plus
 *                maxStreamBytes (72GiB absolute ceiling) and per-op
 *                params.maxBytes (tighter per-request bound enforced upstream).
 *   session:     output-idle reaping is owned by the session manager; the
 *                connection itself is bounded by idleTimeoutMs when quiet.
 *   Upload AND export disk admission is GLOBAL via a shared
 *   DiskReservations ledger: staged payloads reserve their effective max
 *   against statfs free space minus ALL in-flight reservations (uploads and
 *   exports) minus a margin, so concurrent connections cannot each pass the
 *   same check and exhaust the backing filesystem.
 *
 * CONNECTION LIFECYCLE
 *   1. client → {type:'auth', token}; server → {type:'auth-ok'} or
 *      {type:'error', error:{code:'AUTHENTICATION_FAILED',...}} + close.
 *      Token compared constant-time. First frame MUST be auth.
 *   2. Requests are strictly sequential per connection: at most one `request`
 *      outstanding; the connection returns to idle on `response`.
 *   3. Long-lived flows occupy the connection until their terminal message:
 *      upload → final `response`; download → final `response`;
 *      exec session → `session-end`.
 *
 * CLIENT → SERVER control messages (all others are protocol errors):
 *   {type:'auth', token}
 *   {type:'request', request}   — `request` is the frozen contract envelope
 *                                 (workspace OR host; validated by schemas)
 *   {type:'stream-end', streamRef} — terminates an upload stream
 *   {type:'ping'}               — → {type:'pong'}
 *
 * SERVER → CLIENT control messages:
 *   {type:'auth-ok'}
 *   {type:'pong'}
 *   {type:'response', response} — VmSupervisorResponse envelope; terminal
 *                                 for the outstanding request (ok result OR
 *                                 error; error may carry unknown:true)
 *   {type:'stream-ready', streamRef}  — begin upload byte frames
 *   {type:'stream-start', streamRef, maxBytes} — download byte frames follow
 *   {type:'session-data', sessionId, fd, bytes:N} + N bytes of kind-0x01
 *   {type:'session-meta', sessionId, exitCode, signal, returnMetadata?}
 *   {type:'session-end', sessionId}
 *   {type:'error', requestId?, error:{code,message,retryable}, unknown?}
 *                                 — fatal/protocol error (not a request result)
 *
 * UPLOAD FLOW (file.push with streamRef; pushTree always streams)
 *   request → {stream-ready, streamRef} → client sends kind-0x01 frames →
 *   {stream-end, streamRef} → server verifies byte bound + sha256 vs params
 *   → {response}. EOF/disconnect before stream-end = UNKNOWN, never success.
 *   Payload is staged to a bounded temp file; streamed payloads are NEVER
 *   journaled.
 *
 * DOWNLOAD FLOW (vm.export, pullTree)
 *   request → {stream-start, streamRef, maxBytes} → kind-0x01 frames →
 *   {response, result: VmTarTrailer{sha256,bytes,entryCount}}.
 *   Server enforces maxBytes mid-stream; client abort cancels production.
 *
 * EXEC SESSION FLOW (exec.open)
 *   request exec.open → {response ok {sessionId, fdsReady:true}} →
 *   server pushes {session-data} frames on THIS connection →
 *   {session-meta} → {session-end}; connection then returns to idle.
 *   stdin/control are NOT sent on this connection: every write/close/resize/
 *   kill goes through the contract ops exec.write/exec.close/exec.resize/
 *   exec.killSession on any authenticated connection — each carries the full
 *   workspace identity envelope (workspaceId + generation + instanceId +
 *   idempotencyKey), so generation fencing applies to every call.
 */

export const VM_WIRE_VERSION = 1;
export const WIRE_KIND_JSON = 0x00;
export const WIRE_KIND_BYTES = 0x01;

export const WIRE_LIMITS = {
  maxFrameBytes: 8 * 1024 * 1024,
  maxControlBytes: 1024 * 1024,
  maxBufferedBytes: 32 * 1024 * 1024,
  /**
   * Absolute ceiling for any single streamed payload — 72 GiB covers the
   * largest legitimate workspace image (20 GiB guest disk + bounded tar
   * overhead) with wide headroom. Per-request ops apply a TIGHTER bound
   * (guest disk content + computed tar overhead) before stream-ready, and
   * uploads additionally reserve bytes via statfs admission — the ceiling
   * itself is never reserved or allocated.
   */
  maxStreamBytes: 72 * 1024 * 1024 * 1024,
  /** Free-space margin required beyond maxBytes before an upload is accepted. */
  streamDiskMarginBytes: 1024 * 1024 * 1024,
  maxConnections: 64,
  maxSessionDataMessageBytes: 1024 * 1024,
  /** First frame must be auth within this window (slowloris bound). */
  authTimeoutMs: 5_000,
  /**
   * Absolute deadline to COMPLETE one frame once its first byte arrives.
   * Reset only when a frame completes — a trickle of bytes that never
   * finishes a frame is killed, closing the one-byte-per-few-seconds
   * slowloris gap that idle timers alone cannot catch.
   */
  frameDeadlineMs: 120_000,
  /** Absolute deadline for a request to reach an outcome (covers exec.run's 1h cap + margin). */
  requestDeadlineMs: 4_200_000,
  /** Absolute cap on upload/download stream duration regardless of progress. */
  streamDeadlineMs: 14_400_000,
  /** No stream bytes/control for this long during upload/download → abort. */
  streamIdleTimeoutMs: 300_000,
  /** Session connections with no output for this long are reaped by server.ts. */
  idleTimeoutMs: 10 * 60 * 1000
} as const;

// ---------------------------------------------------------------------------
// Frame codec
// ---------------------------------------------------------------------------

export function encodeWireFrame(kind: number, payload: Buffer | string): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const header = Buffer.allocUnsafe(5);
  header.writeUInt32BE(data.length + 1, 0);
  header.writeUInt8(kind, 4);
  return Buffer.concat([header, data]);
}

export function encodeWireJson(message: unknown): Buffer {
  return encodeWireFrame(WIRE_KIND_JSON, JSON.stringify(message));
}

export interface WireFrame {
  kind: number;
  payload: Buffer;
}

/** Incremental frame decoder: feed socket chunks, get complete frames. */
export class WireFrameDecoder {
  private buffer: Buffer = Buffer.alloc(0);

  constructor(private readonly maxFrameBytes: number = WIRE_LIMITS.maxFrameBytes) {}

  push(chunk: Buffer): WireFrame[] {
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    const frames: WireFrame[] = [];
    for (;;) {
      if (this.buffer.length < 5) break;
      const len = this.buffer.readUInt32BE(0);
      if (len < 1 || len > this.maxFrameBytes + 1) {
        throw new Error('wire frame length out of bounds');
      }
      if (this.buffer.length < 4 + len) break;
      frames.push({ kind: this.buffer.readUInt8(4), payload: this.buffer.subarray(5, 4 + len) });
      this.buffer = this.buffer.subarray(4 + len);
    }
    return frames;
  }

  get bufferedBytes(): number {
    return this.buffer.length;
  }
}

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

export interface WireAuthMessage { type: 'auth'; token: string }
export interface WireRequestMessage { type: 'request'; request: unknown }
export interface WireStreamEndMessage { type: 'stream-end'; streamRef: string }
export interface WirePingMessage { type: 'ping' }

export type WireClientMessage =
  | WireAuthMessage
  | WireRequestMessage
  | WireStreamEndMessage
  | WirePingMessage;

export interface WireErrorBody { code: string; message: string; retryable: boolean }
export interface WireAuthOkMessage { type: 'auth-ok' }
export interface WirePongMessage { type: 'pong' }
export interface WireResponseMessage { type: 'response'; response: unknown }
export interface WireStreamReadyMessage { type: 'stream-ready'; streamRef: string }
export interface WireStreamStartMessage { type: 'stream-start'; streamRef: string; maxBytes: number }
export interface WireSessionDataHeader { type: 'session-data'; sessionId: string; fd: number; bytes: number }
export interface WireSessionMetaMessage {
  type: 'session-meta';
  sessionId: string;
  exitCode: number | null;
  signal: string | null;
  returnMetadata?: unknown;
}
export interface WireSessionEndMessage { type: 'session-end'; sessionId: string }
export interface WireErrorMessage {
  type: 'error';
  requestId?: string;
  error: WireErrorBody;
  unknown?: true;
}

export type WireServerMessage =
  | WireAuthOkMessage
  | WirePongMessage
  | WireResponseMessage
  | WireStreamReadyMessage
  | WireStreamStartMessage
  | WireSessionDataHeader
  | WireSessionMetaMessage
  | WireSessionEndMessage
  | WireErrorMessage;

// ---------------------------------------------------------------------------
// Handler surface implemented by server.ts
// ---------------------------------------------------------------------------

/** What an op handler returns to the transport. */
export type WireHandlerOutcome =
  | { kind: 'result'; result: unknown }
  | {
      kind: 'upload';
      /** Client-chosen stream token (file.push streamRef) or requestId (pushTree). */
      streamRef: string;
      maxBytes: number;
      /** Invoked with the staged payload once stream-end arrives. */
      complete: (payloadPath: string, payloadBytes: number, sha256: string) => Promise<unknown>;
    }
  | {
      kind: 'download';
      streamRef: string;
      maxBytes: number;
      /** Produce the byte stream; `emit` applies backpressure. Return = trailer result. */
      produce: (emit: (chunk: Buffer) => Promise<void>) => Promise<unknown>;
    }
  | {
      /** Long-lived exec session: transport marks the connection session-bound. */
      kind: 'session';
      sessionId: string;
      result: unknown;
    };

export interface WireSessionChannel {
  /**
   * Push output bytes for `sessionId`; transport chunks + bounds them.
   * Emissions are serialized per connection: each call's header+payload
   * slices are written atomically before the next queued emission runs, so
   * concurrent stdout/stderr/meta/end can never interleave frames. The
   * returned promise resolves when THIS call's bytes are on the socket —
   * callers use it for backpressure accounting.
   */
  emitData(sessionId: string, fd: number, data: Buffer): Promise<void>;
  emitMeta(sessionId: string, exitCode: number | null, signal: string | null, returnMetadata?: unknown): void;
  /** Sends session-meta+session-end and returns the connection to idle. */
  emitEnd(sessionId: string, exitCode: number | null, signal: string | null, returnMetadata?: unknown): void;
  /** Session-output bytes queued for emission on this connection (all sessions). */
  pendingOutputBytes(): number;
  readonly open: boolean;
}

export interface WireRequestContext {
  channel: WireSessionChannel;
  /** Aborted when the client disconnects mid-request. */
  signal: AbortSignal;
  /** Resolves when the client disconnects (session cleanup hook). */
  closed: Promise<void>;
}

export type WireRequestHandler = (
  request: unknown,
  ctx: WireRequestContext
) => Promise<WireHandlerOutcome>;

export interface WireServerDeps {
  socketPath: string;
  token: string;
  handler: WireRequestHandler;
  /** Directory for staged upload payloads (bounded, cleaned after use). */
  streamDir: string;
  /**
   * Shared host-disk reservation ledger — the SAME instance must back
   * offline-export staging in the request handler so concurrent uploads and
   * exports cannot jointly overcommit the backing filesystem.
   */
  diskReservations?: DiskReservations;
  logger?: (message: string, fields?: Record<string, unknown>) => void;
  /** Test hook: override individual limits (production uses defaults). */
  limits?: Partial<typeof WIRE_LIMITS>;
}

interface UploadState {
  streamRef: string;
  maxBytes: number;
  path: string;
  bytes: number;
  sha256: ReturnType<typeof createHash>;
  writer: WriteStream;
  outcome: Extract<WireHandlerOutcome, { kind: 'upload' }>;
  /** Releases the statfs-backed reservation; idempotent, called once. */
  releaseReservation: () => void;
}

interface ConnectionState {
  socket: Socket;
  decoder: WireFrameDecoder;
  authenticated: boolean;
  mode: 'idle' | 'request' | 'upload' | 'download' | 'session' | 'closing';
  pendingRequestId: string | undefined;
  upload: UploadState | undefined;
  downloadAbort: AbortController | undefined;
  sessionIds: Set<string>;
  bufferedBytes: number;
  lastActivity: number;
  /** FIFO queue serializing ALL session-channel emissions on this conn. */
  emitChain: Promise<void>;
  /** Session-output bytes accepted into emitChain but not yet written. */
  pendingEmitBytes: number;
  authTimer: NodeJS.Timeout | undefined;
  streamIdleTimer: NodeJS.Timeout | undefined;
  streamDeadlineTimer: NodeJS.Timeout | undefined;
  requestDeadlineTimer: NodeJS.Timeout | undefined;
  frameTimer: NodeJS.Timeout | undefined;
}

function sanitizeErrorCode(code: unknown): string {
  const parsed = ErrorCodeSchema.safeParse(code);
  return parsed.success ? parsed.data : 'INTERNAL_ERROR';
}

export class VmSupervisorWireServer {
  private readonly diskReservations: DiskReservations;
  private readonly server: Server;
  private readonly connections = new Set<ConnectionState>();
  private readonly limits: typeof WIRE_LIMITS;
  private closedFlag = false;

  constructor(private readonly deps: WireServerDeps) {
    this.limits = { ...WIRE_LIMITS, ...(deps.limits ?? {}) };
    this.diskReservations = deps.diskReservations ?? new DiskReservations(undefined, this.limits.streamDiskMarginBytes);
    this.server = createServer((socket) => this.accept(socket));
  }

  get connectionCount(): number {
    return this.connections.size;
  }

  listen(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server.once('error', reject);
      this.server.listen(this.deps.socketPath, () => resolve());
    });
  }

  async close(): Promise<void> {
    this.closedFlag = true;
    for (const conn of [...this.connections]) this.destroyConnection(conn);
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  private accept(socket: Socket): void {
    if (this.closedFlag || this.connections.size >= this.limits.maxConnections) {
      socket.destroy();
      return;
    }
    const conn: ConnectionState = {
      socket,
      decoder: new WireFrameDecoder(this.limits.maxFrameBytes),
      authenticated: false,
      mode: 'idle',
      pendingRequestId: undefined,
      upload: undefined,
      downloadAbort: undefined,
      sessionIds: new Set(),
      bufferedBytes: 0,
      lastActivity: Date.now(),
      emitChain: Promise.resolve(),
      pendingEmitBytes: 0,
      authTimer: undefined,
      streamIdleTimer: undefined,
      streamDeadlineTimer: undefined,
      requestDeadlineTimer: undefined,
      frameTimer: undefined
    };
    this.connections.add(conn);
    // Slowloris bound: the first frame must authenticate within authTimeoutMs.
    conn.authTimer = setTimeout(() => {
      if (!conn.authenticated) this.destroyConnection(conn);
    }, this.limits.authTimeoutMs);
    conn.authTimer.unref();
    socket.on('data', (chunk: Buffer) => {
      conn.lastActivity = Date.now();
      this.resetStreamIdleTimer(conn);
      try {
        this.onData(conn, chunk);
      } catch {
        this.destroyConnection(conn);
      }
    });
    socket.on('close', () => this.onClose(conn));
    socket.on('error', () => this.onClose(conn));
    socket.setNoDelay(true);
    const idle = setInterval(() => {
      if (Date.now() - conn.lastActivity > this.limits.idleTimeoutMs && (conn.mode === 'idle' || conn.mode === 'session')) {
        this.destroyConnection(conn);
      }
    }, 30_000);
    idle.unref();
    socket.on('close', () => clearInterval(idle));
  }

  private onClose(conn: ConnectionState): void {
    this.connections.delete(conn);
    if (conn.authTimer !== undefined) clearTimeout(conn.authTimer);
    this.clearStreamTimers(conn);
    this.clearRequestDeadline(conn);
    if (conn.frameTimer !== undefined) {
      clearTimeout(conn.frameTimer);
      conn.frameTimer = undefined;
    }
    if (conn.upload !== undefined) {
      conn.upload.writer.destroy();
      conn.upload.releaseReservation();
      void rm(conn.upload.path, { force: true }).catch(() => undefined);
      conn.upload = undefined;
    }
    conn.downloadAbort?.abort();
    conn.sessionIds.clear();
  }

  private destroyConnection(conn: ConnectionState): void {
    try {
      conn.socket.destroy();
    } catch {
      // already dead
    }
    this.onClose(conn);
  }

  // ---- inbound ---------------------------------------------------------------

  private onData(conn: ConnectionState, chunk: Buffer): void {
    conn.bufferedBytes += chunk.length;
    if (conn.bufferedBytes > this.limits.maxBufferedBytes) {
      this.destroyConnection(conn);
      return;
    }
    let frames: WireFrame[];
    try {
      frames = conn.decoder.push(chunk);
    } catch {
      this.destroyConnection(conn);
      return;
    }
    // Per-frame absolute deadline: armed while a partial frame is buffered,
    // reset ONLY when at least one frame completed — a byte trickle that
    // never finishes a frame cannot extend it.
    if (conn.decoder.bufferedBytes === 0) {
      if (conn.frameTimer !== undefined) {
        clearTimeout(conn.frameTimer);
        conn.frameTimer = undefined;
      }
    } else if (frames.length > 0 || conn.frameTimer === undefined) {
      if (conn.frameTimer !== undefined) clearTimeout(conn.frameTimer);
      conn.frameTimer = setTimeout(() => this.destroyConnection(conn), this.limits.frameDeadlineMs);
      conn.frameTimer.unref();
    }
    for (const frame of frames) {
      if (this.closedFlag || conn.mode === 'closing' || conn.socket.destroyed) return;
      if (frame.kind === WIRE_KIND_BYTES) {
        this.onBytes(conn, frame.payload);
      } else {
        this.onControl(conn, frame.payload);
      }
      if (conn.socket.destroyed) return;
    }
  }

  private onControl(conn: ConnectionState, payload: Buffer): void {
    if (payload.length > this.limits.maxControlBytes) {
      this.destroyConnection(conn);
      return;
    }
    let message: Record<string, unknown>;
    try {
      message = JSON.parse(payload.toString('utf8')) as Record<string, unknown>;
    } catch {
      this.destroyConnection(conn);
      return;
    }
    const type = message.type;
    if (!conn.authenticated) {
      if (type === 'auth' && typeof message.token === 'string' && constantTimeEqual(message.token, this.deps.token)) {
        conn.authenticated = true;
        if (conn.authTimer !== undefined) clearTimeout(conn.authTimer);
        this.sendJson(conn, { type: 'auth-ok' });
      } else {
        this.sendError(conn, { code: 'AUTHENTICATION_FAILED', message: 'authentication failed', retryable: false });
        this.destroyConnection(conn);
      }
      return;
    }
    switch (type) {
      case 'ping':
        this.sendJson(conn, { type: 'pong' });
        return;
      case 'request':
        void this.onRequest(conn, message.request);
        return;
      case 'stream-end':
        void this.onStreamEnd(conn, typeof message.streamRef === 'string' ? message.streamRef : '');
        return;
      default:
        this.sendError(conn, { code: 'INVALID_INPUT', message: `unknown message type: ${String(type)}`, retryable: false });
    }
  }

  private async onRequest(conn: ConnectionState, raw: unknown): Promise<void> {
    const requestId = typeof (raw as { requestId?: unknown })?.requestId === 'string'
      ? (raw as { requestId: string }).requestId
      : undefined;
    if (conn.mode !== 'idle') {
      this.sendErrorResponse(conn, requestId, Object.assign(new Error('connection busy'), { code: 'CONFLICT', retryable: true }), false);
      return;
    }
    conn.mode = 'request';
    conn.pendingRequestId = requestId;
    conn.requestDeadlineTimer = setTimeout(() => this.destroyConnection(conn), this.limits.requestDeadlineMs);
    conn.requestDeadlineTimer.unref();
    const abort = new AbortController();
    const closedPromise = new Promise<void>((resolve) => conn.socket.once('close', resolve));
    const channel = this.makeChannel(conn);
    const ctx: WireRequestContext = { channel, signal: abort.signal, closed: closedPromise };
    conn.socket.once('close', () => abort.abort());
    try {
      const outcome = await this.deps.handler(raw, ctx);
      if (conn.socket.destroyed) return;
      await this.completeOutcome(conn, outcome);
    } catch (error) {
      if (conn.socket.destroyed) return;
      const unknown = error instanceof Error && error.name === 'VmUnknownMutationError';
      this.sendErrorResponse(conn, requestId, error, unknown);
      conn.mode = 'idle';
      conn.pendingRequestId = undefined;
      this.clearRequestDeadline(conn);
    }
  }

  private clearRequestDeadline(conn: ConnectionState): void {
    if (conn.requestDeadlineTimer !== undefined) {
      clearTimeout(conn.requestDeadlineTimer);
      conn.requestDeadlineTimer = undefined;
    }
  }

  /**
   * Reset the stream-idle deadline when one is armed. Called on every
   * inbound byte AND on every outbound stream write — progress in EITHER
   * direction is activity; a one-directional flow must not look idle. A
   * no-op outside upload/download so plain request/session traffic never
   * arms a stream timer.
   */
  private resetStreamIdleTimer(conn: ConnectionState): void {
    if (conn.streamIdleTimer === undefined) return;
    clearTimeout(conn.streamIdleTimer);
    conn.streamIdleTimer = setTimeout(() => this.destroyConnection(conn), this.limits.streamIdleTimeoutMs);
    conn.streamIdleTimer.unref();
  }

  private clearStreamTimers(conn: ConnectionState): void {
    if (conn.streamIdleTimer !== undefined) {
      clearTimeout(conn.streamIdleTimer);
      conn.streamIdleTimer = undefined;
    }
    if (conn.streamDeadlineTimer !== undefined) {
      clearTimeout(conn.streamDeadlineTimer);
      conn.streamDeadlineTimer = undefined;
    }
  }

  private async completeOutcome(conn: ConnectionState, outcome: WireHandlerOutcome): Promise<void> {
    switch (outcome.kind) {
      case 'result':
        this.sendResponse(conn, outcome.result);
        conn.mode = 'idle';
        conn.pendingRequestId = undefined;
        this.clearRequestDeadline(conn);
        return;
      case 'session':
        this.sendResponse(conn, outcome.result);
        conn.mode = 'session';
        conn.sessionIds.add(outcome.sessionId);
        // pendingRequestId cleared: the session, not the request, owns the conn now.
        conn.pendingRequestId = undefined;
        this.clearRequestDeadline(conn);
        return;
      case 'upload': {
        // Disk admission BEFORE stream-ready via the shared reservation
        // ledger: staged payloads reserve their effective max against
        // statfs(streamDir) free space minus ALL in-flight reservations
        // (uploads AND exports) minus margin — refuse early, never mid-stream.
        const effectiveMax = Math.min(outcome.maxBytes, this.limits.maxStreamBytes);
        const path = join(this.deps.streamDir, `${randomUUID()}.bin`);
        let releaseReservation: () => void;
        try {
          await mkdir(this.deps.streamDir, { recursive: true });
          releaseReservation = await this.diskReservations.acquire(`upload:${path}`, this.deps.streamDir, effectiveMax);
        } catch (error) {
          const err = error instanceof Error ? error : new Error(String(error));
          const rawCode = (err as { code?: unknown }).code;
          const code = typeof rawCode === 'string' ? rawCode : 'VM_SUPERVISOR_UNAVAILABLE';
          this.sendErrorResponse(conn, conn.pendingRequestId, Object.assign(err, { code }), false);
          conn.mode = 'idle';
          conn.pendingRequestId = undefined;
          return;
        }
        conn.mode = 'upload';
        const writer = createWriteStream(path, { flags: 'wx' });
        conn.upload = {
          streamRef: outcome.streamRef,
          maxBytes: effectiveMax,
          path,
          bytes: 0,
          sha256: createHash('sha256'),
          writer,
          outcome,
          releaseReservation
        };
        writer.on('error', () => this.destroyConnection(conn));
        conn.streamIdleTimer = setTimeout(() => this.destroyConnection(conn), this.limits.streamIdleTimeoutMs);
        conn.streamIdleTimer.unref();
        conn.streamDeadlineTimer = setTimeout(() => this.destroyConnection(conn), this.limits.streamDeadlineMs);
        conn.streamDeadlineTimer.unref();
        this.clearRequestDeadline(conn);
        this.sendJson(conn, { type: 'stream-ready', streamRef: outcome.streamRef });
        return;
      }
      case 'download': {
        conn.mode = 'download';
        const abort = new AbortController();
        conn.downloadAbort = abort;
        conn.streamIdleTimer = setTimeout(() => {
          abort.abort();
          this.destroyConnection(conn);
        }, this.limits.streamIdleTimeoutMs);
        conn.streamIdleTimer.unref();
        conn.streamDeadlineTimer = setTimeout(() => {
          abort.abort();
          this.destroyConnection(conn);
        }, this.limits.streamDeadlineMs);
        conn.streamDeadlineTimer.unref();
        this.clearRequestDeadline(conn);
        this.sendJson(conn, { type: 'stream-start', streamRef: outcome.streamRef, maxBytes: outcome.maxBytes });
        try {
          const result = await outcome.produce(async (chunk) => {
            if (abort.signal.aborted || conn.socket.destroyed) throw new Error('download aborted');
            if (!conn.socket.write(encodeWireFrame(WIRE_KIND_BYTES, chunk))) {
              await new Promise<void>((resolve) => conn.socket.once('drain', resolve));
            }
            // Outbound progress is activity: a download sends no inbound
            // frames, so without this the idle timer kills long pulls.
            conn.lastActivity = Date.now();
            this.resetStreamIdleTimer(conn);
          });
          if (!conn.socket.destroyed) this.sendResponse(conn, result);
        } catch (error) {
          if (!conn.socket.destroyed) this.sendErrorResponse(conn, conn.pendingRequestId, error, false);
        } finally {
          conn.downloadAbort = undefined;
          this.clearStreamTimers(conn);
          conn.mode = 'idle';
          conn.pendingRequestId = undefined;
        }
        return;
      }
    }
  }

  private onBytes(conn: ConnectionState, payload: Buffer): void {
    const upload = conn.upload;
    if (conn.mode !== 'upload' || upload === undefined) {
      this.destroyConnection(conn);
      return;
    }
    upload.bytes += payload.length;
    if (upload.bytes > upload.maxBytes || upload.bytes > this.limits.maxStreamBytes) {
      this.destroyConnection(conn);
      return;
    }
    upload.sha256.update(payload);
    if (!upload.writer.write(payload)) {
      conn.socket.pause();
      upload.writer.once('drain', () => {
        if (!conn.socket.destroyed) conn.socket.resume();
      });
    }
  }

  private async onStreamEnd(conn: ConnectionState, streamRef: string): Promise<void> {
    const upload = conn.upload;
    if (conn.mode !== 'upload' || upload === undefined || upload.streamRef !== streamRef) {
      this.sendError(conn, { code: 'INVALID_INPUT', message: 'no matching upload stream', retryable: false });
      return;
    }
    const releaseReservation = upload.releaseReservation;
    conn.upload = undefined;
    this.clearStreamTimers(conn);
    const writerEnd = new Promise<void>((resolve, reject) => {
      upload.writer.once('finish', resolve);
      upload.writer.once('error', reject);
      upload.writer.end();
    });
    try {
      await writerEnd;
    } catch {
      releaseReservation();
      await rm(upload.path, { force: true }).catch(() => undefined);
      conn.mode = 'idle';
      conn.pendingRequestId = undefined;
      this.destroyConnection(conn);
      return;
    }
    conn.mode = 'request';
    try {
      const result = await upload.outcome.complete(upload.path, upload.bytes, upload.sha256.digest('hex'));
      await rm(upload.path, { force: true }).catch(() => undefined);
      if (!conn.socket.destroyed) this.sendResponse(conn, result);
    } catch (error) {
      await rm(upload.path, { force: true }).catch(() => undefined);
      if (!conn.socket.destroyed) this.sendErrorResponse(conn, conn.pendingRequestId, error, false);
    } finally {
      releaseReservation();
      conn.mode = 'idle';
      conn.pendingRequestId = undefined;
    }
  }

  // ---- outbound ---------------------------------------------------------------

  private sendJson(conn: ConnectionState, message: Record<string, unknown>): void {
    if (conn.socket.destroyed) return;
    conn.socket.write(encodeWireJson(message));
  }

  private sendResponse(conn: ConnectionState, result: unknown): void {
    this.sendJson(conn, {
      type: 'response',
      response: { version: 1, requestId: conn.pendingRequestId ?? '', ok: true, result }
    });
  }

  private sendError(conn: ConnectionState, error: WireErrorBody): void {
    this.sendJson(conn, { type: 'error', error });
  }

  private sendErrorResponse(conn: ConnectionState, requestId: string | undefined, error: unknown, unknownFlag: boolean): void {
    const err = error instanceof Error ? error : new Error(String(error));
    const rawCode = (err as { code?: unknown }).code;
    this.sendJson(conn, {
      type: 'response',
      response: {
        version: 1,
        requestId: requestId ?? '',
        ok: false,
        error: {
          code: sanitizeErrorCode(rawCode),
          message: err.message.slice(0, 2000),
          retryable: (err as { retryable?: unknown }).retryable === true
        },
        ...(unknownFlag ? { unknown: true as const } : {})
      }
    });
  }

  /**
   * Queue `fn` behind all prior session emissions on this connection. The
   * chain never wedges: a dead socket makes later steps no-op via alive(),
   * and step errors are swallowed (the socket 'close' path owns cleanup).
   */
  private enqueueEmit(conn: ConnectionState, fn: () => void | Promise<void>): Promise<void> {
    const run = conn.emitChain.then(async () => {
      try {
        await fn();
      } catch {
        // dead socket mid-queue — subsequent steps no-op via alive()
      }
    });
    conn.emitChain = run;
    return run;
  }

  /** Channel factory handed to request handlers; sessionId is bound per call. */
  private makeChannel(conn: ConnectionState): WireSessionChannel {
    const alive = (): boolean => !conn.socket.destroyed && conn.authenticated;
    return {
      get open() {
        return alive();
      },
      pendingOutputBytes: () => conn.pendingEmitBytes,
      emitData: (sessionId: string, fd: number, data: Buffer): Promise<void> => {
        conn.pendingEmitBytes += data.length;
        return this.enqueueEmit(conn, async () => {
          try {
            for (let offset = 0; offset < data.length; offset += this.limits.maxSessionDataMessageBytes) {
              if (!alive()) return;
              const slice = data.subarray(offset, offset + this.limits.maxSessionDataMessageBytes);
              // Outbound session bytes are activity for BOTH idle bounds:
              // the 10-minute connection idle timer counts output, not just
              // inbound frames, so an actively-streaming session is never
              // reaped as "quiet".
              conn.lastActivity = Date.now();
              this.sendJson(conn, { type: 'session-data', sessionId, fd, bytes: slice.length });
              if (!conn.socket.write(encodeWireFrame(WIRE_KIND_BYTES, slice))) {
                await new Promise<void>((resolve) => conn.socket.once('drain', resolve));
              }
            }
          } finally {
            conn.pendingEmitBytes -= data.length;
          }
        });
      },
      emitMeta: (sessionId: string, exitCode: number | null, signal: string | null, returnMetadata?: unknown): void => {
        void this.enqueueEmit(conn, () => {
          if (!alive()) return;
          conn.lastActivity = Date.now();
          this.sendJson(conn, { type: 'session-meta', sessionId, exitCode, signal, returnMetadata });
        });
      },
      emitEnd: (sessionId: string, exitCode: number | null, signal: string | null, returnMetadata?: unknown): void => {
        void this.enqueueEmit(conn, () => {
          if (!alive()) return;
          conn.lastActivity = Date.now();
          this.sendJson(conn, { type: 'session-meta', sessionId, exitCode, signal, returnMetadata });
          this.sendJson(conn, { type: 'session-end', sessionId });
          conn.sessionIds.delete(sessionId);
          if (conn.sessionIds.size === 0 && conn.mode === 'session') {
            conn.mode = 'idle';
          }
        });
      }
    };
  }
}
