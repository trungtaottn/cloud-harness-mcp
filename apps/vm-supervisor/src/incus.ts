import { request as httpRequest, type IncomingMessage } from 'node:http';

/**
 * Bounded Incus REST client over the unix socket. Plain HTTP/1.1 via
 * node:http `socketPath`; no TLS (socket perms are the trust boundary).
 * Every response body is size-capped; mutating calls return Incus operation
 * URLs which callers wait on with an explicit deadline so stop latency is
 * measured, never assumed.
 *
 * Live-API details (recursion level, operation polling cadence, exec fd
 * layout) are verified at the phase-11 live gate; all wire assumptions are
 * isolated in this module and `incus-exec.ts`.
 */

export class IncusError extends Error {
  readonly statusCode: number;
  readonly incusStatus: number | undefined;
  constructor(message: string, statusCode: number, incusStatus?: number) {
    super(message);
    this.name = 'IncusError';
    this.statusCode = statusCode;
    this.incusStatus = incusStatus;
  }
}

export interface IncusClientDeps {
  socketPath: string;
  project: string;
  /** Per-request HTTP deadline. Default 30s. */
  requestTimeoutMs?: number;
  /** Response body cap. Default 32 MiB. */
  maxResponseBytes?: number;
  /** Operation wait poll cadence. Default 250ms. */
  operationPollMs?: number;
}

export interface IncusInstanceInfo {
  name: string;
  status: string;
  statusCode: number;
  createdAt?: string | undefined;
  expandedConfig: Record<string, string>;
  expandedDevices: Record<string, Record<string, string>>;
  profiles: string[];
  /** Managed-marker presence is derived by callers from expandedConfig. */
}

export interface IncusExecSessionRequest {
  command: string[];
  cwd?: string;
  environment?: Record<string, string>;
  /**
   * PTY/interactive exec. Maps to the native Incus `interactive` request
   * field (there is no `pty` field); width/height size the terminal.
   */
  pty?: { cols: number; rows: number };
}

export interface IncusExecFdSet {
  /**
   * Full WebSocket paths (path+query) keyed by Incus fd name. Non-interactive
   * exec provides "0"/"1"/"2" (stdin/stdout/stderr); interactive exec provides
   * a single bidirectional "0" PTY. "control" carries window-resize/signal
   * commands. Values are `{operation}/websocket?secret=…` endpoints.
   */
  channels: Record<string, string>;
  /** Incus operation path (`/1.0/operations/<id>`) polled for exit status. */
  operation: string;
}

interface IncusHttpResponse {
  status: number;
  body: Buffer;
}

export class IncusClient {
  private readonly socketPath: string;
  private readonly project: string;
  private readonly requestTimeoutMs: number;
  private readonly maxResponseBytes: number;
  private readonly operationPollMs: number;

  constructor(deps: IncusClientDeps) {
    this.socketPath = deps.socketPath;
    this.project = deps.project;
    this.requestTimeoutMs = deps.requestTimeoutMs ?? 30_000;
    this.maxResponseBytes = deps.maxResponseBytes ?? 33_554_432;
    this.operationPollMs = deps.operationPollMs ?? 250;
  }

  // ---- raw HTTP ------------------------------------------------------------

  private http(opts: {
    method: string;
    path: string;
    body?: Buffer | string | undefined;
    headers?: Record<string, string> | undefined;
    timeoutMs?: number | undefined;
  }): Promise<IncusHttpResponse> {
    return new Promise((resolve, reject) => {
      const body = opts.body === undefined
        ? undefined
        : Buffer.isBuffer(opts.body) ? opts.body : Buffer.from(opts.body, 'utf8');
      const req = httpRequest({
        socketPath: this.socketPath,
        path: opts.path,
        method: opts.method,
        headers: {
          Host: 'localhost',
          ...(body !== undefined ? { 'Content-Length': body.length, 'Content-Type': 'application/octet-stream' } : {}),
          ...(opts.headers ?? {})
        },
        timeout: opts.timeoutMs ?? this.requestTimeoutMs
      }, (res: IncomingMessage) => {
        const chunks: Buffer[] = [];
        let total = 0;
        res.on('data', (chunk: Buffer) => {
          total += chunk.length;
          if (total > this.maxResponseBytes) {
            req.destroy(new Error('incus response exceeded byte bound'));
            return;
          }
          chunks.push(chunk);
        });
        res.on('end', () => {
          resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks) });
        });
        res.on('error', reject);
      });
      req.on('timeout', () => req.destroy(new Error('incus request timed out')));
      req.on('error', reject);
      if (body !== undefined) req.write(body);
      req.end();
    });
  }

  /**
   * JSON request against the Incus REST envelope. Every /1.0 response is
   * `{type, status, status_code, metadata, operation?, error?, error_code?}`;
   * this unwraps `metadata` into `data` for resource callers while surfacing
   * the top-level `type`/`operation`/`error` fields mutating callers need.
   * Operation state lives in `metadata.status` — `waitOperation` reads `data`.
   */
  async api<T = unknown>(method: string, path: string, body?: unknown, timeoutMs?: number): Promise<{
    status: number;
    data: T | undefined;
    type?: string | undefined;
    operation?: string | undefined;
    error?: string | undefined;
    errorCode?: number | undefined;
    raw: Buffer;
  }> {
    const encoded = body === undefined ? undefined : JSON.stringify(body);
    const res = await this.http({
      method,
      path,
      body: encoded,
      headers: encoded !== undefined ? { 'Content-Type': 'application/json' } : undefined,
      timeoutMs
    });
    let envelope: {
      type?: unknown; status?: unknown; metadata?: unknown;
      operation?: unknown; error?: unknown; error_code?: unknown;
    } | undefined;
    if (res.body.length > 0) {
      try {
        const parsed = JSON.parse(res.body.toString('utf8')) as unknown;
        if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
          envelope = parsed as NonNullable<typeof envelope>;
        }
      } catch {
        envelope = undefined;
      }
    }
    const enveloped = envelope !== undefined &&
      ('metadata' in envelope || 'type' in envelope || 'status' in envelope || 'operation' in envelope);
    // Every /1.0 endpoint answers with an envelope carrying `metadata`.
    // A 2xx WITHOUT one — non-envelope body, or an envelope missing
    // `metadata` — is malformed/truncated and must never be accepted as an
    // empty or absent success (a lost create/start/stop ack, or a 200 that
    // silently reads as "instance absent", would both be invisible).
    // Absence is signalled ONLY by 404, which flows back to callers.
    if (res.status >= 200 && res.status < 300 &&
        (envelope === undefined || !enveloped || !('metadata' in envelope))) {
      throw new IncusError('incus returned a malformed success response (missing envelope metadata)', res.status);
    }
    return {
      status: res.status,
      // Envelope responses carry the resource in `metadata`; anything else is
      // returned verbatim so non-enveloped endpoints keep working.
      data: (envelope !== undefined && enveloped ? envelope.metadata : envelope) as T | undefined,
      type: typeof envelope?.type === 'string' ? envelope.type : undefined,
      operation: typeof envelope?.operation === 'string' ? envelope.operation : undefined,
      error: typeof envelope?.error === 'string' && envelope.error !== '' ? envelope.error : undefined,
      errorCode: typeof envelope?.error_code === 'number' ? envelope.error_code : undefined,
      raw: res.body
    };
  }

  private projectQuery(extra = ''): string {
    const sep = extra === '' ? '?' : '&';
    return `?project=${encodeURIComponent(this.project)}${sep === '?' ? '' : sep}${extra}`;
  }

  // ---- server / project ------------------------------------------------------

  async getApiExtensions(): Promise<string[]> {
    const { status, data } = await this.api<{ api_extensions?: string[] }>('GET', '/1.0');
    if (status !== 200 || data === undefined) throw new IncusError('incus API unreachable', status);
    return data.api_extensions ?? [];
  }

  async projectExists(name: string): Promise<boolean> {
    const { status } = await this.api('GET', `/1.0/projects/${encodeURIComponent(name)}`);
    if (status === 200) return true;
    if (status === 404) return false;
    throw new IncusError(`incus project lookup failed with HTTP ${status}`, status);
  }

  // ---- instances -------------------------------------------------------------

  private parseInstance(raw: Record<string, unknown>): IncusInstanceInfo {
    const expandedConfig = (raw.expanded_config ?? {}) as Record<string, string>;
    const expandedDevices = (raw.expanded_devices ?? {}) as Record<string, Record<string, string>>;
    const profiles = Array.isArray(raw.profiles) ? (raw.profiles as string[]) : [];
    return {
      name: String(raw.name ?? ''),
      status: String(raw.status ?? 'Unknown'),
      statusCode: Number(raw.status_code ?? 0),
      createdAt: typeof raw.created_at === 'string' ? raw.created_at : undefined,
      expandedConfig,
      expandedDevices,
      profiles
    };
  }

  async listInstances(): Promise<IncusInstanceInfo[]> {
    const { status, data } = await this.api<unknown[]>('GET', `/1.0/instances${this.projectQuery('recursion=2')}`);
    if (status !== 200 || !Array.isArray(data)) {
      throw new IncusError(`incus instance list failed with HTTP ${status}`, status);
    }
    return data.slice(0, 1_024).map((entry) => this.parseInstance(entry as Record<string, unknown>));
  }

  async getInstance(name: string): Promise<IncusInstanceInfo | null> {
    const { status, data } = await this.api<Record<string, unknown> | undefined>(
      'GET',
      `/1.0/instances/${encodeURIComponent(name)}${this.projectQuery('recursion=2')}`
    );
    if (status === 404) return null;
    if (status !== 200 || data === undefined) {
      throw new IncusError(`incus instance get failed with HTTP ${status}`, status);
    }
    return this.parseInstance(data);
  }

  async getInstanceState(name: string): Promise<{ status: string; statusCode: number } | null> {
    const { status, data } = await this.api<{ status?: string; status_code?: number } | undefined>(
      'GET',
      `/1.0/instances/${encodeURIComponent(name)}/state${this.projectQuery()}`
    );
    if (status === 404) return null;
    if (status !== 200 || data === undefined) {
      throw new IncusError(`incus instance state failed with HTTP ${status}`, status);
    }
    return { status: String(data.status ?? 'Unknown'), statusCode: Number(data.status_code ?? 0) };
  }

  /**
   * Create a stopped VM instance from a fingerprint-pinned image. Returns the
   * Incus operation path when async; callers wait with a deadline.
   */
  async createInstance(spec: {
    name: string;
    /** Incus image fingerprint; mutually exclusive with imageAlias. */
    imageFingerprint?: string;
    /** Incus image alias (e.g. the published supervisor template alias). */
    imageAlias?: string;
    type?: 'virtual-machine';
    config: Record<string, string>;
    devices: Record<string, Record<string, string>>;
    profiles?: string[];
  }): Promise<{ operation?: string; synchronous: boolean }> {
    if ((spec.imageFingerprint === undefined) === (spec.imageAlias === undefined)) {
      throw new Error('createInstance requires exactly one of imageFingerprint or imageAlias');
    }
    const body = {
      name: spec.name,
      type: spec.type ?? 'virtual-machine',
      source: spec.imageFingerprint !== undefined
        ? { type: 'image', fingerprint: spec.imageFingerprint }
        : { type: 'image', alias: spec.imageAlias },
      config: spec.config,
      devices: spec.devices,
      profiles: spec.profiles ?? []
    };
    const { status, type, operation, error } = await this.api<Record<string, unknown>>(
      'POST',
      `/1.0/instances${this.projectQuery()}`,
      body
    );
    // 202 Accepted = async operation in flight; 200/201 = synchronous apply.
    if (status !== 200 && status !== 201 && status !== 202) {
      throw new IncusError(
        `incus instance create failed: ${error ?? `HTTP ${status}`}`,
        status
      );
    }
    // A 202/async response MUST carry an operation handle — treating it as a
    // synchronous success would silently lose the mutation acknowledgement.
    if (status === 202 || type === 'async') {
      if (operation === undefined) {
        throw new IncusError('incus instance create accepted asynchronously without an operation handle', 500);
      }
      return { operation, synchronous: false };
    }
    return { synchronous: true };
  }

  /** Start/stop/restart/freeze via the instance state endpoint. */
  async setInstanceState(
    name: string,
    action: 'start' | 'stop' | 'restart' | 'freeze' | 'unfreeze',
    opts: { force?: boolean; timeoutSeconds?: number; stateful?: boolean } = {}
  ): Promise<{ operation?: string; synchronous: boolean }> {
    const body: Record<string, unknown> = { action };
    if (opts.force !== undefined) body.force = opts.force;
    if (opts.timeoutSeconds !== undefined) body.timeout = opts.timeoutSeconds;
    if (opts.stateful !== undefined) body.stateful = opts.stateful;
    const { status, type, operation, error } = await this.api<{ error?: string }>(
      'PUT',
      `/1.0/instances/${encodeURIComponent(name)}/state${this.projectQuery()}`,
      body
    );
    if (status !== 200 && status !== 202) {
      throw new IncusError(`incus ${action} failed: ${error ?? `HTTP ${status}`}`, status);
    }
    if (status === 202 || type === 'async') {
      if (operation === undefined) {
        throw new IncusError(`incus ${action} accepted asynchronously without an operation handle`, 500);
      }
      return { operation, synchronous: false };
    }
    return { synchronous: true };
  }

  async deleteInstance(name: string): Promise<{ operation?: string; synchronous: boolean }> {
    const { status, type, operation, error } = await this.api<{ error?: string }>(
      'DELETE',
      `/1.0/instances/${encodeURIComponent(name)}${this.projectQuery()}`
    );
    if (status === 404) return { synchronous: true };
    if (status !== 200 && status !== 202) {
      throw new IncusError(`incus delete failed: ${error ?? `HTTP ${status}`}`, status);
    }
    if (status === 202 || type === 'async') {
      if (operation === undefined) {
        throw new IncusError('incus instance delete accepted asynchronously without an operation handle', 500);
      }
      return { operation, synchronous: false };
    }
    return { synchronous: true };
  }

  // ---- operations -------------------------------------------------------------

  /**
   * Wait for an Incus operation to reach a terminal state before `deadlineMs`
   * (epoch ms). Returns elapsed milliseconds so callers can MEASURE stop
   * latency. Throws on deadline expiry or operation failure.
   */
  async waitOperation(operationPath: string, deadlineMs: number): Promise<{ elapsedMs: number; status: string }> {
    const started = Date.now();
    const path = operationPath.startsWith('/1.0/') ? operationPath : `/1.0${operationPath}`;
    for (;;) {
      const { status, data } = await this.api<{ status?: string; status_code?: number; err?: string }>('GET', path);
      if (status === 200 && data !== undefined) {
        const opStatus = String(data.status ?? '');
        if (opStatus === 'Success') {
          return { elapsedMs: Date.now() - started, status: opStatus };
        }
        if (opStatus === 'Failure' || opStatus === 'Cancelled') {
          throw new IncusError(`incus operation failed: ${data.err ?? opStatus}`, 500);
        }
      } else if (status === 404) {
        // Operation record can disappear right after success on some builds;
        // treat as still-pending only briefly, then fail closed.
        if (Date.now() - started > 5_000) {
          throw new IncusError('incus operation record vanished', 500);
        }
      } else {
        throw new IncusError(`incus operation poll failed with HTTP ${status}`, status);
      }
      if (Date.now() >= deadlineMs) {
        throw new IncusError('incus operation wait exceeded deadline', 408);
      }
      await new Promise((resolve) => setTimeout(resolve, this.operationPollMs));
    }
  }

  /**
   * Poll an exec operation until it reaches a terminal state and return the
   * process exit status from `metadata.return`. This is the ONLY reliable
   * exit channel for native Incus exec: websocket fd streams carry process
   * I/O but never an exit frame, so sessions must poll the operation.
   * `signal` lets callers stop polling when the session is torn down.
   */
  async waitExecExit(
    operationPath: string,
    opts: { deadlineMs?: number; pollMs?: number; signal?: AbortSignal } = {}
  ): Promise<{ exitCode: number | null; signal: string | null; error?: string }> {
    const path = operationPath.startsWith('/1.0/') ? operationPath : `/1.0${operationPath}`;
    const started = Date.now();
    const deadlineMs = opts.deadlineMs ?? Number.POSITIVE_INFINITY;
    const pollMs = opts.pollMs ?? this.operationPollMs;
    // Transient poll failures (5xx or transport errors) get a bounded retry:
    // a single Incus hiccup must not kill a healthy exec session. The bound
    // is consecutive-failure count AND the caller's deadline/signal — never
    // an unbounded retry loop.
    const maxTransient = 3;
    let transient = 0;
    const pastDeadline = (): boolean => Date.now() >= deadlineMs;
    for (;;) {
      if (opts.signal?.aborted === true) {
        throw new IncusError('incus exec exit wait aborted', 499);
      }
      if (pastDeadline()) {
        throw new IncusError('incus exec exit wait exceeded deadline', 408);
      }
      let status: number;
      let data: { status?: string; err?: string; metadata?: { return?: unknown } } | undefined;
      try {
        ({ status, data } = await this.api<{
          status?: string;
          err?: string;
          metadata?: { return?: unknown };
        }>('GET', path));
      } catch (error) {
        // Transport-level failure (socket reset, timeout): retry bounded.
        if (transient < maxTransient) {
          transient += 1;
          await new Promise((resolve) => setTimeout(resolve, pollMs));
          continue;
        }
        throw error;
      }
      if (status === 200 && data !== undefined) {
        transient = 0;
        const opStatus = String(data.status ?? '');
        if (opStatus === 'Success' || opStatus === 'Failure' || opStatus === 'Cancelled') {
          const ret = data.metadata?.return;
          if (opStatus !== 'Success') {
            return { exitCode: null, signal: null, error: data.err ?? opStatus };
          }
          return { exitCode: typeof ret === 'number' ? ret : null, signal: null };
        }
      } else if (status === 404) {
        transient = 0; // server answered — transport is healthy again
        if (Date.now() - started > 5_000) {
          throw new IncusError('incus exec operation record vanished', 500);
        }
      } else if (status >= 500 && transient < maxTransient) {
        transient += 1;
        await new Promise((resolve) => setTimeout(resolve, pollMs));
        continue;
      } else {
        throw new IncusError(`incus exec operation poll failed with HTTP ${status}`, status);
      }
      await new Promise((resolve) => setTimeout(resolve, pollMs));
    }
  }

  /** Resolve the Incus storage pool NAME whose source path matches poolPath. */
  async findPoolNameBySourcePath(poolPath: string): Promise<string | undefined> {
    const { status, data } = await this.api<Array<{ name?: string; source?: string }>>('GET', '/1.0/storage-pools?recursion=1');
    if (status !== 200 || !Array.isArray(data)) return undefined;
    const matches = data.filter((p) => p.source === poolPath && typeof p.name === 'string');
    return matches.length === 1 ? matches[0]!.name : undefined;
  }

  // ---- instance files (REST) ----------------------------------------------------

  /**
   * Read a guest file. Returns bytes for regular files; for directories the
   * Incus API returns a JSON listing which callers parse via listPath.
   */
  async readInstanceFile(name: string, guestPath: string, maxBytes: number): Promise<Buffer> {
    const { status, body: raw } = await this.http({
      method: 'GET',
      path: `/1.0/instances/${encodeURIComponent(name)}/files${this.projectQuery(`path=${encodeURIComponent(guestPath)}`)}`,
      timeoutMs: this.requestTimeoutMs
    });
    if (status === 404) throw new IncusError(`guest path not found: ${guestPath}`, 404);
    if (status !== 200) throw new IncusError(`incus file read failed with HTTP ${status}`, status);
    if (raw.length > maxBytes) throw new IncusError('guest file exceeds maxBytes', 413);
    return raw;
  }

  async writeInstanceFile(
    name: string,
    guestPath: string,
    data: Buffer,
    opts: { mode?: number; uid?: number; gid?: number; createDirs?: boolean; timeoutMs?: number } = {}
  ): Promise<void> {
    const params = [`path=${encodeURIComponent(guestPath)}`];
    if (opts.mode !== undefined) params.push(`mode=${opts.mode.toString(8)}`);
    if (opts.uid !== undefined) params.push(`uid=${opts.uid}`);
    if (opts.gid !== undefined) params.push(`gid=${opts.gid}`);
    if (opts.createDirs) params.push('create_dirs=true');
    // Binary body: the files endpoint requires application/octet-stream with
    // raw bytes — routing a Buffer through api() would JSON-encode it.
    const res = await this.http({
      method: 'POST',
      path: `/1.0/instances/${encodeURIComponent(name)}/files${this.projectQuery(params.join('&'))}`,
      body: data,
      headers: { 'Content-Type': 'application/octet-stream' },
      timeoutMs: opts.timeoutMs
    });
    if (res.status !== 200 && res.status !== 201 && res.status !== 202) {
      let errText: string | undefined;
      try {
        const parsed = JSON.parse(res.body.toString('utf8')) as { error?: unknown };
        if (typeof parsed.error === 'string') errText = parsed.error;
      } catch { /* non-JSON error body */ }
      throw new IncusError(`incus file write failed: ${errText ?? `HTTP ${res.status}`}`, res.status);
    }
  }

  async deleteInstanceFile(name: string, guestPath: string, recursive = false): Promise<void> {
    const { status, error } = await this.api<{ error?: string }>(
      'DELETE',
      `/1.0/instances/${encodeURIComponent(name)}/files${this.projectQuery(`path=${encodeURIComponent(guestPath)}${recursive ? '&recursive=true' : ''}`)}`
    );
    if (status === 404) return;
    if (status !== 200) {
      throw new IncusError(`incus file delete failed: ${error ?? `HTTP ${status}`}`, status);
    }
  }

  /**
   * Stream a local file into a guest path without buffering it whole.
   * Content-Length is set from stat; the body is piped.
   */
  async writeInstanceFileStream(
    name: string,
    guestPath: string,
    body: NodeJS.ReadableStream,
    contentLength: number,
    opts: { mode?: number; uid?: number; gid?: number } = {}
  ): Promise<void> {
    const params = [`path=${encodeURIComponent(guestPath)}`];
    if (opts.mode !== undefined) params.push(`mode=${opts.mode.toString(8)}`);
    if (opts.uid !== undefined) params.push(`uid=${opts.uid}`);
    if (opts.gid !== undefined) params.push(`gid=${opts.gid}`);
    const { status, data } = await new Promise<{ status: number; data: { error?: string } | undefined }>((resolve, reject) => {
      const req = httpRequest({
        socketPath: this.socketPath,
        path: `/1.0/instances/${encodeURIComponent(name)}/files${this.projectQuery(params.join('&'))}`,
        method: 'POST',
        headers: {
          Host: 'localhost',
          'Content-Type': 'application/octet-stream',
          'Content-Length': contentLength
        },
        timeout: this.requestTimeoutMs
      }, (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          let parsed: { error?: string } | undefined;
          try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { parsed = undefined; }
          resolve({ status: res.statusCode ?? 0, data: parsed });
        });
      });
      req.on('timeout', () => req.destroy(new Error('incus file stream write timed out')));
      req.on('error', reject);
      body.pipe(req);
    });
    if (status !== 200 && status !== 201 && status !== 202) {
      throw new IncusError(`incus file stream write failed: ${data?.error ?? `HTTP ${status}`}`, status);
    }
  }

  /**
   * Directory listing via the files API. Native Incus answers a directory
   * read with a bare JSON array of filename strings (no stat objects).
   * Entries are validated as single path components; anything else fails
   * closed.
   */
  async listInstancePath(name: string, guestPath: string): Promise<string[]> {
    const { status, body: raw } = await this.http({
      method: 'GET',
      path: `/1.0/instances/${encodeURIComponent(name)}/files${this.projectQuery(`path=${encodeURIComponent(guestPath)}`)}`,
      timeoutMs: this.requestTimeoutMs
    });
    if (status === 404) throw new IncusError(`guest path not found: ${guestPath}`, 404);
    if (status !== 200) throw new IncusError(`incus file list failed with HTTP ${status}`, status);
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw.toString('utf8'));
    } catch {
      throw new IncusError('incus directory listing was not JSON', 500);
    }
    // Native Incus answers a directory read with a bare JSON array of
    // filename strings (no envelope, no stat objects). Tolerate an enveloped
    // `metadata` array defensively; anything else fails closed.
    const list = Array.isArray(parsed)
      ? parsed
      : (parsed !== null && typeof parsed === 'object' && Array.isArray((parsed as { metadata?: unknown }).metadata)
          ? (parsed as { metadata: unknown[] }).metadata
          : undefined);
    if (list === undefined) {
      throw new IncusError('incus directory listing was not a filename array', 500);
    }
    if (list.length > 10_000) {
      throw new IncusError('incus directory listing exceeds entry bound', 413);
    }
    const names: string[] = [];
    for (const entry of list) {
      if (typeof entry !== 'string' || entry === '' || entry.length > 255 ||
          entry.includes('/') || entry.includes('\0') || entry === '.' || entry === '..') {
        throw new IncusError('incus directory listing contained a malformed entry', 500);
      }
      names.push(entry);
    }
    return names;
  }

  /** File metadata via the files API `?path=` on a file returns bytes only;
   *  stat is implemented guest-side by callers via exec `stat` when needed. */

  // ---- exec ---------------------------------------------------------------------

  /**
   * Open an exec channel set. POSTs the exec request with
   * `wait-for-websocket` semantics. Native Incus ALWAYS answers 202 with an
   * async operation whose `metadata.metadata.fds` is a secret MAP keyed by
   * fd number ("0","1","2") plus "control" — never an array of ready paths.
   * Each secret is exchanged for a `{operation}/websocket?secret=…` endpoint
   * the caller dials. `record-output` is never requested.
   */
  async openExecFds(instanceName: string, spec: IncusExecSessionRequest): Promise<IncusExecFdSet> {
    const body: Record<string, unknown> = {
      command: spec.command,
      'wait-for-websocket': true
    };
    if (spec.cwd !== undefined) body.cwd = spec.cwd;
    if (spec.environment !== undefined) body.environment = spec.environment;
    if (spec.pty !== undefined) {
      // Native field is `interactive` (allocates a PTY on fd 0); there is no
      // `pty` request field. width/height size the terminal.
      body.interactive = true;
      body.width = spec.pty.cols;
      body.height = spec.pty.rows;
    }
    const { status, data, type, operation, error } = await this.api<Record<string, unknown>>(
      'POST', `/1.0/instances/${encodeURIComponent(instanceName)}/exec${this.projectQuery()}`, body);
    if (status !== 200 && status !== 201 && status !== 202) {
      throw new IncusError(`incus exec open failed: ${error ?? `HTTP ${status}`}`, status);
    }
    // 202/async without an operation handle can never be tracked or exited —
    // fail closed rather than treat it as synchronously ready.
    if ((status === 202 || type === 'async') && operation === undefined) {
      throw new IncusError('incus exec accepted asynchronously without an operation handle', 500);
    }
    // data = envelope.metadata = the operation resource. Its custom
    // `metadata` field carries `fds`: { "0": secret, "1": secret, "2": secret,
    // "control": secret }. Secrets are single-use connect tokens.
    const opMeta = (data?.metadata ?? {}) as Record<string, unknown>;
    const rawFds = opMeta.fds;
    if (rawFds === null || typeof rawFds !== 'object' || Array.isArray(rawFds)) {
      throw new IncusError('incus exec operation metadata carried no fd secret map', 500);
    }
    const secrets = rawFds as Record<string, unknown>;
    const opRaw = operation ?? '';
    const opPath = opRaw.startsWith('/1.0/') ? opRaw : `/1.0${opRaw}`;
    if (opPath === '/1.0' || opPath === '/1.0/') {
      throw new IncusError('incus exec operation handle was empty', 500);
    }
    const channels: Record<string, string> = {};
    for (const [fd, secret] of Object.entries(secrets)) {
      if (typeof secret !== 'string' || secret === '') continue;
      // Only fd numbers and the literal "control" key are meaningful; drop
      // anything else defensively rather than minting bogus endpoints.
      if (fd !== 'control' && !/^[0-9]+$/.test(fd)) continue;
      channels[fd] = `${opPath}/websocket?secret=${encodeURIComponent(secret)}&project=${encodeURIComponent(this.project)}`;
    }
    if (Object.keys(channels).length === 0) {
      throw new IncusError('incus exec operation metadata carried no usable fd secrets', 500);
    }
    return { channels, operation: opPath };
  }
}
