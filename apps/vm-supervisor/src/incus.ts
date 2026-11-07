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
  /** Incus user spec: 'harness' (workspace) or 'root'. */
  user?: string;
  group?: string;
  pty?: { cols: number; rows: number };
}

export interface IncusExecFdSet {
  /** WebSocket paths (path+query) for stdin/stdout/stderr (or single PTY fd). */
  fds: string[];
  /** Control channel path when present (signals, window-change, exit meta). */
  control?: string | undefined;
  /** Operation URL when the exec was accepted asynchronously. */
  operation?: string | undefined;
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

  /** JSON request; returns parsed body. Throws IncusError on transport/HTTP errors. */
  async api<T = unknown>(method: string, path: string, body?: unknown, timeoutMs?: number): Promise<{ status: number; data: T | undefined; raw: Buffer }> {
    const encoded = body === undefined ? undefined : JSON.stringify(body);
    const res = await this.http({
      method,
      path,
      body: encoded,
      headers: encoded !== undefined ? { 'Content-Type': 'application/json' } : undefined,
      timeoutMs
    });
    let data: T | undefined;
    if (res.body.length > 0) {
      try {
        data = JSON.parse(res.body.toString('utf8')) as T;
      } catch {
        data = undefined;
      }
    }
    return { status: res.status, data, raw: res.body };
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
    const { status, data } = await this.api<{ type?: string; operation?: string; status_code?: number }>(
      'POST',
      `/1.0/instances${this.projectQuery()}`,
      body
    );
    if (status !== 200 && status !== 201) {
      const err = (data as { error?: string; error_code?: number } | undefined);
      throw new IncusError(
        `incus instance create failed: ${err?.error ?? `HTTP ${status}`}`,
        status,
        typeof err?.error_code === 'number' ? err.error_code : undefined
      );
    }
    if (data?.type === 'async' && typeof data.operation === 'string') {
      return { operation: data.operation, synchronous: false };
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
    const { status, data } = await this.api<{ type?: string; operation?: string; error?: string }>(
      'PUT',
      `/1.0/instances/${encodeURIComponent(name)}/state${this.projectQuery()}`,
      body
    );
    if (status !== 200 && status !== 202) {
      throw new IncusError(`incus ${action} failed: ${data?.error ?? `HTTP ${status}`}`, status);
    }
    if (data?.type === 'async' && typeof data.operation === 'string') {
      return { operation: data.operation, synchronous: false };
    }
    return { synchronous: true };
  }

  async deleteInstance(name: string): Promise<{ operation?: string; synchronous: boolean }> {
    const { status, data } = await this.api<{ type?: string; operation?: string; error?: string }>(
      'DELETE',
      `/1.0/instances/${encodeURIComponent(name)}${this.projectQuery()}`
    );
    if (status === 404) return { synchronous: true };
    if (status !== 200) {
      throw new IncusError(`incus delete failed: ${data?.error ?? `HTTP ${status}`}`, status);
    }
    if (data?.type === 'async' && typeof data.operation === 'string') {
      return { operation: data.operation, synchronous: false };
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
    opts: { mode?: number; uid?: number; gid?: number; createDirs?: boolean } = {}
  ): Promise<void> {
    const params = [`path=${encodeURIComponent(guestPath)}`];
    if (opts.mode !== undefined) params.push(`mode=${opts.mode.toString(8)}`);
    if (opts.uid !== undefined) params.push(`uid=${opts.uid}`);
    if (opts.gid !== undefined) params.push(`gid=${opts.gid}`);
    if (opts.createDirs) params.push('create_dirs=true');
    const { status, data: resp } = await this.api<{ error?: string }>(
      'POST',
      `/1.0/instances/${encodeURIComponent(name)}/files${this.projectQuery(params.join('&'))}`,
      data
    );
    if (status !== 200 && status !== 201 && status !== 202) {
      throw new IncusError(`incus file write failed: ${resp?.error ?? `HTTP ${status}`}`, status);
    }
  }

  async deleteInstanceFile(name: string, guestPath: string, recursive = false): Promise<void> {
    const { status, data } = await this.api<{ error?: string }>(
      'DELETE',
      `/1.0/instances/${encodeURIComponent(name)}/files${this.projectQuery(`path=${encodeURIComponent(guestPath)}${recursive ? '&recursive=true' : ''}`)}`
    );
    if (status === 404) return;
    if (status !== 200) {
      throw new IncusError(`incus file delete failed: ${data?.error ?? `HTTP ${status}`}`, status);
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

  /** Directory listing via the files API (returns parsed JSON entries). */
  async listInstancePath(name: string, guestPath: string): Promise<Array<Record<string, unknown>>> {
    const { status, body: raw } = await this.http({
      method: 'GET',
      path: `/1.0/instances/${encodeURIComponent(name)}/files${this.projectQuery(`path=${encodeURIComponent(guestPath)}`)}`,
      timeoutMs: this.requestTimeoutMs
    });
    if (status === 404) throw new IncusError(`guest path not found: ${guestPath}`, 404);
    if (status !== 200) throw new IncusError(`incus file list failed with HTTP ${status}`, status);
    try {
      const parsed = JSON.parse(raw.toString('utf8')) as unknown;
      return Array.isArray(parsed) ? (parsed as Array<Record<string, unknown>>) : [];
    } catch {
      throw new IncusError('incus directory listing was not JSON', 500);
    }
  }

  /** File metadata via the files API `?path=` on a file returns bytes only;
   *  stat is implemented guest-side by callers via exec `stat` when needed. */

  // ---- exec ---------------------------------------------------------------------

  /**
   * Open an interactive exec channel set. POSTs the exec request with
   * `wait-for-websocket` semantics and returns the WebSocket fd paths the
   * caller connects to. `record-output` is never requested (unsupported on
   * VM exec); stdout/stderr are only available over the fd websockets.
   */
  async openExecFds(instanceName: string, spec: IncusExecSessionRequest): Promise<IncusExecFdSet> {
    const body: Record<string, unknown> = {
      command: spec.command,
      'wait-for-websocket': true
    };
    if (spec.cwd !== undefined) body.cwd = spec.cwd;
    if (spec.environment !== undefined) body.environment = spec.environment;
    if (spec.user !== undefined) body.user = spec.user;
    if (spec.group !== undefined) body.group = spec.group;
    if (spec.pty !== undefined) {
      body.pty = true;
      body.width = spec.pty.cols;
      body.height = spec.pty.rows;
    }
    const { status, data } = await this.api<{
      type?: string;
      operation?: string;
      metadata?: { fds?: unknown; control?: unknown };
      error?: string;
    }>('POST', `/1.0/instances/${encodeURIComponent(instanceName)}/exec${this.projectQuery()}`, body);
    if (status !== 200 && status !== 201) {
      throw new IncusError(`incus exec open failed: ${data?.error ?? `HTTP ${status}`}`, status);
    }
    const metadata = data?.metadata;
    const rawFds = metadata?.fds;
    const fds = Array.isArray(rawFds) ? rawFds.filter((f): f is string => typeof f === 'string') : [];
    if (fds.length === 0) {
      // Async-accepted exec without websocket fds: only an operation handle.
      if (typeof data?.operation === 'string') {
        return { fds: [], operation: data.operation };
      }
      throw new IncusError('incus exec returned no websocket fds', 500);
    }
    const control = typeof metadata?.control === 'string' ? metadata.control : undefined;
    return { fds, control, operation: typeof data?.operation === 'string' ? data.operation : undefined };
  }
}
