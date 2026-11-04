import { Sandbox } from '@insforge/instabox-sdk';
import { HarnessError } from '@cloud-harness/contracts';
import { createReadStream, createWriteStream } from 'node:fs';
import { readFile, stat, rename, unlink } from 'node:fs/promises';
import { resolve, posix } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { StringDecoder } from 'node:string_decoder';
import type { RemoteExecutionBackend, RemoteExecutorRef, ExecutionOptions, ExecutionResult, RemoteJobSpec, RemoteJobObservation, RemoteMachineState } from './execution-backend.js';
import { InstaBoxPty } from './instabox-pty.js';

const API = 'https://api.instabox.sh';
const FILE_LIMIT = 5 * 1024 ** 3;
export const shellQuote = (value: string): string => `'${value.replaceAll("'", "'\\''")}'`;
type BackendOptions = { apiKey: string; allowedMachineIds: readonly string[]; principalId: string; validateRef: (ref: RemoteExecutorRef) => void };
/** Never expose provider messages, request URLs or credentials in errors. */
export class InstaBoxProviderError extends HarnessError {
  constructor(readonly providerCode: string, readonly retryAfterMs?: number) {
    super('UNAVAILABLE', `InstaBox request failed (${providerCode})`, 503, false);
  }
}
function bound(value: number, limit = Number.MAX_SAFE_INTEGER): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > limit) throw new HarnessError('INVALID_INPUT', 'Invalid byte limit');
}
function codeOf(error: unknown): string {
  const code = (error as { code?: unknown })?.code;
  return typeof code === 'string' && /^[a-z_]{1,64}$/.test(code) ? code : 'transport_error';
}
function limiter(maxBytes: number, hash?: ReturnType<typeof createHash>): Transform {
  let bytes = 0;
  return new Transform({ transform(chunk: Buffer, _encoding, callback) {
    bytes += chunk.length;
    if (bytes > maxBytes) return callback(new HarnessError('INVALID_INPUT', 'File exceeds byte limit'));
    hash?.update(chunk); callback(null, chunk);
  } });
}
async function bodyBytes(response: Response, maxBytes: number): Promise<Buffer> {
  if (!response.body) return Buffer.alloc(0);
  const chunks: Buffer[] = []; let bytes = 0;
  const reader = response.body.getReader();
  try { for (;;) { const next = await reader.read(); if (next.done) break; bytes += next.value.length; if (bytes > maxBytes) throw new InstaBoxProviderError('response_too_large'); chunks.push(Buffer.from(next.value)); } }
  finally { await reader.cancel().catch(() => {}); }
  return Buffer.concat(chunks, bytes);
}
export class InstaBoxBackend implements RemoteExecutionBackend {
  private readonly starts: number[] = [];
  private cooldownUntil = 0;
  constructor(private readonly options: BackendOptions) {}
  validate(ref: RemoteExecutorRef): void {
    if (ref.provider !== 'instabox' || ref.ownerId !== this.options.principalId || !this.options.allowedMachineIds.includes(ref.machineId) || !Number.isSafeInteger(ref.generation) || ref.generation < 1 || !ref.root.startsWith('/data/home/.cloud-harness/') || posix.normalize(ref.root) !== ref.root) {
      throw new HarnessError('FORBIDDEN', 'Remote allocation is not authorized', 403);
    }
    this.options.validateRef(ref);
  }
  private path(ref: RemoteExecutorRef, path: string): string {
    this.validate(ref);
    if (!path.startsWith(ref.root + '/') || posix.normalize(path) !== path || path.includes('\0')) throw new HarnessError('FORBIDDEN', 'Path is outside remote allocation', 403);
    return path;
  }
  private async request(ref: RemoteExecutorRef, route: string, init: RequestInit = {}): Promise<Response> {
    this.validate(ref);
    // These provider routes can implicitly wake an idle-suspended machine. Lifecycle owns wakes.
    if (route.startsWith('/files') || (route.startsWith('/activity-leases/') && init.method === 'PUT')) {
      if (!(await this.inspect(ref)).ready) throw new InstaBoxProviderError('machine_not_ready');
      this.validate(ref);
    }
    try {
      const response = await fetch(`${API}/v1/machines/${encodeURIComponent(ref.machineId)}${route}`, {
        ...init, redirect: 'error', signal: init.signal ?? AbortSignal.timeout(120_000),
        headers: { ...init.headers, Authorization: `Bearer ${this.options.apiKey}` }
      });
      if (!response.ok) {
        let code = `http_${response.status}`;
        try { const data = JSON.parse((await bodyBytes(response, 16_384)).toString()) as { error?: { code?: string } }; if (data.error?.code && /^[a-z_]{1,64}$/.test(data.error.code)) code = data.error.code; } catch { /* retain HTTP status */ }
        const retry = Number(response.headers.get('retry-after'));
        const retryAfterMs = Number.isFinite(retry) && retry > 0 ? Math.min(retry * 1000, 86400000) : undefined;
        if (response.status === 429) this.cooldownUntil = Date.now() + (retryAfterMs ?? 60_000);
        throw new InstaBoxProviderError(code, retryAfterMs);
      }
      return response;
    } catch (error) { if (error instanceof HarnessError) throw error; throw new InstaBoxProviderError(codeOf(error)); }
  }
  async run(ref: RemoteExecutorRef, command: string, options: ExecutionOptions): Promise<ExecutionResult> {
    this.validate(ref); bound(options.maxBytes, 64 * 1024 * 1024);
    if (options.timeoutMs <= 0 || options.timeoutMs > 600_000) throw new HarnessError('INVALID_INPUT', 'Remote foreground timeout must be 1–600000 ms');
    const signal = AbortSignal.any([AbortSignal.timeout(options.timeoutMs + 10_000), ...(options.signal ? [options.signal] : [])]);
    const response = await this.request(ref, '/exec', { method: 'POST', signal, headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream' }, body: JSON.stringify({ cmd: command, noHistory: true, cwd: options.cwd ?? `${ref.root}/repo`, envs: options.env ?? {}, stdin: options.stdin ?? '', timeoutSeconds: Math.ceil(options.timeoutMs / 1000) }) });
    const stdout: Buffer[] = [], stderr: Buffer[] = [];
    let used = 0, truncated = false, exitCode: number | undefined;
    const append = (kind: string, data: string) => {
      const bytes = Buffer.from(data); const take = bytes.subarray(0, Math.max(0, options.maxBytes - used));
      used += take.length; if (take.length < bytes.length) truncated = true;
      if (take.length) (kind === 'stdout' ? stdout : stderr).push(take);
    };
    // Omit an incomplete UTF-8 tail at the byte boundary; U+FFFD would expand past the budget.
    const output = () => ({ stdout: new StringDecoder('utf8').write(Buffer.concat(stdout)), stderr: new StringDecoder('utf8').write(Buffer.concat(stderr)) });
    if (!response.headers.get('content-type')?.includes('text/event-stream')) {
      const result = JSON.parse((await bodyBytes(response, 8 * 1024 * 1024)).toString()) as ExecutionResult;
      append('stdout', result.stdout); append('stderr', result.stderr);
      return { ...output(), exitCode: result.exitCode, truncated: truncated || result.truncated === true };
    }
    if (!response.body) throw new InstaBoxProviderError('missing_stream');
    const reader = response.body.getReader(); const decoder = new TextDecoder(); let pending = '';
    try {
      for (;;) {
        const next = await reader.read(); if (next.done) break;
        pending += decoder.decode(next.value, { stream: true });
        if (pending.length > 2 * 1024 * 1024) throw new InstaBoxProviderError('event_too_large');
        let end: number;
        while ((end = pending.indexOf('\n\n')) >= 0) {
          const frame = pending.slice(0, end); pending = pending.slice(end + 2);
          const event = frame.match(/^event: ?(.*)$/m)?.[1]; const data = frame.match(/^data: ?(.*)$/m)?.[1];
          if (!data) continue;
          const value = JSON.parse(data) as { data?: string; exitCode?: number };
          if (event === 'stdout' || event === 'stderr') append(event, value.data ?? '');
          if (event === 'exit') exitCode = value.exitCode;
          if (event === 'error') throw new InstaBoxProviderError('execution_unknown');
        }
      }
    } catch (error) { if (error instanceof HarnessError) throw error; throw new InstaBoxProviderError('execution_unknown'); }
    finally { await reader.cancel().catch(() => {}); }
    if (!Number.isInteger(exitCode)) throw new InstaBoxProviderError('execution_unknown');
    return { ...output(), exitCode: exitCode!, truncated };
  }
  private async sandbox(ref: RemoteExecutorRef): Promise<Sandbox> {
    this.validate(ref);
    try { return await Sandbox.connect(ref.machineId, { apiKey: this.options.apiKey, apiUrl: API, resume: false, requestTimeoutMs: 30_000, operationTimeoutMs: 180_000 }); }
    catch (error) { throw new InstaBoxProviderError(codeOf(error)); }
  }
  async inspect(ref: RemoteExecutorRef): Promise<RemoteMachineState> {
    this.validate(ref);
    const info = await (await this.sandbox(ref)).getInfo().catch(error => { throw new InstaBoxProviderError(codeOf(error)); });
    const providerCooldown = (info.machine as typeof info.machine & { cooldownUntil?: string }).cooldownUntil;
    const deadline = providerCooldown ? Date.parse(providerCooldown) : 0;
    if (Number.isFinite(deadline)) this.cooldownUntil = Math.max(this.cooldownUntil, deadline);
    return { state: info.state, ready: info.state === 'running' && info.machine.runtime.ready === true, ...(this.cooldownUntil > Date.now() ? { cooldownUntil: new Date(this.cooldownUntil).toISOString(), retryAfterMs: this.cooldownUntil - Date.now() } : {}) };
  }
  private reserveStart(): void {
    const now = Date.now(); while (this.starts[0] !== undefined && this.starts[0] <= now - 60_000) this.starts.shift();
    const retry = Math.max(this.cooldownUntil - now, this.starts.length >= 3 ? this.starts[0]! + 60_000 - now : 0);
    if (retry > 0) throw new InstaBoxProviderError('rate_limited', retry);
    this.starts.push(now);
  }
  async start(ref: RemoteExecutorRef): Promise<void> {
    this.validate(ref); const box = await this.sandbox(ref);
    try { const info = await box.getInfo(); if (info.state === 'running' && info.machine.runtime.ready) return;
      const deadline = Date.parse((info.machine as typeof info.machine & { cooldownUntil?: string }).cooldownUntil ?? '');
      if (Number.isFinite(deadline)) this.cooldownUntil = Math.max(this.cooldownUntil, deadline);
      this.reserveStart(); this.validate(ref); await box.resume(); const state = await this.inspect(ref); if (!state.ready) throw new InstaBoxProviderError('machine_not_ready'); }
    catch (error) { if (error instanceof InstaBoxProviderError) throw error; const code = codeOf(error); if (code === 'rate_limited') this.cooldownUntil = Date.now() + 60_000; throw new InstaBoxProviderError(code); }
  }
  async stop(ref: RemoteExecutorRef): Promise<void> {
    this.validate(ref); const box = await this.sandbox(ref);
    try { const info = await box.getInfo(); if (info.state === 'stopped') return; if (info.state === 'suspended') this.reserveStart(); this.validate(ref); await box.stop(); if ((await this.inspect(ref)).state !== 'stopped') throw new InstaBoxProviderError('stop_unconfirmed'); }
    catch (error) { if (error instanceof InstaBoxProviderError) throw error; throw new InstaBoxProviderError(codeOf(error)); }
  }
  async bootstrap(ref: RemoteExecutorRef, files: ReadonlyArray<{ path: string; content: string; mode?: number }>): Promise<void> {
    this.validate(ref);
    const containment = await this.run(ref, `python3 -c ${shellQuote("import ctypes,sys; lib=ctypes.CDLL(None,use_errno=True); set_result=lib.prctl(36,1,0,0,0); value=ctypes.c_int(); get_result=lib.prctl(37,ctypes.byref(value),0,0,0); sys.exit(0 if set_result==0 and get_result==0 and value.value==1 else 125)")}`, { cwd: '/data/home', timeoutMs: 10000, maxBytes: 4096 });
    if (containment.exitCode !== 0) throw new InstaBoxProviderError('kernel_subreaper_unavailable');
    const script = `const f=require('fs'),p=require('path');const root=${JSON.stringify(ref.root)},receipt=${JSON.stringify(JSON.stringify(ref))};f.mkdirSync(p.dirname(root),{recursive:true});try{f.mkdirSync(root);f.writeFileSync(root+'/.ch-allocation.json',receipt,{flag:'wx',mode:384});}catch(e){if(e.code!=='EEXIST'||f.readFileSync(root+'/.ch-allocation.json','utf8')!==receipt)throw Error('allocation marker conflict');}f.mkdirSync(root+'/runtime',{recursive:true});`;
    const result = await this.run(ref, `node -e ${shellQuote(script)}`, { cwd: '/data/home', timeoutMs: 30_000, maxBytes: 4096 });
    if (result.exitCode !== 0) throw new InstaBoxProviderError('allocation_marker_conflict');
    await this.writeFile(ref, `${ref.root}/runtime/remote-executor.mjs`, await readFile(resolve('worker/remote-executor.mjs')));
    for (const file of files) {
      const path = file.path.startsWith('/') ? file.path : `${ref.root}/${file.path}`;
      this.path(ref, path); await this.writeFile(ref, path, Buffer.from(file.content));
      if (file.mode !== undefined) { if (!Number.isInteger(file.mode) || file.mode < 0 || file.mode > 0o777) throw new HarnessError('INVALID_INPUT', 'Invalid file mode'); const r = await this.run(ref, `chmod ${file.mode.toString(8)} -- ${shellQuote(path)}`, { cwd: ref.root, timeoutMs: 10_000, maxBytes: 4096 }); if (r.exitCode) throw new InstaBoxProviderError('bootstrap_chmod_failed'); }
    }
  }
  async uploadFile(ref: RemoteExecutorRef, localPath: string, guestPath: string, maxBytes: number): Promise<void> {
    this.path(ref, guestPath); bound(maxBytes); const size = (await stat(localPath)).size;
    const transferLimit = Math.min(maxBytes, FILE_LIMIT);
    if (size > transferLimit) throw new HarnessError('LIMIT_EXCEEDED', 'File exceeds configured or InstaBox 5 GiB upload limit');
    const hash = createHash('sha256'); const input = createReadStream(localPath); const stream = input.pipe(limiter(transferLimit, hash));
    input.on('error', error => stream.destroy(error));
    try {
      const response = await this.request(ref, `/files?parents=true&mode=0600&path=${encodeURIComponent(guestPath)}`, { method: 'PUT', headers: { 'Content-Type': 'application/octet-stream' }, body: stream as unknown as BodyInit, duplex: 'half' } as RequestInit);
      const receipt = JSON.parse((await bodyBytes(response, 16384)).toString()) as { size?: number; sha256?: string };
      if (receipt.size !== size || receipt.sha256 !== hash.digest('hex')) throw new InstaBoxProviderError('transfer_mismatch');
    } finally { input.destroy(); stream.destroy(); }
  }
  async downloadFile(ref: RemoteExecutorRef, guestPath: string, localPath: string, maxBytes: number): Promise<void> {
    this.path(ref, guestPath); bound(maxBytes);
    const response = await this.request(ref, `/files/content?path=${encodeURIComponent(guestPath)}`);
    const temp = `${localPath}.${randomUUID()}.partial`;
    try { if (!response.body) throw new InstaBoxProviderError('missing_body'); await pipeline(Readable.fromWeb(response.body as never), limiter(maxBytes), createWriteStream(temp, { flags: 'wx', mode: 0o600 })); await rename(temp, localPath); }
    finally { await unlink(temp).catch(() => {}); }
  }
  async readFile(ref: RemoteExecutorRef, guestPath: string, maxBytes: number): Promise<Buffer> {
    this.path(ref, guestPath); bound(maxBytes, 64 * 1024 * 1024);
    return bodyBytes(await this.request(ref, `/files/content?path=${encodeURIComponent(guestPath)}`), maxBytes);
  }
  async writeFile(ref: RemoteExecutorRef, guestPath: string, content: Buffer): Promise<void> {
    this.path(ref, guestPath); bound(content.length, 64 * 1024 * 1024);
    const response = await this.request(ref, `/files?parents=true&mode=0600&path=${encodeURIComponent(guestPath)}`, { method: 'PUT', headers: { 'Content-Type': 'application/octet-stream' }, body: new Uint8Array(content) });
    const receipt = JSON.parse((await bodyBytes(response, 16384)).toString()) as { size?: number; sha256?: string };
    if (receipt.size !== content.length || receipt.sha256 !== createHash('sha256').update(content).digest('hex')) throw new InstaBoxProviderError('transfer_mismatch');
  }
  private async job(ref: RemoteExecutorRef, action: string, args: object): Promise<Record<string, unknown>> {
    this.validate(ref);
    const data = JSON.stringify(args);
    // Exec commands are capped at 64 KiB. Carry payloads on stdin, never in shell arguments.
    const large = Buffer.byteLength(data) > 1048576;
    const inputPath = `${ref.root}/runtime/input-${randomUUID()}.json`;
    if (large) await this.writeFile(ref, inputPath, Buffer.from(data));
    const command = `node ${shellQuote(`${ref.root}/runtime/remote-executor.mjs`)} ${shellQuote(ref.root)} ${shellQuote(action)} -${large ? ` < ${shellQuote(inputPath)}; code=$?; rm -f -- ${shellQuote(inputPath)}; exit "$code"` : ''}`;
    const result = await this.run(ref, command, { cwd: ref.root, timeoutMs: 15_000, maxBytes: 2 * 1024 * 1024, ...(large ? {} : { stdin: data }) });
    if (result.exitCode !== 0 || result.truncated) throw new InstaBoxProviderError('job_operation_unconfirmed');
    return JSON.parse(result.stdout) as Record<string, unknown>;
  }
  async startJob(ref: RemoteExecutorRef, spec: RemoteJobSpec): Promise<void> {
    this.validate(ref);
    const relative = spec.cwd === '/workspace' ? '.' : spec.cwd.startsWith('/workspace/') ? spec.cwd.slice(11) : spec.cwd;
    const cwd = relative.startsWith('/') ? relative : posix.resolve(ref.root, 'repo', relative);
    this.path(ref, cwd); bound(spec.maxBytes, 64 * 1024 * 1024);
    if (!Number.isSafeInteger(spec.timeoutMs) || spec.timeoutMs <= 0 || spec.timeoutMs > 2147483647) throw new HarnessError('INVALID_INPUT', 'Invalid remote job timeout');
    await this.job(ref, 'start', { ...spec, cwd });
  }
  async readJob(ref: RemoteExecutorRef, jobId: string, offset: number, maxBytes: number): Promise<RemoteJobObservation> {
    this.validate(ref); bound(maxBytes, 1048576); bound(offset);
    const result = await this.job(ref, 'read', { id: jobId, offset, maxBytes });
    return { ...result, output: Buffer.from(String(result.output), 'base64') } as RemoteJobObservation;
  }
  async writeJob(ref: RemoteExecutorRef, jobId: string, input: string): Promise<void> { this.validate(ref); bound(Buffer.byteLength(input), 1048576); await this.job(ref, 'write', { id: jobId, input }); }
  async cancelJob(ref: RemoteExecutorRef, jobId: string): Promise<void> { this.validate(ref); await this.job(ref, 'cancel', { id: jobId }); }
  pty(ref: RemoteExecutorRef): InstaBoxPty { this.validate(ref); return new InstaBoxPty(ref, this.options.apiKey, this); }
  async activity(ref: RemoteExecutorRef, taskId: string, active: boolean): Promise<void> {
    this.validate(ref);
    const id = 'ch-' + createHash('sha256').update(`${ref.workspaceId}:${ref.generation}:${taskId}`).digest('hex').slice(0, 48);
    await this.request(ref, `/activity-leases/${id}`, { method: active ? 'PUT' : 'DELETE', ...(active ? { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ttlSeconds: 300 }) } : {}) });
  }
}
