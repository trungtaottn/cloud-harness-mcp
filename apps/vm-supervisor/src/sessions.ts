import type { VmJournal } from './journal.js';
import type { IncusClient } from './incus.js';
import { IncusExecSession, type ExecExitInfo } from './incus-exec.js';
import type { WireSessionChannel } from './transport.js';
import { VmOpError, VmUnknownMutationError, type VmLifecycle } from './lifecycle.js';

/**
 * Exec session manager: one-shot `exec.run` bounded capture and persistent
 * `exec.open` sessions proxied over the wire channel.
 *
 * Cancellation ladder (frozen): control-close (Incus control-close SIGKILLs
 * the session leader) → bounded wait for exit metadata → guest-side
 * `kill -- -<pgid>` via pid file (exec.killSession) → ws teardown. Any
 * unverifiable outcome is recorded UNKNOWN — never reported as cleaned.
 * Disconnect of the session's connection triggers the same ladder; sessions
 * are never silently orphaned.
 */

const EXEC_RUN_KILL_GRACE_MS = 5_000;
const SESSION_CLOSE_VERIFY_MS = 10_000;
const REAPER_INTERVAL_MS = 30_000;
const SESSION_CLOSING_TIMEOUT_MS = 60_000;

/** Absolute path — the exec environment's PATH is caller-controlled. */
const GUEST_RUNUSER = '/usr/sbin/runuser';

/**
 * Workspace execs run `runuser -p -u <guestUser> -- …` AS ROOT: Incus exec
 * uid/gid mapping does NOT initialize supplementary groups, so a plain
 * uid/gid exec cannot reach group-owned guest resources (e.g. the `docker`
 * group for the guest socket). `runuser`'s credential setup applies
 * initgroups; `-p` preserves the exact environment map supplied via the
 * exec `environment` field (nothing secret ever enters argv). The child
 * stays in the wrapper's process group and session — pgid-based
 * `exec.killSession` semantics are unchanged — and `user: 'root'` execs
 * bypass the wrap entirely.
 */
/** Wire backpressure: pause guest output reads while >16MiB is queued, resume <4MiB. */
const SESSION_OUTPUT_HIGH_WATER_BYTES = 16 * 1024 * 1024;
const SESSION_OUTPUT_LOW_WATER_BYTES = 4 * 1024 * 1024;
let linkScanSeq = 0;

function wrapWorkspaceArgv(argv: readonly string[], guestUser: string): string[] {
  return [GUEST_RUNUSER, '-p', '-u', guestUser, '--', ...argv];
}

export interface VmSessionDeps {
  journal: VmJournal;
  incus: IncusClient;
  incusSocketPath: string;
  lifecycle: VmLifecycle;
  /** Guest user for 'workspace' exec mapping (template contract: harness uid 10001). */
  guestUser?: string;
  guestGroup?: string;
  now?: () => number;
}

interface LiveSession {
  sessionId: string;
  workspaceId: string;
  vmName: string;
  channel: WireSessionChannel;
  incus: IncusExecSession;
  lastActivityMs: number;
  closing: boolean;
  /** Guest output channels paused for wire backpressure. */
  outputPaused?: boolean;
  exitInfo?: ExecExitInfo;
}

export interface ExecRunOutcome {
  opId: string;
  exitCode: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  timedOut: boolean;
}

export class VmSessionManager {
  private readonly sessions = new Map<string, LiveSession>();
  private reaperTimer: NodeJS.Timeout | undefined;
  private readonly nowFn: () => number;

  constructor(private readonly deps: VmSessionDeps) {
    this.nowFn = deps.now ?? (() => Date.now());
  }

  get guestUser(): string {
    return this.deps.guestUser ?? 'harness';
  }

  get guestGroup(): string {
    return this.deps.guestGroup ?? 'harness';
  }

  startReaper(): void {
    if (this.reaperTimer !== undefined) return;
    this.reaperTimer = setInterval(() => void this.reap(), REAPER_INTERVAL_MS);
    this.reaperTimer.unref();
  }

  stopReaper(): void {
    if (this.reaperTimer !== undefined) clearInterval(this.reaperTimer);
    this.reaperTimer = undefined;
  }

  private reap(): void {
    const now = this.nowFn();
    for (const session of this.sessions.values()) {
      if (session.closing && now - session.lastActivityMs > SESSION_CLOSING_TIMEOUT_MS) {
        // Stuck closing → force teardown, mark unknown honestly.
        session.incus.closeAll();
        this.deps.journal.setSessionState(session.sessionId, 'closed');
        this.deps.journal.appendEvent('session.reaper-unknown', session.workspaceId, { sessionId: session.sessionId });
        this.sessions.delete(session.sessionId);
      }
    }
  }

  // ---- one-shot exec.run -----------------------------------------------------

  /** Open an Incus exec session and capture bounded output. */
  async openAndCapture(input: {
    opId: string;
    workspaceId: string;
    vmName: string;
    argv: string[];
    cwd?: string;
    environment: Record<string, string>;
    stdinBase64?: string;
    timeoutMs: number;
    maxBytes: number;
    user?: 'workspace' | 'root';
    envKeys: string[];
    envDigest: string;
  }): Promise<ExecRunOutcome> {
    const { journal, incus, incusSocketPath } = this.deps;
    journal.recordExecStart({ opId: input.opId, workspaceId: input.workspaceId });

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let truncated = false;
    let timedOut = false;
    let exitInfo: ExecExitInfo | undefined;

    const exitPromise = new Promise<ExecExitInfo>((resolve, reject) => {
      const finish = (info: ExecExitInfo) => { exitInfo = info; resolve(info); };
      const fail = (e: Error) => { reject(e); };

      const asRoot = input.user === 'root';
      const spec = {
        command: asRoot ? [...input.argv] : wrapWorkspaceArgv(input.argv, this.guestUser),
        ...(input.cwd !== undefined ? { cwd: input.cwd } : {}),
        environment: input.environment,
        // Both branches exec as root: 'root' runs the argv directly, workspace
        // argv is the runuser drop which needs root to initgroups.
        user: 'root',
        group: 'root'
      };
      void IncusExecSession.open(
        incus as unknown as Pick<IncusClient, 'openExecFds'>,
        incusSocketPath,
        input.vmName,
        spec,
        {
          onStdout: (chunk) => {
            if (stdoutBytes + chunk.length > input.maxBytes) {
              const allowed = Math.max(0, input.maxBytes - stdoutBytes);
              if (allowed > 0) stdoutChunks.push(chunk.subarray(0, allowed));
              stdoutBytes = input.maxBytes;
              truncated = true;
            } else {
              stdoutChunks.push(chunk);
              stdoutBytes += chunk.length;
            }
          },
          onStderr: (chunk) => {
            if (stderrBytes + chunk.length > input.maxBytes) {
              const allowed = Math.max(0, input.maxBytes - stderrBytes);
              if (allowed > 0) stderrChunks.push(chunk.subarray(0, allowed));
              stderrBytes = input.maxBytes;
              truncated = true;
            } else {
              stderrChunks.push(chunk);
              stderrBytes += chunk.length;
            }
          },
          onExit: finish,
          onTransportError: fail
        },
        5_000
      ).then((session) => {
        if (input.stdinBase64 !== undefined && input.stdinBase64.length > 0) {
          const stdin = Buffer.from(input.stdinBase64, 'base64');
          // Write in bounded slices; Incus stdin accepts binary frames.
          const SLICE = 256 * 1024;
          for (let offset = 0; offset < stdin.length; offset += SLICE) {
            if (!session.writeStdin(stdin.subarray(offset, offset + SLICE))) break;
          }
        }
        session.stdinEof();
        // Timeout: SIGKILL then bounded wait, then hard teardown.
        const timer = setTimeout(() => {
          if (exitInfo !== undefined) return;
          timedOut = true;
          session.signal('SIGKILL');
          setTimeout(() => {
            if (exitInfo === undefined) {
              session.closeAll();
              finish({ exitCode: null, signal: 'SIGKILL' });
            }
          }, EXEC_RUN_KILL_GRACE_MS);
        }, input.timeoutMs);
        timer.unref();
      }).catch(fail);
    });

    try {
      const info = await exitPromise;
      const outcome: ExecRunOutcome = {
        opId: input.opId,
        exitCode: info.exitCode,
        signal: info.signal,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: Buffer.concat(stderrChunks).toString('utf8'),
        truncated,
        timedOut
      };
      journal.recordExecEnd(input.opId, {
        exitCode: outcome.exitCode,
        signal: outcome.signal,
        returnMetadata: { envKeys: input.envKeys, envDigest: input.envDigest, return: info.metadata }
      });
      return outcome;
    } catch (error) {
      journal.recordExecEnd(input.opId, { exitCode: null, signal: null, returnMetadata: { error: 'transport' } });
      throw error instanceof VmOpError ? error : new VmUnknownMutationError(
        `exec transport failure: ${error instanceof Error ? error.message : 'unknown'}`
      );
    }
  }

  // ---- persistent exec.open sessions ------------------------------------------

  async openSession(input: {
    sessionId: string;
    workspaceId: string;
    vmName: string;
    instanceId: string;
    generation: number;
    argv: string[];
    cwd?: string;
    environment: Record<string, string>;
    pty?: { cols: number; rows: number };
    channel: WireSessionChannel;
    onClosed: () => void;
  }): Promise<{ sessionId: string; fdsReady: true }> {
    const { journal, incus, incusSocketPath } = this.deps;
    // exec.open has no user field — sessions are workspace sessions by
    // contract, so the runuser wrapper always applies (supplementary groups
    // included); the exec itself runs as root for the credential drop.
    const spec = {
      command: wrapWorkspaceArgv(input.argv, this.guestUser),
      ...(input.cwd !== undefined ? { cwd: input.cwd } : {}),
      environment: input.environment,
      user: 'root',
      group: 'root',
      ...(input.pty !== undefined ? { pty: input.pty } : {})
    };
    const session = await IncusExecSession.open(
      incus as unknown as Pick<IncusClient, 'openExecFds'>,
      incusSocketPath,
      input.vmName,
      spec,
      {
        onStdout: (chunk) => {
          const live = this.sessions.get(input.sessionId);
          if (live !== undefined) {
            live.lastActivityMs = this.nowFn();
            this.emitSessionChunk(live, 1, chunk);
          }
        },
        onStderr: (chunk) => {
          const live = this.sessions.get(input.sessionId);
          if (live !== undefined) {
            live.lastActivityMs = this.nowFn();
            // PTY mode merges stdio: everything is fd 1 on the wire.
            const fd = input.pty !== undefined ? 1 : 2;
            this.emitSessionChunk(live, fd, chunk);
          }
        },
        onMeta: () => undefined,
        onExit: (info) => {
          const live = this.sessions.get(input.sessionId);
          if (live !== undefined) {
            live.exitInfo = info;
            live.channel.emitMeta(input.sessionId, info.exitCode, info.signal, info.metadata);
            live.channel.emitEnd(input.sessionId, info.exitCode, info.signal, info.metadata);
            journal.setSessionState(input.sessionId, 'closed');
            journal.recordExecEnd(`sess:${input.sessionId}`, {
              exitCode: info.exitCode, signal: info.signal, returnMetadata: info.metadata
            });
            this.sessions.delete(input.sessionId);
          }
          input.onClosed();
        },
        onTransportError: () => {
          // Transport loss → run the cancel ladder; outcome recorded honestly.
          void this.cleanupSession(input.sessionId, 'transport-error');
        }
      },
      5_000
    );
    journal.registerSession({
      sessionId: input.sessionId,
      workspaceId: input.workspaceId,
      instanceId: input.instanceId,
      generation: input.generation,
      pty: input.pty !== undefined
    });
    journal.recordExecStart({ opId: `sess:${input.sessionId}`, workspaceId: input.workspaceId, sessionId: input.sessionId });
    this.sessions.set(input.sessionId, {
      sessionId: input.sessionId,
      workspaceId: input.workspaceId,
      vmName: input.vmName,
      channel: input.channel,
      incus: session,
      lastActivityMs: this.nowFn(),
      closing: false
    });
    return { sessionId: input.sessionId, fdsReady: true };
  }

  private live(sessionId: string): LiveSession {
    const session = this.sessions.get(sessionId);
    if (session === undefined) {
      // Session may have exited; check journal for a definitive answer.
      const row = this.deps.journal.getSession(sessionId);
      if (row === undefined) throw new VmOpError('NOT_FOUND', 'unknown exec session');
      if (row.state === 'closed') throw new VmOpError('CONFLICT', 'exec session already closed');
      throw new VmOpError('CONFLICT', 'exec session is not attached to this supervisor process');
    }
    return session;
  }

  writeStdin(sessionId: string, fd: number, dataBase64: string, eof?: boolean): { acceptedBytes: number } {
    if (fd !== 0) {
      // stdout/stderr are read-only channels; only fd 0 (stdin) is writable.
      throw new VmOpError('INVALID_INPUT', 'exec.write accepts fd 0 only');
    }
    const session = this.live(sessionId);
    const data = Buffer.from(dataBase64, 'base64');
    if (data.length > 0 && !session.incus.writeStdin(data)) {
      throw new VmOpError('VM_SUPERVISOR_UNAVAILABLE', 'session stdin write failed', { retryable: true });
    }
    session.lastActivityMs = this.nowFn();
    if (eof === true) session.incus.stdinEof();
    return { acceptedBytes: data.length };
  }

  async closeSession(sessionId: string, fd?: number): Promise<{ closed: true }> {
    const session = this.live(sessionId);
    if (fd === -1 || fd === undefined) {
      // Control close: SIGKILL the session leader via the control channel.
      session.incus.signal('SIGKILL');
      await this.cleanupSession(sessionId, 'control-close');
      return { closed: true };
    }
    if (fd === 0) {
      session.incus.stdinEof();
      return { closed: true };
    }
    // fd 1|2 close: no remote equivalent; treated as control close for safety.
    await this.cleanupSession(sessionId, 'fd-close');
    return { closed: true };
  }

  resizeSession(sessionId: string, cols: number, rows: number): Record<string, never> {
    const session = this.live(sessionId);
    if (!session.incus.resize(cols, rows)) {
      throw new VmOpError('VM_CAPABILITY_UNSUPPORTED', 'session does not support resize');
    }
    session.lastActivityMs = this.nowFn();
    return {};
  }

  /**
   * exec.killSession ladder: control-close → bounded exec `kill -- -<pgid>`
   * via the guest pid file → ws teardown. Verified exit → killed:true;
   * anything else throws UNKNOWN (caller surfaces unknown semantics).
   */
  async killSession(sessionId: string, pidFile: string): Promise<{ killed: true }> {
    const session = this.live(sessionId);
    session.closing = true;
    // Step 1: control-close (SIGKILL leader).
    session.incus.signal('SIGKILL');
    const exited = await this.waitExit(sessionId, SESSION_CLOSE_VERIFY_MS);
    if (exited) {
      session.incus.closeAll();
      this.finishClosed(sessionId);
      return { killed: true };
    }
    // Step 2: guest-side process-group kill via pid file (root exec).
    try {
      const pgidKill = await this.openAndCapture({
        opId: `kill:${sessionId}:${this.nowFn()}`,
        workspaceId: session.workspaceId,
        vmName: session.vmName,
        argv: ['sh', '-c', `kill -- -$(cat ${JSON.stringify(pidFile)} 2>/dev/null) 2>/dev/null || true`],
        user: 'root',
        environment: {},
        timeoutMs: 15_000,
        maxBytes: 4096,
        envKeys: [],
        envDigest: ''
      });
      void pgidKill;
    } catch {
      // pgid kill is best-effort; verification below decides.
    }
    const exitedAfter = await this.waitExit(sessionId, SESSION_CLOSE_VERIFY_MS);
    session.incus.closeAll();
    if (!exitedAfter) {
      this.deps.journal.appendEvent('session.kill-unknown', session.workspaceId, { sessionId });
      throw new VmUnknownMutationError('session kill could not be verified');
    }
    this.finishClosed(sessionId);
    return { killed: true };
  }

  /** Disconnect/cancel path: same ladder minus the pgid step (no pidFile). */
  async cleanupSession(sessionId: string, reason: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session === undefined) return;
    if (session.closing) return;
    session.closing = true;
    session.incus.signal('SIGKILL');
    const exited = await this.waitExit(sessionId, SESSION_CLOSE_VERIFY_MS);
    session.incus.closeAll();
    if (exited) {
      this.finishClosed(sessionId);
    } else {
      this.deps.journal.setSessionState(sessionId, 'closed');
      this.deps.journal.appendEvent('session.cleanup-unknown', session.workspaceId, { sessionId, reason });
      this.sessions.delete(sessionId);
    }
  }

  /** Called by server.ts when the session's connection drops. */
  onConnectionClosed(sessionIds: readonly string[]): void {
    for (const sessionId of sessionIds) {
      void this.cleanupSession(sessionId, 'connection-closed');
    }
  }

  private waitExit(sessionId: string, timeoutMs: number): Promise<boolean> {
    return new Promise((resolve) => {
      const deadline = this.nowFn() + timeoutMs;
      const poll = () => {
        const session = this.sessions.get(sessionId);
        if (session === undefined || session.exitInfo !== undefined) {
          resolve(true);
          return;
        }
        if (this.nowFn() >= deadline) {
          resolve(false);
          return;
        }
        setTimeout(poll, 200);
      };
      poll();
    });
  }

  private finishClosed(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (session === undefined) return;
    this.deps.journal.setSessionState(sessionId, 'closed');
    this.sessions.delete(sessionId);
  }

  /**
   * Reject extraction when a PRE-EXISTING guest symlink sits on the ancestor
   * path of any archive member: `tar -x` follows such links and would write
   * outside the advertised destination root (e.g. a planted
   * `dest/link -> /home/harness`). Archive-internal links are already
   * canonicalized by inspectTarSafety; this covers the guest-FS vector it
   * cannot see. Fails closed when the link set cannot be fully enumerated.
   */
  private async assertNoDestinationLinkAncestors(
    workspaceId: string,
    vmName: string,
    guestPath: string,
    entryPaths: string[]
  ): Promise<void> {
    const needed = new Set<string>();
    for (const p of entryPaths) {
      const segs = p.split('/');
      for (let i = 1; i < segs.length; i += 1) needed.add(segs.slice(0, i).join('/'));
    }
    if (needed.size === 0) return;
    const out = await this.openAndCapture({
      opId: `linkscan:${vmName}:${this.nowFn()}:${linkScanSeq += 1}`,
      workspaceId,
      vmName,
      argv: ['find', '-H', guestPath, '-type', 'l', '-printf', '%P\n'],
      environment: {},
      timeoutMs: 60_000,
      maxBytes: 4 * 1024 * 1024,
      user: 'workspace',
      envKeys: [],
      envDigest: ''
    });
    if (out.truncated) {
      throw new VmOpError('LIMIT_EXCEEDED', 'destination contains too many symlinks to verify safely');
    }
    if (out.exitCode !== 0) {
      throw new VmOpError('EXECUTION_FAILED', `destination symlink scan failed: ${out.stderr.slice(0, 200)}`);
    }
    for (const line of out.stdout.split('\n')) {
      const rel = line.trim();
      if (rel !== '' && needed.has(rel)) {
        throw new VmOpError('CONFLICT', `destination path '${rel}' is an existing symlink; refusing to extract through it`);
      }
    }
  }

  /**
   * `mkdir -p <guestPath>` as the guest user — idempotent, argv-exact, used
   * before guest tar extraction so pushTree targets need not pre-exist.
   * Throws on non-zero exit, timeout, or transport loss.
   */
  private async guestEnsureDir(vmName: string, guestPath: string): Promise<void> {
    const spec = {
      command: ['mkdir', '-p', guestPath],
      environment: {},
      user: this.guestUser,
      group: this.guestGroup
    };
    const session = await IncusExecSession.open(
      this.deps.incus as unknown as Pick<IncusClient, 'openExecFds'>,
      this.deps.incusSocketPath,
      vmName,
      spec,
      { onStdout: () => undefined, onStderr: () => undefined, onMeta: () => undefined, onExit: () => undefined, onTransportError: () => undefined },
      10_000
    );
    const info = await new Promise<ExecExitInfo>((resolve, reject) => {
      const timer = setTimeout(() => {
        session.signal('SIGKILL');
        setTimeout(() => { session.closeAll(); reject(new VmUnknownMutationError('guest mkdir timed out')); }, 5_000);
      }, 30_000);
      timer.unref();
      const poll = () => {
        if (session.exitInfo !== undefined) {
          clearTimeout(timer);
          session.closeAll();
          resolve(session.exitInfo);
        } else {
          setTimeout(poll, 50);
        }
      };
      poll();
    });
    if (info.exitCode !== 0) {
      throw new VmOpError('EXECUTION_FAILED', `guest mkdir failed (exit ${info.exitCode ?? 'unknown'})`);
    }
  }

  /**
   * Emit one guest-output chunk with bounded backpressure: the transport
   * serializes writes per connection, and when queued output exceeds the
   * high-water mark the guest's data channels are paused (TCP backpressure
   * reaches the guest writer) until the queue drains below low-water.
   */
  private emitSessionChunk(live: LiveSession, fd: number, chunk: Buffer): void {
    const pending = live.channel.emitData(live.sessionId, fd, chunk);
    if (live.channel.pendingOutputBytes() > SESSION_OUTPUT_HIGH_WATER_BYTES && live.outputPaused !== true) {
      live.outputPaused = true;
      live.incus.pauseOutputChannels();
    }
    void pending.finally(() => {
      if (live.outputPaused === true && live.channel.pendingOutputBytes() < SESSION_OUTPUT_LOW_WATER_BYTES) {
        live.outputPaused = false;
        live.incus.resumeOutputChannels();
      }
    });
  }

  /**
   * Stream a staged tar file into the guest: `tar -xf - -C <dir>` via exec
   * stdin. The destination is created first (`mkdir -p`, guest-user owned)
   * because pushTree targets may not exist yet — `tar -C` fails on a missing
   * dir. Bounded by timeoutMs; any failure throws — never reports success
   * on incomplete extraction.
   */
  async extractTarStream(input: {
    workspaceId: string;
    vmName: string;
    guestPath: string;
    tar: NodeJS.ReadableStream;
    tarBytes: number;
    /** Validated archive member paths (from inspectTarSafety) for the guest link-ancestor scan. */
    entryPaths?: string[];
    timeoutMs?: number;
  }): Promise<{ exitCode: number | null; signal: string | null; stderr: string }> {
    // Defense below the server allow-list: absolute, no `..` — argv-array
    // exec makes injection impossible, this guards future callers.
    if (!input.guestPath.startsWith('/') || input.guestPath.split('/').includes('..')) {
      throw new VmOpError('INVALID_INPUT', 'guestPath must be absolute and must not contain .. segments');
    }
    await this.guestEnsureDir(input.vmName, input.guestPath);
    if (input.entryPaths !== undefined && input.entryPaths.length > 0) {
      await this.assertNoDestinationLinkAncestors(input.workspaceId, input.vmName, input.guestPath, input.entryPaths);
    }
    const timeoutMs = input.timeoutMs ?? 15 * 60 * 1000;
    const spec = {
      command: ['tar', '-xf', '-', '-C', input.guestPath, '--no-same-owner', '--no-same-permissions'],
      environment: {},
      user: this.guestUser,
      group: this.guestGroup
    };
    const stderrChunks: Buffer[] = [];
    let stderrBytes = 0;
    const session = await IncusExecSession.open(
      this.deps.incus as unknown as Pick<IncusClient, 'openExecFds'>,
      this.deps.incusSocketPath,
      input.vmName,
      spec,
      {
        onStdout: () => undefined,
        onStderr: (chunk) => {
          if (stderrBytes < 64 * 1024) {
            stderrChunks.push(chunk.subarray(0, 64 * 1024 - stderrBytes));
            stderrBytes += chunk.length;
          }
        },
        onMeta: () => undefined,
        onExit: () => undefined,
        onTransportError: () => undefined
      },
      10_000
    );
    return await new Promise((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        session.signal('SIGKILL');
        setTimeout(() => { session.closeAll(); reject(new VmUnknownMutationError('tar extract timed out')); }, 5_000);
      }, timeoutMs);
      timer.unref();
      const pump = async () => {
        for await (const chunk of input.tar) {
          if (!session.writeStdin(chunk as Buffer)) throw new Error('stdin write failed');
        }
        session.stdinEof();
      };
      void pump().then(() => {
        const waitExit = () => {
          if (session.exitInfo !== undefined) {
            clearTimeout(timer);
            session.closeAll();
            resolve({ exitCode: session.exitInfo.exitCode, signal: session.exitInfo.signal, stderr: Buffer.concat(stderrChunks).toString('utf8') });
          } else {
            setTimeout(waitExit, 100);
          }
        };
        waitExit();
      }).catch((e) => { clearTimeout(timer); session.closeAll(); reject(e); });
    });
  }

  /**
   * Stream `tar -cf - -C <parent> <base>` stdout through emit with sha256 /
   * bytes / tar-entry counting. Returns the trailer on guest exit.
   */
  async streamGuestTar(input: {
    workspaceId: string;
    vmName: string;
    guestPath: string;
    maxBytes: number;
    emit: (chunk: Buffer) => Promise<void>;
    timeoutMs?: number;
  }): Promise<{ sha256: string; bytes: number; entryCount: number }> {
    const timeoutMs = input.timeoutMs ?? 30 * 60 * 1000;
    const { createHash } = await import('node:crypto');
    const { TarEntryCounter } = await import('./export.js');
    const hash = createHash('sha256');
    const counter = new TarEntryCounter();
    let bytes = 0;
    let settled = false;

    const parent = input.guestPath.slice(0, input.guestPath.lastIndexOf('/')) || '/';
    const base = input.guestPath.slice(input.guestPath.lastIndexOf('/') + 1) || input.guestPath;
    const spec = {
      command: ['tar', '-cf', '-', '-C', parent, base],
      environment: {},
      user: this.guestUser,
      group: this.guestGroup
    };
    return await new Promise((resolve, reject) => {
      let session!: IncusExecSession;
      const fail = (e: Error) => {
        if (settled) return;
        settled = true;
        try { session.signal('SIGKILL'); session.closeAll(); } catch { /* noop */ }
        reject(e);
      };
      const timer = setTimeout(() => fail(new VmOpError('LIMIT_EXCEEDED', 'pullTree timed out')), timeoutMs);
      timer.unref();
      void IncusExecSession.open(
        this.deps.incus as unknown as Pick<IncusClient, 'openExecFds'>,
        this.deps.incusSocketPath,
        input.vmName,
        spec,
        {
          onStdout: (chunk) => {
            if (settled) return;
            bytes += chunk.length;
            if (bytes > input.maxBytes) {
              fail(new VmOpError('LIMIT_EXCEEDED', 'pullTree exceeded maxBytes'));
              return;
            }
            hash.update(chunk);
            counter.push(chunk);
            void input.emit(chunk).catch(() => undefined);
          },
          onStderr: () => undefined,
          onMeta: () => undefined,
          onExit: (info) => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            session.closeAll();
            if (info.exitCode === 0) {
              resolve({ sha256: hash.digest('hex'), bytes, entryCount: counter.entryCount });
            } else {
              reject(new VmOpError('INTERNAL_ERROR', `guest tar failed (exit ${info.exitCode ?? 'unknown'})`));
            }
          },
          onTransportError: (e) => fail(new VmUnknownMutationError(`pullTree transport: ${e.message}`))
        },
        10_000
      ).then((s) => { session = s; }).catch((e) => fail(e instanceof Error ? e : new Error(String(e))));
    });
  }

  inspectOp(opId: string): { state: 'running' | 'exited' | 'unknown'; exitCode?: number | null; returnMetadata?: Record<string, unknown> } {
    const row = this.deps.journal.getExecOp(opId);
    if (row === undefined) return { state: 'unknown' };
    if (row.state === 'running') return { state: 'running' };
    return {
      state: 'exited',
      exitCode: row.exitCode,
      ...(row.returnMetadata !== null && typeof row.returnMetadata === 'object'
        ? { returnMetadata: row.returnMetadata as Record<string, unknown> }
        : {})
    };
  }
}
