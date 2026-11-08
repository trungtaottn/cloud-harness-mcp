import { createHash, randomUUID } from 'node:crypto';
import { once } from 'node:events';
import { createReadStream, createWriteStream } from 'node:fs';
import { mkdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import type { Readable } from 'node:stream';
import { finished } from 'node:stream/promises';
import { tarSizeField } from './tar-safety.js';

/**
 * Offline `vm.export`: extract a bounded tar of `guestPath` from a STOPPED
 * VM's disk image using an isolated libguestfs appliance (`virt-tar-out`).
 *
 * Safety invariants (frozen):
 * - The guest filesystem is NEVER mounted in the host kernel — no loop
 *   device, no host mount, no host-side filesystem parser. libguestfs runs
 *   its own minimal no-network appliance VM that parses the image internally.
 * - No guest code executes; output is treated as untrusted bytes.
 * - Resource-bounded: appliance wall-clock timeout, output byte cap
 *   (maxBytes) enforced WHILE the archive is produced — virt-tar-out writes
 *   the tar to stdout (`-` operand) and this module streams it through a
 *   counting sink that never writes past maxBytes; on overflow, timeout or
 *   abort the appliance is cancelled and its exit is awaited (real
 *   stop/reap, not a detached race). The real spawner runs the appliance
 *   behind an appliance-shim sentinel that self-signals its whole process
 *   group on cancel, so guestfish/qemu descendants cannot survive holding
 *   the pipes or the disk image. Staging file deleted in `finally` on
 *   every path.
 * - ANY extraction failure retains the disk and reports failure; the disk
 *   image itself is never touched beyond read-only appliance access.
 */

/**
 * Minimal child-process surface the export sink needs. Structurally
 * satisfied by node:child_process ChildProcess; tests substitute fakes.
 * `kill()` MUST terminate the spawned process AND its descendants — the
 * real spawner (runtime.ts) runs the child detached behind an
 * appliance-shim sentinel that self-signals its whole process group on a
 * control-pipe cancel, so appliance children (guestfish/qemu) cannot
 * survive holding the pipes or the disk image.
 */
export interface VmApplianceProcess {
  readonly stdout: Readable | null;
  readonly stderr: Readable | null;
  kill(signal?: NodeJS.Signals | number): boolean;
  once(event: 'error', listener: (error: Error) => void): unknown;
  once(event: 'close', listener: (code: number | null, signal: NodeJS.Signals | null) => void): unknown;
}

/**
 * Spawns the appliance argv; export.ts owns every bound around it.
 * `opts.deadlineMs` is an optional backstop deadline the real spawner
 * forwards to its sentinel (export timeout + grace); fakes may ignore it.
 */
export type VmApplianceSpawner = (argv: readonly string[], opts?: { deadlineMs?: number }) => VmApplianceProcess;

export interface VmExportDeps {
  poolPath: string;
  /** Appliance spawner (real impl: spawnApplianceProcess in runtime.ts). */
  spawnAppliance: VmApplianceSpawner;
  /** Appliance wall-clock bound. Default 10min. */
  applianceTimeoutMs?: number;
  now?: () => number;
}

export interface VmExportProduce {
  /** Stream the tar bytes through `emit`; returns the trailer result. */
  produce(emit: (chunk: Buffer) => Promise<void>): Promise<{ sha256: string; bytes: number; entryCount: number }>;
  cleanup(): Promise<void>;
}

/** Locate the VM root disk image for dir-backed Incus pools. */
export function rootDiskImagePath(poolPath: string, vmName: string): string {
  return join(poolPath, 'virtual-machines', vmName, 'root.img');
}

export const APPLIANCE_TIMEOUT_MS = 10 * 60 * 1000;
const TAR_HEADER = 512;
const APPLIANCE_STDERR_MAX = 64 * 1024;

/**
 * Parse tar entry count incrementally over a byte stream. Handles ustar
 * prefix fields and stops at the first zero block. Malformed streams throw —
 * the caller treats that as extraction failure, never partial success.
 *
 * Bounded memory: only the 512-byte header window and at most one chunk are
 * retained; entry bodies (including multi-GiB files and base-256 sizes) are
 * skipped incrementally, never buffered.
 */
export class TarEntryCounter {
  private buffer: Buffer = Buffer.alloc(0);
  private skipRemaining = 0n;
  private entries = 0;
  private done = false;

  push(chunk: Buffer): void {
    if (this.done) return;
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    for (;;) {
      if (this.skipRemaining > 0n) {
        if (this.buffer.length === 0) return;
        const take = Number(this.skipRemaining < BigInt(this.buffer.length) ? this.skipRemaining : BigInt(this.buffer.length));
        this.buffer = this.buffer.subarray(take);
        this.skipRemaining -= BigInt(take);
        if (this.skipRemaining > 0n) return;
        continue;
      }
      if (this.buffer.length < TAR_HEADER) return;
      const header = this.buffer.subarray(0, TAR_HEADER);
      // Zero block → end of archive (two consecutive, but one suffices to stop counting).
      if (header.every((b) => b === 0)) {
        this.done = true;
        return;
      }
      const size = tarSizeField(header.subarray(124, 136));
      if (size === undefined) throw new Error('malformed tar size field');
      // Count REAL members only — GNU longname/longlink ('L','K') and PAX
      // ('x','g') headers carry no member of their own; inspectTarSafety
      // applies the same rule, so both counters report identical parity.
      const typeflag = String.fromCharCode(header[156] ?? 0);
      if (typeflag !== 'L' && typeflag !== 'K' && typeflag !== 'x' && typeflag !== 'g') {
        this.entries += 1;
        // Bound matches tar-safety MAX_ENTRIES and the server's 1 GiB
        // tar-overhead proof: >50k entries aborts the stream.
        if (this.entries > 50_000) throw new Error('too many tar entries');
      }
      this.buffer = this.buffer.subarray(TAR_HEADER);
      this.skipRemaining = ((size + 511n) / 512n) * 512n;
    }
  }

  get entryCount(): number {
    return this.entries;
  }

  /**
   * True only once the end-of-archive marker was observed. A staged file
   * that ends mid-header or mid-body leaves this false — produce() treats
   * that as a truncated archive, never a successful export.
   */
  get complete(): boolean {
    return this.done;
  }
}

interface ApplianceRunResult {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  timedOut: boolean;
  aborted: boolean;
  /** stdout exceeded maxBytes — child was killed; staged file stays <= maxBytes. */
  overflow: boolean;
  spawnError?: string;
  fileError?: string;
  stdoutError?: string;
  /** Bytes actually written to the staging file (<= maxBytes always). */
  written: number;
  /** 'close' observed within the reap bound; false ⇒ a descendant may linger. */
  reaped: boolean;
  stderr: string;
}

const describe = (error: unknown): string => (error instanceof Error ? error.message : String(error));

/** Upper bound on waiting for 'close' after the child was cancelled. */
const REAP_TIMEOUT_MS = 5_000;
/** Second, shorter bound for 'close' after a last-chance cancel at reap timeout. */
const REAP_RETRY_MS = 1_000;
/** Shim deadline backstop = export timeout + this grace. */
const SHIM_DEADLINE_GRACE_MS = 60_000;

/**
 * Run the appliance with the tar on stdout, streaming it into `outPath`
 * through a counting sink. The byte cap is enforced BEFORE each write, so
 * the staging file can never exceed maxBytes regardless of how fast the
 * appliance produces. Overflow, appliance timeout and caller abort all
 * SIGKILL the child and await its 'close' — the process is really stopped
 * and reaped, never left running against an unlinked inode.
 */
async function runAppliance(
  spawn: VmApplianceSpawner,
  argv: readonly string[],
  outPath: string,
  maxBytes: number,
  timeoutMs: number,
  signal: AbortSignal | undefined
): Promise<ApplianceRunResult> {
  // An already-aborted caller must not spawn the appliance at all.
  if (signal?.aborted === true) {
    return { exitCode: null, signal: null, timedOut: false, aborted: true, overflow: false, reaped: true, written: 0, stderr: '' };
  }
  let child: VmApplianceProcess;
  try {
    child = spawn(argv, { deadlineMs: timeoutMs + SHIM_DEADLINE_GRACE_MS });
  } catch (error) {
    return { exitCode: null, signal: null, timedOut: false, aborted: false, overflow: false, spawnError: describe(error), reaped: true, written: 0, stderr: '' };
  }

  let spawnError: string | undefined;
  child.once('error', (error) => {
    spawnError ??= describe(error);
  });
  const closed = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
    child.once('close', (code, sig) => resolve({ code, signal: sig }));
  });

  // Bounded stderr tail for diagnostics; never unbounded buffering.
  const stderrChunks: Buffer[] = [];
  let stderrBytes = 0;
  if (child.stderr !== null) {
    child.stderr.on('data', (chunk: Buffer) => {
      if (stderrBytes >= APPLIANCE_STDERR_MAX) return;
      const take = chunk.subarray(0, APPLIANCE_STDERR_MAX - stderrBytes);
      stderrChunks.push(take);
      stderrBytes += take.length;
    });
    child.stderr.on('error', () => undefined);
  }

  const kill = (): void => {
    // Destroy our read ends FIRST: a surviving descendant may keep the
    // pipes open, and the sink loop must not wait on them — the cancel
    // below is what actually stops the writers.
    for (const stream of [child.stdout, child.stderr]) {
      try {
        stream?.destroy();
      } catch {
        // already closed
      }
    }
    try {
      child.kill('SIGKILL');
    } catch {
      // already exited — 'close' still resolves the wait below
    }
  };

  let timedOut = false;
  // Pre-aborted callers already returned above; re-read signal.aborted here
  // so an abort landing between the early check and listener registration
  // is still honored.
  let aborted = false;
  const timer = setTimeout(() => {
    timedOut = true;
    kill();
  }, timeoutMs);
  const onAbort = (): void => {
    aborted = true;
    kill();
  };
  if (signal !== undefined) {
    if (signal.aborted) onAbort();
    else signal.addEventListener('abort', onAbort, { once: true });
  }

  let written = 0;
  let overflow = false;
  let fileError: string | undefined;
  let stdoutError: string | undefined;

  if (child.stdout === null) {
    spawnError ??= 'appliance stdout unavailable';
  } else {
    const file = createWriteStream(outPath);
    let streamFileError: Error | undefined;
    file.on('error', (error) => {
      streamFileError ??= error;
      // A dead staging file must stop the producer NOW: if the appliance
      // has paused stdout, the read loop would otherwise wait for a chunk
      // that never comes and the export would ride to its full timeout.
      kill();
    });
    try {
      for await (const chunk of child.stdout) {
        if (aborted || streamFileError !== undefined) break;
        const buf = chunk as Buffer;
        if (written + buf.length > maxBytes) {
          overflow = true;
          break;
        }
        written += buf.length;
        if (!file.write(buf)) {
          try {
            await once(file, 'drain');
          } catch {
            break;
          }
        }
      }
    } catch (error) {
      stdoutError = describe(error);
    }
    // Stop the producer before flushing: a failed/over-cap run must not
    // keep the appliance writing into a pipe nobody reads.
    if (overflow || streamFileError !== undefined || stdoutError !== undefined || aborted) kill();
    file.end();
    try {
      await finished(file);
    } catch (error) {
      streamFileError ??= error instanceof Error ? error : new Error(describe(error));
    }
    fileError = streamFileError?.message;
  }

  // Bounded reap: with the sentinel shim, 'close' fires only after the
  // shim exits — which its contract makes equivalent to "process group
  // fully drained". A descendant that escaped the group and still holds a
  // pipe must not hang the export — wait at most REAP_TIMEOUT_MS. On
  // timeout send ONE last-chance cancel (a control-pipe write, never a
  // pgid signal — group identity is unprovable once the shim is gone) and
  // re-check briefly: a shim still drain-waiting on a lingering descendant
  // will self-kill the group and 'close' may yet arrive. Otherwise report
  // reaped=false so the caller fails closed.
  const awaitClose = (ms: number) => {
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<{ code: null; signal: null; reaped: false }>((resolve) => {
      timer = setTimeout(() => resolve({ code: null, signal: null, reaped: false }), ms);
      timer.unref();
    });
    // Whichever side wins, the loser's timer must not linger — a fast
    // 'close' would otherwise retain a live 5s timer per export.
    return Promise.race([
      closed.then((v) => ({ code: v.code, signal: v.signal, reaped: true as const })),
      timeout
    ]).finally(() => clearTimeout(timer));
  };
  let settled = await awaitClose(REAP_TIMEOUT_MS);
  if (!settled.reaped) {
    kill();
    settled = await awaitClose(REAP_RETRY_MS);
  }
  clearTimeout(timer);
  if (signal !== undefined) signal.removeEventListener('abort', onAbort);

  return {
    exitCode: settled.code,
    signal: settled.signal,
    timedOut,
    aborted,
    overflow,
    reaped: settled.reaped,
    ...(spawnError !== undefined ? { spawnError } : {}),
    ...(fileError !== undefined ? { fileError } : {}),
    ...(stdoutError !== undefined ? { stdoutError } : {}),
    written,
    stderr: Buffer.concat(stderrChunks).toString('utf8')
  };
}

/**
 * Prepare an export: run the appliance to produce `outPath`, then return a
 * produce() that streams it with sha256/bytes/entryCount accounting.
 * Throws VmOpError-compatible errors; caller maps to contract codes.
 */
export async function prepareVmExport(
  deps: VmExportDeps,
  input: { vmName: string; guestPath: string; maxBytes: number; expectedSha256?: string; signal?: AbortSignal }
): Promise<VmExportProduce> {
  const imagePath = rootDiskImagePath(deps.poolPath, input.vmName);
  // Unique per call: two exports of the same VM must never share a staging
  // path (Date.now() alone collides within one millisecond).
  const outPath = join(deps.poolPath, '.exports', `${input.vmName}-${Date.now()}-${randomUUID()}.tar`);
  await mkdir(join(deps.poolPath, '.exports'), { recursive: true });

  const timeoutMs = deps.applianceTimeoutMs ?? APPLIANCE_TIMEOUT_MS;
  // virt-tar-out: -a disk image, guest path, `-` = tar on stdout so the
  // bounded sink — not the appliance — owns the staging file. --ro is a
  // supported libguestfs common option (passed through to guestfish; see
  // libguestfs.org/virt-tar-out.1.html + guestfish.1.html) — keep it so the
  // appliance never writes to the image.
  const argv = ['virt-tar-out', '-a', imagePath, '--ro', input.guestPath, '-'];

  const fail = async (message: string): Promise<never> => {
    await rm(outPath, { force: true }).catch(() => undefined);
    throw new Error(message);
  };

  let result: ApplianceRunResult;
  try {
    result = await runAppliance(deps.spawnAppliance, argv, outPath, input.maxBytes, timeoutMs, input.signal);
  } catch (error) {
    await rm(outPath, { force: true }).catch(() => undefined);
    throw error;
  }

  // Cap violation is checked first: it is the bounded-disk guarantee the
  // reservation was taken against, and must be reported distinctly. A run we
  // killed for timeout/abort reports that cause before secondary stream
  // errors the kill itself may have induced.
  if (result.overflow) await fail('export exceeds maxBytes');
  if (result.aborted) await fail('export aborted');
  if (result.timedOut) await fail('export appliance failed: timed out');
  const ioError = result.spawnError ?? result.fileError ?? result.stdoutError;
  if (ioError !== undefined) await fail(`export appliance failed: ${ioError.slice(0, 200)}`);
  if (result.exitCode !== 0) {
    await fail(`export appliance failed: ${result.stderr.slice(0, 200) || `exit ${result.exitCode ?? result.signal ?? 'unknown'}`}`);
  }
  // A clean exit whose process group never fully reaped means a descendant
  // may still hold the image or pipes — fail closed rather than attesting.
  if (!result.reaped) await fail('export appliance failed: reap timeout');
  if (result.written === 0) await fail('export appliance failed: no tar output');

  return {
    async produce(emit) {
      const hash = createHash('sha256');
      const counter = new TarEntryCounter();
      let bytes = 0;
      const stream = createReadStream(outPath, { highWaterMark: 1024 * 1024 });
      try {
        for await (const chunk of stream) {
          // Caller abort during streaming: staging already succeeded, but a
          // cancelled export must never keep emitting or report success.
          if (input.signal?.aborted === true) throw new Error('export aborted');
          const buf = chunk as Buffer;
          bytes += buf.length;
          if (bytes > input.maxBytes) throw new Error('export stream exceeded maxBytes');
          hash.update(buf);
          counter.push(buf);
          await emit(buf);
        }
      } finally {
        stream.destroy();
      }
      // An abort landing on the FINAL emit must still fail the export —
      // the loop-top check alone would let a one-chunk archive report success.
      if (input.signal?.aborted === true) throw new Error('export aborted');
      // The staged archive must carry its end-of-archive marker; a file cut
      // short mid-entry is a failed export, not a partial success.
      if (!counter.complete) throw new Error('export archive is truncated');
      const trailer = { sha256: hash.digest('hex'), bytes, entryCount: counter.entryCount };
      if (input.expectedSha256 !== undefined && trailer.sha256 !== input.expectedSha256) {
        throw new Error('export digest mismatch');
      }
      return trailer;
    },
    async cleanup() {
      await rm(outPath, { force: true }).catch(() => undefined);
    }
  };
}
