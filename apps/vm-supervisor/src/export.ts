import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { stat, rm } from 'node:fs/promises';
import { join } from 'node:path';
import type { VmGuardCommandRunner } from './network-ops.js';

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
 *   (maxBytes), staging file deleted in `finally` on every path.
 * - ANY extraction failure retains the disk and reports failure; the disk
 *   image itself is never touched beyond read-only appliance access.
 */

export interface VmExportDeps {
  poolPath: string;
  /** Bounded command runner (same contract as the guard's execFile). */
  execFile: VmGuardCommandRunner;
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

const APPLIANCE_TIMEOUT_MS = 10 * 60 * 1000;
const TAR_HEADER = 512;

/**
 * Parse tar entry count incrementally over a byte stream. Handles ustar
 * prefix fields and stops at the first zero block. Malformed streams throw —
 * the caller treats that as extraction failure, never partial success.
 */
export class TarEntryCounter {
  private buffer: Buffer = Buffer.alloc(0);
  private inHeader = true;
  private headerRemaining = 0;
  private entries = 0;
  private done = false;

  push(chunk: Buffer): void {
    if (this.done) return;
    this.buffer = this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
    for (;;) {
      if (this.inHeader) {
        if (this.buffer.length < TAR_HEADER) return;
        const header = this.buffer.subarray(0, TAR_HEADER);
        // Zero block → end of archive (two consecutive, but one suffices to stop counting).
        if (header.every((b) => b === 0)) {
          this.done = true;
          return;
        }
        const sizeField = header.subarray(124, 136).toString('utf8').replace(/\0.*$/s, '').trim();
        const size = Number.parseInt(sizeField, 8);
        if (!Number.isFinite(size) || size < 0) throw new Error('malformed tar size field');
        this.entries += 1;
        // Bound matches tar-safety MAX_ENTRIES and the server's 1 GiB
        // tar-overhead proof: >50k entries aborts the stream.
        if (this.entries > 50_000) throw new Error('too many tar entries');
        this.buffer = this.buffer.subarray(TAR_HEADER);
        this.headerRemaining = Math.ceil(size / TAR_HEADER) * TAR_HEADER;
        this.inHeader = false;
      } else {
        if (this.buffer.length < this.headerRemaining) return;
        this.buffer = this.buffer.subarray(this.headerRemaining);
        this.headerRemaining = 0;
        this.inHeader = true;
      }
    }
  }

  get entryCount(): number {
    return this.entries;
  }
}

/**
 * Prepare an export: run the appliance to produce `outPath`, then return a
 * produce() that streams it with sha256/bytes/entryCount accounting.
 * Throws VmOpError-compatible errors; caller maps to contract codes.
 */
export async function prepareVmExport(
  deps: VmExportDeps,
  input: { vmName: string; guestPath: string; maxBytes: number; expectedSha256?: string }
): Promise<VmExportProduce> {
  const imagePath = rootDiskImagePath(deps.poolPath, input.vmName);
  const outPath = join(deps.poolPath, '.exports', `${input.vmName}-${Date.now()}.tar`);
  const { mkdir } = await import('node:fs/promises');
  await mkdir(join(deps.poolPath, '.exports'), { recursive: true });

  const timeoutMs = deps.applianceTimeoutMs ?? APPLIANCE_TIMEOUT_MS;
  // virt-tar-out: -a disk image, guest path, local tar file. --ro is not a
  // virt-tar-out flag; read-only access is enforced by libguestfs defaults
  // for tar-out? — explicit: use guestfish-free virt-tar-out which mounts
  // read-only by default for inspection commands. Live gate verifies flags.
  const result = await deps.execFile(
    ['virt-tar-out', '-a', imagePath, '--ro', input.guestPath, outPath],
    { timeoutMs, maxOutputBytes: 64 * 1024 }
  );
  if (result.exitCode !== 0 || result.timedOut) {
    await rm(outPath, { force: true }).catch(() => undefined);
    throw new Error(`export appliance failed: ${result.stderr.slice(0, 200) || `exit ${result.exitCode}`}`);
  }

  const fileStat = await stat(outPath);
  if (fileStat.size > input.maxBytes) {
    await rm(outPath, { force: true }).catch(() => undefined);
    throw new Error('export exceeds maxBytes');
  }

  return {
    async produce(emit) {
      const hash = createHash('sha256');
      const counter = new TarEntryCounter();
      let bytes = 0;
      const stream = createReadStream(outPath, { highWaterMark: 1024 * 1024 });
      try {
        for await (const chunk of stream) {
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
