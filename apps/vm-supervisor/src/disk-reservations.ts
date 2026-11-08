import { statfs } from 'node:fs/promises';

/**
 * Shared host-disk reservation ledger for supervisor-staged payloads.
 *
 * Every byte the supervisor stages on the host backing filesystem — upload
 * payloads in `streamDir`, offline-export tarballs in `poolPath/.exports` —
 * must hold a reservation BEFORE staging begins. `maxBytes` bounds alone
 * cannot prevent host exhaustion: N concurrent streams each under their
 * per-request cap can still exceed free space in aggregate.
 *
 * `acquire` checks `statfs(dir).bavail*bsize - heldTotal - margin >= bytes`
 * atomically (the check-and-hold section is synchronous after the statfs
 * await, so concurrent acquires cannot both pass the same free bytes).
 * The returned release function is idempotent; callers release in `finally`
 * on success, abort, and error. Downloads stream directly to the client and
 * hold no supervisor-side reservation.
 */

export interface DiskStatfsResult {
  bavail: number | bigint;
  bsize: number | bigint;
}
export type DiskStatfsFn = (path: string) => Promise<DiskStatfsResult>;

export class DiskReservations {
  private readonly held = new Map<string, number>();
  private heldTotal = 0;

  constructor(
    private readonly statfsFn: DiskStatfsFn = (path) => statfs(path),
    private readonly marginBytes = 1024 * 1024 * 1024
  ) {}

  /** Bytes currently reserved across all holders. */
  get reservedBytes(): number {
    return this.heldTotal;
  }

  /**
   * Reserve `bytes` against the filesystem backing `dir`. Throws a coded
   * error — VM_QUOTA_EXCEEDED when space (free minus in-flight reservations
   * minus margin) is insufficient, VM_SUPERVISOR_UNAVAILABLE when statfs
   * itself fails. Returns an idempotent release function on success.
   */
  async acquire(key: string, dir: string, bytes: number): Promise<() => void> {
    if (this.held.has(key)) {
      throw new Error(`duplicate disk reservation key: ${key}`);
    }
    let freeBytes: number;
    try {
      const fs = await this.statfsFn(dir);
      freeBytes = Number(fs.bavail) * Number(fs.bsize);
    } catch (error) {
      const e = new Error('cannot stat staging filesystem') as Error & { code: string; retryable: boolean };
      e.code = 'VM_SUPERVISOR_UNAVAILABLE';
      e.retryable = true;
      e.cause = error;
      throw e;
    }
    if (freeBytes - this.heldTotal < bytes + this.marginBytes) {
      const e = new Error('insufficient staging space for transfer') as Error & { code: string; retryable: boolean };
      e.code = 'VM_QUOTA_EXCEEDED';
      e.retryable = true;
      throw e;
    }
    this.held.set(key, bytes);
    this.heldTotal += bytes;
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.heldTotal -= this.held.get(key) ?? 0;
      this.held.delete(key);
    };
  }
}
