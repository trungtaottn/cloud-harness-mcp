import { describe, expect, it } from 'vitest';
import { DiskReservations, type DiskStatfsFn } from '../src/disk-reservations.js';

const GIB = 1024 ** 3;

function statfsWith(freeBytes: number): DiskStatfsFn {
  return async () => ({ bavail: freeBytes, bsize: 1 });
}

describe('DiskReservations', () => {
  it('admits when free-minus-margin covers the request and releases idempotently', async () => {
    const r = new DiskReservations(statfsWith(10 * GIB), GIB);
    const release = await r.acquire('a', '/tmp', 4 * GIB);
    expect(r.reservedBytes).toBe(4 * GIB);
    release();
    release(); // idempotent — no double-release
    expect(r.reservedBytes).toBe(0);
    const again = await r.acquire('b', '/tmp', 4 * GIB);
    again();
  });

  it('rejects when free space minus margin is insufficient (low-space)', async () => {
    const r = new DiskReservations(statfsWith(4 * GIB + 512 * 1024 ** 2), GIB);
    await expect(r.acquire('a', '/tmp', 4 * GIB)).rejects.toMatchObject({ code: 'VM_QUOTA_EXCEEDED' });
    expect(r.reservedBytes).toBe(0);
  });

  it('subtracts concurrent reservations so two streams cannot overcommit', async () => {
    // 10GiB free, 1GiB margin → 9GiB usable. Two 6GiB requests: first holds,
    // second must see only 3GiB headroom and reject.
    const r = new DiskReservations(statfsWith(10 * GIB), GIB);
    const first = await r.acquire('a', '/tmp', 6 * GIB);
    await expect(r.acquire('b', '/tmp', 6 * GIB)).rejects.toMatchObject({ code: 'VM_QUOTA_EXCEEDED' });
    first();
    const second = await r.acquire('c', '/tmp', 6 * GIB);
    second();
  });

  it('serializes concurrent acquires against the same free bytes', async () => {
    const r = new DiskReservations(statfsWith(10 * GIB), GIB);
    const results = await Promise.allSettled([
      r.acquire('a', '/tmp', 6 * GIB),
      r.acquire('b', '/tmp', 6 * GIB)
    ]);
    const ok = results.filter((x) => x.status === 'fulfilled');
    const bad = results.filter((x) => x.status === 'rejected');
    expect(ok).toHaveLength(1);
    expect(bad).toHaveLength(1);
    expect((bad[0] as PromiseRejectedResult).reason).toMatchObject({ code: 'VM_QUOTA_EXCEEDED' });
    for (const x of ok) (x as PromiseFulfilledResult<() => void>).value();
  });

  it('maps statfs failure to VM_SUPERVISOR_UNAVAILABLE', async () => {
    const r = new DiskReservations(async () => { throw new Error('enoent'); }, GIB);
    await expect(r.acquire('a', '/tmp', 1)).rejects.toMatchObject({ code: 'VM_SUPERVISOR_UNAVAILABLE' });
  });

  it('rejects duplicate keys without leaking the first hold', async () => {
    const r = new DiskReservations(statfsWith(100 * GIB), GIB);
    const release = await r.acquire('dup', '/tmp', GIB);
    await expect(r.acquire('dup', '/tmp', GIB)).rejects.toThrow(/duplicate/);
    expect(r.reservedBytes).toBe(GIB);
    release();
    expect(r.reservedBytes).toBe(0);
  });
});
