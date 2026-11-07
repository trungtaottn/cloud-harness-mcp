import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

/**
 * Deterministic JSON serialization with recursively sorted object keys, used
 * so HMAC request digests are stable regardless of caller key ordering.
 * Only JSON-safe values are supported; callers must not pass undefined,
 * functions, BigInt or cyclic structures.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = sortValue((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}

const KEY_HEX = /^[0-9a-f]{64}$/;

/**
 * Supervisor-local HMAC-SHA256 key for request/environment digests. The key
 * lives in a dedicated 0600 file inside the supervisor state directory — it
 * is never journaled, logged, or exposed through any RPC surface. Idempotency
 * records store only the keyed digest, so journal contents cannot be used to
 * recover environment values.
 */
export class RequestDigester {
  private readonly key: Buffer;

  constructor(keyFilePath: string) {
    this.key = loadOrCreateKey(keyFilePath);
  }

  /** HMAC-SHA256 hex digest of the canonical serialization of `payload`. */
  digest(payload: unknown): string {
    return createHmac('sha256', this.key).update(canonicalJson(payload), 'utf8').digest('hex');
  }

  /** Constant-time comparison helper for digest equality checks. */
  static digestsEqual(a: string, b: string): boolean {
    const left = Buffer.from(a, 'utf8');
    const right = Buffer.from(b, 'utf8');
    return left.length === right.length && timingSafeEqual(left, right);
  }
}

function loadOrCreateKey(path: string): Buffer {
  if (existsSync(path)) {
    const raw = readFileSync(path, 'utf8').trim();
    if (!KEY_HEX.test(raw)) {
      throw new Error(`HMAC key file ${path} is malformed; refusing to continue`);
    }
    return Buffer.from(raw, 'hex');
  }
  mkdirSync(dirname(path), { recursive: true });
  const key = randomBytes(32);
  writeFileSync(path, key.toString('hex') + '\n', { mode: 0o600 });
  try {
    chmodSync(path, 0o600);
  } catch {
    // chmod may be a no-op on filesystems without POSIX modes; the file was
    // created 0600 already and the state dir itself is root-only.
  }
  return key;
}
