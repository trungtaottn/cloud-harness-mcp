import { timingSafeEqual } from 'node:crypto';

/** Constant-time string equality for bearer-token comparison. */
export function constantTimeEqual(actual: string, expected: string): boolean {
  const left = Buffer.from(actual, 'utf8');
  const right = Buffer.from(expected, 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
}
