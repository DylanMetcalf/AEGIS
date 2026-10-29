import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/** 256-bit random token, base64url encoded. */
export function generateToken(): string {
  return randomBytes(32).toString('base64url');
}

export function sha256(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

export function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Session tokens are base64url of 32 bytes: exactly 43 characters. */
export function isWellFormedToken(value: string): boolean {
  return /^[A-Za-z0-9_-]{43}$/.test(value);
}
