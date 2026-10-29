import { z } from 'zod';
import { Errors } from './errors.js';

/**
 * Opaque keyset-pagination cursors: base64url JSON of (sort value, id).
 * Cursors are untrusted input and are validated strictly on the way in.
 */

const cursorSchema = z
  .object({
    v: z.string().max(256),
    i: z.string().uuid(),
  })
  .strict();

export type Cursor = z.infer<typeof cursorSchema>;

export function encodeCursor(c: Cursor): string {
  return Buffer.from(JSON.stringify(c), 'utf8').toString('base64url');
}

export function decodeCursor(raw: string | undefined): Cursor | null {
  if (raw === undefined) return null;
  try {
    if (!/^[A-Za-z0-9_-]{1,512}$/.test(raw)) throw new Error('bad');
    const parsed = cursorSchema.safeParse(
      JSON.parse(Buffer.from(raw, 'base64url').toString('utf8')),
    );
    if (!parsed.success) throw new Error('bad');
    return parsed.data;
  } catch {
    throw Errors.validation([{ path: 'cursor', message: 'Invalid cursor' }]);
  }
}

/** Decode a cursor whose sort value must be an ISO-8601 timestamp. */
export function decodeTimestampCursor(raw: string | undefined): Cursor | null {
  const c = decodeCursor(raw);
  if (c && (!/^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/.test(c.v) || Number.isNaN(Date.parse(c.v)))) {
    throw Errors.validation([{ path: 'cursor', message: 'Invalid cursor' }]);
  }
  return c;
}
