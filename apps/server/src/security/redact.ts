/**
 * Redaction for anything that leaves the request path: audit metadata,
 * structured logs, and error details. Key-based, recursive, and bounded.
 */

const SENSITIVE_KEY =
  /pass(word|phrase)?|secret|token|credential(?!_?ref)|authorization|cookie|api[-_]?key|private[-_]?key|bearer|signature/i;

const MAX_DEPTH = 6;
const MAX_STRING = 500;
const MAX_ARRAY = 50;
const MAX_KEYS = 50;

export const REDACTED = '[REDACTED]';

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY.test(key);
}

export function redact(value: unknown, depth = 0): unknown {
  if (value === null || value === undefined) return value ?? null;
  if (typeof value === 'string') {
    return value.length > MAX_STRING ? `${value.slice(0, MAX_STRING)}…[truncated]` : value;
  }
  if (typeof value === 'number' || typeof value === 'boolean') return value;
  if (typeof value === 'bigint') return value.toString();
  if (value instanceof Date) return value.toISOString();
  if (depth >= MAX_DEPTH) return '[MAX_DEPTH]';
  if (Array.isArray(value)) {
    return value.slice(0, MAX_ARRAY).map((v) => redact(v, depth + 1));
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>).slice(0, MAX_KEYS)) {
      out[k] = isSensitiveKey(k) ? REDACTED : redact(v, depth + 1);
    }
    return out;
  }
  return `[${typeof value}]`;
}

/** Pino redaction paths for request logging. */
export const LOG_REDACT_PATHS = [
  'req.headers.cookie',
  'req.headers.authorization',
  'req.headers["x-api-key"]',
  'res.headers["set-cookie"]',
  '*.password',
  '*.currentPassword',
  '*.newPassword',
  '*.token',
  '*.secret',
  '*.credential',
];
