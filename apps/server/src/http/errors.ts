import type { ZodError } from 'zod';

/**
 * Application errors carry a stable machine code and a message that is safe
 * to show to the client. Anything that is not an AppError is reported as a
 * generic internal error; its details go to the server log only.
 */
export class AppError extends Error {
  constructor(
    public readonly statusCode: number,
    public readonly code: string,
    message: string,
    public readonly details?: { path: string; message: string }[],
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export const Errors = {
  validation: (details?: { path: string; message: string }[], message = 'Request validation failed') =>
    new AppError(400, 'VALIDATION_FAILED', message, details),
  unauthenticated: () => new AppError(401, 'UNAUTHENTICATED', 'Authentication required'),
  invalidCredentials: () =>
    new AppError(401, 'INVALID_CREDENTIALS', 'Invalid email or password'),
  forbidden: () => new AppError(403, 'FORBIDDEN', 'You are not permitted to perform this action'),
  reauthRequired: () =>
    new AppError(403, 'REAUTHENTICATION_REQUIRED', 'Confirm your password to continue'),
  csrf: () => new AppError(403, 'ORIGIN_REJECTED', 'Request origin not permitted'),
  notFound: (what = 'Resource') => new AppError(404, 'NOT_FOUND', `${what} not found`),
  conflict: (message = 'The resource was modified or already exists') =>
    new AppError(409, 'CONFLICT', message),
  invalidTransition: (from: string, to: string) =>
    new AppError(409, 'INVALID_STATE_TRANSITION', `Cannot change state from ${from} to ${to}`),
  unsupportedMediaType: () =>
    new AppError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Request body must be application/json'),
  unprocessable: (code: string, message: string) => new AppError(422, code, message),
  rateLimited: () => new AppError(429, 'RATE_LIMITED', 'Too many requests; try again later'),
  dependency: (message = 'A required dependency is unavailable') =>
    new AppError(503, 'DEPENDENCY_UNAVAILABLE', message),
  internal: () => new AppError(500, 'INTERNAL_ERROR', 'An internal error occurred'),
};

export function fromZod(err: ZodError): AppError {
  return Errors.validation(
    err.issues.slice(0, 20).map((i) => ({
      path: i.path.join('.') || '(body)',
      message: i.message,
    })),
  );
}

/** Parse untrusted input with a schema, throwing a safe validation error. */
export function parse<T>(schema: { safeParse(v: unknown): { success: true; data: T } | { success: false; error: ZodError } }, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) throw fromZod(result.error);
  return result.data;
}
