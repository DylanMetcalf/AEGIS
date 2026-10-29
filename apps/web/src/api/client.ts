import type { ApiErrorBody } from '@aegis/shared';

/**
 * Same-origin JSON client. The session lives in an HttpOnly cookie that
 * JavaScript cannot read; nothing sensitive is kept in localStorage.
 * Authorization is always decided by the server: this client only reports
 * what the server said.
 */

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
    public readonly requestId: string | null,
    public readonly details: { path: string; message: string }[] = [],
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

type ReauthHandler = () => Promise<boolean>;
type UnauthenticatedHandler = () => void;

let reauthHandler: ReauthHandler | null = null;
let unauthenticatedHandler: UnauthenticatedHandler | null = null;

/** Called when the server requires password confirmation. Resolve true to retry. */
export function setReauthHandler(h: ReauthHandler | null) {
  reauthHandler = h;
}
export function setUnauthenticatedHandler(h: UnauthenticatedHandler | null) {
  unauthenticatedHandler = h;
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  /** Internal: prevents reauth loops. */
  retried?: boolean;
}

async function parseError(res: Response): Promise<ApiError> {
  let body: Partial<ApiErrorBody> | null = null;
  try {
    body = (await res.json()) as ApiErrorBody;
  } catch {
    body = null;
  }
  const e = body?.error;
  return new ApiError(
    res.status,
    e?.code ?? 'HTTP_ERROR',
    e?.message ?? `Request failed (${res.status})`,
    e?.requestId ?? res.headers.get('x-request-id'),
    e?.details ?? [],
  );
}

export async function api<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  if (!path.startsWith('/api/')) throw new Error('API paths must be same-origin /api/ paths');
  const init: RequestInit = {
    method: opts.method ?? 'GET',
    credentials: 'same-origin',
    headers: {
      accept: 'application/json',
      ...(opts.body !== undefined ? { 'content-type': 'application/json' } : {}),
      ...opts.headers,
    },
    signal: opts.signal,
    ...(opts.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
  };
  let res: Response;
  try {
    res = await fetch(path, init);
  } catch (err) {
    if ((err as Error).name === 'AbortError') throw err;
    throw new ApiError(0, 'NETWORK_ERROR', 'The server could not be reached', null);
  }
  if (res.ok) {
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  }
  const error = await parseError(res);
  if (error.code === 'REAUTHENTICATION_REQUIRED' && reauthHandler && !opts.retried) {
    if (await reauthHandler()) return api<T>(path, { ...opts, retried: true });
  }
  if (error.status === 401 && error.code === 'UNAUTHENTICATED') unauthenticatedHandler?.();
  throw error;
}
