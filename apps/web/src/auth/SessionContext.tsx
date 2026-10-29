import type { SessionInfo } from '@aegis/shared';
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { api, ApiError, setReauthHandler, setUnauthenticatedHandler } from '../api/client';
import { ReauthDialog } from './ReauthDialog';

interface SessionContextValue {
  session: SessionInfo | null;
  status: 'loading' | 'authenticated' | 'anonymous' | 'error';
  error: ApiError | null;
  refresh: () => Promise<void>;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  selectTenant: (tenantId: string) => Promise<void>;
  /** UI hint only. The server enforces every capability on every request. */
  can: (capability: string) => boolean;
}

const SessionContext = createContext<SessionContextValue | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [status, setStatus] = useState<SessionContextValue['status']>('loading');
  const [error, setError] = useState<ApiError | null>(null);
  const [reauthOpen, setReauthOpen] = useState(false);
  const reauthResolver = useRef<((ok: boolean) => void) | null>(null);

  const refresh = useCallback(async () => {
    try {
      const s = await api<SessionInfo>('/api/session');
      setSession(s);
      setStatus('authenticated');
      setError(null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setSession(null);
        setStatus('anonymous');
      } else {
        setError(err instanceof ApiError ? err : null);
        setStatus('error');
      }
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    setUnauthenticatedHandler(() => {
      setSession(null);
      setStatus('anonymous');
    });
    setReauthHandler(
      () =>
        new Promise<boolean>((resolve) => {
          reauthResolver.current = resolve;
          setReauthOpen(true);
        }),
    );
    return () => {
      setUnauthenticatedHandler(null);
      setReauthHandler(null);
    };
  }, []);

  const finishReauth = useCallback(
    (ok: boolean) => {
      setReauthOpen(false);
      reauthResolver.current?.(ok);
      reauthResolver.current = null;
      if (ok) void refresh();
    },
    [refresh],
  );

  const value = useMemo<SessionContextValue>(
    () => ({
      session,
      status,
      error,
      refresh,
      login: async (email, password) => {
        await api('/api/auth/login', { method: 'POST', body: { email, password } });
        await refresh();
      },
      logout: async () => {
        try {
          await api('/api/auth/logout', { method: 'POST' });
        } finally {
          setSession(null);
          setStatus('anonymous');
        }
      },
      selectTenant: async (tenantId) => {
        await api('/api/session/tenant', { method: 'PUT', body: { tenantId } });
        await refresh();
      },
      can: (capability) => session?.capabilities.includes(capability) ?? false,
    }),
    [session, status, error, refresh],
  );

  return (
    <SessionContext.Provider value={value}>
      {children}
      <ReauthDialog open={reauthOpen} onDone={finishReauth} />
    </SessionContext.Provider>
  );
}

export function useSession(): SessionContextValue {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error('useSession must be used inside SessionProvider');
  return ctx;
}
