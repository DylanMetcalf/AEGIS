import type { ReactNode } from 'react';
import type { ApiError } from '../api/client';
import { Button } from './Button';

export function Loading({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="loading" role="status" aria-live="polite" aria-busy="true">
      <span className="visually-hidden">{label}…</span>
      <div className="stack-sm" style={{ width: 'min(28rem, 100%)' }} aria-hidden="true">
        <div className="skeleton" />
        <div className="skeleton" style={{ width: '80%' }} />
        <div className="skeleton" style={{ width: '60%' }} />
      </div>
    </div>
  );
}

export function EmptyState({
  title,
  children,
  action,
}: {
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <h3>{title}</h3>
      {children && <div className="small">{children}</div>}
      {action && <div style={{ marginTop: 'var(--space-3)' }}>{action}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  const title =
    error.status === 403
      ? 'You do not have access to this'
      : error.status === 404
        ? 'Not found'
        : error.status === 0
          ? 'Server unreachable'
          : 'Something went wrong';
  return (
    <div className="error-state" role="alert">
      <h3>
        <span aria-hidden="true">✕ </span>
        {title}
      </h3>
      <p className="small">{error.message}</p>
      {error.requestId && <p className="id">Request ID {error.requestId}</p>}
      {onRetry && error.status !== 403 && (
        <Button size="sm" onClick={onRetry} style={{ marginTop: 'var(--space-3)' }}>
          Try again
        </Button>
      )}
    </div>
  );
}
