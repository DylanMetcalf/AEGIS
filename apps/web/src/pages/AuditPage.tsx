import type { AuditEventDto, AuditOutcome, Page } from '@aegis/shared';
import { useEffect, useState } from 'react';
import { api, ApiError } from '../api/client';
import { useApi } from '../api/useApi';
import { Button } from '../ui/Button';
import { SelectField } from '../ui/Field';
import { EmptyState, ErrorState, Loading } from '../ui/States';
import { StatusBadge } from '../ui/Status';
import { useToast } from '../ui/Toasts';
import { formatDateTime } from '../ui/format';

const OUTCOMES: { value: '' | AuditOutcome; label: string }[] = [
  { value: '', label: 'All outcomes' },
  { value: 'SUCCESS', label: 'Success' },
  { value: 'DENIED', label: 'Denied' },
  { value: 'FAILURE', label: 'Failure' },
];

export function AuditPage() {
  const toast = useToast();
  const [outcome, setOutcome] = useState('');
  const base = `/api/audit-events?limit=50${outcome ? `&outcome=${outcome}` : ''}`;
  const { data, error, loading, reload } = useApi<Page<AuditEventDto>>(base);
  const [extra, setExtra] = useState<AuditEventDto[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);

  useEffect(() => {
    setExtra([]);
    setCursor(data?.nextCursor ?? null);
  }, [data]);

  const more = async () => {
    if (!cursor) return;
    try {
      const page = await api<Page<AuditEventDto>>(`${base}&cursor=${cursor}`);
      setExtra((x) => [...x, ...page.items]);
      setCursor(page.nextCursor);
    } catch (err) {
      toast('crit', err instanceof ApiError ? err.message : 'Could not load more events');
    }
  };
  const items = [...(data?.items ?? []), ...extra];

  return (
    <div className="page">
      <div className="page-header">
        <div className="titles">
          <span className="eyebrow">Govern</span>
          <h1>Audit log</h1>
          <p className="muted small">
            Append-only and hash-chained in the database. The chain detects alteration of recorded
            events; it is not independent of the database administrator (see Known Limitations).
          </p>
        </div>
        <div style={{ width: '12rem' }}>
          <SelectField
            label="Outcome"
            value={outcome}
            onChange={(e) => setOutcome(e.target.value)}
            options={OUTCOMES}
          />
        </div>
      </div>
      {loading && !data && <Loading label="Loading audit events" />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && items.length === 0 && (
        <div className="card">
          <EmptyState title="No events" />
        </div>
      )}
      {items.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <caption className="visually-hidden">Audit events, newest first</caption>
            <thead>
              <tr>
                <th scope="col">#</th>
                <th scope="col">Time</th>
                <th scope="col">Action</th>
                <th scope="col">Outcome</th>
                <th scope="col">Actor</th>
                <th scope="col">Target</th>
                <th scope="col">Detail</th>
              </tr>
            </thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.id}>
                  <td className="id">{e.chainPosition}</td>
                  <td className="small">{formatDateTime(e.occurredAt)}</td>
                  <td className="event-action">{e.action}</td>
                  <td>
                    <StatusBadge state={e.outcome} />
                    {e.reasonCode && <div className="id">{e.reasonCode}</div>}
                  </td>
                  <td className="small">
                    {e.actorType.toLowerCase()}
                    {e.actorPrincipalId && (
                      <div className="id">{e.actorPrincipalId.slice(0, 8)}</div>
                    )}
                  </td>
                  <td className="small">
                    {e.targetType ?? '—'}
                    {e.targetId && <div className="id">{e.targetId.slice(0, 8)}</div>}
                  </td>
                  <td>
                    {Object.keys(e.metadata).length > 0 && (
                      <details>
                        <summary className="small">Metadata</summary>
                        <pre className="id" style={{ whiteSpace: 'pre-wrap', maxWidth: '24rem' }}>
                          {JSON.stringify(e.metadata, null, 2)}
                        </pre>
                      </details>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {cursor && (
        <div className="row" style={{ justifyContent: 'center' }}>
          <Button onClick={() => void more()}>Load older events</Button>
        </div>
      )}
    </div>
  );
}
