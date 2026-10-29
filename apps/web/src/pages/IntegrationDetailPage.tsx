import type { HealthCheckDto, IntegrationDto, JobDto, ProviderDto } from '@aegis/shared';
import { useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { api, ApiError } from '../api/client';
import { useApi } from '../api/useApi';
import { useSession } from '../auth/SessionContext';
import { Button } from '../ui/Button';
import { ConfirmDialog } from '../ui/ConfirmDialog';
import { ErrorState, Loading } from '../ui/States';
import { Notice, StatusBadge } from '../ui/Status';
import { useToast } from '../ui/Toasts';
import { formatDateTime, formatRelative } from '../ui/format';

const TERMINAL = new Set(['SUCCEEDED', 'FAILED', 'CANCELLED']);

export function IntegrationDetailPage() {
  const { id = '' } = useParams();
  const { can } = useSession();
  const toast = useToast();
  const { data, error, loading, reload } = useApi<{
    integration: IntegrationDto;
    healthChecks: HealthCheckDto[];
  }>(`/api/integrations/${encodeURIComponent(id)}`);
  const { data: providers } = useApi<{ items: ProviderDto[] }>('/api/integration-providers');
  const [checking, setChecking] = useState<JobDto | null>(null);
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [busy, setBusy] = useState(false);

  if (loading && !data) return <Loading label="Loading integration" />;
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (!data) return null;
  const i = data.integration;
  const provider = providers?.items.find((p) => p.id === i.provider);
  const fail = (err: unknown) =>
    toast('crit', err instanceof ApiError ? err.message : 'Request failed');

  const runCheck = async () => {
    try {
      let job = await api<JobDto>(`/api/integrations/${i.id}/health-checks`, { method: 'POST' });
      setChecking(job);
      for (let n = 0; n < 40 && !TERMINAL.has(job.status); n++) {
        await new Promise((r) => setTimeout(r, 1000));
        job = await api<JobDto>(`/api/jobs/${job.id}`);
        setChecking(job);
      }
      if (!TERMINAL.has(job.status))
        toast('info', 'The check is still queued. Is the background worker running?');
      else if (job.status !== 'SUCCEEDED')
        toast(
          'crit',
          `Health check ${job.status.toLowerCase()}: ${job.lastErrorCode ?? 'unknown error'}`,
        );
      reload();
    } catch (err) {
      fail(err);
    } finally {
      setChecking(null);
    }
  };

  const transition = async (action: 'suspend' | 'resume' | 'revoke') => {
    setBusy(true);
    try {
      await api(`/api/integrations/${i.id}/${action}`, {
        method: 'POST',
        body: { version: i.version },
      });
      toast(
        'ok',
        `Integration ${action === 'revoke' ? 'revoked' : action === 'suspend' ? 'suspended' : 'resumed'}`,
      );
      reload();
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
      setConfirmRevoke(false);
    }
  };

  return (
    <div className="page">
      <nav aria-label="Breadcrumb" className="small">
        <Link to="/integrations">Integrations</Link> <span className="subtle">/</span>{' '}
        <span className="muted">{i.name}</span>
      </nav>
      <div className="page-header">
        <div className="titles">
          <h1>{i.name}</h1>
          <div className="row">
            <StatusBadge state={i.effectiveStatus} />
            <span className="small muted">{i.providerDisplayName}</span>
            {i.testAdapter && (
              <span className="badge tone-foundation">Simulated · not a real connection</span>
            )}
          </div>
        </div>
        {can('integration.health_check') && i.status !== 'REVOKED' && i.status !== 'SUSPENDED' && (
          <Button variant="primary" onClick={() => void runCheck()} loading={checking !== null}>
            {checking ? `Check ${checking.status.toLowerCase()}…` : 'Run health check'}
          </Button>
        )}
        {can('integration.manage') &&
          ['CONFIGURED', 'CONNECTED', 'DEGRADED', 'DISCONNECTED', 'UNKNOWN'].includes(i.status) && (
            <Button onClick={() => void transition('suspend')} loading={busy}>
              Suspend
            </Button>
          )}
        {can('integration.manage') && i.status === 'SUSPENDED' && (
          <Button onClick={() => void transition('resume')} loading={busy}>
            Resume
          </Button>
        )}
        {can('integration.revoke') && i.status !== 'REVOKED' && (
          <Button variant="danger" onClick={() => setConfirmRevoke(true)}>
            Revoke
          </Button>
        )}
      </div>

      {i.effectiveStatus === 'STALE' && (
        <Notice tone="warn" title="Health result is stale.">
          The last check was {formatRelative(i.lastHealthAt)}. Its result no longer describes
          current state.
        </Notice>
      )}
      {i.status === 'CONFIGURED' && (
        <Notice tone="info" title="Not yet checked.">
          Configuration alone does not establish connectivity. Run a health check.
        </Notice>
      )}
      {i.status === 'REVOKED' && (
        <Notice tone="neutral" title="Revoked.">
          This integration is permanently disabled. Its credential reference and permissions were
          removed.
        </Notice>
      )}

      <div className="grid grid-2">
        <section className="card" aria-labelledby="cfg-h">
          <div className="card-header">
            <h2 id="cfg-h">Configuration</h2>
            <span className="spacer" />
            <span className="small subtle">version {i.configVersion}</span>
          </div>
          <dl className="kv">
            {Object.entries(i.config).map(([k, v]) => (
              <div key={k} style={{ display: 'contents' }}>
                <dt>{k}</dt>
                <dd>
                  <code>{String(v)}</code>
                </dd>
              </div>
            ))}
            <dt>Credential</dt>
            <dd>
              {i.credentialRef ? (
                <code>{i.credentialRef}</code>
              ) : (
                <span className="subtle">None</span>
              )}
            </dd>
            <dt>Last check</dt>
            <dd>
              {i.lastHealthAt ? (
                formatDateTime(i.lastHealthAt)
              ) : (
                <span className="subtle">Never</span>
              )}
              {i.lastErrorCode && <div className="id">{i.lastErrorCode}</div>}
            </dd>
          </dl>
        </section>
        <section className="card" aria-labelledby="cap-h">
          <div className="card-header">
            <h2 id="cap-h">Capabilities</h2>
          </div>
          <table className="table">
            <caption className="visually-hidden">
              Declared capabilities and whether they are usable
            </caption>
            <thead>
              <tr>
                <th scope="col">Capability</th>
                <th scope="col">Requires</th>
                <th scope="col">Usable</th>
              </tr>
            </thead>
            <tbody>
              {(provider?.capabilities ?? []).map((c) => {
                const usable = i.availableCapabilities.includes(c.key);
                return (
                  <tr key={c.key}>
                    <td>
                      <code>{c.key}</code>
                      <div className="small muted">{c.description}</div>
                    </td>
                    <td className="small">{c.requiredPermissions.join(', ') || '—'}</td>
                    <td>
                      {!c.implemented ? (
                        <StatusBadge state="NOT_IMPLEMENTED" />
                      ) : usable ? (
                        <StatusBadge state="ACTIVE" label="Usable" />
                      ) : (
                        <StatusBadge state="UNCONFIGURED" label="Permission not granted" />
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </section>
      </div>

      <section className="card" aria-labelledby="hist-h">
        <div className="card-header">
          <h2 id="hist-h">Health check history</h2>
        </div>
        {data.healthChecks.length === 0 ? (
          <p className="small muted">No checks have run.</p>
        ) : (
          <table className="table">
            <caption className="visually-hidden">Recent health checks</caption>
            <thead>
              <tr>
                <th scope="col">Observed</th>
                <th scope="col">Result</th>
                <th scope="col">Latency</th>
                <th scope="col">Error</th>
                <th scope="col">Config</th>
              </tr>
            </thead>
            <tbody>
              {data.healthChecks.map((h) => (
                <tr key={h.id}>
                  <td className="small">{formatDateTime(h.observedAt)}</td>
                  <td>
                    <StatusBadge state={h.result} />
                  </td>
                  <td className="small">{h.latencyMs === null ? '—' : `${h.latencyMs} ms`}</td>
                  <td className="id">{h.errorCode ?? '—'}</td>
                  <td className="small subtle">v{h.configVersion}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <ConfirmDialog
        open={confirmRevoke}
        title={`Revoke ${i.name}?`}
        description="Revocation is permanent. The credential reference and granted permissions are removed and the integration can never run again."
        confirmLabel="Revoke integration"
        typeToConfirm={i.name}
        destructive
        busy={busy}
        onConfirm={() => void transition('revoke')}
        onCancel={() => setConfirmRevoke(false)}
      />
    </div>
  );
}
