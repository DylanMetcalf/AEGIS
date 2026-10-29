import type { OverviewDto } from '@aegis/shared';
import { Link } from 'react-router-dom';
import { useApi } from '../api/useApi';
import { ErrorState, Loading } from '../ui/States';
import { Notice, StatusBadge } from '../ui/Status';
import { formatRelative, humanize } from '../ui/format';

/** States render as status badges; plain categories (environment) as neutral labels without a status glyph. */
function Breakdown({
  data,
  categorical = false,
}: {
  data: Partial<Record<string, number>>;
  categorical?: boolean;
}) {
  const entries = Object.entries(data).filter(([, n]) => (n ?? 0) > 0);
  if (entries.length === 0) return <span className="small subtle">None</span>;
  return (
    <ul className="row" style={{ listStyle: 'none', margin: 0, padding: 0, gap: 'var(--space-2)' }}>
      {entries.map(([k, n]) => (
        <li key={k}>
          {categorical ? (
            <span className="badge tone-neutral">{`${humanize(k)} · ${n}`}</span>
          ) : (
            <StatusBadge state={k} label={`${humanize(k)} · ${n}`} />
          )}
        </li>
      ))}
    </ul>
  );
}

export function OverviewPage() {
  const { data, error, loading, reload } = useApi<OverviewDto>('/api/overview');

  return (
    <div className="page">
      <div className="page-header">
        <div className="titles">
          <span className="eyebrow">Overview</span>
          <h1>{data?.tenant.displayName ?? 'Overview'}</h1>
          <p className="muted small">
            Everything on this page is computed from records AEGIS holds. There is no security
            score: no scoring methodology exists yet.
          </p>
        </div>
      </div>

      {loading && !data && <Loading label="Loading overview" />}
      {error && <ErrorState error={error} onRetry={reload} />}

      {data && (
        <>
          <Notice tone="foundation" title="Security telemetry is not collected yet.">
            {data.telemetry.detail} {data.findings.detail}
          </Notice>

          <section aria-labelledby="sys-heading" className="card">
            <div className="card-header">
              <h2 id="sys-heading">Platform components</h2>
              <span className="spacer" />
              <span className="small subtle">Updated {formatRelative(data.generatedAt)}</span>
            </div>
            <div className="table-wrap" style={{ border: 'none' }}>
              <table className="table">
                <caption className="visually-hidden">Status of platform components</caption>
                <thead>
                  <tr>
                    <th scope="col">Component</th>
                    <th scope="col">State</th>
                    <th scope="col">Detail</th>
                    <th scope="col">Observed</th>
                  </tr>
                </thead>
                <tbody>
                  {data.components.map((c) => (
                    <tr key={c.key}>
                      <td>
                        {c.label}
                        {c.required && <span className="subtle small"> · required</span>}
                      </td>
                      <td>
                        <StatusBadge state={c.state} />
                      </td>
                      <td className="small muted">{c.detail}</td>
                      <td className="small subtle">
                        {c.observedAt ? formatRelative(c.observedAt) : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <div className="grid grid-4">
            <section className="card stat" aria-labelledby="assets-stat">
              <span className="eyebrow" id="assets-stat">
                Registered assets
              </span>
              <span className="stat-value">{data.assets.total}</span>
              <Breakdown data={data.assets.byEnvironment} categorical />
              <Link to="/assets" className="small">
                View assets →
              </Link>
            </section>
            <section className="card stat" aria-labelledby="coverage-stat">
              <span className="eyebrow" id="coverage-stat">
                Asset coverage
              </span>
              <Breakdown data={data.assets.byCoverage} />
              <span className="small subtle">
                Coverage computation arrives in Phase 2; all assets report Unknown.
              </span>
            </section>
            <section className="card stat" aria-labelledby="int-stat">
              <span className="eyebrow" id="int-stat">
                Integrations
              </span>
              <span className="stat-value">{data.integrations.total}</span>
              <Breakdown data={data.integrations.byEffectiveStatus} />
              <Link to="/integrations" className="small">
                View integrations →
              </Link>
            </section>
            <section className="card stat" aria-labelledby="crit-stat">
              <span className="eyebrow" id="crit-stat">
                Assets by criticality
              </span>
              <Breakdown data={data.assets.byCriticality} />
            </section>
          </div>

          <div className="grid grid-2">
            <section className="card" aria-labelledby="issues-heading">
              <div className="card-header">
                <h2 id="issues-heading">Setup and configuration</h2>
              </div>
              {data.setupIssues.length === 0 ? (
                <p className="small muted">
                  No outstanding setup items were detected by the checks that exist today.
                </p>
              ) : (
                <ul className="stack-sm" style={{ listStyle: 'none', margin: 0, padding: 0 }}>
                  {data.setupIssues.map((i) => (
                    <li
                      key={i.code}
                      className="row"
                      style={{ alignItems: 'flex-start', flexWrap: 'nowrap' }}
                    >
                      <StatusBadge state={i.severity} />
                      <span className="small">{i.message}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
            <section className="card" aria-labelledby="audit-heading">
              <div className="card-header">
                <h2 id="audit-heading">Recent audit activity</h2>
                <span className="spacer" />
                {data.recentAudit && (
                  <Link to="/audit" className="small">
                    Audit log →
                  </Link>
                )}
              </div>
              {data.recentAudit === null ? (
                <p className="small muted">Your role does not include audit access.</p>
              ) : data.recentAudit.length === 0 ? (
                <p className="small muted">No events recorded for this tenant yet.</p>
              ) : (
                <ul className="stack-sm" style={{ listStyle: 'none', margin: 0, padding: 0 }}>
                  {data.recentAudit.map((e) => (
                    <li key={e.id} className="row" style={{ flexWrap: 'nowrap' }}>
                      <StatusBadge state={e.outcome} />
                      <span className="event-action">{e.action}</span>
                      <span className="spacer" />
                      <span className="small subtle">{formatRelative(e.occurredAt)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        </>
      )}
    </div>
  );
}
