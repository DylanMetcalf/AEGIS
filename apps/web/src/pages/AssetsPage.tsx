import { ASSET_TYPES, ENVIRONMENTS, type AssetDto, type Page } from '@aegis/shared';
import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api, ApiError } from '../api/client';
import { useApi } from '../api/useApi';
import { useSession } from '../auth/SessionContext';
import { Button } from '../ui/Button';
import { SelectField } from '../ui/Field';
import { Drawer } from '../ui/Modal';
import { EmptyState, ErrorState, Loading } from '../ui/States';
import { StatusBadge } from '../ui/Status';
import { useToast } from '../ui/Toasts';
import { formatDateTime, humanize } from '../ui/format';
import { AssetForm } from './AssetForm';

const all = (values: readonly string[], label: string) => [
  { value: '', label },
  ...values.map((v) => ({ value: v, label: humanize(v) })),
];

export function AssetsPage() {
  const { can } = useSession();
  const toast = useToast();
  const navigate = useNavigate();
  const [filters, setFilters] = useState({ environment: '', assetType: '' });
  const [creating, setCreating] = useState(false);
  const query = new URLSearchParams({
    limit: '25',
    ...Object.fromEntries(Object.entries(filters).filter(([, v]) => v)),
  });
  const { data, error, loading, reload } = useApi<Page<AssetDto>>(`/api/assets?${query}`);
  const [extra, setExtra] = useState<AssetDto[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);

  useEffect(() => {
    setExtra([]);
    setCursor(data?.nextCursor ?? null);
  }, [data]);

  const loadMore = async () => {
    if (!cursor) return;
    setLoadingMore(true);
    try {
      const page = await api<Page<AssetDto>>(
        `/api/assets?${query}&cursor=${encodeURIComponent(cursor)}`,
      );
      setExtra((x) => [...x, ...page.items]);
      setCursor(page.nextCursor);
    } catch (err) {
      toast('crit', err instanceof ApiError ? err.message : 'Could not load more assets');
    } finally {
      setLoadingMore(false);
    }
  };

  const items = [...(data?.items ?? []), ...extra];

  return (
    <div className="page">
      <div className="page-header">
        <div className="titles">
          <span className="eyebrow">Operate</span>
          <h1>Assets</h1>
          <p className="muted small">
            Applications, APIs, repositories and infrastructure that AEGIS is authorized to defend.
          </p>
        </div>
        {can('asset.create') && (
          <Button variant="primary" onClick={() => setCreating(true)}>
            Register asset
          </Button>
        )}
      </div>

      <div className="row" role="search" aria-label="Filter assets">
        <div style={{ width: '12rem' }}>
          <SelectField
            label="Environment"
            value={filters.environment}
            options={all(ENVIRONMENTS, 'All environments')}
            onChange={(e) => setFilters({ ...filters, environment: e.target.value })}
          />
        </div>
        <div style={{ width: '12rem' }}>
          <SelectField
            label="Type"
            value={filters.assetType}
            options={all(ASSET_TYPES, 'All types')}
            onChange={(e) => setFilters({ ...filters, assetType: e.target.value })}
          />
        </div>
      </div>

      {loading && !data && <Loading label="Loading assets" />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && items.length === 0 && (
        <div className="card">
          <EmptyState
            title="No assets registered"
            action={
              can('asset.create') ? (
                <Button onClick={() => setCreating(true)}>Register your first asset</Button>
              ) : undefined
            }
          >
            AEGIS only defends assets that are registered with an explicit authorization scope.
          </EmptyState>
        </div>
      )}
      {items.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <caption className="visually-hidden">Registered assets</caption>
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Type</th>
                <th scope="col">Environment</th>
                <th scope="col">Criticality</th>
                <th scope="col">Status</th>
                <th scope="col">Coverage</th>
                <th scope="col">Updated</th>
              </tr>
            </thead>
            <tbody>
              {items.map((a) => (
                <tr key={a.id}>
                  <td>
                    <Link to={`/assets/${a.id}`}>{a.name}</Link>
                  </td>
                  <td className="small">{humanize(a.assetType)}</td>
                  <td className="small">{humanize(a.environment)}</td>
                  <td>
                    <StatusBadge state={a.criticality} />
                  </td>
                  <td>
                    <StatusBadge state={a.status} />
                  </td>
                  <td>
                    <StatusBadge state={a.coverageState} />
                  </td>
                  <td className="small subtle">{formatDateTime(a.updatedAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {cursor && (
        <div className="row" style={{ justifyContent: 'center' }}>
          <Button onClick={() => void loadMore()} loading={loadingMore}>
            Load more
          </Button>
        </div>
      )}

      <Drawer open={creating} title="Register asset" onClose={() => setCreating(false)}>
        {creating && (
          <AssetForm
            submitLabel="Register asset"
            onCancel={() => setCreating(false)}
            onSubmit={async (body) => {
              const created = await api<AssetDto>('/api/assets', { method: 'POST', body });
              setCreating(false);
              toast('ok', `Registered ${created.name}`);
              reload();
              navigate(`/assets/${created.id}`);
            }}
          />
        )}
      </Drawer>
    </div>
  );
}
