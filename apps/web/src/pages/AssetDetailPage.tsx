import { assetStateMachine, type AssetDto, type AssetStatus } from '@aegis/shared';
import { useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { api, ApiError } from '../api/client';
import { useApi } from '../api/useApi';
import { useSession } from '../auth/SessionContext';
import { Button } from '../ui/Button';
import { ConfirmDialog } from '../ui/ConfirmDialog';
import { Drawer } from '../ui/Modal';
import { ErrorState, Loading } from '../ui/States';
import { Notice, StatusBadge } from '../ui/Status';
import { useToast } from '../ui/Toasts';
import { formatDateTime, humanize } from '../ui/format';
import { AssetForm } from './AssetForm';

export function AssetDetailPage() {
  const { id = '' } = useParams();
  const { can } = useSession();
  const toast = useToast();
  const navigate = useNavigate();
  const {
    data: asset,
    error,
    loading,
    reload,
  } = useApi<AssetDto>(`/api/assets/${encodeURIComponent(id)}`);
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [busy, setBusy] = useState(false);

  if (loading && !asset) return <Loading label="Loading asset" />;
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (!asset) return null;

  const fail = (err: unknown) =>
    toast('crit', err instanceof ApiError ? err.message : 'Request failed');

  const transition = async (status: AssetStatus) => {
    setBusy(true);
    try {
      await api(`/api/assets/${asset.id}`, {
        method: 'PATCH',
        body: { version: asset.version, status },
      });
      toast('ok', `Asset marked ${humanize(status).toLowerCase()}`);
      reload();
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    setBusy(true);
    try {
      await api(`/api/assets/${asset.id}`, { method: 'DELETE' });
      toast('ok', `Deleted ${asset.name}`);
      navigate('/assets');
    } catch (err) {
      fail(err);
      setDeleting(false);
    } finally {
      setBusy(false);
    }
  };

  const nextStates = assetStateMachine.transitions[asset.status];
  const scope = asset.authorizationScope;
  const expired = scope.expiresAt ? Date.parse(scope.expiresAt) < Date.now() : false;
  const sensitive = asset.environment === 'PRODUCTION' || asset.criticality === 'CRITICAL';

  return (
    <div className="page">
      <nav aria-label="Breadcrumb" className="small">
        <Link to="/assets">Assets</Link> <span className="subtle">/</span>{' '}
        <span className="muted">{asset.name}</span>
      </nav>
      <div className="page-header">
        <div className="titles">
          <h1>{asset.name}</h1>
          <div className="row">
            <StatusBadge state={asset.status} />
            <StatusBadge
              state={asset.criticality}
              label={`${humanize(asset.criticality)} criticality`}
            />
            <span className="badge tone-neutral">{humanize(asset.environment)}</span>
          </div>
        </div>
        {can('asset.update') && asset.status !== 'DECOMMISSIONED' && (
          <Button onClick={() => setEditing(true)}>Edit</Button>
        )}
        {can('asset.update') &&
          nextStates.map((s) => (
            <Button
              key={s}
              onClick={() => void transition(s)}
              loading={busy}
              variant={s === 'DECOMMISSIONED' ? 'danger' : 'secondary'}
            >
              {s === 'ACTIVE' ? 'Reactivate' : s === 'INACTIVE' ? 'Mark inactive' : 'Decommission'}
            </Button>
          ))}
        {can('asset.delete') && (
          <Button variant="danger" onClick={() => setDeleting(true)}>
            Delete
          </Button>
        )}
      </div>

      {expired && (
        <Notice tone="warn" title="Authorization expired.">
          This asset’s authorization scope expired on {formatDateTime(scope.expiresAt)}.
        </Notice>
      )}

      <div className="grid grid-2">
        <section className="card" aria-labelledby="details-h">
          <div className="card-header">
            <h2 id="details-h">Details</h2>
          </div>
          <dl className="kv">
            <dt>Type</dt>
            <dd>{humanize(asset.assetType)}</dd>
            <dt>Environment</dt>
            <dd>{humanize(asset.environment)}</dd>
            <dt>Coverage</dt>
            <dd>
              <StatusBadge state={asset.coverageState} />{' '}
              <span className="small subtle">Coverage is computed from Phase 2 onward.</span>
            </dd>
            <dt>Description</dt>
            <dd style={{ whiteSpace: 'pre-wrap' }}>
              {asset.description || <span className="subtle">—</span>}
            </dd>
            <dt>Created</dt>
            <dd>{formatDateTime(asset.createdAt)}</dd>
            <dt>Updated</dt>
            <dd>
              {formatDateTime(asset.updatedAt)}{' '}
              <span className="subtle small">· version {asset.version}</span>
            </dd>
            <dt>ID</dt>
            <dd className="id">{asset.id}</dd>
          </dl>
        </section>
        <section className="card" aria-labelledby="scope-h">
          <div className="card-header">
            <h2 id="scope-h">Authorization scope</h2>
          </div>
          <dl className="kv">
            <dt>Statement</dt>
            <dd style={{ whiteSpace: 'pre-wrap' }}>{scope.statement}</dd>
            <dt>Identifiers</dt>
            <dd>
              <ul style={{ margin: 0, paddingLeft: '1.1rem' }}>
                {scope.identifiers.map((i) => (
                  <li key={i}>
                    <code>{i}</code>
                  </li>
                ))}
              </ul>
            </dd>
            <dt>Authorized by</dt>
            <dd>{scope.authorizedBy}</dd>
            <dt>Authorized on</dt>
            <dd>{formatDateTime(scope.authorizedAt)}</dd>
            <dt>Expires</dt>
            <dd>
              {scope.expiresAt ? (
                formatDateTime(scope.expiresAt)
              ) : (
                <span className="subtle">No expiry set</span>
              )}
            </dd>
          </dl>
        </section>
      </div>

      <Drawer open={editing} title={`Edit ${asset.name}`} onClose={() => setEditing(false)}>
        {editing && (
          <AssetForm
            initial={asset}
            submitLabel="Save changes"
            onCancel={() => setEditing(false)}
            onSubmit={async (body) => {
              await api(`/api/assets/${asset.id}`, {
                method: 'PATCH',
                body: { ...body, description: body.description ?? null, version: asset.version },
              });
              setEditing(false);
              toast('ok', 'Asset updated');
              reload();
            }}
          />
        )}
      </Drawer>

      <ConfirmDialog
        open={deleting}
        title={`Delete ${asset.name}?`}
        description={
          sensitive
            ? 'This is a production or critical asset. Deleting it removes it from the registry permanently and requires password confirmation. The audit log keeps a record.'
            : 'This removes the asset from the registry permanently. The audit log keeps a record.'
        }
        confirmLabel="Delete asset"
        typeToConfirm={sensitive ? asset.name : undefined}
        destructive
        busy={busy}
        onConfirm={() => void remove()}
        onCancel={() => setDeleting(false)}
      />
    </div>
  );
}
