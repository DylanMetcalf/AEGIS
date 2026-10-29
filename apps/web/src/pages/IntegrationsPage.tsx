import type { IntegrationDto, Page, ProviderDto } from '@aegis/shared';
import { useState, type FormEvent } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api, ApiError } from '../api/client';
import { useApi } from '../api/useApi';
import { useSession } from '../auth/SessionContext';
import { Button } from '../ui/Button';
import { SelectField, TextField } from '../ui/Field';
import { Drawer } from '../ui/Modal';
import { EmptyState, ErrorState, Loading } from '../ui/States';
import { Notice, StatusBadge } from '../ui/Status';
import { useToast } from '../ui/Toasts';
import { formatRelative } from '../ui/format';

export function IntegrationsPage() {
  const { can } = useSession();
  const { data, error, loading, reload } = useApi<Page<IntegrationDto>>(
    '/api/integrations?limit=100',
  );
  const [creating, setCreating] = useState(false);

  return (
    <div className="page">
      <div className="page-header">
        <div className="titles">
          <span className="eyebrow">Operate</span>
          <h1>Integrations</h1>
          <p className="muted small">
            Connections to external systems. An integration is only reported connected after a
            successful check, and results go stale.
          </p>
        </div>
        {can('integration.manage') && (
          <Button variant="primary" onClick={() => setCreating(true)}>
            Add integration
          </Button>
        )}
      </div>

      {loading && !data && <Loading label="Loading integrations" />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && data.items.length === 0 && (
        <div className="card">
          <EmptyState title="No integrations configured">
            Phase 1 provides an HTTPS endpoint probe and a simulated test adapter. Further providers
            arrive in later phases.
          </EmptyState>
        </div>
      )}
      {data && data.items.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <caption className="visually-hidden">Configured integrations</caption>
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Provider</th>
                <th scope="col">Status</th>
                <th scope="col">Last check</th>
                <th scope="col">Capabilities</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((i) => (
                <tr key={i.id}>
                  <td>
                    <Link to={`/integrations/${i.id}`}>{i.name}</Link>
                  </td>
                  <td className="small">
                    {i.providerDisplayName}
                    {i.testAdapter && (
                      <>
                        {' '}
                        <span className="badge tone-foundation">Simulated</span>
                      </>
                    )}
                  </td>
                  <td>
                    <StatusBadge state={i.effectiveStatus} />
                    {i.lastErrorCode && <div className="id">{i.lastErrorCode}</div>}
                  </td>
                  <td className="small subtle">{formatRelative(i.lastHealthAt)}</td>
                  <td className="small muted">
                    {i.availableCapabilities.length
                      ? i.availableCapabilities.join(', ')
                      : 'None usable'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Drawer open={creating} title="Add integration" onClose={() => setCreating(false)}>
        {creating && <CreateIntegration onDone={() => setCreating(false)} onCreated={reload} />}
      </Drawer>
    </div>
  );
}

function CreateIntegration({ onDone, onCreated }: { onDone: () => void; onCreated: () => void }) {
  const { can } = useSession();
  const toast = useToast();
  const navigate = useNavigate();
  const {
    data: providers,
    error,
    loading,
  } = useApi<{ items: ProviderDto[] }>('/api/integration-providers');
  const [providerId, setProviderId] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [config, setConfig] = useState<Record<string, string>>({});
  const [permissions, setPermissions] = useState<string[]>([]);
  const [credentialRef, setCredentialRef] = useState('');
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (loading) return <Loading label="Loading providers" />;
  if (error) return <ErrorState error={error} />;
  const provider = providers?.items.find((p) => p.id === providerId) ?? null;

  if (!provider) {
    return (
      <div className="stack">
        <p className="small muted">
          Choose a provider. Each declares exactly what it can do and which permissions it needs.
        </p>
        {providers?.items.map((p) => (
          <button
            key={p.id}
            type="button"
            className="card stack-sm"
            style={{ textAlign: 'left', cursor: 'pointer', font: 'inherit', color: 'inherit' }}
            onClick={() => {
              setProviderId(p.id);
              setPermissions(p.permissions.map((x) => x.key));
            }}
          >
            <span className="row">
              <strong>{p.displayName}</strong>
              {p.testAdapter && (
                <span className="badge tone-foundation">Simulated · not a real connection</span>
              )}
            </span>
            <span className="small muted">{p.description}</span>
          </button>
        ))}
      </div>
    );
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setErrors({});
    setFormError(null);
    const typedConfig: Record<string, unknown> = {};
    for (const f of provider.configFields) {
      const raw = config[f.key];
      if (raw === undefined || raw === '') continue;
      typedConfig[f.key] = f.type === 'number' ? Number(raw) : raw;
    }
    try {
      const created = await api<IntegrationDto>('/api/integrations', {
        method: 'POST',
        body: {
          provider: provider.id,
          name,
          config: typedConfig,
          grantedPermissions: permissions,
          ...(credentialRef ? { credentialRef } : {}),
        },
      });
      toast('ok', `Added ${created.name}. Run a health check to establish its status.`);
      onCreated();
      onDone();
      navigate(`/integrations/${created.id}`);
    } catch (err) {
      if (err instanceof ApiError) {
        const next: Record<string, string> = {};
        for (const d of err.details) next[d.path.replace(/^config\./, '')] = d.message;
        setErrors(next);
        setFormError(err.message);
      } else setFormError('Could not create the integration');
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="stack" onSubmit={submit} noValidate>
      <div className="row">
        <strong>{provider.displayName}</strong>
        {provider.testAdapter && <span className="badge tone-foundation">Simulated</span>}
        <span className="spacer" />
        <Button size="sm" variant="ghost" onClick={() => setProviderId(null)}>
          Change provider
        </Button>
      </div>
      {provider.testAdapter && (
        <Notice tone="foundation">
          This adapter simulates outcomes for testing. It never contacts an external system.
        </Notice>
      )}
      {formError && <Notice tone="crit">{formError}</Notice>}
      <TextField
        label="Name"
        value={name}
        onChange={(e) => setName(e.target.value)}
        error={errors.name}
        required
      />
      {provider.configFields.map((f) =>
        f.type === 'enum' ? (
          <SelectField
            key={f.key}
            label={f.label}
            value={config[f.key] ?? ''}
            onChange={(e) => setConfig({ ...config, [f.key]: e.target.value })}
            options={[
              { value: '', label: 'Select…' },
              ...(f.options ?? []).map((o) => ({ value: o, label: o })),
            ]}
            error={errors[f.key]}
            hint={f.help}
            required={f.required}
          />
        ) : (
          <TextField
            key={f.key}
            label={f.label}
            type={f.type === 'number' ? 'number' : f.type === 'url' ? 'url' : 'text'}
            value={config[f.key] ?? ''}
            onChange={(e) => setConfig({ ...config, [f.key]: e.target.value })}
            error={errors[f.key]}
            hint={f.help}
            required={f.required}
          />
        ),
      )}
      <fieldset className="stack-sm" style={{ border: 'none', padding: 0, margin: 0 }}>
        <legend
          className="field"
          style={{ fontSize: 'var(--text-sm)', fontWeight: 500, marginBottom: 'var(--space-2)' }}
        >
          Granted permissions
        </legend>
        {provider.permissions.map((p) => (
          <label
            key={p.key}
            className="row small"
            style={{ flexWrap: 'nowrap', alignItems: 'flex-start' }}
          >
            <input
              type="checkbox"
              checked={permissions.includes(p.key)}
              onChange={(e) =>
                setPermissions(
                  e.target.checked
                    ? [...permissions, p.key]
                    : permissions.filter((x) => x !== p.key),
                )
              }
            />
            <span>
              <code>{p.key}</code> <span className="muted">— {p.description}</span>
            </span>
          </label>
        ))}
        {errors.grantedPermissions && (
          <span className="error small">{errors.grantedPermissions}</span>
        )}
      </fieldset>
      {provider.supportsCredential && can('integration.credential.manage') && (
        <TextField
          label="Credential reference (optional)"
          value={credentialRef}
          onChange={(e) => setCredentialRef(e.target.value)}
          error={errors.credentialRef}
          placeholder="env:AEGIS_SECRET_EXAMPLE_TOKEN"
          hint="A reference to a server-side secret, never the secret itself. Only AEGIS_SECRET_* variables can be referenced."
          autoComplete="off"
          spellCheck={false}
        />
      )}
      <div className="form-actions">
        <Button variant="ghost" onClick={onDone}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" loading={busy} disabled={!name}>
          Add integration
        </Button>
      </div>
    </form>
  );
}
