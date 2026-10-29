import {
  ASSET_TYPES,
  CRITICALITIES,
  ENVIRONMENTS,
  createAssetRequestSchema,
  type AssetDto,
  type CreateAssetRequest,
} from '@aegis/shared';
import { useState, type FormEvent } from 'react';
import { ApiError } from '../api/client';
import { Button } from '../ui/Button';
import { SelectField, TextAreaField, TextField } from '../ui/Field';
import { Notice } from '../ui/Status';
import { humanize } from '../ui/format';

const opts = (values: readonly string[]) => values.map((v) => ({ value: v, label: humanize(v) }));
const toDate = (iso: string | null | undefined) => (iso ? iso.slice(0, 10) : '');

interface Props {
  initial?: AssetDto;
  submitLabel: string;
  onSubmit: (body: CreateAssetRequest) => Promise<void>;
  onCancel: () => void;
}

/** Shared create/edit form. Client validation mirrors the server's schema; the server remains authoritative. */
export function AssetForm({ initial, submitLabel, onSubmit, onCancel }: Props) {
  const [v, setV] = useState({
    name: initial?.name ?? '',
    assetType: initial?.assetType ?? 'APPLICATION',
    environment: initial?.environment ?? 'PRODUCTION',
    criticality: initial?.criticality ?? 'MEDIUM',
    description: initial?.description ?? '',
    statement: initial?.authorizationScope.statement ?? '',
    identifiers: initial?.authorizationScope.identifiers.join('\n') ?? '',
    authorizedBy: initial?.authorizationScope.authorizedBy ?? '',
    authorizedAt:
      toDate(initial?.authorizationScope.authorizedAt) || new Date().toISOString().slice(0, 10),
    expiresAt: toDate(initial?.authorizationScope.expiresAt),
  });
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof v) => (e: { target: { value: string } }) =>
    setV({ ...v, [k]: e.target.value });

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setFormError(null);
    const body = {
      name: v.name,
      assetType: v.assetType,
      environment: v.environment,
      criticality: v.criticality,
      ...(v.description ? { description: v.description } : {}),
      authorizationScope: {
        statement: v.statement,
        identifiers: v.identifiers
          .split(/[\n,]/)
          .map((s) => s.trim())
          .filter(Boolean),
        authorizedBy: v.authorizedBy,
        authorizedAt: v.authorizedAt ? new Date(`${v.authorizedAt}T00:00:00Z`).toISOString() : '',
        expiresAt: v.expiresAt ? new Date(`${v.expiresAt}T23:59:59Z`).toISOString() : null,
      },
    };
    const parsed = createAssetRequestSchema.safeParse(body);
    if (!parsed.success) {
      const next: Record<string, string> = {};
      for (const issue of parsed.error.issues) {
        const key = String(issue.path.at(-1) ?? 'form');
        next[key] ??= issue.message;
      }
      setErrors(next);
      return;
    }
    setErrors({});
    setBusy(true);
    try {
      await onSubmit(parsed.data);
    } catch (err) {
      if (err instanceof ApiError) {
        const next: Record<string, string> = {};
        for (const d of err.details) next[d.path.split('.').at(-1) ?? 'form'] = d.message;
        setErrors(next);
        setFormError(err.message);
      } else setFormError('Could not save the asset');
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="stack" noValidate>
      {formError && <Notice tone="crit">{formError}</Notice>}
      <TextField
        label="Name"
        value={v.name}
        onChange={set('name')}
        error={errors.name}
        required
        maxLength={200}
      />
      <div className="form-grid">
        <SelectField
          label="Type"
          value={v.assetType}
          onChange={set('assetType')}
          options={opts(ASSET_TYPES)}
        />
        <SelectField
          label="Environment"
          value={v.environment}
          onChange={set('environment')}
          options={opts(ENVIRONMENTS)}
        />
        <SelectField
          label="Criticality"
          value={v.criticality}
          onChange={set('criticality')}
          options={opts(CRITICALITIES)}
        />
      </div>
      <TextAreaField
        label="Description"
        value={v.description}
        onChange={set('description')}
        error={errors.description}
        maxLength={2000}
      />
      <fieldset
        className="stack"
        style={{
          border: 'var(--border-width) solid var(--color-border)',
          borderRadius: 'var(--radius-md)',
          padding: 'var(--space-4)',
        }}
      >
        <legend className="eyebrow" style={{ padding: '0 var(--space-2)' }}>
          Authorization scope
        </legend>
        <p className="small muted">
          State exactly what AEGIS is authorized to observe and defend for this asset, and who
          authorized it.
        </p>
        <TextAreaField
          label="Authorization statement"
          value={v.statement}
          onChange={set('statement')}
          error={errors.statement}
          required
        />
        <TextAreaField
          label="In-scope identifiers"
          hint="One per line: hostnames, repository names, account IDs"
          value={v.identifiers}
          onChange={set('identifiers')}
          error={errors.identifiers}
          required
        />
        <div className="form-grid">
          <TextField
            label="Authorized by"
            value={v.authorizedBy}
            onChange={set('authorizedBy')}
            error={errors.authorizedBy}
            required
          />
          <TextField
            label="Authorized on"
            type="date"
            value={v.authorizedAt}
            onChange={set('authorizedAt')}
            error={errors.authorizedAt}
            required
          />
          <TextField
            label="Authorization expires"
            type="date"
            value={v.expiresAt}
            onChange={set('expiresAt')}
            error={errors.expiresAt}
          />
        </div>
      </fieldset>
      <div className="form-actions">
        <Button variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" loading={busy}>
          {submitLabel}
        </Button>
      </div>
    </form>
  );
}
