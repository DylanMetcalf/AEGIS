import {
  TENANT_ROLES,
  newPasswordSchema,
  type MemberDto,
  type SessionSummary,
  type TenantRole,
} from '@aegis/shared';
import { useState, type FormEvent } from 'react';
import { api, ApiError } from '../api/client';
import { useApi } from '../api/useApi';
import { useSession } from '../auth/SessionContext';
import { Button } from '../ui/Button';
import { SelectField, TextField } from '../ui/Field';
import { ErrorState, Loading } from '../ui/States';
import { Notice, StatusBadge } from '../ui/Status';
import { useToast } from '../ui/Toasts';
import { formatDateTime, formatRelative, humanize } from '../ui/format';

const HUMAN_ROLES = TENANT_ROLES.filter((r) => r !== 'SERVICE' && r !== 'AI_WORKER').map((r) => ({
  value: r,
  label: humanize(r),
}));

export function SettingsPage() {
  const { can, session } = useSession();
  return (
    <div className="page">
      <div className="page-header">
        <div className="titles">
          <span className="eyebrow">Govern</span>
          <h1>Settings</h1>
        </div>
      </div>
      <div className="grid grid-2">
        <PasswordCard />
        <SessionsCard />
      </div>
      {session?.activeTenant && can('membership.read') && <MembersCard />}
      {can('platform.tenant.read') && <PlatformCard />}
    </div>
  );
}

function PasswordCard() {
  const toast = useToast();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const check = newPasswordSchema.safeParse(next);
    if (!check.success) return setError(check.error.issues[0]?.message ?? 'Invalid password');
    setBusy(true);
    setError(null);
    try {
      const res = await api<{ otherSessionsRevoked: number }>('/api/auth/password', {
        method: 'POST',
        body: { currentPassword: current, newPassword: next },
      });
      setCurrent('');
      setNext('');
      toast('ok', `Password changed. ${res.otherSessionsRevoked} other session(s) signed out.`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not change password');
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="card" aria-labelledby="pw-h">
      <div className="card-header">
        <h2 id="pw-h">Change password</h2>
      </div>
      <form className="stack" onSubmit={submit} noValidate>
        <TextField
          label="Current password"
          type="password"
          autoComplete="current-password"
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
          required
        />
        <TextField
          label="New password"
          type="password"
          autoComplete="new-password"
          value={next}
          onChange={(e) => setNext(e.target.value)}
          hint="At least 12 characters. Changing it signs out your other sessions."
          error={error}
          required
        />
        <div className="form-actions">
          <Button type="submit" variant="primary" loading={busy} disabled={!current || !next}>
            Change password
          </Button>
        </div>
      </form>
    </section>
  );
}

function SessionsCard() {
  const toast = useToast();
  const { logout } = useSession();
  const { data, error, loading, reload } = useApi<{ items: SessionSummary[] }>('/api/sessions');
  const revoke = async (id: string) => {
    try {
      await api(`/api/sessions/${id}`, { method: 'DELETE' });
      toast('ok', 'Session signed out');
      reload();
    } catch (err) {
      toast('crit', err instanceof ApiError ? err.message : 'Could not revoke session');
    }
  };
  const all = async () => {
    try {
      await api('/api/auth/logout-all', { method: 'POST' });
    } finally {
      await logout();
    }
  };
  return (
    <section className="card" aria-labelledby="sess-h">
      <div className="card-header">
        <h2 id="sess-h">Active sessions</h2>
        <span className="spacer" />
        <Button size="sm" variant="danger" onClick={() => void all()}>
          Sign out everywhere
        </Button>
      </div>
      {loading && !data && <Loading />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && (
        <ul className="stack-sm" style={{ listStyle: 'none', margin: 0, padding: 0 }}>
          {data.items.map((s) => (
            <li key={s.id} className="row" style={{ flexWrap: 'nowrap' }}>
              <div className="stack-sm" style={{ flex: 1, gap: 0, minWidth: 0 }}>
                <span
                  className="small"
                  style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                >
                  {s.userAgent ?? 'Unknown client'}
                </span>
                <span className="small subtle">
                  Active {formatRelative(s.lastSeenAt)} · expires {formatDateTime(s.expiresAt)}
                </span>
              </div>
              {s.current ? (
                <span className="badge tone-info">This session</span>
              ) : (
                <Button size="sm" onClick={() => void revoke(s.id)}>
                  Sign out
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function MembersCard() {
  const { can, session } = useSession();
  const toast = useToast();
  const { data, error, loading, reload } = useApi<{ items: MemberDto[] }>('/api/members');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState<TenantRole>('READ_ONLY_ANALYST');
  const [busy, setBusy] = useState(false);
  const manage = can('membership.manage');

  const add = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api('/api/members', { method: 'POST', body: { email, role } });
      setEmail('');
      toast('ok', 'Member added');
      reload();
    } catch (err) {
      toast('crit', err instanceof ApiError ? err.message : 'Could not add member');
    } finally {
      setBusy(false);
    }
  };
  const update = async (m: MemberDto, body: Record<string, string>) => {
    try {
      await api(`/api/members/${m.id}`, { method: 'PATCH', body });
      toast('ok', 'Membership updated');
      reload();
    } catch (err) {
      toast('crit', err instanceof ApiError ? err.message : 'Could not update membership');
      reload();
    }
  };

  return (
    <section className="card stack" aria-labelledby="mem-h">
      <div className="card-header" style={{ marginBottom: 0 }}>
        <h2 id="mem-h">Members of {session?.activeTenant?.displayName}</h2>
      </div>
      {manage && (
        <form className="row" onSubmit={add} style={{ alignItems: 'flex-end' }} noValidate>
          <div style={{ flex: '1 1 16rem' }}>
            <TextField
              label="Email of an existing account"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>
          <div style={{ width: '14rem' }}>
            <SelectField
              label="Role"
              value={role}
              onChange={(e) => setRole(e.target.value as TenantRole)}
              options={HUMAN_ROLES}
            />
          </div>
          <Button type="submit" variant="primary" loading={busy} disabled={!email}>
            Add member
          </Button>
        </form>
      )}
      {manage && <p className="small subtle">Membership changes require password confirmation.</p>}
      {loading && !data && <Loading />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && (
        <div className="table-wrap">
          <table className="table">
            <caption className="visually-hidden">Tenant members</caption>
            <thead>
              <tr>
                <th scope="col">Member</th>
                <th scope="col">Role</th>
                <th scope="col">Status</th>
                <th scope="col">Since</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((m) => (
                <tr key={m.id}>
                  <td>
                    {m.displayName}
                    <div className="small subtle">
                      {m.email ?? `${m.kind.toLowerCase()} identity`}
                    </div>
                  </td>
                  <td>
                    {manage && m.kind === 'HUMAN' ? (
                      <select
                        className="select"
                        aria-label={`Role for ${m.displayName}`}
                        value={m.role}
                        onChange={(e) => void update(m, { role: e.target.value })}
                      >
                        {HUMAN_ROLES.map((r) => (
                          <option key={r.value} value={r.value}>
                            {r.label}
                          </option>
                        ))}
                      </select>
                    ) : (
                      humanize(m.role)
                    )}
                  </td>
                  <td>
                    {manage ? (
                      <select
                        className="select"
                        aria-label={`Status for ${m.displayName}`}
                        value={m.status}
                        onChange={(e) => void update(m, { status: e.target.value })}
                      >
                        <option value="ACTIVE">Active</option>
                        <option value="SUSPENDED">Suspended</option>
                        <option value="REMOVED">Removed</option>
                      </select>
                    ) : (
                      <StatusBadge state={m.status} />
                    )}
                  </td>
                  <td className="small subtle">{formatDateTime(m.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

interface ChainResult {
  verified: boolean;
  eventsChecked: number;
  firstInvalidPosition: string | null;
  reason: string | null;
  headPosition: string | null;
  headHash: string | null;
  verifiedAt: string;
}

function PlatformCard() {
  const toast = useToast();
  const { can, refresh } = useSession();
  const { data, error, loading, reload } = useApi<{
    items: { id: string; slug: string; displayName: string; status: string; createdAt: string }[];
  }>('/api/platform/tenants');
  const [slug, setSlug] = useState('');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [chain, setChain] = useState<ChainResult | null>(null);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api('/api/platform/tenants', { method: 'POST', body: { slug, displayName: name } });
      setSlug('');
      setName('');
      toast('ok', 'Tenant created; you were added as its administrator');
      reload();
      void refresh();
    } catch (err) {
      toast('crit', err instanceof ApiError ? err.message : 'Could not create tenant');
    } finally {
      setBusy(false);
    }
  };
  const verify = async () => {
    try {
      setChain(await api<ChainResult>('/api/platform/audit/verify', { method: 'POST' }));
    } catch (err) {
      toast('crit', err instanceof ApiError ? err.message : 'Verification failed to run');
    }
  };

  return (
    <section className="card stack" aria-labelledby="plat-h">
      <div className="card-header" style={{ marginBottom: 0 }}>
        <h2 id="plat-h">Platform administration</h2>
        <span className="badge tone-violet tone-foundation">System owner</span>
      </div>
      <p className="small muted">
        Platform administration manages tenants. It does not grant access to any tenant’s data.
      </p>
      {can('platform.audit.verify') && (
        <div className="stack-sm">
          <div className="row">
            <Button onClick={() => void verify()}>Verify audit chain</Button>
            {chain && (
              <StatusBadge
                state={chain.verified ? 'OPERATIONAL' : 'FAILED'}
                label={chain.verified ? 'Chain intact' : 'Chain broken'}
              />
            )}
          </div>
          {chain && (
            <p className="small muted">
              {chain.eventsChecked} events checked at {formatDateTime(chain.verifiedAt)}.
              {chain.verified ? (
                <>
                  {' '}
                  Head #{chain.headPosition}:{' '}
                  <code style={{ overflowWrap: 'anywhere' }}>{chain.headHash}</code>. Record this
                  value outside AEGIS to detect later truncation.
                </>
              ) : (
                <>
                  {' '}
                  First invalid event #{chain.firstInvalidPosition} ({chain.reason}).
                </>
              )}
            </p>
          )}
          {chain && !chain.verified && (
            <Notice tone="crit">
              The audit log has been altered. Treat the platform as compromised and follow the
              incident procedure.
            </Notice>
          )}
        </div>
      )}
      {can('platform.tenant.manage') && (
        <form className="row" onSubmit={create} style={{ alignItems: 'flex-end' }} noValidate>
          <div style={{ width: '12rem' }}>
            <TextField
              label="Slug"
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              hint="e.g. acme-corp"
              required
            />
          </div>
          <div style={{ flex: '1 1 14rem' }}>
            <TextField
              label="Display name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>
          <Button type="submit" variant="primary" loading={busy} disabled={!slug || !name}>
            Create tenant
          </Button>
        </form>
      )}
      {loading && !data && <Loading />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && (
        <ul className="stack-sm" style={{ listStyle: 'none', margin: 0, padding: 0 }}>
          {data.items.map((t) => (
            <li key={t.id} className="row">
              <strong className="small">{t.displayName}</strong>
              <code className="small subtle">{t.slug}</code>
              <StatusBadge state={t.status} />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
