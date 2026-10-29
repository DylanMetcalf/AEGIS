import { useSession } from '../auth/SessionContext';
import { Button } from '../ui/Button';
import { EmptyState } from '../ui/States';
import { useToast } from '../ui/Toasts';

/** Shown when the session has no active tenant. */
export function TenantSelectPage() {
  const { session, selectTenant, can } = useSession();
  const toast = useToast();
  if (!session) return null;
  return (
    <div className="page">
      <div className="page-header">
        <div className="titles">
          <h1>Choose a tenant</h1>
          <p className="muted">Tenant data is isolated. Select which tenant to work in.</p>
        </div>
      </div>
      {session.memberships.length === 0 ? (
        <div className="card">
          <EmptyState title="You are not a member of any tenant">
            {can('platform.tenant.manage')
              ? 'As a system owner you can create tenants from Settings. Platform roles do not grant access to tenant data.'
              : 'Ask a tenant administrator to add you.'}
          </EmptyState>
        </div>
      ) : (
        <ul className="grid grid-2" style={{ listStyle: 'none', padding: 0, margin: 0 }}>
          {session.memberships.map((m) => (
            <li key={m.tenantId} className="card row">
              <div className="stack-sm" style={{ flex: 1 }}>
                <strong>{m.displayName}</strong>
                <span className="small muted">
                  {m.slug} · {m.role.replace(/_/g, ' ').toLowerCase()}
                </span>
              </div>
              <Button
                variant="primary"
                onClick={() =>
                  selectTenant(m.tenantId).catch(() => toast('crit', 'Could not select tenant'))
                }
              >
                Open
              </Button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
