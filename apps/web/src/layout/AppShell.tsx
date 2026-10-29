import { PRODUCT_MODULES, type ProductModule } from '@aegis/shared';
import { NavLink, Outlet, useNavigate } from 'react-router-dom';
import { useSession } from '../auth/SessionContext';
import { Button } from '../ui/Button';
import { Logo } from '../ui/Logo';
import { statusLabel } from '../ui/Status';
import { useToast } from '../ui/Toasts';

const GROUPS: { key: ProductModule['group']; label: string }[] = [
  { key: 'operate', label: 'Operate' },
  { key: 'defend', label: 'Defend' },
  { key: 'assure', label: 'Assure' },
  { key: 'govern', label: 'Govern' },
];

export function AppShell() {
  const { session, logout, selectTenant } = useSession();
  const navigate = useNavigate();
  const toast = useToast();
  if (!session) return null;

  const switchTenant = async (tenantId: string) => {
    try {
      await selectTenant(tenantId);
      navigate('/');
    } catch {
      toast('crit', 'Could not switch tenant');
    }
  };

  return (
    <div className="shell">
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <aside className="sidebar">
        <NavLink to="/" className="brand" aria-label="AEGIS home">
          <Logo />
          AEGIS
        </NavLink>
        <nav className="nav" aria-label="Primary">
          {GROUPS.map((g) => (
            <div key={g.key} className="nav-group">
              <div className="eyebrow" id={`nav-${g.key}`}>
                {g.label}
              </div>
              <ul aria-labelledby={`nav-${g.key}`}>
                {PRODUCT_MODULES.filter((m) => m.group === g.key).map((m) => (
                  <li key={m.key}>
                    <NavLink to={m.path} end={m.path === '/'}>
                      {m.label}
                      {m.state !== 'OPERATIONAL' && (
                        <span className="nav-state" title={statusLabel(m.state)}>
                          {m.state === 'FOUNDATION_ONLY' ? 'foundation' : `phase ${m.phase}`}
                        </span>
                      )}
                    </NavLink>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>
      </aside>
      <header className="header">
        {session.memberships.length > 1 ? (
          <label className="row small">
            <span className="muted">Tenant</span>
            <select
              className="select"
              style={{ width: 'auto', minHeight: '2rem' }}
              value={session.activeTenant?.id ?? ''}
              onChange={(e) => void switchTenant(e.target.value)}
            >
              {!session.activeTenant && <option value="">Select…</option>}
              {session.memberships.map((m) => (
                <option key={m.tenantId} value={m.tenantId}>
                  {m.displayName}
                </option>
              ))}
            </select>
          </label>
        ) : (
          <span className="small muted">
            {session.activeTenant?.displayName ?? 'No tenant selected'}
          </span>
        )}
        {session.activeTenant && (
          <span className="badge tone-info">{session.activeTenant.role.replace(/_/g, ' ')}</span>
        )}
        <div className="spacer" />
        <span className="small muted" title={session.principal.email ?? undefined}>
          {session.principal.displayName}
          {session.principal.platformRole && <span className="subtle"> · system owner</span>}
        </span>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => void logout().then(() => navigate('/login'))}
        >
          Sign out
        </Button>
      </header>
      <main id="main" className="main" tabIndex={-1}>
        <Outlet />
      </main>
    </div>
  );
}
