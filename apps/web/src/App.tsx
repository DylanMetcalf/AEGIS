import { PRODUCT_MODULES } from '@aegis/shared';
import type { ReactNode } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { useSession } from './auth/SessionContext';
import { AppShell } from './layout/AppShell';
import { AssetDetailPage } from './pages/AssetDetailPage';
import { AssetsPage } from './pages/AssetsPage';
import { AuditPage } from './pages/AuditPage';
import { IntegrationDetailPage } from './pages/IntegrationDetailPage';
import { IntegrationsPage } from './pages/IntegrationsPage';
import { LoginPage } from './pages/LoginPage';
import { ModuleStatusPage } from './pages/ModuleStatusPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { OverviewPage } from './pages/OverviewPage';
import { SettingsPage } from './pages/SettingsPage';
import { TenantSelectPage } from './pages/TenantSelectPage';
import { ErrorState, Loading } from './ui/States';

/** Client-side route guard. A UX convenience only: the API enforces authentication. */
function RequireSession({ children }: { children: ReactNode }) {
  const { status, error, refresh } = useSession();
  const location = useLocation();
  if (status === 'loading') return <Loading label="Checking your session" />;
  if (status === 'error' && error)
    return <ErrorState error={error} onRetry={() => void refresh()} />;
  if (status !== 'authenticated')
    return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <>{children}</>;
}

/** Tenant-scoped pages need an active tenant. */
function RequireTenant({ children }: { children: ReactNode }) {
  const { session } = useSession();
  return session?.activeTenant ? <>{children}</> : <TenantSelectPage />;
}

const IMPLEMENTED = new Set(['overview', 'assets', 'integrations', 'audit', 'settings']);

export function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireSession>
            <AppShell />
          </RequireSession>
        }
      >
        <Route
          index
          element={
            <RequireTenant>
              <OverviewPage />
            </RequireTenant>
          }
        />
        <Route
          path="assets"
          element={
            <RequireTenant>
              <AssetsPage />
            </RequireTenant>
          }
        />
        <Route
          path="assets/:id"
          element={
            <RequireTenant>
              <AssetDetailPage />
            </RequireTenant>
          }
        />
        <Route
          path="integrations"
          element={
            <RequireTenant>
              <IntegrationsPage />
            </RequireTenant>
          }
        />
        <Route
          path="integrations/:id"
          element={
            <RequireTenant>
              <IntegrationDetailPage />
            </RequireTenant>
          }
        />
        <Route
          path="audit"
          element={
            <RequireTenant>
              <AuditPage />
            </RequireTenant>
          }
        />
        <Route path="settings" element={<SettingsPage />} />
        {PRODUCT_MODULES.filter((m) => !IMPLEMENTED.has(m.key)).map((m) => (
          <Route key={m.key} path={m.path.slice(1)} element={<ModuleStatusPage module={m} />} />
        ))}
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
