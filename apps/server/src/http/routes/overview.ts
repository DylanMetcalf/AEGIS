import type {
  ComponentStatusDto,
  CoverageState,
  Criticality,
  Environment,
  IntegrationStatus,
  OverviewDto,
  SetupIssueDto,
  Severity,
} from '@aegis/shared';
import type { FastifyInstance } from 'fastify';
import { authorize } from '../../authz/authorize.js';
import { loadCoverage } from '../../coverage/coverage.js';
import { listAuditEvents } from '../../audit/audit.js';
import type { AuditVerificationState } from '../../health/health.js';
import { checkDatabase, sentinelStatus, workerStatus } from '../../health/health.js';
import { effectiveStatus, type IntegrationRow } from '../../integrations/integrations.js';
import { inTenant, requireActor, type AppDeps } from '../context.js';

/**
 * Overview and component status. Every figure here is computed from stored
 * records. There is no security score, and absent telemetry is reported as
 * not collected rather than as "no threats".
 */
export const overviewRoutes =
  (deps: AppDeps, verification: AuditVerificationState) => async (app: FastifyInstance) => {
    const { pool, config, providers } = deps;

    async function components(): Promise<ComponentStatusDto[]> {
      const db = await checkDatabase(pool);
      return [
        {
          key: 'api',
          label: 'API server',
          required: true,
          state: 'OPERATIONAL',
          observedAt: new Date().toISOString(),
          detail: 'Serving this request',
        },
        ...db.map((c) => ({
          key: c.name,
          label: c.name === 'database' ? 'Database' : 'Database schema',
          required: c.required,
          state: c.state,
          observedAt: c.observedAt,
          detail: c.detail,
        })),
        await workerStatus(pool, config),
        verification.status(),
        sentinelStatus(),
      ];
    }

    app.get('/api/system/status', { config: { auth: 'system.status.read' } }, async () => ({
      generatedAt: new Date().toISOString(),
      components: await components(),
    }));

    app.get(
      '/api/overview',
      { config: { auth: 'tenant.read' } },
      async (req): Promise<OverviewDto> => {
        const actor = requireActor(req);
        const canReadAudit = authorize(actor, 'audit.read', {
          reauthWindowMs: config.session.reauthWindowMs,
        }).allowed;
        const canReadAssets = authorize(actor, 'asset.read', {
          reauthWindowMs: config.session.reauthWindowMs,
        }).allowed;
        const canReadTelemetry = authorize(actor, 'telemetry.read', {
          reauthWindowMs: config.session.reauthWindowMs,
        }).allowed;
        const canReadFindings = authorize(actor, 'finding.read', {
          reauthWindowMs: config.session.reauthWindowMs,
        }).allowed;
        const canReadIntegrations = authorize(actor, 'integration.read', {
          reauthWindowMs: config.session.reauthWindowMs,
        }).allowed;

        const data = await inTenant(deps, req, async (c, tenantId) => {
          const tenant = (
            await c.query<{ id: string; display_name: string }>(
              'SELECT id, display_name FROM tenants WHERE id = $1',
              [tenantId],
            )
          ).rows[0]!;
          const assetCounts = canReadAssets
            ? (
                await c.query<{
                  environment: Environment;
                  criticality: Criticality;
                  n: string;
                  expired: string;
                }>(
                  `SELECT environment, criticality, count(*) AS n,
                      count(*) FILTER (WHERE authorization_scope ? 'expiresAt'
                                         AND authorization_scope->>'expiresAt' IS NOT NULL
                                         AND (authorization_scope->>'expiresAt')::timestamptz < now()) AS expired
                 FROM assets WHERE tenant_id = $1 AND status <> 'DECOMMISSIONED'
                GROUP BY environment, criticality`,
                  [tenantId],
                )
              ).rows
            : [];
          const integrations = canReadIntegrations
            ? (
                await c.query<
                  Pick<IntegrationRow, 'provider' | 'status' | 'last_health_at' | 'updated_at'>
                >(
                  `SELECT provider, status, last_health_at, updated_at FROM integrations WHERE tenant_id = $1 AND status <> 'REVOKED'`,
                  [tenantId],
                )
              ).rows
            : [];
          const recentAudit = canReadAudit
            ? (await listAuditEvents(c, { scope: { tenantId }, limit: 8 })).items
            : null;
          const coverage = canReadAssets
            ? await loadCoverage(c, tenantId, providers, config.health.staleAfterMs)
            : new Map<string, { state: CoverageState }>();
          const telemetryStats = canReadTelemetry
            ? (
                await c.query<{ n: number; last: Date | null }>(
                  `SELECT (SELECT count(*)::int FROM telemetry_events
                            WHERE tenant_id = $1 AND received_at > now() - interval '24 hours') AS n,
                          (SELECT max(last_event_at) FROM integrations WHERE tenant_id = $1) AS last`,
                  [tenantId],
                )
              ).rows[0]!
            : null;
          const openFindings = canReadFindings
            ? (
                await c.query<{ severity: Severity; n: number }>(
                  `SELECT severity, count(*)::int AS n FROM findings
                    WHERE tenant_id = $1 AND status IN ('OPEN', 'TRIAGED', 'IN_PROGRESS') GROUP BY severity`,
                  [tenantId],
                )
              ).rows
            : null;
          return {
            tenant,
            assetCounts,
            integrations,
            recentAudit,
            coverage,
            telemetryStats,
            openFindings,
          };
        });

        const byEnvironment: OverviewDto['assets']['byEnvironment'] = {};
        const byCriticality: OverviewDto['assets']['byCriticality'] = {};
        const byCoverage: OverviewDto['assets']['byCoverage'] = {};
        let totalAssets = 0;
        let expiredScopes = 0;
        for (const r of data.assetCounts) {
          const n = Number(r.n);
          totalAssets += n;
          expiredScopes += Number(r.expired);
          byEnvironment[r.environment] = (byEnvironment[r.environment] ?? 0) + n;
          byCriticality[r.criticality] = (byCriticality[r.criticality] ?? 0) + n;
        }

        for (const v of data.coverage.values())
          byCoverage[v.state] = (byCoverage[v.state] ?? 0) + 1;
        const openBySeverity: Partial<Record<Severity, number>> = {};
        for (const r of data.openFindings ?? []) openBySeverity[r.severity] = r.n;
        const openTotal = (data.openFindings ?? []).reduce((a, r) => a + r.n, 0);
        const lastEventAt = data.telemetryStats?.last ?? null;
        const telemetryFresh =
          lastEventAt !== null && Date.now() - lastEventAt.getTime() <= config.health.staleAfterMs;

        const byEffectiveStatus: Partial<Record<IntegrationStatus | 'STALE', number>> = {};
        let testAdapters = 0;
        for (const i of data.integrations) {
          const provider = providers.get(i.provider);
          if (provider?.testAdapter) testAdapters += 1;
          const s = effectiveStatus(i, config.health.staleAfterMs, provider !== null);
          byEffectiveStatus[s] = (byEffectiveStatus[s] ?? 0) + 1;
        }

        const comps = await components();
        const issues: SetupIssueDto[] = [];
        const worker = comps.find((x) => x.key === 'worker');
        if (worker && worker.state !== 'OPERATIONAL') {
          issues.push({
            code: 'WORKER_NOT_RUNNING',
            severity: 'critical',
            message: `Background worker: ${worker.detail}`,
          });
        }
        if (canReadAssets && totalAssets === 0) {
          issues.push({
            code: 'NO_ASSETS',
            severity: 'info',
            message: 'No assets are registered. AEGIS defends only registered, authorized assets.',
          });
        }
        if (expiredScopes > 0) {
          issues.push({
            code: 'AUTHORIZATION_SCOPE_EXPIRED',
            severity: 'warning',
            message: `${expiredScopes} asset(s) have an expired authorization scope.`,
          });
        }
        if (canReadIntegrations && data.integrations.length === 0) {
          issues.push({
            code: 'NO_INTEGRATIONS',
            severity: 'info',
            message: 'No integrations are configured.',
          });
        }
        const count = (s: IntegrationStatus | 'STALE') => byEffectiveStatus[s] ?? 0;
        if (count('CONFIGURED') > 0) {
          issues.push({
            code: 'INTEGRATIONS_UNCHECKED',
            severity: 'warning',
            message: `${count('CONFIGURED')} integration(s) have never been checked since configuration.`,
          });
        }
        if (count('STALE') > 0) {
          issues.push({
            code: 'INTEGRATIONS_STALE',
            severity: 'warning',
            message: `${count('STALE')} integration(s) have stale health results.`,
          });
        }
        if (count('DISCONNECTED') + count('DEGRADED') + count('UNKNOWN') > 0) {
          issues.push({
            code: 'INTEGRATIONS_UNHEALTHY',
            severity: 'critical',
            message: `${count('DISCONNECTED') + count('DEGRADED') + count('UNKNOWN')} integration(s) are disconnected, degraded, or in an unknown state.`,
          });
        }
        if (testAdapters > 0) {
          issues.push({
            code: 'TEST_ADAPTERS_IN_USE',
            severity: 'info',
            message: `${testAdapters} integration(s) use the simulated test adapter and do not connect to real systems.`,
          });
        }

        return {
          generatedAt: new Date().toISOString(),
          tenant: { id: data.tenant.id, displayName: data.tenant.display_name },
          assets: { total: totalAssets, byEnvironment, byCriticality, byCoverage },
          integrations: { total: data.integrations.length, byEffectiveStatus, testAdapters },
          telemetry: !data.telemetryStats
            ? {
                state: 'UNKNOWN',
                detail: 'Your role cannot view telemetry.',
                eventsLast24h: 0,
                lastEventAt: null,
              }
            : {
                state:
                  lastEventAt === null ? 'UNCONFIGURED' : telemetryFresh ? 'OPERATIONAL' : 'STALE',
                detail:
                  lastEventAt === null
                    ? 'No telemetry has been received. Configure an Event Intake integration. Absence of data is not evidence of safety.'
                    : telemetryFresh
                      ? 'Telemetry is arriving. Detection covers only the event types and rules AEGIS implements.'
                      : 'No recent telemetry. Detection cannot see current activity.',
                eventsLast24h: data.telemetryStats.n,
                lastEventAt: lastEventAt?.toISOString() ?? null,
              },
          findings: !data.openFindings
            ? {
                state: 'UNKNOWN',
                detail: 'Your role cannot view findings.',
                open: 0,
                openBySeverity: {},
              }
            : {
                state: lastEventAt === null ? 'UNCONFIGURED' : 'OPERATIONAL',
                detail:
                  openTotal === 0
                    ? 'No open findings from the implemented rules. This is not proof that no threats exist.'
                    : `${openTotal} open finding(s) require attention.`,
                open: openTotal,
                openBySeverity,
              },
          components: comps,
          setupIssues: issues,
          recentAudit: data.recentAudit,
        };
      },
    );
  };
