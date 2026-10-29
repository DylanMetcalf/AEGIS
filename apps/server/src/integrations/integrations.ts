import {
  integrationStateMachine,
  type HealthCheckDto,
  type HealthCheckResult,
  type IntegrationDto,
  type IntegrationStatus,
} from '@aegis/shared';
import type { DbClient } from '../db/pool.js';
import { decodeTimestampCursor, encodeCursor } from '../http/cursor.js';
import { Errors } from '../http/errors.js';
import type { UrlPolicy } from '../security/safe-http.js';
import { ProviderConfigError } from './providers/types.js';
import { availableCapabilities, unknownPermissions, type ProviderRegistry } from './registry.js';

export interface IntegrationRow {
  id: string;
  tenant_id: string;
  name: string;
  provider: string;
  status: IntegrationStatus;
  config: Record<string, unknown>;
  config_version: number;
  credential_ref: string | null;
  declared_capabilities: string[];
  granted_permissions: string[];
  asset_id: string | null;
  last_health_status: HealthCheckResult | null;
  last_health_at: Date | null;
  last_error_code: string | null;
  revoked_at: Date | null;
  version: number;
  created_at: Date;
  updated_at: Date;
}

const COLUMNS = `id, tenant_id, name, provider, status, config, config_version, credential_ref,
  declared_capabilities, granted_permissions, asset_id, last_health_status, last_health_at,
  last_error_code, revoked_at, version, created_at, updated_at`;

const HEALTH_STATES: readonly IntegrationStatus[] = [
  'CONNECTED',
  'DEGRADED',
  'DISCONNECTED',
  'UNKNOWN',
];

export function effectiveStatus(
  row: Pick<IntegrationRow, 'status' | 'last_health_at'>,
  staleAfterMs: number,
  providerAvailable: boolean,
  now = new Date(),
): IntegrationStatus | 'STALE' {
  if (!providerAvailable && row.status !== 'REVOKED') return 'UNKNOWN';
  if (HEALTH_STATES.includes(row.status)) {
    if (!row.last_health_at || now.getTime() - row.last_health_at.getTime() > staleAfterMs) {
      return 'STALE';
    }
  }
  return row.status;
}

export function toIntegrationDto(
  row: IntegrationRow,
  providers: ProviderRegistry,
  staleAfterMs: number,
): IntegrationDto {
  const provider = providers.get(row.provider);
  return {
    id: row.id,
    name: row.name,
    provider: row.provider,
    providerDisplayName: provider?.displayName ?? `${row.provider} (provider unavailable)`,
    testAdapter: provider?.testAdapter ?? false,
    status: row.status,
    effectiveStatus: effectiveStatus(row, staleAfterMs, provider !== null),
    config: row.config,
    configVersion: row.config_version,
    hasCredential: row.credential_ref !== null,
    credentialRef: row.credential_ref,
    declaredCapabilities: row.declared_capabilities,
    grantedPermissions: row.granted_permissions,
    availableCapabilities: provider ? availableCapabilities(provider, row.granted_permissions) : [],
    assetId: row.asset_id,
    lastHealthStatus: row.last_health_status,
    lastHealthAt: row.last_health_at?.toISOString() ?? null,
    lastErrorCode: row.last_error_code,
    version: row.version,
    createdAt: row.created_at.toISOString(),
    updatedAt: row.updated_at.toISOString(),
  };
}

export async function getIntegration(
  client: DbClient,
  tenantId: string,
  id: string,
  opts: { forUpdate?: boolean } = {},
): Promise<IntegrationRow | null> {
  const { rows } = await client.query<IntegrationRow>(
    `SELECT ${COLUMNS} FROM integrations WHERE tenant_id = $1 AND id = $2${opts.forUpdate ? ' FOR UPDATE' : ''}`,
    [tenantId, id],
  );
  return rows[0] ?? null;
}

export async function listIntegrations(
  client: DbClient,
  tenantId: string,
  opts: { limit: number; cursor?: string },
): Promise<{ rows: IntegrationRow[]; nextCursor: string | null }> {
  const cursor = decodeTimestampCursor(opts.cursor);
  const params: unknown[] = [tenantId];
  let where = 'tenant_id = $1';
  if (cursor) {
    params.push(cursor.v, cursor.i);
    where += ' AND (created_at, id) < ($2::timestamptz, $3::uuid)';
  }
  params.push(opts.limit + 1);
  const { rows } = await client.query<IntegrationRow>(
    `SELECT ${COLUMNS} FROM integrations WHERE ${where}
      ORDER BY created_at DESC, id DESC LIMIT $${params.length}`,
    params,
  );
  const page = rows.slice(0, opts.limit);
  const last = page.at(-1);
  return {
    rows: page,
    nextCursor:
      rows.length > opts.limit && last
        ? encodeCursor({ v: last.created_at.toISOString(), i: last.id })
        : null,
  };
}

function validateProviderInput(
  providers: ProviderRegistry,
  providerId: string,
  config: unknown,
  credentialRef: string | null | undefined,
  grantedPermissions: string[],
  network: UrlPolicy,
) {
  const provider = providers.get(providerId);
  if (!provider) {
    throw Errors.unprocessable(
      'UNSUPPORTED_PROVIDER',
      'This integration provider is not available',
    );
  }
  let normalized: unknown;
  try {
    normalized = provider.validateConfig(config, network);
  } catch (err) {
    if (err instanceof ProviderConfigError) {
      throw Errors.validation(
        err.issues.map((i) => ({ path: `config.${i.path}`, message: i.message })),
      );
    }
    throw err;
  }
  if (credentialRef && !provider.supportsCredential) {
    throw Errors.validation([
      { path: 'credentialRef', message: 'Provider does not accept credentials' },
    ]);
  }
  const unknown = unknownPermissions(provider, grantedPermissions);
  if (unknown.length > 0) {
    throw Errors.validation([
      {
        path: 'grantedPermissions',
        message: `Unknown permissions for provider: ${unknown.join(', ')}`,
      },
    ]);
  }
  return { provider, config: normalized as Record<string, unknown> };
}

async function assertAssetInTenant(client: DbClient, tenantId: string, assetId: string) {
  const { rowCount } = await client.query('SELECT 1 FROM assets WHERE tenant_id = $1 AND id = $2', [
    tenantId,
    assetId,
  ]);
  if (rowCount !== 1) throw Errors.validation([{ path: 'assetId', message: 'Asset not found' }]);
}

export async function createIntegration(
  client: DbClient,
  tenantId: string,
  actorId: string,
  input: {
    provider: string;
    name: string;
    config: Record<string, unknown>;
    credentialRef?: string | null;
    grantedPermissions: string[];
    assetId?: string | null;
  },
  providers: ProviderRegistry,
  network: UrlPolicy,
): Promise<IntegrationRow> {
  const { provider, config } = validateProviderInput(
    providers,
    input.provider,
    input.config,
    input.credentialRef,
    input.grantedPermissions,
    network,
  );
  if (input.assetId) await assertAssetInTenant(client, tenantId, input.assetId);
  const { rows } = await client.query<IntegrationRow>(
    `INSERT INTO integrations
       (tenant_id, name, provider, status, config, credential_ref, declared_capabilities,
        granted_permissions, asset_id, created_by)
     VALUES ($1, $2, $3, 'CONFIGURED', $4, $5, $6, $7, $8, $9)
     RETURNING ${COLUMNS}`,
    [
      tenantId,
      input.name,
      provider.id,
      JSON.stringify(config),
      input.credentialRef ?? null,
      provider.capabilities.map((c) => c.key),
      [...new Set(input.grantedPermissions)].sort(),
      input.assetId ?? null,
      actorId,
    ],
  );
  return rows[0]!;
}

export async function updateIntegration(
  client: DbClient,
  tenantId: string,
  existing: IntegrationRow,
  input: {
    version: number;
    name?: string;
    config?: Record<string, unknown>;
    credentialRef?: string | null;
    grantedPermissions?: string[];
    assetId?: string | null;
  },
  providers: ProviderRegistry,
  network: UrlPolicy,
): Promise<{ row: IntegrationRow; changed: string[] }> {
  if (existing.status === 'REVOKED') throw Errors.invalidTransition('REVOKED', 'CONFIGURED');
  if (existing.version !== input.version)
    throw Errors.conflict('The integration was modified by someone else');

  const nextConfig = input.config ?? existing.config;
  const nextCredential =
    input.credentialRef !== undefined ? input.credentialRef : existing.credential_ref;
  const nextPermissions = input.grantedPermissions ?? existing.granted_permissions;
  const { config } = validateProviderInput(
    providers,
    existing.provider,
    nextConfig,
    nextCredential,
    nextPermissions,
    network,
  );
  if (input.assetId) await assertAssetInTenant(client, tenantId, input.assetId);

  const changed: string[] = [];
  if (input.name !== undefined && input.name !== existing.name) changed.push('name');
  if (input.config !== undefined && JSON.stringify(config) !== JSON.stringify(existing.config))
    changed.push('config');
  if (input.credentialRef !== undefined && input.credentialRef !== existing.credential_ref)
    changed.push('credentialRef');
  if (input.grantedPermissions !== undefined) changed.push('grantedPermissions');
  if (input.assetId !== undefined && input.assetId !== existing.asset_id) changed.push('assetId');

  // Any change to what or how we connect invalidates previous health results.
  const connectionChanged = changed.some((c) => c !== 'name' && c !== 'assetId');
  let nextStatus = existing.status;
  if (connectionChanged && existing.status !== 'SUSPENDED') {
    if (!integrationStateMachine.canTransition(existing.status, 'CONFIGURED')) {
      throw Errors.invalidTransition(existing.status, 'CONFIGURED');
    }
    nextStatus = 'CONFIGURED';
  }

  const { rows } = await client.query<IntegrationRow>(
    `UPDATE integrations SET
        name = $3, config = $4, credential_ref = $5, granted_permissions = $6, asset_id = $7,
        status = $8,
        config_version = config_version + CASE WHEN $9 THEN 1 ELSE 0 END,
        last_health_status = CASE WHEN $9 THEN NULL ELSE last_health_status END,
        last_health_at = CASE WHEN $9 THEN NULL ELSE last_health_at END,
        last_error_code = CASE WHEN $9 THEN NULL ELSE last_error_code END,
        version = version + 1
      WHERE tenant_id = $1 AND id = $2 AND version = $10
      RETURNING ${COLUMNS}`,
    [
      tenantId,
      existing.id,
      input.name ?? existing.name,
      JSON.stringify(config),
      nextCredential,
      [...new Set(nextPermissions)].sort(),
      input.assetId !== undefined ? input.assetId : existing.asset_id,
      nextStatus,
      connectionChanged,
      input.version,
    ],
  );
  if (!rows[0]) throw Errors.conflict('The integration was modified by someone else');
  return { row: rows[0], changed };
}

/** Apply a validated lifecycle transition (suspend, resume, revoke). */
export async function transitionIntegration(
  client: DbClient,
  tenantId: string,
  existing: IntegrationRow,
  to: IntegrationStatus,
  version: number,
): Promise<IntegrationRow> {
  if (existing.version !== version)
    throw Errors.conflict('The integration was modified by someone else');
  if (!integrationStateMachine.canTransition(existing.status, to)) {
    throw Errors.invalidTransition(existing.status, to);
  }
  const revoking = to === 'REVOKED';
  const { rows } = await client.query<IntegrationRow>(
    `UPDATE integrations SET
        status = $3,
        revoked_at = CASE WHEN $4 THEN now() ELSE revoked_at END,
        credential_ref = CASE WHEN $4 THEN NULL ELSE credential_ref END,
        granted_permissions = CASE WHEN $4 THEN '{}'::text[] ELSE granted_permissions END,
        last_health_status = CASE WHEN $3 = 'CONFIGURED' THEN NULL ELSE last_health_status END,
        last_health_at = CASE WHEN $3 = 'CONFIGURED' THEN NULL ELSE last_health_at END,
        version = version + 1
      WHERE tenant_id = $1 AND id = $2 AND version = $5
      RETURNING ${COLUMNS}`,
    [tenantId, existing.id, to, revoking, version],
  );
  if (!rows[0]) throw Errors.conflict('The integration was modified by someone else');
  return rows[0];
}

export async function listHealthChecks(
  client: DbClient,
  tenantId: string,
  integrationId: string,
  limit = 20,
): Promise<HealthCheckDto[]> {
  const { rows } = await client.query<{
    id: string;
    result: HealthCheckResult;
    observed_at: Date;
    latency_ms: number | null;
    error_code: string | null;
    config_version: number;
  }>(
    `SELECT id, result, observed_at, latency_ms, error_code, config_version
       FROM integration_health_checks
      WHERE tenant_id = $1 AND integration_id = $2
      ORDER BY observed_at DESC LIMIT $3`,
    [tenantId, integrationId, limit],
  );
  return rows.map((r) => ({
    id: r.id,
    result: r.result,
    observedAt: r.observed_at.toISOString(),
    latencyMs: r.latency_ms,
    errorCode: r.error_code,
    configVersion: r.config_version,
  }));
}
