import { randomUUID } from 'node:crypto';
import type { IngestTokenDto, TelemetryEventInput } from '@aegis/shared';
import { authorize, type Actor } from '../authz/authorize.js';
import { loadActorForTenant } from '../authz/load-actor.js';
import { withTransaction, type DbClient, type Pool } from '../db/pool.js';
import { AppError, Errors } from '../http/errors.js';
import { EVENTS_COLLECT_CAPABILITY } from '../integrations/providers/event-ingest.js';
import {
  CapabilityError,
  assertCapabilityUsable,
  type ProviderRegistry,
} from '../integrations/registry.js';
import { DETECTION_JOB, DETECTION_JOB_LIMITS } from '../jobs/detection-job.js';
import { enqueueJob } from '../jobs/jobs.js';
import { generateToken, sha256 } from '../security/tokens.js';

/**
 * Ingest tokens and telemetry intake.
 *
 * Each ingest integration acts through its own SERVICE principal (member of
 * the tenant with the SERVICE role), so ingestion and detection go through
 * the same authorization and row-level security as everything else.
 */

const TOKEN_PREFIX = 'aegis_ing_';
const TOKEN_RE = /^aegis_ing_[A-Za-z0-9_-]{43}$/;
export const MAX_ACTIVE_TOKENS = 5;
/** Accepted clock window for event timestamps. */
const MAX_FUTURE_MS = 5 * 60_000;
const MAX_AGE_MS = 7 * 24 * 3600_000;

interface TokenRow {
  id: string;
  token_prefix: string;
  created_at: Date;
  last_used_at: Date | null;
  revoked_at: Date | null;
}

const toTokenDto = (r: TokenRow): IngestTokenDto => ({
  id: r.id,
  prefix: r.token_prefix,
  createdAt: r.created_at.toISOString(),
  lastUsedAt: r.last_used_at?.toISOString() ?? null,
  revokedAt: r.revoked_at?.toISOString() ?? null,
});

export async function listIngestTokens(client: DbClient, tenantId: string, integrationId: string) {
  const { rows } = await client.query<TokenRow>(
    `SELECT id, token_prefix, created_at, last_used_at, revoked_at FROM ingest_tokens
      WHERE tenant_id = $1 AND integration_id = $2 ORDER BY created_at DESC LIMIT 50`,
    [tenantId, integrationId],
  );
  return rows.map(toTokenDto);
}

/** Issue a token; provisions the integration's service principal on first use. Returns the secret once. */
export async function issueIngestToken(
  client: DbClient,
  tenantId: string,
  integration: { id: string; name: string; service_principal_id: string | null },
  createdBy: string,
): Promise<{ token: string; dto: IngestTokenDto }> {
  const { rows: active } = await client.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM ingest_tokens
      WHERE tenant_id = $1 AND integration_id = $2 AND revoked_at IS NULL`,
    [tenantId, integration.id],
  );
  if ((active[0]?.n ?? 0) >= MAX_ACTIVE_TOKENS) {
    throw Errors.unprocessable(
      'TOKEN_LIMIT_REACHED',
      `At most ${MAX_ACTIVE_TOKENS} active tokens per integration`,
    );
  }
  let principalId = integration.service_principal_id;
  if (!principalId) {
    const { rows } = await client.query<{ id: string }>(
      `INSERT INTO principals (kind, display_name) VALUES ('SERVICE', $1) RETURNING id`,
      [`Ingest: ${integration.name}`.slice(0, 200)],
    );
    principalId = rows[0]!.id;
    await client.query(
      `INSERT INTO memberships (tenant_id, principal_id, role, created_by) VALUES ($1, $2, 'SERVICE', $3)`,
      [tenantId, principalId, createdBy],
    );
    await client.query(
      'UPDATE integrations SET service_principal_id = $3 WHERE tenant_id = $1 AND id = $2',
      [tenantId, integration.id, principalId],
    );
  }
  const token = `${TOKEN_PREFIX}${generateToken()}`;
  const { rows } = await client.query<TokenRow>(
    `INSERT INTO ingest_tokens (tenant_id, integration_id, principal_id, token_hash, token_prefix, created_by)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id, token_prefix, created_at, last_used_at, revoked_at`,
    [
      tenantId,
      integration.id,
      principalId,
      sha256(token),
      token.slice(0, TOKEN_PREFIX.length + 4),
      createdBy,
    ],
  );
  return { token, dto: toTokenDto(rows[0]!) };
}

export async function revokeIngestTokens(
  client: DbClient,
  tenantId: string,
  integrationId: string,
  tokenId: string | null,
): Promise<number> {
  const res = await client.query(
    `UPDATE ingest_tokens SET revoked_at = now()
      WHERE tenant_id = $1 AND integration_id = $2 AND revoked_at IS NULL AND ($3::uuid IS NULL OR id = $3::uuid)`,
    [tenantId, integrationId, tokenId],
  );
  return res.rowCount ?? 0;
}

export interface IngestPrincipal {
  tokenId: string;
  tenantId: string;
  integrationId: string;
  actor: Actor;
}

const unauthenticated = () =>
  new AppError(401, 'UNAUTHENTICATED', 'A valid ingest token is required');

/** Authenticate a bearer ingest token and establish the service actor. */
export async function authenticateIngest(
  pool: Pool,
  authorization: string | undefined,
  reauthWindowMs: number,
): Promise<IngestPrincipal> {
  const token = /^Bearer (\S+)$/.exec(authorization ?? '')?.[1];
  if (!token || !TOKEN_RE.test(token)) throw unauthenticated();
  const { rows } = await pool.query<{
    token_id: string;
    tenant_id: string;
    integration_id: string;
    principal_id: string;
  }>('SELECT * FROM resolve_ingest_token($1)', [sha256(token)]);
  const t = rows[0];
  if (!t) throw unauthenticated();
  const actor = await loadActorForTenant(pool, t.tenant_id, t.principal_id);
  const decision = authorize(actor, 'telemetry.ingest', {
    resource: { type: 'integration', tenantId: t.tenant_id, id: t.integration_id },
    reauthWindowMs,
  });
  if (!decision.allowed) throw Errors.forbidden();
  return {
    tokenId: t.token_id,
    tenantId: t.tenant_id,
    integrationId: t.integration_id,
    actor: actor!,
  };
}

export class IngestRejected extends AppError {}

/** Store a validated batch, record the connectivity observation, and queue detection. */
export async function ingestBatch(
  pool: Pool,
  providers: ProviderRegistry,
  who: IngestPrincipal,
  events: TelemetryEventInput[],
  correlationId: string,
  now = new Date(),
): Promise<{ batchId: string; accepted: number; duplicates: number }> {
  const details = events.flatMap((e, i) => {
    const t = Date.parse(e.observedAt);
    if (t > now.getTime() + MAX_FUTURE_MS)
      return [{ path: `events.${i}.observedAt`, message: 'Timestamp is in the future' }];
    if (t < now.getTime() - MAX_AGE_MS)
      return [{ path: `events.${i}.observedAt`, message: 'Timestamp older than 7 days' }];
    return [];
  });
  if (details.length) throw Errors.validation(details.slice(0, 20));

  const batchId = randomUUID();
  return withTransaction(
    pool,
    { tenantId: who.tenantId, principalId: who.actor.principalId },
    async (c) => {
      const { rows: integ } = await c.query<{
        status: string;
        provider: string;
        granted_permissions: string[];
        asset_id: string | null;
      }>(
        `SELECT status, provider, granted_permissions, asset_id FROM integrations
        WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
        [who.tenantId, who.integrationId],
      );
      const integration = integ[0];
      if (!integration) throw Errors.forbidden();
      if (integration.status === 'SUSPENDED' || integration.status === 'REVOKED') {
        throw new IngestRejected(
          403,
          'INTEGRATION_NOT_ACTIVE',
          'This integration is not accepting events',
        );
      }
      const provider = providers.get(integration.provider);
      try {
        if (!provider) throw new CapabilityError('CAPABILITY_NOT_DECLARED');
        assertCapabilityUsable(
          provider,
          EVENTS_COLLECT_CAPABILITY,
          integration.granted_permissions,
        );
      } catch (err) {
        if (err instanceof CapabilityError)
          throw new IngestRejected(403, err.code, 'This integration cannot collect events');
        throw err;
      }

      const rows = events.map((e) => ({
        event_type: e.eventType,
        severity: e.severity,
        observed_at: e.observedAt,
        actor_user_id: e.actor?.userId ?? null,
        actor_ip: e.actor?.ip ?? null,
        attributes: e.attributes,
        source_event_id: e.sourceEventId ?? null,
        // Without a source id, identical content is treated as the same event.
        dedupe_key:
          e.sourceEventId ??
          `sha256:${sha256(JSON.stringify(canonical(e)))
            .toString('hex')
            .slice(0, 64)}`,
      }));
      const inserted = await c.query(
        `INSERT INTO telemetry_events (tenant_id, integration_id, asset_id, batch_id, event_type, severity, observed_at,
                                     actor_user_id, actor_ip, attributes, source_event_id, dedupe_key, content_sha256)
       SELECT $1, $2, $3, $4, e.event_type, e.severity, e.observed_at, e.actor_user_id, e.actor_ip::inet,
              COALESCE(e.attributes, '{}'::jsonb), e.source_event_id, e.dedupe_key, '\\x00'::bytea
         FROM jsonb_to_recordset($5::jsonb) AS e(event_type text, severity text, observed_at timestamptz,
              actor_user_id text, actor_ip text, attributes jsonb, source_event_id text, dedupe_key text)
       ON CONFLICT (tenant_id, integration_id, dedupe_key) DO NOTHING`,
        [who.tenantId, who.integrationId, integration.asset_id, batchId, JSON.stringify(rows)],
      );
      const accepted = inserted.rowCount ?? 0;

      // Authenticated events arriving are themselves the connectivity observation.
      await c.query(
        `UPDATE integrations
          SET last_event_at = now(), status = 'CONNECTED', last_health_status = 'CONNECTED',
              last_health_at = now(), last_error_code = NULL
        WHERE tenant_id = $1 AND id = $2`,
        [who.tenantId, who.integrationId],
      );
      await c.query(
        `INSERT INTO integration_health_checks (tenant_id, integration_id, result, latency_ms, config_version)
       SELECT $1, $2, 'CONNECTED', NULL, i.config_version FROM integrations i
        WHERE i.tenant_id = $1 AND i.id = $2
          AND NOT EXISTS (SELECT 1 FROM integration_health_checks h
                           WHERE h.tenant_id = $1 AND h.integration_id = $2
                             AND h.observed_at > now() - interval '1 minute')`,
        [who.tenantId, who.integrationId],
      );
      await c.query(
        'UPDATE ingest_tokens SET last_used_at = now() WHERE tenant_id = $1 AND id = $2',
        [who.tenantId, who.tokenId],
      );
      if (accepted > 0) {
        await enqueueJob(c, {
          tenantId: who.tenantId,
          actorPrincipalId: who.actor.principalId,
          kind: DETECTION_JOB,
          payload: { batchId },
          idempotencyKey: `batch:${batchId}`,
          ...DETECTION_JOB_LIMITS,
          correlationId,
        });
      }
      return { batchId, accepted, duplicates: events.length - accepted };
    },
  );
}

function canonical(e: TelemetryEventInput): Record<string, unknown> {
  const sort = (o: Record<string, unknown>) =>
    Object.fromEntries(Object.entries(o).sort(([a], [b]) => a.localeCompare(b)));
  return sort({ ...e, actor: e.actor ? sort(e.actor) : null, attributes: sort(e.attributes) });
}
