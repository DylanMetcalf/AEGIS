import { ingestBatchSchema, uuidSchema } from '@aegis/shared';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { getIntegration } from '../../integrations/integrations.js';
import { sha256 } from '../../security/tokens.js';
import {
  authenticateIngest,
  ingestBatch,
  issueIngestToken,
  listIngestTokens,
  revokeIngestTokens,
} from '../../telemetry/ingest.js';
import { auditInTx, enforce, inTenant, type AppDeps } from '../context.js';
import { Errors, parse } from '../errors.js';

const idParams = z.object({ id: uuidSchema }).strict();

export const ingestRoutes = (deps: AppDeps) => async (app: FastifyInstance) => {
  const { config, pool, providers } = deps;

  /**
   * Machine telemetry intake. Bearer ingest token, JSON body, no cookies.
   * Not subject to the browser Origin check (no ambient credentials are used).
   * Rate-limited per token; batches are not individually audited (they are
   * themselves immutable records tagged with a batch id).
   */
  app.post(
    '/ingest/v1/events',
    {
      bodyLimit: config.ingest.bodyLimitBytes,
      config: {
        auth: 'ingest_token',
        rateLimit: {
          max: config.ingest.rateLimitPerMinute,
          timeWindow: 60_000,
          keyGenerator: (req) =>
            `ingest:${sha256(String(req.headers.authorization ?? req.ip))
              .toString('hex')
              .slice(0, 32)}`,
        },
      },
    },
    async (req, reply) => {
      const who = await authenticateIngest(
        pool,
        req.headers.authorization,
        config.session.reauthWindowMs,
      );
      const body = parse(ingestBatchSchema, req.body);
      const result = await ingestBatch(pool, providers, who, body.events, req.correlationId);
      return reply.status(202).send(result);
    },
  );

  app.get(
    '/api/integrations/:id/ingest-tokens',
    { config: { auth: 'integration.read' } },
    async (req) => {
      const { id } = parse(idParams, req.params);
      return inTenant(deps, req, async (c, tenantId) => {
        if (!(await getIntegration(c, tenantId, id))) throw Errors.notFound('Integration');
        return { items: await listIngestTokens(c, tenantId, id) };
      });
    },
  );

  app.post(
    '/api/integrations/:id/ingest-tokens',
    { config: { auth: 'integration.credential.manage' } },
    async (req, reply) => {
      const { id } = parse(idParams, req.params);
      const result = await inTenant(deps, req, async (c, tenantId) => {
        const row = await getIntegration(c, tenantId, id, { forUpdate: true });
        if (!row) throw Errors.notFound('Integration');
        await enforce(deps, req, 'integration.credential.manage', {
          type: 'integration',
          tenantId: row.tenant_id,
          id,
        });
        if (
          !providers
            .get(row.provider)
            ?.capabilities.some((cap) => cap.key === 'events.collect' && cap.implemented)
        ) {
          throw Errors.unprocessable(
            'CAPABILITY_NOT_DECLARED',
            'This integration does not accept pushed events',
          );
        }
        if (row.status === 'REVOKED' || row.status === 'SUSPENDED')
          throw Errors.invalidTransition(row.status, 'token issuance');
        const { rows: sp } = await c.query<{ service_principal_id: string | null }>(
          'SELECT service_principal_id FROM integrations WHERE tenant_id = $1 AND id = $2',
          [tenantId, id],
        );
        const issued = await issueIngestToken(
          c,
          tenantId,
          { id, name: row.name, service_principal_id: sp[0]?.service_principal_id ?? null },
          req.actor!.principalId,
        );
        await auditInTx(c, req, {
          tenantId,
          action: 'integration.ingest_token.create',
          outcome: 'SUCCESS',
          targetType: 'integration',
          targetId: id,
          metadata: { tokenId: issued.dto.id, prefix: issued.dto.prefix },
        });
        return issued;
      });
      // The secret is returned exactly once and never stored or logged.
      return reply.status(201).send({ ...result.dto, token: result.token });
    },
  );

  app.delete(
    '/api/integrations/:id/ingest-tokens/:tokenId',
    { config: { auth: 'integration.credential.manage' } },
    async (req, reply) => {
      const { id, tokenId } = parse(
        z.object({ id: uuidSchema, tokenId: uuidSchema }).strict(),
        req.params,
      );
      await inTenant(deps, req, async (c, tenantId) => {
        const row = await getIntegration(c, tenantId, id);
        if (!row) throw Errors.notFound('Integration');
        await enforce(deps, req, 'integration.credential.manage', {
          type: 'integration',
          tenantId: row.tenant_id,
          id,
        });
        if ((await revokeIngestTokens(c, tenantId, id, tokenId)) !== 1)
          throw Errors.notFound('Token');
        await auditInTx(c, req, {
          tenantId,
          action: 'integration.ingest_token.revoke',
          outcome: 'SUCCESS',
          targetType: 'integration',
          targetId: id,
          metadata: { tokenId },
        });
      });
      return reply.status(204).send();
    },
  );
};
