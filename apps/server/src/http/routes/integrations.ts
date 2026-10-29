import {
  createIntegrationRequestSchema,
  integrationTransitionRequestSchema,
  listQuerySchema,
  updateIntegrationRequestSchema,
  uuidSchema,
  type IntegrationStatus,
} from '@aegis/shared';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { Capability } from '../../authz/capabilities.js';
import {
  createIntegration,
  getIntegration,
  listHealthChecks,
  listIntegrations,
  toIntegrationDto,
  transitionIntegration,
  updateIntegration,
} from '../../integrations/integrations.js';
import { HEALTH_CHECK_CAPABILITY, toProviderDto } from '../../integrations/providers/types.js';
import { CapabilityError, assertCapabilityUsable } from '../../integrations/registry.js';
import { HEALTH_CHECK_JOB, HEALTH_CHECK_JOB_LIMITS } from '../../jobs/health-check-job.js';
import { enqueueJob, getJob, toJobDto } from '../../jobs/jobs.js';
import { auditInTx, enforce, inTenant, type AppDeps } from '../context.js';
import { Errors, parse } from '../errors.js';

const idParams = z.object({ id: uuidSchema }).strict();
const IDEMPOTENCY_KEY = /^[A-Za-z0-9_.:-]{1,128}$/;

export const integrationRoutes = (deps: AppDeps) => async (app: FastifyInstance) => {
  const { config, providers } = deps;
  const network = {
    allowPrivateNetwork: config.integrations.allowPrivateNetwork,
    allowInsecureHttp: config.integrations.allowInsecureHttp,
  };
  const dto = (row: Parameters<typeof toIntegrationDto>[0]) =>
    toIntegrationDto(row, providers, config.health.staleAfterMs);

  app.get('/api/integration-providers', { config: { auth: 'integration.read' } }, async () => ({
    items: providers.list().map(toProviderDto),
  }));

  app.get('/api/integrations', { config: { auth: 'integration.read' } }, async (req) => {
    const q = parse(listQuerySchema, req.query);
    const { rows, nextCursor } = await inTenant(deps, req, (c, tenantId) => listIntegrations(c, tenantId, q));
    return { items: rows.map(dto), nextCursor };
  });

  app.post('/api/integrations', { config: { auth: 'integration.manage' } }, async (req, reply) => {
    const body = parse(createIntegrationRequestSchema, req.body);
    if (body.credentialRef) await enforce(deps, req, 'integration.credential.manage');
    const created = await inTenant(deps, req, async (c, tenantId) => {
      const row = await createIntegration(c, tenantId, req.actor!.principalId, body, providers, network);
      await auditInTx(c, req, {
        tenantId,
        action: 'integration.create',
        outcome: 'SUCCESS',
        targetType: 'integration',
        targetId: row.id,
        metadata: {
          provider: row.provider,
          credentialRef: row.credential_ref,
          grantedPermissions: row.granted_permissions,
        },
      });
      return dto(row);
    });
    return reply.status(201).send(created);
  });

  app.get('/api/integrations/:id', { config: { auth: 'integration.read' } }, async (req) => {
    const { id } = parse(idParams, req.params);
    return inTenant(deps, req, async (c, tenantId) => {
      const row = await getIntegration(c, tenantId, id);
      if (!row) throw Errors.notFound('Integration');
      await enforce(deps, req, 'integration.read', { type: 'integration', tenantId: row.tenant_id, id });
      return { integration: dto(row), healthChecks: await listHealthChecks(c, tenantId, id) };
    });
  });

  app.patch('/api/integrations/:id', { config: { auth: 'integration.manage' } }, async (req) => {
    const { id } = parse(idParams, req.params);
    const body = parse(updateIntegrationRequestSchema, req.body);
    return inTenant(deps, req, async (c, tenantId) => {
      const existing = await getIntegration(c, tenantId, id, { forUpdate: true });
      if (!existing) throw Errors.notFound('Integration');
      const resource = { type: 'integration', tenantId: existing.tenant_id, id };
      await enforce(deps, req, 'integration.manage', resource);
      if (body.credentialRef !== undefined && body.credentialRef !== existing.credential_ref) {
        await enforce(deps, req, 'integration.credential.manage', resource);
      }
      const { row, changed } = await updateIntegration(c, tenantId, existing, body, providers, network);
      await auditInTx(c, req, {
        tenantId,
        action: 'integration.update',
        outcome: 'SUCCESS',
        targetType: 'integration',
        targetId: id,
        metadata: {
          changed,
          configVersion: row.config_version,
          ...(changed.includes('credentialRef')
            ? { credentialRefFrom: existing.credential_ref, credentialRefTo: row.credential_ref }
            : {}),
        },
      });
      return dto(row);
    });
  });

  const transition = (path: string, to: IntegrationStatus, capability: Capability, action: string) =>
    app.post(path, { config: { auth: capability } }, async (req: FastifyRequest) => {
      const { id } = parse(idParams, req.params);
      const { version } = parse(integrationTransitionRequestSchema, req.body);
      return inTenant(deps, req, async (c, tenantId) => {
        const existing = await getIntegration(c, tenantId, id, { forUpdate: true });
        if (!existing) throw Errors.notFound('Integration');
        await enforce(deps, req, capability, { type: 'integration', tenantId: existing.tenant_id, id });
        const row = await transitionIntegration(c, tenantId, existing, to, version);
        await auditInTx(c, req, {
          tenantId,
          action,
          outcome: 'SUCCESS',
          targetType: 'integration',
          targetId: id,
          metadata: { from: existing.status, to },
        });
        return dto(row);
      });
    });

  transition('/api/integrations/:id/suspend', 'SUSPENDED', 'integration.manage', 'integration.suspend');
  transition('/api/integrations/:id/resume', 'CONFIGURED', 'integration.manage', 'integration.resume');
  transition('/api/integrations/:id/revoke', 'REVOKED', 'integration.revoke', 'integration.revoke');

  app.post(
    '/api/integrations/:id/health-checks',
    { config: { auth: 'integration.health_check' } },
    async (req, reply) => {
      const { id } = parse(idParams, req.params);
      if (req.body !== undefined && req.body !== null && Object.keys(req.body as object).length > 0) {
        throw Errors.validation([{ path: '(body)', message: 'No request body expected' }]);
      }
      const rawKey = req.headers['idempotency-key'];
      if (rawKey !== undefined && (typeof rawKey !== 'string' || !IDEMPOTENCY_KEY.test(rawKey))) {
        throw Errors.validation([{ path: 'Idempotency-Key', message: 'Invalid idempotency key' }]);
      }
      const result = await inTenant(deps, req, async (c, tenantId) => {
        const row = await getIntegration(c, tenantId, id);
        if (!row) throw Errors.notFound('Integration');
        await enforce(deps, req, 'integration.health_check', { type: 'integration', tenantId: row.tenant_id, id });
        if (row.status === 'SUSPENDED' || row.status === 'REVOKED') {
          throw Errors.invalidTransition(row.status, 'CONNECTING');
        }
        const provider = providers.get(row.provider);
        if (!provider) throw Errors.unprocessable('UNSUPPORTED_PROVIDER', 'This integration provider is not available');
        try {
          assertCapabilityUsable(provider, HEALTH_CHECK_CAPABILITY, row.granted_permissions);
        } catch (err) {
          if (err instanceof CapabilityError) {
            throw Errors.unprocessable(err.code, 'This integration cannot perform health checks with its current permissions');
          }
          throw err;
        }
        const { job, created } = await enqueueJob(c, {
          tenantId,
          actorPrincipalId: req.actor!.principalId,
          kind: HEALTH_CHECK_JOB,
          payload: { integrationId: id, configVersion: row.config_version },
          idempotencyKey: (rawKey as string | undefined) ?? null,
          ...HEALTH_CHECK_JOB_LIMITS,
          correlationId: req.correlationId,
        });
        if (created) {
          await auditInTx(c, req, {
            tenantId,
            action: 'integration.health_check_requested',
            outcome: 'SUCCESS',
            targetType: 'integration',
            targetId: id,
            metadata: { jobId: job.id },
          });
        }
        return { job: toJobDto(job), created };
      });
      return reply.status(result.created ? 202 : 200).send(result.job);
    },
  );

  app.get('/api/jobs/:id', { config: { auth: 'job.read' } }, async (req) => {
    const { id } = parse(idParams, req.params);
    const row = await inTenant(deps, req, (c, tenantId) => getJob(c, tenantId, id));
    if (!row) throw Errors.notFound('Job');
    return toJobDto(row);
  });
};
