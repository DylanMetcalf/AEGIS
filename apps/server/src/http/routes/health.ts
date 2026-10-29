import type { FastifyInstance } from 'fastify';
import type { AppDeps } from '../context.js';
import { checkDatabase, isReady, type AuditVerificationState } from '../../health/health.js';

/**
 * Unauthenticated probes for orchestrators. Liveness says only that the
 * process serves requests. Readiness checks required dependencies and
 * reports 503 when any is not operational.
 */
export const healthRoutes = (deps: AppDeps, _audit: AuditVerificationState) => async (app: FastifyInstance) => {
  app.get('/health/live', { config: { rateLimit: false } }, async () => ({
    status: 'live',
    observedAt: new Date().toISOString(),
  }));

  app.get('/health/ready', { config: { rateLimit: false } }, async (_req, reply) => {
    const checks = await checkDatabase(deps.pool);
    const ready = isReady(checks);
    return reply.status(ready ? 200 : 503).send({ status: ready ? 'ready' : 'not_ready', checks });
  });
};
