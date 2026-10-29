import { integrationStateMachine } from '@aegis/shared';
import { z } from 'zod';
import { recordAudit } from '../audit/audit.js';
import type { AppConfig } from '../config.js';
import { getIntegration } from '../integrations/integrations.js';
import { HEALTH_CHECK_CAPABILITY } from '../integrations/providers/types.js';
import {
  CapabilityError,
  assertCapabilityUsable,
  resolveCredentialRef,
  runHealthCheck,
  type ProviderRegistry,
} from '../integrations/registry.js';
import { JobCancelled, JobError, type JobHandler } from './worker.js';

export const HEALTH_CHECK_JOB = 'integration.health_check';

/** Resource budget for one health check job (see contracts/resource-budget.ts). */
export const HEALTH_CHECK_JOB_LIMITS = { maxAttempts: 2, timeoutMs: 20_000 } as const;

const payloadSchema = z
  .object({
    integrationId: z.string().uuid(),
    configVersion: z.number().int().positive(),
  })
  .strict();

/** Provider calls get less time than the job so the result can still be recorded. */
const PROVIDER_TIMEOUT_MS = 10_000;

export function healthCheckJobHandler(deps: {
  config: AppConfig;
  providers: ProviderRegistry;
  env?: NodeJS.ProcessEnv;
}): JobHandler<z.infer<typeof payloadSchema>> {
  return {
    kind: HEALTH_CHECK_JOB,
    capability: 'integration.health_check',
    ...HEALTH_CHECK_JOB_LIMITS,
    payloadSchema,
    async run(ctx, payload) {
      // Phase 1: mark CONNECTING. Validate everything before touching the network.
      const prepared = await ctx.tx(async (client) => {
        const row = await getIntegration(client, ctx.tenantId, payload.integrationId, {
          forUpdate: true,
        });
        if (!row) throw new JobError('INTEGRATION_NOT_FOUND', false);
        if (row.status === 'SUSPENDED' || row.status === 'REVOKED') {
          throw new JobError('INTEGRATION_NOT_ACTIVE', false);
        }
        if (row.config_version !== payload.configVersion) throw new JobCancelled('SUPERSEDED');
        const provider = deps.providers.get(row.provider);
        if (!provider) throw new JobError('PROVIDER_UNAVAILABLE', false);
        try {
          assertCapabilityUsable(provider, HEALTH_CHECK_CAPABILITY, row.granted_permissions);
        } catch (err) {
          if (err instanceof CapabilityError) throw new JobError(err.code, false);
          throw err;
        }
        if (row.status !== 'CONNECTING') {
          if (!integrationStateMachine.canTransition(row.status, 'CONNECTING')) {
            throw new JobError('INVALID_STATE_TRANSITION', false);
          }
          await client.query(
            `UPDATE integrations SET status = 'CONNECTING' WHERE tenant_id = $1 AND id = $2`,
            [ctx.tenantId, row.id],
          );
        }
        return { row, provider };
      });

      // Phase 2: the network call, outside any transaction, with a hard timeout.
      const outcome = await runHealthCheck(
        prepared.provider,
        prepared.row.config,
        {
          network: {
            allowPrivateNetwork: deps.config.integrations.allowPrivateNetwork,
            allowInsecureHttp: deps.config.integrations.allowInsecureHttp,
          },
          resolveCredential: () => resolveCredentialRef(prepared.row.credential_ref, deps.env),
        },
        PROVIDER_TIMEOUT_MS,
        ctx.signal,
      );

      // Phase 3: record the observation; only update status if nothing changed meanwhile.
      const applied = await ctx.tx(async (client) => {
        await client.query(
          `INSERT INTO integration_health_checks
             (tenant_id, integration_id, result, latency_ms, error_code, config_version, job_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [
            ctx.tenantId,
            prepared.row.id,
            outcome.result,
            outcome.latencyMs,
            outcome.errorCode,
            payload.configVersion,
            ctx.jobId,
          ],
        );
        const res = await client.query(
          `UPDATE integrations
              SET status = $3, last_health_status = $3, last_health_at = now(), last_error_code = $4
            WHERE tenant_id = $1 AND id = $2 AND status = 'CONNECTING' AND config_version = $5`,
          [ctx.tenantId, prepared.row.id, outcome.result, outcome.errorCode, payload.configVersion],
        );
        await recordAudit(client, {
          tenantId: ctx.tenantId,
          actorPrincipalId: ctx.actor.principalId,
          actorType: ctx.actor.kind,
          action: 'integration.health_checked',
          targetType: 'integration',
          targetId: prepared.row.id,
          outcome: outcome.result === 'CONNECTED' ? 'SUCCESS' : 'FAILURE',
          reasonCode: outcome.errorCode,
          correlationId: ctx.correlationId,
          metadata: {
            jobId: ctx.jobId,
            result: outcome.result,
            latencyMs: outcome.latencyMs,
            provider: prepared.row.provider,
          },
        });
        return (res.rowCount ?? 0) === 1;
      });

      return { result: outcome.result, errorCode: outcome.errorCode, statusApplied: applied };
    },
  };
}
