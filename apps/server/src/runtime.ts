import type { FastifyBaseLogger } from 'fastify';
import type { AppConfig } from './config.js';
import { assertRuntimeRoleIsRestricted, createPool, type Pool } from './db/pool.js';
import { createProviderRegistry, type ProviderRegistry } from './integrations/registry.js';
import { healthCheckJobHandler } from './jobs/health-check-job.js';
import { Worker } from './jobs/worker.js';

/** Shared startup for the API process and the standalone worker. */
export async function createRuntime(config: AppConfig): Promise<{ pool: Pool; providers: ProviderRegistry }> {
  const pool = createPool({
    url: config.database.url,
    max: config.database.poolMax,
    statementTimeoutMs: config.database.statementTimeoutMs,
  });
  await assertRuntimeRoleIsRestricted(pool);
  const providers = createProviderRegistry({ testAdapterEnabled: config.integrations.testAdapterEnabled });
  return { pool, providers };
}

export function createWorker(
  config: AppConfig,
  pool: Pool,
  providers: ProviderRegistry,
  log: FastifyBaseLogger,
): Worker {
  return new Worker({ pool, config, log }, [healthCheckJobHandler({ config, providers })]);
}
