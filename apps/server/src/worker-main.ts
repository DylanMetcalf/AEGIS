import pino from 'pino';
import { ConfigError, loadConfig } from './config.js';
import { LOG_REDACT_PATHS } from './security/redact.js';
import { createRuntime, createWorker } from './runtime.js';

/** Standalone worker process (WORKER_ENABLED is ignored here). */
async function main() {
  const config = loadConfig();
  const log = pino({ level: config.logLevel, redact: { paths: LOG_REDACT_PATHS, censor: '[REDACTED]' } });
  const { pool, providers } = await createRuntime(config);
  const worker = createWorker(config, pool, providers, log);
  const shutdown = async () => {
    await worker.stop();
    await pool.end();
    process.exit(0);
  };
  process.once('SIGTERM', () => void shutdown());
  process.once('SIGINT', () => void shutdown());
  await worker.start();
  log.info({ workerId: worker.workerId }, 'AEGIS worker started');
}

main().catch((err) => {
  if (err instanceof ConfigError) console.error(err.message);
  else console.error('Fatal worker error:', err instanceof Error ? err.message : 'unknown error');
  process.exit(1);
});
