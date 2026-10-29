import { ConfigError, loadConfig } from './config.js';
import { buildApp } from './http/app.js';
import { createRuntime, createWorker } from './runtime.js';

async function main() {
  const config = loadConfig();
  const { pool, providers } = await createRuntime(config);
  const app = await buildApp({ config, pool, providers });
  const worker = config.worker.enabled ? createWorker(config, pool, providers, app.log) : null;

  const shutdown = async (signal: string) => {
    app.log.info({ signal }, 'shutting down');
    await worker?.stop();
    await app.close();
    await pool.end();
    process.exit(0);
  };
  process.once('SIGTERM', () => void shutdown('SIGTERM'));
  process.once('SIGINT', () => void shutdown('SIGINT'));

  await app.listen({ host: config.host, port: config.port });
  await worker?.start();
  app.log.info({ env: config.env, worker: Boolean(worker) }, 'AEGIS API started');
}

main().catch((err) => {
  // Configuration errors list variable names only, never values.
  if (err instanceof ConfigError) console.error(err.message);
  else console.error('Fatal startup error:', err instanceof Error ? err.message : 'unknown error');
  process.exit(1);
});
