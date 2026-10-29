import { setTimeout as sleep } from 'node:timers/promises';
import { z } from 'zod';
import { HEALTH_CHECK_CAPABILITY, ProviderConfigError, type IntegrationProvider } from './types.js';

/**
 * TEST ADAPTER — NOT A PRODUCTION CONNECTION.
 *
 * Deterministically simulates integration behaviour so that the integration
 * lifecycle, job execution, and status reporting can be exercised without an
 * external provider. It is disabled unless INTEGRATION_TEST_ADAPTER_ENABLED
 * is set, which configuration validation forbids in staging and production.
 */

const configSchema = z
  .object({
    scenario: z.enum(['healthy', 'degraded', 'unreachable', 'auth_failure', 'timeout', 'crash']),
    latencyMs: z.number().int().min(0).max(5000).default(0),
  })
  .strict();

export type TestAdapterConfig = z.infer<typeof configSchema>;

export const testAdapterProvider: IntegrationProvider<TestAdapterConfig> = {
  id: 'aegis.test_adapter',
  displayName: 'Test Adapter (simulated)',
  description:
    'Simulated provider for development and automated tests. It does not connect to any external system.',
  version: '1.0.0',
  testAdapter: true,
  supportsCredential: true,
  permissions: [{ key: 'test.read', description: 'Read simulated status' }],
  capabilities: [
    {
      key: HEALTH_CHECK_CAPABILITY,
      description: 'Simulated connection check',
      requiredPermissions: ['test.read'],
      implemented: true,
    },
    {
      key: 'events.collect',
      description: 'Event collection (declared to exercise capability gating; not implemented)',
      requiredPermissions: ['test.read'],
      implemented: false,
    },
  ],
  configFields: [
    {
      key: 'scenario',
      label: 'Simulated scenario',
      type: 'enum',
      required: true,
      options: ['healthy', 'degraded', 'unreachable', 'auth_failure', 'timeout', 'crash'],
    },
    { key: 'latencyMs', label: 'Simulated latency (ms)', type: 'number', required: false },
  ],

  validateConfig(raw) {
    const parsed = configSchema.safeParse(raw);
    if (!parsed.success) {
      throw new ProviderConfigError(
        parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
      );
    }
    return parsed.data;
  },

  async healthCheck(config, ctx) {
    ctx.resolveCredential();
    if (config.latencyMs) await sleep(config.latencyMs, undefined, { signal: ctx.signal });
    switch (config.scenario) {
      case 'healthy':
        return { result: 'CONNECTED', latencyMs: config.latencyMs, errorCode: null };
      case 'degraded':
        return {
          result: 'DEGRADED',
          latencyMs: config.latencyMs,
          errorCode: 'SIMULATED_DEGRADATION',
        };
      case 'unreachable':
        return { result: 'DISCONNECTED', latencyMs: null, errorCode: 'CONNECTION_REFUSED' };
      case 'auth_failure':
        return { result: 'DISCONNECTED', latencyMs: null, errorCode: 'AUTHENTICATION_REJECTED' };
      case 'timeout':
        // Wait until the platform's timeout aborts us.
        await sleep(600_000, undefined, { signal: ctx.signal });
        return { result: 'UNKNOWN', latencyMs: null, errorCode: 'TIMEOUT' };
      case 'crash':
        throw new Error('simulated provider crash');
    }
  },
};
