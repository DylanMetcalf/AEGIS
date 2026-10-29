import { z } from 'zod';
import { SafeHttpError, checkUrlPolicy, safeHttpGet } from '../../security/safe-http.js';
import { HEALTH_CHECK_CAPABILITY, ProviderConfigError, type IntegrationProvider } from './types.js';

/**
 * HTTPS endpoint probe: a real network integration that checks whether an
 * authorized endpoint is reachable and answers with the expected status.
 * It reports only status and latency; response bodies are discarded.
 */

const configSchema = z
  .object({
    url: z.string().max(2048),
    expectedStatus: z.number().int().min(100).max(599).optional(),
  })
  .strict();

export type HttpProbeConfig = z.infer<typeof configSchema>;

export const httpProbeProvider: IntegrationProvider<HttpProbeConfig> = {
  id: 'http.endpoint_probe',
  displayName: 'HTTPS Endpoint Probe',
  description:
    'Checks that an authorized HTTPS endpoint is reachable and returns the expected status. Does not follow redirects and never reads response content.',
  version: '1.0.0',
  testAdapter: false,
  supportsCredential: true,
  permissions: [
    {
      key: 'http.get',
      description:
        'Send unauthenticated or bearer-authenticated GET requests to the configured URL',
    },
  ],
  capabilities: [
    {
      key: HEALTH_CHECK_CAPABILITY,
      description: 'Check endpoint reachability and status',
      requiredPermissions: ['http.get'],
      implemented: true,
    },
  ],
  configFields: [
    {
      key: 'url',
      label: 'Endpoint URL',
      type: 'url',
      required: true,
      help: 'https:// URL of an endpoint you are authorized to probe',
    },
    {
      key: 'expectedStatus',
      label: 'Expected status',
      type: 'number',
      required: false,
      help: 'Defaults to any 2xx',
    },
  ],

  validateConfig(raw, network) {
    const parsed = configSchema.safeParse(raw);
    if (!parsed.success) {
      throw new ProviderConfigError(
        parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
      );
    }
    const policyError = checkUrlPolicy(parsed.data.url, network);
    if (policyError) {
      throw new ProviderConfigError([{ path: 'url', message: `URL rejected: ${policyError}` }]);
    }
    return { ...parsed.data, url: new URL(parsed.data.url).toString() };
  },

  async healthCheck(config, ctx) {
    const credential = ctx.resolveCredential();
    try {
      const res = await safeHttpGet(config.url, {
        ...ctx.network,
        signal: ctx.signal,
        headers: credential ? { authorization: `Bearer ${credential}` } : {},
      });
      const ok = config.expectedStatus
        ? res.status === config.expectedStatus
        : res.status >= 200 && res.status < 300;
      if (ok) return { result: 'CONNECTED', latencyMs: res.latencyMs, errorCode: null };
      if (res.status === 401 || res.status === 403) {
        return {
          result: 'DISCONNECTED',
          latencyMs: res.latencyMs,
          errorCode: 'AUTHENTICATION_REJECTED',
        };
      }
      if (res.status >= 500) {
        return { result: 'DEGRADED', latencyMs: res.latencyMs, errorCode: 'UPSTREAM_ERROR_STATUS' };
      }
      return { result: 'DEGRADED', latencyMs: res.latencyMs, errorCode: 'UNEXPECTED_STATUS' };
    } catch (err) {
      if (err instanceof SafeHttpError) {
        return { result: 'DISCONNECTED', latencyMs: null, errorCode: err.code };
      }
      throw err;
    }
  },
};
