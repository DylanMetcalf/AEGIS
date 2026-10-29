import { z } from 'zod';
import { ProviderConfigError, type IntegrationProvider } from './types.js';

/**
 * Event intake: applications and security tools push telemetry to
 * POST /ingest/v1/events with a per-integration bearer token. There is no
 * outbound connection to check; the integration's health is the observation
 * of authenticated events arriving (recorded on each ingest).
 */

export const EVENTS_COLLECT_CAPABILITY = 'events.collect';
export const EVENTS_INGEST_PERMISSION = 'events.ingest';

const configSchema = z.object({ description: z.string().max(200).optional() }).strict();

export const eventIngestProvider: IntegrationProvider<z.infer<typeof configSchema>> = {
  id: 'aegis.event_ingest',
  displayName: 'Event Intake (HTTPS push)',
  description:
    'Receives security telemetry pushed by your applications and tools using an ingest token. Supports authentication, HTTP request, IAM, configuration, and alert events.',
  version: '1.0.0',
  testAdapter: false,
  supportsCredential: false,
  permissions: [
    {
      key: EVENTS_INGEST_PERMISSION,
      description: 'Accept telemetry pushed with this integration’s ingest tokens',
    },
  ],
  capabilities: [
    {
      key: EVENTS_COLLECT_CAPABILITY,
      description: 'Collect pushed telemetry events',
      requiredPermissions: [EVENTS_INGEST_PERMISSION],
      implemented: true,
    },
  ],
  configFields: [{ key: 'description', label: 'Description', type: 'string', required: false }],
  validateConfig(raw) {
    const parsed = configSchema.safeParse(raw);
    if (!parsed.success) {
      throw new ProviderConfigError(
        parsed.error.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
      );
    }
    return parsed.data;
  },
};
