import type { CapabilityDeclaration, HealthCheckResult, ProviderDto } from '@aegis/shared';
import type { UrlPolicy } from '../../security/safe-http.js';

/**
 * Integration provider contract.
 *
 * A provider declares, up front and in code:
 *  - what it can do (capabilities) and whether each is implemented,
 *  - which permissions each capability needs,
 *  - how its configuration is validated.
 * Nothing is inherited between providers, and the platform never executes a
 * capability a provider has not declared and implemented, or one whose
 * permissions the integration has not been granted.
 */

export const HEALTH_CHECK_CAPABILITY = 'connection.health_check';

export interface HealthCheckOutcome {
  result: HealthCheckResult;
  latencyMs: number | null;
  /** Stable machine code (UPPER_SNAKE). Never contains response content or secrets. */
  errorCode: string | null;
}

export interface ProviderContext {
  signal: AbortSignal;
  network: UrlPolicy;
  /** Resolves the integration's credential reference. Throws CredentialUnavailableError. */
  resolveCredential: () => string | null;
}

export class ProviderConfigError extends Error {
  constructor(public readonly issues: { path: string; message: string }[]) {
    super('Invalid integration configuration');
    this.name = 'ProviderConfigError';
  }
}

export interface IntegrationProvider<C = Record<string, unknown>> {
  id: string;
  displayName: string;
  description: string;
  version: string;
  /** Test adapters simulate behaviour and are never production connections. */
  testAdapter: boolean;
  supportsCredential: boolean;
  permissions: { key: string; description: string }[];
  capabilities: CapabilityDeclaration[];
  configFields: ProviderDto['configFields'];
  /** Validate and normalize untrusted configuration. Throws ProviderConfigError. */
  validateConfig(raw: unknown, network: UrlPolicy): C;
  healthCheck?(config: C, ctx: ProviderContext): Promise<HealthCheckOutcome>;
}

export function toProviderDto(p: IntegrationProvider<unknown>): ProviderDto {
  return {
    id: p.id,
    displayName: p.displayName,
    description: p.description,
    testAdapter: p.testAdapter,
    version: p.version,
    capabilities: p.capabilities,
    permissions: p.permissions,
    configFields: p.configFields,
    supportsCredential: p.supportsCredential,
  };
}
