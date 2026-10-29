import type { HealthCheckResult } from '@aegis/shared';
import { eventIngestProvider } from './providers/event-ingest.js';
import { httpProbeProvider } from './providers/http-probe.js';
import { testAdapterProvider } from './providers/test-adapter.js';
import type {
  HealthCheckOutcome,
  IntegrationProvider,
  ProviderContext,
} from './providers/types.js';

export interface ProviderRegistry {
  list(): IntegrationProvider<unknown>[];
  get(id: string): IntegrationProvider<unknown> | null;
}

export function createProviderRegistry(opts: { testAdapterEnabled: boolean }): ProviderRegistry {
  const providers = [
    httpProbeProvider,
    eventIngestProvider,
    ...(opts.testAdapterEnabled ? [testAdapterProvider] : []),
  ] as IntegrationProvider<unknown>[];
  const byId = new Map(providers.map((p) => [p.id, p]));
  return {
    list: () => [...providers],
    get: (id) => byId.get(id) ?? null,
  };
}

export class CapabilityError extends Error {
  constructor(
    public readonly code:
      'CAPABILITY_NOT_DECLARED' | 'CAPABILITY_NOT_IMPLEMENTED' | 'PERMISSION_NOT_GRANTED',
  ) {
    super(code);
    this.name = 'CapabilityError';
  }
}

/** Capabilities an integration can actually use with its granted permissions. */
export function availableCapabilities(
  provider: IntegrationProvider<unknown>,
  grantedPermissions: readonly string[],
): string[] {
  return provider.capabilities
    .filter(
      (c) => c.implemented && c.requiredPermissions.every((p) => grantedPermissions.includes(p)),
    )
    .map((c) => c.key);
}

/** Throws unless the capability is declared, implemented, and permitted. */
export function assertCapabilityUsable(
  provider: IntegrationProvider<unknown>,
  capability: string,
  grantedPermissions: readonly string[],
): void {
  const decl = provider.capabilities.find((c) => c.key === capability);
  if (!decl) throw new CapabilityError('CAPABILITY_NOT_DECLARED');
  if (!decl.implemented) throw new CapabilityError('CAPABILITY_NOT_IMPLEMENTED');
  if (!decl.requiredPermissions.every((p) => grantedPermissions.includes(p))) {
    throw new CapabilityError('PERMISSION_NOT_GRANTED');
  }
}

/** Permissions requested that the provider does not define. */
export function unknownPermissions(
  provider: IntegrationProvider<unknown>,
  requested: readonly string[],
): string[] {
  const known = new Set(provider.permissions.map((p) => p.key));
  return requested.filter((p) => !known.has(p));
}

/**
 * Run a provider health check with a hard timeout. Provider exceptions and
 * timeouts become explicit non-healthy outcomes; nothing is reported as
 * CONNECTED unless the provider affirmatively said so.
 */
export async function runHealthCheck(
  provider: IntegrationProvider<unknown>,
  config: unknown,
  ctx: Omit<ProviderContext, 'signal'>,
  timeoutMs: number,
  parentSignal?: AbortSignal,
): Promise<HealthCheckOutcome> {
  if (!provider.healthCheck) {
    return { result: 'UNKNOWN', latencyMs: null, errorCode: 'CAPABILITY_NOT_IMPLEMENTED' };
  }
  const signals = [AbortSignal.timeout(timeoutMs), ...(parentSignal ? [parentSignal] : [])];
  const signal = AbortSignal.any(signals);
  const started = performance.now();
  try {
    const outcome = await provider.healthCheck(config, { ...ctx, signal });
    if (!isValidOutcome(outcome)) {
      return { result: 'UNKNOWN', latencyMs: null, errorCode: 'INVALID_PROVIDER_RESPONSE' };
    }
    return outcome;
  } catch (err) {
    if (signal.aborted) {
      return {
        result: 'DISCONNECTED',
        latencyMs: Math.round(performance.now() - started),
        errorCode: 'TIMEOUT',
      };
    }
    if (err instanceof CredentialUnavailableError) {
      return { result: 'DISCONNECTED', latencyMs: null, errorCode: 'CREDENTIAL_UNAVAILABLE' };
    }
    return { result: 'UNKNOWN', latencyMs: null, errorCode: 'PROVIDER_ERROR' };
  }
}

const RESULTS: readonly HealthCheckResult[] = ['CONNECTED', 'DEGRADED', 'DISCONNECTED', 'UNKNOWN'];

function isValidOutcome(o: unknown): o is HealthCheckOutcome {
  if (!o || typeof o !== 'object') return false;
  const v = o as HealthCheckOutcome;
  return (
    RESULTS.includes(v.result) &&
    (v.errorCode === null || /^[A-Z][A-Z0-9_]{0,63}$/.test(v.errorCode)) &&
    (v.latencyMs === null || (Number.isInteger(v.latencyMs) && v.latencyMs >= 0))
  );
}

export class CredentialUnavailableError extends Error {
  constructor() {
    super('Credential unavailable');
    this.name = 'CredentialUnavailableError';
  }
}

const CREDENTIAL_REF = /^env:(AEGIS_SECRET_[A-Z0-9_]{1,64})$/;

/**
 * Resolve a credential reference to its secret value. Only environment
 * variables in the AEGIS_SECRET_ namespace can be referenced, so an
 * integration can never be pointed at the database URL or other platform
 * secrets. The value is returned to the provider only; it is never stored,
 * logged, or returned by the API.
 */
export function resolveCredentialRef(
  ref: string | null,
  env: NodeJS.ProcessEnv = process.env,
): string | null {
  if (ref === null) return null;
  const m = CREDENTIAL_REF.exec(ref);
  if (!m) throw new CredentialUnavailableError();
  const value = env[m[1]!];
  if (!value) throw new CredentialUnavailableError();
  return value;
}
