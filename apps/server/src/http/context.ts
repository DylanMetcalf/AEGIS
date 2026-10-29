import type { FastifyReply, FastifyRequest } from 'fastify';
import type { AppConfig } from '../config.js';
import type { Actor } from '../authz/authorize.js';
import { authorize } from '../authz/authorize.js';
import type { Capability, ResourceRef } from '../authz/capabilities.js';
import { recordAudit, recordAuditIndependently, type AuditEventInput } from '../audit/audit.js';
import { withTransaction, type DbClient, type DbContext, type Pool } from '../db/pool.js';
import type { SessionWithPrincipal } from '../identity/sessions.js';
import { Errors } from './errors.js';
import type { ProviderRegistry } from '../integrations/registry.js';

/** Shared dependencies for route handlers. */
export interface AppDeps {
  config: AppConfig;
  pool: Pool;
  providers: ProviderRegistry;
}

/**
 * Every /api route must declare how it is protected. A route without this
 * declaration fails application startup (see security plugin).
 *  - public: no session required (login, health)
 *  - session: any valid session; the handler performs its own checks
 *  - a capability: enforced before the handler runs
 */
export type RouteAuth = 'public' | 'session' | Capability;

declare module 'fastify' {
  interface FastifyContextConfig {
    auth?: RouteAuth;
  }
  interface FastifyRequest {
    actor: Actor | null;
    session: SessionWithPrincipal | null;
    activeTenant: { id: string; slug: string; displayName: string } | null;
    correlationId: string;
  }
}

export function requireActor(req: FastifyRequest): Actor {
  if (!req.actor || !req.session) throw Errors.unauthenticated();
  return req.actor;
}

export function auditActorType(actor: Actor | null): AuditEventInput['actorType'] {
  return actor ? actor.kind : 'ANONYMOUS';
}

/** Base audit fields for an event caused by this request. */
export function auditBase(
  req: FastifyRequest,
): Pick<AuditEventInput, 'actorPrincipalId' | 'actorType' | 'requestId' | 'correlationId'> {
  return {
    actorPrincipalId: req.actor?.principalId ?? null,
    actorType: auditActorType(req.actor),
    requestId: req.id,
    correlationId: req.correlationId,
  };
}

/**
 * Enforce a capability for the current actor, optionally against a loaded
 * resource. Denials are audited (in an independent transaction) and become
 * 401/403 responses. Never returns normally on denial.
 */
export async function enforce(
  deps: AppDeps,
  req: FastifyRequest,
  capability: Capability,
  resource?: ResourceRef,
): Promise<Actor> {
  const decision = authorize(req.actor, capability, {
    resource,
    reauthWindowMs: deps.config.session.reauthWindowMs,
  });
  if (decision.allowed) return req.actor!;
  if (decision.reason === 'NO_ACTOR') throw Errors.unauthenticated();
  await recordAuditIndependently(
    deps.pool,
    {
      ...auditBase(req),
      tenantId: req.actor?.tenantId ?? null,
      action: 'authz.denied',
      targetType: resource?.type ?? null,
      targetId: resource?.id ?? null,
      outcome: 'DENIED',
      reasonCode: decision.reason,
      metadata: { capability, method: req.method, route: req.routeOptions.url ?? null },
    },
    (err) => req.log.error({ err }, 'failed to record authorization denial'),
  );
  req.log.warn({ capability, reason: decision.reason }, 'authorization denied');
  throw decision.reason === 'REAUTH_REQUIRED' ? Errors.reauthRequired() : Errors.forbidden();
}

/** Context for a transaction in the actor's active tenant. */
export function tenantContext(req: FastifyRequest): DbContext & { tenantId: string } {
  const actor = requireActor(req);
  if (!actor.tenantId) throw Errors.forbidden();
  return { tenantId: actor.tenantId, principalId: actor.principalId };
}

/** Run fn in a transaction scoped to the actor's active tenant (RLS enforced). */
export function inTenant<T>(
  deps: AppDeps,
  req: FastifyRequest,
  fn: (client: DbClient, tenantId: string) => Promise<T>,
): Promise<T> {
  const ctx = tenantContext(req);
  return withTransaction(deps.pool, ctx, (client) => fn(client, ctx.tenantId));
}

/** Record a successful tenant-scoped audit event inside the caller's transaction. */
export function auditInTx(
  client: DbClient,
  req: FastifyRequest,
  e: Omit<AuditEventInput, 'actorPrincipalId' | 'actorType' | 'requestId' | 'correlationId'>,
): Promise<void> {
  return recordAudit(client, { ...auditBase(req), ...e });
}

export function noStore(reply: FastifyReply): FastifyReply {
  return reply.header('cache-control', 'no-store');
}
