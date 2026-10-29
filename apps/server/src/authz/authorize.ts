import type {
  MembershipStatus,
  PlatformRole,
  PrincipalKind,
  PrincipalStatus,
  TenantRole,
} from '@aegis/shared';
import {
  CAPABILITIES,
  PLATFORM_ROLE_CAPABILITIES,
  TENANT_ROLE_CAPABILITIES,
  isCapability,
  type Capability,
  type CapabilityDef,
  type ResourceRef,
} from './capabilities.js';

/**
 * The authenticated actor as established by the server. Every field comes
 * from server-side state (session + database), never from the request body.
 */
export interface Actor {
  principalId: string;
  kind: PrincipalKind;
  status: PrincipalStatus;
  platformRole: PlatformRole | null;
  /** Active tenant context, if any. */
  tenantId: string | null;
  tenantStatus: 'ACTIVE' | 'SUSPENDED' | null;
  role: TenantRole | null;
  membershipStatus: MembershipStatus | null;
  sessionId: string | null;
  reauthenticatedAt: Date | null;
}

export type DenyReason =
  | 'NO_ACTOR'
  | 'UNKNOWN_CAPABILITY'
  | 'PRINCIPAL_INACTIVE'
  | 'NO_TENANT_CONTEXT'
  | 'TENANT_INACTIVE'
  | 'NOT_A_MEMBER'
  | 'MEMBERSHIP_INACTIVE'
  | 'CAPABILITY_NOT_GRANTED'
  | 'TENANT_MISMATCH'
  | 'ACTOR_TYPE_RESTRICTED'
  | 'REAUTH_REQUIRED';

export type Decision = { allowed: true } | { allowed: false; reason: DenyReason };

export interface AuthorizeOptions {
  resource?: ResourceRef;
  now?: Date;
  reauthWindowMs: number;
}

const deny = (reason: DenyReason): Decision => ({ allowed: false, reason });

/**
 * Deterministic authorization decision. Pure: no I/O, no global state.
 * Any condition that cannot be positively established results in denial.
 */
export function authorize(
  actor: Actor | null | undefined,
  capability: string,
  opts: AuthorizeOptions,
): Decision {
  if (!actor) return deny('NO_ACTOR');
  if (!isCapability(capability)) return deny('UNKNOWN_CAPABILITY');
  const def: CapabilityDef = CAPABILITIES[capability];
  if (actor.status !== 'ACTIVE') return deny('PRINCIPAL_INACTIVE');

  // Phase 1: AI workers are strictly read-only, whatever role they hold.
  if (actor.kind === 'AI_WORKER' && def.sensitivity !== 'read') {
    return deny('ACTOR_TYPE_RESTRICTED');
  }
  // Non-interactive identities cannot satisfy reauthentication, so they can
  // never perform operations that require it.
  if (actor.kind !== 'HUMAN' && def.sensitivity === 'privileged') {
    return deny('ACTOR_TYPE_RESTRICTED');
  }

  if (def.scope === 'platform') {
    const granted = actor.platformRole ? PLATFORM_ROLE_CAPABILITIES[actor.platformRole] : [];
    if (!granted.includes(capability)) return deny('CAPABILITY_NOT_GRANTED');
    if (opts.resource && opts.resource.tenantId !== null) return deny('TENANT_MISMATCH');
  } else {
    if (!actor.tenantId) return deny('NO_TENANT_CONTEXT');
    if (actor.tenantStatus !== 'ACTIVE') return deny('TENANT_INACTIVE');
    if (!actor.role || !actor.membershipStatus) return deny('NOT_A_MEMBER');
    if (actor.membershipStatus !== 'ACTIVE') return deny('MEMBERSHIP_INACTIVE');
    const granted: readonly Capability[] = TENANT_ROLE_CAPABILITIES[actor.role] ?? [];
    if (!granted.includes(capability)) return deny('CAPABILITY_NOT_GRANTED');
    // Possessing a resource ID is not permission: the resource must belong to
    // the actor's active tenant.
    if (opts.resource && opts.resource.tenantId !== actor.tenantId) return deny('TENANT_MISMATCH');
  }

  const needsRecentAuth =
    typeof def.requiresRecentAuth === 'function'
      ? def.requiresRecentAuth(opts.resource)
      : def.requiresRecentAuth === true;
  if (needsRecentAuth) {
    const now = (opts.now ?? new Date()).getTime();
    const at = actor.reauthenticatedAt?.getTime();
    if (at === undefined || now - at > opts.reauthWindowMs || at > now + 60_000) {
      return deny('REAUTH_REQUIRED');
    }
  }
  return { allowed: true };
}

/**
 * Capabilities the actor holds, assuming reauthentication would be provided
 * when required. Advisory for the UI only; the server checks every request.
 */
export function effectiveCapabilities(actor: Actor): Capability[] {
  const now = new Date();
  const reauthed: Actor = { ...actor, reauthenticatedAt: now };
  return (Object.keys(CAPABILITIES) as Capability[])
    .filter((c) => authorize(reauthed, c, { now, reauthWindowMs: 60_000 }).allowed)
    .sort();
}
