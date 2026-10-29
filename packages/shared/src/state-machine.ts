import type { ActionStatus, AssetStatus, FindingStatus, IntegrationStatus } from './enums.js';

/**
 * A finite state machine described by an explicit transition table.
 * Anything not listed is rejected. Used server-side to validate every
 * state change before it is written.
 */
export interface StateMachine<S extends string> {
  readonly name: string;
  readonly transitions: Readonly<Record<S, readonly S[]>>;
  canTransition(from: S, to: S): boolean;
  /** Terminal states have no outgoing transitions. */
  isTerminal(state: S): boolean;
}

export function defineStateMachine<S extends string>(
  name: string,
  transitions: Record<S, readonly S[]>,
): StateMachine<S> {
  const frozen = Object.freeze(
    Object.fromEntries(
      Object.entries(transitions).map(([k, v]) => [k, Object.freeze([...(v as S[])])]),
    ),
  ) as Readonly<Record<S, readonly S[]>>;
  return {
    name,
    transitions: frozen,
    canTransition(from, to) {
      const allowed = frozen[from];
      return Array.isArray(allowed) && allowed.includes(to);
    },
    isTerminal(state) {
      const allowed = frozen[state];
      return !allowed || allowed.length === 0;
    },
  };
}

/**
 * Integration lifecycle. Note that creating or reconfiguring an integration
 * lands in CONFIGURED, never CONNECTED: only a health check can establish
 * connectivity, and any configuration change invalidates prior results.
 */
export const integrationStateMachine = defineStateMachine<IntegrationStatus>('integration', {
  UNCONFIGURED: ['CONFIGURED', 'REVOKED'],
  CONFIGURED: ['CONNECTING', 'SUSPENDED', 'REVOKED', 'CONFIGURED'],
  CONNECTING: ['CONNECTED', 'DEGRADED', 'DISCONNECTED', 'UNKNOWN', 'SUSPENDED', 'REVOKED'],
  CONNECTED: ['CONNECTING', 'CONFIGURED', 'SUSPENDED', 'REVOKED'],
  DEGRADED: ['CONNECTING', 'CONFIGURED', 'SUSPENDED', 'REVOKED'],
  DISCONNECTED: ['CONNECTING', 'CONFIGURED', 'SUSPENDED', 'REVOKED'],
  UNKNOWN: ['CONNECTING', 'CONFIGURED', 'SUSPENDED', 'REVOKED'],
  SUSPENDED: ['CONFIGURED', 'REVOKED'],
  REVOKED: [],
});

export const assetStateMachine = defineStateMachine<AssetStatus>('asset', {
  ACTIVE: ['INACTIVE', 'DECOMMISSIONED'],
  INACTIVE: ['ACTIVE', 'DECOMMISSIONED'],
  DECOMMISSIONED: [],
});

/**
 * Defensive-action lifecycle contract (execution is NOT implemented in
 * Phase 1). OBSERVE -> INVESTIGATE happen before an action record exists;
 * the record begins at PROPOSED.
 */
export const actionStateMachine = defineStateMachine<ActionStatus>('defensive_action', {
  PROPOSED: ['PENDING_APPROVAL', 'AUTHORIZED', 'CANCELLED'],
  PENDING_APPROVAL: ['AUTHORIZED', 'CANCELLED'],
  AUTHORIZED: ['EXECUTING', 'CANCELLED'],
  EXECUTING: ['EXECUTED', 'PARTIALLY_EXECUTED', 'FAILED'],
  EXECUTED: ['VERIFYING'],
  PARTIALLY_EXECUTED: ['VERIFYING', 'FAILED'],
  VERIFYING: ['VERIFIED', 'FAILED', 'INCONCLUSIVE'],
  VERIFIED: [],
  FAILED: [],
  INCONCLUSIVE: ['VERIFYING'],
  CANCELLED: [],
});

/**
 * Finding lifecycle. Closing states require a resolution note (DB constraint);
 * any closed finding can be reopened. Recurrence after closure opens a new finding.
 */
export const findingStateMachine = defineStateMachine<FindingStatus>('finding', {
  OPEN: ['TRIAGED', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'],
  TRIAGED: ['IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'],
  IN_PROGRESS: ['TRIAGED', 'RESOLVED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'],
  RESOLVED: ['OPEN'],
  FALSE_POSITIVE: ['OPEN'],
  ACCEPTED_RISK: ['OPEN'],
});
