import { actionStateMachine, type ActionStatus, type VerificationStatus } from '@aegis/shared';
import type { Capability } from '../authz/capabilities.js';

/**
 * Defensive-action contract. STATUS: INTERFACE_ONLY.
 *
 * Lifecycle: OBSERVE -> INVESTIGATE -> PROPOSE -> AUTHORIZE -> EXECUTE ->
 * VERIFY -> RECORD. A DefensiveAction record begins at PROPOSED; its status
 * follows actionStateMachine (packages/shared/src/state-machine.ts).
 *
 * Phase 1 deliberately provides NO executor: DisabledActionExecutor refuses
 * every request. There is no shell execution, remote code execution, or
 * generic privileged infrastructure operation anywhere in the application.
 */

export const RISK_TIERS = ['LOW', 'MODERATE', 'HIGH', 'CRITICAL'] as const;
export type RiskTier = (typeof RISK_TIERS)[number];

export interface ActionTarget {
  tenantId: string;
  assetId: string;
  /** Narrowest identifier within the asset's authorization scope. */
  scopeIdentifier: string;
}

export interface DefensiveAction {
  id: string;
  tenantId: string;
  actionType: string;
  target: ActionTarget;
  riskTier: RiskTier;
  requestedBy: { principalId: string; kind: 'HUMAN' | 'SERVICE' | 'AI_WORKER' };
  preconditions: { description: string; verified: boolean }[];
  /** Approvals required before AUTHORIZED; derived from risk tier and policy. */
  requiredApprovals: number;
  approvals: { principalId: string; at: string }[];
  status: ActionStatus;
  executionRecord: { startedAt: string; finishedAt: string | null; outputRef: string | null } | null;
  verification: { status: VerificationStatus; resultRef: string | null } | null;
  auditEventIds: string[];
  failure: { code: string; at: string } | null;
  /** How to undo or recover if the action causes harm. Required for HIGH and CRITICAL. */
  recoveryRef: string | null;
}

/** Approvals required per risk tier. Higher tiers also need a distinct approver. */
export const REQUIRED_APPROVALS: Readonly<Record<RiskTier, number>> = {
  LOW: 0,
  MODERATE: 1,
  HIGH: 1,
  CRITICAL: 2,
};

/** Capability needed to approve, by tier (enforced through authorize()). */
export const APPROVAL_CAPABILITY: Capability = 'action.approve';

/** Checks that must all hold before an action may move to EXECUTING. */
export function executionPreconditionErrors(a: DefensiveAction): string[] {
  const errors: string[] = [];
  if (!actionStateMachine.canTransition(a.status, 'EXECUTING')) errors.push('NOT_AUTHORIZED');
  if (a.approvals.length < REQUIRED_APPROVALS[a.riskTier]) errors.push('INSUFFICIENT_APPROVALS');
  if (a.approvals.some((x) => x.principalId === a.requestedBy.principalId) && a.riskTier !== 'LOW') {
    errors.push('SELF_APPROVAL');
  }
  if (new Set(a.approvals.map((x) => x.principalId)).size !== a.approvals.length) errors.push('DUPLICATE_APPROVER');
  if (a.preconditions.some((p) => !p.verified)) errors.push('UNVERIFIED_PRECONDITION');
  if ((a.riskTier === 'HIGH' || a.riskTier === 'CRITICAL') && !a.recoveryRef) errors.push('NO_RECOVERY_PLAN');
  if (a.requestedBy.kind === 'AI_WORKER' && a.riskTier !== 'LOW' && a.approvals.length === 0) {
    errors.push('AI_PROPOSAL_REQUIRES_HUMAN_APPROVAL');
  }
  return errors;
}

export interface ActionExecutor {
  execute(action: DefensiveAction, signal: AbortSignal): Promise<never>;
}

export class ActionExecutionDisabledError extends Error {
  readonly code = 'ACTION_EXECUTION_DISABLED';
  constructor() {
    super('Defensive action execution is not available in this phase');
    this.name = 'ActionExecutionDisabledError';
  }
}

/** The only executor that exists in Phase 1. */
export const DisabledActionExecutor: ActionExecutor = {
  async execute() {
    throw new ActionExecutionDisabledError();
  },
};
