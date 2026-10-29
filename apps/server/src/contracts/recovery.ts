import type { VerificationStatus } from '@aegis/shared';

/**
 * Recovery contract. STATUS: INTERFACE_ONLY. Recovery execution is Phase 3.
 * Readiness is reported UNVERIFIED until a recovery procedure has been
 * exercised and its evidence recorded.
 */

export interface RecoveryPlan {
  id: string;
  tenantId: string | null;
  scope: 'PLATFORM' | 'TENANT' | 'ASSET';
  subjectId: string | null;
  steps: { order: number; description: string; requiresCapability: 'recovery.execute' }[];
  /** Recovery authority must be distinct from ordinary administration. */
  requiredAuthority: 'RECOVERY_AUTHORITY';
  lastExercisedAt: string | null;
  lastExerciseResult: VerificationStatus;
}

export function recoveryReadiness(
  plan: RecoveryPlan | null,
  maxAgeMs: number,
  now = new Date(),
): VerificationStatus {
  if (!plan || !plan.lastExercisedAt) return 'NOT_RUN';
  if (now.getTime() - Date.parse(plan.lastExercisedAt) > maxAgeMs) return 'STALE';
  return plan.lastExerciseResult;
}
