import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  ActionExecutionDisabledError,
  DisabledActionExecutor,
  executionPreconditionErrors,
  type DefensiveAction,
} from '../src/contracts/defensive-action.js';
import { evidenceReferenceSchema, isConfirmedEvidence, type EvidenceReference } from '../src/contracts/evidence.js';
import { recoveryReadiness } from '../src/contracts/recovery.js';
import { isOperationPermitted, resourceBudgetSchema } from '../src/contracts/resource-budget.js';
import { aggregateVerification, type VerificationCheck } from '../src/contracts/verification.js';

describe('defensive action contract', () => {
  const action = (o: Partial<DefensiveAction> = {}): DefensiveAction => ({
    id: randomUUID(),
    tenantId: randomUUID(),
    actionType: 'block_ip',
    target: { tenantId: 't', assetId: 'a', scopeIdentifier: 'x' },
    riskTier: 'HIGH',
    requestedBy: { principalId: 'requester', kind: 'HUMAN' },
    preconditions: [{ description: 'target in scope', verified: true }],
    requiredApprovals: 1,
    approvals: [{ principalId: 'approver', at: new Date().toISOString() }],
    status: 'AUTHORIZED',
    executionRecord: null,
    verification: null,
    auditEventIds: [],
    failure: null,
    recoveryRef: 'plan-1',
    ...o,
  });

  it('has no working executor in Phase 1', async () => {
    await expect(DisabledActionExecutor.execute(action(), AbortSignal.timeout(1000))).rejects.toBeInstanceOf(
      ActionExecutionDisabledError,
    );
  });

  it('accepts a fully authorized, approved, recoverable action', () => {
    expect(executionPreconditionErrors(action())).toEqual([]);
  });

  it('rejects unauthorized, self-approved, unrecoverable, or unverified actions', () => {
    expect(executionPreconditionErrors(action({ status: 'PROPOSED' }))).toContain('NOT_AUTHORIZED');
    expect(executionPreconditionErrors(action({ approvals: [] }))).toContain('INSUFFICIENT_APPROVALS');
    expect(
      executionPreconditionErrors(action({ approvals: [{ principalId: 'requester', at: '' }] })),
    ).toContain('SELF_APPROVAL');
    expect(executionPreconditionErrors(action({ recoveryRef: null }))).toContain('NO_RECOVERY_PLAN');
    expect(
      executionPreconditionErrors(action({ preconditions: [{ description: 'x', verified: false }] })),
    ).toContain('UNVERIFIED_PRECONDITION');
    expect(
      executionPreconditionErrors(
        action({ riskTier: 'CRITICAL', approvals: [{ principalId: 'a', at: '' }, { principalId: 'a', at: '' }] }),
      ),
    ).toContain('DUPLICATE_APPROVER');
  });
});

describe('evidence contract', () => {
  const ev = (o: Partial<EvidenceReference> = {}): EvidenceReference => ({
    id: randomUUID(),
    tenantId: randomUUID(),
    kind: 'TEST_RESULT',
    subjects: [{ type: 'asset', id: 'a1' }],
    provenance: {
      collector: { type: 'PLATFORM', id: 'probe', version: '1' },
      collectedAt: new Date().toISOString(),
      sourceRef: 'job:1',
      contentSha256: 'a'.repeat(64),
      integrationId: null,
    },
    verificationStatus: 'VERIFIED',
    expiresAt: null,
    ...o,
  });

  it('validates the reference shape', () => {
    expect(evidenceReferenceSchema.safeParse(ev()).success).toBe(true);
    expect(evidenceReferenceSchema.safeParse({ ...ev(), subjects: [] }).success).toBe(false);
  });

  it('distinguishes evidence from recommendations, notes, and model assertions', () => {
    expect(isConfirmedEvidence(ev())).toBe(true);
    for (const kind of ['RECOMMENDATION', 'OPERATOR_NOTE', 'MODEL_ASSERTION'] as const) {
      expect(isConfirmedEvidence(ev({ kind }))).toBe(false);
    }
    expect(
      isConfirmedEvidence(ev({ provenance: { ...ev().provenance, collector: { type: 'AI_MODEL', id: 'm', version: '1' } } })),
    ).toBe(false);
    expect(isConfirmedEvidence(ev({ verificationStatus: 'NOT_RUN' }))).toBe(false);
    expect(isConfirmedEvidence(ev({ expiresAt: '2000-01-01T00:00:00Z' }))).toBe(false);
  });
});

describe('verification aggregation', () => {
  const now = new Date('2026-06-01T00:00:00Z');
  const c = (status: VerificationCheck['status'], o: Partial<VerificationCheck> = {}): VerificationCheck => ({
    key: Math.random().toString(),
    required: true,
    status,
    observedAt: now.toISOString(),
    verifier: { id: 'v', independent: true },
    evidenceIds: [],
    ...o,
  });
  const agg = (checks: VerificationCheck[], extra = {}) =>
    aggregateVerification(checks, { maxAgeMs: 3600_000, now, ...extra }).status;

  it('is VERIFIED only when every required check passed and is fresh', () => {
    expect(agg([c('VERIFIED'), c('VERIFIED')])).toBe('VERIFIED');
    expect(agg([c('VERIFIED'), c('VERIFIED', { observedAt: '2026-01-01T00:00:00Z' })])).toBe('STALE');
    expect(agg([c('VERIFIED'), c('NOT_RUN')])).toBe('PARTIALLY_VERIFIED');
  });

  it('never treats a verifier that could not run as a pass', () => {
    expect(agg([])).toBe('NOT_RUN');
    expect(agg([c('NOT_RUN')])).toBe('NOT_RUN');
    expect(agg([c('VERIFIED'), c('BLOCKED')])).toBe('BLOCKED');
    expect(agg([c('INCONCLUSIVE')])).toBe('INCONCLUSIVE');
    expect(agg([c('VERIFIED', { required: false })])).toBe('INCONCLUSIVE');
  });

  it('lets any failure dominate', () => {
    expect(agg([c('VERIFIED'), c('FAILED'), c('BLOCKED')])).toBe('FAILED');
  });

  it('can require independent verifiers', () => {
    const self = c('VERIFIED', { verifier: { id: 'app', independent: false } });
    expect(agg([self])).toBe('VERIFIED');
    expect(agg([self], { requireIndependentVerifier: true })).toBe('INCONCLUSIVE');
  });
});

describe('resource budgets', () => {
  const budget = {
    objective: 'check integration health',
    scope: { tenantId: randomUUID(), assetIds: [] },
    allowedOperations: ['integration.health_check'],
    timeBudgetMs: 20000,
    maxOperations: 1,
    maxRetries: 1,
    maxConcurrency: 1,
  };

  it('enforces hard ceilings and explicit allow lists', () => {
    const parsed = resourceBudgetSchema.parse(budget);
    expect(isOperationPermitted(parsed, 'integration.health_check')).toBe(true);
    expect(isOperationPermitted(parsed, 'asset.delete')).toBe(false);
    expect(resourceBudgetSchema.safeParse({ ...budget, timeBudgetMs: 10_000_000 }).success).toBe(false);
    expect(resourceBudgetSchema.safeParse({ ...budget, maxRetries: 1000 }).success).toBe(false);
    expect(
      resourceBudgetSchema.safeParse({ ...budget, deniedOperations: ['integration.health_check'] }).success,
    ).toBe(false);
  });
});

describe('recovery readiness', () => {
  it('is not run or stale without recent exercised evidence', () => {
    expect(recoveryReadiness(null, 1000)).toBe('NOT_RUN');
    const plan = {
      id: 'p',
      tenantId: null,
      scope: 'PLATFORM' as const,
      subjectId: null,
      steps: [],
      requiredAuthority: 'RECOVERY_AUTHORITY' as const,
      lastExercisedAt: '2020-01-01T00:00:00Z',
      lastExerciseResult: 'VERIFIED' as const,
    };
    expect(recoveryReadiness(plan, 1000)).toBe('STALE');
    expect(recoveryReadiness({ ...plan, lastExercisedAt: new Date().toISOString() }, 60_000)).toBe('VERIFIED');
  });
});
