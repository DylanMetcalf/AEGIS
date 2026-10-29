import { z } from 'zod';

/**
 * Resource budget contract for bounded execution.
 * STATUS: PARTIALLY_IMPLEMENTED. Background jobs enforce timeout, retry, and
 * concurrency limits today (jobs table constraints + worker). Agent-specific
 * fields (allowed/denied operations, stop conditions, expected evidence)
 * are enforced only when AI workers are implemented (Phase 4).
 */

/** Hard ceilings no budget may exceed, regardless of who requests it. */
export const BUDGET_CEILINGS = {
  timeBudgetMs: 300_000,
  maxRetries: 9,
  maxConcurrency: 16,
  maxOperations: 10_000,
} as const;

export const resourceBudgetSchema = z
  .object({
    objective: z.string().min(1).max(500),
    scope: z.object({ tenantId: z.string().uuid(), assetIds: z.array(z.string().uuid()).max(100) }).strict(),
    allowedOperations: z.array(z.string().regex(/^[a-z][a-z0-9_.]*$/)).min(1).max(50),
    deniedOperations: z.array(z.string().regex(/^[a-z][a-z0-9_.]*$/)).max(50).default([]),
    timeBudgetMs: z.number().int().min(100).max(BUDGET_CEILINGS.timeBudgetMs),
    maxOperations: z.number().int().min(1).max(BUDGET_CEILINGS.maxOperations),
    maxRetries: z.number().int().min(0).max(BUDGET_CEILINGS.maxRetries),
    maxConcurrency: z.number().int().min(1).max(BUDGET_CEILINGS.maxConcurrency),
    stopConditions: z.array(z.string().max(200)).max(20).default([]),
    expectedEvidence: z.array(z.string().max(200)).max(20).default([]),
  })
  .strict()
  .refine((b) => !b.allowedOperations.some((op) => b.deniedOperations.includes(op)), {
    message: 'An operation cannot be both allowed and denied',
    path: ['deniedOperations'],
  });

export type ResourceBudget = z.infer<typeof resourceBudgetSchema>;

/** Deny wins; anything not explicitly allowed is denied. */
export function isOperationPermitted(budget: ResourceBudget, operation: string): boolean {
  if (budget.deniedOperations.includes(operation)) return false;
  return budget.allowedOperations.includes(operation);
}
