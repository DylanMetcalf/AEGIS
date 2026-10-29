/**
 * Policy definition contract. STATUS: INTERFACE_ONLY. No policy engine runs
 * in Phase 1 and nothing in the application consumes these types yet.
 *
 * Policies are deterministic: the same inputs always produce the same
 * decision, and evaluation never calls a model. Every decision cites the
 * rule that produced it.
 */

export type PolicyEffect = 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL';

export interface PolicyRule {
  id: string;
  description: string;
  /** Declarative match over a typed input document; no executable code. */
  when: { field: string; op: 'eq' | 'neq' | 'in' | 'gte' | 'lte'; value: string | number | string[] }[];
  effect: PolicyEffect;
}

export interface PolicyDefinition {
  id: string;
  tenantId: string | null;
  version: number;
  name: string;
  /** Default when no rule matches. Must be DENY for security-relevant policies. */
  defaultEffect: PolicyEffect;
  rules: PolicyRule[];
  /** SHA-256 over the canonical definition, for configuration-integrity checks. */
  contentSha256: string;
  approvedBy: string[];
  effectiveFrom: string;
}

export interface PolicyEvaluation {
  policyId: string;
  policyVersion: number;
  decision: PolicyEffect;
  matchedRuleId: string | null;
  evaluatedAt: string;
  inputSha256: string;
}
