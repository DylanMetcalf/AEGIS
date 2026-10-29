import type { VerificationStatus } from '@aegis/shared';

/**
 * Verification result contract. STATUS: INTERFACE_ONLY (no verifier runs).
 *
 * Aggregation is deliberately pessimistic: a result is VERIFIED only when
 * every required check ran, is fresh, and passed. A verifier that could not
 * run is never treated as a pass.
 */

export interface VerificationCheck {
  key: string;
  required: boolean;
  status: VerificationStatus;
  observedAt: string | null;
  /** Identity of the verifier. Later phases require it to be independent of the actor verified. */
  verifier: { id: string; independent: boolean };
  evidenceIds: string[];
}

export interface VerificationResult {
  status: VerificationStatus;
  checks: VerificationCheck[];
  evaluatedAt: string;
}

export function aggregateVerification(
  checks: VerificationCheck[],
  opts: { maxAgeMs: number; now?: Date; requireIndependentVerifier?: boolean },
): VerificationResult {
  const now = opts.now ?? new Date();
  const normalized = checks.map((c): VerificationCheck => {
    if (c.status === 'VERIFIED' || c.status === 'PARTIALLY_VERIFIED') {
      const age = c.observedAt ? now.getTime() - Date.parse(c.observedAt) : Infinity;
      if (!(age <= opts.maxAgeMs)) return { ...c, status: 'STALE' };
      if (opts.requireIndependentVerifier && !c.verifier.independent) return { ...c, status: 'INCONCLUSIVE' };
    }
    return c;
  });
  const required = normalized.filter((c) => c.required);
  const result = (status: VerificationStatus): VerificationResult => ({
    status,
    checks: normalized,
    evaluatedAt: now.toISOString(),
  });

  if (required.length === 0) {
    return result(normalized.length === 0 ? 'NOT_RUN' : 'INCONCLUSIVE');
  }
  const has = (s: VerificationStatus) => required.some((c) => c.status === s);
  if (has('FAILED')) return result('FAILED');
  if (has('BLOCKED')) return result('BLOCKED');
  if (required.every((c) => c.status === 'NOT_APPLICABLE')) return result('NOT_APPLICABLE');
  const relevant = required.filter((c) => c.status !== 'NOT_APPLICABLE');
  if (relevant.every((c) => c.status === 'VERIFIED')) return result('VERIFIED');
  if (relevant.every((c) => c.status === 'NOT_RUN')) return result('NOT_RUN');
  if (has('STALE') && relevant.every((c) => c.status === 'VERIFIED' || c.status === 'STALE')) return result('STALE');
  if (relevant.some((c) => c.status === 'VERIFIED' || c.status === 'PARTIALLY_VERIFIED')) {
    return result('PARTIALLY_VERIFIED');
  }
  return result('INCONCLUSIVE');
}
