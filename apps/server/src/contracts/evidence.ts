import { z } from 'zod';
import type { VerificationStatus } from '@aegis/shared';

/**
 * Evidence contract. STATUS: INTERFACE_ONLY. The evidence engine (collection,
 * provenance capture, storage) is Phase 2. Today the hash-chained audit log
 * is the only evidence source.
 *
 * Evidence must be distinguishable from things that merely look like it.
 * Only OBSERVATION and TEST_RESULT kinds, collected by a non-model collector
 * and independently VERIFIED, count as confirmed evidence.
 */

export const EVIDENCE_KINDS = [
  'OBSERVATION', // raw data collected from a system
  'TEST_RESULT', // outcome of a defined, repeatable check
  'AUDIT_RECORD', // reference to an audit event
  'OPERATOR_NOTE', // human commentary; never proof
  'RECOMMENDATION', // suggested action; never proof
  'MODEL_ASSERTION', // AI-generated claim; never proof
] as const;
export type EvidenceKind = (typeof EVIDENCE_KINDS)[number];

export const SUBJECT_TYPES = [
  'asset',
  'finding',
  'action',
  'verification',
  'audit_event',
  'integration',
  'incident',
] as const;

export const provenanceSchema = z
  .object({
    collector: z.object({
      type: z.enum(['INTEGRATION', 'PLATFORM', 'HUMAN', 'AI_MODEL']),
      id: z.string().min(1).max(128),
      version: z.string().max(64),
    }),
    collectedAt: z.string().datetime({ offset: true }),
    sourceRef: z.string().max(512),
    /** SHA-256 of the stored evidence content. */
    contentSha256: z.string().regex(/^[0-9a-f]{64}$/),
    integrationId: z.string().uuid().nullable(),
  })
  .strict();

export const evidenceReferenceSchema = z
  .object({
    id: z.string().uuid(),
    tenantId: z.string().uuid(),
    kind: z.enum(EVIDENCE_KINDS),
    subjects: z
      .array(z.object({ type: z.enum(SUBJECT_TYPES), id: z.string().min(1).max(128) }).strict())
      .min(1)
      .max(20),
    provenance: provenanceSchema,
    verificationStatus: z.enum([
      'VERIFIED',
      'FAILED',
      'PARTIALLY_VERIFIED',
      'INCONCLUSIVE',
      'NOT_RUN',
      'BLOCKED',
      'STALE',
      'NOT_APPLICABLE',
    ]),
    expiresAt: z.string().datetime({ offset: true }).nullable(),
  })
  .strict();

export type EvidenceReference = z.infer<typeof evidenceReferenceSchema>;

/** Whether a piece of evidence may be cited as proof. */
export function isConfirmedEvidence(e: EvidenceReference, now = new Date()): boolean {
  if (e.kind !== 'OBSERVATION' && e.kind !== 'TEST_RESULT' && e.kind !== 'AUDIT_RECORD')
    return false;
  if (e.provenance.collector.type === 'AI_MODEL') return false;
  if (e.verificationStatus !== ('VERIFIED' satisfies VerificationStatus)) return false;
  if (e.expiresAt && Date.parse(e.expiresAt) <= now.getTime()) return false;
  return true;
}
