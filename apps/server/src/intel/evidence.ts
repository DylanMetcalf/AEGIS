import type { EvidenceDto, EvidenceKind, VerificationStatus } from '@aegis/shared';
import type { DbClient } from '../db/pool.js';
import { Errors } from '../http/errors.js';
import { sha256 } from '../security/tokens.js';

/** Kinds that can ever count as proof. Notes, recommendations and model output never do. */
export const PROBATIVE_KINDS: readonly EvidenceKind[] = [
  'OBSERVATION',
  'TEST_RESULT',
  'AUDIT_RECORD',
];

interface EvidenceRow {
  id: string;
  kind: EvidenceKind;
  finding_id: string | null;
  investigation_id: string | null;
  telemetry_event_id: string | null;
  collector_type: EvidenceDto['provenance']['collectorType'];
  collector_id: string;
  collector_version: string;
  collected_at: Date;
  source_ref: string;
  content_sha256: Buffer;
  body: Record<string, unknown> | null;
  verification_status: VerificationStatus;
  verified_at: Date | null;
  created_by: string | null;
  created_at: Date;
}

const toDto = (r: EvidenceRow): EvidenceDto => ({
  id: r.id,
  kind: r.kind,
  probative: PROBATIVE_KINDS.includes(r.kind),
  findingId: r.finding_id,
  investigationId: r.investigation_id,
  telemetryEventId: r.telemetry_event_id,
  provenance: {
    collectorType: r.collector_type,
    collectorId: r.collector_id,
    collectorVersion: r.collector_version,
    collectedAt: r.collected_at.toISOString(),
    sourceRef: r.source_ref,
    contentSha256: r.content_sha256.toString('hex'),
  },
  body: r.body,
  verificationStatus: r.verification_status,
  verifiedAt: r.verified_at?.toISOString() ?? null,
  createdBy: r.created_by,
  createdAt: r.created_at.toISOString(),
});

export async function listEvidence(
  client: DbClient,
  tenantId: string,
  filter: { findingId?: string; investigationId?: string; limit: number },
): Promise<EvidenceDto[]> {
  const { rows } = await client.query<EvidenceRow>(
    `SELECT * FROM evidence
      WHERE tenant_id = $1 AND ($2::uuid IS NULL OR finding_id = $2) AND ($3::uuid IS NULL OR investigation_id = $3)
      ORDER BY created_at DESC, id DESC LIMIT $4`,
    [tenantId, filter.findingId ?? null, filter.investigationId ?? null, filter.limit],
  );
  return rows.map(toDto);
}

/** Record an analyst note. Notes are OPERATOR_NOTE evidence and can never be verified as proof. */
export async function addNote(
  client: DbClient,
  tenantId: string,
  subject: { findingId?: string; investigationId?: string },
  text: string,
  authorId: string,
): Promise<EvidenceDto> {
  const body = { text };
  const { rows } = await client.query<EvidenceRow>(
    `INSERT INTO evidence (tenant_id, kind, finding_id, investigation_id, collector_type, collector_id,
                           collector_version, collected_at, source_ref, content_sha256, body,
                           verification_status, created_by)
     VALUES ($1, 'OPERATOR_NOTE', $2, $3, 'HUMAN', $4::text, '1', now(), 'note', $5, $6, 'NOT_APPLICABLE', $4::uuid)
     RETURNING *`,
    [
      tenantId,
      subject.findingId ?? null,
      subject.investigationId ?? null,
      authorId,
      sha256(JSON.stringify(body)),
      JSON.stringify(body),
    ],
  );
  return toDto(rows[0]!);
}

/**
 * Re-verify an observation: the database recomputes the telemetry event's
 * canonical digest and compares it with both the event's stored digest and
 * the digest captured in the evidence record when it was linked.
 */
export async function verifyEvidence(
  client: DbClient,
  tenantId: string,
  id: string,
): Promise<EvidenceDto> {
  const { rows } = await client.query<EvidenceRow & { recomputed_ok: boolean | null }>(
    `SELECT e.*, (telemetry_event_digest(t) = e.content_sha256 AND t.content_sha256 = e.content_sha256) AS recomputed_ok
       FROM evidence e LEFT JOIN telemetry_events t ON t.tenant_id = e.tenant_id AND t.id = e.telemetry_event_id
      WHERE e.tenant_id = $1 AND e.id = $2 FOR UPDATE OF e`,
    [tenantId, id],
  );
  const row = rows[0];
  if (!row) throw Errors.notFound('Evidence');
  if (!PROBATIVE_KINDS.includes(row.kind) || row.kind !== 'OBSERVATION') {
    throw Errors.unprocessable('NOT_VERIFIABLE', 'Only telemetry observations can be re-verified');
  }
  const status: VerificationStatus =
    row.recomputed_ok === true
      ? 'VERIFIED'
      : row.recomputed_ok === false
        ? 'FAILED'
        : 'INCONCLUSIVE';
  const { rows: updated } = await client.query<EvidenceRow>(
    `UPDATE evidence SET verification_status = $3, verified_at = now() WHERE tenant_id = $1 AND id = $2 RETURNING *`,
    [tenantId, id, status],
  );
  return toDto(updated[0]!);
}
