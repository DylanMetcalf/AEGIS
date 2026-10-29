import {
  CLOSED_FINDING_STATUSES,
  findingStateMachine,
  type FindingDto,
  type FindingStatus,
  type Severity,
  type UpdateFindingRequest,
} from '@aegis/shared';
import type { DbClient } from '../db/pool.js';
import { decodeTimestampCursor, encodeCursor } from '../http/cursor.js';
import { Errors } from '../http/errors.js';

export interface FindingRow {
  id: string;
  tenant_id: string;
  rule_id: string;
  rule_version: number;
  title: string;
  severity: Severity;
  status: FindingStatus;
  group_key: string;
  asset_id: string | null;
  integration_id: string | null;
  occurrence_count: number;
  first_seen_at: Date;
  last_seen_at: Date;
  summary: Record<string, unknown>;
  resolution_note: string | null;
  assignee_principal_id: string | null;
  version: number;
  created_at: Date;
  updated_at: Date;
}

export const toFindingDto = (r: FindingRow): FindingDto => ({
  id: r.id,
  ruleId: r.rule_id,
  ruleVersion: r.rule_version,
  title: r.title,
  severity: r.severity,
  status: r.status,
  groupKey: r.group_key,
  assetId: r.asset_id,
  integrationId: r.integration_id,
  occurrenceCount: r.occurrence_count,
  firstSeenAt: r.first_seen_at.toISOString(),
  lastSeenAt: r.last_seen_at.toISOString(),
  summary: r.summary,
  resolutionNote: r.resolution_note,
  assigneePrincipalId: r.assignee_principal_id,
  version: r.version,
  createdAt: r.created_at.toISOString(),
  updatedAt: r.updated_at.toISOString(),
});

export async function getFinding(client: DbClient, tenantId: string, id: string, lock = false) {
  const { rows } = await client.query<FindingRow>(
    `SELECT * FROM findings WHERE tenant_id = $1 AND id = $2${lock ? ' FOR UPDATE' : ''}`,
    [tenantId, id],
  );
  return rows[0] ?? null;
}

export async function listFindings(
  client: DbClient,
  tenantId: string,
  q: {
    limit: number;
    cursor?: string;
    status?: FindingStatus;
    severity?: Severity;
    assetId?: string;
    active?: 'true' | 'false';
  },
) {
  const params: unknown[] = [tenantId];
  const where = ['tenant_id = $1'];
  const add = (sql: string, v: unknown) => {
    params.push(v);
    where.push(sql.replace('?', `$${params.length}`));
  };
  if (q.status) add('status = ?', q.status);
  if (q.severity) add('severity = ?', q.severity);
  if (q.assetId) add('asset_id = ?', q.assetId);
  if (q.active === 'true') where.push(`status IN ('OPEN', 'TRIAGED', 'IN_PROGRESS')`);
  if (q.active === 'false') where.push(`status NOT IN ('OPEN', 'TRIAGED', 'IN_PROGRESS')`);
  const cursor = decodeTimestampCursor(q.cursor);
  if (cursor) {
    params.push(cursor.v, cursor.i);
    where.push(
      `(last_seen_at, id) < ($${params.length - 1}::timestamptz, $${params.length}::uuid)`,
    );
  }
  params.push(q.limit + 1);
  const { rows } = await client.query<FindingRow>(
    `SELECT * FROM findings WHERE ${where.join(' AND ')}
      ORDER BY last_seen_at DESC, id DESC LIMIT $${params.length}`,
    params,
  );
  const page = rows.slice(0, q.limit);
  const last = page.at(-1);
  return {
    items: page.map(toFindingDto),
    nextCursor:
      rows.length > q.limit && last
        ? encodeCursor({ v: last.last_seen_at.toISOString(), i: last.id })
        : null,
  };
}

/** Validate and apply a finding update. Caller has already authorized; ACCEPTED_RISK needs an extra capability. */
export async function updateFinding(
  client: DbClient,
  tenantId: string,
  existing: FindingRow,
  input: UpdateFindingRequest,
) {
  if (existing.version !== input.version)
    throw Errors.conflict('The finding was modified by someone else');
  const nextStatus = input.status ?? existing.status;
  if (
    nextStatus !== existing.status &&
    !findingStateMachine.canTransition(existing.status, nextStatus)
  ) {
    throw Errors.invalidTransition(existing.status, nextStatus);
  }
  const closing = nextStatus !== existing.status && CLOSED_FINDING_STATUSES.includes(nextStatus);
  if (closing && !input.resolutionNote) {
    throw Errors.validation([
      { path: 'resolutionNote', message: 'A resolution note is required to close a finding' },
    ]);
  }
  if (input.assigneePrincipalId) {
    const { rowCount } = await client.query(
      `SELECT 1 FROM memberships m JOIN principals p ON p.id = m.principal_id
        WHERE m.tenant_id = $1 AND m.principal_id = $2 AND m.status = 'ACTIVE' AND p.kind = 'HUMAN'`,
      [tenantId, input.assigneePrincipalId],
    );
    if (rowCount !== 1)
      throw Errors.validation([
        { path: 'assigneePrincipalId', message: 'Assignee must be an active member' },
      ]);
  }
  const reopening = !CLOSED_FINDING_STATUSES.includes(nextStatus);
  const note = closing ? input.resolutionNote! : reopening ? null : existing.resolution_note;
  const { rows } = await client.query<FindingRow>(
    `UPDATE findings SET status = $3, resolution_note = $4,
            assignee_principal_id = $5, version = version + 1
      WHERE tenant_id = $1 AND id = $2 AND version = $6 RETURNING *`,
    [
      tenantId,
      existing.id,
      nextStatus,
      note,
      input.assigneePrincipalId !== undefined
        ? input.assigneePrincipalId
        : existing.assignee_principal_id,
      input.version,
    ],
  );
  if (!rows[0]) throw Errors.conflict('The finding was modified by someone else');
  return rows[0];
}
