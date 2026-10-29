import type { InvestigationDto } from '@aegis/shared';
import type { DbClient } from '../db/pool.js';
import { decodeTimestampCursor, encodeCursor } from '../http/cursor.js';
import { Errors } from '../http/errors.js';

interface InvestigationRow {
  id: string;
  title: string;
  status: 'OPEN' | 'CLOSED';
  summary: string | null;
  closed_at: Date | null;
  version: number;
  created_at: Date;
  updated_at: Date;
  finding_ids: string[] | null;
}

const SELECT = `SELECT i.*, (SELECT array_agg(f.finding_id ORDER BY f.added_at) FROM investigation_findings f
                              WHERE f.tenant_id = i.tenant_id AND f.investigation_id = i.id) AS finding_ids
                  FROM investigations i`;

const toDto = (r: InvestigationRow): InvestigationDto => ({
  id: r.id,
  title: r.title,
  status: r.status,
  summary: r.summary,
  findingIds: r.finding_ids ?? [],
  closedAt: r.closed_at?.toISOString() ?? null,
  version: r.version,
  createdAt: r.created_at.toISOString(),
  updatedAt: r.updated_at.toISOString(),
});

export async function getInvestigation(client: DbClient, tenantId: string, id: string) {
  const { rows } = await client.query<InvestigationRow>(
    `${SELECT} WHERE i.tenant_id = $1 AND i.id = $2`,
    [tenantId, id],
  );
  return rows[0] ? toDto(rows[0]) : null;
}

export async function listInvestigations(
  client: DbClient,
  tenantId: string,
  q: { limit: number; cursor?: string },
) {
  const cursor = decodeTimestampCursor(q.cursor);
  const params: unknown[] = [tenantId, q.limit + 1];
  let extra = '';
  if (cursor) {
    params.push(cursor.v, cursor.i);
    extra = ' AND (i.created_at, i.id) < ($3::timestamptz, $4::uuid)';
  }
  const { rows } = await client.query<InvestigationRow>(
    `${SELECT} WHERE i.tenant_id = $1${extra} ORDER BY i.created_at DESC, i.id DESC LIMIT $2`,
    params,
  );
  const page = rows.slice(0, q.limit);
  const last = page.at(-1);
  return {
    items: page.map(toDto),
    nextCursor:
      rows.length > q.limit && last
        ? encodeCursor({ v: last.created_at.toISOString(), i: last.id })
        : null,
  };
}

async function linkFindings(
  client: DbClient,
  tenantId: string,
  investigationId: string,
  ids: string[],
  actor: string,
) {
  if (ids.length === 0) return;
  const { rows } = await client.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM findings WHERE tenant_id = $1 AND id = ANY ($2::uuid[])',
    [tenantId, [...new Set(ids)]],
  );
  if (rows[0]!.n !== new Set(ids).size)
    throw Errors.validation([{ path: 'findingIds', message: 'Unknown finding' }]);
  await client.query(
    `INSERT INTO investigation_findings (tenant_id, investigation_id, finding_id, added_by)
     SELECT $1, $2, unnest($3::uuid[]), $4 ON CONFLICT DO NOTHING`,
    [tenantId, investigationId, [...new Set(ids)], actor],
  );
}

export async function createInvestigation(
  client: DbClient,
  tenantId: string,
  actor: string,
  input: { title: string; summary?: string; findingIds: string[] },
) {
  const { rows } = await client.query<{ id: string }>(
    'INSERT INTO investigations (tenant_id, title, summary, created_by) VALUES ($1, $2, $3, $4) RETURNING id',
    [tenantId, input.title, input.summary ?? null, actor],
  );
  await linkFindings(client, tenantId, rows[0]!.id, input.findingIds, actor);
  return (await getInvestigation(client, tenantId, rows[0]!.id))!;
}

export async function updateInvestigation(
  client: DbClient,
  tenantId: string,
  existing: InvestigationDto,
  actor: string,
  input: {
    version: number;
    title?: string;
    summary?: string | null;
    status?: 'OPEN' | 'CLOSED';
    addFindingIds?: string[];
    removeFindingIds?: string[];
  },
) {
  if (existing.version !== input.version)
    throw Errors.conflict('The investigation was modified by someone else');
  const nextStatus = input.status ?? existing.status;
  const editing =
    input.title !== undefined ||
    input.summary !== undefined ||
    input.addFindingIds ||
    input.removeFindingIds;
  if (existing.status === 'CLOSED' && nextStatus === 'CLOSED' && editing) {
    throw Errors.invalidTransition('CLOSED', 'CLOSED (reopen before editing)');
  }
  const { rowCount } = await client.query(
    `UPDATE investigations SET title = $3, summary = $4, status = $5,
            closed_at = CASE WHEN $5 = 'CLOSED' THEN COALESCE(closed_at, now()) ELSE NULL END,
            version = version + 1
      WHERE tenant_id = $1 AND id = $2 AND version = $6`,
    [
      tenantId,
      existing.id,
      input.title ?? existing.title,
      input.summary !== undefined ? input.summary : existing.summary,
      nextStatus,
      input.version,
    ],
  );
  if (rowCount !== 1) throw Errors.conflict('The investigation was modified by someone else');
  await linkFindings(client, tenantId, existing.id, input.addFindingIds ?? [], actor);
  if (input.removeFindingIds?.length) {
    await client.query(
      'DELETE FROM investigation_findings WHERE tenant_id = $1 AND investigation_id = $2 AND finding_id = ANY ($3::uuid[])',
      [tenantId, existing.id, input.removeFindingIds],
    );
  }
  return (await getInvestigation(client, tenantId, existing.id))!;
}
