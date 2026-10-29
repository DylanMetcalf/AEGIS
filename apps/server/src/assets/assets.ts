import {
  assetStateMachine,
  type AssetDto,
  type AssetStatus,
  type AssetType,
  type AuthorizationScope,
  type CoverageState,
  type CreateAssetRequest,
  type Criticality,
  type Environment,
  type UpdateAssetRequest,
} from '@aegis/shared';
import type { DbClient } from '../db/pool.js';
import { decodeCursor, decodeTimestampCursor, encodeCursor } from '../http/cursor.js';
import { Errors } from '../http/errors.js';

export interface AssetRow {
  id: string;
  tenant_id: string;
  name: string;
  asset_type: AssetType;
  environment: Environment;
  criticality: Criticality;
  status: AssetStatus;
  description: string | null;
  authorization_scope: AuthorizationScope;
  version: number;
  created_at: Date;
  updated_at: Date;
}

const COLUMNS = `id, tenant_id, name, asset_type, environment, criticality, status,
  description, authorization_scope, version, created_at, updated_at`;

/** Coverage is computed from live signals (coverage/coverage.ts); callers supply it. */
export function toAssetDto(r: AssetRow, coverageState: CoverageState = 'UNKNOWN'): AssetDto {
  return {
    id: r.id,
    name: r.name,
    assetType: r.asset_type,
    environment: r.environment,
    criticality: r.criticality,
    status: r.status,
    coverageState,
    description: r.description,
    authorizationScope: r.authorization_scope,
    version: r.version,
    createdAt: r.created_at.toISOString(),
    updatedAt: r.updated_at.toISOString(),
  };
}

export async function getAsset(
  client: DbClient,
  tenantId: string,
  id: string,
): Promise<AssetRow | null> {
  const { rows } = await client.query<AssetRow>(
    `SELECT ${COLUMNS} FROM assets WHERE tenant_id = $1 AND id = $2`,
    [tenantId, id],
  );
  return rows[0] ?? null;
}

export async function listAssets(
  client: DbClient,
  tenantId: string,
  q: {
    limit: number;
    cursor?: string;
    assetType?: AssetType;
    environment?: Environment;
    status?: AssetStatus;
    sort: 'createdAt' | 'name';
    order: 'asc' | 'desc';
  },
): Promise<{ items: AssetDto[]; nextCursor: string | null }> {
  // Sort column and direction come from an allowlist, never from raw input.
  const sortCol = q.sort === 'name' ? 'name' : 'created_at';
  const sortType = q.sort === 'name' ? 'text' : 'timestamptz';
  const dir = q.order === 'asc' ? 'ASC' : 'DESC';
  const cmp = q.order === 'asc' ? '>' : '<';

  const params: unknown[] = [tenantId];
  const where = ['tenant_id = $1'];
  for (const [col, val] of [
    ['asset_type', q.assetType],
    ['environment', q.environment],
    ['status', q.status],
  ] as const) {
    if (val) {
      params.push(val);
      where.push(`${col} = $${params.length}`);
    }
  }
  const cursor = q.sort === 'name' ? decodeCursor(q.cursor) : decodeTimestampCursor(q.cursor);
  if (cursor) {
    params.push(cursor.v, cursor.i);
    where.push(
      `(${sortCol}, id) ${cmp} ($${params.length - 1}::${sortType}, $${params.length}::uuid)`,
    );
  }
  params.push(q.limit + 1);
  const { rows } = await client.query<AssetRow>(
    `SELECT ${COLUMNS} FROM assets WHERE ${where.join(' AND ')}
      ORDER BY ${sortCol} ${dir}, id ${dir} LIMIT $${params.length}`,
    params,
  );
  const page = rows.slice(0, q.limit);
  const last = page.at(-1);
  return {
    items: page.map((r) => toAssetDto(r)),
    nextCursor:
      rows.length > q.limit && last
        ? encodeCursor({
            v: q.sort === 'name' ? last.name : last.created_at.toISOString(),
            i: last.id,
          })
        : null,
  };
}

export async function createAsset(
  client: DbClient,
  tenantId: string,
  actorId: string,
  input: CreateAssetRequest,
): Promise<AssetRow> {
  const { rows } = await client.query<AssetRow>(
    `INSERT INTO assets (tenant_id, name, asset_type, environment, criticality, description,
                         authorization_scope, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     RETURNING ${COLUMNS}`,
    [
      tenantId,
      input.name,
      input.assetType,
      input.environment,
      input.criticality,
      input.description ?? null,
      JSON.stringify(input.authorizationScope),
      actorId,
    ],
  );
  return rows[0]!;
}

export async function updateAsset(
  client: DbClient,
  tenantId: string,
  existing: AssetRow,
  input: UpdateAssetRequest,
): Promise<{ row: AssetRow; changed: string[] }> {
  if (existing.version !== input.version)
    throw Errors.conflict('The asset was modified by someone else');
  if (existing.status === 'DECOMMISSIONED') {
    throw Errors.invalidTransition('DECOMMISSIONED', input.status ?? 'DECOMMISSIONED');
  }
  if (input.status && input.status !== existing.status) {
    if (!assetStateMachine.canTransition(existing.status, input.status)) {
      throw Errors.invalidTransition(existing.status, input.status);
    }
  }
  const next = {
    name: input.name ?? existing.name,
    asset_type: input.assetType ?? existing.asset_type,
    environment: input.environment ?? existing.environment,
    criticality: input.criticality ?? existing.criticality,
    status: input.status ?? existing.status,
    description: input.description !== undefined ? input.description : existing.description,
    authorization_scope: input.authorizationScope ?? existing.authorization_scope,
  };
  const changed = (Object.keys(next) as (keyof typeof next)[]).filter(
    (k) => JSON.stringify(next[k]) !== JSON.stringify(existing[k]),
  );
  const { rows } = await client.query<AssetRow>(
    `UPDATE assets SET name = $3, asset_type = $4, environment = $5, criticality = $6, status = $7,
            description = $8, authorization_scope = $9, version = version + 1
      WHERE tenant_id = $1 AND id = $2 AND version = $10
      RETURNING ${COLUMNS}`,
    [
      tenantId,
      existing.id,
      next.name,
      next.asset_type,
      next.environment,
      next.criticality,
      next.status,
      next.description,
      JSON.stringify(next.authorization_scope),
      input.version,
    ],
  );
  if (!rows[0]) throw Errors.conflict('The asset was modified by someone else');
  return { row: rows[0], changed };
}

export async function deleteAsset(
  client: DbClient,
  tenantId: string,
  id: string,
): Promise<boolean> {
  const res = await client.query('DELETE FROM assets WHERE tenant_id = $1 AND id = $2', [
    tenantId,
    id,
  ]);
  return (res.rowCount ?? 0) === 1;
}
