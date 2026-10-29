import type { GraphDto, RelationshipDto, RelationshipKind } from '@aegis/shared';
import type { DbClient } from '../db/pool.js';
import { Errors } from '../http/errors.js';

/** Relational knowledge graph over assets (ADR: no graph database until a demonstrated need). */

const MAX_GRAPH_ASSETS = 100;

interface RelRow {
  id: string;
  from_asset_id: string;
  to_asset_id: string;
  kind: RelationshipKind;
  created_at: Date;
}
const toDto = (r: RelRow): RelationshipDto => ({
  id: r.id,
  fromAssetId: r.from_asset_id,
  toAssetId: r.to_asset_id,
  kind: r.kind,
  createdAt: r.created_at.toISOString(),
});

export async function listRelationships(client: DbClient, tenantId: string, assetId: string) {
  const { rows } = await client.query<RelRow>(
    `SELECT id, from_asset_id, to_asset_id, kind, created_at FROM asset_relationships
      WHERE tenant_id = $1 AND (from_asset_id = $2 OR to_asset_id = $2) ORDER BY created_at LIMIT 200`,
    [tenantId, assetId],
  );
  return rows.map(toDto);
}

export async function createRelationship(
  client: DbClient,
  tenantId: string,
  actor: string,
  input: { fromAssetId: string; toAssetId: string; kind: RelationshipKind },
) {
  const { rows: found } = await client.query<{ n: number }>(
    'SELECT count(*)::int AS n FROM assets WHERE tenant_id = $1 AND id = ANY ($2::uuid[])',
    [tenantId, [input.fromAssetId, input.toAssetId]],
  );
  if (found[0]!.n !== 2)
    throw Errors.validation([
      { path: 'toAssetId', message: 'Both assets must exist in this tenant' },
    ]);
  const { rows } = await client.query<RelRow>(
    `INSERT INTO asset_relationships (tenant_id, from_asset_id, to_asset_id, kind, created_by)
     VALUES ($1, $2, $3, $4, $5) RETURNING id, from_asset_id, to_asset_id, kind, created_at`,
    [tenantId, input.fromAssetId, input.toAssetId, input.kind, actor],
  );
  return toDto(rows[0]!);
}

export async function deleteRelationship(
  client: DbClient,
  tenantId: string,
  id: string,
): Promise<RelationshipDto | null> {
  const { rows } = await client.query<RelRow>(
    'DELETE FROM asset_relationships WHERE tenant_id = $1 AND id = $2 RETURNING id, from_asset_id, to_asset_id, kind, created_at',
    [tenantId, id],
  );
  return rows[0] ? toDto(rows[0]) : null;
}

/** Neighbourhood of an asset: related assets (both directions, bounded depth), their active findings and integrations. */
export async function assetGraph(
  client: DbClient,
  tenantId: string,
  assetId: string,
  depth: number,
): Promise<GraphDto | null> {
  const { rows: assets } = await client.query<{ id: string; name: string; status: string }>(
    `WITH RECURSIVE walk(id, d) AS (
        SELECT id, 0 FROM assets WHERE tenant_id = $1 AND id = $2
        UNION
        SELECT CASE WHEN r.from_asset_id = w.id THEN r.to_asset_id ELSE r.from_asset_id END, w.d + 1
          FROM walk w JOIN asset_relationships r
            ON r.tenant_id = $1 AND (r.from_asset_id = w.id OR r.to_asset_id = w.id)
         WHERE w.d < $3)
     SELECT a.id, a.name, a.status FROM assets a
      WHERE a.tenant_id = $1 AND a.id IN (SELECT id FROM walk) LIMIT $4`,
    [tenantId, assetId, depth, MAX_GRAPH_ASSETS + 1],
  );
  if (!assets.some((a) => a.id === assetId)) return null;
  const truncated = assets.length > MAX_GRAPH_ASSETS;
  const ids = assets.slice(0, MAX_GRAPH_ASSETS).map((a) => a.id);
  const [edges, findings, integrations] = await Promise.all([
    client.query<{ from_asset_id: string; to_asset_id: string; kind: string }>(
      `SELECT from_asset_id, to_asset_id, kind FROM asset_relationships
        WHERE tenant_id = $1 AND from_asset_id = ANY ($2::uuid[]) AND to_asset_id = ANY ($2::uuid[])`,
      [tenantId, ids],
    ),
    client.query<{ id: string; title: string; severity: string; asset_id: string }>(
      `SELECT id, title, severity, asset_id FROM findings
        WHERE tenant_id = $1 AND asset_id = ANY ($2::uuid[]) AND status IN ('OPEN', 'TRIAGED', 'IN_PROGRESS')
        ORDER BY last_seen_at DESC LIMIT 100`,
      [tenantId, ids],
    ),
    client.query<{ id: string; name: string; status: string; asset_id: string }>(
      `SELECT id, name, status, asset_id FROM integrations WHERE tenant_id = $1 AND asset_id = ANY ($2::uuid[])`,
      [tenantId, ids],
    ),
  ]);
  return {
    nodes: [
      ...assets
        .slice(0, MAX_GRAPH_ASSETS)
        .map((a) => ({ id: a.id, type: 'asset' as const, label: a.name, state: a.status })),
      ...findings.rows.map((f) => ({
        id: f.id,
        type: 'finding' as const,
        label: f.title,
        state: f.severity,
      })),
      ...integrations.rows.map((i) => ({
        id: i.id,
        type: 'integration' as const,
        label: i.name,
        state: i.status,
      })),
    ],
    edges: [
      ...edges.rows.map((e) => ({ from: e.from_asset_id, to: e.to_asset_id, kind: e.kind })),
      ...findings.rows.map((f) => ({ from: f.id, to: f.asset_id, kind: 'AFFECTS' })),
      ...integrations.rows.map((i) => ({ from: i.id, to: i.asset_id, kind: 'OBSERVES' })),
    ],
    truncated,
  };
}
