import {
  assetListQuerySchema,
  createAssetRequestSchema,
  updateAssetRequestSchema,
  uuidSchema,
} from '@aegis/shared';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  createAsset,
  deleteAsset,
  getAsset,
  listAssets,
  toAssetDto,
  updateAsset,
} from '../../assets/assets.js';
import type { AssetDto } from '@aegis/shared';
import { loadCoverage } from '../../coverage/coverage.js';
import type { DbClient } from '../../db/pool.js';
import { auditInTx, enforce, inTenant, type AppDeps } from '../context.js';
import { Errors, parse } from '../errors.js';

const idParams = z.object({ id: uuidSchema }).strict();

export const assetRoutes = (deps: AppDeps) => async (app: FastifyInstance) => {
  /** Attach computed coverage to asset DTOs. */
  const withCoverage = async (c: DbClient, tenantId: string, items: AssetDto[]) => {
    if (items.length === 0) return items;
    const cov = await loadCoverage(
      c,
      tenantId,
      deps.providers,
      deps.config.health.staleAfterMs,
      items.map((a) => a.id),
    );
    return items.map((a) => ({ ...a, coverageState: cov.get(a.id)?.state ?? 'UNKNOWN' }));
  };

  app.get('/api/assets', { config: { auth: 'asset.read' } }, async (req) => {
    const q = parse(assetListQuerySchema, req.query);
    return inTenant(deps, req, async (c, tenantId) => {
      const page = await listAssets(c, tenantId, q);
      return { ...page, items: await withCoverage(c, tenantId, page.items) };
    });
  });

  app.post('/api/assets', { config: { auth: 'asset.create' } }, async (req, reply) => {
    const body = parse(createAssetRequestSchema, req.body);
    const asset = await inTenant(deps, req, async (c, tenantId) => {
      const row = await createAsset(c, tenantId, req.actor!.principalId, body);
      await auditInTx(c, req, {
        tenantId,
        action: 'asset.create',
        outcome: 'SUCCESS',
        targetType: 'asset',
        targetId: row.id,
        metadata: { name: row.name, environment: row.environment, criticality: row.criticality },
      });
      return (await withCoverage(c, tenantId, [toAssetDto(row)]))[0]!;
    });
    return reply.status(201).send(asset);
  });

  app.get('/api/assets/:id', { config: { auth: 'asset.read' } }, async (req) => {
    const { id } = parse(idParams, req.params);
    const row = await inTenant(deps, req, (c, tenantId) => getAsset(c, tenantId, id));
    if (!row) throw Errors.notFound('Asset');
    await enforce(deps, req, 'asset.read', { type: 'asset', tenantId: row.tenant_id, id: row.id });
    return inTenant(
      deps,
      req,
      async (c, tenantId) => (await withCoverage(c, tenantId, [toAssetDto(row)]))[0]!,
    );
  });

  app.patch('/api/assets/:id', { config: { auth: 'asset.update' } }, async (req) => {
    const { id } = parse(idParams, req.params);
    const body = parse(updateAssetRequestSchema, req.body);
    return inTenant(deps, req, async (c, tenantId) => {
      const existing = await getAsset(c, tenantId, id);
      if (!existing) throw Errors.notFound('Asset');
      await enforce(deps, req, 'asset.update', {
        type: 'asset',
        tenantId: existing.tenant_id,
        id,
        environment: existing.environment,
        criticality: existing.criticality,
      });
      const { row, changed } = await updateAsset(c, tenantId, existing, body);
      await auditInTx(c, req, {
        tenantId,
        action: 'asset.update',
        outcome: 'SUCCESS',
        targetType: 'asset',
        targetId: id,
        metadata: {
          changed,
          ...(changed.includes('status')
            ? { statusFrom: existing.status, statusTo: row.status }
            : {}),
        },
      });
      return (await withCoverage(c, tenantId, [toAssetDto(row)]))[0]!;
    });
  });

  app.delete('/api/assets/:id', { config: { auth: 'asset.delete' } }, async (req, reply) => {
    const { id } = parse(idParams, req.params);
    await inTenant(deps, req, async (c, tenantId) => {
      const existing = await getAsset(c, tenantId, id);
      if (!existing) throw Errors.notFound('Asset');
      // Production or critical assets additionally require recent reauthentication.
      await enforce(deps, req, 'asset.delete', {
        type: 'asset',
        tenantId: existing.tenant_id,
        id,
        environment: existing.environment,
        criticality: existing.criticality,
      });
      if (!(await deleteAsset(c, tenantId, id))) throw Errors.notFound('Asset');
      await auditInTx(c, req, {
        tenantId,
        action: 'asset.delete',
        outcome: 'SUCCESS',
        targetType: 'asset',
        targetId: id,
        metadata: {
          name: existing.name,
          environment: existing.environment,
          criticality: existing.criticality,
        },
      });
    });
    return reply.status(204).send();
  });
};
