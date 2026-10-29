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
import { auditInTx, enforce, inTenant, type AppDeps } from '../context.js';
import { Errors, parse } from '../errors.js';

const idParams = z.object({ id: uuidSchema }).strict();

export const assetRoutes = (deps: AppDeps) => async (app: FastifyInstance) => {
  app.get('/api/assets', { config: { auth: 'asset.read' } }, async (req) => {
    const q = parse(assetListQuerySchema, req.query);
    return inTenant(deps, req, (c, tenantId) => listAssets(c, tenantId, q));
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
      return toAssetDto(row);
    });
    return reply.status(201).send(asset);
  });

  app.get('/api/assets/:id', { config: { auth: 'asset.read' } }, async (req) => {
    const { id } = parse(idParams, req.params);
    const row = await inTenant(deps, req, (c, tenantId) => getAsset(c, tenantId, id));
    if (!row) throw Errors.notFound('Asset');
    await enforce(deps, req, 'asset.read', { type: 'asset', tenantId: row.tenant_id, id: row.id });
    return toAssetDto(row);
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
      return toAssetDto(row);
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
