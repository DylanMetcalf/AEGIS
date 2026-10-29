import {
  createRelationshipRequestSchema,
  graphQuerySchema,
  uuidSchema,
  type CoverageDto,
} from '@aegis/shared';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { loadCoverage } from '../../coverage/coverage.js';
import {
  assetGraph,
  createRelationship,
  deleteRelationship,
  listRelationships,
} from '../../graph/graph.js';
import { auditInTx, inTenant, type AppDeps } from '../context.js';
import { Errors, parse } from '../errors.js';

export const graphRoutes = (deps: AppDeps) => async (app: FastifyInstance) => {
  const { providers, config } = deps;

  app.get('/api/coverage', { config: { auth: 'asset.read' } }, async (req) =>
    inTenant(deps, req, async (c, tenantId) => {
      const evaluatedAt = new Date().toISOString();
      const map = await loadCoverage(c, tenantId, providers, config.health.staleAfterMs);
      const items: CoverageDto[] = [...map.entries()].map(([assetId, v]) => ({
        assetId,
        assetName: v.assetName,
        state: v.state,
        reasons: v.reasons,
        evaluatedAt,
      }));
      return { items, freshnessMinutes: Math.round(config.health.staleAfterMs / 60_000) };
    }),
  );

  app.get('/api/asset-relationships', { config: { auth: 'asset.read' } }, async (req) => {
    const { assetId } = parse(z.object({ assetId: uuidSchema }).strict(), req.query);
    return inTenant(deps, req, async (c, tenantId) => ({
      items: await listRelationships(c, tenantId, assetId),
    }));
  });

  app.post('/api/asset-relationships', { config: { auth: 'asset.update' } }, async (req, reply) => {
    const body = parse(createRelationshipRequestSchema, req.body);
    const rel = await inTenant(deps, req, async (c, tenantId) => {
      const created = await createRelationship(c, tenantId, req.actor!.principalId, body);
      await auditInTx(c, req, {
        tenantId,
        action: 'asset_relationship.create',
        outcome: 'SUCCESS',
        targetType: 'asset_relationship',
        targetId: created.id,
        metadata: { ...body },
      });
      return created;
    });
    return reply.status(201).send(rel);
  });

  app.delete(
    '/api/asset-relationships/:id',
    { config: { auth: 'asset.update' } },
    async (req, reply) => {
      const { id } = parse(z.object({ id: uuidSchema }).strict(), req.params);
      await inTenant(deps, req, async (c, tenantId) => {
        const removed = await deleteRelationship(c, tenantId, id);
        if (!removed) throw Errors.notFound('Relationship');
        await auditInTx(c, req, {
          tenantId,
          action: 'asset_relationship.delete',
          outcome: 'SUCCESS',
          targetType: 'asset_relationship',
          targetId: id,
          metadata: { from: removed.fromAssetId, to: removed.toAssetId, kind: removed.kind },
        });
      });
      return reply.status(204).send();
    },
  );

  app.get('/api/graph', { config: { auth: 'asset.read' } }, async (req) => {
    const q = parse(graphQuerySchema, req.query);
    const graph = await inTenant(deps, req, (c, tenantId) =>
      assetGraph(c, tenantId, q.assetId, q.depth),
    );
    if (!graph) throw Errors.notFound('Asset');
    return graph;
  });
};
