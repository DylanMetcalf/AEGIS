import {
  createInvestigationRequestSchema,
  findingListQuerySchema,
  listQuerySchema,
  noteRequestSchema,
  updateFindingRequestSchema,
  updateInvestigationRequestSchema,
  uuidSchema,
  type TelemetryEventDto,
} from '@aegis/shared';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { DETECTION_RULES } from '../../detection/rules.js';
import { addNote, listEvidence, verifyEvidence } from '../../intel/evidence.js';
import {
  getFinding,
  listFindings,
  toFindingDto,
  updateFinding,
  type FindingRow,
} from '../../intel/findings.js';
import {
  createInvestigation,
  getInvestigation,
  listInvestigations,
  updateInvestigation,
} from '../../intel/investigations.js';
import { auditInTx, enforce, inTenant, type AppDeps } from '../context.js';
import { decodeTimestampCursor, encodeCursor } from '../cursor.js';
import { Errors, parse } from '../errors.js';

const idParams = z.object({ id: uuidSchema }).strict();

export const intelRoutes = (deps: AppDeps) => async (app: FastifyInstance) => {
  // --- Detection rules (static catalogue) ---
  app.get('/api/detection-rules', { config: { auth: 'finding.read' } }, async () => ({
    items: DETECTION_RULES.map((r) => ({
      id: r.id,
      version: r.version,
      severity: r.severity,
      title: r.title,
      description: r.description,
    })),
  }));

  // --- Telemetry ---
  app.get('/api/telemetry-events', { config: { auth: 'telemetry.read' } }, async (req) => {
    const q = parse(
      listQuerySchema.extend({ integrationId: uuidSchema.optional() }).strict(),
      req.query,
    );
    const cursor = decodeTimestampCursor(q.cursor);
    return inTenant(deps, req, async (c, tenantId) => {
      const { rows } = await c.query<{
        id: string;
        event_type: TelemetryEventDto['eventType'];
        severity: TelemetryEventDto['severity'];
        observed_at: Date;
        received_at: Date;
        actor_user_id: string | null;
        actor_ip: string | null;
        attributes: TelemetryEventDto['attributes'];
        integration_id: string;
        asset_id: string | null;
      }>(
        `SELECT id, event_type, severity, observed_at, received_at, actor_user_id, host(actor_ip) AS actor_ip,
                attributes, integration_id, asset_id
           FROM telemetry_events
          WHERE tenant_id = $1 AND ($2::uuid IS NULL OR integration_id = $2)
            AND ($3::timestamptz IS NULL OR (observed_at, id) < ($3::timestamptz, $4::uuid))
          ORDER BY observed_at DESC, id DESC LIMIT $5`,
        [tenantId, q.integrationId ?? null, cursor?.v ?? null, cursor?.i ?? null, q.limit + 1],
      );
      const page = rows.slice(0, q.limit);
      const last = page.at(-1);
      return {
        items: page.map((r): TelemetryEventDto => ({
          id: r.id,
          eventType: r.event_type,
          severity: r.severity,
          observedAt: r.observed_at.toISOString(),
          receivedAt: r.received_at.toISOString(),
          actorUserId: r.actor_user_id,
          actorIp: r.actor_ip,
          attributes: r.attributes,
          integrationId: r.integration_id,
          assetId: r.asset_id,
        })),
        nextCursor:
          rows.length > q.limit && last
            ? encodeCursor({ v: last.observed_at.toISOString(), i: last.id })
            : null,
      };
    });
  });

  // --- Findings ---
  app.get('/api/findings', { config: { auth: 'finding.read' } }, async (req) => {
    const q = parse(findingListQuerySchema, req.query);
    return inTenant(deps, req, (c, tenantId) => listFindings(c, tenantId, q));
  });

  app.get('/api/findings/:id', { config: { auth: 'finding.read' } }, async (req) => {
    const { id } = parse(idParams, req.params);
    return inTenant(deps, req, async (c, tenantId) => {
      const row = await getFinding(c, tenantId, id);
      if (!row) throw Errors.notFound('Finding');
      const { rows: inv } = await c.query<{ investigation_id: string }>(
        'SELECT investigation_id FROM investigation_findings WHERE tenant_id = $1 AND finding_id = $2',
        [tenantId, id],
      );
      return {
        finding: toFindingDto(row),
        evidence: await listEvidence(c, tenantId, { findingId: id, limit: 200 }),
        investigationIds: inv.map((r) => r.investigation_id),
      };
    });
  });

  app.patch('/api/findings/:id', { config: { auth: 'finding.update' } }, async (req) => {
    const { id } = parse(idParams, req.params);
    const body = parse(updateFindingRequestSchema, req.body);
    return inTenant(deps, req, async (c, tenantId) => {
      const existing = await getFinding(c, tenantId, id, true);
      if (!existing) throw Errors.notFound('Finding');
      const resource = { type: 'finding', tenantId: existing.tenant_id, id };
      await enforce(deps, req, 'finding.update', resource);
      if (body.status === 'ACCEPTED_RISK' && existing.status !== 'ACCEPTED_RISK') {
        await enforce(deps, req, 'finding.accept_risk', resource);
      }
      const row = await updateFinding(c, tenantId, existing, body);
      await auditInTx(c, req, {
        tenantId,
        action: 'finding.update',
        outcome: 'SUCCESS',
        targetType: 'finding',
        targetId: id,
        metadata: {
          from: { status: existing.status, assignee: existing.assignee_principal_id },
          to: { status: row.status, assignee: row.assignee_principal_id },
        },
      });
      return toFindingDto(row);
    });
  });

  app.post(
    '/api/findings/:id/notes',
    { config: { auth: 'finding.update' } },
    async (req, reply) => {
      const { id } = parse(idParams, req.params);
      const { text } = parse(noteRequestSchema, req.body);
      const note = await inTenant(deps, req, async (c, tenantId) => {
        if (!(await getFinding(c, tenantId, id))) throw Errors.notFound('Finding');
        const ev = await addNote(c, tenantId, { findingId: id }, text, req.actor!.principalId);
        await auditInTx(c, req, {
          tenantId,
          action: 'finding.note',
          outcome: 'SUCCESS',
          targetType: 'finding',
          targetId: id,
          metadata: { evidenceId: ev.id },
        });
        return ev;
      });
      return reply.status(201).send(note);
    },
  );

  // --- Evidence ---
  app.get('/api/evidence', { config: { auth: 'evidence.read' } }, async (req) => {
    const q = parse(
      z.object({ limit: z.coerce.number().int().min(1).max(100).default(50) }).strict(),
      req.query,
    );
    return inTenant(deps, req, async (c, tenantId) => ({
      items: await listEvidence(c, tenantId, { limit: q.limit }),
    }));
  });

  app.post('/api/evidence/:id/verify', { config: { auth: 'evidence.verify' } }, async (req) => {
    const { id } = parse(idParams, req.params);
    return inTenant(deps, req, async (c, tenantId) => {
      const ev = await verifyEvidence(c, tenantId, id);
      await auditInTx(c, req, {
        tenantId,
        action: 'evidence.verify',
        outcome: ev.verificationStatus === 'VERIFIED' ? 'SUCCESS' : 'FAILURE',
        reasonCode: ev.verificationStatus === 'VERIFIED' ? null : ev.verificationStatus,
        targetType: 'evidence',
        targetId: id,
      });
      return ev;
    });
  });

  // --- Investigations ---
  app.get('/api/investigations', { config: { auth: 'investigation.read' } }, async (req) => {
    const q = parse(listQuerySchema, req.query);
    return inTenant(deps, req, (c, tenantId) => listInvestigations(c, tenantId, q));
  });

  app.post(
    '/api/investigations',
    { config: { auth: 'investigation.manage' } },
    async (req, reply) => {
      const body = parse(createInvestigationRequestSchema, req.body);
      const inv = await inTenant(deps, req, async (c, tenantId) => {
        const created = await createInvestigation(c, tenantId, req.actor!.principalId, body);
        await auditInTx(c, req, {
          tenantId,
          action: 'investigation.create',
          outcome: 'SUCCESS',
          targetType: 'investigation',
          targetId: created.id,
          metadata: { findings: created.findingIds.length },
        });
        return created;
      });
      return reply.status(201).send(inv);
    },
  );

  app.get('/api/investigations/:id', { config: { auth: 'investigation.read' } }, async (req) => {
    const { id } = parse(idParams, req.params);
    return inTenant(deps, req, async (c, tenantId) => {
      const inv = await getInvestigation(c, tenantId, id);
      if (!inv) throw Errors.notFound('Investigation');
      const { rows } = await c.query<FindingRow>(
        'SELECT * FROM findings WHERE tenant_id = $1 AND id = ANY ($2::uuid[]) ORDER BY last_seen_at DESC',
        [tenantId, inv.findingIds],
      );
      return {
        investigation: inv,
        findings: rows.map(toFindingDto),
        notes: await listEvidence(c, tenantId, { investigationId: id, limit: 200 }),
      };
    });
  });

  app.patch(
    '/api/investigations/:id',
    { config: { auth: 'investigation.manage' } },
    async (req) => {
      const { id } = parse(idParams, req.params);
      const body = parse(updateInvestigationRequestSchema, req.body);
      return inTenant(deps, req, async (c, tenantId) => {
        const existing = await getInvestigation(c, tenantId, id);
        if (!existing) throw Errors.notFound('Investigation');
        const updated = await updateInvestigation(
          c,
          tenantId,
          existing,
          req.actor!.principalId,
          body,
        );
        await auditInTx(c, req, {
          tenantId,
          action: 'investigation.update',
          outcome: 'SUCCESS',
          targetType: 'investigation',
          targetId: id,
          metadata: {
            statusFrom: existing.status,
            statusTo: updated.status,
            added: body.addFindingIds?.length ?? 0,
            removed: body.removeFindingIds?.length ?? 0,
          },
        });
        return updated;
      });
    },
  );

  app.post(
    '/api/investigations/:id/notes',
    { config: { auth: 'investigation.manage' } },
    async (req, reply) => {
      const { id } = parse(idParams, req.params);
      const { text } = parse(noteRequestSchema, req.body);
      const note = await inTenant(deps, req, async (c, tenantId) => {
        const inv = await getInvestigation(c, tenantId, id);
        if (!inv) throw Errors.notFound('Investigation');
        if (inv.status === 'CLOSED') throw Errors.invalidTransition('CLOSED', 'note');
        const ev = await addNote(
          c,
          tenantId,
          { investigationId: id },
          text,
          req.actor!.principalId,
        );
        await auditInTx(c, req, {
          tenantId,
          action: 'investigation.note',
          outcome: 'SUCCESS',
          targetType: 'investigation',
          targetId: id,
          metadata: { evidenceId: ev.id },
        });
        return ev;
      });
      return reply.status(201).send(note);
    },
  );
};
