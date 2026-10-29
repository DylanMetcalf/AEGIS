import { z } from 'zod';
import { recordAudit } from '../audit/audit.js';
import { DETECTION_RULES, type StoredEvent } from '../detection/rules.js';
import type { ProviderRegistry } from '../integrations/registry.js';
import type { JobHandler } from './worker.js';

export const DETECTION_JOB = 'detection.evaluate';
export const DETECTION_JOB_LIMITS = { maxAttempts: 3, timeoutMs: 60_000 } as const;
const MAX_EVIDENCE_PER_FINDING = 200;

const payloadSchema = z.object({ batchId: z.string().uuid() }).strict();

/**
 * Evaluate every rule over one ingested batch. Idempotent: findings are
 * upserted on (rule, group) while active, evidence is unique per
 * (finding, event), and occurrence counts are recomputed from evidence.
 */
export function detectionJobHandler(deps: {
  providers: ProviderRegistry;
}): JobHandler<z.infer<typeof payloadSchema>> {
  return {
    kind: DETECTION_JOB,
    capability: 'detection.run',
    ...DETECTION_JOB_LIMITS,
    payloadSchema,
    async run(ctx, payload) {
      return ctx.tx(async (client) => {
        const { rows } = await client.query<{
          id: string;
          event_type: StoredEvent['eventType'];
          severity: StoredEvent['severity'];
          observed_at: Date;
          actor_user_id: string | null;
          actor_ip: string | null;
          attributes: StoredEvent['attributes'];
          source_event_id: string | null;
          integration_id: string;
          asset_id: string | null;
        }>(
          `SELECT id, event_type, severity, observed_at, actor_user_id, host(actor_ip) AS actor_ip, attributes,
                  source_event_id, integration_id, asset_id
             FROM telemetry_events WHERE tenant_id = $1 AND batch_id = $2`,
          [ctx.tenantId, payload.batchId],
        );
        if (rows.length === 0) return { detections: 0, created: 0 };
        const integrationId = rows[0]!.integration_id;
        const assetId = rows[0]!.asset_id;
        const { rows: integ } = await client.query<{ provider: string }>(
          'SELECT provider FROM integrations WHERE tenant_id = $1 AND id = $2',
          [ctx.tenantId, integrationId],
        );
        const providerVersion = deps.providers.get(integ[0]?.provider ?? '')?.version ?? 'unknown';
        const events: StoredEvent[] = rows.map((r) => ({
          id: r.id,
          eventType: r.event_type,
          severity: r.severity,
          observedAt: r.observed_at,
          actorUserId: r.actor_user_id,
          actorIp: r.actor_ip,
          attributes: r.attributes,
          sourceEventId: r.source_event_id,
        }));

        let detections = 0;
        let created = 0;
        for (const rule of DETECTION_RULES) {
          for (const d of await rule.evaluate({ tenantId: ctx.tenantId, events, client })) {
            detections += 1;
            const { rows: f } = await client.query<{ id: string; inserted: boolean }>(
              `INSERT INTO findings (tenant_id, rule_id, rule_version, title, severity, group_key, asset_id,
                                     integration_id, first_seen_at, last_seen_at, summary)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
               ON CONFLICT (tenant_id, rule_id, group_key) WHERE status IN ('OPEN', 'TRIAGED', 'IN_PROGRESS')
               DO UPDATE SET first_seen_at = LEAST(findings.first_seen_at, EXCLUDED.first_seen_at),
                             last_seen_at = GREATEST(findings.last_seen_at, EXCLUDED.last_seen_at),
                             title = EXCLUDED.title, summary = EXCLUDED.summary
               RETURNING id, (xmax = 0) AS inserted`,
              [
                ctx.tenantId,
                rule.id,
                rule.version,
                d.title.slice(0, 200),
                d.severity,
                d.groupKey,
                assetId,
                integrationId,
                d.firstSeenAt,
                d.lastSeenAt,
                JSON.stringify(d.summary),
              ],
            );
            const finding = f[0]!;
            await client.query(
              `INSERT INTO evidence (tenant_id, kind, finding_id, telemetry_event_id, collector_type, collector_id,
                                     collector_version, collected_at, source_ref, content_sha256)
               SELECT $1, 'OBSERVATION', $2, t.id, 'INTEGRATION', t.integration_id::text, $3, t.received_at,
                      'telemetry:' || t.id, t.content_sha256
                 FROM telemetry_events t
                WHERE t.tenant_id = $1 AND t.id = ANY ($4::uuid[])
                  AND (SELECT count(*) FROM evidence x WHERE x.tenant_id = $1 AND x.finding_id = $2) < $5
               ON CONFLICT (tenant_id, finding_id, telemetry_event_id)
                 WHERE finding_id IS NOT NULL AND telemetry_event_id IS NOT NULL DO NOTHING`,
              [ctx.tenantId, finding.id, providerVersion, d.eventIds, MAX_EVIDENCE_PER_FINDING],
            );
            await client.query(
              `UPDATE findings SET occurrence_count =
                  (SELECT count(*) FROM evidence e WHERE e.tenant_id = $1 AND e.finding_id = $2 AND e.kind = 'OBSERVATION')
                WHERE tenant_id = $1 AND id = $2`,
              [ctx.tenantId, finding.id],
            );
            if (finding.inserted) {
              created += 1;
              await recordAudit(client, {
                tenantId: ctx.tenantId,
                actorPrincipalId: ctx.actor.principalId,
                actorType: ctx.actor.kind,
                action: 'finding.create',
                targetType: 'finding',
                targetId: finding.id,
                outcome: 'SUCCESS',
                correlationId: ctx.correlationId,
                metadata: {
                  ruleId: rule.id,
                  ruleVersion: rule.version,
                  severity: d.severity,
                  batchId: payload.batchId,
                },
              });
            }
          }
        }
        return { detections, created };
      });
    },
  };
}
