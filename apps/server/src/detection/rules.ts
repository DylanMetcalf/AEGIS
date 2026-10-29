import type { Severity, TelemetryEventType } from '@aegis/shared';
import type { DbClient } from '../db/pool.js';

/**
 * Built-in detection rules. Deterministic: given the same stored events they
 * produce the same detections. Each rule is versioned; changing its logic
 * requires a version bump. Window rules query stored telemetry, so they see
 * events across batches.
 */

export interface StoredEvent {
  id: string;
  eventType: TelemetryEventType;
  severity: Severity;
  observedAt: Date;
  actorUserId: string | null;
  actorIp: string | null;
  attributes: Record<string, string | number | boolean>;
  sourceEventId: string | null;
}

export interface Detection {
  groupKey: string;
  title: string;
  severity: Severity;
  eventIds: string[];
  firstSeenAt: Date;
  lastSeenAt: Date;
  summary: Record<string, unknown>;
}

export interface RuleContext {
  tenantId: string;
  events: StoredEvent[];
  client: DbClient;
}

export interface DetectionRule {
  id: string;
  version: number;
  severity: Severity;
  title: string;
  description: string;
  evaluate(ctx: RuleContext): Promise<Detection[]>;
}

export const MAX_EVIDENCE_PER_DETECTION = 20;

async function eventsFromIp(
  ctx: RuleContext,
  ip: string,
  type: TelemetryEventType,
  from: Date,
  to: Date,
): Promise<{ id: string; observed_at: Date; actor_user_id: string | null }[]> {
  const { rows } = await ctx.client.query<{
    id: string;
    observed_at: Date;
    actor_user_id: string | null;
  }>(
    `SELECT id, observed_at, actor_user_id FROM telemetry_events
      WHERE tenant_id = $1 AND actor_ip = $2::inet AND event_type = $3
        AND observed_at >= $4 AND observed_at <= $5
      ORDER BY observed_at DESC LIMIT 200`,
    [ctx.tenantId, ip, type, from, to],
  );
  return rows;
}

const minutes = (n: number) => n * 60_000;
const span = (dates: Date[]) => ({
  firstSeenAt: new Date(Math.min(...dates.map((d) => d.getTime()))),
  lastSeenAt: new Date(Math.max(...dates.map((d) => d.getTime()))),
});

export const BRUTE_FORCE_THRESHOLD = 10;
const bruteForce: DetectionRule = {
  id: 'auth.brute_force',
  version: 1,
  severity: 'HIGH',
  title: 'Repeated authentication failures from one address',
  description: `${BRUTE_FORCE_THRESHOLD}+ auth.failure events from the same source IP within 5 minutes.`,
  async evaluate(ctx) {
    const latestByIp = new Map<string, Date>();
    for (const e of ctx.events) {
      if (e.eventType !== 'auth.failure' || !e.actorIp) continue;
      const prev = latestByIp.get(e.actorIp);
      if (!prev || e.observedAt > prev) latestByIp.set(e.actorIp, e.observedAt);
    }
    const out: Detection[] = [];
    for (const [ip, latest] of latestByIp) {
      const rows = await eventsFromIp(
        ctx,
        ip,
        'auth.failure',
        new Date(latest.getTime() - minutes(5)),
        latest,
      );
      if (rows.length < BRUTE_FORCE_THRESHOLD) continue;
      out.push({
        groupKey: `ip:${ip}`,
        title: `${rows.length >= 200 ? '200+' : rows.length} authentication failures from ${ip} within 5 minutes`,
        severity: this.severity,
        eventIds: rows.slice(0, MAX_EVIDENCE_PER_DETECTION).map((r) => r.id),
        ...span(rows.map((r) => r.observed_at)),
        summary: {
          sourceIp: ip,
          failures: rows.length,
          windowMinutes: 5,
          distinctUsers: new Set(rows.map((r) => r.actor_user_id).filter(Boolean)).size,
        },
      });
    }
    return out;
  },
};

export const SUCCESS_AFTER_FAILURES_THRESHOLD = 5;
const successAfterFailures: DetectionRule = {
  id: 'auth.success_after_failures',
  version: 1,
  severity: 'CRITICAL',
  title: 'Successful sign-in after repeated failures',
  description: `auth.success from a source IP that produced ${SUCCESS_AFTER_FAILURES_THRESHOLD}+ auth.failure events in the preceding 10 minutes.`,
  async evaluate(ctx) {
    const out: Detection[] = [];
    for (const e of ctx.events) {
      if (e.eventType !== 'auth.success' || !e.actorIp) continue;
      const failures = await eventsFromIp(
        ctx,
        e.actorIp,
        'auth.failure',
        new Date(e.observedAt.getTime() - minutes(10)),
        new Date(e.observedAt.getTime() - 1),
      );
      if (failures.length < SUCCESS_AFTER_FAILURES_THRESHOLD) continue;
      const user = e.actorUserId ?? 'unknown';
      out.push({
        groupKey: `ip:${e.actorIp}:user:${user}`,
        title: `Sign-in as ${user} from ${e.actorIp} after ${failures.length} failures`,
        severity: this.severity,
        eventIds: [e.id, ...failures.slice(0, MAX_EVIDENCE_PER_DETECTION - 1).map((f) => f.id)],
        ...span([e.observedAt, ...failures.map((f) => f.observed_at)]),
        summary: { sourceIp: e.actorIp, user, priorFailures: failures.length, windowMinutes: 10 },
      });
    }
    return out;
  },
};

/** Simple, linear-time signatures (no nested quantifiers) applied to bounded strings. */
export const INJECTION_SIGNATURES: { kind: string; re: RegExp }[] = [
  {
    kind: 'sql_injection',
    re: /\bunion\s+(all\s+)?select\b|'\s*or\s+'?1'?\s*=\s*'?1|;\s*drop\s+table\b|\bsleep\s*\(\s*\d+\s*\)/i,
  },
  { kind: 'path_traversal', re: /\.\.[/\\]|%2e%2e(%2f|%5c|\/)/i },
  { kind: 'cross_site_scripting', re: /<script\b|javascript:|\bon(error|load)\s*=/i },
  { kind: 'command_injection', re: /;\s*(cat|wget|curl|bash|sh)\s|\$\([^)]{1,64}\)|`[^`]{1,64}`/i },
];
const INSPECTED_ATTRIBUTES = ['path', 'query', 'url', 'body_sample', 'user_agent'];

const injection: DetectionRule = {
  id: 'http.injection_attempt',
  version: 1,
  severity: 'MEDIUM',
  title: 'Injection payload in HTTP request',
  description: `http.request whose ${INSPECTED_ATTRIBUTES.join(', ')} attributes match SQL injection, path traversal, XSS, or command injection signatures.`,
  async evaluate(ctx) {
    const groups = new Map<string, { kinds: Set<string>; events: StoredEvent[]; ip: string }>();
    for (const e of ctx.events) {
      if (e.eventType !== 'http.request') continue;
      const values = INSPECTED_ATTRIBUTES.map((k) => e.attributes[k]).filter(
        (v): v is string => typeof v === 'string',
      );
      for (const { kind, re } of INJECTION_SIGNATURES) {
        if (!values.some((v) => re.test(v))) continue;
        const ip = e.actorIp ?? 'unknown';
        const key = `ip:${ip}:${kind}`;
        const g = groups.get(key) ?? { kinds: new Set(), events: [], ip };
        g.kinds.add(kind);
        g.events.push(e);
        groups.set(key, g);
      }
    }
    return [...groups.entries()].map(([groupKey, g]) => {
      const kind = [...g.kinds][0]!;
      return {
        groupKey,
        title: `${kind.replace(/_/g, ' ')} attempt from ${g.ip}`,
        severity: this.severity,
        eventIds: g.events.slice(0, MAX_EVIDENCE_PER_DETECTION).map((e) => e.id),
        ...span(g.events.map((e) => e.observedAt)),
        summary: { sourceIp: g.ip, signature: kind, requests: g.events.length },
      };
    });
  },
};

const PRIVILEGED_ROLE = /\b(admin|administrator|owner|root|superuser)\b/i;
const privilegedGrant: DetectionRule = {
  id: 'iam.privileged_grant',
  version: 1,
  severity: 'MEDIUM',
  title: 'Privileged role granted',
  description:
    'iam.role_granted where the role attribute names an administrative role (admin, owner, root, superuser).',
  async evaluate(ctx) {
    return ctx.events.flatMap((e) => {
      const role = e.attributes.role;
      if (
        e.eventType !== 'iam.role_granted' ||
        typeof role !== 'string' ||
        !PRIVILEGED_ROLE.test(role)
      )
        return [];
      const target =
        typeof e.attributes.target_user === 'string'
          ? e.attributes.target_user
          : (e.actorUserId ?? 'unknown');
      return [
        {
          groupKey: `user:${target}:role:${role.toLowerCase()}`.slice(0, 200),
          title: `Role ${role} granted to ${target}`,
          severity: this.severity,
          eventIds: [e.id],
          firstSeenAt: e.observedAt,
          lastSeenAt: e.observedAt,
          summary: { role, targetUser: target, grantedBy: e.actorUserId },
        },
      ];
    });
  },
};

const sourceAlert: DetectionRule = {
  id: 'source.high_severity_alert',
  version: 1,
  severity: 'HIGH',
  title: 'High-severity alert reported by a source',
  description:
    'security.alert events that the reporting source marked HIGH or CRITICAL. Severity follows the source.',
  async evaluate(ctx) {
    return ctx.events.flatMap((e) => {
      if (e.eventType !== 'security.alert' || (e.severity !== 'HIGH' && e.severity !== 'CRITICAL'))
        return [];
      const alertId =
        typeof e.attributes.alert_id === 'string'
          ? e.attributes.alert_id
          : (e.sourceEventId ?? e.id);
      const name = typeof e.attributes.name === 'string' ? e.attributes.name : 'Source alert';
      return [
        {
          groupKey: `alert:${alertId}`.slice(0, 200),
          title: name.slice(0, 200),
          severity: e.severity,
          eventIds: [e.id],
          firstSeenAt: e.observedAt,
          lastSeenAt: e.observedAt,
          summary: { alertId, reportedSeverity: e.severity },
        },
      ];
    });
  },
};

export const DETECTION_RULES: readonly DetectionRule[] = [
  bruteForce,
  successAfterFailures,
  injection,
  privilegedGrant,
  sourceAlert,
];
