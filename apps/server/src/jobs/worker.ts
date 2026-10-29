import { hostname } from 'node:os';
import type { z } from 'zod';
import type { FastifyBaseLogger } from 'fastify';
import { authorize, type Actor } from '../authz/authorize.js';
import type { Capability } from '../authz/capabilities.js';
import { recordAudit } from '../audit/audit.js';
import type { AppConfig } from '../config.js';
import { withTransaction, type DbClient, type Pool } from '../db/pool.js';
import { pruneSessions } from '../identity/sessions.js';
import type { JobRow } from './jobs.js';

/**
 * Background worker.
 *
 * Jobs are leased from PostgreSQL (claim_job, FOR UPDATE SKIP LOCKED), so
 * several workers can run safely. Each job carries the tenant and actor that
 * requested it. Before running, the worker re-establishes that actor's
 * authorization in that tenant; every database access the handler makes is
 * scoped to that tenant by row-level security. Retries and timeouts are
 * bounded per job kind.
 */

export class JobError extends Error {
  constructor(
    public readonly code: string,
    public readonly retryable: boolean,
  ) {
    super(code);
    this.name = 'JobError';
  }
}

/** Ends the job as CANCELLED (e.g. superseded) rather than FAILED. */
export class JobCancelled extends Error {
  constructor(public readonly code: string) {
    super(code);
    this.name = 'JobCancelled';
  }
}

export interface JobContext {
  jobId: string;
  tenantId: string;
  actor: Actor;
  correlationId: string | null;
  signal: AbortSignal;
  /** Transaction in the job's tenant context. The only database access a handler gets. */
  tx<T>(fn: (client: DbClient) => Promise<T>): Promise<T>;
  log: FastifyBaseLogger;
}

export interface JobHandler<P = unknown> {
  kind: string;
  /** Capability the requesting actor must still hold when the job runs. */
  capability: Capability;
  maxAttempts: number;
  timeoutMs: number;
  payloadSchema: z.ZodType<P>;
  run(ctx: JobContext, payload: P): Promise<Record<string, unknown>>;
}

export interface WorkerDeps {
  pool: Pool;
  config: AppConfig;
  log: FastifyBaseLogger;
}

const HEARTBEAT_MS = 10_000;
const MAINTENANCE_MS = 10 * 60_000;
const VERSION = '0.1.0';

export class Worker {
  readonly workerId = `${hostname().slice(0, 40)}:${process.pid}:${Math.random().toString(36).slice(2, 8)}`.replace(
    /[^A-Za-z0-9_.:-]/g,
    '_',
  );
  private readonly handlers = new Map<string, JobHandler<unknown>>();
  private readonly inFlight = new Set<Promise<void>>();
  private readonly shutdown = new AbortController();
  private timers: NodeJS.Timeout[] = [];
  private running = false;
  private lastMaintenance = 0;

  constructor(
    private readonly deps: WorkerDeps,
    handlers: JobHandler<unknown>[],
  ) {
    for (const h of handlers) this.handlers.set(h.kind, h as unknown as JobHandler<unknown>);
  }

  async start(): Promise<void> {
    if (this.running) return;
    this.running = true;
    await this.heartbeat(true);
    this.timers.push(setInterval(() => void this.heartbeat(false), HEARTBEAT_MS).unref());
    const loop = async () => {
      if (!this.running) return;
      try {
        await this.tick();
      } catch (err) {
        this.deps.log.error({ err }, 'worker tick failed');
      }
      if (this.running) {
        this.timers.push(setTimeout(loop, this.deps.config.worker.pollIntervalMs).unref());
      }
    };
    void loop();
  }

  async stop(): Promise<void> {
    this.running = false;
    this.timers.forEach((t) => clearTimeout(t));
    this.timers = [];
    this.shutdown.abort();
    await Promise.allSettled([...this.inFlight]);
    await this.deps.pool
      .query('DELETE FROM worker_heartbeats WHERE worker_id = $1', [this.workerId])
      .catch(() => undefined);
  }

  private async heartbeat(initial: boolean): Promise<void> {
    try {
      await this.deps.pool.query(
        `INSERT INTO worker_heartbeats (worker_id, started_at, last_seen_at, version)
         VALUES ($1, now(), now(), $2)
         ON CONFLICT (worker_id) DO UPDATE SET last_seen_at = now()`,
        [this.workerId, VERSION],
      );
    } catch (err) {
      if (initial) throw err;
      this.deps.log.error({ err }, 'worker heartbeat failed');
    }
  }

  /** Claim and start as many jobs as free slots allow. */
  async tick(): Promise<void> {
    await this.deps.pool.query('SELECT reap_expired_jobs()');
    if (Date.now() - this.lastMaintenance > MAINTENANCE_MS) {
      this.lastMaintenance = Date.now();
      await pruneSessions(this.deps.pool).catch((err) =>
        this.deps.log.error({ err }, 'session pruning failed'),
      );
    }
    while (this.inFlight.size < this.deps.config.worker.concurrency) {
      const job = await this.claim();
      if (!job) break;
      const p = this.execute(job)
        .catch((err) => this.deps.log.error({ err, jobId: job.id }, 'job finalization failed'))
        .finally(() => this.inFlight.delete(p));
      this.inFlight.add(p);
    }
  }

  /** Claim and fully execute at most one job. For tests and CLI use. */
  async runOnce(): Promise<JobRow | null> {
    const job = await this.claim();
    if (!job) return null;
    await this.execute(job);
    return job;
  }

  private async claim(): Promise<JobRow | null> {
    const { rows } = await this.deps.pool.query<JobRow>('SELECT * FROM claim_job($1, $2)', [
      this.workerId,
      [...this.handlers.keys()],
    ]);
    return rows[0] ?? null;
  }

  private async loadActor(job: JobRow): Promise<Actor | null> {
    return withTransaction(
      this.deps.pool,
      { tenantId: job.tenant_id, principalId: job.actor_principal_id },
      async (client) => {
        const { rows } = await client.query<{
          kind: Actor['kind'];
          status: Actor['status'];
          platform_role: Actor['platformRole'];
          tenant_status: 'ACTIVE' | 'SUSPENDED';
          role: Actor['role'];
          membership_status: Actor['membershipStatus'];
        }>(
          `SELECT p.kind, p.status, p.platform_role, t.status AS tenant_status,
                  m.role, m.status AS membership_status
             FROM principals p
             JOIN tenants t ON t.id = $1
             LEFT JOIN memberships m ON m.tenant_id = t.id AND m.principal_id = p.id
            WHERE p.id = $2`,
          [job.tenant_id, job.actor_principal_id],
        );
        const r = rows[0];
        if (!r) return null;
        return {
          principalId: job.actor_principal_id,
          kind: r.kind,
          status: r.status,
          platformRole: r.platform_role,
          tenantId: job.tenant_id,
          tenantStatus: r.tenant_status,
          role: r.role,
          membershipStatus: r.membership_status,
          sessionId: null,
          reauthenticatedAt: null,
        };
      },
    );
  }

  private async execute(job: JobRow): Promise<void> {
    const log = this.deps.log.child({ jobId: job.id, kind: job.kind, attempt: job.attempts });
    const handler = this.handlers.get(job.kind);
    try {
      if (!handler) throw new JobError('UNKNOWN_JOB_KIND', false);
      const parsed = handler.payloadSchema.safeParse(job.payload);
      if (!parsed.success) throw new JobError('INVALID_PAYLOAD', false);

      const actor = await this.loadActor(job);
      const decision = authorize(actor, handler.capability, {
        resource: { type: 'job', tenantId: job.tenant_id, id: job.id },
        reauthWindowMs: this.deps.config.session.reauthWindowMs,
      });
      if (!decision.allowed) {
        await this.audit(job, actor, 'job.denied', 'DENIED', decision.reason);
        throw new JobError('AUTHORIZATION_REVOKED', false);
      }

      const signal = AbortSignal.any([AbortSignal.timeout(job.timeout_ms), this.shutdown.signal]);
      const ctx: JobContext = {
        jobId: job.id,
        tenantId: job.tenant_id,
        actor: actor!,
        correlationId: job.correlation_id,
        signal,
        tx: (fn) =>
          withTransaction(
            this.deps.pool,
            { tenantId: job.tenant_id, principalId: job.actor_principal_id },
            fn,
          ),
        log,
      };
      const result = await handler.run(ctx, parsed.data);
      await this.finish(job, 'SUCCEEDED', null, result);
    } catch (err) {
      if (err instanceof JobCancelled) {
        await this.finish(job, 'CANCELLED', err.code, null);
        return;
      }
      const jobErr =
        err instanceof JobError
          ? err
          : new JobError(this.shutdown.signal.aborted ? 'WORKER_SHUTDOWN' : 'HANDLER_ERROR', true);
      if (!(err instanceof JobError)) log.error({ err }, 'job handler failed');
      if (jobErr.retryable && job.attempts < job.max_attempts) {
        await this.retry(job, jobErr.code);
      } else {
        await this.finish(job, 'FAILED', jobErr.code, null);
        await this.audit(job, null, 'job.failed', 'FAILURE', jobErr.code).catch(() => undefined);
      }
    }
  }

  private async finish(
    job: JobRow,
    status: 'SUCCEEDED' | 'FAILED' | 'CANCELLED',
    errorCode: string | null,
    result: Record<string, unknown> | null,
  ): Promise<void> {
    await withTransaction(this.deps.pool, { tenantId: job.tenant_id, principalId: null }, (c) =>
      c.query(
        `UPDATE jobs SET status = $3, last_error_code = $4, result = $5, finished_at = now(),
                locked_by = NULL, locked_until = NULL
          WHERE id = $1 AND locked_by = $2 AND status = 'RUNNING'`,
        [job.id, this.workerId, status, errorCode, result ? JSON.stringify(result) : null],
      ),
    );
  }

  private async retry(job: JobRow, errorCode: string): Promise<void> {
    const backoffSeconds = Math.min(60, 2 ** job.attempts);
    await withTransaction(this.deps.pool, { tenantId: job.tenant_id, principalId: null }, (c) =>
      c.query(
        `UPDATE jobs SET status = 'QUEUED', last_error_code = $3, locked_by = NULL, locked_until = NULL,
                run_after = now() + make_interval(secs => $4)
          WHERE id = $1 AND locked_by = $2 AND status = 'RUNNING'`,
        [job.id, this.workerId, errorCode, backoffSeconds],
      ),
    );
  }

  private async audit(
    job: JobRow,
    actor: Actor | null,
    action: string,
    outcome: 'DENIED' | 'FAILURE',
    reason: string,
  ): Promise<void> {
    await withTransaction(this.deps.pool, { tenantId: job.tenant_id, principalId: null }, (c) =>
      recordAudit(c, {
        tenantId: job.tenant_id,
        actorPrincipalId: job.actor_principal_id,
        actorType: actor?.kind ?? 'SYSTEM',
        action,
        targetType: 'job',
        targetId: job.id,
        outcome,
        reasonCode: reason,
        correlationId: job.correlation_id,
        metadata: { kind: job.kind, attempt: job.attempts },
      }),
    );
  }
}
