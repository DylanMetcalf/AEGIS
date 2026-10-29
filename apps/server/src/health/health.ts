import type { ComponentState, ComponentStatusDto } from '@aegis/shared';
import type { AppConfig } from '../config.js';
import type { Pool } from '../db/pool.js';
import { latestMigrationVersion } from '../db/migrate.js';
import type { ChainVerification } from '../audit/audit.js';

/**
 * Health semantics:
 *  - liveness: the process is running and serving requests. Says nothing
 *    about dependencies.
 *  - readiness: required dependencies (database, schema version) are usable.
 *  - component status: per-subsystem state with observation timestamps.
 *    Unknown, unconfigured, stale, and foundation-only are reported as such,
 *    never as operational.
 */

export interface ReadinessCheck {
  name: string;
  required: boolean;
  state: ComponentState;
  observedAt: string;
  detail: string;
}

const DB_CHECK_TIMEOUT_MS = 2000;

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      p,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('timeout')), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export async function checkDatabase(pool: Pool): Promise<ReadinessCheck[]> {
  const observedAt = new Date().toISOString();
  const expected = latestMigrationVersion();
  try {
    const { rows } = await withTimeout(
      pool.query<{ version: string | null }>('SELECT max(version) AS version FROM schema_migrations'),
      DB_CHECK_TIMEOUT_MS,
    );
    const current = rows[0]?.version ?? null;
    return [
      { name: 'database', required: true, state: 'OPERATIONAL', observedAt, detail: 'Reachable' },
      {
        name: 'schema',
        required: true,
        state: current === expected ? 'OPERATIONAL' : 'FAILED',
        observedAt,
        detail:
          current === expected
            ? `Schema at version ${current}`
            : `Schema version mismatch: expected ${expected ?? 'none'}, found ${current ?? 'none'}`,
      },
    ];
  } catch {
    return [
      { name: 'database', required: true, state: 'UNAVAILABLE', observedAt, detail: 'Unreachable or timed out' },
      { name: 'schema', required: true, state: 'UNKNOWN', observedAt, detail: 'Cannot be checked without the database' },
    ];
  }
}

export function isReady(checks: ReadinessCheck[]): boolean {
  return checks.filter((c) => c.required).every((c) => c.state === 'OPERATIONAL');
}

export async function workerStatus(pool: Pool, config: AppConfig): Promise<ComponentStatusDto> {
  const base = { key: 'worker', label: 'Background worker', required: false };
  try {
    const { rows } = await pool.query<{ last_seen_at: Date | null; workers: string }>(
      `SELECT max(last_seen_at) AS last_seen_at, count(*) AS workers FROM worker_heartbeats`,
    );
    const lastSeen = rows[0]?.last_seen_at ?? null;
    if (!lastSeen) {
      return {
        ...base,
        state: config.worker.enabled ? 'UNKNOWN' : 'UNAVAILABLE',
        observedAt: null,
        detail: 'No worker heartbeat recorded; queued jobs will not run',
      };
    }
    const ageMs = Date.now() - lastSeen.getTime();
    const stale = ageMs > 30_000;
    return {
      ...base,
      state: stale ? 'STALE' : 'OPERATIONAL',
      observedAt: lastSeen.toISOString(),
      detail: stale
        ? `Last heartbeat ${Math.round(ageMs / 1000)}s ago`
        : `${rows[0]!.workers} worker(s) reporting`,
    };
  } catch {
    return { ...base, state: 'UNKNOWN', observedAt: null, detail: 'Could not read worker heartbeats' };
  }
}

/** In-process record of the last audit chain verification. */
export class AuditVerificationState {
  private last: ChainVerification | null = null;
  set(v: ChainVerification) {
    this.last = v;
  }
  status(maxAgeMs = 24 * 3600_000): ComponentStatusDto {
    const base = { key: 'audit_chain', label: 'Audit chain integrity', required: true };
    if (!this.last) {
      return {
        ...base,
        state: 'UNVERIFIED',
        observedAt: null,
        detail: 'Not verified since this process started. A system owner can run verification.',
      };
    }
    const age = Date.now() - Date.parse(this.last.verifiedAt);
    if (!this.last.verified) {
      return {
        ...base,
        state: 'FAILED',
        observedAt: this.last.verifiedAt,
        detail: `Chain verification failed at position ${this.last.firstInvalidPosition} (${this.last.reason})`,
      };
    }
    return {
      ...base,
      state: age > maxAgeMs ? 'STALE' : 'OPERATIONAL',
      observedAt: this.last.verifiedAt,
      detail: `${this.last.eventsChecked} events verified (same-database check; not independent)`,
    };
  }
}

export function sentinelStatus(): ComponentStatusDto {
  return {
    key: 'sentinel',
    label: 'SENTINEL supervision',
    required: false,
    state: 'FOUNDATION_ONLY',
    observedAt: null,
    detail: 'Contracts defined; no independent supervision is running.',
  };
}
