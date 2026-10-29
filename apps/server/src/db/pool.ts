import pg from 'pg';

export type Pool = pg.Pool;
export type DbClient = pg.PoolClient;

/** Return timestamps and bigints in a form we control explicitly. */
pg.types.setTypeParser(pg.types.builtins.INT8, (v) => v);

export function createPool(opts: {
  url: string;
  max: number;
  statementTimeoutMs: number;
  applicationName?: string;
}): Pool {
  const pool = new pg.Pool({
    connectionString: opts.url,
    max: opts.max,
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000,
    statement_timeout: opts.statementTimeoutMs,
    application_name: opts.applicationName ?? 'aegis',
  });
  // An idle client error must not crash the process; it is reported by readiness.
  pool.on('error', () => undefined);
  return pool;
}

/**
 * The authorization context a transaction runs under. It is applied with
 * transaction-local settings (set_config(..., true)) so it is discarded at
 * COMMIT/ROLLBACK and can never leak to the next user of a pooled connection.
 */
export interface DbContext {
  tenantId: string | null;
  principalId: string | null;
  /** Set only after a platform capability has been authorized. */
  platformScope?: boolean;
}

export const NO_CONTEXT: DbContext = Object.freeze({ tenantId: null, principalId: null });

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Run fn inside a READ COMMITTED transaction with the given context.
 * All tenant-scoped data access must go through this function.
 */
export async function withTransaction<T>(
  pool: Pool,
  ctx: DbContext,
  fn: (client: DbClient) => Promise<T>,
): Promise<T> {
  if (ctx.tenantId !== null && !UUID_RE.test(ctx.tenantId))
    throw new Error('Invalid tenant context');
  if (ctx.principalId !== null && !UUID_RE.test(ctx.principalId)) {
    throw new Error('Invalid principal context');
  }
  const client = await pool.connect();
  let released = false;
  try {
    await client.query('BEGIN ISOLATION LEVEL READ COMMITTED');
    await client.query(
      `SELECT set_config('aegis.tenant_id', $1, true),
              set_config('aegis.principal_id', $2, true),
              set_config('aegis.platform_scope', $3, true)`,
      [ctx.tenantId ?? '', ctx.principalId ?? '', ctx.platformScope ? 'on' : 'off'],
    );
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // Connection is broken; destroy it rather than returning it to the pool.
      client.release(true);
      released = true;
    }
    throw err;
  } finally {
    if (!released) client.release();
  }
}

/**
 * Verify that the runtime role is subject to row-level security. Running as
 * a superuser, a BYPASSRLS role, or the table owner would silently disable
 * tenant isolation, so startup refuses.
 */
export async function assertRuntimeRoleIsRestricted(pool: Pool): Promise<void> {
  const { rows } = await pool.query<{
    rolsuper: boolean;
    rolbypassrls: boolean;
    owns_tables: boolean;
  }>(
    `SELECT r.rolsuper, r.rolbypassrls,
            EXISTS (SELECT 1 FROM pg_tables t
                     WHERE t.schemaname = 'public'
                       AND pg_has_role(current_user, t.tableowner, 'USAGE')) AS owns_tables
       FROM pg_roles r WHERE r.rolname = current_user`,
  );
  const role = rows[0];
  if (!role) throw new Error('Unable to determine database role');
  if (role.rolsuper || role.rolbypassrls || role.owns_tables) {
    throw new Error(
      'DATABASE_URL must use the restricted runtime role (not a superuser, BYPASSRLS role, or table owner)',
    );
  }
}
