import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

/**
 * Forward-only SQL migrations with integrity checks.
 *
 * - Files are named NNNN_description.sql and applied in order.
 * - Each migration runs in its own transaction together with its ledger row.
 * - The SHA-256 of every applied file is recorded; if an applied file is
 *   later edited, or the database has a migration this code does not know,
 *   the runner refuses to continue.
 * - A session advisory lock prevents concurrent migrators.
 */

export const MIGRATIONS_DIR = fileURLToPath(new URL('../../migrations/', import.meta.url));
const FILE_RE = /^(\d{4})_[a-z0-9_]+\.sql$/;
const LOCK_KEY = 7412000;

export interface MigrationFile {
  version: string;
  name: string;
  checksum: string;
  sql: string;
}

export function loadMigrationFiles(dir = MIGRATIONS_DIR): MigrationFile[] {
  return readdirSync(dir)
    .filter((f) => FILE_RE.test(f))
    .sort()
    .map((name) => {
      const sql = readFileSync(`${dir}/${name}`, 'utf8');
      return {
        version: name.slice(0, 4),
        name,
        checksum: createHash('sha256').update(sql).digest('hex'),
        sql,
      };
    });
}

export function latestMigrationVersion(dir = MIGRATIONS_DIR): string | null {
  const files = loadMigrationFiles(dir);
  return files.at(-1)?.version ?? null;
}

export class MigrationIntegrityError extends Error {
  override name = 'MigrationIntegrityError';
}

export async function migrate(
  connectionString: string,
  opts: { dir?: string; log?: (msg: string) => void } = {},
): Promise<{ applied: string[] }> {
  const log = opts.log ?? (() => undefined);
  const files = loadMigrationFiles(opts.dir);
  const client = new pg.Client({ connectionString, application_name: 'aegis-migrate' });
  await client.connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [LOCK_KEY]);
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version    text PRIMARY KEY CHECK (version ~ '^[0-9]{4}$'),
        name       text NOT NULL,
        checksum   text NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
        applied_at timestamptz NOT NULL DEFAULT now()
      )`);
    const { rows: applied } = await client.query<{ version: string; checksum: string; name: string }>(
      'SELECT version, name, checksum FROM schema_migrations ORDER BY version',
    );
    const byVersion = new Map(files.map((f) => [f.version, f]));
    for (const row of applied) {
      const file = byVersion.get(row.version);
      if (!file) {
        throw new MigrationIntegrityError(
          `Database has migration ${row.version} (${row.name}) that is not present in this build`,
        );
      }
      if (file.checksum !== row.checksum) {
        throw new MigrationIntegrityError(
          `Applied migration ${row.name} has been modified (checksum mismatch)`,
        );
      }
    }
    const appliedVersions = new Set(applied.map((r) => r.version));
    const done: string[] = [];
    for (const file of files) {
      if (appliedVersions.has(file.version)) continue;
      log(`Applying ${file.name}`);
      await client.query('BEGIN');
      try {
        await client.query(file.sql);
        await client.query(
          'INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)',
          [file.version, file.name, file.checksum],
        );
        await client.query('COMMIT');
      } catch (err) {
        await client.query('ROLLBACK');
        throw err;
      }
      done.push(file.name);
    }
    return { applied: done };
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [LOCK_KEY]).catch(() => undefined);
    await client.end();
  }
}
