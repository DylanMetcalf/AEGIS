import { cpSync, mkdtempSync, rmSync, writeFileSync, appendFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { inject } from 'vitest';
import { assertRuntimeRoleIsRestricted, createPool } from '../src/db/pool.js';
import {
  MIGRATIONS_DIR,
  MigrationIntegrityError,
  loadMigrationFiles,
  migrate,
} from '../src/db/migrate.js';
import { owner } from './helpers.js';

const dirs: string[] = [];
afterAll(() => dirs.forEach((d) => rmSync(d, { recursive: true, force: true })));

function copyMigrations(): string {
  const dir = mkdtempSync(join(tmpdir(), 'aegis-mig-'));
  dirs.push(dir);
  cpSync(MIGRATIONS_DIR, dir, { recursive: true });
  return dir;
}

describe('migrations', () => {
  it('records every migration with its checksum', async () => {
    const files = loadMigrationFiles();
    const { rows } = await owner().query(
      'SELECT version, checksum FROM schema_migrations ORDER BY version',
    );
    expect(rows).toEqual(files.map((f) => ({ version: f.version, checksum: f.checksum })));
  });

  it('is idempotent', async () => {
    expect((await migrate(inject('db').ownerUrl)).applied).toEqual([]);
  });

  it('refuses to run when an applied migration was edited', async () => {
    const dir = copyMigrations();
    appendFileSync(join(dir, '0001_foundation.sql'), '\n-- sneaky edit\n');
    await expect(migrate(inject('db').ownerUrl, { dir })).rejects.toThrow(MigrationIntegrityError);
  });

  it('refuses to run when the database has a migration this build does not know', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'aegis-mig-empty-'));
    dirs.push(dir);
    await expect(migrate(inject('db').ownerUrl, { dir })).rejects.toThrow(
      /not present in this build/,
    );
  });

  it('rolls back a failing migration completely', async () => {
    const dir = copyMigrations();
    writeFileSync(
      join(dir, '9999_broken.sql'),
      'CREATE TABLE should_not_exist (id int);\nSELECT * FROM table_that_does_not_exist;\n',
    );
    await expect(migrate(inject('db').ownerUrl, { dir })).rejects.toThrow();
    const { rows } = await owner().query("SELECT to_regclass('public.should_not_exist') AS t");
    expect(rows[0].t).toBeNull();
    const { rows: ledger } = await owner().query(
      "SELECT 1 FROM schema_migrations WHERE version = '9999'",
    );
    expect(ledger).toHaveLength(0);
  });

  it('accepts the restricted runtime role and rejects the schema owner', async () => {
    const app = createPool({ url: inject('db').appUrl, max: 1, statementTimeoutMs: 5000 });
    const own = createPool({ url: inject('db').ownerUrl, max: 1, statementTimeoutMs: 5000 });
    const su = createPool({ url: inject('db').adminUrl, max: 1, statementTimeoutMs: 5000 });
    try {
      await expect(assertRuntimeRoleIsRestricted(app)).resolves.toBeUndefined();
      await expect(assertRuntimeRoleIsRestricted(own)).rejects.toThrow(/restricted runtime role/);
      await expect(assertRuntimeRoleIsRestricted(su)).rejects.toThrow(/restricted runtime role/);
    } finally {
      await Promise.all([app.end(), own.end(), su.end()]);
    }
  });

  it('defines tenant isolation policies on every tenant-scoped table', async () => {
    const { rows } = await owner().query<{ tablename: string; rowsecurity: boolean }>(
      `SELECT c.relname AS tablename, c.relrowsecurity AS rowsecurity
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
         JOIN information_schema.columns col ON col.table_name = c.relname AND col.column_name = 'tenant_id'
        WHERE n.nspname = 'public' AND c.relkind = 'r'`,
    );
    expect(rows.length).toBeGreaterThanOrEqual(6);
    for (const r of rows) expect(r.rowsecurity, r.tablename).toBe(true);
  });
});
