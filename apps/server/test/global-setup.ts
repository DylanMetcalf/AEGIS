import { randomBytes } from 'node:crypto';
import pg from 'pg';
import type {} from 'vitest';
import type { TestProject } from 'vitest/node';
import { migrate } from '../src/db/migrate.js';

/**
 * Provisions an isolated test database exactly as production is provisioned:
 * a schema owner that runs the real migrations, and a restricted runtime
 * login role that is a member of aegis_app. Passwords are random per run.
 *
 * Requires a PostgreSQL admin connection (TEST_DATABASE_ADMIN_URL).
 */

declare module 'vitest' {
  export interface ProvidedContext {
    db: { adminUrl: string; ownerUrl: string; appUrl: string };
  }
}

const DB_NAME = 'aegis_test';
const OWNER = 'aegis_test_owner';
const APP = 'aegis_test_app';

function withDb(url: string, db: string, user?: string, password?: string): string {
  const u = new URL(url);
  u.pathname = `/${db}`;
  if (user) u.username = user;
  if (password) u.password = password;
  return u.toString();
}

export default async function setup(project: TestProject): Promise<void> {
  const adminUrl =
    process.env.TEST_DATABASE_ADMIN_URL ?? 'postgres://postgres:postgres@127.0.0.1:5432/postgres'; // secret-scan:allow matches the CI service container default
  const ownerPassword = randomBytes(24).toString('base64url');
  const appPassword = randomBytes(24).toString('base64url');

  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    const exists = async (role: string) =>
      (await admin.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [role])).rowCount === 1;
    if (!(await exists('aegis_app'))) {
      await admin.query(
        'CREATE ROLE aegis_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS',
      );
    }
    await admin.query(`DROP DATABASE IF EXISTS ${DB_NAME} WITH (FORCE)`);
    for (const [role, pw, extra] of [
      [OWNER, ownerPassword, ''],
      [APP, appPassword, 'INHERIT'],
    ] as const) {
      const verb = (await exists(role)) ? 'ALTER' : 'CREATE';
      const { rows } = await admin.query<{ q: string }>(
        `SELECT format('${verb} ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS ${extra} PASSWORD %L', $1::text, $2::text) AS q`,
        [role, pw],
      );
      await admin.query(rows[0]!.q);
    }
    await admin.query(`GRANT aegis_app TO ${APP}`);
    await admin.query(`CREATE DATABASE ${DB_NAME} OWNER ${OWNER}`);
    await admin.query(`REVOKE ALL ON DATABASE ${DB_NAME} FROM PUBLIC`);
    await admin.query(`GRANT CONNECT ON DATABASE ${DB_NAME} TO aegis_app`);
  } finally {
    await admin.end();
  }

  const ownerUrl = withDb(adminUrl, DB_NAME, OWNER, ownerPassword);
  const appUrl = withDb(adminUrl, DB_NAME, APP, appPassword);
  await migrate(ownerUrl);

  project.provide('db', { adminUrl: withDb(adminUrl, DB_NAME), ownerUrl, appUrl });
}
