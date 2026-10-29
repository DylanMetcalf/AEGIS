import { createInterface } from 'node:readline';
import { Writable } from 'node:stream';
import { parseArgs } from 'node:util';
import { createTenantRequestSchema, emailSchema, newPasswordSchema, safeText } from '@aegis/shared';
import { recordAudit } from '../audit/audit.js';
import { ConfigError, loadConfig } from '../config.js';
import {
  assertRuntimeRoleIsRestricted,
  createPool,
  withTransaction,
  type Pool,
} from '../db/pool.js';
import { revokeSessionsForPrincipal } from '../identity/sessions.js';
import { hashPassword } from '../security/passwords.js';

/**
 * Operator CLI for actions that must not be reachable over HTTP:
 *
 *   bootstrap      --email --name --tenant-slug --tenant-name
 *                  Create the first SYSTEM_OWNER and an initial tenant.
 *                  Refuses if a system owner already exists.
 *   create-user    --email --name
 *   reset-password --email          (revokes all of the user's sessions)
 *   disable-user   --email          (revokes all of the user's sessions)
 *
 * Passwords are read from standard input (hidden when interactive), never
 * from command-line arguments, which are visible in process listings.
 * Every action is written to the audit log with actor type SYSTEM.
 */

async function readPassword(prompt: string): Promise<string> {
  const muted = new Writable({ write: (_c, _e, cb) => cb() });
  const interactive = process.stdin.isTTY;
  if (interactive) process.stdout.write(prompt);
  const rl = createInterface({
    input: process.stdin,
    output: interactive ? muted : undefined,
    terminal: interactive,
  });
  const line = await new Promise<string>((resolve) => rl.once('line', resolve));
  rl.close();
  if (interactive) process.stdout.write('\n');
  const parsed = newPasswordSchema.safeParse(line);
  if (!parsed.success) throw new Error(parsed.error.issues[0]?.message ?? 'Invalid password');
  return parsed.data;
}

function required(values: Record<string, string | undefined>, ...keys: string[]): void {
  const missing = keys.filter((k) => !values[k]);
  if (missing.length)
    throw new Error(`Missing required option(s): ${missing.map((k) => `--${k}`).join(', ')}`);
}

async function findPrincipal(pool: Pool, email: string) {
  const { rows } = await pool.query<{ id: string; kind: string }>(
    'SELECT id, kind FROM principals WHERE email = $1',
    [email],
  );
  return rows[0] ?? null;
}

async function main() {
  const { positionals, values } = parseArgs({
    allowPositionals: true,
    options: {
      email: { type: 'string' },
      name: { type: 'string' },
      'tenant-slug': { type: 'string' },
      'tenant-name': { type: 'string' },
    },
  });
  const command = positionals[0];
  const config = loadConfig();
  const pool = createPool({
    url: config.database.url,
    max: 2,
    statementTimeoutMs: 30000,
    applicationName: 'aegis-admin',
  });
  await assertRuntimeRoleIsRestricted(pool);
  const system = {
    actorPrincipalId: null,
    actorType: 'SYSTEM' as const,
    metadata: { via: 'admin-cli' },
  };

  try {
    switch (command) {
      case 'bootstrap': {
        required(values, 'email', 'name', 'tenant-slug', 'tenant-name');
        const email = emailSchema.parse(values.email);
        const name = safeText(1, 200).parse(values.name);
        const tenant = createTenantRequestSchema.parse({
          slug: values['tenant-slug'],
          displayName: values['tenant-name'],
        });
        const existing = await pool.query(
          "SELECT 1 FROM principals WHERE platform_role = 'SYSTEM_OWNER'",
        );
        if (existing.rowCount) throw new Error('A system owner already exists; bootstrap refused');
        const password = await readPassword('Password for the system owner: ');
        const hash = await hashPassword(password);
        await withTransaction(
          pool,
          { tenantId: null, principalId: null, platformScope: true },
          async (c) => {
            await c.query('LOCK TABLE principals IN SHARE ROW EXCLUSIVE MODE');
            const again = await c.query(
              "SELECT 1 FROM principals WHERE platform_role = 'SYSTEM_OWNER'",
            );
            if (again.rowCount) throw new Error('A system owner already exists; bootstrap refused');
            const p = await c.query<{ id: string }>(
              `INSERT INTO principals (kind, email, display_name, password_hash, platform_role, password_changed_at)
             VALUES ('HUMAN', $1, $2, $3, 'SYSTEM_OWNER', now()) RETURNING id`,
              [email, name, hash],
            );
            const principalId = p.rows[0]!.id;
            const t = await c.query<{ id: string }>(
              'INSERT INTO tenants (slug, display_name, created_by) VALUES ($1, $2, $3) RETURNING id',
              [tenant.slug, tenant.displayName, principalId],
            );
            await c.query(
              `INSERT INTO memberships (tenant_id, principal_id, role, created_by) VALUES ($1, $2, 'TENANT_ADMIN', $2)`,
              [t.rows[0]!.id, principalId],
            );
            await recordAudit(c, {
              ...system,
              tenantId: null,
              action: 'platform.bootstrap',
              outcome: 'SUCCESS',
              targetType: 'principal',
              targetId: principalId,
            });
          },
        );
        console.log(`Bootstrap complete: system owner ${email}, tenant ${tenant.slug}`);
        break;
      }
      case 'create-user': {
        required(values, 'email', 'name');
        const email = emailSchema.parse(values.email);
        const name = safeText(1, 200).parse(values.name);
        if (await findPrincipal(pool, email))
          throw new Error('An account with that email already exists');
        const hash = await hashPassword(await readPassword(`Initial password for ${email}: `));
        await withTransaction(pool, { tenantId: null, principalId: null }, async (c) => {
          const p = await c.query<{ id: string }>(
            `INSERT INTO principals (kind, email, display_name, password_hash, password_changed_at)
             VALUES ('HUMAN', $1, $2, $3, now()) RETURNING id`,
            [email, name, hash],
          );
          await recordAudit(c, {
            ...system,
            tenantId: null,
            action: 'principal.create',
            outcome: 'SUCCESS',
            targetType: 'principal',
            targetId: p.rows[0]!.id,
          });
        });
        console.log(`Created ${email}. Add them to a tenant from Settings → Members.`);
        break;
      }
      case 'reset-password':
      case 'disable-user': {
        required(values, 'email');
        const email = emailSchema.parse(values.email);
        const p = await findPrincipal(pool, email);
        if (!p || p.kind !== 'HUMAN') throw new Error('No human account with that email');
        const hash =
          command === 'reset-password'
            ? await hashPassword(await readPassword(`New password for ${email}: `))
            : null;
        await withTransaction(pool, { tenantId: null, principalId: null }, async (c) => {
          if (hash) {
            await c.query(
              'UPDATE principals SET password_hash = $2, password_changed_at = now() WHERE id = $1',
              [p.id, hash],
            );
          } else {
            await c.query("UPDATE principals SET status = 'DISABLED' WHERE id = $1", [p.id]);
          }
          const n = await revokeSessionsForPrincipal(
            c,
            p.id,
            hash ? 'PASSWORD_CHANGED' : 'PRINCIPAL_DISABLED',
          );
          await recordAudit(c, {
            ...system,
            tenantId: null,
            action: hash ? 'principal.password_reset' : 'principal.disable',
            outcome: 'SUCCESS',
            targetType: 'principal',
            targetId: p.id,
            metadata: { via: 'admin-cli', sessionsRevoked: n },
          });
        });
        console.log(
          `${command === 'reset-password' ? 'Password reset' : 'Account disabled'} for ${email}; sessions revoked.`,
        );
        break;
      }
      default:
        console.error('Usage: admin <bootstrap|create-user|reset-password|disable-user> [options]');
        process.exitCode = 2;
    }
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  if (err instanceof ConfigError) console.error(err.message);
  else console.error(`Error: ${err instanceof Error ? err.message : 'unknown error'}`);
  process.exit(1);
});
