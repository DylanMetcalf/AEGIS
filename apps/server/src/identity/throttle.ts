import type { DbClient } from '../db/pool.js';
import { sha256 } from '../security/tokens.js';

/**
 * Database-backed failed-authentication throttle, shared by all application
 * processes. Keys are hashed so the table holds no raw emails or addresses.
 *
 * Account keys lock after `maxFailures` failures within the window; client
 * keys tolerate more (shared NAT) before locking. Lockouts are temporary.
 */

export function accountKey(email: string): Buffer {
  return sha256(`account:${email.trim().toLowerCase()}`);
}

export function clientKey(ip: string): Buffer {
  return sha256(`client:${ip}`);
}

export async function isLocked(client: DbClient, keys: Buffer[]): Promise<boolean> {
  const { rows } = await client.query<{ locked: boolean }>(
    `SELECT EXISTS (SELECT 1 FROM auth_throttle
                     WHERE key_hash = ANY ($1::bytea[]) AND locked_until > now()) AS locked`,
    [keys],
  );
  return rows[0]?.locked === true;
}

export async function registerFailure(
  client: DbClient,
  key: Buffer,
  maxFailures: number,
  lockoutMs: number,
): Promise<void> {
  await client.query(
    `INSERT INTO auth_throttle AS t (key_hash, failure_count, window_started_at, locked_until)
     VALUES ($1, 1, now(), CASE WHEN 1 >= $2 THEN now() + make_interval(secs => $3::double precision / 1000) END)
     ON CONFLICT (key_hash) DO UPDATE SET
       failure_count = CASE WHEN t.window_started_at < now() - make_interval(secs => $3::double precision / 1000)
                            THEN 1 ELSE t.failure_count + 1 END,
       window_started_at = CASE WHEN t.window_started_at < now() - make_interval(secs => $3::double precision / 1000)
                                THEN now() ELSE t.window_started_at END,
       locked_until = CASE
         WHEN (CASE WHEN t.window_started_at < now() - make_interval(secs => $3::double precision / 1000)
                    THEN 1 ELSE t.failure_count + 1 END) >= $2
         THEN now() + make_interval(secs => $3::double precision / 1000)
         ELSE t.locked_until END`,
    [key, maxFailures, lockoutMs],
  );
}

export async function clearFailures(client: DbClient, key: Buffer): Promise<void> {
  await client.query('DELETE FROM auth_throttle WHERE key_hash = $1', [key]);
}
