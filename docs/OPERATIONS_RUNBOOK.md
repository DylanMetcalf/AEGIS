# Operations Runbook

Applies to the Phase 1 codebase. Nothing here has been exercised in a production environment.

## Components

| Process       | Command                                        | Needs                                                                                  |
| ------------- | ---------------------------------------------- | -------------------------------------------------------------------------------------- |
| API (+worker) | `node apps/server/dist/main.js`                | `DATABASE_URL` (runtime role), app config                                              |
| Worker only   | `node apps/server/dist/worker-main.js`         | Same as API; set `WORKER_ENABLED=false` on API instances if the worker runs separately |
| Migrations    | `node apps/server/dist/cli/migrate.js`         | `DATABASE_MIGRATION_URL` (owner role) **only**                                         |
| Admin CLI     | `node apps/server/dist/cli/admin.js <command>` | `DATABASE_URL`; shell access                                                           |

## First-time provisioning

1. As a PostgreSQL superuser, run `apps/server/db/provision.sql` with `db_name`, `owner_role`,
   `owner_password`, `app_login`, and `app_password` supplied as psql variables. Generate the
   passwords in your secret manager.
2. Run migrations with `DATABASE_MIGRATION_URL`.
3. Start the API with `DATABASE_URL` for the runtime login role. Startup fails if that role is a
   superuser, has BYPASSRLS, or can act as a table owner.
4. Create the first system owner: `printf '%s\n' "$PW" | node dist/cli/admin.js bootstrap --email … --name … --tenant-slug … --tenant-name …`.
   Read the password from your secret manager. Never put it on the command line.

## Production configuration requirements

`AEGIS_ENV=production` enforces: `SESSION_COOKIE_SECURE=true`, https `APP_ORIGIN`,
`DATABASE_URL` with `sslmode=require|verify-ca|verify-full` (use `verify-full`), no
`INTEGRATION_ALLOW_*`, no test adapter, and no debug or trace logging. Also required (not enforced
by code):

- TLS termination and HSTS at the edge. Set `TRUST_PROXY=true` **only** behind a proxy that
  overwrites `X-Forwarded-For`; otherwise per-client throttles see the proxy address.
- An egress firewall for the worker (defence in depth for SSRF).
- Secrets injected from a secret manager. The API gets only `DATABASE_URL` and the `AEGIS_SECRET_*`
  values it needs; `DATABASE_MIGRATION_URL` goes only to the migration job.
- For more than one API instance, note that HTTP rate limiting is per instance (F-09).

## Deploy / upgrade

1. Build: `pnpm install --frozen-lockfile && pnpm run build`.
2. Run migrations (release step, owner role). The runner takes an advisory lock and refuses edited or
   unknown migrations.
3. Roll out the API. `/health/ready` returns 503 until the database is reachable and the schema
   version matches the build.
4. Rollback: migrations are forward-only. Roll back the application only if the schema change is
   backward compatible. Otherwise restore from backup or ship a corrective forward migration.

## Health

- `/health/live`: process liveness only.
- `/health/ready`: database reachable and schema current (required checks).
- `GET /api/system/status` (authenticated): API, database, schema, worker heartbeat (OPERATIONAL /
  STALE >30 s / UNAVAILABLE), audit chain (UNVERIFIED until verified this process; STALE after 24 h),
  SENTINEL (FOUNDATION_ONLY).

## Audit chain verification

A system owner runs **Settings → Verify audit chain** (or `POST /api/platform/audit/verify`).
**Record the returned `headPosition` and `headHash` outside AEGIS** (ticket, external log) on a
schedule. A later verification whose chain no longer contains that head means events were truncated.
If verification fails, treat the database as compromised: preserve a snapshot, restrict access, and
start incident response.

## Account and credential operations

| Task                             | Procedure                                                                                                    |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Create user                      | `admin create-user --email … --name …` (password on stdin), then add them to a tenant in Settings → Members  |
| Reset password                   | `admin reset-password --email …`; revokes all of the user's sessions                                         |
| Disable user                     | `admin disable-user --email …`; revokes sessions immediately                                                 |
| Revoke a user's tenant access    | Settings → Members → status Suspended/Removed (takes effect on the next request)                             |
| Rotate runtime DB password       | Set the new password on the app login role → update the secret → restart processes. Sessions are unaffected  |
| Rotate an integration credential | Update the `AEGIS_SECRET_<NAME>` value in the secret manager → restart the worker → run a health check       |
| Exposed integration credential   | Revoke it at the provider first; then revoke or rotate in AEGIS (Integrations → Revoke clears the reference) |
| Exposed DB credential            | Rotate the role password; review `audit_events` and database logs; verify the audit chain                    |
| Suspected session theft          | `admin disable-user`, or have the user use **Sign out everywhere**, then reset the password                  |

## Background jobs

- Stuck jobs: the worker fails jobs whose final lease expired (`LEASE_EXPIRED`) and retries earlier
  attempts.
- Inspect with SQL as the owner role: `SELECT status, last_error_code, count(*) FROM jobs GROUP BY 1,2;`
- Sessions that ended more than 7 days ago are pruned by the worker every 10 minutes.

## Backups

Use PostgreSQL-native backups (PITR recommended). Audit events are only as durable as the database
until an external sink exists (Phase 3). Recovery procedures are not implemented or exercised
(recovery readiness: NOT_RUN).
