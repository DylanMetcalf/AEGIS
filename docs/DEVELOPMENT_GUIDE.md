# Development Guide

## Prerequisites

Node.js ≥ 22.12, pnpm 10 (`corepack enable`), and PostgreSQL 16 with an admin login (local install or
container).

## Setup

```bash
pnpm install
PG_ADMIN_URL=postgres://postgres:<password>@127.0.0.1:5432/postgres scripts/dev-setup.sh
```

`dev-setup.sh` creates roles `aegis_dev_owner` and `aegis_dev_app` (member of `aegis_app`) with random
passwords and a database named `aegis_dev`. It writes `.env` (gitignored, mode 600) and runs
migrations. Re-running it rotates the passwords.

Create your first account (no default accounts exist):

```bash
printf '%s\n' '<password, 12+ chars>' | pnpm --filter @aegis/server admin bootstrap \
  --email you@example.com --name "You" --tenant-slug dev --tenant-name "Development"
```

## Run

```bash
pnpm --filter @aegis/server dev    # API on :3000 with in-process worker (tsx watch)
pnpm --filter @aegis/web dev       # Vite on :5173, proxies /api and /health to :3000
```

The dev `.env` sets `APP_ORIGIN=http://localhost:5173` because the browser talks to Vite. To serve
the built UI from the API instead, use
`pnpm run build && APP_ORIGIN=http://localhost:3000 WEB_DIST_DIR=$PWD/apps/web/dist node --env-file=.env apps/server/dist/main.js`.

The simulated **Test Adapter** integration is enabled in development (`INTEGRATION_TEST_ADAPTER_ENABLED=true`).
To probe a local HTTP service with the endpoint probe, also set `INTEGRATION_ALLOW_PRIVATE_NETWORK=true`
and `INTEGRATION_ALLOW_INSECURE_HTTP=true`. Both are rejected outside development.

## Test

```bash
pnpm run test           # everything (builds shared first)
pnpm run test:server    # needs PostgreSQL admin access
pnpm run test:web
```

Server tests create a database `aegis_test` and roles `aegis_test_owner` / `aegis_test_app`. The roles
get random passwords on each run, and the real migrations are applied. Set `TEST_DATABASE_ADMIN_URL`
if your admin connection differs from the default (user and password `postgres` on 127.0.0.1:5432, as in the CI service container). Tests
never touch your dev database.

Full local CI equivalent:

```bash
pnpm run check
```

## Conventions

- **Every `/api` route declares `config.auth`** (`'public'`, `'session'`, or a capability). Startup
  fails otherwise.
- Load tenant data only through `inTenant(deps, req, fn)` or `withTransaction(pool, ctx, fn)`, never
  `pool.query` against tenant tables. After loading a resource, call `enforce(deps, req, capability,
resourceRef)`.
- Write success audit events with `auditInTx` inside the same transaction as the change.
- Validate every input with a strict zod schema from `@aegis/shared`. Never interpolate values into
  SQL. Sort columns come from allowlists.
- New enum values need a matching migration (CHECK constraints) and a shared enum update.
- New tenant-scoped tables need `tenant_id`, `UNIQUE (tenant_id, id)`, composite foreign keys, RLS
  `USING`/`WITH CHECK` policies for `aegis_app`, and explicit grants. `migrations.test.ts` asserts that
  every table with `tenant_id` has RLS enabled.
- New integration providers declare capabilities (with `implemented`), permissions, and config
  schema. Use `safeHttpGet` for any outbound HTTP.
- New product areas update `PRODUCT_MODULES` with an honest `state`. Do not show sample data.
- Frontend: no `dangerouslySetInnerHTML`, no localStorage or sessionStorage (lint-enforced), status
  always as text plus glyph via `StatusBadge`.
- Mark any reviewed secret-scanner false positive with `secret-scan:allow <reason>` on the same line.

## Migrations

Add `apps/server/migrations/NNNN_description.sql`. **Never edit an applied migration**: the runner
detects checksum changes and refuses to run. Apply with `pnpm --filter @aegis/server migrate`.
