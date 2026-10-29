# Data Model

Source of truth: `apps/server/migrations/*.sql`. Enumerations are `text` + `CHECK` constraints mirrored
in `packages/shared/src/enums.ts`.

## Migrations

| Version | File                                           | Purpose                                                               |
| ------- | ---------------------------------------------- | --------------------------------------------------------------------- |
| 0001    | `0001_foundation.sql`                          | All Phase 1 tables, RLS, grants, audit chain, job functions           |
| 0002    | `0002_tenant_visibility_active_membership.sql` | Tenant visibility via RLS requires an ACTIVE membership (review F-15) |

Migrations are forward-only, each applied in its own transaction with a SHA-256 ledger entry in
`schema_migrations`. The runner refuses to run if an applied file changed or the database has a
version the build lacks (tested). Down migrations are deliberately not provided (DECISIONS ADR-007).

## Tables

| Table                       | Scope           | Key columns / constraints                                                                                                                                                                                         | RLS                                                                                          |
| --------------------------- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `principals`                | Global          | `kind` ∈ HUMAN/SERVICE/AI_WORKER; `email` citext unique; Argon2id hash format check; humans must have email+hash; only humans have platform roles                                                                 | No (needed pre-auth); no DELETE grant                                                        |
| `tenants`                   | Isolation root  | `slug` unique + format; `status` ACTIVE/SUSPENDED                                                                                                                                                                 | Visible in own context, via ACTIVE membership, or platform scope; writes platform scope only |
| `memberships`               | Tenant          | unique (tenant, principal); role enum; status ACTIVE/SUSPENDED/REMOVED; trigger enforces role ↔ principal kind                                                                                                    | Tenant context or own principal                                                              |
| `sessions`                  | Global          | `token_hash` 32 bytes unique; `expires_at > created_at`; `revoked_at` ⇔ `revoke_reason`                                                                                                                           | No                                                                                           |
| `auth_throttle`             | Global          | hashed key; failure window; `locked_until`                                                                                                                                                                        | No                                                                                           |
| `assets`                    | Tenant          | unique (tenant, name); enums for type, environment, criticality, status, coverage; `authorization_scope` jsonb (statement + identifiers required, ≤16 KB); optimistic `version`                                   | Tenant isolation                                                                             |
| `integrations`              | Tenant          | provider id format; status enum; `config` jsonb ≤16 KB (non-secret); `credential_ref` restricted to `env:AEGIS_SECRET_*`; composite FK to `assets(tenant_id,id)`; REVOKED ⇔ `revoked_at`; revoked ⇒ no credential | Tenant isolation                                                                             |
| `integration_health_checks` | Tenant          | composite FK to integration; result enum; error code format; config version                                                                                                                                       | Tenant isolation                                                                             |
| `jobs`                      | Tenant          | actor principal; kind format; payload ≤16 KB; attempts ≤ max_attempts ≤ 10; timeout 100 ms–300 s; terminal ⇔ `finished_at`; unique (tenant, kind, idempotency_key)                                                | Tenant isolation                                                                             |
| `worker_heartbeats`         | System          | worker id format                                                                                                                                                                                                  | No                                                                                           |
| `audit_events`              | Tenant/platform | `chain_position` PK; action and id formats; outcome enum; metadata ≤8 KB; `prev_hash`/`hash` 32 bytes                                                                                                             | Insert: own tenant or NULL; select: own tenant, or NULL with platform scope                  |
| `schema_migrations`         | System          | version, checksum                                                                                                                                                                                                 | No (read-only grant)                                                                         |

## Indexes

| Index                                                             | Purpose                                    |
| ----------------------------------------------------------------- | ------------------------------------------ |
| `assets_tenant_created_idx (tenant_id, created_at DESC, id DESC)` | Keyset pagination by creation time         |
| `assets (tenant_id, name)` unique                                 | Name uniqueness and name-sorted pagination |
| `integrations_tenant_created_idx`                                 | Keyset pagination                          |
| `integrations_asset_idx` (partial)                                | Integrations by asset                      |
| `integration_health_checks_recent_idx`                            | Recent checks per integration              |
| `jobs_claimable_idx` (partial QUEUED)                             | Job claiming                               |
| `jobs_lease_idx` (partial RUNNING)                                | Expired lease reaping                      |
| `audit_events_tenant_idx (tenant_id, chain_position DESC)`        | Tenant audit history                       |
| `sessions_principal_active_idx` (partial)                         | Session listing and revocation             |
| `sessions_expires_idx`                                            | Pruning                                    |
| `memberships_principal_idx`                                       | A principal's memberships                  |

## Database functions

| Function                   | Security        | Purpose                                                                |
| -------------------------- | --------------- | ---------------------------------------------------------------------- |
| `app_tenant_id()` etc.     | Invoker         | Read transaction-local context                                         |
| `claim_job(worker, kinds)` | DEFINER         | Lease one job across tenants (`FOR UPDATE SKIP LOCKED`)                |
| `reap_expired_jobs()`      | DEFINER         | Fail jobs whose final lease expired                                    |
| `audit_event_digest(row)`  | Invoker         | Canonical SHA-256 over jsonb of all event fields + previous hash       |
| `audit_events_chain()`     | DEFINER trigger | Serialise (advisory lock), assign position and timestamp, compute hash |
| `audit_verify_chain()`     | DEFINER         | Recompute the chain; returns first invalid position and head hash      |

Execute rights on DEFINER functions are revoked from PUBLIC and granted to `aegis_app` only.

## State machines (`packages/shared/src/state-machine.ts`)

- **Integration:** UNCONFIGURED → CONFIGURED → CONNECTING → {CONNECTED, DEGRADED, DISCONNECTED,
  UNKNOWN} → CONNECTING / CONFIGURED (on reconfiguration); any non-terminal → SUSPENDED → CONFIGURED;
  any → REVOKED (terminal). Configuration never leads directly to CONNECTED.
- **Asset:** ACTIVE ⇄ INACTIVE → DECOMMISSIONED (terminal; no edits).
- **Defensive action (contract):** PROPOSED → [PENDING_APPROVAL] → AUTHORIZED → EXECUTING → EXECUTED |
  PARTIALLY_EXECUTED | FAILED → VERIFYING → VERIFIED | FAILED | INCONCLUSIVE; CANCELLED before
  execution.
- **Job:** QUEUED → RUNNING → SUCCEEDED | FAILED | CANCELLED, or back to QUEUED (retry with backoff).

State history is preserved as audit events (from/to in metadata) and `integration_health_checks`.

## Contracts without tables (Phase 1)

Policy definitions, defensive actions, evidence references, verification results, resource budgets,
SENTINEL observations, and recovery plans are TypeScript and zod contracts in
`apps/server/src/contracts/`. Tables are intentionally not created until the owning phase implements
the behaviour.
