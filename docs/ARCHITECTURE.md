# Architecture

Status as of Phase 1 (2026-10-29). This describes what is implemented; planned elements are labelled.

## Shape

AEGIS is a **modular monolith**: one TypeScript codebase, one PostgreSQL database, and up to two process
types built from the same code.

```
Browser ──HTTPS, same origin──► API process (Fastify) ──► PostgreSQL 16
  (React SPA, HttpOnly cookie)    │  └─ in-process worker (optional)
                                  └─ static web bundle (production)
                                 Worker process (optional, same image) ──► PostgreSQL
                                 Outbound probes ──► authorized HTTPS endpoints (SSRF-guarded)
```

| Package         | Path              | Responsibility                                                                        |
| --------------- | ----------------- | ------------------------------------------------------------------------------------- |
| `@aegis/shared` | `packages/shared` | Enumerations, state machines, request schemas, API DTO types, product module registry |
| `@aegis/server` | `apps/server`     | API, authorization, persistence, jobs, integrations, CLIs                             |
| `@aegis/web`    | `apps/web`        | Browser application shell and pages                                                   |

Separate services were rejected for Phase 1 (see DECISIONS ADR-001). The worker can run as its own
process (`dist/worker-main.js`) for resource isolation without any code change.

## Server modules (`apps/server/src`)

| Module          | Responsibility                                                                        | Status                            |
| --------------- | ------------------------------------------------------------------------------------- | --------------------------------- |
| `config.ts`     | Validated configuration; fails closed; hardened-environment rules                     | Implemented                       |
| `db/`           | Pool, context-scoped transactions, runtime-role check, migration runner               | Implemented                       |
| `security/`     | Tokens, Argon2id passwords, redaction, SSRF-safe HTTP                                 | Implemented                       |
| `identity/`     | Sessions, failed-login throttle                                                       | Implemented                       |
| `authz/`        | Capability catalogue, role map, deterministic `authorize()`                           | Implemented                       |
| `audit/`        | Audit writes (in-transaction and independent), listing, chain verification            | Implemented                       |
| `assets/`       | Asset registry persistence and rules                                                  | Implemented                       |
| `integrations/` | Provider contract, registry, capability gating, credential refs, two providers        | Implemented                       |
| `jobs/`         | Job queue, worker, health-check job                                                   | Implemented                       |
| `health/`       | Readiness checks, component status                                                    | Implemented                       |
| `http/`         | App assembly, security hooks, error mapping, routes                                   | Implemented                       |
| `contracts/`    | Defensive action, evidence, verification, policy, resource budget, SENTINEL, recovery | Interface only (see README there) |
| `cli/`          | `migrate`, `admin` (bootstrap, create-user, reset-password, disable-user)             | Implemented                       |

### Allowed dependency directions

```
http/routes ─► http/context ─► authz, audit, db
http/routes ─► assets, integrations, jobs, identity, health
jobs ─► authz, audit, integrations, db
integrations ─► security, db
authz ─► (shared enums only; no I/O)
audit ─► db, security/redact
security ─► (node built-ins only)
contracts ─► shared, authz/capabilities (types)
```

`authz/authorize.ts` is pure: it imports no database, HTTP, or business modules, so business logic
cannot bypass it by injecting state. The frontend imports only `@aegis/shared`; it has no database
access and no server credentials.

## Request lifecycle

1. **onRequest**: assign a server-generated request ID; accept a safe `X-Correlation-Id`, otherwise
   use the request ID; set `Cache-Control: no-store` on `/api`; **reject unsafe methods whose `Origin`
   is not `APP_ORIGIN`**.
2. **Body parsing**: JSON only, with a size limit. The `text/plain` parser is removed, so form posts
   get a 415.
3. **preHandler**: resolve the session cookie (hash lookup, then revocation, absolute and idle expiry,
   and principal status), then load the active tenant membership. Enforce the route's declared `auth`
   policy. Every `/api` route must declare one, or startup fails.
4. **Handler**: parse input with strict zod schemas, then open a tenant-scoped transaction
   (`set_config('aegis.tenant_id', …, true)`). Load the target and enforce resource-level authorization
   (tenant match, reauthentication). Mutate, validating state transitions and optimistic concurrency
   (`version`). Write the audit event **in the same transaction**, then commit.
5. **Errors**: map to stable codes. Stack traces never reach clients. Postgres constraint and RLS
   errors map to 400, 403, or 409.

## Trust boundaries and enforcement

| Boundary                                | Enforcement                                                                                                          |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Browser → server                        | All input untrusted; strict schemas; JSON only; body limit; origin check on unsafe methods; CSP `default-src 'self'` |
| Unauthenticated → authenticated         | Opaque 256-bit session token, HttpOnly + SameSite=Strict (+ Secure, `__Host-` outside dev); route policy guard       |
| Authenticated → authorized              | `authorize()` per route capability and again per loaded resource; deny by default                                    |
| Ordinary → privileged operation         | Capability sensitivity + reauthentication within `REAUTH_WINDOW_MINUTES`                                             |
| Tenant ↔ tenant                         | Active tenant from server session only; RLS on every tenant table; composite FKs; resource tenant re-check           |
| Platform admin ↔ tenant data            | Platform scope grants tenant lifecycle and platform audit only (RLS + capability map)                                |
| Application ↔ database                  | Runtime role is not owner, superuser, or BYPASSRLS (checked at startup); schema owner is used only by migrations     |
| Application ↔ integrations              | Declared capabilities and permissions; SSRF-guarded HTTP; timeouts; credentials by reference only                    |
| API ↔ background jobs                   | Jobs carry tenant and actor from the request; authorization re-checked at execution; RLS on every job query          |
| Application logs ↔ audit records        | Separate stores; audit append-only and hash-chained; logs redacted                                                   |
| Development ↔ production                | Config validation forbids dev conveniences in staging and production                                                 |
| AI output / repo content ↔ instructions | No AI or repository ingestion exists in Phase 1. AI_WORKER identities are read-only by rule                          |
| Proposed ↔ authorized change            | Defensive-action contract requires AUTHORIZED state and approvals; executor disabled                                 |
| Ordinary admin ↔ emergency recovery     | RECOVERY_AUTHORITY role reserved; `recovery.execute` has no endpoint                                                 |
| Main app ↔ SENTINEL                     | Not yet separated; shared dependencies documented in `contracts/sentinel.ts`                                         |

## Data flows

- **Login**: credentials → throttle check → Argon2id verify (dummy hash when the account is unknown)
  → session row (token hash) → cookie → audit `auth.login`.
- **Asset change**: request → capability → tenant transaction → state and version checks → write →
  audit → commit.
- **Health check**: API enqueues a job carrying the tenant, actor, and config version (idempotency
  key optional) → worker leases it via `claim_job()` → re-authorizes the actor → marks the integration
  CONNECTING → calls the provider outside any transaction with a hard timeout → records the
  observation, applies the status only if the config version is unchanged, and writes the audit
  event.

## Deployment model (assumed; nothing is deployed by this repository)

- Single container image running `node dist/main.js` (API with in-process worker), or API and worker
  as separate processes from the same image.
- `WEB_DIST_DIR` serves the built SPA from the API for a single origin (no CORS).
- TLS terminates at a reverse proxy; set `TRUST_PROXY=true` only behind a trusted proxy.
- PostgreSQL 16 with TLS. Roles are provisioned by `apps/server/db/provision.sql`, and migrations run
  as the owner role in a release step.

## Extension points for later phases

| Future capability         | Extension point                                                                                         |
| ------------------------- | ------------------------------------------------------------------------------------------------------- |
| Telemetry, detection (P2) | New tenant tables with RLS; providers declare `events.collect`; job kinds; `EvidenceReference` contract |
| Knowledge graph (P2)      | Relational edges with composite tenant FKs (no graph database until a demonstrated need)                |
| Coverage (P2)             | `assets.coverage_state` column and enumeration already exist; computation writes it                     |
| SENTINEL (P3)             | `contracts/sentinel.ts` observation format; independence table; must run in a separate trust domain     |
| Defensive actions (P3)    | `contracts/defensive-action.ts` lifecycle, preconditions, approvals; reserved capabilities              |
| Verification (P3)         | `contracts/verification.ts` pessimistic aggregation                                                     |
| AI agents (P4)            | `AI_WORKER` identity kind and role (read-only), `contracts/resource-budget.ts`, job framework           |
| Recovery (P3)             | `RECOVERY_AUTHORITY` role, `recovery.execute` capability, `contracts/recovery.ts`                       |
