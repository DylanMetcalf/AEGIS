# Security Model

Each statement here is backed by code and, where marked, a test. See VERIFICATION_MATRIX.md for the
evidence.

## Identities

| Kind        | Authentication in Phase 1                   | Constraints                                                                                    |
| ----------- | ------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `HUMAN`     | Email + password (Argon2id), server session | Only kind that may hold a platform role or human tenant roles                                  |
| `SERVICE`   | None yet (used as job actors in future)     | DB trigger: may only hold the `SERVICE` role; never privileged capabilities                    |
| `AI_WORKER` | None yet                                    | DB trigger: may only hold the `AI_WORKER` role; `authorize()` denies every non-read capability |

There are no default accounts. The first `SYSTEM_OWNER` is created by the `admin bootstrap` CLI. It
refuses to run if an owner already exists and reads the password from standard input.

## Sessions

- A 256-bit random token in an HttpOnly cookie, `SameSite=Strict` and `Path=/`. When secure cookies
  are enabled (required outside development), it is `Secure` with the `__Host-` prefix. The database
  stores only SHA-256(token).
- Absolute lifetime `SESSION_ABSOLUTE_TTL_MINUTES` (default 12 h). Idle timeout
  `SESSION_IDLE_TTL_MINUTES` (default 30 min).
- Login always creates a new session and revokes any session presented with the request (fixation
  defence).
- Logout revokes server-side. Logout-all, password change (other sessions), admin reset, and
  disabling a principal all revoke sessions. A disabled principal's sessions stop working on the
  next request.
- Reauthentication sets `reauthenticated_at`; sensitive capabilities require it within
  `REAUTH_WINDOW_MINUTES` (default 10). Login counts as authentication.
- Failed logins are throttled per account (`LOGIN_MAX_FAILURES`, `LOGIN_LOCKOUT_MINUTES`) and per
  client address (4× the account limit), in the database so all processes share the state. There is
  also a per-client HTTP rate limit on credential endpoints.
- The account-enumeration defences are: a single generic error for wrong password, unknown account,
  or disabled account; the same throttling response for every account; and a dummy hash
  verification for unknown accounts.

## Authorization

`authorize(actor, capability, { resource, reauthWindowMs })` in `apps/server/src/authz/authorize.ts` is
pure and deterministic. Evaluation order:

1. No actor → `NO_ACTOR`. Unknown capability → `UNKNOWN_CAPABILITY`. Principal not active → deny.
2. `AI_WORKER` + non-read → deny. Any non-human + privileged → deny.
3. Platform capability: must be granted to the platform role, and a resource must not belong to a
   tenant.
4. Tenant capability: requires an active tenant, an active tenant record, an active membership, a role
   that grants the capability, and `resource.tenantId === actor.tenantId`.
5. Reauthentication, if the capability requires it (some only for production or critical resources).

Routes declare `config.auth` (`public`, `session`, or a capability), and startup fails if an `/api`
route lacks one. Handlers call `enforce()` again with the loaded resource. Denials are audited as
`authz.denied` (capability, method, route, and reason; never the request body) and logged.

### Roles → capabilities

| Capability                             | TENANT_ADMIN | SECURITY_ADMIN | SECURITY_OPERATOR | INTEGRATION_ADMIN | AUDITOR | READ_ONLY_ANALYST | SERVICE | AI_WORKER | RECOVERY_AUTHORITY |
| -------------------------------------- | :----------: | :------------: | :---------------: | :---------------: | :-----: | :---------------: | :-----: | :-------: | :----------------: |
| tenant.read                            |      ✓       |       ✓        |         ✓         |         ✓         |    ✓    |         ✓         |    ✓    |     ✓     |         ✓          |
| system.status.read                     |      ✓       |       ✓        |         ✓         |         ✓         |    ✓    |         ✓         |         |           |                    |
| membership.read                        |      ✓       |       ✓        |                   |                   |    ✓    |                   |         |           |                    |
| membership.manage (reauth)             |      ✓       |                |                   |                   |         |                   |         |           |                    |
| asset.read                             |      ✓       |       ✓        |         ✓         |         ✓         |    ✓    |         ✓         |    ✓    |     ✓     |                    |
| asset.create / asset.update            |      ✓       |       ✓        |         ✓         |                   |         |                   |         |           |                    |
| asset.delete (reauth if prod/critical) |      ✓       |       ✓        |                   |                   |         |                   |         |           |                    |
| integration.read                       |      ✓       |       ✓        |         ✓         |         ✓         |    ✓    |         ✓         |    ✓    |     ✓     |                    |
| integration.manage                     |      ✓       |                |                   |         ✓         |         |                   |         |           |                    |
| integration.credential.manage (reauth) |      ✓       |                |                   |         ✓         |         |                   |         |           |                    |
| integration.revoke (reauth)            |      ✓       |                |                   |         ✓         |         |                   |         |           |                    |
| integration.health_check               |      ✓       |       ✓        |         ✓         |         ✓         |         |                   |    ✓    |           |                    |
| job.read                               |      ✓       |       ✓        |         ✓         |         ✓         |    ✓    |                   |    ✓    |           |                    |
| audit.read                             |      ✓       |       ✓        |                   |                   |    ✓    |                   |         |           |                    |
| action.propose _(reserved)_            |              |                |         ✓         |                   |         |                   |         |           |                    |
| action.approve _(reserved, reauth)_    |              |       ✓        |                   |                   |         |                   |         |           |                    |
| recovery.execute _(reserved, reauth)_  |              |                |                   |                   |         |                   |         |           |         ✓          |

`SYSTEM_OWNER` (platform role) has `platform.tenant.read`, `platform.tenant.manage` (reauth),
`platform.audit.read`, and `platform.audit.verify`, and **no tenant capabilities**. A system owner
sees tenant data only through an explicit tenant membership. The prompt's "Customer Administrator"
maps to `TENANT_ADMIN` and "Customer Operator" maps to `SECURITY_OPERATOR`.

## Tenant isolation

- The active tenant comes only from the server-side session. Selecting a tenant verifies an active
  membership. Request bodies with a `tenantId` are rejected by the strict schemas.
- PostgreSQL row-level security on `tenants`, `memberships`, `assets`, `integrations`,
  `integration_health_checks`, `jobs`, and `audit_events`. Context is transaction-local via
  `set_config(…, true)`. Missing context matches nothing.
- The runtime login role is a member of the `aegis_app` group. It owns no tables and is not a
  superuser or BYPASSRLS role; startup verifies this.
- Composite foreign keys `(tenant_id, id)` prevent cross-tenant relationships, even for the table
  owner.
- Cross-tenant resource IDs produce 404 (the resource is invisible), not 403.
- Jobs persist their tenant and actor. The worker re-establishes both before execution, and the only
  cross-tenant database operation (`claim_job()`) is a narrow SECURITY DEFINER function that leases
  jobs.
- Record classes: **global** (`principals`, `sessions`, `auth_throttle`, `worker_heartbeats`,
  `schema_migrations`); **tenant-scoped** (all others); **platform** audit events (`tenant_id NULL`).
  No caches exist. Any future cache must key by tenant.

What RLS protects against: application query bugs, such as a missing `WHERE tenant_id`. What it
does not protect against: a compromised application process, which can set any context it wants.

## Secrets

| Category                           | Handling                                                                                                                                      |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Database credentials               | Env vars only; the API needs only the runtime role. The owner role (`DATABASE_MIGRATION_URL`) is for the migration step only                  |
| Session tokens                     | Never stored; only hashes. Never logged (pino redaction of `cookie` and `set-cookie`)                                                         |
| Passwords                          | Argon2id (m=19 MiB, t=2, p=1); hashes are never returned by the API                                                                           |
| Integration credentials            | Stored as references `env:AEGIS_SECRET_<NAME>` only; resolved in the worker at call time; the namespace prevents referencing platform secrets |
| Signing, encryption, recovery keys | None in Phase 1                                                                                                                               |
| CI secrets                         | None required; CI uses an ephemeral Postgres container                                                                                        |

Controls: repository secret scanner (`pnpm scan:secrets`), frontend bundle scanner (`pnpm scan:bundle`,
which also checks the literal values of secrets in the build environment), configuration errors
that name variables but never values (tested), log redaction (tested), and audit metadata redaction
(tested).

**Production requirement:** inject secrets from a secret manager (for example Vault, AWS Secrets
Manager, or GCP Secret Manager) as environment variables at process start. Give the API process only
`DATABASE_URL` and the `AEGIS_SECRET_*` values it needs. Rotate per OPERATIONS_RUNBOOK.md.

## Audit

- Events record actor, actor type, action, target, outcome (`SUCCESS`, `DENIED`, `FAILURE`), reason
  code, request and correlation IDs, redacted metadata, and timestamps from the database clock.
- Recorded today: login success, failure, and throttling; logout; logout-all; reauthentication;
  password change; tenant selection (and denials); session revocation; every authorization denial;
  membership create and update; tenant create; bootstrap and CLI user lifecycle; asset create,
  update, and delete; integration create, update, suspend, resume, and revoke; health-check
  request and result; job denial and failure; audit chain verification.
- Success events commit in the same transaction as the change; if the audit write fails, the change
  fails. Denials are written in an independent transaction; if that fails, the failure is logged and
  the request is still denied.
- Integrity: the runtime role has only INSERT and SELECT. A trigger blocks UPDATE, DELETE, and
  TRUNCATE for every role, including the owner. Each row is hash-chained, and `audit_verify_chain()`
  detects modified, reordered, or removed interior events.
- **Limit:** a database superuser, or the owner disabling triggers, can rewrite rows _and_ recompute
  the chain. Tail truncation is detectable only against an externally recorded head hash (shown after
  verification). This is tamper-_evidence_ inside one database, not independent tamper-proofing.

## Failure behaviour

| Condition                           | Behaviour                                                                           |
| ----------------------------------- | ----------------------------------------------------------------------------------- |
| Required config missing or invalid  | Process exits with the variable names (no values)                                   |
| Runtime DB role too privileged      | Process exits                                                                       |
| Database unavailable                | Readiness 503; requests fail with 5xx; nothing is reported healthy                  |
| Schema version mismatch             | Readiness 503 until migrations run                                                  |
| Authorization cannot be established | Deny                                                                                |
| Audit write fails (success path)    | Whole operation rolls back                                                          |
| Audit write fails (denial path)     | Denial stands; failure logged                                                       |
| Integration unavailable or timeout  | Explicit DISCONNECTED/UNKNOWN with an error code; old results become STALE          |
| Worker not running                  | Component status UNAVAILABLE, UNKNOWN, or STALE; setup issue raised on the overview |
| Verifier unavailable                | Contract aggregation yields NOT_RUN, BLOCKED, or INCONCLUSIVE, never VERIFIED       |
