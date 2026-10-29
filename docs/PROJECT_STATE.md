# Project State

**Current milestone:** Phase 1 (Foundation) implementation complete; awaiting human review. Updated 2026-10-29.

## Starting point

The repository was empty: no commits and no files (category A). The stack was chosen from scratch
(DECISIONS ADR-001 to ADR-013).

## Completed capabilities

| Capability                                                                                 | Status                                                                                        |
| ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- |
| Password authentication, server sessions, logout, revocation, throttling, reauthentication | IMPLEMENTED_AND_VERIFIED                                                                      |
| Central authorization with role → capability map and route policy guard                    | IMPLEMENTED_AND_VERIFIED                                                                      |
| Tenant isolation (session tenant, RLS, composite FKs, restricted DB role)                  | IMPLEMENTED_AND_VERIFIED                                                                      |
| Asset registry with authorization scopes, state machine, optimistic concurrency            | IMPLEMENTED_AND_VERIFIED                                                                      |
| Integration registry, capability and permission gating, credential references              | IMPLEMENTED_AND_VERIFIED                                                                      |
| HTTPS endpoint probe (real network, SSRF-guarded)                                          | IMPLEMENTED_AND_VERIFIED (local server only)                                                  |
| Simulated test adapter                                                                     | IMPLEMENTED_AND_VERIFIED (test use only)                                                      |
| Postgres job queue with tenant and actor context                                           | IMPLEMENTED_AND_VERIFIED                                                                      |
| Hash-chained append-only audit log + verification                                          | IMPLEMENTED_AND_VERIFIED (same-DB integrity only)                                             |
| Health, readiness, component status                                                        | IMPLEMENTED_AND_VERIFIED                                                                      |
| Validated configuration; secret handling; log redaction                                    | IMPLEMENTED_AND_VERIFIED                                                                      |
| Web shell, overview, assets, integrations, audit, settings                                 | IMPLEMENTED_AND_VERIFIED (unit tests + manual e2e)                                            |
| Admin CLI (bootstrap, create-user, reset-password, disable-user)                           | IMPLEMENTED_NOT_FULLY_VERIFIED (bootstrap and refusal exercised manually; no automated tests) |
| CI workflow                                                                                | IMPLEMENTED_NOT_FULLY_VERIFIED (steps run locally; not yet run on GitHub)                     |
| Defensive action, evidence, verification, policy, SENTINEL, recovery contracts             | INTERFACE_ONLY                                                                                |
| Resource budgets                                                                           | PARTIALLY_IMPLEMENTED (job limits enforced; agent budgets interface-only)                     |
| Telemetry, detection, findings, coverage, agents, world, reports                           | PLANNED                                                                                       |

## Important paths

| Path                           | Contents                                        |
| ------------------------------ | ----------------------------------------------- |
| `apps/server/migrations/`      | Schema (0001 foundation, 0002 RLS fix)          |
| `apps/server/db/provision.sql` | Role and database provisioning                  |
| `apps/server/src/authz/`       | Capabilities and `authorize()`                  |
| `apps/server/src/http/app.ts`  | Security hooks, route guard, error mapping      |
| `apps/server/src/contracts/`   | Future-phase contracts                          |
| `apps/server/test/`            | Database-backed test suites                     |
| `apps/web/src/`                | UI; `ui/` holds the design system               |
| `packages/shared/src/`         | Enums, state machines, schemas, module registry |
| `scripts/`                     | dev-setup, secret-scan, bundle-scan             |

## Test status

`pnpm run check` passes: lint, format, typecheck, secret scan, 218 tests (server 180 on PostgreSQL 16,
web 27, shared 11), build, bundle scan. `pnpm audit --prod` reports no known vulnerabilities. A manual
Playwright walkthrough against a running server passed 16 of 16 steps.

Test corrections made during development (none weakened a security check):

- Three UI assertions were wrong rather than the code: a "no score" check matched the page's own
  disclaimer, a loading-state check raced a fast mock, and a description check expected an
  `aria-hidden` glyph.
- The e2e script expected the overview after login, but the app correctly returned the user to the
  originally requested page.

## Known blockers

None for continuing development. Production use is blocked by F-06 (no MFA) and unverified deployment
infrastructure (KNOWN_LIMITATIONS.md).

## Next actions

See IMPLEMENTATION_PLAN.md, "Phase 2 prerequisites".
