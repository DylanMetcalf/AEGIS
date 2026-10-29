# Decisions

Format: Decision · Context · Alternatives · Reasoning · Consequences · Revisit when. All dated 2026-10-29 unless noted.

## ADR-001 Modular monolith in TypeScript

- **Context:** Empty repository. Phase 1 needs identity, authorization, data, jobs, and UI with strong
  isolation.
- **Alternatives:** Microservices; Python/Django; Go.
- **Reasoning:** A single deployable keeps trust boundaries explicit and testable without network
  hops. TypeScript allows sharing schemas and enumerations between server and browser. The worker can
  already run as a separate process when isolation is needed.
- **Consequences:** One database and one codebase. Module boundaries are enforced by convention and
  review, not by process separation.
- **Revisit:** When SENTINEL is implemented (it must not share this trust domain), or when scaling
  needs differ per component.

## ADR-002 Fastify + plain SQL (`pg`) rather than an ORM

- **Reasoning:** Tenant context must be applied per transaction (`set_config(…, true)`), and RLS
  behaviour must be obvious in review. Parameterized SQL in small repository functions is explicit;
  sort columns come from allowlists only.
- **Consequences:** Some boilerplate. No unsafe dynamic SQL: values are always parameters.
- **Revisit:** If query count grows enough that a typed builder (e.g. Kysely) clearly reduces errors.

## ADR-003 PostgreSQL row-level security as the tenant-isolation backstop

- **Alternatives:** Application filtering only; schema per tenant; database per tenant.
- **Reasoning:** Application filters remain, and RLS catches the query that forgets one. Schema or
  database per tenant is premature for an initially single-tenant deployment.
- **Consequences:** The runtime role must not own tables or bypass RLS (startup check). The schema
  owner runs migrations only. RLS does not defend against a compromised app process.
- **Revisit:** Phase 5 multi-tenant release gates, or for tenants requiring physical separation.

## ADR-004 Server-side sessions, not JWTs

- **Reasoning:** Revocation must be immediate (logout, password change, disabled user). Opaque random
  tokens with hashed storage give that; JWTs would need a revocation list anyway.
- **Consequences:** One indexed lookup per request.
- **Revisit:** If an external API for machine clients is added (service identities would use
  separate scoped credentials).

## ADR-005 CSRF defence by Origin check + SameSite=Strict + JSON-only, without tokens

- **Reasoning:** A single first-party SPA on one origin. Strict SameSite cookies stop cross-site
  sending. The Origin check rejects cross-site unsafe requests, and removing the `text/plain` parser
  makes "simple" cross-site posts fail. This avoids the complexity of token synchronisation.
- **Revisit:** If the app must be embedded cross-site, or supports browsers without Origin headers.

## ADR-006 Hash-chained audit table in the primary database

- **Alternatives:** External append-only log service; WORM storage.
- **Reasoning:** Gives real tamper evidence now with no new infrastructure, and the limits are
  stated explicitly.
- **Consequences:** Database superusers can rewrite and re-chain. Writes are serialised by an advisory
  lock.
- **Revisit:** Phase 3 or SENTINEL: stream events to an external, separately administered
  append-only store and anchor head hashes periodically.

## ADR-007 Forward-only migrations with checksums

- **Reasoning:** Down migrations are rarely safe for security-relevant data. Reversal is done by new
  forward migrations and database backups. Checksums detect edits to applied migrations.
- **Consequences:** Every schema change needs a new file. Restore relies on backups.

## ADR-008 PostgreSQL-backed job queue

- **Alternatives:** Redis/BullMQ; a cloud queue.
- **Reasoning:** One job type with low volume. `FOR UPDATE SKIP LOCKED` leasing gives safe
  concurrency, and the job row carries tenant and actor under RLS. No new infrastructure.
- **Revisit:** If throughput or scheduling needs exceed what Postgres comfortably supports.

## ADR-009 Unversioned `/api` during Phase 1

- **Reasoning:** The only client is the bundled SPA, deployed together with the server.
- **Revisit:** Before any external or third-party API consumer exists.

## ADR-010 Integration credentials as environment references in an `AEGIS_SECRET_` namespace

- **Alternatives:** Encrypt secrets in the database; integrate a vault now.
- **Reasoning:** Never storing secrets in ordinary records was a hard requirement. Database encryption
  needs key management that doesn't exist yet. References let a secret manager inject values, and
  the namespace stops an integration from referencing platform secrets.
- **Consequences:** Adding a credential needs an operator to provision the variable and restart the
  process.
- **Revisit:** Phase 2/5: a vault provider with short-lived, scoped credentials.

## ADR-011 Contracts without tables for future capabilities

- **Reasoning:** The prompt forbids decorative tables. Typed contracts with tested rules (approvals,
  pessimistic verification aggregation, budget ceilings) fix the shapes later phases depend on,
  without pretending the capability exists.

## ADR-012 Upgrade to zod 4, react-router 7.18, @fastify/static 10 during Phase 1

- **Context:** `pnpm audit` reported high-severity advisories (zod memory exhaustion; @fastify/static
  path traversal) and a moderate react-router open redirect.
- **Reasoning:** Fixing now is cheaper than carrying known vulnerabilities into later phases. The test
  suites passed unchanged except for library-specific message text.

## ADR-013 React 18 rather than React 19

- **Reasoning:** Stable, well-understood API. react-router 7.18 supports React 18. Upgrading later is
  mechanical.
