# Implementation Plan

## Phase 1: Foundation (this repository state)

Delivered in three batches, each followed by review, tests, and documentation:

1. **Server foundation:** schema, RLS, roles, sessions, authorization, audit, assets, integrations,
   jobs, health, contracts, and 177 database-backed tests.
2. **Web app and quality gates:** application shell, pages, design system, web tests, lint, format,
   secret and bundle scanners, CI, dependency upgrades, and review fixes.
3. **Security review and documentation:** migration 0002, stuck-CONNECTING handling, cursor
   robustness, and the canonical documents.

## Phase 2 prerequisites (recommended before starting detection work)

1. **MFA** (TOTP or WebAuthn) and token rotation on reauthentication (F-06, F-19).
2. Run CI on GitHub and fix anything environment-specific. Pin actions to commit SHAs (F-17).
3. Decide on the audit throughput strategy before high-volume ingestion (F-12).
4. Shared rate-limit store if more than one API instance is planned (F-09).

## Phase 2: Security intelligence

Telemetry ingestion (new provider capability `events.collect`, tenant-scoped tables with RLS and
composite FKs); detection engine; finding lifecycle (new state machine); evidence engine implementing
`contracts/evidence.ts`; investigations; relational knowledge graph; coverage computation writing
`assets.coverage_state`; first real application-protection integration. Any rendering of repository
or Markdown content requires a sanitizer.

## Phase 3: SENTINEL and defensive action

SENTINEL as a separate deployment with its own credentials, storage, and administrators
(`contracts/sentinel.ts` independence table). Policy engine; defensive-action execution behind the
contract (approvals, preconditions, recovery reference); independent verification
(`contracts/verification.ts`); recovery execution; external append-only audit sink with head-hash
anchoring (F-10, F-11).

## Phase 4: AI and evolution

AI worker orchestration under `contracts/resource-budget.ts` with enforced operation allow-lists;
prompt-injection boundaries; controlled research and remediation development; the 3D Security World
backed by real data.

## Phase 5: Assurance and production readiness

Adversarial testing, supply-chain controls (SBOM, provenance, SHA-pinned CI), multi-tenant release
gates, extended integrations, and production-readiness assessment by an independent reviewer.
