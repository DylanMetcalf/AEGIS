# Phase 1 Security Review

Reviewed: the implementation on branch `claude/inspiring-meitner-jue9r8` (server, web, migrations 0001
and 0002, CI, scripts). Method: manual code review of every trust boundary in ARCHITECTURE.md, the
automated suites, `pnpm audit`, the secret and bundle scanners, and an end-to-end browser walkthrough
against a running server and database (including SSRF, XSS payload, logout, keyboard, and mobile
checks).

Reviewer independence: **this review was performed by the same agent that wrote the code.** It is not
an independent audit. An independent reviewer should repeat it before production use.

## Findings

| ID   | Severity | Confidence | Component          | Description                                                                                                                                             | Evidence / reproduction                                                                                 | Remediation                                                                             | Verification                                                   | Status                                         |
| ---- | -------- | ---------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | -------------------------------------------------------------- | ---------------------------------------------- |
| F-01 | Medium   | High       | API pagination     | Crafted but well-formed cursors (non-date sort value; bigint overflow) reached SQL casts and returned **500**                                           | `test/cursor-robustness.test.ts` failed before the fix (500 instead of 400)                             | Validate timestamp cursors and bigint range in the app; map PG 22003/22007/22008 to 400 | Test passes                                                    | Fixed                                          |
| F-02 | Medium   | High       | Static serving     | SPA fallback served `index.html` (200, text/html) for **missing assets**; masks deploy errors and serves HTML for script URLs                           | Observed in the e2e run after a rebuild (MIME errors)                                                   | Fallback only for extension-less navigation paths                                       | `curl /assets/nope.js` → 404 JSON                              | Fixed                                          |
| F-03 | High     | High       | Dependencies       | `@fastify/static` ≤10.1.1 (path traversal / guard bypass, high), `zod` <4.6.6 (memory exhaustion, high), `react-router` <7.18 (open redirect, moderate) | `pnpm audit --prod`                                                                                     | Upgraded to @fastify/static 10.1.8, zod 4.6.7, react-router-dom 7.18.5                  | `pnpm audit --prod`: no known vulnerabilities; all suites pass | Fixed                                          |
| F-04 | Medium   | High       | Web login          | Post-login redirect accepted `/\evil.example` (backslash open redirect)                                                                                 | Code review of `LoginPage`                                                                              | `safeReturnPath` allows only plain in-app paths                                         | `ui.test.tsx` redirect cases                                   | Fixed                                          |
| F-05 | Low      | High       | Web layout         | Page overflowed horizontally on narrow screens (accessibility and usability)                                                                            | e2e at 390 px                                                                                           | `minmax(0,1fr)` grid tracks                                                             | e2e mobile step passes                                         | Fixed                                          |
| F-15 | Low      | High       | RLS                | `tenants` SELECT policy matched suspended or removed memberships (defence-in-depth gap; the app already checks status)                                  | Policy review                                                                                           | Migration 0002 requires ACTIVE membership                                               | `tenancy.test.ts` new case                                     | Fixed                                          |
| F-16 | Low      | High       | Integration status | A job dying after marking CONNECTING left the UI showing "Checking" forever                                                                             | Code review of job phases                                                                               | `effectiveStatus` reports CONNECTING older than 5 min as UNKNOWN                        | `integrations.test.ts` new case                                | Fixed                                          |
| F-06 | Medium   | High       | Identity           | No MFA                                                                                                                                                  | —                                                                                                       | Implement TOTP/WebAuthn                                                                 | —                                                              | Open (accepted for Phase 1, blocks production) |
| F-07 | Low      | High       | Identity           | No self-service reset                                                                                                                                   | —                                                                                                       | Email-based reset when email exists                                                     | —                                                              | Open                                           |
| F-08 | Low      | High       | Identity           | Targeted account lockout                                                                                                                                | Reasoning                                                                                               | Risk-based throttling with MFA                                                          | —                                                              | Accepted                                       |
| F-09 | Low      | High       | HTTP               | Per-process rate-limit store                                                                                                                            | Library default                                                                                         | Shared store (Redis) for multi-instance                                                 | —                                                              | Open                                           |
| F-10 | Low      | Medium     | Audit              | Denial audit can be lost under pool exhaustion                                                                                                          | Reasoning: second connection                                                                            | External sink / reserved pool                                                           | —                                                              | Open                                           |
| F-11 | Medium   | High       | Audit              | Tamper evidence bounded by DB administrators                                                                                                            | `audit.test.ts` demonstrates superuser rewrite is _detected_ only because the attacker did not re-chain | External anchoring (Phase 3)                                                            | —                                                              | Accepted, documented                           |
| F-12 | Low      | Medium     | Audit              | Serialised chain writes                                                                                                                                 | Design                                                                                                  | Measure, then partition chains                                                          | —                                                              | Open                                           |
| F-13 | Info     | High       | Health             | Readiness reveals schema version                                                                                                                        | —                                                                                                       | Ingress restriction                                                                     | —                                                              | Accepted                                       |
| F-14 | Low      | High       | Members            | Admin-only email enumeration                                                                                                                            | —                                                                                                       | Invitations                                                                             | —                                                              | Accepted                                       |
| F-17 | Low      | High       | CI                 | Actions not SHA-pinned; no SBOM                                                                                                                         | —                                                                                                       | Phase 5 supply-chain controls                                                           | —                                                              | Open                                           |
| F-18 | Info     | High       | CSRF               | No synchronizer tokens (by design)                                                                                                                      | ADR-005                                                                                                 | —                                                                                       | `auth.test.ts` origin and media-type tests                     | Accepted                                       |
| F-19 | Low      | High       | Sessions           | No token rotation on reauthentication or tenant switch                                                                                                  | —                                                                                                       | Rotate with MFA work                                                                    | —                                                              | Open                                           |

**Critical findings: none open. High findings: one (F-03), fixed.**

## Area-by-area conclusions

1. **Authentication:** sound for password-only. Argon2id, server sessions, revocation, throttling, and
   generic errors are all tested. Main gap: MFA.
2. **Authorization:** central and deterministic. Every route declares its policy (startup guard), and
   resource re-checks happen in handlers. Direct-API bypass is tested for read-only roles, non-admins,
   and system owners.
3. **Tenant isolation:** layered (session tenant, RLS, composite FKs, re-check). Tested at the API and
   database levels, including pool reuse, malformed context, and background jobs.
4. **Secrets:** no secrets committed (scanner), none in the bundle (scanner checks live values), none
   in logs or audit (tests), and config errors are value-free (tests).
5. **API validation:** strict schemas reject unknown keys, control characters, oversized inputs,
   invalid enums, and tampered cursors.
6. **Database integrity:** constraints for enums, formats, relationships, and terminal states;
   optimistic concurrency; transactional audit; migration integrity checks.
7. **Audit:** used for every significant action and denial; append-only; chain verified; limits
   documented.
8. **Configuration:** fails closed; hardened environments reject dev conveniences.
9. **Error handling:** stable codes, no stacks, Postgres errors mapped; one 500 path found and fixed
   (F-01).
10. **Dependencies:** advisories fixed (F-03). The CI audit gate prevents regressions at the `high`
    level.
11. **Integration boundaries:** capability and permission gating, SSRF guard, timeouts, references
    only. Real-network probe tested locally.
12. **Background jobs:** tenant and actor persisted, re-authorized at run time, bounded retries and
    timeouts, idempotency, lease ownership.
13. **Unsafe dynamic execution:** none. ESLint bans eval-like constructs, and there are no shell or
    exec paths. The defensive-action executor is disabled.
14. **Frontend/backend boundary:** the UI is advisory only; the server enforces everything.
    Same-origin client; no web storage (lint and e2e).
15. **Health indicators:** unknown, stale, unverified, and foundation-only states are explicit and
    tested. Overview has no score.
16. **Feature-completion indicators:** module registry drives navigation; tests assert that
    non-operational modules show status and fetch no data.
17. **SENTINEL independence:** not achieved and not claimed; shared dependencies listed.
18. **Recovery and administration:** CLI-only privileged operations; recovery is a contract only.
19. **Testing quality:** server tests hit real PostgreSQL. Mocks are used only in UI tests and for
    simulated providers. No test was weakened to pass: three UI assertions were corrected because
    they tested the wrong thing (documented in PROJECT_STATE).
20. **Operational readiness:** suitable for development and staging evaluation. **Not production
    ready** while F-06 is open and no deployment or TLS setup has been verified.
