# Threat Model (Phase 1)

Method: asset- and boundary-driven, STRIDE-informed. Scope: the code in this repository as it runs
under the deployment model in ARCHITECTURE.md. Updated 2026-10-29.

## Assets

| Asset                                      | Why it matters                                                   |
| ------------------------------------------ | ---------------------------------------------------------------- |
| Tenant data (assets, scopes, integrations) | Describes a customer's estate; disclosure aids attackers         |
| Authorization scopes                       | Define what AEGIS may act on; forging one could authorize misuse |
| Integration credentials                    | Grant access to external systems                                 |
| Sessions and password hashes               | Account takeover                                                 |
| Audit log                                  | Accountability; future evidence base                             |
| Platform configuration and DB roles        | Control over isolation and security settings                     |
| Availability of health/status reporting    | Operators rely on it not lying                                   |

## Threat actors

1. Unauthenticated internet attacker.
2. Authenticated user of tenant A trying to reach tenant B.
3. Low-privilege insider (analyst or operator) seeking privileged actions.
4. Malicious or compromised integration endpoint (responses, redirects, DNS).
5. Malicious website visited by a logged-in user (CSRF, clickjacking).
6. Compromised AI worker or service identity (future; the identity types exist now).
7. Database or infrastructure administrator (privileged insider).
8. Supply-chain attacker via dependencies or CI.

## Attack surface

HTTP API (`/api/*`), static SPA, `/health/*`, admin and migrate CLIs (shell access required), the
database, outbound probe requests, CI workflow, and npm dependencies.

## Threat scenarios

| #   | Scenario                                                       | Actor   | Mitigations (implemented)                                                                                                                                                                     | Residual / missing                                                                                       |
| --- | -------------------------------------------------------------- | ------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| T1  | Credential stuffing / brute force                              | 1       | Argon2id; per-account and per-client DB throttle; per-client HTTP limit on credential routes; generic errors                                                                                  | No MFA (F-06). Lockout can be abused to lock a known account for 15 min (F-08)                           |
| T2  | Account enumeration                                            | 1       | Same message and status for unknown, wrong, and disabled; dummy hash; identical throttling                                                                                                    | Timing equalised but not proven constant-time; tenant admins can probe emails when adding members (F-14) |
| T3  | Session theft or fixation                                      | 1, 5    | HttpOnly, SameSite=Strict, Secure + `__Host-`; token hashed at rest; rotated on login; idle and absolute expiry; server-side revocation                                                       | No token binding to device; token not rotated on reauthentication (F-19)                                 |
| T4  | CSRF                                                           | 5       | Origin must equal APP_ORIGIN on unsafe methods; JSON-only bodies (text/plain parser removed); SameSite=Strict                                                                                 | Relies on browsers sending Origin (all current browsers do for these requests)                           |
| T5  | Clickjacking                                                   | 5       | CSP `frame-ancestors 'none'`, X-Frame-Options                                                                                                                                                 | —                                                                                                        |
| T6  | XSS (stored or reflected)                                      | 1–3     | React escapes all output; lint bans `dangerouslySetInnerHTML`; strict CSP (`script-src 'self'`, no inline); API returns JSON only; control characters rejected                                | Future Markdown or repository rendering needs a sanitizer (Phase 2+)                                     |
| T7  | Cross-tenant read, write, or delete by ID guessing             | 2       | Session-derived tenant; RLS; composite FKs; resource tenant re-check; 404 on foreign IDs                                                                                                      | RLS does not stop a compromised app process                                                              |
| T8  | Tenant-context confusion (pooled connections, background jobs) | 2       | Transaction-local context; malformed context rejected; jobs carry and re-verify tenant; tests on pool reuse                                                                                   | —                                                                                                        |
| T9  | Privilege escalation via role or membership manipulation       | 3       | Membership management is TENANT_ADMIN-only with reauthentication; last-admin protection; DB trigger forbids admin roles for AI and service identities                                         | No approval workflow for role grants                                                                     |
| T10 | Bypass of UI restrictions with direct API calls                | 3       | Server-side capability on every route plus resource checks; startup guard on undeclared routes                                                                                                | —                                                                                                        |
| T11 | SSRF through integration URLs                                  | 2, 3, 4 | Scheme allowlist; no URL credentials; blocklist of private, reserved, and mapped ranges; DNS answers all checked; connection pinned to the checked IP; no redirects; timeouts; body discarded | IPv6 blocklist may need extension; egress firewall still recommended                                     |
| T12 | Credential exfiltration via integrations                       | 3, 4    | References only; `AEGIS_SECRET_` namespace; values never returned or logged; revocation clears the reference                                                                                  | Secrets live in process env (no vault integration yet)                                                   |
| T13 | Secret leakage via logs, errors, bundle, or VCS                | all     | Pino redaction; value-free config errors; audit metadata redaction; secret scanner; bundle scanner; `.env` gitignored, mode 600                                                               | Scanner is pattern-based                                                                                 |
| T14 | Audit tampering or repudiation                                 | 3, 7    | Insert-only grants; mutation and truncate triggers; hash chain; verification endpoint; head hash for external anchoring                                                                       | Superuser or owner can rewrite and re-chain; tail truncation needs an external anchor (F-11)             |
| T15 | Misleading health or security status                           | —       | Explicit UNKNOWN, STALE, UNVERIFIED, FOUNDATION_ONLY states; integrations start CONFIGURED; staleness; stuck CONNECTING becomes UNKNOWN                                                       | Status is computed by the system being observed (no independent SENTINEL yet)                            |
| T16 | Resource exhaustion                                            | 1       | Body limit; rate limits; bounded pagination; statement timeout; job retry and timeout limits; zod upgraded past CVE                                                                           | Rate-limit store is per process (F-09); audit chain writes serialised (F-12)                             |
| T17 | Malicious job payloads or replay                               | 3       | Strict payload schemas; idempotency keys with payload comparison; lease ownership checks                                                                                                      | —                                                                                                        |
| T18 | Misconfiguration in production                                 | 7       | Config validation forbids insecure flags, debug logs, non-TLS DB, and http origin; runtime role check                                                                                         | Deployment pipeline not part of this repo                                                                |
| T19 | Dependency or CI compromise                                    | 8       | Lockfile; `pnpm audit` gate; minimal dependencies; CI `permissions: contents: read`; no CI secrets                                                                                            | Actions pinned by tag, not SHA (F-17); no SBOM or signature verification yet (Phase 5)                   |
| T20 | Open redirect after login                                      | 1       | Only plain in-app paths accepted (`safeReturnPath`); react-router patched                                                                                                                     | —                                                                                                        |
| T21 | AI-generated instructions treated as trusted                   | 6       | No AI execution in Phase 1; AI_WORKER is read-only by rule and DB trigger                                                                                                                     | Prompt-injection controls are Phase 4 work                                                               |

## Common-mode risks relevant to SENTINEL

SENTINEL does not exist as an independent system. If it were added inside this process, it would share
the identity provider, database, credentials, administrators, and infrastructure, so one compromise
could silence both. See `contracts/sentinel.ts` (`SENTINEL_INDEPENDENCE`) and KNOWN_LIMITATIONS.md.

## Residual risk summary

The highest residual risks for a production deployment are: **no MFA** (T1); **audit integrity bounded
by database administrators** (T14); **no independent supervision** (T15); and **supply-chain
hardening incomplete** (T19). None is hidden; all are listed in KNOWN_LIMITATIONS.md with planned
phases.
