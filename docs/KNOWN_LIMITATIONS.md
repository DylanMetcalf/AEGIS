# Known Limitations

Current as of 2026-10-29. Each item states whether it is a security gap, an unimplemented capability,
or an unverified assumption.

## Security gaps (open)

| ID   | Gap                                                                                              | Impact                                                                                               | Planned                                                      |
| ---- | ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| F-06 | No multi-factor authentication                                                                   | A stolen password gives full account access                                                          | Before any production use (Phase 2 prerequisite recommended) |
| F-07 | No self-service password reset (no email delivery)                                               | Resets need an operator with shell access (`admin reset-password`)                                   | When an email provider is integrated                         |
| F-08 | Per-account lockout can be triggered by anyone who knows an email                                | Targeted 15-minute denial of login                                                                   | Revisit with MFA / risk-based throttling                     |
| F-09 | HTTP rate-limit counters are per process (in-memory)                                             | Limits multiply with instance count. Login throttling itself is DB-backed and shared                 | When running more than one API instance                      |
| F-10 | Denial audit events use a second DB connection; under pool exhaustion they can be lost (logged)  | Gaps in denial records under extreme load                                                            | Phase 3 (external audit sink)                                |
| F-11 | Audit tamper evidence lives in the same database                                                 | A DB superuser or owner can rewrite and re-chain; tail truncation needs an external head-hash record | Phase 3: external append-only sink and anchoring             |
| F-12 | Audit chain writes are serialised by an advisory lock                                            | Throughput ceiling on audited writes                                                                 | Measure before Phase 2 ingestion; partition chains if needed |
| F-13 | `/health/ready` is public and reveals the schema version                                         | Minor information disclosure                                                                         | Restrict at the ingress if undesired                         |
| F-14 | Tenant admins can learn whether an email has an account (member add)                             | Enumeration by a privileged role                                                                     | Invitation flow when email exists                            |
| F-17 | GitHub Actions pinned by tag, not commit SHA; no SBOM or provenance                              | Supply-chain exposure                                                                                | Phase 5                                                      |
| F-19 | Session token not rotated on reauthentication or tenant switch                                   | Small fixation window, mitigated by HttpOnly/SameSite                                                | Revisit with MFA                                             |
| —    | Secrets come from process environment variables; no vault integration or short-lived credentials | Rotation requires a restart                                                                          | Phase 2/5                                                    |
| —    | No egress firewall is configured by this repository                                              | SSRF defence relies on application checks only                                                       | Deployment responsibility                                    |
| —    | No password breach-list or complexity check beyond length ≥ 12                                   | Weak but long passwords accepted                                                                     | With MFA work                                                |

## Unimplemented capabilities (by design in Phase 1)

| Area                                                                       | State                                                                 |
| -------------------------------------------------------------------------- | --------------------------------------------------------------------- |
| Telemetry ingestion, detection engine, findings, incidents, investigations | NOT_IMPLEMENTED (Phase 2)                                             |
| Coverage computation                                                       | NOT_IMPLEMENTED; every asset reports `UNKNOWN` (Phase 2)              |
| Evidence engine and provenance capture                                     | INTERFACE_ONLY contract (Phase 2)                                     |
| Knowledge graph                                                            | PLANNED (Phase 2, relational first)                                   |
| SENTINEL supervision                                                       | FOUNDATION_ONLY: contracts only; shares every dependency with the app |
| Policy engine                                                              | INTERFACE_ONLY (Phase 3)                                              |
| Defensive action execution, containment                                    | INTERFACE_ONLY; executor permanently disabled (Phase 3)               |
| Independent verification                                                   | INTERFACE_ONLY aggregation rules (Phase 3)                            |
| Recovery execution and readiness                                           | INTERFACE_ONLY; readiness reported NOT_RUN or UNVERIFIED (Phase 3)    |
| AI agents, evolution, remediation                                          | NOT_IMPLEMENTED; AI_WORKER identities are read-only (Phase 4)         |
| 3D Security World                                                          | NOT_IMPLEMENTED (Phase 4)                                             |
| Reports                                                                    | NOT_IMPLEMENTED (Phase 5)                                             |
| Service/AI identity authentication (API keys, workload identity)           | NOT_IMPLEMENTED; identities exist as job actors only                  |
| Tenant suspension UI, user creation UI                                     | CLI-only (`admin` command) or not yet exposed                         |

## Supported integrations

| Provider                                               | Status                                                                                                   |
| ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------- |
| `http.endpoint_probe`: HTTPS endpoint reachability     | IMPLEMENTED_AND_VERIFIED against a local HTTP server; not verified against a production endpoint from CI |
| `aegis.test_adapter`: simulated                        | Test adapter only; disabled outside development                                                          |
| Cloud providers, SIEMs, code hosts, identity providers | UNSUPPORTED in Phase 1                                                                                   |

## Unverified assumptions

- A TLS-terminating reverse proxy sits in front of the API in production, and `TRUST_PROXY` is set
  correctly. Not part of this repository.
- Production PostgreSQL enforces TLS (`sslmode=verify-full`). Configuration requires an `sslmode`, but
  the server certificate setup is the deployer's.
- Browsers send `Origin` on state-changing fetches (true for current evergreen browsers).
- Timing equalisation of login responses was not measured statistically.
- CI workflow (`.github/workflows/ci.yml`) has not run on GitHub at the time of writing; every step
  was executed locally with identical commands (`pnpm run check`).
- No load or performance testing was done; no performance claims are made.
