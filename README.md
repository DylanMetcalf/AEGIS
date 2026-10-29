# AEGIS

AEGIS is a cyber-defense platform being built in five phases. **This repository contains Phase 1: the
foundation.** It covers identity, authorization, tenant isolation, audit, asset and integration
registries, background jobs, health reporting, and the application shell, plus contracts for the
capabilities that later phases implement.

Phase 1 does **not** detect threats, collect security telemetry, execute defensive actions, or run
SENTINEL supervision. The interface says so wherever those areas appear.

## Quick start (local development)

Requirements: Node.js ≥ 22.12, pnpm 10, PostgreSQL 16 (an admin connection is needed once).

```bash
pnpm install
PG_ADMIN_URL=postgres://postgres:<password>@127.0.0.1:5432/postgres scripts/dev-setup.sh
printf '%s\n' '<choose-a-password>' | pnpm --filter @aegis/server admin bootstrap \
  --email you@example.com --name "Your Name" --tenant-slug dev --tenant-name "Development"
pnpm --filter @aegis/server dev     # API + worker on :3000
pnpm --filter @aegis/web dev        # UI on :5173 (proxies /api)
```

Open http://localhost:5173 and sign in. See [docs/DEVELOPMENT_GUIDE.md](docs/DEVELOPMENT_GUIDE.md).

## Checks

```bash
pnpm run check   # lint, format, typecheck, secret scan, all tests, build, bundle scan
```

Server tests run against a real PostgreSQL database. They need `TEST_DATABASE_ADMIN_URL`, which
defaults to the CI service container credentials.

## Documentation

| Document                                                   | Purpose                                                    |
| ---------------------------------------------------------- | ---------------------------------------------------------- |
| [PROJECT_STATE](docs/PROJECT_STATE.md)                     | What exists now, test status, blockers, next actions       |
| [ARCHITECTURE](docs/ARCHITECTURE.md)                       | Components, trust boundaries, data flows, extension points |
| [SECURITY_MODEL](docs/SECURITY_MODEL.md)                   | Identities, roles, capabilities, isolation, secrets, audit |
| [THREAT_MODEL](docs/THREAT_MODEL.md)                       | Assets, actors, threats, mitigations, residual risk        |
| [DATA_MODEL](docs/DATA_MODEL.md)                           | Tables, constraints, RLS, state machines                   |
| [API_CONTRACTS](docs/API_CONTRACTS.md)                     | Endpoints, errors, pagination                              |
| [VERIFICATION_MATRIX](docs/VERIFICATION_MATRIX.md)         | Security property → implementation → test → result         |
| [KNOWN_LIMITATIONS](docs/KNOWN_LIMITATIONS.md)             | Gaps, unsupported features, unverified assumptions         |
| [DECISIONS](docs/DECISIONS.md)                             | Architecture decision records                              |
| [IMPLEMENTATION_PLAN](docs/IMPLEMENTATION_PLAN.md)         | Phase plan and dependencies                                |
| [OPERATIONS_RUNBOOK](docs/OPERATIONS_RUNBOOK.md)           | Deploy, migrate, rotate, recover                           |
| [DEVELOPMENT_GUIDE](docs/DEVELOPMENT_GUIDE.md)             | Local setup and conventions                                |
| [SECURITY_REVIEW_PHASE_1](docs/SECURITY_REVIEW_PHASE_1.md) | Phase 1 review findings                                    |
| [PHASE_1_ACCEPTANCE](docs/PHASE_1_ACCEPTANCE.md)           | Gate-by-gate acceptance with evidence                      |
