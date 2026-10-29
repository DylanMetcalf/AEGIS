# API Contracts

Base path `/api`. JSON only. Versioning: unversioned during Phase 1 (single first-party client); a
`/api/v1` prefix will be introduced before any external consumer exists (DECISIONS ADR-009).

## Conventions

- **Authentication:** session cookie (`__Host-aegis_session` with secure cookies, `aegis_session` in
  local development). No bearer tokens.
- **Unsafe methods** (POST, PUT, PATCH, DELETE) require `Origin: <APP_ORIGIN>`, or the response is
  `403 ORIGIN_REJECTED`. Bodies must be `application/json` (otherwise 415) and no larger than
  `BODY_LIMIT_BYTES` (otherwise 413).
- **Tenant:** always the session's active tenant. Clients never send a tenant ID except to `PUT /api/session/tenant`.
- **Headers:** responses include `x-request-id` and `x-correlation-id`. API responses are `Cache-Control: no-store`.
- **Pagination:** `?limit=1..100` (default 25) and `?cursor=<opaque>`, with responses shaped as
  `{ items, nextCursor }`. Cursors are validated; tampered ones return 400.
- **Concurrency:** mutable resources carry `version`, and updates must send the current version
  (otherwise `409 CONFLICT`).

## Error shape

```json
{
  "error": {
    "code": "VALIDATION_FAILED",
    "message": "Request validation failed",
    "requestId": "…",
    "details": [{ "path": "name", "message": "…" }]
  }
}
```

| Status | Codes                                                                                                                                                    | Meaning                                         |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| 400    | `VALIDATION_FAILED`                                                                                                                                      | Malformed or invalid input                      |
| 401    | `UNAUTHENTICATED`, `INVALID_CREDENTIALS`                                                                                                                 | No valid session / bad credentials              |
| 403    | `FORBIDDEN`, `REAUTHENTICATION_REQUIRED`, `ORIGIN_REJECTED`                                                                                              | Not permitted / confirm password / CSRF         |
| 404    | `NOT_FOUND`                                                                                                                                              | Missing **or belongs to another tenant**        |
| 409    | `CONFLICT`, `INVALID_STATE_TRANSITION`                                                                                                                   | Version or uniqueness conflict / bad transition |
| 413    | `PAYLOAD_TOO_LARGE`                                                                                                                                      | Body limit                                      |
| 415    | `UNSUPPORTED_MEDIA_TYPE`                                                                                                                                 | Not JSON                                        |
| 422    | `UNSUPPORTED_PROVIDER`, `PERMISSION_NOT_GRANTED`, `CAPABILITY_NOT_DECLARED`, `CAPABILITY_NOT_IMPLEMENTED`, `PRINCIPAL_NOT_ELIGIBLE`, `LAST_TENANT_ADMIN` | Semantically refused                            |
| 429    | `RATE_LIMITED`                                                                                                                                           | Rate limit or login lockout                     |
| 500    | `INTERNAL_ERROR`                                                                                                                                         | Unexpected; details only in server logs         |
| 503    | `DEPENDENCY_UNAVAILABLE`                                                                                                                                 | Required dependency down                        |

## Endpoints

`Auth` column: `public`, `session` (any valid session), or the capability enforced. "+res" means the
check is repeated against the loaded resource.

### Health (outside `/api`, unauthenticated, not rate-limited)

| Method | Path            | Response                                           |
| ------ | --------------- | -------------------------------------------------- |
| GET    | `/health/live`  | `200 { status: "live", observedAt }`: process only |
| GET    | `/health/ready` | `200/503 { status: "ready"                         | "not_ready", checks: [{ name, required, state, observedAt, detail }] }` |

### Authentication and session

| Method | Path                       | Auth    | Notes                                                               |
| ------ | -------------------------- | ------- | ------------------------------------------------------------------- |
| POST   | `/api/auth/login`          | public  | `{ email, password }` → sets cookie; 401 generic; 429 throttled     |
| POST   | `/api/auth/logout`         | public  | Revokes the current session if any; clears cookie; 204              |
| POST   | `/api/auth/logout-all`     | session | Revokes all of the principal's sessions                             |
| POST   | `/api/auth/reauthenticate` | session | `{ password }` → `{ reauthenticatedUntil }`                         |
| POST   | `/api/auth/password`       | session | `{ currentPassword, newPassword (≥12) }`; revokes other sessions    |
| GET    | `/api/session`             | session | `SessionInfo` (principal, active tenant, memberships, capabilities) |
| PUT    | `/api/session/tenant`      | session | `{ tenantId }`; requires an active membership; 204                  |
| GET    | `/api/sessions`            | session | Own active sessions                                                 |
| DELETE | `/api/sessions/:id`        | session | Own sessions only (others → 404)                                    |

### Tenant administration

| Method | Path               | Auth                       | Notes                                            |
| ------ | ------------------ | -------------------------- | ------------------------------------------------ |
| GET    | `/api/members`     | membership.read            | Bounded to 500                                   |
| POST   | `/api/members`     | membership.manage (reauth) | `{ email, role }`; existing active accounts only |
| PATCH  | `/api/members/:id` | membership.manage (reauth) | `{ role?, status? }`; last-admin protection      |

### Assets

| Method | Path              | Auth                                        | Notes                                                         |
| ------ | ----------------- | ------------------------------------------- | ------------------------------------------------------------- |
| GET    | `/api/assets`     | asset.read                                  | Filters `assetType`, `environment`, `status`; `sort=createdAt | name`, `order=asc | desc` |
| POST   | `/api/assets`     | asset.create                                | `CreateAssetRequest`; coverage always starts UNKNOWN          |
| GET    | `/api/assets/:id` | asset.read +res                             |                                                               |
| PATCH  | `/api/assets/:id` | asset.update +res                           | Requires `version`; status transitions validated              |
| DELETE | `/api/assets/:id` | asset.delete +res (reauth if prod/critical) | 204                                                           |

### Integrations and jobs

| Method | Path                                  | Auth                                                       | Notes                                                           |
| ------ | ------------------------------------- | ---------------------------------------------------------- | --------------------------------------------------------------- |
| GET    | `/api/integration-providers`          | integration.read                                           | Capabilities, permissions, config fields, `testAdapter`         |
| GET    | `/api/integrations`                   | integration.read                                           | Includes `effectiveStatus` (with STALE)                         |
| POST   | `/api/integrations`                   | integration.manage (+credential.manage if `credentialRef`) | Starts CONFIGURED                                               |
| GET    | `/api/integrations/:id`               | integration.read +res                                      | `{ integration, healthChecks }`                                 |
| PATCH  | `/api/integrations/:id`               | integration.manage +res (+credential.manage on change)     | Connection changes reset to CONFIGURED and bump `configVersion` |
| POST   | `/api/integrations/:id/suspend`       | integration.manage +res                                    | `{ version }`                                                   |
| POST   | `/api/integrations/:id/resume`        | integration.manage +res                                    | `{ version }` → CONFIGURED                                      |
| POST   | `/api/integrations/:id/revoke`        | integration.revoke +res (reauth)                           | Terminal; clears credential and permissions                     |
| POST   | `/api/integrations/:id/health-checks` | integration.health_check +res                              | Optional `Idempotency-Key`; 202 new job, 200 replay             |
| GET    | `/api/jobs/:id`                       | job.read                                                   | `JobDto`                                                        |

### Audit, status, overview

| Method | Path                 | Auth               | Notes                                      |
| ------ | -------------------- | ------------------ | ------------------------------------------ |
| GET    | `/api/audit-events`  | audit.read         | Tenant events; `action`, `outcome` filters |
| GET    | `/api/system/status` | system.status.read | Component states with observation times    |
| GET    | `/api/overview`      | tenant.read        | Counts computed from records; no score     |

### Platform (SYSTEM_OWNER)

| Method | Path                         | Auth                            | Notes                                      |
| ------ | ---------------------------- | ------------------------------- | ------------------------------------------ |
| GET    | `/api/platform/tenants`      | platform.tenant.read            |                                            |
| POST   | `/api/platform/tenants`      | platform.tenant.manage (reauth) | `{ slug, displayName, addCreatorAsAdmin }` |
| GET    | `/api/platform/audit-events` | platform.audit.read             | Platform-level events only                 |
| POST   | `/api/platform/audit/verify` | platform.audit.verify           | Chain verification result + head hash      |

There are no generic CRUD endpoints, no file upload, no arbitrary URL fetching, and no command execution.
