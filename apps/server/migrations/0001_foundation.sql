-- AEGIS Phase 1 foundation schema.
--
-- Runs as the schema-owner role (DATABASE_MIGRATION_URL). The group role
-- `aegis_app` must already exist (see apps/server/db/provision.sql). Runtime
-- login roles are members of it; they own nothing, so row-level security
-- applies to them, and they receive only the privileges granted below.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aegis_app') THEN
    RAISE EXCEPTION 'Role aegis_app must exist before migrations run (see apps/server/db/provision.sql)';
  END IF;
END
$$;

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO aegis_app;

-- ---------------------------------------------------------------------------
-- Request context. Set per transaction with set_config(..., true) by the
-- application after authentication. Missing context resolves to NULL, which
-- matches no tenant row (deny by default).
-- ---------------------------------------------------------------------------

CREATE FUNCTION app_tenant_id() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  AS $$ SELECT NULLIF(current_setting('aegis.tenant_id', true), '')::uuid $$;

CREATE FUNCTION app_principal_id() RETURNS uuid
  LANGUAGE sql STABLE PARALLEL SAFE
  AS $$ SELECT NULLIF(current_setting('aegis.principal_id', true), '')::uuid $$;

CREATE FUNCTION app_platform_scope() RETURNS boolean
  LANGUAGE sql STABLE PARALLEL SAFE
  AS $$ SELECT COALESCE(current_setting('aegis.platform_scope', true), '') = 'on' $$;

CREATE FUNCTION set_updated_at() RETURNS trigger
  LANGUAGE plpgsql
  AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END
$$;

-- ---------------------------------------------------------------------------
-- Identity
-- ---------------------------------------------------------------------------

CREATE TABLE principals (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  kind                text NOT NULL CHECK (kind IN ('HUMAN', 'SERVICE', 'AI_WORKER')),
  email               citext UNIQUE
                        CHECK (email IS NULL OR (length(email) <= 254 AND email ~ '^[^@[:space:]]+@[^@[:space:]]+$')),
  display_name        text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
  password_hash       text,
  platform_role       text CHECK (platform_role IN ('SYSTEM_OWNER')),
  status              text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'DISABLED')),
  password_changed_at timestamptz,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT principals_human_credentials
    CHECK (kind <> 'HUMAN' OR (email IS NOT NULL AND password_hash IS NOT NULL)),
  CONSTRAINT principals_nonhuman_no_password CHECK (kind = 'HUMAN' OR password_hash IS NULL),
  CONSTRAINT principals_platform_role_human CHECK (platform_role IS NULL OR kind = 'HUMAN'),
  CONSTRAINT principals_password_hash_format
    CHECK (password_hash IS NULL OR password_hash LIKE '$argon2id$%')
);
CREATE TRIGGER principals_updated_at BEFORE UPDATE ON principals
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE tenants (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug         citext NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
  status       text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED')),
  created_by   uuid REFERENCES principals (id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER tenants_updated_at BEFORE UPDATE ON tenants
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE memberships (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id    uuid NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  principal_id uuid NOT NULL REFERENCES principals (id) ON DELETE RESTRICT,
  role         text NOT NULL CHECK (role IN (
                 'TENANT_ADMIN', 'SECURITY_ADMIN', 'SECURITY_OPERATOR', 'INTEGRATION_ADMIN',
                 'AUDITOR', 'READ_ONLY_ANALYST', 'SERVICE', 'AI_WORKER', 'RECOVERY_AUTHORITY')),
  status       text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REMOVED')),
  created_by   uuid REFERENCES principals (id),
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, principal_id),
  UNIQUE (tenant_id, id)
);
CREATE INDEX memberships_principal_idx ON memberships (principal_id);
CREATE TRIGGER memberships_updated_at BEFORE UPDATE ON memberships
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Roles must match the kind of identity: an AI worker or service identity
-- can never hold a human administrative role, whatever the application does.
CREATE FUNCTION memberships_role_matches_kind() RETURNS trigger
  LANGUAGE plpgsql
  AS $$
DECLARE
  p_kind text;
BEGIN
  SELECT kind INTO p_kind FROM principals WHERE id = NEW.principal_id;
  IF p_kind IS NULL THEN
    RAISE EXCEPTION 'principal % does not exist', NEW.principal_id USING ERRCODE = '23503';
  END IF;
  IF (p_kind = 'AI_WORKER' AND NEW.role <> 'AI_WORKER')
     OR (p_kind = 'SERVICE' AND NEW.role <> 'SERVICE')
     OR (p_kind = 'HUMAN' AND NEW.role IN ('AI_WORKER', 'SERVICE')) THEN
    RAISE EXCEPTION 'role % is not permitted for principal kind %', NEW.role, p_kind
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER memberships_role_kind BEFORE INSERT OR UPDATE OF role, principal_id ON memberships
  FOR EACH ROW EXECUTE FUNCTION memberships_role_matches_kind();

CREATE TABLE sessions (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  -- SHA-256 of the 256-bit random session token. The token itself is never stored.
  token_hash         bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  principal_id       uuid NOT NULL REFERENCES principals (id),
  active_tenant_id   uuid REFERENCES tenants (id),
  created_at         timestamptz NOT NULL DEFAULT now(),
  last_seen_at       timestamptz NOT NULL DEFAULT now(),
  expires_at         timestamptz NOT NULL,
  reauthenticated_at timestamptz,
  revoked_at         timestamptz,
  revoke_reason      text CHECK (revoke_reason IN (
                       'LOGOUT', 'LOGOUT_ALL', 'PASSWORD_CHANGED', 'ADMIN', 'SUPERSEDED',
                       'PRINCIPAL_DISABLED', 'USER_REVOKED')),
  user_agent         text CHECK (length(user_agent) <= 256),
  CHECK (expires_at > created_at),
  CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);
CREATE INDEX sessions_principal_active_idx ON sessions (principal_id) WHERE revoked_at IS NULL;
CREATE INDEX sessions_expires_idx ON sessions (expires_at);

-- Failed-login throttling keyed by SHA-256 of a normalized identifier
-- (account email or client address). Shared across application processes.
CREATE TABLE auth_throttle (
  key_hash          bytea PRIMARY KEY CHECK (octet_length(key_hash) = 32),
  failure_count     integer NOT NULL DEFAULT 0 CHECK (failure_count >= 0),
  window_started_at timestamptz NOT NULL DEFAULT now(),
  locked_until      timestamptz
);

-- ---------------------------------------------------------------------------
-- Assets
-- ---------------------------------------------------------------------------

CREATE TABLE assets (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           uuid NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  name                text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  asset_type          text NOT NULL CHECK (asset_type IN (
                        'APPLICATION', 'API', 'REPOSITORY', 'CLOUD_ACCOUNT', 'HOST',
                        'CONTAINER_WORKLOAD', 'DATABASE', 'DOMAIN', 'NETWORK', 'OTHER')),
  environment         text NOT NULL CHECK (environment IN ('PRODUCTION', 'STAGING', 'DEVELOPMENT', 'TEST')),
  criticality         text NOT NULL CHECK (criticality IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  status              text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'INACTIVE', 'DECOMMISSIONED')),
  coverage_state      text NOT NULL DEFAULT 'UNKNOWN' CHECK (coverage_state IN (
                        'VERIFIED_WITHIN_DEFINED_SCOPE', 'PARTIALLY_COVERED', 'DEGRADED',
                        'DISCONNECTED', 'STALE', 'VERIFICATION_REQUIRED', 'UNKNOWN')),
  description         text CHECK (length(description) <= 2000),
  authorization_scope jsonb NOT NULL
                        CHECK (jsonb_typeof(authorization_scope) = 'object'
                               AND authorization_scope ? 'statement'
                               AND authorization_scope ? 'identifiers'
                               AND pg_column_size(authorization_scope) <= 16384),
  version             integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_by          uuid REFERENCES principals (id),
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, id)
);
CREATE INDEX assets_tenant_created_idx ON assets (tenant_id, created_at DESC, id DESC);
CREATE TRIGGER assets_updated_at BEFORE UPDATE ON assets
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Integrations
-- ---------------------------------------------------------------------------

CREATE TABLE integrations (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             uuid NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  name                  text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  provider              text NOT NULL CHECK (provider ~ '^[a-z0-9_.-]{1,64}$'),
  status                text NOT NULL DEFAULT 'CONFIGURED' CHECK (status IN (
                          'UNCONFIGURED', 'CONFIGURED', 'CONNECTING', 'CONNECTED', 'DEGRADED',
                          'DISCONNECTED', 'SUSPENDED', 'REVOKED', 'UNKNOWN')),
  -- Non-secret configuration only. Secrets are referenced via credential_ref.
  config                jsonb NOT NULL DEFAULT '{}'
                          CHECK (jsonb_typeof(config) = 'object' AND pg_column_size(config) <= 16384),
  config_version        integer NOT NULL DEFAULT 1 CHECK (config_version > 0),
  credential_ref        text CHECK (credential_ref ~ '^env:AEGIS_SECRET_[A-Z0-9_]{1,64}$'),
  declared_capabilities text[] NOT NULL DEFAULT '{}',
  granted_permissions   text[] NOT NULL DEFAULT '{}',
  asset_id              uuid,
  last_health_status    text CHECK (last_health_status IN ('CONNECTED', 'DEGRADED', 'DISCONNECTED', 'UNKNOWN')),
  last_health_at        timestamptz,
  last_error_code       text CHECK (last_error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  revoked_at            timestamptz,
  version               integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_by            uuid REFERENCES principals (id),
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, id),
  -- Composite key: an integration can only reference an asset in its own tenant.
  FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE SET NULL (asset_id),
  CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL)),
  CHECK (status <> 'REVOKED' OR credential_ref IS NULL)
);
CREATE INDEX integrations_tenant_created_idx ON integrations (tenant_id, created_at DESC, id DESC);
CREATE INDEX integrations_asset_idx ON integrations (tenant_id, asset_id) WHERE asset_id IS NOT NULL;
CREATE TRIGGER integrations_updated_at BEFORE UPDATE ON integrations
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE integration_health_checks (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL,
  integration_id uuid NOT NULL,
  result         text NOT NULL CHECK (result IN ('CONNECTED', 'DEGRADED', 'DISCONNECTED', 'UNKNOWN')),
  observed_at    timestamptz NOT NULL DEFAULT now(),
  latency_ms     integer CHECK (latency_ms >= 0),
  error_code     text CHECK (error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  config_version integer NOT NULL,
  job_id         uuid,
  FOREIGN KEY (tenant_id, integration_id) REFERENCES integrations (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX integration_health_checks_recent_idx
  ON integration_health_checks (tenant_id, integration_id, observed_at DESC);

-- ---------------------------------------------------------------------------
-- Background jobs
-- ---------------------------------------------------------------------------

CREATE TABLE jobs (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id          uuid NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  -- The principal on whose behalf the job runs. Authorization is re-checked at execution.
  actor_principal_id uuid NOT NULL REFERENCES principals (id),
  kind               text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$'),
  payload            jsonb NOT NULL DEFAULT '{}'
                       CHECK (jsonb_typeof(payload) = 'object' AND pg_column_size(payload) <= 16384),
  idempotency_key    text CHECK (idempotency_key ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  status             text NOT NULL DEFAULT 'QUEUED'
                       CHECK (status IN ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
  attempts           integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  max_attempts       integer NOT NULL CHECK (max_attempts BETWEEN 1 AND 10),
  timeout_ms         integer NOT NULL CHECK (timeout_ms BETWEEN 100 AND 300000),
  run_after          timestamptz NOT NULL DEFAULT now(),
  locked_by          text,
  locked_until       timestamptz,
  last_error_code    text CHECK (last_error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  result             jsonb CHECK (result IS NULL OR pg_column_size(result) <= 16384),
  correlation_id     text CHECK (correlation_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),
  finished_at        timestamptz,
  CHECK (attempts <= max_attempts),
  CHECK ((status IN ('SUCCEEDED', 'FAILED', 'CANCELLED')) = (finished_at IS NOT NULL)),
  UNIQUE (tenant_id, kind, idempotency_key)
);
CREATE INDEX jobs_claimable_idx ON jobs (run_after) WHERE status = 'QUEUED';
CREATE INDEX jobs_lease_idx ON jobs (locked_until) WHERE status = 'RUNNING';
CREATE TRIGGER jobs_updated_at BEFORE UPDATE ON jobs
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE worker_heartbeats (
  worker_id    text PRIMARY KEY CHECK (worker_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  started_at   timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  version      text CHECK (length(version) <= 64)
);

-- Cross-tenant job claiming is the one place the runtime needs to see jobs
-- from every tenant. It is confined to this definer function, which only
-- leases a job; the worker then sets that job's tenant context before doing
-- any work.
CREATE FUNCTION claim_job(p_worker text, p_kinds text[]) RETURNS SETOF jobs
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
BEGIN
  RETURN QUERY
  WITH candidate AS (
    SELECT j.id FROM jobs j
     WHERE j.kind = ANY (p_kinds)
       AND j.attempts < j.max_attempts
       AND ((j.status = 'QUEUED' AND j.run_after <= now())
            OR (j.status = 'RUNNING' AND j.locked_until < now()))
     ORDER BY j.run_after
     FOR UPDATE SKIP LOCKED
     LIMIT 1
  )
  UPDATE jobs j
     SET status = 'RUNNING',
         attempts = j.attempts + 1,
         locked_by = p_worker,
         locked_until = now() + make_interval(secs => (j.timeout_ms / 1000.0) + 30)
    FROM candidate
   WHERE j.id = candidate.id
  RETURNING j.*;
END
$$;

-- Jobs whose lease expired after their final attempt are failed rather than
-- left RUNNING forever.
CREATE FUNCTION reap_expired_jobs() RETURNS integer
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
DECLARE
  n integer;
BEGIN
  UPDATE jobs
     SET status = 'FAILED', last_error_code = 'LEASE_EXPIRED', finished_at = now(),
         locked_by = NULL, locked_until = NULL
   WHERE status = 'RUNNING' AND locked_until < now() AND attempts >= max_attempts;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n;
END
$$;

-- ---------------------------------------------------------------------------
-- Audit events: append-only and hash-chained.
-- ---------------------------------------------------------------------------

CREATE TABLE audit_events (
  chain_position     bigint PRIMARY KEY,
  id                 uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
  occurred_at        timestamptz NOT NULL,
  tenant_id          uuid REFERENCES tenants (id) ON DELETE RESTRICT,
  actor_principal_id uuid,
  actor_type         text NOT NULL CHECK (actor_type IN ('HUMAN', 'SERVICE', 'AI_WORKER', 'SYSTEM', 'ANONYMOUS')),
  action             text NOT NULL CHECK (action ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$' AND length(action) <= 100),
  target_type        text CHECK (target_type ~ '^[a-z][a-z0-9_]{0,63}$'),
  target_id          text CHECK (target_id ~ '^[A-Za-z0-9_.:@-]{1,128}$'),
  outcome            text NOT NULL CHECK (outcome IN ('SUCCESS', 'DENIED', 'FAILURE')),
  reason_code        text CHECK (reason_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
  request_id         text CHECK (request_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  correlation_id     text CHECK (correlation_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  metadata           jsonb NOT NULL DEFAULT '{}'
                       CHECK (jsonb_typeof(metadata) = 'object' AND pg_column_size(metadata) <= 8192),
  prev_hash          bytea CHECK (prev_hash IS NULL OR octet_length(prev_hash) = 32),
  hash               bytea NOT NULL CHECK (octet_length(hash) = 32)
);
CREATE INDEX audit_events_tenant_idx ON audit_events (tenant_id, chain_position DESC);

-- Canonical digest of an event. jsonb text output is deterministic (sorted
-- keys, escaped control characters), which makes it a safe serialization.
CREATE FUNCTION audit_event_digest(e audit_events) RETURNS bytea
  LANGUAGE sql STABLE SET search_path = public, pg_temp
  AS $$
  SELECT digest(convert_to(jsonb_build_object(
      'prev', COALESCE(encode(e.prev_hash, 'hex'), 'GENESIS'),
      'pos', e.chain_position,
      'id', e.id,
      'at', to_char(e.occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      'tenant', e.tenant_id,
      'actor', e.actor_principal_id,
      'actorType', e.actor_type,
      'action', e.action,
      'targetType', e.target_type,
      'targetId', e.target_id,
      'outcome', e.outcome,
      'reason', e.reason_code,
      'requestId', e.request_id,
      'correlationId', e.correlation_id,
      'metadata', e.metadata
    )::text, 'UTF8'), 'sha256')
$$;

CREATE FUNCTION audit_events_chain() RETURNS trigger
  LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
DECLARE
  last_pos  bigint;
  last_hash bytea;
BEGIN
  -- The chain is computed from the latest committed event, which is only
  -- sound when each statement sees fresh committed data.
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'audit events must be written under READ COMMITTED isolation';
  END IF;
  PERFORM pg_advisory_xact_lock(7412001);
  SELECT chain_position, hash INTO last_pos, last_hash
    FROM audit_events ORDER BY chain_position DESC LIMIT 1;
  NEW.occurred_at := clock_timestamp();
  IF last_pos IS NULL THEN
    NEW.chain_position := 1;
    NEW.prev_hash := NULL;
  ELSE
    NEW.chain_position := last_pos + 1;
    NEW.prev_hash := last_hash;
  END IF;
  NEW.hash := audit_event_digest(NEW);
  RETURN NEW;
END
$$;
CREATE TRIGGER audit_events_chain BEFORE INSERT ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_chain();

CREATE FUNCTION audit_events_append_only() RETURNS trigger
  LANGUAGE plpgsql
  AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only' USING ERRCODE = '42501';
END
$$;
CREATE TRIGGER audit_events_no_mutation BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_append_only();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION audit_events_append_only();

-- Recomputes the whole chain. Detects modified, reordered, or removed
-- interior events. It cannot detect removal of the newest events on its
-- own: compare head_hash against an externally recorded value for that.
CREATE FUNCTION audit_verify_chain()
  RETURNS TABLE (verified boolean, events_checked bigint, first_invalid_position bigint,
                 reason text, head_position bigint, head_hash text)
  LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
DECLARE
  r             audit_events;
  expected_prev bytea := NULL;
  expected_pos  bigint := 1;
  n             bigint := 0;
BEGIN
  FOR r IN SELECT * FROM audit_events ORDER BY chain_position LOOP
    n := n + 1;
    IF r.chain_position <> expected_pos THEN
      RETURN QUERY SELECT false, n, r.chain_position, 'GAP_OR_REORDER'::text, NULL::bigint, NULL::text;
      RETURN;
    END IF;
    IF r.prev_hash IS DISTINCT FROM expected_prev THEN
      RETURN QUERY SELECT false, n, r.chain_position, 'PREV_HASH_MISMATCH'::text, NULL::bigint, NULL::text;
      RETURN;
    END IF;
    IF r.hash <> audit_event_digest(r) THEN
      RETURN QUERY SELECT false, n, r.chain_position, 'HASH_MISMATCH'::text, NULL::bigint, NULL::text;
      RETURN;
    END IF;
    expected_prev := r.hash;
    expected_pos := expected_pos + 1;
  END LOOP;
  RETURN QUERY SELECT true, n, NULL::bigint, NULL::text,
    CASE WHEN n = 0 THEN NULL ELSE expected_pos - 1 END,
    encode(expected_prev, 'hex');
END
$$;

-- ---------------------------------------------------------------------------
-- Row-level security. aegis_app is not the owner of these tables, so the
-- policies apply to every query it issues.
-- ---------------------------------------------------------------------------

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenants_select ON tenants FOR SELECT TO aegis_app USING (
  id = app_tenant_id()
  OR app_platform_scope()
  OR EXISTS (SELECT 1 FROM memberships m
              WHERE m.tenant_id = tenants.id AND m.principal_id = app_principal_id()));
CREATE POLICY tenants_insert ON tenants FOR INSERT TO aegis_app WITH CHECK (app_platform_scope());
CREATE POLICY tenants_update ON tenants FOR UPDATE TO aegis_app
  USING (app_platform_scope()) WITH CHECK (app_platform_scope());

ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
CREATE POLICY memberships_select ON memberships FOR SELECT TO aegis_app USING (
  tenant_id = app_tenant_id() OR principal_id = app_principal_id());
CREATE POLICY memberships_insert ON memberships FOR INSERT TO aegis_app
  WITH CHECK (tenant_id = app_tenant_id() OR app_platform_scope());
CREATE POLICY memberships_update ON memberships FOR UPDATE TO aegis_app
  USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
CREATE POLICY assets_tenant_isolation ON assets TO aegis_app
  USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

ALTER TABLE integrations ENABLE ROW LEVEL SECURITY;
CREATE POLICY integrations_tenant_isolation ON integrations TO aegis_app
  USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

ALTER TABLE integration_health_checks ENABLE ROW LEVEL SECURITY;
CREATE POLICY integration_health_checks_tenant_isolation ON integration_health_checks TO aegis_app
  USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;
CREATE POLICY jobs_tenant_isolation ON jobs TO aegis_app
  USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id());

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_events_insert ON audit_events FOR INSERT TO aegis_app
  WITH CHECK (tenant_id IS NULL OR tenant_id = app_tenant_id());
-- Platform scope sees platform-level events only; tenant events require tenant context.
CREATE POLICY audit_events_select ON audit_events FOR SELECT TO aegis_app USING (
  tenant_id = app_tenant_id() OR (tenant_id IS NULL AND app_platform_scope()));

-- ---------------------------------------------------------------------------
-- Privileges for the runtime role. Nothing is granted by default.
-- ---------------------------------------------------------------------------

GRANT SELECT, INSERT, UPDATE ON principals TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON tenants TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON memberships TO aegis_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON sessions TO aegis_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON auth_throttle TO aegis_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON assets TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON integrations TO aegis_app;
GRANT SELECT, INSERT ON integration_health_checks TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON jobs TO aegis_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON worker_heartbeats TO aegis_app;
GRANT SELECT, INSERT ON audit_events TO aegis_app;
GRANT SELECT ON schema_migrations TO aegis_app;

REVOKE ALL ON FUNCTION claim_job(text, text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION reap_expired_jobs() FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_verify_chain() FROM PUBLIC;
REVOKE ALL ON FUNCTION audit_events_chain() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION claim_job(text, text[]) TO aegis_app;
GRANT EXECUTE ON FUNCTION reap_expired_jobs() TO aegis_app;
GRANT EXECUTE ON FUNCTION audit_verify_chain() TO aegis_app;
