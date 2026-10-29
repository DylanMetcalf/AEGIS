-- AEGIS Phase 2: telemetry intake, detection findings, evidence, investigations,
-- asset relationships, and computed coverage.
--
-- Every tenant table follows the Phase 1 pattern: tenant_id, UNIQUE (tenant_id, id),
-- composite foreign keys, RLS for aegis_app, and explicit grants.

-- Coverage is now computed from live signals (see src/coverage/coverage.ts);
-- a stored column would be a second, stale source of truth.
ALTER TABLE assets DROP COLUMN coverage_state;

-- Ingest integrations act through a dedicated SERVICE principal; events update last_event_at.
ALTER TABLE integrations
  ADD COLUMN service_principal_id uuid REFERENCES principals (id),
  ADD COLUMN last_event_at timestamptz;

-- ---------------------------------------------------------------------------
-- Ingest tokens: bearer credentials for machine telemetry push.
-- Only SHA-256(token) is stored; the token is shown once at creation.
-- ---------------------------------------------------------------------------
CREATE TABLE ingest_tokens (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id      uuid NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  integration_id uuid NOT NULL,
  principal_id   uuid NOT NULL REFERENCES principals (id),
  token_hash     bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
  token_prefix   text NOT NULL CHECK (token_prefix ~ '^aegis_ing_[A-Za-z0-9_-]{4}$'),
  created_by     uuid REFERENCES principals (id),
  created_at     timestamptz NOT NULL DEFAULT now(),
  last_used_at   timestamptz,
  revoked_at     timestamptz,
  UNIQUE (tenant_id, id),
  FOREIGN KEY (tenant_id, integration_id) REFERENCES integrations (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX ingest_tokens_integration_idx ON ingest_tokens (tenant_id, integration_id);

-- Token lookup happens before any tenant context exists. This definer function
-- returns only identifiers for an active token; it never exposes other rows.
CREATE FUNCTION resolve_ingest_token(p_hash bytea)
  RETURNS TABLE (token_id uuid, tenant_id uuid, integration_id uuid, principal_id uuid)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp
  AS $$
  SELECT t.id, t.tenant_id, t.integration_id, t.principal_id
    FROM ingest_tokens t
   WHERE t.token_hash = p_hash AND t.revoked_at IS NULL
$$;

-- ---------------------------------------------------------------------------
-- Telemetry events: immutable once written (INSERT/SELECT only for the app).
-- ---------------------------------------------------------------------------
CREATE TABLE telemetry_events (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id       uuid NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  integration_id  uuid NOT NULL,
  asset_id        uuid,
  batch_id        uuid NOT NULL,
  event_type      text NOT NULL CHECK (event_type IN (
                    'auth.success', 'auth.failure', 'http.request', 'iam.role_granted',
                    'iam.role_revoked', 'config.changed', 'security.alert')),
  severity        text NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  observed_at     timestamptz NOT NULL,
  received_at     timestamptz NOT NULL DEFAULT now(),
  actor_user_id   text CHECK (actor_user_id ~ '^[A-Za-z0-9_.:@-]{1,128}$'),
  actor_ip        inet,
  attributes      jsonb NOT NULL DEFAULT '{}'
                    CHECK (jsonb_typeof(attributes) = 'object' AND pg_column_size(attributes) <= 8192),
  source_event_id text CHECK (source_event_id ~ '^[A-Za-z0-9_.:-]{1,128}$'),
  dedupe_key      text NOT NULL CHECK (length(dedupe_key) BETWEEN 1 AND 128),
  content_sha256  bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, integration_id, dedupe_key),
  FOREIGN KEY (tenant_id, integration_id) REFERENCES integrations (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE SET NULL (asset_id)
);
-- Canonical content digest computed by the database from the stored values, so
-- evidence verification recomputes exactly the same function (no client/DB
-- normalisation mismatch). Assigned by trigger; client-supplied values are ignored.
CREATE FUNCTION telemetry_event_digest(e telemetry_events) RETURNS bytea
  LANGUAGE sql STABLE SET search_path = public, pg_temp
  AS $$
  SELECT digest(convert_to(jsonb_build_object(
      'tenant', e.tenant_id,
      'integration', e.integration_id,
      'type', e.event_type,
      'severity', e.severity,
      'observedAt', to_char(e.observed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      'actorUserId', e.actor_user_id,
      'actorIp', host(e.actor_ip),
      'attributes', e.attributes,
      'sourceEventId', e.source_event_id
    )::text, 'UTF8'), 'sha256')
$$;

CREATE FUNCTION telemetry_events_digest_trigger() RETURNS trigger
  LANGUAGE plpgsql SET search_path = public, pg_temp
  AS $$
BEGIN
  NEW.content_sha256 := telemetry_event_digest(NEW);
  RETURN NEW;
END
$$;
CREATE TRIGGER telemetry_events_digest BEFORE INSERT ON telemetry_events
  FOR EACH ROW EXECUTE FUNCTION telemetry_events_digest_trigger();

CREATE INDEX telemetry_events_recent_idx ON telemetry_events (tenant_id, observed_at DESC);
CREATE INDEX telemetry_events_batch_idx ON telemetry_events (tenant_id, batch_id);
CREATE INDEX telemetry_events_actor_ip_idx
  ON telemetry_events (tenant_id, actor_ip, event_type, observed_at) WHERE actor_ip IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Findings: produced by deterministic detection rules; deduplicated while active.
-- ---------------------------------------------------------------------------
CREATE TABLE findings (
  id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id             uuid NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  rule_id               text NOT NULL CHECK (rule_id ~ '^[a-z][a-z0-9_.]{2,63}$'),
  rule_version          integer NOT NULL CHECK (rule_version > 0),
  title                 text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
  severity              text NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
  status                text NOT NULL DEFAULT 'OPEN' CHECK (status IN (
                          'OPEN', 'TRIAGED', 'IN_PROGRESS', 'RESOLVED', 'FALSE_POSITIVE', 'ACCEPTED_RISK')),
  group_key             text NOT NULL CHECK (length(group_key) BETWEEN 1 AND 200),
  asset_id              uuid,
  integration_id        uuid,
  occurrence_count      integer NOT NULL DEFAULT 0 CHECK (occurrence_count >= 0),
  first_seen_at         timestamptz NOT NULL,
  last_seen_at          timestamptz NOT NULL,
  summary               jsonb NOT NULL DEFAULT '{}'
                          CHECK (jsonb_typeof(summary) = 'object' AND pg_column_size(summary) <= 8192),
  resolution_note       text CHECK (length(resolution_note) <= 2000),
  assignee_principal_id uuid REFERENCES principals (id),
  version               integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at            timestamptz NOT NULL DEFAULT now(),
  updated_at            timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  CHECK (last_seen_at >= first_seen_at),
  CHECK (status NOT IN ('RESOLVED', 'FALSE_POSITIVE', 'ACCEPTED_RISK') OR resolution_note IS NOT NULL),
  FOREIGN KEY (tenant_id, asset_id) REFERENCES assets (tenant_id, id) ON DELETE SET NULL (asset_id),
  FOREIGN KEY (tenant_id, integration_id) REFERENCES integrations (tenant_id, id) ON DELETE SET NULL (integration_id)
);
-- One active finding per rule and group; a recurrence after closure opens a new finding.
CREATE UNIQUE INDEX findings_active_dedupe_idx ON findings (tenant_id, rule_id, group_key)
  WHERE status IN ('OPEN', 'TRIAGED', 'IN_PROGRESS');
CREATE INDEX findings_tenant_recent_idx ON findings (tenant_id, last_seen_at DESC, id DESC);
CREATE INDEX findings_asset_idx ON findings (tenant_id, asset_id) WHERE asset_id IS NOT NULL;
CREATE TRIGGER findings_updated_at BEFORE UPDATE ON findings
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------------
-- Investigations group findings; analyst notes are OPERATOR_NOTE evidence.
-- ---------------------------------------------------------------------------
CREATE TABLE investigations (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id  uuid NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  title      text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
  status     text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'CLOSED')),
  summary    text CHECK (length(summary) <= 4000),
  created_by uuid REFERENCES principals (id),
  closed_at  timestamptz,
  version    integer NOT NULL DEFAULT 1 CHECK (version > 0),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  CHECK ((status = 'CLOSED') = (closed_at IS NOT NULL))
);
CREATE INDEX investigations_tenant_recent_idx ON investigations (tenant_id, created_at DESC, id DESC);
CREATE TRIGGER investigations_updated_at BEFORE UPDATE ON investigations
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

CREATE TABLE investigation_findings (
  tenant_id        uuid NOT NULL,
  investigation_id uuid NOT NULL,
  finding_id       uuid NOT NULL,
  added_by         uuid REFERENCES principals (id),
  added_at         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, investigation_id, finding_id),
  FOREIGN KEY (tenant_id, investigation_id) REFERENCES investigations (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, finding_id) REFERENCES findings (tenant_id, id) ON DELETE CASCADE
);

-- ---------------------------------------------------------------------------
-- Evidence with provenance. Immutable except for recording verification results.
-- ---------------------------------------------------------------------------
CREATE TABLE evidence (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id           uuid NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  kind                text NOT NULL CHECK (kind IN (
                        'OBSERVATION', 'TEST_RESULT', 'AUDIT_RECORD', 'OPERATOR_NOTE',
                        'RECOMMENDATION', 'MODEL_ASSERTION')),
  finding_id          uuid,
  investigation_id    uuid,
  telemetry_event_id  uuid,
  collector_type      text NOT NULL CHECK (collector_type IN ('INTEGRATION', 'PLATFORM', 'HUMAN', 'AI_MODEL')),
  collector_id        text NOT NULL CHECK (length(collector_id) BETWEEN 1 AND 128),
  collector_version   text NOT NULL CHECK (length(collector_version) BETWEEN 1 AND 64),
  collected_at        timestamptz NOT NULL,
  source_ref          text NOT NULL CHECK (length(source_ref) BETWEEN 1 AND 512),
  content_sha256      bytea NOT NULL CHECK (octet_length(content_sha256) = 32),
  body                jsonb CHECK (body IS NULL OR (jsonb_typeof(body) = 'object' AND pg_column_size(body) <= 8192)),
  verification_status text NOT NULL DEFAULT 'NOT_RUN' CHECK (verification_status IN (
                        'VERIFIED', 'FAILED', 'PARTIALLY_VERIFIED', 'INCONCLUSIVE', 'NOT_RUN',
                        'BLOCKED', 'STALE', 'NOT_APPLICABLE')),
  verified_at         timestamptz,
  created_by          uuid REFERENCES principals (id),
  created_at          timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  CHECK (finding_id IS NOT NULL OR investigation_id IS NOT NULL),
  -- Human notes and model output can never be marked verified proof.
  CHECK (kind NOT IN ('OPERATOR_NOTE', 'RECOMMENDATION', 'MODEL_ASSERTION')
         OR verification_status = 'NOT_APPLICABLE'),
  CHECK (kind <> 'OBSERVATION' OR telemetry_event_id IS NOT NULL),
  FOREIGN KEY (tenant_id, finding_id) REFERENCES findings (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, investigation_id) REFERENCES investigations (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, telemetry_event_id) REFERENCES telemetry_events (tenant_id, id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX evidence_finding_event_idx ON evidence (tenant_id, finding_id, telemetry_event_id)
  WHERE finding_id IS NOT NULL AND telemetry_event_id IS NOT NULL;
CREATE INDEX evidence_investigation_idx ON evidence (tenant_id, investigation_id) WHERE investigation_id IS NOT NULL;
CREATE INDEX evidence_tenant_recent_idx ON evidence (tenant_id, created_at DESC, id DESC);

-- Only verification columns may change after insert.
CREATE FUNCTION evidence_immutable() RETURNS trigger
  LANGUAGE plpgsql
  AS $$
BEGIN
  IF (NEW.kind, NEW.finding_id, NEW.investigation_id, NEW.telemetry_event_id, NEW.collector_type,
      NEW.collector_id, NEW.collector_version, NEW.collected_at, NEW.source_ref, NEW.content_sha256,
      NEW.body, NEW.created_by, NEW.created_at, NEW.tenant_id)
     IS DISTINCT FROM
     (OLD.kind, OLD.finding_id, OLD.investigation_id, OLD.telemetry_event_id, OLD.collector_type,
      OLD.collector_id, OLD.collector_version, OLD.collected_at, OLD.source_ref, OLD.content_sha256,
      OLD.body, OLD.created_by, OLD.created_at, OLD.tenant_id) THEN
    RAISE EXCEPTION 'evidence content is immutable' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER evidence_immutable BEFORE UPDATE ON evidence
  FOR EACH ROW EXECUTE FUNCTION evidence_immutable();

-- ---------------------------------------------------------------------------
-- Asset relationships (relational knowledge graph).
-- ---------------------------------------------------------------------------
CREATE TABLE asset_relationships (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     uuid NOT NULL REFERENCES tenants (id) ON DELETE RESTRICT,
  from_asset_id uuid NOT NULL,
  to_asset_id   uuid NOT NULL,
  kind          text NOT NULL CHECK (kind IN (
                  'DEPENDS_ON', 'CONNECTS_TO', 'CONTAINS', 'AUTHENTICATES_WITH', 'STORES_DATA_IN')),
  created_by    uuid REFERENCES principals (id),
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, from_asset_id, to_asset_id, kind),
  CHECK (from_asset_id <> to_asset_id),
  FOREIGN KEY (tenant_id, from_asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE,
  FOREIGN KEY (tenant_id, to_asset_id) REFERENCES assets (tenant_id, id) ON DELETE CASCADE
);
CREATE INDEX asset_relationships_to_idx ON asset_relationships (tenant_id, to_asset_id);

-- ---------------------------------------------------------------------------
-- RLS and grants.
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['ingest_tokens', 'telemetry_events', 'findings', 'investigations',
                           'investigation_findings', 'evidence', 'asset_relationships'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY %I ON %I TO aegis_app USING (tenant_id = app_tenant_id()) WITH CHECK (tenant_id = app_tenant_id())',
      t || '_tenant_isolation', t);
  END LOOP;
END
$$;

GRANT SELECT, INSERT, UPDATE ON ingest_tokens TO aegis_app;
GRANT SELECT, INSERT ON telemetry_events TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON findings TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON investigations TO aegis_app;
GRANT SELECT, INSERT, DELETE ON investigation_findings TO aegis_app;
GRANT SELECT, INSERT, UPDATE ON evidence TO aegis_app;
GRANT SELECT, INSERT, DELETE ON asset_relationships TO aegis_app;

REVOKE ALL ON FUNCTION resolve_ingest_token(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION resolve_ingest_token(bytea) TO aegis_app;
