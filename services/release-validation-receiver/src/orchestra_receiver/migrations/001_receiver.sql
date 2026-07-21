CREATE SCHEMA IF NOT EXISTS orchestra_lab_receiver;

CREATE TABLE IF NOT EXISTS orchestra_lab_receiver.schema_migrations (
  version integer PRIMARY KEY,
  script_digest text NOT NULL CHECK (script_digest ~ '^sha256:[0-9a-f]{64}$'),
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS orchestra_lab_receiver.inbox_events (
  event_id text PRIMARY KEY,
  organization_id text NOT NULL,
  validation_id text NOT NULL,
  state_version bigint NOT NULL CHECK (state_version > 0),
  body_digest text NOT NULL CHECK (body_digest ~ '^sha256:[0-9a-f]{64}$'),
  disposition text NOT NULL CHECK (disposition IN ('APPLIED', 'STALE')),
  recommendation text NOT NULL CHECK (recommendation IN ('continue', 'hold', 'rollback')),
  release_id text NOT NULL,
  deployment_id text NOT NULL,
  environment text NOT NULL,
  artifact_digest text NOT NULL CHECK (artifact_digest ~ '^sha256:[0-9a-f]{64}$'),
  evidence_digest text CHECK (evidence_digest IS NULL OR evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
  received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (organization_id, validation_id, state_version)
);

CREATE TABLE IF NOT EXISTS orchestra_lab_receiver.validation_heads (
  organization_id text NOT NULL,
  validation_id text NOT NULL,
  state_version bigint NOT NULL CHECK (state_version > 0),
  event_id text NOT NULL REFERENCES orchestra_lab_receiver.inbox_events(event_id),
  body_digest text NOT NULL CHECK (body_digest ~ '^sha256:[0-9a-f]{64}$'),
  recommendation text NOT NULL CHECK (recommendation IN ('continue', 'hold', 'rollback')),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (organization_id, validation_id)
);

CREATE TABLE IF NOT EXISTS orchestra_lab_receiver.action_outbox (
  event_id text PRIMARY KEY REFERENCES orchestra_lab_receiver.inbox_events(event_id),
  status text NOT NULL CHECK (
    status IN ('PENDING', 'CLAIMED', 'RETRY', 'DELIVERED', 'INDETERMINATE', 'DEAD_LETTER')
  ),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  lease_owner text,
  lease_expires_at timestamptz,
  last_error_code text,
  last_http_status integer,
  github_request_id text,
  delivered_at timestamptz,
  indeterminate_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (
    (status = 'CLAIMED' AND lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)
    OR (status <> 'CLAIMED' AND lease_owner IS NULL AND lease_expires_at IS NULL)
  )
);

CREATE INDEX IF NOT EXISTS action_outbox_due_idx
  ON orchestra_lab_receiver.action_outbox (next_attempt_at, created_at)
  WHERE status IN ('PENDING', 'RETRY');

CREATE TABLE IF NOT EXISTS orchestra_lab_receiver.action_reconciliations (
  id bigserial PRIMARY KEY,
  event_id text NOT NULL REFERENCES orchestra_lab_receiver.action_outbox(event_id),
  previous_status text NOT NULL,
  resolved_status text NOT NULL CHECK (resolved_status IN ('RETRY', 'DELIVERED', 'DEAD_LETTER')),
  evidence_digest text NOT NULL CHECK (evidence_digest ~ '^sha256:[0-9a-f]{64}$'),
  actor_digest text NOT NULL CHECK (actor_digest ~ '^sha256:[0-9a-f]{64}$'),
  reconciled_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
