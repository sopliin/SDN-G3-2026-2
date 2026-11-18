-- 002_policy.sql — reglas, versiones, elevaciones, decisiones y metadatos.
-- El AST vive en JSONB y el texto DSL se conserva para el operador; el
-- motor evalúa el AST, nunca el texto. Idempotente: el registro de
-- versiones lo lleva schema_migrations (storage.apply_migrations).

CREATE TABLE IF NOT EXISTS policy_rules (
    rule_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    effect TEXT NOT NULL CHECK (effect IN ('permit', 'deny')),
    permission TEXT NOT NULL,
    action TEXT,
    priority INTEGER NOT NULL DEFAULT 100
        CHECK (priority BETWEEN 0 AND 999),
    scope TEXT NOT NULL DEFAULT 'dynamic'
        CHECK (scope IN ('base', 'dynamic', 'grant')),
    dsl_text TEXT,
    subject_expr JSONB,
    resource_expr JSONB,
    context_expr JSONB,
    state_expr JSONB,
    valid_from DATE NOT NULL DEFAULT CURRENT_DATE,
    valid_to DATE,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled', 'draft')),
    version INTEGER NOT NULL DEFAULT 1,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policy_rule_versions (
    rule_id TEXT NOT NULL REFERENCES policy_rules (rule_id),
    version INTEGER NOT NULL,
    snapshot JSONB NOT NULL,
    dsl_text TEXT,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason TEXT,
    PRIMARY KEY (rule_id, version)
);

CREATE TABLE IF NOT EXISTS policy_elevations (
    elevation_id TEXT PRIMARY KEY,
    person_id TEXT NOT NULL REFERENCES dir_people (person_id),
    identity_id TEXT NOT NULL,
    resource_id TEXT NOT NULL REFERENCES dir_resources (resource_id),
    requested_by TEXT NOT NULL,
    approved_by TEXT,
    status TEXT NOT NULL DEFAULT 'requested'
        CHECK (status IN ('requested', 'approved', 'rejected',
                          'revoked', 'expired')),
    ttl_s INTEGER NOT NULL CHECK (ttl_s > 0),
    reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    grant_id TEXT REFERENCES dir_resource_grants (grant_id),
    order_cookies JSONB NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS policy_decisions (
    decision_id BIGSERIAL PRIMARY KEY,
    ts TIMESTAMPTZ NOT NULL DEFAULT now(),
    subject_id TEXT NOT NULL,
    population TEXT NOT NULL DEFAULT 'university',
    action TEXT,
    permission TEXT,
    resource_id TEXT,
    context JSONB NOT NULL DEFAULT '{}'::jsonb,
    state JSONB NOT NULL DEFAULT '{}'::jsonb,
    validity JSONB NOT NULL DEFAULT '{}'::jsonb,
    matched_rule_id TEXT,
    matched_rule_version INTEGER,
    matched_grant_id TEXT,
    result TEXT NOT NULL,
    reasons JSONB NOT NULL DEFAULT '[]'::jsonb,
    trace JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS policy_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS policy_rules_active_idx
    ON policy_rules (status, priority DESC);
CREATE INDEX IF NOT EXISTS policy_rule_versions_rule_idx
    ON policy_rule_versions (rule_id);
CREATE INDEX IF NOT EXISTS policy_elevations_status_idx
    ON policy_elevations (status, created_at DESC);
CREATE INDEX IF NOT EXISTS policy_elevations_identity_idx
    ON policy_elevations (identity_id);
CREATE INDEX IF NOT EXISTS policy_decisions_ts_idx
    ON policy_decisions (ts DESC);
