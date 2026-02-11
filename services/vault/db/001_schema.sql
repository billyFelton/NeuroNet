-- ============================================================
-- Neuro-Network Vault Database Schema
-- Two schemas: iam (identity/RBAC) and audit (SOC2 audit trail)
-- ============================================================

-- ────────────────────────────────────────────────────────────
-- SCHEMA: iam
-- ────────────────────────────────────────────────────────────

CREATE SCHEMA IF NOT EXISTS iam;

CREATE TABLE iam.users (
    id              UUID PRIMARY KEY,
    email           TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    upn             TEXT,
    job_title       TEXT,
    department      TEXT,
    account_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    mfa_enabled     BOOLEAN DEFAULT FALSE,
    last_sign_in    TIMESTAMPTZ,
    entra_synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON iam.users (email);
CREATE INDEX idx_users_enabled ON iam.users (account_enabled);

CREATE TABLE iam.groups (
    id              UUID PRIMARY KEY,
    display_name    TEXT NOT NULL,
    description     TEXT,
    mail            TEXT,
    group_type      TEXT DEFAULT 'security',
    entra_synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE iam.user_groups (
    user_id         UUID NOT NULL REFERENCES iam.users(id) ON DELETE CASCADE,
    group_id        UUID NOT NULL REFERENCES iam.groups(id) ON DELETE CASCADE,
    synced_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, group_id)
);

CREATE INDEX idx_user_groups_group ON iam.user_groups (group_id);

CREATE TABLE iam.roles (
    id              TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    description     TEXT,
    is_system_role  BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO iam.roles (id, display_name, description, is_system_role) VALUES
    ('security-admin', 'Security Administrator',
     'Full access to all security data, Wazuh, EntraID, audit logs, and remediation actions', TRUE),
    ('security-analyst', 'Security Analyst',
     'Read access to Wazuh alerts, security events, and user authentication patterns', TRUE),
    ('it-support', 'IT Support',
     'Basic account status checks, MFA enrollment, general IT support queries', TRUE),
    ('general-user', 'General User',
     'General Q&A, own account status, security best practices only', TRUE),
    ('ai-admin', 'AI Administrator',
     'Manage AI model configuration, prompt templates, and agent routing rules', TRUE)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE iam.user_roles (
    user_id         UUID NOT NULL REFERENCES iam.users(id) ON DELETE CASCADE,
    role_id         TEXT NOT NULL REFERENCES iam.roles(id) ON DELETE CASCADE,
    assigned_by     TEXT NOT NULL DEFAULT 'manual',
    assigned_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE iam.group_role_mappings (
    group_id        UUID NOT NULL REFERENCES iam.groups(id) ON DELETE CASCADE,
    role_id         TEXT NOT NULL REFERENCES iam.roles(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (group_id, role_id)
);

CREATE TABLE iam.resources (
    id              TEXT PRIMARY KEY,
    display_name    TEXT NOT NULL,
    description     TEXT,
    service         TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO iam.resources (id, display_name, description, service) VALUES
    ('wazuh-alerts', 'Wazuh Alerts', 'Security alerts from Wazuh SIEM', 'connector-wazuh'),
    ('wazuh-agents', 'Wazuh Agents', 'Wazuh agent inventory and status', 'connector-wazuh'),
    ('wazuh-vulnerability', 'Wazuh Vulnerabilities', 'Vulnerability scan results', 'connector-wazuh'),
    ('entra-users', 'EntraID Users', 'User directory from Microsoft EntraID', 'connector-entraid'),
    ('entra-signin-logs', 'EntraID Sign-in Logs', 'User authentication history', 'connector-entraid'),
    ('entra-groups', 'EntraID Groups', 'Group directory from Microsoft EntraID', 'connector-entraid'),
    ('entra-mfa-status', 'EntraID MFA Status', 'MFA enrollment and status', 'connector-entraid'),
    ('audit-logs', 'Audit Logs', 'Neuro-Network audit trail', 'vault-audit'),
    ('ai-config', 'AI Configuration', 'AI model and prompt template settings', 'agent-router')
ON CONFLICT (id) DO NOTHING;

CREATE TABLE iam.policies (
    id              SERIAL PRIMARY KEY,
    role_id         TEXT NOT NULL REFERENCES iam.roles(id) ON DELETE CASCADE,
    resource_id     TEXT NOT NULL REFERENCES iam.resources(id) ON DELETE CASCADE,
    action          TEXT NOT NULL,
    effect          TEXT NOT NULL DEFAULT 'permit',
    scopes          TEXT[] DEFAULT '{}',
    conditions      JSONB DEFAULT '{}',
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (role_id, resource_id, action)
);

INSERT INTO iam.policies (role_id, resource_id, action, effect, description) VALUES
    ('security-admin', 'wazuh-alerts', '*', 'permit', 'Full Wazuh alert access'),
    ('security-admin', 'wazuh-agents', '*', 'permit', 'Full Wazuh agent access'),
    ('security-admin', 'wazuh-vulnerability', '*', 'permit', 'Full vulnerability access'),
    ('security-admin', 'entra-users', '*', 'permit', 'Full EntraID user access'),
    ('security-admin', 'entra-signin-logs', '*', 'permit', 'Full sign-in log access'),
    ('security-admin', 'entra-groups', '*', 'permit', 'Full EntraID group access'),
    ('security-admin', 'entra-mfa-status', '*', 'permit', 'Full MFA status access'),
    ('security-admin', 'audit-logs', 'query', 'permit', 'Query audit logs'),
    ('security-admin', 'ai-config', '*', 'permit', 'Full AI config access'),
    ('security-analyst', 'wazuh-alerts', 'query', 'permit', 'Query Wazuh alerts'),
    ('security-analyst', 'wazuh-agents', 'query', 'permit', 'Query Wazuh agents'),
    ('security-analyst', 'wazuh-vulnerability', 'query', 'permit', 'Query vulnerabilities'),
    ('security-analyst', 'entra-users', 'query', 'permit', 'Query EntraID users'),
    ('security-analyst', 'entra-signin-logs', 'query', 'permit', 'Query sign-in logs'),
    ('security-analyst', 'entra-mfa-status', 'query', 'permit', 'Query MFA status'),
    ('it-support', 'entra-users', 'view', 'permit', 'View basic user status'),
    ('it-support', 'entra-mfa-status', 'view', 'permit', 'View MFA enrollment status'),
    ('general-user', 'entra-users', 'view', 'permit', 'View own account status')
ON CONFLICT (role_id, resource_id, action) DO NOTHING;

CREATE TABLE iam.identity_mappings (
    provider        TEXT NOT NULL,
    external_id     TEXT NOT NULL,
    user_id         UUID NOT NULL REFERENCES iam.users(id) ON DELETE CASCADE,
    verified        BOOLEAN DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (provider, external_id)
);

CREATE INDEX idx_identity_mappings_user ON iam.identity_mappings (user_id);

CREATE TABLE iam.service_accounts (
    service_name    TEXT PRIMARY KEY,
    token_hash      TEXT NOT NULL,
    allowed_actions TEXT[] DEFAULT '{}',
    last_auth       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ────────────────────────────────────────────────────────────
-- SCHEMA: audit
-- ────────────────────────────────────────────────────────────

CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE audit.events (
    event_id            UUID NOT NULL,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_service      TEXT NOT NULL,
    event_type          TEXT NOT NULL,
    actor_user_id       UUID,
    actor_email         TEXT,
    actor_roles         TEXT[],
    actor_source        TEXT,
    actor_is_service    BOOLEAN DEFAULT FALSE,
    action              TEXT NOT NULL,
    resource            TEXT NOT NULL,
    resource_id         TEXT,
    auth_decision       TEXT,
    auth_policy         TEXT,
    auth_denied_reason  TEXT,
    ai_model            TEXT,
    ai_provider         TEXT,
    ai_request_id       TEXT,
    ai_prompt_hash      TEXT,
    ai_response_hash    TEXT,
    ai_input_tokens     INTEGER,
    ai_output_tokens    INTEGER,
    ai_latency_ms       INTEGER,
    ai_cost_usd         NUMERIC(10, 6),
    outcome_status      TEXT NOT NULL DEFAULT 'success',
    outcome_details     JSONB DEFAULT '{}',
    correlation_id      UUID,
    causation_id        UUID,
    message_id          UUID,
    previous_event_hash TEXT,
    event_hash          TEXT NOT NULL,
    raw_event           JSONB NOT NULL,
    PRIMARY KEY (event_id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Create partitions (extend as needed)
CREATE TABLE audit.events_2026_02 PARTITION OF audit.events
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
CREATE TABLE audit.events_2026_03 PARTITION OF audit.events
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE audit.events_2026_04 PARTITION OF audit.events
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
CREATE TABLE audit.events_2026_05 PARTITION OF audit.events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE audit.events_2026_06 PARTITION OF audit.events
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

CREATE INDEX idx_events_source ON audit.events (source_service, timestamp);
CREATE INDEX idx_events_type ON audit.events (event_type, timestamp);
CREATE INDEX idx_events_actor ON audit.events (actor_user_id, timestamp);
CREATE INDEX idx_events_actor_email ON audit.events (actor_email, timestamp);
CREATE INDEX idx_events_resource ON audit.events (resource, timestamp);
CREATE INDEX idx_events_correlation ON audit.events (correlation_id);
CREATE INDEX idx_events_auth_decision ON audit.events (auth_decision, timestamp);
CREATE INDEX idx_events_ai_model ON audit.events (ai_model, timestamp) WHERE ai_model IS NOT NULL;
CREATE INDEX idx_events_outcome ON audit.events (outcome_status, timestamp);
CREATE INDEX idx_events_hash ON audit.events (event_hash);
CREATE INDEX idx_events_raw_gin ON audit.events USING GIN (raw_event);

-- SOC2 reporting views
CREATE VIEW audit.chain_integrity AS
SELECT
    e.event_id, e.timestamp, e.event_hash, e.previous_event_hash,
    LAG(e.event_hash) OVER (ORDER BY e.timestamp, e.event_id) AS expected_previous_hash,
    CASE
        WHEN e.previous_event_hash IS NULL AND
             LAG(e.event_hash) OVER (ORDER BY e.timestamp, e.event_id) IS NULL
        THEN 'ok_first_event'
        WHEN e.previous_event_hash =
             LAG(e.event_hash) OVER (ORDER BY e.timestamp, e.event_id)
        THEN 'ok'
        ELSE 'CHAIN_BROKEN'
    END AS chain_status
FROM audit.events e
ORDER BY e.timestamp, e.event_id;

CREATE VIEW audit.daily_summary AS
SELECT
    DATE(timestamp) AS event_date, event_type, source_service,
    outcome_status, auth_decision, COUNT(*) AS event_count,
    COUNT(DISTINCT actor_user_id) AS unique_users
FROM audit.events
GROUP BY DATE(timestamp), event_type, source_service, outcome_status, auth_decision
ORDER BY event_date DESC, event_count DESC;

CREATE VIEW audit.ai_usage_summary AS
SELECT
    DATE(timestamp) AS usage_date, ai_model, ai_provider,
    COUNT(*) AS request_count,
    SUM(ai_input_tokens) AS total_input_tokens,
    SUM(ai_output_tokens) AS total_output_tokens,
    AVG(ai_latency_ms) AS avg_latency_ms,
    SUM(ai_cost_usd) AS total_cost_usd,
    COUNT(DISTINCT actor_user_id) AS unique_users
FROM audit.events
WHERE event_type = 'ai_interaction'
GROUP BY DATE(timestamp), ai_model, ai_provider
ORDER BY usage_date DESC;

CREATE VIEW audit.denied_access_report AS
SELECT
    timestamp, actor_email, actor_roles, actor_source,
    action, resource, auth_policy, auth_denied_reason, correlation_id
FROM audit.events
WHERE auth_decision = 'deny'
ORDER BY timestamp DESC;


-- ────────────────────────────────────────────────────────────
-- DATABASE ROLES
-- ────────────────────────────────────────────────────────────

DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vault_iam') THEN
        CREATE ROLE vault_iam LOGIN;
    END IF;
END $$;

GRANT USAGE ON SCHEMA iam TO vault_iam;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA iam TO vault_iam;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA iam TO vault_iam;

DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vault_audit') THEN
        CREATE ROLE vault_audit LOGIN;
    END IF;
END $$;

GRANT USAGE ON SCHEMA audit TO vault_audit;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA audit TO vault_audit;
GRANT USAGE ON SCHEMA iam TO vault_audit;
GRANT SELECT ON ALL TABLES IN SCHEMA iam TO vault_audit;
