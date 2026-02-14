-- Audit schema for Kevin's activity logging
-- Stores all actions, RBAC decisions, data access, and AI interactions

CREATE SCHEMA IF NOT EXISTS audit;

-- Main audit log table
CREATE TABLE IF NOT EXISTS audit.events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id VARCHAR(100) UNIQUE,              -- original event ID from the audit event
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    event_type VARCHAR(50) NOT NULL,           -- authentication, authorization, data_access, ai_interaction, system
    source_service VARCHAR(100) NOT NULL,       -- which service generated this event
    action VARCHAR(200) NOT NULL,               -- what happened (query_alerts, email_search, rbac_deny, etc.)
    resource VARCHAR(200),                      -- what was accessed (wazuh-alerts, email, scheduler, etc.)
    resource_id VARCHAR(200),                   -- specific resource ID if applicable
    outcome VARCHAR(20) DEFAULT 'success',      -- success, denied, error
    
    -- Actor info
    actor_user_id VARCHAR(200),
    actor_email VARCHAR(200),
    actor_display_name VARCHAR(200),
    actor_roles TEXT[],
    
    -- Details
    details JSONB DEFAULT '{}',
    
    -- AI interaction fields (populated for ai_interaction events)
    ai_model VARCHAR(100),
    ai_provider VARCHAR(50),
    ai_input_tokens INT,
    ai_output_tokens INT,
    ai_latency_ms INT,
    ai_cost_usd NUMERIC(10,6),
    ai_prompt_hash VARCHAR(128),
    ai_response_hash VARCHAR(128),
    
    -- Hash chain for tamper detection
    event_hash VARCHAR(128),
    previous_hash VARCHAR(128),
    
    -- Correlation
    correlation_id VARCHAR(100),
    
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit.events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit.events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_actor_email ON audit.events(actor_email);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit.events(action);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit.events(resource);
CREATE INDEX IF NOT EXISTS idx_audit_outcome ON audit.events(outcome);
CREATE INDEX IF NOT EXISTS idx_audit_source ON audit.events(source_service);
CREATE INDEX IF NOT EXISTS idx_audit_correlation ON audit.events(correlation_id);

-- Daily summary view for quick reporting
CREATE OR REPLACE VIEW audit.daily_summary AS
SELECT
    date_trunc('day', timestamp) AS day,
    event_type,
    action,
    outcome,
    count(*) AS event_count,
    count(DISTINCT actor_email) AS unique_users
FROM audit.events
GROUP BY 1, 2, 3, 4
ORDER BY 1 DESC, 5 DESC;

-- User activity view
CREATE OR REPLACE VIEW audit.user_activity AS
SELECT
    actor_email,
    actor_display_name,
    date_trunc('hour', timestamp) AS hour,
    event_type,
    action,
    resource,
    outcome,
    count(*) AS event_count
FROM audit.events
WHERE actor_email IS NOT NULL
GROUP BY 1, 2, 3, 4, 5, 6, 7
ORDER BY 3 DESC, 8 DESC;

-- RBAC denial view
CREATE OR REPLACE VIEW audit.rbac_denials AS
SELECT
    timestamp,
    actor_email,
    actor_display_name,
    action,
    resource,
    details->>'denied_reason' AS denied_reason,
    details->>'decision' AS decision
FROM audit.events
WHERE event_type = 'authorization' AND outcome = 'denied'
ORDER BY timestamp DESC;

-- AI usage view
CREATE OR REPLACE VIEW audit.ai_usage AS
SELECT
    date_trunc('day', timestamp) AS day,
    ai_model,
    count(*) AS api_calls,
    sum(ai_input_tokens) AS total_input_tokens,
    sum(ai_output_tokens) AS total_output_tokens,
    sum(ai_cost_usd) AS total_cost_usd,
    avg(ai_latency_ms)::int AS avg_latency_ms
FROM audit.events
WHERE event_type = 'ai_interaction'
GROUP BY 1, 2
ORDER BY 1 DESC;

-- Grant access
GRANT USAGE ON SCHEMA audit TO vault_iam;
GRANT SELECT, INSERT ON ALL TABLES IN SCHEMA audit TO vault_iam;
GRANT SELECT ON ALL TABLES IN SCHEMA audit TO vault_iam;
