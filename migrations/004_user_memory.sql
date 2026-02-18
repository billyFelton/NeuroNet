-- User Memory & Conversation History System
-- Kevin maintains persistent relationships with each person
-- Run on neuro-vault-db: psql -U neuro -d neuro_vault -f this_file.sql

-- ═══════════════════════════════════════════════════════════════
-- USER PROFILES — Kevin's personal knowledge about each person
-- ═══════════════════════════════════════════════════════════════
-- This is NOT the IAM record. This is Kevin's memory of who
-- someone is, what they care about, how they work, and what
-- he's learned from interacting with them.

CREATE TABLE IF NOT EXISTS knowledge.user_profiles (
    id SERIAL PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL UNIQUE,

    -- Identity (seeded from EntraID/IAM, enriched over time)
    display_name VARCHAR(255),
    first_name VARCHAR(100),
    preferred_name VARCHAR(100),        -- Maybe they go by a nickname
    job_title VARCHAR(255),
    department VARCHAR(255),
    manager_email VARCHAR(255),
    location VARCHAR(255),
    timezone VARCHAR(100),

    -- Relationship state
    first_interaction TIMESTAMPTZ,       -- When Kevin first talked to them
    last_interaction TIMESTAMPTZ,        -- Most recent exchange
    total_interactions INT DEFAULT 0,    -- Lifetime message count
    rapport_notes TEXT DEFAULT '',       -- Free-text notes about the relationship

    -- Personal preferences & facts Kevin has learned
    preferences JSONB DEFAULT '{}',
    -- Example: {
    --   "communication_style": "prefers concise answers",
    --   "interests": ["coffee", "jazz", "hiking"],
    --   "pet_peeves": ["long bullet lists"],
    --   "fun_facts": ["has a dog named Biscuit", "runs marathons"],
    --   "report_format": "prefers tables over paragraphs",
    --   "notification_preference": "email for summaries, slack for alerts"
    -- }

    -- Work context Kevin has learned
    work_context JSONB DEFAULT '{}',
    -- Example: {
    --   "responsibilities": ["manages endpoint security", "leads IR team"],
    --   "systems_owned": ["wazuh-dt", "crowdstrike console"],
    --   "common_queries": ["daily alert reviews", "user investigations"],
    --   "projects": ["SOC2 audit prep", "EDR migration"],
    --   "team_members": ["lfelton@heads-up.com", "amarshall@heads-up.com"]
    -- }

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_user_profiles_email
    ON knowledge.user_profiles (user_email);


-- ═══════════════════════════════════════════════════════════════
-- MESSAGE HISTORY — Every exchange Kevin has with anyone
-- ═══════════════════════════════════════════════════════════════
-- Stored by Kevin, independent of which connector delivered it.
-- This is Kevin's memory, not Slack's or Teams'.

CREATE TABLE IF NOT EXISTS knowledge.message_history (
    id BIGSERIAL PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,
    agent_id VARCHAR(100) NOT NULL DEFAULT 'kevin',

    -- The exchange
    role VARCHAR(20) NOT NULL,           -- 'user' or 'assistant'
    content TEXT NOT NULL,
    channel_type VARCHAR(50),            -- 'slack_dm', 'slack_channel', 'teams', 'email', 'conductor'
    channel_id VARCHAR(255),             -- Platform-specific channel reference

    -- Context
    intent VARCHAR(100),                 -- Classified intent for this message
    had_data BOOLEAN DEFAULT FALSE,      -- Did this message include system data?
    data_sources TEXT[],                 -- Which connectors provided data

    -- Metadata
    model_used VARCHAR(100),             -- Which AI model responded (for assistant messages)
    input_tokens INT,
    output_tokens INT,

    -- Timestamps
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Fast lookups: recent messages per user
CREATE INDEX IF NOT EXISTS idx_message_history_user_time
    ON knowledge.message_history (user_email, created_at DESC);

-- Partition-friendly index for cleanup
CREATE INDEX IF NOT EXISTS idx_message_history_created
    ON knowledge.message_history (created_at);


-- ═══════════════════════════════════════════════════════════════
-- CONVERSATION SESSIONS — Rolling summaries of active discussions
-- ═══════════════════════════════════════════════════════════════
-- Replaces the earlier knowledge.conversations table with a
-- richer model that tracks sessions.

-- Drop old table if it exists (we're replacing it)
-- DROP TABLE IF EXISTS knowledge.conversations;

CREATE TABLE IF NOT EXISTS knowledge.conversation_sessions (
    id SERIAL PRIMARY KEY,
    user_email VARCHAR(255) NOT NULL,
    agent_id VARCHAR(100) NOT NULL DEFAULT 'kevin',

    -- Rolling summary
    summary TEXT NOT NULL DEFAULT '',
    topic TEXT DEFAULT '',
    key_entities TEXT[] DEFAULT '{}',
    open_questions TEXT[] DEFAULT '{}',
    last_action TEXT DEFAULT '',

    -- Session tracking
    message_count INT DEFAULT 0,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),

    -- A session expires after inactivity
    -- New messages after expiry start a fresh session
    UNIQUE (user_email, agent_id)
);

CREATE INDEX IF NOT EXISTS idx_sessions_user
    ON knowledge.conversation_sessions (user_email, agent_id);


-- ═══════════════════════════════════════════════════════════════
-- AUTO-UPDATE TRIGGERS
-- ═══════════════════════════════════════════════════════════════

CREATE OR REPLACE FUNCTION knowledge.auto_update_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_user_profiles_updated ON knowledge.user_profiles;
CREATE TRIGGER trg_user_profiles_updated
    BEFORE UPDATE ON knowledge.user_profiles
    FOR EACH ROW EXECUTE FUNCTION knowledge.auto_update_timestamp();

DROP TRIGGER IF EXISTS trg_sessions_updated ON knowledge.conversation_sessions;
CREATE TRIGGER trg_sessions_updated
    BEFORE UPDATE ON knowledge.conversation_sessions
    FOR EACH ROW EXECUTE FUNCTION knowledge.auto_update_timestamp();
