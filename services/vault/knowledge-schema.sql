-- Knowledge Base schema for NeuroNet
-- Stores persistent facts, network topology, known issues, and learned context

CREATE SCHEMA IF NOT EXISTS knowledge;

-- Core knowledge entries — facts Kevin learns and remembers
CREATE TABLE knowledge.entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    category VARCHAR(50) NOT NULL,  -- 'network', 'host', 'incident', 'policy', 'contact', 'general'
    subject VARCHAR(255) NOT NULL,  -- e.g., 'HUT-Laser', 'VPN subnet', 'password policy'
    content TEXT NOT NULL,          -- the actual knowledge
    source VARCHAR(100),            -- who/what provided this: 'user:bfelton', 'wazuh:alert', 'admin'
    confidence FLOAT DEFAULT 1.0,   -- 0.0-1.0, lower for inferred facts
    tags TEXT[] DEFAULT '{}',       -- searchable tags
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_by VARCHAR(255),        -- user email or system
    expires_at TIMESTAMPTZ          -- optional TTL for temporary facts
);

-- Indexes for fast lookup
CREATE INDEX idx_knowledge_category ON knowledge.entries(category);
CREATE INDEX idx_knowledge_subject ON knowledge.entries(subject);
CREATE INDEX idx_knowledge_tags ON knowledge.entries USING gin(tags);
CREATE INDEX idx_knowledge_search ON knowledge.entries USING gin(to_tsvector('english', subject || ' ' || content));

-- Network topology — hosts, subnets, services
CREATE TABLE knowledge.hosts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    hostname VARCHAR(255) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    os VARCHAR(100),
    role VARCHAR(100),          -- 'domain-controller', 'file-server', 'workstation', 'printer'
    location VARCHAR(255),      -- physical or logical location
    wazuh_agent_id VARCHAR(20), -- link to Wazuh agent
    owner VARCHAR(255),         -- responsible person/team
    notes TEXT,
    criticality VARCHAR(20) DEFAULT 'standard',  -- 'critical', 'high', 'standard', 'low'
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_hosts_hostname ON knowledge.hosts(hostname);
CREATE INDEX idx_hosts_role ON knowledge.hosts(role);
CREATE INDEX idx_hosts_criticality ON knowledge.hosts(criticality);

-- Incident journal — track ongoing and past issues
CREATE TABLE knowledge.incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(500) NOT NULL,
    status VARCHAR(20) DEFAULT 'open',  -- 'open', 'investigating', 'resolved', 'closed'
    severity VARCHAR(20) DEFAULT 'medium',
    affected_hosts TEXT[] DEFAULT '{}',
    description TEXT,
    timeline JSONB DEFAULT '[]',  -- [{timestamp, event, actor}]
    resolution TEXT,
    lessons_learned TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    created_by VARCHAR(255)
);

CREATE INDEX idx_incidents_status ON knowledge.incidents(status);
CREATE INDEX idx_incidents_severity ON knowledge.incidents(severity);

-- Grant access to the vault_iam user (used by our services)
GRANT USAGE ON SCHEMA knowledge TO vault_iam;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA knowledge TO vault_iam;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA knowledge TO vault_iam;
ALTER DEFAULT PRIVILEGES IN SCHEMA knowledge GRANT ALL ON TABLES TO vault_iam;
