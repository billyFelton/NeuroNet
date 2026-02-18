-- Asset Inventory — Kevin's knowledge of the environment
-- Hosts, servers, network devices, applications, services
-- Run on neuro-vault-db: psql -U neuro -d neuro_vault -f this_file.sql

-- ═══════════════════════════════════════════════════════════════
-- ASSETS — Every host, device, and service Kevin learns about
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS knowledge.assets (
    id SERIAL PRIMARY KEY,
    
    -- Identity
    asset_type VARCHAR(50) NOT NULL,     -- 'server', 'workstation', 'network_device', 
                                         -- 'printer', 'appliance', 'vm', 'container',
                                         -- 'application', 'service', 'cloud_resource'
    hostname VARCHAR(255),               -- Primary hostname
    fqdn VARCHAR(255),                   -- Fully qualified domain name
    aliases TEXT[] DEFAULT '{}',          -- Other names (short names, CNAMEs, nicknames)
    
    -- Network
    ip_addresses TEXT[] DEFAULT '{}',    -- All known IPs (v4 and v6)
    mac_addresses TEXT[] DEFAULT '{}',   -- Physical addresses
    vlan VARCHAR(50),
    subnet VARCHAR(50),                  -- e.g., '10.20.0.0/24'
    network_zone VARCHAR(100),           -- 'dmz', 'internal', 'guest', 'management'
    
    -- Classification
    os VARCHAR(255),                     -- 'Windows Server 2022', 'Ubuntu 24.04', 'Cisco IOS 17'
    os_version VARCHAR(100),
    device_model VARCHAR(255),           -- Hardware model
    manufacturer VARCHAR(255),
    
    -- Ownership & purpose
    owner_email VARCHAR(255),            -- Who's responsible
    department VARCHAR(255),
    location VARCHAR(255),               -- Physical location or datacenter
    environment VARCHAR(50),             -- 'production', 'staging', 'development', 'test'
    purpose TEXT,                        -- What this asset does in plain language
    criticality VARCHAR(20) DEFAULT 'medium', -- 'critical', 'high', 'medium', 'low'
    
    -- Services & software
    services JSONB DEFAULT '{}',         -- Running services
    -- Example: {
    --   "web": {"port": 443, "software": "nginx 1.24"},
    --   "ssh": {"port": 22},
    --   "wazuh-agent": {"version": "4.7.1", "status": "active"}
    -- }
    
    installed_software JSONB DEFAULT '{}', -- Key software
    -- Example: {
    --   "antivirus": "CrowdStrike Falcon 7.x",
    --   "backup_agent": "Veeam 12",
    --   "monitoring": "Wazuh 4.7.1"
    -- }
    
    -- Relationships
    parent_asset_id INT REFERENCES knowledge.assets(id),  -- e.g., VM → hypervisor
    related_assets TEXT[] DEFAULT '{}',                     -- Hostnames of related systems
    
    -- Security context
    wazuh_agent_id VARCHAR(100),         -- Wazuh agent ID if monitored
    wazuh_instance VARCHAR(50),          -- 'desktops' or 'infrastructure'
    last_vulnerability_scan TIMESTAMPTZ,
    known_issues TEXT[] DEFAULT '{}',    -- Current known problems
    
    -- Notes & history
    notes TEXT DEFAULT '',               -- Free-text notes Kevin has accumulated
    tags TEXT[] DEFAULT '{}',            -- Searchable tags
    
    -- Data source tracking
    learned_from VARCHAR(100),           -- 'wazuh_agent_sync', 'conversation', 'entraid', 'manual'
    confidence FLOAT DEFAULT 0.5,        -- How sure Kevin is about this info (0-1)
    
    -- Timestamps
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    -- Unique on hostname + type (allow same hostname for different types)
    UNIQUE (hostname, asset_type)
);

-- Indexes for common lookups
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON knowledge.assets (hostname);
CREATE INDEX IF NOT EXISTS idx_assets_fqdn ON knowledge.assets (fqdn);
CREATE INDEX IF NOT EXISTS idx_assets_type ON knowledge.assets (asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_owner ON knowledge.assets (owner_email);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON knowledge.assets USING GIN (ip_addresses);
CREATE INDEX IF NOT EXISTS idx_assets_tags ON knowledge.assets USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_assets_aliases ON knowledge.assets USING GIN (aliases);

-- Full-text search across hostname, purpose, and notes
CREATE INDEX IF NOT EXISTS idx_assets_fts ON knowledge.assets 
    USING GIN (to_tsvector('english', 
        COALESCE(hostname, '') || ' ' || 
        COALESCE(fqdn, '') || ' ' || 
        COALESCE(purpose, '') || ' ' || 
        COALESCE(notes, '')));

-- Auto-update trigger
DROP TRIGGER IF EXISTS trg_assets_updated ON knowledge.assets;
CREATE TRIGGER trg_assets_updated
    BEFORE UPDATE ON knowledge.assets
    FOR EACH ROW EXECUTE FUNCTION knowledge.auto_update_timestamp();


-- ═══════════════════════════════════════════════════════════════
-- NETWORK MAP — Relationships between network segments
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS knowledge.network_segments (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,   -- 'Server VLAN', 'User Desktops', 'DMZ'
    subnet VARCHAR(50),                  -- '10.20.0.0/24'
    vlan_id VARCHAR(20),
    gateway VARCHAR(50),
    dns_servers TEXT[] DEFAULT '{}',
    dhcp_range VARCHAR(100),
    zone VARCHAR(100),                   -- 'internal', 'dmz', 'guest'
    purpose TEXT,
    asset_count INT DEFAULT 0,
    notes TEXT DEFAULT '',
    tags TEXT[] DEFAULT '{}',
    learned_from VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

DROP TRIGGER IF EXISTS trg_network_segments_updated ON knowledge.network_segments;
CREATE TRIGGER trg_network_segments_updated
    BEFORE UPDATE ON knowledge.network_segments
    FOR EACH ROW EXECUTE FUNCTION knowledge.auto_update_timestamp();
