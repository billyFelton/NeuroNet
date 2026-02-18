-- Company Policies & Approved Tools
-- Knowledge Kevin can share with ALL users including general-user
-- Run on neuro-vault-db: psql -U neuro -d neuro_vault -f this_file.sql

-- ═══════════════════════════════════════════════════════════════
-- COMPANY POLICIES — IT and security policies employees should know
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS knowledge.company_policies (
    id SERIAL PRIMARY KEY,
    category VARCHAR(100) NOT NULL,      -- 'data_handling', 'acceptable_use', 'access_control',
                                         -- 'device_security', 'incident_response', 'remote_work',
                                         -- 'physical_security', 'communication', 'compliance'
    title VARCHAR(255) NOT NULL,
    summary TEXT NOT NULL,               -- Plain language summary Kevin can share
    details TEXT DEFAULT '',             -- More detailed explanation if user asks follow-up
    dos TEXT[] DEFAULT '{}',             -- What employees SHOULD do
    donts TEXT[] DEFAULT '{}',           -- What employees should NOT do
    exceptions TEXT DEFAULT '',          -- Any known exceptions
    contact VARCHAR(255) DEFAULT '',     -- Who to contact for questions
    policy_url VARCHAR(500) DEFAULT '',  -- Link to full policy document
    effective_date DATE,
    review_date DATE,
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_company_policies_category
    ON knowledge.company_policies (category);
CREATE INDEX IF NOT EXISTS idx_company_policies_tags
    ON knowledge.company_policies USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_company_policies_fts
    ON knowledge.company_policies
    USING GIN (to_tsvector('english',
        COALESCE(title, '') || ' ' ||
        COALESCE(summary, '') || ' ' ||
        COALESCE(details, '')));


-- ═══════════════════════════════════════════════════════════════
-- APPROVED TOOLS — What software/services employees can use
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS knowledge.approved_tools (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,          -- 'Dropbox', 'Slack', 'Zoom'
    category VARCHAR(100) NOT NULL,      -- 'file_sharing', 'communication', 'email',
                                         -- 'project_management', 'development', 'security',
                                         -- 'productivity', 'remote_access', 'cloud_storage'
    status VARCHAR(50) NOT NULL,         -- 'approved', 'prohibited', 'restricted', 'deprecated'
    description TEXT DEFAULT '',         -- What it's for
    usage_guidelines TEXT DEFAULT '',    -- How to use it properly
    restrictions TEXT DEFAULT '',        -- Any limitations or conditions
    alternative VARCHAR(255) DEFAULT '', -- If prohibited, what to use instead
    who_can_use VARCHAR(255) DEFAULT 'all', -- 'all', 'it-only', 'security-only', 'management'
    request_process TEXT DEFAULT '',     -- How to get access if restricted
    support_contact VARCHAR(255) DEFAULT '',
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (name)
);

CREATE INDEX IF NOT EXISTS idx_approved_tools_category
    ON knowledge.approved_tools (category);
CREATE INDEX IF NOT EXISTS idx_approved_tools_status
    ON knowledge.approved_tools (status);


-- ═══════════════════════════════════════════════════════════════
-- SEED DATA — Initial policies and tools
-- ═══════════════════════════════════════════════════════════════

-- Approved / Prohibited Tools
INSERT INTO knowledge.approved_tools (name, category, status, description, usage_guidelines, restrictions, alternative, tags) VALUES

-- Approved tools
('Slack', 'communication', 'approved',
 'Primary internal messaging platform for team communication.',
 'Use for day-to-day work communication. Keep sensitive data out of public channels. Use private channels or DMs for confidential discussions.',
 'Do not share passwords, API keys, or customer PII in Slack messages.',
 '', ARRAY['messaging', 'chat', 'communication']),

('Dropbox', 'file_sharing', 'approved',
 'Company-approved cloud storage and file sharing platform.',
 'Use your company Dropbox account for sharing work files. Set appropriate sharing permissions — avoid public links for sensitive documents.',
 'Do not store highly classified data without encryption. Always use company account, not personal.',
 '', ARRAY['files', 'storage', 'sharing', 'cloud']),

('Zoom', 'communication', 'approved',
 'Video conferencing platform for meetings.',
 'Use for internal and external meetings. Enable waiting rooms for external meetings. Use meeting passwords.',
 'Do not record meetings without participant consent.',
 '', ARRAY['video', 'meetings', 'conferencing']),

('Microsoft 365', 'productivity', 'approved',
 'Office suite including Outlook, Word, Excel, PowerPoint, Teams.',
 'Primary email and productivity platform. Use for all official business communication.',
 'Follow data classification guidelines when sharing documents externally.',
 '', ARRAY['email', 'office', 'outlook', 'word', 'excel']),

-- Prohibited tools/practices
('USB Drives', 'data_transfer', 'prohibited',
 'USB flash drives and external storage devices are not permitted for transferring company data.',
 '',
 'USB drives pose significant security risks including malware infection and data loss. They cannot be remotely wiped if lost.',
 'Use Dropbox or approved cloud storage for file transfers. For large files, contact IT for secure transfer options.',
 ARRAY['usb', 'flash drive', 'thumb drive', 'external storage', 'removable media']),

('Personal Email for Work', 'communication', 'prohibited',
 'Do not use personal email accounts (Gmail, Yahoo, etc.) for company business.',
 '',
 'Personal email is not monitored, backed up, or secured to company standards. Data sent via personal email cannot be recovered or controlled.',
 'Use your company Microsoft 365 / Outlook account for all work communication.',
 ARRAY['gmail', 'yahoo', 'personal email', 'hotmail']),

('Unauthorized VPN', 'remote_access', 'prohibited',
 'Third-party VPN services (NordVPN, ExpressVPN, etc.) are not permitted on company devices.',
 '',
 'Unauthorized VPNs can bypass security controls and make it impossible to monitor network traffic for threats.',
 'Use the company-provided VPN for remote access. Contact IT if you need VPN access set up.',
 ARRAY['vpn', 'nordvpn', 'expressvpn', 'proxy'])

ON CONFLICT (name) DO NOTHING;


-- Company Policies
INSERT INTO knowledge.company_policies (category, title, summary, details, dos, donts, contact, tags) VALUES

('data_handling', 'Data Classification & Handling',
 'All company data must be classified and handled according to its sensitivity level.',
 'We use three classification levels: Public (anyone can see), Internal (employees only), and Confidential (need-to-know only). When in doubt, treat data as Internal.',
 ARRAY['Classify documents before sharing', 'Use approved tools for file sharing', 'Encrypt confidential files before sending externally', 'Report accidental data exposure immediately'],
 ARRAY['Share confidential data via Slack public channels', 'Store sensitive data on personal devices', 'Send customer PII via unencrypted email', 'Leave sensitive documents on printers'],
 'security@heads-up.com',
 ARRAY['data', 'classification', 'sensitive', 'confidential', 'pii', 'handling']),

('device_security', 'Device Security Policy',
 'Company devices must be kept secure and up to date at all times.',
 'All company laptops and desktops have endpoint security monitoring installed. Keep your device updated, locked when unattended, and report any loss or theft immediately.',
 ARRAY['Lock your screen when stepping away (Win+L or Cmd+L)', 'Keep your OS and software updated', 'Report lost or stolen devices immediately to IT', 'Use full disk encryption (enabled by default)'],
 ARRAY['Disable or uninstall security software', 'Connect to untrusted networks without VPN', 'Let others use your device with your credentials', 'Use USB drives for data transfer'],
 'it-support@heads-up.com',
 ARRAY['laptop', 'computer', 'device', 'security', 'lock', 'encryption', 'lost', 'stolen']),

('acceptable_use', 'Acceptable Use Policy',
 'Company technology resources should be used responsibly and primarily for business purposes.',
 'Limited personal use is acceptable as long as it does not interfere with work, consume excessive bandwidth, or violate any other policies. All network activity may be monitored.',
 ARRAY['Use company resources primarily for work', 'Follow all other security policies when using company tech', 'Report suspicious activity on company systems'],
 ARRAY['Access inappropriate or illegal content', 'Install unauthorized software', 'Use company resources for personal business ventures', 'Attempt to bypass security controls'],
 'it-support@heads-up.com',
 ARRAY['acceptable use', 'personal use', 'internet', 'software', 'install']),

('incident_response', 'Security Incident Reporting',
 'If you suspect a security incident, report it immediately. There is no penalty for reporting.',
 'A security incident includes: phishing emails clicked, suspicious account activity, lost devices, malware warnings, unauthorized access, or data accidentally shared with the wrong person. Report immediately — early reporting helps us contain issues faster.',
 ARRAY['Report suspicious emails by forwarding to phishing@heads-up.com', 'Report lost/stolen devices to IT immediately', 'Report any unusual account activity', 'Preserve evidence — don''t delete suspicious emails'],
 ARRAY['Ignore security warnings', 'Try to fix a security issue yourself without reporting', 'Delete suspicious emails before reporting them', 'Wait to report — time matters'],
 'security@heads-up.com or #security on Slack',
 ARRAY['incident', 'breach', 'phishing', 'suspicious', 'report', 'malware', 'virus', 'hack']),

('access_control', 'Password & Authentication Policy',
 'Use strong, unique passwords and enable MFA on all accounts.',
 'All company accounts require multi-factor authentication (MFA). Passwords must be at least 12 characters. Use a password manager to generate and store unique passwords for each service.',
 ARRAY['Use MFA on all accounts', 'Use a password manager', 'Use unique passwords for each service', 'Change passwords immediately if you suspect compromise'],
 ARRAY['Reuse passwords across services', 'Share passwords with anyone including IT', 'Write passwords on sticky notes', 'Use simple or common passwords', 'Send passwords via email or Slack'],
 'it-support@heads-up.com',
 ARRAY['password', 'mfa', 'authentication', '2fa', 'two-factor', 'login', 'credentials']),

('remote_work', 'Remote Work Security',
 'When working remotely, take extra precautions to protect company data.',
 'Working from home or public locations introduces additional security risks. Use VPN, avoid public Wi-Fi for sensitive work, and ensure your home network is secured.',
 ARRAY['Use company VPN when accessing internal resources', 'Lock your screen when stepping away, even at home', 'Use a private, secured Wi-Fi network', 'Keep work and personal activities separated'],
 ARRAY['Use public Wi-Fi for sensitive work without VPN', 'Let family members use your work device', 'Leave your laptop visible in your car', 'Work on confidential documents in public where screens are visible'],
 'it-support@heads-up.com',
 ARRAY['remote', 'wfh', 'work from home', 'vpn', 'wifi', 'public', 'travel']),

('physical_security', 'Physical Security',
 'Maintain physical security of company spaces and equipment.',
 'Keep doors closed, don''t let strangers tailgate into the office, wear your badge, and secure your workstation.',
 ARRAY['Wear your badge visibly', 'Challenge or report unescorted visitors', 'Lock your workstation when leaving your desk', 'Shred sensitive documents', 'Report broken locks or access control issues'],
 ARRAY['Hold doors open for strangers (tailgating)', 'Leave sensitive documents on your desk overnight', 'Share your badge or access codes', 'Prop open secure doors'],
 'facilities@heads-up.com',
 ARRAY['physical', 'badge', 'tailgating', 'office', 'building', 'access', 'visitor', 'shred'])

ON CONFLICT DO NOTHING;

-- Grants
GRANT ALL ON knowledge.company_policies TO vault_iam;
GRANT ALL ON knowledge.company_policies_id_seq TO vault_iam;
GRANT ALL ON knowledge.approved_tools TO vault_iam;
GRANT ALL ON knowledge.approved_tools_id_seq TO vault_iam;
