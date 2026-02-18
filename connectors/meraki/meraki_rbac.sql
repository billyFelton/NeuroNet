-- Add Meraki resource
INSERT INTO iam.resources (id, display_name, description, service) VALUES
    ('meraki', 'Meraki Network', 'Meraki network infrastructure', 'connector-meraki')
ON CONFLICT (id) DO NOTHING;

-- security-admin: full access
INSERT INTO iam.policies (role_id, resource_id, action, effect, description) VALUES
    ('security-admin', 'meraki', '*', 'permit', 'Full Meraki network access')
ON CONFLICT (role_id, resource_id, action) DO NOTHING;

-- security-analyst: query only
INSERT INTO iam.policies (role_id, resource_id, action, effect, description) VALUES
    ('security-analyst', 'meraki', 'query', 'permit', 'Query Meraki network data')
ON CONFLICT (role_id, resource_id, action) DO NOTHING;

-- it-support: query only
INSERT INTO iam.policies (role_id, resource_id, action, effect, description) VALUES
    ('it-support', 'meraki', 'query', 'permit', 'Query Meraki network data')
ON CONFLICT (role_id, resource_id, action) DO NOTHING;
