-- Add ZenDesk resource
INSERT INTO iam.resources (id, display_name, description, service) VALUES
    ('zendesk', 'ZenDesk Tickets', 'ZenDesk ticket management', 'connector-zendesk')
ON CONFLICT (id) DO NOTHING;

-- Add policies for security-admin (full access)
INSERT INTO iam.policies (role_id, resource_id, action, effect, description) VALUES
    ('security-admin', 'zendesk', '*', 'permit', 'Full ZenDesk ticket access')
ON CONFLICT (role_id, resource_id, action) DO NOTHING;

-- Add policies for security-analyst (query + comment only)
INSERT INTO iam.policies (role_id, resource_id, action, effect, description) VALUES
    ('security-analyst', 'zendesk', 'query', 'permit', 'Query ZenDesk tickets'),
    ('security-analyst', 'zendesk', 'update', 'permit', 'Comment on ZenDesk tickets')
ON CONFLICT (role_id, resource_id, action) DO NOTHING;

-- Add policies for it-support (query + create + comment)
INSERT INTO iam.policies (role_id, resource_id, action, effect, description) VALUES
    ('it-support', 'zendesk', 'query', 'permit', 'Query ZenDesk tickets'),
    ('it-support', 'zendesk', 'create', 'permit', 'Create ZenDesk tickets'),
    ('it-support', 'zendesk', 'update', 'permit', 'Update ZenDesk tickets')
ON CONFLICT (role_id, resource_id, action) DO NOTHING;
