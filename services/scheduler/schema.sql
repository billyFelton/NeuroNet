-- Scheduler schema for Kevin's proactive tasks

CREATE TABLE IF NOT EXISTS knowledge.scheduled_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    task_type VARCHAR(50) NOT NULL,  -- 'alert_sweep', 'daily_summary', 'critical_monitor', 'agent_health', 'custom'
    schedule VARCHAR(100) NOT NULL,  -- cron expression: "0 8 * * *" or interval: "every 1h", "every 30m"
    enabled BOOLEAN DEFAULT true,
    config JSONB DEFAULT '{}',       -- task-specific config
    last_run TIMESTAMPTZ,
    next_run TIMESTAMPTZ,
    last_result JSONB,               -- outcome of last run
    created_by VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Execution history
CREATE TABLE IF NOT EXISTS knowledge.task_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    task_id UUID REFERENCES knowledge.scheduled_tasks(id) ON DELETE CASCADE,
    started_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    status VARCHAR(20) DEFAULT 'running',  -- 'running', 'completed', 'failed'
    result JSONB,
    tickets_created INT DEFAULT 0,
    emails_sent INT DEFAULT 0,
    alerts_processed INT DEFAULT 0,
    error TEXT
);

CREATE INDEX idx_task_runs_task_id ON knowledge.task_runs(task_id);
CREATE INDEX idx_task_runs_started ON knowledge.task_runs(started_at DESC);

-- Seed default tasks
INSERT INTO knowledge.scheduled_tasks (name, description, task_type, schedule, config) VALUES
(
    'Wazuh Alert Sweep',
    'Sweep Wazuh alerts for high/critical issues and create IT tickets via email',
    'alert_sweep',
    '0 */2 * * *',  -- every 2 hours
    '{"min_severity": "high", "ticket_email": "ITSupport@heads-up.com", "lookback_hours": 2}'::jsonb
),
(
    'Daily Security Summary',
    'Generate and email a daily security summary to the security team',
    'daily_summary',
    '0 8 * * 1-5',  -- 8 AM weekdays
    '{"recipients": ["bfelton@heads-up.com"], "include_alerts": true, "include_agents": true, "include_vulnerabilities": true}'::jsonb
),
(
    'Critical Alert Monitor',
    'Monitor for critical severity alerts and notify immediately via Slack and email',
    'critical_monitor',
    'every 5m',  -- every 5 minutes
    '{"min_level": 13, "notify_slack_channel": "security-alerts", "notify_email": ["bfelton@heads-up.com"], "lookback_minutes": 6}'::jsonb
)
ON CONFLICT DO NOTHING;
