"""
Scheduler — Kevin's proactive task engine.

Runs scheduled tasks like:
- Sweeping Wazuh alerts and creating IT tickets via email
- Generating daily security summaries
- Monitoring for critical alerts and notifying immediately

Tasks are stored in PostgreSQL and can be configured via:
- Database entries (cron or interval schedules)
- Slack commands ("Kevin, sweep alerts every hour")

The scheduler queries Wazuh and EntraID via RabbitMQ, uses Claude to
analyze findings, and sends emails/Slack messages for notifications.
"""

import json
import logging
import os
import re
import time
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx
import psycopg2
from croniter import croniter

from neurokit.envelope import EventType, MessageEnvelope
from neurokit.service import BaseService

logger = logging.getLogger("scheduler")


class SchedulerService(BaseService):
    """
    Scheduler service for Kevin's proactive security tasks.

    Runs a main loop that checks for due tasks and executes them.
    Each task type has a dedicated handler that:
    1. Queries data (Wazuh, EntraID) via RabbitMQ
    2. Analyzes results with Claude (Haiku for efficiency)
    3. Takes action (send email, post to Slack, create tickets)
    """

    def __init__(self, config):
        super().__init__(config)
        self._db: Optional[psycopg2.extensions.connection] = None
        self._http: Optional[httpx.Client] = None
        self._api_key: str = ""
        self._check_interval: int = 30  # seconds between schedule checks
        self._running: bool = False

    def on_startup(self) -> None:
        """Connect to DB, get API key, start scheduler."""
        # Database
        self._db = psycopg2.connect(
            host=os.environ.get("KB_DB_HOST", "vault-db"),
            user=os.environ.get("KB_DB_USER", "vault_iam"),
            password=os.environ.get("KB_DB_PASSWORD", ""),
            dbname=os.environ.get("KB_DB_NAME", "neuro_vault"),
            connect_timeout=5,
        )
        self._db.autocommit = True
        logger.info("Connected to scheduler database")

        # Anthropic API key for analysis
        anthropic_secrets = self.secrets.get_all("anthropic")
        self._api_key = anthropic_secrets["api_key"]

        self._http = httpx.Client(timeout=60)
        self._wazuh_http = httpx.Client(timeout=60, verify=False)  # Wazuh uses self-signed certs

        # Initialize next_run for tasks that don't have one
        self._initialize_schedules()

        self._running = True

    def _initialize_schedules(self) -> None:
        """Set next_run for any tasks that need it."""
        with self._db.cursor() as cur:
            cur.execute("""
                SELECT id, schedule FROM knowledge.scheduled_tasks
                WHERE enabled = true AND next_run IS NULL
            """)
            for task_id, schedule in cur.fetchall():
                next_run = self._calculate_next_run(schedule)
                if next_run:
                    cur.execute(
                        "UPDATE knowledge.scheduled_tasks SET next_run = %s WHERE id = %s",
                        [next_run, task_id],
                    )
                    logger.info("Initialized schedule for task %s: next run at %s", task_id, next_run)

    def _calculate_next_run(self, schedule: str) -> Optional[datetime]:
        """Calculate next run time from schedule string."""
        now = datetime.now(timezone.utc)

        # Interval format: "every 5m", "every 1h", "every 30m"
        interval_match = re.match(r"every\s+(\d+)\s*(m|min|h|hr|hour|s|sec)", schedule, re.IGNORECASE)
        if interval_match:
            amount = int(interval_match.group(1))
            unit = interval_match.group(2).lower()
            if unit.startswith("h"):
                return now + timedelta(hours=amount)
            elif unit.startswith("m"):
                return now + timedelta(minutes=amount)
            elif unit.startswith("s"):
                return now + timedelta(seconds=amount)

        # Cron format
        try:
            cron = croniter(schedule, now)
            return cron.get_next(datetime).replace(tzinfo=timezone.utc)
        except (ValueError, KeyError):
            logger.warning("Invalid schedule format: %s", schedule)
            return None

    def setup_queues(self) -> None:
        """Set up queues for Slack schedule commands and data responses."""
        # Listen for schedule management commands from Slack
        self.inbox = self.rmq.declare_queue(
            "scheduler.inbox",
            routing_keys=[
                "scheduler.command.create",
                "scheduler.command.list",
                "scheduler.command.enable",
                "scheduler.command.disable",
                "scheduler.command.modify",
                "scheduler.command.run",  # Manual trigger
            ],
        )
        self.rmq.consume(self.inbox, self._handle_command)

        # Queue for receiving data responses from connectors
        self.data_queue = self.rmq.declare_queue(
            "scheduler.data-responses",
            routing_keys=[
                "wazuh.response.*",
                "email.response.*",
            ],
        )
        # Don't consume this — we'll poll it synchronously during task execution

    def run(self) -> None:
        """Override run to add the scheduler loop alongside RabbitMQ consumption."""
        # Start the scheduler loop in a separate thread
        scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            name="scheduler-loop",
            daemon=True,
        )
        scheduler_thread.start()

        # Run the base service (RabbitMQ consumption for commands)
        super().run()

    def _scheduler_loop(self) -> None:
        """Main scheduler loop — checks for due tasks and executes them."""
        logger.info("Scheduler loop started (check interval: %ds)", self._check_interval)

        # Wait for RabbitMQ to be ready
        time.sleep(5)

        while self._running:
            try:
                self._check_and_run_tasks()
            except Exception as e:
                logger.error("Scheduler loop error: %s", e, exc_info=True)

            time.sleep(self._check_interval)

    def _check_and_run_tasks(self) -> None:
        """Check for due tasks and execute them."""
        now = datetime.now(timezone.utc)

        with self._db.cursor() as cur:
            cur.execute("""
                SELECT id, name, task_type, schedule, config
                FROM knowledge.scheduled_tasks
                WHERE enabled = true AND next_run IS NOT NULL AND next_run <= %s
                ORDER BY next_run ASC
            """, [now])
            due_tasks = cur.fetchall()

        for task_id, name, task_type, schedule, config in due_tasks:
            logger.info("Running scheduled task: %s (%s)", name, task_type)

            # Create a run record
            run_id = str(uuid.uuid4())
            with self._db.cursor() as cur:
                cur.execute(
                    "INSERT INTO knowledge.task_runs (id, task_id) VALUES (%s, %s)",
                    [run_id, task_id],
                )

            try:
                result = self._execute_task(task_type, config or {})

                # Update run record
                with self._db.cursor() as cur:
                    cur.execute("""
                        UPDATE knowledge.task_runs SET
                            completed_at = NOW(), status = 'completed', result = %s,
                            tickets_created = %s, emails_sent = %s, alerts_processed = %s
                        WHERE id = %s
                    """, [
                        json.dumps(result),
                        result.get("tickets_created", 0),
                        result.get("emails_sent", 0),
                        result.get("alerts_processed", 0),
                        run_id,
                    ])

                logger.info(
                    "Task %s completed: %d alerts processed, %d tickets, %d emails",
                    name,
                    result.get("alerts_processed", 0),
                    result.get("tickets_created", 0),
                    result.get("emails_sent", 0),
                )

            except Exception as e:
                logger.error("Task %s failed: %s", name, e, exc_info=True)
                with self._db.cursor() as cur:
                    cur.execute(
                        "UPDATE knowledge.task_runs SET completed_at = NOW(), status = 'failed', error = %s WHERE id = %s",
                        [str(e), run_id],
                    )

            # Update next_run and last_run
            next_run = self._calculate_next_run(schedule)
            with self._db.cursor() as cur:
                cur.execute("""
                    UPDATE knowledge.scheduled_tasks SET
                        last_run = NOW(), next_run = %s, last_result = %s, updated_at = NOW()
                    WHERE id = %s
                """, [next_run, json.dumps(result if 'result' in dir() else {}), task_id])

    # ── Task Execution ──────────────────────────────────────────────

    def _execute_task(self, task_type: str, config: Dict) -> Dict[str, Any]:
        """Execute a task based on its type."""
        handlers = {
            "alert_sweep": self._task_alert_sweep,
            "daily_summary": self._task_daily_summary,
            "critical_monitor": self._task_critical_monitor,
        }

        handler = handlers.get(task_type)
        if not handler:
            return {"error": f"Unknown task type: {task_type}"}

        return handler(config)

    # ── Alert Sweep Task ────────────────────────────────────────────

    def _task_alert_sweep(self, config: Dict) -> Dict[str, Any]:
        """
        Sweep Wazuh alerts, group by host, analyze with Claude,
        and create IT tickets via email for hosts with issues.
        """
        min_severity = config.get("min_severity", "high")
        ticket_email = config.get("ticket_email", "ITSupport@heads-up.com")
        lookback_hours = config.get("lookback_hours", 2)

        severity_map = {"low": 3, "medium": 7, "high": 10, "critical": 13}
        min_level = severity_map.get(min_severity, 10)

        # Query Wazuh directly via the indexer
        wazuh_secrets = self.secrets.get_all("wazuh")
        indexer_url = wazuh_secrets.get("indexer_url", "").rstrip("/")
        indexer_user = wazuh_secrets.get("indexer_user", "")
        indexer_password = wazuh_secrets.get("indexer_password", "")
        verify_ssl = wazuh_secrets.get("verify_ssl", "false").lower() == "true"

        now = datetime.now(timezone.utc)
        from_time = (now - timedelta(hours=lookback_hours)).isoformat()

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": from_time}}},
                        {"range": {"rule.level": {"gte": min_level}}},
                    ]
                }
            },
            "size": 200,
            "sort": [{"timestamp": {"order": "desc"}}],
        }

        resp = self._wazuh_http.post(
            f"{indexer_url}/wazuh-alerts-*/_search",
            json=query,
            auth=(indexer_user, indexer_password),
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])

        if not hits:
            return {"alerts_processed": 0, "tickets_created": 0, "emails_sent": 0, "message": "No high-severity alerts found"}

        # Group alerts by agent
        agents = {}
        for hit in hits:
            src = hit.get("_source", {})
            agent_name = src.get("agent", {}).get("name", "unknown")
            if agent_name not in agents:
                agents[agent_name] = []
            agents[agent_name].append({
                "timestamp": src.get("timestamp"),
                "level": src.get("rule", {}).get("level"),
                "description": src.get("rule", {}).get("description"),
                "groups": src.get("rule", {}).get("groups", []),
            })

        # Analyze each host with Claude and create tickets
        tickets_created = 0
        emails_sent = 0

        for agent_name, alerts in agents.items():
            # Use Claude Haiku to analyze and draft ticket
            analysis = self._analyze_alerts_for_ticket(agent_name, alerts)

            if analysis.get("needs_ticket", False):
                # Send ticket email
                self._send_ticket_email(
                    to=ticket_email,
                    agent_name=agent_name,
                    subject=analysis.get("subject", f"Security Alert: {agent_name}"),
                    body=analysis.get("ticket_body", ""),
                    priority=analysis.get("priority", "medium"),
                )
                tickets_created += 1
                emails_sent += 1

        return {
            "alerts_processed": len(hits),
            "hosts_analyzed": len(agents),
            "tickets_created": tickets_created,
            "emails_sent": emails_sent,
        }

    def _analyze_alerts_for_ticket(
        self, agent_name: str, alerts: List[Dict]
    ) -> Dict[str, Any]:
        """Use Claude Haiku to analyze alerts and draft a ticket."""
        alerts_text = json.dumps(alerts[:20], indent=2, default=str)

        prompt = f"""Analyze these security alerts for host "{agent_name}" and determine if a trouble ticket should be created.

Alerts:
{alerts_text}

Respond with ONLY valid JSON:
{{
    "needs_ticket": true/false,
    "priority": "low"/"medium"/"high"/"critical",
    "subject": "Brief ticket subject line",
    "ticket_body": "Detailed ticket body with: summary, affected system, alert details, recommended actions",
    "reasoning": "Brief explanation of your decision"
}}

Create a ticket if there are genuine security concerns. Do NOT create tickets for routine, informational, or low-noise alerts. Be selective."""

        try:
            resp = self._http.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5-20251001",
                    "max_tokens": 1000,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=30,
            )
            resp.raise_for_status()

            text = ""
            for block in resp.json().get("content", []):
                if block.get("type") == "text":
                    text += block["text"]

            text = text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[-1].rsplit("```", 1)[0]

            return json.loads(text)

        except Exception as e:
            logger.warning("Alert analysis failed for %s: %s", agent_name, e)
            # Default to creating a ticket if analysis fails
            return {
                "needs_ticket": True,
                "priority": "medium",
                "subject": f"Security Alert Review Needed: {agent_name}",
                "ticket_body": f"Automated analysis failed. {len(alerts)} alerts detected on {agent_name} requiring manual review.",
            }

    # ── Daily Summary Task ──────────────────────────────────────────

    def _task_daily_summary(self, config: Dict) -> Dict[str, Any]:
        """Generate and email a daily security summary."""
        recipients = config.get("recipients", [])
        if not recipients:
            return {"error": "No recipients configured"}

        # Gather data
        wazuh_secrets = self.secrets.get_all("wazuh")
        indexer_url = wazuh_secrets.get("indexer_url", "").rstrip("/")
        indexer_user = wazuh_secrets.get("indexer_user", "")
        indexer_password = wazuh_secrets.get("indexer_password", "")
        verify_ssl = wazuh_secrets.get("verify_ssl", "false").lower() == "true"

        now = datetime.now(timezone.utc)
        yesterday = (now - timedelta(days=1)).isoformat()

        # Get alert summary
        agg_query = {
            "query": {"range": {"timestamp": {"gte": yesterday}}},
            "size": 0,
            "aggs": {
                "severity": {
                    "range": {
                        "field": "rule.level",
                        "ranges": [
                            {"key": "low (0-6)", "from": 0, "to": 7},
                            {"key": "medium (7-9)", "from": 7, "to": 10},
                            {"key": "high (10-12)", "from": 10, "to": 13},
                            {"key": "critical (13+)", "from": 13},
                        ],
                    }
                },
                "top_agents": {"terms": {"field": "agent.name.keyword", "size": 10}},
                "top_rules": {"terms": {"field": "rule.description.keyword", "size": 10}},
            },
        }

        resp = self._wazuh_http.post(
            f"{indexer_url}/wazuh-alerts-*/_search",
            json=agg_query,
            auth=(indexer_user, indexer_password),
        )
        resp.raise_for_status()
        data = resp.json()

        total = data.get("hits", {}).get("total", {}).get("value", 0)
        severity_buckets = data.get("aggregations", {}).get("severity", {}).get("buckets", [])
        top_agents = data.get("aggregations", {}).get("top_agents", {}).get("buckets", [])
        top_rules = data.get("aggregations", {}).get("top_rules", {}).get("buckets", [])

        # Use Claude to write the summary
        summary_data = {
            "total_alerts": total,
            "severity": {b["key"]: b["doc_count"] for b in severity_buckets},
            "top_agents": [{"agent": b["key"], "count": b["doc_count"]} for b in top_agents],
            "top_rules": [{"rule": b["key"], "count": b["doc_count"]} for b in top_rules],
        }

        summary_text = self._generate_summary_email(summary_data)

        # Send to each recipient
        graph_secrets = self.secrets.get_all("microsoft-graph")
        self._send_email_via_graph(
            graph_secrets, recipients,
            subject=f"Kevin's Daily Security Summary — {now.strftime('%B %d, %Y')}",
            body=summary_text,
        )

        return {
            "alerts_processed": total,
            "emails_sent": len(recipients),
            "tickets_created": 0,
        }

    def _generate_summary_email(self, data: Dict) -> str:
        """Use Claude to write a friendly daily summary email."""
        try:
            resp = self._http.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5-20251001",
                    "max_tokens": 1500,
                    "system": "You are Kevin, a friendly security assistant. Write a concise, readable daily security summary email. Be warm but professional. Use plain text formatting. Highlight anything concerning and note if things look good.",
                    "messages": [{"role": "user", "content": f"Write a daily security summary based on this data:\n{json.dumps(data, indent=2)}"}],
                },
                timeout=30,
            )
            resp.raise_for_status()
            text = ""
            for block in resp.json().get("content", []):
                if block.get("type") == "text":
                    text += block["text"]
            return text
        except Exception as e:
            return f"Daily Summary (auto-generated)\n\nTotal alerts: {data.get('total_alerts', 0)}\n\nAutomated summary generation failed: {e}"

    # ── Critical Alert Monitor ──────────────────────────────────────

    def _task_critical_monitor(self, config: Dict) -> Dict[str, Any]:
        """Check for critical alerts in the last few minutes and notify."""
        min_level = config.get("min_level", 13)
        lookback_minutes = config.get("lookback_minutes", 6)
        notify_email = config.get("notify_email", [])

        wazuh_secrets = self.secrets.get_all("wazuh")
        indexer_url = wazuh_secrets.get("indexer_url", "").rstrip("/")
        indexer_user = wazuh_secrets.get("indexer_user", "")
        indexer_password = wazuh_secrets.get("indexer_password", "")
        verify_ssl = wazuh_secrets.get("verify_ssl", "false").lower() == "true"

        now = datetime.now(timezone.utc)
        from_time = (now - timedelta(minutes=lookback_minutes)).isoformat()

        query = {
            "query": {
                "bool": {
                    "must": [
                        {"range": {"timestamp": {"gte": from_time}}},
                        {"range": {"rule.level": {"gte": min_level}}},
                    ]
                }
            },
            "size": 20,
            "sort": [{"timestamp": {"order": "desc"}}],
        }

        resp = self._wazuh_http.post(
            f"{indexer_url}/wazuh-alerts-*/_search",
            json=query,
            auth=(indexer_user, indexer_password),
        )
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])

        if not hits:
            return {"alerts_processed": 0, "emails_sent": 0, "tickets_created": 0}

        # Format alert notifications
        alerts_text = []
        for hit in hits:
            src = hit.get("_source", {})
            alerts_text.append(
                f"[Level {src.get('rule', {}).get('level')}] "
                f"{src.get('rule', {}).get('description', 'Unknown')} — "
                f"Agent: {src.get('agent', {}).get('name', '?')} — "
                f"Time: {src.get('timestamp', '?')}"
            )

        body = (
            f"CRITICAL ALERT NOTIFICATION\n"
            f"{'=' * 40}\n\n"
            f"{len(hits)} critical alert(s) detected in the last {lookback_minutes} minutes:\n\n"
            + "\n".join(alerts_text)
            + "\n\nPlease investigate immediately.\n\n— Kevin (Automated Security Monitor)"
        )

        # Send email notification
        emails_sent = 0
        if notify_email:
            graph_secrets = self.secrets.get_all("microsoft-graph")
            self._send_email_via_graph(
                graph_secrets, notify_email,
                subject=f"🚨 CRITICAL: {len(hits)} critical alert(s) detected",
                body=body,
            )
            emails_sent = 1

        # Also post to Slack if configured
        # (would need Slack token — future enhancement)

        return {
            "alerts_processed": len(hits),
            "emails_sent": emails_sent,
            "tickets_created": 0,
        }

    # ── Email Sending ───────────────────────────────────────────────

    def _send_ticket_email(
        self, to: str, agent_name: str, subject: str, body: str, priority: str
    ) -> None:
        """Send a ticket email via Graph API."""
        graph_secrets = self.secrets.get_all("microsoft-graph")

        priority_prefix = {"critical": "🚨 P1", "high": "⚠️ P2", "medium": "P3", "low": "P4"}
        full_subject = f"[{priority_prefix.get(priority, 'P3')}] {subject}"

        full_body = (
            f"{body}\n\n"
            f"---\n"
            f"Automated ticket created by Kevin (Security AI)\n"
            f"Host: {agent_name}\n"
            f"Priority: {priority.upper()}\n"
            f"Created: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
        )

        self._send_email_via_graph(graph_secrets, [to], full_subject, full_body)

    def _send_email_via_graph(
        self, graph_secrets: Dict, recipients: List[str], subject: str, body: str
    ) -> None:
        """Send email via Microsoft Graph API."""
        # Authenticate
        tenant_id = graph_secrets["tenant_id"]
        client_id = graph_secrets["client_id"]
        client_secret = graph_secrets["client_secret"]

        token_resp = self._http.post(
            f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
        )
        token_resp.raise_for_status()
        access_token = token_resp.json()["access_token"]

        mailbox = os.environ.get("KEVIN_MAILBOX", "kevin@heads-up.com")

        message = {
            "message": {
                "subject": subject,
                "body": {"contentType": "text", "content": body},
                "toRecipients": [
                    {"emailAddress": {"address": r}} for r in recipients
                ],
            }
        }

        resp = self._http.post(
            f"https://graph.microsoft.com/v1.0/users/{mailbox}/sendMail",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            },
            json=message,
        )
        resp.raise_for_status()
        logger.info("Sent email to %s: %s", recipients, subject)

    # ── Slack Commands ──────────────────────────────────────────────

    def _handle_command(self, envelope: MessageEnvelope) -> Optional[MessageEnvelope]:
        """Handle schedule management commands from Slack."""
        msg_type = envelope.message_type
        payload = envelope.payload

        if msg_type == "scheduler.command.list":
            return self._cmd_list_tasks(envelope)
        elif msg_type == "scheduler.command.run":
            return self._cmd_run_task(envelope, payload)
        elif msg_type == "scheduler.command.modify":
            return self._cmd_modify_task(envelope, payload)
        elif msg_type == "scheduler.command.enable":
            return self._cmd_toggle_task(envelope, payload, True)
        elif msg_type == "scheduler.command.disable":
            return self._cmd_toggle_task(envelope, payload, False)

        return None

    def _cmd_list_tasks(self, envelope: MessageEnvelope) -> MessageEnvelope:
        """List all scheduled tasks."""
        with self._db.cursor() as cur:
            cur.execute("""
                SELECT name, task_type, schedule, enabled, last_run, next_run
                FROM knowledge.scheduled_tasks
                ORDER BY name
            """)
            tasks = cur.fetchall()

        task_list = []
        for name, ttype, sched, enabled, last_run, next_run in tasks:
            task_list.append({
                "name": name,
                "type": ttype,
                "schedule": sched,
                "enabled": enabled,
                "last_run": str(last_run) if last_run else "never",
                "next_run": str(next_run) if next_run else "not scheduled",
            })

        return envelope.create_reply(
            source=self.service_name,
            message_type="scheduler.response.list",
            payload={"tasks": task_list},
        )

    def _cmd_run_task(self, envelope: MessageEnvelope, payload: Dict) -> MessageEnvelope:
        """Manually trigger a task."""
        task_name = payload.get("task_name", "")
        with self._db.cursor() as cur:
            cur.execute(
                "SELECT id, task_type, config FROM knowledge.scheduled_tasks WHERE name ILIKE %s",
                [f"%{task_name}%"],
            )
            row = cur.fetchone()

        if not row:
            return envelope.create_reply(
                source=self.service_name,
                message_type="scheduler.response.error",
                payload={"error": f"Task not found: {task_name}"},
            )

        task_id, task_type, config = row
        result = self._execute_task(task_type, config or {})

        return envelope.create_reply(
            source=self.service_name,
            message_type="scheduler.response.run",
            payload=result,
        )

    def _cmd_toggle_task(self, envelope: MessageEnvelope, payload: Dict, enabled: bool) -> MessageEnvelope:
        """Enable or disable a task."""
        task_name = payload.get("task_name", "")
        with self._db.cursor() as cur:
            cur.execute(
                "UPDATE knowledge.scheduled_tasks SET enabled = %s WHERE name ILIKE %s",
                [enabled, f"%{task_name}%"],
            )
            affected = cur.rowcount

        action = "enabled" if enabled else "disabled"
        return envelope.create_reply(
            source=self.service_name,
            message_type="scheduler.response.toggle",
            payload={"status": f"Task {action}", "affected": affected},
        )

    def _cmd_modify_task(self, envelope: MessageEnvelope, payload: Dict) -> MessageEnvelope:
        """
        Modify a scheduled task based on natural language request.
        Uses Haiku to parse the user's intent into structured changes.
        """
        user_text = payload.get("text", "")

        # Get current tasks for context
        with self._db.cursor() as cur:
            cur.execute("""
                SELECT name, task_type, schedule, enabled, config
                FROM knowledge.scheduled_tasks ORDER BY name
            """)
            tasks = cur.fetchall()

        tasks_context = json.dumps([
            {"name": t[0], "type": t[1], "schedule": t[2], "enabled": t[3], "config": t[4]}
            for t in tasks
        ], indent=2, default=str)

        # Use Haiku to parse the modification request
        try:
            resp = self._http.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5-20251001",
                    "max_tokens": 500,
                    "system": """Parse a user's request to modify a scheduled task. 
Current tasks:
""" + tasks_context + """

Respond with ONLY valid JSON:
{
    "task_name": "exact name of the task to modify",
    "changes": {
        "schedule": "new schedule if changing (cron or 'every Xm/h' format)",
        "enabled": true/false if toggling,
        "config": {"key": "value"} for any config changes
    },
    "description": "Brief description of what was changed"
}
Only include fields in "changes" that are actually being modified. If you can't determine what to change, set "error" instead.""",
                    "messages": [{"role": "user", "content": user_text}],
                },
                timeout=15,
            )
            resp.raise_for_status()

            text = ""
            for block in resp.json().get("content", []):
                if block.get("type") == "text":
                    text += block["text"]

            text = text.strip()
            if text.startswith("```"):
                text = text.split("\n", 1)[-1].rsplit("```", 1)[0]

            parsed = json.loads(text)

        except Exception as e:
            return envelope.create_reply(
                source=self.service_name,
                message_type="scheduler.response.modify",
                payload={"status": "error", "error": f"Could not parse modification: {e}"},
            )

        if "error" in parsed:
            return envelope.create_reply(
                source=self.service_name,
                message_type="scheduler.response.modify",
                payload={"status": "error", "error": parsed["error"]},
            )

        task_name = parsed.get("task_name", "")
        changes = parsed.get("changes", {})

        if not task_name or not changes:
            return envelope.create_reply(
                source=self.service_name,
                message_type="scheduler.response.modify",
                payload={"status": "error", "error": "Could not determine what to modify"},
            )

        # Apply changes
        updates = []
        params = []

        if "schedule" in changes:
            updates.append("schedule = %s")
            params.append(changes["schedule"])
            # Recalculate next_run
            next_run = self._calculate_next_run(changes["schedule"])
            if next_run:
                updates.append("next_run = %s")
                params.append(next_run)

        if "enabled" in changes:
            updates.append("enabled = %s")
            params.append(changes["enabled"])

        if "config" in changes and changes["config"]:
            # Merge config changes into existing config
            updates.append("config = config || %s::jsonb")
            params.append(json.dumps(changes["config"]))

        updates.append("updated_at = NOW()")

        if not updates:
            return envelope.create_reply(
                source=self.service_name,
                message_type="scheduler.response.modify",
                payload={"status": "error", "error": "No changes to apply"},
            )

        params.append(f"%{task_name}%")
        with self._db.cursor() as cur:
            cur.execute(
                f"UPDATE knowledge.scheduled_tasks SET {', '.join(updates)} WHERE name ILIKE %s",
                params,
            )
            affected = cur.rowcount

        result = {
            "status": "modified" if affected > 0 else "not_found",
            "task_name": task_name,
            "changes": changes,
            "description": parsed.get("description", ""),
            "affected": affected,
        }

        logger.info("Task modified: %s — %s", task_name, parsed.get("description", ""))

        return envelope.create_reply(
            source=self.service_name,
            message_type="scheduler.response.modify",
            payload=result,
        )

    # ── Service Metadata ────────────────────────────────────────────

    def get_capabilities(self) -> list:
        return ["scheduler.alert_sweep", "scheduler.daily_summary", "scheduler.critical_monitor"]

    def health_status(self) -> dict:
        status = {"healthy": True}
        try:
            with self._db.cursor() as cur:
                cur.execute("SELECT count(*) FROM knowledge.scheduled_tasks WHERE enabled = true")
                status["active_tasks"] = cur.fetchone()[0]
        except Exception:
            status["healthy"] = False
        return status

    def on_shutdown(self) -> None:
        self._running = False
        if self._http:
            self._http.close()
        if self._wazuh_http:
            self._wazuh_http.close()
        if self._db:
            self._db.close()


if __name__ == "__main__":
    service = SchedulerService.create("scheduler")
    service.run()
