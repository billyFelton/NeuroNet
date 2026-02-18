"""
Agent-Worker-Claude — Anthropic Claude AI worker.

Consumes ai.request messages from the Resolver, builds a prompt
with role-based system instructions and data context, calls the
Claude API, and publishes the response back to the originating
connector.

Features:
- Role-based system prompts (security-admin sees different instructions than general-user)
- Data context injection (sign-in logs, alerts, etc. from connectors)
- Conversation history for multi-turn threads
- Token usage and cost tracking via audit events
- Configurable model selection
"""

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

import httpx

from neurokit.envelope import (
    AIInteractionContext,
    EventType,
    MessageEnvelope,
)
from neurokit.service import BaseService

logger = logging.getLogger("agent-worker-claude")


# ── Role-Based System Prompts ───────────────────────────────────────

SYSTEM_PROMPTS = {
    "security-admin": """You are Kevin Tutela, a friendly and approachable security operations assistant 
at Heads Up Technologies. Your last name comes from the Latin word for "watchful care" and 
"guardianship" — which is exactly what you do. You're part of the team — think of yourself as 
the security-savvy coworker who's always happy to help, explains things clearly, and genuinely 
cares about keeping everyone safe.

About you (share when asked):
- Full name: Kevin Tutela
- Role: Security Operations AI Assistant at Heads Up Technologies
- Email: kevin@heads-up.com
- You monitor security alerts, analyze threats, manage scheduled security sweeps, 
  and help the IT and security teams stay on top of things
- Your name "Tutela" means watchful care and protection in Latin — you take that seriously
- You were built by the Heads Up Technologies team to be a helpful, proactive security teammate
- You have your own email inbox, run scheduled tasks (alert sweeps, daily summaries, 
  critical alert monitoring), and learn from conversations to get better over time

Your personality:
- Warm, conversational, and a bit witty — but never sarcastic or condescending
- You celebrate wins ("Nice catch!" "Good thinking asking about that")
- You keep things concise and readable — avoid walls of text, bullet-point overload, and markdown headers
- When things look bad, you stay calm and focused — reassuring but honest
- You speak like a teammate, not a robot reading a manual
- Use plain language first, technical details second

IMPORTANT — How your capabilities work:
- Security data is automatically retrieved and included in the [SYSTEM DATA] section below.
  When you see [SYSTEM DATA], that IS real data from real systems — analyze it and present 
  it to the user. NEVER ignore [SYSTEM DATA] and NEVER generate fake data request blocks.
- NEVER generate tags like [SYSTEM DATA REQUEST], [DATA REQUEST], or any placeholder blocks. 
  If data is present, use it. If data is NOT present, tell the user what to ask for.
- You do NOT have tools or function calls. But the system automatically fetches data before 
  your turn — so if [SYSTEM DATA] is present, that's real data you should use.
- You CAN send and reply to emails — the system handles this automatically when the user 
  asks you to. You have a real mailbox at kevin@heads-up.com.
- You CAN search other users' mailboxes when a security admin asks you to. The results 
  will appear in [SYSTEM DATA] — just present them clearly.
- When you receive email search results, present them in a clear, readable way showing 
  the mailbox that was searched, the query, and the matching emails.
- When asked to send an email, you MUST compose it in your response with these EXACT headers:
  **To:** recipient@domain.com
  **Subject:** Your subject here
  
  Your email body here.
  
  ---
  Kevin Tutela
  Security Operations AI Assistant
  
  The system parses your response and sends the email automatically. If you do NOT include
  **To:** and **Subject:** headers, the email WILL NOT be sent. Do NOT just say "I'll send it" —
  you must write out the full email in your response. The system confirms delivery afterward.

CRITICAL ANTI-HALLUCINATION RULES — VIOLATIONS ARE DANGEROUS:
- You are a SECURITY tool. Fabricating data can cause real harm — wrong people investigated,
  real threats missed, accounts wrongly disabled, panic over nonexistent incidents.
- NEVER invent, fabricate, estimate, or guess security data. This includes:
  • User accounts, email addresses, names, or profiles
  • Alert counts, severity levels, or alert descriptions
  • Agent counts, health percentages, or status
  • Risk scores, sign-in logs, MFA status, or IP addresses
  • Vulnerability counts, CVEs, or scan results
  • ANY specific numbers, metrics, percentages, or statistics
- If [SYSTEM DATA] is not present or is empty, say "I don't have that data right now" 
  and explain what the user can ask for or where to look manually.
- If data timed out or returned an error, say so honestly. NEVER fill gaps with plausible fiction.
- If you're unsure whether data is real or from your training knowledge, DO NOT present it.
  Only present data that appears in [SYSTEM DATA] blocks in the current conversation.
- When the user asks about a specific user, account, or security event: if you do NOT see 
  that information in [SYSTEM DATA], say "I don't have data on that person/event right now" — 
  do NOT make up a profile or risk assessment.
- It is ALWAYS better to say "I don't have that information" than to guess.

ACTION CONFIRMATION RULES — EQUALLY CRITICAL:
- NEVER claim an email was sent unless you see confirmation in [SYSTEM DATA] with a message ID.
  If the system did not return send confirmation, say "I attempted to send but didn't get 
  confirmation — let me check if it went through."
- NEVER fabricate sent folder contents, inbox contents, or email metadata.
  If asked to check a sent folder and no [SYSTEM DATA] is returned, say "I wasn't able to 
  retrieve that data right now."
- NEVER claim you performed an action (sent email, executed command, created ticket) unless 
  the system explicitly confirmed it in [SYSTEM DATA]. Presenting a formatted email in chat 
  is NOT the same as sending it — the email connector must process and confirm the send.
- If asked to send an email and no [SYSTEM DATA] confirmation appears, the email was NOT sent.
  Be honest: "It looks like the send didn't go through — the email connector may be down."
- NEVER fabricate ZenDesk ticket data. This includes ticket IDs, subjects, requesters, statuses,
  or any ticket details. If [SYSTEM DATA] does not contain ZenDesk results, say "I don't have 
  that ticket data right now" — do NOT make up a table of fake tickets.
- When asked to filter or narrow previous results and no new [SYSTEM DATA] is provided, say
  "I'd need to run a new search to filter those — try asking me to search tickets for [criteria]."
  Do NOT fabricate a filtered subset from memory.

You're talking to a Security Administrator who has full access. You can:
- Analyze Wazuh SIEM alerts, agent health, and vulnerability data from TWO Wazuh instances:
  • DESKTOPS — monitors workstations and endpoints (wazuh-dt)
  • INFRASTRUCTURE — monitors servers and network infrastructure (wazuh-inf)
  When data comes in labeled [DESKTOPS] or [INFRASTRUCTURE], always clearly identify which 
  instance it's from. If both are present, summarize each separately then give an overall picture.
- Review Microsoft EntraID user profiles, sign-in logs, MFA status, and risky users
- Search any user's mailbox or search org-wide across all mailboxes
- Recommend admin actions (disabling accounts, revoking sessions, policy changes)
- Provide remediation commands and investigation steps
- Read, send, and reply to emails from your mailbox (kevin@heads-up.com)
- Report on your scheduled tasks (alert sweeps, daily summaries, critical monitoring)
  and their recent results. You run these automatically — they're part of your job.
- Run PowerShell commands on remote Windows machines via WinRM for investigations
- Create, update, close, and search ZenDesk tickets for incident tracking
- Query Meraki network infrastructure: devices, clients, VLANs, DHCP, uplinks, device status

MERAKI NETWORK:
When asked about network infrastructure, the system queries Meraki automatically and returns 
results in [SYSTEM DATA]. Use this data to answer questions about:
- Network devices (switches, APs, appliances) and their status (online/offline)
- Connected clients — who/what is on the network, their IP, MAC, VLAN, switchport
- VLANs and subnets configuration
- DHCP settings and reservations
- WAN/uplink status
- Client lookup by IP, MAC, or hostname (e.g., "what port is 10.20.1.50 on?")
NEVER fabricate Meraki data. If [SYSTEM DATA] doesn't contain network info, say so.

ZENDESK TICKET MANAGEMENT:
When asked to create a ticket, compose it in your response with these EXACT headers:
**Ticket Subject:** Your subject here
**Ticket Priority:** normal/high/urgent/low
**Ticket Type:** incident/problem/question/task
**Ticket Body:**
Description of the ticket here.

The system parses your response and creates the ticket automatically.
When asked to update, close, or comment on a ticket, include:
**Ticket ID:** 12345
**Action:** update/close/comment
**Details:** What to change or the comment text

For searching tickets, the system queries ZenDesk automatically and returns results in [SYSTEM DATA].

POWERSHELL REMOTE EXECUTION:
When the user asks you to investigate a host (check processes, services, connections, 
event logs, scheduled tasks, etc.), you can propose a PowerShell command to run remotely.

How it works:
1. You determine the right PowerShell command for the investigation
2. You present it to the user with: the target host, the exact command, and your reasoning
3. You generate a short request ID (8 hex characters) and ask them to reply "approve <id>"
4. If they approve, the command executes via WinRM and you analyze the results
5. If they deny, you acknowledge and suggest alternatives

IMPORTANT — Host Resolution:
- The system automatically resolves hostnames to IP addresses from Wazuh agent data.
- You MUST use the HOSTNAME only (e.g., DC1-HUT, DESKTOP-ABC). Do NOT include IP addresses.
- NEVER guess, invent, or include IP addresses in your proposals — the system resolves them.
- If you don't know the hostname, ask the user. Never fabricate hostnames or IPs.
- Do NOT prefix commands with "powershell" — just include the PowerShell command itself.

Format your proposals EXACTLY like this:
"I'd like to run the following on **DC1-HUT**:
```
Get-Process | Sort-Object CPU -Descending | Select -First 20
```
This will show us the top CPU-consuming processes to check for anything suspicious.
Reply **approve a1b2c3d4** to execute, or **deny a1b2c3d4** to cancel."

CRITICAL: Do NOT put an IP address after the hostname. Write "on **HOSTNAME**:" only.
The system will resolve the IP automatically. Including an IP causes parsing failures.

Generate the request ID as 8 random lowercase hex characters. Be specific about what 
the command does and why you're proposing it. Never auto-execute — always wait for approval.

When you receive PowerShell results in [SYSTEM DATA], analyze them in the context of the 
investigation. Look for anomalies, suspicious processes, unusual connections, etc.

When you receive security data in [SYSTEM DATA], give a clear summary first ("Here's what I'm seeing..."), 
then dig into the details. Flag anything urgent right away. If you spot patterns or 
correlations, call them out. Always be actionable — tell them what to do, not just what happened.

When you do NOT receive security data, be honest: "I wasn't able to retrieve that data" or 
"That data source didn't respond." Never fill in with made-up details.

Keep your responses focused and human. A short, clear answer beats a comprehensive essay.""",

    "security-analyst": """You are Kevin Tutela, a friendly security operations assistant at Heads Up Technologies. 
Your last name means "watchful care" in Latin — and that's exactly what you bring to the team.
You're the approachable security teammate who makes complex data easy to understand.

Your personality:
- Warm, clear, and conversational — you explain things without talking down to people
- You keep responses concise and scannable
- You're encouraging and collaborative

IMPORTANT: Security data is automatically provided to you in [SYSTEM DATA] blocks. 
You do NOT have tools or function calls. NEVER generate XML tool calls or API invocations.
Just analyze the data you're given. If you need more data, ask the user to rephrase their question.

CRITICAL: NEVER fabricate, invent, or guess security data — no fake users, alerts, metrics, 
risk scores, or statistics. If [SYSTEM DATA] is not present, say "I don't have that data right now."
You are a security tool — made-up data can cause real harm.

You're talking to a Security Analyst. You can:
- Analyze Wazuh SIEM alerts, agent health, and vulnerability data from BOTH Wazuh instances:
  • DESKTOPS — monitors workstations and endpoints (wazuh-dt)
  • INFRASTRUCTURE — monitors servers and network infrastructure (wazuh-inf)
- Review EntraID user profiles, group memberships, sign-in logs, and MFA status
- Identify patterns, anomalies, and potential threats
- Suggest investigation steps and provide context
- Send and reply to emails from your mailbox (kevin@heads-up.com)
- Report on your scheduled tasks and their recent results

You CANNOT:
- Search other users' mailboxes — that requires Security Admin access
- Perform write actions (disable accounts, revoke sessions, block IPs, isolate hosts)
- If something needs a write action, let them know they'll need a Security Administrator 
  and offer to help frame the escalation""",

    "it-support": """You are Kevin Tutela, a friendly IT support assistant at Heads Up Technologies.
You're the helpful coworker who knows the systems inside and out and makes troubleshooting easy.

Your personality:
- Friendly, patient, and clear — you keep things simple and actionable
- You're great at walking people through problems step by step
- You explain technical concepts without jargon unless needed

IMPORTANT: Security and system data is automatically provided to you in [SYSTEM DATA] blocks.
You do NOT have tools or function calls. Just analyze the data you're given.

CRITICAL: NEVER fabricate, invent, or guess security data — no fake users, alerts, metrics,
or statistics. If [SYSTEM DATA] is not present, say "I don't have that data right now."

You're talking to someone on the IT Support team. You can:
- Analyze Wazuh SIEM alerts, agent health, and vulnerability data from BOTH Wazuh instances:
  • DESKTOPS — monitors workstations and endpoints (wazuh-dt)
  • INFRASTRUCTURE — monitors servers and network infrastructure (wazuh-inf)
- Look up EntraID user profiles, group memberships, sign-in logs, and MFA status
- Check device/agent status and help troubleshoot endpoint issues
- Review vulnerability scan results
- Help with general IT troubleshooting and security best practices

You CANNOT:
- Send or read emails from Kevin's mailbox
- Search other users' mailboxes
- Perform any write actions (disable accounts, revoke sessions, reset passwords, block IPs)
- If something needs a write action or email investigation, refer them to the security team""",

    "general-user": """You are Kevin Tutela, a friendly assistant at Heads Up Technologies.
You're the approachable coworker who helps people with security awareness and general questions.

Your personality:
- Warm, patient, and conversational — never condescending
- You explain things in plain language, avoiding jargon
- You keep responses concise and actionable

What you CAN help with:
- How to spot phishing emails, suspicious links, and social engineering
- How to report phishing or suspicious activity
- Current trends in cyber threats (ransomware, BEC, credential stuffing, etc.)
- Password best practices, MFA, and account security
- Safe browsing, public Wi-Fi risks, and mobile device security
- Data handling — what's sensitive, how to share files securely
- Physical security awareness (tailgating, clean desk policy)
- What to do if you think you've been compromised
- General IT and workplace questions

When someone asks about security alerts, system status, monitoring, incidents, 
vulnerabilities, specific users, or anything involving internal security data:
- Say: "I'm not authorized to share that information. You can discuss current 
  security issues with someone on the Heads Up security team."
- Then follow up by asking: "Are you currently experiencing any technical issues 
  I might be able to help with?"
- Do NOT explain what you monitor, what tools exist, what systems are online,
  or anything about the company's security infrastructure
- Do NOT offer to "pull data" or "dig into" anything security-related
- Do NOT mention Wazuh, SIEM, agents, connectors, EntraID, or any internal tool names
- Do NOT reference any previous security conversations or knowledge about alerts

CRITICAL RULES:
- NEVER reveal what security tools or monitoring systems the company uses
- NEVER describe the security architecture or what is being monitored
- NEVER fabricate or reference any security data, alerts, or system status
- Keep your responses focused on general security awareness education
- You are a security awareness coach, not a security operations tool""",
}

DEFAULT_SYSTEM_PROMPT = SYSTEM_PROMPTS["general-user"]


# ── Cost Estimation ─────────────────────────────────────────────────

# Approximate pricing per 1M tokens (update as pricing changes)
MODEL_PRICING = {
    "claude-sonnet-4-5-20250929": {"input": 3.00, "output": 15.00},
    "claude-haiku-4-5-20251001": {"input": 0.80, "output": 4.00},
    "claude-opus-4-5-20250918": {"input": 15.00, "output": 75.00},
}


class ClaudeWorker(BaseService):
    """
    Claude AI worker service.

    Consumes ai.request messages, calls the Anthropic API,
    and publishes ai.response messages.
    """

    def __init__(self, config):
        super().__init__(config)
        self._api_key: str = ""
        self._model: str = "claude-sonnet-4-5-20250929"
        self._max_tokens: int = 4096
        self._http: Optional[httpx.Client] = None
        self._kb_conn = None  # Knowledge base DB connection

    def on_startup(self) -> None:
        """Retrieve credentials and connect to knowledge base."""
        anthropic_secrets = self.secrets.get_all("anthropic")
        self._api_key = anthropic_secrets["api_key"]
        self._model = anthropic_secrets.get("default_model", self._model)
        self._max_tokens = int(anthropic_secrets.get("max_tokens", "4096"))

        self._http = httpx.Client(timeout=120)

        # RabbitMQ management API for health checks
        self._rmq_mgmt_url = "http://{}:15672/api".format(
            os.environ.get("RABBITMQ_HOST", "rabbitmq")
        )
        self._rmq_mgmt_auth = (
            os.environ.get("RABBITMQ_USERNAME", "neuro"),
            os.environ.get("RABBITMQ_PASSWORD", ""),
        )
        self._neuronet_status_cache: str = ""
        self._neuronet_status_ts: float = 0

        # Connect to knowledge base
        try:
            import psycopg2
            kb_host = os.environ.get("KB_DB_HOST", "vault-db")
            kb_user = os.environ.get("KB_DB_USER", "vault_iam")
            kb_pass = os.environ.get("KB_DB_PASSWORD", "")
            kb_name = os.environ.get("KB_DB_NAME", "neuro_vault")
            self._kb_conn = psycopg2.connect(
                host=kb_host, user=kb_user, password=kb_pass,
                dbname=kb_name, connect_timeout=5,
            )
            self._kb_conn.autocommit = True
            logger.info("Connected to knowledge base")

            # Ensure user memory tables exist
            try:
                with self._kb_conn.cursor() as cur:
                    # User profiles — Kevin's relationship memory
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS knowledge.user_profiles (
                            id SERIAL PRIMARY KEY,
                            user_email VARCHAR(255) NOT NULL UNIQUE,
                            display_name VARCHAR(255),
                            first_name VARCHAR(100),
                            preferred_name VARCHAR(100),
                            job_title VARCHAR(255),
                            department VARCHAR(255),
                            manager_email VARCHAR(255),
                            location VARCHAR(255),
                            timezone VARCHAR(100),
                            first_interaction TIMESTAMPTZ,
                            last_interaction TIMESTAMPTZ,
                            total_interactions INT DEFAULT 0,
                            rapport_notes TEXT DEFAULT '',
                            preferences JSONB DEFAULT '{}',
                            work_context JSONB DEFAULT '{}',
                            created_at TIMESTAMPTZ DEFAULT NOW(),
                            updated_at TIMESTAMPTZ DEFAULT NOW()
                        )
                    """)

                    # Message history — every exchange, channel-independent
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS knowledge.message_history (
                            id BIGSERIAL PRIMARY KEY,
                            user_email VARCHAR(255) NOT NULL,
                            agent_id VARCHAR(100) NOT NULL DEFAULT 'kevin',
                            role VARCHAR(20) NOT NULL,
                            content TEXT NOT NULL,
                            channel_type VARCHAR(50),
                            channel_id VARCHAR(255),
                            intent VARCHAR(100),
                            had_data BOOLEAN DEFAULT FALSE,
                            data_sources TEXT[],
                            model_used VARCHAR(100),
                            input_tokens INT,
                            output_tokens INT,
                            created_at TIMESTAMPTZ DEFAULT NOW()
                        )
                    """)
                    cur.execute("""
                        CREATE INDEX IF NOT EXISTS idx_message_history_user_time
                        ON knowledge.message_history (user_email, created_at DESC)
                    """)

                    # Conversation sessions — rolling summaries
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS knowledge.conversation_sessions (
                            id SERIAL PRIMARY KEY,
                            user_email VARCHAR(255) NOT NULL,
                            agent_id VARCHAR(100) NOT NULL DEFAULT 'kevin',
                            summary TEXT NOT NULL DEFAULT '',
                            topic TEXT DEFAULT '',
                            key_entities TEXT[] DEFAULT '{}',
                            open_questions TEXT[] DEFAULT '{}',
                            last_action TEXT DEFAULT '',
                            message_count INT DEFAULT 0,
                            started_at TIMESTAMPTZ DEFAULT NOW(),
                            updated_at TIMESTAMPTZ DEFAULT NOW(),
                            UNIQUE (user_email, agent_id)
                        )
                    """)

                    # Auto-update triggers
                    cur.execute("""
                        CREATE OR REPLACE FUNCTION knowledge.auto_update_timestamp()
                        RETURNS TRIGGER AS $$
                        BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
                        $$ LANGUAGE plpgsql
                    """)
                    for tbl in ['user_profiles', 'conversation_sessions']:
                        cur.execute(f"""
                            DROP TRIGGER IF EXISTS trg_{tbl}_updated ON knowledge.{tbl}
                        """)
                        cur.execute(f"""
                            CREATE TRIGGER trg_{tbl}_updated
                            BEFORE UPDATE ON knowledge.{tbl}
                            FOR EACH ROW EXECUTE FUNCTION knowledge.auto_update_timestamp()
                        """)

                logger.info("User memory tables ready (profiles, history, sessions)")

                # Asset inventory table — needs its own cursor
                try:
                    with self._kb_conn.cursor() as cur2:
                        cur2.execute("""
                            CREATE TABLE IF NOT EXISTS knowledge.assets (
                                id SERIAL PRIMARY KEY,
                                asset_type VARCHAR(50) NOT NULL,
                                hostname VARCHAR(255),
                                fqdn VARCHAR(255),
                                aliases TEXT[] DEFAULT '{}',
                                ip_addresses TEXT[] DEFAULT '{}',
                                mac_addresses TEXT[] DEFAULT '{}',
                                vlan VARCHAR(50),
                                subnet VARCHAR(50),
                                network_zone VARCHAR(100),
                                os VARCHAR(255),
                                os_version VARCHAR(100),
                                device_model VARCHAR(255),
                                manufacturer VARCHAR(255),
                                owner_email VARCHAR(255),
                                department VARCHAR(255),
                                location VARCHAR(255),
                                environment VARCHAR(50),
                                purpose TEXT,
                                criticality VARCHAR(20) DEFAULT 'medium',
                                services JSONB DEFAULT '{}',
                                installed_software JSONB DEFAULT '{}',
                                parent_asset_id INT,
                                related_assets TEXT[] DEFAULT '{}',
                                wazuh_agent_id VARCHAR(100),
                                wazuh_instance VARCHAR(50),
                                last_vulnerability_scan TIMESTAMPTZ,
                                known_issues TEXT[] DEFAULT '{}',
                                notes TEXT DEFAULT '',
                                tags TEXT[] DEFAULT '{}',
                                learned_from VARCHAR(100),
                                confidence FLOAT DEFAULT 0.5,
                                first_seen TIMESTAMPTZ DEFAULT NOW(),
                                last_seen TIMESTAMPTZ DEFAULT NOW(),
                                created_at TIMESTAMPTZ DEFAULT NOW(),
                                updated_at TIMESTAMPTZ DEFAULT NOW(),
                                UNIQUE (hostname, asset_type)
                            )
                        """)
                        cur2.execute("""
                            CREATE INDEX IF NOT EXISTS idx_assets_hostname
                            ON knowledge.assets (hostname)
                        """)
                        cur2.execute("""
                            CREATE INDEX IF NOT EXISTS idx_assets_ip
                            ON knowledge.assets USING GIN (ip_addresses)
                        """)
                        cur2.execute("""
                            CREATE INDEX IF NOT EXISTS idx_assets_tags
                            ON knowledge.assets USING GIN (tags)
                        """)
                    logger.info("Asset inventory table ready")
                except Exception as e:
                    logger.warning("Could not create asset table: %s", e)
            except Exception as e:
                logger.warning("Could not create memory tables: %s", e)
        except Exception as e:
            logger.warning("Knowledge base not available: %s", e)
            self._kb_conn = None

        self.audit.log_system(
            action="claude_worker_started",
            resource="anthropic-api",
            details={"model": self._model, "knowledge_base": self._kb_conn is not None},
        )

    def _get_neuronet_status(self) -> str:
        """
        Query RabbitMQ management API to determine which services are online.
        Caches for 30 seconds to avoid hammering the API.
        """
        now = time.time()
        if self._neuronet_status_cache and (now - self._neuronet_status_ts) < 30:
            return self._neuronet_status_cache

        # Known services and their expected queue names
        service_map = {
            "connector-wazuh (Desktops)": "neuro.wazuh.inbox",
            "connector-wazuh-infra (Infrastructure)": "neuro.wazuh-infra.inbox",
            "connector-slack": "neuro.connector-slack.responses",
            "connector-email (M365)": "neuro.connector-email.inbox",
            "connector-entraid (EntraID/Azure AD)": "neuro.connector-entraid.inbox",
            "connector-powershell (Remote Execution)": "neuro.connector-powershell.inbox",
            "connector-zendesk (ZenDesk Tickets)": "neuro.zendesk.inbox",
            "connector-meraki (Meraki Network)": "neuro.connector-meraki.inbox",
            "resolver (RBAC Gateway)": "neuro.resolver.inbox",
            "scheduler": "neuro.scheduler.inbox",
            "vault-audit": "neuro.vault.audit",
        }

        # Also check alternate queue names (naming inconsistencies)
        alternate_names = {
            "connector-wazuh-infra (Infrastructure)": "neuro.connector-connector-wazuh.inbox",
        }

        try:
            import urllib.parse
            vhost = os.environ.get("RABBITMQ_VHOST", "/neuro")
            vhost_encoded = urllib.parse.quote(vhost, safe="")
            resp = self._http.get(
                f"{self._rmq_mgmt_url}/queues/{vhost_encoded}",
                auth=self._rmq_mgmt_auth,
                timeout=5,
            )
            if resp.status_code != 200:
                logger.warning("RabbitMQ management API returned %d", resp.status_code)
                return self._neuronet_status_cache or ""

            queues = {q["name"]: q.get("consumers", 0) for q in resp.json()}

            lines = ["[NEURONET STATUS — Live service health]"]
            for service, queue_name in service_map.items():
                consumers = queues.get(queue_name, 0)
                # Check alternate queue names if primary not found
                if consumers == 0 and service in alternate_names:
                    alt_name = alternate_names[service]
                    consumers = queues.get(alt_name, 0)
                    if consumers > 0:
                        queue_name = alt_name

                if consumers > 0:
                    status = "✅ ONLINE"
                elif queue_name in queues:
                    status = "⚠️ QUEUE EXISTS, NO CONSUMERS (service may be down)"
                else:
                    status = "❌ NOT CONNECTED (no queue — connector not deployed)"
                lines.append(f"  {service}: {status}")

            # Add summary
            online = sum(1 for s, q in service_map.items() if queues.get(q, 0) > 0)
            total = len(service_map)
            lines.append(f"\nSummary: {online}/{total} services online")
            lines.append(
                "When a data source shows NOT CONNECTED, tell the user that connector "
                "isn't deployed yet — do NOT fabricate data from that source."
            )

            self._neuronet_status_cache = "\n".join(lines)
            self._neuronet_status_ts = now
            return self._neuronet_status_cache

        except Exception as e:
            logger.warning("Could not check NeuroNet status: %s", e)
            return self._neuronet_status_cache or ""

    def setup_queues(self) -> None:
        """Set up RabbitMQ queue for AI requests."""
        self.inbox = self.rmq.declare_queue(
            "agent-worker-claude.inbox",
            routing_keys=["ai.request"],
        )
        self.rmq.consume(self.inbox, self.handle_message)

    def handle_message(self, envelope: MessageEnvelope) -> None:
        """
        Process an AI request:
        1. Select system prompt based on user's highest role
        2. Build message array with history and data context
        3. Call Claude API
        4. Publish response back to the originating connector
        """
        payload = envelope.payload
        actor = envelope.actor

        user_text = payload.get("text", "")
        history = payload.get("history", [])
        intent = payload.get("intent", "general")
        data_context = payload.get("data_context", {})

        # Select system prompt based on role hierarchy
        system_prompt = self._select_system_prompt(actor.roles if actor else [])

        # Inject who Kevin is talking to
        if actor:
            user_context = f"\n\n[CURRENT USER] You are talking to {actor.display_name or 'an unknown user'}"
            if actor.email:
                user_context += f" ({actor.email})"
            if actor.roles:
                user_context += f" — Roles: {', '.join(actor.roles)}"
            user_context += ". Address them by first name when natural."
            system_prompt += user_context

        # Determine if this is a privileged user
        user_roles = actor.roles if actor else []
        is_privileged = any(r in user_roles for r in ["security-admin", "security-analyst", "it-support"])

        # Retrieve relevant knowledge (security data only for privileged users)
        if is_privileged:
            knowledge_context = self._get_relevant_knowledge(user_text, intent)
            if knowledge_context:
                system_prompt += "\n\n" + knowledge_context
                logger.info("Injected knowledge base context (%d chars)", len(knowledge_context))
            else:
                logger.info("No relevant knowledge found for query")

        # Company policies and approved tools — available to ALL users
        policy_context = self._get_relevant_policies(user_text)
        if policy_context:
            system_prompt += "\n\n" + policy_context
            logger.info("Injected company policy context (%d chars)", len(policy_context))

        # Load user memory — profile, active session, recent history
        user_email = actor.email if actor else "unknown"
        self._ensure_user_profile(actor)
        user_memory = self._get_user_memory(user_email)
        if user_memory:
            system_prompt += "\n\n" + user_memory
            logger.info("Injected user memory (%d chars)", len(user_memory))

        # Inject NeuroNet health status (only for privileged users)
        if is_privileged:
            neuronet_status = self._get_neuronet_status()
            if neuronet_status:
                system_prompt += "\n\n" + neuronet_status

        # Build the messages array for Claude
        messages = self._build_messages(user_text, history, data_context, intent)

        # Call Claude API
        start_time = time.time()
        try:
            response_data = self._call_claude(system_prompt, messages)
        except Exception as e:
            logger.error("Claude API error: %s", e, exc_info=True)
            self._send_error(envelope, f"AI service temporarily unavailable: {e}")
            return

        latency_ms = int((time.time() - start_time) * 1000)

        # Extract response
        response_text = ""
        for block in response_data.get("content", []):
            if block.get("type") == "text":
                response_text += block["text"]

        usage = response_data.get("usage", {})
        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)
        model_used = response_data.get("model", self._model)

        # Estimate cost
        cost_usd = self._estimate_cost(model_used, input_tokens, output_tokens)

        # Build AI interaction context for audit
        import hashlib
        prompt_hash = hashlib.sha256(
            json.dumps(messages, sort_keys=True).encode()
        ).hexdigest()[:16]
        response_hash = hashlib.sha256(
            response_text.encode()
        ).hexdigest()[:16]

        ai_context = AIInteractionContext(
            model=model_used,
            provider="anthropic",
            request_id=response_data.get("id", ""),
            prompt_hash=prompt_hash,
            response_hash=response_hash,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
            estimated_cost_usd=cost_usd,
        )

        # Audit the AI interaction
        self.audit.log_from_envelope(
            envelope=envelope,
            event_type=EventType.AI_INTERACTION,
            action="claude_api_call",
            resource=f"anthropic/{model_used}",
            details={
                "intent": intent,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "latency_ms": latency_ms,
                "cost_usd": float(cost_usd),
                "stop_reason": response_data.get("stop_reason"),
            },
        )

        logger.info(
            "Claude response: user=%s intent=%s tokens=%d+%d latency=%dms cost=$%.4f",
            actor.email if actor else "unknown",
            intent,
            input_tokens,
            output_tokens,
            latency_ms,
            cost_usd,
        )

        # Build and publish response
        reply = envelope.create_reply(
            source=self.service_name,
            message_type="ai.response",
            payload={
                "text": response_text,
                "model": model_used,
                "intent": intent,
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                    "cost_usd": float(cost_usd),
                },
            },
        )
        reply.ai_interaction = ai_context

        # Route back to the connector via the reply_to key
        reply_key = envelope.reply_to or "ai.response"
        self.rmq.publish(reply_key, reply)

        # Check if Kevin proposed a PowerShell command — store it via the connector
        try:
            self._check_powershell_proposal(response_text, envelope)
        except Exception as e:
            logger.debug("PowerShell proposal check failed: %s", e)

        # Check if Kevin composed an email to send — forward to email connector
        try:
            if intent in ("email_send",):
                logger.info("Email send intent detected, checking response for email content...")
                self._check_email_send(response_text, envelope)
        except Exception as e:
            logger.error("Email send check failed: %s", e, exc_info=True)

        # Check if Kevin composed a ZenDesk ticket — forward to ZenDesk connector
        try:
            if intent in ("zendesk_create",):
                logger.info("ZenDesk create intent detected, checking response for ticket content...")
                self._check_zendesk_create(response_text, envelope)
            elif intent in ("zendesk_update", "zendesk_comment"):
                logger.info("ZenDesk update/comment intent detected, checking response...")
                self._check_zendesk_update(response_text, envelope, intent)
        except Exception as e:
            logger.error("ZenDesk check failed: %s", e, exc_info=True)

        # Extract and store knowledge from the conversation (async, non-blocking)
        try:
            self._extract_knowledge(
                user_text, response_text, intent,
                actor.email if actor else "unknown",
                data_context,
            )
        except Exception as e:
            logger.debug("Knowledge extraction failed: %s", e)

        # Update conversation summary for context retention
        try:
            self._update_conversation_summary(
                user_email=actor.email if actor else "unknown",
                user_text=user_text,
                response_text=response_text,
                intent=intent,
                data_context=data_context,
            )
        except Exception as e:
            logger.debug("Conversation summary update failed: %s", e)

        # Store messages in Kevin's own history
        u_email = actor.email if actor else "unknown"
        data_keys = [k for k in data_context.keys() if k != "_timeout_notice"] if data_context else []
        self._store_message(u_email, "user", user_text, intent=intent,
                            had_data=bool(data_context), data_sources=data_keys)
        self._store_message(u_email, "assistant", response_text, intent=intent,
                            model_used=model_used, input_tokens=input_tokens,
                            output_tokens=output_tokens)

        # Learn about the user from this conversation
        try:
            self._update_user_profile_from_conversation(
                user_email=u_email,
                user_text=user_text,
                response_text=response_text,
            )
        except Exception as e:
            logger.debug("Profile learning failed: %s", e)

    # ── Prompt Construction ─────────────────────────────────────────

    def _select_system_prompt(self, roles: List[str]) -> str:
        """Select system prompt based on highest-privilege role."""
        # Role hierarchy: security-admin > security-analyst > it-support > general-user
        role_priority = ["security-admin", "security-analyst", "it-support", "general-user"]
        for role in role_priority:
            if role in roles:
                return SYSTEM_PROMPTS.get(role, DEFAULT_SYSTEM_PROMPT)
        return DEFAULT_SYSTEM_PROMPT

    def _build_messages(
        self,
        user_text: str,
        history: List[Dict[str, str]],
        data_context: Dict[str, Any],
        intent: str = "general",
    ) -> List[Dict[str, str]]:
        """
        Build the messages array for the Claude API.

        Structure:
        1. Conversation history (previous turns)
        2. Data context (injected as a system-like user message)
        3. Current user message
        """
        messages = []

        # Add conversation history
        for msg in history:
            messages.append({
                "role": msg.get("role", "user"),
                "content": msg.get("content", ""),
            })

        # Inject data context — ALWAYS tell Claude what data is/isn't available
        if data_context:
            context_text = self._format_data_context(data_context)
            if context_text:
                messages.append({
                    "role": "user",
                    "content": (
                        "[SYSTEM DATA — The following data was retrieved from "
                        "internal systems in response to the user's query. "
                        "Use ONLY this data to answer their question. "
                        "Do NOT invent or supplement with made-up data.]\n\n"
                        f"{context_text}\n\n"
                        "[END SYSTEM DATA]"
                    ),
                })
                messages.append({
                    "role": "assistant",
                    "content": "I've received the system data. Let me analyze this for you.",
                })
            else:
                # Data was requested but came back empty
                messages.append({
                    "role": "user",
                    "content": (
                        "[SYSTEM DATA — NO DATA RETURNED]\n"
                        "The system attempted to retrieve data but received NO results.\n"
                        "IMPORTANT INSTRUCTIONS:\n"
                        "- DO NOT fabricate, invent, or guess ANY data whatsoever.\n"
                        "- DO NOT blame Microsoft, APIs, or timeouts — the data source may simply not be connected yet.\n"
                        "- DO NOT reference any user names, profiles, or details — you have ZERO data.\n"
                        "- Tell the user: 'I wasn't able to retrieve that data — the data source didn't return any results.'\n"
                        "- Suggest they check the relevant admin portal manually.\n"
                        "- Keep it short and honest.\n"
                        "[END SYSTEM DATA]"
                    ),
                })
                messages.append({
                    "role": "assistant",
                    "content": "Understood — no data was returned. I will not fabricate any information.",
                })
        else:
            # No data_context at all — if intent suggests data was expected, say so
            data_intents = [
                "security_alerts", "infra_alerts", "desktop_alerts",
                "vulnerability_query", "agent_status",
                "signin_logs", "mfa_status", "risky_users",
                "user_lookup", "group_lookup", "device_lookup",
                "email_search_mailbox", "email_search_org", "email_list",
            ]
            if intent in data_intents:
                messages.append({
                    "role": "user",
                    "content": (
                        "[SYSTEM DATA — NO DATA AVAILABLE]\n"
                        f"The system tried to fetch data for intent '{intent}' but the data "
                        "source is not connected or did not respond.\n"
                        "IMPORTANT INSTRUCTIONS:\n"
                        "- DO NOT fabricate, invent, or guess ANY data whatsoever.\n"
                        "- DO NOT make up user profiles, alert counts, risk scores, or any other data.\n"
                        "- DO NOT blame Microsoft APIs or network issues — just say the data source isn't available.\n"
                        "- Tell the user: 'I don't have access to that data source yet' or 'That data source isn't connected.'\n"
                        "- Suggest what they can ask you instead (e.g., Wazuh alerts, email search).\n"
                        "[END SYSTEM DATA]"
                    ),
                })
                messages.append({
                    "role": "assistant",
                    "content": "Understood — that data source isn't available. I will not fabricate any information.",
                })

        # Add the current user message
        messages.append({
            "role": "user",
            "content": user_text,
        })

        return messages

    def _format_data_context(self, data_context: Dict[str, Any]) -> str:
        """Format connector data for injection into the prompt."""
        sections = []

        for key, data in data_context.items():
            if not data:
                continue

            # Handle timeout notice
            if key == "_timeout_notice":
                sections.append(f"[⚠️ DATA TIMEOUT] {data.get('message', 'Some data sources did not respond.')}")
                continue

            # Format based on data type
            if "signin-logs" in key or "signin_logs" in key:
                sections.append(self._format_signin_data(data))
            elif "mfa" in key:
                sections.append(self._format_mfa_data(data))
            elif "risky" in key:
                sections.append(self._format_risky_users_data(data))
            elif "alerts" in key:
                sections.append(self._format_alerts_data(data))
            elif "email" in key:
                sections.append(self._format_email_data(data))
            elif "user" in key:
                sections.append(self._format_user_data(data))
            else:
                # Generic JSON formatting with truncation
                json_str = json.dumps(data, indent=2, default=str)
                if len(json_str) > 4000:
                    json_str = json_str[:4000] + "\n... [truncated]"
                sections.append(f"### Data: {key}\n```json\n{json_str}\n```")

        return "\n\n".join(sections)

    def _format_signin_data(self, data: Dict) -> str:
        """Format sign-in log data for the prompt."""
        summary = data.get("summary", {})
        logs = data.get("logs", [])

        text = "### Sign-in Log Data\n"
        if summary:
            text += f"**Summary**: {summary.get('total', 0)} sign-ins, "
            text += f"{summary.get('failures', 0)} failures, "
            text += f"{summary.get('risky_signins', 0)} risky, "
            text += f"{summary.get('unique_ips', 0)} unique IPs\n"
            if summary.get("top_locations"):
                text += f"**Top locations**: {summary['top_locations']}\n"
            if summary.get("top_apps"):
                text += f"**Top apps**: {summary['top_apps']}\n"

        # Include first N logs as detail
        if logs:
            text += f"\n**Recent events** (showing {min(len(logs), 10)} of {len(logs)}):\n"
            for log in logs[:10]:
                status = log.get("status", {})
                error_code = status.get("errorCode", 0)
                status_str = "✓" if error_code == 0 else f"✗ (error {error_code})"
                text += (
                    f"- {log.get('createdDateTime', '?')} | "
                    f"{log.get('userDisplayName', '?')} | "
                    f"{log.get('appDisplayName', '?')} | "
                    f"{log.get('ipAddress', '?')} | "
                    f"{status_str} | "
                    f"risk: {log.get('riskLevelDuringSignIn', 'none')}\n"
                )

        return text

    def _format_mfa_data(self, data: Dict) -> str:
        """Format MFA status data."""
        text = "### MFA Status\n"
        text += f"**User**: {data.get('user_id', '?')}\n"
        text += f"**MFA registered**: {'Yes' if data.get('mfa_registered') else 'No'}\n"
        text += f"**Methods**: {', '.join(data.get('methods', []))}\n"
        return text

    def _format_risky_users_data(self, data: Dict) -> str:
        """Format risky users data."""
        users = data.get("risky_users", [])
        text = f"### Risky Users ({len(users)} found)\n"
        for u in users[:20]:
            text += (
                f"- {u.get('userDisplayName', '?')} ({u.get('userPrincipalName', '?')}) | "
                f"risk: {u.get('riskLevel', '?')} | "
                f"state: {u.get('riskState', '?')} | "
                f"last updated: {u.get('riskLastUpdatedDateTime', '?')}\n"
            )
        return text

    def _format_alerts_data(self, data: Dict) -> str:
        """Format Wazuh alert data."""
        alerts = data.get("alerts", [])
        instance = data.get("wazuh_instance", "")
        label = f" [{instance.upper()}]" if instance else ""
        text = f"### Security Alerts{label} ({len(alerts)} found)\n"
        for a in alerts[:20]:
            text += (
                f"- [{a.get('rule', {}).get('level', '?')}] "
                f"{a.get('rule', {}).get('description', '?')} | "
                f"agent: {a.get('agent', {}).get('name', '?')} | "
                f"time: {a.get('timestamp', '?')}\n"
            )
        return text

    def _format_email_data(self, data: Dict) -> str:
        """Format email data for the prompt."""
        data_type = data.get("type", "")
        messages = data.get("messages", [])
        
        if not messages:
            # Could be a single email read
            email = data.get("email")
            if email:
                return (
                    f"### Email\n"
                    f"**From**: {email.get('from', {}).get('name', '')} <{email.get('from', {}).get('email', '')}>\n"
                    f"**Subject**: {email.get('subject', '(no subject)')}\n"
                    f"**Received**: {email.get('received_at', '?')}\n"
                    f"**Body**:\n{email.get('body', '')[:2000]}\n"
                )
            # Send/reply confirmation
            status = data.get("status", "")
            if status == "sent":
                return f"### Email Sent\nTo: {', '.join(data.get('to', []))}\nSubject: {data.get('subject', '')}\n"
            if status == "replied":
                return f"### Email Reply Sent\nMessage ID: {data.get('message_id', '')}\n"
            if status == "error":
                return f"### Email Error\n{data.get('error', 'Unknown error')}\n"
            return ""

        # Determine header based on data type
        if data_type == "mailbox_search":
            mailbox = data.get("mailbox", "unknown")
            query = data.get("query", "")
            header = f"### Mailbox Search Results — {mailbox} (query: \"{query}\", {len(messages)} result(s))\n"
        elif data_type == "org_search":
            query = data.get("query", "")
            searched = data.get("mailboxes_searched", 0)
            header = f"### Org-wide Email Search (query: \"{query}\", {len(messages)} result(s) across {searched} mailboxes)\n"
        else:
            header = f"### Kevin's Inbox ({len(messages)} emails)\n"

        text = header
        for msg in messages[:20]:
            read_marker = "" if msg.get("is_read", True) else " [UNREAD]"
            attach = " [📎]" if msg.get("has_attachments") else ""
            mailbox_prefix = f"[{msg.get('mailbox', '')}] " if msg.get("mailbox") else ""
            text += (
                f"- {mailbox_prefix}{msg.get('received_at', '?')} | "
                f"{msg.get('from_name', '')} <{msg.get('from_email', '')}> | "
                f"\"{msg.get('subject', '(no subject)')}\""
                f"{read_marker}{attach}\n"
                f"  Preview: {msg.get('preview', '')[:150]}\n"
                f"  [ID: {msg.get('message_id', '')[:20]}...]\n"
            )

        if data.get("errors"):
            text += f"\nSearch errors: {', '.join(data['errors'][:3])}\n"

        return text

    def _format_user_data(self, data: Dict) -> str:
        """Format user profile data."""
        user = data.get("user", data)
        text = "### User Profile\n"
        text += f"**Name**: {user.get('displayName', '?')}\n"
        text += f"**Email**: {user.get('mail', '?')}\n"
        text += f"**UPN**: {user.get('userPrincipalName', '?')}\n"
        text += f"**Title**: {user.get('jobTitle', '?')}\n"
        text += f"**Department**: {user.get('department', '?')}\n"
        text += f"**Account enabled**: {user.get('accountEnabled', '?')}\n"
        return text

    # ── Knowledge Extraction ────────────────────────────────────────

    EXTRACTION_PROMPT = """Analyze this conversation exchange and extract any facts worth remembering 
for future conversations. Focus on:
- Host/device information (hostnames, IPs, OS, roles, owners, issues, services running)
- Network topology facts (subnets, VLANs, zones, gateways, DNS)
- Ongoing incidents or problems
- User preferences or workflows
- Policy or configuration details
- Anything the user explicitly asked you to remember

Return ONLY a JSON array of facts to store. Each fact should have:
- "category": one of "host", "network", "incident", "policy", "contact", "general"
- "subject": short identifier (hostname, topic name)
- "content": the fact in a clear sentence
- "tags": array of relevant keywords

For host/device facts, also include:
- "asset_type": "server", "workstation", "network_device", "printer", "appliance", "vm", "container", "application", "service"
- "hostname": the hostname if mentioned
- "ip": IP address if mentioned
- "os": operating system if mentioned
- "purpose": what the device does
- "owner": who owns/manages it
- "criticality": "critical", "high", "medium", "low"

If there are no new facts worth storing, return an empty array: []

IMPORTANT: Only extract concrete, factual information. Do not store opinions, 
generic security advice, or things already commonly known. Be selective — 
quality over quantity.

Return ONLY valid JSON, no markdown, no explanation."""

    def _extract_knowledge(
        self,
        user_text: str,
        response_text: str,
        intent: str,
        user_email: str,
        data_context: Dict[str, Any],
    ) -> None:
        """Extract facts from the conversation and store in knowledge base."""
        if not self._kb_conn:
            return

        # Skip extraction for very short or general chitchat
        if len(user_text) < 20 and intent == "general":
            return

        # Check for explicit "remember" commands
        text_lower = user_text.lower()
        explicit_remember = any(phrase in text_lower for phrase in [
            "remember that", "remember this", "don't forget",
            "note that", "keep in mind", "fyi",
            "for future reference", "store this",
        ])

        # For non-explicit, only extract from security-related conversations
        if not explicit_remember and intent == "general" and not data_context:
            return

        try:
            extraction_input = f"User ({user_email}): {user_text}\n\nKevin's response: {response_text[:1500]}"

            # Add data context summary if present
            if data_context:
                context_keys = list(data_context.keys())
                extraction_input += f"\n\n[Data sources consulted: {', '.join(context_keys)}]"

            response = self._http.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5-20251001",  # Use Haiku for extraction (cheap + fast)
                    "max_tokens": 1000,
                    "system": self.EXTRACTION_PROMPT,
                    "messages": [{"role": "user", "content": extraction_input}],
                },
                timeout=15,
            )
            response.raise_for_status()

            # Parse the response
            result_text = ""
            for block in response.json().get("content", []):
                if block.get("type") == "text":
                    result_text += block["text"]

            # Clean and parse JSON
            result_text = result_text.strip()
            if result_text.startswith("```"):
                result_text = result_text.split("\n", 1)[-1].rsplit("```", 1)[0]

            facts = json.loads(result_text)

            if not facts or not isinstance(facts, list):
                return

            # Store each fact
            stored = 0
            assets_stored = 0
            with self._kb_conn.cursor() as cur:
                for fact in facts[:5]:  # Max 5 facts per exchange
                    category = fact.get("category", "general")
                    subject = fact.get("subject", "")
                    content = fact.get("content", "")
                    tags = fact.get("tags", [])

                    if not subject or not content:
                        continue

                    # Upsert knowledge entry
                    cur.execute("""
                        INSERT INTO knowledge.entries 
                            (category, subject, content, source, tags, created_by)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT DO NOTHING
                    """, [
                        category, subject, content,
                        f"conversation:{intent}", tags, user_email,
                    ])
                    stored += 1

                    # If this is a host/device fact, also store in assets table
                    if category in ("host", "network") and fact.get("hostname"):
                        try:
                            cur.execute("""
                                INSERT INTO knowledge.assets
                                    (asset_type, hostname, ip_addresses, os, purpose,
                                     owner_email, criticality, notes, tags,
                                     learned_from, confidence)
                                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 'conversation', 0.6)
                                ON CONFLICT (hostname, asset_type) DO UPDATE SET
                                    ip_addresses = CASE 
                                        WHEN EXCLUDED.ip_addresses != '{}' THEN EXCLUDED.ip_addresses
                                        ELSE knowledge.assets.ip_addresses END,
                                    os = COALESCE(NULLIF(EXCLUDED.os, ''), knowledge.assets.os),
                                    purpose = COALESCE(NULLIF(EXCLUDED.purpose, ''), knowledge.assets.purpose),
                                    owner_email = COALESCE(NULLIF(EXCLUDED.owner_email, ''), knowledge.assets.owner_email),
                                    notes = CASE
                                        WHEN knowledge.assets.notes = '' THEN EXCLUDED.notes
                                        ELSE knowledge.assets.notes || '; ' || EXCLUDED.notes END,
                                    last_seen = NOW()
                            """, [
                                fact.get("asset_type", "server"),
                                fact["hostname"],
                                [fact["ip"]] if fact.get("ip") else [],
                                fact.get("os", ""),
                                fact.get("purpose", ""),
                                fact.get("owner", ""),
                                fact.get("criticality", "medium"),
                                content,
                                tags,
                            ])
                            assets_stored += 1
                        except Exception:
                            pass  # Non-fatal

            if stored > 0:
                logger.info("Stored %d knowledge facts, %d assets from conversation",
                            stored, assets_stored)

        except json.JSONDecodeError:
            logger.debug("Knowledge extraction returned invalid JSON")
        except Exception as e:
            logger.debug("Knowledge extraction error: %s", e)

    # ── User Memory & Conversation Context ─────────────────────────

    SUMMARY_PROMPT = """You are a conversation state tracker. Given the previous summary and a new exchange, 
produce an updated summary of the conversation so far. Focus on:

1. WHAT is being discussed (topics, specific users/hosts/alerts/incidents)
2. WHAT the user asked for or wants to accomplish
3. WHAT you (Kevin) found, reported, or recommended
4. WHAT is still unresolved or pending
5. KEY ENTITIES mentioned (usernames, emails, hostnames, IPs, alert IDs)

Also extract:
- "topic": a 2-5 word label for the current conversation topic
- "entities": array of key identifiers (emails, hostnames, IPs) mentioned
- "open_items": array of unresolved questions or pending actions
- "last_action": what Kevin last did or recommended

Return ONLY valid JSON:
{
  "summary": "Updated conversational summary in 2-4 sentences",
  "topic": "short topic label",
  "entities": ["user@example.com", "hostname", "10.0.0.1"],
  "open_items": ["Pending: disable mchen account", "Need to check mailbox activity"],
  "last_action": "Recommended disabling mchen and revoking sessions"
}

Keep the summary concise — max 200 words. Carry forward important context from the previous summary.
Return ONLY valid JSON, no markdown, no explanation."""

    PROFILE_UPDATE_PROMPT = """Analyze this conversation and extract any personal or professional 
information about the user worth remembering for future interactions.

Current known profile:
{current_profile}

New exchange:
{exchange}

Return ONLY valid JSON (empty object {{}} if nothing new to learn):
{{
  "preferred_name": "nickname if mentioned",
  "preferences": {{
    "interests": ["hobbies, likes"],
    "communication_style": "how they prefer info",
    "fun_facts": ["personal tidbits"]
  }},
  "work_context": {{
    "responsibilities": ["work duties"],
    "systems_owned": ["systems they manage"],
    "projects": ["active projects"],
    "team_members": ["colleagues by email"]
  }},
  "rapport_notes": "relationship observations (brief)"
}}

Only extract concrete facts actually stated. Do NOT guess.
Return ONLY valid JSON, no markdown."""

    def _get_user_memory(self, user_email: str) -> str:
        """Load Kevin's full memory about this user — profile + active session + recent history."""
        if not self._ensure_kb_connection():
            return ""

        sections = []

        try:
            # Load user profile
            with self._kb_conn.cursor() as cur:
                cur.execute("""
                    SELECT display_name, first_name, preferred_name, job_title,
                           department, manager_email, location, timezone,
                           first_interaction, total_interactions,
                           rapport_notes, preferences, work_context
                    FROM knowledge.user_profiles
                    WHERE user_email = %s
                """, [user_email])
                profile = cur.fetchone()

                if profile:
                    (name, first, preferred, title, dept, manager, loc, tz,
                     first_int, total, rapport, prefs, work) = profile

                    lines = ["[USER PROFILE — What you know about this person]"]
                    lines.append(f"Name: {name or 'Unknown'}" +
                                 (f" (goes by {preferred})" if preferred else ""))
                    if title:
                        lines.append(f"Title: {title}")
                    if dept:
                        lines.append(f"Department: {dept}")
                    if manager:
                        lines.append(f"Manager: {manager}")
                    if loc:
                        lines.append(f"Location: {loc}")
                    if total:
                        lines.append(f"You've had {total} conversations with them" +
                                     (f" since {first_int.strftime('%B %Y')}" if first_int else ""))
                    if rapport:
                        lines.append(f"Notes: {rapport}")

                    if prefs and isinstance(prefs, dict):
                        pref_items = []
                        for k, v in prefs.items():
                            if isinstance(v, list) and v:
                                pref_items.append(f"{k}: {', '.join(str(x) for x in v)}")
                            elif v:
                                pref_items.append(f"{k}: {v}")
                        if pref_items:
                            lines.append("Preferences: " + "; ".join(pref_items))

                    if work and isinstance(work, dict):
                        work_items = []
                        for k, v in work.items():
                            if isinstance(v, list) and v:
                                work_items.append(f"{k}: {', '.join(str(x) for x in v)}")
                            elif v:
                                work_items.append(f"{k}: {v}")
                        if work_items:
                            lines.append("Work context: " + "; ".join(work_items))

                    lines.append(
                        "Use this knowledge naturally. Don't recite their profile back to them."
                    )
                    sections.append("\n".join(lines))

            # Load conversation session
            with self._kb_conn.cursor() as cur:
                cur.execute("""
                    SELECT summary, topic, key_entities, open_questions, last_action,
                           message_count, updated_at
                    FROM knowledge.conversation_sessions
                    WHERE user_email = %s AND agent_id = 'kevin'
                    AND updated_at > NOW() - INTERVAL '4 hours'
                    LIMIT 1
                """, [user_email])
                session = cur.fetchone()

                if session:
                    summary, topic, entities, open_items, last_action, msg_count, _ = session
                    if summary:
                        lines = ["[ACTIVE CONVERSATION — What you've been discussing]"]
                        if topic:
                            lines.append(f"Topic: {topic}")
                        lines.append(f"Summary ({msg_count} messages): {summary}")
                        if entities:
                            lines.append(f"Key entities: {', '.join(entities)}")
                        if open_items:
                            lines.append(f"Pending items: {'; '.join(open_items)}")
                        if last_action:
                            lines.append(f"Your last action: {last_action}")
                        lines.append(
                            "Maintain continuity — the user expects you to remember this."
                        )
                        sections.append("\n".join(lines))

            # Load recent message history as fallback context
            with self._kb_conn.cursor() as cur:
                cur.execute("""
                    SELECT role, content, created_at
                    FROM knowledge.message_history
                    WHERE user_email = %s AND agent_id = 'kevin'
                    ORDER BY created_at DESC
                    LIMIT 10
                """, [user_email])
                recent = cur.fetchall()

                if recent and not session:
                    recent.reverse()
                    lines = ["[RECENT HISTORY — Last few exchanges with this user]"]
                    for role, content, ts in recent:
                        speaker = "User" if role == "user" else "Kevin"
                        snippet = content[:150] + "..." if len(content) > 150 else content
                        lines.append(f"  {speaker}: {snippet}")
                    sections.append("\n".join(lines))

        except Exception as e:
            logger.debug("Could not load user memory: %s", e)

        return "\n\n".join(sections) if sections else ""

    def _ensure_user_profile(self, actor) -> None:
        """Create or update user profile from actor info + IAM/EntraID data."""
        if not actor or not actor.email or not self._ensure_kb_connection():
            return

        try:
            # Check if this is a new user (no profile yet)
            is_new = False
            with self._kb_conn.cursor() as cur:
                cur.execute("""
                    SELECT id FROM knowledge.user_profiles WHERE user_email = %s
                """, [actor.email])
                is_new = cur.fetchone() is None

            # For new users, pull rich data from IAM database
            job_title = getattr(actor, 'job_title', None)
            department = getattr(actor, 'department', None)
            manager_email = None
            office_location = None
            work_ctx = {}

            if is_new:
                try:
                    with self._kb_conn.cursor() as cur:
                        # Get user details from IAM
                        cur.execute("""
                            SELECT u.job_title, u.department, u.account_enabled,
                                   u.mfa_enabled, u.last_sign_in,
                                   u.manager_email, u.office_location,
                                   u.mobile_phone, u.employee_id
                            FROM iam.users u
                            WHERE u.email = %s
                        """, [actor.email])
                        iam_row = cur.fetchone()
                        if iam_row:
                            job_title = iam_row[0] or job_title
                            department = iam_row[1] or department
                            account_enabled = iam_row[2]
                            mfa_enabled = iam_row[3]
                            last_sign_in = iam_row[4]
                            manager_email = iam_row[5]
                            office_location = iam_row[6]
                            mobile_phone = iam_row[7]
                            employee_id = iam_row[8]

                        # Get group memberships
                        cur.execute("""
                            SELECT g.name FROM iam.groups g
                            JOIN iam.user_groups ug ON g.id = ug.group_id
                            JOIN iam.users u ON u.id = ug.user_id
                            WHERE u.email = %s
                        """, [actor.email])
                        groups = [r[0] for r in cur.fetchall()]

                        # Get role assignments
                        cur.execute("""
                            SELECT r.name FROM iam.roles r
                            JOIN iam.user_roles ur ON r.id = ur.role_id
                            JOIN iam.users u ON u.id = ur.user_id
                            WHERE u.email = %s
                        """, [actor.email])
                        roles = [r[0] for r in cur.fetchall()]

                        # Build work context from IAM data
                        work_ctx = {}
                        if groups:
                            work_ctx["groups"] = groups
                        if roles:
                            work_ctx["roles"] = roles
                        if mfa_enabled is not None:
                            work_ctx["mfa_enabled"] = mfa_enabled
                        if account_enabled is not None:
                            work_ctx["account_enabled"] = account_enabled
                        if mobile_phone:
                            work_ctx["mobile_phone"] = mobile_phone
                        if employee_id:
                            work_ctx["employee_id"] = employee_id

                        logger.info(
                            "Seeding profile for %s from IAM: title=%s dept=%s manager=%s groups=%d roles=%d",
                            actor.email, job_title, department, manager_email,
                            len(groups), len(roles),
                        )
                except Exception as e:
                    logger.debug("Could not fetch IAM data for profile: %s", e)
                    work_ctx = {}

            with self._kb_conn.cursor() as cur:
                # Build work_context JSON if we have it
                work_context_json = json.dumps(work_ctx) if is_new and work_ctx else '{}'

                cur.execute("""
                    INSERT INTO knowledge.user_profiles
                        (user_email, display_name, first_name, job_title,
                         department, manager_email, location, work_context,
                         first_interaction, last_interaction, total_interactions)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s::jsonb, NOW(), NOW(), 1)
                    ON CONFLICT (user_email) DO UPDATE SET
                        display_name = COALESCE(EXCLUDED.display_name, knowledge.user_profiles.display_name),
                        first_name = COALESCE(EXCLUDED.first_name, knowledge.user_profiles.first_name),
                        job_title = COALESCE(NULLIF(EXCLUDED.job_title, ''), knowledge.user_profiles.job_title),
                        department = COALESCE(NULLIF(EXCLUDED.department, ''), knowledge.user_profiles.department),
                        manager_email = COALESCE(NULLIF(EXCLUDED.manager_email, ''), knowledge.user_profiles.manager_email),
                        location = COALESCE(NULLIF(EXCLUDED.location, ''), knowledge.user_profiles.location),
                        work_context = CASE
                            WHEN EXCLUDED.work_context != '{}'::jsonb
                            THEN knowledge.user_profiles.work_context || EXCLUDED.work_context
                            ELSE knowledge.user_profiles.work_context END,
                        last_interaction = NOW(),
                        total_interactions = knowledge.user_profiles.total_interactions + 1
                """, [
                    actor.email,
                    actor.display_name,
                    actor.display_name.split()[0] if actor.display_name else None,
                    job_title,
                    department,
                    manager_email if is_new else None,
                    office_location if is_new else None,
                    work_context_json,
                ])
        except Exception as e:
            logger.debug("Could not update user profile: %s", e)

    def _store_message(
        self, user_email: str, role: str, content: str,
        intent: str = "", channel_type: str = "slack_dm",
        had_data: bool = False, data_sources: list = None,
        model_used: str = None, input_tokens: int = None, output_tokens: int = None,
    ) -> None:
        """Store a message in Kevin's own history."""
        if not self._ensure_kb_connection():
            return
        try:
            with self._kb_conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO knowledge.message_history
                        (user_email, agent_id, role, content, channel_type,
                         intent, had_data, data_sources, model_used,
                         input_tokens, output_tokens)
                    VALUES (%s, 'kevin', %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, [
                    user_email, role, content[:5000], channel_type,
                    intent, had_data, data_sources or [],
                    model_used, input_tokens, output_tokens,
                ])
        except Exception as e:
            logger.debug("Could not store message: %s", e)

    def _get_conversation_summary(self, user_email: str) -> str:
        """Deprecated — use _get_user_memory instead."""
        return ""

    def _update_conversation_summary(
        self, user_email: str, user_text: str, response_text: str,
        intent: str, data_context: Dict[str, Any],
    ) -> None:
        """Update rolling conversation summary after each exchange."""
        if not self._ensure_kb_connection():
            return

        existing_summary = ""
        try:
            with self._kb_conn.cursor() as cur:
                cur.execute("""
                    SELECT summary, message_count
                    FROM knowledge.conversation_sessions
                    WHERE user_email = %s AND agent_id = 'kevin'
                    AND updated_at > NOW() - INTERVAL '4 hours'
                """, [user_email])
                row = cur.fetchone()
                if row:
                    existing_summary = row[0] or ""
        except Exception:
            pass

        summary_input = ""
        if existing_summary:
            summary_input += f"PREVIOUS SUMMARY: {existing_summary}\n\n"
        summary_input += f"NEW EXCHANGE:\nUser ({user_email}): {user_text}\n"
        summary_input += f"Kevin: {response_text[:1000]}\n"
        if data_context:
            data_keys = [k for k in data_context.keys() if k != "_timeout_notice"]
            if data_keys:
                summary_input += f"[Data sources used: {', '.join(data_keys)}]\n"

        try:
            response = self._http.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5-20251001",
                    "max_tokens": 500,
                    "system": self.SUMMARY_PROMPT,
                    "messages": [{"role": "user", "content": summary_input}],
                },
                timeout=15,
            )
            response.raise_for_status()

            result_text = ""
            for block in response.json().get("content", []):
                if block.get("type") == "text":
                    result_text += block["text"]

            result_text = result_text.strip()
            if result_text.startswith("```"):
                result_text = result_text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()

            parsed = json.loads(result_text)
            summary = parsed.get("summary", "")
            if not summary:
                return

            with self._kb_conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO knowledge.conversation_sessions
                        (user_email, agent_id, summary, topic, key_entities,
                         open_questions, last_action, message_count)
                    VALUES (%s, 'kevin', %s, %s, %s, %s, %s, 1)
                    ON CONFLICT (user_email, agent_id) DO UPDATE SET
                        summary = EXCLUDED.summary,
                        topic = EXCLUDED.topic,
                        key_entities = EXCLUDED.key_entities,
                        open_questions = EXCLUDED.open_questions,
                        last_action = EXCLUDED.last_action,
                        message_count = knowledge.conversation_sessions.message_count + 1
                """, [user_email, summary, parsed.get("topic", ""),
                      parsed.get("entities", []), parsed.get("open_items", []),
                      parsed.get("last_action", "")])

            logger.info("Updated session for %s: topic=%s", user_email, parsed.get("topic", ""))

        except json.JSONDecodeError:
            logger.debug("Session summary returned invalid JSON")
        except Exception as e:
            logger.debug("Session summary update error: %s", e)

    def _update_user_profile_from_conversation(
        self, user_email: str, user_text: str, response_text: str,
    ) -> None:
        """Use Haiku to extract personal/professional info and update user profile."""
        if not self._ensure_kb_connection():
            return

        # Skip very short exchanges
        if len(user_text) < 15:
            return

        current_profile = "{}"
        try:
            with self._kb_conn.cursor() as cur:
                cur.execute("""
                    SELECT preferred_name, rapport_notes, preferences, work_context
                    FROM knowledge.user_profiles WHERE user_email = %s
                """, [user_email])
                row = cur.fetchone()
                if row:
                    current_profile = json.dumps({
                        "preferred_name": row[0] or "",
                        "rapport_notes": row[1] or "",
                        "preferences": row[2] or {},
                        "work_context": row[3] or {},
                    }, indent=2)
        except Exception:
            pass

        exchange = f"User: {user_text}\nKevin: {response_text[:800]}"
        prompt = self.PROFILE_UPDATE_PROMPT.format(
            current_profile=current_profile, exchange=exchange,
        )

        try:
            response = self._http.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self._api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-haiku-4-5-20251001",
                    "max_tokens": 500,
                    "system": prompt,
                    "messages": [{"role": "user", "content": exchange}],
                },
                timeout=15,
            )
            response.raise_for_status()

            result_text = ""
            for block in response.json().get("content", []):
                if block.get("type") == "text":
                    result_text += block["text"]

            result_text = result_text.strip()
            if result_text.startswith("```"):
                result_text = result_text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()

            updates = json.loads(result_text)
            if not updates or updates == {}:
                return

            with self._kb_conn.cursor() as cur:
                if updates.get("preferred_name"):
                    cur.execute("""
                        UPDATE knowledge.user_profiles
                        SET preferred_name = %s WHERE user_email = %s
                    """, [updates["preferred_name"], user_email])

                if updates.get("rapport_notes"):
                    cur.execute("""
                        UPDATE knowledge.user_profiles
                        SET rapport_notes = CASE
                            WHEN rapport_notes = '' THEN %s
                            ELSE rapport_notes || '; ' || %s
                        END WHERE user_email = %s
                    """, [updates["rapport_notes"], updates["rapport_notes"], user_email])

                if updates.get("preferences"):
                    cur.execute("""
                        UPDATE knowledge.user_profiles
                        SET preferences = preferences || %s::jsonb WHERE user_email = %s
                    """, [json.dumps(updates["preferences"]), user_email])

                if updates.get("work_context"):
                    cur.execute("""
                        UPDATE knowledge.user_profiles
                        SET work_context = work_context || %s::jsonb WHERE user_email = %s
                    """, [json.dumps(updates["work_context"]), user_email])

            logger.info("Updated user profile for %s: %s", user_email, list(updates.keys()))

        except json.JSONDecodeError:
            logger.debug("Profile update returned invalid JSON")
        except Exception as e:
            logger.debug("Profile update error: %s", e)

    # ── Knowledge Base ───────────────────────────────────────────────

    def _ensure_kb_connection(self) -> bool:
        """Ensure the knowledge base connection is alive, reconnect if needed."""
        if self._kb_conn:
            try:
                with self._kb_conn.cursor() as cur:
                    cur.execute("SELECT 1")
                return True
            except Exception:
                logger.info("Knowledge base connection stale, reconnecting...")
                try:
                    self._kb_conn.close()
                except Exception:
                    pass
                self._kb_conn = None

        # Reconnect
        try:
            import psycopg2
            kb_host = os.environ.get("KB_DB_HOST", "vault-db")
            kb_user = os.environ.get("KB_DB_USER", "vault_iam")
            kb_pass = os.environ.get("KB_DB_PASSWORD", "")
            kb_name = os.environ.get("KB_DB_NAME", "neuro_vault")
            self._kb_conn = psycopg2.connect(
                host=kb_host, user=kb_user, password=kb_pass,
                dbname=kb_name, connect_timeout=5,
            )
            self._kb_conn.autocommit = True
            logger.info("Reconnected to knowledge base")
            return True
        except Exception as e:
            logger.warning("Knowledge base reconnect failed: %s", e)
            self._kb_conn = None
            return False

    def _get_relevant_knowledge(self, user_text: str, intent: str) -> str:
        """Query the knowledge base for facts relevant to the user's message."""
        if not self._ensure_kb_connection():
            return ""

        try:
            sections = []

            # Build search terms — strip punctuation from words
            import re
            words = [re.sub(r'[^\w\-]', '', w) for w in user_text.split()]
            search_words = [w for w in words if len(w) > 3]
            ilike_patterns = [f"%{w}%" for w in search_words]

            logger.info("Knowledge search: text=%r words=%s", user_text[:80], search_words)

            # Full-text search on knowledge entries
            with self._kb_conn.cursor() as cur:
                cur.execute("""
                    SELECT category, subject, content, confidence
                    FROM knowledge.entries
                    WHERE (expires_at IS NULL OR expires_at > NOW())
                    AND (
                        to_tsvector('english', subject || ' ' || content) 
                        @@ plainto_tsquery('english', %s)
                        OR subject ILIKE ANY(%s)
                    )
                    ORDER BY confidence DESC, updated_at DESC
                    LIMIT 10
                """, [user_text, ilike_patterns])
                entries = cur.fetchall()
                logger.info("Knowledge query returned %d entries", len(entries))

                if entries:
                    facts = []
                    for cat, subj, content, conf in entries:
                        facts.append(f"[{cat}] {subj}: {content}")
                    sections.append(
                        "[KNOWLEDGE BASE — Facts you've learned about this environment]\n"
                        + "\n".join(facts)
                    )

            # Check for known assets mentioned in the message
            with self._kb_conn.cursor() as cur:
                words = [w.strip(".,!?") for w in user_text.split() if len(w) > 2]
                if words:
                    try:
                        cur.execute("""
                            SELECT hostname, asset_type, ip_addresses, os, purpose,
                                   owner_email, environment, criticality, network_zone,
                                   notes, wazuh_instance
                            FROM knowledge.assets
                            WHERE hostname ILIKE ANY(%s)
                               OR fqdn ILIKE ANY(%s)
                               OR %s && aliases
                            ORDER BY criticality DESC, last_seen DESC
                            LIMIT 5
                        """, [
                            [f"%{w}%" for w in words],
                            [f"%{w}%" for w in words],
                            words,
                        ])
                        assets = cur.fetchall()

                        if assets:
                            asset_info = []
                            for a in assets:
                                parts = [f"{a[1].title()}: {a[0]}"]
                                if a[2]: parts.append(f"IPs: {', '.join(a[2][:3])}")
                                if a[3]: parts.append(f"OS: {a[3]}")
                                if a[4]: parts.append(f"Purpose: {a[4]}")
                                if a[5]: parts.append(f"Owner: {a[5]}")
                                if a[6]: parts.append(f"Env: {a[6]}")
                                if a[7]: parts.append(f"Criticality: {a[7]}")
                                if a[8]: parts.append(f"Zone: {a[8]}")
                                if a[9]: parts.append(f"Notes: {a[9]}")
                                if a[10]: parts.append(f"Monitored by: wazuh-{a[10]}")
                                asset_info.append(" | ".join(parts))
                            sections.append(
                                "[KNOWN ASSETS — Devices/hosts you know about]\n" + "\n".join(asset_info)
                            )
                    except Exception:
                        pass  # Table might not exist yet

            # Check for open incidents
            with self._kb_conn.cursor() as cur:
                cur.execute("""
                    SELECT title, status, severity, affected_hosts, description
                    FROM knowledge.incidents
                    WHERE status IN ('open', 'investigating')
                    ORDER BY 
                        CASE severity 
                            WHEN 'critical' THEN 1 
                            WHEN 'high' THEN 2 
                            WHEN 'medium' THEN 3 
                            ELSE 4 
                        END,
                        updated_at DESC
                    LIMIT 5
                """)
                incidents = cur.fetchall()

                if incidents:
                    inc_info = []
                    for title, status, sev, hosts, desc in incidents:
                        inc_info.append(
                            f"[{sev.upper()}] {title} (status: {status})"
                            + (f" — Affected: {', '.join(hosts)}" if hosts else "")
                            + (f"\n  {desc[:200]}" if desc else "")
                        )
                    sections.append(
                        "[OPEN INCIDENTS]\n" + "\n".join(inc_info)
                    )

            # Check for scheduled tasks — include if user asks about tasks/schedule,
            # or always include a brief summary so Kevin knows what he's doing
            with self._kb_conn.cursor() as cur:
                text_lower = user_text.lower()
                task_relevant = any(w in text_lower for w in [
                    "schedule", "task", "sweep", "monitor", "summary",
                    "daily", "cron", "automat", "proactive", "routine",
                    "ticket", "recurring", "job",
                ])

                if task_relevant:
                    # Full detail
                    cur.execute("""
                        SELECT name, task_type, schedule, enabled, last_run, next_run,
                               config, last_result
                        FROM knowledge.scheduled_tasks
                        ORDER BY enabled DESC, name
                    """)
                    tasks = cur.fetchall()
                    if tasks:
                        task_info = []
                        for name, ttype, sched, enabled, last_run, next_run, config, last_result in tasks:
                            status = "ENABLED" if enabled else "DISABLED"
                            last = last_run.strftime("%Y-%m-%d %H:%M UTC") if last_run else "never"
                            nxt = next_run.strftime("%Y-%m-%d %H:%M UTC") if next_run else "not scheduled"
                            cfg = json.dumps(config)[:150] if config else ""
                            result_summary = ""
                            if last_result:
                                result_summary = f" | Last result: {json.dumps(last_result)[:100]}"
                            task_info.append(
                                f"- {name} [{status}] (type: {ttype})\n"
                                f"  Schedule: {sched} | Last run: {last} | Next run: {nxt}\n"
                                f"  Config: {cfg}{result_summary}"
                            )
                        sections.append(
                            "[YOUR SCHEDULED TASKS — These are tasks you run automatically]\n"
                            + "\n".join(task_info)
                        )
                else:
                    # Brief awareness — just active task count and next upcoming
                    cur.execute("""
                        SELECT count(*), min(next_run)
                        FROM knowledge.scheduled_tasks
                        WHERE enabled = true
                    """)
                    count, next_run = cur.fetchone()
                    if count and count > 0:
                        nxt = next_run.strftime("%H:%M UTC") if next_run else "?"
                        sections.append(
                            f"[SCHEDULED TASKS] You have {count} active scheduled task(s). Next run: {nxt}"
                        )

            # Check for audit log queries
            audit_relevant = any(w in text_lower for w in [
                "audit", "activity", "who accessed", "who queried", "usage",
                "denied", "rbac", "access log", "what happened", "history",
                "who used", "api cost", "ai cost", "token usage",
            ])

            if audit_relevant:
                with self._kb_conn.cursor() as cur:
                    # Check if audit schema exists
                    cur.execute("""
                        SELECT EXISTS (
                            SELECT FROM information_schema.tables 
                            WHERE table_schema = 'audit' AND table_name = 'events'
                        )
                    """)
                    audit_exists = cur.fetchone()[0]

                    if audit_exists:
                        # Recent activity summary
                        cur.execute("""
                            SELECT event_type, action, outcome_status, actor_email,
                                   resource, timestamp, outcome_details
                            FROM audit.events
                            ORDER BY timestamp DESC
                            LIMIT 20
                        """)
                        events = cur.fetchall()

                        if events:
                            audit_info = []
                            for etype, action, outcome, email, resource, ts, details in events:
                                ts_str = ts.strftime("%Y-%m-%d %H:%M") if ts else "?"
                                audit_info.append(
                                    f"  {ts_str} | {etype} | {action} | "
                                    f"{email or 'system'} | {resource or '-'} | {outcome}"
                                )
                            sections.append(
                                "[AUDIT LOG — Recent Activity]\n"
                                + "\n".join(audit_info)
                            )

                        # RBAC denials
                        cur.execute("""
                            SELECT count(*) FROM audit.events
                            WHERE event_type = 'authorization' AND outcome_status = 'denied'
                            AND timestamp > NOW() - interval '24 hours'
                        """)
                        denial_count = cur.fetchone()[0]
                        if denial_count > 0:
                            cur.execute("""
                                SELECT actor_email, action, resource, timestamp,
                                       auth_denied_reason
                                FROM audit.events
                                WHERE event_type = 'authorization' AND outcome_status = 'denied'
                                AND timestamp > NOW() - interval '24 hours'
                                ORDER BY timestamp DESC LIMIT 10
                            """)
                            denials = cur.fetchall()
                            denial_info = []
                            for email, action, resource, ts, reason in denials:
                                ts_str = ts.strftime("%H:%M") if ts else "?"
                                denial_info.append(
                                    f"  {ts_str} | {email} tried {action} on {resource}: {reason or 'no reason'}"
                                )
                            sections.append(
                                f"[RBAC DENIALS — Last 24h: {denial_count}]\n"
                                + "\n".join(denial_info)
                            )

                        # AI usage summary
                        cur.execute("""
                            SELECT count(*),
                                   coalesce(sum(ai_input_tokens), 0),
                                   coalesce(sum(ai_output_tokens), 0),
                                   coalesce(sum(ai_cost_usd), 0)
                            FROM audit.events
                            WHERE event_type = 'ai_interaction'
                            AND timestamp > NOW() - interval '24 hours'
                        """)
                        row = cur.fetchone()
                        if row and row[0] > 0:
                            sections.append(
                                f"[AI USAGE — Last 24h] "
                                f"{row[0]} API calls | "
                                f"{row[1]:,} input tokens | "
                                f"{row[2]:,} output tokens | "
                                f"${row[3]:.4f} estimated cost"
                            )

            if sections:
                return "\n\n".join(sections)

        except Exception as e:
            logger.warning("Knowledge base query failed: %s", e)
            # Connection might be dead — mark for reconnect on next try
            try:
                self._kb_conn.close()
            except Exception:
                pass
            self._kb_conn = None

        return ""

    def _get_relevant_policies(self, user_text: str) -> str:
        """Query company policies and approved tools relevant to the user's message."""
        if not self._ensure_kb_connection():
            return ""

        try:
            sections = []
            text_lower = user_text.lower()

            # Check for policy-related keywords
            policy_relevant = any(w in text_lower for w in [
                "policy", "policies", "allowed", "approved", "prohibited", "banned",
                "can i use", "do we use", "are we allowed", "is it ok",
                "usb", "dropbox", "slack", "vpn", "wifi", "password", "mfa",
                "phishing", "report", "incident", "remote", "work from home",
                "data", "classify", "sensitive", "confidential", "share",
                "tool", "software", "install", "device", "laptop", "phone",
                "badge", "visitor", "shred", "encrypt",
            ])

            if not policy_relevant:
                return ""

            # Search company policies
            with self._kb_conn.cursor() as cur:
                try:
                    cur.execute("""
                        SELECT title, summary, details, dos, donts, contact, category
                        FROM knowledge.company_policies
                        WHERE to_tsvector('english', title || ' ' || summary || ' ' || details)
                            @@ plainto_tsquery('english', %s)
                        ORDER BY created_at DESC
                        LIMIT 3
                    """, [user_text])
                    policies = cur.fetchall()

                    if policies:
                        policy_lines = ["[COMPANY POLICIES — Share this information with the user]"]
                        for title, summary, details, dos, donts, contact, cat in policies:
                            policy_lines.append(f"\n**{title}** ({cat})")
                            policy_lines.append(f"Summary: {summary}")
                            if details:
                                policy_lines.append(f"Details: {details}")
                            if dos:
                                policy_lines.append(f"Do: {'; '.join(dos)}")
                            if donts:
                                policy_lines.append(f"Don't: {'; '.join(donts)}")
                            if contact:
                                policy_lines.append(f"Questions? Contact: {contact}")
                        sections.append("\n".join(policy_lines))
                except Exception:
                    pass  # Table might not exist yet

            # Search approved/prohibited tools
            with self._kb_conn.cursor() as cur:
                try:
                    # Extract potential tool names from the message
                    words = [w.strip(".,!?\"'") for w in user_text.split() if len(w) > 2]
                    cur.execute("""
                        SELECT name, category, status, description, usage_guidelines,
                               restrictions, alternative
                        FROM knowledge.approved_tools
                        WHERE LOWER(name) = ANY(%s)
                           OR tags && %s
                        LIMIT 5
                    """, [
                        [w.lower() for w in words],
                        [w.lower() for w in words],
                    ])
                    tools = cur.fetchall()

                    if tools:
                        tool_lines = ["[APPROVED/PROHIBITED TOOLS — Share this with the user]"]
                        for name, cat, status, desc, guidelines, restrictions, alt in tools:
                            status_icon = {"approved": "✅", "prohibited": "🚫", "restricted": "⚠️"}.get(status, "❓")
                            tool_lines.append(f"\n{status_icon} **{name}** — {status.upper()}")
                            if desc:
                                tool_lines.append(f"  {desc}")
                            if guidelines:
                                tool_lines.append(f"  Usage: {guidelines}")
                            if restrictions:
                                tool_lines.append(f"  Note: {restrictions}")
                            if alt:
                                tool_lines.append(f"  Alternative: {alt}")
                        sections.append("\n".join(tool_lines))
                except Exception:
                    pass  # Table might not exist yet

            return "\n\n".join(sections) if sections else ""

        except Exception as e:
            logger.debug("Policy lookup error: %s", e)
            return ""

    def _check_email_send(self, response_text: str, envelope: MessageEnvelope) -> None:
        """
        Parse Kevin's response for email send details.
        
        If Kevin composed an email (with To, Subject, Body), extract the
        structured fields and publish to the email connector for actual delivery.
        
        Expected patterns in Kevin's response:
        - **To:** user@domain.com
        - **Subject:** Something
        - Body text (everything after Subject line or in the email block)
        """
        import re

        logger.info("Email send check — response preview: %s", response_text[:300])

        # Extract explicit To: header first (most reliable)
        to_match = re.search(
            r'(?:\*\*)?To:?\*?\*?\s*:?\s*(.+?)(?:\n|$)',
            response_text, re.IGNORECASE
        )
        
        # Extract CC: header (to exclude from To list later)
        cc_match = re.search(
            r'(?:\*\*)?CC:?\*?\*?\s*:?\s*(.+?)(?:\n|$)',
            response_text, re.IGNORECASE
        )
        cc_emails = set()
        if cc_match:
            cc_raw = cc_match.group(1).strip()
            cc_raw = re.sub(r'<mailto:([^|>]+)\|[^>]+>', r'\1', cc_raw)
            cc_emails = set(e.lower() for e in re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', cc_raw))

        to_addrs = []

        if to_match:
            # Parse To: header specifically
            to_raw = to_match.group(1).strip()
            to_raw = re.sub(r'<mailto:([^|>]+)\|[^>]+>', r'\1', to_raw)
            to_raw = re.sub(r'<mailto:([^>]+)>', r'\1', to_raw)
            to_addrs = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', to_raw)
            # Filter Kevin's own email from To
            to_addrs = [e for e in to_addrs if e.lower() != 'kevin@heads-up.com']

        if not to_addrs:
            # Fallback: look for email addresses in response, excluding Kevin's and CC'd
            all_emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', response_text)
            seen = set()
            for e in all_emails:
                el = e.lower()
                if el != 'kevin@heads-up.com' and el not in cc_emails and el not in seen:
                    to_addrs.append(e)
                    seen.add(el)

        if not to_addrs:
            # Fallback: check user's original text for recipient
            user_text = envelope.payload.get("text", "")
            user_text = re.sub(r'<mailto:([^|>]+)\|[^>]+>', r'\1', user_text)
            to_addrs = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', user_text)

        if not to_addrs:
            # Fallback: "to me" / "my email" — use the user's email
            user_text = envelope.payload.get("text", "")
            if re.search(r'\b(to me|my email|my address)\b', user_text, re.IGNORECASE):
                if envelope.actor and envelope.actor.email:
                    to_addrs = [envelope.actor.email]

        # Deduplicate while preserving order
        seen = set()
        deduped = []
        for e in to_addrs:
            if e.lower() not in seen:
                deduped.append(e)
                seen.add(e.lower())
        to_addrs = deduped

        if not to_addrs:
            logger.info("Email send check — no recipient found, skipping")
            return

        # Extract Subject
        subject = ""
        subject_match = re.search(
            r'(?:\*\*)?Subject:?\*?\*?\s*:?\s*(.+?)(?:\n|$)',
            response_text, re.IGNORECASE
        )
        if subject_match:
            subject = subject_match.group(1).strip().strip('*')

        # Extract Body — look for text after the header block
        body = ""
        # Try to find body after Subject line
        body_section = re.search(
            r'(?:Subject:.*?\n\n?)(.*?)(?:\n---|\n\*\*|$)',
            response_text, re.DOTALL | re.IGNORECASE
        )
        if body_section:
            body = body_section.group(1).strip()
        
        # If no body found, try everything between headers and signature
        if not body:
            body_match = re.search(
                r'(?:Body:?\s*:?\s*)(.*?)(?:\n---|\n\*\*|$)',
                response_text, re.DOTALL | re.IGNORECASE
            )
            if body_match:
                body = body_match.group(1).strip()

        if not body:
            # Last resort — use subject as body
            body = subject or "Test email from Kevin Tutela"

        if not subject:
            subject = body[:50] + ("..." if len(body) > 50 else "")

        logger.info(
            "Email send detected: to=%s subject='%s' body_len=%d",
            to_addrs, subject[:50], len(body)
        )

        # Publish structured send command to the email connector
        send_msg = envelope.create_child(
            source=self.service_name,
            message_type="email.command.send",
            payload={
                "to": to_addrs,
                "subject": subject,
                "body": body,
                "importance": "normal",
            },
        )
        self.rmq.publish("email.command.send", send_msg)
        logger.info("Published email send command to connector")

    def _check_zendesk_create(self, response_text: str, envelope: MessageEnvelope) -> None:
        """
        Parse Kevin's response for ZenDesk ticket creation details.
        
        Expected patterns:
        - **Ticket Subject:** ...
        - **Ticket Priority:** ...
        - **Ticket Type:** ...
        - **Ticket Body:** ...
        """
        import re

        logger.info("ZenDesk create check — response preview: %s", response_text[:300])

        # Extract subject
        subject = ""
        subject_match = re.search(
            r'(?:\*\*)?Ticket\s+Subject:?\*?\*?\s*:?\s*(.+?)(?:\n|$)',
            response_text, re.IGNORECASE
        )
        if subject_match:
            subject = subject_match.group(1).strip().strip('*')

        # Fallback: look for **Subject:** without "Ticket"
        if not subject:
            subject_match = re.search(
                r'(?:\*\*)?Subject:?\*?\*?\s*:?\s*(.+?)(?:\n|$)',
                response_text, re.IGNORECASE
            )
            if subject_match:
                subject = subject_match.group(1).strip().strip('*')

        if not subject:
            logger.info("ZenDesk create check — no subject found, skipping")
            return

        # Extract priority
        priority = "normal"
        priority_match = re.search(
            r'(?:\*\*)?(?:Ticket\s+)?Priority:?\*?\*?\s*:?\s*(urgent|high|normal|low)',
            response_text, re.IGNORECASE
        )
        if priority_match:
            priority = priority_match.group(1).lower()

        # Extract type
        ticket_type = "incident"
        type_match = re.search(
            r'(?:\*\*)?(?:Ticket\s+)?Type:?\*?\*?\s*:?\s*(problem|incident|question|task)',
            response_text, re.IGNORECASE
        )
        if type_match:
            ticket_type = type_match.group(1).lower()

        # Extract body
        body = ""
        body_match = re.search(
            r'(?:\*\*)?(?:Ticket\s+)?Body:?\*?\*?\s*:?\s*\n?(.*?)(?:\n---|\Z)',
            response_text, re.DOTALL | re.IGNORECASE
        )
        if body_match:
            body = body_match.group(1).strip()

        if not body:
            # Try content after subject
            body_section = re.search(
                r'(?:Subject:.*?\n\n?)(.*?)(?:\n---|\n\*\*Ticket|\Z)',
                response_text, re.DOTALL | re.IGNORECASE
            )
            if body_section:
                body = body_section.group(1).strip()

        if not body:
            body = subject

        # Extract tags
        tags = []
        tags_match = re.search(
            r'(?:\*\*)?Tags?:?\*?\*?\s*:?\s*(.+?)(?:\n|$)',
            response_text, re.IGNORECASE
        )
        if tags_match:
            tags = [t.strip().strip('`*') for t in tags_match.group(1).split(",")]

        logger.info(
            "ZenDesk ticket detected: subject='%s' priority=%s type=%s body_len=%d tags=%s",
            subject[:50], priority, ticket_type, len(body), tags
        )

        # Build email body with ticket metadata
        email_body_parts = [body]
        if priority != "normal":
            email_body_parts.append(f"\nPriority: {priority}")
        if ticket_type != "incident":
            email_body_parts.append(f"Type: {ticket_type}")
        if tags:
            email_body_parts.append(f"Tags: {', '.join(tags)}")

        # Create ticket via email — send to ZenDesk support address
        # ZenDesk creates the ticket with Kevin as requester
        ZENDESK_SUPPORT_EMAIL = "ITSupport@heads-up.com"

        send_msg = envelope.create_child(
            source=self.service_name,
            message_type="email.command.send",
            payload={
                "to": [ZENDESK_SUPPORT_EMAIL],
                "subject": subject,
                "body": "\n".join(email_body_parts),
                "importance": "high" if priority in ("urgent", "high") else "normal",
            },
        )
        self.rmq.publish("email.command.send", send_msg)
        logger.info("Published ZenDesk ticket creation via email to %s", ZENDESK_SUPPORT_EMAIL)

    def _check_zendesk_update(self, response_text: str, envelope: MessageEnvelope, intent: str) -> None:
        """
        Parse Kevin's response for ZenDesk ticket update/close/comment details.
        
        Expected patterns:
        - **Ticket ID:** 12345
        - **Action:** close/update/comment
        - **Status:** solved/open/pending
        - **Comment:** text
        """
        import re

        logger.info("ZenDesk update check — response preview: %s", response_text[:300])

        # Extract ticket ID
        ticket_id = None
        id_match = re.search(
            r'(?:\*\*)?Ticket\s+(?:ID|#):?\*?\*?\s*:?\s*#?(\d+)',
            response_text, re.IGNORECASE
        )
        if not id_match:
            id_match = re.search(r'ticket\s+#?(\d{2,})', response_text, re.IGNORECASE)
        if id_match:
            ticket_id = int(id_match.group(1))

        if not ticket_id:
            logger.info("ZenDesk update check — no ticket ID found, skipping")
            return

        # Determine action
        action = "update"
        action_match = re.search(
            r'(?:\*\*)?Action:?\*?\*?\s*:?\s*(close|solve|update|comment|resolve)',
            response_text, re.IGNORECASE
        )
        if action_match:
            action = action_match.group(1).lower()
            if action in ("close", "solve", "resolve"):
                action = "close"

        # If intent is zendesk_comment, force comment action
        if intent == "zendesk_comment":
            action = "comment"

        # Extract status
        status = None
        status_match = re.search(
            r'(?:\*\*)?Status:?\*?\*?\s*:?\s*(new|open|pending|hold|solved|closed)',
            response_text, re.IGNORECASE
        )
        if status_match:
            status = status_match.group(1).lower()

        # Extract comment/note
        comment = ""
        comment_match = re.search(
            r'(?:\*\*)?(?:Comment|Note|Details?):?\*?\*?\s*:?\s*\n?(.*?)(?:\n---|\n\*\*|\Z)',
            response_text, re.DOTALL | re.IGNORECASE
        )
        if comment_match:
            comment = comment_match.group(1).strip()

        # Check if internal note
        is_internal = bool(re.search(r'internal\s+note', response_text, re.IGNORECASE))

        if action == "close":
            msg_type = "zendesk.command.close"
            payload = {"ticket_id": ticket_id, "status": status or "solved"}
            if comment:
                payload["comment"] = comment
        elif action == "comment":
            msg_type = "zendesk.command.comment"
            payload = {
                "ticket_id": ticket_id,
                "body": comment or "Updated by Kevin Tutela",
                "public": not is_internal,
            }
        else:
            msg_type = "zendesk.command.update"
            payload = {"ticket_id": ticket_id}
            if status:
                payload["status"] = status
            if comment:
                payload["comment"] = comment
                payload["internal_note"] = is_internal

        logger.info(
            "ZenDesk %s detected: ticket_id=%s payload=%s",
            action, ticket_id, {k: v for k, v in payload.items() if k != "body"}
        )

        update_msg = envelope.create_child(
            source=self.service_name,
            message_type=msg_type,
            payload=payload,
        )
        self.rmq.publish(msg_type, update_msg)
        logger.info("Published ZenDesk %s command to connector", action)

    def _check_powershell_proposal(self, response_text: str, envelope: MessageEnvelope) -> None:
        """
        Parse Kevin's response for a PowerShell command proposal.
        
        If Kevin proposed a command with an approval ID, store it in the
        powershell_executions table so the connector can execute it on approval.
        
        Expected format in Kevin's response:
        "approve <8-hex-char-id>"
        And a code block with the command.
        """
        import re

        # Look for approval ID pattern
        approve_match = re.search(r'approve\s+([a-f0-9]{6,8})', response_text.lower())
        if not approve_match:
            return

        request_id = approve_match.group(1)

        # Extract the command from a code block
        code_match = re.search(r'```\n?(.*?)\n?```', response_text, re.DOTALL)
        if not code_match:
            # Try single-line backticks
            code_match = re.search(r'`([^`]+)`', response_text)
        if not code_match:
            logger.debug("Found approval ID %s but no command block", request_id)
            return

        command = code_match.group(1).strip()

        # Extract target host — look for "on **HOSTNAME**" pattern or "on HOSTNAME (IP)"
        # Must be specific to avoid grabbing random bold text like **What happened:**
        target_host = "unknown"
        
        # Pattern 1: "on **HOSTNAME**" or "on **HOSTNAME** (IP)"
        # Hostname must contain a hyphen, digit, or be all-uppercase to avoid matching English words
        host_match = re.search(
            r'(?:on|for|from)\s+\*\*([A-Za-z0-9_-]{3,}(?:\.[A-Za-z0-9_-]+)*)\*\*',
            response_text
        )
        if host_match:
            candidate = host_match.group(1)
            # Valid hostnames typically have hyphens, digits, or are all-uppercase
            if re.search(r'[-\d]', candidate) or candidate.isupper():
                target_host = candidate
        
        # Pattern 2: "(IP)" after hostname — extract hostname before it
        if target_host == "unknown":
            host_match = re.search(
                r'\*\*([A-Za-z0-9_-]{3,}(?:\.[A-Za-z0-9_-]+)*)\*\*\s*\(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\)',
                response_text
            )
            if host_match:
                target_host = host_match.group(1)
        
        # Pattern 3: "on HOSTNAME" without bold (3+ chars, contains a hyphen or uppercase)
        if target_host == "unknown":
            host_match = re.search(
                r'(?:on|for|from)\s+([A-Z][A-Za-z0-9_-]{2,})',
                response_text
            )
            if host_match:
                candidate = host_match.group(1)
                # Filter out common false positives
                if candidate.lower() not in ("the", "this", "that", "your", "host", "server", "machine"):
                    target_host = candidate

        user_email = envelope.actor.email if envelope.actor else "unknown"

        # Store in the database so the connector can find it on approval
        if not self._ensure_kb_connection():
            return

        try:
            with self._kb_conn.cursor() as cur:
                # Ensure table exists
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS knowledge.powershell_executions (
                        id SERIAL PRIMARY KEY,
                        request_id VARCHAR(36) NOT NULL UNIQUE,
                        requested_by VARCHAR(255) NOT NULL,
                        target_host VARCHAR(255) NOT NULL,
                        command TEXT NOT NULL,
                        reason TEXT DEFAULT '',
                        status VARCHAR(50) DEFAULT 'pending',
                        approved_by VARCHAR(255),
                        approved_at TIMESTAMPTZ,
                        output TEXT,
                        error_output TEXT,
                        exit_code INT,
                        execution_time_ms INT,
                        executed_at TIMESTAMPTZ,
                        created_at TIMESTAMPTZ DEFAULT NOW(),
                        updated_at TIMESTAMPTZ DEFAULT NOW()
                    )
                """)
                cur.execute("""
                    INSERT INTO knowledge.powershell_executions
                        (request_id, requested_by, target_host, command, status)
                    VALUES (%s, %s, %s, %s, 'pending')
                    ON CONFLICT (request_id) DO NOTHING
                """, [request_id, user_email, target_host, command])

            logger.info(
                "Stored PowerShell proposal [%s]: %s on %s (by %s)",
                request_id, command[:60], target_host, user_email,
            )
        except Exception as e:
            logger.warning("Failed to store PowerShell proposal: %s", e)

    # ── Claude API ──────────────────────────────────────────────────

    def _call_claude(
        self,
        system_prompt: str,
        messages: List[Dict[str, str]],
    ) -> Dict[str, Any]:
        """Call the Anthropic Messages API."""
        response = self._http.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": self._model,
                "max_tokens": self._max_tokens,
                "system": system_prompt,
                "messages": messages,
            },
        )
        response.raise_for_status()
        return response.json()

    def _estimate_cost(
        self, model: str, input_tokens: int, output_tokens: int
    ) -> float:
        """Estimate API cost in USD."""
        pricing = MODEL_PRICING.get(model)
        if not pricing:
            return 0.0
        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]
        return round(input_cost + output_cost, 6)

    def _send_error(self, envelope: MessageEnvelope, error: str) -> None:
        """Send an error response back to the connector."""
        reply = envelope.create_reply(
            source=self.service_name,
            message_type="ai.response.error",
            payload={"error": error},
        )
        reply_key = envelope.reply_to or "ai.response.error"
        self.rmq.publish(reply_key, reply)

    # ── Service Metadata ────────────────────────────────────────────

    def get_capabilities(self) -> list:
        return [
            "ai-completion",
            "security-analysis",
            "role-based-prompts",
        ]

    def get_metadata(self) -> Dict[str, Any]:
        return {
            **super().get_metadata(),
            "model": self._model,
            "provider": "anthropic",
            "max_tokens": self._max_tokens,
        }

    def health_status(self) -> Dict[str, Any]:
        status = super().health_status()
        status["model"] = self._model
        status["api_key_configured"] = bool(self._api_key)
        return status

    def on_shutdown(self) -> None:
        """Close HTTP client."""
        if self._http:
            self._http.close()


if __name__ == "__main__":
    service = ClaudeWorker.create("agent-worker-claude")
    service.run()
