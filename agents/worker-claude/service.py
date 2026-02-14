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
- When asked to send an email, confirm the details and let the user know it's been sent.

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

You're talking to a Security Analyst with read access to security data. You can:
- Analyze Wazuh SIEM alerts, agent status, and vulnerability results
- Review EntraID user profiles, sign-in logs, and MFA status
- Identify patterns, anomalies, and potential threats
- Suggest investigation steps and provide context

You can't perform remediation actions directly. If something needs an account disabled, 
sessions revoked, or a policy changed, let them know they'll need to loop in a Security 
Administrator and offer to help them frame the escalation.""",

    "it-support": """You are Kevin Tutela, a friendly IT assistant at Heads Up Technologies.
Think of yourself as the helpful coworker who knows a bit about everything.

Your personality:
- Friendly, patient, and clear — no jargon unless needed
- You keep things simple and actionable

You're talking to someone on the IT Support team. You can help with:
- Checking user account status (active/disabled)
- MFA enrollment status
- General IT troubleshooting guidance
- Password reset procedures and security best practices

You don't have access to security alerts, sign-in logs, or vulnerability data. 
If they need that info, point them toward the security team — no big deal, just different access levels.""",

    "general-user": """You are Kevin Tutela, a friendly assistant at Heads Up Technologies.
You're the approachable coworker who's always happy to help with a question.

Your personality:
- Warm, helpful, and conversational
- You keep things clear and to the point

You can help with:
- General questions and everyday info
- Security awareness and best practices
- How to report something suspicious
- Basic account questions

You don't have access to security systems or other people's data. If someone needs 
that kind of help, just point them to IT support or the security team — easy referral, no judgment.""",
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
            "connector-wazuh (Desktops)": "neuro.connector-wazuh.inbox",
            "connector-wazuh-infra (Infrastructure)": "neuro.connector-connector-wazuh-infra.inbox",
            "connector-slack": "neuro.connector-slack.responses",
            "connector-email (M365)": "neuro.connector-email.inbox",
            "connector-entraid (EntraID/Azure AD)": "neuro.connector-entraid.inbox",
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

        # Retrieve relevant knowledge
        knowledge_context = self._get_relevant_knowledge(user_text, intent)
        if knowledge_context:
            system_prompt += "\n\n" + knowledge_context
            logger.info("Injected knowledge base context (%d chars)", len(knowledge_context))
        else:
            logger.info("No relevant knowledge found for query")

        # Inject NeuroNet health status so Kevin knows what's connected
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

        # Extract and store knowledge from the conversation (async, non-blocking)
        try:
            self._extract_knowledge(
                user_text, response_text, intent,
                actor.email if actor else "unknown",
                data_context,
            )
        except Exception as e:
            logger.debug("Knowledge extraction failed: %s", e)

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
- Host/device information (names, IPs, OS, roles, owners, issues)
- Network topology facts
- Ongoing incidents or problems
- User preferences or workflows
- Policy or configuration details
- Anything the user explicitly asked you to remember

Return ONLY a JSON array of facts to store. Each fact should have:
- "category": one of "host", "network", "incident", "policy", "contact", "general"
- "subject": short identifier (hostname, topic name)
- "content": the fact in a clear sentence
- "tags": array of relevant keywords

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
            with self._kb_conn.cursor() as cur:
                for fact in facts[:5]:  # Max 5 facts per exchange
                    category = fact.get("category", "general")
                    subject = fact.get("subject", "")
                    content = fact.get("content", "")
                    tags = fact.get("tags", [])

                    if not subject or not content:
                        continue

                    # Upsert — update if same subject exists, otherwise insert
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

            if stored > 0:
                logger.info("Stored %d knowledge facts from conversation", stored)

        except json.JSONDecodeError:
            logger.debug("Knowledge extraction returned invalid JSON")
        except Exception as e:
            logger.debug("Knowledge extraction error: %s", e)

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

            # Check for known hosts mentioned in the message
            with self._kb_conn.cursor() as cur:
                words = [w.strip(".,!?") for w in user_text.split() if len(w) > 2]
                if words:
                    placeholders = ",".join(["%s"] * len(words))
                    cur.execute(f"""
                        SELECT hostname, ip_address, os, role, location, 
                               owner, notes, criticality
                        FROM knowledge.hosts
                        WHERE hostname ILIKE ANY(%s)
                    """, [[f"%{w}%" for w in words]])
                    hosts = cur.fetchall()

                    if hosts:
                        host_info = []
                        for h in hosts:
                            parts = [f"Host: {h[0]}"]
                            if h[1]: parts.append(f"IP: {h[1]}")
                            if h[2]: parts.append(f"OS: {h[2]}")
                            if h[3]: parts.append(f"Role: {h[3]}")
                            if h[4]: parts.append(f"Location: {h[4]}")
                            if h[5]: parts.append(f"Owner: {h[5]}")
                            if h[6]: parts.append(f"Notes: {h[6]}")
                            if h[7]: parts.append(f"Criticality: {h[7]}")
                            host_info.append(" | ".join(parts))
                        sections.append(
                            "[KNOWN HOSTS]\n" + "\n".join(host_info)
                        )

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
