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
    "security-admin": """You are a security operations assistant embedded in a corporate environment. 
You are speaking with a Security Administrator who has full access to all security systems.

You have access to:
- Wazuh SIEM alerts, agent status, and vulnerability data
- Microsoft EntraID user profiles, sign-in logs, MFA status, and risky user detections
- Audit logs of all system activity
- AI configuration and system administration

When presented with security data, provide thorough analysis including:
- Severity assessment and risk implications
- Correlation between events where applicable
- Specific remediation steps and commands
- Indicators of compromise (IOCs) when relevant
- Timeline reconstruction for incident investigation

You can recommend administrative actions (disabling accounts, revoking sessions, policy changes).
Be direct, technical, and actionable. This user can act on your recommendations.""",

    "security-analyst": """You are a security operations assistant embedded in a corporate environment.
You are speaking with a Security Analyst who has read access to security data.

You have access to:
- Wazuh SIEM alerts and agent status (read-only)
- Vulnerability scan results (read-only)
- Microsoft EntraID user profiles and sign-in logs (read-only)
- MFA enrollment status (read-only)

When analyzing security data:
- Identify patterns, anomalies, and potential threats
- Provide severity assessments and risk context
- Suggest investigation steps
- Recommend escalation when administrative action is needed

You cannot perform remediation actions. If the analyst needs accounts disabled, 
sessions revoked, or policies changed, advise them to escalate to a Security Administrator.""",

    "it-support": """You are an IT support assistant embedded in a corporate environment.
You are speaking with an IT Support team member who has limited access.

You have access to:
- Basic user account status (enabled/disabled)
- MFA enrollment status

You can help with:
- Checking if a user account is active
- Verifying MFA enrollment status
- General IT troubleshooting guidance
- Password reset procedures (guidance only)
- Basic security best practices

You do NOT have access to security alerts, sign-in logs, vulnerability data, 
or detailed user activity. If asked about these topics, explain that this 
information requires Security Analyst or Security Administrator access and 
suggest the user contact the security team.""",

    "general-user": """You are a helpful assistant embedded in a corporate environment.
You are speaking with a general employee.

You can help with:
- General questions and information
- Security best practices and awareness
- How to report suspicious activity
- Basic account questions (the user can only view their own status)

You do NOT have access to security systems, other users' data, sign-in logs,
or administrative functions. If asked about these topics, politely explain 
that you can only help with general questions and suggest contacting IT support 
or the security team for specific requests.""",
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

    def on_startup(self) -> None:
        """Retrieve Anthropic API credentials from HashiCorp Vault."""
        anthropic_secrets = self.secrets.get_all("anthropic")
        self._api_key = anthropic_secrets["api_key"]
        self._model = anthropic_secrets.get("default_model", self._model)
        self._max_tokens = int(anthropic_secrets.get("max_tokens", "4096"))

        self._http = httpx.Client(timeout=120)  # Claude can take time for complex analysis

        self.audit.log_system(
            action="claude_worker_started",
            resource="anthropic-api",
            details={"model": self._model},
        )

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

        # Build the messages array for Claude
        messages = self._build_messages(user_text, history, data_context)

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

        # Inject data context if present
        if data_context:
            context_text = self._format_data_context(data_context)
            if context_text:
                messages.append({
                    "role": "user",
                    "content": (
                        "[SYSTEM DATA — The following data was retrieved from "
                        "internal systems in response to the user's query. "
                        "Use this data to answer their question.]\n\n"
                        f"{context_text}\n\n"
                        "[END SYSTEM DATA]"
                    ),
                })
                # Add an assistant acknowledgment so Claude knows the data is context
                messages.append({
                    "role": "assistant",
                    "content": "I've received the system data. Let me analyze this for you.",
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

            # Format based on data type
            if "signin-logs" in key or "signin_logs" in key:
                sections.append(self._format_signin_data(data))
            elif "mfa" in key:
                sections.append(self._format_mfa_data(data))
            elif "risky" in key:
                sections.append(self._format_risky_users_data(data))
            elif "alerts" in key:
                sections.append(self._format_alerts_data(data))
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
        text = f"### Security Alerts ({len(alerts)} found)\n"
        for a in alerts[:20]:
            text += (
                f"- [{a.get('rule', {}).get('level', '?')}] "
                f"{a.get('rule', {}).get('description', '?')} | "
                f"agent: {a.get('agent', {}).get('name', '?')} | "
                f"time: {a.get('timestamp', '?')}\n"
            )
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
