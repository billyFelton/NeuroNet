"""
Resolver — Authentication enrichment and RBAC enforcement gateway.

Sits between inbound connectors and the AI layer. Every user query
passes through the Resolver, which:

1. Validates the actor identity (is this a known user?)
2. Determines what the user is asking for (intent classification)
3. Checks RBAC permissions (can this user access that data?)
4. Enriches the envelope with authorization context
5. Routes permitted messages to the appropriate service
6. Returns denial messages directly to the originating connector

Message Flow:
    Connector → [user.query] → Resolver → [ai.request] → Agent Router/Worker
                                       → [connector.query] → Data Connectors
                                       → [ai.response.error] → Back to Connector (denied)
"""

import logging
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from neurokit.envelope import (
    AuthorizationContext,
    AuthorizationDecision,
    EventType,
    MessageEnvelope,
)
from neurokit.service import BaseService

logger = logging.getLogger("resolver")


# ── Intent Classification ───────────────────────────────────────────

class Intent:
    """Classified user intent with required resources and actions."""

    def __init__(
        self,
        name: str,
        resources: List[Tuple[str, str]],  # (resource, action) pairs
        data_queries: Optional[List[Dict]] = None,
    ):
        self.name = name
        self.resources = resources  # What RBAC permissions are needed
        self.data_queries = data_queries or []  # Pre-fetch data from connectors


# Intent patterns — maps user query keywords to required resources.
# In production, the Agent Router or an LLM classifier would handle this.
# For now, keyword matching gets us a working loop.
INTENT_PATTERNS = [
    # ── Scheduler (most specific — must be checked before broad patterns) ──
    # Scheduler — modify (enable/disable/change schedule)
    {
        "pattern": r"\b(enable|disable|pause|resume|stop|start|change|update|modify|set)\s+.*(task|sweep|monitor|schedule|summary|cron|job)\b",
        "intent": Intent(
            name="scheduler_modify",
            resources=[("scheduler", "manage")],
            data_queries=[{"routing_key": "scheduler.command.modify", "type": "scheduler-modify"}],
        ),
    },
    # Scheduler — run now
    {
        "pattern": r"\b(run|trigger|execute|do)\s+.*(sweep|scan|summary|monitor|task)\s*(now|immediately)?\b",
        "intent": Intent(
            name="scheduler_run",
            resources=[("scheduler", "manage")],
            data_queries=[{"routing_key": "scheduler.command.run", "type": "scheduler-run"}],
        ),
    },
    # Scheduler — list tasks
    {
        "pattern": r"\b(scheduled?\s+tasks?|your\s+(scheduled?|routine|tasks?|jobs?)|what\s+(do\s+you|are\s+you)\s+run|cron|recurring|proactive\s+tasks?|your\s+schedule)\b",
        "intent": Intent(
            name="scheduler_list",
            resources=[("scheduler", "query")],
            data_queries=[{"routing_key": "scheduler.command.list", "type": "scheduler-list"}],
        ),
    },
    # ── Security / Wazuh ──
    # Infrastructure-specific
    {
        "pattern": r"\b(infra(structure)?\s+(alert|alerts|agent|agents|vuln|siem)|server\s+(alert|alerts|agent|agents)|wazuh.infra)\b",
        "intent": Intent(
            name="infra_alerts",
            resources=[("wazuh-alerts", "query")],
            data_queries=[{"routing_key": "wazuh-infra.query.alerts", "type": "infra-alerts"}],
        ),
    },
    # Desktop-specific
    {
        "pattern": r"\b(desktop\s+(alert|alerts|agent|agents)|workstation\s+(alert|alerts)|endpoint\s+alert|wazuh.desktop)\b",
        "intent": Intent(
            name="desktop_alerts",
            resources=[("wazuh-alerts", "query")],
            data_queries=[{"routing_key": "wazuh.query.alerts", "type": "desktop-alerts"}],
        ),
    },
    # Generic (queries BOTH instances)
    {
        "pattern": r"\b(alert|alerts|security\s+event|siem|threat|wazuh)\b",
        "intent": Intent(
            name="security_alerts",
            resources=[("wazuh-alerts", "query")],
            data_queries=[
                {"routing_key": "wazuh.query.alerts", "type": "desktop-alerts"},
                {"routing_key": "wazuh-infra.query.alerts", "type": "infra-alerts"},
            ],
        ),
    },
    {
        "pattern": r"\b(vulnerabilit|vuln|cve|patch)\b",
        "intent": Intent(
            name="vulnerability_query",
            resources=[("wazuh-vulnerability", "query")],
            data_queries=[
                {"routing_key": "wazuh.query.vulnerabilities", "type": "desktop-vulns"},
                {"routing_key": "wazuh-infra.query.vulnerabilities", "type": "infra-vulns"},
            ],
        ),
    },
    {
        "pattern": r"\b(agent|agents|endpoint|wazuh\s+agent)\b",
        "intent": Intent(
            name="agent_status",
            resources=[("wazuh-agents", "query")],
            data_queries=[
                {"routing_key": "wazuh.query.agents", "type": "desktop-agents"},
                {"routing_key": "wazuh-infra.query.agents", "type": "infra-agents"},
            ],
        ),
    },
    # Identity / EntraID
    {
        "pattern": r"\b(sign.?in|login|auth.*log|failed\s+login|brute\s+force)\b",
        "intent": Intent(
            name="signin_logs",
            resources=[("entra-signin-logs", "query")],
            data_queries=[{"routing_key": "entraid.query.signin-logs", "type": "signin-logs"}],
        ),
    },
    {
        "pattern": r"\b(mfa|multi.?factor|authenticat.*method|2fa)\b",
        "intent": Intent(
            name="mfa_status",
            resources=[("entra-mfa-status", "query")],
            data_queries=[{"routing_key": "entraid.query.mfa-status", "type": "mfa-status"}],
        ),
    },
    {
        "pattern": r"\b(risky|risk\s+detect|compromised\s+user|identity\s+protect)\b",
        "intent": Intent(
            name="risky_users",
            resources=[("entra-users", "query")],
            data_queries=[{"routing_key": "entraid.query.risky-users", "type": "risky-users"}],
        ),
    },
    {
        "pattern": r"\b(user\s+info|user\s+profile|look\s*up\s+user|account\s+status|who\s+is|entra\s*id?\s+profile|tell\s+me\s+about\s+\S+@|profile\s+for\s+\S+@|check\s+on\s+\S+@|disable\s+\S+@|block\s+\S+@)\b",
        "intent": Intent(
            name="user_lookup",
            resources=[("entra-users", "view")],
            data_queries=[{"routing_key": "entraid.query.user", "type": "user"}],
        ),
    },
    {
        "pattern": r"\b(group|groups|team\s+member|membership)\b",
        "intent": Intent(
            name="group_query",
            resources=[("entra-groups", "query")],
            data_queries=[{"routing_key": "entraid.query.groups", "type": "groups"}],
        ),
    },
    {
        "pattern": r"\b(device|devices|laptop|workstation|enrolled)\b",
        "intent": Intent(
            name="device_query",
            resources=[("entra-users", "query")],
            data_queries=[{"routing_key": "entraid.query.devices", "type": "devices"}],
        ),
    },
    # Audit
    {
        "pattern": r"\b(audit\s+log|audit\s+trail|who\s+accessed|access\s+log)\b",
        "intent": Intent(
            name="audit_query",
            resources=[("audit-logs", "query")],
        ),
    },
    # Email — search specific mailbox (most specific, must be first)
    {
        "pattern": r"(search\s+\S+@\S+|check\s+\S+@\S+.*(mail|inbox)|look\s+(in|at)\s+\S+@\S+|emails?\s+(from|to)\s+\S+@\S+|show\s+(me\s+)?emails?\s+(in|from|for)\s+\S+@|get\s+emails?\s+(from|in)\s+\S+@|\S+@\S+.*(inbox|mailbox|emails?).*(?:for|with|about|contain|subject))",
        "intent": Intent(
            name="email_search_mailbox",
            resources=[("email-investigation", "query")],
            data_queries=[{"routing_key": "email.command.search_mailbox", "type": "email-search"}],
        ),
    },
    # Email — org-wide search
    {
        "pattern": r"\b(search\s+(all\s+)?(mailboxes|emails?\s+org|company\s+email|everyone.s?\s+email)|org.wide\s+search|ediscovery|find\s+emails?\s+(across|in\s+all|company))\b",
        "intent": Intent(
            name="email_search_org",
            resources=[("email-investigation", "query")],
            data_queries=[{"routing_key": "email.command.search_org", "type": "email-search-org"}],
        ),
    },
    # Email — send
    {
        "pattern": r"\b(send\s+(an?\s+)?email|write\s+to|compose|draft\s+(an?\s+)?email|send\s+\S+@)\b",
        "intent": Intent(
            name="email_send",
            resources=[("email", "send")],
            data_queries=[{"routing_key": "email.command.send", "type": "email-send"}],
        ),
    },
    # Email — check inbox
    {
        "pattern": r"\b(inbox|check\s+(my\s+)?mail|check\s+(my\s+)?email|unread|my\s+email|read\s+email|show\s+(my\s+)?mail)\b",
        "intent": Intent(
            name="email_list",
            resources=[("email", "query")],
            data_queries=[{"routing_key": "email.command.list", "type": "email-list"}],
        ),
    },
]

# Default intent — general conversation, no data access needed
DEFAULT_INTENT = Intent(name="general", resources=[])


class ResolverService(BaseService):
    """
    Resolver service — the RBAC gateway for the Neuro-Network.

    Consumes user.query messages from connectors, enforces RBAC,
    fetches required data from connectors, and forwards enriched
    requests to the AI layer.
    """

    def on_startup(self) -> None:
        """No special startup needed — uses NeuroKit clients."""
        logger.info("Resolver ready — RBAC enforcement active")

    def setup_queues(self) -> None:
        """Set up inbound queue for user queries."""
        # Inbound from connectors
        self.inbox = self.rmq.declare_queue(
            "resolver.inbox",
            routing_keys=["user.query"],
        )
        self.rmq.consume(self.inbox, self.handle_message)

        # Queue for receiving data responses from connectors
        self.data_responses = self.rmq.declare_queue(
            "resolver.data-responses",
            routing_keys=[
                "entraid.response.*",
                "wazuh.response.*",
                "wazuh-infra.response.*",
                "email.response.*",
                "scheduler.response.*",
            ],
        )
        self.rmq.consume(self.data_responses, self._handle_data_response)

        # Track pending data fetches: correlation_id → context
        self._pending_data: Dict[str, Dict] = {}

        # Schedule periodic timeout check every 5 seconds
        self._schedule_timeout_check()

    def _schedule_timeout_check(self) -> None:
        """Schedule periodic check for timed-out data requests."""
        try:
            if self.rmq._connection and not self.rmq._connection.is_closed:
                self.rmq._connection.call_later(5, self._periodic_timeout_check)
        except Exception:
            pass  # Non-fatal — timeout check will still run on next message

    def _periodic_timeout_check(self) -> None:
        """Called every 5 seconds by pika to check for stale pending requests."""
        self._check_pending_timeouts()
        self._schedule_timeout_check()  # Reschedule

    def handle_message(self, envelope: MessageEnvelope) -> None:
        """
        Process an inbound user query.

        1. Validate actor identity
        2. Classify intent
        3. Check RBAC for each required resource
        4. If permitted: fetch data and forward to AI
        5. If denied: return error to originating connector
        """
        # Check for any timed-out data requests
        self._check_pending_timeouts()

        text = envelope.payload.get("text", "")
        actor = envelope.actor

        # ── Step 1: Validate identity ───────────────────────────────
        if not actor or not actor.user_id:
            logger.warning("Message with no actor identity, denying")
            self._deny(envelope, "Identity not resolved. Please contact IT support.")
            return

        if not actor.roles:
            # Try to enrich from Vault-IAM
            try:
                identity = self.iam.resolve_identity(
                    provider=actor.source_channel or "unknown",
                    external_id=actor.source_channel_id or "",
                )
                actor.roles = identity.get("roles", [])
                actor.groups = identity.get("groups", [])
                actor.email = identity.get("email", actor.email)
                actor.display_name = identity.get("display_name", actor.display_name)
            except Exception as e:
                logger.warning("Could not enrich identity for %s: %s", actor.user_id, e)

        if not actor.roles:
            self._deny(envelope, "No roles assigned to your account. Please contact your administrator.")
            return

        # ── Step 2: Classify intent ─────────────────────────────────
        intent = self._classify_intent(text)
        logger.info(
            "User %s intent: %s (roles: %s) text: %.100s",
            actor.email, intent.name, actor.roles, text,
        )

        # ── Step 3: RBAC check ──────────────────────────────────────
        if intent.resources:
            denied_resources = []
            granted_resources = []

            for resource, action in intent.resources:
                try:
                    auth_result = self.iam.check_permission(
                        user_id=actor.user_id,
                        action=action,
                        resource=resource,
                    )
                    if auth_result.get("permitted"):
                        granted_resources.append((resource, action, auth_result))
                    else:
                        denied_resources.append((resource, action, auth_result))
                except Exception as e:
                    logger.error("RBAC check failed for %s/%s: %s", resource, action, e)
                    # Fail closed
                    denied_resources.append((resource, action, {
                        "denied_reason": f"RBAC check error: {e}"
                    }))

            # Log all authorization decisions
            for resource, action, result in granted_resources + denied_resources:
                decision = "permit" if result.get("permitted") else "deny"
                self.audit.log_from_envelope(
                    envelope=envelope,
                    event_type=EventType.AUTHORIZATION,
                    action=action,
                    resource=resource,
                    outcome_status="success" if result.get("permitted") else "denied",
                    details={
                        "decision": decision,
                        "policy": result.get("policy_matched"),
                        "intent": intent.name,
                    },
                )

            # If ALL resources denied, reject entirely
            if denied_resources and not granted_resources:
                reasons = [r[2].get("denied_reason", "Access denied") for r in denied_resources]
                self._deny(
                    envelope,
                    f"You don't have permission for this request. {reasons[0]}",
                )
                return

            # Attach authorization context to envelope
            envelope.authorization = AuthorizationContext(
                decision=AuthorizationDecision.PERMIT,
                evaluated_by="resolver",
                policy_matched=", ".join(
                    r[2].get("policy_matched", "") for r in granted_resources if r[2].get("policy_matched")
                ),
                scopes_granted=[
                    scope
                    for r in granted_resources
                    for scope in (r[2].get("scopes_granted") or [])
                ],
            )

        # ── Step 4: Fetch data or forward directly ──────────────────
        if intent.data_queries:
            self._fetch_data_and_forward(envelope, intent)
        else:
            # General conversation — forward directly to AI
            self._forward_to_ai(envelope, intent, data_context={})

    def _classify_intent(self, text: str) -> Intent:
        """
        Classify user intent from message text.

        Uses keyword matching for now. In production, the Agent Router
        could use an LLM for more sophisticated classification.
        """
        text_lower = text.lower()
        for entry in INTENT_PATTERNS:
            if re.search(entry["pattern"], text_lower):
                return entry["intent"]
        return DEFAULT_INTENT

    def _fetch_data_and_forward(
        self, envelope: MessageEnvelope, intent: Intent
    ) -> None:
        """
        Send data queries to connectors, then forward to AI once data arrives.

        For simplicity in v1, we send the queries but also forward to AI
        immediately with the intent metadata. The AI worker can wait for
        data or respond based on what's available.
        """
        data_context = {
            "intent": intent.name,
            "requested_data": [],
        }

        for query in intent.data_queries:
            # Create a child message to the appropriate connector
            child = envelope.create_child(
                source=self.service_name,
                message_type=query["routing_key"],
                payload={
                    **envelope.payload,
                    "query_type": query["type"],
                },
            )
            # Set reply_to so the connector's response routes back via the exchange
            # e.g., "wazuh.query.alerts" → "wazuh.response.alerts"
            # e.g., "email.command.list" → "email.response.list"
            reply_key = query["routing_key"]
            if ".query." in reply_key:
                child.reply_to = reply_key.replace(".query.", ".response.")
            elif ".command." in reply_key:
                child.reply_to = reply_key.replace(".command.", ".response.")
            else:
                child.reply_to = reply_key + ".response"
            self.rmq.publish(query["routing_key"], child)
            data_context["requested_data"].append(query["type"])
            logger.debug("Dispatched data query: %s (reply_to: %s)", query["routing_key"], child.reply_to)

        # Track that we're waiting for data
        self._pending_data[envelope.correlation_id] = {
            "original_envelope": envelope,
            "intent": intent,
            "expected_responses": len(intent.data_queries),
            "received_responses": 0,
            "data": {},
            "created_at": time.time(),
        }

    def _check_pending_timeouts(self) -> None:
        """Forward any pending requests that have timed out (10s)."""
        now = time.time()
        timed_out = []

        for corr_id, pending in self._pending_data.items():
            age = now - pending["created_at"]
            if age > 10:  # 10 second timeout
                timed_out.append(corr_id)

        for corr_id in timed_out:
            pending = self._pending_data.pop(corr_id)
            logger.warning(
                "Data request timed out after %.1fs (%d/%d responses received). Forwarding with partial data.",
                time.time() - pending["created_at"],
                pending["received_responses"],
                pending["expected_responses"],
            )
            original = pending["original_envelope"]
            intent = pending["intent"]
            # Add timeout notice to data context
            data = pending["data"]
            if pending["received_responses"] < pending["expected_responses"]:
                data["_timeout_notice"] = {
                    "status": "partial",
                    "message": f"Some data sources did not respond in time ({pending['received_responses']}/{pending['expected_responses']} received). Results may be incomplete.",
                }
            self._forward_to_ai(original, intent, data_context=data)

    def _handle_data_response(self, envelope: MessageEnvelope) -> None:
        """Handle data responses from connectors and forward to AI when complete."""
        # Check for timed-out requests while we're here
        self._check_pending_timeouts()

        correlation_id = envelope.correlation_id
        pending = self._pending_data.get(correlation_id)

        if not pending:
            logger.debug("Data response for unknown correlation: %s", correlation_id)
            return

        # Store the data
        msg_type = envelope.message_type  # e.g., "entraid.response.signin-logs"
        pending["data"][msg_type] = envelope.payload
        pending["received_responses"] += 1

        # Check if all data has arrived
        if pending["received_responses"] >= pending["expected_responses"]:
            original = pending["original_envelope"]
            intent = pending["intent"]
            del self._pending_data[correlation_id]

            self._forward_to_ai(original, intent, data_context=pending["data"])

    def _forward_to_ai(
        self,
        envelope: MessageEnvelope,
        intent: Intent,
        data_context: Dict[str, Any],
    ) -> None:
        """Forward the enriched message to the AI layer."""
        ai_request = envelope.create_child(
            source=self.service_name,
            message_type="ai.request",
            payload={
                "text": envelope.payload.get("text", ""),
                "history": envelope.payload.get("history", []),
                "intent": intent.name,
                "data_context": data_context,
                "channel": envelope.payload.get("channel"),
                "thread_ts": envelope.payload.get("thread_ts"),
            },
        )

        # Carry forward the reply_to so AI response routes back to connector
        ai_request.reply_to = envelope.reply_to

        self.rmq.publish("ai.request", ai_request)
        logger.info(
            "Forwarded to AI: user=%s intent=%s data_keys=%s",
            envelope.actor.email,
            intent.name,
            list(data_context.keys()) if data_context else "none",
        )

    def _deny(self, envelope: MessageEnvelope, reason: str) -> None:
        """Send a denial response back to the originating connector."""
        denial = envelope.create_reply(
            source=self.service_name,
            message_type="ai.response.error",
            payload={
                "error": reason,
                "type": "access_denied",
            },
        )
        denial.authorization = AuthorizationContext(
            decision=AuthorizationDecision.DENY,
            evaluated_by="resolver",
            denied_reason=reason,
        )

        # Route back to the connector's response queue
        reply_key = envelope.reply_to or "ai.response.error"
        self.rmq.publish(reply_key, denial)

        self.audit.log_from_envelope(
            envelope=envelope,
            event_type=EventType.AUTHORIZATION,
            action="access_denied",
            resource="resolver",
            outcome_status="denied",
            details={"reason": reason},
        )

        logger.info("Denied request from %s: %s", envelope.actor.email, reason)

    # ── Service Metadata ────────────────────────────────────────────

    def get_capabilities(self) -> list:
        return [
            "rbac-enforcement",
            "intent-classification",
            "data-enrichment",
            "message-routing",
        ]

    def health_status(self) -> Dict[str, Any]:
        status = super().health_status()
        status["pending_data_fetches"] = len(self._pending_data)
        return status


if __name__ == "__main__":
    service = ResolverService.create("resolver")
    service.run()
