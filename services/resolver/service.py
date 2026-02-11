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
    # Security / Wazuh
    {
        "pattern": r"\b(alert|alerts|security\s+event|siem|threat|wazuh)\b",
        "intent": Intent(
            name="security_alerts",
            resources=[("wazuh-alerts", "query")],
            data_queries=[{"routing_key": "wazuh.query.alerts", "type": "alerts"}],
        ),
    },
    {
        "pattern": r"\b(vulnerabilit|vuln|cve|patch)\b",
        "intent": Intent(
            name="vulnerability_query",
            resources=[("wazuh-vulnerability", "query")],
            data_queries=[{"routing_key": "wazuh.query.vulnerabilities", "type": "vulnerabilities"}],
        ),
    },
    {
        "pattern": r"\b(agent|agents|endpoint|wazuh\s+agent)\b",
        "intent": Intent(
            name="agent_status",
            resources=[("wazuh-agents", "query")],
            data_queries=[{"routing_key": "wazuh.query.agents", "type": "agents"}],
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
        "pattern": r"\b(user\s+info|user\s+profile|look\s*up\s+user|account\s+status|who\s+is)\b",
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
            ],
        )
        self.rmq.consume(self.data_responses, self._handle_data_response)

        # Track pending data fetches: correlation_id → context
        self._pending_data: Dict[str, Dict] = {}

    def handle_message(self, envelope: MessageEnvelope) -> None:
        """
        Process an inbound user query.

        1. Validate actor identity
        2. Classify intent
        3. Check RBAC for each required resource
        4. If permitted: fetch data and forward to AI
        5. If denied: return error to originating connector
        """
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
            "User %s intent: %s (roles: %s)",
            actor.email, intent.name, actor.roles,
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
            self.rmq.publish(query["routing_key"], child)
            data_context["requested_data"].append(query["type"])
            logger.debug("Dispatched data query: %s", query["routing_key"])

        # Track that we're waiting for data
        self._pending_data[envelope.correlation_id] = {
            "original_envelope": envelope,
            "intent": intent,
            "expected_responses": len(intent.data_queries),
            "received_responses": 0,
            "data": {},
        }

    def _handle_data_response(self, envelope: MessageEnvelope) -> None:
        """Handle data responses from connectors and forward to AI when complete."""
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
