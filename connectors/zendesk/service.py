"""
Connector-ZenDesk — ZenDesk ticket management via REST API.

Provides Kevin with the ability to:
- Create new tickets
- Query/search existing tickets
- Update ticket status, priority, assignee
- Close/resolve tickets
- Add comments (public or internal notes)

Uses ZenDesk API v2 with email + API token authentication.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from neurokit.envelope import EventType, MessageEnvelope
from neurokit.service import BaseService

logger = logging.getLogger("connector-zendesk")


class ZenDeskConnector(BaseService):
    """
    ZenDesk connector for ticket management.

    Command-driven — responds to messages from the Resolver/AI worker
    to create, query, update, and close tickets.
    """

    def __init__(self, config):
        super().__init__(config)
        self._http: Optional[httpx.Client] = None
        self._base_url: str = ""
        self._auth_email: str = ""
        self._api_token: str = ""
        self._group_id: Optional[int] = None
        self._group_name: str = ""

    def on_startup(self) -> None:
        """Retrieve ZenDesk credentials from HashiCorp Vault."""
        secrets = self.secrets.get_all("zendesk")

        self._base_url = secrets.get("base_url", "").rstrip("/")
        self._auth_email = secrets.get("auth_email", "")
        self._api_token = secrets.get("api_token", "")
        self._group_name = secrets.get("group_name", "IT-Support")

        if not self._base_url or not self._auth_email or not self._api_token:
            raise ValueError(
                "ZenDesk config incomplete — need base_url, auth_email, api_token in Vault"
            )

        # ZenDesk API uses email/token auth
        self._http = httpx.Client(
            base_url=f"{self._base_url}/api/v2",
            auth=(f"{self._auth_email}/token", self._api_token),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=30,
        )

        # Verify connectivity
        self._verify_connection()

        # Discover group ID
        self._discover_group()

        self.audit.log_system(
            action="zendesk_connected",
            resource="zendesk-api",
            details={
                "base_url": self._base_url,
                "auth_email": self._auth_email,
                "group": self._group_name,
                "group_id": self._group_id,
            },
        )

        logger.info(
            "Connected to ZenDesk: %s (auth: %s, group: %s [%s])",
            self._base_url, self._auth_email, self._group_name, self._group_id
        )

    def _verify_connection(self) -> None:
        """Verify ZenDesk API connectivity."""
        try:
            resp = self._http.get("/users/me.json")
            resp.raise_for_status()
            me = resp.json().get("user", {})
            logger.info(
                "ZenDesk auth verified: %s (%s)",
                me.get("name", "unknown"),
                me.get("role", "unknown"),
            )
        except Exception as e:
            logger.error("ZenDesk connection failed: %s", e)
            raise

    def _discover_group(self) -> None:
        """Discover the group ID by name from ZenDesk."""
        try:
            resp = self._http.get("/groups.json")
            resp.raise_for_status()
            groups = resp.json().get("groups", [])
            for group in groups:
                if self._group_name.lower() == group.get("name", "").lower():
                    self._group_id = group.get("id")
                    self._group_name = group.get("name", self._group_name)
                    logger.info(
                        "Discovered group: '%s' (id=%s)", self._group_name, self._group_id
                    )
                    return
            # Log available groups if not found
            available = [g.get("name") for g in groups]
            logger.warning(
                "Group '%s' not found. Available groups: %s",
                self._group_name, available
            )
        except Exception as e:
            logger.warning("Group discovery failed: %s", e)

    def setup_queues(self) -> None:
        """Set up RabbitMQ queues for ZenDesk commands."""
        self.inbox = self.rmq.declare_queue(
            f"{self.config.service_name}.inbox",
            routing_keys=[
                "zendesk.command.create",
                "zendesk.command.update",
                "zendesk.command.close",
                "zendesk.command.comment",
                "zendesk.query.ticket",
                "zendesk.query.search",
                "zendesk.query.list",
            ],
        )
        self.rmq.consume(self.inbox, self.handle_message)

    def handle_message(self, envelope: MessageEnvelope) -> Optional[MessageEnvelope]:
        """Route incoming commands to the appropriate handler."""
        msg_type = envelope.message_type
        payload = envelope.payload

        handlers = {
            "zendesk.command.create": self._handle_create,
            "zendesk.command.update": self._handle_update,
            "zendesk.command.close": self._handle_close,
            "zendesk.command.comment": self._handle_comment,
            "zendesk.query.ticket": self._handle_get_ticket,
            "zendesk.query.search": self._handle_search,
            "zendesk.query.list": self._handle_list,
        }

        handler = handlers.get(msg_type)
        if not handler:
            logger.warning("Unknown message type: %s", msg_type)
            return envelope.create_reply(
                source=self.service_name,
                message_type="zendesk.response.error",
                payload={"error": f"Unknown command: {msg_type}"},
            )

        try:
            result = handler(payload, envelope)

            try:
                self.audit.log_from_envelope(
                    envelope=envelope,
                    event_type=EventType.DATA_ACCESS,
                    action=msg_type,
                    resource="zendesk",
                    details={"result_keys": list(result.keys()) if result else []},
                )
            except Exception:
                pass

            reply_type = msg_type.replace("command.", "response.").replace(
                "query.", "response."
            )
            return envelope.create_reply(
                source=self.service_name,
                message_type=reply_type,
                payload=result,
            )

        except Exception as e:
            logger.error("ZenDesk handler error (%s): %s", msg_type, e, exc_info=True)
            reply_type = msg_type.replace("command.", "response.").replace(
                "query.", "response."
            )
            return envelope.create_reply(
                source=self.service_name,
                message_type=reply_type,
                payload={"error": str(e)},
            )

    # ── Command Handlers ────────────────────────────────────────────

    def _handle_create(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Create a new ZenDesk ticket.

        Expected payload:
        - subject: Ticket subject (required)
        - body: Ticket description/body (required)
        - priority: urgent, high, normal, low (default: normal)
        - type: problem, incident, question, task (default: incident)
        - tags: list of tags (optional)
        - requester_email: email of the requester (optional)
        - assignee_email: email of the assignee (optional)
        - group_name: support group name (optional)

        Also accepts natural language in 'text' field as fallback.
        """
        subject = payload.get("subject", "")
        body = payload.get("body", "")
        priority = payload.get("priority", "normal")
        ticket_type = payload.get("type", "incident")
        tags = payload.get("tags", [])
        requester_email = payload.get("requester_email", "")
        assignee_email = payload.get("assignee_email", "")
        group_name = payload.get("group_name", "")

        # Fallback: parse from natural language text
        if not subject and payload.get("text"):
            parsed = self._parse_create_text(payload["text"])
            subject = parsed.get("subject", subject)
            body = parsed.get("body", body)
            priority = parsed.get("priority", priority)
            tags = parsed.get("tags", tags)

        if not subject:
            return {"status": "error", "error": "Missing required field: subject"}
        if not body:
            body = subject  # Use subject as body if not provided

        # Build ticket object
        ticket_data: Dict[str, Any] = {
            "ticket": {
                "subject": subject,
                "comment": {"body": body},
                "priority": priority,
                "type": ticket_type,
            }
        }

        if tags:
            ticket_data["ticket"]["tags"] = tags

        if requester_email:
            ticket_data["ticket"]["requester"] = {"email": requester_email}

        if assignee_email:
            assignee_id = self._lookup_user_id(assignee_email)
            if assignee_id:
                ticket_data["ticket"]["assignee_id"] = assignee_id

        if group_name:
            group_id = self._lookup_group_id(group_name)
            if group_id:
                ticket_data["ticket"]["group_id"] = group_id
        elif self._group_id:
            # Default to configured group
            ticket_data["ticket"]["group_id"] = self._group_id

        resp = self._http.post("/tickets.json", json=ticket_data)
        resp.raise_for_status()
        ticket = resp.json().get("ticket", {})

        logger.info(
            "Created ticket #%s: %s (priority=%s)",
            ticket.get("id"),
            subject[:50],
            priority,
        )

        return {
            "status": "created",
            "ticket": self._format_ticket(ticket),
        }

    def _handle_update(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Update an existing ZenDesk ticket.

        Expected payload:
        - ticket_id: ID of the ticket to update (required)
        - status: new, open, pending, hold, solved, closed (optional)
        - priority: urgent, high, normal, low (optional)
        - assignee_email: new assignee (optional)
        - tags: replacement tags (optional)
        - add_tags: tags to add (optional)
        - remove_tags: tags to remove (optional)
        - comment: comment to add with the update (optional)
        - internal_note: if true, comment is internal (optional)
        """
        ticket_id = payload.get("ticket_id")
        if not ticket_id:
            return {"status": "error", "error": "Missing required field: ticket_id"}

        update_data: Dict[str, Any] = {"ticket": {}}

        if "status" in payload:
            update_data["ticket"]["status"] = payload["status"]
        if "priority" in payload:
            update_data["ticket"]["priority"] = payload["priority"]
        if "tags" in payload:
            update_data["ticket"]["tags"] = payload["tags"]
        if "add_tags" in payload:
            update_data["ticket"]["additional_tags"] = payload["add_tags"]
        if "remove_tags" in payload:
            update_data["ticket"]["remove_tags"] = payload["remove_tags"]
        if "assignee_email" in payload:
            assignee_id = self._lookup_user_id(payload["assignee_email"])
            if assignee_id:
                update_data["ticket"]["assignee_id"] = assignee_id

        if "comment" in payload:
            update_data["ticket"]["comment"] = {
                "body": payload["comment"],
                "public": not payload.get("internal_note", False),
            }

        if not update_data["ticket"]:
            return {"status": "error", "error": "No update fields provided"}

        resp = self._http.put(f"/tickets/{ticket_id}.json", json=update_data)
        resp.raise_for_status()
        ticket = resp.json().get("ticket", {})

        logger.info("Updated ticket #%s", ticket_id)

        return {
            "status": "updated",
            "ticket": self._format_ticket(ticket),
        }

    def _handle_close(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Close/solve a ZenDesk ticket.

        Expected payload:
        - ticket_id: ID of the ticket to close (required)
        - comment: closing comment (optional)
        - status: solved or closed (default: solved)
        """
        ticket_id = payload.get("ticket_id")
        if not ticket_id:
            return {"status": "error", "error": "Missing required field: ticket_id"}

        status = payload.get("status", "solved")
        update_data: Dict[str, Any] = {"ticket": {"status": status}}

        if "comment" in payload:
            update_data["ticket"]["comment"] = {
                "body": payload["comment"],
                "public": True,
            }

        resp = self._http.put(f"/tickets/{ticket_id}.json", json=update_data)
        resp.raise_for_status()
        ticket = resp.json().get("ticket", {})

        logger.info("Closed ticket #%s (status=%s)", ticket_id, status)

        return {
            "status": "closed",
            "ticket": self._format_ticket(ticket),
        }

    def _handle_comment(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Add a comment to an existing ZenDesk ticket.

        Expected payload:
        - ticket_id: ID of the ticket (required)
        - body: Comment text (required)
        - public: Whether the comment is public or internal (default: true)
        """
        ticket_id = payload.get("ticket_id")
        body = payload.get("body", "")

        if not ticket_id:
            return {"status": "error", "error": "Missing required field: ticket_id"}
        if not body:
            return {"status": "error", "error": "Missing required field: body"}

        is_public = payload.get("public", True)

        update_data = {
            "ticket": {
                "comment": {
                    "body": body,
                    "public": is_public,
                }
            }
        }

        resp = self._http.put(f"/tickets/{ticket_id}.json", json=update_data)
        resp.raise_for_status()
        ticket = resp.json().get("ticket", {})

        comment_type = "public comment" if is_public else "internal note"
        logger.info("Added %s to ticket #%s", comment_type, ticket_id)

        return {
            "status": "commented",
            "ticket_id": ticket_id,
            "comment_type": comment_type,
            "ticket": self._format_ticket(ticket),
        }

    # ── Query Handlers ──────────────────────────────────────────────

    def _handle_get_ticket(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Get a specific ticket by ID.

        Expected payload:
        - ticket_id: ID of the ticket (required)
        - include_comments: Whether to include comments (default: false)
        """
        ticket_id = payload.get("ticket_id")
        if not ticket_id:
            # Try to extract from text
            import re
            text = payload.get("text", "")
            match = re.search(r'#?(\d{2,})', text)
            if match:
                ticket_id = match.group(1)

        if not ticket_id:
            return {"status": "error", "error": "Missing required field: ticket_id"}

        resp = self._http.get(f"/tickets/{ticket_id}.json")
        resp.raise_for_status()
        ticket = resp.json().get("ticket", {})

        result = {
            "status": "ok",
            "ticket": self._format_ticket(ticket),
        }

        if payload.get("include_comments", False):
            comments = self._get_ticket_comments(ticket_id)
            result["comments"] = comments

        return result

    def _handle_search(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Search ZenDesk tickets.

        Expected payload:
        - query: ZenDesk search query string (optional)
        - status: Filter by status (optional)
        - priority: Filter by priority (optional)
        - assignee: Filter by assignee email (optional)
        - tags: Filter by tags (optional)
        - text: Natural language search (fallback)
        - limit: Max results (default: 25)
        """
        query_parts = []

        # Build query from structured fields
        if payload.get("query"):
            query_parts.append(payload["query"])
        if payload.get("status"):
            query_parts.append(f"status:{payload['status']}")
        if payload.get("priority"):
            query_parts.append(f"priority:{payload['priority']}")
        if payload.get("assignee"):
            query_parts.append(f"assignee:{payload['assignee']}")
        if payload.get("tags"):
            tags = payload["tags"]
            if isinstance(tags, list):
                for tag in tags:
                    query_parts.append(f"tags:{tag}")
            else:
                query_parts.append(f"tags:{tags}")

        # Fallback: parse natural language text into ZenDesk query filters
        if not query_parts and payload.get("text"):
            text = payload["text"].lower()
            import re

            # Extract status keywords
            status_keywords = {
                "open": "open", "pending": "pending", "new": "new",
                "solved": "solved", "closed": "closed", "hold": "hold",
                "on hold": "hold", "unresolved": "open",
            }
            for keyword, status in status_keywords.items():
                if keyword in text:
                    query_parts.append(f"status:{status}")
                    break

            # Extract priority keywords
            priority_keywords = {
                "urgent": "urgent", "high": "high", "critical": "urgent",
                "normal": "normal", "low": "low",
            }
            for keyword, priority in priority_keywords.items():
                if keyword in text:
                    query_parts.append(f"priority:{priority}")
                    break

            # Extract email/assignee
            email_match = re.search(r'[\w.+-]+@[\w-]+\.[\w.-]+', text)
            if email_match:
                query_parts.append(f"assignee:{email_match.group()}")

            # If no structured filters extracted, default to open tickets
            if not query_parts:
                query_parts.append("type:ticket status<solved")
            else:
                query_parts.insert(0, "type:ticket")

        if not query_parts:
            # Default: recent open tickets
            query_parts.append("type:ticket status<solved")

        # Always apply brand filter
        brand = self._group_filter()
        if brand:
            query_parts.append(brand)

        query = " ".join(query_parts)
        limit = min(int(payload.get("limit", 25)), 100)

        resp = self._http.get(
            "/search.json",
            params={"query": query, "per_page": limit, "sort_by": "updated_at", "sort_order": "desc"},
        )
        resp.raise_for_status()
        data = resp.json()

        tickets = [self._format_ticket(t) for t in data.get("results", [])]

        logger.info("Search '%s' returned %d tickets", query[:50], len(tickets))

        return {
            "status": "ok",
            "query": query,
            "count": data.get("count", len(tickets)),
            "tickets": tickets,
        }

    def _handle_list(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        List recent tickets (open/pending by default).

        Expected payload:
        - status: Filter by status (default: open,pending)
        - limit: Max results (default: 25)
        - sort_by: updated_at, created_at (default: updated_at)
        - sort_order: asc, desc (default: desc)
        """
        status_filter = payload.get("status", "open,pending")
        limit = min(int(payload.get("limit", 25)), 100)
        sort_by = payload.get("sort_by", "updated_at")
        sort_order = payload.get("sort_order", "desc")

        # Use search API for flexible filtering
        statuses = [s.strip() for s in status_filter.split(",")]
        status_query = " ".join(f"status:{s}" for s in statuses)
        query = f"type:ticket {status_query}"

        # Always apply brand filter
        brand = self._group_filter()
        if brand:
            query += f" {brand}"

        resp = self._http.get(
            "/search.json",
            params={
                "query": query,
                "per_page": limit,
                "sort_by": sort_by,
                "sort_order": sort_order,
            },
        )
        resp.raise_for_status()
        data = resp.json()

        tickets = [self._format_ticket(t) for t in data.get("results", [])]

        logger.info("Listed %d tickets (status=%s)", len(tickets), status_filter)

        return {
            "status": "ok",
            "filter": status_filter,
            "count": data.get("count", len(tickets)),
            "tickets": tickets,
        }

    # ── Helpers ──────────────────────────────────────────────────────

    def _group_filter(self) -> str:
        """Return ZenDesk search filter clause for the configured group."""
        if self._group_id:
            return f"group_id:{self._group_id}"
        return ""

    def _format_ticket(self, ticket: Dict[str, Any]) -> Dict[str, Any]:
        """Format a ZenDesk ticket for consistent output."""
        return {
            "id": ticket.get("id"),
            "subject": ticket.get("subject", ""),
            "status": ticket.get("status", ""),
            "priority": ticket.get("priority", ""),
            "type": ticket.get("type", ""),
            "created_at": ticket.get("created_at", ""),
            "updated_at": ticket.get("updated_at", ""),
            "requester_id": ticket.get("requester_id"),
            "assignee_id": ticket.get("assignee_id"),
            "group_id": ticket.get("group_id"),
            "tags": ticket.get("tags", []),
            "description": ticket.get("description", "")[:500],
            "url": f"{self._base_url}/agent/tickets/{ticket.get('id')}",
        }

    def _get_ticket_comments(self, ticket_id: int) -> List[Dict[str, Any]]:
        """Get comments for a ticket."""
        try:
            resp = self._http.get(f"/tickets/{ticket_id}/comments.json")
            resp.raise_for_status()
            comments = resp.json().get("comments", [])
            return [
                {
                    "id": c.get("id"),
                    "body": c.get("body", "")[:500],
                    "public": c.get("public", True),
                    "author_id": c.get("author_id"),
                    "created_at": c.get("created_at", ""),
                }
                for c in comments[-10:]  # Last 10 comments
            ]
        except Exception as e:
            logger.error("Failed to get comments for ticket #%s: %s", ticket_id, e)
            return []

    def _lookup_user_id(self, email: str) -> Optional[int]:
        """Look up a ZenDesk user ID by email."""
        try:
            resp = self._http.get(
                "/users/search.json", params={"query": email}
            )
            resp.raise_for_status()
            users = resp.json().get("users", [])
            if users:
                return users[0].get("id")
        except Exception as e:
            logger.error("User lookup failed for %s: %s", email, e)
        return None

    def _lookup_group_id(self, name: str) -> Optional[int]:
        """Look up a ZenDesk group ID by name."""
        try:
            resp = self._http.get("/groups.json")
            resp.raise_for_status()
            groups = resp.json().get("groups", [])
            for g in groups:
                if g.get("name", "").lower() == name.lower():
                    return g.get("id")
        except Exception as e:
            logger.error("Group lookup failed for %s: %s", name, e)
        return None

    def _parse_create_text(self, text: str) -> Dict[str, Any]:
        """Parse natural language ticket creation request."""
        import re
        result: Dict[str, Any] = {}

        # Extract subject from quotes or after "subject:"
        subject_match = re.search(
            r'subject[:\s]+["\']?(.+?)["\']?(?:\n|$)',
            text, re.IGNORECASE
        )
        if subject_match:
            result["subject"] = subject_match.group(1).strip()

        # Extract priority
        priority_match = re.search(
            r'\b(urgent|high|normal|low)\s+priority\b|\bpriority[:\s]+(urgent|high|normal|low)\b',
            text, re.IGNORECASE
        )
        if priority_match:
            result["priority"] = (priority_match.group(1) or priority_match.group(2)).lower()

        # Extract tags
        tags_match = re.search(
            r'tags?[:\s]+(.+?)(?:\n|$)', text, re.IGNORECASE
        )
        if tags_match:
            result["tags"] = [
                t.strip().strip("'\"")
                for t in tags_match.group(1).split(",")
            ]

        # Body — everything else or explicit body field
        body_match = re.search(
            r'(?:body|description|details?)[:\s]+(.+?)(?:\n---|\n\*\*|$)',
            text, re.DOTALL | re.IGNORECASE,
        )
        if body_match:
            result["body"] = body_match.group(1).strip()

        return result

    def on_shutdown(self) -> None:
        """Clean up HTTP client."""
        if self._http:
            self._http.close()
            logger.info("ZenDesk HTTP client closed")


# ── Entrypoint ──────────────────────────────────────────────────────

if __name__ == "__main__":
    import os
    svc = os.environ.get("NEURO_SERVICE_NAME", "connector-zendesk")
    if svc.startswith("connector-"):
        svc = svc[len("connector-"):]
    service = ZenDeskConnector.create(svc)
    service.run()
