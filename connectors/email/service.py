"""
Connector-Email — Microsoft 365 mailbox management via Graph API.

Manages Kevin's email inbox (kevin@heads-up.com):
- Polls for new incoming emails at a configurable interval
- Publishes new emails to RabbitMQ for AI processing
- Handles send/reply commands from the AI worker
- Marks emails as read after processing
- Queries M365 active users and mailbox usage

Uses Microsoft Graph API with application permissions:
- Mail.Read, Mail.ReadWrite, Mail.Send, User.Read.All
"""

import logging
import time
import threading
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

import httpx

from neurokit.envelope import EventType, MessageEnvelope
from neurokit.service import BaseService

logger = logging.getLogger("connector-email")


class EmailConnector(BaseService):
    """
    Email connector for Kevin's Microsoft 365 mailbox.

    Runs two loops:
    1. Inbox poller (thread) — checks for new emails, publishes to RabbitMQ
    2. Command consumer — listens for send/reply commands from AI worker
    """

    GRAPH_BASE = "https://graph.microsoft.com/v1.0"

    def __init__(self, config):
        super().__init__(config)
        self._http: Optional[httpx.Client] = None
        self._access_token: Optional[str] = None
        self._token_expiry: float = 0
        self._tenant_id: str = ""
        self._client_id: str = ""
        self._client_secret: str = ""
        self._mailbox: str = ""
        self._poll_interval: int = 60  # seconds
        self._last_poll_time: Optional[str] = None
        self._poller_thread: Optional[threading.Thread] = None
        self._running: bool = False

    def on_startup(self) -> None:
        """Retrieve Graph API credentials and mailbox config."""
        graph_secrets = self.secrets.get_all("microsoft-graph")
        self._tenant_id = graph_secrets["tenant_id"]
        self._client_id = graph_secrets["client_id"]
        self._client_secret = graph_secrets["client_secret"]

        email_config = self.secrets.get_all("email")
        self._mailbox = email_config.get("mailbox", "kevin@heads-up.com")
        self._poll_interval = int(email_config.get("poll_interval", "60"))

        self._http = httpx.Client(timeout=30)
        self._authenticate()

        # Verify mailbox access
        self._verify_mailbox()

        self.audit.log_system(
            action="email_connected",
            resource="microsoft-graph-mail",
            details={"mailbox": self._mailbox},
        )

        # Start inbox poller thread
        self._running = True
        self._poller_thread = threading.Thread(
            target=self._poll_inbox_loop,
            name="email-inbox-poller",
            daemon=True,
        )
        self._poller_thread.start()

    def _verify_mailbox(self) -> None:
        """Verify we can access Kevin's mailbox."""
        try:
            self._ensure_authenticated()
            resp = self._http.get(
                f"{self.GRAPH_BASE}/users/{self._mailbox}/mailFolders/inbox",
                headers={"Authorization": f"Bearer {self._access_token}"},
            )
            resp.raise_for_status()
            folder = resp.json()
            logger.info(
                "Mailbox verified: %s (unread: %d, total: %d)",
                self._mailbox,
                folder.get("unreadItemCount", 0),
                folder.get("totalItemCount", 0),
            )
        except Exception as e:
            logger.warning("Could not verify mailbox %s: %s", self._mailbox, e)

    # ── Authentication ──────────────────────────────────────────────

    def _authenticate(self) -> None:
        """Obtain OAuth2 token via client credentials flow."""
        url = f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token"
        resp = self._http.post(url, data={
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        })
        resp.raise_for_status()
        data = resp.json()
        self._access_token = data["access_token"]
        self._token_expiry = time.time() + data.get("expires_in", 3600) - 120
        logger.info("Authenticated with Microsoft Graph for mail")

    def _ensure_authenticated(self) -> None:
        """Refresh token if expired."""
        if time.time() >= self._token_expiry:
            self._authenticate()

    def _graph_request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        """Make an authenticated request to Microsoft Graph."""
        self._ensure_authenticated()
        kwargs.setdefault("headers", {})["Authorization"] = f"Bearer {self._access_token}"
        # Handle full URLs (from pagination nextLink)
        if path.startswith("http"):
            url = path
        else:
            url = f"{self.GRAPH_BASE}{path}"
        resp = self._http.request(method, url, **kwargs)
        resp.raise_for_status()
        if resp.status_code == 204:
            return {}
        return resp.json()

    # ── Queue Setup ─────────────────────────────────────────────────

    def setup_queues(self) -> None:
        """Set up RabbitMQ queues for email commands."""
        self.inbox = self.rmq.declare_queue(
            "connector-email.inbox",
            routing_keys=[
                "email.command.send",
                "email.command.reply",
                "email.command.list",
                "email.command.read",
                "email.command.search_mailbox",
                "email.command.search_org",
                "email.query.active-users",
                "email.query.mailbox-usage",
            ],
        )
        self.rmq.consume(self.inbox, self.handle_message)

    def handle_message(self, envelope: MessageEnvelope) -> Optional[MessageEnvelope]:
        """Route email commands to handlers."""
        msg_type = envelope.message_type
        payload = envelope.payload

        handlers = {
            "email.command.send": self._handle_send,
            "email.command.reply": self._handle_reply,
            "email.command.list": self._handle_list,
            "email.command.read": self._handle_read,
            "email.command.search_mailbox": self._handle_search_mailbox,
            "email.command.search_org": self._handle_search_org,
            "email.query.active-users": self._handle_active_users,
            "email.query.mailbox-usage": self._handle_mailbox_usage,
        }

        handler = handlers.get(msg_type)
        if not handler:
            return envelope.create_reply(
                source=self.service_name,
                message_type="email.response.error",
                payload={"error": f"Unknown command: {msg_type}"},
            )

        try:
            result = handler(payload, envelope)

            try:
                self.audit.log_from_envelope(
                    envelope=envelope,
                    event_type=EventType.DATA_ACCESS,
                    action=msg_type,
                    resource="email",
                    details={"result": result.get("status", "ok")},
                )
            except Exception as audit_err:
                logger.warning("Audit log failed (non-fatal): %s", audit_err)

            # For query types, use query/response pattern
            if ".query." in msg_type:
                resp_type = msg_type.replace("query", "response")
            else:
                resp_type = msg_type.replace("command", "response")

            return envelope.create_reply(
                source=self.service_name,
                message_type=resp_type,
                payload=result,
            )

        except Exception as e:
            logger.error("Email command error for %s: %s", msg_type, e, exc_info=True)
            return envelope.create_reply(
                source=self.service_name,
                message_type="email.response.error",
                payload={"error": str(e)},
            )

    # ── Inbox Polling ───────────────────────────────────────────────

    def _poll_inbox_loop(self) -> None:
        """Background thread that polls for new emails."""
        logger.info("Inbox poller started (interval: %ds)", self._poll_interval)

        # Set initial poll time to now (only get future emails)
        self._last_poll_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        while self._running:
            try:
                self._poll_inbox()
            except Exception as e:
                logger.warning("Inbox poll error: %s", e)

            time.sleep(self._poll_interval)

    def _poll_inbox(self) -> None:
        """Check for new unread emails and publish them."""
        self._ensure_authenticated()

        # Fetch unread emails received since last poll
        filter_str = f"isRead eq false"
        if self._last_poll_time:
            filter_str += f" and receivedDateTime ge {self._last_poll_time}"

        try:
            resp = self._http.get(
                f"{self.GRAPH_BASE}/users/{self._mailbox}/mailFolders/inbox/messages",
                headers={"Authorization": f"Bearer {self._access_token}"},
                params={
                    "$filter": filter_str,
                    "$orderby": "receivedDateTime desc",
                    "$top": 20,
                    "$select": "id,subject,from,toRecipients,ccRecipients,receivedDateTime,bodyPreview,body,isRead,importance,hasAttachments,conversationId",
                },
            )
            resp.raise_for_status()
            messages = resp.json().get("value", [])
        except Exception as e:
            logger.warning("Failed to fetch inbox: %s", e)
            return

        if not messages:
            return

        logger.info("Found %d new email(s)", len(messages))

        for msg in messages:
            # Publish each email to RabbitMQ
            email_data = self._format_email(msg)

            envelope = MessageEnvelope.create(
                source=self.service_name,
                message_type="email.incoming",
                payload=email_data,
            )
            self.rmq.publish("email.incoming", envelope)

            # Mark as read
            try:
                self._http.patch(
                    f"{self.GRAPH_BASE}/users/{self._mailbox}/messages/{msg['id']}",
                    headers={
                        "Authorization": f"Bearer {self._access_token}",
                        "Content-Type": "application/json",
                    },
                    json={"isRead": True},
                )
            except Exception as e:
                logger.warning("Failed to mark email %s as read: %s", msg["id"], e)

        # Update poll timestamp
        self._last_poll_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def _format_email(self, msg: Dict[str, Any]) -> Dict[str, Any]:
        """Format a Graph API message into a clean structure."""
        from_addr = msg.get("from", {}).get("emailAddress", {})
        to_addrs = [
            r.get("emailAddress", {}).get("address", "")
            for r in msg.get("toRecipients", [])
        ]
        cc_addrs = [
            r.get("emailAddress", {}).get("address", "")
            for r in msg.get("ccRecipients", [])
        ]

        # Get body — prefer text, fall back to HTML with tag stripping
        body = msg.get("body", {})
        body_content = body.get("content", "")
        if body.get("contentType") == "html":
            import re
            body_text = re.sub(r'<[^>]+>', '', body_content)
            body_text = re.sub(r'\s+', ' ', body_text).strip()
        else:
            body_text = body_content

        # Truncate very long bodies
        if len(body_text) > 3000:
            body_text = body_text[:3000] + "\n... [truncated]"

        return {
            "message_id": msg.get("id"),
            "conversation_id": msg.get("conversationId"),
            "subject": msg.get("subject", "(no subject)"),
            "from": {
                "name": from_addr.get("name", ""),
                "email": from_addr.get("address", ""),
            },
            "to": to_addrs,
            "cc": cc_addrs,
            "received_at": msg.get("receivedDateTime"),
            "body_preview": msg.get("bodyPreview", ""),
            "body": body_text,
            "importance": msg.get("importance", "normal"),
            "has_attachments": msg.get("hasAttachments", False),
        }

    # ── Send Email ──────────────────────────────────────────────────

    def _handle_send(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Send a new email from Kevin's mailbox.

        Accepts either structured payload or natural language text.
        """
        to_addrs = payload.get("to", [])
        subject = payload.get("subject", "")
        body = payload.get("body", "")

        if not to_addrs and payload.get("text"):
            parsed = self._parse_send_text(payload["text"])
            to_addrs = parsed.get("to", [])
            subject = parsed.get("subject", subject)
            body = parsed.get("body", body)

        if isinstance(to_addrs, str):
            to_addrs = [to_addrs]
        cc_addrs = payload.get("cc", [])
        if isinstance(cc_addrs, str):
            cc_addrs = [cc_addrs]
        importance = payload.get("importance", "normal")

        if not to_addrs or not body:
            return {"status": "error", "error": "Could not determine recipient and/or body from request"}

        if not subject:
            subject = body[:50] + ("..." if len(body) > 50 else "")

        message = {
            "message": {
                "subject": subject,
                "body": {
                    "contentType": "text",
                    "content": body,
                },
                "toRecipients": [
                    {"emailAddress": {"address": addr}} for addr in to_addrs
                ],
                "importance": importance,
            }
        }

        if cc_addrs:
            message["message"]["ccRecipients"] = [
                {"emailAddress": {"address": addr}} for addr in cc_addrs
            ]

        self._graph_request(
            "POST",
            f"/users/{self._mailbox}/sendMail",
            json=message,
        )

        logger.info("Sent email to %s: %s", to_addrs, subject)

        self.audit.log_from_envelope(
            envelope=envelope,
            event_type=EventType.DATA_ACCESS,
            action="email_sent",
            resource="email",
            details={
                "to": to_addrs,
                "cc": cc_addrs,
                "subject": subject,
            },
        )

        return {
            "status": "sent",
            "to": to_addrs,
            "cc": cc_addrs,
            "subject": subject,
        }

    # ── Reply to Email ──────────────────────────────────────────────

    def _handle_reply(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """Reply to an existing email."""
        message_id = payload.get("message_id")
        body = payload.get("body", "")
        reply_all = payload.get("reply_all", False)

        if not message_id or not body:
            return {"status": "error", "error": "Missing 'message_id' and/or 'body'"}

        endpoint = "replyAll" if reply_all else "reply"

        self._graph_request(
            "POST",
            f"/users/{self._mailbox}/messages/{message_id}/{endpoint}",
            json={
                "message": {
                    "body": {
                        "contentType": "text",
                        "content": body,
                    },
                },
                "comment": body,
            },
        )

        logger.info("Replied to email %s (reply_all=%s)", message_id, reply_all)

        return {
            "status": "replied",
            "message_id": message_id,
            "reply_all": reply_all,
        }

    # ── List Emails ─────────────────────────────────────────────────

    def _handle_list(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """List emails from Kevin's mailbox."""
        folder = payload.get("folder", "inbox")
        unread_only = payload.get("unread_only", False)
        from_email = payload.get("from_email")
        subject_filter = payload.get("subject")
        limit = min(int(payload.get("limit", 10)), 50)

        filters = []
        if unread_only:
            filters.append("isRead eq false")
        if from_email:
            filters.append(f"from/emailAddress/address eq '{from_email}'")
        if subject_filter:
            filters.append(f"contains(subject, '{subject_filter}')")

        params = {
            "$orderby": "receivedDateTime desc",
            "$top": limit,
            "$select": "id,subject,from,receivedDateTime,bodyPreview,isRead,importance,hasAttachments",
        }
        if filters:
            params["$filter"] = " and ".join(filters)

        data = self._graph_request(
            "GET",
            f"/users/{self._mailbox}/mailFolders/{folder}/messages",
            params=params,
        )

        messages = []
        for msg in data.get("value", []):
            from_addr = msg.get("from", {}).get("emailAddress", {})
            messages.append({
                "message_id": msg.get("id"),
                "subject": msg.get("subject", "(no subject)"),
                "from_name": from_addr.get("name", ""),
                "from_email": from_addr.get("address", ""),
                "received_at": msg.get("receivedDateTime"),
                "preview": msg.get("bodyPreview", "")[:200],
                "is_read": msg.get("isRead", True),
                "importance": msg.get("importance", "normal"),
                "has_attachments": msg.get("hasAttachments", False),
            })

        return {
            "status": "ok",
            "folder": folder,
            "count": len(messages),
            "messages": messages,
        }

    # ── Read Single Email ───────────────────────────────────────────

    def _handle_read(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """Read the full content of a specific email."""
        message_id = payload.get("message_id")
        if not message_id:
            return {"status": "error", "error": "Missing 'message_id'"}

        data = self._graph_request(
            "GET",
            f"/users/{self._mailbox}/messages/{message_id}",
            params={
                "$select": "id,subject,from,toRecipients,ccRecipients,receivedDateTime,body,importance,hasAttachments,conversationId",
            },
        )

        return {
            "status": "ok",
            "email": self._format_email(data),
        }

    # ── M365 User & Mailbox Queries ─────────────────────────────────

    def _handle_active_users(
        self, payload: Dict, envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        List M365 users with license/account status from Graph API.

        Filters based on natural language:
        - active/enabled: accountEnabled eq true
        - disabled: accountEnabled eq false
        - all: no filter
        """
        text = payload.get("text", "").lower()

        # Determine filter
        filter_str = ""
        if "disabled" in text or "inactive" in text:
            filter_str = "accountEnabled eq false"
        elif "active" in text or "enabled" in text:
            filter_str = "accountEnabled eq true"

        # Graph API limitations:
        # - Cannot use $orderby with $filter on some property combinations
        # - assignedPlans is a complex type that causes issues with $filter
        # So we use basic select, filter, and sort client-side
        params = {
            "$select": "id,displayName,mail,userPrincipalName,jobTitle,department,"
                       "accountEnabled,assignedLicenses,createdDateTime",
            "$top": "999",
        }
        if filter_str:
            params["$filter"] = filter_str

        # Paginate through all users
        all_users = []
        path = "/users"
        first_request = True
        while path:
            try:
                if first_request:
                    result = self._graph_request("GET", path, params=params)
                    first_request = False
                else:
                    # Subsequent pages: nextLink is a full URL with params
                    result = self._graph_request("GET", path)
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 400 and first_request:
                    # Retry without $orderby if present
                    params.pop("$orderby", None)
                    result = self._graph_request("GET", path, params=params)
                    first_request = False
                else:
                    raise

            all_users.extend(result.get("value", []))

            # Handle pagination
            next_link = result.get("@odata.nextLink", "")
            if next_link:
                path = next_link  # Full URL, _graph_request handles it
            else:
                path = None

        # Format results
        formatted = []
        for u in all_users:
            has_license = bool(u.get("assignedLicenses"))

            formatted.append({
                "name": u.get("displayName", ""),
                "email": u.get("mail", ""),
                "upn": u.get("userPrincipalName", ""),
                "title": u.get("jobTitle", ""),
                "department": u.get("department", ""),
                "enabled": u.get("accountEnabled", False),
                "has_license": has_license,
                "license_count": len(u.get("assignedLicenses") or []),
            })

        # Sort by name client-side
        formatted.sort(key=lambda u: (u.get("name") or "").lower())

        active = sum(1 for u in formatted if u["enabled"])
        disabled = sum(1 for u in formatted if not u["enabled"])
        licensed = sum(1 for u in formatted if u["has_license"])
        disabled_with_license = sum(
            1 for u in formatted if not u["enabled"] and u["has_license"]
        )

        logger.info(
            "M365 user query: %d total, %d active, %d disabled, %d licensed, %d disabled+licensed",
            len(formatted), active, disabled, licensed, disabled_with_license,
        )

        return {
            "status": "ok",
            "count": len(formatted),
            "active": active,
            "disabled": disabled,
            "licensed": licensed,
            "disabled_with_license": disabled_with_license,
            "users": formatted,
        }

    def _handle_mailbox_usage(
        self, payload: Dict, envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Get mailbox usage details from M365 reports API.

        Uses: GET /reports/getMailboxUsageDetail(period='D7')
        Requires: Reports.Read.All permission
        """
        text = payload.get("text", "").lower()

        # Determine period
        period = "D7"  # Default: 7 days
        if "30" in text or "month" in text:
            period = "D30"
        elif "90" in text or "quarter" in text:
            period = "D90"
        elif "180" in text or "half" in text:
            period = "D180"

        try:
            # Reports API returns CSV, need to handle differently
            self._ensure_authenticated()
            headers = {"Authorization": f"Bearer {self._access_token}"}
            resp = self._http.get(
                f"{self.GRAPH_BASE}/reports/getMailboxUsageDetail(period='{period}')",
                headers=headers,
                follow_redirects=True,
            )
            resp.raise_for_status()

            # Parse CSV response
            import csv
            import io
            reader = csv.DictReader(io.StringIO(resp.text))
            mailboxes = []
            for row in reader:
                mailboxes.append({
                    "name": row.get("Display Name", ""),
                    "upn": row.get("User Principal Name", ""),
                    "storage_used_bytes": int(row.get("Storage Used (Byte)", 0) or 0),
                    "storage_used_mb": round(int(row.get("Storage Used (Byte)", 0) or 0) / 1048576, 1),
                    "item_count": int(row.get("Item Count", 0) or 0),
                    "last_activity": row.get("Last Activity Date", ""),
                    "has_archive": row.get("Has Archive", "").lower() == "true",
                    "deleted_item_count": int(row.get("Deleted Item Count", 0) or 0),
                })

            # Sort by storage used descending
            mailboxes.sort(key=lambda m: m["storage_used_bytes"], reverse=True)

            total_storage = sum(m["storage_used_bytes"] for m in mailboxes)

            logger.info("Mailbox usage report: %d mailboxes, %.1f GB total",
                       len(mailboxes), total_storage / 1073741824)

            return {
                "status": "ok",
                "period": period,
                "count": len(mailboxes),
                "total_storage_gb": round(total_storage / 1073741824, 2),
                "mailboxes": mailboxes[:100],
            }

        except httpx.HTTPStatusError as e:
            if e.response.status_code == 403:
                return {
                    "status": "error",
                    "error": "Reports.Read.All permission required. Add this to the app registration in Azure AD.",
                }
            raise
        except Exception as e:
            logger.error("Mailbox usage report failed: %s", e)
            return {"status": "error", "error": str(e)}

    # ── Search Specific Mailbox ──────────────────────────────────────

    def _handle_search_mailbox(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """Search a specific user's mailbox."""
        mailbox = payload.get("mailbox", "")
        query = payload.get("query", "")
        text = payload.get("text", "")

        if not mailbox and text:
            parsed = self._parse_search_text(text)
            mailbox = parsed.get("mailbox", mailbox)
            query = parsed.get("query", query)
            payload = {**payload, **parsed}

        if not mailbox:
            return {"status": "error", "error": "No mailbox specified. Include a user email address."}

        folder = payload.get("folder", "all")
        from_email = payload.get("from_email")
        to_email = payload.get("to_email")
        date_from = payload.get("date_from")
        has_attachments = payload.get("has_attachments")
        limit = min(int(payload.get("limit", 20)), 50)

        filters = []
        if from_email:
            filters.append(f"from/emailAddress/address eq '{from_email}'")
        if to_email:
            filters.append(f"toRecipients/any(r:r/emailAddress/address eq '{to_email}')")
        if has_attachments is not None:
            filters.append(f"hasAttachments eq {str(has_attachments).lower()}")

        if date_from:
            date_from = self._resolve_date(date_from)
            if date_from:
                filters.append(f"receivedDateTime ge {date_from}")

        params = {
            "$top": limit,
            "$select": "id,subject,from,toRecipients,ccRecipients,receivedDateTime,bodyPreview,isRead,importance,hasAttachments",
        }

        if query:
            import re as _re
            clean_query = _re.sub(r"['\"\(\)\[\]{}]", "", query)
            clean_query = clean_query.strip()
            if clean_query:
                params["$search"] = f'"{clean_query}"'
        else:
            params["$orderby"] = "receivedDateTime desc"

        if filters:
            params["$filter"] = " and ".join(filters)

        if folder == "all":
            path = f"/users/{mailbox}/messages"
        elif folder == "sentitems":
            path = f"/users/{mailbox}/mailFolders/sentitems/messages"
        else:
            path = f"/users/{mailbox}/mailFolders/{folder}/messages"

        logger.info("Searching mailbox %s: query=%r folder=%s", mailbox, query, folder)

        try:
            data = self._graph_request("GET", path, params=params)
        except Exception as e:
            logger.warning("Mailbox search failed for %s: %s", mailbox, e)
            return {"status": "error", "error": f"Could not search mailbox {mailbox}: {e}"}

        messages = []
        for msg in data.get("value", []):
            from_addr = msg.get("from", {}).get("emailAddress", {})
            to_addrs = [r.get("emailAddress", {}).get("address", "") for r in msg.get("toRecipients", [])]
            messages.append({
                "message_id": msg.get("id"),
                "subject": msg.get("subject", "(no subject)"),
                "from_name": from_addr.get("name", ""),
                "from_email": from_addr.get("address", ""),
                "to": to_addrs,
                "received_at": msg.get("receivedDateTime"),
                "preview": msg.get("bodyPreview", "")[:200],
                "is_read": msg.get("isRead", True),
                "importance": msg.get("importance", "normal"),
                "has_attachments": msg.get("hasAttachments", False),
            })

        return {
            "status": "ok",
            "type": "mailbox_search",
            "mailbox": mailbox,
            "query": query,
            "count": len(messages),
            "messages": messages,
        }

    # ── Org-wide Content Search ─────────────────────────────────────

    def _handle_search_org(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """Search across multiple mailboxes in the organization."""
        query = payload.get("query", "")
        text = payload.get("text", "")

        if not query and text:
            parsed = self._parse_search_text(text)
            query = parsed.get("query", "")
            payload = {**payload, **parsed}

        if not query:
            return {"status": "error", "error": "No search terms provided."}

        mailboxes = payload.get("mailboxes", [])
        date_from = payload.get("date_from")
        limit_per = min(int(payload.get("limit_per_mailbox", 10)), 25)

        if not mailboxes:
            try:
                users_data = self._graph_request(
                    "GET", "/users",
                    params={
                        "$filter": "accountEnabled eq true",
                        "$select": "mail,userPrincipalName",
                        "$top": 100,
                    },
                )
                mailboxes = [
                    u.get("mail") or u.get("userPrincipalName", "")
                    for u in users_data.get("value", [])
                    if u.get("mail")
                ]
            except Exception as e:
                return {"status": "error", "error": f"Could not list users: {e}"}

        all_results = []
        errors = []

        filters = []
        if date_from:
            resolved = self._resolve_date(date_from)
            if resolved:
                filters.append(f"receivedDateTime ge {resolved}")

        for mbox in mailboxes[:50]:
            try:
                params = {
                    "$search": f'"{query}"',
                    "$top": limit_per,
                    "$select": "id,subject,from,toRecipients,receivedDateTime,bodyPreview,hasAttachments",
                }
                if filters:
                    params["$filter"] = " and ".join(filters)

                data = self._graph_request(
                    "GET", f"/users/{mbox}/messages",
                    params=params,
                )

                for msg in data.get("value", []):
                    from_addr = msg.get("from", {}).get("emailAddress", {})
                    to_addrs = [r.get("emailAddress", {}).get("address", "") for r in msg.get("toRecipients", [])]
                    all_results.append({
                        "mailbox": mbox,
                        "subject": msg.get("subject", "(no subject)"),
                        "from_name": from_addr.get("name", ""),
                        "from_email": from_addr.get("address", ""),
                        "to": to_addrs,
                        "received_at": msg.get("receivedDateTime"),
                        "preview": msg.get("bodyPreview", "")[:200],
                        "has_attachments": msg.get("hasAttachments", False),
                    })

            except Exception as e:
                errors.append(f"{mbox}: {e}")

        all_results.sort(key=lambda x: x.get("received_at", ""), reverse=True)

        return {
            "status": "ok",
            "type": "org_search",
            "query": query,
            "mailboxes_searched": len(mailboxes),
            "count": len(all_results),
            "messages": all_results[:100],
            "errors": errors[:5] if errors else [],
        }

    # ── Search Text Parser ──────────────────────────────────────────

    def _parse_search_text(self, text: str) -> Dict[str, Any]:
        """Parse natural language email search request."""
        import re
        result = {}

        text = re.sub(r'<mailto:([^|>]+)\|[^>]+>', r'\1', text)
        text = re.sub(r'<mailto:([^>]+)>', r'\1', text)
        text = re.sub(r'<([^|>]+)\|[^>]+>', r'\1', text)

        emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', text)
        if emails:
            from_match = re.search(r'(?:from|sent by)\s+(\S+@\S+)', text, re.IGNORECASE)
            to_match = re.search(r'(?:to|sent to|received by)\s+(\S+@\S+)', text, re.IGNORECASE)
            mailbox_match = re.search(r"(?:search|check|look in|look at)\s+(\S+@\S+)(?:'s)?(?:\s+mailbox)?", text, re.IGNORECASE)

            if mailbox_match:
                result["mailbox"] = mailbox_match.group(1)
            elif from_match:
                result["from_email"] = from_match.group(1)
            elif to_match:
                result["to_email"] = to_match.group(1)

            if "mailbox" not in result and "from_email" not in result and "to_email" not in result:
                result["mailbox"] = emails[0]

        query_match = re.search(
            r'(?:for|about|containing|with|mentioning|regarding)\s+["\']?(.+?)["\']?\s*$',
            text, re.IGNORECASE,
        )
        if query_match:
            raw_query = query_match.group(1).strip("'\" ")
            raw_query = re.sub(
                r'\b(emails?|with|in\s+the|subject\s+line|subject|body|that\s+contain|containing|line)\b',
                '', raw_query, flags=re.IGNORECASE,
            )
            raw_query = re.sub(r"['\"]", "", raw_query)
            raw_query = re.sub(r'\s+', ' ', raw_query).strip()
            if raw_query:
                result["query"] = raw_query

        if "query" not in result:
            cleaned = re.sub(r'[\w.+-]+@[\w-]+\.[\w.-]+', '', text)
            cleaned = re.sub(
                r'\b(search|check|find|look|emails?|mailbox|inbox|messages?|from|to|sent|in|for|the|a|an|my|their|his|her|show|me|get|where|subject|contains?|line)\b',
                '', cleaned, flags=re.IGNORECASE,
            )
            cleaned = re.sub(r"['\"]", "", cleaned)
            cleaned = re.sub(r'\s+', ' ', cleaned).strip()
            if cleaned:
                result["query"] = cleaned

        date_match = re.search(r'(?:last|past)\s+(\d+)\s*(days?|weeks?|months?|d|w|m)', text, re.IGNORECASE)
        if date_match:
            amount = int(date_match.group(1))
            unit = date_match.group(2).lower()
            result["date_from"] = f"{amount}{'d' if unit.startswith('d') else 'w' if unit.startswith('w') else 'm'}"

        return result

    def _resolve_date(self, date_str: str) -> Optional[str]:
        """Resolve relative date strings to ISO format."""
        import re
        now = datetime.now(timezone.utc)

        rel_match = re.match(r'(\d+)\s*(d|w|m)', date_str, re.IGNORECASE)
        if rel_match:
            amount = int(rel_match.group(1))
            unit = rel_match.group(2).lower()
            if unit == 'd':
                dt = now - timedelta(days=amount)
            elif unit == 'w':
                dt = now - timedelta(weeks=amount)
            elif unit == 'm':
                dt = now - timedelta(days=amount * 30)
            else:
                return None
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        if 'T' in date_str or '-' in date_str:
            return date_str

        return None

    # ── Service Metadata ────────────────────────────────────────────

    def get_capabilities(self) -> list:
        return [
            "email.send",
            "email.reply",
            "email.list",
            "email.read",
            "email.poll",
            "m365.active-users",
            "m365.mailbox-usage",
        ]

    def get_metadata(self) -> dict:
        return {
            "mailbox": self._mailbox,
            "poll_interval": self._poll_interval,
        }

    def health_status(self) -> dict:
        status = {"healthy": True, "mailbox": self._mailbox}
        try:
            self._ensure_authenticated()
            status["graph_api"] = "connected"
        except Exception:
            status["graph_api"] = "unreachable"
            status["healthy"] = False
        return status

    def on_shutdown(self) -> None:
        """Stop poller and close HTTP client."""
        self._running = False
        if self._http:
            self._http.close()

    def _parse_send_text(self, text: str) -> Dict[str, Any]:
        """Parse natural language email send request."""
        import re
        result = {"to": [], "subject": "", "body": ""}

        text = re.sub(r'<mailto:([^|>]+)\|[^>]+>', r'\1', text)
        text = re.sub(r'<mailto:([^>]+)>', r'\1', text)

        emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.-]+', text)
        result["to"] = emails

        saying_match = re.search(r"(?:saying|with message|with body|that says|message)\s+['\"]?(.+?)['\"]?\s*$", text, re.IGNORECASE)
        if saying_match:
            result["body"] = saying_match.group(1).strip("'\"")
        else:
            subject_match = re.search(r"subject[:\s]+['\"]?(.+?)['\"]?(?:\s+body|\s+saying|\s*$)", text, re.IGNORECASE)
            body_match = re.search(r"body[:\s]+['\"]?(.+?)['\"]?\s*$", text, re.IGNORECASE)
            if subject_match:
                result["subject"] = subject_match.group(1).strip("'\"")
            if body_match:
                result["body"] = body_match.group(1).strip("'\"")

        if not result["body"] and emails:
            after_email = text.split(emails[-1])[-1].strip()
            after_email = re.sub(r'^[\s,]*(saying|with|that|and)\s+', '', after_email, flags=re.IGNORECASE)
            after_email = after_email.strip("'\" ")
            if after_email:
                result["body"] = after_email

        return result


# ── Entrypoint ──────────────────────────────────────────────────────

if __name__ == "__main__":
    service = EmailConnector.create("connector-email")
    service.run()
