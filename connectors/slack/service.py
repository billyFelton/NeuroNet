"""
Slack Connector — Acts as a real Slack user in the workspace.

Uses a user OAuth token (xoxp-) so the agent appears as a normal
team member, not a bot. Listens for mentions, DMs, and configurable
trigger patterns, then routes requests through the Neuro-Network.

The agent:
- Appears as a real user (name, avatar, status, no APP badge)
- Responds when @mentioned in channels
- Responds to all DMs
- Can respond to thread replies in conversations it's part of
- Shows typing indicator while processing
- Uses emoji reactions to acknowledge receipt
- Stays silent unless triggered (no unsolicited messages)
"""

import json
import logging
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set

from neurokit.config import NeuroConfig
from neurokit.envelope import (
    ActorContext,
    EventType,
    MessageEnvelope,
)
from neurokit.service import BaseService

logger = logging.getLogger("connector-slack")


class SlackConnector(BaseService):
    """
    Slack connector that operates as a normal workspace user.

    Uses Socket Mode for real-time event handling without exposing
    a public endpoint. Authenticates with a user token so all
    messages appear from the agent's user account.
    """

    def __init__(self, config: NeuroConfig):
        super().__init__(config)

        # Slack clients — initialized in on_startup
        self._socket_client = None   # SocketModeClient
        self._web_client = None      # WebClient (user token)
        self._bot_user_id: str = ""  # The agent's Slack user ID
        self._bot_user_name: str = ""

        # Track active conversations to handle thread continuity
        self._active_threads: Dict[str, Dict] = {}  # thread_ts → context
        self._active_threads_lock = threading.Lock()

        # Response queue tracking — map correlation_id → slack context
        self._pending_responses: Dict[str, Dict] = {}
        self._pending_lock = threading.Lock()

        # Configuration
        self._trigger_config = TriggerConfig()

    def on_startup(self) -> None:
        """Initialize Slack clients with user token from HashiCorp Vault."""
        from slack_sdk import WebClient
        from slack_sdk.socket_mode import SocketModeClient

        # Retrieve tokens from HashiCorp Vault
        slack_secrets = self.secrets.get_all("slack")
        user_token = slack_secrets["user_token"]          # xoxp-...
        app_token = slack_secrets["app_level_token"]       # xapp-...

        # WebClient with USER token — this is what makes us appear as a real user
        self._web_client = WebClient(token=user_token)

        # Verify identity
        auth_response = self._web_client.auth_test()
        self._bot_user_id = auth_response["user_id"]
        self._bot_user_name = auth_response["user"]
        logger.info(
            "Authenticated as Slack user: %s (%s)",
            self._bot_user_name,
            self._bot_user_id,
        )

        # Socket Mode client for real-time events (uses app-level token)
        self._socket_client = SocketModeClient(
            app_token=app_token,
            web_client=self._web_client,
        )

        # Set agent status to show it's online
        try:
            self._web_client.users_profile_set(profile={
                "status_text": "Online — mention me for help",
                "status_emoji": ":brain:",
            })
        except Exception as e:
            logger.warning("Could not set Slack status: %s", e)

        # Load trigger configuration from Vault-IAM or defaults
        self._load_trigger_config()

        self.audit.log_system(
            action="slack_connected",
            resource="slack-workspace",
            details={
                "user_id": self._bot_user_id,
                "user_name": self._bot_user_name,
            },
        )

    def setup_queues(self) -> None:
        """Set up RabbitMQ queues for inbound responses from the network."""
        # Queue for receiving AI responses back
        self.response_queue = self.rmq.declare_queue(
            "connector-slack.responses",
            routing_keys=["ai.response", "ai.response.error"],
        )
        self.rmq.consume(self.response_queue, self._handle_ai_response)

        # Queue for system notifications to post to Slack
        self.notification_queue = self.rmq.declare_queue(
            "connector-slack.notifications",
            routing_keys=["notification.slack", "alert.slack.*"],
        )
        self.rmq.consume(self.notification_queue, self._handle_notification)

    def run(self) -> None:
        """Override run to handle both Socket Mode and RabbitMQ consumption."""
        self._setup_signal_handlers()

        try:
            self.connect()
            self.on_startup()
            self.setup_queues()

            self.conductor.register(
                capabilities=self.get_capabilities(),
                metadata=self.get_metadata(),
            )
            self.conductor.start_heartbeat(status_callback=self.health_status)

            self._running = True
            self.audit.log_system(action="service_started", resource=self.service_name)
            logger.info("%s is running as @%s", self.service_name, self._bot_user_name)

            # Register Socket Mode event handlers
            self._register_socket_handlers()

            # Run Socket Mode in a background thread
            socket_thread = threading.Thread(
                target=self._socket_client.connect,
                daemon=True,
                name="slack-socket-mode",
            )
            socket_thread.start()

            # Block on RabbitMQ consumption in main thread
            self.rmq.start_consuming()

        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received")
        except Exception as e:
            logger.error("Fatal error: %s", e, exc_info=True)
        finally:
            self.shutdown()

    def on_shutdown(self) -> None:
        """Clear Slack status and disconnect."""
        try:
            if self._web_client:
                self._web_client.users_profile_set(profile={
                    "status_text": "",
                    "status_emoji": "",
                })
        except Exception:
            pass
        if self._socket_client:
            self._socket_client.disconnect()

    # ── Socket Mode Event Handlers ──────────────────────────────────

    def _register_socket_handlers(self) -> None:
        """Register handlers for Slack events via Socket Mode."""
        from slack_sdk.socket_mode.request import SocketModeRequest
        from slack_sdk.socket_mode.response import SocketModeResponse

        def _event_handler(client, req: SocketModeRequest):
            # Acknowledge immediately
            client.send_socket_mode_response(
                SocketModeResponse(envelope_id=req.envelope_id)
            )

            if req.type == "events_api":
                event = req.payload.get("event", {})
                event_type = event.get("type")

                if event_type == "message":
                    self._handle_message_event(event)
                elif event_type == "app_mention":
                    self._handle_mention_event(event)
                elif event_type == "reaction_added":
                    self._handle_reaction_event(event)

        self._socket_client.socket_mode_request_listeners.append(_event_handler)

    def _handle_message_event(self, event: Dict[str, Any]) -> None:
        """Handle incoming Slack messages."""
        # Ignore our own messages
        if event.get("user") == self._bot_user_id:
            return

        # Ignore message subtypes (edits, deletes, joins, etc.)
        if event.get("subtype"):
            return

        text = event.get("text", "")
        channel = event.get("channel", "")
        user_id = event.get("user", "")
        thread_ts = event.get("thread_ts")
        message_ts = event.get("ts", "")
        channel_type = event.get("channel_type", "")

        # Determine if we should respond
        trigger = self._should_respond(
            text=text,
            channel=channel,
            channel_type=channel_type,
            user_id=user_id,
            thread_ts=thread_ts,
        )

        if not trigger:
            return

        logger.info(
            "Triggered by %s in %s (reason: %s)",
            user_id, channel, trigger.reason,
        )

        # Process the message
        self._process_inbound(
            text=text,
            channel=channel,
            user_id=user_id,
            thread_ts=thread_ts or message_ts,
            message_ts=message_ts,
            trigger_reason=trigger.reason,
        )

    def _handle_mention_event(self, event: Dict[str, Any]) -> None:
        """Handle @mentions — always respond to these."""
        if event.get("user") == self._bot_user_id:
            return

        text = event.get("text", "")
        # Strip the mention from the text
        text = re.sub(rf"<@{self._bot_user_id}>", "", text).strip()

        self._process_inbound(
            text=text,
            channel=event.get("channel", ""),
            user_id=event.get("user", ""),
            thread_ts=event.get("thread_ts") or event.get("ts", ""),
            message_ts=event.get("ts", ""),
            trigger_reason="direct_mention",
        )

    def _handle_reaction_event(self, event: Dict[str, Any]) -> None:
        """Handle emoji reactions — can be used as triggers."""
        # Example: reacting with :mag: on a message sends it for analysis
        if event.get("reaction") in self._trigger_config.reaction_triggers:
            # Fetch the original message
            try:
                result = self._web_client.conversations_history(
                    channel=event["item"]["channel"],
                    latest=event["item"]["ts"],
                    limit=1,
                    inclusive=True,
                )
                if result["messages"]:
                    msg = result["messages"][0]
                    self._process_inbound(
                        text=msg.get("text", ""),
                        channel=event["item"]["channel"],
                        user_id=event.get("user", ""),
                        thread_ts=event["item"]["ts"],
                        message_ts=event["item"]["ts"],
                        trigger_reason=f"reaction:{event['reaction']}",
                    )
            except Exception as e:
                logger.error("Failed to fetch reacted message: %s", e)

    # ── Trigger Logic ───────────────────────────────────────────────

    def _should_respond(
        self,
        text: str,
        channel: str,
        channel_type: str,
        user_id: str,
        thread_ts: Optional[str],
    ) -> Optional["TriggerResult"]:
        """
        Determine if the agent should respond to this message.

        Response triggers (in priority order):
        1. Direct message (IM) — always respond
        2. @mention — always respond (handled separately via app_mention)
        3. Thread reply in a conversation we're active in — respond
        4. Keyword/pattern match in monitored channels — respond
        5. Everything else — stay silent
        """
        # 1. DMs — always respond
        if channel_type == "im":
            return TriggerResult("direct_message")

        # 2. @mention in text (backup — app_mention event usually catches this)
        if f"<@{self._bot_user_id}>" in text:
            return TriggerResult("mention_in_text")

        # 3. Thread reply in active conversation
        if thread_ts:
            with self._active_threads_lock:
                if thread_ts in self._active_threads:
                    return TriggerResult("active_thread")

        # 4. Keyword triggers in monitored channels
        if channel in self._trigger_config.monitored_channels:
            for pattern in self._trigger_config.keyword_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    return TriggerResult(f"keyword:{pattern}")

        # 5. Don't respond
        return None

    # ── Message Processing ──────────────────────────────────────────

    def _process_inbound(
        self,
        text: str,
        channel: str,
        user_id: str,
        thread_ts: str,
        message_ts: str,
        trigger_reason: str,
    ) -> None:
        """
        Process an inbound Slack message:
        1. Show typing / acknowledge with reaction
        2. Resolve user identity via Vault-IAM
        3. Build envelope and publish to Neuro-Network
        4. Track for response routing
        """
        # Acknowledge receipt with a reaction (eyes emoji = "I see you")
        try:
            self._web_client.reactions_add(
                channel=channel,
                name="eyes",
                timestamp=message_ts,
            )
        except Exception:
            pass  # Non-critical

        # Resolve Slack user to canonical identity
        try:
            identity = self.iam.resolve_identity(
                provider="slack",
                external_id=user_id,
            )
        except Exception as e:
            logger.warning("Could not resolve identity for %s: %s", user_id, e)
            # Fallback: get basic info from Slack
            identity = self._get_slack_user_info(user_id)

        # Build the message envelope
        actor = ActorContext(
            user_id=identity.get("user_id"),
            email=identity.get("email"),
            display_name=identity.get("display_name"),
            roles=identity.get("roles", []),
            groups=identity.get("groups", []),
            source_channel="slack",
            source_channel_id=user_id,
        )

        # Get conversation history for context
        history = self._get_thread_history(channel, thread_ts)

        envelope = MessageEnvelope.create(
            source="connector-slack",
            message_type="user.query",
            payload={
                "text": text,
                "history": history,
                "channel": channel,
                "thread_ts": thread_ts,
                "trigger_reason": trigger_reason,
            },
            actor=actor,
            reply_to="ai.response",  # Route response back to our response queue
            priority=7 if trigger_reason == "direct_message" else 5,
        )

        # Track this message for response routing
        with self._pending_lock:
            self._pending_responses[envelope.correlation_id] = {
                "channel": channel,
                "thread_ts": thread_ts,
                "message_ts": message_ts,
                "user_id": user_id,
                "timestamp": time.time(),
            }

        # Mark thread as active
        with self._active_threads_lock:
            self._active_threads[thread_ts] = {
                "channel": channel,
                "last_activity": time.time(),
                "correlation_id": envelope.correlation_id,
            }

        # Publish to the Neuro-Network
        self.rmq.publish("user.query", envelope)

        # Audit the inbound message
        self.audit.log_from_envelope(
            envelope=envelope,
            event_type=EventType.DATA_ACCESS,
            action="slack_message_received",
            resource="slack-channel",
            details={
                "channel": channel,
                "trigger_reason": trigger_reason,
                "text_length": len(text),
            },
        )

    # ── Response Handling ───────────────────────────────────────────

    def _handle_ai_response(self, envelope: MessageEnvelope) -> None:
        """Handle AI responses from the network and post to Slack."""
        correlation_id = envelope.correlation_id

        # Find the original Slack context
        with self._pending_lock:
            slack_ctx = self._pending_responses.pop(correlation_id, None)

        if not slack_ctx:
            logger.warning(
                "Received response for unknown correlation_id: %s",
                correlation_id,
            )
            return

        channel = slack_ctx["channel"]
        thread_ts = slack_ctx["thread_ts"]

        # Check if this is an error response
        if envelope.message_type == "ai.response.error":
            error_msg = envelope.payload.get("error", "Something went wrong.")
            self._post_message(channel, thread_ts, f"Sorry, I ran into an issue: {error_msg}")
            return

        # Post the AI response
        response_text = envelope.payload.get("text", "")

        if not response_text:
            self._post_message(channel, thread_ts, "I processed your request but didn't generate a response. Could you rephrase?")
            return

        # Handle long responses — Slack has a 4000 char limit per message
        if len(response_text) > 3900:
            chunks = self._chunk_message(response_text, 3900)
            for chunk in chunks:
                self._post_message(channel, thread_ts, chunk)
                time.sleep(0.5)  # Small delay between chunks
        else:
            self._post_message(channel, thread_ts, response_text)

        # Remove the "eyes" reaction and add a checkmark
        try:
            self._web_client.reactions_remove(
                channel=channel,
                name="eyes",
                timestamp=slack_ctx["message_ts"],
            )
            self._web_client.reactions_add(
                channel=channel,
                name="white_check_mark",
                timestamp=slack_ctx["message_ts"],
            )
        except Exception:
            pass

        # Audit the outbound response
        self.audit.log_from_envelope(
            envelope=envelope,
            event_type=EventType.DATA_ACCESS,
            action="slack_response_sent",
            resource="slack-channel",
            details={
                "channel": channel,
                "response_length": len(response_text),
            },
        )

    def _handle_notification(self, envelope: MessageEnvelope) -> None:
        """Handle system notifications to post to Slack channels."""
        channel = envelope.payload.get("channel")
        text = envelope.payload.get("text", "")
        thread_ts = envelope.payload.get("thread_ts")

        if not channel or not text:
            logger.warning("Notification missing channel or text")
            return

        self._post_message(channel, thread_ts, text)

    # ── Slack API Helpers ───────────────────────────────────────────

    def _post_message(
        self,
        channel: str,
        thread_ts: Optional[str],
        text: str,
    ) -> Optional[str]:
        """Post a message as the agent user."""
        try:
            result = self._web_client.chat_postMessage(
                channel=channel,
                text=text,
                thread_ts=thread_ts,
                unfurl_links=False,
                unfurl_media=False,
            )
            return result.get("ts")
        except Exception as e:
            logger.error("Failed to post Slack message: %s", e)
            return None

    def _get_thread_history(
        self,
        channel: str,
        thread_ts: str,
        limit: int = 10,
    ) -> List[Dict[str, str]]:
        """Fetch recent thread history for conversation context."""
        try:
            result = self._web_client.conversations_replies(
                channel=channel,
                ts=thread_ts,
                limit=limit,
            )
            messages = []
            for msg in result.get("messages", [])[:-1]:  # Exclude the current message
                role = "assistant" if msg.get("user") == self._bot_user_id else "user"
                messages.append({
                    "role": role,
                    "content": msg.get("text", ""),
                })
            return messages
        except Exception as e:
            logger.debug("Could not fetch thread history: %s", e)
            return []

    def _get_slack_user_info(self, user_id: str) -> Dict[str, Any]:
        """Fallback: get user info directly from Slack if IAM resolution fails."""
        try:
            result = self._web_client.users_info(user=user_id)
            user = result.get("user", {})
            profile = user.get("profile", {})
            return {
                "user_id": None,  # No canonical ID — IAM resolution failed
                "email": profile.get("email"),
                "display_name": (
                    profile.get("display_name")
                    or profile.get("real_name")
                    or user.get("name", "Unknown")
                ),
                "roles": [],  # No roles — will be treated as unauthenticated
                "groups": [],
            }
        except Exception:
            return {
                "user_id": None,
                "email": None,
                "display_name": "Unknown User",
                "roles": [],
                "groups": [],
            }

    def _chunk_message(self, text: str, max_length: int) -> List[str]:
        """Split a long message into chunks at paragraph boundaries."""
        if len(text) <= max_length:
            return [text]

        chunks = []
        while text:
            if len(text) <= max_length:
                chunks.append(text)
                break

            # Try to break at paragraph
            split_at = text.rfind("\n\n", 0, max_length)
            if split_at == -1:
                # Try single newline
                split_at = text.rfind("\n", 0, max_length)
            if split_at == -1:
                # Try space
                split_at = text.rfind(" ", 0, max_length)
            if split_at == -1:
                split_at = max_length

            chunks.append(text[:split_at])
            text = text[split_at:].lstrip()

        return chunks

    # ── Trigger Configuration ───────────────────────────────────────

    def _load_trigger_config(self) -> None:
        """Load trigger configuration (channels, keywords, etc.)."""
        # TODO: Load from Vault-IAM or a config endpoint
        # For now, use defaults
        self._trigger_config = TriggerConfig(
            monitored_channels=set(),  # Configure these per deployment
            keyword_patterns=[
                r"\bsecurity\s+alert\b",
                r"\bincident\b",
                r"\bcompromised\b",
                r"\bmalware\b",
                r"\bphishing\b",
            ],
            reaction_triggers={"mag", "rotating_light", "warning"},
        )

    # ── Service Metadata ────────────────────────────────────────────

    def get_capabilities(self) -> List[str]:
        return [
            "slack-inbound",
            "slack-outbound",
            "slack-notifications",
        ]

    def get_metadata(self) -> Dict[str, Any]:
        return {
            **super().get_metadata(),
            "slack_user_id": self._bot_user_id,
            "slack_user_name": self._bot_user_name,
        }

    def health_status(self) -> Dict[str, Any]:
        status = super().health_status()
        status["slack_connected"] = self._socket_client is not None
        status["slack_user"] = self._bot_user_name
        with self._pending_lock:
            status["pending_responses"] = len(self._pending_responses)
        with self._active_threads_lock:
            status["active_threads"] = len(self._active_threads)
        return status


class TriggerConfig:
    """Configuration for when the agent should respond."""

    def __init__(
        self,
        monitored_channels: Optional[Set[str]] = None,
        keyword_patterns: Optional[List[str]] = None,
        reaction_triggers: Optional[Set[str]] = None,
    ):
        self.monitored_channels = monitored_channels or set()
        self.keyword_patterns = keyword_patterns or []
        self.reaction_triggers = reaction_triggers or set()


class TriggerResult:
    """Result of trigger evaluation."""

    def __init__(self, reason: str):
        self.reason = reason


if __name__ == "__main__":
    service = SlackConnector.create("connector-slack")
    service.run()
