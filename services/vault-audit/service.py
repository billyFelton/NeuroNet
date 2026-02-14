"""
Vault-Audit — Audit event consumer and persistence service.

Consumes audit events from the RabbitMQ audit exchange and:
1. Stores them in PostgreSQL (audit.events table) for querying
2. Writes them to daily log files for archival
3. Maintains hash-chain integrity verification

Kevin can query the audit DB to report on activity, RBAC denials,
and AI usage metrics.
"""

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import psycopg2
import psycopg2.extras

from neurokit.envelope import AuditEvent
from neurokit.service import BaseService

logger = logging.getLogger("vault-audit")

AUDIT_LOG_DIR = os.environ.get("AUDIT_LOG_DIR", "/var/log/neuronet/audit")


class VaultAuditService(BaseService):
    """
    Consumes audit events from the audit fanout exchange and persists them.

    Storage:
    - PostgreSQL: audit.events table (queryable by Kevin and admins)
    - Log files: /var/log/neuronet/audit/YYYY-MM-DD.jsonl (archival)

    Integrity:
    - Verifies hash chain on incoming events
    - Logs warnings for broken chains (but still stores events)
    """

    def __init__(self, config):
        super().__init__(config)
        self._db: Optional[psycopg2.extensions.connection] = None
        self._last_hash: Optional[str] = None
        self._events_processed: int = 0
        self._events_failed: int = 0
        self._log_dir = Path(AUDIT_LOG_DIR)

    def on_startup(self) -> None:
        """Connect to DB and ensure log directory exists."""
        self._db = psycopg2.connect(
            host=os.environ.get("KB_DB_HOST", "vault-db"),
            user=os.environ.get("KB_DB_USER", "vault_iam"),
            password=os.environ.get("KB_DB_PASSWORD", ""),
            dbname=os.environ.get("KB_DB_NAME", "neuro_vault"),
            connect_timeout=5,
        )
        self._db.autocommit = True
        logger.info("Connected to audit database")

        # Create log directory
        self._log_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Audit log directory: %s", self._log_dir)

        # Load last hash for chain verification
        self._load_last_hash()

    def _load_last_hash(self) -> None:
        """Load the last event hash from the DB for chain verification."""
        try:
            with self._db.cursor() as cur:
                cur.execute(
                    "SELECT event_hash FROM audit.events ORDER BY created_at DESC LIMIT 1"
                )
                row = cur.fetchone()
                if row:
                    self._last_hash = row[0]
                    logger.info("Loaded last audit hash for chain verification")
        except Exception as e:
            logger.warning("Could not load last hash: %s", e)

    def setup_queues(self) -> None:
        """Declare the audit consumer queue and consume raw messages."""
        # Declare the audit queue bound to the audit fanout exchange
        self.audit_queue = self.rmq.declare_audit_queue("vault.audit")

        # We need to consume RAW messages — audit events are raw JSON,
        # not MessageEnvelope. But NeuroKit's consume() tries to deserialize
        # as MessageEnvelope. So we use basic_consume directly and set the
        # _consuming flag so start_consuming() works.
        def _raw_callback(ch, method, properties, body):
            try:
                event_data = json.loads(body.decode())
                self._handle_audit_event(event_data)
            except Exception as e:
                logger.error("Failed to process audit event: %s", e, exc_info=True)
            finally:
                ch.basic_ack(delivery_tag=method.delivery_tag)

        self.rmq._operational_channel.basic_consume(
            queue=self.audit_queue,
            on_message_callback=_raw_callback,
            auto_ack=False,
        )
        self.rmq._consuming = True  # Tell NeuroKit we have consumers
        logger.info("Consuming raw audit events from %s", self.audit_queue)

    def _handle_audit_event(self, event_data: Dict[str, Any]) -> None:
        """Process a parsed audit event dict."""
        try:
            if not event_data:
                logger.warning("Empty audit event received, skipping")
                self._events_failed += 1
                return

            logger.debug(
                "Audit event: type=%s action=%s source=%s",
                event_data.get("event_type"),
                event_data.get("action"),
                event_data.get("source_service"),
            )

            self._store_event(event_data)
            self._write_log_file(event_data)
            self._events_processed += 1

            if self._events_processed % 50 == 0:
                logger.info(
                    "Audit stats: %d processed, %d failed",
                    self._events_processed,
                    self._events_failed,
                )
        except Exception as e:
            logger.error("Failed to store audit event: %s", e, exc_info=True)
            self._events_failed += 1

    def _store_event(self, event: Dict[str, Any]) -> None:
        """Store an audit event in PostgreSQL (existing partitioned schema)."""
        actor = event.get("actor", {}) or {}
        ai = event.get("ai_interaction", {}) or {}

        # Generate a UUID for event_id if not present
        import uuid as _uuid
        event_id = event.get("event_id")
        if event_id:
            try:
                _uuid.UUID(event_id)  # validate it's a UUID
            except (ValueError, AttributeError):
                event_id = str(_uuid.uuid4())
        else:
            event_id = str(_uuid.uuid4())

        # Correlation ID as UUID
        corr_id = event.get("correlation_id")
        if corr_id:
            try:
                _uuid.UUID(corr_id)
            except (ValueError, AttributeError):
                corr_id = None

        with self._db.cursor() as cur:
            cur.execute("""
                INSERT INTO audit.events (
                    event_id, timestamp, source_service, event_type,
                    actor_user_id, actor_email, actor_roles,
                    actor_source, actor_is_service,
                    action, resource, resource_id,
                    auth_decision, auth_policy, auth_denied_reason,
                    ai_model, ai_provider, ai_request_id,
                    ai_prompt_hash, ai_response_hash,
                    ai_input_tokens, ai_output_tokens,
                    ai_latency_ms, ai_cost_usd,
                    outcome_status, outcome_details,
                    correlation_id,
                    previous_event_hash, event_hash,
                    raw_event
                ) VALUES (
                    %(event_id)s, %(timestamp)s, %(source_service)s, %(event_type)s,
                    %(actor_user_id)s, %(actor_email)s, %(actor_roles)s,
                    %(actor_source)s, %(actor_is_service)s,
                    %(action)s, %(resource)s, %(resource_id)s,
                    %(auth_decision)s, %(auth_policy)s, %(auth_denied_reason)s,
                    %(ai_model)s, %(ai_provider)s, %(ai_request_id)s,
                    %(ai_prompt_hash)s, %(ai_response_hash)s,
                    %(ai_input_tokens)s, %(ai_output_tokens)s,
                    %(ai_latency_ms)s, %(ai_cost_usd)s,
                    %(outcome_status)s, %(outcome_details)s,
                    %(correlation_id)s,
                    %(previous_event_hash)s, %(event_hash)s,
                    %(raw_event)s
                )
                ON CONFLICT (event_id, timestamp) DO NOTHING
            """, {
                "event_id": event_id,
                "timestamp": event.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "source_service": event.get("source_service", "unknown"),
                "event_type": event.get("event_type", "unknown"),
                "actor_user_id": actor.get("user_id"),
                "actor_email": actor.get("email"),
                "actor_roles": actor.get("roles"),
                "actor_source": actor.get("source_channel"),
                "actor_is_service": actor.get("is_service_account", False),
                "action": event.get("action", "unknown"),
                "resource": event.get("resource", ""),
                "resource_id": event.get("resource_id"),
                "auth_decision": event.get("details", {}).get("decision") if event.get("event_type") == "authorization" else None,
                "auth_policy": event.get("details", {}).get("policy") if event.get("event_type") == "authorization" else None,
                "auth_denied_reason": event.get("details", {}).get("denied_reason") if event.get("event_type") == "authorization" else None,
                "ai_model": ai.get("model"),
                "ai_provider": ai.get("provider"),
                "ai_request_id": ai.get("request_id"),
                "ai_prompt_hash": ai.get("prompt_hash"),
                "ai_response_hash": ai.get("response_hash"),
                "ai_input_tokens": ai.get("input_tokens"),
                "ai_output_tokens": ai.get("output_tokens"),
                "ai_latency_ms": ai.get("latency_ms"),
                "ai_cost_usd": ai.get("estimated_cost_usd"),
                "outcome_status": event.get("outcome_status", "success"),
                "outcome_details": json.dumps(event.get("details", {})),
                "correlation_id": corr_id,
                "previous_event_hash": event.get("previous_hash"),
                "event_hash": event.get("event_hash", ""),
                "raw_event": json.dumps(event, default=str),
            })

        # Verify hash chain
        event_hash = event.get("event_hash")
        prev_hash = event.get("previous_hash")

        if self._last_hash and prev_hash and prev_hash != self._last_hash:
            logger.warning(
                "Hash chain break detected! Expected previous=%s, got=%s (event_id=%s)",
                self._last_hash, prev_hash, event_id,
            )

        if event_hash:
            self._last_hash = event_hash

    def _write_log_file(self, event: Dict[str, Any]) -> None:
        """Append audit event to daily JSONL log file."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        log_file = self._log_dir / f"{today}.jsonl"

        line = json.dumps(event, default=str, separators=(",", ":"))

        with open(log_file, "a") as f:
            f.write(line + "\n")

    # ── Service Metadata ────────────────────────────────────────────

    def get_capabilities(self) -> list:
        return ["audit.consume", "audit.store", "audit.verify"]

    def health_status(self) -> dict:
        status = {
            "healthy": True,
            "events_processed": self._events_processed,
            "events_failed": self._events_failed,
        }
        try:
            with self._db.cursor() as cur:
                cur.execute("SELECT count(*) FROM audit.events")
                status["total_events"] = cur.fetchone()[0]
        except Exception:
            status["healthy"] = False
        return status

    def on_shutdown(self) -> None:
        if self._db:
            self._db.close()


if __name__ == "__main__":
    service = VaultAuditService.create("vault-audit")
    service.run()
