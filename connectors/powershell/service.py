"""
Connector-PowerShell — Remote PowerShell execution via WinRM.

Executes PowerShell commands on domain-joined Windows machines for
security investigations. ALL commands require explicit user approval
before execution.

Flow:
1. Claude worker sends powershell.propose with command + target
2. Connector stores pending command, replies with approval prompt
3. User approves in Slack conversation
4. Claude worker sends powershell.execute with approval token
5. Connector executes via WinRM, returns results

Credentials are read from HashiCorp Vault at startup.
"""

import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psycopg2

from neurokit.envelope import EventType, MessageEnvelope
from neurokit.service import BaseService

logger = logging.getLogger("connector-powershell")

# Commands that are NEVER allowed, even with approval
BLOCKED_PATTERNS = [
    "format-c", "format c:", "format d:",
    "remove-item -recurse /",
    "remove-item -recurse c:\\",
    "stop-computer", "restart-computer",
    "clear-eventlog",
    "invoke-expression", "iex(",
    "new-localuser", "add-localgroupmember",
    "set-executionpolicy unrestricted",
    "disable-windowsoptionalfeature",
    "bcdedit", "diskpart",
    "del /f /s /q c:",
    "rd /s /q c:",
    "net user /add",
    "net localgroup administrators",
    "reg delete hklm",
    "wmic os where",  # WMI destructive
    "-encodedcommand",  # Encoded payloads
    "downloadstring", "downloadfile",  # Web downloads
    "invoke-webrequest -outfile",
]

# Max output size (bytes)
MAX_OUTPUT_SIZE = 50_000

# Approval expiry (seconds)
APPROVAL_EXPIRY = 600  # 10 minutes

# Max pending commands per user per hour
MAX_PENDING_PER_HOUR = 10


class PowerShellConnector(BaseService):
    """
    PowerShell connector for remote command execution via WinRM.

    Listens for powershell.propose and powershell.execute messages.
    All commands require explicit approval before execution.
    """

    def __init__(self, config):
        super().__init__(config)
        self._domain: str = ""
        self._username: str = ""
        self._password: str = ""
        self._auth_method: str = "ntlm"
        self._port: int = 5985
        self._use_ssl: bool = False
        self._db_conn = None

    def on_startup(self) -> None:
        """Retrieve WinRM credentials from Vault and connect to database."""
        # Get WinRM credentials
        secrets = self.secrets.get_all("powershell")
        self._domain = secrets.get("domain", "")
        self._username = secrets.get("username", "")
        self._password = secrets.get("password", "")
        self._auth_method = secrets.get("auth_method", "ntlm")
        self._port = int(secrets.get("port", "5985"))
        self._use_ssl = secrets.get("use_ssl", "false").lower() == "true"

        if not self._username or not self._password:
            logger.error("PowerShell connector requires username and password in Vault")
            return

        logger.info(
            "PowerShell connector configured: domain=%s user=%s auth=%s port=%d ssl=%s",
            self._domain, self._username, self._auth_method, self._port, self._use_ssl,
        )

        # Connect to database for tracking executions
        try:
            kb_host = os.environ.get("KB_DB_HOST", "vault-db")
            kb_user = os.environ.get("KB_DB_USER", "vault_iam")
            kb_pass = os.environ.get("KB_DB_PASSWORD", "")
            kb_name = os.environ.get("KB_DB_NAME", "neuro_vault")
            self._db_conn = psycopg2.connect(
                host=kb_host, user=kb_user, password=kb_pass,
                dbname=kb_name, connect_timeout=5,
            )
            self._db_conn.autocommit = True
            logger.info("Connected to database")
        except Exception as e:
            logger.warning("Database not available: %s", e)
            self._db_conn = None

        # Ensure tracking table exists
        self._ensure_tables()

        self.audit.log_system(
            action="powershell_connector_started",
            resource="powershell",
            details={"domain": self._domain, "auth_method": self._auth_method},
        )

    def _ensure_tables(self) -> None:
        """Create the execution tracking table if it doesn't exist."""
        if not self._db_conn:
            return
        try:
            with self._db_conn.cursor() as cur:
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
                    CREATE INDEX IF NOT EXISTS idx_ps_exec_request
                    ON knowledge.powershell_executions (request_id)
                """)
                cur.execute("""
                    CREATE INDEX IF NOT EXISTS idx_ps_exec_status
                    ON knowledge.powershell_executions (status, created_at)
                """)
            logger.info("PowerShell execution tracking table ready")
        except Exception as e:
            logger.warning("Could not create tracking table: %s", e)

    # ── Queue Setup ─────────────────────────────────────────────────

    def setup_queues(self) -> None:
        """Set up RabbitMQ queues."""
        self.inbox = self.rmq.declare_queue(
            "connector-powershell.inbox",
            routing_keys=[
                "powershell.propose",
                "powershell.execute",
                "powershell.status",
                "powershell.command.propose",
                "powershell.command.execute",
                "powershell.command.status",
            ],
        )
        self.rmq.consume(self.inbox, self.handle_message)

    def handle_message(self, envelope: MessageEnvelope) -> Optional[MessageEnvelope]:
        """Route incoming messages."""
        msg_type = envelope.message_type
        handlers = {
            "powershell.propose": self._handle_propose,
            "powershell.execute": self._handle_execute,
            "powershell.status": self._handle_status,
            "powershell.command.propose": self._handle_propose,
            "powershell.command.execute": self._handle_execute,
            "powershell.command.status": self._handle_status,
        }

        handler = handlers.get(msg_type)
        if not handler:
            logger.warning("Unknown message type: %s", msg_type)
            return envelope.create_reply(
                source=self.service_name,
                message_type="powershell.response.error",
                payload={"error": f"Unknown type: {msg_type}"},
            )

        try:
            result = handler(envelope.payload, envelope)

            self.audit.log_from_envelope(
                envelope=envelope,
                event_type=EventType.DATA_ACCESS,
                action=msg_type,
                resource="powershell",
                details={
                    "target": envelope.payload.get("target_host", ""),
                    "status": result.get("status", "unknown"),
                },
            )

            return envelope.create_reply(
                source=self.service_name,
                message_type=f"powershell.response.{result.get('type', 'result')}",
                payload=result,
            )

        except Exception as e:
            logger.error("PowerShell handler error: %s", e, exc_info=True)
            return envelope.create_reply(
                source=self.service_name,
                message_type="powershell.response.error",
                payload={"error": str(e)},
            )

    # ── Handlers ────────────────────────────────────────────────────

    def _handle_propose(self, payload: Dict, envelope: MessageEnvelope) -> Dict:
        """
        Handle a command proposal from the Claude worker.

        Kevin has generated a PowerShell command and wants approval.
        We validate it, store it as pending, and return the approval prompt.
        """
        target_host = payload.get("target_host", "").strip()
        command = payload.get("command", "").strip()
        reason = payload.get("reason", "").strip()
        user_email = envelope.actor.email if envelope.actor else "unknown"

        # Validate inputs
        if not target_host:
            return {"type": "error", "status": "error", "error": "No target host specified"}
        if not command:
            return {"type": "error", "status": "error", "error": "No command specified"}

        # Check for blocked commands
        cmd_lower = command.lower()
        for blocked in BLOCKED_PATTERNS:
            if blocked in cmd_lower:
                logger.warning(
                    "BLOCKED command from %s on %s: %s (matched: %s)",
                    user_email, target_host, command[:100], blocked,
                )
                self.audit.log_from_envelope(
                    envelope=envelope,
                    event_type=EventType.AUTHORIZATION,
                    action="powershell.execute",
                    resource="powershell",
                    outcome_status="denied",
                    details={
                        "reason": f"Blocked pattern: {blocked}",
                        "command": command[:200],
                        "target": target_host,
                    },
                )
                return {
                    "type": "blocked",
                    "status": "blocked",
                    "error": f"This command contains a blocked pattern ({blocked}) and cannot be executed. "
                             f"This restriction exists to prevent accidental destructive operations.",
                }

        # Check rate limiting
        if self._db_conn:
            try:
                with self._db_conn.cursor() as cur:
                    cur.execute("""
                        SELECT COUNT(*) FROM knowledge.powershell_executions
                        WHERE requested_by = %s
                        AND created_at > NOW() - INTERVAL '1 hour'
                    """, [user_email])
                    count = cur.fetchone()[0]
                    if count >= MAX_PENDING_PER_HOUR:
                        return {
                            "type": "error",
                            "status": "rate_limited",
                            "error": f"Rate limit reached ({MAX_PENDING_PER_HOUR} commands/hour). Please wait.",
                        }
            except Exception:
                pass

        # Generate request ID and store
        request_id = str(uuid.uuid4())[:8]

        if self._db_conn:
            try:
                with self._db_conn.cursor() as cur:
                    cur.execute("""
                        INSERT INTO knowledge.powershell_executions
                            (request_id, requested_by, target_host, command, reason, status)
                        VALUES (%s, %s, %s, %s, %s, 'pending')
                    """, [request_id, user_email, target_host, command, reason])
            except Exception as e:
                logger.warning("Could not store pending command: %s", e)

        logger.info(
            "PowerShell proposal [%s] from %s: %s on %s",
            request_id, user_email, command[:80], target_host,
        )

        return {
            "type": "approval_required",
            "status": "pending",
            "request_id": request_id,
            "target_host": target_host,
            "command": command,
            "reason": reason,
            "message": (
                f"I'd like to run the following command on **{target_host}**:\n"
                f"```\n{command}\n```\n"
                f"{'Reason: ' + reason + chr(10) if reason else ''}"
                f"Reply **approve {request_id}** to execute, or **deny {request_id}** to cancel.\n"
                f"This request expires in 10 minutes."
            ),
        }

    def _handle_execute(self, payload: Dict, envelope: MessageEnvelope) -> Dict:
        """
        Execute an approved command via WinRM.

        Called after the user has approved a pending command.
        """
        request_id = payload.get("request_id", "").strip()
        user_email = envelope.actor.email if envelope.actor else "unknown"

        if not request_id:
            return {"type": "error", "status": "error", "error": "No request_id provided"}

        # Load the pending command
        pending = self._get_pending_command(request_id)
        if not pending:
            return {
                "type": "error",
                "status": "not_found",
                "error": f"No pending command found with ID {request_id}. It may have expired.",
            }

        target_host = pending["target_host"]
        command = pending["command"]
        status = pending["status"]

        # Check status
        if status != "pending":
            return {
                "type": "error",
                "status": "invalid_state",
                "error": f"Command {request_id} is already {status}.",
            }

        # Check expiry
        created = pending["created_at"]
        if created and (datetime.now(timezone.utc) - created).total_seconds() > APPROVAL_EXPIRY:
            self._update_status(request_id, "expired")
            return {
                "type": "error",
                "status": "expired",
                "error": f"Command {request_id} has expired (10 minute limit). Please propose a new command.",
            }

        # Mark as approved and executing
        self._update_status(request_id, "executing", approved_by=user_email)

        # Clean up the command — strip "powershell" prefix if Kevin added it
        if command.lower().startswith("powershell\n"):
            command = command[len("powershell\n"):].strip()
        elif command.lower().startswith("powershell "):
            command = command[len("powershell "):].strip()

        logger.info(
            "EXECUTING PowerShell [%s] approved by %s: %s on %s",
            request_id, user_email, command[:80], target_host,
        )

        # Execute via WinRM
        start_time = time.time()
        try:
            output, error_output, exit_code = self._execute_winrm(target_host, command)
            execution_ms = int((time.time() - start_time) * 1000)

            # Truncate output if too large
            if len(output) > MAX_OUTPUT_SIZE:
                output = output[:MAX_OUTPUT_SIZE] + f"\n\n[OUTPUT TRUNCATED — {len(output)} bytes total]"

            # Store results
            self._store_result(request_id, output, error_output, exit_code, execution_ms)

            self.audit.log_from_envelope(
                envelope=envelope,
                event_type=EventType.DATA_ACCESS,
                action="powershell.execute",
                resource=f"host:{target_host}",
                details={
                    "request_id": request_id,
                    "command": command[:200],
                    "exit_code": exit_code,
                    "output_length": len(output),
                    "execution_ms": execution_ms,
                },
            )

            return {
                "type": "result",
                "status": "completed",
                "request_id": request_id,
                "target_host": target_host,
                "command": command,
                "output": output,
                "error_output": error_output,
                "exit_code": exit_code,
                "execution_time_ms": execution_ms,
            }

        except Exception as e:
            execution_ms = int((time.time() - start_time) * 1000)
            error_msg = str(e)
            self._store_result(request_id, "", error_msg, -1, execution_ms)

            logger.error("WinRM execution failed [%s]: %s", request_id, e)
            return {
                "type": "error",
                "status": "failed",
                "request_id": request_id,
                "target_host": target_host,
                "command": command,
                "error": f"Execution failed: {error_msg}",
                "execution_time_ms": execution_ms,
            }

    def _handle_status(self, payload: Dict, envelope: MessageEnvelope) -> Dict:
        """Check the status of a pending or completed command."""
        request_id = payload.get("request_id", "")
        pending = self._get_pending_command(request_id)
        if not pending:
            return {"type": "status", "status": "not_found", "error": "Command not found"}
        return {
            "type": "status",
            "status": pending["status"],
            "request_id": request_id,
            "target_host": pending["target_host"],
            "command": pending["command"],
        }

    # ── WinRM Execution ─────────────────────────────────────────────

    def _execute_winrm(self, target_host: str, command: str) -> tuple:
        """
        Execute a PowerShell command on a remote host via WinRM.

        If target_host is a hostname (not an IP), attempt to resolve it
        from Wazuh agent data or the asset inventory.

        Returns: (stdout, stderr, exit_code)
        """
        import re
        from pypsrp.client import Client

        # Check if target is already an IP address
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        connect_target = target_host

        if not ip_pattern.match(target_host):
            # Try to resolve hostname to IP from database
            resolved_ip = self._resolve_host_ip(target_host)
            if resolved_ip:
                logger.info("Resolved %s -> %s from database", target_host, resolved_ip)
                connect_target = resolved_ip
            else:
                logger.warning(
                    "Could not resolve %s to IP — attempting direct connection (may fail without DNS)",
                    target_host,
                )

        # Build connection parameters
        username = f"{self._domain}\\{self._username}" if self._domain else self._username

        client = Client(
            connect_target,
            username=username,
            password=self._password,
            port=self._port,
            ssl=self._use_ssl,
            auth=self._auth_method,
            cert_validation=False,  # Internal network
            connection_timeout=15,
            operation_timeout=60,
        )

        logger.info("Connecting to %s (%s) via WinRM (port %d, auth=%s)", 
                     target_host, connect_target, self._port, self._auth_method)

        output, streams, had_errors = client.execute_ps(command)

        # Collect error stream
        error_output = ""
        if had_errors and streams and streams.error:
            error_output = "\n".join(str(e) for e in streams.error)

        exit_code = 0 if not had_errors else 1

        logger.info(
            "WinRM execution on %s completed: exit_code=%d output=%d bytes errors=%d bytes",
            target_host, exit_code, len(output), len(error_output),
        )

        return output, error_output, exit_code

    def _resolve_host_ip(self, hostname: str) -> Optional[str]:
        """Resolve a hostname to IP from Wazuh agent data or asset inventory."""
        if not self._db_conn:
            return None
        try:
            with self._db_conn.cursor() as cur:
                # Try asset inventory first
                cur.execute("""
                    SELECT ip_addresses FROM knowledge.assets
                    WHERE LOWER(hostname) = LOWER(%s)
                    AND ip_addresses != '{}'
                    LIMIT 1
                """, [hostname])
                row = cur.fetchone()
                if row and row[0]:
                    # Return first non-empty IP
                    for ip in row[0]:
                        if ip and not ip.startswith("127."):
                            return ip

                # Try partial hostname match (e.g. "DESKTOP-TICJH0K" in assets)
                cur.execute("""
                    SELECT ip_addresses FROM knowledge.assets
                    WHERE LOWER(hostname) LIKE LOWER(%s)
                    AND ip_addresses != '{}'
                    LIMIT 1
                """, [f"%{hostname}%"])
                row = cur.fetchone()
                if row and row[0]:
                    for ip in row[0]:
                        if ip and not ip.startswith("127."):
                            return ip

        except Exception as e:
            logger.debug("Host IP resolution error: %s", e)
        return None

    # ── Database Helpers ────────────────────────────────────────────

    def _get_pending_command(self, request_id: str) -> Optional[Dict]:
        """Load a command record by request ID."""
        if not self._db_conn:
            return None
        try:
            with self._db_conn.cursor() as cur:
                cur.execute("""
                    SELECT request_id, requested_by, target_host, command, reason,
                           status, approved_by, created_at
                    FROM knowledge.powershell_executions
                    WHERE request_id = %s
                """, [request_id])
                row = cur.fetchone()
                if row:
                    return {
                        "request_id": row[0],
                        "requested_by": row[1],
                        "target_host": row[2],
                        "command": row[3],
                        "reason": row[4],
                        "status": row[5],
                        "approved_by": row[6],
                        "created_at": row[7],
                    }
        except Exception as e:
            logger.warning("Could not load command %s: %s", request_id, e)
        return None

    def _update_status(self, request_id: str, status: str, approved_by: str = None) -> None:
        """Update the status of a command record."""
        if not self._db_conn:
            return
        try:
            with self._db_conn.cursor() as cur:
                if approved_by:
                    cur.execute("""
                        UPDATE knowledge.powershell_executions
                        SET status = %s, approved_by = %s, approved_at = NOW(), updated_at = NOW()
                        WHERE request_id = %s
                    """, [status, approved_by, request_id])
                else:
                    cur.execute("""
                        UPDATE knowledge.powershell_executions
                        SET status = %s, updated_at = NOW()
                        WHERE request_id = %s
                    """, [status, request_id])
        except Exception as e:
            logger.warning("Could not update status for %s: %s", request_id, e)

    def _store_result(
        self, request_id: str, output: str, error_output: str,
        exit_code: int, execution_ms: int,
    ) -> None:
        """Store execution results."""
        if not self._db_conn:
            return
        try:
            status = "completed" if exit_code == 0 else "failed"
            with self._db_conn.cursor() as cur:
                cur.execute("""
                    UPDATE knowledge.powershell_executions
                    SET output = %s, error_output = %s, exit_code = %s,
                        execution_time_ms = %s, executed_at = NOW(),
                        status = %s, updated_at = NOW()
                    WHERE request_id = %s
                """, [output[:100000], error_output[:10000], exit_code,
                      execution_ms, status, request_id])
        except Exception as e:
            logger.warning("Could not store result for %s: %s", request_id, e)


# ── Service Entry Point ─────────────────────────────────────────────

if __name__ == "__main__":
    service = PowerShellConnector.create("connector-powershell")
    service.run()
