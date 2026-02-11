"""
Connector-EntraID — On-demand Microsoft Graph API queries.

Handles RabbitMQ messages requesting EntraID data:
- User profile lookups
- Sign-in log queries (risky sign-ins, failed logins, MFA challenges)
- MFA registration and status
- Group membership queries
- Conditional access policy evaluation
- Risky users and risk detections

This connector does NOT handle the periodic user/group sync into the
IAM database — that's done by Vault-IAM's EntraSyncService. This
connector handles real-time, on-demand queries from the AI layer and
other services.

Requires Microsoft Graph API permissions (Application):
- User.Read.All
- AuditLog.Read.All
- Directory.Read.All
- IdentityRiskyUser.Read.All
- Policy.Read.All
- UserAuthenticationMethod.Read.All
- Reports.Read.All
"""

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx

from neurokit.envelope import EventType, MessageEnvelope
from neurokit.service import BaseService

logger = logging.getLogger("connector-entraid")


class EntraIDConnector(BaseService):
    """
    EntraID connector for on-demand Graph API queries.

    Listens for messages on the entraid.* routing keys and
    dispatches to the appropriate Graph API query handler.
    """

    GRAPH_BASE = "https://graph.microsoft.com/v1.0"
    GRAPH_BETA = "https://graph.microsoft.com/beta"

    def __init__(self, config):
        super().__init__(config)
        self._http: Optional[httpx.Client] = None
        self._access_token: Optional[str] = None
        self._token_expiry: float = 0
        self._tenant_id: str = ""
        self._client_id: str = ""
        self._client_secret: str = ""

    def on_startup(self) -> None:
        """Retrieve Graph API credentials from HashiCorp Vault."""
        graph_secrets = self.secrets.get_all("microsoft-graph")
        self._tenant_id = graph_secrets["tenant_id"]
        self._client_id = graph_secrets["client_id"]
        self._client_secret = graph_secrets["client_secret"]

        self._http = httpx.Client(timeout=30)
        self._authenticate()

        self.audit.log_system(
            action="entraid_connected",
            resource="microsoft-graph",
            details={"tenant_id": self._tenant_id},
        )

    def setup_queues(self) -> None:
        """Set up RabbitMQ queues for EntraID query requests."""
        self.inbox = self.rmq.declare_queue(
            "connector-entraid.inbox",
            routing_keys=[
                "entraid.query.user",
                "entraid.query.signin-logs",
                "entraid.query.mfa-status",
                "entraid.query.risky-users",
                "entraid.query.groups",
                "entraid.query.devices",
            ],
        )
        self.rmq.consume(self.inbox, self.handle_message)

    def handle_message(self, envelope: MessageEnvelope) -> Optional[MessageEnvelope]:
        """Route incoming queries to the appropriate handler."""
        msg_type = envelope.message_type
        payload = envelope.payload

        handlers = {
            "entraid.query.user": self._handle_user_query,
            "entraid.query.signin-logs": self._handle_signin_logs,
            "entraid.query.mfa-status": self._handle_mfa_status,
            "entraid.query.risky-users": self._handle_risky_users,
            "entraid.query.groups": self._handle_group_query,
            "entraid.query.devices": self._handle_device_query,
        }

        handler = handlers.get(msg_type)
        if not handler:
            logger.warning("Unknown message type: %s", msg_type)
            return envelope.create_reply(
                source=self.service_name,
                message_type="entraid.response.error",
                payload={"error": f"Unknown query type: {msg_type}"},
            )

        try:
            self._ensure_authenticated()
            result = handler(payload, envelope)

            self.audit.log_from_envelope(
                envelope=envelope,
                event_type=EventType.DATA_ACCESS,
                action=msg_type,
                resource=self._resource_for_type(msg_type),
                details={"result_count": result.get("count", 0)},
            )

            return envelope.create_reply(
                source=self.service_name,
                message_type=msg_type.replace("query", "response"),
                payload=result,
            )

        except httpx.HTTPStatusError as e:
            logger.error("Graph API error: %s %s", e.response.status_code, e.response.text)
            self.audit.log_from_envelope(
                envelope=envelope,
                event_type=EventType.DATA_ACCESS,
                action=msg_type,
                resource=self._resource_for_type(msg_type),
                outcome_status="error",
                details={"error": str(e), "status_code": e.response.status_code},
            )
            return envelope.create_reply(
                source=self.service_name,
                message_type="entraid.response.error",
                payload={"error": f"Graph API error: {e.response.status_code}"},
            )

        except Exception as e:
            logger.error("Handler error for %s: %s", msg_type, e, exc_info=True)
            return envelope.create_reply(
                source=self.service_name,
                message_type="entraid.response.error",
                payload={"error": str(e)},
            )

    # ── Authentication ──────────────────────────────────────────────

    def _authenticate(self) -> None:
        """Obtain OAuth2 token via client credentials flow."""
        url = (
            f"https://login.microsoftonline.com/"
            f"{self._tenant_id}/oauth2/v2.0/token"
        )
        data = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": "https://graph.microsoft.com/.default",
        }

        response = self._http.post(url, data=data)
        response.raise_for_status()
        token_data = response.json()

        self._access_token = token_data["access_token"]
        self._token_expiry = time.time() + token_data.get("expires_in", 3600)
        logger.info("Graph API token acquired")

    def _ensure_authenticated(self) -> None:
        """Refresh token if expired."""
        if time.time() >= self._token_expiry - 60:
            self._authenticate()

    def _graph_get(
        self,
        path: str,
        params: Optional[Dict] = None,
        beta: bool = False,
    ) -> Dict[str, Any]:
        """Make authenticated GET to Microsoft Graph."""
        base = self.GRAPH_BETA if beta else self.GRAPH_BASE
        headers = {"Authorization": f"Bearer {self._access_token}"}
        response = self._http.get(f"{base}{path}", headers=headers, params=params)
        response.raise_for_status()
        return response.json()

    def _graph_get_all(
        self,
        path: str,
        params: Optional[Dict] = None,
        beta: bool = False,
        max_pages: int = 10,
    ) -> List[Dict]:
        """Paginate through all results."""
        all_items = []
        result = self._graph_get(path, params, beta=beta)
        all_items.extend(result.get("value", []))

        pages = 1
        while "@odata.nextLink" in result and pages < max_pages:
            headers = {"Authorization": f"Bearer {self._access_token}"}
            response = self._http.get(result["@odata.nextLink"], headers=headers)
            response.raise_for_status()
            result = response.json()
            all_items.extend(result.get("value", []))
            pages += 1

        return all_items

    # ── Query Handlers ──────────────────────────────────────────────

    def _handle_user_query(
        self, payload: Dict, envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Query user profile from EntraID.

        Payload:
            user_id: str — EntraID object ID or UPN
            fields: list[str] — optional, specific fields to return
        """
        user_id = payload.get("user_id") or payload.get("email") or payload.get("upn")
        if not user_id:
            return {"error": "user_id, email, or upn required", "count": 0}

        select_fields = payload.get("fields", [
            "id", "displayName", "mail", "userPrincipalName",
            "jobTitle", "department", "accountEnabled",
            "createdDateTime", "lastSignInDateTime",
        ])

        result = self._graph_get(
            f"/users/{user_id}",
            params={"$select": ",".join(select_fields)},
        )

        return {"user": result, "count": 1}

    def _handle_signin_logs(
        self, payload: Dict, envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Query sign-in logs from EntraID.

        Payload:
            user_id: str — optional, filter by specific user
            hours: int — lookback period (default 24)
            status: str — optional, "success", "failure", "interrupted"
            risk_level: str — optional, "low", "medium", "high"
            top: int — max results (default 50)
        """
        hours = payload.get("hours", 24)
        top = min(payload.get("top", 50), 200)
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=hours)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        filters = [f"createdDateTime ge {cutoff}"]

        user_id = payload.get("user_id")
        if user_id:
            filters.append(f"userId eq '{user_id}'")

        status = payload.get("status")
        if status == "failure":
            filters.append("status/errorCode ne 0")
        elif status == "success":
            filters.append("status/errorCode eq 0")

        risk_level = payload.get("risk_level")
        if risk_level:
            filters.append(f"riskLevelDuringSignIn eq '{risk_level}'")

        filter_str = " and ".join(filters)

        logs = self._graph_get_all(
            "/auditLogs/signIns",
            params={
                "$filter": filter_str,
                "$top": str(top),
                "$orderby": "createdDateTime desc",
                "$select": (
                    "id,createdDateTime,userDisplayName,userPrincipalName,"
                    "userId,appDisplayName,ipAddress,clientAppUsed,"
                    "location,status,riskDetail,riskLevelDuringSignIn,"
                    "mfaDetail,conditionalAccessStatus,"
                    "authenticationRequirement"
                ),
            },
        )

        # Summarize for the AI layer
        summary = self._summarize_signin_logs(logs)

        return {
            "logs": logs,
            "summary": summary,
            "count": len(logs),
            "filter": {
                "hours": hours,
                "user_id": user_id,
                "status": status,
                "risk_level": risk_level,
            },
        }

    def _handle_mfa_status(
        self, payload: Dict, envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Query MFA registration and authentication methods for a user.

        Payload:
            user_id: str — EntraID object ID or UPN
        """
        user_id = payload.get("user_id")
        if not user_id:
            return {"error": "user_id required", "count": 0}

        # Get authentication methods (beta API)
        methods = self._graph_get_all(
            f"/users/{user_id}/authentication/methods",
            beta=True,
        )

        # Categorize methods
        method_types = []
        for m in methods:
            odata_type = m.get("@odata.type", "")
            if "microsoftAuthenticator" in odata_type:
                method_types.append("authenticator_app")
            elif "phone" in odata_type:
                method_types.append("phone")
            elif "fido2" in odata_type:
                method_types.append("fido2_key")
            elif "email" in odata_type:
                method_types.append("email")
            elif "password" in odata_type:
                method_types.append("password")
            elif "windowsHello" in odata_type:
                method_types.append("windows_hello")
            elif "temporaryAccessPass" in odata_type:
                method_types.append("temporary_access_pass")
            else:
                method_types.append(odata_type.split(".")[-1])

        mfa_registered = any(
            t in method_types
            for t in ["authenticator_app", "phone", "fido2_key", "windows_hello"]
        )

        return {
            "user_id": user_id,
            "mfa_registered": mfa_registered,
            "methods": method_types,
            "method_details": methods,
            "count": len(methods),
        }

    def _handle_risky_users(
        self, payload: Dict, envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Query risky users from Identity Protection.

        Payload:
            risk_level: str — optional, "low", "medium", "high"
            risk_state: str — optional, "atRisk", "confirmedCompromised", "remediated"
            top: int — max results (default 50)
        """
        top = min(payload.get("top", 50), 200)
        filters = []

        risk_level = payload.get("risk_level")
        if risk_level:
            filters.append(f"riskLevel eq '{risk_level}'")

        risk_state = payload.get("risk_state")
        if risk_state:
            filters.append(f"riskState eq '{risk_state}'")

        params = {
            "$top": str(top),
            "$orderby": "riskLastUpdatedDateTime desc",
        }
        if filters:
            params["$filter"] = " and ".join(filters)

        users = self._graph_get_all(
            "/identityProtection/riskyUsers",
            params=params,
        )

        return {
            "risky_users": users,
            "count": len(users),
            "filter": {"risk_level": risk_level, "risk_state": risk_state},
        }

    def _handle_group_query(
        self, payload: Dict, envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Query group details or members.

        Payload:
            group_id: str — EntraID group ID
            action: str — "details" or "members" (default "details")
        """
        group_id = payload.get("group_id")
        if not group_id:
            return {"error": "group_id required", "count": 0}

        action = payload.get("action", "details")

        if action == "members":
            members = self._graph_get_all(
                f"/groups/{group_id}/members",
                params={
                    "$select": "id,displayName,mail,userPrincipalName,accountEnabled",
                    "$top": "999",
                },
            )
            return {"group_id": group_id, "members": members, "count": len(members)}
        else:
            group = self._graph_get(
                f"/groups/{group_id}",
                params={
                    "$select": "id,displayName,description,mail,"
                              "groupTypes,securityEnabled,membershipRule",
                },
            )
            return {"group": group, "count": 1}

    def _handle_device_query(
        self, payload: Dict, envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Query devices registered to a user.

        Payload:
            user_id: str — EntraID object ID or UPN
        """
        user_id = payload.get("user_id")
        if not user_id:
            return {"error": "user_id required", "count": 0}

        devices = self._graph_get_all(
            f"/users/{user_id}/registeredDevices",
            params={
                "$select": "id,displayName,operatingSystem,operatingSystemVersion,"
                          "trustType,isManaged,isCompliant,registrationDateTime",
            },
        )

        return {
            "user_id": user_id,
            "devices": devices,
            "count": len(devices),
        }

    # ── Helpers ─────────────────────────────────────────────────────

    def _summarize_signin_logs(self, logs: List[Dict]) -> Dict[str, Any]:
        """Create a summary of sign-in logs for the AI layer."""
        if not logs:
            return {"total": 0}

        total = len(logs)
        failures = sum(1 for l in logs if l.get("status", {}).get("errorCode", 0) != 0)
        mfa_required = sum(
            1 for l in logs
            if l.get("authenticationRequirement") == "multiFactorAuthentication"
        )
        risky = sum(
            1 for l in logs
            if l.get("riskLevelDuringSignIn") in ("medium", "high")
        )

        # Top locations
        locations = {}
        for l in logs:
            loc = l.get("location", {})
            city = loc.get("city", "Unknown")
            country = loc.get("countryOrRegion", "Unknown")
            key = f"{city}, {country}"
            locations[key] = locations.get(key, 0) + 1

        # Top apps
        apps = {}
        for l in logs:
            app = l.get("appDisplayName", "Unknown")
            apps[app] = apps.get(app, 0) + 1

        # Unique IPs
        unique_ips = set(l.get("ipAddress") for l in logs if l.get("ipAddress"))

        return {
            "total": total,
            "failures": failures,
            "mfa_required": mfa_required,
            "risky_signins": risky,
            "unique_ips": len(unique_ips),
            "top_locations": dict(sorted(locations.items(), key=lambda x: -x[1])[:5]),
            "top_apps": dict(sorted(apps.items(), key=lambda x: -x[1])[:5]),
        }

    def _resource_for_type(self, msg_type: str) -> str:
        """Map message type to audit resource name."""
        resource_map = {
            "entraid.query.user": "entra-users",
            "entraid.query.signin-logs": "entra-signin-logs",
            "entraid.query.mfa-status": "entra-mfa-status",
            "entraid.query.risky-users": "entra-users",
            "entraid.query.groups": "entra-groups",
            "entraid.query.devices": "entra-users",
        }
        return resource_map.get(msg_type, "entra-users")

    # ── Service Metadata ────────────────────────────────────────────

    def get_capabilities(self) -> list:
        return [
            "entraid-user-lookup",
            "entraid-signin-logs",
            "entraid-mfa-status",
            "entraid-risky-users",
            "entraid-group-query",
            "entraid-device-query",
        ]

    def get_metadata(self) -> Dict[str, Any]:
        return {
            **super().get_metadata(),
            "tenant_id": self._tenant_id,
            "graph_api": "v1.0 + beta",
        }

    def health_status(self) -> Dict[str, Any]:
        status = super().health_status()
        status["graph_token_valid"] = (
            self._access_token is not None
            and time.time() < self._token_expiry
        )
        return status

    def on_shutdown(self) -> None:
        """Close HTTP client."""
        if self._http:
            self._http.close()


if __name__ == "__main__":
    service = EntraIDConnector.create("connector-entraid")
    service.run()
