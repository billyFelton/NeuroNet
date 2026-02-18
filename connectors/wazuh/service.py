"""
Connector-Wazuh — On-demand SIEM queries via Wazuh Indexer + Manager API.

Handles RabbitMQ messages requesting Wazuh data:
- Alert/event queries (via Wazuh Indexer / OpenSearch)
- Agent status and health (via Wazuh Manager API)
- Vulnerability detection results (via Indexer)
- File Integrity Monitoring events (via Indexer)
- Security Configuration Assessment (via Manager API)

Uses two backends:
1. Wazuh Indexer (OpenSearch on :9200) — for searching alerts, events, FIM, vulnerabilities
2. Wazuh Manager API (:55000) — for agent management, SCA, active response

Credentials are read from HashiCorp Vault at startup.
"""

import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx

from neurokit.envelope import EventType, MessageEnvelope
from neurokit.service import BaseService

logger = logging.getLogger("connector-wazuh")


class WazuhConnector(BaseService):
    """
    Wazuh connector for on-demand SIEM queries.

    Listens for messages on wazuh.* routing keys and dispatches
    to the appropriate Wazuh Indexer or Manager API handler.
    """

    def __init__(self, config):
        super().__init__(config)
        # Indexer (OpenSearch)
        self._indexer_url: str = ""
        self._indexer_user: str = ""
        self._indexer_password: str = ""
        # Manager API
        self._api_url: str = ""
        self._api_user: str = ""
        self._api_password: str = ""
        self._api_token: Optional[str] = None
        self._api_token_expiry: float = 0
        self._verify_ssl: bool = False
        # HTTP clients
        self._indexer_http: Optional[httpx.Client] = None
        self._api_http: Optional[httpx.Client] = None
        # Configurable instance identity (allows multiple Wazuh connectors)
        self._vault_secret = os.environ.get("WAZUH_VAULT_SECRET", "wazuh")
        self._routing_prefix = os.environ.get("WAZUH_ROUTING_PREFIX", "wazuh")
        self._instance_label = os.environ.get("WAZUH_INSTANCE_LABEL", "desktops")

    def on_startup(self) -> None:
        """Retrieve Wazuh credentials from HashiCorp Vault."""
        secrets = self.secrets.get_all(self._vault_secret)

        self._indexer_url = secrets.get("indexer_url", "").rstrip("/")
        self._indexer_user = secrets.get("indexer_user", "")
        self._indexer_password = secrets.get("indexer_password", "")
        self._api_url = secrets.get("api_url", "").rstrip("/")
        self._api_user = secrets.get("api_user", "")
        self._api_password = secrets.get("api_password", "")
        self._verify_ssl = secrets.get("verify_ssl", "false").lower() == "true"

        # Indexer client (OpenSearch)
        self._indexer_http = httpx.Client(
            base_url=self._indexer_url,
            auth=(self._indexer_user, self._indexer_password),
            verify=self._verify_ssl,
            timeout=30,
        )

        # Manager API client
        self._api_http = httpx.Client(
            base_url=self._api_url,
            verify=self._verify_ssl,
            timeout=30,
        )

        # Test connections
        self._test_indexer()
        self._test_manager_api()

        self.audit.log_system(
            action="wazuh_connected",
            resource="wazuh",
            details={
                "indexer_url": self._indexer_url,
                "api_url": self._api_url,
                "instance_label": self._instance_label,
            },
        )

    def _test_indexer(self) -> None:
        """Test the Wazuh Indexer connection."""
        try:
            resp = self._indexer_http.get("/")
            resp.raise_for_status()
            info = resp.json()
            logger.info(
                "Connected to Wazuh Indexer: %s (version %s)",
                info.get("cluster_name", "unknown"),
                info.get("version", {}).get("number", "unknown"),
            )
        except Exception as e:
            logger.warning("Could not connect to Wazuh Indexer at %s: %s", self._indexer_url, e)

    def _test_manager_api(self) -> None:
        """Test the Wazuh Manager API connection."""
        try:
            self._authenticate_manager()
            resp = self._api_http.get(
                "/manager/info",
                headers={"Authorization": f"Bearer {self._api_token}"},
            )
            resp.raise_for_status()
            data = resp.json().get("data", {}).get("affected_items", [{}])
            if data:
                info = data[0]
                logger.info(
                    "Connected to Wazuh Manager: %s (version %s)",
                    info.get("name", "unknown"),
                    info.get("version", "unknown"),
                )
        except Exception as e:
            logger.warning("Could not connect to Wazuh Manager at %s: %s", self._api_url, e)

    # ── Queue Setup ─────────────────────────────────────────────────

    def setup_queues(self) -> None:
        """Set up RabbitMQ queues for Wazuh query requests."""
        prefix = self._routing_prefix
        self.inbox = self.rmq.declare_queue(
            f"{self.config.service_name}.inbox",
            routing_keys=[
                f"{prefix}.query.alerts",
                f"{prefix}.query.agents",
                f"{prefix}.query.vulnerabilities",
                f"{prefix}.query.fim",
                f"{prefix}.query.sca",
                f"{prefix}.query.summary",
            ],
        )
        self.rmq.consume(self.inbox, self.handle_message)

    def handle_message(self, envelope: MessageEnvelope) -> Optional[MessageEnvelope]:
        """Route incoming queries to the appropriate handler."""
        msg_type = envelope.message_type
        payload = envelope.payload
        prefix = self._routing_prefix

        handlers = {
            f"{prefix}.query.alerts": self._handle_alerts_query,
            f"{prefix}.query.agents": self._handle_agents_query,
            f"{prefix}.query.vulnerabilities": self._handle_vuln_query,
            f"{prefix}.query.fim": self._handle_fim_query,
            f"{prefix}.query.sca": self._handle_sca_query,
            f"{prefix}.query.summary": self._handle_summary_query,
        }

        handler = handlers.get(msg_type)
        if not handler:
            logger.warning("Unknown message type: %s", msg_type)
            return envelope.create_reply(
                source=self.service_name,
                message_type=f"{prefix}.response.error",
                payload={"error": f"Unknown query type: {msg_type}"},
            )

        try:
            result = handler(payload, envelope)
            # Tag with instance label so Kevin knows which Wazuh this is from
            result["wazuh_instance"] = self._instance_label

            try:
                self.audit.log_from_envelope(
                    envelope=envelope,
                    event_type=EventType.DATA_ACCESS,
                    action=msg_type,
                    resource=self._resource_for_type(msg_type),
                    details={"result_count": result.get("count", 0), "instance": self._instance_label},
                )
            except Exception as audit_err:
                logger.warning("Audit log failed (non-fatal): %s", audit_err)

            return envelope.create_reply(
                source=self.service_name,
                message_type=msg_type.replace("query", "response"),
                payload=result,
            )

        except Exception as e:
            logger.error("Handler error for %s: %s", msg_type, e, exc_info=True)
            self.audit.log_from_envelope(
                envelope=envelope,
                event_type=EventType.DATA_ACCESS,
                action=msg_type,
                resource=self._resource_for_type(msg_type),
                outcome_status="error",
                details={"error": str(e)},
            )
            return envelope.create_reply(
                source=self.service_name,
                message_type="wazuh.response.error",
                payload={"error": str(e)},
            )

    # ── Manager API Authentication ──────────────────────────────────

    def _authenticate_manager(self) -> None:
        """Authenticate with Wazuh Manager API and get a JWT token."""
        resp = self._api_http.post(
            "/security/user/authenticate",
            auth=(self._api_user, self._api_password),
        )
        resp.raise_for_status()
        self._api_token = resp.json().get("data", {}).get("token")
        # Wazuh tokens last ~15 minutes
        self._api_token_expiry = time.time() + 840
        logger.debug("Authenticated with Wazuh Manager API")

    def _ensure_manager_auth(self) -> None:
        """Refresh Manager API token if expired."""
        if not self._api_token or time.time() >= self._api_token_expiry:
            self._authenticate_manager()

    def _manager_request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
        """Make an authenticated request to the Wazuh Manager API."""
        self._ensure_manager_auth()
        kwargs.setdefault("headers", {})["Authorization"] = f"Bearer {self._api_token}"
        resp = self._api_http.request(method, path, **kwargs)
        resp.raise_for_status()
        return resp.json()

    # ── Indexer Queries ─────────────────────────────────────────────

    def _indexer_search(
        self,
        index: str,
        query: Dict[str, Any],
        size: int = 50,
        sort: Optional[List] = None,
    ) -> Dict[str, Any]:
        """Execute an OpenSearch query against the Wazuh Indexer."""
        body = {"query": query, "size": size}
        if sort:
            body["sort"] = sort

        resp = self._indexer_http.post(
            f"/{index}/_search",
            json=body,
        )
        resp.raise_for_status()
        return resp.json()

    # ── Alert Queries ───────────────────────────────────────────────

    def _handle_alerts_query(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Query Wazuh alerts from the Indexer.

        Supported payload fields:
        - time_range: "1h", "24h", "7d", "30d" (default: "24h")
        - severity: "low", "medium", "high", "critical" or min level int
        - agent_name: filter by agent name
        - agent_id: filter by agent ID
        - rule_id: filter by specific rule ID
        - search: free-text search across alert fields
        - limit: max results (default: 50, max: 200)
        """
        time_range = payload.get("time_range", "24h")
        severity = payload.get("severity")
        agent_name = payload.get("agent_name")
        agent_id = payload.get("agent_id")
        rule_id = payload.get("rule_id")
        search_text = payload.get("search")
        limit = min(int(payload.get("limit", 50)), 200)

        # Build time filter
        now = datetime.now(timezone.utc)
        time_map = {
            "1h": timedelta(hours=1),
            "6h": timedelta(hours=6),
            "12h": timedelta(hours=12),
            "24h": timedelta(days=1),
            "7d": timedelta(days=7),
            "30d": timedelta(days=30),
        }
        delta = time_map.get(time_range, timedelta(days=1))
        from_time = (now - delta).isoformat()

        # Build query
        must = [
            {"range": {"timestamp": {"gte": from_time, "lte": now.isoformat()}}},
        ]

        if severity:
            severity_map = {"low": 3, "medium": 7, "high": 10, "critical": 13}
            min_level = severity_map.get(severity, int(severity) if severity.isdigit() else 3)
            must.append({"range": {"rule.level": {"gte": min_level}}})

        if agent_name:
            must.append({"match": {"agent.name": agent_name}})
        if agent_id:
            must.append({"term": {"agent.id": agent_id}})
        if rule_id:
            must.append({"term": {"rule.id": str(rule_id)}})
        if search_text:
            must.append({"query_string": {"query": search_text}})

        query = {"bool": {"must": must}}

        result = self._indexer_search(
            index="wazuh-alerts-*",
            query=query,
            size=limit,
            sort=[{"timestamp": {"order": "desc"}}],
        )

        hits = result.get("hits", {})
        total = hits.get("total", {}).get("value", 0)
        alerts = []

        for hit in hits.get("hits", []):
            src = hit.get("_source", {})
            alerts.append({
                "timestamp": src.get("timestamp"),
                "agent": {
                    "id": src.get("agent", {}).get("id"),
                    "name": src.get("agent", {}).get("name"),
                    "ip": src.get("agent", {}).get("ip"),
                },
                "rule": {
                    "id": src.get("rule", {}).get("id"),
                    "level": src.get("rule", {}).get("level"),
                    "description": src.get("rule", {}).get("description"),
                    "groups": src.get("rule", {}).get("groups", []),
                    "mitre": src.get("rule", {}).get("mitre", {}),
                },
                "source": {
                    "ip": src.get("data", {}).get("srcip") or src.get("srcip"),
                    "port": src.get("data", {}).get("srcport"),
                },
                "destination": {
                    "ip": src.get("data", {}).get("dstip") or src.get("dstip"),
                    "port": src.get("data", {}).get("dstport"),
                },
                "full_log": src.get("full_log", "")[:500],  # Truncate
                "location": src.get("location"),
            })

        # Generate severity summary
        severity_counts = {}
        for alert in alerts:
            level = alert["rule"].get("level", 0)
            if level >= 13:
                sev = "critical"
            elif level >= 10:
                sev = "high"
            elif level >= 7:
                sev = "medium"
            else:
                sev = "low"
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "type": "alerts",
            "count": len(alerts),
            "total_matching": total,
            "time_range": time_range,
            "severity_summary": severity_counts,
            "alerts": alerts,
        }

    # ── Agent Queries ───────────────────────────────────────────────

    def _handle_agents_query(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Query Wazuh agent status and health via Manager API.

        Supported payload fields:
        - status: "active", "disconnected", "never_connected", "pending"
        - name: filter by agent name (partial match)
        - os_platform: "linux", "windows", "macos"
        - group: filter by agent group
        - limit: max results (default: 50)
        """
        status = payload.get("status")
        name = payload.get("name")
        os_platform = payload.get("os_platform")
        group = payload.get("group")
        limit = min(int(payload.get("limit", 50)), 500)

        # Build query parameters
        params = {"limit": limit, "offset": 0}
        if status:
            params["status"] = status
        if name:
            params["search"] = name
        if os_platform:
            params["os.platform"] = os_platform
        if group:
            params["group"] = group

        data = self._manager_request("GET", "/agents", params=params)
        items = data.get("data", {}).get("affected_items", [])
        total = data.get("data", {}).get("total_affected_items", 0)

        agents = []
        status_counts = {}

        for agent in items:
            agent_status = agent.get("status", "unknown")
            status_counts[agent_status] = status_counts.get(agent_status, 0) + 1

            agents.append({
                "id": agent.get("id"),
                "name": agent.get("name"),
                "ip": agent.get("ip"),
                "status": agent_status,
                "os": {
                    "name": agent.get("os", {}).get("name"),
                    "platform": agent.get("os", {}).get("platform"),
                    "version": agent.get("os", {}).get("version"),
                },
                "version": agent.get("version"),
                "group": agent.get("group", []),
                "last_keep_alive": agent.get("lastKeepAlive"),
                "date_add": agent.get("dateAdd"),
                "node_name": agent.get("node_name"),
            })

        return {
            "type": "agents",
            "count": len(agents),
            "total_matching": total,
            "status_summary": status_counts,
            "agents": agents,
        }

    # ── Vulnerability Queries ───────────────────────────────────────

    def _handle_vuln_query(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Query vulnerability detection results from the Indexer.

        Supported payload fields:
        - time_range: "24h", "7d", "30d" (default: "7d")
        - severity: "Low", "Medium", "High", "Critical"
        - agent_name: filter by agent
        - cve: specific CVE ID
        - package: filter by affected package name
        - limit: max results (default: 50)
        """
        time_range = payload.get("time_range", "7d")
        severity = payload.get("severity")
        agent_name = payload.get("agent_name")
        cve = payload.get("cve")
        package = payload.get("package")
        limit = min(int(payload.get("limit", 50)), 200)

        now = datetime.now(timezone.utc)
        time_map = {
            "24h": timedelta(days=1),
            "7d": timedelta(days=7),
            "30d": timedelta(days=30),
            "90d": timedelta(days=90),
        }
        delta = time_map.get(time_range, timedelta(days=7))
        from_time = (now - delta).isoformat()

        must = [
            {"range": {"timestamp": {"gte": from_time, "lte": now.isoformat()}}},
        ]

        if severity:
            must.append({"match": {"data.vulnerability.severity": severity}})
        if agent_name:
            must.append({"match": {"agent.name": agent_name}})
        if cve:
            must.append({"term": {"data.vulnerability.cve": cve}})
        if package:
            must.append({"match": {"data.vulnerability.package.name": package}})

        query = {"bool": {"must": must}}

        result = self._indexer_search(
            index="wazuh-alerts-*",
            query=query,
            size=limit,
            sort=[{"timestamp": {"order": "desc"}}],
        )

        hits = result.get("hits", {})
        total = hits.get("total", {}).get("value", 0)
        vulns = []
        severity_counts = {}

        for hit in hits.get("hits", []):
            src = hit.get("_source", {})
            vuln_data = src.get("data", {}).get("vulnerability", {})
            sev = vuln_data.get("severity", "Unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            vulns.append({
                "timestamp": src.get("timestamp"),
                "agent": {
                    "id": src.get("agent", {}).get("id"),
                    "name": src.get("agent", {}).get("name"),
                },
                "cve": vuln_data.get("cve"),
                "severity": sev,
                "title": vuln_data.get("title"),
                "package": {
                    "name": vuln_data.get("package", {}).get("name"),
                    "version": vuln_data.get("package", {}).get("version"),
                    "fix_version": vuln_data.get("package", {}).get("fix_version"),
                },
                "reference": vuln_data.get("reference"),
                "cvss": vuln_data.get("cvss", {}),
            })

        return {
            "type": "vulnerabilities",
            "count": len(vulns),
            "total_matching": total,
            "time_range": time_range,
            "severity_summary": severity_counts,
            "vulnerabilities": vulns,
        }

    # ── FIM Queries ─────────────────────────────────────────────────

    def _handle_fim_query(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Query File Integrity Monitoring events from the Indexer.

        Supported payload fields:
        - time_range: "24h", "7d", "30d" (default: "24h")
        - agent_name: filter by agent
        - path: filter by file path
        - event_type: "added", "modified", "deleted"
        - limit: max results (default: 50)
        """
        time_range = payload.get("time_range", "24h")
        agent_name = payload.get("agent_name")
        path = payload.get("path")
        event_type = payload.get("event_type")
        limit = min(int(payload.get("limit", 50)), 200)

        now = datetime.now(timezone.utc)
        time_map = {
            "24h": timedelta(days=1),
            "7d": timedelta(days=7),
            "30d": timedelta(days=30),
        }
        delta = time_map.get(time_range, timedelta(days=1))
        from_time = (now - delta).isoformat()

        must = [
            {"range": {"timestamp": {"gte": from_time}}},
            {"term": {"rule.groups": "syscheck"}},
        ]

        if agent_name:
            must.append({"match": {"agent.name": agent_name}})
        if path:
            must.append({"wildcard": {"syscheck.path": f"*{path}*"}})
        if event_type:
            must.append({"term": {"syscheck.event": event_type}})

        query = {"bool": {"must": must}}

        result = self._indexer_search(
            index="wazuh-alerts-*",
            query=query,
            size=limit,
            sort=[{"timestamp": {"order": "desc"}}],
        )

        hits = result.get("hits", {})
        events = []

        for hit in hits.get("hits", []):
            src = hit.get("_source", {})
            syscheck = src.get("syscheck", {})
            events.append({
                "timestamp": src.get("timestamp"),
                "agent": {
                    "name": src.get("agent", {}).get("name"),
                },
                "path": syscheck.get("path"),
                "event": syscheck.get("event"),
                "size_before": syscheck.get("size_before"),
                "size_after": syscheck.get("size_after"),
                "md5_before": syscheck.get("md5_before"),
                "md5_after": syscheck.get("md5_after"),
                "uid_after": syscheck.get("uid_after"),
                "gid_after": syscheck.get("gid_after"),
                "perm_after": syscheck.get("perm_after"),
                "rule": {
                    "description": src.get("rule", {}).get("description"),
                    "level": src.get("rule", {}).get("level"),
                },
            })

        return {
            "type": "fim",
            "count": len(events),
            "total_matching": hits.get("total", {}).get("value", 0),
            "time_range": time_range,
            "events": events,
        }

    # ── SCA Queries ─────────────────────────────────────────────────

    def _handle_sca_query(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Query Security Configuration Assessment results via Manager API.

        Supported payload fields:
        - agent_id: specific agent ID (required)
        - policy_id: specific SCA policy
        - result: "passed", "failed", "not_applicable"
        """
        agent_id = payload.get("agent_id")
        policy_id = payload.get("policy_id")
        result_filter = payload.get("result")

        if not agent_id:
            return {
                "type": "sca",
                "error": "agent_id is required for SCA queries",
                "count": 0,
            }

        # Get SCA policies for the agent
        data = self._manager_request("GET", f"/sca/{agent_id}")
        policies = data.get("data", {}).get("affected_items", [])

        if policy_id:
            # Get specific policy checks
            check_data = self._manager_request(
                "GET", f"/sca/{agent_id}/checks/{policy_id}"
            )
            checks = check_data.get("data", {}).get("affected_items", [])

            if result_filter:
                checks = [c for c in checks if c.get("result") == result_filter]

            return {
                "type": "sca_checks",
                "agent_id": agent_id,
                "policy_id": policy_id,
                "count": len(checks),
                "checks": [
                    {
                        "id": c.get("id"),
                        "title": c.get("title"),
                        "description": c.get("description"),
                        "result": c.get("result"),
                        "remediation": c.get("remediation"),
                        "rationale": c.get("rationale"),
                        "compliance": c.get("compliance", []),
                    }
                    for c in checks[:100]
                ],
            }

        return {
            "type": "sca",
            "agent_id": agent_id,
            "count": len(policies),
            "policies": [
                {
                    "policy_id": p.get("policy_id"),
                    "name": p.get("name"),
                    "description": p.get("description"),
                    "pass": p.get("pass"),
                    "fail": p.get("fail"),
                    "score": p.get("score"),
                    "invalid": p.get("invalid"),
                    "total_checks": p.get("total_checks"),
                }
                for p in policies
            ],
        }

    # ── Summary Query ───────────────────────────────────────────────

    def _handle_summary_query(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Get a high-level security summary — agent health + recent alert stats.
        Used when the user asks something like "how's our security posture?"
        """
        results = {}

        # Agent summary from Manager API
        try:
            agent_data = self._manager_request(
                "GET", "/agents/summary/status"
            )
            results["agents"] = agent_data.get("data", {})
        except Exception as e:
            logger.warning("Could not fetch agent summary: %s", e)
            results["agents"] = {"error": str(e)}

        # Recent alert summary from Indexer (last 24h)
        try:
            now = datetime.now(timezone.utc)
            from_time = (now - timedelta(days=1)).isoformat()

            # Severity aggregation
            agg_query = {
                "query": {
                    "range": {"timestamp": {"gte": from_time}}
                },
                "size": 0,
                "aggs": {
                    "severity_levels": {
                        "range": {
                            "field": "rule.level",
                            "ranges": [
                                {"key": "low", "from": 0, "to": 7},
                                {"key": "medium", "from": 7, "to": 10},
                                {"key": "high", "from": 10, "to": 13},
                                {"key": "critical", "from": 13},
                            ],
                        }
                    },
                    "top_rules": {
                        "terms": {
                            "field": "rule.description.keyword",
                            "size": 10,
                        }
                    },
                    "top_agents": {
                        "terms": {
                            "field": "agent.name.keyword",
                            "size": 10,
                        }
                    },
                }
            }

            resp = self._indexer_http.post(
                "/wazuh-alerts-*/_search",
                json=agg_query,
            )
            resp.raise_for_status()
            agg_result = resp.json()

            total_alerts = agg_result.get("hits", {}).get("total", {}).get("value", 0)
            severity_buckets = agg_result.get("aggregations", {}).get(
                "severity_levels", {}
            ).get("buckets", [])
            top_rules = agg_result.get("aggregations", {}).get(
                "top_rules", {}
            ).get("buckets", [])
            top_agents = agg_result.get("aggregations", {}).get(
                "top_agents", {}
            ).get("buckets", [])

            results["alerts_24h"] = {
                "total": total_alerts,
                "by_severity": {
                    b["key"]: b["doc_count"] for b in severity_buckets
                },
                "top_rules": [
                    {"rule": b["key"], "count": b["doc_count"]}
                    for b in top_rules
                ],
                "top_agents": [
                    {"agent": b["key"], "count": b["doc_count"]}
                    for b in top_agents
                ],
            }

        except Exception as e:
            logger.warning("Could not fetch alert summary: %s", e)
            results["alerts_24h"] = {"error": str(e)}

        return {
            "type": "summary",
            "count": 1,
            **results,
        }

    # ── Helpers ──────────────────────────────────────────────────────

    def _resource_for_type(self, msg_type: str) -> str:
        """Map message types to RBAC resource names."""
        resource_map = {
            "wazuh.query.alerts": "wazuh-alerts",
            "wazuh.query.agents": "wazuh-agents",
            "wazuh.query.vulnerabilities": "wazuh-vulnerability",
            "wazuh.query.fim": "wazuh-fim",
            "wazuh.query.sca": "wazuh-sca",
            "wazuh.query.summary": "wazuh-alerts",
        }
        return resource_map.get(msg_type, "wazuh")

    def get_capabilities(self) -> list:
        return [
            "wazuh.alerts",
            "wazuh.agents",
            "wazuh.vulnerabilities",
            "wazuh.fim",
            "wazuh.sca",
            "wazuh.summary",
        ]

    def get_metadata(self) -> dict:
        return {
            "indexer_url": self._indexer_url,
            "api_url": self._api_url,
        }

    def health_status(self) -> dict:
        status = {"healthy": True}
        try:
            resp = self._indexer_http.get("/_cluster/health")
            cluster = resp.json()
            status["indexer"] = cluster.get("status", "unknown")
        except Exception:
            status["indexer"] = "unreachable"
            status["healthy"] = False

        try:
            self._ensure_manager_auth()
            status["manager_api"] = "connected"
        except Exception:
            status["manager_api"] = "unreachable"

        return status


# ── Entrypoint ──────────────────────────────────────────────────────

if __name__ == "__main__":
    import os
    svc = os.environ.get("NEURO_SERVICE_NAME", "connector-wazuh")
    if svc.startswith("connector-"):
        svc = svc[len("connector-"):]
    service = WazuhConnector.create(svc)
    service.run()
