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

Architecture:
- Alert queries use an in-memory cache with configurable TTL.
- On first query (or cache miss), the connector pulls ALL matching alerts
  from the Indexer (using scroll API for large result sets) and caches them.
- Subsequent queries within the TTL window are served from cache with
  local filtering, sorting, and aggregation — no Indexer round-trip.
- This means Kevin gets accurate severity counts and can drill down into
  any subset without re-querying Wazuh.

Credentials are read from HashiCorp Vault at startup.
"""

import hashlib
import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

from neurokit.envelope import EventType, MessageEnvelope
from neurokit.service import BaseService

logger = logging.getLogger("connector-wazuh")

# ── Severity bands aligned with Wazuh Dashboard ────────────────────
# Critical: Level 15+    High: Level 12-14
# Medium:   Level 7-11   Low:  Level 0-6
SEVERITY_MAP = {"low": 0, "medium": 7, "high": 12, "critical": 15}
SEVERITY_AGG_RANGES = [
    {"key": "low", "from": 0, "to": 7},
    {"key": "medium", "from": 7, "to": 12},
    {"key": "high", "from": 12, "to": 15},
    {"key": "critical", "from": 15},
]

# Default cache TTL in seconds (5 minutes)
DEFAULT_CACHE_TTL = int(os.environ.get("WAZUH_CACHE_TTL", "300"))


def classify_severity(level: int) -> str:
    """Classify a rule level into a severity label matching the Wazuh dashboard."""
    if level >= 15:
        return "critical"
    elif level >= 12:
        return "high"
    elif level >= 7:
        return "medium"
    return "low"


# ── Alert Cache ─────────────────────────────────────────────────────

class AlertCache:
    """
    In-memory cache for Wazuh alert data with TTL-based expiry.

    Stores the full alert dataset for a given time range + severity
    combination, enabling fast local queries without re-hitting the
    Wazuh Indexer.

    Each cache entry has a TTL. Expired entries are lazily evicted
    on the next access.
    """

    def __init__(self, ttl: int = DEFAULT_CACHE_TTL):
        self._ttl = ttl
        self._store: Dict[str, Dict[str, Any]] = {}

    def get(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Return cached entry if it exists and hasn't expired."""
        entry = self._store.get(cache_key)
        if entry is None:
            return None
        age = time.time() - entry["created_at"]
        if age > self._ttl:
            del self._store[cache_key]
            logger.debug("Cache expired for key %s (age %.0fs > TTL %ds)", cache_key, age, self._ttl)
            return None
        logger.debug("Cache hit for key %s (age %.0fs)", cache_key, age)
        return entry

    def put(
        self,
        cache_key: str,
        alerts: List[Dict],
        time_range: str,
        min_level: int,
        total_from_indexer: int,
    ) -> None:
        """Store alerts in the cache."""
        self._store[cache_key] = {
            "alerts": alerts,
            "created_at": time.time(),
            "time_range": time_range,
            "min_level": min_level,
            "total_from_indexer": total_from_indexer,
        }
        logger.info(
            "Cached %d alerts (key=%s, time_range=%s, min_level=%d, TTL=%ds)",
            len(alerts), cache_key, time_range, min_level, self._ttl,
        )

    def invalidate(self, cache_key: Optional[str] = None) -> None:
        """Invalidate a specific key or all keys."""
        if cache_key:
            self._store.pop(cache_key, None)
        else:
            self._store.clear()
            logger.info("Alert cache cleared")

    def stats(self) -> Dict[str, Any]:
        """Return cache statistics."""
        now = time.time()
        entries = []
        for key, entry in self._store.items():
            age = now - entry["created_at"]
            entries.append({
                "key": key,
                "alert_count": len(entry["alerts"]),
                "age_seconds": round(age),
                "ttl_remaining": max(0, round(self._ttl - age)),
                "time_range": entry["time_range"],
            })
        return {
            "ttl": self._ttl,
            "entries": entries,
            "total_cached_alerts": sum(len(e["alerts"]) for e in self._store.values()),
        }

    @staticmethod
    def make_key(
        time_range: str,
        min_level: int,
        agent_name: Optional[str] = None,
        agent_id: Optional[str] = None,
        rule_id: Optional[str] = None,
    ) -> str:
        """
        Generate a composite cache key from query parameters.

        Scoped queries (by agent or rule) get their own cache entries
        so they can store all severity levels without polluting the
        fleet-wide cache.
        """
        parts = [time_range, f"lvl{min_level}"]
        if agent_name:
            parts.append(f"agent:{agent_name.lower()}")
        if agent_id:
            parts.append(f"aid:{agent_id}")
        if rule_id:
            parts.append(f"rule:{rule_id}")
        return ":".join(parts)


# ── Local Query Engine ──────────────────────────────────────────────

def query_cached_alerts(
    alerts: List[Dict],
    severity: Optional[str] = None,
    agent_name: Optional[str] = None,
    agent_id: Optional[str] = None,
    rule_id: Optional[str] = None,
    search_text: Optional[str] = None,
) -> List[Dict]:
    """Filter cached alerts using local Python operations."""
    results = alerts

    if severity:
        min_level = SEVERITY_MAP.get(severity, 0)
        max_level = {"low": 6, "medium": 11, "high": 14, "critical": 99}.get(severity)
        if max_level:
            results = [a for a in results if min_level <= a["rule"].get("level", 0) <= max_level]
        else:
            results = [a for a in results if a["rule"].get("level", 0) >= min_level]

    if agent_name:
        agent_lower = agent_name.lower()
        results = [a for a in results if agent_lower in (a["agent"].get("name") or "").lower()]

    if agent_id:
        results = [a for a in results if a["agent"].get("id") == agent_id]

    if rule_id:
        results = [a for a in results if str(a["rule"].get("id")) == str(rule_id)]

    if search_text:
        search_lower = search_text.lower()
        results = [
            a for a in results
            if search_lower in (a["rule"].get("description") or "").lower()
            or search_lower in (a.get("full_log") or "").lower()
            or search_lower in (a["agent"].get("name") or "").lower()
        ]

    return results


def build_alert_summary(alerts: List[Dict]) -> Dict[str, Any]:
    """Build analytical summary from a list of alerts."""
    severity_counts = defaultdict(int)
    agent_counts = defaultdict(int)
    rule_counts = defaultdict(int)

    for alert in alerts:
        level = alert["rule"].get("level", 0)
        severity_counts[classify_severity(level)] += 1
        agent_name = alert["agent"].get("name", "unknown")
        agent_counts[agent_name] += 1
        rule_desc = alert["rule"].get("description", "unknown")
        rule_counts[rule_desc] += 1

    return {
        "severity_summary": dict(severity_counts),
        "top_agents": sorted(
            [{"agent": k, "count": v} for k, v in agent_counts.items()],
            key=lambda x: x["count"], reverse=True,
        )[:10],
        "top_rules": sorted(
            [{"rule": k, "count": v} for k, v in rule_counts.items()],
            key=lambda x: x["count"], reverse=True,
        )[:10],
    }


# ── Wazuh Connector ────────────────────────────────────────────────

class WazuhConnector(BaseService):
    """
    Wazuh connector for on-demand SIEM queries.

    Alert queries use an in-memory cache with configurable TTL
    (default 5min, set via WAZUH_CACHE_TTL env var). On first query
    or cache miss, the connector pulls ALL matching alerts via the
    scroll API and caches them locally. Subsequent queries within
    the TTL window are served from cache with local filtering.
    """

    def __init__(self, config):
        super().__init__(config)
        self._indexer_url: str = ""
        self._indexer_user: str = ""
        self._indexer_password: str = ""
        self._api_url: str = ""
        self._api_user: str = ""
        self._api_password: str = ""
        self._api_token: Optional[str] = None
        self._api_token_expiry: float = 0
        self._verify_ssl: bool = False
        self._indexer_http: Optional[httpx.Client] = None
        self._api_http: Optional[httpx.Client] = None
        self._vault_secret = os.environ.get("WAZUH_VAULT_SECRET", "wazuh")
        self._routing_prefix = os.environ.get("WAZUH_ROUTING_PREFIX", "wazuh")
        self._instance_label = os.environ.get("WAZUH_INSTANCE_LABEL", "desktops")
        # Alert cache with TTL
        self._alert_cache = AlertCache(ttl=DEFAULT_CACHE_TTL)

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

        self._indexer_http = httpx.Client(
            base_url=self._indexer_url,
            auth=(self._indexer_user, self._indexer_password),
            verify=self._verify_ssl,
            timeout=30,
        )
        self._api_http = httpx.Client(
            base_url=self._api_url,
            verify=self._verify_ssl,
            timeout=30,
        )

        self._test_indexer()
        self._test_manager_api()

        self.audit.log_system(
            action="wazuh_connected",
            resource="wazuh",
            details={
                "indexer_url": self._indexer_url,
                "api_url": self._api_url,
                "instance_label": self._instance_label,
                "cache_ttl": DEFAULT_CACHE_TTL,
            },
        )

    def _test_indexer(self) -> None:
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
        resp = self._api_http.post(
            "/security/user/authenticate",
            auth=(self._api_user, self._api_password),
        )
        resp.raise_for_status()
        self._api_token = resp.json().get("data", {}).get("token")
        self._api_token_expiry = time.time() + 840
        logger.debug("Authenticated with Wazuh Manager API")

    def _ensure_manager_auth(self) -> None:
        if not self._api_token or time.time() >= self._api_token_expiry:
            self._authenticate_manager()

    def _manager_request(self, method: str, path: str, **kwargs) -> Dict[str, Any]:
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
        body = {"query": query, "size": size}
        if sort:
            body["sort"] = sort
        resp = self._indexer_http.post(f"/{index}/_search", json=body)
        resp.raise_for_status()
        return resp.json()

    def _indexer_scroll(
        self,
        index: str,
        query: Dict[str, Any],
        sort: Optional[List] = None,
        max_results: int = 10000,
        batch_size: int = 1000,
    ) -> Tuple[List[Dict], int]:
        """
        Fetch large result sets from the Wazuh Indexer using the scroll API.

        Returns (hits_list, total_matching) where hits_list contains the
        raw _source dicts from OpenSearch.
        """
        body: Dict[str, Any] = {"query": query, "size": batch_size}
        if sort:
            body["sort"] = sort

        resp = self._indexer_http.post(
            f"/{index}/_search?scroll=2m",
            json=body,
        )
        resp.raise_for_status()
        data = resp.json()

        scroll_id = data.get("_scroll_id")
        total = data.get("hits", {}).get("total", {}).get("value", 0)
        all_hits = [hit.get("_source", {}) for hit in data.get("hits", {}).get("hits", [])]

        try:
            while len(all_hits) < max_results and len(data.get("hits", {}).get("hits", [])) > 0:
                resp = self._indexer_http.post(
                    "/_search/scroll",
                    json={"scroll": "2m", "scroll_id": scroll_id},
                )
                resp.raise_for_status()
                data = resp.json()
                scroll_id = data.get("_scroll_id")
                batch = data.get("hits", {}).get("hits", [])
                if not batch:
                    break
                all_hits.extend(hit.get("_source", {}) for hit in batch)
        finally:
            if scroll_id:
                try:
                    self._indexer_http.delete(
                        "/_search/scroll",
                        json={"scroll_id": scroll_id},
                    )
                except Exception:
                    pass

        logger.info("Scroll query fetched %d/%d alerts from %s", len(all_hits), total, index)
        return all_hits[:max_results], total

    # ── Alert Queries (Cached) ──────────────────────────────────────

    def _parse_alert(self, src: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a raw alert _source dict into our standard format."""
        return {
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
            "full_log": src.get("full_log", "")[:500],
            "location": src.get("location"),
        }

    def _populate_cache(
        self,
        time_range: str,
        min_level: int,
        agent_name: Optional[str] = None,
        agent_id: Optional[str] = None,
        rule_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Pull matching alerts from the Indexer via scroll and cache them.

        Query variants:
        - Fleet-wide (no scope): pulls all alerts >= min_level, max 10K
        - Agent-scoped: pulls ALL levels for a single agent, max 10K
        - Rule-scoped: pulls ALL levels for a single rule, max 10K

        Scoped queries use a lower max_results cap since they target
        a specific subset of the data.
        """
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

        # Build the query based on scope
        must = [
            {"range": {"timestamp": {"gte": from_time, "lte": now.isoformat()}}},
        ]

        # Always apply minimum level filter
        if min_level > 0:
            must.append({"range": {"rule.level": {"gte": min_level}}})

        # Scope filters — these get baked into the Indexer query
        if agent_name:
            must.append({"match": {"agent.name": agent_name}})
        if agent_id:
            must.append({"term": {"agent.id": agent_id}})
        if rule_id:
            must.append({"term": {"rule.id": str(rule_id)}})

        query = {"bool": {"must": must}}

        # Scoped queries can afford a higher max since volume is bounded
        is_scoped = bool(agent_name or agent_id or rule_id)
        max_results = 10000 if is_scoped else 10000

        raw_hits, total = self._indexer_scroll(
            index="wazuh-alerts-*",
            query=query,
            sort=[
                {"rule.level": {"order": "desc"}},
                {"timestamp": {"order": "desc"}},
            ],
            max_results=max_results,
        )

        alerts = [self._parse_alert(src) for src in raw_hits]

        cache_key = AlertCache.make_key(time_range, min_level, agent_name, agent_id, rule_id)
        self._alert_cache.put(
            cache_key=cache_key,
            alerts=alerts,
            time_range=time_range,
            min_level=min_level,
            total_from_indexer=total,
        )

        return self._alert_cache.get(cache_key)

    def _get_cached_alerts(
        self,
        time_range: str,
        min_level: int,
        agent_name: Optional[str] = None,
        agent_id: Optional[str] = None,
        rule_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Get alerts from cache or populate if missing/expired."""
        cache_key = AlertCache.make_key(time_range, min_level, agent_name, agent_id, rule_id)
        entry = self._alert_cache.get(cache_key)
        if entry is None:
            entry = self._populate_cache(time_range, min_level, agent_name, agent_id, rule_id)
        return entry

    def _handle_alerts_query(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        """
        Query Wazuh alerts — served from cache when possible.

        Uses variant query strategies based on scope and severity:

        ┌─────────────────┬───────────────┬──────────────┬─────────────────────┐
        │ Query Type       │ Severity Floor│ Max Time     │ Cache Key Example   │
        ├─────────────────┼───────────────┼──────────────┼─────────────────────┤
        │ Fleet-wide       │ Level 7+      │ 30d          │ 24h:lvl7            │
        │ Agent-scoped     │ Level 0+      │ 6h for low   │ 6h:lvl0:agent:host1 │
        │ Rule-scoped      │ Level 0+      │ 6h for low   │ 6h:lvl0:rule:5710   │
        │ Fleet + low sev  │ DENIED        │ —            │ —                   │
        └─────────────────┴───────────────┴──────────────┴─────────────────────┘

        Guardrails:
        - Fleet-wide low-severity queries are denied (too many results)
        - Scoped queries requesting low severity are capped at 6h time range
        - All results are cached with TTL for fast drill-downs

        Supported payload fields:
        - time_range: "1h", "6h", "12h", "24h", "7d", "30d" (default: "24h")
        - severity: "low", "medium", "high", "critical"
        - agent_name: filter by agent name (enables scoped pull)
        - agent_id: filter by agent ID (enables scoped pull)
        - rule_id: filter by specific rule ID (enables scoped pull)
        - search: free-text search across alert fields (local filter)
        - limit: max alert details to return (default: 200)
        - nocache: if true, bypass cache and force fresh pull
        """
        time_range = payload.get("time_range", "24h")
        severity = payload.get("severity")
        agent_name = payload.get("agent_name")
        agent_id = payload.get("agent_id")
        rule_id = payload.get("rule_id")
        search_text = payload.get("search")
        limit = int(payload.get("limit", 200))
        nocache = payload.get("nocache", False)

        is_scoped = bool(agent_name or agent_id or rule_id)
        wants_low = severity and severity.lower() == "low"

        # ── Query Strategy & Guardrails ─────────────────────────────
        warnings = []

        if wants_low and not is_scoped:
            # Fleet-wide low severity = 180K+ alerts. Deny it.
            return {
                "type": "alerts",
                "count": 0,
                "total_matching": 0,
                "total_cached": 0,
                "time_range": time_range,
                "alerts": [],
                "severity_summary": {},
                "warning": (
                    "Fleet-wide low-severity queries are not supported — the "
                    "volume (100K+ alerts) is too large to be useful. Use the "
                    "summary endpoint for severity counts, or scope to a "
                    "specific agent or rule to include low-severity events. "
                    "Example: 'Show me low severity alerts for ADTX-LCROSS'"
                ),
            }

        if is_scoped:
            # Scoped: pull all severity levels for full investigation context
            cache_min_level = 0

            # Cap time range at 6h when pulling all levels (including low)
            max_scoped_ranges = ["1h", "6h"]
            if time_range not in max_scoped_ranges:
                original_range = time_range
                time_range = "6h"
                warnings.append(
                    f"Time range capped from {original_range} to 6h for "
                    f"scoped all-severity query to keep results manageable."
                )

            cache_agent_name = agent_name
            cache_agent_id = agent_id
            cache_rule_id = rule_id
        else:
            # Fleet-wide: use severity floor (medium+ minimum)
            if severity:
                cache_min_level = SEVERITY_MAP.get(
                    severity,
                    int(severity) if isinstance(severity, str) and severity.isdigit() else 7,
                )
            else:
                cache_min_level = 7  # Default: medium and above

            cache_agent_name = None
            cache_agent_id = None
            cache_rule_id = None

        # ── Cache Lookup / Populate ─────────────────────────────────
        if nocache:
            cache_key = AlertCache.make_key(
                time_range, cache_min_level,
                cache_agent_name, cache_agent_id, cache_rule_id,
            )
            self._alert_cache.invalidate(cache_key)

        cache_entry = self._get_cached_alerts(
            time_range, cache_min_level,
            cache_agent_name, cache_agent_id, cache_rule_id,
        )
        all_alerts = cache_entry["alerts"]

        # ── Local Filtering ─────────────────────────────────────────
        # For scoped queries, agent/rule filters are already baked into
        # the cache pull. Only severity and search are applied locally.
        if is_scoped:
            filtered = query_cached_alerts(
                alerts=all_alerts,
                severity=severity,
                search_text=search_text,
            )
        else:
            filtered = query_cached_alerts(
                alerts=all_alerts,
                severity=severity,
                agent_name=agent_name,
                agent_id=agent_id,
                rule_id=rule_id,
                search_text=search_text,
            )

        # ── Build Summaries ─────────────────────────────────────────
        full_summary = build_alert_summary(all_alerts)
        has_filters = len(filtered) != len(all_alerts)
        filtered_summary = build_alert_summary(filtered) if has_filters else full_summary

        # Sort: severity desc, then timestamp desc
        filtered.sort(
            key=lambda a: (a["rule"].get("level", 0), a.get("timestamp", "")),
            reverse=True,
        )

        returned_alerts = filtered[:limit]

        # ── Build Query Strategy Label ──────────────────────────────
        if is_scoped:
            scope_parts = []
            if agent_name:
                scope_parts.append(f"agent:{agent_name}")
            if agent_id:
                scope_parts.append(f"agent_id:{agent_id}")
            if rule_id:
                scope_parts.append(f"rule:{rule_id}")
            query_strategy = f"scoped({','.join(scope_parts)}):all_levels"
        else:
            query_strategy = f"fleet_wide:lvl{cache_min_level}+"

        # ── Response ────────────────────────────────────────────────
        result = {
            "type": "alerts",
            "query_strategy": query_strategy,
            "count": len(returned_alerts),
            "total_matching": len(filtered),
            "total_cached": len(all_alerts),
            "time_range": time_range,
            "cache_ttl": self._alert_cache._ttl,
            "served_from_cache": True,
            # Summary of ALL cached alerts
            "severity_summary": full_summary["severity_summary"],
            "top_agents": full_summary["top_agents"],
            "top_rules": full_summary["top_rules"],
            # Alert details
            "alerts": returned_alerts,
        }

        if has_filters:
            result["filtered_severity_summary"] = filtered_summary["severity_summary"]

        if warnings:
            result["warnings"] = warnings

        return result

    # ── Agent Queries ───────────────────────────────────────────────

    def _handle_agents_query(
        self, payload: Dict[str, Any], envelope: MessageEnvelope
    ) -> Dict[str, Any]:
        status = payload.get("status")
        name = payload.get("name")
        os_platform = payload.get("os_platform")
        group = payload.get("group")
        limit = min(int(payload.get("limit", 50)), 500)

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
                "agent": {"name": src.get("agent", {}).get("name")},
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
        agent_id = payload.get("agent_id")
        policy_id = payload.get("policy_id")
        result_filter = payload.get("result")

        if not agent_id:
            return {"type": "sca", "error": "agent_id is required for SCA queries", "count": 0}

        data = self._manager_request("GET", f"/sca/{agent_id}")
        policies = data.get("data", {}).get("affected_items", [])

        if policy_id:
            check_data = self._manager_request("GET", f"/sca/{agent_id}/checks/{policy_id}")
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
        High-level security summary. Uses cache when available,
        falls back to direct aggregation query.
        """
        results = {}

        # Agent summary from Manager API
        try:
            agent_data = self._manager_request("GET", "/agents/summary/status")
            results["agents"] = agent_data.get("data", {})
        except Exception as e:
            logger.warning("Could not fetch agent summary: %s", e)
            results["agents"] = {"error": str(e)}

        # Alert summary — try cache first, fall back to aggregation
        try:
            cache_key = AlertCache.make_key("24h", 0, None, None, None)
            cache_entry = self._alert_cache.get(cache_key)

            if cache_entry:
                summary = build_alert_summary(cache_entry["alerts"])
                results["alerts_24h"] = {
                    "total": cache_entry["total_from_indexer"],
                    "by_severity": summary["severity_summary"],
                    "top_rules": summary["top_rules"],
                    "top_agents": summary["top_agents"],
                    "source": "cache",
                }
            else:
                now = datetime.now(timezone.utc)
                from_time = (now - timedelta(days=1)).isoformat()

                agg_query = {
                    "query": {"range": {"timestamp": {"gte": from_time}}},
                    "size": 0,
                    "aggs": {
                        "severity_levels": {
                            "range": {
                                "field": "rule.level",
                                "ranges": SEVERITY_AGG_RANGES,
                            }
                        },
                        "top_rules": {
                            "terms": {"field": "rule.description.keyword", "size": 10}
                        },
                        "top_agents": {
                            "terms": {"field": "agent.name.keyword", "size": 10}
                        },
                    }
                }

                resp = self._indexer_http.post("/wazuh-alerts-*/_search", json=agg_query)
                resp.raise_for_status()
                agg_result = resp.json()

                total_alerts = agg_result.get("hits", {}).get("total", {}).get("value", 0)
                severity_buckets = agg_result.get("aggregations", {}).get(
                    "severity_levels", {}).get("buckets", [])
                top_rules = agg_result.get("aggregations", {}).get(
                    "top_rules", {}).get("buckets", [])
                top_agents = agg_result.get("aggregations", {}).get(
                    "top_agents", {}).get("buckets", [])

                results["alerts_24h"] = {
                    "total": total_alerts,
                    "by_severity": {b["key"]: b["doc_count"] for b in severity_buckets},
                    "top_rules": [{"rule": b["key"], "count": b["doc_count"]} for b in top_rules],
                    "top_agents": [{"agent": b["key"], "count": b["doc_count"]} for b in top_agents],
                    "source": "indexer_aggregation",
                }

        except Exception as e:
            logger.warning("Could not fetch alert summary: %s", e)
            results["alerts_24h"] = {"error": str(e)}

        return {"type": "summary", "count": 1, **results}

    # ── Helpers ──────────────────────────────────────────────────────

    def _resource_for_type(self, msg_type: str) -> str:
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
        return ["wazuh.alerts", "wazuh.agents", "wazuh.vulnerabilities",
                "wazuh.fim", "wazuh.sca", "wazuh.summary"]

    def get_metadata(self) -> dict:
        return {
            "indexer_url": self._indexer_url,
            "api_url": self._api_url,
            "cache_stats": self._alert_cache.stats(),
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
        status["alert_cache"] = self._alert_cache.stats()
        return status


# ── Entrypoint ──────────────────────────────────────────────────────

if __name__ == "__main__":
    import os
    svc = os.environ.get("NEURO_SERVICE_NAME", "connector-wazuh")
    if svc.startswith("connector-"):
        svc = svc[len("connector-"):]
    service = WazuhConnector.create(svc)
    service.run()
