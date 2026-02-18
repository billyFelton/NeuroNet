"""
Meraki Dashboard API Connector for NeuroNet.

Provides read-only network visibility:
- Organization & network inventory
- Network devices (switches, APs, appliances)
- Clients (connected endpoints with IP, MAC, VLAN, switchport)
- VLANs & subnets
- DHCP leases
- Device statuses & uplinks
- Client search by IP, MAC, hostname

Command-driven: responds to queries from the Resolver.
"""

import os
import re
import time
import logging
from typing import Any, Dict, List, Optional

import httpx

from neurokit.service import BaseService
from neurokit.envelope import MessageEnvelope
from neurokit.audit import EventType

logger = logging.getLogger("meraki")

# Rate limiting: Meraki allows 10 req/s per org
RATE_LIMIT_DELAY = 0.12  # ~8 req/s to stay safe


class MerakiConnector(BaseService):
    """
    Meraki Dashboard API connector.

    Read-only access to network infrastructure:
    organizations, networks, devices, clients, VLANs, DHCP.
    """

    def __init__(self, config):
        super().__init__(config)
        self._http: Optional[httpx.Client] = None
        self._api_key: str = ""
        self._org_id: str = ""
        self._org_name: str = ""
        self._networks: Dict[str, Dict] = {}  # id -> {name, ...}
        self._last_request_time: float = 0

    def on_startup(self) -> None:
        """Retrieve Meraki credentials from HashiCorp Vault."""
        secrets = self.secrets.get_all("meraki")

        self._api_key = secrets.get("api_key", "")
        self._org_id = secrets.get("org_id", "")
        base_url = secrets.get("base_url", "https://api.meraki.com/api/v1")

        if not self._api_key:
            raise ValueError("Meraki config incomplete — need api_key in Vault")

        self._http = httpx.Client(
            base_url=base_url,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            timeout=30,
        )

        # Discover org if not provided
        if not self._org_id:
            self._discover_org()
        else:
            self._load_org_name()

        # Cache network list
        self._cache_networks()

        self.audit.log_system(
            action="meraki_connected",
            resource="meraki-api",
            details={
                "org_id": self._org_id,
                "org_name": self._org_name,
                "networks": len(self._networks),
            },
        )

        logger.info(
            "Connected to Meraki: org=%s (%s), %d networks",
            self._org_name, self._org_id, len(self._networks),
        )

    def _discover_org(self) -> None:
        """Discover the organization from the API key."""
        try:
            resp = self._api_get("/organizations")
            orgs = resp
            if orgs:
                self._org_id = str(orgs[0]["id"])
                self._org_name = orgs[0].get("name", "Unknown")
                logger.info("Discovered org: %s (%s)", self._org_name, self._org_id)
                if len(orgs) > 1:
                    names = [o.get("name") for o in orgs]
                    logger.info("Multiple orgs available: %s (using first)", names)
        except Exception as e:
            logger.error("Org discovery failed: %s", e)
            raise

    def _load_org_name(self) -> None:
        """Load org name for a known org ID."""
        try:
            resp = self._api_get(f"/organizations/{self._org_id}")
            self._org_name = resp.get("name", "Unknown")
        except Exception as e:
            logger.warning("Could not load org name: %s", e)
            self._org_name = f"org-{self._org_id}"

    def _cache_networks(self) -> None:
        """Cache the list of networks in the org."""
        try:
            networks = self._api_get(f"/organizations/{self._org_id}/networks")
            for net in networks:
                self._networks[net["id"]] = {
                    "name": net.get("name", ""),
                    "type": net.get("productTypes", []),
                    "tags": net.get("tags", []),
                    "timezone": net.get("timeZone", ""),
                }
            logger.info("Cached %d networks", len(self._networks))
        except Exception as e:
            logger.warning("Network cache failed: %s", e)

    def _api_get(self, path: str, params: Dict = None) -> Any:
        """Make a rate-limited GET request to the Meraki API."""
        # Rate limiting
        elapsed = time.time() - self._last_request_time
        if elapsed < RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY - elapsed)
        self._last_request_time = time.time()

        resp = self._http.get(path, params=params or {})

        if resp.status_code == 429:
            retry_after = int(resp.headers.get("Retry-After", "5"))
            logger.warning("Rate limited, waiting %ds", retry_after)
            time.sleep(retry_after)
            resp = self._http.get(path, params=params or {})

        resp.raise_for_status()
        return resp.json()

    def _api_get_paginated(self, path: str, params: Dict = None, max_pages: int = 5) -> List:
        """Make paginated GET requests, following Link headers."""
        all_results = []
        params = params or {}
        url = path

        for _ in range(max_pages):
            elapsed = time.time() - self._last_request_time
            if elapsed < RATE_LIMIT_DELAY:
                time.sleep(RATE_LIMIT_DELAY - elapsed)
            self._last_request_time = time.time()

            resp = self._http.get(url, params=params)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", "5"))
                time.sleep(retry_after)
                resp = self._http.get(url, params=params)

            resp.raise_for_status()
            data = resp.json()
            if isinstance(data, list):
                all_results.extend(data)
            else:
                all_results.append(data)

            # Check for next page
            link_header = resp.headers.get("Link", "")
            next_match = re.search(r'<([^>]+)>;\s*rel=next', link_header)
            if next_match:
                url = next_match.group(1)
                params = {}  # URL already contains params
            else:
                break

        return all_results

    # ── Queue Setup ──────────────────────────────────────────────

    def setup_queues(self) -> None:
        self.inbox = self.rmq.declare_queue(
            "connector-meraki.inbox",
            routing_keys=[
                "meraki.query.networks",
                "meraki.query.devices",
                "meraki.query.clients",
                "meraki.query.client_search",
                "meraki.query.vlans",
                "meraki.query.dhcp",
                "meraki.query.device_status",
                "meraki.query.uplinks",
                "meraki.query.summary",
            ],
        )
        self.rmq.consume(self.inbox, self.handle_message)

    def handle_message(self, envelope: MessageEnvelope) -> Optional[MessageEnvelope]:
        msg_type = envelope.message_type
        handlers = {
            "meraki.query.networks": self._handle_networks,
            "meraki.query.devices": self._handle_devices,
            "meraki.query.clients": self._handle_clients,
            "meraki.query.client_search": self._handle_client_search,
            "meraki.query.vlans": self._handle_vlans,
            "meraki.query.dhcp": self._handle_dhcp,
            "meraki.query.device_status": self._handle_device_status,
            "meraki.query.uplinks": self._handle_uplinks,
            "meraki.query.summary": self._handle_summary,
        }

        handler = handlers.get(msg_type)
        if not handler:
            logger.warning("Unknown message type: %s", msg_type)
            return envelope.create_reply(
                source=self.service_name,
                message_type="meraki.response.error",
                payload={"error": f"Unknown type: {msg_type}"},
            )

        try:
            result = handler(envelope.payload, envelope)

            self.audit.log_from_envelope(
                envelope=envelope,
                event_type=EventType.DATA_ACCESS,
                action=msg_type,
                resource="meraki",
                details={
                    "status": result.get("status", "unknown"),
                    "count": result.get("count", 0),
                },
            )

            return envelope.create_reply(
                source=self.service_name,
                message_type=f"meraki.response.{msg_type.split('.')[-1]}",
                payload=result,
            )

        except Exception as e:
            logger.error("Meraki handler error: %s", e, exc_info=True)
            return envelope.create_reply(
                source=self.service_name,
                message_type="meraki.response.error",
                payload={"error": str(e)},
            )

    # ── Query Handlers ───────────────────────────────────────────

    def _handle_networks(
        self, payload: Dict, envelope: MessageEnvelope
    ) -> Dict:
        """List all networks in the org."""
        networks = self._api_get(f"/organizations/{self._org_id}/networks")

        formatted = []
        for net in networks:
            formatted.append({
                "id": net["id"],
                "name": net.get("name", ""),
                "type": ", ".join(net.get("productTypes", [])),
                "tags": net.get("tags", []),
                "timezone": net.get("timeZone", ""),
            })

        return {
            "status": "ok",
            "org": self._org_name,
            "count": len(formatted),
            "networks": formatted,
        }

    def _handle_devices(
        self, payload: Dict, envelope: MessageEnvelope
    ) -> Dict:
        """List devices — optionally filtered by network name or type."""
        text = payload.get("text", "").lower()
        network_filter = payload.get("network", "")
        product_type = payload.get("product_type", "")  # switch, wireless, appliance

        # Determine which networks to query
        target_networks = self._resolve_networks(text, network_filter)

        all_devices = []
        for net_id, net_info in target_networks.items():
            try:
                devices = self._api_get(f"/networks/{net_id}/devices")
                for dev in devices:
                    if product_type and dev.get("productType") != product_type:
                        continue
                    all_devices.append(self._format_device(dev, net_info["name"]))
            except Exception as e:
                logger.warning("Error fetching devices for %s: %s", net_info["name"], e)

        return {
            "status": "ok",
            "count": len(all_devices),
            "devices": all_devices[:50],  # Cap at 50
        }

    def _handle_clients(
        self, payload: Dict, envelope: MessageEnvelope
    ) -> Dict:
        """
        List network clients — connected endpoints.
        
        Optionally filter by network name, timespan, or per-page.
        """
        text = payload.get("text", "").lower()
        network_filter = payload.get("network", "")
        timespan = int(payload.get("timespan", 86400))  # Default: 24h

        target_networks = self._resolve_networks(text, network_filter)

        all_clients = []
        for net_id, net_info in target_networks.items():
            try:
                clients = self._api_get(
                    f"/networks/{net_id}/clients",
                    params={"timespan": timespan, "perPage": 100},
                )
                for client in clients:
                    all_clients.append(self._format_client(client, net_info["name"]))
            except Exception as e:
                logger.warning("Error fetching clients for %s: %s", net_info["name"], e)

        # Sort by last seen (most recent first)
        all_clients.sort(key=lambda c: c.get("last_seen", ""), reverse=True)

        return {
            "status": "ok",
            "count": len(all_clients),
            "clients": all_clients[:100],  # Cap at 100
        }

    def _handle_client_search(
        self, payload: Dict, envelope: MessageEnvelope
    ) -> Dict:
        """
        Search for a specific client by IP, MAC, or hostname.
        Searches across all networks.
        """
        text = payload.get("text", "")
        search_term = payload.get("search", "")

        # Extract search term from natural language
        if not search_term:
            # Try to find IP address
            ip_match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text)
            if ip_match:
                search_term = ip_match.group()
            else:
                # Try MAC address
                mac_match = re.search(r'([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}', text)
                if mac_match:
                    search_term = mac_match.group()
                else:
                    # Use raw text as hostname search
                    # Extract likely hostname (uppercase with hyphens)
                    host_match = re.search(r'([A-Z][A-Za-z0-9_-]{2,})', text)
                    if host_match:
                        search_term = host_match.group(1)

        if not search_term:
            return {"status": "error", "error": "No search term found. Provide an IP, MAC, or hostname."}

        logger.info("Searching Meraki clients for: %s", search_term)

        results = []
        search_lower = search_term.lower()

        for net_id, net_info in self._networks.items():
            try:
                clients = self._api_get(
                    f"/networks/{net_id}/clients",
                    params={"timespan": 86400, "perPage": 200},
                )
                for client in clients:
                    # Match on IP, MAC, description, or DHCP hostname
                    if (search_lower in (client.get("ip") or "").lower()
                            or search_lower in (client.get("mac") or "").lower()
                            or search_lower in (client.get("description") or "").lower()
                            or search_lower in (client.get("dhcpHostname") or "").lower()
                            or search_lower in (client.get("user") or "").lower()):
                        results.append(self._format_client(client, net_info["name"]))
            except Exception as e:
                logger.debug("Client search skip network %s: %s", net_info["name"], e)

        return {
            "status": "ok",
            "search": search_term,
            "count": len(results),
            "clients": results[:25],
        }

    def _handle_vlans(
        self, payload: Dict, envelope: MessageEnvelope
    ) -> Dict:
        """List VLANs across networks."""
        text = payload.get("text", "").lower()
        network_filter = payload.get("network", "")
        target_networks = self._resolve_networks(text, network_filter)

        all_vlans = []
        for net_id, net_info in target_networks.items():
            try:
                vlans = self._api_get(f"/networks/{net_id}/appliance/vlans")
                for vlan in vlans:
                    all_vlans.append({
                        "network": net_info["name"],
                        "id": vlan.get("id"),
                        "name": vlan.get("name", ""),
                        "subnet": vlan.get("subnet", ""),
                        "gateway": vlan.get("applianceIp", ""),
                        "dhcp_handling": vlan.get("dhcpHandling", ""),
                        "dns": vlan.get("dnsNameservers", ""),
                    })
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 400:
                    # VLANs not enabled on this network
                    pass
                else:
                    logger.warning("VLAN error for %s: %s", net_info["name"], e)
            except Exception as e:
                logger.warning("VLAN error for %s: %s", net_info["name"], e)

        return {
            "status": "ok",
            "count": len(all_vlans),
            "vlans": all_vlans,
        }

    def _handle_dhcp(
        self, payload: Dict, envelope: MessageEnvelope
    ) -> Dict:
        """List DHCP subnets and fixed IP assignments."""
        text = payload.get("text", "").lower()
        network_filter = payload.get("network", "")
        target_networks = self._resolve_networks(text, network_filter)

        all_dhcp = []
        for net_id, net_info in target_networks.items():
            try:
                vlans = self._api_get(f"/networks/{net_id}/appliance/vlans")
                for vlan in vlans:
                    dhcp_entry = {
                        "network": net_info["name"],
                        "vlan_id": vlan.get("id"),
                        "vlan_name": vlan.get("name", ""),
                        "subnet": vlan.get("subnet", ""),
                        "dhcp_handling": vlan.get("dhcpHandling", ""),
                        "dhcp_lease_time": vlan.get("dhcpLeaseTime", ""),
                        "dns": vlan.get("dnsNameservers", ""),
                        "reserved_ranges": vlan.get("reservedIpRanges", []),
                        "fixed_assignments": vlan.get("fixedIpAssignments", {}),
                    }
                    all_dhcp.append(dhcp_entry)
            except httpx.HTTPStatusError as e:
                if e.response.status_code != 400:
                    logger.warning("DHCP error for %s: %s", net_info["name"], e)
            except Exception as e:
                logger.warning("DHCP error for %s: %s", net_info["name"], e)

        return {
            "status": "ok",
            "count": len(all_dhcp),
            "dhcp_subnets": all_dhcp,
        }

    def _handle_device_status(
        self, payload: Dict, envelope: MessageEnvelope
    ) -> Dict:
        """Get device statuses (online/offline/alerting)."""
        statuses = self._api_get(
            f"/organizations/{self._org_id}/devices/statuses",
            params={"perPage": 200},
        )

        formatted = []
        for dev in statuses:
            net_name = self._networks.get(dev.get("networkId"), {}).get("name", "Unknown")
            formatted.append({
                "name": dev.get("name", ""),
                "serial": dev.get("serial", ""),
                "model": dev.get("model", ""),
                "mac": dev.get("mac", ""),
                "status": dev.get("status", ""),
                "lan_ip": dev.get("lanIp", ""),
                "public_ip": dev.get("publicIp", ""),
                "network": net_name,
                "last_reported": dev.get("lastReportedAt", ""),
                "product_type": dev.get("productType", ""),
            })

        # Count by status
        online = sum(1 for d in formatted if d["status"] == "online")
        offline = sum(1 for d in formatted if d["status"] == "offline")
        alerting = sum(1 for d in formatted if d["status"] == "alerting")

        return {
            "status": "ok",
            "count": len(formatted),
            "summary": {
                "online": online,
                "offline": offline,
                "alerting": alerting,
            },
            "devices": formatted,
        }

    def _handle_uplinks(
        self, payload: Dict, envelope: MessageEnvelope
    ) -> Dict:
        """Get uplink status for all appliances (WAN connections)."""
        try:
            uplinks = self._api_get(
                f"/organizations/{self._org_id}/appliance/uplink/statuses"
            )
        except Exception:
            # Fallback to device uplinks
            uplinks = self._api_get(
                f"/organizations/{self._org_id}/devices/uplinksLossAndLatency"
            )

        formatted = []
        for entry in uplinks:
            net_name = self._networks.get(entry.get("networkId"), {}).get("name", "Unknown")
            for uplink in entry.get("uplinks", []):
                formatted.append({
                    "network": net_name,
                    "serial": entry.get("serial", ""),
                    "model": entry.get("model", ""),
                    "interface": uplink.get("interface", ""),
                    "status": uplink.get("status", ""),
                    "ip": uplink.get("ip", ""),
                    "gateway": uplink.get("gateway", ""),
                    "public_ip": uplink.get("publicIp", ""),
                    "dns": uplink.get("dns", ""),
                    "provider": uplink.get("provider", ""),
                })

        return {
            "status": "ok",
            "count": len(formatted),
            "uplinks": formatted,
        }

    def _handle_summary(
        self, payload: Dict, envelope: MessageEnvelope
    ) -> Dict:
        """High-level summary: org, networks, device counts, status."""
        # Device statuses
        statuses = self._api_get(
            f"/organizations/{self._org_id}/devices/statuses",
            params={"perPage": 200},
        )

        by_type = {}
        by_status = {"online": 0, "offline": 0, "alerting": 0, "dormant": 0}
        for dev in statuses:
            ptype = dev.get("productType", "unknown")
            by_type[ptype] = by_type.get(ptype, 0) + 1
            status = dev.get("status", "unknown")
            if status in by_status:
                by_status[status] += 1

        return {
            "status": "ok",
            "organization": self._org_name,
            "org_id": self._org_id,
            "network_count": len(self._networks),
            "networks": [
                {"name": n["name"], "type": ", ".join(n["type"])}
                for n in self._networks.values()
            ],
            "device_count": len(statuses),
            "devices_by_type": by_type,
            "devices_by_status": by_status,
        }

    # ── Helpers ──────────────────────────────────────────────────

    def _resolve_networks(
        self, text: str, network_filter: str
    ) -> Dict[str, Dict]:
        """Resolve which networks to query based on text or filter."""
        if network_filter:
            # Exact match
            for nid, ninfo in self._networks.items():
                if network_filter.lower() in ninfo["name"].lower():
                    return {nid: ninfo}

        if text:
            # Try to find a network name in the text
            for nid, ninfo in self._networks.items():
                if ninfo["name"].lower() in text:
                    return {nid: ninfo}

        # Default: all networks
        return self._networks

    def _format_device(self, dev: Dict, network_name: str) -> Dict:
        """Format a device record."""
        return {
            "name": dev.get("name", ""),
            "serial": dev.get("serial", ""),
            "model": dev.get("model", ""),
            "mac": dev.get("mac", ""),
            "lan_ip": dev.get("lanIp", ""),
            "network": network_name,
            "firmware": dev.get("firmware", ""),
            "product_type": dev.get("productType", ""),
            "tags": dev.get("tags", []),
            "address": dev.get("address", ""),
        }

    def _format_client(self, client: Dict, network_name: str) -> Dict:
        """Format a client record."""
        return {
            "id": client.get("id", ""),
            "description": client.get("description", ""),
            "hostname": client.get("dhcpHostname", ""),
            "mac": client.get("mac", ""),
            "ip": client.get("ip", ""),
            "ip6": client.get("ip6", ""),
            "vlan": client.get("vlan", ""),
            "vlan_name": client.get("namedVlan", ""),
            "switchport": client.get("switchport", ""),
            "ssid": client.get("ssid", ""),
            "status": client.get("status", ""),
            "manufacturer": client.get("manufacturer", ""),
            "os": client.get("os", ""),
            "user": client.get("user", ""),
            "network": network_name,
            "first_seen": client.get("firstSeen", ""),
            "last_seen": client.get("lastSeen", ""),
            "connection": client.get("recentDeviceConnection", ""),
            "usage_sent": client.get("usage", {}).get("sent", 0),
            "usage_recv": client.get("usage", {}).get("recv", 0),
        }


if __name__ == "__main__":
    import os
    svc = os.environ.get("NEURO_SERVICE_NAME", "connector-meraki")
    if svc.startswith("connector-"):
        svc = svc[len("connector-"):]
    service = MerakiConnector.create(svc)
    service.run()
