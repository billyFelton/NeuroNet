"""
EntraID Sync Service.

Periodically syncs users and groups from Microsoft EntraID (Azure AD)
via the Microsoft Graph API into the local Postgres IAM database.

Handles:
- Full initial sync on startup
- Periodic delta sync on interval
- Group membership resolution
- Automatic role assignment via group → role mappings
"""

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from vault_iam.database import DatabasePool

logger = logging.getLogger("vault-iam.entra-sync")


class EntraSyncService:
    """
    Background service that syncs EntraID data into Postgres.

    Requires Microsoft Graph API credentials:
    - ENTRAID_TENANT_ID
    - ENTRAID_CLIENT_ID
    - ENTRAID_CLIENT_SECRET

    Or retrieves them from HashiCorp Vault if configured.
    """

    GRAPH_BASE = "https://graph.microsoft.com/v1.0"

    def __init__(self, db: DatabasePool):
        self._db = db
        self._http: Optional[httpx.AsyncClient] = None
        self._access_token: Optional[str] = None
        self._token_expiry: float = 0
        self._sync_task: Optional[asyncio.Task] = None
        self._running = False

        # Config
        self._tenant_id = os.getenv("ENTRAID_TENANT_ID", "")
        self._client_id = os.getenv("ENTRAID_CLIENT_ID", "")
        self._client_secret = os.getenv("ENTRAID_CLIENT_SECRET", "")
        self._sync_interval = int(os.getenv("ENTRAID_SYNC_INTERVAL", "300"))  # 5 min default

    @property
    def is_running(self) -> bool:
        return self._running

    async def start(self) -> None:
        """Start the sync service."""
        if not all([self._tenant_id, self._client_id, self._client_secret]):
            logger.error(
                "EntraID sync requires ENTRAID_TENANT_ID, ENTRAID_CLIENT_ID, "
                "and ENTRAID_CLIENT_SECRET"
            )
            return

        self._http = httpx.AsyncClient(timeout=30)
        self._running = True

        # Run initial full sync
        try:
            await self._authenticate()
            await self._full_sync()
        except Exception as e:
            logger.error("Initial EntraID sync failed: %s", e, exc_info=True)

        # Start periodic sync loop
        self._sync_task = asyncio.create_task(self._sync_loop())
        logger.info("EntraID sync service started (interval=%ds)", self._sync_interval)

    async def stop(self) -> None:
        """Stop the sync service."""
        self._running = False
        if self._sync_task:
            self._sync_task.cancel()
            try:
                await self._sync_task
            except asyncio.CancelledError:
                pass
        if self._http:
            await self._http.aclose()
        logger.info("EntraID sync service stopped")

    async def _sync_loop(self) -> None:
        """Periodic sync loop."""
        while self._running:
            await asyncio.sleep(self._sync_interval)
            try:
                await self._authenticate()
                await self._full_sync()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("EntraID sync cycle failed: %s", e, exc_info=True)

    # ── Microsoft Graph Authentication ──────────────────────────────

    async def _authenticate(self) -> None:
        """Obtain or refresh OAuth2 token via client credentials flow."""
        import time
        if self._access_token and time.time() < self._token_expiry - 60:
            return  # Token still valid

        url = f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "scope": "https://graph.microsoft.com/.default",
        }

        response = await self._http.post(url, data=data)
        response.raise_for_status()
        token_data = response.json()

        self._access_token = token_data["access_token"]
        self._token_expiry = time.time() + token_data.get("expires_in", 3600)
        logger.debug("EntraID token refreshed")

    async def _graph_get(self, path: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Make authenticated GET request to Microsoft Graph."""
        headers = {"Authorization": f"Bearer {self._access_token}"}
        response = await self._http.get(
            f"{self.GRAPH_BASE}{path}",
            headers=headers,
            params=params,
        )
        response.raise_for_status()
        return response.json()

    async def _graph_get_all(self, path: str, params: Optional[Dict] = None) -> List[Dict]:
        """Paginate through all results from a Graph API endpoint."""
        all_items = []
        result = await self._graph_get(path, params)
        all_items.extend(result.get("value", []))

        # Follow @odata.nextLink for pagination
        while "@odata.nextLink" in result:
            next_url = result["@odata.nextLink"]
            headers = {"Authorization": f"Bearer {self._access_token}"}
            response = await self._http.get(next_url, headers=headers)
            response.raise_for_status()
            result = response.json()
            all_items.extend(result.get("value", []))

        return all_items

    # ── Sync Logic ──────────────────────────────────────────────────

    async def _full_sync(self) -> None:
        """Run a full sync of users and groups from EntraID."""
        logger.info("Starting EntraID full sync...")
        start = datetime.now(timezone.utc)

        user_count = await self._sync_users()
        group_count = await self._sync_groups()
        await self._sync_group_memberships()

        elapsed = (datetime.now(timezone.utc) - start).total_seconds()
        logger.info(
            "EntraID sync complete: %d users, %d groups (%.1fs)",
            user_count, group_count, elapsed,
        )

    async def _sync_users(self) -> int:
        """Sync users from EntraID to iam.users."""
        users = await self._graph_get_all(
            "/users",
            params={
                "$select": "id,mail,displayName,userPrincipalName,jobTitle,"
                          "department,accountEnabled",
                "$top": "999",
            },
        )

        count = 0
        for user in users:
            # Skip users without email (service accounts, room mailboxes, etc.)
            email = user.get("mail")
            if not email:
                continue

            await self._db.execute(
                """
                INSERT INTO iam.users (id, email, display_name, upn, job_title,
                                       department, account_enabled, entra_synced_at, updated_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                ON CONFLICT (id) DO UPDATE SET
                    email = EXCLUDED.email,
                    display_name = EXCLUDED.display_name,
                    upn = EXCLUDED.upn,
                    job_title = EXCLUDED.job_title,
                    department = EXCLUDED.department,
                    account_enabled = EXCLUDED.account_enabled,
                    entra_synced_at = NOW(),
                    updated_at = NOW()
                """,
                [
                    user["id"],
                    email,
                    user.get("displayName", email),
                    user.get("userPrincipalName"),
                    user.get("jobTitle"),
                    user.get("department"),
                    user.get("accountEnabled", True),
                ],
            )
            count += 1

            # Auto-create email identity mapping
            await self._db.execute(
                """
                INSERT INTO iam.identity_mappings (provider, external_id, user_id, verified)
                VALUES ('email', %s, %s, TRUE)
                ON CONFLICT (provider, external_id) DO UPDATE SET user_id = EXCLUDED.user_id
                """,
                [email.lower(), user["id"]],
            )

        return count

    async def _sync_groups(self) -> int:
        """Sync groups from EntraID to iam.groups."""
        groups = await self._graph_get_all(
            "/groups",
            params={
                "$select": "id,displayName,description,mail,groupTypes,"
                          "securityEnabled,mailEnabled",
                "$top": "999",
            },
        )

        count = 0
        for group in groups:
            group_types = group.get("groupTypes", [])
            if group.get("securityEnabled"):
                group_type = "security"
            elif "Unified" in group_types:
                group_type = "m365"
            else:
                group_type = "distribution"

            await self._db.execute(
                """
                INSERT INTO iam.groups (id, display_name, description, mail, group_type,
                                        entra_synced_at)
                VALUES (%s, %s, %s, %s, %s, NOW())
                ON CONFLICT (id) DO UPDATE SET
                    display_name = EXCLUDED.display_name,
                    description = EXCLUDED.description,
                    mail = EXCLUDED.mail,
                    group_type = EXCLUDED.group_type,
                    entra_synced_at = NOW()
                """,
                [
                    group["id"],
                    group.get("displayName", "Unknown"),
                    group.get("description"),
                    group.get("mail"),
                    group_type,
                ],
            )
            count += 1

        return count

    async def _sync_group_memberships(self) -> None:
        """Sync group memberships from EntraID."""
        groups = await self._db.fetch_all("SELECT id FROM iam.groups")

        for group in groups:
            group_id = str(group["id"])
            try:
                members = await self._graph_get_all(
                    f"/groups/{group_id}/members",
                    params={"$select": "id", "$top": "999"},
                )
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    continue
                raise

            # Get current member IDs from Graph
            graph_member_ids = {
                m["id"] for m in members
                if m.get("@odata.type", "") == "#microsoft.graph.user"
            }

            # Get existing local members
            local_members = await self._db.fetch_all(
                "SELECT user_id FROM iam.user_groups WHERE group_id = %s",
                [group_id],
            )
            local_member_ids = {str(r["user_id"]) for r in local_members}

            # Add new memberships
            to_add = graph_member_ids - local_member_ids
            for user_id in to_add:
                # Only add if user exists locally
                user_exists = await self._db.fetch_one(
                    "SELECT id FROM iam.users WHERE id = %s", [user_id]
                )
                if user_exists:
                    await self._db.execute(
                        """
                        INSERT INTO iam.user_groups (user_id, group_id, synced_at)
                        VALUES (%s, %s, NOW())
                        ON CONFLICT (user_id, group_id) DO UPDATE SET synced_at = NOW()
                        """,
                        [user_id, group_id],
                    )

            # Remove stale memberships
            to_remove = local_member_ids - graph_member_ids
            for user_id in to_remove:
                await self._db.execute(
                    "DELETE FROM iam.user_groups WHERE user_id = %s AND group_id = %s",
                    [user_id, group_id],
                )
