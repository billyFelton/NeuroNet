"""
Identity resolution endpoints.

Maps external identities (Slack user ID, email, Teams ID) to the
canonical Neuro-Network identity backed by EntraID.
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from vault_iam.routes.auth import TokenPayload, verify_service_token

logger = logging.getLogger("vault-iam.identity")

router = APIRouter()


class IdentityResponse(BaseModel):
    """Canonical identity returned to callers."""
    user_id: Optional[str] = None
    email: Optional[str] = None
    display_name: Optional[str] = None
    upn: Optional[str] = None
    job_title: Optional[str] = None
    department: Optional[str] = None
    account_enabled: bool = True
    mfa_enabled: bool = False
    roles: list[str] = []
    groups: list[str] = []


class UserRolesResponse(BaseModel):
    roles: list[str]


class UserGroupsResponse(BaseModel):
    groups: list[str]


@router.get("/resolve")
async def resolve_identity(
    request: Request,
    provider: str = Query(..., description="Identity source: slack, email, teams, entra"),
    external_id: str = Query(..., description="Provider-specific user ID or email"),
    auth: TokenPayload = Depends(verify_service_token),
):
    """
    Resolve an external identity to the canonical Neuro-Network identity.

    This is the primary endpoint called by connectors when a message arrives.
    It maps Slack user IDs, email addresses, etc. to the EntraID-backed user
    with their roles and group memberships.
    """
    db = request.app.state.db

    # If provider is "email", look up directly by email
    if provider == "email":
        user = await _get_user_by_email(db, external_id)
    else:
        # Look up the identity mapping
        mapping = await db.fetch_one(
            """
            SELECT user_id, verified
            FROM iam.identity_mappings
            WHERE provider = %s AND external_id = %s
            """,
            [provider, external_id],
        )

        if not mapping:
            # Attempt email-based auto-resolution for Slack
            # (if we can look up the email from the external_id pattern)
            raise HTTPException(
                status_code=404,
                detail=f"No identity mapping for {provider}:{external_id}. "
                       f"Create a mapping in iam.identity_mappings.",
            )

        user = await _get_user_by_id(db, str(mapping["user_id"]))

    if not user:
        raise HTTPException(status_code=404, detail="Mapped user not found in directory")

    # Fetch roles and groups
    roles = await _get_user_roles(db, str(user["id"]))
    groups = await _get_user_groups(db, str(user["id"]))

    return {
        "identity": {
            "user_id": str(user["id"]),
            "email": user["email"],
            "display_name": user["display_name"],
            "upn": user.get("upn"),
            "job_title": user.get("job_title"),
            "department": user.get("department"),
            "account_enabled": user["account_enabled"],
            "mfa_enabled": user.get("mfa_enabled", False),
            "roles": roles,
            "groups": groups,
        }
    }


@router.get("/{user_id}")
async def get_user(
    user_id: str,
    request: Request,
    auth: TokenPayload = Depends(verify_service_token),
):
    """Get full user profile by canonical user ID (EntraID object ID)."""
    db = request.app.state.db
    user = await _get_user_by_id(db, user_id)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    roles = await _get_user_roles(db, user_id)
    groups = await _get_user_groups(db, user_id)

    return {
        "user_id": str(user["id"]),
        "email": user["email"],
        "display_name": user["display_name"],
        "upn": user.get("upn"),
        "job_title": user.get("job_title"),
        "department": user.get("department"),
        "account_enabled": user["account_enabled"],
        "mfa_enabled": user.get("mfa_enabled", False),
        "roles": roles,
        "groups": groups,
    }


@router.get("/{user_id}/roles", response_model=UserRolesResponse)
async def get_user_roles(
    user_id: str,
    request: Request,
    auth: TokenPayload = Depends(verify_service_token),
):
    """Get all roles assigned to a user (direct + group-mapped)."""
    db = request.app.state.db
    roles = await _get_user_roles(db, user_id)
    return {"roles": roles}


@router.get("/{user_id}/groups", response_model=UserGroupsResponse)
async def get_user_groups(
    user_id: str,
    request: Request,
    auth: TokenPayload = Depends(verify_service_token),
):
    """Get all groups a user belongs to."""
    db = request.app.state.db
    groups = await _get_user_groups(db, user_id)
    return {"groups": groups}


# ── Database Helpers ────────────────────────────────────────────────

async def _get_user_by_id(db, user_id: str) -> Optional[Dict[str, Any]]:
    return await db.fetch_one(
        "SELECT * FROM iam.users WHERE id = %s",
        [user_id],
    )


async def _get_user_by_email(db, email: str) -> Optional[Dict[str, Any]]:
    return await db.fetch_one(
        "SELECT * FROM iam.users WHERE LOWER(email) = LOWER(%s)",
        [email],
    )


async def _get_user_roles(db, user_id: str) -> List[str]:
    """Get roles from direct assignment + group-based mapping."""
    rows = await db.fetch_all(
        """
        SELECT DISTINCT r.id AS role_id
        FROM iam.roles r
        WHERE r.id IN (
            -- Direct role assignments
            SELECT role_id FROM iam.user_roles WHERE user_id = %s
            UNION
            -- Roles mapped from EntraID group membership
            SELECT grm.role_id
            FROM iam.group_role_mappings grm
            JOIN iam.user_groups ug ON ug.group_id = grm.group_id
            WHERE ug.user_id = %s
        )
        """,
        [user_id, user_id],
    )
    return [row["role_id"] for row in rows]


async def _get_user_groups(db, user_id: str) -> List[str]:
    rows = await db.fetch_all(
        """
        SELECT g.display_name
        FROM iam.groups g
        JOIN iam.user_groups ug ON ug.group_id = g.id
        WHERE ug.user_id = %s
        """,
        [user_id],
    )
    return [row["display_name"] for row in rows]
