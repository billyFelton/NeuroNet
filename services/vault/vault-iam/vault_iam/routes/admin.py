"""
Admin endpoints for managing IAM data.

Used for:
- Creating identity mappings (Slack → EntraID)
- Assigning roles to users
- Mapping EntraID groups to Neuro-Network roles
- Managing service accounts
"""

import hashlib
import logging
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from vault_iam.routes.auth import TokenPayload, verify_service_token

logger = logging.getLogger("vault-iam.admin")

router = APIRouter()


# ── Identity Mappings ───────────────────────────────────────────────

class CreateIdentityMappingRequest(BaseModel):
    provider: str        # "slack", "teams", "email"
    external_id: str     # Slack user ID, Teams ID, etc.
    user_id: str         # EntraID object ID (UUID)
    verified: bool = False


@router.post("/identity-mappings")
async def create_identity_mapping(
    body: CreateIdentityMappingRequest,
    request: Request,
    auth: TokenPayload = Depends(verify_service_token),
):
    """Create or update an external identity → EntraID user mapping."""
    db = request.app.state.db

    # Verify the user exists
    user = await db.fetch_one(
        "SELECT id, email FROM iam.users WHERE id = %s", [body.user_id]
    )
    if not user:
        raise HTTPException(status_code=404, detail=f"User {body.user_id} not found")

    await db.execute(
        """
        INSERT INTO iam.identity_mappings (provider, external_id, user_id, verified)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (provider, external_id)
        DO UPDATE SET user_id = EXCLUDED.user_id,
                      verified = EXCLUDED.verified
        """,
        [body.provider, body.external_id, body.user_id, body.verified],
    )

    logger.info(
        "Identity mapping created: %s:%s → %s (%s)",
        body.provider, body.external_id, user["email"], body.user_id,
    )
    return {"status": "created", "provider": body.provider, "external_id": body.external_id}


@router.get("/identity-mappings")
async def list_identity_mappings(
    request: Request,
    provider: Optional[str] = None,
    auth: TokenPayload = Depends(verify_service_token),
):
    """List all identity mappings, optionally filtered by provider."""
    db = request.app.state.db

    if provider:
        rows = await db.fetch_all(
            """
            SELECT im.provider, im.external_id, im.user_id, im.verified,
                   u.email, u.display_name
            FROM iam.identity_mappings im
            JOIN iam.users u ON u.id = im.user_id
            WHERE im.provider = %s
            ORDER BY u.email
            """,
            [provider],
        )
    else:
        rows = await db.fetch_all(
            """
            SELECT im.provider, im.external_id, im.user_id, im.verified,
                   u.email, u.display_name
            FROM iam.identity_mappings im
            JOIN iam.users u ON u.id = im.user_id
            ORDER BY im.provider, u.email
            """,
        )

    return {"mappings": [{**r, "user_id": str(r["user_id"])} for r in rows]}


# ── Role Assignments ────────────────────────────────────────────────

class AssignRoleRequest(BaseModel):
    user_id: str
    role_id: str


@router.post("/roles/assign")
async def assign_role(
    body: AssignRoleRequest,
    request: Request,
    auth: TokenPayload = Depends(verify_service_token),
):
    """Assign a role directly to a user."""
    db = request.app.state.db

    # Verify role exists
    role = await db.fetch_one("SELECT id FROM iam.roles WHERE id = %s", [body.role_id])
    if not role:
        raise HTTPException(status_code=404, detail=f"Role '{body.role_id}' not found")

    # Verify user exists
    user = await db.fetch_one("SELECT id, email FROM iam.users WHERE id = %s", [body.user_id])
    if not user:
        raise HTTPException(status_code=404, detail=f"User '{body.user_id}' not found")

    await db.execute(
        """
        INSERT INTO iam.user_roles (user_id, role_id, assigned_by)
        VALUES (%s, %s, 'manual')
        ON CONFLICT (user_id, role_id) DO NOTHING
        """,
        [body.user_id, body.role_id],
    )

    logger.info("Role '%s' assigned to %s", body.role_id, user["email"])
    return {"status": "assigned", "user_id": body.user_id, "role_id": body.role_id}


@router.delete("/roles/revoke")
async def revoke_role(
    body: AssignRoleRequest,
    request: Request,
    auth: TokenPayload = Depends(verify_service_token),
):
    """Revoke a directly-assigned role from a user."""
    db = request.app.state.db

    count = await db.execute(
        "DELETE FROM iam.user_roles WHERE user_id = %s AND role_id = %s",
        [body.user_id, body.role_id],
    )

    if count == 0:
        raise HTTPException(status_code=404, detail="Role assignment not found")

    logger.info("Role '%s' revoked from %s", body.role_id, body.user_id)
    return {"status": "revoked", "user_id": body.user_id, "role_id": body.role_id}


# ── Group → Role Mappings ──────────────────────────────────────────

class GroupRoleMappingRequest(BaseModel):
    group_id: str   # EntraID group UUID
    role_id: str    # Neuro-Network role ID


@router.post("/group-role-mappings")
async def create_group_role_mapping(
    body: GroupRoleMappingRequest,
    request: Request,
    auth: TokenPayload = Depends(verify_service_token),
):
    """Map an EntraID group to a Neuro-Network role (auto-assign)."""
    db = request.app.state.db

    group = await db.fetch_one("SELECT id, display_name FROM iam.groups WHERE id = %s", [body.group_id])
    if not group:
        raise HTTPException(status_code=404, detail=f"Group '{body.group_id}' not found")

    role = await db.fetch_one("SELECT id FROM iam.roles WHERE id = %s", [body.role_id])
    if not role:
        raise HTTPException(status_code=404, detail=f"Role '{body.role_id}' not found")

    await db.execute(
        """
        INSERT INTO iam.group_role_mappings (group_id, role_id)
        VALUES (%s, %s)
        ON CONFLICT (group_id, role_id) DO NOTHING
        """,
        [body.group_id, body.role_id],
    )

    logger.info(
        "Group '%s' → role '%s' mapping created",
        group["display_name"], body.role_id,
    )
    return {
        "status": "created",
        "group": group["display_name"],
        "role": body.role_id,
    }


# ── Service Accounts ───────────────────────────────────────────────

class CreateServiceAccountRequest(BaseModel):
    service_name: str
    allowed_actions: list[str] = []


@router.post("/service-accounts")
async def create_service_account(
    body: CreateServiceAccountRequest,
    request: Request,
    auth: TokenPayload = Depends(verify_service_token),
):
    """
    Create a service account and return the generated token.

    The token is only shown once — store it securely (e.g., in HashiCorp Vault).
    """
    db = request.app.state.db

    # Generate a secure token
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    await db.execute(
        """
        INSERT INTO iam.service_accounts (service_name, token_hash, allowed_actions)
        VALUES (%s, %s, %s)
        ON CONFLICT (service_name)
        DO UPDATE SET token_hash = EXCLUDED.token_hash,
                      allowed_actions = EXCLUDED.allowed_actions
        """,
        [body.service_name, token_hash, body.allowed_actions],
    )

    logger.info("Service account created: %s", body.service_name)
    return {
        "service_name": body.service_name,
        "token": token,
        "note": "Store this token securely. It cannot be retrieved again.",
    }
