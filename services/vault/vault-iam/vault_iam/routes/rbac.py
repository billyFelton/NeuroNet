"""
RBAC permission check endpoints.

Evaluates whether a user is authorized to perform an action on a resource
based on their roles and the policy table.
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from vault_iam.routes.auth import TokenPayload, verify_service_token
from vault_iam.routes.identity import _get_user_roles

logger = logging.getLogger("vault-iam.rbac")

router = APIRouter()


class PermissionCheckRequest(BaseModel):
    user_id: str
    action: str
    resource: str
    resource_id: Optional[str] = None
    context: dict = {}


class PermissionCheckResponse(BaseModel):
    permitted: bool
    policy_matched: Optional[str] = None
    scopes_granted: list[str] = []
    denied_reason: Optional[str] = None


@router.post("/check", response_model=PermissionCheckResponse)
async def check_permission(
    body: PermissionCheckRequest,
    request: Request,
    auth: TokenPayload = Depends(verify_service_token),
):
    """
    Check if a user is authorized for an action on a resource.

    Evaluation logic:
    1. Get all roles for the user (direct + group-mapped)
    2. Find matching policies (role + resource + action)
    3. Explicit deny wins over permit
    4. Wildcard action (*) matches any action
    5. If no policy matches, deny (fail closed)
    """
    db = request.app.state.db

    # Get user's effective roles
    roles = await _get_user_roles(db, body.user_id)

    if not roles:
        return PermissionCheckResponse(
            permitted=False,
            denied_reason="User has no assigned roles",
        )

    # Find all matching policies for this user's roles and the requested resource
    policies = await db.fetch_all(
        """
        SELECT
            p.id,
            p.role_id,
            p.resource_id,
            p.action,
            p.effect,
            p.scopes,
            p.conditions,
            p.description
        FROM iam.policies p
        WHERE p.role_id = ANY(%s)
          AND p.resource_id = %s
          AND (p.action = %s OR p.action = '*')
        ORDER BY
            -- Explicit deny takes priority
            CASE WHEN p.effect = 'deny' THEN 0 ELSE 1 END,
            -- Exact action match takes priority over wildcard
            CASE WHEN p.action = %s THEN 0 ELSE 1 END
        """,
        [roles, body.resource, body.action, body.action],
    )

    if not policies:
        return PermissionCheckResponse(
            permitted=False,
            denied_reason=f"No policy grants '{body.action}' on '{body.resource}' "
                         f"for roles: {', '.join(roles)}",
        )

    # Check for explicit deny first
    for policy in policies:
        if policy["effect"] == "deny":
            return PermissionCheckResponse(
                permitted=False,
                policy_matched=policy["description"] or f"policy:{policy['id']}",
                denied_reason=f"Explicitly denied by policy for role '{policy['role_id']}'",
            )

    # Evaluate conditions on the first matching permit policy
    for policy in policies:
        if policy["effect"] == "permit":
            # Check conditions if any
            conditions = policy.get("conditions") or {}
            if conditions:
                condition_met = await _evaluate_conditions(conditions, body, request)
                if not condition_met:
                    continue

            scopes = policy.get("scopes") or []

            # Handle self-only access for general users
            if "self-only" in scopes and body.resource_id:
                if body.resource_id != body.user_id:
                    return PermissionCheckResponse(
                        permitted=False,
                        policy_matched=policy["description"] or f"policy:{policy['id']}",
                        denied_reason="Policy restricts access to own resources only",
                        scopes_granted=scopes,
                    )

            return PermissionCheckResponse(
                permitted=True,
                policy_matched=policy["description"] or f"policy:{policy['id']}",
                scopes_granted=scopes,
            )

    return PermissionCheckResponse(
        permitted=False,
        denied_reason="All matching policies failed condition evaluation",
    )


async def _evaluate_conditions(
    conditions: Dict[str, Any],
    body: PermissionCheckRequest,
    request: Request,
) -> bool:
    """
    Evaluate optional policy conditions.

    Supported conditions:
    - time_window: {"start": "HH:MM", "end": "HH:MM"} — restrict to business hours
    - ip_ranges: ["10.0.0.0/8"] — restrict by source IP
    - require_mfa: true — require MFA-enabled account

    Returns True if all conditions are met.
    """
    from datetime import datetime, timezone

    # Time window check
    if "time_window" in conditions:
        now = datetime.now(timezone.utc)
        window = conditions["time_window"]
        start_hour, start_min = map(int, window["start"].split(":"))
        end_hour, end_min = map(int, window["end"].split(":"))
        current_minutes = now.hour * 60 + now.minute
        start_minutes = start_hour * 60 + start_min
        end_minutes = end_hour * 60 + end_min
        if not (start_minutes <= current_minutes <= end_minutes):
            return False

    # MFA requirement check
    if conditions.get("require_mfa"):
        db = request.app.state.db
        user = await db.fetch_one(
            "SELECT mfa_enabled FROM iam.users WHERE id = %s",
            [body.user_id],
        )
        if not user or not user.get("mfa_enabled"):
            return False

    return True
