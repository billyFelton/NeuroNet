"""
Service-to-service authentication.

Each Neuro-Network container authenticates with Vault-IAM using
a pre-shared service token. This validates the token and returns
a short-lived JWT for subsequent API calls.
"""

import hashlib
import logging
import os
import time
from typing import Optional

import jwt
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel

logger = logging.getLogger("vault-iam.auth")

router = APIRouter()

# JWT config
JWT_SECRET = os.getenv("VAULT_IAM_JWT_SECRET", "change-me-in-production")
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = 3600  # 1 hour


class ServiceAuthRequest(BaseModel):
    service_name: str
    service_version: str = "0.0.0"


class ServiceAuthResponse(BaseModel):
    token: str
    expires_in: int
    service_name: str


class TokenPayload(BaseModel):
    """Decoded JWT payload."""
    sub: str           # service_name
    iss: str           # "vault-iam"
    iat: int
    exp: int
    allowed_actions: list[str]


def _hash_token(token: str) -> str:
    """SHA256 hash of a service token for DB comparison."""
    return hashlib.sha256(token.encode()).hexdigest()


@router.post("/service", response_model=ServiceAuthResponse)
async def authenticate_service(body: ServiceAuthRequest, request: Request):
    """
    Authenticate a service and return a JWT.

    The service provides its name, and its pre-shared token is
    passed in the Authorization header. We validate against the
    iam.service_accounts table.
    """
    # For initial bootstrap, check env var for a master service token
    master_token = os.getenv("VAULT_IAM_MASTER_SERVICE_TOKEN")
    auth_header = request.headers.get("Authorization", "")
    provided_token = auth_header.replace("Bearer ", "").strip()

    if not provided_token:
        raise HTTPException(status_code=401, detail="No authorization token provided")

    db = request.app.state.db

    # Check master token first (bootstrap only)
    if master_token and provided_token == master_token:
        logger.info("Service %s authenticated via master token", body.service_name)
        return _issue_jwt(body.service_name, allowed_actions=["*"])

    # Check service_accounts table
    token_hash = _hash_token(provided_token)
    row = await db.fetch_one(
        """
        SELECT service_name, allowed_actions
        FROM iam.service_accounts
        WHERE service_name = %s AND token_hash = %s
        """,
        [body.service_name, token_hash],
    )

    if not row:
        logger.warning("Auth failed for service %s", body.service_name)
        raise HTTPException(status_code=401, detail="Invalid service credentials")

    # Update last_auth timestamp
    await db.execute(
        "UPDATE iam.service_accounts SET last_auth = NOW() WHERE service_name = %s",
        [body.service_name],
    )

    logger.info("Service %s authenticated", body.service_name)
    return _issue_jwt(body.service_name, allowed_actions=row["allowed_actions"] or [])


def _issue_jwt(service_name: str, allowed_actions: list[str]) -> ServiceAuthResponse:
    """Create a signed JWT for the service."""
    now = int(time.time())
    payload = {
        "sub": service_name,
        "iss": "vault-iam",
        "iat": now,
        "exp": now + JWT_EXPIRY_SECONDS,
        "allowed_actions": allowed_actions,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return ServiceAuthResponse(
        token=token,
        expires_in=JWT_EXPIRY_SECONDS,
        service_name=service_name,
    )


async def verify_service_token(
    authorization: str = Header(..., description="Bearer <jwt>"),
) -> TokenPayload:
    """
    FastAPI dependency to verify JWT on protected endpoints.

    Usage:
        @router.get("/protected")
        async def protected_endpoint(auth: TokenPayload = Depends(verify_service_token)):
            print(auth.sub)  # service name
    """
    token = authorization.replace("Bearer ", "").strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return TokenPayload(**payload)
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")
