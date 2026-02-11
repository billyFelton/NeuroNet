"""
Vault-IAM — Identity, RBAC, and EntraID sync service.

Exposes REST API for:
- Identity resolution (Slack/email/Teams → EntraID canonical identity)
- RBAC permission checks
- User/group/role management
- EntraID sync status
- Service-to-service authentication
"""

import logging
import os
import sys

from contextlib import asynccontextmanager
from fastapi import FastAPI

from vault_iam.database import DatabasePool
from vault_iam.routes import auth, identity, rbac, health, admin
from vault_iam.entra_sync import EntraSyncService

logging.basicConfig(
    level=os.getenv("NEURO_LOG_LEVEL", "INFO"),
    format="%(asctime)s [vault-iam] %(levelname)s %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("vault-iam")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage startup and shutdown lifecycle."""
    # Startup
    logger.info("Vault-IAM starting...")

    # Initialize database pool
    app.state.db = DatabasePool()
    await app.state.db.initialize()
    logger.info("Database pool initialized")

    # Initialize EntraID sync service (if configured)
    entra_enabled = os.getenv("ENTRAID_SYNC_ENABLED", "false").lower() == "true"
    if entra_enabled:
        app.state.entra_sync = EntraSyncService(app.state.db)
        await app.state.entra_sync.start()
        logger.info("EntraID sync service started")
    else:
        app.state.entra_sync = None
        logger.info("EntraID sync disabled")

    logger.info("Vault-IAM ready")
    yield

    # Shutdown
    logger.info("Vault-IAM shutting down...")
    if app.state.entra_sync:
        await app.state.entra_sync.stop()
    await app.state.db.close()
    logger.info("Vault-IAM shutdown complete")


app = FastAPI(
    title="Vault-IAM",
    description="Neuro-Network Identity, Access Management, and RBAC Service",
    version="0.1.0",
    lifespan=lifespan,
)

# Mount route modules
app.include_router(health.router, tags=["health"])
app.include_router(auth.router, prefix="/api/v1/auth", tags=["authentication"])
app.include_router(identity.router, prefix="/api/v1/identity", tags=["identity"])
app.include_router(rbac.router, prefix="/api/v1/rbac", tags=["rbac"])
app.include_router(admin.router, prefix="/api/v1/admin", tags=["admin"])
