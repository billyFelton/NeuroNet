"""Health check endpoints."""

from fastapi import APIRouter, Request

router = APIRouter()


@router.get("/health")
async def health_check(request: Request):
    """Basic health check for container orchestration."""
    db_ok = False
    try:
        result = await request.app.state.db.fetch_one("SELECT 1 AS ok")
        db_ok = result is not None
    except Exception:
        pass

    entra_sync = request.app.state.entra_sync
    status = "healthy" if db_ok else "degraded"

    return {
        "status": status,
        "service": "vault-iam",
        "checks": {
            "database": "ok" if db_ok else "error",
            "entra_sync": (
                "running" if entra_sync and entra_sync.is_running
                else "disabled"
            ),
        },
    }
