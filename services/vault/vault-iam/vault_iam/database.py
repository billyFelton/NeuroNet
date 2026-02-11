"""
Async Postgres connection pool for Vault-IAM.

Uses psycopg3 async pool for non-blocking database access.
All queries operate against the 'iam' schema.
"""

import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

logger = logging.getLogger("vault-iam.database")


class DatabasePool:
    """
    Async connection pool wrapper for the IAM database.

    Usage:
        db = DatabasePool()
        await db.initialize()

        rows = await db.fetch_all("SELECT * FROM iam.users WHERE email = %s", [email])
        row = await db.fetch_one("SELECT * FROM iam.users WHERE id = %s", [user_id])
        await db.execute("INSERT INTO iam.users ...", [...])

        await db.close()
    """

    def __init__(self):
        self._pool: Optional[AsyncConnectionPool] = None
        self._dsn = self._build_dsn()

    def _build_dsn(self) -> str:
        host = os.getenv("POSTGRES_HOST", "vault-db")
        port = os.getenv("POSTGRES_PORT", "5432")
        database = os.getenv("POSTGRES_DB", "neuro_vault")
        user = os.getenv("POSTGRES_USER", "vault_iam")
        password = os.getenv("POSTGRES_PASSWORD", "")
        return f"postgresql://{user}:{password}@{host}:{port}/{database}"

    async def initialize(self) -> None:
        """Create the connection pool."""
        min_size = int(os.getenv("POSTGRES_MIN_CONN", "2"))
        max_size = int(os.getenv("POSTGRES_MAX_CONN", "10"))

        self._pool = AsyncConnectionPool(
            conninfo=self._dsn,
            min_size=min_size,
            max_size=max_size,
            kwargs={"row_factory": dict_row},
        )
        await self._pool.open()
        await self._pool.wait()
        logger.info("Database pool ready (min=%d, max=%d)", min_size, max_size)

    async def close(self) -> None:
        """Close the connection pool."""
        if self._pool:
            await self._pool.close()
            logger.info("Database pool closed")

    async def fetch_one(
        self, query: str, params: Optional[list] = None
    ) -> Optional[Dict[str, Any]]:
        """Fetch a single row."""
        async with self._pool.connection() as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(query, params)
                return await cur.fetchone()

    async def fetch_all(
        self, query: str, params: Optional[list] = None
    ) -> List[Dict[str, Any]]:
        """Fetch all matching rows."""
        async with self._pool.connection() as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(query, params)
                return await cur.fetchall()

    async def execute(
        self, query: str, params: Optional[list] = None
    ) -> int:
        """Execute a query and return affected row count."""
        async with self._pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute(query, params)
                await conn.commit()
                return cur.rowcount

    async def execute_returning(
        self, query: str, params: Optional[list] = None
    ) -> Optional[Dict[str, Any]]:
        """Execute a query with RETURNING and fetch the result."""
        async with self._pool.connection() as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute(query, params)
                await conn.commit()
                return await cur.fetchone()
