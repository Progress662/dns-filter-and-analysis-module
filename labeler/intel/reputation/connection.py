"""
Connection Module
=================
Manages a thread-safe PostgreSQL connection pool using psycopg2.

Exposes:
    get_connection()  — obtain a connection from the pool (context manager).
    close_pool()      — close all connections in the pool.

All database operations should acquire a connection via get_connection()
to guarantee proper release back to the pool.
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Generator

import psycopg2
from psycopg2 import pool as pg_pool
from psycopg2.extensions import connection as PgConnection

from .config import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level pool (initialised once by initialize_database)
# ---------------------------------------------------------------------------
_pool: pg_pool.ThreadedConnectionPool | None = None


# ---------------------------------------------------------------------------
# Pool lifecycle
# ---------------------------------------------------------------------------
def create_pool() -> pg_pool.ThreadedConnectionPool:
    """Create and return a new threaded connection pool.

    Raises
    ------
    psycopg2.OperationalError
        If the database is unreachable or credentials are invalid.
    """
    config.validate()
    pool = pg_pool.ThreadedConnectionPool(
        config.min_conn,
        config.max_conn,
        dsn=config.dsn,
    )
    logger.info(
        "Connected to PostgreSQL — %s:%s/%s",
        config.host,
        config.port,
        config.dbname,
    )
    return pool


def close_pool() -> None:
    """Close every connection in the pool gracefully."""
    global _pool
    if _pool is not None:
        _pool.closeall()
        _pool = None
        logger.info("PostgreSQL connection pool closed.")


# ---------------------------------------------------------------------------
# Connection context manager
# ---------------------------------------------------------------------------
@contextmanager
def get_connection() -> Generator[PgConnection, None, None]:
    """Yield a connection from the pool, returning it on exit.

    If the pool is not yet initialised, it is auto-created on first use.

    Usage::

        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(...)

    The outer context manager handles commit/rollback automatically.
    """
    global _pool
    if _pool is None:
        _pool = create_pool()

    conn = _pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        _pool.putconn(conn)
