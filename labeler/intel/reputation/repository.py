"""
Repository Module
=================
Public-facing CRUD operations for the ``reputation`` table.

This is the only module your pipeline needs to import::

    from database import (
        initialize_database,
        store_malicious_domain,
        get_domain,
        update_domain,
        cleanup_old_domains,
        close_connection,
    )

Every function uses the connection pool defined in ``connection.py``
and manages its own transaction lifecycle.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Optional

from psycopg2.extensions import connection as PgConnection
import psycopg2.extras

from .connection import get_connection, close_pool
from .schema import create_reputation_table

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────
_DEFAULT_SOURCE: str = "URLHaus"
_DEFAULT_STATUS: str = "malicious"
_DEFAULT_DAYS: int = 180


# ──────────────────────────────────────────────────────────────────────
# Initialisation
# ──────────────────────────────────────────────────────────────────────
def initialize_database() -> None:
    """Create the connection pool and the ``reputation`` table.

    Call this **once** at application startup, *before* any pipeline
    processing begins.

    Example::

        from database import initialize_database
        initialize_database()
    """
    with get_connection() as conn:
        create_reputation_table(conn)
    logger.info("Database initialization successful.")


# ──────────────────────────────────────────────────────────────────────
# Insert / Upsert
# ──────────────────────────────────────────────────────────────────────
def store_malicious_domain(
    domain: str,
    metadata: Optional[dict[str, Any]] = None,
) -> bool:
    """Store a malicious domain in the reputation database.

    * If the domain is **new**, a row is inserted.
    * If the domain **already exists**, ``last_seen``, ``times_seen``,
      ``query_count`` and ``updated_at`` are incremented / updated.

    The deduplication is handled atomically by PostgreSQL's
    ``ON CONFLICT (domain) DO UPDATE`` clause — no separate SELECT
    is needed.

    Parameters
    ----------
    domain : str
        The fully-qualified domain name to store (e.g. ``evil.example``).
    metadata : dict or None
        Optional overrides for the row columns.  Supported keys:

        * ``source``     — threat-intel source name (default ``URLHaus``)
        * ``confidence`` — float confidence score (default ``None``)
        * ``query_count`` — int (default ``1``)
        * ``client_ip``  — originating client IP (default ``None``)
        * ``query_type`` — DNS query type, e.g. ``A``/``AAAA``/``MX``
          (default ``None``)

    Returns
    -------
    bool
        ``True`` if a new row was inserted, ``False`` if an existing row
        was updated.

    Raises
    ------
    psycopg2.Error
        On database-level failures (the transaction is rolled back).
    """
    metadata = metadata or {}
    print("\n========== store_malicious_domain ==========")
    print("Domain      :", domain)
    print("Metadata    :", metadata)
    print("============================================")
    source: str = metadata.get("source", _DEFAULT_SOURCE)
    confidence: Optional[float] = metadata.get("confidence")
    query_count: int = metadata.get("query_count", 1)
    client_ip: Optional[str] = metadata.get("client_ip")
    query_type: Optional[str] = metadata.get("query_type")
    print("client_ip :", client_ip)
    print("query_type:", query_type)
    
    upsert_sql: str = """
        INSERT INTO reputation_domains
            (domain, status, source, confidence, first_seen, last_seen,
             times_seen, query_count, client_ip, query_type, created_at, updated_at)
        VALUES
            (%s, %s, %s, %s, NOW(), NOW(), 1, %s, %s, %s, NOW(), NOW())
        ON CONFLICT (domain) DO UPDATE
            SET last_seen    = NOW(),
                times_seen   = reputation_domains.times_seen + 1,
                query_count  = reputation_domains.query_count + %s,
                client_ip    = EXCLUDED.client_ip,
                query_type   = EXCLUDED.query_type,
                updated_at   = NOW()
        RETURNING (xmax = 0) AS inserted;
    """

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                upsert_sql,
                (
                    domain,
                    _DEFAULT_STATUS,
                    source,
                    confidence,
                    query_count,
                    client_ip,
                    query_type,
                    query_count,
                ),
            )
            inserted: bool = cur.fetchone()[0]

    if inserted:
        logger.info("Inserted malicious domain: %s (source=%s)", domain, source)
    else:
        logger.info("Updated existing malicious domain: %s", domain)

    return inserted


# ──────────────────────────────────────────────────────────────────────
# Select
# ──────────────────────────────────────────────────────────────────────
def get_domain(domain: str) -> Optional[dict[str, Any]]:
    """Fetch a single domain's reputation record.

    Parameters
    ----------
    domain : str
        The domain to look up.

    Returns
    -------
    dict or None
        A dictionary of column-name → value, or ``None`` if the domain
        is not in the database.
    """
    sql: str = "SELECT * FROM reputation_domains WHERE domain = %s;"
    with get_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, (domain,))
            row = cur.fetchone()

    if row is None:
        logger.debug("Domain not found in reputation DB: %s", domain)
        return None

    # Convert the RealDictRow to a plain dict for safety
    return dict(row)


# ──────────────────────────────────────────────────────────────────────
# Update (generic)
# ──────────────────────────────────────────────────────────────────────
def update_domain(domain: str, **kwargs: Any) -> bool:
    """Update arbitrary columns on an existing domain record.

    This is a **generic** helper intended for future use (e.g. when
    VirusTotal enriches a record with ``confidence``).  It does **not**
    update ``times_seen`` / ``last_seen`` — that logic lives in
    ``store_malicious_domain``.

    Parameters
    ----------
    domain : str
        The domain whose record will be updated.
    **kwargs
        Column-name → value pairs to set (e.g. ``confidence=0.95``).

    Returns
    -------
    bool
        ``True`` if a row was updated, ``False`` if the domain was not
        found.
    """
    if not kwargs:
        return False

    set_clauses: list[str] = []
    values: list[Any] = []
    for col, val in kwargs.items():
        set_clauses.append(f"{col} = %s")
        values.append(val)

    # Always bump updated_at
    set_clauses.append("updated_at = NOW()")
    values.append(domain)  # for the WHERE clause

    sql: str = (
        f"UPDATE reputation_domains SET {', '.join(set_clauses)} "
        f"WHERE domain = %s;"
    )

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, values)
            updated: int = cur.rowcount

    if updated:
        logger.info("Updated domain %s with %s", domain, kwargs)
    else:
        logger.warning("No record found to update for domain: %s", domain)

    return updated > 0


# ──────────────────────────────────────────────────────────────────────
# Cleanup
# ──────────────────────────────────────────────────────────────────────
def cleanup_old_domains(days: int = _DEFAULT_DAYS) -> int:
    """Delete records whose ``last_seen`` is older than *days*.

    .. important::
        Deletion is based on **last_seen**, not **first_seen**.

    Parameters
    ----------
    days : int
        Age threshold in days (default 180).

    Returns
    -------
    int
        Number of deleted rows.
    """
    sql: str = "DELETE FROM reputation_domains WHERE CURRENT_DATE - last_seen::date > %s;"
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (days,))
            deleted: int = cur.rowcount

    if deleted:
        logger.info("Deleted %d expired records (last_seen > %d days).", deleted, days)
    else:
        logger.info("No expired records found (threshold=%d days).", days)

    return deleted


# ──────────────────────────────────────────────────────────────────────
# Connection lifecycle
# ──────────────────────────────────────────────────────────────────────
def close_connection() -> None:
    """Close the PostgreSQL connection pool.

    Call this during graceful application shutdown.
    """
    close_pool()