"""
Schema Module
=============
Manages the creation of the ``reputation`` table inside the PostgreSQL
database.

The table stores every domain that has been labelled **malicious** by
the DNS Threat Intelligence pipeline.

One-time call::

    create_reputation_table(conn)
"""

from __future__ import annotations

import logging
from typing import Optional

from psycopg2.extensions import connection as PgConnection

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DDL statement
# ---------------------------------------------------------------------------
_CREATE_TABLE_SQL: str = """
CREATE TABLE IF NOT EXISTS reputation_domains (
    id              SERIAL PRIMARY KEY,
    domain          VARCHAR(255) UNIQUE NOT NULL,
    status          VARCHAR(20)  NOT NULL DEFAULT 'malicious',
    source          VARCHAR(50)  NOT NULL DEFAULT 'URLHaus',
    confidence      FLOAT,
    first_seen      TIMESTAMP    NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMP    NOT NULL DEFAULT NOW(),
    times_seen      INTEGER      NOT NULL DEFAULT 1,
    query_count     INTEGER      NOT NULL DEFAULT 1,
    client_ip       INET,
    query_type      VARCHAR(10),
    created_at      TIMESTAMP    NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP    NOT NULL DEFAULT NOW()
);
"""

# Indexes to accelerate common queries
_CREATE_INDEXES: list[str] = [
    "CREATE INDEX IF NOT EXISTS idx_reputation_domain   ON reputation_domains (domain);",
    "CREATE INDEX IF NOT EXISTS idx_reputation_last_seen ON reputation_domains (last_seen);",
    "CREATE INDEX IF NOT EXISTS idx_reputation_status    ON reputation_domains (status);",
]


def create_reputation_table(conn: PgConnection) -> bool:
    """Create the ``reputation`` table (and indexes) if they don't exist.

    Parameters
    ----------
    conn : PgConnection
        An active PostgreSQL connection.

    Returns
    -------
    bool
        ``True`` if the table was created, ``False`` if it already existed.
    """
    with conn.cursor() as cur:
        # Check if the table already exists
        cur.execute(
            "SELECT EXISTS ("
            "  SELECT FROM information_schema.tables "
            "  WHERE table_name = 'reputation_domains'"
            ");"
        )
        exists: bool = cur.fetchone()[0]

        cur.execute(_CREATE_TABLE_SQL)
        for idx_sql in _CREATE_INDEXES:
            cur.execute(idx_sql)

    if not exists:
        logger.info("Created reputation_domains table and indexes.")
    else:
        logger.info("reputation_domains table already exists — skipped creation.")

    return not exists