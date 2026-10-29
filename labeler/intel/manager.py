from datetime import datetime
import sqlite3
import threading

from . import config
from . import database
from . import updater

__all__ = ["is_trusted"]

_THREAD_LOCAL = threading.local()
_NEXT_UPDATE_CHECK: datetime | None = None

_LOOKUP_SQL = "SELECT 1 FROM trusted_domains WHERE domain = ? LIMIT 1"


def _close_connection() -> None:
    connection = getattr(_THREAD_LOCAL, "connection", None)

    if connection is not None:
        try:
            connection.close()
        finally:
            del _THREAD_LOCAL.connection


def _open_lookup_connection() -> sqlite3.Connection:
    try:
        connection = sqlite3.connect(
            f"file:{config.DATABASE_PATH}?mode=ro",
            uri=True,
            timeout=config.SQLITE_TIMEOUT,
            isolation_level=None,
            cached_statements=config.SQLITE_CACHED_STATEMENTS,
        )

        connection.execute(
            f"PRAGMA busy_timeout = {int(config.SQLITE_TIMEOUT * 1000)}"
        )
        connection.execute("PRAGMA temp_store = MEMORY")
        connection.execute("PRAGMA query_only = ON")
        connection.execute(f"PRAGMA mmap_size = {config.SQLITE_MMAP_SIZE}")

        return connection

    except sqlite3.Error as exc:
        raise database.TrustedDatabaseError(
            "Failed to open trusted domains lookup database"
        ) from exc


def _get_connection() -> sqlite3.Connection:
    connection = getattr(_THREAD_LOCAL, "connection", None)

    if connection is None:
        connection = _open_lookup_connection()
        _THREAD_LOCAL.connection = connection

    return connection


def _refresh_next_update_check() -> None:
    global _NEXT_UPDATE_CHECK

    metadata = database.read_metadata(config.DATABASE_PATH)
    last_update = database.parse_timestamp(metadata.get("last_update", ""))

    if last_update is None:
        _NEXT_UPDATE_CHECK = database.utc_now()
        return

    _NEXT_UPDATE_CHECK = last_update + config.REFRESH_INTERVAL


def _ensure_database_ready() -> None:
    now = database.utc_now()

    if (
        not config.DATABASE_PATH.exists()
        or _NEXT_UPDATE_CHECK is None
        or now >= _NEXT_UPDATE_CHECK
    ):
        _close_connection()
        updater.ensure_updated(config.DATABASE_PATH)
        _refresh_next_update_check()


def is_trusted(domain: str) -> bool:
    _ensure_database_ready()

    normalized_domain = database.normalize_domain(domain)

    if not normalized_domain:
        return False

    connection = _get_connection()

    try:
        return (
            connection.execute(
                _LOOKUP_SQL,
                (normalized_domain,),
            ).fetchone()
            is not None
        )

    except sqlite3.Error as exc:
        _close_connection()
        raise database.TrustedDatabaseError(
            "Trusted domain lookup failed"
        ) from exc