# labeler/intel/malicious/database.py
"""
Malicious Domain Database Implementation.

Handles SQLite initialization, validation, batching, and threading.
Mirrors the Trusted Database database.py architecture.
"""

from __future__ import annotations

import os
import logging
import sqlite3
import threading
from typing import Optional, Any, List

from .config import (
    DB_PATH,
    WAL_MODE,
    MAP_SIZE_MB,
)

# --- Custom Exceptions ---

class MaliciousDatabaseError(Exception):
    """Base exception for all malicious database errors."""
    pass

class MaliciousDBConnectionError(MaliciousDatabaseError):
    """Raised when a database connection fails."""
    pass

class MaliciousDBValidationError(MaliciousDatabaseError):
    """Raised when database validation fails."""
    pass

# --- Threading Local Storage ---
_local = threading.local()

logger = logging.getLogger(__name__)


def get_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """
    Retrieves a thread-local read-only SQLite connection.
    Implements WAL mode and mmap optimization if configured.
    """
    if hasattr(_local, 'connection') and _local.connection:
        try:
            # Check if the connection is active and not corrupted
            _local.connection.execute("SELECT 1")
            if not _local.connection.in_transaction:
                return _local.connection
        except (sqlite3.ProgrammingError, sqlite3.OperationalError):
            try:
                _local.connection.close()
            except Exception:
                pass
            _local.connection = None
            
    try:
        conn = sqlite3.connect(
            db_path,
            timeout=30.0,
            isolation_level=None,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
        )
        
        # Optimization settings mirroring Trusted DB
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA cache_size = -10000")  # 10MB cache limit
        
        if WAL_MODE:
            conn.execute("PRAGMA journal_mode = WAL")
            
        conn.execute(f"PRAGMA mmap_size = {MAP_SIZE_MB * 1024 * 1024}")
        
        _local.connection = conn
        return conn
    except Exception as e:
        logger.error(f"Failed to connect to SQLite database at {db_path}: {e}")
        raise MaliciousDBConnectionError(f"Database connection failed: {e}")


def close_connection():
    """Closes the current thread's connection if open."""
    if hasattr(_local, 'connection'):
        try:
            if _local.connection:
                _local.connection.close()
        except Exception as e:
            logger.debug(f"Error while closing thread-local connection: {e}")
        finally:
            _local.connection = None


def execute_query(query: str, params: tuple = ()) -> Optional[Any]:
    """Executes a query using the current thread's connection."""
    try:
        conn = get_connection(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchone()
    except sqlite3.Error as e:
        logger.error(f"Failed to execute query '{query}': {e}")
        return None


def execute_many_queries(queries: List[tuple], db_path: str = DB_PATH) -> int:
    """
    Executes many queries in a single transaction.
    Used primarily during the database build phase in New DB.
    """
    conn = None
    try:
        conn = sqlite3.connect(db_path, timeout=30.0)
        conn.execute("BEGIN IMMEDIATE TRANSACTION")
        for q, p in queries:
            conn.execute(q, p)
        conn.commit()
        return len(queries)
    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except Exception as rollback_err:
                logger.error(f"Rollback failed during batch error handling: {rollback_err}")
        logger.error(f"Batch write transaction failed: {e}")
        raise MaliciousDBValidationError(f"Batch insert failed: {e}")
    finally:
        if conn:
            conn.close()


def initialize_db_structure(path: str = DB_PATH) -> None:
    """
    Initializes the database schema and metadata tables.
    Ensures tables exist safely and idempotently.
    """
    # Ensure parent directory exists safely
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    
    conn = None
    try:
        conn = sqlite3.connect(path, timeout=30.0)
        
        # 1. Main Domain Table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS malicious_domains (
                domain TEXT PRIMARY KEY,
                source TEXT NOT NULL DEFAULT 'urlhaus',
                downloaded_at TEXT
            );
        """)

        # Explicit lookup index
        conn.execute("CREATE INDEX IF NOT EXISTS idx_domain ON malicious_domains(domain);")

        # 2. Metadata Table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            );
        """)

        # Safe metadata row populating
        conn.execute("INSERT OR IGNORE INTO metadata (key, value) VALUES ('last_update', '');")
        conn.execute("INSERT OR IGNORE INTO metadata (key, value) VALUES ('dataset_version', '');")
        conn.execute("INSERT OR IGNORE INTO metadata (key, value) VALUES ('record_count', '0');")
        conn.execute("INSERT OR IGNORE INTO metadata (key, value) VALUES ('source', '');")
        
        conn.commit()
        logger.info(f"Initialized database structure at {path}")
    except Exception as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        logger.error(f"Failed to initialize database structure at {path}: {e}")
        raise MaliciousDatabaseError(f"Failed to initialize database structure: {e}")
    finally:
        if conn:
            conn.close()


def verify_schema(path: str = DB_PATH) -> bool:
    """Verifies critical tables and columns exist."""
    required_tables = {"malicious_domains", "metadata"}
    conn = None
    try:
        conn = sqlite3.connect(path, timeout=10.0)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0] for row in cursor.fetchall()}
        return required_tables.issubset(tables)
    except Exception as e:
        logger.error(f"Schema verification failed on database {path}: {e}")
        return False
    finally:
        if conn:
            conn.close()


def validate_integrity(path: str = DB_PATH) -> bool:
    """Performs SQLite integrity check."""
    conn = None
    try:
        conn = sqlite3.connect(path, timeout=10.0)
        cursor = conn.execute("PRAGMA integrity_check")
        result = cursor.fetchone()[0]
        return result == "ok"
    except Exception as e:
        logger.error(f"Integrity check failed on database {path}: {e}")
        return False
    finally:
        if conn:
            conn.close()


def get_metadata_value(key: str, path: str = DB_PATH) -> Optional[str]:
    """Retrieves a metadata value safely."""
    conn = None
    try:
        conn = sqlite3.connect(path, timeout=10.0)
        cursor = conn.execute(
            "SELECT value FROM metadata WHERE key = ?", (key,)
        )
        row = cursor.fetchone()
        return row[0] if row else None
    except Exception as e:
        logger.error(f"Failed to read metadata key '{key}' from {path}: {e}")
        return None
    finally:
        if conn:
            conn.close()


def set_metadata_value(key: str, value: str, path: str = DB_PATH) -> None:
    """Updates or inserts a metadata value safely."""
    conn = None
    try:
        conn = sqlite3.connect(path, timeout=30.0)
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            (key, value)
        )
        conn.commit()
    except Exception as e:
        logger.error(f"Failed to set metadata key '{key}' to '{value}' on {path}: {e}")
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        raise MaliciousDatabaseError(f"Metadata write transaction failed: {e}")
    finally:
        if conn:
            conn.close()