"""
Database connection pool management

Provides a connection pool for efficient database access.
Uses psycopg3 connection pooling for production reliability.
"""

import logging
from psycopg_pool import ConnectionPool
from .config import DB_CONFIG, POOL_CONFIG

logger = logging.getLogger(__name__)

# Global connection pool
_pool = None


def get_connection_string():
    """
    Build PostgreSQL connection string from configuration.
    
    Returns:
        str: PostgreSQL connection string
    """
    return (
        f"host={DB_CONFIG['host']} "
        f"port={DB_CONFIG['port']} "
        f"dbname={DB_CONFIG['dbname']} "
        f"user={DB_CONFIG['user']} "
        f"password={DB_CONFIG['password']}"
    )


def initialize_pool():
    """
    Initialize the connection pool.
    
    This should be called once at application startup.
    The pool will be reused for all subsequent database operations.
    
    Raises:
        Exception: If pool initialization fails
    """
    global _pool
    
    if _pool is not None:
        logger.warning("Connection pool already initialized")
        return
    
    try:
        conninfo = get_connection_string()
        _pool = ConnectionPool(
            conninfo=conninfo,
            min_size=POOL_CONFIG["min_size"],
            max_size=POOL_CONFIG["max_size"],
            open=True,
        )
        logger.info(
            f"Connection pool initialized "
            f"(min={POOL_CONFIG['min_size']}, max={POOL_CONFIG['max_size']})"
        )
    except Exception as e:
        logger.error(f"Failed to initialize connection pool: {e}")
        raise


def get_pool():
    """
    Get the global connection pool.
    
    Returns:
        ConnectionPool: The global connection pool
        
    Raises:
        RuntimeError: If pool has not been initialized
    """
    if _pool is None:
        raise RuntimeError(
            "Connection pool not initialized. Call initialize_pool() first."
        )
    return _pool


def close_pool():
    """
    Close the connection pool.
    
    This should be called at application shutdown to cleanly
    release all database connections.
    """
    global _pool
    
    if _pool is not None:
        _pool.close()
        _pool = None
        logger.info("Connection pool closed")