"""
Connection pooling manager for the Domain Profiling database module.

This module provides a thread-safe connection pool using psycopg2.pool.ThreadedConnectionPool
to manage connections to the 'dns_threat_detection' PostgreSQL database.
"""

import logging
from contextlib import contextmanager
from typing import Generator, Any
import psycopg2
import psycopg2.extensions
from psycopg2.pool import ThreadedConnectionPool

# Configure logger
logger = logging.getLogger("dns_threat_detection.domain_profiling.connection")


class ConnectionPoolManager:
    """
    Thread-safe connection pool manager for PostgreSQL.
    Implements a singleton pattern to prevent recreating connection pools.
    """
    _pool: ThreadedConnectionPool | None = None

    @classmethod
    def initialize_pool(cls) -> None:
        """
        Initializes the ThreadedConnectionPool using configurations from DBConfig.
        """
        if cls._pool is not None:
            logger.warning("Connection pool is already initialized.")
            return

        # Import DBConfig here to avoid circular dependencies
        from domain_profiling.config import DBConfig

        try:
            db_params = DBConfig.get_connection_params()
            min_conn = DBConfig.DB_MIN_CONNECTIONS
            max_conn = DBConfig.DB_MAX_CONNECTIONS
            
            logger.info(
                f"Initializing ThreadedConnectionPool (min_conn={min_conn}, "
                f"max_conn={max_conn}) for database '{db_params.get('database')}'"
            )
            
            cls._pool = ThreadedConnectionPool(
                minconn=min_conn,
                maxconn=max_conn,
                **db_params
            )
        except Exception as e:
            logger.error(f"Failed to initialize PostgreSQL connection pool: {e}", exc_info=True)
            raise e

    @classmethod
    def get_connection(cls) -> Any:
        """
        Retrieves a connection from the pool. Automatically initializes the pool if it has not been.
        
        Returns:
            psycopg2.extensions.connection: A connection object from the pool.
        """
        if cls._pool is None:
            cls.initialize_pool()
        
        if cls._pool is None:
            raise RuntimeError("Database connection pool could not be initialized.")
            
        try:
            return cls._pool.getconn()
        except Exception as e:
            logger.error(f"Error getting connection from the pool: {e}", exc_info=True)
            raise e

    @classmethod
    def release_connection(cls, conn: Any) -> None:
        """
        Releases a connection back to the pool.
        
        Args:
            conn (psycopg2.extensions.connection): The connection to release.
        """
        if cls._pool is not None and conn is not None:
            try:
                cls._pool.putconn(conn)
            except Exception as e:
                logger.error(f"Error releasing connection to pool: {e}", exc_info=True)

    @classmethod
    def close_all_connections(cls) -> None:
        """
        Closes all connections in the pool and sets the pool to None.
        Useful for application shutdown and cleanups.
        """
        if cls._pool is not None:
            logger.info("Closing all connections in the pool...")
            try:
                cls._pool.closeall()
            except Exception as e:
                logger.error(f"Error closing all connections in the pool: {e}", exc_info=True)
            finally:
                cls._pool = None


@contextmanager
def get_db_connection() -> Generator[Any, None, None]:
    """
    Context manager to safely borrow a connection from the pool and return it.
    Rolls back automatically in case of exception, and releases the connection.
    
    Yields:
        psycopg2.extensions.connection: A database connection.
    """
    conn = None
    try:
        conn = ConnectionPoolManager.get_connection()
        yield conn
    except Exception as e:
        if conn:
            try:
                conn.rollback()
                logger.debug("Database transaction rolled back due to error.")
            except Exception as rollback_err:
                logger.error(f"Database rollback failed: {rollback_err}")
        raise e
    finally:
        if conn:
            ConnectionPoolManager.release_connection(conn)


@contextmanager
def get_db_cursor() -> Generator[Any, None, None]:
    """
    Context manager to borrow a connection and yield a cursor.
    Commits on successful block completion or rolls back on exception.
    
    Yields:
        psycopg2.extensions.cursor: A database cursor.
    """
    with get_db_connection() as conn:
        cursor = None
        try:
            cursor = conn.cursor()
            yield cursor
            conn.commit()
        except Exception as e:
            if conn:
                conn.rollback()
            raise e
        finally:
            if cursor:
                cursor.close()
