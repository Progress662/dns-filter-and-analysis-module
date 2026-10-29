"""
PostgreSQL database layer for the unknown domain repository subsystem.

This module provides production-grade database connectivity using psycopg3
with connection pooling, health checks, schema management, and robust
error handling for high-throughput domain persistence operations.
"""

import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union, Generator
from datetime import datetime, timezone
from typing import Optional, Generator

import psycopg
from psycopg import sql
from psycopg.rows import dict_row, tuple_row
from psycopg_pool import ConnectionPool

from .config import Config, DatabaseConfig
from .constants import (
    SCHEMA_VERSION,
    DOMAIN_TABLE_NAME,
    PERF_BATCH_INSERT_THRESHOLD_MS,
    DEFAULT_RETRY_COUNT,
    DEFAULT_RETRY_DELAY_SECONDS,
    DEFAULT_RETRY_BACKOFF_FACTOR
)
from .exceptions import (
    DatabaseConnectionError,
    ConnectionPoolError,
    DatabaseQueryError,
    TransactionError,
    SchemaError,
    MigrationError,
    HealthCheckError,
    InitializationError
)
from .logger import get_logger, timing_decorator


class DatabaseManager:
    """
    PostgreSQL database manager with connection pooling and health monitoring.
    
    Provides high-level database operations, connection management, and
    schema initialization for the unknown domain repository subsystem.
    Designed for production environments with concurrent access patterns.
    """
    
    def __init__(self, config: Config) -> None:
        """
        Initialize database manager.
        
        Args:
            config: Application configuration containing database settings.
        """
        self.config = config
        self.db_config = config.database  # Fixed to match Config class 'db' attribute
        self.logger = get_logger()
        self._pool: Optional[ConnectionPool] = None
        self._initialized = False
        self._schema_verified = False
        
    def initialize(self) -> None:
        """
        Initialize database connection pool and verify schema.
        """
        if self._initialized:
            return
            
        try:
            self._create_connection_pool()
            self._verify_schema()
            self._initialized = True
            
            self.logger.info(
                "Database manager initialized successfully",
                extra={
                    'pool_size': f"{self.db_config.min_connections}-{self.db_config.max_connections}",
                    'host': self.db_config.host,
                    'database': self.db_config.database
                }
            )
            
        except Exception as e:
            self.logger.exception("Failed to initialize database manager")
            raise InitializationError(f"Database initialization failed: {e}") from e
    
    def _create_connection_pool(self) -> None:
        """Create and configure the database connection pool."""
        try:
            connection_kwargs = {
                "host": self.db_config.host,
                "port": self.db_config.port,
                "dbname": self.db_config.database,
                "user": self.db_config.username,
                "password": self.db_config.password,
                "connect_timeout": 10
            }
            
            self._pool = ConnectionPool(
                kwargs=connection_kwargs,
                min_size=self.db_config.min_connections,
                max_size=self.db_config.max_connections,
                timeout=30,
                configure=self._configure_connection
            )

            self._pool.open()
            self._pool.wait()
            
        except Exception as e:
            raise ConnectionPoolError(
                f"Failed to create connection pool: {e}",
                pool_size=self.db_config.max_connections
            ) from e
    
    def _configure_connection(self, conn: psycopg.Connection) -> None:
        """Configure individual database connections for optimal performance."""
        old_autocommit = conn.autocommit
        conn.autocommit = True
        try:
            conn.execute("SET synchronous_commit = off")
            conn.execute("SET random_page_cost = 1.1")
            conn.execute("SET application_name = 'unknown_domain_repository'")
        finally:
            conn.autocommit = old_autocommit
            
    def _verify_schema(self) -> None:
        """Verify database schema exists and is current."""
        try:
            with self.get_connection() as conn:
                exists = conn.execute("""
                    SELECT EXISTS (
                        SELECT FROM information_schema.tables 
                        WHERE table_schema = 'public' 
                        AND table_name = %s
                    )
                """, (DOMAIN_TABLE_NAME,)).fetchone()[0]
                
                if not exists:
                    self.logger.info("Database schema not found, creating...")
                    self._create_schema(conn)
                else:
                    self.logger.debug("Database schema exists, verifying version...")
                    self._verify_schema_version(conn)
                    
                self._schema_verified = True
        except Exception as e:
            raise SchemaError(f"Schema verification failed: {e}") from e
    
    def _create_schema(self, conn: psycopg.Connection) -> None:
        """Create database schema from SQL file."""
        try:
            schema_file = Path(__file__).parent / "sql" / "schema.sql"
            if not schema_file.exists():
                schema_file = Path(__file__).parent.parent / "sql" / "schema.sql"
            
            if not schema_file.exists():
                raise SchemaError("Schema SQL file not found")
            
            schema_sql = schema_file.read_text(encoding='utf-8')
            
            with conn.transaction():
                conn.execute(schema_sql)
                
            self.logger.info(
                "Database schema created successfully",
                extra={'schema_version': SCHEMA_VERSION}
            )
        except Exception as e:
            raise SchemaError(f"Failed to create schema: {e}") from e
    
    def _verify_schema_version(self, conn: psycopg.Connection) -> None:
        """Verify current schema version matches expected version."""
        try:
            result = conn.execute("""
                SELECT version FROM schema_metadata 
                WHERE component = 'unknown_domain_repository'
            """).fetchone()
            
            if not result:
                # If metadata table is missing but table exists, create metadata
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS schema_metadata (
                        component VARCHAR(50) PRIMARY KEY,
                        version INTEGER NOT NULL,
                        updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.execute("""
                    INSERT INTO schema_metadata (component, version) 
                    VALUES ('unknown_domain_repository', %s)
                """, (SCHEMA_VERSION,))
                return

            current_version = result[0]
            if current_version != SCHEMA_VERSION:
                self.logger.warning(f"Schema version mismatch: {current_version} != {SCHEMA_VERSION}")
        except psycopg.Error as e:
            self.logger.warning(f"Failed to verify schema version: {e}")
    
    @contextmanager
    def get_connection(self, timeout: Optional[float] = None) -> Generator[psycopg.Connection, None, None]:
        """Get database connection from pool with automatic cleanup."""

        if self._pool is None:
            raise ConnectionPoolError("Connection pool not initialized")

        connection_timeout = timeout if timeout is not None else 30
        
        try:
            with self._pool.connection(timeout=connection_timeout) as conn:
                yield conn
        except Exception as e:
            raise DatabaseConnectionError(
                f"Failed to acquire connection: {e}"
                ) from e
    
    @contextmanager
    def transaction(self, connection: Optional[psycopg.Connection] = None) -> Generator[psycopg.Connection, None, None]:
        """Transaction context manager with automatic rollback on error."""
        if connection:
            with connection.transaction():
                yield connection
        else:
            with self.get_connection() as conn:
                with conn.transaction():
                    yield conn
    
    def execute_query(self, query: Union[str, sql.SQL], parameters: Optional[Tuple] = None, 
                      fetch_one: bool = False, fetch_all: bool = False, 
                      connection: Optional[psycopg.Connection] = None) -> Any:
        """Execute database query with monitoring."""
        start_time = time.perf_counter()
        
        def _execute(conn: psycopg.Connection) -> Any:
            cursor = conn.execute(query, parameters) if parameters else conn.execute(query)
            if fetch_one: return cursor.fetchone()
            if fetch_all: return cursor.fetchall()
            return cursor.rowcount
        
        if connection:
            return _execute(connection)
        else:
            with self.get_connection() as conn:
                return _execute(conn)
    
    def batch_insert(self, table: str, columns: List[str], values: List[Tuple], 
                     connection: Optional[psycopg.Connection] = None, 
                     on_conflict_action: str = "DO NOTHING") -> int:
        """Perform batch insert operation."""
        if not values:
            return 0
        
        placeholders = ", ".join(["%s"] * len(columns))
        columns_str = ", ".join(columns)
        query = sql.SQL("INSERT INTO {} ({}) VALUES ({}) ON CONFLICT {}").format(
            sql.Identifier(table), sql.SQL(columns_str), sql.SQL(placeholders), sql.SQL(on_conflict_action)
        )
        
        if connection:
            with connection.cursor() as cur:
                cur.executemany(query, values)
                return cur.rowcount
        else:
            with self.get_connection() as conn:
                with conn.cursor() as cur:
                    cur.executemany(query, values)
                    return cur.rowcount

    def health_check(self, timeout: float = 5.0) -> Dict[str, Any]:
        """Comprehensive database health check."""
        try:
            with self.get_connection(timeout=timeout) as conn:
                conn.execute("SELECT 1").fetchone()
                return {"healthy": True, "status": "ok"}
        except Exception as e:
            return {"healthy": False, "error": str(e)}

    def close(self) -> None:
        """Close database connection pool."""
        if self._pool:
            self._pool.close()
            self._pool = None
            self._initialized = False

    def __enter__(self) -> 'DatabaseManager':
        if not self._initialized:
            self.initialize()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

def create_database_manager(config: Config) -> DatabaseManager:
    manager = DatabaseManager(config)
    manager.initialize()
    return manager