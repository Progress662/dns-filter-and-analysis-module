"""
Configuration module for the Domain Profiling module.

This module loads database connection parameters, pool sizes, and retention properties
from system environment variables with secure, sensible defaults.
"""

import os
from typing import Dict, Any


class DBConfig:
    """
    Static configuration class holding PostgreSQL parameters and pooling limits.
    """
    # Database connection parameters
    DB_HOST: str = os.getenv("DB_HOST", "localhost")
    DB_PORT: int = int(os.getenv("DB_PORT", "5432"))
    DB_NAME: str = os.getenv("DB_NAME", "dns_threat_detection")
    DB_USER: str = os.getenv("DB_USER", "postgres")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "Bloodreaper")

    # Connection pooling parameters
    DB_MIN_CONNECTIONS: int = int(os.getenv("DB_MIN_CONNECTIONS", "5"))
    DB_MAX_CONNECTIONS: int = int(os.getenv("DB_MAX_CONNECTIONS", "20"))

    # Cleanup and retention configurations
    HISTORY_RETENTION_DAYS: int = int(os.getenv("HISTORY_RETENTION_DAYS", "30"))

    @classmethod
    def get_connection_params(cls) -> Dict[str, Any]:
        """
        Constructs and returns a psycopg2-compatible parameter dictionary.
        
        Returns:
            Dict[str, Any]: Connection arguments for psycopg2.connect.
        """
        return {
            "host": cls.DB_HOST,
            "port": cls.DB_PORT,
            "database": cls.DB_NAME,
            "user": cls.DB_USER,
            "password": cls.DB_PASSWORD,
            # Set a connection timeout (in seconds)
            "connect_timeout": int(os.getenv("DB_CONNECT_TIMEOUT", "10"))
        }
