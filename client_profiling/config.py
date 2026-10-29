"""
Configuration for the Client Profiling Database Module

Adjust these settings according to your environment.
"""

import os

# PostgreSQL Connection Settings
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": os.getenv("DB_PORT", "5432"),
    "dbname": os.getenv("DB_NAME", "dns_profiling"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "Bloodreaper"),
}

# Connection Pool Settings
POOL_CONFIG = {
    "min_size": int(os.getenv("POOL_MIN_SIZE", "2")),
    "max_size": int(os.getenv("POOL_MAX_SIZE", "10")),
}

# Cleanup Settings
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "180"))

# Application Settings
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")