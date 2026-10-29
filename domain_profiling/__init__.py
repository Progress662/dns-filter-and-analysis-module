"""
Domain Profiling Module for the DNS Threat Detection System.

This module profiles incoming DNS queries by extracting behavioral features, aggregating
query type distributions per domain, and recording unique client behaviors before domain labeling.
It supports deep indexing, automated database pooling, batch processing, and analytics.

Exposed Classes & Functions:
    - DomainProfilingService: High-level pipeline processing and analytical reports.
    - DomainProfilingRepository: Low-level transactional and batch operations.
    - DBConfig: Environment-backed configuration parameters.
    - ConnectionPoolManager: PostgreSQL thread-safe pooling singleton.
    - get_db_connection: Context manager for scoped connection leasing.
    - get_db_cursor: Context manager for transaction-managed operations.
"""

from domain_profiling.config import DBConfig
from domain_profiling.connection import (
    ConnectionPoolManager,
    get_db_connection,
    get_db_cursor,
)
from domain_profiling.repository import DomainProfilingRepository
from domain_profiling.service import DomainProfilingService

__version__ = "1.0.0"
__author__ = "DRDO Intern Project Contributor"

__all__ = [
    "DomainProfilingService",
    "DomainProfilingRepository",
    "DBConfig",
    "ConnectionPoolManager",
    "get_db_connection",
    "get_db_cursor",
    "__version__",
]
