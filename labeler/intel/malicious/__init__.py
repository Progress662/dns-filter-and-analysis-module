"""
Malicious Domain Database Module

Mirrors the Trusted Domain Database architecture.
Provides thread-safe lookup and automatic updates from URLhaus.
"""

from __future__ import annotations

import logging

from .config import DB_PATH
from .manager import MaliciousDBManager
from .database import (
    MaliciousDatabaseError,
    MaliciousDBConnectionError,
    MaliciousDBValidationError,
    initialize_db_structure,
)
from .updater import check_and_refresh

logger = logging.getLogger(__name__)

__all__ = [
    "MaliciousDBManager",
    "initialize_db_structure",
    "MaliciousDatabaseError",
    "MaliciousDBConnectionError",
    "MaliciousDBValidationError",
    "get_manager",
    "is_malicious",
    "refresh_database_if_needed",
]

# Singleton manager instance
_manager_instance: MaliciousDBManager | None = None


def get_manager() -> MaliciousDBManager:
    """
    Returns the singleton manager instance.
    Creates it on first call.
    """
    global _manager_instance

    if _manager_instance is None:
        _manager_instance = MaliciousDBManager(DB_PATH, logger)

    return _manager_instance


def is_malicious(domain: str) -> bool:
    """
    Convenience function to check if a domain is malicious.
    """
    return get_manager().is_malicious(domain)


def refresh_database_if_needed() -> bool:
    """
    Runs an update if the configured interval has elapsed.

    Returns:
        True if the database is already current or the update succeeds.
        False if the update fails.
    """
    return check_and_refresh(logger)