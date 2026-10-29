"""
Lookup Manager.

Provides the high-level API for checking domains.
Implements auto-refresh logic and thread-local caching.
Mirrors Trusted DB manager.py.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime

from .database import (
    close_connection,
    execute_query,
    get_metadata_value,
)
from .downloader import normalize_domain
from .updater import check_and_refresh, should_update

logger = logging.getLogger(__name__)


class MaliciousDBManager:
    def __init__(self, db_path: str, log: logging.Logger):
        self.db_path = db_path
        self.logger = log
        self._ensure_initialization()

    def _ensure_initialization(self) -> None:
        """
        Ensures the database exists before accepting queries.
        """
        if os.path.exists(self.db_path):
            self.logger.debug(
                "Malicious database found at '%s'.",
                self.db_path,
            )
            return

        self.logger.warning(
            "Database missing at '%s'. Initializing.",
            self.db_path,
        )

        try:
            from .database import initialize_db_structure

            initialize_db_structure(self.db_path)

            if os.path.exists(self.db_path):
                self.logger.info(
                    "Initialized malicious database at '%s'.",
                    self.db_path,
                )
            else:
                self.logger.error(
                    "Database initialization completed but database was not created at '%s'.",
                    self.db_path,
                )

        except Exception:
            self.logger.exception(
                "Failed to initialize malicious database at '%s'.",
                self.db_path,
            )

    def update_if_needed(self) -> bool:
        """
        Triggers an update check.
        """
        try:
            return check_and_refresh(self.logger)
        except Exception:
            self.logger.exception("Automatic update check failed.")
            return False

    def is_malicious(self, domain: str) -> bool:
        """
        Public API: Checks if a domain is known malicious.

        1. Normalizes domain.
        2. Checks age (auto updates if stale).
        3. Looks up the domain in SQLite.
        """
        if not domain:
            self.logger.debug("Lookup requested with empty domain.")
            return False

        self.logger.debug("Incoming lookup domain: %s", domain)

        normalized = normalize_domain(domain)

        self.logger.debug("Normalized lookup domain: %s", normalized)

        if not normalized:
            return False

        try:
            last_ts_str = get_metadata_value("last_update")

            if last_ts_str:
                try:
                    last_ts_float = datetime.strptime(
                        last_ts_str,
                        "%Y-%m-%d %H:%M:%S",
                    ).timestamp()

                    if should_update(last_ts_float):
                        self.logger.debug(
                            "Database refresh triggered due to stale metadata."
                        )
                        self.update_if_needed()
                    else:
                        self.logger.debug(
                            "Database refresh skipped; database is current."
                        )

                except ValueError:
                    self.logger.warning(
                        "Invalid last_update metadata value: %r",
                        last_ts_str,
                    )

        except Exception:
            self.logger.exception("Failed while checking update status.")

        try:
            self.logger.debug(
                "Querying malicious database at '%s'.",
                self.db_path,
            )

            query = (
                "SELECT 1 FROM malicious_domains "
                "WHERE domain = ? "
                "LIMIT 1;"
            )

            #
            # NOTE:
            # execute_query() currently does not accept a database path and
            # uses the database module's configured path internally.
            # This manager records self.db_path for diagnostics and future
            # compatibility, but remains compatible with the existing API.
            #
            result = execute_query(query, (normalized,))

            found = result is not None

            self.logger.debug(
                "Lookup result for '%s': %s",
                normalized,
                found,
            )

            return found

        except Exception:
            self.logger.exception(
                "Lookup failed for domain '%s'.",
                normalized,
            )
            return False

        finally:
            try:
                close_connection()
            except Exception:
                self.logger.exception(
                    "Failed to close SQLite connection."
                )