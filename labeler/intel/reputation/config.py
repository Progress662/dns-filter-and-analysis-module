"""
Configuration Module
====================
Loads PostgreSQL credentials and database settings from environment
variables.  No secrets are hardcoded.

Environment variables (see .env.example):
    DB_HOST       — PostgreSQL host          (default: localhost)
    DB_PORT       — PostgreSQL port          (default: 5432)
    DB_NAME       — Database name            (default: reputation_db)
    DB_USER       — Database user
    DB_PASSWORD   — Database password
    DB_MIN_CONN   — Minimum connection pool  (default: 1)
    DB_MAX_CONN   — Maximum connection pool  (default: 5)
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from pathlib import Path
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Load environment files once at import time.
# .env       contains PostgreSQL credentials (UDR_DB_* variables).
# api.env    contains VT_API_KEYS / OTX_API_KEYS for online TI providers.
# Both are loaded here so this module works whether imported standalone or
# from run_live_pipeline.py (which already loaded api.env before importing).
# ---------------------------------------------------------------------------
_THIS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _THIS_DIR.parents[2]  # labeler/intel/reputation/ → project root

load_dotenv(_PROJECT_ROOT / ".env", override = True)
load_dotenv(_PROJECT_ROOT / "api.env", override = True)


@dataclass(frozen=True)
class DatabaseConfig:
    """Immutable configuration container for the PostgreSQL connection."""

    host: str = field(default_factory=lambda: os.getenv("UDR_DB_HOST", "localhost"))
    port: int = field(
        default_factory=lambda: int(os.getenv("UDR_DB_PORT", "5432"))
    )
    dbname: str = field(
        default_factory=lambda: os.getenv("UDR_DB_DATABASE", "dns_threat_detection")
    )
    user: str = field(default_factory=lambda: os.getenv("UDR_DB_USERNAME", ""))
    password: str = field(default_factory=lambda: os.getenv("UDR_DB_PASSWORD", ""))
    min_conn: int = field(
        default_factory=lambda: int(os.getenv("UDR_DB_MIN_CONNECTIONS", "2"))
    )
    max_conn: int = field(
        default_factory=lambda: int(os.getenv("UDR_DB_MAX_CONNECTIONS", "10"))
    )

    @property
    def dsn(self) -> str:
        """Return a PostgreSQL DSN string built from the config fields."""
        return (
            f"host={self.host} port={self.port} "
            f"dbname={self.dbname} user={self.user} password={self.password}"
        )

    def validate(self) -> None:
        """Raise ValueError if required credentials are missing."""
        missing: list[str] = []
        if not self.user:
            missing.append("UDR_DB_USERNAME")
        if not self.password:
            missing.append("UDR_DB_PASSWORD")
        if missing:
            raise ValueError(
                f"Missing required environment variable(s): {', '.join(missing)}. "
                "Create a .env file. See .env.example."
            )


# ---------------------------------------------------------------------------
# Module-level singleton — importers share one config instance
# ---------------------------------------------------------------------------
config: DatabaseConfig = DatabaseConfig()
