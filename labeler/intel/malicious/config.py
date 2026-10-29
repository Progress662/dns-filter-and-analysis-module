# labeler/intel/malicious/config.py
"""
Configuration constants for the Malicious Domain Database.

Mirrors the configuration structure of the Trusted Database module.
"""

from __future__ import annotations
import os
from pathlib import Path

# --- Database Configuration ---
DB_NAME = "malicious_domains.db"
# Default: sibling 'data/' directory next to this package.
# Override with INTEL_DB_BASE_DIR environment variable.
_PACKAGE_DIR = Path(__file__).resolve().parent
BASE_DIR = os.environ.get(
    "INTEL_DB_BASE_DIR",
    str(_PACKAGE_DIR.parents[2] / "data"),  # labeler/intel/../../data
)
DB_PATH = os.path.join(BASE_DIR, DB_NAME)
NEW_DB_SUFFIX = ".new"
FULL_NEW_DB_PATH = f"{DB_PATH}{NEW_DB_SUFFIX}"

# --- Update Configuration ---
UPDATE_INTERVAL_SECONDS = 86400  # 7 Days in seconds
DEFAULT_UPDATE_INTERVAL_HOURS = 24

# --- Network / Download Configuration ---
DATA_SOURCE_URL = "https://urlhaus.abuse.ch/downloads/csv/"
DOWNLOAD_TIMEOUT = 30
MAX_DOWNLOAD_RETRIES = 3
TEMP_DOWNLOAD_BUFFER_SIZE = 8192
CHECKSUM_ALGORITHM = "sha256"

# --- Performance & Safety ---
MAX_CONNECTIONS = 10
WAL_MODE = True
SYNC_MODE = "NORMAL"
MAP_SIZE_MB = 256

# --- Domain Filtering ---
MIN_DOMAIN_LENGTH = 3
IGNORE_TLDS = set()  # Reserved for future TLD exclusions

# --- Logging ---
LOG_LEVEL = os.environ.get("MALICIOUS_DB_LOG_LEVEL", "INFO")
LOG_FILE = os.path.join(BASE_DIR, "malicious_db.log")
