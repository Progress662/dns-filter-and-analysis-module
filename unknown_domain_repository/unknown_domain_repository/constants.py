"""
Constants and enumerations for the unknown domain repository subsystem.
"""

from enum import Enum
import re
from typing import Final, List, Tuple


# ---------------------------------------------------------------------------
# Schema Versioning
# ---------------------------------------------------------------------------

SCHEMA_VERSION: Final[int] = 2


# ---------------------------------------------------------------------------
# Database Schema Constants
# ---------------------------------------------------------------------------

SCHEMA_NAME: Final[str] = "public"
DOMAIN_TABLE_NAME: Final[str] = "unknown_domains"

COLUMN_ID: Final[str] = "id"
COLUMN_DOMAIN: Final[str] = "domain"
COLUMN_FIRST_SEEN: Final[str] = "first_seen"
COLUMN_LAST_SEEN: Final[str] = "last_seen"
COLUMN_SOURCE: Final[str] = "source"
COLUMN_STATUS: Final[str] = "status"
COLUMN_METADATA: Final[str] = "metadata"
COLUMN_CREATED_AT: Final[str] = "created_at"
COLUMN_UPDATED_AT: Final[str] = "updated_at"
COLUMN_SCHEMA_VERSION: Final[str] = "schema_version"

ALL_COLUMNS: Final[Tuple[str, ...]] = (
    COLUMN_ID,
    COLUMN_DOMAIN,
    COLUMN_FIRST_SEEN,
    COLUMN_LAST_SEEN,
    COLUMN_SOURCE,
    COLUMN_STATUS,
    COLUMN_METADATA,
    COLUMN_CREATED_AT,
    COLUMN_UPDATED_AT,
    COLUMN_SCHEMA_VERSION,
)

INSERT_COLUMNS: Final[Tuple[str, ...]] = (
    COLUMN_DOMAIN,
    COLUMN_FIRST_SEEN,
    COLUMN_LAST_SEEN,
    COLUMN_SOURCE,
    COLUMN_STATUS,
    COLUMN_METADATA,
    COLUMN_CREATED_AT,
    COLUMN_UPDATED_AT,
    COLUMN_SCHEMA_VERSION,
)

UPSERT_CONFLICT_COLUMNS: Final[Tuple[str, ...]] = (COLUMN_DOMAIN,)
UPSERT_UPDATE_COLUMNS: Final[Tuple[str, ...]] = (
    COLUMN_LAST_SEEN,
    COLUMN_STATUS,
    COLUMN_METADATA,
    COLUMN_UPDATED_AT,
)

DOMAIN_TABLE_ID_SEQUENCE: Final[str] = f"{DOMAIN_TABLE_NAME}_{COLUMN_ID}_seq"


# ---------------------------------------------------------------------------
# Default Values
# ---------------------------------------------------------------------------

DEFAULT_BATCH_SIZE: Final[int] = 1000
MAX_BATCH_SIZE: Final[int] = 10000
DEFAULT_RETRY_COUNT: Final[int] = 3
DEFAULT_RETRY_DELAY_SECONDS: Final[float] = 1.0
DEFAULT_RETRY_BACKOFF_FACTOR: Final[float] = 2.0


# ---------------------------------------------------------------------------
# Domain Status Enum
# ---------------------------------------------------------------------------

class DomainStatus(str, Enum):
    NEW = "new"
    PROCESSING = "processing"
    MALICIOUS = "malicious"
    CLEAN = "clean"
    REVIEW_NEEDED = "review_needed"
    ERROR = "error"
    
    @classmethod
    def list_values(cls) -> List[str]:
        return [member.value for member in cls]


# ---------------------------------------------------------------------------
# Domain Source Enum
# ---------------------------------------------------------------------------

class DomainSource(str, Enum):
    DNS_QUERY_LOG = "dns_query_log"
    MANUAL_IMPORT = "manual_import"
    SYSTEM_TEST = "system_test"
    
    @classmethod
    def list_values(cls) -> List[str]:
        return [member.value for member in cls]


# ---------------------------------------------------------------------------
# Logging Constants
# ---------------------------------------------------------------------------

LOG_COMPONENT_NAME: Final[str] = "unknown_domain_repository"
LOG_MESSAGE_DOMAIN_INSERTED: Final[str] = "Domain inserted successfully"
LOG_MESSAGE_DOMAIN_UPSERTED: Final[str] = "Domain upserted successfully"
LOG_MESSAGE_BATCH_INSERTED: Final[str] = "Batch of domains inserted"
LOG_MESSAGE_CONNECTION_FAILED: Final[str] = "Failed to acquire database connection"
LOG_MESSAGE_QUERY_FAILED: Final[str] = "Database query failed"
LOG_MESSAGE_POOL_EXHAUSTED: Final[str] = "Connection pool exhausted"
LOG_MESSAGE_SCHEMA_CREATED: Final[str] = "Database schema created/verified"
LOG_MESSAGE_MIGRATION_APPLIED: Final[str] = "Migration applied successfully"
LOG_MESSAGE_HEALTH_CHECK_FAILED: Final[str] = "Health check failed"


# ---------------------------------------------------------------------------
# Error Messages
# ---------------------------------------------------------------------------

ERROR_DOMAIN_EXISTS: Final[str] = "Domain already exists in repository"
ERROR_DOMAIN_NOT_FOUND: Final[str] = "Domain not found in repository"
ERROR_DOMAIN_INVALID: Final[str] = "Domain name is invalid"
ERROR_DATABASE_CONNECTION: Final[str] = "Failed to connect to database"
ERROR_TRANSACTION_FAILED: Final[str] = "Transaction failed, rolling back"
ERROR_POOL_INITIALIZATION: Final[str] = "Failed to initialize connection pool"
ERROR_SCHEMA_CREATION: Final[str] = "Failed to create database schema"
ERROR_MIGRATION_FAILED: Final[str] = "Database migration failed"
ERROR_HEALTH_CHECK_FAILED: Final[str] = "Health check failed"
ERROR_CONFIG_INVALID: Final[str] = "Invalid configuration"


# ---------------------------------------------------------------------------
# Performance Indicators
# ---------------------------------------------------------------------------

PERF_BATCH_INSERT_THRESHOLD_MS: Final[int] = 500
PERF_UPSERT_THRESHOLD_MS: Final[int] = 100


# ---------------------------------------------------------------------------
# Testing Constants
# ---------------------------------------------------------------------------

TEST_DOMAIN_COUNT: Final[int] = 1000
INTEGRATION_TEST_DATABASE_NAME: Final[str] = "test_unknown_domains"


# ===========================================================================
# *** CRITICAL SECTION ***
# These three symbols MUST be exported for utils.py to work
# ===========================================================================

# Maximum total length for domain names per RFC 1035
DOMAIN_LENGTH_MAX: Final[int] = 253

# Maximum length for individual domain labels per RFC 1035
DOMAIN_LABEL_MAX: Final[int] = 63

# Compiled regex pattern for validating domain name structure
# Matches RFC-compliant domains:
# - Labels can contain letters, numbers, hyphens (1-63 chars each)
# - Labels cannot start/end with hyphens
# - Separated by dots
# - Total length <= 253 chars
DOMAIN_PATTERN: Final[re.Pattern] = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$",
    re.IGNORECASE
)