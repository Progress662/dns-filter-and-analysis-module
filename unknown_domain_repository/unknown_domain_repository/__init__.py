"""
Unknown Domain Repository - DNS Threat Detection Pipeline Persistence Subsystem

A production-grade Python package for persisting domains not found in known
threat intelligence databases (Tranco, URLhaus). Designed specifically for
integration with DNS threat detection pipelines.
"""

from typing import List, Dict, Any, Optional, Tuple, Union

# Package metadata
__version__ = "1.0.0"
__author__ = "DNS Threat Detection Team"
__email__ = "security-team@your-organization.com"
__description__ = "Production-grade domain persistence for DNS threat detection pipelines"
__url__ = "https://github.com/your-org/unknown-domain-repository"

# =============================================================================
# Core API Imports
# =============================================================================

# Main service interface - primary entry point for most users
from .service import (
    UnknownDomainService,
    ProcessingStats,
    create_service
)

# Configuration management
from .config import (
    Config,
    DatabaseConfig,
    LoggingConfig,
    BatchConfig,
    load_config
)

# Domain models and data structures
from .models import (
    UnknownDomain,
    DomainBatch
)

# Constants and enumerations
# FIX: Added DOMAIN_PATTERN, DOMAIN_LENGTH_MAX, and DOMAIN_LABEL_MAX here
from .constants import (
    DomainStatus,
    DomainSource,
    SCHEMA_VERSION,
    DOMAIN_PATTERN,
    DOMAIN_LENGTH_MAX,
    DOMAIN_LABEL_MAX
)

# =============================================================================
# Advanced API Imports (for specialized use cases)
# =============================================================================

# Database layer (for advanced database operations)
from .database import (
    DatabaseManager,
    create_database_manager
)

# Repository layer (for custom data access patterns)
from .repository import (
    UnknownDomainRepository
)

# =============================================================================
# Exception Classes
# =============================================================================

from .exceptions import (
    UnknownDomainRepositoryError,
    ConfigurationError,
    InitializationError,
    DatabaseConnectionError,
    ConnectionPoolError,
    DatabaseQueryError,
    TransactionError,
    SchemaError,
    MigrationError,
    DomainValidationError,
    DomainExistsError,
    DomainNotFoundError,
    BatchProcessingError,
    RepositoryError,
    HealthCheckError
)

# =============================================================================
# Utility Functions
# =============================================================================

from .utils import (
    is_valid_domain_format,
    normalize_domain,
    extract_root_domain,
    is_private_domain,
    extract_domain_from_url,
    extract_domains_from_text,
    deduplicate_domains
)

# =============================================================================
# Logging Setup
# =============================================================================

from .logger import (
    get_logger,
    initialize_logger
)

# =============================================================================
# Public API Definition
# =============================================================================

__all__ = [
    # Version and metadata
    "__version__",
    "__author__", 
    "__description__",
    
    # Main service interface
    "UnknownDomainService",
    "ProcessingStats",
    "create_service",
    
    # Configuration
    "Config",
    "DatabaseConfig", 
    "LoggingConfig",
    "BatchConfig",
    "load_config",
    
    # Models and data structures
    "UnknownDomain",
    "DomainBatch",
    
    # Constants and enums
    "DomainStatus",
    "DomainSource", 
    "SCHEMA_VERSION",
    "DOMAIN_PATTERN",     # Added to __all__
    "DOMAIN_LENGTH_MAX",  # Added to __all__
    "DOMAIN_LABEL_MAX",   # Added to __all__
    
    # Advanced interfaces
    "DatabaseManager",
    "create_database_manager",
    "UnknownDomainRepository",
    
    # Exceptions
    "UnknownDomainRepositoryError",
    "ConfigurationError",
    "InitializationError", 
    "DatabaseConnectionError",
    "ConnectionPoolError",
    "DatabaseQueryError",
    "TransactionError",
    "SchemaError",
    "MigrationError",
    "DomainValidationError",
    "DomainExistsError",
    "DomainNotFoundError", 
    "BatchProcessingError",
    "RepositoryError",
    "HealthCheckError",
    
    # Utilities
    "is_valid_domain_format",
    "normalize_domain",
    "extract_root_domain",
    "is_private_domain", 
    "extract_domain_from_url",
    "extract_domains_from_text",
    "deduplicate_domains",
    
    # Logging
    "get_logger",
    "initialize_logger"
]

# =============================================================================
# Package-Level Functions
# =============================================================================

def get_version_info() -> Dict[str, Any]:
    return {
        "version": __version__,
        "author": __author__,
        "description": __description__,
        "url": __url__,
        "schema_version": SCHEMA_VERSION,
        "supported_python": ">=3.8",
        "dependencies": {
            "psycopg": ">=3.0.0",
            "psycopg_pool": ">=3.0.0"
        }
    }


def health_check_service(config: Optional[Config] = None) -> Dict[str, Any]:
    try:
        if config is None:
            config = load_config()
        with create_database_manager(config) as db_manager:
            health_info = db_manager.health_check(timeout=5.0)
        return {
            "package_healthy": health_info.get("healthy", False),
            "package_version": __version__,
            "schema_version": SCHEMA_VERSION,
            "database_health": health_info,
            "configuration": config.to_dict(mask_secrets=True)
        }
    except Exception as e:
        return {
            "package_healthy": False,
            "package_version": __version__,
            "error": str(e),
            "error_type": type(e).__name__
        }


def create_default_service() -> UnknownDomainService:
    config = load_config()
    return create_service(config)


def configure_package_logging(level: str = "INFO", format: str = "json") -> None:
    from .config import LoggingConfig
    try:
        logging_config = LoggingConfig(level=level, format=format)
        initialize_logger(logging_config)
    except Exception as e:
        import logging
        logging.basicConfig(
            level=getattr(logging, level.upper(), logging.INFO),
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )


def create_pipeline_integration(config: Optional[Config] = None) -> 'PipelineIntegration':
    if config is None:
        config = load_config()
    return PipelineIntegration(config)


class PipelineIntegration:
    def __init__(self, config: Config):
        self.config = config
        self._service: Optional[UnknownDomainService] = None
    
    def __enter__(self) -> 'PipelineIntegration':
        self._service = create_service(self.config)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        if self._service:
            self._service.shutdown()
            self._service = None
    
    def store_unknown_domains(
        self,
        domains: List[str],
        source: Union[str, DomainSource] = DomainSource.DNS_QUERY_LOG
    ) -> ProcessingStats:
        if not self._service:
            raise RuntimeError("Service not initialized - use within context manager")
        if isinstance(source, str):
            source = DomainSource(source)
        return self._service.process_domains(domains, source=source, batch_process=True)

# Run version check on import
import sys
if sys.version_info < (3, 8):
    import warnings
    warnings.warn(
        "Python versions below 3.8 are not officially supported.",
        DeprecationWarning,
        stacklevel=2
    )