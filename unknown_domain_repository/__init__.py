"""
Unknown Domain Repository - DNS Threat Detection Pipeline Persistence Subsystem

A production-grade Python package for persisting domains not found in known
threat intelligence databases (Tranco, URLhaus). Designed specifically for
integration with DNS threat detection pipelines.
"""

# 1. First, expose the submodules themselves so that 
# 'from unknown_domain_repository.constants import ...' works.
from . import unknown_domain_repository as _inner

import sys
# Link submodules to the top-level namespace
sys.modules[f"{__name__}.config"] = _inner.config
sys.modules[f"{__name__}.constants"] = _inner.constants
sys.modules[f"{__name__}.database"] = _inner.database
sys.modules[f"{__name__}.exceptions"] = _inner.exceptions
sys.modules[f"{__name__}.logger"] = _inner.logger
sys.modules[f"{__name__}.models"] = _inner.models
sys.modules[f"{__name__}.repository"] = _inner.repository
sys.modules[f"{__name__}.service"] = _inner.service
sys.modules[f"{__name__}.utils"] = _inner.utils

# 2. Re-export all public symbols for 'from unknown_domain_repository import ...'
from .unknown_domain_repository import (
    # Main service interface
    UnknownDomainService,
    ProcessingStats,
    create_service,
    
    # Configuration management
    Config,
    DatabaseConfig,
    LoggingConfig,
    BatchConfig,
    load_config,
    
    # Domain models and data structures
    UnknownDomain,
    DomainBatch,
    
    # Constants and enumerations
    DomainStatus,
    DomainSource,
    SCHEMA_VERSION,
    DOMAIN_PATTERN,
    DOMAIN_LENGTH_MAX,
    DOMAIN_LABEL_MAX,
    
    # Advanced interfaces
    DatabaseManager,
    create_database_manager,
    UnknownDomainRepository,
    
    # Exceptions
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
    HealthCheckError,
    
    # Utilities
    is_valid_domain_format,
    normalize_domain,
    extract_root_domain,
    is_private_domain,
    extract_domain_from_url,
    extract_domains_from_text,
    deduplicate_domains,
    
    # Logging
    get_logger,
    initialize_logger
)

# =============================================================================
# Package Metadata
# =============================================================================

__version__ = "1.0.0"
__author__ = "DNS Threat Detection Team"
__description__ = "Production-grade domain persistence for DNS threat detection pipelines"

__all__ = [
    "UnknownDomainService",
    "ProcessingStats",
    "create_service",
    "Config",
    "DatabaseConfig", 
    "LoggingConfig",
    "BatchConfig",
    "load_config",
    "UnknownDomain",
    "DomainBatch",
    "DomainStatus",
    "DomainSource", 
    "SCHEMA_VERSION",
    "DOMAIN_PATTERN",
    "DOMAIN_LENGTH_MAX",
    "DOMAIN_LABEL_MAX",
    "DatabaseManager",
    "create_database_manager",
    "UnknownDomainRepository",
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
    "is_valid_domain_format",
    "normalize_domain",
    "extract_root_domain",
    "is_private_domain", 
    "extract_domain_from_url",
    "extract_domains_from_text",
    "deduplicate_domains",
    "get_logger",
    "initialize_logger"
]

# =============================================================================
# Package-Level Functions
# =============================================================================

def health_check_service(config=None):
    from .unknown_domain_repository.service import health_check_service as _hc
    return _hc(config)

def create_default_service():
    from .unknown_domain_repository.service import create_default_service as _cds
    return _cds()

def configure_package_logging(level="INFO", format="json"):
    from .unknown_domain_repository.logger import initialize_logger
    from .unknown_domain_repository.config import LoggingConfig
    logging_config = LoggingConfig(level=level, format=format)
    initialize_logger(logging_config)