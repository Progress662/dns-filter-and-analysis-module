"""
Exception classes for the unknown domain repository subsystem.

This module defines a comprehensive exception hierarchy for handling different
types of errors that can occur during domain persistence operations.
All exceptions are designed to provide rich context for debugging while
maintaining security by not exposing sensitive database credentials.
"""

from typing import Optional, Dict, Any, List


class UnknownDomainRepositoryError(Exception):
    """
    Base exception for all unknown domain repository errors.
    
    This is the root exception class that all subsystem-specific exceptions
    inherit from. It provides common functionality for error context and
    structured information useful for logging and debugging.
    
    Attributes:
        operation: The operation being performed when the error occurred.
        context: Additional context information as a dictionary.
    """
    
    def __init__(
        self, 
        message: str, 
        operation: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Initialize the base repository exception.
        
        Args:
            message: Human-readable error description.
            operation: Name of the operation that failed (e.g., 'insert_domain').
            context: Additional context information for debugging.
        """
        super().__init__(message)
        self.operation = operation
        self.context = context or {}
        
    def get_context(self) -> Dict[str, Any]:
        """
        Get structured error context for logging.
        
        Returns:
            Dictionary containing error context information.
        """
        return {
            'error_type': self.__class__.__name__,
            'message': str(self),
            'operation': self.operation,
            'context': self.context
        }


# ---------------------------------------------------------------------------
# Configuration and Initialization Errors
# ---------------------------------------------------------------------------

class ConfigurationError(UnknownDomainRepositoryError):
    """
    Raised when there is an error in configuration parameters.
    
    This exception indicates problems with configuration values such as
    invalid database connection parameters, malformed connection strings,
    or missing required configuration options.
    """
    
    def __init__(
        self, 
        message: str, 
        config_key: Optional[str] = None,
        config_value: Optional[str] = None
    ) -> None:
        """
        Initialize configuration error.
        
        Args:
            message: Description of the configuration problem.
            config_key: The configuration key that caused the error.
            config_value: The problematic value (will be masked if sensitive).
        """
        context = {}
        if config_key:
            context['config_key'] = config_key
        if config_value:
            # Mask potentially sensitive values
            if 'password' in config_key.lower() if config_key else False:
                context['config_value'] = '***'
            else:
                context['config_value'] = config_value
                
        super().__init__(message, operation='configuration_validation', context=context)


class InitializationError(UnknownDomainRepositoryError):
    """
    Raised when the repository subsystem fails to initialize properly.
    
    This includes errors during connection pool setup, schema creation,
    or migration application during startup.
    """
    
    def __init__(self, message: str, component: Optional[str] = None) -> None:
        """
        Initialize initialization error.
        
        Args:
            message: Description of the initialization failure.
            component: The component that failed to initialize.
        """
        context = {}
        if component:
            context['component'] = component
            
        super().__init__(message, operation='initialization', context=context)


# ---------------------------------------------------------------------------
# Database Connection and Pool Errors
# ---------------------------------------------------------------------------

class DatabaseConnectionError(UnknownDomainRepositoryError):
    """
    Raised when database connection establishment fails.
    
    This exception indicates network connectivity issues, authentication
    failures, or database server unavailability.
    """
    
    def __init__(
        self, 
        message: str, 
        host: Optional[str] = None,
        port: Optional[int] = None,
        database: Optional[str] = None
    ) -> None:
        """
        Initialize database connection error.
        
        Args:
            message: Description of the connection failure.
            host: Database host that failed to connect.
            port: Database port used in connection attempt.
            database: Database name used in connection attempt.
        """
        context = {}
        if host:
            context['host'] = host
        if port:
            context['port'] = port
        if database:
            context['database'] = database
            
        super().__init__(message, operation='database_connection', context=context)


class ConnectionPoolError(UnknownDomainRepositoryError):
    """
    Raised when connection pool operations fail.
    
    This includes pool exhaustion, failed pool initialization,
    or errors during connection acquisition/release.
    """
    
    def __init__(
        self, 
        message: str, 
        pool_size: Optional[int] = None,
        active_connections: Optional[int] = None
    ) -> None:
        """
        Initialize connection pool error.
        
        Args:
            message: Description of the pool error.
            pool_size: Maximum pool size.
            active_connections: Number of active connections when error occurred.
        """
        context = {}
        if pool_size is not None:
            context['pool_size'] = pool_size
        if active_connections is not None:
            context['active_connections'] = active_connections
            
        super().__init__(message, operation='connection_pool', context=context)


# ---------------------------------------------------------------------------
# Database Operation Errors
# ---------------------------------------------------------------------------

class DatabaseQueryError(UnknownDomainRepositoryError):
    """
    Raised when database queries fail to execute.
    
    This includes SQL syntax errors, constraint violations,
    deadlocks, and other query execution failures.
    """
    
    def __init__(
        self, 
        message: str, 
        query: Optional[str] = None,
        error_code: Optional[str] = None
    ) -> None:
        """
        Initialize database query error.
        
        Args:
            message: Description of the query failure.
            query: The SQL query that failed (truncated for security).
            error_code: Database-specific error code if available.
        """
        context = {}
        if query:
            # Truncate long queries and remove potential sensitive data
            truncated_query = query[:200] + "..." if len(query) > 200 else query
            context['query'] = truncated_query
        if error_code:
            context['error_code'] = error_code
            
        super().__init__(message, operation='database_query', context=context)


class TransactionError(UnknownDomainRepositoryError):
    """
    Raised when database transaction operations fail.
    
    This includes transaction commit failures, rollback errors,
    and deadlock situations.
    """
    
    def __init__(
        self, 
        message: str, 
        transaction_state: Optional[str] = None
    ) -> None:
        """
        Initialize transaction error.
        
        Args:
            message: Description of the transaction failure.
            transaction_state: Current transaction state when error occurred.
        """
        context = {}
        if transaction_state:
            context['transaction_state'] = transaction_state
            
        super().__init__(message, operation='transaction', context=context)


# ---------------------------------------------------------------------------
# Schema and Migration Errors
# ---------------------------------------------------------------------------

class SchemaError(UnknownDomainRepositoryError):
    """
    Raised when database schema operations fail.
    
    This includes schema creation failures, missing tables,
    and schema validation errors.
    """
    
    def __init__(
        self, 
        message: str, 
        schema_version: Optional[int] = None,
        expected_version: Optional[int] = None
    ) -> None:
        """
        Initialize schema error.
        
        Args:
            message: Description of the schema error.
            schema_version: Current schema version.
            expected_version: Expected schema version.
        """
        context = {}
        if schema_version is not None:
            context['schema_version'] = schema_version
        if expected_version is not None:
            context['expected_version'] = expected_version
            
        super().__init__(message, operation='schema_validation', context=context)


class MigrationError(UnknownDomainRepositoryError):
    """
    Raised when database migration operations fail.
    
    This includes migration script execution failures,
    version conflicts, and rollback errors.
    """
    
    def __init__(
        self, 
        message: str, 
        migration_version: Optional[int] = None,
        migration_file: Optional[str] = None
    ) -> None:
        """
        Initialize migration error.
        
        Args:
            message: Description of the migration failure.
            migration_version: Version number of the failed migration.
            migration_file: Name of the migration file that failed.
        """
        context = {}
        if migration_version is not None:
            context['migration_version'] = migration_version
        if migration_file:
            context['migration_file'] = migration_file
            
        super().__init__(message, operation='migration', context=context)


# ---------------------------------------------------------------------------
# Domain Validation Errors
# ---------------------------------------------------------------------------

class DomainValidationError(UnknownDomainRepositoryError):
    """
    Raised when domain name validation fails.
    
    This includes invalid domain formats, overly long domains,
    and domains containing invalid characters.
    """
    
    def __init__(
        self, 
        message: str, 
        domain: Optional[str] = None,
        validation_rule: Optional[str] = None
    ) -> None:
        """
        Initialize domain validation error.
        
        Args:
            message: Description of the validation failure.
            domain: The invalid domain name.
            validation_rule: The validation rule that failed.
        """
        context = {}
        if domain:
            context['domain'] = domain
        if validation_rule:
            context['validation_rule'] = validation_rule
            
        super().__init__(message, operation='domain_validation', context=context)


class DomainExistsError(UnknownDomainRepositoryError):
    """
    Raised when attempting to insert a domain that already exists.
    
    This is used in strict insertion scenarios where duplicates
    should be treated as errors rather than ignored.
    """
    
    def __init__(self, domain: str) -> None:
        """
        Initialize domain exists error.
        
        Args:
            domain: The domain that already exists.
        """
        message = f"Domain already exists: {domain}"
        context = {'domain': domain}
        super().__init__(message, operation='domain_insert', context=context)


class DomainNotFoundError(UnknownDomainRepositoryError):
    """
    Raised when attempting to operate on a domain that doesn't exist.
    
    This is used in update or query scenarios where the domain
    is expected to exist in the repository.
    """
    
    def __init__(self, domain: str) -> None:
        """
        Initialize domain not found error.
        
        Args:
            domain: The domain that was not found.
        """
        message = f"Domain not found: {domain}"
        context = {'domain': domain}
        super().__init__(message, operation='domain_lookup', context=context)


# ---------------------------------------------------------------------------
# Batch Processing Errors
# ---------------------------------------------------------------------------

class BatchProcessingError(UnknownDomainRepositoryError):
    """
    Raised when batch operations fail.
    
    This includes oversized batches, batch timeout errors,
    and partial batch failures.
    """
    
    def __init__(
        self, 
        message: str, 
        batch_size: Optional[int] = None,
        processed_count: Optional[int] = None,
        failed_domains: Optional[List[str]] = None
    ) -> None:
        """
        Initialize batch processing error.
        
        Args:
            message: Description of the batch processing failure.
            batch_size: Size of the batch being processed.
            processed_count: Number of domains successfully processed.
            failed_domains: List of domains that failed processing.
        """
        context = {}
        if batch_size is not None:
            context['batch_size'] = batch_size
        if processed_count is not None:
            context['processed_count'] = processed_count
        if failed_domains:
            # Limit the number of failed domains in context to prevent huge logs
            context['failed_domains'] = failed_domains[:10]  # First 10 failures
            if len(failed_domains) > 10:
                context['failed_domains_total'] = len(failed_domains)
                
        super().__init__(message, operation='batch_processing', context=context)


# ---------------------------------------------------------------------------
# Repository Operation Errors
# ---------------------------------------------------------------------------

class RepositoryError(UnknownDomainRepositoryError):
    """
    Raised when high-level repository operations fail.
    
    This is a general repository error that encompasses failures
    in the data access layer that don't fit other specific categories.
    """
    
    def __init__(
        self, 
        message: str, 
        repository_operation: Optional[str] = None
    ) -> None:
        """
        Initialize repository error.
        
        Args:
            message: Description of the repository failure.
            repository_operation: Specific repository operation that failed.
        """
        context = {}
        if repository_operation:
            context['repository_operation'] = repository_operation
            
        super().__init__(message, operation='repository', context=context)


# ---------------------------------------------------------------------------
# Health Check Errors
# ---------------------------------------------------------------------------

class HealthCheckError(UnknownDomainRepositoryError):
    """
    Raised when health check operations fail.
    
    This includes database connectivity checks, pool health validation,
    and system readiness verification failures.
    """
    
    def __init__(
        self, 
        message: str, 
        check_type: Optional[str] = None,
        check_details: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Initialize health check error.
        
        Args:
            message: Description of the health check failure.
            check_type: Type of health check that failed.
            check_details: Additional details about the health check failure.
        """
        context = {}
        if check_type:
            context['check_type'] = check_type
        if check_details:
            context['check_details'] = check_details
            
        super().__init__(message, operation='health_check', context=context)