"""
Configuration management for the unknown domain repository subsystem.

This module provides centralized configuration with environment-based overrides,
validation, and type safety. Configurations are immutable after creation.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, Any, Union
from urllib.parse import urlparse
from dotenv import load_dotenv
load_dotenv()


@dataclass(frozen=True)
class DatabaseConfig:
    """
    Database connection and pool configuration.
    
    All parameters support environment variable overrides using the pattern:
    UDR_DB_<PARAMETER_NAME> (e.g., UDR_DB_HOST, UDR_DB_PASSWORD)
    """
    
    host: str = field(default_factory=lambda: os.getenv('UDR_DB_HOST', 'localhost'))
    port: int = field(default_factory=lambda: int(os.getenv('UDR_DB_PORT', '5432')))
    database: str = field(default_factory=lambda: os.getenv('UDR_DB_DATABASE', 'dns_threats'))
    username: str = field(default_factory=lambda: os.getenv('UDR_DB_USERNAME', 'dns_user'))
    password: str = field(default_factory=lambda: os.getenv('UDR_DB_PASSWORD', ''))
    
    # Connection Pool Settings
    min_connections: int = field(default_factory=lambda: int(os.getenv('UDR_DB_MIN_CONNECTIONS', '2')))
    max_connections: int = field(default_factory=lambda: int(os.getenv('UDR_DB_MAX_CONNECTIONS', '20')))
    max_idle_time: float = field(default_factory=lambda: float(os.getenv('UDR_DB_MAX_IDLE_TIME', '300.0')))
    
    # Connection Timeout Settings  
    connect_timeout: float = field(default_factory=lambda: float(os.getenv('UDR_DB_CONNECT_TIMEOUT', '10.0')))
    command_timeout: float = field(default_factory=lambda: float(os.getenv('UDR_DB_COMMAND_TIMEOUT', '30.0')))
    
    # Retry Configuration
    max_retries: int = field(default_factory=lambda: int(os.getenv('UDR_DB_MAX_RETRIES', '3')))
    retry_delay: float = field(default_factory=lambda: float(os.getenv('UDR_DB_RETRY_DELAY', '1.0')))
    retry_backoff: float = field(default_factory=lambda: float(os.getenv('UDR_DB_RETRY_BACKOFF', '2.0')))
    
    # SSL Configuration
    sslmode: str = field(default_factory=lambda: os.getenv('UDR_DB_SSLMODE', 'prefer'))
    sslcert: Optional[str] = field(default_factory=lambda: os.getenv('UDR_DB_SSLCERT'))
    sslkey: Optional[str] = field(default_factory=lambda: os.getenv('UDR_DB_SSLKEY'))
    sslrootcert: Optional[str] = field(default_factory=lambda: os.getenv('UDR_DB_SSLROOTCERT'))
    
    def __post_init__(self) -> None:
        """Validate configuration parameters after initialization."""
        self._validate()
    
    def _validate(self) -> None:
        """
        Validate database configuration parameters.
        
        Raises:
            ValueError: If any configuration parameter is invalid.
        """
        if not self.host:
            raise ValueError("Database host cannot be empty")
        
        if not (1 <= self.port <= 65535):
            raise ValueError(f"Database port must be between 1 and 65535, got {self.port}")
        
        if not self.database:
            raise ValueError("Database name cannot be empty")
        
        if not self.username:
            raise ValueError("Database username cannot be empty")
        
        if not self.password:
            raise ValueError("Database password cannot be empty")
        
        if self.min_connections < 1:
            raise ValueError(f"Minimum connections must be >= 1, got {self.min_connections}")
        
        if self.max_connections < self.min_connections:
            raise ValueError(
                f"Maximum connections ({self.max_connections}) must be >= "
                f"minimum connections ({self.min_connections})"
            )
        
        if self.max_idle_time <= 0:
            raise ValueError(f"Max idle time must be > 0, got {self.max_idle_time}")
        
        if self.connect_timeout <= 0:
            raise ValueError(f"Connect timeout must be > 0, got {self.connect_timeout}")
        
        if self.command_timeout <= 0:
            raise ValueError(f"Command timeout must be > 0, got {self.command_timeout}")
        
        if self.max_retries < 0:
            raise ValueError(f"Max retries must be >= 0, got {self.max_retries}")
        
        if self.retry_delay < 0:
            raise ValueError(f"Retry delay must be >= 0, got {self.retry_delay}")
        
        if self.retry_backoff <= 0:
            raise ValueError(f"Retry backoff must be > 0, got {self.retry_backoff}")
        
        valid_ssl_modes = {'disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full'}
        if self.sslmode not in valid_ssl_modes:
            raise ValueError(f"Invalid SSL mode '{self.sslmode}'. Must be one of {valid_ssl_modes}")
        
        # Validate SSL file paths if provided
        for ssl_file, name in [(self.sslcert, 'sslcert'), (self.sslkey, 'sslkey'), (self.sslrootcert, 'sslrootcert')]:
            if ssl_file and not Path(ssl_file).is_file():
                raise ValueError(f"SSL file {name} does not exist: {ssl_file}")
    
    def get_connection_string(self, mask_password: bool = True) -> str:
        """
        Generate PostgreSQL connection string.
        
        Args:
            mask_password: Whether to mask the password in the connection string.
            
        Returns:
            PostgreSQL connection string.
        """
        password = '***' if mask_password else self.password
        
        conn_str = (
            f"postgresql://{self.username}:{password}@{self.host}:{self.port}/{self.database}"
            f"?sslmode={self.sslmode}"
        )
        
        if self.sslcert:
            conn_str += f"&sslcert={self.sslcert}"
        if self.sslkey:
            conn_str += f"&sslkey={self.sslkey}"
        if self.sslrootcert:
            conn_str += f"&sslrootcert={self.sslrootcert}"
        
        return conn_str
    
    def get_connection_kwargs(self) -> Dict[str, Any]:
        """
        Get connection parameters as a dictionary for psycopg3.
        
        Returns:
            Dictionary of connection parameters.
        """
        kwargs = {
            'host': self.host,
            'port': self.port,
            'dbname': self.database,
            'user': self.username,
            'password': self.password,
            'connect_timeout': self.connect_timeout,
            'sslmode': self.sslmode,
        }
        
        if self.sslcert:
            kwargs['sslcert'] = self.sslcert
        if self.sslkey:
            kwargs['sslkey'] = self.sslkey
        if self.sslrootcert:
            kwargs['sslrootcert'] = self.sslrootcert
        
        return kwargs


@dataclass(frozen=True)
class LoggingConfig:
    """
    Logging configuration with structured output support.
    
    Environment variables:
    - UDR_LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    - UDR_LOG_FORMAT: Log format (json, text)
    - UDR_LOG_FILE: Log file path (optional)
    """
    
    level: str = field(default_factory=lambda: os.getenv('UDR_LOG_LEVEL', 'INFO'))
    format: str = field(default_factory=lambda: os.getenv('UDR_LOG_FORMAT', 'json'))
    file_path: Optional[str] = field(default_factory=lambda: os.getenv('UDR_LOG_FILE'))
    max_file_size: int = field(default_factory=lambda: int(os.getenv('UDR_LOG_MAX_FILE_SIZE', '10485760')))  # 10MB
    backup_count: int = field(default_factory=lambda: int(os.getenv('UDR_LOG_BACKUP_COUNT', '5')))
    
    def __post_init__(self) -> None:
        """Validate logging configuration after initialization."""
        self._validate()
    
    def _validate(self) -> None:
        """
        Validate logging configuration parameters.
        
        Raises:
            ValueError: If any configuration parameter is invalid.
        """
        valid_levels = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
        if self.level.upper() not in valid_levels:
            raise ValueError(f"Invalid log level '{self.level}'. Must be one of {valid_levels}")
        
        valid_formats = {'json', 'text'}
        if self.format.lower() not in valid_formats:
            raise ValueError(f"Invalid log format '{self.format}'. Must be one of {valid_formats}")
        
        if self.max_file_size <= 0:
            raise ValueError(f"Max file size must be > 0, got {self.max_file_size}")
        
        if self.backup_count < 0:
            raise ValueError(f"Backup count must be >= 0, got {self.backup_count}")
        
        if self.file_path:
            file_path = Path(self.file_path)
            if not file_path.parent.exists():
                raise ValueError(f"Log file directory does not exist: {file_path.parent}")


@dataclass(frozen=True)
class BatchConfig:
    """
    Batch processing configuration for optimal performance.
    
    Environment variables:
    - UDR_BATCH_SIZE: Number of domains to process in a single batch
    - UDR_BATCH_TIMEOUT: Maximum time to wait for a batch to fill
    - UDR_BATCH_MAX_MEMORY: Maximum memory usage before forcing batch processing
    """
    
    size: int = field(default_factory=lambda: int(os.getenv('UDR_BATCH_SIZE', '1000')))
    timeout: float = field(default_factory=lambda: float(os.getenv('UDR_BATCH_TIMEOUT', '5.0')))
    max_memory_mb: int = field(default_factory=lambda: int(os.getenv('UDR_BATCH_MAX_MEMORY', '100')))
    
    def __post_init__(self) -> None:
        """Validate batch configuration after initialization."""
        self._validate()
    
    def _validate(self) -> None:
        """
        Validate batch configuration parameters.
        
        Raises:
            ValueError: If any configuration parameter is invalid.
        """
        if self.size <= 0:
            raise ValueError(f"Batch size must be > 0, got {self.size}")
        
        if self.timeout <= 0:
            raise ValueError(f"Batch timeout must be > 0, got {self.timeout}")
        
        if self.max_memory_mb <= 0:
            raise ValueError(f"Max memory must be > 0, got {self.max_memory_mb}")


@dataclass(frozen=True)
class Config:
    """
    Main configuration class that combines all subsystem configurations.
    
    This is the primary configuration object used throughout the application.
    """
    
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    batch: BatchConfig = field(default_factory=BatchConfig)
    
    # Environment and debugging
    environment: str = field(default_factory=lambda: os.getenv('UDR_ENVIRONMENT', 'development'))
    debug: bool = field(default_factory=lambda: os.getenv('UDR_DEBUG', 'false').lower() == 'true')
    
    def __post_init__(self) -> None:
        """Validate main configuration after initialization."""
        self._validate()
    
    def _validate(self) -> None:
        """
        Validate main configuration parameters.
        
        Raises:
            ValueError: If any configuration parameter is invalid.
        """
        valid_environments = {'development', 'testing', 'staging', 'production'}
        if self.environment.lower() not in valid_environments:
            raise ValueError(f"Invalid environment '{self.environment}'. Must be one of {valid_environments}")
    
    @classmethod
    def from_env(cls) -> 'Config':
        """
        Create configuration from environment variables.
        
        Returns:
            Configured Config instance.
        """
        return cls()
    
    def to_dict(self, mask_secrets: bool = True) -> Dict[str, Any]:
        """
        Convert configuration to dictionary for logging or debugging.
        
        Args:
            mask_secrets: Whether to mask sensitive information.
            
        Returns:
            Configuration as a dictionary.
        """
        return {
            'environment': self.environment,
            'debug': self.debug,
            'database': {
                'host': self.database.host,
                'port': self.database.port,
                'database': self.database.database,
                'username': self.database.username,
                'password': '***' if mask_secrets else self.database.password,
                'min_connections': self.database.min_connections,
                'max_connections': self.database.max_connections,
                'max_idle_time': self.database.max_idle_time,
                'connect_timeout': self.database.connect_timeout,
                'command_timeout': self.database.command_timeout,
                'max_retries': self.database.max_retries,
                'retry_delay': self.database.retry_delay,
                'retry_backoff': self.database.retry_backoff,
                'sslmode': self.database.sslmode,
            },
            'logging': {
                'level': self.logging.level,
                'format': self.logging.format,
                'file_path': self.logging.file_path,
                'max_file_size': self.logging.max_file_size,
                'backup_count': self.logging.backup_count,
            },
            'batch': {
                'size': self.batch.size,
                'timeout': self.batch.timeout,
                'max_memory_mb': self.batch.max_memory_mb,
            }
        }


def load_config() -> Config:
    """
    Load and validate configuration from environment variables.
    
    This is the primary function used to initialize the configuration
    throughout the application.
    
    Returns:
        Validated Config instance.
        
    Raises:
        ValueError: If any configuration parameter is invalid.
    """
    try:
        return Config.from_env()
    except Exception as e:
        raise ValueError(f"Failed to load configuration: {e}") from e