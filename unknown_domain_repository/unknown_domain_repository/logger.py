"""
Structured logging system for the unknown domain repository subsystem.

This module provides production-grade logging with structured output,
contextual information, performance timing, and integration with
the custom exception hierarchy.
"""

import json
import logging
import logging.handlers
import time
import threading
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, Optional, Union, Generator
from pathlib import Path

from .config import LoggingConfig
from .constants import LOG_COMPONENT_NAME
from .exceptions import UnknownDomainRepositoryError


class StructuredFormatter(logging.Formatter):
    """
    Custom formatter for structured JSON logging.
    
    Produces consistent JSON output with standardized fields
    for integration with log aggregation systems.
    """
    
    def __init__(self, component: str = LOG_COMPONENT_NAME) -> None:
        """
        Initialize structured formatter.
        
        Args:
            component: Component name for log filtering.
        """
        super().__init__()
        self.component = component
        
    def format(self, record: logging.LogRecord) -> str:
        """
        Format log record as structured JSON.
        
        Args:
            record: Log record to format.
            
        Returns:
            JSON string representation of the log record.
        """
        # Base log structure
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'component': self.component,
            'logger': record.name,
            'message': record.getMessage(),
        }
        
        # Add thread information for concurrent operations
        if hasattr(record, 'thread') and record.thread:
            log_entry['thread_id'] = record.thread
            
        # Add process information
        if hasattr(record, 'process') and record.process:
            log_entry['process_id'] = record.process
            
        # Add exception information if present
        if record.exc_info:
            log_entry['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': self.formatException(record.exc_info)
            }
            
        # Add custom fields from extra parameter
        extra_fields = {}
        for key, value in record.__dict__.items():
            if key not in {'name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'lineno', 'funcName', 'created',
                          'msecs', 'relativeCreated', 'thread', 'threadName',
                          'processName', 'process', 'getMessage', 'exc_info',
                          'exc_text', 'stack_info'}:
                extra_fields[key] = value
                
        if extra_fields:
            log_entry['extra'] = extra_fields
            
        # Handle custom exception context
        if hasattr(record, 'exception_context'):
            log_entry['exception_context'] = record.exception_context
            
        try:
            return json.dumps(log_entry, ensure_ascii=False, default=str)
        except (TypeError, ValueError) as e:
            # Fallback to basic format if JSON serialization fails
            return f"JSON_SERIALIZE_ERROR: {log_entry.get('message', '')} - {e}"


class TextFormatter(logging.Formatter):
    """
    Custom formatter for human-readable text logging.
    
    Provides readable format for development and console output.
    """
    
    def __init__(self, component: str = LOG_COMPONENT_NAME) -> None:
        """
        Initialize text formatter.
        
        Args:
            component: Component name for log identification.
        """
        format_string = (
            f'%(asctime)s - {component} - %(name)s - %(levelname)s - %(message)s'
        )
        super().__init__(format_string, datefmt='%Y-%m-%d %H:%M:%S')


class RepositoryLogger:
    """
    Main logger class for the unknown domain repository subsystem.
    
    Provides structured logging with contextual information,
    performance timing, and integration with custom exceptions.
    """
    
    def __init__(self, config: LoggingConfig, name: str = LOG_COMPONENT_NAME) -> None:
        """
        Initialize repository logger.
        
        Args:
            config: Logging configuration.
            name: Logger name.
        """
        self.config = config
        self.logger = logging.getLogger(name)
        self._configure_logger()
        self._local = threading.local()
        
    def _configure_logger(self) -> None:
        """Configure logger with handlers and formatters based on config."""
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Set log level
        self.logger.setLevel(getattr(logging, self.config.level.upper()))
        
        # Prevent duplicate logs from propagating to root logger
        self.logger.propagate = False
        
        # Choose formatter based on configuration
        if self.config.format.lower() == 'json':
            formatter = StructuredFormatter()
        else:
            formatter = TextFormatter()
            
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # File handler with rotation if file path is configured
        if self.config.file_path:
            try:
                # Ensure directory exists
                Path(self.config.file_path).parent.mkdir(parents=True, exist_ok=True)
                
                file_handler = logging.handlers.RotatingFileHandler(
                    self.config.file_path,
                    maxBytes=self.config.max_file_size,
                    backupCount=self.config.backup_count,
                    encoding='utf-8'
                )
                file_handler.setFormatter(formatter)
                self.logger.addHandler(file_handler)
            except (OSError, IOError) as e:
                # Log to console if file handler fails
                self.logger.error(
                    "Failed to configure file logging",
                    extra={'file_path': self.config.file_path, 'error': str(e)}
                )
    
    def _get_context(self) -> Dict[str, Any]:
        """
        Get current logging context from thread-local storage.
        
        Returns:
            Dictionary of contextual information.
        """
        return getattr(self._local, 'context', {})
    
    def _set_context(self, context: Dict[str, Any]) -> None:
        """
        Set logging context in thread-local storage.
        
        Args:
            context: Context dictionary to set.
        """
        self._local.context = context
    
    def _merge_extra(self, extra: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Merge additional context with current thread context.
        
        Args:
            extra: Additional context to merge.
            
        Returns:
            Merged context dictionary.
        """
        base_context = self._get_context()
        if extra:
            merged = base_context.copy()
            merged.update(extra)
            return merged
        return base_context
    
    @contextmanager
    def operation_context(
        self, 
        operation: str, 
        **kwargs: Any
    ) -> Generator[None, None, None]:
        """
        Context manager for adding operation context to logs.
        
        Args:
            operation: Operation name.
            **kwargs: Additional context parameters.
            
        Yields:
            None
        """
        old_context = self._get_context()
        new_context = old_context.copy()
        new_context.update({
            'operation': operation,
            **kwargs
        })
        
        self._set_context(new_context)
        try:
            yield
        finally:
            self._set_context(old_context)
    
    @contextmanager
    def timed_operation(
        self, 
        operation: str, 
        log_level: int = logging.INFO,
        threshold_ms: Optional[int] = None,
        **kwargs: Any
    ) -> Generator[None, None, None]:
        """
        Context manager for timing operations and automatic logging.
        
        Args:
            operation: Operation name for logging.
            log_level: Log level for timing information.
            threshold_ms: Log as warning if operation exceeds this threshold.
            **kwargs: Additional context parameters.
            
        Yields:
            None
        """
        start_time = time.perf_counter()
        
        with self.operation_context(operation, **kwargs):
            try:
                yield
                success = True
            except Exception as e:
                success = False
                self.exception(
                    f"Operation '{operation}' failed",
                    extra={'operation': operation, 'success': False, **kwargs}
                )
                raise
            finally:
                duration_ms = (time.perf_counter() - start_time) * 1000
                
                log_extra = {
                    'operation': operation,
                    'duration_ms': round(duration_ms, 2),
                    'success': success,
                    **kwargs
                }
                
                # Log as warning if threshold exceeded
                if threshold_ms and duration_ms > threshold_ms:
                    self.warning(
                        f"Operation '{operation}' exceeded threshold ({duration_ms:.2f}ms > {threshold_ms}ms)",
                        extra=log_extra
                    )
                else:
                    self.log(
                        log_level,
                        f"Operation '{operation}' completed in {duration_ms:.2f}ms",
                        extra=log_extra
                    )
    
    def log_exception(
        self, 
        exception: UnknownDomainRepositoryError, 
        message: Optional[str] = None
    ) -> None:
        """
        Log custom exceptions with structured context.
        
        Args:
            exception: Custom exception to log.
            message: Optional override message.
        """
        log_message = message or str(exception)
        context = exception.get_context()
        
        self.error(
            log_message,
            extra={'exception_context': context},
            exc_info=True
        )
    
    # Standard logging methods with context support
    
    def debug(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log debug message with context."""
        self.logger.debug(message, extra=self._merge_extra(extra))
    
    def info(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log info message with context."""
        self.logger.info(message, extra=self._merge_extra(extra))
    
    def warning(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log warning message with context."""
        self.logger.warning(message, extra=self._merge_extra(extra))
    
    def error(
        self, 
        message: str, 
        extra: Optional[Dict[str, Any]] = None,
        exc_info: bool = False
    ) -> None:
        """Log error message with context."""
        self.logger.error(message, extra=self._merge_extra(extra), exc_info=exc_info)
    
    def critical(
        self, 
        message: str, 
        extra: Optional[Dict[str, Any]] = None,
        exc_info: bool = False
    ) -> None:
        """Log critical message with context."""
        self.logger.critical(message, extra=self._merge_extra(extra), exc_info=exc_info)
    
    def exception(self, message: str, extra: Optional[Dict[str, Any]] = None) -> None:
        """Log exception message with context and traceback."""
        self.logger.exception(message, extra=self._merge_extra(extra))
    
    def log(
        self, 
        level: int, 
        message: str, 
        extra: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log message at specified level with context."""
        self.logger.log(level, message, extra=self._merge_extra(extra))


# Global logger instance
_logger_instance: Optional[RepositoryLogger] = None
_logger_lock = threading.Lock()


def get_logger(config: Optional[LoggingConfig] = None) -> RepositoryLogger:
    """
    Get the global logger instance.
    
    Thread-safe singleton pattern for logger access.
    
    Args:
        config: Logging configuration (only used for first initialization).
        
    Returns:
        Configured logger instance.
        
    Raises:
        ValueError: If logger not initialized and no config provided.
    """
    global _logger_instance
    
    if _logger_instance is None:
        with _logger_lock:
            if _logger_instance is None:
                if config is None:
                    raise ValueError("Logger not initialized and no config provided")
                _logger_instance = RepositoryLogger(config)
    
    return _logger_instance


def initialize_logger(config: LoggingConfig) -> RepositoryLogger:
    """
    Initialize the global logger instance.
    
    Args:
        config: Logging configuration.
        
    Returns:
        Configured logger instance.
    """
    global _logger_instance
    
    with _logger_lock:
        _logger_instance = RepositoryLogger(config)
        
    return _logger_instance


def timing_decorator(
    operation_name: Optional[str] = None,
    log_level: int = logging.INFO,
    threshold_ms: Optional[int] = None
):
    """
    Decorator for automatic operation timing and logging.
    
    Args:
        operation_name: Override operation name (defaults to function name).
        log_level: Log level for timing information.
        threshold_ms: Log as warning if operation exceeds this threshold.
        
    Returns:
        Decorator function.
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            logger = get_logger()
            op_name = operation_name or func.__name__
            
            with logger.timed_operation(
                op_name, 
                log_level=log_level, 
                threshold_ms=threshold_ms
            ):
                return func(*args, **kwargs)
        return wrapper
    return decorator


# Convenience functions for common logging patterns

def log_domain_operation(
    operation: str, 
    domain: str, 
    success: bool = True,
    extra: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log domain-specific operations with standardized format.
    
    Args:
        operation: Operation name.
        domain: Domain being operated on.
        success: Whether operation succeeded.
        extra: Additional context.
    """
    logger = get_logger()
    log_extra = {'operation': operation, 'domain': domain, 'success': success}
    
    if extra:
        log_extra.update(extra)
    
    message = f"Domain {operation}: {domain}"
    if success:
        logger.info(message, extra=log_extra)
    else:
        logger.error(message, extra=log_extra)


def log_batch_operation(
    operation: str,
    batch_size: int,
    processed_count: int,
    success: bool = True,
    duration_ms: Optional[float] = None,
    extra: Optional[Dict[str, Any]] = None
) -> None:
    """
    Log batch operations with standardized format.
    
    Args:
        operation: Batch operation name.
        batch_size: Size of the batch.
        processed_count: Number of items processed.
        success: Whether operation succeeded.
        duration_ms: Operation duration in milliseconds.
        extra: Additional context.
    """
    logger = get_logger()
    log_extra = {
        'operation': operation,
        'batch_size': batch_size,
        'processed_count': processed_count,
        'success': success
    }
    
    if duration_ms is not None:
        log_extra['duration_ms'] = round(duration_ms, 2)
        log_extra['throughput_per_sec'] = round(processed_count / (duration_ms / 1000), 2)
    
    if extra:
        log_extra.update(extra)
    
    message = f"Batch {operation}: {processed_count}/{batch_size} items"
    if duration_ms:
        message += f" in {duration_ms:.2f}ms"
    
    if success:
        logger.info(message, extra=log_extra)
    else:
        logger.error(message, extra=log_extra)