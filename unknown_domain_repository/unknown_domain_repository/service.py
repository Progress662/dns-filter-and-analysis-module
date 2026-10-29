"""
High-level service layer for unknown domain persistence operations.

This module provides the main business logic interface for the DNS threat detection
pipeline, implementing domain filtering, batch processing, and orchestration of
repository operations for production-scale domain storage.
"""

import time
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any, Set, Tuple, Iterator, Generator
from dataclasses import dataclass

from .config import Config
from .database import DatabaseManager, create_database_manager
from .repository import UnknownDomainRepository
from .models import UnknownDomain, DomainBatch, validate_domain_name
from .constants import (
    DomainStatus,
    DomainSource,
    DEFAULT_BATCH_SIZE,
    MAX_BATCH_SIZE
)
from .exceptions import (
    UnknownDomainRepositoryError,
    RepositoryError,
    BatchProcessingError,
    InitializationError,
    ConfigurationError
)
from .logger import (
    get_logger, 
    timing_decorator, 
    log_domain_operation, 
    log_batch_operation
)


@dataclass
class ProcessingStats:
    """Statistics for domain processing operations."""
    
    total_processed: int = 0
    domains_stored: int = 0
    domains_skipped: int = 0
    domains_updated: int = 0
    processing_time_ms: float = 0.0
    throughput_per_second: float = 0.0
    errors: List[str] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert stats to dictionary for logging."""
        return {
            'total_processed': self.total_processed,
            'domains_stored': self.domains_stored,
            'domains_skipped': self.domains_skipped,
            'domains_updated': self.domains_updated,
            'processing_time_ms': round(self.processing_time_ms, 2),
            'throughput_per_second': round(self.throughput_per_second, 2),
            'error_count': len(self.errors),
            'success_rate': round(
                (self.domains_stored + self.domains_updated) / max(1, self.total_processed) * 100, 2
            )
        }


class DomainBatchProcessor:
    """
    Handles batched domain processing with deduplication and optimization.
    
    Accumulates domains and processes them in optimal batches to maximize
    database throughput while minimizing resource usage.
    """
    
    def __init__(
        self, 
        repository: UnknownDomainRepository,
        batch_size: int = DEFAULT_BATCH_SIZE,
        batch_timeout_seconds: float = 5.0
    ):
        """
        Initialize batch processor.
        
        Args:
            repository: Domain repository for persistence operations.
            batch_size: Target batch size for processing.
            batch_timeout_seconds: Maximum time to wait before processing partial batch.
        """
        self.repository = repository
        self.batch_size = min(batch_size, MAX_BATCH_SIZE)
        self.batch_timeout = batch_timeout_seconds
        self.logger = get_logger()
        
        # Batch accumulation
        self._pending_domains: Dict[str, UnknownDomain] = {}
        self._batch_start_time: Optional[float] = None
        self._total_processed = 0
        
    def add_domain(self, domain: UnknownDomain) -> bool:
        """
        Add domain to pending batch.
        
        Args:
            domain: Domain to add to batch.
            
        Returns:
            True if batch should be flushed, False otherwise.
        """
        # Deduplicate by domain name (keep latest)
        self._pending_domains[domain.domain] = domain
        
        # Set batch start time on first domain
        if self._batch_start_time is None:
            self._batch_start_time = time.perf_counter()
        
        # Check if batch should be processed
        return (
            len(self._pending_domains) >= self.batch_size or
            self._should_flush_by_timeout()
        )
    
    def _should_flush_by_timeout(self) -> bool:
        """Check if batch should be flushed due to timeout."""
        if self._batch_start_time is None:
            return False
        
        elapsed = time.perf_counter() - self._batch_start_time
        return elapsed >= self.batch_timeout
    
    @timing_decorator("batch_flush")
    def flush(self, force: bool = False) -> ProcessingStats:
        """
        Process accumulated domains in batch.
        
        Args:
            force: Process even if batch is small.
            
        Returns:
            Processing statistics.
        """
        if not self._pending_domains and not force:
            return ProcessingStats()
        
        if not self._pending_domains:
            return ProcessingStats()
        
        start_time = time.perf_counter()
        domains_to_process = list(self._pending_domains.values())
        
        try:
            # Execute batch upsert
            inserted_count, updated_count = self.repository.batch_upsert(
                domains=domains_to_process,
                chunk_size=self.batch_size,
                update_last_seen=True
            )
            
            processing_time = (time.perf_counter() - start_time) * 1000
            throughput = len(domains_to_process) / (processing_time / 1000) if processing_time > 0 else 0
            
            stats = ProcessingStats(
                total_processed=len(domains_to_process),
                domains_stored=inserted_count,
                domains_updated=updated_count,
                processing_time_ms=processing_time,
                throughput_per_second=throughput
            )
            
            self._total_processed += len(domains_to_process)
            
            log_batch_operation(
                "flush",
                len(domains_to_process),
                inserted_count + updated_count,
                success=True,
                duration_ms=processing_time,
                extra={
                    'inserted': inserted_count,
                    'updated': updated_count,
                    'throughput': round(throughput, 2)
                }
            )
            
            return stats
            
        except Exception as e:
            processing_time = (time.perf_counter() - start_time) * 1000
            
            self.logger.exception(
                f"Batch flush failed for {len(domains_to_process)} domains",
                extra={'batch_size': len(domains_to_process), 'error': str(e)}
            )
            
            stats = ProcessingStats(
                total_processed=len(domains_to_process),
                processing_time_ms=processing_time,
                errors=[str(e)]
            )
            return stats
            
        finally:
            # Clear batch
            self._pending_domains.clear()
            self._batch_start_time = None
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current processor statistics."""
        return {
            'pending_domains': len(self._pending_domains),
            'total_processed': self._total_processed,
            'batch_size': self.batch_size,
            'batch_timeout': self.batch_timeout,
            'time_since_batch_start': (
                time.perf_counter() - self._batch_start_time 
                if self._batch_start_time else 0
            )
        }


class UnknownDomainService:
    """
    Main service class for unknown domain persistence operations.
    
    Provides the primary interface for the DNS threat detection pipeline
    to store domains that are not found in known threat intelligence databases.
    Handles business logic, batch processing, and resource management.
    """
    
    def __init__(self, config: Config) -> None:
        """
        Initialize domain service.
        
        Args:
            config: Application configuration.
        """
        self.config = config
        self.logger = get_logger()
        self._db_manager: Optional[DatabaseManager] = None
        self._repository: Optional[UnknownDomainRepository] = None
        self._batch_processor: Optional[DomainBatchProcessor] = None
        self._initialized = False
        self._shutdown_requested = False
        
        # Performance tracking
        self._session_stats = ProcessingStats()
        self._session_start_time: Optional[float] = None
    
    def initialize(self) -> None:
        """
        Initialize service components.
        
        Must be called before using service operations.
        
        Raises:
            InitializationError: If initialization fails.
        """
        if self._initialized:
            return
        
        try:
            self.logger.info("Initializing Unknown Domain Service...")
            
            # Initialize database manager
            self._db_manager = create_database_manager(self.config)
            
            # Initialize repository
            self._repository = UnknownDomainRepository(self._db_manager)
            
            # Initialize batch processor
            self._batch_processor = DomainBatchProcessor(
                repository=self._repository,
                batch_size=self.config.batch.size,
                batch_timeout_seconds=self.config.batch.timeout
            )
            
            # Verify health
            health_check = self._db_manager.health_check(timeout=10.0)
            if not health_check.get('healthy', False):
                raise InitializationError(f"Health check failed: {health_check}")
            
            self._initialized = True
            self._session_start_time = time.perf_counter()
            
            self.logger.info(
                "Unknown Domain Service initialized successfully",
                extra={
                    'batch_size': self.config.batch.size,
                    'batch_timeout': self.config.batch.timeout,
                    'pool_size': f"{self.config.database.min_connections}-{self.config.database.max_connections}"
                }
            )
            
        except Exception as e:
            self.logger.exception("Failed to initialize Unknown Domain Service")
            raise InitializationError(f"Service initialization failed: {e}") from e
    
    def process_domains(
        self,
        domains: List[Dict[str, Optional[str]]],
        source: DomainSource = DomainSource.DNS_QUERY_LOG,
        observed_at: Optional[datetime] = None,
        batch_process: bool = True
    ) -> ProcessingStats:
        """
        Process a list of domain records for storage.
        
        This is the primary method called by the DNS pipeline to store domains
        that were not found in Tranco or URLhaus databases.
        
        Args:
            domains: List of domain records to process. Each record is a
                dict shaped as ``{"domain": str, "client_ip": Optional[str],
                "query_type": Optional[str]}``.
            source: Source of the domains.
            observed_at: When domains were observed (defaults to now).
            batch_process: Whether to use batch processing for efficiency.
            
        Returns:
            Processing statistics.
            
        Raises:
            UnknownDomainRepositoryError: If processing fails.
        """
        if not self._initialized:
            raise InitializationError("Service not initialized")
        
        if not domains:
            return ProcessingStats()
        
        start_time = time.perf_counter()
        observation_time = observed_at or datetime.now(timezone.utc)
        
        self.logger.info(
            f"Processing {len(domains)} domains for storage",
            extra={
                'domain_count': len(domains),
                'source': source.value,
                'batch_process': batch_process
            }
        )
        
        try:
            if batch_process:
                return self._process_domains_batch(domains, source, observation_time)
            else:
                return self._process_domains_individual(domains, source, observation_time)
                
        except Exception as e:
            processing_time = (time.perf_counter() - start_time) * 1000
            
            self.logger.exception(
                f"Failed to process {len(domains)} domains",
                extra={'processing_time_ms': processing_time}
            )
            
            stats = ProcessingStats(
                total_processed=len(domains),
                processing_time_ms=processing_time,
                errors=[str(e)]
            )
            self._update_session_stats(stats)
            raise
    
    def _process_domains_batch(
        self,
        domains: List[Dict[str, Optional[str]]],
        source: DomainSource,
        observed_at: datetime
    ) -> ProcessingStats:
        """Process domains using batch processing for efficiency."""
        start_time = time.perf_counter()
        total_stats = ProcessingStats()
        
        valid_domains = []
        validation_errors = []
        
        # Validate and create domain entities
        for record in domains:
            domain_name = record.get("domain")
            client_ip = record.get("client_ip")
            query_type = record.get("query_type")
            try:
                # Validate domain name
                normalized_domain = validate_domain_name(domain_name)
                
                # Create domain entity
                domain = UnknownDomain.create_new(
                    domain=normalized_domain,
                    first_seen=observed_at,
                    last_seen=observed_at,
                    source=source,
                    client_ip=client_ip,
                    query_type=query_type,
                )
                
                valid_domains.append(domain)
                
            except Exception as e:
                validation_errors.append(f"Domain {domain_name}: {e}")
                continue
        
        if validation_errors:
            self.logger.warning(
                f"Validation failed for {len(validation_errors)} domains",
                extra={'validation_errors': validation_errors[:10]}  # Log first 10
            )
        
        # Process valid domains in batches
        if valid_domains:
            try:
                inserted, updated = self._repository.batch_upsert(
                    domains=valid_domains,
                    chunk_size=self.config.batch.size,
                    update_last_seen=True
                )
                
                total_stats.total_processed = len(domains)
                total_stats.domains_stored = inserted
                total_stats.domains_updated = updated
                total_stats.domains_skipped = len(validation_errors)
                
            except Exception as e:
                total_stats.errors.append(str(e))
                raise
        else:
            total_stats.total_processed = len(domains)
            total_stats.domains_skipped = len(validation_errors)
        
        # Update timing
        total_stats.processing_time_ms = (time.perf_counter() - start_time) * 1000
        if total_stats.processing_time_ms > 0:
            total_stats.throughput_per_second = len(domains) / (total_stats.processing_time_ms / 1000)
        
        total_stats.errors.extend(validation_errors)
        self._update_session_stats(total_stats)
        
        return total_stats
    
    def _process_domains_individual(
        self,
        domains: List[Dict[str, Optional[str]]],
        source: DomainSource,
        observed_at: datetime
    ) -> ProcessingStats:
        """Process domains individually (for small batches or testing)."""
        start_time = time.perf_counter()
        stats = ProcessingStats()
        
        for record in domains:
            domain_name = record.get("domain")
            client_ip = record.get("client_ip")
            query_type = record.get("query_type")
            try:
                # Validate domain
                normalized_domain = validate_domain_name(domain_name)
                
                # Create domain entity
                domain = UnknownDomain.create_new(
                    domain=normalized_domain,
                    first_seen=observed_at,
                    last_seen=observed_at,
                    source=source,
                    client_ip=client_ip,
                    query_type=query_type,
                )
                
                # Store domain
                stored_domain, was_inserted = self._repository.upsert_domain(
                    domain=domain,
                    update_last_seen=True
                )
                
                if was_inserted:
                    stats.domains_stored += 1
                else:
                    stats.domains_updated += 1
                    
                log_domain_operation(
                    "store", 
                    domain_name, 
                    success=True, 
                    extra={'inserted': was_inserted, 'id': stored_domain.id}
                )
                
            except Exception as e:
                stats.errors.append(f"Domain {domain_name}: {e}")
                log_domain_operation("store", domain_name, success=False, extra={'error': str(e)})
                continue
            
            stats.total_processed += 1
        
        # Update timing
        stats.processing_time_ms = (time.perf_counter() - start_time) * 1000
        if stats.processing_time_ms > 0:
            stats.throughput_per_second = len(domains) / (stats.processing_time_ms / 1000)
        
        self._update_session_stats(stats)
        return stats
    
    @timing_decorator("store_single_domain")
    def store_unknown_domain(
        self,
        domain_name: str,
        observed_at: Optional[datetime] = None,
        source: DomainSource = DomainSource.DNS_QUERY_LOG,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[UnknownDomain, bool]:
        """
        Store a single unknown domain.
        
        Convenience method for storing individual domains. For bulk operations,
        use process_domains() instead.
        
        Args:
            domain_name: Domain name to store.
            observed_at: When domain was observed (defaults to now).
            source: Source of the domain.
            metadata: Optional metadata to associate with domain.
            
        Returns:
            Tuple of (stored domain entity, was_inserted boolean).
            
        Raises:
            UnknownDomainRepositoryError: If storage fails.
        """
        if not self._initialized:
            raise InitializationError("Service not initialized")
        
        observation_time = observed_at or datetime.now(timezone.utc)
        
        try:
            # Validate and create domain
            normalized_domain = validate_domain_name(domain_name)
            domain = UnknownDomain.create_new(
                domain=normalized_domain,
                first_seen=observation_time,
                last_seen=observation_time,
                source=source,
                metadata=metadata
            )
            
            # Store domain
            result = self._repository.upsert_domain(domain, update_last_seen=True)
            
            # Update session stats
            stats = ProcessingStats(
                total_processed=1,
                domains_stored=1 if result[1] else 0,
                domains_updated=0 if result[1] else 1
            )
            self._update_session_stats(stats)
            
            return result
            
        except Exception as e:
            stats = ProcessingStats(
                total_processed=1,
                errors=[str(e)]
            )
            self._update_session_stats(stats)
            
            self.logger.exception(f"Failed to store domain {domain_name}")
            raise
    
    def add_domain_to_batch(self, domain_name: str, observed_at: Optional[datetime] = None) -> bool:
        """
        Add domain to batch processor queue.
        
        For high-throughput scenarios where you want to accumulate domains
        and process them in optimal batches.
        
        Args:
            domain_name: Domain name to add.
            observed_at: When domain was observed.
            
        Returns:
            True if batch was automatically flushed, False otherwise.
            
        Raises:
            UnknownDomainRepositoryError: If batch processing fails.
        """
        if not self._initialized or not self._batch_processor:
            raise InitializationError("Service not initialized")
        
        try:
            observation_time = observed_at or datetime.now(timezone.utc)
            
            # Create domain entity
            normalized_domain = validate_domain_name(domain_name)
            domain = UnknownDomain.create_new(
                domain=normalized_domain,
                first_seen=observation_time,
                last_seen=observation_time,
                source=DomainSource.DNS_QUERY_LOG
            )
            
            # Add to batch
            should_flush = self._batch_processor.add_domain(domain)
            
            if should_flush:
                stats = self._batch_processor.flush()
                self._update_session_stats(stats)
                return True
            
            return False
            
        except Exception as e:
            self.logger.exception(f"Failed to add domain {domain_name} to batch")
            raise
    
    def flush_batch(self) -> ProcessingStats:
        """
        Force flush of pending batch.
        
        Returns:
            Processing statistics for flushed batch.
        """
        if not self._batch_processor:
            return ProcessingStats()
        
        stats = self._batch_processor.flush(force=True)
        self._update_session_stats(stats)
        return stats
    
    def get_pending_domains(self) -> List[UnknownDomain]:
        """
        Retrieve domains awaiting online threat-intelligence evaluation.

        Thin delegation used by UnknownDomainProcessor to pull domains
        that have not yet been evaluated (status == "new").

        Returns:
            List of domain entities with status DomainStatus.NEW.

        Raises:
            RepositoryError: If the query fails.
        """
        if not self._repository:
            raise InitializationError("Service not initialized")

        return self._repository.get_domains_by_status(DomainStatus.NEW)

    def update_status(
        self,
        domain_name: str,
        status: DomainStatus,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Update the status of a domain.

        Thin delegation used by UnknownDomainProcessor to record the
        outcome of an online threat-intelligence evaluation.

        Args:
            domain_name: Domain name to update.
            status: New status to set.
            metadata: Optional metadata to store alongside the update.

        Raises:
            RepositoryError: If the update fails.
        """
        if not self._repository:
            raise InitializationError("Service not initialized")

        self._repository.update_domain_status(domain_name, status, metadata)

    def get_repository_stats(self) -> Dict[str, Any]:
        """
        Get repository statistics.
        
        Returns:
            Dictionary containing repository statistics.
        """
        if not self._repository:
            return {}
        
        try:
            return self._repository.get_repository_stats()
        except Exception as e:
            self.logger.exception("Failed to get repository stats")
            return {'error': str(e)}
    
    def get_session_stats(self) -> Dict[str, Any]:
        """
        Get current session statistics.
        
        Returns:
            Dictionary containing session statistics.
        """
        session_time = (
            time.perf_counter() - self._session_start_time 
            if self._session_start_time else 0
        )
        
        stats = self._session_stats.to_dict()
        stats.update({
            'session_duration_seconds': round(session_time, 2),
            'average_throughput': (
                self._session_stats.total_processed / session_time 
                if session_time > 0 else 0
            ),
            'batch_processor_stats': (
                self._batch_processor.get_stats() 
                if self._batch_processor else {}
            )
        })
        
        return stats
    
    def health_check(self, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Perform service health check.
        
        Args:
            timeout: Health check timeout.
            
        Returns:
            Dictionary containing health status.
        """
        health_info = {
            'service_initialized': self._initialized,
            'service_healthy': False,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }
        
        if not self._initialized or not self._db_manager:
            health_info['reason'] = 'Service not initialized'
            return health_info
        
        try:
            # Database health check
            db_health = self._db_manager.health_check(timeout=timeout)
            health_info['database'] = db_health
            
            # Repository health check
            if self._repository:
                try:
                    count = self._repository.count_domains()
                    health_info['repository'] = {
                        'healthy': True,
                        'total_domains': count
                    }
                except Exception as e:
                    health_info['repository'] = {
                        'healthy': False,
                        'error': str(e)
                    }
            
            # Overall health
            health_info['service_healthy'] = (
                db_health.get('healthy', False) and
                health_info.get('repository', {}).get('healthy', False)
            )
            
            return health_info
            
        except Exception as e:
            health_info['error'] = str(e)
            health_info['service_healthy'] = False
            return health_info
    
    def _update_session_stats(self, stats: ProcessingStats) -> None:
        """Update cumulative session statistics."""
        self._session_stats.total_processed += stats.total_processed
        self._session_stats.domains_stored += stats.domains_stored
        self._session_stats.domains_skipped += stats.domains_skipped
        self._session_stats.domains_updated += stats.domains_updated
        self._session_stats.errors.extend(stats.errors)
    
    def shutdown(self) -> None:
        """
        Gracefully shutdown service.
        
        Flushes pending batches and closes database connections.
        Should be called during application shutdown.
        """
        if self._shutdown_requested:
            return
        
        self._shutdown_requested = True
        
        self.logger.info("Shutting down Unknown Domain Service...")
        
        try:
            # Flush any pending batches
            if self._batch_processor:
                final_stats = self._batch_processor.flush(force=True)
                if final_stats.total_processed > 0:
                    self.logger.info(
                        f"Flushed {final_stats.total_processed} domains during shutdown",
                        extra=final_stats.to_dict()
                    )
            
            # Log final session statistics
            if self._session_stats.total_processed > 0:
                self.logger.info(
                    "Session statistics",
                    extra=self.get_session_stats()
                )
            
            # Close database connections
            if self._db_manager:
                self._db_manager.close()
            
            self.logger.info("Unknown Domain Service shutdown complete")
            
        except Exception as e:
            self.logger.exception("Error during service shutdown")
        finally:
            self._initialized = False
    
    def __enter__(self) -> 'UnknownDomainService':
        """Context manager entry."""
        if not self._initialized:
            self.initialize()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit with cleanup."""
        self.shutdown()


# Convenience function for creating service from config
def create_service(config: Config) -> UnknownDomainService:
    """
    Create and initialize unknown domain service.
    
    Args:
        config: Application configuration.
        
    Returns:
        Initialized UnknownDomainService instance.
    """
    service = UnknownDomainService(config)
    service.initialize()
    return service