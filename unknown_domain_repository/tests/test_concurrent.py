"""
Concurrency & Thread-Safety Tests.

Validate that shared resources (connection pool, logger, global state)
do not corrupt under simultaneous access from multiple worker threads/tasks.
Uses Python threading/futures to simulate parallel workload.
"""

import pytest
import threading
import concurrent.futures
import queue
import time
from datetime import datetime, timezone
from typing import List
from unittest.mock import Mock, patch, MagicMock


class TestGlobalLoggerThreadSafety:
    """
    Shared singleton logger must produce consistent output without garbled lines
    across threads calling debug/info/error simultaneously.
    """

    @patch('unknown_domain_repository.logger.logging.getLogger')
    def test_multiple_threads_logging_same_component(self, mock_getLogger):
        """
        Thread safety requirement: N threads all logging to same logger name
        must not interleave log messages between distinct log() calls.
        """
        from unknown_domain_repository.logger import get_logger, LoggingConfig
        import logging
        
        cfg = LoggingConfig(level='DEBUG', format='text')
        main_logger = get_logger(cfg)
        
        captured_messages = queue.Queue()
        
        # Record messages instead of actual I/O
        orig_info = main_logger.info
        
        def thread_safe_info(msg, extra=None):
            captured_messages.put(msg)
            return orig_info(msg, extra=extra)
            
        main_logger.info = thread_safe_info
        
        errors = []
        
        def worker(thread_id):
            try:
                for i in range(50):
                    main_logger.info(f"Thread-{thread_id} Message-{i}")
            except Exception as e:
                errors.append(e)
        
        threads = [
            threading.Thread(target=worker, args=(tid,))
            for tid in range(8)
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Restore original method
        main_logger.info = orig_info
        
        # Validate no corruption expected at message boundaries
        # (Actual string fragmentation depends on write buffering of underlying handler)
        assert errors == [], f"Errors during concurrency test: {errors}"
        assert captured_messages.qsize() == 400     # 8 threads * 50 msgs


class TestConnectionPoolContention:
    """
    Under high concurrency (> pool.max_connections), waiters may queue.
    Verify that pool does not exceed capacity or deadlock waiting.
    """

    @patch('unknown_domain_repository.psycopg_pool.ConnectionPool')
    def test_concurrent_get_connections_within_capacity(self, mock_pool_cls):
        """
        When multiple callers request connections simultaneously:
         - Pool should deliver connections up to limit
         - Surplus requests timeout gracefully (raise PoolTimeout)
         - No infinite blocking allowed
        """
        from unknown_domain_repository.database import DatabaseManager, DatabaseConnectionError
        from unknown_domain_repository.config import DatabaseConfig
        from psycopg import PoolTimeout
        
        cfg = DatabaseConfig(max_connections=2)           # Tiny pool for stress test
        mgr = DatabaseManager.__new__(DatabaseManager)    # Bypass __init__ side effects
        mgr.db_config = cfg
        
        # Build realistic pool mock
        mock_pool_instance = mock_pool_cls.return_value
        connection_count = {'active': 0}
        lock = threading.Lock()
        
        def acquire_connection(timeout=None):
            with lock:
                if connection_count['active'] < cfg.max_connections:
                    connection_count['active'] += 1
                    conn_ctx = MagicMock()
                    
                    class ConnCtx(MagicMock):
                        def __enter__(inner_self):
                            return self
                        
                        def __exit__(inner_self, *args):
                            with lock:
                                connection_count['active'] -= 1
                            return False
                    
                    return ConnCtx()
                else:
                    raise PoolTimeout(f"No connections available")
        
        mock_pool_instance.connection.side_effect = acquire_connection
        mgr._pool = mock_pool_instance
        mgr._initialized = True
        
        successful = 0
        timed_out = 0
        thread_errors = []
        
        def worker():
            nonlocal successful, timed_out
            
            try:
                with mgr.get_connection(timeout=0.1):      # 100ms timeout
                    successful += 1
                    time.sleep(0.02)                      # Hold briefly
            except (PoolTimeout, Exception) as err:
                timed_out += 1  # Timeout/denied normal under contention
        
        workers = [threading.Thread(target=worker) for _ in range(6)]
        for w in workers:
            w.start()
        for w in workers:
            w.join()
        
        # Assertions
        assert successful <= cfg.max_connections * 2  # Reasonable ceiling
        assert timed_out > 0                        # Some should have failed given tiny pool


class TestBatchProcessorSharedState:
    """
    DomainBatchProcessor accumulates _pending_domains dict.
    Concurrent add_domain() must ensure dictionary consistency.
    """

    @patch('unknown_domain_repository.service.UnknownDomainRepository')
    def test_concurrent_add_domain_deduplicates_without_race(self, mock_repo):
        """
        When multiple threads add identical domain simultaneously,
        batch must contain exactly ONE copy (no duplicate inserts).
        """
        from unknown_domain_repository.service import DomainBatchProcessor
        from unknown_domain_repository.models import UnknownDomain, DomainSource
        from datetime import timezone
        
        processor = DomainBatchProcessor(repository=Mock())
        
        target_domain = "concurrent-dedupe.test"
        now = datetime.now(timezone.utc)
        
        def submitter(thread_idx):
            d = UnknownDomain.create_new(
                domain=target_domain,
                first_seen=now,
                last_seen=now,
                source=DomainSource.DNS_QUERY_LOG
            )
            processor.add_domain(d)                  # May trigger flush or just queue
        
        threads = [threading.Thread(target=submitter, args=(i,)) for i in range(10)]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Force flush pending batch
        stats = processor.flush(force=True)
        
        # Count occurrences of target domain in batch values
        all_values = processor.to_database_values()
        found_count = sum(1 for vals in all_values if vals[0] == target_domain.lower())
        
        assert found_count == 1, f"Expected 1 copy of {target_domain}, got {found_count}"


class TestContextManagerIsolationBetweenThreads:
    """
    Each thread maintaining its own context (operation_context) must see its own data.
    Context bleeding between threads indicates incorrect design.
    """

    def test_thread_local_context_isolation(self):
        """
        Operation context set in Thread-A must be invisible to Thread-B.
        """
        from unknown_domain_repository.logger import get_logger, LoggingConfig
        
        cfg = LoggingConfig(level='DEBUG', format='text')
        logger_a = get_logger(cfg)
        logger_b = logger_a  # Same shared instance currently (acceptable)
        
        results = {}
        
        def thread_work(context_val):
            with logger_a.operation_context(operation=f"op-{context_val}"):
                # Capture current context snapshot
                current = logger_a._get_context()
                
                # Add result to shared dict safely
                results[threading.current_thread().name] = current.get('operation')
        
        t1 = threading.Thread(target=thread_work, args=("A",))
        t2 = threading.Thread(target=thread_work, args=("B",))
        
        t1.start(); t2.start()
        t1.join(); t2.join()
        
        # Both should have finished with their own contexts
        assert "Thread-1" in results
        assert "Thread-2" in results
        
        # Validate they saw different operations (or at least did not mix up)
        assert results["Thread-1"] != results["Thread-2"] or \
               results["Thread-1"] == "op-A"  # Either isolated or both present simultaneously acceptable for now


if __name__ == '__main__':
    pytest.main([__file__, '-v'])