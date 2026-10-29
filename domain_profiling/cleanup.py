"""
Cleanup script for the Domain Profiling module.

This module provides scheduled or manual CLI execution to purge historical DNS query
records older than a configured retention period (default: 30 days) from the
'domain_query_history' table. It preserves 'domain_profiles' intact.
"""

import argparse
import logging
import sys
import time
from datetime import datetime, timezone

from domain_profiling.service import DomainProfilingService
from domain_profiling.connection import ConnectionPoolManager

# Configure CLI logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("dns_threat_detection.domain_profiling.cleanup")


def run_cleanup(retention_days: int) -> int:
    """
    Executes the cleanup task using the DomainProfilingService.
    
    Args:
        retention_days (int): Max age of history queries in days.
        
    Returns:
        int: Number of deleted history records.
    """
    logger.info("Starting Domain Profiling history cleanup job...")
    logger.info(f"Target retention: {retention_days} days. Queries older than this will be deleted.")

    start_time = time.time()
    deleted_count = 0
    
    try:
        service = DomainProfilingService()
        deleted_count = service.cleanup_old_history(retention_days=retention_days)
        
        duration = time.time() - start_time
        logger.info(
            f"Cleanup job completed successfully in {duration:.2f} seconds. "
            f"Deleted {deleted_count} stale DNS query log rows."
        )
    except Exception as e:
        logger.error(f"Cleanup job failed with an error: {e}", exc_info=True)
        raise e
    finally:
        # Close connection pool resources if initiated during CLI run
        ConnectionPoolManager.close_all_connections()
        
    return deleted_count


def main() -> None:
    """
    Main entry point for command-line execution of the cleanup script.
    """
    parser = argparse.ArgumentParser(
        description="Clean up stale domain query history older than N days."
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=30,
        help="Number of days of history to retain (default: 30)."
    )
    
    args = parser.parse_args()
    
    if args.retention_days < 0:
        logger.error("Error: --retention-days must be a non-negative integer.")
        sys.exit(1)
        
    try:
        run_cleanup(args.retention_days)
        sys.exit(0)
    except Exception:
        sys.exit(2)


if __name__ == "__main__":
    main()
