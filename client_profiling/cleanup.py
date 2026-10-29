"""
Cleanup operations for old records

Provides functions to remove stale data based on retention policy.
"""

import logging
from datetime import datetime, timedelta
from .db import get_pool
from .config import RETENTION_DAYS

logger = logging.getLogger(__name__)


def cleanup_old_records(retention_days=None):
    """
    Delete client history records older than the retention period.
    
    After deleting history records, also removes client profiles
    that no longer have any associated history.
    
    This function is designed to be called periodically (e.g., daily)
    by an external scheduler (cron, systemd timer, etc.).
    
    Args:
        retention_days (int, optional): Number of days to retain records.
                                       Defaults to RETENTION_DAYS from config.
    
    Returns:
        dict: Statistics about the cleanup operation with keys:
              - history_deleted: Number of history records deleted
              - clients_deleted: Number of client profiles deleted
              - cutoff_date: The cutoff date used for deletion
              
    Raises:
        Exception: If cleanup operation fails
    """
    if retention_days is None:
        retention_days = RETENTION_DAYS
    
    # Calculate cutoff date
    cutoff_date = datetime.now() - timedelta(days=retention_days)
    
    logger.info(f"Starting cleanup: removing records older than {cutoff_date}")
    
    pool = get_pool()
    
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                # Step 1: Delete old history records
                cur.execute(
                    """
                    DELETE FROM client_history
                    WHERE last_seen < %s
                    """,
                    (cutoff_date,)
                )
                
                history_deleted = cur.rowcount
                logger.info(f"Deleted {history_deleted} old history records")
                
                # Step 2: Delete client profiles with no history
                # This uses ON DELETE CASCADE, but we'll do it explicitly
                # to track the count
                cur.execute(
                    """
                    DELETE FROM client_profiles
                    WHERE client_ip NOT IN (
                        SELECT DISTINCT client_ip
                        FROM client_history
                    )
                    """
                )
                
                clients_deleted = cur.rowcount
                logger.info(f"Deleted {clients_deleted} orphaned client profiles")
                
                # Commit the transaction
                conn.commit()
                
                result = {
                    "history_deleted": history_deleted,
                    "clients_deleted": clients_deleted,
                    "cutoff_date": cutoff_date,
                }
                
                logger.info(f"Cleanup completed successfully: {result}")
                
                return result
                
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        raise


def get_cleanup_stats(retention_days=None):
    """
    Get statistics about what would be deleted without actually deleting.
    
    Useful for monitoring or deciding when to run cleanup.
    
    Args:
        retention_days (int, optional): Number of days to check.
                                       Defaults to RETENTION_DAYS from config.
    
    Returns:
        dict: Statistics with keys:
              - old_history_count: Number of old history records
              - orphaned_clients_count: Number of clients that would be orphaned
              - cutoff_date: The cutoff date being checked
    """
    if retention_days is None:
        retention_days = RETENTION_DAYS
    
    cutoff_date = datetime.now() - timedelta(days=retention_days)
    
    pool = get_pool()
    
    try:
        with pool.connection() as conn:
            with conn.cursor() as cur:
                # Count old history records
                cur.execute(
                    """
                    SELECT COUNT(*)
                    FROM client_history
                    WHERE last_seen < %s
                    """,
                    (cutoff_date,)
                )
                
                old_history_count = cur.fetchone()[0]
                
                # Count clients that would become orphaned
                cur.execute(
                    """
                    SELECT COUNT(DISTINCT ch_old.client_ip)
                    FROM client_history ch_old
                    WHERE ch_old.last_seen < %s
                      AND NOT EXISTS (
                          SELECT 1
                          FROM client_history ch_new
                          WHERE ch_new.client_ip = ch_old.client_ip
                            AND ch_new.last_seen >= %s
                      )
                    """,
                    (cutoff_date, cutoff_date)
                )
                
                orphaned_clients_count = cur.fetchone()[0]
                
                return {
                    "old_history_count": old_history_count,
                    "orphaned_clients_count": orphaned_clients_count,
                    "cutoff_date": cutoff_date,
                }
                
    except Exception as e:
        logger.error(f"Failed to get cleanup stats: {e}")
        raise