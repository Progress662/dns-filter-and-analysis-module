"""
Update Manager.

Handles update scheduling, validation, and atomic replacement.
Mirrors Trusted DB updater.py.
"""

from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import time
import traceback
from typing import Optional

from .config import (
    DATA_SOURCE_URL,
    DB_PATH,
    FULL_NEW_DB_PATH,
    UPDATE_INTERVAL_SECONDS,
)
from .database import (
    execute_many_queries,
    get_metadata_value,
    initialize_db_structure,
    set_metadata_value,
    validate_integrity,
    verify_schema,
)
from .downloader import download_file, parse_urlhaus_csv
from .lock import acquire_lock

logger = logging.getLogger(__name__)

_BATCH_SIZE = 10000


def should_update(last_update_timestamp: Optional[float]) -> bool:
    """
    Checks if enough time has passed since the last update.
    """
    if not last_update_timestamp:
        return True

    return (time.time() - last_update_timestamp) >= UPDATE_INTERVAL_SECONDS


def _sqlite_row_count(path: str) -> int:
    """
    Returns the actual number of rows stored in the malicious_domains table.
    """
    conn = None
    try:
        conn = sqlite3.connect(path, timeout=30.0)
        cursor = conn.execute("SELECT COUNT(*) FROM malicious_domains")
        row = cursor.fetchone()
        return int(row[0]) if row else 0
    finally:
        if conn:
            conn.close()


def build_new_database(csv_data: bytes, source: str = "urlhaus") -> int:
    """
    Builds a new SQLite database from the downloaded feed.

    Returns:
        Actual number of rows stored in SQLite.
    """
    if os.path.exists(FULL_NEW_DB_PATH):
        try:
            os.remove(FULL_NEW_DB_PATH)
            logger.info("Removed stale temporary database: %s", FULL_NEW_DB_PATH)
        except OSError as exc:
            logger.warning(
                "Unable to remove stale temporary database '%s': %s",
                FULL_NEW_DB_PATH,
                exc,
            )

    logger.info("Building temporary database: %s", FULL_NEW_DB_PATH)

    initialize_db_structure(FULL_NEW_DB_PATH)

    sql = (
        "INSERT OR IGNORE INTO malicious_domains "
        "(domain, source, downloaded_at) "
        "VALUES (?, ?, ?)"
    )

    batch = []
    parsed_domains = 0
    inserted_batches = 0
    started = time.time()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

    first_ten = []

    for domain, _status in parse_urlhaus_csv(csv_data):
        parsed_domains += 1
        if len(first_ten) < 10:
            first_ten.append(domain)
        batch.append((sql, (domain, source, timestamp)))

        if len(batch) >= _BATCH_SIZE:
            logger.info("[DIAGNOSTIC] Before execute_many_queries: batch number with size %d", len(batch))
            execute_many_queries(batch, FULL_NEW_DB_PATH)
            logger.info("[DIAGNOSTIC] Batch committed successfully")
            conn_tmp = sqlite3.connect(FULL_NEW_DB_PATH)
            count_after = conn_tmp.execute("SELECT COUNT(*) FROM malicious_domains").fetchone()[0]
            conn_tmp.close()
            logger.info("[DIAGNOSTIC] SQLite rows after batch: %d", count_after)
            inserted_batches += len(batch)
            batch.clear()

    if batch:
        logger.info("[DIAGNOSTIC] Before execute_many_queries: final batch size %d", len(batch))
        execute_many_queries(batch, FULL_NEW_DB_PATH)
        logger.info("[DIAGNOSTIC] Batch committed successfully")
        inserted_batches += len(batch)
        batch.clear()

    logger.info("[DIAGNOSTIC] First 10 parsed domains: %s", first_ten)
    logger.info("[DIAGNOSTIC] Total parsed domains: %d", parsed_domains)

    conn_final = sqlite3.connect(FULL_NEW_DB_PATH)
    final_count_before_meta = conn_final.execute("SELECT COUNT(*) FROM malicious_domains").fetchone()[0]
    conn_final.close()
    logger.info("[DIAGNOSTIC] Final SQLite row count before metadata: %d", final_count_before_meta)

    if parsed_domains == 0:
        raise RuntimeError("Parser produced zero domains. Aborting database build.")

    actual_rows = _sqlite_row_count(FULL_NEW_DB_PATH)

    if actual_rows <= 0:
        raise RuntimeError(
            "Database build completed but SQLite contains zero rows."
        )

    duplicate_count = max(parsed_domains - actual_rows, 0)

    set_metadata_value(
        "last_update",
        time.strftime("%Y-%m-%d %H:%M:%S"),
        FULL_NEW_DB_PATH,
    )
    set_metadata_value("dataset_version", "v1", FULL_NEW_DB_PATH)
    set_metadata_value("record_count", str(actual_rows), FULL_NEW_DB_PATH)
    set_metadata_value("source", source, FULL_NEW_DB_PATH)

    logger.info(
        (
            "Database build complete in %.2fs "
            "(parsed=%d, attempted_inserts=%d, stored=%d, duplicates=%d)"
        ),
        time.time() - started,
        parsed_domains,
        inserted_batches,
        actual_rows,
        duplicate_count,
    )

    return actual_rows


def validate_database(path: str = FULL_NEW_DB_PATH) -> bool:
    """
    Validates the generated database prior to replacement.

    Validation requires:
    - database exists
    - schema is valid
    - integrity_check passes
    - SQLite contains at least one malicious domain
    """
    if not os.path.exists(path):
        logger.error("Validation failed: database does not exist: %s", path)
        return False

    schema_result = verify_schema(path)
    integrity_result = validate_integrity(path)

    try:
        row_count = _sqlite_row_count(path)
    except Exception:
        logger.exception("[DIAGNOSTIC] Exception during validation row count")
        row_count = -1

    metadata_count = get_metadata_value("record_count", path)

    logger.info("[DIAGNOSTIC] Schema result: %s", schema_result)
    logger.info("[DIAGNOSTIC] Integrity result: %s", integrity_result)
    logger.info("[DIAGNOSTIC] Metadata record_count: %s", metadata_count)
    logger.info("[DIAGNOSTIC] Actual SQLite row count: %d", row_count)

    if not schema_result:
        logger.error("Validation failed: schema verification failed.")
        return False

    if not integrity_result:
        logger.error("Validation failed: SQLite integrity check failed.")
        return False

    logger.info("Validation row count: %d", row_count)

    if row_count <= 0:
        logger.error("Validation failed: database contains zero domains.")
        return False

    if metadata_count is not None and metadata_count != str(row_count):
        logger.warning(
            "Metadata record_count (%s) did not match SQLite row count (%d).",
            metadata_count,
            row_count,
        )

    logger.info("Database validation succeeded.")
    return True


def perform_update(url: str = DATA_SOURCE_URL) -> bool:
    """
    Performs a complete database update.

    Steps:
    1. Download
    2. Build temporary database
    3. Validate
    4. Atomically replace production database
    """
    backup_path = f"{DB_PATH}.bak"

    try:
        with acquire_lock():
            logger.info("Acquired update lock.")

            logger.info("[DIAGNOSTIC] Download URL: %s", url)
            raw_data = download_file(url)
            logger.info("[DIAGNOSTIC] Downloaded byte count: %d", len(raw_data))

            actual_rows = records = build_new_database(raw_data)
            logger.info("=" * 80)
            logger.info("[DIAGNOSTIC] build_new_database() returned %d SQLite rows", records)
            logger.info("=" * 80)

            if actual_rows <= 0:
                raise RuntimeError(
                    "Temporary database contains zero records."
                )

            if not validate_database(FULL_NEW_DB_PATH):
                raise RuntimeError(
                    "Temporary database validation failed."
                )

            logger.info("[DIAGNOSTIC] Before atomic swap FULL_NEW_DB_PATH: %s DB_PATH: %s backup_path: %s",
                        FULL_NEW_DB_PATH, DB_PATH, backup_path)

            if os.path.exists(backup_path):
                try:
                    os.remove(backup_path)
                except OSError as exc:
                    logger.warning(
                        "Unable to remove stale backup '%s': %s",
                        backup_path,
                        exc,
                    )

            if os.path.exists(DB_PATH):
                shutil.move(DB_PATH, backup_path)
                logger.info("Backed up production database.")

            try:
                logger.info("[DIAGNOSTIC] Moving %s to %s", FULL_NEW_DB_PATH, DB_PATH)
                shutil.move(FULL_NEW_DB_PATH, DB_PATH)
                logger.info("[DIAGNOSTIC] Atomic replacement complete")
            except Exception as exc:
                exc_type = type(exc).__name__
                logger.exception("[DIAGNOSTIC] Exception during swap: type=%s stage=atomic_replacement traceback follows", exc_type)
                logger.info("[DIAGNOSTIC] Full traceback for exception during swap:")
                logger.info(traceback.format_exc())

                if os.path.exists(backup_path):
                    try:
                        shutil.move(backup_path, DB_PATH)
                        logger.info("Production database restored from backup.")
                    except Exception:
                        logger.exception(
                            "Failed to restore production database backup."
                        )

                raise RuntimeError(
                    "Database replacement failed."
                ) from exc

            conn_after = sqlite3.connect(DB_PATH)
            final_prod_rows = conn_after.execute("SELECT COUNT(*) FROM malicious_domains").fetchone()[0]
            conn_after.close()
            logger.info("[DIAGNOSTIC] Final production database row count: %d", final_prod_rows)

            if os.path.exists(backup_path):
                try:
                    os.remove(backup_path)
                except OSError as exc:
                    logger.warning(
                        "Unable to remove backup database '%s': %s",
                        backup_path,
                        exc,
                    )

            logger.info(
                "Malicious database successfully updated (%d rows).",
                actual_rows,
            )
            return True

    except Exception as exc:
        exc_type = type(exc).__name__
        stage = "update_pipeline"
        try:
            stage = "perform_update_lock"
        except Exception:
            pass
        logger.exception("[DIAGNOSTIC] Exception during update: type=%s stage=%s traceback follows", exc_type, stage)
        logger.info("[DIAGNOSTIC] Full traceback:")
        logger.info(traceback.format_exc())
        return False

    finally:
        if os.path.exists(FULL_NEW_DB_PATH):
            try:
                os.remove(FULL_NEW_DB_PATH)
            except OSError:
                logger.debug(
                    "Temporary database could not be removed.",
                    exc_info=True,
                )


def check_and_refresh(logger_obj: logging.Logger = logger) -> bool:
    """
    Public entry point for checking whether an update is required.
    """
    last_ts = get_metadata_value("last_update")

    if last_ts:
        try:
            last_update = time.mktime(
                time.strptime(last_ts, "%Y-%m-%d %H:%M:%S")
            )
        except ValueError:
            last_update = None
    else:
        last_update = None

    if should_update(last_update):
        logger_obj.info("Update interval reached.")
        return perform_update()

    logger_obj.debug("Malicious database is current.")
    return True