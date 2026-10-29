"""
Repository pattern implementation for unknown domain persistence.

This module provides the primary data access layer for UnknownDomain entities,
implementing high-level persistence operations with batch processing, deduplication,
and transaction management for production-scale domain storage.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any, Iterator, Tuple, Generator
import time

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from .database import DatabaseManager
from .models import UnknownDomain, DomainBatch, validate_domain_name
from .constants import (
    DOMAIN_TABLE_NAME,
    INSERT_COLUMNS,
    UPSERT_CONFLICT_COLUMNS,
    UPSERT_UPDATE_COLUMNS,
    COLUMN_DOMAIN,
    COLUMN_FIRST_SEEN,
    COLUMN_LAST_SEEN,
    COLUMN_STATUS,
    COLUMN_METADATA,
    COLUMN_UPDATED_AT,
    DomainStatus,
    DomainSource,
    DEFAULT_BATCH_SIZE,
    MAX_BATCH_SIZE
)
from .exceptions import (
    RepositoryError,
    DomainNotFoundError,
    DomainExistsError,
    BatchProcessingError,
    DatabaseQueryError,
    DomainValidationError
)
from .logger import get_logger, timing_decorator, log_domain_operation, log_batch_operation


class UnknownDomainRepository:
    """
    Repository for UnknownDomain entity persistence operations.
    
    Provides high-level data access methods with batch processing, transaction
    management, and performance optimization for production domain storage.
    Implements the repository pattern to abstract database operations.
    """

    # Resolve audit-column positions once at class definition time so that
    # _stamp_audit_timestamps() never relies on hardcoded numeric offsets.
    # If INSERT_COLUMNS is reordered in constants.py these will update
    # automatically and no other code needs to change.
    _INSERT_COLUMNS_LIST: List[str] = list(INSERT_COLUMNS)
    _CREATED_AT_IDX: int = _INSERT_COLUMNS_LIST.index("created_at")
    _UPDATED_AT_IDX: int = _INSERT_COLUMNS_LIST.index("updated_at")

    # Statuses that must be reset back to NEW when a domain is seen again
    # (i.e. it re-appears in a fresh batch of "unknown domains"). Domains
    # sitting in PROCESSING, CLEAN, or MALICIOUS keep their current status
    # since those represent a completed or in-flight verdict.
    _STATUSES_RESET_TO_NEW: Tuple[DomainStatus, ...] = (
        DomainStatus.REVIEW_NEEDED,
        DomainStatus.ERROR,
    )

    def __init__(self, database_manager: DatabaseManager) -> None:
        """
        Initialize repository with database manager.
        
        Args:
            database_manager: Initialized database manager instance.
        """
        self.db_manager = database_manager
        self.logger = get_logger()

    # =========================================================================
    # Private Helpers
    # =========================================================================

    @staticmethod
    def _stamp_audit_timestamps(values_list: List[Any], now: datetime) -> None:
        """
        Write *now* into the created_at and updated_at slots of a mutable
        values list that was produced by UnknownDomain.to_database_values().

        Positions are looked up by name from INSERT_COLUMNS so this method
        keeps working correctly even if the column order in INSERT_COLUMNS
        is changed in the future.  No hardcoded numeric offsets are used.

        Args:
            values_list: Mutable list from list(domain.to_database_values()).
            now:         Timezone-aware UTC datetime to write into both slots.
        """
        values_list[UnknownDomainRepository._CREATED_AT_IDX] = now
        values_list[UnknownDomainRepository._UPDATED_AT_IDX] = now

    @classmethod
    def _status_reset_case_sql(cls) -> sql.Composed:
        """
        Build the ``CASE ... END`` SQL fragment used on UPSERT conflict to
        decide the new status of an existing row.

        Rules (see module-level docs / ticket for the full transition table):
            REVIEW_NEEDED -> NEW
            ERROR         -> NEW
            PROCESSING    -> unchanged
            CLEAN         -> unchanged
            MALICIOUS     -> unchanged
            NEW           -> unchanged

        All status values are passed as bound SQL literals (``sql.Literal``)
        rather than interpolated strings, so this remains injection-safe
        even though the values originate from an internal enum.

        Returns:
            A composed SQL fragment starting with ``CASE`` and ending with
            ``END``, safe to splice into an ``UPDATE SET`` clause.
        """
        when_clauses = [
            sql.SQL("WHEN {} THEN {}").format(
                sql.Literal(status.value),
                sql.Literal(DomainStatus.NEW.value),
            )
            for status in cls._STATUSES_RESET_TO_NEW
        ]

        return sql.SQL("CASE {table}.{status_col} {whens} ELSE {table}.{status_col} END").format(
            table=sql.Identifier(DOMAIN_TABLE_NAME),
            status_col=sql.Identifier(COLUMN_STATUS),
            whens=sql.SQL(" ").join(when_clauses),
        )

    # =========================================================================
    # Single Domain Operations
    # =========================================================================
    
    @timing_decorator("domain_insert")
    def insert_domain(
        self, 
        domain: UnknownDomain,
        allow_duplicates: bool = False
    ) -> UnknownDomain:
        """
        Insert a single domain into the repository.
        
        Args:
            domain: Domain entity to insert.
            allow_duplicates: If False, raise error on duplicate domains.
            
        Returns:
            Domain entity with populated ID and timestamps.
            
        Raises:
            DomainExistsError: If domain exists and allow_duplicates is False.
            RepositoryError: If insertion fails.
        """
        try:
            with self.db_manager.transaction() as conn:
                if not allow_duplicates:
                    # Check for existing domain
                    if self._domain_exists(domain.domain, conn):
                        raise DomainExistsError(domain.domain)
                
                # Insert domain
                now = datetime.now(timezone.utc)
                values = domain.to_database_values()
                
                # Update timestamps for new record using named-column positions
                # rather than hardcoded offsets (-2/-1 were wrong because
                # schema_version sits after updated_at in INSERT_COLUMNS).
                values_list = list(values)
                self._stamp_audit_timestamps(values_list, now)
                
                query = sql.SQL("""
                    INSERT INTO {} ({}) 
                    VALUES ({})
                    RETURNING id, created_at, updated_at
                """).format(
                    sql.Identifier(DOMAIN_TABLE_NAME),
                    sql.SQL(", ").join(sql.Identifier(col) for col in INSERT_COLUMNS),
                    sql.SQL(", ").join(sql.Placeholder() for _ in INSERT_COLUMNS)
                )
                
                result = conn.execute(query, tuple(values_list)).fetchone()
                
                # Create updated domain with database-generated values
                updated_domain = UnknownDomain(
                    id=result[0],
                    domain=domain.domain,
                    first_seen=domain.first_seen,
                    last_seen=domain.last_seen,
                    source=domain.source,
                    status=domain.status,
                    metadata=domain.metadata,
                    created_at=result[1],
                    updated_at=result[2],
                    schema_version=domain.schema_version
                )
                
                log_domain_operation("insert", domain.domain, success=True, extra={'id': result[0]})
                return updated_domain
                
        except DomainExistsError:
            log_domain_operation("insert", domain.domain, success=False, extra={'reason': 'duplicate'})
            raise
        except Exception as e:
            log_domain_operation("insert", domain.domain, success=False, extra={'error': str(e)})
            raise RepositoryError(
                f"Failed to insert domain {domain.domain}: {e}",
                repository_operation="insert_domain"
            ) from e
    
    @timing_decorator("domain_upsert")
    def upsert_domain(
        self, 
        domain: UnknownDomain,
        update_last_seen: bool = True
    ) -> Tuple[UnknownDomain, bool]:
        """
        Insert domain or update if already exists (UPSERT operation).

        On conflict, in addition to refreshing last_seen/updated_at/metadata,
        the row's status is reset to NEW whenever it is currently
        REVIEW_NEEDED or ERROR, so that domains which previously fell
        through review (or errored out) get reprocessed the next time they
        are seen. Domains already PROCESSING, CLEAN, or MALICIOUS keep
        their current status.
        
        Args:
            domain: Domain entity to upsert.
            update_last_seen: Whether to update last_seen timestamp on conflict.
            
        Returns:
            Tuple of (domain entity with current values, was_inserted boolean).
            
        Raises:
            RepositoryError: If upsert operation fails.
        """
        try:
            with self.db_manager.transaction() as conn:
                now = datetime.now(timezone.utc)
                values = domain.to_database_values()
                
                # Update timestamps for new record using named-column positions
                # rather than hardcoded offsets (-2/-1 were wrong because
                # schema_version sits after updated_at in INSERT_COLUMNS).
                values_list = list(values)
                self._stamp_audit_timestamps(values_list, now)
                
                # Build conflict resolution clause
                if update_last_seen:
                    conflict_update = sql.SQL("""
                        DO UPDATE SET
                            last_seen = GREATEST(excluded.last_seen, {table}.last_seen),
                            updated_at = NOW(),
                            metadata = COALESCE(excluded.metadata, {table}.metadata),
                            {status_col} = {status_case}
                    """).format(
                        table=sql.Identifier(DOMAIN_TABLE_NAME),
                        status_col=sql.Identifier(COLUMN_STATUS),
                        status_case=self._status_reset_case_sql(),
                    )
                else:
                    conflict_update = sql.SQL("DO NOTHING")
                
                query = sql.SQL("""
                    INSERT INTO {} ({})
                    VALUES ({})
                    ON CONFLICT ({}) {}
                    RETURNING id, created_at, updated_at,
                              (xmax = 0) AS was_inserted
                """).format(
                    sql.Identifier(DOMAIN_TABLE_NAME),
                    sql.SQL(", ").join(sql.Identifier(col) for col in INSERT_COLUMNS),
                    sql.SQL(", ").join(sql.Placeholder() for _ in INSERT_COLUMNS),
                    sql.SQL(", ").join(sql.Identifier(col) for col in UPSERT_CONFLICT_COLUMNS),
                    conflict_update
                )
                
                result = conn.execute(query, tuple(values_list)).fetchone()
                
                if result:
                    # Successfully upserted
                    was_inserted = result[3]
                    updated_domain = UnknownDomain(
                        id=result[0],
                        domain=domain.domain,
                        first_seen=domain.first_seen,
                        last_seen=domain.last_seen,
                        source=domain.source,
                        status=domain.status,
                        metadata=domain.metadata,
                        created_at=result[1],
                        updated_at=result[2],
                        schema_version=domain.schema_version
                    )
                    
                    operation = "insert" if was_inserted else "update"
                    log_domain_operation(f"upsert_{operation}", domain.domain, success=True, extra={'id': result[0]})
                    return updated_domain, was_inserted
                else:
                    # Handle DO NOTHING case - retrieve existing record
                    existing = self.get_domain_by_name(domain.domain)
                    if existing:
                        log_domain_operation("upsert_existing", domain.domain, success=True, extra={'id': existing.id})
                        return existing, False
                    else:
                        raise RepositoryError("UPSERT returned no result and domain not found")
                        
        except Exception as e:
            log_domain_operation("upsert", domain.domain, success=False, extra={'error': str(e)})
            raise RepositoryError(
                f"Failed to upsert domain {domain.domain}: {e}",
                repository_operation="upsert_domain"  
            ) from e
    
    @timing_decorator("domain_status_update")
    def update_domain_status(
        self,
        domain_name: str,
        status: DomainStatus,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Update the status of an existing domain.

        Used by the online threat-intelligence pipeline
        (UnknownDomainProcessor) to record the outcome of evaluating a
        previously-unknown domain (e.g. "processing", "malicious",
        "clean", "review_needed", "error").
        
        Args:
            domain_name: Domain name to update.
            status: New status to set.
            metadata: Optional metadata to store alongside the status
                update. If omitted, existing metadata is left unchanged.
            
        Raises:
            RepositoryError: If the update fails.
        """
        try:
            normalized_domain = validate_domain_name(domain_name)

            with self.db_manager.transaction() as conn:
                if metadata is not None:
                    query = sql.SQL("""
                        UPDATE {}
                        SET {} = %s, {} = %s, {} = NOW()
                        WHERE {} = %s
                    """).format(
                        sql.Identifier(DOMAIN_TABLE_NAME),
                        sql.Identifier(COLUMN_STATUS),
                        sql.Identifier(COLUMN_METADATA),
                        sql.Identifier(COLUMN_UPDATED_AT),
                        sql.Identifier(COLUMN_DOMAIN)
                    )
                    params = (status.value, metadata, normalized_domain)
                else:
                    query = sql.SQL("""
                        UPDATE {}
                        SET {} = %s, {} = NOW()
                        WHERE {} = %s
                    """).format(
                        sql.Identifier(DOMAIN_TABLE_NAME),
                        sql.Identifier(COLUMN_STATUS),
                        sql.Identifier(COLUMN_UPDATED_AT),
                        sql.Identifier(COLUMN_DOMAIN)
                    )
                    params = (status.value, normalized_domain)

                conn.execute(query, params)

            log_domain_operation(
                "update_status", normalized_domain, success=True,
                extra={'status': status.value}
            )

        except Exception as e:
            log_domain_operation(
                "update_status", domain_name, success=False,
                extra={'error': str(e)}
            )
            raise RepositoryError(
                f"Failed to update status for domain {domain_name}: {e}",
                repository_operation="update_domain_status"
            ) from e
    
    def get_domain_by_name(self, domain_name: str) -> Optional[UnknownDomain]:
        """
        Retrieve domain by name.
        
        Args:
            domain_name: Domain name to search for.
            
        Returns:
            Domain entity if found, None otherwise.
            
        Raises:
            RepositoryError: If query fails.
        """
        try:
            # Validate and normalize domain name
            normalized_domain = validate_domain_name(domain_name)
            
            query = sql.SQL("""
                SELECT * FROM {}
                WHERE {} = %s
            """).format(
                sql.Identifier(DOMAIN_TABLE_NAME),
                sql.Identifier(COLUMN_DOMAIN)
            )
            
            with self.db_manager.get_connection() as conn:
                conn.row_factory = dict_row
                result = conn.execute(query, (normalized_domain,)).fetchone()
                
                if result:
                    return UnknownDomain.from_database_row(result)
                return None
                
        except DomainValidationError:
            # Invalid domain name
            return None
        except Exception as e:
            raise RepositoryError(
                f"Failed to retrieve domain {domain_name}: {e}",
                repository_operation="get_domain_by_name"
            ) from e
    
    def get_domain_by_id(self, domain_id: int) -> Optional[UnknownDomain]:
        """
        Retrieve domain by ID.
        
        Args:
            domain_id: Domain ID to search for.
            
        Returns:
            Domain entity if found, None otherwise.
            
        Raises:
            RepositoryError: If query fails.
        """
        try:
            query = sql.SQL("""
                SELECT * FROM {}
                WHERE id = %s
            """).format(sql.Identifier(DOMAIN_TABLE_NAME))
            
            with self.db_manager.get_connection() as conn:
                conn.row_factory = dict_row
                result = conn.execute(query, (domain_id,)).fetchone()
                
                if result:
                    return UnknownDomain.from_database_row(result)
                return None
                
        except Exception as e:
            raise RepositoryError(
                f"Failed to retrieve domain with ID {domain_id}: {e}",
                repository_operation="get_domain_by_id"
            ) from e
    
    # =========================================================================
    # Batch Operations
    # =========================================================================
    
    @timing_decorator("batch_insert", threshold_ms=1000)
    def batch_insert(
        self,
        domains: List[UnknownDomain],
        chunk_size: int = DEFAULT_BATCH_SIZE,
        skip_duplicates: bool = True
    ) -> int:
        """
        Insert multiple domains in batches.
        
        Args:
            domains: List of domain entities to insert.
            chunk_size: Number of domains per batch chunk.
            skip_duplicates: Whether to skip domains that already exist.
            
        Returns:
            Number of domains successfully inserted.
            
        Raises:
            BatchProcessingError: If batch processing fails.
        """
        if not domains:
            return 0
        
        if chunk_size > MAX_BATCH_SIZE:
            chunk_size = MAX_BATCH_SIZE
        
        start_time = time.perf_counter()
        total_inserted = 0
        failed_domains = []
        
        try:
            # Process in chunks to avoid memory issues
            domain_batch = DomainBatch(domains=domains)
            chunks = domain_batch.split(chunk_size)
            
            for chunk in chunks:
                try:
                    inserted_count = self._insert_chunk(chunk, skip_duplicates)
                    total_inserted += inserted_count
                    
                except Exception as e:
                    self.logger.error(
                        f"Failed to insert chunk of {chunk.size} domains: {e}",
                        extra={'chunk_size': chunk.size, 'error': str(e)}
                    )
                    failed_domains.extend(chunk.domain_names)
            
            duration_ms = (time.perf_counter() - start_time) * 1000
            log_batch_operation(
                "batch_insert",
                len(domains),
                total_inserted,
                success=len(failed_domains) == 0,
                duration_ms=duration_ms,
                extra={'failed_count': len(failed_domains)}
            )
            
            if failed_domains:
                raise BatchProcessingError(
                    f"Batch insert partially failed: {total_inserted}/{len(domains)} inserted",
                    batch_size=len(domains),
                    processed_count=total_inserted,
                    failed_domains=failed_domains
                )
            
            return total_inserted
            
        except Exception as e:
            if not isinstance(e, BatchProcessingError):
                raise BatchProcessingError(
                    f"Batch insert failed: {e}",
                    batch_size=len(domains),
                    processed_count=total_inserted,
                    failed_domains=failed_domains
                ) from e
            raise
    
    def _insert_chunk(self, chunk: DomainBatch, skip_duplicates: bool) -> int:
        """
        Insert a single chunk of domains.
        
        Args:
            chunk: Domain batch chunk to insert.
            skip_duplicates: Whether to skip duplicate domains.
            
        Returns:
            Number of domains inserted from this chunk.
        """
        with self.db_manager.transaction() as conn:
            now = datetime.now(timezone.utc)
            
            # Prepare batch values with current timestamps using named-column
            # positions rather than hardcoded offsets (-2/-1 were wrong because
            # schema_version sits after updated_at in INSERT_COLUMNS).
            batch_values = []
            for domain in chunk.domains:
                values = list(domain.to_database_values())
                self._stamp_audit_timestamps(values, now)
                batch_values.append(tuple(values))
            
            # Choose conflict resolution strategy
            conflict_action = "DO NOTHING" if skip_duplicates else "DO UPDATE SET updated_at = NOW()"
            
            # Execute batch insert
            return self.db_manager.batch_insert(
                table=DOMAIN_TABLE_NAME,
                columns=list(INSERT_COLUMNS),
                values=batch_values,
                connection=conn,
                on_conflict_action=f"({COLUMN_DOMAIN}) {conflict_action}"
            )
    
    @timing_decorator("batch_upsert", threshold_ms=1000)
    def batch_upsert(
        self,
        domains: List[UnknownDomain],
        chunk_size: int = DEFAULT_BATCH_SIZE,
        update_last_seen: bool = True
    ) -> Tuple[int, int]:
        """
        Upsert multiple domains in batches.

        On conflict (i.e. a domain that already exists), besides refreshing
        last_seen/updated_at/metadata, this resets the row's status back to
        NEW whenever it is currently REVIEW_NEEDED or ERROR - so a domain
        that previously fell through review or errored out will be picked
        up again by UnknownDomainProcessor.get_domains_by_status(NEW) the
        next time it is seen in the DNS logs. Domains already PROCESSING,
        CLEAN, or MALICIOUS are left untouched.
        
        Args:
            domains: List of domain entities to upsert.
            chunk_size: Number of domains per batch chunk.
            update_last_seen: Whether to update last_seen on conflicts.
            
        Returns:
            Tuple of (inserted_count, updated_count).
            
        Raises:
            BatchProcessingError: If batch processing fails.
        """
        if not domains:
            return 0, 0
        
        if chunk_size > MAX_BATCH_SIZE:
            chunk_size = MAX_BATCH_SIZE
        
        start_time = time.perf_counter()
        total_inserted = 0
        total_updated = 0
        failed_domains = []
        
        try:
            domain_batch = DomainBatch(domains=domains)
            chunks = domain_batch.split(chunk_size)
            
            for chunk in chunks:
                try:
                    inserted, updated = self._upsert_chunk(chunk, update_last_seen)
                    total_inserted += inserted
                    total_updated += updated
                    
                except Exception as e:
                    self.logger.error(
                        f"Failed to upsert chunk of {chunk.size} domains: {e}",
                        extra={'chunk_size': chunk.size, 'error': str(e)}
                    )
                    failed_domains.extend(chunk.domain_names)
            
            duration_ms = (time.perf_counter() - start_time) * 1000
            log_batch_operation(
                "batch_upsert",
                len(domains),
                total_inserted + total_updated,
                success=len(failed_domains) == 0,
                duration_ms=duration_ms,
                extra={
                    'inserted_count': total_inserted,
                    'updated_count': total_updated,
                    'failed_count': len(failed_domains)
                }
            )
            
            if failed_domains:
                raise BatchProcessingError(
                    f"Batch upsert partially failed: {total_inserted + total_updated}/{len(domains)} processed",
                    batch_size=len(domains),
                    processed_count=total_inserted + total_updated,
                    failed_domains=failed_domains
                )
            
            return total_inserted, total_updated
            
        except Exception as e:
            if not isinstance(e, BatchProcessingError):
                raise BatchProcessingError(
                    f"Batch upsert failed: {e}",
                    batch_size=len(domains),
                    processed_count=total_inserted + total_updated,
                    failed_domains=failed_domains
                ) from e
            raise
    
    def _upsert_chunk(
        self, 
        chunk: DomainBatch, 
        update_last_seen: bool
    ) -> Tuple[int, int]:
        """
        Upsert a single chunk of domains.

        Implementation notes / bug fixes:
          * The previous implementation created a scratch temp table via
            ``CREATE TEMP TABLE ... AS SELECT * FROM ... WHERE FALSE`` and
            then inserted into it with ``ON CONFLICT (domain) DO NOTHING``.
            ``CREATE TABLE ... AS SELECT`` does **not** copy indexes,
            constraints, or the primary key from the source table, so that
            temp table had no unique constraint on ``domain`` at all - the
            ``ON CONFLICT (domain)`` target was invalid and would raise a
            ``psycopg.errors.InvalidColumnReference`` at runtime (or, in
            environments where it happened not to error, would silently
            produce meaningless existing/inserted counts). This method now
            explicitly creates a unique index on the temp table before
            using it as an ON CONFLICT target.
          * The temp table is scoped with ``ON COMMIT DROP`` so it is
            cleaned up automatically at the end of the transaction instead
            of leaking for the lifetime of the (possibly pooled) session.
          * On conflict against the real table, the row's status is now
            reset to NEW when it is currently REVIEW_NEEDED or ERROR (see
            ``_status_reset_case_sql``), fixing domains getting stuck in
            REVIEW_NEEDED forever.

        Args:
            chunk: Domain batch chunk to upsert.
            update_last_seen: Whether to update last_seen on conflicts.
            
        Returns:
            Tuple of (inserted_count, updated_count).
        """
        with self.db_manager.transaction() as conn:
            now = datetime.now(timezone.utc)
            
            # Prepare batch values using named-column positions rather than
            # hardcoded offsets (-2/-1 were wrong because schema_version sits
            # after updated_at in INSERT_COLUMNS).
            batch_values = []
            for domain in chunk.domains:
                values = list(domain.to_database_values())
                self._stamp_audit_timestamps(values, now)
                batch_values.append(tuple(values))
            
            # Build conflict resolution against the real table.
            if update_last_seen:
                conflict_action_sql = sql.SQL("""
                    ({domain_col}) DO UPDATE SET
                        {last_seen_col} = GREATEST(excluded.{last_seen_col}, {table}.{last_seen_col}),
                        {updated_at_col} = NOW(),
                        {metadata_col} = COALESCE(excluded.{metadata_col}, {table}.{metadata_col}),
                        {status_col} = {status_case}
                """).format(
                    domain_col=sql.Identifier(COLUMN_DOMAIN),
                    last_seen_col=sql.Identifier(COLUMN_LAST_SEEN),
                    updated_at_col=sql.Identifier(COLUMN_UPDATED_AT),
                    metadata_col=sql.Identifier(COLUMN_METADATA),
                    status_col=sql.Identifier(COLUMN_STATUS),
                    table=sql.Identifier(DOMAIN_TABLE_NAME),
                    status_case=self._status_reset_case_sql(),
                )
            else:
                conflict_action_sql = sql.SQL("({}) DO NOTHING").format(
                    sql.Identifier(COLUMN_DOMAIN)
                )
            
            # db_manager.batch_insert() takes on_conflict_action as a plain
            # string fragment that it splices after "ON CONFLICT " - render
            # our safely-composed SQL to text via conn so it stays
            # identifier-quoted correctly instead of hand-building an
            # f-string.
            conflict_action = conflict_action_sql.as_string(conn)
            
            # Use a unique, unpredictable temp table name so concurrent
            # batches on different connections never collide.
            temp_table = f"temp_upsert_{int(time.time() * 1_000_000)}"
            
            # Create a scoped temp table that mirrors the real table's
            # columns and is dropped automatically at commit. Note this
            # does NOT copy indexes/constraints - we add the unique index
            # we need explicitly below.
            conn.execute(sql.SQL("""
                CREATE TEMP TABLE {} (LIKE {} INCLUDING DEFAULTS)
                ON COMMIT DROP
            """).format(
                sql.Identifier(temp_table),
                sql.Identifier(DOMAIN_TABLE_NAME)
            ))
            
            # A unique index on domain is required for this table to be a
            # valid ON CONFLICT (domain) target below.
            conn.execute(sql.SQL("""
                CREATE UNIQUE INDEX ON {} ({})
            """).format(
                sql.Identifier(temp_table),
                sql.Identifier(COLUMN_DOMAIN)
            ))
            
            # Insert this chunk's domains into the temp table so we can
            # diff them against the real table before performing the
            # actual upsert.
            self.db_manager.batch_insert(
                table=temp_table,
                columns=list(INSERT_COLUMNS),
                values=batch_values,
                connection=conn,
                on_conflict_action=f"({COLUMN_DOMAIN}) DO NOTHING"
            )
            
            # Count how many of this chunk's domains already existed in the
            # real table *before* the upsert below mutates it.
            existing_count = conn.execute(sql.SQL("""
                SELECT COUNT(*) FROM {} t
                JOIN {} m ON t.{} = m.{}
            """).format(
                sql.Identifier(temp_table),
                sql.Identifier(DOMAIN_TABLE_NAME),
                sql.Identifier(COLUMN_DOMAIN),
                sql.Identifier(COLUMN_DOMAIN)
            )).fetchone()[0]
            
            # Perform the actual upsert against the real table.
            affected_rows = self.db_manager.batch_insert(
                table=DOMAIN_TABLE_NAME,
                columns=list(INSERT_COLUMNS),
                values=batch_values,
                connection=conn,
                on_conflict_action=conflict_action
            )
            
            # Calculate inserted vs updated. affected_rows counts every row
            # touched by the statement (both newly-inserted and
            # conflict-updated rows) when the conflict action is DO UPDATE;
            # existing_count tells us how many of those were pre-existing.
            inserted_count = max(affected_rows - existing_count, 0)
            updated_count = existing_count if update_last_seen else 0
            
            return inserted_count, updated_count
    
    # =========================================================================
    # Query Operations
    # =========================================================================
    
    def get_domains_by_status(
        self,
        status: DomainStatus,
        limit: Optional[int] = None,
        offset: int = 0
    ) -> List[UnknownDomain]:
        """
        Retrieve domains by status with pagination.
        
        Args:
            status: Domain status to filter by.
            limit: Maximum number of domains to return.
            offset: Number of domains to skip.
            
        Returns:
            List of matching domain entities.
            
        Raises:
            RepositoryError: If query fails.
        """
        try:
            query = sql.SQL("""
                SELECT * FROM {}
                WHERE {} = %s
                ORDER BY {} ASC
            """).format(
                sql.Identifier(DOMAIN_TABLE_NAME),
                sql.Identifier(COLUMN_STATUS),
                sql.Identifier(COLUMN_FIRST_SEEN)
            )
            
            if limit:
                query = sql.SQL("{} LIMIT %s OFFSET %s").format(query)
                params = (status.value, limit, offset)
            else:
                query = sql.SQL("{} OFFSET %s").format(query)
                params = (status.value, offset)
            
            with self.db_manager.get_connection() as conn:
                conn.row_factory = dict_row
                results = conn.execute(query, params).fetchall()
                
                return [UnknownDomain.from_database_row(row) for row in results]
                
        except Exception as e:
            raise RepositoryError(
                f"Failed to retrieve domains by status {status.value}: {e}",
                repository_operation="get_domains_by_status"
            ) from e
    
    def get_domains_by_date_range(
        self,
        start_date: datetime,
        end_date: datetime,
        date_field: str = "first_seen",
        limit: Optional[int] = None
    ) -> List[UnknownDomain]:
        """
        Retrieve domains by date range.
        
        Args:
            start_date: Start of date range (inclusive).
            end_date: End of date range (inclusive).
            date_field: Date field to filter on ("first_seen" or "last_seen").
            limit: Maximum number of domains to return.
            
        Returns:
            List of matching domain entities.
            
        Raises:
            RepositoryError: If query fails.
        """
        try:
            if date_field not in [COLUMN_FIRST_SEEN, COLUMN_LAST_SEEN]:
                raise ValueError(f"Invalid date field: {date_field}")
            
            query = sql.SQL("""
                SELECT * FROM {}
                WHERE {} >= %s AND {} <= %s
                ORDER BY {} ASC
            """).format(
                sql.Identifier(DOMAIN_TABLE_NAME),
                sql.Identifier(date_field),
                sql.Identifier(date_field),
                sql.Identifier(date_field)
            )
            
            if limit:
                query = sql.SQL("{} LIMIT %s").format(query)
                params = (start_date, end_date, limit)
            else:
                params = (start_date, end_date)
            
            with self.db_manager.get_connection() as conn:
                conn.row_factory = dict_row
                results = conn.execute(query, params).fetchall()
                
                return [UnknownDomain.from_database_row(row) for row in results]
                
        except Exception as e:
            raise RepositoryError(
                f"Failed to retrieve domains by date range: {e}",
                repository_operation="get_domains_by_date_range"
            ) from e
    
    def count_domains(
        self,
        status: Optional[DomainStatus] = None,
        source: Optional[DomainSource] = None
    ) -> int:
        """
        Count domains with optional filters.
        
        Args:
            status: Optional status filter.
            source: Optional source filter.
            
        Returns:
            Number of matching domains.
            
        Raises:
            RepositoryError: If query fails.
        """
        try:
            conditions = []
            params = []
            
            if status:
                conditions.append(sql.SQL("{} = %s").format(sql.Identifier(COLUMN_STATUS)))
                params.append(status.value)
            
            if source:
                conditions.append(sql.SQL("source = %s"))
                params.append(source.value)
            
            if conditions:
                where_clause = sql.SQL("WHERE ") + sql.SQL(" AND ").join(conditions)
            else:
                where_clause = sql.SQL("")
            
            query = sql.SQL("""
                SELECT COUNT(*) FROM {} {}
            """).format(
                sql.Identifier(DOMAIN_TABLE_NAME),
                where_clause
            )
            
            with self.db_manager.get_connection() as conn:
                result = conn.execute(query, params).fetchone()
                return result[0] if result else 0
                
        except Exception as e:
            raise RepositoryError(
                f"Failed to count domains: {e}",
                repository_operation="count_domains"
            ) from e
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def _domain_exists(self, domain_name: str, connection: psycopg.Connection) -> bool:
        """
        Check if domain exists using provided connection.
        
        Args:
            domain_name: Domain name to check.
            connection: Database connection to use.
            
        Returns:
            True if domain exists, False otherwise.
        """
        normalized_domain = validate_domain_name(domain_name)
        
        query = sql.SQL("""
            SELECT EXISTS(
                SELECT 1 FROM {} WHERE {} = %s
            )
        """).format(
            sql.Identifier(DOMAIN_TABLE_NAME),
            sql.Identifier(COLUMN_DOMAIN)
        )
        
        result = connection.execute(query, (normalized_domain,)).fetchone()
        return result[0] if result else False
    
    def domain_exists(self, domain_name: str) -> bool:
        """
        Check if domain exists in repository.
        
        Args:
            domain_name: Domain name to check.
            
        Returns:
            True if domain exists, False otherwise.
            
        Raises:
            RepositoryError: If query fails.
        """
        try:
            with self.db_manager.get_connection() as conn:
                return self._domain_exists(domain_name, conn)
        except Exception as e:
            raise RepositoryError(
                f"Failed to check domain existence for {domain_name}: {e}",
                repository_operation="domain_exists"
            ) from e
    
    def get_repository_stats(self) -> Dict[str, Any]:
        """
        Get repository statistics.
        
        Returns:
            Dictionary containing repository statistics.
            
        Raises:
            RepositoryError: If stats query fails.
        """
        try:
            with self.db_manager.get_connection() as conn:
                # Total count
                total_count = conn.execute(sql.SQL("""
                    SELECT COUNT(*) FROM {}
                """).format(sql.Identifier(DOMAIN_TABLE_NAME))).fetchone()[0]
                
                # Status breakdown
                status_counts = {}
                for status in DomainStatus:
                    count = conn.execute(sql.SQL("""
                        SELECT COUNT(*) FROM {} WHERE {} = %s
                    """).format(
                        sql.Identifier(DOMAIN_TABLE_NAME),
                        sql.Identifier(COLUMN_STATUS)
                    ), (status.value,)).fetchone()[0]
                    status_counts[status.value] = count
                
                # Source breakdown
                source_counts = {}
                for source in DomainSource:
                    count = conn.execute(sql.SQL("""
                        SELECT COUNT(*) FROM {} WHERE source = %s
                    """).format(sql.Identifier(DOMAIN_TABLE_NAME)), (source.value,)).fetchone()[0]
                    source_counts[source.value] = count
                
                # Recent activity (last 24 hours)
                recent_count = conn.execute(sql.SQL("""
                    SELECT COUNT(*) FROM {} 
                    WHERE {} >= NOW() - INTERVAL '24 hours'
                """).format(
                    sql.Identifier(DOMAIN_TABLE_NAME),
                    sql.Identifier(COLUMN_FIRST_SEEN)
                )).fetchone()[0]
                
                return {
                    'total_domains': total_count,
                    'by_status': status_counts,
                    'by_source': source_counts,
                    'recent_24h': recent_count,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                
        except Exception as e:
            raise RepositoryError(
                f"Failed to get repository stats: {e}",
                repository_operation="get_repository_stats"
            ) from e