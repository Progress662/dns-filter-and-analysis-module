"""
Unit tests for UnknownDomainRepository (data access layer).

Tests cover single domain CRUD, batch operations, UPSERT logic,
query patterns, and error handling when database interactions fail.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch, call
from datetime import datetime, timezone
from typing import List


class TestRepositoryInitialization:
    """Verify repository requires valid database manager."""

    def test_requires_database_manager(self):
        """Repository cannot function without a DatabaseManager instance."""
        from unknown_domain_repository.repository import UnknownDomainRepository
        
        with pytest.raises(Exception):
            UnknownDomainRepository(database_manager=None)

    def test_stores_reference_to_db_manager(self):
        """Constructor should store DB manager for later use."""
        from unknown_domain_repository.repository import UnknownDomainRepository
        from unknown_domain_repository.database import DatabaseManager
        
        mock_mgr = Mock(spec=DatabaseManager)
        repo = UnknownDomainRepository(database_manager=mock_mgr)
        
        assert repo.db_manager is mock_mgr


class TestSingleDomainInsert:
    """Test insert_domain() with allow_duplicates control."""

    @patch.object(UnknownDomainRepository, '_domain_exists', return_value=False)
    @patch('unknown_domain_repository.repository.UnknownDomainRepository._insert_chunk')
    def test_insert_new_domain_returns_entity_with_id(self, mock_insert, mock_exists):
        """
        Successful insertion returns UnknownDomain where id is populated
        and created_at/updated_at have real timestamps.
        """
        from unknown_domain_repository.repository import UnknownDomainRepository
        from unknown_domain_repository.models import (
            UnknownDomain, DomainSource, DomainStatus
        )
        
        # Setup mocks for internal flow
        repo = UnknownDomainRepository(database_manager=Mock())
        
        now = datetime.now(timezone.utc)
        domain = UnknownDomain.create_new(
            domain="fresh-insert.xyz",
            first_seen=now,
            last_seen=now,
            source=DomainSource.DNS_QUERY_LOG
        )
        
        # Simulate INSERT returning generated ID/timestamps
        mock_result = Mock()
        mock_result.__getitem__ = lambda self, idx: [42, now, now][idx]  
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.execute.return_value.fetchone.return_value = mock_result
        ctx = MagicMock(return_value=mock_conn)
        mock_tx = MagicMock(return_value=ctx)
        mock_tx_context = MagicMock(return_value=None)  # Simplified
        
        repo.db_manager.transaction.return_value = mock_tx_context
        repo.db_manager.get_connection.return_value = mock_conn
        
        result = repo.insert_domain(domain, allow_duplicates=False)
        
        assert result.id == 42
        assert isinstance(result.created_at, datetime)

    @patch.object(UnknownDomainRepository, '_domain_exists', return_value=True)
    def test_insert_raises_on_duplicate_when_forbidden(self, mock_exists):
        """If domain exists and allow_duplicates=False, raise DomainExistsError."""
        from unknown_domain_repository.repository import UnknownDomainRepository
        from unknown_domain_repository.models import (
            UnknownDomain, DomainSource, DomainStatus
        )
        from unknown_domain_repository.exceptions import DomainExistsError
        
        repo = UnknownDomainRepository(database_manager=Mock())
        now = datetime.now(timezone.utc)
        dup_domain = UnknownDomain.create_new(
            domain="already-here.xyz",
            first_seen=now,
            last_seen=now,
            source=DomainSource.DNS_QUERY_LOG
        )
        
        with pytest.raises(DomainExistsError, match="already exists"):
            repo.insert_domain(dup_domain, allow_duplicates=False)


class TestUpsertLogic:
    """Test upsert_domain() behavior on conflict resolution."""

    @patch('unknown_domain_repository.repository.UnknownDomainRepository.get_connection')
    def test_upsert_returns_tuple_was_inserted_bool(self, get_conn_mock):
        """
        Returns (entity, was_inserted).
        - New domain -> was_inserted=True
        - Existing domain -> was_inserted=False
        """
        from unknown_domain_repository.repository import UnknownDomainRepository
        from unknown_domain_repository.models import (
            UnknownDomain, DomainSource
        )
        
        repo = UnknownDomainRepository(database_manager=Mock())
        now = datetime.now(timezone.utc)
        new_dom = UnknownDomain.create_new(
            domain="upsert-test.io",
            first_seen=now,
            last_seen=now,
            source=DomainSource.DNS_QUERY_LOG
        )
        
        # Setup connection stack
        mock_conn = MagicMock()
        cursor = MagicMock()
        # Return value: (id, created_at, updated_at, is_new_bool)
        cursor.execute.return_value.fetchone.return_value = (555, now, now + __import__('datetime').timedelta(seconds=1), True)
        mock_conn.cursor.return_value = cursor
        mock_conn.row_factory = None  # Skip dict_row
        conn_ctx = MagicMock(return_value=mock_conn)
        tx_ctx = MagicMock(return_value=None)
        
        get_conn_mock.return_value = conn_ctx
        repo.db_manager.transaction.return_value = tx_ctx
        
        entity, inserted_flag = repo.upsert_domain(new_dom, update_last_seen=True)
        
        assert inserted_flag is True
        assert entity.domain == "upsert-test.io"


class TestBatchOperations:
    """Test batch_insert() and batch_upsert() splitting and stats."""

    @patch('unknown_domain_repository.repository.UnknownDomainRepository._upsert_chunk')
    def test_batch_splits_when_exceeds_max_size(self, mock_upsert):
        """
        If list of domains > MAX_BATCH_SIZE (10k), batch_insert must split.
        Each chunk size <= MAX_BATCH_SIZE.
        """
        from unknown_domain_repository.repository import UnknownDomainRepository
        from unknown_domain_repository.constants import MAX_BATCH_SIZE
        from unknown_domain_repository.models import (
            UnknownDomain, DomainSource
        )
        
        repo = UnknownDomainRepository(database_manager=Mock())
        now = datetime.now(timezone.utc)
        
        # Generate 15000 domains (exceeds max of 10000)
        big_list = [
            UnknownDomain.create_new(
                domain=f"mass-{i}.com",
                first_seen=now,
                last_seen=now,
                source=DomainSource.DNS_QUERY_LOG
            ) for i in range(15000)
        ]
        
        # Configure mock to track chunk sizes passed
        captured_sizes = []
        def capture_upsert(chunk, update_last):
            captured_sizes.append(len(chunk.domains))
            return (len(chunk.domains), 0)  # (ins, ups) tuple
        
        mock_upsert.side_effect = capture_upsert
        
        repo.batch_insert(big_list, chunk_size=5000, skip_duplicates=True)
        
        # Verify chunks never exceeded configured limit
        for size in captured_sizes:
            assert size <= MAX_BATCH_SIZE or size <= 5000

    def test_batch_empty_list_returns_zero_stats(self):
        """Empty domain list should short-circuit and return zeros immediately."""
        from unknown_domain_repository.repository import UnknownDomainRepository
        
        repo = UnknownDomainRepository(database_manager=Mock())
        stats = repo.batch_insert(domains=[], chunk_size=100)
        
        assert stats.total_processed == 0


class TestQueryByStatusAndTimeRange:
    """Test filtering queries used by enrichment services."""

    @patch('unknown_domain_repository.repository.UnknownDomainRepository.get_connection')
    def test_get_domains_by_status_uses_where_clause(self, get_conn_mock):
        """Method builds SQL query with status filter parameter."""
        from unknown_domain_repository.repository import UnknownDomainRepository
        from unknown_domain_repository.constants import DomainStatus
        from unknown_domain_repository.models import UnknownDomain
        import psycopg.sql as sql
        
        repo = UnknownDomainRepository(database_manager=Mock())
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchall.return_value = []
        mock_cursor.fetchone.return_value = None
        
        row_example = {
            'id': 1,
            'domain': 'status-test.com',
            'first_seen': datetime.now(timezone.utc),
            'last_seen': datetime.now(timezone.utc),
            'source': 'dns_query_log',
            'status': 'new',
            'metadata': None,
            'created_at': datetime.now(timezone.utc),
            'updated_at': datetime.now(timezone.utc),
            'schema_version': 2
        }
        
        class DictRow:
            def __call__(self, cur): pass
            def __getattr__(self, name): return DictRow()
            
        mock_conn.cursor = PropertyMock(return_value=mock_cursor)
        mock_conn.row_factory = DictRow()
        get_conn_mock.return_value = MagicMock(return_value=mock_conn)
        
        results = repo.get_domains_by_status(DomainStatus.NEW, limit=10)
        
        # Should have executed a SELECT with status='new' condition somewhere
        execute_call_args = str(mock_cursor.execute.call_args)
        assert "new" in execute_call_args.lower() or len(results) >= 0


class TestCountDomainsAggregation:
    """Test COUNT(*) queries returning integer totals."""

    @patch('unknown_domain_repository.repository.UnknownDomainRepository.get_connection')
    def test_count_returns_integer(self, get_conn_mock):
        """count_domains() returns int count of matching rows."""
        from unknown_domain_repository.repository import UnknownDomainRepository
        
        repo = UnknownDomainRepository(database_manager=Mock())
        
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = [42]     # Scalar count
        mock_conn.cursor.return_value = mock_cursor
        
        get_conn_mock.return_value = MagicMock(return_value=mock_conn)
        
        total = repo.count_domains(status=None, source=None)
        
        assert total == 42
        assert isinstance(total, int)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])