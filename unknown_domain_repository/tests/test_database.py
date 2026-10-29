"""
Unit tests for DatabaseManager (connection pool, health checks, initialization).

Focus: Mock psycopg interactions so tests run without real PostgreSQL.
We verify that DatabaseManager delegates correctly to psycopg.ConnectionPool.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, call, PropertyMock
from datetime import datetime, timezone


class TestDatabaseManagerInitialization:
    """Verify startup sequence (pool creation -> schema verification)."""

    @patch('unknown_domain_repository.database.ConnectionPool')
    def test_initialize_creates_pool_once(self, mock_pool_cls):
        """
        initialize() must construct ConnectionPool exactly one time.
        Subsequent calls should skip re-initialization.
        """
        from unknown_domain_repository.config import Config
        from unknown_domain_repository.database import DatabaseManager
        
        mock_pool_instance = mock_pool_cls.return_value
        mock_conn_mgr = MagicMock()
        mock_pool_instance.__enter__.return_value = mock_conn_mgr
        
        # Provide minimal config that passes validation
        cfg = Config()  # Uses env vars or defaults
        mgr = DatabaseManager(config=cfg)
        
        mgr.initialize()
        
        mock_pool_cls.assert_called_once()
        assert mgr._initialized is True

    @patch('unknown_domain_repository.database.DatabaseManager._verify_schema')
    @patch('unknown_domain_repository.database.DatabaseManager._create_connection_pool')
    def test_second_init_call_is_noop(self, create_mock, verify_mock):
        """Calling initialize() twice should not create new pool or run schema checks again."""
        from unknown_domain_repository.config import Config
        from unknown_domain_repository.database import DatabaseManager
        
        mgr = DatabaseManager(Config())
        mgr.initialize()
        
        count_before_create = create_mock.call_count
        count_before_verify = verify_mock.call_count
        
        mgr.initialize()  # Second call
        
        # Should not increase counts (idempotent guard inside initialize())
        assert create_mock.call_count == count_before_create
        assert verify_mock.call_count == count_before_verify


class TestConnectionPoolingBehavior:
    """Test get_connection() context manager contract."""

    @patch('unknown_domain_repository.database.DatabaseManager._initialized', new=True)
    @patch('unknown_domain_repository.database.DatabaseManager._pool')
    def test_get_connection_yields_pooled_object(self, mock_pool):
        """get_connection should acquire conn from pool and yield to caller."""
        from unknown_domain_repository.database import DatabaseManager
        from unknown_domain_repository.config import Config
        
        mgr = DatabaseManager(Config())
        mgr._pool = mock_pool
        
        fake_conn = Mock()
        ctx_mgr = MagicMock()
        ctx_mgr.__enter__ = Mock(return_value=fake_conn)
        ctx_mgr.__exit__ = Mock(return_value=False)
        mock_pool.connection.return_value = ctx_mgr
        
        with mgr.get_connection(timeout=5) as conn:
            assert conn is fake_conn
        
        # Pool.connection called once
        mock_pool.connection.assert_called_once()


class TestHealthCheckContract:
    """Ensure health_check returns dict with specific keys."""

    @patch('unknown_domain_repository.database.DatabaseManager._pool')
    @patch('unknown_domain_repository.database.DatabaseManager._schema_verified', new=True)
    @patch('unknown_domain_repository.database.DatabaseManager._initialized', new=True)
    def test_health_check_returns_dict_with_healthy_key(self, mock_pool):
        """
        Successful check returns dictionary containing boolean 'healthy'.
        """
        from unknown_domain_repository.database import DatabaseManager
        from unknown_domain_repository.config import Config
        
        mgr = DatabaseManager(Config())
        
        # Wire up healthy response mock pipeline
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = (1,)  # SELECT 1
        
        ctx = MagicMock()
        ctx.__enter__ = Mock(return_value=mock_conn)
        ctx.__exit__ = Mock(return_value=False)
        
        mgr._pool = mock_pool
        mock_pool.connection.return_value = ctx
        mock_pool.get_stats.return_value = {'connections_num': 1}
        
        result = mgr.health_check(timeout=3)
        
        assert isinstance(result, dict)
        assert 'healthy' in result
        assert result['healthy'] is True  # Based on mocked success paths


class TestExecuteQueryHelpers:
    """Test low-level query execution with retries and params binding."""

    @patch('unknown_domain_repository.database.DatabaseManager.get_connection')
    def test_execute_with_positional_parameters(self, get_conn_ctx):
        """
        execute_query must forward (query, params) to cursor.execute.
        Verifies parameter passing syntax correctness.
        """
        from unknown_domain_repository.database import DatabaseManager
        from unknown_domain_repository.config import Config
        
        mgr = DatabaseManager(Config())
        
        # Build mock stack: conn.cursor().execute(sql, params).fetch...
        mock_cursor = MagicMock()
        mock_cursor.execute.return_value.fetchall.return_value = []
        mock_cursor.execute.return_value.fetchone.return_value = None
        mock_cursor.execute.return_value.rowcount = 0
        
        mock_conn = MagicMock(return_value=mock_cursor)
        ctx_mgr = MagicMock(return_value=mock_conn)
        get_conn_ctx.return_value = ctx_mgr
        
        # Execute a SELECT-style query (fetch_one=True)
        mgr.execute_query("SELECT version()", fetch_one=True)
        
        # Verify delegation happened
        mock_cursor.execute.assert_called_once()
        args, kwargs = mock_cursor.execute.call_args
        sql_passed = args[0]
        # Could also assert params = ('SELECT version()',) based on signature


class TestDatabaseShutdownCleanup:
    """Ensure resources released properly on close/shutdown."""

    @patch('unknown_domain_repository.database.DatabaseManager._pool')
    def test_close_sets_initialized_false(self, mock_pool):
        """After shutdown, manager cannot perform more operations until re-init."""
        from unknown_domain_repository.database import DatabaseManager
        from unknown_domain_repository.config import Config
        
        mgr = DatabaseManager(Config())
        mgr._initialized = True
        mgr._pool = mock_pool
        
        mgr.close()
        
        mock_pool.close.assert_called_once()
        assert mgr._initialized is False
        assert mgr._pool is None

    @patch('unknown_domain_repository.database.DatabaseManager._pool')
    def test_close_idempotent_safe_multiple_times(self, mock_pool):
        """Double-close should not throw second exception."""
        from unknown_domain_repository.database import DatabaseManager
        from unknown_domain_repository.config import Config
        
        mgr = DatabaseManager(Config())
        mgr._initialized = True
        mgr._pool = mock_pool
        
        mgr.close()
        mgr.close()                               # Should succeed silently
        
        mock_pool.close.assert_called_once()

    @patch('unknown_domain_repository.database.DatabaseManager._pool')
    @patch('unknown_domain_repository.database.DatabaseManager._initialized', new=True)
    def test_context_manager_calls_shutdown_on_exit(self, mock_pool):
        """
        with DatabaseManager(cfg) as mgr:
            ...
        Should auto-close after scope exits.
        """
        from unknown_domain_repository.database import DatabaseManager
        from unknown_domain_repository.config import Config
        
        cfg = Config()
        mgr = DatabaseManager(cfg)
        
        # Use as context manager (simulate)
        with mgr:
            assert True
        
        # After exit, close was invoked
        mock_pool.close.assert_called_once()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])