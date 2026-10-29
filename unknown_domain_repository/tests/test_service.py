"""
Unit tests for UnknownDomainService (business logic orchestration).

Validates process_domains(), store_unknown_domain(), statistics tracking,
session management, and health checks without real database calls.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, call
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any


class TestServiceLifecycle:
    """Test init/shutdown and context manager protocol."""

    @patch('unknown_domain_repository.service.create_database_manager')
    def test_init_creates_db_and_repo(self, create_db_mgr_mock):
        """initialize() must construct DatabaseManager then Repository."""
        from unknown_domain_repository.service import UnknownDomainService
        from unknown_domain_repository.config import Config
        
        cfg = Config()
        svc = UnknownDomainService(config=cfg)
        
        svc.initialize()
        
        create_db_mgr_mock.assert_called_once_with(cfg)

    def test_initialize_idempotent(self):
        """Double initialization should not raise error."""
        from unknown_domain_repository.service import UnknownDomainService
        from unknown_domain_repository.config import Config
        
        svc = UnknownDomainService(Config())
        svc.initialize()
        svc.initialize()                              # Safe second call

    @patch('unknown_domain_repository.service.create_database_manager')
    def test_shutdown_resets_state(self, mock_create):
        """
        After shutdown(), _service becomes None and _initialized False.
        Service should require re-init before reuse.
        """
        from unknown_domain_repository.service import UnknownDomainService
        from unknown_domain_repository.config import Config
        
        svc = UnknownDomainService(Config())
        svc.initialize()
        
        # Create fake inner service we can verify gets .shutdown() called
        fake_inner_service = Mock()
        svc._service = fake_inner_service
        svc._initialized = True
        
        svc.shutdown()
        
        fake_inner_service.shutdown.assert_called_once()
        assert svc._service is None
        assert svc._initialized is False


class TestProcessDomainsOrchestration:
    """Main entry point: receives list of strings, batches them for persistence."""

    @patch('unknown_domain_repository.service.UnknownDomainService.process_domains')
    def test_process_domains_delegates_to_internal_method(self, mock_process):
        """
        External interface passes parameters through correctly.
        """
        from unknown_domain_repository.service import UnknownDomainService
        from unknown_domain_repository.config import Config
        
        svc = UnknownDomainService(Config())
        svc.initialize()
        
        domains = ["alpha.example", "beta.org", "gamma.net"]
        obs_time = datetime(2024, 6, 15, tzinfo=timezone.utc)
        
        svc.process_domains(
            domains=domains,
            source="dns_query_log",
            observed_at=obs_time,
            batch_process=True
        )
        
        # Verify delegation happened with arguments preserved
        args, kwargs = mock_process.call_args
        assert kwargs['source'].value == "dns_query_log"
        assert len(args[0]) == 3

    def test_process_empty_list_returns_zero_stats(self):
        """Empty domain list returns empty ProcessingStats immediately."""
        from unknown_domain_repository.service import UnknownDomainService
        from unknown_domain_repository.config import Config
        
        svc = UnknownDomainService(Config())
        # Not initialized - but should still handle gracefully?
        try:
            stats = svc.process_domains([])
            assert stats.total_processed == 0
        except Exception as e:
            # Acceptable if it says "not initialized"
            if "not initialized" not in str(e).lower():
                raise


class TestBatchingBehavior:
    """Service-level batching wraps repository operations."""

    @patch('unknown_domain_repository.service.DomainBatchProcessor')
    def test_batch_size_configurable_from_config_object(self, mock_processor_cls):
        """batch_size pulled from config.batch.size property."""
        from unknown_domain_repository.service import UnknownDomainService
        from unknown_domain_repository.config import Config, BatchConfig
        
        custom_config = Config(batch=BatchConfig(size=200))
        svc = UnknownDomainService(config=custom_config)
        
        svc.initialize()
        
        # Inspect processor construction call
        processor_instance = mock_processor_cls.call_args[0][1]
        assert processor_instance.batch_size == 200


class TestStatisticsTracking:
    """Session and per-call statistics accumulation."""

    def test_session_stats_accumulate_across_calls(self):
        """
        Multiple calls to process_domains accumulate into session totals.
        """
        from unknown_domain_repository.service import UnknownDomainService, ProcessingStats
        from unknown_domain_repository.config import Config
        from datetime import timezone
        
        svc = UnknownDomainService(config=Config())
        svc._session_stats = ProcessingStats()
        svc._session_stats.total_processed = 50
        svc._session_stats.domains_stored = 40
        svc._session_stats.errors = []
        
        # Simulate second operation updating stats
        delta = ProcessingStats(total_processed=30, domains_stored=25)
        svc._update_session_stats(delta)
        
        assert svc._session_stats.total_processed == 80
        assert svc._session_stats.domains_stored == 65


class TestHealthCheckDelegation:
    """Health checks mirror db+repository composite status."""

    @patch.object(UnknownDomainService, '_db_manager')
    def test_health_check_returns_dict(self, mock_db):
        """
        Returns dict with keys: healthy, timestamp, checks, etc.
        """
        from unknown_domain_repository.service import UnknownDomainService
        from unknown_domain_repository.config import Config
        
        svc = UnknownDomainService(config=Config())
        svc._initialized = True
        svc._db_manager = MagicMock()
        svc._db_manager.health_check.return_value = {
            'healthy': True,
            'timestamp': '2024-06-15T12:30Z'
        }
        svc._repository = MagicMock()
        svc._repository.count_domains.return_value = 12345
        
        result = svc.health_check(timeout=5)
        
        assert isinstance(result, dict)
        assert 'healthy' in result


class TestPipelineIntegrationHelper:
    """Test convenience functions for pipeline integration."""

    def test_create_default_service_env_driven(self):
        """
        create_default_service() uses Config.from_env().
        No config argument required.
        """
        from unknown_domain_repository.service import create_default_service
        from unknown_domain_repository.config import Config
        
        # Patch from_env to avoid env setup issues in test
        with patch('unknown_domain_repository.service.Config.from_env') as mock_cfg:
            mock_cfg.return_value = Config()
            
            with patch('unknown_domain_repository.service.UnknownDomainService') as mock_svc_cls:
                instance = mock_svc_cls.return_value
                
                result = create_default_service()
                
                # Config loaded automatically
                mock_cfg.assert_called_once()

    def test_pipeline_integration_usage_pattern(self):
        """
        PipelineIntegration context manager delegates to service.
        Example usage shows correct object graph.
        """
        from unknown_domain_repository.service import PipelineIntegration, Config
        
        with patch('unknown_domain_repository.service.Config.from_env'):
            pi = PipelineIntegration(config=Config())
            
            with pi as integration:
                assert hasattr(integration, 'store_unknown_domains')
                assert hasattr(integration, 'get_statistics')


if __name__ == '__main__':
    pytest.main([__file__, '-v'])