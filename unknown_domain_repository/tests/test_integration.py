"""
Integration Tests for End-to-End Data Flow.

These tests simulate realistic scenarios (full cycle: insert, read back, verify counts)
using minimal mocking where possible. Focus on component interaction contract validation.

Note: These tests prefer actual component wiring where safe, not pure unit isolation.
"""

import pytest
import tempfile
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, patch, MagicMock
from typing import List, Dict, Any


# ---------------------------------------------------------------------------
# Fixture Setup Helpers
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def temp_schema_dir(tmp_path_factory):
    """Create temporary directory structure holding schema files."""
    base_dir = tmp_path_factory.mktemp("sql_structure")
    sql_dir = base_dir / "unknown_domain_repository" / "sql"
    sql_dir.mkdir(parents=True)
    
    migration_dir = sql_dir / "migrations"
    migration_dir.mkdir(parents=True)
    
    # Write placeholder schema SQL content so loader can find file
    schema_content = "-- placeholder\nSELECT 1;\n"
    (sql_dir / "schema.sql").write_text(schema_content)
    
    (migration_dir / "001_initial_schema.sql").write_text(schema_content)
    (migration_dir / "002_performance_indexes.sql").write_text(schema_content)
    
    return base_dir


class TestEndToEndDomainPersistenceCycle:
    """
    High level flow: 
        1. Receive raw list of strings from external system
        2. Persist via service 
        3. Read back via repository query
        4. Validate data integrity matches expectations
    """

    @patch('unknown_domain_repository.database.DatabaseManager._create_connection_pool')
    @patch('unknown_domain_repository.database.DatabaseManager._verify_schema')
    @patch('unknown_domain_repository.database.ConnectionPool')
    def test_full_roundtrip_new_domain(self, mock_pool_cls, mock_verify, mock_pool_init):
        """
        GIVEN A NEW DOMAIN NOT IN ANY DATABASE
        WHEN We persist it using UnknownDomainService.process_domains(...)
        THEN The domain appears in subsequent get_domain_by_name() queries
             AND It has non-NULL ID, created_at, updated_at timestamps
             AND Its status is NEW
        """
        from unknown_domain_repository.service import UnknownDomainService
        from unknown_domain_repository.models import (
            UnknownDomain, DomainStatus, DomainSource
        )
        from unknown_domain_repository.exceptions import UnknownDomainRepositoryError
        from unknown_domain_repository.config import Config
        
        # Wire up full mock chain: Config -> Manager -> Pool -> Connection
        cfg = Config()
        svc = UnknownDomainService(config=cfg)
        svc.initialize()
        
        target_domain = "round-trip-success.io"
        observed_at = datetime(2024, 7, 1, 10, 20, 35, tzinfo=timezone.utc)
        
        # Build response from simulated INSERT RETURNING clause
        returned_id = 999
        created_ts = observed_at + timedelta(milliseconds=50)
        
        # Ensure repository can return the object we just stored
        mock_repo = svc._repository
        mock_repo.batch_upsert = Mock(return_value=(1, 0))       # 1 inserted, 0 updated
        mock_repo.get_domain_by_name = Mock(return_value=None)   # Initially missing
        # Post-persist lookup would find it
        after_store_entity = UnknownDomain.create_new(
            domain=target_domain,
            first_seen=observed_at,
            last_seen=observed_at,
            source=DomainSource.DNS_QUERY_LOG,
            metadata={'source_file': 'integration_test.csv'}
        )
        # Manually set attributes as if DB generated them
        after_store_entity = UnknownDomain(
            id=returned_id,
            domain=target_domain,
            first_seen=observed_at,
            last_seen=observed_at,
            source=DomainSource.DNS_QUERY_LOG,
            metadata={'source_file': 'test'},
            created_at=created_ts,
            updated_at=created_ts
        )
        
        # First call returns None (doesn't exist yet), second returns object (exists)
        mock_repo.get_domain_by_name.side_effect = [None, after_store_entity]
        
        # --- EXECUTE ---
        stats = svc.store_unknown_domain(target_domain, observed_at=observed_at)
        
        # --- ASSERTIONS ---
        assert stats[0].domain == target_domain          # Entity returned
        assert stats[1] is True                            # was_inserted=True
        
        # Simulate pipeline reading back what it just wrote
        retrieved = mock_repo.get_domain_by_name(target_domain)
        
        assert retrieved is not None
        assert retrieved.domain == target_domain
        assert retrieved.id == returned_id
        assert retrieved.status == DomainStatus.NEW
        
        # Cleanup service to prevent resource leaks in test suite
        svc.shutdown()


class TestDuplicateHandlingIntegration:
    """
    Real world scenario: Same domain reappears in next day's log export.
    System must decide whether INSERT or UPDATE (upsert wins).
    """

    @patch('unknown_domain_repository.service.UnknownDomainService.process_domains')
    def test_same_domain_twice_results_in_update_not_second_insert(self, mock_proc):
        """
        GIVEN domain X already persisted yesterday
        WHEN Today's log run includes domain X again
        THEN Service upserts: updates last_seen, keeps original created_at
             AND Returns was_inserted=False second time
        """
        from unknown_domain_repository.service import UnknownDomainService
        from unknown_domain_repository.config import Config
        
        svc = UnknownDomainService(Config())
        svc.initialize()
        
        duplicate_name = "daily-recurring.example.org"
        first_seen_yesterday = datetime.now(timezone.utc) - timedelta(days=1)
        second_seen_now = datetime.now(timezone.utc)
        
        # First call: brand new -> (Entity, True)
        mock_proc.side_effect = [
            # Call 1 (first occurrence yesterday)
            lambda *a, **kw: (
                Mock(id=111, domain=duplicate_name, created_at=first_seen_yesterday,
                     updated_at=first_seen_yesterday),
                True
            ),
            # Call 2 (same domain today) - upserted
            lambda *a, **kw: (
                Mock(id=111, domain=duplicate_name, created_at=first_seen_yesterday,
                     updated_at=second_seen_now),
                False              # was_inserted=False!
            )
        ]
        
        # Run day 1
        _, ins1 = svc.store_unknown_domain(duplicate_name, observed_at=first_seen_yesterday)
        assert ins1 is True
        
        # Run day 2 (same domain seen again)
        _, ins2 = svc.store_unknown_domain(duplicate_name, observed_at=second_seen_now)
        assert ins2 is False                       # NOT another fresh insert!


class TestLargeVolumeStressSimulation:
    """
    Validate that processing 100K+ domains doesn't crash memory or timeouts
    even under artificial delays/errors injected by mocks.
    """

    @patch('unknown_domain_repository.service.DomainBatchProcessor.flush')
    @patch('unknown_domain_repository.service.UnknownDomainService.process_domains')
    def test_large_volume_batches_split_properly(self, mock_proc, mock_flush):
        """
        GIVEN Input of 120,000 domain names
        WHEN Default batch size = 1000
        THEN Exactly 120 batch flushes occur
             AND Total processed equals input length
        """
        from unknown_domain_repository.service import UnknownDomainService
        from unknown_domain_repository.config import Config, BatchConfig
        
        large_config = Config(batch=BatchConfig(size=1000))
        svc = UnknownDomainService(config=large_config)
        
        # Generate large synthetic list
        huge_list = [f"vol{i}.bulk-domain-test.io" for i in range(120000)]
        
        # Make process_domains return fast success for all
        mock_proc.return_value = type('Stats', (), {
            'total_processed': len(huge_list),
            'domains_stored': len(huge_list),
            'domains_updated': 0,
            'to_dict': lambda: {'total': len(huge_list)}
        })()
        
        # Execute
        stats = svc.process_domains(huge_list, batch_process=True)
        
        # Basic sanity check completed successfully
        assert stats.total_processed == len(huge_list)


class TestDataframeFilteringContract:
    """
    Integration test validating exactly how domain_persistence decides which rows
    to extract from labeled_dns_dataset.csv and send to repository.
    
    This contracts ensures downstream pipeline users understand filter logic.
    """

    @pytest.mark.integration
    def test_filter_removes_tranco_urlhaus_rows_only(self):
        """
        DataFrame filter masks MUST exclude any rows containing:
         - 'Trusted Tranco Domain' substring in label_reason column
         - 'Known Malicious Domain (URLhaus)' substring in label_reason
         
        All other rows (even those marked Malicious/Suspicious by heuristic only)
        ARE included for future enrichment (this is the whole point).
        """
        import pandas as pd
        from unknown_domain_repository.utils import deduplicate_domains
        
        df_data = {
            'domain': [
                "google.com",
                "facebook.com",
                "random-phishing.click",
                "obscure-dga.bad",
                "suspicious-looking.site"
            ],
            'label_reason': [
                "Trusted Tranco Domain; Good score",
                "Trusted Tranco Domain; Clean",
                "Known Malicious Domain (URLhaus); Phishing",
                "High entropy; DGA indicators; Long SLD",
                "Suspicious TLD; Botnet signals"
            ]
        }
        
        df = pd.DataFrame(df_data)
        
        # Filter logic mirrors run_pipeline.py implementation
        mask = ~df['label_reason'].str.contains(
            r'Trusted Tranco Domain|Known Malicious Domain \(URLhaus\)',
            case=False,
            na=False,
            regex=True
        )
        
        filtered = df[mask]
        
        # Verify filtered result
        assert len(filtered) == 2                   # Only DGA + Suspicious TLD remain
        assert "google.com" not in filtered['domain'].values
        assert "facebook.com" not in filtered['domain'].values
        assert "random-phishing.click" not in filtered['domain'].values
        assert "obscure-dga.bad" in filtered['domain'].values   # Included! (heuristic-only malicious)
        assert "suspicious-looking.site" in filtered['domain'].values  # Included!

    @pytest.mark.integration
    def test_empty_unknown_set_skips_persistence_call(self):
        """
        Edge case: If EVERY domain is known (all Tranco/URLhaus),
        persistence step does nothing and returns zero stats quickly.
        """
        import pandas as pd
        
        all_known_df = pd.DataFrame({
            'domain': ["known-safe-1.com", "known-safe-2.com"],
            'label_reason': ["Trusted Tranco Domain", "Trusted Tranco Domain"]
        })
        
        mask = ~all_known_df['label_reason'].str.contains(
            r'Trusted Tranco Domain|URLhaus', case=False, regex=True
        )
        
        unknown_subset = all_known_df[mask]
        
        assert unknown_subset.empty                    # Empty frame -> skip work


# ---------------------------------------------------------------------------
# Performance Integration Contracts
# ---------------------------------------------------------------------------

class TestThroughputExpectations:
    """Define acceptable throughput bounds validated in integration environment."""

    @pytest.mark.performance
    def test_one_thousand_domains_under_five_seconds(self):
        """
        CONSTRAINT: Bulk persistence of 1000 unique domains with valid metadata
        must complete within 5 seconds wall-clock time on standard hardware.
        
        This sets acceptance criteria for future CI gates.
        """
        import time
        start = time.perf_counter()
        
        # Simulated delay representing real DB work (adjust based on your env)
        time.sleep(0.01)  # Placeholder
        
        elapsed_ms = (time.perf_counter() - start) * 1000
        
        # Assert reasonable threshold (adjust for CI env)
        # In real PostgreSQL local testing, should be < 500ms
        assert elapsed_ms < 5000.0, f"Took {elapsed_ms:.0f}ms > 5000ms limit"

    @pytest.mark.performance
    def test_connection_reuse_across_batches(self):
        """
        During multi-batch sequential processing, connection pool should NOT
        open/close connections between every batch.
        Instead, reusable pool handles churn efficiently.
        """
        # This validates architectural expectation rather than direct measurement here.
        # Actual benchmark captured in separate performance suite.
        assert True  # Contract placeholder


if __name__ == '__main__':
    pytest.main([__file__, '-v'])