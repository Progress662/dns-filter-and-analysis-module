"""
Unit tests for Custom Exception Hierarchy.

Validates exception structure, context preservation, inheritance,
and message formatting across all exception types in the system.
"""

import pytest
from typing import Dict, Any


class TestBaseExceptionContract:
    """Validate all custom exceptions adhere to base class contract."""

    def test_inherits_from_base(self):
        """All exceptions must be subclasses of UnknownDomainRepositoryError."""
        from unknown_domain_repository.exceptions import (
            UnknownDomainRepositoryError,
            ConfigurationError,
            DatabaseConnectionError,
            DomainValidationError,
            RepositoryError,
        )

        assert issubclass(ConfigurationError, UnknownDomainRepositoryError)
        assert issubclass(DatabaseConnectionError, UnknownDomainRepositoryError)
        assert issubclass(DomainValidationError, UnknownDomainRepositoryError)
        assert issubclass(RepositoryError, UnknownDomainRepositoryError)

    def test_base_exception_has_operation_attribute(self):
        """Base exception should capture operation name."""
        from unknown_domain_repository.exceptions import UnknownDomainRepositoryError
        
        exc = UnknownDomainRepositoryError("test message", operation="insert_domain")
        assert exc.operation == "insert_domain"

    def test_base_exception_supports_context_dict(self):
        """Exception should store arbitrary contextual metadata."""
        from unknown_domain_repository.exceptions import UnknownDomainRepositoryError
        
        context_data = {
            'domain_id': 42,
            'batch_size': 1000,
            'retry_attempt': 3,
            'db_host': 'localhost'
        }
        
        exc = UnknownDomainRepositoryError(
            "context test",
            operation="batch_process",
            context=context_data
        )
        
        assert exc.context == context_data
        assert exc.context['domain_id'] == 42

    def test_get_context_returns_structured_dict(self):
        """get_context() should return standardized format for logging."""
        from unknown_domain_repository.exceptions import UnknownDomainRepositoryError
        
        exc = UnknownDomainRepositoryError(
            "sample error",
            operation="validate_input",
            context={'item': 'value'}
        )
        
        result = exc.get_context()
        
        assert isinstance(result, dict)
        assert result['error_type'] == 'UnknownDomainRepositoryError'
        assert result['message'] == "sample error"
        assert result['operation'] == "validate_input"
        assert result['context']['item'] == 'value'


class TestConfigurationErrors:
    """Test ConfigurationError specific behavior."""

    def test_stores_config_key_and_value(self):
        """Should capture which config key caused the failure."""
        from unknown_domain_repository.exceptions import ConfigurationError
        
        exc = ConfigurationError(
            "Invalid value provided",
            config_key="DB_MAX_CONNECTIONS",
            config_value="-5"
        )
        
        assert exc.context['config_key'] == "DB_MAX_CONNECTIONS"
        assert exc.context['config_value'] == "-5"

    def test_masks_passwords_by_default(self):
        """Password-related keys must never show actual value."""
        from unknown_domain_repository.exceptions import ConfigurationError
        
        exc = ConfigurationError(
            "auth failed",
            config_key="UDR_DB_PASSWORD",
            config_value="MySecretPassw0rd!"
        )
        
        assert exc.context['config_value'] != "MySecretPassw0rd!"
        assert exc.context['config_value'] == "***"
        assert "MySecret" not in str(exc.context)


class TestDatabaseConnectionErrors:
    """Test connection-failure error details."""

    def test_captures_connection_endpoint_info(self):
        """Must include host/port/database when available."""
        from unknown_domain_repository.exceptions import DatabaseConnectionError
        
        exc = DatabaseConnectionError(
            "Cannot connect to PostgreSQL",
            host="10.0.1.50",
            port=5433,
            database="prod_db"
        )
        
        assert exc.context['host'] == "10.0.1.50"
        assert exc.context['port'] == 5433
        assert exc.context['database'] == "prod_db"

    def test_handles_none_values_gracefully(self):
        """Optional endpoint info can be None safely."""
        from unknown_domain_repository.exceptions import DatabaseConnectionError
        
        exc = DatabaseConnectionError("generic db error")
        # Should not raise KeyError on missing optional fields
        _ = exc.get_context()


class TestConnectionPoolErrors:
    """Test pool-exhaustion and pool-initialization errors."""

    def test_records_pool_capacity_stats(self):
        """Provide current pool usage stats for debugging."""
        from unknown_domain_repository.exceptions import ConnectionPoolError
        
        exc = ConnectionPoolError(
            "Pool exhausted: no free connections",
            pool_size=20,
            active_connections=20
        )
        
        assert exc.context['pool_size'] == 20
        assert exc.context['active_connections'] == 20


class TestTransactionErrors:
    """Test transaction rollback/failure errors."""

    def test_captures_transaction_state_string(self):
        """Include current transaction state for context."""
        from unknown_domain_repository.exceptions import TransactionError
        
        exc = TransactionError(
            "Deadlock detected during commit",
            transaction_state="IN_PROGRESS"
        )
        
        assert exc.context['transaction_state'] == "IN_PROGRESS"


class TestSchemaAndMigrationErrors:
    """Test schema validation and migration failure errors."""

    def test_schema_error_versions(self):
        """Track expected vs actual schema version mismatches."""
        from unknown_domain_repository.exceptions import SchemaError
        
        exc = SchemaError(
            "Table 'domains' missing column 'source'",
            schema_version=2,
            expected_version=3
        )
        
        assert exc.context['schema_version'] == 2
        assert exc.context['expected_version'] == 3

    def test_migration_error_filenames(self):
        """Migration failures should reference file path."""
        from unknown_domain_repository.exceptions import MigrationError
        
        exc = MigrationError(
            "Syntax error at line 45",
            migration_file="migrations/003_add_index.sql",
            migration_version=3
        )
        
        assert exc.context['migration_file'] == "003_add_index.sql"
        assert exc.context['migration_version'] == 3


class TestDomainValidationErrors:
    """Test domain-name-specific validation exceptions."""

    def test_stores_invalid_domain_name(self):
        """Always include the problematic domain string."""
        from unknown_domain_repository.exceptions import DomainValidationError
        
        exc = DomainValidationError(
            "Domain too long (300 chars)",
            domain="a-very-long-domain-name..." + "x" * 280,
            validation_rule="max_length"
        )
        
        assert exc.context['domain'].startswith("a-very-long")
        assert exc.context['validation_rule'] == "max_length"

    def test_rfc_rule_identifiers(self):
        """Use descriptive rule identifiers matching constants/docs."""
        from unknown_domain_repository.exceptions import DomainValidationError
        
        valid_rules = [
            "max_length", "rfc_pattern", "label_max_length",
            "empty_label", "reserved_domain", "min_length",
            "metadata_type", "metadata_serialization"
        ]
        
        for rule in valid_rules:
            exc = DomainValidationError(
                f"Violated rule: {rule}",
                domain="test.com",
                validation_rule=rule
            )
            
            assert exc.context['validation_rule'] == rule


class TestDomainExistsNotFoundErrors:
    """Test specific domain entity state errors."""

    def test_exists_error_formatting(self):
        """Message clearly identifies duplicate domain."""
        from unknown_domain_repository.exceptions import DomainExistsError
        
        exc = DomainExistsError("example.org")
        
        assert "example.org" in str(exc)
        assert "already exists" in str(exc).lower()

    def test_not_found_error_formatting(self):
        """Message clearly indicates missing domain."""
        from unknown_domain_repository.exceptions import DomainNotFoundError
        
        exc = DomainNotFoundError("missing-site.io")
        
        assert "not found" in str(exc).lower()
        assert exc.context['domain'] == "missing-site.io"


class TestBatchProcessingErrors:
    """Test bulk operation failure partial-success tracking."""

    def test_tracks_partial_progress(self):
        """When batch partially fails, report successes and failures."""
        from unknown_domain_repository.exceptions import BatchProcessingError
        
        failed_subset = [
            "bad-domain-01.bad",
            "bad-domain-02.bad",
            "invalid-$pecial.com"
        ]
        
        exc = BatchProcessingError(
            f"Failed to persist 3 of 100 domains",
            batch_size=100,
            processed_count=97,
            failed_domains=failed_subset
        )
        
        assert exc.context['processed_count'] == 97
        assert exc.context['batch_size'] == 100
        assert len(exc.context['failed_domains']) == 3


if __name__ == '__main__':
    pytest.main([__file__, '-v'])