"""
Unit tests for Configuration management module.

Tests cover:
- DatabaseConfig validation and default values
- LoggingConfig parameter handling
- BatchConfig constraints
- Config factory methods (from_env)
- Edge cases (invalid inputs, missing values)
- Environment variable override behavior
"""

import os
import pytest
from pathlib import Path
from unittest.mock import patch
from dataclasses import FrozenInstanceError


class TestDatabaseConfigDefaults:
    """Test DatabaseConfig initialization with defaults."""

    def test_default_values(self, test_config):
        """Config should use sensible defaults when no env vars set."""
        from unknown_domain_repository.config import DatabaseConfig
        
        cfg = DatabaseConfig()
        
        assert cfg.host == 'localhost'
        assert cfg.port == 5432
        assert cfg.database == 'dns_threats'
        assert cfg.min_connections >= 1
        assert cfg.max_connections >= cfg.min_connections
        assert cfg.max_idle_time > 0
        assert cfg.connect_timeout > 0
        assert cfg.command_timeout > 0
        assert cfg.max_retries >= 0
        assert cfg.retry_delay >= 0
        assert cfg.sslmode in ['disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full']

    def test_custom_values_override_defaults(self):
        """Explicit parameters should replace defaults."""
        from unknown_domain_repository.config import DatabaseConfig
        
        cfg = DatabaseConfig(
            host='192.168.1.100',
            port=15432,
            database='myapp_db',
            username='admin',
            password='secret123'
        )
        
        assert cfg.host == '192.168.1.100'
        assert cfg.port == 15432
        assert cfg.database == 'myapp_db'

    def test_immutability(self, test_config):
        """Frozen dataclass should prevent modification after creation."""
        from unknown_domain_repository.config import DatabaseConfig
        
        cfg = DatabaseConfig()
        
        with pytest.raises(FrozenInstanceError):
            cfg.host = 'new-host'


class TestDatabaseConfigValidation:
    """Test DatabaseConfig input validation rules."""

    def test_reject_empty_host(self):
        """Empty host string should raise ValueError."""
        from unknown_domain_repository.config import DatabaseConfig
        from unknown_domain_repository.exceptions import ConfigurationError
        
        with pytest.raises((ConfigurationError, ValueError)):
            DatabaseConfig(host='', username='u', password='p')

    def test_reject_invalid_port_range_low(self):
        """Port below 1 should be rejected."""
        from unknown_domain_repository.config import DatabaseConfig
        
        with pytest.raises((ValueError)):
            DatabaseConfig(port=0)

    def test_reject_invalid_port_range_high(self):
        """Port above 65535 should be rejected."""
        from unknown_domain_repository.config import DatabaseConfig
        
        with pytest.raises((ValueError)):
            DatabaseConfig(port=70000)

    def test_reject_max_connections_less_than_min(self):
        """Max connections must equal or exceed min."""
        from unknown_domain_repository.config import DatabaseConfig
        
        with pytest.raises((ValueError)):
            DatabaseConfig(min_connections=5, max_connections=2)

    def test_reject_negative_connect_timeout(self):
        """Timeouts must be positive numbers."""
        from unknown_domain_repository.config import DatabaseConfig
        
        with pytest.raises((ValueError)):
            DatabaseConfig(connect_timeout=-1)

    def test_reject_invalid_ssl_mode(self):
        """Invalid SSL mode strings should raise error."""
        from unknown_domain_repository.config import DatabaseConfig
        
        with pytest.raises((ValueError)):
            DatabaseConfig(sslmode='invalid_mode')

    def test_accept_valid_ssl_modes(self):
        """All documented SSL modes should pass validation."""
        from unknown_domain_repository.config import DatabaseConfig
        
        valid_modes = ['disable', 'allow', 'prefer', 'require', 'verify-ca', 'verify-full']
        for mode in valid_modes:
            cfg = DatabaseConfig(sslmode=mode)
            assert cfg.sslmode == mode

    def test_missing_required_fields(self):
        """Empty required fields should trigger error if not defaulted."""
        from unknown_domain_repository.config import DatabaseConfig
        from unknown_domain_repository.exceptions import ConfigurationError
        
        # NOTE: Our implementation uses defaults via .get(), but if we force empties...
        with pytest.raises(Exception):  # Catch any validation failure
            DatabaseConfig(host='', database='', username='')


class TestLoggingConfig:
    """Test logging configuration validation."""

    def test_default_level_is_info(self):
        """Default logging level should be INFO."""
        from unknown_domain_repository.config import LoggingConfig
        
        cfg = LoggingConfig()
        assert cfg.level.upper() == 'INFO'

    def test_accept_debug_level(self):
        """Should accept DEBUG level."""
        from unknown_domain_repository.config import LoggingConfig
        
        cfg = LoggingConfig(level='DEBUG')
        assert cfg.level == 'DEBUG'

    def test_format_validation(self):
        """Only allow 'json' or 'text' formats."""
        from unknown_domain_repository.config import LoggingConfig
        
        json_cfg = LoggingConfig(format='json')
        text_cfg = LoggingConfig(format='text')
        
        with pytest.raises(ValueError):
            LoggingConfig(format='xml')

    def test_max_file_size_must_be_positive(self):
        """File size limits must exceed zero."""
        from unknown_domain_repository.config import LoggingConfig
        
        with pytest.raises(ValueError):
            LoggingConfig(max_file_size=-1)

    def test_backup_count_cannot_be_negative(self):
        """Backup rotation count must be non-negative integer."""
        from unknown_domain_repository.config import LoggingConfig
        
        with pytest.raises(ValueError):
            LoggingConfig(backup_count=-5)

    def test_no_file_path_is_ok(self):
        """Disabling file logging by setting None should work."""
        from unknown_domain_repository.config import LoggingConfig
        
        cfg = LoggingConfig(file_path=None)
        assert cfg.file_path is None


class TestBatchConfig:
    """Test batch processing configuration constraints."""

    def test_positive_batch_size_required(self):
        """Batch size must be greater than 0."""
        from unknown_domain_repository.config import BatchConfig
        
        with pytest.raises(ValueError):
            BatchConfig(size=0)
        
        with pytest.raises(ValueError):
            BatchConfig(size=-10)

    def test_positive_timeout_required(self):
        """Timeout must be positive number."""
        from unknown_domain_repository.config import BatchConfig
        
        with pytest.raises(ValueError):
            BatchConfig(timeout=0)

    def test_positive_memory_limit(self):
        """Memory limit must be positive MB."""
        from unknown_domain_repository.config import BatchConfig
        
        with pytest.raises(ValueError):
            BatchConfig(max_memory_mb=0)


class TestConfigIntegration:
    """Test top-level Config aggregation class."""

    def test_config_aggregates_subconfigs(self, test_config):
        """Main Config object should contain all three sub-configs."""
        from unknown_domain_repository.config import Config
        
        cfg = Config.from_env()
        
        assert hasattr(cfg, 'database')
        assert hasattr(cfg, 'logging')
        assert hasattr(cfg, 'batch')

    def test_environment_defaults_to_development(self):
        """Default environment should be development unless overridden."""
        from unknown_domain_repository.config import Config
        
        cfg = Config.from_env()
        assert cfg.environment == 'development'

    def test_debug_defaults_false(self):
        """Debug flag should default to False."""
        from unknown_domain_repository.config import Config
        
        cfg = Config.from_env()
        assert cfg.debug is False

    def test_environment_validation(self):
        """Reject invalid environment names."""
        from unknown_domain_repository.config import Config
        
        with pytest.raises(ValueError):
            Config(environment='production_invalid')


class TestEnvironmentVariableOverrides:
    """Verify environment variables correctly override defaults."""

    @pytest.mark.unit
    def test_udr_db_host_overrides(self):
        """UDR_DB_HOST env var should change host setting."""
        from unknown_domain_repository.config import DatabaseConfig
        
        original = os.environ.get('UDR_DB_HOST')
        try:
            os.environ['UDR_DB_HOST'] = 'custom-host.local'
            cfg = DatabaseConfig()
            assert cfg.host == 'custom-host.local'
        finally:
            if original is None:
                os.environ.pop('UDR_DB_HOST', None)
            else:
                os.environ['UDR_DB_HOST'] = original

    @pytest.mark.unit
    def test_log_level_override_via_env(self):
        """UDR_LOG_LEVEL env var should control logging verbosity."""
        from unknown_domain_repository.config import LoggingConfig
        
        original = os.environ.get('UDR_LOG_LEVEL')
        try:
            os.environ['UDR_LOG_LEVEL'] = 'WARNING'
            cfg = LoggingConfig()
            assert cfg.level == 'WARNING'
        finally:
            if original is None:
                os.environ.pop('UDR_LOG_LEVEL', None)
            else:
                os.environ['UDR_LOG_LEVEL'] = original


class TestConfigSerialization:
    """Test to_dict() utility method for masking secrets."""

    def test_masks_password_in_output(self):
        """Dictionary representation must never contain real passwords."""
        from unknown_domain_repository.config import DatabaseConfig
        
        cfg = DatabaseConfig(password='super_secret_123!')
        result_dict = cfg.to_dict(mask_secrets=True)
        
        assert result_dict['database']['password'] != 'super_secret_123!'
        assert result_dict['database']['password'] == '***'
        assert 'super_secret' not in str(result_dict)

    def test_exposes_password_when_unmasked(self):
        """Unmasked serialization may expose secrets for debugging only."""
        from unknown_domain_repository.config import DatabaseConfig
        
        cfg = DatabaseConfig(password='clear_text_pass')
        result_dict = cfg.to_dict(mask_secrets=False)
        
        assert result_dict['database']['password'] == 'clear_text_pass'

    def test_output_contains_all_keys(self, test_config):
        """Serialized dict must include structured nesting for monitoring."""
        from unknown_domain_repository.config import Config
        
        cfg = Config.from_env()
        output = cfg.to_dict(mask_secrets=True)
        
        assert 'environment' in output
        assert 'database' in output
        assert 'logging' in output
        assert 'batch' in output
        assert 'host' in output['database']
        assert 'level' in output['logging']
        assert 'size' in output['batch']


if __name__ == '__main__':
    pytest.main([__file__, '-v'])