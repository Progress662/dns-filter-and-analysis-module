"""
Pytest configuration and shared fixtures for Unknown Domain Repository tests.
"""

import os
import sys
import tempfile
from pathlib import Path
from typing import Generator
from unittest.mock import Mock, patch

import pytest

# Ensure package is importable during testing
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(scope="session")
def test_config():
    """Provide a valid test configuration using environment overrides."""
    return {
        'database': {
            'host': 'localhost',
            'port': 5432,
            'database': 'test_unknown_domains',
            'username': 'test_user',
            'password': 'test_password',
            'min_connections': 2,
            'max_connections': 5,
            'connect_timeout': 10,
            'command_timeout': 30,
            'max_retries': 3,
            'retry_delay': 1.0,
            'sslmode': 'prefer',
        },
        'logging': {
            'level': 'DEBUG',
            'format': 'text',          # Use text format for test readability
            'file_path': None,         # No file logging in tests
        },
        'batch': {
            'size': 100,               # Smaller batches for tests
            'timeout': 2.0,
            'max_memory_mb': 50,
        },
        'environment': 'testing',
        'debug': True,
    }


@pytest.fixture(autouse=True)
def reset_environment(test_config):
    """Reset environment variables before each test."""
    original_env = {}
    
    try:
        # Set environment variables for testing
        env_mappings = {
            'UDR_DB_HOST': test_config['database']['host'],
            'UDR_DB_PORT': str(test_config['database']['port']),
            'UDR_DB_DATABASE': test_config['database']['database'],
            'UDR_DB_USERNAME': test_config['database']['username'],
            'UDR_DB_PASSWORD': test_config['database']['password'],
            'UDR_LOG_LEVEL': test_config['logging']['level'],
            'UDR_LOG_FORMAT': test_config['logging']['format'],
            'UDR_ENVIRONMENT': test_config['environment'],
            'UDR_DEBUG': str(test_config['debug']).lower(),
        }
        
        # Store originals and set test values
        for key, value in env_mappings.items():
            original_env[key] = os.environ.get(key)
            if value is not None:
                os.environ[key] = value
            elif key in os.environ:
                del os.environ[key]
        
        yield
        
    finally:
        # Restore original environment
        for key, original_value in original_env.items():
            if original_value is not None:
                os.environ[key] = original_value
            elif key in os.environ:
                del os.environ[key]


@pytest.fixture
def sample_domains():
    """Return list of sample domain names for testing."""
    return [
        "google.com",
        "facebook.com", 
        "unknown-test-123.example.org",
        "suspicious-domain.click",
        "api.service.io",
        "mail.company.net",
        "cdn.staticfiles.net",
    ]


@pytest.fixture
def sample_unknown_domains(sample_domains):
    """Return list of unknown domain entities ready for persistence."""
    from datetime import datetime, timezone
    from unknown_domain_repository.models import UnknownDomain, DomainSource
    
    domains = []
    now = datetime.now(timezone.utc)
    
    for i, domain_name in enumerate(sample_domains):
        domain = UnknownDomain.create_new(
            domain=domain_name,
            first_seen=now,
            last_seen=now,
            source=DomainSource.DNS_QUERY_LOG,
            metadata={'source_file': f'test_file_{i}.csv'}
        )
        domains.append(domain)
    
    return domains


@pytest.fixture
def mock_database_connection():
    """Mock database connection for unit tests."""
    mock_conn = Mock()
    
    # Mock execute method returns appropriate data based on query type
    def execute_side_effect(query, params=None):
        result_mock = Mock()
        
        # Mock schema existence check
        if "information_schema" in str(query) and "table_name" in str(query):
            result_mock.fetchone.return_value = (True,)  # Table exists
            
        # Mock version check
        elif "schema_metadata" in str(query):
            result_mock.fetchone.return_value = (2,)
            
        else:
            # Default: empty result
            result_mock.fetchall.return_value = []
            result_mock.fetchone.return_value = None
            result_mock.rowcount = 0
            
        return result_mock
    
    mock_conn.execute.side_effect = execute_side_effect
    
    # Support context manager protocol
    mock_conn.__enter__ = Mock(return_value=mock_conn)
    mock_conn.__exit__ = Mock(return_value=False)
    
    return mock_conn


@pytest.fixture
def mock_connection_pool(mock_database_connection):
    """Mock connection pool for unit tests."""
    mock_pool = Mock()
    
    def get_connection_side_effect(timeout=None):
        context_manager = Mock()
        context_manager.__enter__ = Mock(return_value=mock_database_connection)
        context_manager.__exit__ = Mock(return_value=False)
        return context_manager
    
    mock_pool.connection.side_effect = get_connection_side_effect
    mock_pool.get_stats.return_value = {
        'connections_num': 1,
        'connections_free': 0,
        'connections_waiting': 0
    }
    mock_pool.close.return_value = None
    mock_pool.open.return_value = None
    
    return mock_pool


@pytest.fixture
def temp_csv_file(tmp_path, sample_domains):
    """Create temporary CSV file with labeled dataset format."""
    import pandas as pd
    
    csv_data = {
        'domain': [
            "google.com",
            "facebook.com", 
            "unknown-test-123.example.org",
            "suspicious-domain.click",
            "malware-site.bad.tld"
        ],
        'registered_domain': [
            "google.com",
            "facebook.com",
            "example.org",
            "domain.click",
            "site.bad.tld"
        ],
        'tld': ['com', 'com', 'org', 'click', 'tld'],
        'response_code': ['NOERROR', 'NOERROR', 'NOERROR', 'NOERROR', 'NXDOMAIN'],
        'threat_score': [-100, -100, 45, 85, 100],
        'label': ['Benign', 'Benign', 'Suspicious', 'Malicious', 'Malicious'],
        'confidence': [95, 95, 78, 92, 98],
        'label_reason': [
            'Trusted Tranco Domain; Benign score',
            'Trusted Tranco Domain; Benign score',
            'Long second-level domain; High digit ratio',
            'Suspicious TLD; Botnet indicators',
            'Known Malicious Domain (URLhaus); Phishing'
        ]
    }
    
    df = pd.DataFrame(csv_data)
    csv_path = tmp_path / "test_labeled_dataset.csv"
    df.to_csv(csv_path, index=False)
    
    return csv_path


# Pytest markers for test categorization
def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line("markers", "unit: marks tests as unit tests")
    config.addinivalue_line("markers", "integration: marks tests as integration tests")
    config.addinivalue_line("markers", "performance: marks tests as performance tests")
    config.addinivalue_line("markers", "slow: marks tests that take long time")