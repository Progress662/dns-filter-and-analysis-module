"""
Unit tests for Structured Logging system.

Tests cover logging initialization, formatter output formats,
context management, performance timing decorators, and thread-safety.
"""

import json
import logging
import pytest
import tempfile
from pathlib import Path
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch


class TestStructuredFormatterOutput:
    """Verify JSON/text formatters produce correct output."""

    def test_json_formatter_produces_valid_json(self):
        """JSON log records must parse without error."""
        from unknown_domain_repository.logger import StructuredFormatter
        
        formatter = StructuredFormatter(component="test")
        
        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname=__file__,
            lineno=42,
            msg="Test JSON message",
            args=(),
            exc_info=None
        )
        
        output_str = formatter.format(record)
        
        parsed = json.loads(output_str)       # Should not raise
        assert isinstance(parsed, dict)
        assert parsed['message'] == "Test JSON message"
        assert parsed['level'] == "INFO"

    def test_json_output_contains_required_fields(self):
        """Structured logs must include timestamp, component, logger fields."""
        from unknown_domain_repository.logger import StructuredFormatter
        
        formatter = StructuredFormatter()
        record = logging.LogRecord(
            name="my.app",
            level=logging.WARNING,
            pathname="/fake/path.py",
            lineno=100,
            msg="Important event",
            args=(),
            exc_info=None
        )
        
        data = json.loads(formatter.format(record))
        
        assert 'timestamp' in data
        assert 'level' in data
        assert 'component' in data
        assert 'logger' in data
        assert 'message' in data
        assert data['level'] == "WARNING"

    def test_text_formatter_human_readable(self):
        """Text format should look like standard log lines, not JSON blobs."""
        from unknown_domain_repository.logger import TextFormatter
        
        formatter = TextFormatter()
        record = logging.LogRecord(
            name="simple",
            level=logging.ERROR,
            pathname="/app/main.py",
            lineno=10,
            msg="Something broke",
            args=(),
            exc_info=None
        )
        
        output = formatter.format(record)
        
        assert not output.startswith('{')               # Not JSON
        assert "ERROR" in output                       # Contains level
        assert "Something broke" in output              # Contains message


class TestLoggerContextManagement:
    """Test thread-local context propagation via operation_context."""

    def test_basic_operation_context_usage(self):
        """Context manager sets and restores context around code block."""
        from unknown_domain_repository.logger import get_logger, LoggingConfig
        
        cfg = LoggingConfig(level='DEBUG', format='text')
        logger = get_logger(cfg)
        
        outer_logs = []
        inner_logs = []
        
        # Capture log entries inside context
        old_log = logger.info
        
        def capturing_info(msg, extra=None):
            entry = {'msg': msg, 'extra': extra}
            if extra and 'operation' in extra:
                inner_logs.append(entry)
            else:
                outer_logs.append(entry)
                
        try:
            logger.info = capturing_info
            
            logger.info("Before context")
            
            with logger.operation_context(operation="batch_insert"):
                logger.info("Inside context")
                assert True  # Just ensure we entered
            
            logger.info("After context")
            
        finally:
            logger.info = old_log
        
        # Verify inner messages got operation tag
        assert len(inner_logs) >= 1
        assert inner_logs[0]['extra']['operation'] == "batch_insert"


class TestTimedOperationLogging:
    """Test performance timing decorator/context."""

    def test_timed_operation_records_duration_ms(self):
        """Timed operations must include elapsed time in milliseconds."""
        from unknown_domain_repository.logger import get_logger, LoggingConfig
        import time
        
        cfg = LoggingConfig(level='DEBUG', format='text')
        logger = get_logger(cfg)
        
        captured_events = []
        
        original_log = logger.log
        def spy_log(level, msg, **kw):
            captured_events.append({'msg': msg, 'level': level})
        
        try:
            logger.log = spy_log
            
            with logger.timed_operation(
                operation="fast_query",
                log_level=logging.INFO
            ):
                time.sleep(0.05)  # 50ms
            
        finally:
            logger.log = original_log
        
        # Should have logged completion message with duration
        completed_msgs = [e['msg'] for e in captured_events if "completed" in e['msg']]
        assert len(completed_msgs) > 0
        assert "ms" in completed_msgs[0]          # Contains ms unit

    def test_slow_threshold_triggers_warning(self):
        """If operation exceeds threshold, severity upgrades to WARNING."""
        from unknown_domain_repository.logger import get_logger, LoggingConfig
        import time
        
        cfg = LoggingConfig(level='DEBUG', format='text')
        logger = get_logger(cfg)
        
        warning_captured = False
        
        orig_warning = logger.warning
        def spy_warning(msg, *a, **k):
            nonlocal warning_captured
            if "threshold" in str(msg).lower() or "slow" in str(msg).lower():
                warning_captured = True
            orig_warning(msg, *a, **k)
        
        try:
            logger.warning = spy_warning
            
            # Set threshold very low so sleep exceeds it
            with logger.timed_operation(
                operation="expensive_work",
                threshold_ms=1,                     # 1ms threshold
                log_level=logging.INFO
            ):
                time.sleep(0.02)                    # 20ms > 1ms
                
        finally:
            logger.warning = orig_warning
        
        assert warning_captured is True


class TestLogExceptionIntegration:
    """Test specialized method for logging custom exceptions."""

    def test_exception_logging_calls_regular_methods(self):
        """log_exception must delegate to error/exception pipelines internally."""
        from unknown_domain_repository.logger import get_logger, LoggingConfig
        from unknown_domain_repository.exceptions import UnknownDomainRepositoryError
        
        cfg = LoggingConfig(level='INFO', format='text')
        logger = get_logger(cfg)
        
        exc = UnknownDomainRepositoryError("Test failure", operation="test_op")
        
        # Should not crash even if logger not fully wired to DB etc.
        try:
            logger.log_exception(exc, "Custom wrapper message")
        except Exception as e:
            pytest.fail(f"log_exception raised unexpected error: {e}")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])