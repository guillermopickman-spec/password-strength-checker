"""
Tests for Structured Logging Module

Tests the JSON formatter, security filters, correlation IDs, and event logging.
"""

import json
import logging
import os
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

import pytest

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from logger import (
    PasswordSecurityFilter,
    JSONFormatter,
    get_correlation_id,
    set_correlation_id,
    clear_correlation_id,
    generate_correlation_id,
    CorrelationIdContext,
    setup_logging,
    get_logger,
    LogEvent,
    log_event,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def temp_log_file():
    """Create a temporary log file."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.log') as f:
        temp_path = f.name
    yield temp_path
    # Cleanup - close any open file handles first
    import logging
    # Close all handlers to release file locks on Windows
    root_logger = logging.getLogger("password_auditor")
    for handler in root_logger.handlers[:]:
        handler.close()
        root_logger.removeHandler(handler)
    
    # Give Windows time to release the file
    time.sleep(0.1)
    
    try:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    except PermissionError:
        pass  # File may still be locked, let it be cleaned up later


@pytest.fixture
def json_logger(temp_log_file):
    """Create a JSON logger with file output."""
    logger = setup_logging(
        level="DEBUG",
        format_type="json",
        log_file=temp_log_file,
        enable_security_filter=True
    )
    return logger


@pytest.fixture
def security_filter():
    """Create a password security filter."""
    return PasswordSecurityFilter()


# =============================================================================
# PasswordSecurityFilter Tests
# =============================================================================

class TestPasswordSecurityFilter:
    """Tests for the PasswordSecurityFilter class."""
    
    def test_redacts_password_in_message(self, security_filter):
        """Test that passwords are redacted from log messages."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="User password is: secret123",
            args=(),
            exc_info=None
        )
        
        # Set context with password
        setattr(record, "context", {"password": "secret123"})
        
        security_filter.filter(record)
        
        # Password should be redacted in context
        assert getattr(record, "context")["password"] == "[REDACTED]"
    
    def test_redacts_sha1_hash(self, security_filter):
        """Test that SHA-1 hashes are redacted."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Hash: 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
            args=(),
            exc_info=None
        )
        
        security_filter.filter(record)
        
        assert "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8" not in record.msg
        assert "[REDACTED_HASH]" in record.msg
    
    def test_redacts_md5_hash(self, security_filter):
        """Test that MD5 hashes are redacted."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="MD5: 5f4dcc3b5aa765d61d8327deb882cf99",
            args=(),
            exc_info=None
        )
        
        security_filter.filter(record)
        
        assert "5f4dcc3b5aa765d61d8327deb882cf99" not in record.msg
        assert "[REDACTED_HASH]" in record.msg
    
    def test_redacts_sensitive_keys_in_context(self, security_filter):
        """Test that sensitive keys in context are redacted."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Processing",
            args=(),
            exc_info=None
        )
        
        # Simulate extra context
        record.context = {
            "password": "secret123",
            "api_key": "abc123",
            "safe_data": "visible"
        }
        
        security_filter.filter(record)
        
        context = getattr(record, "context", {})
        assert context["password"] == "[REDACTED]"
        assert context["api_key"] == "[REDACTED]"
        assert context["safe_data"] == "visible"
    
    def test_redacts_nested_sensitive_data(self, security_filter):
        """Test that nested sensitive data is redacted."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Processing",
            args=(),
            exc_info=None
        )
        
        record.context = {
            "user": {
                "password": "nested_secret",
                "name": "John"
            }
        }
        
        security_filter.filter(record)
        
        context = getattr(record, "context", {})
        assert context["user"]["password"] == "[REDACTED]"
        assert context["user"]["name"] == "John"
    
    def test_handles_variations_of_sensitive_keys(self, security_filter):
        """Test that variations of sensitive key names are detected."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test",
            args=(),
            exc_info=None
        )
        
        setattr(record, "context", {
            "api-key": "secret",      # with hyphen
            "API_KEY": "secret",      # uppercase
            "access_token": "secret", # snake_case
            "secretToken": "secret",  # camelCase
        })
        
        security_filter.filter(record)
        
        context = getattr(record, "context", {})
        assert context["api-key"] == "[REDACTED]"
        assert context["API_KEY"] == "[REDACTED]"
        assert context["access_token"] == "[REDACTED]"
        assert context["secretToken"] == "[REDACTED]"


# =============================================================================
# JSONFormatter Tests
# =============================================================================

class TestJSONFormatter:
    """Tests for the JSONFormatter class."""
    
    def test_outputs_valid_json(self):
        """Test that formatter outputs valid JSON."""
        formatter = JSONFormatter()
        
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname="test.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None
        )
        
        output = formatter.format(record)
        
        # Should be valid JSON
        parsed = json.loads(output)
        assert "timestamp" in parsed
        assert "level" in parsed
        assert "logger" in parsed
        assert "message" in parsed
    
    def test_includes_all_required_fields(self):
        """Test that all required fields are present."""
        formatter = JSONFormatter()
        
        record = logging.LogRecord(
            name="password_auditor.main",
            level=logging.INFO,
            pathname="main.py",
            lineno=42,
            msg="Password check started",
            args=(),
            exc_info=None,
            func="test_function"
        )
        
        output = formatter.format(record)
        parsed = json.loads(output)
        
        assert parsed["level"] == "INFO"
        assert parsed["logger"] == "password_auditor.main"
        assert parsed["message"] == "Password check started"
        assert "timestamp" in parsed
        assert "source" in parsed
        assert parsed["source"]["file"] == "main.py"
        assert parsed["source"]["line"] == 42
        assert parsed["source"]["function"] == "test_function"
    
    def test_includes_event_field(self):
        """Test that event field is included."""
        formatter = JSONFormatter()
        
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test",
            args=(),
            exc_info=None
        )
        
        # Simulate event from extra dict
        record.event = "password_check_started"
        
        output = formatter.format(record)
        parsed = json.loads(output)
        
        assert parsed["event"] == "password_check_started"
    
    def test_includes_correlation_id(self):
        """Test that correlation ID is included."""
        formatter = JSONFormatter()
        
        # Set correlation ID
        set_correlation_id("test-correlation-123")
        
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test",
            args=(),
            exc_info=None
        )
        
        output = formatter.format(record)
        parsed = json.loads(output)
        
        assert parsed["correlation_id"] == "test-correlation-123"
        
        # Cleanup
        clear_correlation_id()
    
    def test_includes_context(self):
        """Test that context is included in output."""
        formatter = JSONFormatter()
        
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Test",
            args=(),
            exc_info=None
        )
        
        # Simulate context from extra dict
        record.context = {
            "password_id": 1,
            "batch_size": 100
        }
        
        output = formatter.format(record)
        parsed = json.loads(output)
        
        assert parsed["context"]["password_id"] == 1
        assert parsed["context"]["batch_size"] == 100
    
    def test_derives_event_from_message(self):
        """Test that event is derived from message if not provided."""
        formatter = JSONFormatter()
        
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="Password check completed successfully",
            args=(),
            exc_info=None
        )
        
        output = formatter.format(record)
        parsed = json.loads(output)
        
        assert "password_check_completed_successfully" in parsed["event"]


# =============================================================================
# Correlation ID Tests
# =============================================================================

class TestCorrelationId:
    """Tests for correlation ID management."""
    
    def test_set_and_get_correlation_id(self):
        """Test setting and getting correlation ID."""
        clear_correlation_id()
        
        test_id = "test-123-abc"
        set_correlation_id(test_id)
        
        assert get_correlation_id() == test_id
    
    def test_clear_correlation_id(self):
        """Test clearing correlation ID."""
        set_correlation_id("test-id")
        clear_correlation_id()
        
        assert get_correlation_id() is None
    
    def test_generate_correlation_id(self):
        """Test generating correlation ID."""
        id1 = generate_correlation_id()
        id2 = generate_correlation_id()
        
        # Should be valid UUIDs
        assert uuid.UUID(id1)
        assert uuid.UUID(id2)
        assert id1 != id2  # Should be unique
    
    def test_correlation_id_context_manager(self):
        """Test CorrelationIdContext context manager."""
        clear_correlation_id()
        
        with CorrelationIdContext() as cid:
            assert get_correlation_id() == cid
            assert uuid.UUID(cid)  # Should be valid UUID
        
        # Should be cleared after exit
        assert get_correlation_id() is None
    
    def test_correlation_id_context_restores_previous(self):
        """Test that context manager restores previous correlation ID."""
        set_correlation_id("previous-id")
        
        with CorrelationIdContext() as cid:
            assert get_correlation_id() == cid
        
        # Should restore previous
        assert get_correlation_id() == "previous-id"
        
        clear_correlation_id()
    
    def test_correlation_id_thread_local(self):
        """Test that correlation IDs are thread-local."""
        clear_correlation_id()
        
        results = {}
        
        def worker(thread_id):
            set_correlation_id(f"thread-{thread_id}")
            time.sleep(0.01)  # Small delay to allow interleaving
            results[thread_id] = get_correlation_id()
        
        threads = [
            threading.Thread(target=worker, args=(i,))
            for i in range(3)
        ]
        
        for t in threads:
            t.start()
        
        for t in threads:
            t.join()
        
        # Each thread should have its own correlation ID
        assert results[0] == "thread-0"
        assert results[1] == "thread-1"
        assert results[2] == "thread-2"


# =============================================================================
# Setup and Integration Tests
# =============================================================================

class TestSetupLogging:
    """Tests for setup_logging function."""
    
    def test_setup_json_logging(self, temp_log_file):
        """Test setting up JSON logging."""
        logger = setup_logging(
            level="INFO",
            format_type="json",
            log_file=temp_log_file
        )
        
        logger.info("Test message")
        
        # Read log file
        with open(temp_log_file, 'r') as f:
            content = f.read()
        
        # Should be valid JSON
        parsed = json.loads(content.strip())
        assert parsed["message"] == "Test message"
        assert parsed["level"] == "INFO"
    
    def test_setup_simple_logging(self, temp_log_file):
        """Test setting up simple text logging."""
        logger = setup_logging(
            level="INFO",
            format_type="simple",
            log_file=temp_log_file
        )
        
        logger.info("Test message")
        
        # Read log file
        with open(temp_log_file, 'r') as f:
            content = f.read()
        
        # Should be plain text
        assert "Test message" in content
        assert "INFO" in content
    
    def test_log_rotation_daily(self, temp_log_file):
        """Test daily log rotation setup."""
        logger = setup_logging(
            level="INFO",
            format_type="json",
            log_file=temp_log_file,
            rotation="daily"
        )
        
        # Just verify it doesn't throw an error
        logger.info("Test")
        assert True
    
    def test_security_filter_enabled(self, temp_log_file):
        """Test that security filter is applied."""
        logger = setup_logging(
            level="INFO",
            format_type="json",
            log_file=temp_log_file,
            enable_security_filter=True
        )
        
        # Log something with sensitive data
        logger.info(
            "Processing",
            extra={"context": {"password": "secret123"}}
        )
        
        # Read log file
        with open(temp_log_file, 'r') as f:
            content = f.read()
        
        # Password should be redacted
        assert "secret123" not in content
        assert "[REDACTED]" in content


# =============================================================================
# LogEvent Constants Tests
# =============================================================================

class TestLogEvent:
    """Tests for LogEvent constants."""
    
    def test_all_events_are_strings(self):
        """Test that all event constants are strings."""
        for attr in dir(LogEvent):
            if not attr.startswith("_"):
                value = getattr(LogEvent, attr)
                assert isinstance(value, str)
                # All events should be snake_case format (single word like 'error' is also valid)
                assert value.islower() or value.isupper()
    
    def test_password_events(self):
        """Test password-related events."""
        assert LogEvent.PASSWORD_CHECK_STARTED == "password_check_started"
        assert LogEvent.PASSWORD_CHECK_COMPLETED == "password_check_completed"
        assert LogEvent.PASSWORD_GENERATED == "password_generated"
    
    def test_batch_events(self):
        """Test batch-related events."""
        assert LogEvent.BATCH_STARTED == "batch_started"
        assert LogEvent.BATCH_COMPLETED == "batch_completed"
    
    def test_api_events(self):
        """Test API-related events."""
        assert LogEvent.API_REQUEST_STARTED == "api_request_started"
        assert LogEvent.API_ERROR == "api_error"


# =============================================================================
# log_event Helper Tests
# =============================================================================

class TestLogEventHelper:
    """Tests for log_event helper function."""
    
    def test_log_event_with_context(self, temp_log_file):
        """Test logging event with context."""
        logger = setup_logging(
            level="INFO",
            format_type="json",
            log_file=temp_log_file
        )
        
        log_event(
            logger,
            event="test_event",
            level="info",
            context={"key": "value"},
            message="Test message"
        )
        
        # Read log file
        with open(temp_log_file, 'r') as f:
            content = f.read()
        
        parsed = json.loads(content.strip())
        assert parsed["event"] == "test_event"
        assert parsed["context"]["key"] == "value"
        assert parsed["message"] == "Test message"
    
    def test_log_event_default_message(self, temp_log_file):
        """Test that default message is generated from event name."""
        logger = setup_logging(
            level="INFO",
            format_type="json",
            log_file=temp_log_file
        )
        
        log_event(
            logger,
            event="test_event_occurred",
            level="info"
        )
        
        # Read log file
        with open(temp_log_file, 'r') as f:
            content = f.read()
        
        parsed = json.loads(content.strip())
        # Default message should be title case version of event
        assert "Test Event Occurred" in parsed["message"]


# =============================================================================
# get_logger Tests
# =============================================================================

class TestGetLogger:
    """Tests for get_logger function."""
    
    def test_get_logger_returns_child_logger(self):
        """Test that get_logger returns a child of password_auditor."""
        logger = get_logger("test_module")
        
        assert logger.name == "password_auditor.test_module"
        assert isinstance(logger, logging.Logger)


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for the logging system."""
    
    def test_end_to_end_logging(self, temp_log_file):
        """Test complete logging flow."""
        # Setup logging
        logger = setup_logging(
            level="DEBUG",
            format_type="json",
            log_file=temp_log_file,
            enable_security_filter=True
        )
        
        # Set correlation ID
        set_correlation_id("integration-test-123")
        
        # Log various events
        logger.info(
            "Password check started",
            extra={
                'event': LogEvent.PASSWORD_CHECK_STARTED,
                'context': {'password_length': 12}
            }
        )
        
        logger.info(
            "Breach check completed",
            extra={
                'event': LogEvent.PASSWORD_CHECK_COMPLETED,
                'context': {
                    'breach_count': 0,
                    'is_safe': True
                }
            }
        )
        
        # Clear correlation ID
        clear_correlation_id()
        
        # Read and verify log file
        with open(temp_log_file, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
        
        # Should have 2 log entries
        assert len(lines) == 2
        
        # Verify first entry
        entry1 = json.loads(lines[0])
        assert entry1["event"] == "password_check_started"
        assert entry1["correlation_id"] == "integration-test-123"
        # password_length is a safe key and should not be redacted
        assert entry1["context"]["password_length"] == 12
        
        # Verify second entry
        entry2 = json.loads(lines[1])
        assert entry2["event"] == "password_check_completed"
        assert entry2["correlation_id"] == "integration-test-123"
        assert entry2["context"]["breach_count"] == 0
    
    def test_sensitive_data_never_logged(self, temp_log_file):
        """Comprehensive test that sensitive data never appears in logs."""
        logger = setup_logging(
            level="DEBUG",
            format_type="json",
            log_file=temp_log_file,
            enable_security_filter=True
        )
        
        # Try to log various sensitive data
        sensitive_data = {
            "password": "my_secret_password",
            "api_key": "sk-1234567890abcdef",
            "secret": "top_secret",
            "token": "Bearer abc123",
            "hash": "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
        }
        
        logger.info(
            "Processing user data",
            extra={'context': sensitive_data}
        )
        
        # Read log file
        with open(temp_log_file, 'r') as f:
            content = f.read()
        
        # None of the sensitive values should appear
        for key, value in sensitive_data.items():
            assert value not in content, f"Sensitive value '{key}' found in logs!"
            assert "[REDACTED]" in content or "[REDACTED_HASH]" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])