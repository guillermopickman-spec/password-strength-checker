"""
Structured Logging Module for Password Strength Auditor

Provides JSON-formatted logging with security filters to prevent password exposure.
Supports correlation IDs for tracing batch operations and configurable destinations.

Security-critical: NEVER logs passwords, password hashes, or API keys.

Usage:
    from logger import get_logger, set_correlation_id
    
    logger = get_logger(__name__)
    logger.info("password_check_started", extra={"context": {"password_id": 1}})
    
    # For batch operations
    set_correlation_id("batch-123")
    logger.info("batch_started", extra={"context": {"total_passwords": 100}})
"""

import json
import logging
import logging.handlers
import sys
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from config import Config


# =============================================================================
# Security Filter - Prevents Password Exposure
# =============================================================================

class PasswordSecurityFilter(logging.Filter):
    """
    Security filter that prevents passwords and sensitive data from being logged.
    
    Scans log records for potential password patterns and redacts them.
    """
    
    # Patterns that indicate sensitive data (exact matches or specific patterns)
    SENSITIVE_KEYS = {
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
        'access_token', 'refresh_token', 'auth_token', 'bearer_token',
        'sha1', 'md5', 'password_hash', 'pwned_hash',
        'hibp_api_key', 'api_secret', 'private_key', 'credential',
    }
    
    # Keys that are safe (should not be redacted even if they contain sensitive words)
    SAFE_KEYS = {
        'password_length', 'password_id', 'password_count', 'password_policy',
        'password_strength', 'password_score', 'is_password', 'has_password',
    }
    
    # Regex patterns for sensitive values
    SENSITIVE_PATTERNS = [
        r'\b[a-fA-F0-9]{40}\b',  # SHA-1 hash
        r'\b[a-fA-F0-9]{32}\b',  # MD5 hash
        r'\b[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}\b',  # JWT
    ]
    
    def __init__(self, name: str = ""):
        super().__init__(name)
        import re
        self._patterns = [re.compile(p) for p in self.SENSITIVE_PATTERNS]
    
    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter log record to remove sensitive data.
        
        Returns:
            True always (we modify in place, don't drop records)
        """
        # Check message
        if hasattr(record, 'msg') and isinstance(record.msg, str):
            record.msg = self._redact_sensitive_data(record.msg)
        
        # Check args
        if hasattr(record, 'args') and record.args:
            record.args = self._redact_args(record.args)
        
        # Check extra context
        context = getattr(record, 'context', None)
        if isinstance(context, dict):
            record.context = self._redact_context(context)
        
        return True
    
    def _redact_sensitive_data(self, text: str) -> str:
        """Redact sensitive patterns from text."""
        if not isinstance(text, str):
            return text
        
        # Redact hash patterns
        for pattern in self._patterns:
            text = pattern.sub('[REDACTED_HASH]', text)
        
        return text
    
    def _redact_args(self, args: Any) -> Any:
        """Redact sensitive data from log args."""
        if args is None:
            return args
        
        # Handle both tuple and dict (Mapping) types
        if isinstance(args, dict):
            return self._redact_context(args)
        
        redacted = []
        for arg in args:
            if isinstance(arg, str):
                redacted.append(self._redact_sensitive_data(arg))
            elif isinstance(arg, dict):
                redacted.append(self._redact_context(arg))
            else:
                redacted.append(arg)
        return tuple(redacted)
    
    def _redact_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive keys from context dictionary."""
        if not isinstance(context, dict):
            return context
        
        redacted = {}
        import re
        for key, value in context.items():
            # Normalize key: handle hyphens, spaces, and camelCase
            key_normalized = str(key).replace('-', '_').replace(' ', '_')
            # Handle camelCase: secretToken → secret_token, APIKey → api_key
            key_normalized = re.sub(r'([a-z])([A-Z])', r'\1_\2', key_normalized)
            # Now lowercase
            key_normalized = key_normalized.lower()
            
            # Skip safe keys
            if key_normalized in self.SAFE_KEYS:
                redacted[key] = value
                continue
            
            # Check for exact match or sensitive key patterns
            is_sensitive = False
            for sensitive in self.SENSITIVE_KEYS:
                # Match exact key or key that starts/ends with sensitive word
                if (key_normalized == sensitive or 
                    key_normalized.startswith(sensitive + '_') or
                    key_normalized.endswith('_' + sensitive)):
                    is_sensitive = True
                    break
            
            if is_sensitive:
                redacted[key] = '[REDACTED]'
            elif isinstance(value, dict):
                redacted[key] = self._redact_context(value)
            elif isinstance(value, str):
                redacted[key] = self._redact_sensitive_data(value)
            else:
                redacted[key] = value
        
        return redacted


# =============================================================================
# JSON Formatter
# =============================================================================

class JSONFormatter(logging.Formatter):
    """
    JSON formatter for structured logging.
    
    Output format:
    {
        "timestamp": "2024-01-15T10:30:00.123456Z",
        "level": "INFO",
        "logger": "password_auditor.main",
        "event": "password_check_started",
        "message": "Human readable message",
        "correlation_id": "uuid-123",
        "context": {
            "password_id": 1,
            "batch_size": 100
        },
        "source": {
            "file": "main.py",
            "line": 42,
            "function": "check_password"
        }
    }
    """
    
    def __init__(self):
        super().__init__()
        self._hostname = self._get_hostname()
    
    def _get_hostname(self) -> str:
        """Get system hostname."""
        import socket
        try:
            return socket.gethostname()
        except Exception:
            return "unknown"
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        # Build base log entry
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        
        # Add event type if available
        event = getattr(record, 'event', None)
        if event:
            log_entry['event'] = event
        else:
            # Derive event from message or logger name
            log_entry['event'] = self._derive_event(record)
        
        # Add correlation ID if available
        correlation_id = get_correlation_id()
        if correlation_id:
            log_entry['correlation_id'] = correlation_id
        
        # Add context if available
        context = getattr(record, 'context', None)
        if context:
            log_entry['context'] = context
        
        # Add source information
        log_entry['source'] = {  # type: ignore
            "file": record.filename,
            "line": record.lineno,
            "function": record.funcName,
            "module": record.module,
        }
        
        # Add hostname
        log_entry['hostname'] = self._hostname
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry, default=str)
    
    def _derive_event(self, record: logging.LogRecord) -> str:
        """Derive event name from log record."""
        # Try to extract from message (snake_case)
        msg = record.getMessage().lower().replace(' ', '_')
        msg = ''.join(c if c.isalnum() or c == '_' else '_' for c in msg)
        msg = '_'.join(filter(None, msg.split('_')))  # Remove empty parts
        
        # Limit length
        if len(msg) > 50:
            msg = msg[:50]
        
        return msg or "log_message"


# =============================================================================
# Correlation ID Management
# =============================================================================

# Thread-local storage for correlation IDs
_local_storage = threading.local()


def get_correlation_id() -> Optional[str]:
    """Get current correlation ID for this thread."""
    return getattr(_local_storage, 'correlation_id', None)


def set_correlation_id(correlation_id: Optional[str]) -> None:
    """
    Set correlation ID for current thread.
    
    Args:
        correlation_id: UUID or string identifier for tracing
    """
    if correlation_id:
        _local_storage.correlation_id = str(correlation_id)
    else:
        _local_storage.correlation_id = None


def clear_correlation_id() -> None:
    """Clear correlation ID for current thread."""
    _local_storage.correlation_id = None


def generate_correlation_id() -> str:
    """Generate a new correlation ID."""
    return str(uuid.uuid4())


# Context manager for correlation IDs
class CorrelationIdContext:
    """Context manager for setting correlation ID."""
    
    def __init__(self, correlation_id: Optional[str] = None):
        self.correlation_id = correlation_id or generate_correlation_id()
        self.previous_id: Optional[str] = None
    
    def __enter__(self):
        self.previous_id = get_correlation_id()
        set_correlation_id(self.correlation_id)
        return self.correlation_id
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.previous_id:
            set_correlation_id(self.previous_id)
        else:
            clear_correlation_id()
        return False


# =============================================================================
# Logger Setup
# =============================================================================

def setup_logging(
    level: str = "INFO",
    format_type: str = "json",
    log_file: Optional[str] = None,
    rotation: Optional[str] = None,
    enable_security_filter: bool = True
) -> logging.Logger:
    """
    Setup structured logging with security filters.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_type: Output format ("json" or "simple")
        log_file: Optional file path for logging
        rotation: Rotation policy ("daily", "weekly", "size")
        enable_security_filter: Whether to enable password security filter
    
    Returns:
        Configured root logger
    """
    # Get root logger for password_auditor
    logger = logging.getLogger("password_auditor")
    logger.setLevel(getattr(logging, level.upper()))
    
    # Only clear handlers if they exist (avoid closing file handles prematurely)
    if logger.handlers:
        for handler in logger.handlers[:]:
            handler.close()
            logger.removeHandler(handler)
    
    # Create formatter
    if format_type.lower() == "json":
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        if rotation == "daily":
            file_handler = logging.handlers.TimedRotatingFileHandler(
                log_file, when='midnight', backupCount=7
            )
        elif rotation == "weekly":
            file_handler = logging.handlers.TimedRotatingFileHandler(
                log_file, when='W0', backupCount=4
            )
        elif rotation == "size":
            file_handler = logging.handlers.RotatingFileHandler(
                log_file, maxBytes=10*1024*1024, backupCount=5
            )
        else:
            file_handler = logging.FileHandler(log_file)
        
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Add security filter
    if enable_security_filter:
        security_filter = PasswordSecurityFilter()
        logger.addFilter(security_filter)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the specified name.
    
    The logger will be a child of the password_auditor root logger
    and will inherit security filters and formatters.
    
    Args:
        name: Logger name (typically __name__)
    
    Returns:
        Configured logger instance
    """
    return logging.getLogger(f"password_auditor.{name}")


# =============================================================================
# Convenience Logging Functions
# =============================================================================

def log_event(
    logger: logging.Logger,
    event: str,
    level: str = "info",
    context: Optional[Dict[str, Any]] = None,
    message: Optional[str] = None
) -> None:
    """
    Log a structured event.
    
    Args:
        logger: Logger instance
        event: Event name (snake_case recommended)
        level: Log level
        context: Additional context data
        message: Optional human-readable message
    """
    extra: Dict[str, Any] = {'event': event}
    
    if context:
        extra['context'] = context
    
    msg = message or event.replace('_', ' ').title()
    
    log_method = getattr(logger, level.lower())
    log_method(msg, extra=extra)


# =============================================================================
# Auto-initialization from Config
# =============================================================================

def init_logging_from_config(config: Optional[Config] = None) -> logging.Logger:
    """
    Initialize logging from configuration.
    
    Args:
        config: Configuration instance (loads default if None)
    
    Returns:
        Configured root logger
    """
    if config is None:
        config = Config.load()
    
    return setup_logging(
        level=config.logging.level,
        format_type=config.logging.format,
        log_file=config.logging.file,
        rotation=config.logging.rotation,
        enable_security_filter=True
    )


# Initialize on module load
_root_logger: Optional[logging.Logger] = None


def get_root_logger() -> logging.Logger:
    """Get or initialize the root logger."""
    global _root_logger
    if _root_logger is None:
        _root_logger = init_logging_from_config()
    return _root_logger


# =============================================================================
# Event Types (Constants for Standardization)
# =============================================================================

class LogEvent:
    """Standard event types for logging."""
    
    # Password operations
    PASSWORD_CHECK_STARTED = "password_check_started"
    PASSWORD_CHECK_COMPLETED = "password_check_completed"
    PASSWORD_GENERATED = "password_generated"
    PASSPHRASE_GENERATED = "passphrase_generated"
    
    # Batch operations
    BATCH_STARTED = "batch_started"
    BATCH_COMPLETED = "batch_completed"
    BATCH_PROGRESS = "batch_progress"
    
    # API operations
    API_REQUEST_STARTED = "api_request_started"
    API_REQUEST_COMPLETED = "api_request_completed"
    API_ERROR = "api_error"
    API_RATE_LIMITED = "api_rate_limited"
    
    # Cache operations
    CACHE_HIT = "cache_hit"
    CACHE_MISS = "cache_miss"
    CACHE_ERROR = "cache_error"
    
    # Security events
    SECURITY_VIOLATION = "security_violation"
    SENSITIVE_DATA_BLOCKED = "sensitive_data_blocked"
    
    # Configuration
    CONFIG_LOADED = "config_loaded"
    CONFIG_ERROR = "config_error"
    
    # Application lifecycle
    APPLICATION_STARTED = "application_started"
    APPLICATION_SHUTDOWN = "application_shutdown"
    ERROR = "error"


# Example usage
if __name__ == "__main__":
    # Demo logging
    logger = setup_logging(level="INFO", format_type="json")
    
    # Single password check
    logger.info(
        "Password check started",
        extra={
            'event': LogEvent.PASSWORD_CHECK_STARTED,
            'context': {'password_length': 12}
        }
    )
    
    # With correlation ID
    set_correlation_id("demo-batch-123")
    logger.info(
        "Batch processing started",
        extra={
            'event': LogEvent.BATCH_STARTED,
            'context': {'total_passwords': 100}
        }
    )
    
    # Try to log sensitive data (will be redacted)
    logger.info(
        "Processing password with hash: 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
        extra={
            'event': 'test_event',
            'context': {'password': 'secret123', 'api_key': 'abc123'}
        }
    )
    
    clear_correlation_id()