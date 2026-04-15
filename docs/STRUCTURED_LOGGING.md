# 📊 Structured Logging Documentation

## Overview

The Password Strength Auditor includes **enterprise-grade structured logging** for SIEM integration and comprehensive audit trails. This feature enables integration with security information and event management (SIEM) systems like Splunk, ELK Stack, and Datadog.

## Features

| Feature | Description | Status |
|---------|-------------|--------|
| **JSON Format** | Machine-readable logs for automated processing | ✅ |
| **Security Filters** | Automatic redaction of sensitive data | ✅ |
| **Correlation IDs** | Distributed tracing across operations | ✅ |
| **Configurable Destinations** | Console, file, or syslog output | ✅ |
| **Log Rotation** | Daily, weekly, or size-based rotation | ✅ |
| **Thread-Safe** | Multi-threaded batch processing support | ✅ |

## Quick Start

```python
from logger import get_logger, set_correlation_id, LogEvent

# Get structured logger
logger = get_logger(__name__)

# Set correlation ID for tracing batch operations
set_correlation_id("batch-123")

# Log events with structured context
logger.info(
    "Password check started",
    extra={
        'event': LogEvent.PASSWORD_CHECK_STARTED,
        'context': {
            'password_length': 12,
            'batch_size': 100
        }
    }
)
```

## Log Output Format

### Standard JSON Log Entry

```json
{
  "timestamp": "2024-01-15T10:30:00.123456Z",
  "level": "INFO",
  "logger": "password_auditor.main",
  "event": "password_check_started",
  "message": "Password check started",
  "correlation_id": "batch-123",
  "context": {
    "password_length": 12,
    "batch_size": 100
  },
  "source": {
    "file": "main.py",
    "line": 42,
    "function": "check_password",
    "module": "main"
  },
  "hostname": "server-01"
}
```

### Event Types

Standard events are defined in `LogEvent`:

| Event | Description |
|-------|-------------|
| `PASSWORD_CHECK_STARTED` | Single password evaluation began |
| `PASSWORD_CHECK_COMPLETED` | Single password evaluation finished |
| `PASSWORD_GENERATED` | New secure password created |
| `BATCH_STARTED` | Batch processing began |
| `BATCH_COMPLETED` | Batch processing finished |
| `API_REQUEST_STARTED` | HIBP API call initiated |
| `API_ERROR` | API call failed |
| `CACHE_HIT` | Local cache lookup succeeded |
| `SECURITY_VIOLATION` | Security policy violation detected |

## Security Guarantees

### Automatic Redaction

The logging system **NEVER** logs:

- ❌ Passwords or password fragments
- ❌ SHA-1/MD5 password hashes
- ❌ API keys or tokens
- ❌ Private keys or credentials

### Safe Keys Whitelist

The following keys are considered safe and will NOT be redacted:

- `password_length`, `password_id`, `password_count`
- `password_policy`, `password_strength`, `password_score`
- `is_password`, `has_password`

### Redaction Examples

```python
# Input context
context = {
    "password": "secret123",           # → REDACTED
    "password_length": 12,             # → Kept (safe key)
    "api_key": "sk-abc123",            # → REDACTED
    "hash": "5baa61e4c9b93f3f...",     # → REDACTED_HASH
    "user_id": "user_123"              # → Kept
}
```

## Configuration

### YAML Configuration

```yaml
# .password-auditor.yaml
logging:
  level: INFO           # DEBUG, INFO, WARNING, ERROR, CRITICAL
  format: json          # json or simple
  file: /var/log/password-auditor.log
  rotation: daily       # daily, weekly, size, or null
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `LOG_FORMAT` | `json` | Output format (json/simple) |
| `LOG_FILE` | `null` | Log file path (null = stdout only) |

## Correlation IDs

Correlation IDs enable tracing of requests across multiple operations:

```python
from logger import set_correlation_id, CorrelationIdContext

# Method 1: Manual management
set_correlation_id("user-request-123")
# ... perform operations ...
clear_correlation_id()

# Method 2: Context manager (recommended)
with CorrelationIdContext() as cid:
    # All logs in this block include correlation_id
    logger.info("Batch started")
    process_batch()
    logger.info("Batch completed")
# Correlation ID automatically cleared
```

## Log Rotation

Supported rotation strategies:

- **daily**: Rotate at midnight, keep 7 days
- **weekly**: Rotate on Sundays, keep 4 weeks  
- **size**: Rotate at 10MB, keep 5 backups

## SIEM Integration Examples

### Splunk

```bash
# Forward logs to Splunk
python main.py --batch passwords.txt 2>&1 | \
  tee -a /var/log/password-auditor.log | \
  splunk add oneshot /var/log/password-auditor.log
```

### ELK Stack (Filebeat)

```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  paths:
    - /var/log/password-auditor.log
  json.keys_under_root: true
  json.add_error_key: true

output.elasticsearch:
  hosts: ["localhost:9200"]
```

### Datadog Agent

```yaml
# datadog.yaml
logs:
  - type: file
    path: /var/log/password-auditor.log
    service: password-auditor
    source: python
```

## Module Reference

### `logger.py`

| Function/Class | Purpose |
|----------------|---------|
| `get_logger(name)` | Get a child logger of password_auditor |
| `setup_logging()` | Configure logging with filters and formatters |
| `set_correlation_id(id)` | Set thread-local correlation ID |
| `CorrelationIdContext` | Context manager for correlation IDs |
| `LogEvent` | Standard event type constants |
| `PasswordSecurityFilter` | Redacts sensitive data from logs |
| `JSONFormatter` | Formats logs as JSON |

## Testing

Run structured logging tests:

```bash
pytest tests/test_logger.py -v
```

Test coverage: **31 tests** covering:
- Security filter redaction
- JSON formatting
- Correlation ID management
- Integration scenarios

## Compliance

Structured logging supports compliance requirements for:

- **SOC 2 Type II**: Audit trails and event logging
- **ISO 27001**: Security monitoring and incident detection
- **PCI DSS**: Access logging and monitoring
- **GDPR**: Data processing audit trails

## Future Enhancements

- [ ] Syslog destination support
- [ ] Log aggregation buffering
- [ ] Metrics collection integration
- [ ] Real-time alerting webhooks