"""
Pytest configuration and fixtures for Password Strength Auditor tests
"""

import pytest
from typing import Generator
from unittest.mock import Mock, MagicMock

# Configure pytest-asyncio
pytest_plugins = ('pytest_asyncio',)


@pytest.fixture
def strong_password() -> str:
    """Return a strong password for testing."""
    return "Tr0ub4dor&3!Secure"


@pytest.fixture
def weak_password() -> str:
    """Return a weak password for testing."""
    return "123456"


@pytest.fixture
def medium_password() -> str:
    """Return a medium strength password for testing."""
    return "Password123!"


@pytest.fixture
def pwned_password_response() -> str:
    """Return a mock HIBP API response containing a breached password suffix."""
    # Format: SUFFIX:COUNT
    return """0018A45C4D1DEF81644B54AB7F969B88D65:1
00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2
011053FD0102E94D6AE2F8B83D76FAF94F6:150
0123A45B67C89D0E1F23456789012345678:3
01A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D7:1"""


@pytest.fixture
def clean_password_response() -> str:
    """Return a mock HIBP API response with no breached passwords."""
    return """ABCDEF1234567890ABCDEF1234567890ABCD:1
FEDCBA0987654321FEDCBA0987654321FEDC:2
11223344556677889900AABBCCDDEEFF1122:150"""


@pytest.fixture
def mock_response_factory():
    """Factory for creating mock HTTP responses."""
    def _create_mock_response(status_code=200, text="", json_data=None, raise_error=None):
        mock_response = Mock()
        mock_response.status_code = status_code
        mock_response.text = text
        mock_response.json.return_value = json_data or {}
        
        if raise_error:
            mock_response.raise_for_status.side_effect = raise_error
        else:
            mock_response.raise_for_status.return_value = None
            
        return mock_response
    
    return _create_mock_response


@pytest.fixture(autouse=True)
def reset_logging():
    """Reset logging configuration after each test."""
    import logging
    yield
    # Cleanup: reset logging to default state
    logging.shutdown()
    logging.root.handlers = []
    logging.root.setLevel(logging.WARNING)