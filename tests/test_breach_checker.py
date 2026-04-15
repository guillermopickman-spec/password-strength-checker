"""
Tests for breach_checker.py module

Tests cover:
- Successful API calls with breached passwords
- Successful API calls with clean passwords
- API error handling (timeouts, connection errors, HTTP errors)
- K-anonymity verification (only prefix sent)
- Result formatting
- Security considerations (no full hashes logged)
"""

import hashlib
import pytest
from unittest.mock import Mock, patch
import requests

from breach_checker import check_pwned, format_breach_result


class TestCheckPwnedSuccess:
    """Tests for successful breach checks."""
    
    def test_breached_password_returns_count(self, pwned_password_response):
        """Breached password should return the breach count."""
        # Calculate what suffix would be in the response
        # The response contains: 0018A45C4D1DEF81644B54AB7F969B88D65:1
        test_hash_suffix = "0018A45C4D1DEF81644B54AB7F969B88D65"
        test_prefix = "ABC12"  # Mock prefix
        test_password = "testpassword123"  # This won't actually hash to match, we'll mock
        
        with patch('breach_checker.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = f"{test_hash_suffix}:150"
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            # Patch the hash generation to return predictable values
            with patch('breach_checker.hashlib.sha1') as mock_sha1:
                mock_hash = Mock()
                mock_hash.hexdigest.return_value = f"{test_prefix}{test_hash_suffix}".lower()
                mock_sha1.return_value = mock_hash
                
                result = check_pwned(test_password)
                
                assert result == 150
    
    def test_clean_password_returns_zero(self, clean_password_response):
        """Non-breached password should return 0."""
        with patch('breach_checker.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = clean_password_response
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            result = check_pwned("very_unique_password_that_is_not_breached")
            
            assert result == 0
    
    def test_api_called_with_correct_prefix(self):
        """API should be called with first 5 chars of SHA-1 hash."""
        password = "testpassword"
        expected_sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        expected_prefix = expected_sha1[:5]
        
        with patch('breach_checker.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = ""
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            check_pwned(password)
            
            # Verify the URL contains the correct prefix
            mock_get.assert_called_once()
            call_args = mock_get.call_args
            assert expected_prefix in call_args[0][0]
            assert "api.pwnedpasswords.com" in call_args[0][0]
    
    def test_api_called_with_user_agent(self):
        """API request should include User-Agent header."""
        with patch('breach_checker.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = ""
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            check_pwned("test")
            
            call_kwargs = mock_get.call_args[1]
            assert 'headers' in call_kwargs
            assert 'User-Agent' in call_kwargs['headers']
            assert 'PasswordStrengthChecker' in call_kwargs['headers']['User-Agent']


class TestCheckPwnedErrors:
    """Tests for error handling."""
    
    def test_timeout_returns_none(self):
        """Timeout should return None (not raise exception)."""
        with patch('breach_checker.requests.get') as mock_get:
            mock_get.side_effect = requests.exceptions.Timeout()
            
            result = check_pwned("testpassword")
            
            assert result is None
    
    def test_connection_error_returns_none(self):
        """Connection error should return None."""
        with patch('breach_checker.requests.get') as mock_get:
            mock_get.side_effect = requests.exceptions.ConnectionError()
            
            result = check_pwned("testpassword")
            
            assert result is None
    
    def test_http_error_returns_none(self):
        """HTTP error should return None."""
        with patch('breach_checker.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.raise_for_status.side_effect = requests.exceptions.HTTPError()
            mock_get.return_value = mock_response
            
            result = check_pwned("testpassword")
            
            assert result is None
    
    def test_general_exception_returns_none(self):
        """Unexpected exceptions should return None."""
        with patch('breach_checker.requests.get') as mock_get:
            mock_get.side_effect = Exception("Unexpected error")
            
            result = check_pwned("testpassword")
            
            assert result is None
    
    def test_timeout_uses_custom_timeout(self):
        """Custom timeout should be passed to requests."""
        with patch('breach_checker.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.text = ""
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            check_pwned("test", timeout=10)
            
            call_kwargs = mock_get.call_args[1]
            assert call_kwargs['timeout'] == 10
    
    def test_default_timeout_is_5_seconds(self):
        """Default timeout should be 5 seconds."""
        with patch('breach_checker.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.text = ""
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            check_pwned("test")
            
            call_kwargs = mock_get.call_args[1]
            assert call_kwargs['timeout'] == 5


class TestFormatBreachResult:
    """Tests for format_breach_result function."""
    
    def test_none_shows_warning(self):
        """None result should show warning message."""
        result = format_breach_result(None)
        
        assert "⚠️" in result or "Could not check" in result
    
    def test_zero_shows_safe(self):
        """Zero breaches should show safe message."""
        result = format_breach_result(0)
        
        assert "✅" in result or "NOT been found" in result
        assert "0" not in result  # Should not show "0 breaches"
    
    def test_positive_shows_danger(self):
        """Positive count should show danger message."""
        result = format_breach_result(150)
        
        assert "🚨" in result or "DANGER" in result
        assert "150" in result
        assert "NEVER use" in result
    
    def test_large_number_formatted(self):
        """Large numbers should be formatted with commas."""
        result = format_breach_result(1234567)
        
        assert "1,234,567" in result


class TestKAnonymity:
    """Tests verifying k-anonymity is properly implemented."""
    
    def test_only_prefix_sent_to_api(self):
        """Only first 5 characters of hash should be sent."""
        password = "supersecretpassword"
        full_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        
        with patch('breach_checker.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.text = ""
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            check_pwned(password)
            
            # Get the URL that was called
            call_args = mock_get.call_args[0][0]
            
            # Only the prefix should be in the URL
            prefix = full_hash[:5]
            suffix = full_hash[5:]
            
            assert prefix in call_args
            assert suffix not in call_args  # Critical: suffix never leaves the system


class TestSecurityConsiderations:
    """Security-focused tests."""
    
    def test_password_not_logged_on_success(self, caplog):
        """Password should not appear in logs on success."""
        with patch('breach_checker.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.text = ""
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            with caplog.at_level('ERROR'):
                check_pwned("secretpassword123")
            
            assert "secretpassword" not in caplog.text
            assert "secretpassword123" not in caplog.text
    
    def test_password_not_logged_on_error(self, caplog):
        """Password should not appear in logs on error."""
        with patch('breach_checker.requests.get') as mock_get:
            mock_get.side_effect = requests.exceptions.Timeout()
            
            with caplog.at_level('ERROR'):
                check_pwned("secretpassword123")
            
            assert "secretpassword" not in caplog.text
            assert "secretpassword123" not in caplog.text
    
    def test_hash_suffix_checked_locally(self):
        """Suffix matching should happen locally, not on server."""
        test_suffix = "ABC123DEF4567890ABC123DEF4567890ABC"
        test_prefix = "12345"
        test_hash = test_prefix + test_suffix
        
        with patch('breach_checker.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            # Server returns the matching suffix
            mock_response.text = f"{test_suffix}:5"
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            with patch('breach_checker.hashlib.sha1') as mock_sha1:
                mock_hash = Mock()
                mock_hash.hexdigest.return_value = test_hash.lower()
                mock_sha1.return_value = mock_hash
                
                result = check_pwned("anypassword")
                
                # Should find the match locally
                assert result == 5


class TestEdgeCases:
    """Edge case tests."""
    
    def test_empty_password(self):
        """Empty password should be handled."""
        with patch('breach_checker.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.text = ""
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            result = check_pwned("")
            
            # Empty password hash is still valid SHA-1
            assert result is not None or result == 0
    
    def test_unicode_password(self):
        """Unicode password should be handled."""
        with patch('breach_checker.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.text = ""
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            result = check_pwned("пароль密码🎉")
            
            assert result is not None or result == 0
    
    def test_very_long_password(self):
        """Very long password should be handled."""
        long_password = "A" * 1000
        
        with patch('breach_checker.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.text = ""
            mock_response.raise_for_status.return_value = None
            mock_get.return_value = mock_response
            
            result = check_pwned(long_password)
            
            assert result is not None or result == 0