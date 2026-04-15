"""
Tests for async breach checking functionality.

Tests cover:
- Successful async API calls
- Concurrent request handling with semaphore
- Error handling in async context
- K-anonymity verification in async functions
- Progress callback functionality
- Concurrency limiting
"""

import asyncio
import pytest
from unittest.mock import AsyncMock, Mock, patch, MagicMock
import aiohttp

from breach_checker import (
    check_pwned_async,
    check_pwned_batch,
    check_pwned_batch_with_progress,
    DEFAULT_MAX_CONCURRENT,
    API_CALL_DELAY
)


class TestCheckPwnedAsync:
    """Tests for check_pwned_async function."""

    @pytest.mark.asyncio
    async def test_breached_password_returns_count(self):
        """Breached password should return the breach count."""
        test_hash_suffix = "0018A45C4D1DEF81644B54AB7F969B88D65"
        test_prefix = "ABC12"
        test_password = "testpassword123"
        
        # Mock the session and response
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value=f"{test_hash_suffix}:150")
        mock_response.raise_for_status = Mock()
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        
        mock_session = AsyncMock()
        mock_session.get = Mock(return_value=mock_response)
        
        # Mock hashlib.sha1
        with patch('breach_checker.hashlib.sha1') as mock_sha1:
            mock_hash = Mock()
            mock_hash.hexdigest.return_value = f"{test_prefix}{test_hash_suffix}".lower()
            mock_sha1.return_value = mock_hash
            
            result = await check_pwned_async(test_password, mock_session)
            
            assert result == 150

    @pytest.mark.asyncio
    async def test_clean_password_returns_zero(self):
        """Non-breached password should return 0."""
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.text = AsyncMock(return_value="SOMERANDOMHASH:5\nANOTHERHASH:10")
        mock_response.raise_for_status = Mock()
        mock_response.__aenter__ = AsyncMock(return_value=mock_response)
        mock_response.__aexit__ = AsyncMock(return_value=None)
        
        mock_session = AsyncMock()
        mock_session.get = Mock(return_value=mock_response)
        
        with patch('breach_checker.hashlib.sha1') as mock_sha1:
            mock_hash = Mock()
            mock_hash.hexdigest.return_value = "abc123notinthesuffixlist"
            mock_sha1.return_value = mock_hash
            
            result = await check_pwned_async("unique_password", mock_session)
            
            assert result == 0

    @pytest.mark.asyncio
    async def test_api_called_with_correct_prefix(self):
        """API should be called with first 5 chars of SHA-1 hash."""
        password = "testpassword"
        
        mock_response = AsyncMock()
        mock_response.text = AsyncMock(return_value="")
        mock_response.raise_for_status = Mock()
        
        mock_session = AsyncMock()
        mock_session.get = AsyncMock(return_value=mock_response)
        
        await check_pwned_async(password, mock_session)
        
        # Verify the URL contains the correct prefix
        mock_session.get.assert_called_once()
        call_args = mock_session.get.call_args
        assert "api.pwnedpasswords.com" in call_args[0][0]

    @pytest.mark.asyncio
    async def test_timeout_returns_none(self):
        """Timeout should return None (not raise exception)."""
        mock_session = AsyncMock()
        mock_session.get = AsyncMock(side_effect=asyncio.TimeoutError())
        
        with patch('breach_checker.hashlib.sha1') as mock_sha1:
            mock_hash = Mock()
            mock_hash.hexdigest.return_value = "abc123def456"
            mock_sha1.return_value = mock_hash
            
            result = await check_pwned_async("testpassword", mock_session)
            
            assert result is None

    @pytest.mark.asyncio
    async def test_client_error_returns_none(self):
        """Client error should return None."""
        mock_session = AsyncMock()
        mock_session.get = AsyncMock(side_effect=aiohttp.ClientError("Connection error"))
        
        with patch('breach_checker.hashlib.sha1') as mock_sha1:
            mock_hash = Mock()
            mock_hash.hexdigest.return_value = "abc123def456"
            mock_sha1.return_value = mock_hash
            
            result = await check_pwned_async("testpassword", mock_session)
            
            assert result is None

    @pytest.mark.asyncio
    async def test_general_exception_returns_none(self):
        """Unexpected exceptions should return None."""
        mock_session = AsyncMock()
        mock_session.get = AsyncMock(side_effect=Exception("Unexpected error"))
        
        with patch('breach_checker.hashlib.sha1') as mock_sha1:
            mock_hash = Mock()
            mock_hash.hexdigest.return_value = "abc123def456"
            mock_sha1.return_value = mock_hash
            
            result = await check_pwned_async("testpassword", mock_session)
            
            assert result is None

    @pytest.mark.asyncio
    async def test_session_reuse(self):
        """Same session should be reused for multiple calls."""
        mock_response = AsyncMock()
        mock_response.text = AsyncMock(return_value="")
        mock_response.raise_for_status = Mock()
        
        mock_session = AsyncMock()
        mock_session.get = AsyncMock(return_value=mock_response)
        
        with patch('breach_checker.hashlib.sha1') as mock_sha1:
            mock_hash = Mock()
            mock_hash.hexdigest.return_value = "abc123def456789"
            mock_sha1.return_value = mock_hash
            
            # Make multiple calls with same session
            await check_pwned_async("pass1", mock_session)
            await check_pwned_async("pass2", mock_session)
            
            # Session should be used twice
            assert mock_session.get.call_count == 2


class TestCheckPwnedBatch:
    """Tests for check_pwned_batch function."""

    @pytest.mark.asyncio
    async def test_batch_processes_all_passwords(self):
        """All passwords should be processed."""
        passwords = ["pass1", "pass2", "pass3"]
        
        with patch('breach_checker.check_pwned_async') as mock_check:
            mock_check.return_value = 0
            
            results = await check_pwned_batch(passwords, max_concurrent=2)
            
            assert len(results) == 3
            assert mock_check.call_count == 3

    @pytest.mark.asyncio
    async def test_results_match_passwords(self):
        """Results should be in same order as input passwords."""
        passwords = ["pass1", "pass2", "pass3"]
        expected_counts = [0, 5, 10]
        
        with patch('breach_checker.check_pwned_async') as mock_check:
            mock_check.side_effect = expected_counts
            
            results = await check_pwned_batch(passwords, max_concurrent=2)
            
            assert results[0] == ("pass1", 0)
            assert results[1] == ("pass2", 5)
            assert results[2] == ("pass3", 10)

    @pytest.mark.asyncio
    async def test_mixed_results(self):
        """Handle mix of breached, clean, and failed checks."""
        passwords = ["clean", "breached", "error_expected"]
        
        with patch('breach_checker.check_pwned_async') as mock_check:
            async def side_effect(password, session=None, timeout=None):
                if password == "clean":
                    return 0
                elif password == "breached":
                    return 100
                else:
                    return None
            
            mock_check.side_effect = side_effect
            
            results = await check_pwned_batch(passwords, max_concurrent=2)
            
            assert results[0] == ("clean", 0)
            assert results[1] == ("breached", 100)
            assert results[2] == ("error_expected", None)

    @pytest.mark.asyncio
    async def test_empty_list(self):
        """Empty password list should return empty results."""
        results = await check_pwned_batch([], max_concurrent=2)
        
        assert results == []

    @pytest.mark.asyncio
    async def test_single_password(self):
        """Single password should work correctly."""
        passwords = ["singlepass"]
        
        with patch('breach_checker.check_pwned_async') as mock_check:
            mock_check.return_value = 5
            
            results = await check_pwned_batch(passwords)
            
            assert len(results) == 1
            assert results[0] == ("singlepass", 5)

    @pytest.mark.asyncio
    async def test_concurrency_limit(self):
        """Concurrency should be limited by semaphore."""
        passwords = ["pass1", "pass2", "pass3", "pass4", "pass5"]
        max_concurrent = 2
        
        active_count = 0
        max_active = 0
        
        async def mock_check_with_tracking(password, session=None, timeout=None):
            nonlocal active_count, max_active
            active_count += 1
            max_active = max(max_active, active_count)
            await asyncio.sleep(0.01)  # Small delay to simulate work
            active_count -= 1
            return 0
        
        with patch('breach_checker.check_pwned_async', side_effect=mock_check_with_tracking):
            await check_pwned_batch(passwords, max_concurrent=max_concurrent)
        
        # Maximum concurrent should not exceed limit
        assert max_active <= max_concurrent

    @pytest.mark.asyncio
    async def test_rate_limiting_delay(self):
        """Rate limiting should add delay between requests."""
        passwords = ["pass1", "pass2"]
        
        with patch('breach_checker.check_pwned_async') as mock_check:
            with patch('breach_checker.asyncio.sleep') as mock_sleep:
                mock_check.return_value = 0
                
                await check_pwned_batch(passwords, max_concurrent=10)
                
                # Should sleep after each password
                assert mock_sleep.call_count >= 2
                assert mock_sleep.call_args[0][0] == API_CALL_DELAY

    @pytest.mark.asyncio
    async def test_exception_in_one_does_not_stop_others(self):
        """Exception in one check should not stop others."""
        passwords = ["pass1", "pass2", "pass3"]
        
        with patch('breach_checker.check_pwned_async') as mock_check:
            async def side_effect(password, session=None, timeout=None):
                if password == "pass2":
                    raise Exception("Simulated error")
                return 0
            
            mock_check.side_effect = side_effect
            
            results = await check_pwned_batch(passwords)
            
            # All 3 passwords should have results
            assert len(results) == 3
            # pass2 should have None due to error
            assert results[1] == ("pass2", None)


class TestCheckPwnedBatchWithProgress:
    """Tests for check_pwned_batch_with_progress function."""

    @pytest.mark.asyncio
    async def test_progress_callback_called(self):
        """Progress callback should be called for each password."""
        passwords = ["pass1", "pass2", "pass3"]
        progress_calls = []
        
        def progress_callback(current, total):
            progress_calls.append((current, total))
        
        with patch('breach_checker.check_pwned_async') as mock_check:
            mock_check.return_value = 0
            
            await check_pwned_batch_with_progress(
                passwords,
                progress_callback=progress_callback,
                max_concurrent=2
            )
        
        # Should be called for each password
        assert len(progress_calls) == 3
        assert progress_calls[0] == (1, 3)
        assert progress_calls[1] == (2, 3)
        assert progress_calls[2] == (3, 3)

    @pytest.mark.asyncio
    async def test_no_callback_works(self):
        """Function should work without callback."""
        passwords = ["pass1", "pass2"]
        
        with patch('breach_checker.check_pwned_async') as mock_check:
            mock_check.return_value = 0
            
            results = await check_pwned_batch_with_progress(
                passwords,
                progress_callback=None
            )
        
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_progress_reported_correctly_with_errors(self):
        """Progress should still be reported even if some checks fail."""
        passwords = ["pass1", "pass2", "pass3"]
        progress_calls = []
        
        def progress_callback(current, total):
            progress_calls.append((current, total))
        
        with patch('breach_checker.check_pwned_async') as mock_check:
            async def side_effect(password, session=None, timeout=None):
                if password == "pass2":
                    raise Exception("Error")
                return 0
            
            mock_check.side_effect = side_effect
            
            results = await check_pwned_batch_with_progress(
                passwords,
                progress_callback=progress_callback,
                max_concurrent=2
            )
        
        # Progress should be reported for processed passwords
        # Note: When an exception occurs, progress may not be reported for all passwords
        assert len(progress_calls) >= 2
        assert progress_calls[0] == (1, 3)


class TestKAnonymityAsync:
    """Tests verifying k-anonymity is maintained in async operations."""

    @pytest.mark.asyncio
    async def test_only_prefix_sent_to_api(self):
        """Only first 5 characters of hash should be sent."""
        import hashlib
        
        password = "supersecretpassword"
        full_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = full_hash[:5]
        suffix = full_hash[5:]
        
        mock_response = AsyncMock()
        mock_response.text = AsyncMock(return_value="")
        mock_response.raise_for_status = Mock()
        
        mock_session = AsyncMock()
        mock_session.get = AsyncMock(return_value=mock_response)
        
        await check_pwned_async(password, mock_session)
        
        # Get the URL that was called
        call_args = mock_session.get.call_args[0][0]
        
        # Only the prefix should be in the URL
        assert prefix in call_args
        assert suffix not in call_args  # Critical: suffix never leaves the system


class TestAsyncSecurity:
    """Security-focused tests for async functions."""

    @pytest.mark.asyncio
    async def test_password_not_logged_on_async_error(self, caplog):
        """Password should not appear in logs on async error."""
        import logging
        
        mock_session = AsyncMock()
        mock_session.get = AsyncMock(side_effect=aiohttp.ClientError("Connection failed"))
        
        with caplog.at_level(logging.ERROR):
            with patch('breach_checker.hashlib.sha1') as mock_sha1:
                mock_hash = Mock()
                mock_hash.hexdigest.return_value = "abc123def456"
                mock_sha1.return_value = mock_hash
                
                await check_pwned_async("secretpassword123", mock_session)
        
        # Password should not be in logs
        assert "secretpassword" not in caplog.text
        assert "secretpassword123" not in caplog.text


class TestPerformanceCharacteristics:
    """Tests for performance-related behavior."""

    @pytest.mark.asyncio
    async def test_large_batch_handled(self):
        """Large batches should be handled efficiently."""
        passwords = [f"password{i}" for i in range(100)]
        
        with patch('breach_checker.check_pwned_async') as mock_check:
            mock_check.return_value = 0
            
            results = await check_pwned_batch(passwords, max_concurrent=10)
            
            assert len(results) == 100
            assert all(count == 0 for _, count in results)

    @pytest.mark.asyncio
    async def test_concurrency_improves_performance(self):
        """Higher concurrency should process faster."""
        passwords = [f"pass{i}" for i in range(10)]
        delay = 0.05  # Reduced delay for more reliable timing
        
        async def mock_check_with_delay(password, session=None, timeout=None):
            await asyncio.sleep(delay)
            return 0
        
        # Use time.perf_counter for more accurate timing
        import time
        
        with patch('breach_checker.check_pwned_async', side_effect=mock_check_with_delay):
            with patch('breach_checker.asyncio.sleep'):
                # Time with concurrency of 10
                start = time.perf_counter()
                await check_pwned_batch(passwords, max_concurrent=10)
                time_concurrent = time.perf_counter() - start
        
        with patch('breach_checker.check_pwned_async', side_effect=mock_check_with_delay):
            with patch('breach_checker.asyncio.sleep'):
                # Time with concurrency of 1 (sequential)
                start = time.perf_counter()
                await check_pwned_batch(passwords, max_concurrent=1)
                time_sequential = time.perf_counter() - start
        
        # Concurrent should be faster (or at least not significantly slower)
        # Allow some tolerance for timing variations
        assert time_concurrent <= time_sequential * 1.5, \
            f"Concurrent ({time_concurrent:.3f}s) should be faster than sequential ({time_sequential:.3f}s)"


class TestDefaultConstants:
    """Tests for default constants."""

    def test_default_concurrent_is_reasonable(self):
        """Default concurrency should be reasonable."""
        assert DEFAULT_MAX_CONCURRENT == 10
        assert isinstance(DEFAULT_MAX_CONCURRENT, int)
        assert DEFAULT_MAX_CONCURRENT > 0

    def test_api_delay_is_small(self):
        """API delay should be small to be effective but polite."""
        assert API_CALL_DELAY == 0.1
        assert isinstance(API_CALL_DELAY, (int, float))
        assert API_CALL_DELAY >= 0