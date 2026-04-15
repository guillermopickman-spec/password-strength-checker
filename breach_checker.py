"""
Breach Checker Module

Handles password breach detection using the HaveIBeenPwned API
with k-anonymity for secure queries.

Supports both synchronous and asynchronous operations for optimal
performance in single-password and batch-processing scenarios.
"""

import asyncio
import hashlib
import logging
from typing import List, Optional, Tuple

import aiohttp
import requests


logger = logging.getLogger(__name__)


# Default concurrency limit for async batch operations
DEFAULT_MAX_CONCURRENT = 10
# Delay between API calls to be a good API citizen (seconds)
API_CALL_DELAY = 0.1


def check_pwned(password: str, timeout: int = 5) -> Optional[int]:
    """
    Check if a password has been leaked using HaveIBeenPwned API.
    
    Uses k-anonymity: only sends first 5 characters of SHA-1 hash.
    
    Args:
        password: The password to check
        timeout: Request timeout in seconds (default: 5)
    
    Returns:
        int: Number of times password appeared in breaches (0 if not found)
        None: If the API request failed
    
    Raises:
        No exceptions are raised; errors are logged and None is returned
    """
    # Generate SHA-1 hash of password
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {'User-Agent': 'PasswordStrengthChecker-Project'}
    
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        
        # Parse response for matching suffix
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)
        return 0
        
    except requests.exceptions.Timeout:
        logger.error("HaveIBeenPwned API request timed out")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"HaveIBeenPwned API request failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error checking breach status: {e}")
        return None


def format_breach_result(count: Optional[int]) -> str:
    """
    Format breach check result for user display.
    
    Args:
        count: Number of breaches (None if check failed)
    
    Returns:
        Formatted string with appropriate warning level
    """
    if count is None:
        return "⚠️  Could not check breaches at this time."
    elif count > 0:
        return (
            f"🚨  DANGER! This password has appeared in {count:,} known breaches.\n"
            f"    NEVER use it!"
        )
    else:
        return "✅  This password has NOT been found in known public breaches."


async def check_pwned_async(
    password: str,
    session: aiohttp.ClientSession,
    timeout: int = 5
) -> Optional[int]:
    """
    Check if a password has been leaked using HaveIBeenPwned API (async version).
    
    Uses k-anonymity: only sends first 5 characters of SHA-1 hash.
    
    Args:
        password: The password to check
        session: aiohttp ClientSession for connection pooling
        timeout: Request timeout in seconds (default: 5)
    
    Returns:
        int: Number of times password appeared in breaches (0 if not found)
        None: If the API request failed
    
    Raises:
        No exceptions are raised; errors are logged and None is returned
    """
    # Generate SHA-1 hash of password
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout)
        ) as response:
            response.raise_for_status()
            
            # Parse response for matching suffix
            text = await response.text()
            for line in text.splitlines():
                h, count = line.split(':')
                if h == suffix:
                    return int(count)
            return 0
            
    except asyncio.TimeoutError:
        logger.error("HaveIBeenPwned API request timed out")
        return None
    except aiohttp.ClientError as e:
        logger.error(f"HaveIBeenPwned API request failed: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error checking breach status: {e}")
        return None


async def check_pwned_batch(
    passwords: List[str],
    max_concurrent: int = DEFAULT_MAX_CONCURRENT,
    timeout: int = 5
) -> List[Tuple[str, Optional[int]]]:
    """
    Check multiple passwords concurrently for breaches.
    
    This function uses asyncio to check multiple passwords in parallel,
    significantly improving performance for large-scale audits.
    Concurrency is controlled via a semaphore to avoid overwhelming the API.
    
    Args:
        passwords: List of passwords to check
        max_concurrent: Maximum concurrent API calls (default: 10)
        timeout: Timeout per request in seconds (default: 5)
    
    Returns:
        List of tuples: (password, breach_count)
        breach_count is None if the API check failed
    
    Example:
        >>> passwords = ["password123", "SecurePass123!"]
        >>> results = asyncio.run(check_pwned_batch(passwords))
        >>> for pwd, count in results:
        ...     print(f"{pwd}: {count}")
    """
    # Semaphore to limit concurrent API calls
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def bounded_check(
        password: str,
        session: aiohttp.ClientSession
    ) -> Tuple[str, Optional[int]]:
        """
        Wrapper to enforce concurrency limit and rate limiting.
        """
        async with semaphore:
            result = await check_pwned_async(password, session, timeout)
            # Small delay to be a good API citizen
            await asyncio.sleep(API_CALL_DELAY)
            return (password, result)
    
    # Create shared session with proper headers
    headers = {'User-Agent': 'PasswordStrengthChecker-Project'}
    
    async with aiohttp.ClientSession(headers=headers) as session:
        # Create all tasks
        tasks = [
            bounded_check(pwd, session) for pwd in passwords
        ]
        
        # Execute all tasks concurrently with exception handling
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results and handle any exceptions
        processed_results: List[Tuple[str, Optional[int]]] = []
        for i, result in enumerate(results):
            pwd = passwords[i]
            if isinstance(result, Exception):
                logger.error(f"Error checking password hash: {result}")
                processed_results.append((pwd, None))
            else:
                processed_results.append(result)
        
        return processed_results


async def check_pwned_batch_with_progress(
    passwords: List[str],
    progress_callback=None,
    max_concurrent: int = DEFAULT_MAX_CONCURRENT,
    timeout: int = 5
) -> List[Tuple[str, Optional[int]]]:
    """
    Check multiple passwords concurrently with progress updates.
    
    Similar to check_pwned_batch but calls a progress callback after
    each password is processed.
    
    Args:
        passwords: List of passwords to check
        progress_callback: Optional callable(current: int, total: int) for progress
        max_concurrent: Maximum concurrent API calls (default: 10)
        timeout: Timeout per request in seconds (default: 5)
    
    Returns:
        List of tuples: (password, breach_count)
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    total = len(passwords)
    completed = 0
    
    async def bounded_check_with_progress(
        password: str,
        session: aiohttp.ClientSession
    ) -> Tuple[str, Optional[int]]:
        nonlocal completed
        async with semaphore:
            result = await check_pwned_async(password, session, timeout)
            await asyncio.sleep(API_CALL_DELAY)
            completed += 1
            if progress_callback:
                progress_callback(completed, total)
            return (password, result)
    
    headers = {'User-Agent': 'PasswordStrengthChecker-Project'}
    
    async with aiohttp.ClientSession(headers=headers) as session:
        tasks = [
            bounded_check_with_progress(pwd, session) for pwd in passwords
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        processed_results: List[Tuple[str, Optional[int]]] = []
        for i, result in enumerate(results):
            pwd = passwords[i]
            if isinstance(result, Exception):
                logger.error(f"Error checking password: {result}")
                processed_results.append((pwd, None))
            else:
                processed_results.append(result)
        
        return processed_results
