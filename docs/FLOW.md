# Password Flow Documentation

This document traces how passwords are treated in code, from user input through all processing stages to final output. It serves as a study guide for understanding the Password Strength Auditor architecture.

## Table of Contents

1. [Overview](#overview)
2. [Flow 1: Single Password Check](#flow-1-single-password-check)
3. [Flow 2: Password Generation](#flow-2-password-generation)
4. [Flow 3: Batch Processing](#flow-3-batch-processing)
5. [Module Interactions](#module-interactions)
6. [Data Structures](#data-structures)
7. [Security Considerations](#security-considerations)

---

## Overview

```
┌─────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   User      │────▶│    main.py      │────▶│ password_eval   │
│  Input      │     │  (Entry Point)  │     │   uator.py      │
└─────────────┘     └─────────────────┘     └─────────────────┘
                                                       │
                              ┌──────────────────────┼──────────────────────┐
                              ▼                      ▼                      ▼
                       ┌─────────────┐      ┌─────────────┐        ┌─────────────┐
                       │  zxcvbn     │      │   regex     │        │breach_check │
                       │   library   │      │  checks     │        │  er.py      │
                       └─────────────┘      └─────────────┘        └─────────────┘
                              │                      │                      │
                              └──────────────────────┼──────────────────────┘
                                                     ▼
                                              ┌─────────────┐
                                              │   Output    │
                                              │  Display    │
                                              └─────────────┘
```

---

## Flow 1: Single Password Check

### Entry Point: `main.py::interactive_mode()`

The password enters the system through secure input:

```python
# main.py (lines 207-228)
def interactive_mode():
    """Run interactive password checking loop."""
    print_banner()
    console.print("[dim]Enter passwords to check (press Enter without input to exit):[/]\n")
    
    while True:
        try:
            password = getpass.getpass("Password: ")  # <-- Password enters here
            # Password is now a string variable in memory
            
            if not password:
                console.print("\n[green]Exiting. Stay secure! 🔒[/]")
                break
            
            check_single_password(password, verbose=True)  # <-- Flow continues
```

### Stage 1: Strength Evaluation → `password_evaluator.py`

The password flows to the evaluator:

```python
# main.py (lines 159-171)
def check_single_password(password: str, verbose: bool = True) -> bool:
    """
    Check a single password for strength and breaches.
    """
    # Evaluate strength - password passed to evaluator
    result = evaluate_password_strength(password)  # <-- Flow to evaluator
```

Inside the evaluator, the password undergoes analysis:

```python
# password_evaluator.py (lines 94-155)
def evaluate_password_strength(password: str) -> PasswordStrengthResult:
    """
    Evaluate password strength using zxcvbn and custom checks.
    """
    # STEP 1: Professional entropy estimation via zxcvbn
    zxcvbn_result = zxcvbn(password)  # Password analyzed by zxcvbn library
    
    # STEP 2: Basic regex-based requirement checking
    basic_checks = check_basic_requirements(password)
    
    # STEP 3: Check each requirement
    return {
        "length_ok": len(password) >= MIN_LENGTH,        # Min 12 chars
        "has_uppercase": bool(re.search(r"[A-Z]", password)),  # A-Z
        "has_lowercase": bool(re.search(r"[a-z]", password)),  # a-z
        "has_digits": bool(re.search(r"\d", password)),        # 0-9
        "has_special": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)),
    }
    
    # STEP 4: Calculate entropy from guesses
    guesses = zxcvbn_result["guesses"]
    entropy = math.log2(float(guesses)) if guesses > 0 else 0.0
    
    # STEP 5: Return structured result
    return PasswordStrengthResult(
        score=zxcvbn_result["score"],                    # 0-4 score
        strength_label=score_labels.get(zxcvbn_result["score"], "Unknown"),
        entropy=entropy,                                  # Shannon entropy
        crack_time_display=zxcvbn_result["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
        crack_time_seconds=float(zxcvbn_result["crack_times_seconds"]["offline_slow_hashing_1e4_per_second"]),
        feedback=feedback,
        warning=warning,
        has_patterns=has_patterns
    )
```

### Stage 2: Breach Checking → `breach_checker.py`

The same password flows to breach checking (k-anonymity model):

```python
# main.py (lines 180-191)
# Check breach status with spinner
if verbose:
    console.print()
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True
    ) as progress:
        progress.add_task(description="Checking breach databases...", total=None)
        pwned_count = check_pwned(password)  # <-- Password flows here
else:
    pwned_count = check_pwned(password)
```

Inside the breach checker, the password is hashed and checked securely:

```python
# breach_checker.py (lines 18-62)
def check_pwned(password: str, timeout: int = 5) -> Optional[int]:
    """
    Check if a password has been leaked using HaveIBeenPwned API.
    
    Uses k-anonymity: only sends first 5 characters of SHA-1 hash.
    """
    # STEP 1: Hash password locally (never send plaintext)
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # Example: "password123" → "CBFDAC6008F9CAB4083784CBD1874F76618D2A97"
    
    # STEP 2: Split hash for k-anonymity
    prefix = sha1[:5]    # "CBFDA" - sent to API
    suffix = sha1[5:]    # "C6008F9CAB4083784CBD1874F76618D2A97" - kept local
    
    # STEP 3: Query API with only prefix (k-anonymity)
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {'User-Agent': 'PasswordStrengthChecker-Project'}
    
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        response.raise_for_status()
        
        # STEP 4: Check if our suffix exists in response
        # API returns: "C6008F9CAB4083784CBD1874F76618D2A97:12345\n..."
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)  # Breach count (e.g., 12345)
        return 0  # Not found - password is safe
        
    except requests.exceptions.Timeout:
        logger.error("HaveIBeenPwned API request timed out")
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"HaveIBeenPwned API request failed: {e}")
        return None
```

### Stage 3: Final Decision → `main.py`

Results are combined for final verdict:

```python
# main.py (lines 196-204)
# Determine overall status
is_strong = result.score >= 3           # From evaluator
is_safe = pwned_count == 0              # From breach checker

if verbose:
    console.print()
    display_final_status(is_strong, is_safe)

return is_strong and is_safe            # Final boolean result
```

The final status display:

```python
# main.py (lines 136-156)
def display_final_status(is_strong: bool, is_safe: bool):
    """Display final status panel."""
    if is_strong and is_safe:
        content = "[bold green]✅ PASSWORD STATUS: SECURE[/]\n\nThis password is strong and has not been breached."
        border_color = "green"
    elif is_strong and not is_safe:
        content = "[bold red]❌ PASSWORD STATUS: COMPROMISED[/]\n\nPassword is strong but has been leaked. Do not use!"
        border_color = "red"
    elif not is_strong and is_safe:
        content = "[bold yellow]⚠️ PASSWORD STATUS: WEAK[/]\n\nPassword has not been breached but is too weak."
        border_color = "yellow"
    else:
        content = "[bold red]❌ PASSWORD STATUS: INSECURE[/]\n\nPassword is weak AND has been compromised!"
        border_color = "red"
```

---

## Flow 2: Password Generation

### Entry Point: `main.py::generate_password_cli()`

```python
# main.py (lines 231-301)
def generate_password_cli(
    length: int = 16,
    use_special: bool = True,
    passphrase_mode: bool = False
):
    """
    Generate and display a secure password with rich formatting.
    """
    if passphrase_mode:
        # Flow A: Generate passphrase
        password = generate_passphrase(
            num_words=length,
            separator="-",
            capitalize=True,
            add_number=True
        )
    else:
        # Flow B: Generate random password
        password = generate_secure_password(
            length=length,
            use_uppercase=True,
            use_lowercase=True,
            use_digits=True,
            use_special=use_special,
            avoid_ambiguous=True,
            min_each_type=1
        )
```

### Flow A: Passphrase Generation → `password_generator.py`

```python
# password_generator.py (lines 112-169)
def generate_passphrase(
    num_words: int = 4,
    word_list: Optional[list] = None,
    separator: str = "-",
    capitalize: bool = True,
    add_number: bool = True
) -> str:
    """
    Generate a memorable passphrase (Diceware-style).
    """
    # Default word list
    if word_list is None:
        word_list = [
            "apple", "banana", "cherry", "dragon", "eagle", "falcon",
            "garden", "harbor", "island", "jungle", "kitchen", "lemon",
            # ... 54 words total
        ]
    
    # STEP 1: Select random words using secrets (CSPRNG)
    words = [secrets.choice(word_list) for _ in range(num_words)]
    # Example: ["dragon", "crystal", "mountain", "falcon"]
    
    # STEP 2: Apply random capitalization
    if capitalize:
        words = [
            w.upper() if secrets.choice([True, False]) else w.lower()
            for w in words
        ]
    # Example: ["DRAGON", "crystal", "MOUNTAIN", "falcon"]
    
    # STEP 3: Join with separator
    passphrase = separator.join(words)
    # Result: "DRAGON-crystal-MOUNTAIN-falcon"
    
    # STEP 4: Append random number for extra entropy
    if add_number:
        passphrase += separator + str(secrets.randbelow(1000)).zfill(3)
    # Final: "DRAGON-crystal-MOUNTAIN-falcon-042"
    
    return passphrase
```

### Flow B: Random Password Generation → `password_generator.py`

```python
# password_generator.py (lines 21-109)
def generate_secure_password(
    length: int = 16,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_special: bool = True,
    avoid_ambiguous: bool = True,
    min_each_type: int = 1
) -> str:
    """
    Generate a cryptographically secure password.
    """
    # Character sets
    UPPERCASE = string.ascii_uppercase  # "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    LOWERCASE = string.ascii_lowercase  # "abcdefghijklmnopqrstuvwxyz"
    DIGITS = string.digits               # "0123456789"
    SPECIAL = "!@#$%^&*"                 # Special characters
    AMBIGUOUS = "0O1lI"                  # Visually similar chars to exclude
    
    # STEP 1: Build character pool
    char_pool = ""
    required_sets = []
    
    if use_lowercase:
        chars = LOWERCASE
        if avoid_ambiguous:
            chars = ''.join(c for c in chars if c not in AMBIGUOUS)
        char_pool += chars          # "abcdefghjkmnpqrstuvwxyz"
        required_sets.append(chars)
    
    if use_uppercase:
        chars = UPPERCASE
        if avoid_ambiguous:
            chars = ''.join(c for c in chars if c not in AMBIGUOUS)
        char_pool += chars          # "ABCDEFGHJKMNPQRSTUVWXYZ"
        required_sets.append(chars)
    
    if use_digits:
        chars = DIGITS
        if avoid_ambiguous:
            chars = ''.join(c for c in chars if c not in AMBIGUOUS)
        char_pool += chars          # "23456789"
        required_sets.append(chars)
    
    if use_special:
        char_pool += SPECIAL        # "!@#$%^&*"
        required_sets.append(SPECIAL)
    
    # STEP 2: Ensure minimum from each character type
    password_chars = []
    
    for char_set in required_sets:
        for _ in range(min_each_type):
            password_chars.append(secrets.choice(char_set))
    # Now we have at least 1 from each required type
    
    # STEP 3: Fill remaining length with random choices
    for _ in range(length - len(password_chars)):
        password_chars.append(secrets.choice(char_pool))
    
    # STEP 4: Shuffle to avoid predictable patterns
    secrets.SystemRandom().shuffle(password_chars)
    
    return ''.join(password_chars)
    # Example output: "xK9#mP2$vL5@nQ8!"
```

### Stage 3: Entropy Calculation

After generation, entropy is calculated:

```python
# password_generator.py (lines 172-204)
def calculate_entropy(password: str, charset_size: int = 94) -> float:
    """
    Calculate Shannon entropy of a password.
    
    Formula: entropy = length * log2(charset_size)
    """
    # Determine actual charset size based on password content
    actual_charset = 0
    if any(c in LOWERCASE for c in password):
        actual_charset += 26
    if any(c in UPPERCASE for c in password):
        actual_charset += 26
    if any(c in DIGITS for c in password):
        actual_charset += 10
    if any(c in SPECIAL for c in password):
        actual_charset += len(SPECIAL)
    
    charset = actual_charset if actual_charset > 0 else charset_size
    
    # Shannon entropy formula
    return len(password) * math.log2(charset)
    # Example: 16 chars * log2(62) ≈ 95.3 bits
```

---

## Flow 3: Batch Processing

Multiple passwords processed together using **asynchronous API calls** for optimal performance:

```python
# main.py (lines 304-386)
def batch_check_passwords(
    file_path: Path,
    verbose: bool = True,
    export_path: Optional[Path] = None,
    export_format: str = "json",
    max_concurrent: int = DEFAULT_MAX_CONCURRENT
) -> List[dict]:
    """
    Check multiple passwords from a file.
    
    Uses asynchronous API calls to check passwords concurrently for
    significantly improved performance on large-scale audits.
    """
    # STEP 1: Read passwords from file
    with open(file_path, "r", encoding="utf-8") as f:
        passwords = [line.strip() for line in f if line.strip()]
    
    # STEP 2: Evaluate strength (CPU-bound, synchronous)
    strength_results = {}
    for password in track(
        passwords,
        description="Evaluating strength...",
        console=console
    ):
        strength_results[password] = evaluate_password_strength(password)
    
    # STEP 3: Check breaches asynchronously (IO-bound)
    async def run_async_checks():
        breach_results = await check_pwned_batch(
            passwords,
            max_concurrent=max_concurrent  # Default: 10 concurrent requests
        )
        return {pwd: count for pwd, count in breach_results}
    
    breach_results = asyncio.run(run_async_checks())
    
    # STEP 4: Compile results
    for password in passwords:
        strength_result = strength_results[password]
        pwned_count = breach_results.get(password)
        # ... compile result dict
    
    # STEP 5: Export results (passwords excluded from export)
    if export_path:
        export_results(results, export_path, export_format)
    
    return results
```

### Async Breach Checking Architecture

```python
# breach_checker.py (lines 154-220)
async def check_pwned_batch(
    passwords: List[str],
    max_concurrent: int = 10,
    timeout: int = 5
) -> List[Tuple[str, Optional[int]]]:
    """
    Check multiple passwords concurrently for breaches.
    
    Architecture:
    - Semaphore controls concurrent API calls (default: 10)
    - Connection pooling via aiohttp.ClientSession
    - Rate limiting: 100ms delay between requests
    - Graceful error handling: one failure doesn't stop batch
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def bounded_check(password, session):
        async with semaphore:  # Limit concurrency
            result = await check_pwned_async(password, session, timeout)
            await asyncio.sleep(0.1)  # Rate limiting
            return (password, result)
    
    async with aiohttp.ClientSession() as session:
        tasks = [bounded_check(pwd, session) for pwd in passwords]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        # Process results, handle exceptions...
```

**Performance Improvement:**
- Sequential: 100 passwords × 500ms = ~50 seconds
- Async (10 concurrent): ~5 seconds (10x faster)

Export function (note: passwords are NOT exported for security):

```python
# main.py (lines 490-559)
def export_results(results: List[dict], export_path: Path, format_type: str):
    """
    Export batch results to file.
    """
    if format_type.lower() == "json":
        export_data = {
            "summary": {
                "total_checked": len(results),
                "secure_count": sum(1 for r in results if r["is_secure"]),
                "strong_count": sum(1 for r in results if r["is_strong"]),
                "safe_count": sum(1 for r in results if r["is_safe"])
            },
            "results": [
                {
                    "password_id": i + 1,
                    "password_length": len(r["password"]),  # Length only!
                    # NOT the actual password
                    "strength_score": r["strength_score"],
                    "strength_label": r["strength_label"],
                    "entropy": r["entropy"],
                    "crack_time": r["crack_time"],
                    "breach_count": r["breach_count"],
                    "is_secure": r["is_secure"],
                    "feedback": r["feedback"]
                }
                for i, r in enumerate(results)
            ]
        }
```

---

## Module Interactions

### Import Flow

```python
# main.py (lines 26-39)
# 1. Import breach checker
from breach_checker import check_pwned, format_breach_result

# 2. Import password evaluator
from password_evaluator import (
    evaluate_password_strength,
    format_strength_result,
    is_password_strong,
    MIN_LENGTH,
    PasswordStrengthResult
)

# 3. Import password generator
from password_generator import (
    generate_secure_password,
    generate_passphrase,
    calculate_entropy,
    get_password_strength_rating
)
```

### Function Call Graph

```
main.py
├── check_single_password(password)
│   ├── password_evaluator.evaluate_password_strength(password)
│   │   └── zxcvbn(password) [external library]
│   └── breach_checker.check_pwned(password)
│       └── hashlib.sha1(password.encode()).hexdigest()
├── generate_password_cli()
│   ├── password_generator.generate_secure_password()
│   │   └── secrets.choice(char_pool)
│   ├── password_generator.generate_passphrase()
│   │   └── secrets.choice(word_list)
│   └── password_generator.calculate_entropy(password)
└── batch_check_passwords()
    ├── password_evaluator.evaluate_password_strength(password) [for each]
    └── breach_checker.check_pwned(password) [for each]
```

---

## Data Structures

### PasswordStrengthResult (Dataclass)

```python
# password_evaluator.py (lines 16-38)
@dataclass
class PasswordStrengthResult:
    """
    Container for password strength evaluation results.
    """
    score: int                          # zxcvbn score (0-4)
    strength_label: str                 # "Very Weak" to "Strong"
    entropy: float                      # Shannon entropy in bits
    crack_time_display: str             # Human-readable crack time
    crack_time_seconds: float           # Numeric seconds to crack
    feedback: List[str]                 # Improvement suggestions
    warning: Optional[str]              # High-level warning
    has_patterns: bool                  # Contains common patterns
```

### Example Result Objects

**Weak Password ("password"):**
```python
PasswordStrengthResult(
    score=0,
    strength_label="Very Weak",
    entropy=0.0,                        # Very low entropy
    crack_time_display="instant",       # Crackable instantly
    crack_time_seconds=0.0,
    feedback=[
        "Use at least 12 characters",
        "Add uppercase letters",
        "Add numbers",
        "Add special characters",
        "This is a top-10 common password"
    ],
    warning="This is a top-10 common password",
    has_patterns=True
)
```

**Strong Password ("xK9#mP2$vL5@nQ8!"):**
```python
PasswordStrengthResult(
    score=4,
    strength_label="Strong",
    entropy=107.3,                      # High entropy
    crack_time_display="centuries",     # Un Crackable
    crack_time_seconds=3.2e18,
    feedback=[],                        # No suggestions needed
    warning=None,
    has_patterns=False
)
```

---

## Security Considerations

### 1. Password Handling in Memory

```python
# Passwords are handled as Python strings
password = getpass.getpass("Password: ")  # Not echoed to terminal

# Strings are immutable in Python - old references remain until garbage collected
# For sensitive applications, consider using bytearray and zeroing memory
```

### 2. K-Anonymity in Breach Checking

```python
# NEVER send the full password or hash
sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
prefix = sha1[:5]    # Only send: "CBFDA"
suffix = sha1[5:]    # Keep local: "C6008F9CAB4083784CBD1874F76618D2A97"

# API query includes only prefix
url = f"https://api.pwnedpasswords.com/range/{prefix}"
```

### 3. Cryptographically Secure Random Generation

```python
# WRONG - uses Mersenne Twister (not secure)
import random
password = ''.join(random.choice(chars) for _ in range(16))

# CORRECT - uses OS CSPRNG
import secrets
password = ''.join(secrets.choice(chars) for _ in range(16))
```

### 4. No Logging of Passwords

```python
# breach_checker.py (lines 54-62)
except requests.exceptions.RequestException as e:
    logger.error(f"HaveIBeenPwned API request failed: {e}")
    # Notice: 'password' is NOT logged, only the error 'e'
    return None
```

### 5. Export Security

```python
# batch_results.json contains:
{
    "password_id": 1,           # ID, not the password
    "password_length": 16,      # Length only
    "strength_score": 4,
    # Actual password is NEVER exported
}

# NOT included in export:
# "password": "xK9#mP2$vL5@nQ8!"  # <-- Intentionally excluded
```

---

## Study Questions

1. **Why is k-anonymity important in breach checking?**
   - It prevents the API provider from knowing which specific passwords are being checked

2. **What is the difference between `random` and `secrets` modules?**
   - `random` uses Mersenne Twister (predictable)
   - `secrets` uses OS CSPRNG (/dev/urandom, CryptGenRandom)

3. **How is entropy calculated?**
   - Formula: `entropy = length × log2(charset_size)`
   - Example: 16 characters from 62-character set = 16 × log2(62) ≈ 95.3 bits

4. **What does zxcvbn provide that regex checks don't?**
   - Pattern detection (dictionary words, dates, sequences)
   - Realistic crack time estimation
   - Context-aware feedback

5. **Why are passwords excluded from batch export?**
   - Security: Exported files could be accessed by others
   - Privacy: Length is sufficient for analysis without exposing actual passwords

---

## Flow Summary Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PASSWORD FLOW SUMMARY                           │
└─────────────────────────────────────────────────────────────────────────┘

INPUT OPTIONS:
┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐
│ Interactive │  │   CLI arg   │  │   File      │  │   Generate      │
│  getpass()  │  │   -p pass   │  │  --batch    │  │  --generate     │
└──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └────────┬────────┘
       │                │                │                  │
       └────────────────┴────────────────┘                  │
                      │                                     │
                      ▼                                     │
              ┌─────────────┐                              │
              │  main.py    │                              │
              │  Entry      │◄─────────────────────────────┘
              │  Point      │
              └──────┬──────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
   ┌─────────┐ ┌──────────┐ ┌──────────┐
   │password │ │ password │ │ password │
   │_evaluato│ │_generator│ │_checker  │
   │   r.py  │ │  .py     │ │  .py     │
   └────┬────┘ └────┬─────┘ └────┬─────┘
        │           │            │
        ▼           ▼            ▼
   ┌─────────┐ ┌──────────┐ ┌──────────┐
   │ zxcvbn  │ │ secrets  │ │  SHA-1   │
   │ library │ │  module  │ │  hash    │
   └────┬────┘ └────┬─────┘ └────┬─────┘
        │           │            │
        └────────────┴────────────┘
                     │
                     ▼
              ┌─────────────┐
              │   Results   │
              │   Display   │
              └─────────────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
   ┌─────────┐ ┌──────────┐ ┌──────────┐
   │ Console │ │  JSON    │ │   CSV    │
   │  Rich   │ │  Export  │ │  Export  │
   │  UI     │ │(no pass) │ │(no pass) │
   └─────────┘ └──────────┘ └──────────┘
```

---

*Document generated for educational purposes. Study each module's source code alongside this document for complete understanding.*