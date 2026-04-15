"""
Secure Password Generator Module

Generates cryptographically secure passwords using the secrets module.
Follows security best practices for random password generation.
"""

import secrets
import string
from typing import Optional


# Character sets for password generation
UPPERCASE = string.ascii_uppercase
LOWERCASE = string.ascii_lowercase
DIGITS = string.digits
SPECIAL = "!@#$%^&*"
AMBIGUOUS = "0O1lI"  # Characters that look similar


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
    
    Uses Python's secrets module which provides cryptographically
    strong random numbers suitable for password generation.
    
    Args:
        length: Password length (default: 16, minimum: 4)
        use_uppercase: Include uppercase letters (default: True)
        use_lowercase: Include lowercase letters (default: True)
        use_digits: Include digits (default: True)
        use_special: Include special characters (default: True)
        avoid_ambiguous: Exclude visually similar characters (default: True)
        min_each_type: Minimum characters from each selected type (default: 1)
    
    Returns:
        A securely generated password string
    
    Raises:
        ValueError: If parameters are invalid or impossible to satisfy
    """
    # Validate parameters
    if length < 4:
        raise ValueError("Password length must be at least 4 characters")
    
    # Build character pool
    char_pool = ""
    required_sets = []
    
    if use_lowercase:
        chars = LOWERCASE
        if avoid_ambiguous:
            chars = ''.join(c for c in chars if c not in AMBIGUOUS)
        char_pool += chars
        required_sets.append(chars)
    
    if use_uppercase:
        chars = UPPERCASE
        if avoid_ambiguous:
            chars = ''.join(c for c in chars if c not in AMBIGUOUS)
        char_pool += chars
        required_sets.append(chars)
    
    if use_digits:
        chars = DIGITS
        if avoid_ambiguous:
            chars = ''.join(c for c in chars if c not in AMBIGUOUS)
        char_pool += chars
        required_sets.append(chars)
    
    if use_special:
        char_pool += SPECIAL
        required_sets.append(SPECIAL)
    
    if not char_pool:
        raise ValueError("At least one character type must be selected")
    
    # Check if minimum requirements can be satisfied
    min_required = len(required_sets) * min_each_type
    if min_required > length:
        raise ValueError(
            f"Cannot satisfy minimum of {min_each_type} from each type "
            f"with length {length}. Need at least {min_required}."
        )
    
    # Generate password ensuring minimum from each required set
    password_chars = []
    
    for char_set in required_sets:
        for _ in range(min_each_type):
            password_chars.append(secrets.choice(char_set))
    
    # Fill remaining length with random choices from full pool
    for _ in range(length - len(password_chars)):
        password_chars.append(secrets.choice(char_pool))
    
    # Shuffle to avoid predictable patterns (first chars from each set)
    secrets.SystemRandom().shuffle(password_chars)
    
    return ''.join(password_chars)


def generate_passphrase(
    num_words: int = 4,
    word_list: Optional[list] = None,
    separator: str = "-",
    capitalize: bool = True,
    add_number: bool = True
) -> str:
    """
    Generate a memorable passphrase (Diceware-style).
    
    Creates a passphrase by combining random words, which can be
    easier to remember than random characters while maintaining
    high entropy.
    
    Args:
        num_words: Number of words to combine (default: 4)
        word_list: Custom word list (default: common English words)
        separator: Character(s) between words (default: "-")
        capitalize: Randomly capitalize words (default: True)
        add_number: Append random number (default: True)
    
    Returns:
        A passphrase string
    """
    if num_words < 2:
        raise ValueError("Passphrase must have at least 2 words")
    
    # Default word list - common, recognizable English words
    if word_list is None:
        word_list = [
            "apple", "banana", "cherry", "dragon", "eagle", "falcon",
            "garden", "harbor", "island", "jungle", "kitchen", "lemon",
            "mountain", "nectar", "ocean", "purple", "quartz", "rabbit",
            "silver", "tiger", "umbrella", "violet", "window", "yellow",
            "zebra", "anchor", "bridge", "castle", "diamond", "emerald",
            "forest", "galaxy", "hammer", "iceberg", "journey", "kite",
            "ladder", "mirror", "needle", "orange", "pencil", "quiver",
            "rocket", "sunset", "tunnel", "universe", "volcano", "whistle",
            "crystal", "meadow", "thunder", "breeze", "canyon", "desert"
        ]
    
    # Select random words
    words = [secrets.choice(word_list) for _ in range(num_words)]
    
    # Apply random capitalization
    if capitalize:
        words = [
            w.upper() if secrets.choice([True, False]) else w.lower()
            for w in words
        ]
    
    passphrase = separator.join(words)
    
    # Append random number for extra entropy
    if add_number:
        passphrase += separator + str(secrets.randbelow(1000)).zfill(3)
    
    return passphrase


def calculate_entropy(password: str, charset_size: int = 94) -> float:
    """
    Calculate Shannon entropy of a password.
    
    Formula: entropy = length * log2(charset_size)
    
    Args:
        password: The password to calculate entropy for
        charset_size: Size of character set used (default: 94 printable ASCII)
    
    Returns:
        Entropy in bits
    """
    import math
    
    if not password:
        return 0.0
    
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
    
    # Use detected charset or provided default
    charset = actual_charset if actual_charset > 0 else charset_size
    
    return len(password) * math.log2(charset)


def get_password_strength_rating(entropy: float) -> str:
    """
    Get a human-readable strength rating based on entropy.
    
    Args:
        entropy: Password entropy in bits
    
    Returns:
        Strength rating string
    """
    if entropy < 28:
        return "Very Weak"
    elif entropy < 36:
        return "Weak"
    elif entropy < 60:
        return "Moderate"
    elif entropy < 80:
        return "Strong"
    else:
        return "Very Strong"