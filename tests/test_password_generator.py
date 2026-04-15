"""
Tests for password_generator.py module

Tests cover:
- Secure password generation with various options
- Passphrase generation
- Entropy calculation
- Character set validation
- CSPRNG verification (secrets module usage)
- Edge cases (invalid parameters, empty inputs)
"""

import string
import pytest
from unittest.mock import patch
import secrets

from password_generator import (
    generate_secure_password,
    generate_passphrase,
    calculate_entropy,
    get_password_strength_rating,
    UPPERCASE,
    LOWERCASE,
    DIGITS,
    SPECIAL,
    AMBIGUOUS
)


class TestGenerateSecurePassword:
    """Tests for generate_secure_password function."""
    
    def test_default_password_generation(self):
        """Default call should generate 16-character password."""
        password = generate_secure_password()
        
        assert len(password) == 16
        assert isinstance(password, str)
    
    def test_custom_length(self):
        """Custom length should be respected."""
        password = generate_secure_password(length=24)
        
        assert len(password) == 24
    
    def test_minimum_length_enforced(self):
        """Length below 4 should raise ValueError."""
        with pytest.raises(ValueError, match="at least 4"):
            generate_secure_password(length=3)
    
    def test_includes_uppercase_by_default(self):
        """Default password should include uppercase letters."""
        password = generate_secure_password(length=50)  # Long for statistical certainty
        
        assert any(c in UPPERCASE for c in password)
    
    def test_includes_lowercase_by_default(self):
        """Default password should include lowercase letters."""
        password = generate_secure_password(length=50)
        
        assert any(c in LOWERCASE for c in password)
    
    def test_includes_digits_by_default(self):
        """Default password should include digits."""
        password = generate_secure_password(length=50)
        
        assert any(c in DIGITS for c in password)
    
    def test_includes_special_by_default(self):
        """Default password should include special characters."""
        password = generate_secure_password(length=50)
        
        assert any(c in SPECIAL for c in password)
    
    def test_no_uppercase_when_disabled(self):
        """Password should not have uppercase when disabled."""
        password = generate_secure_password(length=50, use_uppercase=False)
        
        assert not any(c in UPPERCASE for c in password)
        assert any(c in LOWERCASE for c in password)
    
    def test_no_lowercase_when_disabled(self):
        """Password should not have lowercase when disabled."""
        password = generate_secure_password(length=50, use_lowercase=False)
        
        assert not any(c in LOWERCASE for c in password)
        assert any(c in UPPERCASE for c in password)
    
    def test_no_digits_when_disabled(self):
        """Password should not have digits when disabled."""
        password = generate_secure_password(length=50, use_digits=False)
        
        assert not any(c in DIGITS for c in password)
    
    def test_no_special_when_disabled(self):
        """Password should not have special chars when disabled."""
        password = generate_secure_password(length=50, use_special=False)
        
        assert not any(c in SPECIAL for c in password)
    
    def test_ambiguous_characters_excluded(self):
        """Ambiguous characters should be excluded by default."""
        password = generate_secure_password(length=100)
        
        assert not any(c in AMBIGUOUS for c in password)
    
    def test_ambiguous_characters_included_when_allowed(self):
        """Ambiguous characters should appear when not avoiding."""
        # With short length and many exclusions, ambiguous might not appear
        # Test that they CAN appear
        found_ambiguous = False
        for _ in range(100):  # Generate many passwords to statistically find ambiguous
            password = generate_secure_password(
                length=100, 
                avoid_ambiguous=False,
                use_uppercase=True,
                use_lowercase=True,
                use_digits=True
            )
            if any(c in AMBIGUOUS for c in password):
                found_ambiguous = True
                break
        
        assert found_ambiguous, "Should occasionally include ambiguous characters"
    
    def test_minimum_each_type_enforced(self):
        """Minimum from each type should be enforced."""
        password = generate_secure_password(
            length=12,
            min_each_type=2,
            use_uppercase=True,
            use_lowercase=True,
            use_digits=True,
            use_special=True
        )
        
        assert sum(1 for c in password if c in UPPERCASE) >= 2
        assert sum(1 for c in password if c in LOWERCASE) >= 2
        assert sum(1 for c in password if c in DIGITS) >= 2
        assert sum(1 for c in password if c in SPECIAL) >= 2
    
    def test_impossible_requirements_raise_error(self):
        """Should raise error when requirements exceed length."""
        with pytest.raises(ValueError, match="Cannot satisfy"):
            generate_secure_password(
                length=6,
                min_each_type=2,
                use_uppercase=True,
                use_lowercase=True,
                use_digits=True,
                use_special=True
            )
    
    def test_no_character_types_raises_error(self):
        """Should raise error when no character types selected."""
        with pytest.raises(ValueError, match="At least one"):
            generate_secure_password(
                use_uppercase=False,
                use_lowercase=False,
                use_digits=False,
                use_special=False
            )
    
    def test_uses_secrets_module(self):
        """Should use secrets module for CSPRNG."""
        with patch('password_generator.secrets.choice') as mock_choice:
            mock_choice.return_value = 'A'
            generate_secure_password(length=4)
            
            assert mock_choice.called
    
    def test_password_shuffled(self):
        """Password should be shuffled (not predictable pattern)."""
        # Generate multiple passwords and verify they're shuffled
        # Note: There's a small probability this could fail randomly
        passwords = [generate_secure_password(length=20) for _ in range(10)]
        
        # All should be different (extremely high probability)
        assert len(set(passwords)) == len(passwords)


class TestGeneratePassphrase:
    """Tests for generate_passphrase function."""
    
    def test_default_passphrase_generation(self):
        """Default should generate 4-word passphrase."""
        passphrase = generate_passphrase()
        
        words = passphrase.split('-')
        # Remove possible number suffix
        words = [w for w in words if not w.isdigit()]
        assert len(words) == 4
    
    def test_custom_word_count(self):
        """Custom word count should be respected."""
        passphrase = generate_passphrase(num_words=6)
        
        words = passphrase.replace('-', ' ').split()
        words = [w for w in words if not w.isdigit()]
        assert len(words) == 6
    
    def test_minimum_two_words(self):
        """Should require at least 2 words."""
        with pytest.raises(ValueError, match="at least 2 words"):
            generate_passphrase(num_words=1)
    
    def test_custom_separator(self):
        """Custom separator should be used."""
        passphrase = generate_passphrase(separator="_", num_words=3)
        
        assert "_" in passphrase
        assert "-" not in passphrase
    
    def test_capitalization_random(self):
        """Words should be randomly capitalized."""
        # Generate many passphrases to statistically verify random capitalization
        upper_count = 0
        lower_count = 0
        
        for _ in range(100):
            passphrase = generate_passphrase(num_words=4, capitalize=True)
            words = passphrase.split('-')
            words = [w for w in words if not w.isdigit()]
            for word in words:
                if word.isupper():
                    upper_count += 1
                elif word.islower():
                    lower_count += 1
        
        # Should have both uppercase and lowercase words across samples
        assert upper_count > 0, "Should have some uppercase words"
        assert lower_count > 0, "Should have some lowercase words"
    
    def test_no_capitalization_when_disabled(self):
        """All lowercase when capitalization disabled."""
        passphrase = generate_passphrase(capitalize=False, add_number=False)
        
        words = passphrase.split('-')
        for word in words:
            assert word.islower(), f"Word '{word}' should be lowercase"
    
    def test_number_appended(self):
        """Number should be appended when enabled."""
        passphrase = generate_passphrase(add_number=True)
        
        # Should end with a 3-digit number
        parts = passphrase.split('-')
        last_part = parts[-1]
        assert last_part.isdigit()
        assert len(last_part) == 3
    
    def test_no_number_when_disabled(self):
        """No number when add_number=False."""
        passphrase = generate_passphrase(add_number=False)
        
        parts = passphrase.split('-')
        for part in parts:
            assert not part.isdigit()
    
    def test_custom_word_list(self):
        """Custom word list should be used."""
        custom_words = ["alpha", "beta", "gamma", "delta"]
        passphrase = generate_passphrase(
            num_words=2,
            word_list=custom_words,
            add_number=False,
            capitalize=False
        )
        
        words = passphrase.split('-')
        assert all(w in custom_words for w in words)
    
    def test_uses_secrets_choice(self):
        """Should use secrets.choice for word selection."""
        with patch('password_generator.secrets.choice') as mock_choice:
            mock_choice.return_value = "testword"
            generate_passphrase(num_words=2, add_number=False)
            
            assert mock_choice.called


class TestCalculateEntropy:
    """Tests for calculate_entropy function."""
    
    def test_empty_password_zero_entropy(self):
        """Empty password should have 0 entropy."""
        entropy = calculate_entropy("")
        
        assert entropy == 0.0
    
    def test_password_entropy_calculated(self):
        """Entropy should be calculated correctly."""
        # 8 char password with 26 lowercase = 8 * log2(26) ≈ 37.6 bits
        entropy = calculate_entropy("abcdefgh", charset_size=26)
        
        assert entropy > 0
        assert abs(entropy - 37.6035) < 0.01  # Approximate value
    
    def test_detects_charset_from_password(self):
        """Should detect actual charset from password content."""
        # Lowercase only
        entropy_lower = calculate_entropy("abcdefgh")
        
        # Mixed charset
        entropy_mixed = calculate_entropy("Abcdef1!")
        
        # Mixed should have higher entropy per character
        assert entropy_mixed > entropy_lower
    
    def test_very_long_password_high_entropy(self):
        """Very long password should have high entropy."""
        password = "A" * 100 + "1!"
        entropy = calculate_entropy(password)
        
        assert entropy > 500  # Should be very high


class TestGetPasswordStrengthRating:
    """Tests for get_password_strength_rating function."""
    
    def test_very_weak_rating(self):
        """Entropy < 28 should be Very Weak."""
        assert get_password_strength_rating(27) == "Very Weak"
        assert get_password_strength_rating(0) == "Very Weak"
    
    def test_weak_rating(self):
        """Entropy 28-35 should be Weak."""
        assert get_password_strength_rating(28) == "Weak"
        assert get_password_strength_rating(35) == "Weak"
    
    def test_moderate_rating(self):
        """Entropy 36-59 should be Moderate."""
        assert get_password_strength_rating(36) == "Moderate"
        assert get_password_strength_rating(59) == "Moderate"
    
    def test_strong_rating(self):
        """Entropy 60-79 should be Strong."""
        assert get_password_strength_rating(60) == "Strong"
        assert get_password_strength_rating(79) == "Strong"
    
    def test_very_strong_rating(self):
        """Entropy >= 80 should be Very Strong."""
        assert get_password_strength_rating(80) == "Very Strong"
        assert get_password_strength_rating(128) == "Very Strong"


class TestCSPRNG:
    """Tests verifying cryptographically secure random number generation."""
    
    def test_secrets_module_used_not_random(self):
        """Should use secrets module, not random module."""
        with patch('password_generator.secrets') as mock_secrets:
            mock_secrets.choice.return_value = 'A'
            mock_secrets.randbelow.return_value = 123
            mock_secrets.SystemRandom.return_value.shuffle = lambda x: None
            
            generate_secure_password(length=4)
            assert mock_secrets.choice.called
            
            generate_passphrase(num_words=2, add_number=True)
            assert mock_secrets.randbelow.called
    
    def test_generated_passwords_are_unique(self):
        """Generated passwords should be unique (high probability)."""
        passwords = {generate_secure_password() for _ in range(100)}
        
        assert len(passwords) == 100  # All unique
    
    def test_generated_passphrases_are_unique(self):
        """Generated passphrases should be unique (high probability)."""
        passphrases = {generate_passphrase() for _ in range(100)}
        
        assert len(passphrases) == 100  # All unique


class TestEdgeCases:
    """Edge case and security tests."""
    
    def test_unicode_in_passphrase_not_allowed(self):
        """Custom word list with unicode should work."""
        unicode_words = ["café", "naïve", "résumé"]
        passphrase = generate_passphrase(
            num_words=2,
            word_list=unicode_words,
            capitalize=False,
            add_number=False
        )
        
        assert any(word in passphrase for word in unicode_words)
    
    def test_single_word_list(self):
        """Word list with single word should work."""
        single_word = ["only"]
        passphrase = generate_passphrase(
            num_words=2,
            word_list=single_word,
            add_number=False
        )
        
        assert passphrase == "only-only" or passphrase == "ONLY-only" or passphrase == "only-ONLY" or passphrase == "ONLY-ONLY"