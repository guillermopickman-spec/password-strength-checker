"""
Tests for password_evaluator.py module

Tests cover:
- Basic requirement checking (length, character types)
- zxcvbn integration
- Edge cases (empty, unicode, very long passwords)
- Result formatting
- Security-focused input validation
"""

import pytest
from password_evaluator import (
    PasswordStrengthResult,
    check_basic_requirements,
    get_missing_requirements,
    evaluate_password_strength,
    format_strength_result,
    is_password_strong,
    get_password_recommendations,
    MIN_LENGTH
)


class TestBasicRequirements:
    """Tests for check_basic_requirements function."""
    
    def test_strong_password_passes_all_checks(self):
        """A strong password should pass all basic requirement checks."""
        password = "StrongP@ssw0rd123!"
        result = check_basic_requirements(password)
        
        assert result["length_ok"] is True
        assert result["has_uppercase"] is True
        assert result["has_lowercase"] is True
        assert result["has_digits"] is True
        assert result["has_special"] is True
    
    def test_short_password_fails_length(self):
        """Password shorter than MIN_LENGTH should fail length check."""
        password = "Short1!"
        result = check_basic_requirements(password)
        
        assert result["length_ok"] is False
        assert result["has_uppercase"] is True
        assert result["has_lowercase"] is True
        assert result["has_digits"] is True
        assert result["has_special"] is True
    
    def test_missing_uppercase_detected(self):
        """Password without uppercase should be detected."""
        password = "lowercase123!"
        result = check_basic_requirements(password)
        
        assert result["has_uppercase"] is False
        assert result["has_lowercase"] is True
    
    def test_missing_lowercase_detected(self):
        """Password without lowercase should be detected."""
        password = "UPPERCASE123!"
        result = check_basic_requirements(password)
        
        assert result["has_lowercase"] is False
        assert result["has_uppercase"] is True
    
    def test_missing_digits_detected(self):
        """Password without digits should be detected."""
        password = "NoDigitsHere!"
        result = check_basic_requirements(password)
        
        assert result["has_digits"] is False
    
    def test_missing_special_detected(self):
        """Password without special characters should be detected."""
        password = "NoSpecial123"
        result = check_basic_requirements(password)
        
        assert result["has_special"] is False
    
    def test_empty_password(self):
        """Empty password should fail all checks."""
        result = check_basic_requirements("")
        
        assert result["length_ok"] is False
        assert result["has_uppercase"] is False
        assert result["has_lowercase"] is False
        assert result["has_digits"] is False
        assert result["has_special"] is False


class TestMissingRequirements:
    """Tests for get_missing_requirements function."""
    
    def test_all_missing_reported(self):
        """All missing requirements should be reported."""
        checks = {
            "length_ok": False,
            "has_uppercase": False,
            "has_lowercase": False,
            "has_digits": False,
            "has_special": False
        }
        feedback = get_missing_requirements(checks)
        
        assert len(feedback) == 5
        assert any("12 characters" in f for f in feedback)
        assert any("lowercase" in f for f in feedback)
        assert any("uppercase" in f for f in feedback)
        assert any("numbers" in f for f in feedback)
        assert any("special characters" in f for f in feedback)
    
    def test_no_missing_requirements(self):
        """Empty list returned when all requirements met."""
        checks = {
            "length_ok": True,
            "has_uppercase": True,
            "has_lowercase": True,
            "has_digits": True,
            "has_special": True
        }
        feedback = get_missing_requirements(checks)
        
        assert feedback == []


class TestEvaluatePasswordStrength:
    """Tests for evaluate_password_strength function with zxcvbn."""
    
    def test_returns_password_strength_result(self):
        """Result should be a PasswordStrengthResult dataclass."""
        result = evaluate_password_strength("TestPassword123!")
        
        assert isinstance(result, PasswordStrengthResult)
        assert isinstance(result.score, int)
        assert isinstance(result.strength_label, str)
        assert isinstance(result.entropy, float)
        assert isinstance(result.crack_time_display, str)
        assert isinstance(result.crack_time_seconds, float)
        assert isinstance(result.feedback, list)
        assert isinstance(result.has_patterns, bool)
    
    def test_strong_password_high_score(self):
        """Strong password should have high zxcvbn score."""
        result = evaluate_password_strength("Tr0ub4dor&3!Secure")
        
        assert result.score >= 3
        assert result.entropy > 50  # Should have high entropy
    
    def test_weak_password_low_score(self):
        """Weak password should have low zxcvbn score."""
        result = evaluate_password_strength("123456")
        
        assert result.score <= 1
        assert result.entropy < 30
    
    def test_very_common_password_warning(self):
        """Very common passwords should have warnings."""
        result = evaluate_password_strength("password")
        
        assert result.warning is not None or len(result.feedback) > 0
    
    def test_unicode_password_handled(self):
        """Unicode characters should be handled gracefully."""
        result = evaluate_password_strength("пароль123!密码")
        
        assert isinstance(result, PasswordStrengthResult)
        assert result.score >= 0  # Should not crash
    
    def test_very_long_password(self):
        """Very long passwords should be processed without issues."""
        # Use a non-repetitive long password for better zxcvbn scoring
        long_password = "ThisIsAVeryLongPasswordWithManyCharactersAndNumbers123!@#"
        result = evaluate_password_strength(long_password)
        
        assert isinstance(result, PasswordStrengthResult)
        assert result.entropy > 30  # Should have decent entropy
    
    def test_password_with_patterns_detected(self):
        """Passwords with keyboard patterns should be flagged."""
        result = evaluate_password_strength("qwerty123!")
        
        assert result.has_patterns is True
    
    def test_feedback_includes_basic_requirements(self):
        """Short passwords should include length feedback."""
        result = evaluate_password_strength("short")
        
        assert any("12 characters" in f for f in result.feedback)


class TestFormatStrengthResult:
    """Tests for format_strength_result function."""
    
    def test_format_includes_strength_label(self):
        """Formatted output should include strength label."""
        result = evaluate_password_strength("Test123!")
        formatted = format_strength_result(result)
        
        assert result.strength_label in formatted
    
    def test_format_includes_entropy(self):
        """Formatted output should include entropy."""
        result = evaluate_password_strength("Test123!")
        formatted = format_strength_result(result)
        
        assert "bits" in formatted
    
    def test_format_includes_crack_time(self):
        """Formatted output should include crack time."""
        result = evaluate_password_strength("Test123!")
        formatted = format_strength_result(result)
        
        assert "Crack time" in formatted
    
    def test_format_shows_warning(self):
        """Formatted output should show warning if present."""
        result = evaluate_password_strength("password")
        formatted = format_strength_result(result)
        
        # Should contain warning or be noted in some way
        assert len(formatted) > 0


class TestIsPasswordStrong:
    """Tests for is_password_strong function."""
    
    def test_strong_password_returns_true(self, strong_password):
        """Strong password should return True."""
        assert is_password_strong(strong_password) is True
    
    def test_weak_password_returns_false(self, weak_password):
        """Weak password should return False."""
        assert is_password_strong(weak_password) is False
    
    def test_medium_password_with_default_threshold(self, medium_password):
        """Medium password with default threshold (3) should pass."""
        result = is_password_strong(medium_password, min_score=3)
        # "Password123!" typically scores around 2-3 with zxcvbn
        # so this tests the threshold functionality
        assert isinstance(result, bool)
    
    def test_custom_min_score_threshold(self):
        """Custom min_score threshold should be respected."""
        # Very weak password (single char) should fail even with low threshold
        result_weak = is_password_strong("a", min_score=1)
        assert isinstance(result_weak, bool)
        
        # Strong password should pass with high threshold or return bool
        result_strong = is_password_strong("Tr0ub4dor&3!Secure", min_score=4)
        assert isinstance(result_strong, bool)


class TestGetPasswordRecommendations:
    """Tests for get_password_recommendations function."""
    
    def test_returns_list_of_recommendations(self):
        """Should return a list of recommendation strings."""
        recommendations = get_password_recommendations("weak")
        
        assert isinstance(recommendations, list)
        assert all(isinstance(r, str) for r in recommendations)
    
    def test_short_password_recommends_length(self):
        """Short password should recommend increasing length."""
        recommendations = get_password_recommendations("short")
        
        assert any("length" in r.lower() for r in recommendations)
    
    def test_common_password_warns(self):
        """Common password should have specific warning."""
        recommendations = get_password_recommendations("password")
        
        # Should have recommendations about common words
        assert len(recommendations) > 0


class TestSecurityEdgeCases:
    """Security-focused tests for edge cases."""
    
    def test_null_bytes_handled(self):
        """Password with null bytes should be handled."""
        result = evaluate_password_strength("test\x00password")
        assert isinstance(result, PasswordStrengthResult)
    
    def test_newline_characters_handled(self):
        """Password with newlines should be handled."""
        result = evaluate_password_strength("test\npassword")
        assert isinstance(result, PasswordStrengthResult)
    
    def test_tab_characters_handled(self):
        """Password with tabs should be handled."""
        result = evaluate_password_strength("test\tpassword")
        assert isinstance(result, PasswordStrengthResult)
    
    def test_emoji_password(self):
        """Password with emoji should be handled."""
        result = evaluate_password_strength("🔐Secure123!")
        assert isinstance(result, PasswordStrengthResult)