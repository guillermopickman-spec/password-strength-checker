"""
Password Evaluator Module

Evaluates password strength using both pattern matching and
professional entropy estimation via zxcvbn library.
"""

import math
import re
from dataclasses import dataclass
from typing import List, Optional

from zxcvbn import zxcvbn


@dataclass
class PasswordStrengthResult:
    """
    Container for password strength evaluation results.
    
    Attributes:
        score: zxcvbn score (0-4, where 4 is strongest)
        strength_label: Human-readable strength label
        entropy: Shannon entropy in bits (guesses_log2)
        crack_time_display: Human-readable crack time estimate
        crack_time_seconds: Estimated seconds to crack
        feedback: List of improvement suggestions
        warning: High-level warning message
        has_patterns: Whether password contains common patterns
    """
    score: int
    strength_label: str
    entropy: float
    crack_time_display: str
    crack_time_seconds: float
    feedback: List[str]
    warning: Optional[str]
    has_patterns: bool


# Regex-based checks for basic requirements
MIN_LENGTH = 12


def check_basic_requirements(password: str) -> dict:
    """
    Check basic password requirements using regex patterns.
    
    Args:
        password: Password to check
    
    Returns:
        Dictionary with check results
    """
    return {
        "length_ok": len(password) >= MIN_LENGTH,
        "has_uppercase": bool(re.search(r"[A-Z]", password)),
        "has_lowercase": bool(re.search(r"[a-z]", password)),
        "has_digits": bool(re.search(r"\d", password)),
        "has_special": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)),
    }


def get_missing_requirements(checks: dict) -> List[str]:
    """
    Generate feedback for missing requirements.
    
    Args:
        checks: Result from check_basic_requirements
    
    Returns:
        List of improvement suggestions
    """
    feedback = []
    
    if not checks["length_ok"]:
        feedback.append(f"Use at least {MIN_LENGTH} characters (current: insufficient)")
    
    if not checks["has_lowercase"]:
        feedback.append("Add lowercase letters (a-z)")
    
    if not checks["has_uppercase"]:
        feedback.append("Add uppercase letters (A-Z)")
    
    if not checks["has_digits"]:
        feedback.append("Add numbers (0-9)")
    
    if not checks["has_special"]:
        feedback.append("Add special characters (!@#$%^&*)")
    
    return feedback


def evaluate_password_strength(password: str) -> PasswordStrengthResult:
    """
    Evaluate password strength using zxcvbn and custom checks.
    
    Combines professional entropy estimation from zxcvbn with
    basic requirement checking for comprehensive evaluation.
    
    Args:
        password: Password to evaluate
    
    Returns:
        PasswordStrengthResult with detailed analysis
    """
    # Get zxcvbn analysis
    zxcvbn_result = zxcvbn(password)
    
    # Map zxcvbn score to label
    score_labels = {
        0: "Very Weak",
        1: "Weak", 
        2: "Fair",
        3: "Good",
        4: "Strong"
    }
    
    # Get feedback from zxcvbn
    feedback = zxcvbn_result["feedback"]["suggestions"]
    warning = zxcvbn_result["feedback"]["warning"] or None
    
    # Add our custom requirements check
    basic_checks = check_basic_requirements(password)
    missing = get_missing_requirements(basic_checks)
    
    # Combine feedback (prepend our basic requirements if any)
    if missing:
        feedback = missing + feedback
    
    # If no feedback but score is low, add generic message
    if not feedback and zxcvbn_result["score"] < 3:
        feedback.append("Consider using a longer, more random password")
    
    # Check for patterns (dictionary words, sequences, etc.)
    has_patterns = bool(
        zxcvbn_result["sequence"] or 
        warning or 
        zxcvbn_result["score"] < 3
    )
    
    # Calculate entropy from guesses (log2)
    guesses = zxcvbn_result["guesses"]  # type: ignore
    entropy = math.log2(float(guesses)) if guesses > 0 else 0.0
    
    return PasswordStrengthResult(
        score=zxcvbn_result["score"],
        strength_label=score_labels.get(zxcvbn_result["score"], "Unknown"),
        entropy=entropy,
        crack_time_display=zxcvbn_result["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
        crack_time_seconds=float(zxcvbn_result["crack_times_seconds"]["offline_slow_hashing_1e4_per_second"]),
        feedback=feedback,
        warning=warning,
        has_patterns=has_patterns
    )


def format_strength_result(result: PasswordStrengthResult) -> str:
    """
    Format password strength result for display.
    
    Args:
        result: PasswordStrengthResult to format
    
    Returns:
        Formatted multi-line string
    """
    # Strength indicator with emoji
    emojis = {
        "Very Weak": "🔴",
        "Weak": "🟠", 
        "Fair": "🟡",
        "Good": "🟢",
        "Strong": "🟢"
    }
    
    emoji = emojis.get(result.strength_label, "⚪")
    
    lines = [
        f"{emoji}  Strength: {result.strength_label} (Score: {result.score}/4)",
        f"📊  Entropy: {result.entropy:.1f} bits",
        f"⏱️   Crack time: {result.crack_time_display}"
    ]
    
    if result.warning:
        lines.append(f"⚠️   Warning: {result.warning}")
    
    if result.feedback:
        lines.append("\n💡 Suggestions:")
        for suggestion in result.feedback:
            lines.append(f"   • {suggestion}")
    
    return "\n".join(lines)


def is_password_strong(password: str, min_score: int = 3) -> bool:
    """
    Quick check if password meets strong criteria.
    
    Args:
        password: Password to check
        min_score: Minimum zxcvbn score (default: 3 - Good)
    
    Returns:
        True if password is strong enough
    """
    result = evaluate_password_strength(password)
    return result.score >= min_score


def get_password_recommendations(password: str) -> List[str]:
    """
    Get actionable recommendations for improving password.
    
    Args:
        password: Current password
    
    Returns:
        List of specific recommendations
    """
    result = evaluate_password_strength(password)
    
    recommendations = []
    
    # Add high priority items first
    if not check_basic_requirements(password)["length_ok"]:
        recommendations.append(f"Increase length to at least {MIN_LENGTH} characters")
    
    if result.warning:
        recommendations.append(f"Address: {result.warning}")
    
    # Add other feedback
    for item in result.feedback:
        if item not in recommendations:
            recommendations.append(item)
    
    return recommendations