"""
Tests for main.py module (CLI interface)

Tests cover:
- Command-line argument parsing
- Interactive mode
- Password generation mode
- Error handling
- Exit codes
- Rich console output formatting
"""

import sys
import pytest
from unittest.mock import Mock, patch, MagicMock
import argparse

from main import (
    print_banner,
    display_strength_panel,
    display_suggestions,
    display_breach_panel,
    display_final_status,
    check_single_password,
    interactive_mode,
    generate_password_cli,
    main
)


class TestPrintBanner:
    """Tests for print_banner function."""
    
    def test_banner_prints(self, capsys):
        """Banner should print without errors."""
        print_banner()
        # Should not raise any exceptions


class TestDisplayStrengthPanel:
    """Tests for display_strength_panel function."""
    
    def test_panel_displays_strong_password(self):
        """Panel should display for strong password."""
        from password_evaluator import PasswordStrengthResult
        
        result = PasswordStrengthResult(
            score=4,
            strength_label="Strong",
            entropy=65.0,
            crack_time_display="centuries",
            crack_time_seconds=1e20,
            feedback=[],
            warning=None,
            has_patterns=False
        )
        
        # Should not raise any exceptions
        display_strength_panel(result)
    
    def test_panel_displays_weak_password(self):
        """Panel should display for weak password."""
        from password_evaluator import PasswordStrengthResult
        
        result = PasswordStrengthResult(
            score=1,
            strength_label="Weak",
            entropy=15.0,
            crack_time_display="instant",
            crack_time_seconds=0.001,
            feedback=["Add more characters"],
            warning="Too common",
            has_patterns=True
        )
        
        # Should not raise any exceptions
        display_strength_panel(result)


class TestDisplaySuggestions:
    """Tests for display_suggestions function."""
    
    def test_suggestions_displayed_when_feedback_exists(self):
        """Suggestions should display when feedback present."""
        from password_evaluator import PasswordStrengthResult
        
        result = PasswordStrengthResult(
            score=2,
            strength_label="Fair",
            entropy=30.0,
            crack_time_display="seconds",
            crack_time_seconds=5.0,
            feedback=["Add uppercase", "Add numbers"],
            warning=None,
            has_patterns=False
        )
        
        # Should not raise any exceptions
        display_suggestions(result)
    
    def test_no_suggestions_when_no_feedback(self):
        """Nothing displayed when no feedback."""
        from password_evaluator import PasswordStrengthResult
        
        result = PasswordStrengthResult(
            score=4,
            strength_label="Strong",
            entropy=80.0,
            crack_time_display="years",
            crack_time_seconds=1e8,
            feedback=[],
            warning=None,
            has_patterns=False
        )
        
        # Should not raise any exceptions
        display_suggestions(result)


class TestDisplayBreachPanel:
    """Tests for display_breach_panel function."""
    
    def test_panel_shows_safe(self):
        """Panel should show safe status."""
        display_breach_panel(0)
    
    def test_panel_shows_breached(self):
        """Panel should show breached status."""
        display_breach_panel(150)
    
    def test_panel_shows_unknown(self):
        """Panel should show unknown status."""
        display_breach_panel(None)


class TestDisplayFinalStatus:
    """Tests for display_final_status function."""
    
    def test_secure_status(self):
        """Should display secure status."""
        display_final_status(is_strong=True, is_safe=True)
    
    def test_compromised_status(self):
        """Should display compromised status."""
        display_final_status(is_strong=True, is_safe=False)
    
    def test_weak_status(self):
        """Should display weak status."""
        display_final_status(is_strong=False, is_safe=True)
    
    def test_insecure_status(self):
        """Should display insecure status."""
        display_final_status(is_strong=False, is_safe=False)


class TestCheckSinglePassword:
    """Tests for check_single_password function."""
    
    def test_returns_true_for_strong_clean_password(self):
        """Should return True for strong, non-breached password."""
        with patch('main.evaluate_password_strength') as mock_eval:
            mock_eval.return_value = Mock(
                score=4,
                strength_label="Strong",
                entropy=80.0,
                crack_time_display="centuries",
                crack_time_seconds=1e20,
                feedback=[],
                warning=None,
                has_patterns=False
            )
            
            with patch('main.check_pwned') as mock_pwned:
                mock_pwned.return_value = 0
                
                result = check_single_password("StrongP@ss123!", verbose=False)
                
                assert result is True
    
    def test_returns_false_for_weak_password(self):
        """Should return False for weak password."""
        with patch('main.evaluate_password_strength') as mock_eval:
            mock_eval.return_value = Mock(
                score=1,
                strength_label="Weak",
                entropy=10.0,
                crack_time_display="instant",
                crack_time_seconds=0.001,
                feedback=["Too short"],
                warning="Too common",
                has_patterns=True
            )
            
            with patch('main.check_pwned') as mock_pwned:
                mock_pwned.return_value = 0
                
                result = check_single_password("weak", verbose=False)
                
                assert result is False
    
    def test_returns_false_for_breached_password(self):
        """Should return False for breached password."""
        with patch('main.evaluate_password_strength') as mock_eval:
            mock_eval.return_value = Mock(
                score=4,
                strength_label="Strong",
                entropy=80.0,
                crack_time_display="centuries",
                crack_time_seconds=1e20,
                feedback=[],
                warning=None,
                has_patterns=False
            )
            
            with patch('main.check_pwned') as mock_pwned:
                mock_pwned.return_value = 150
                
                result = check_single_password("breached", verbose=False)
                
                assert result is False
    
    def test_returns_false_for_unknown_breach_status(self):
        """Should return False when breach status unknown."""
        with patch('main.evaluate_password_strength') as mock_eval:
            mock_eval.return_value = Mock(
                score=4,
                strength_label="Strong",
                entropy=80.0,
                crack_time_display="centuries",
                crack_time_seconds=1e20,
                feedback=[],
                warning=None,
                has_patterns=False
            )
            
            with patch('main.check_pwned') as mock_pwned:
                mock_pwned.return_value = None
                
                result = check_single_password("unknown", verbose=False)
                
                assert result is False
    
    def test_verbose_output_calls_display_functions(self):
        """Verbose mode should call display functions."""
        with patch('main.evaluate_password_strength') as mock_eval:
            mock_eval.return_value = Mock(
                score=4,
                strength_label="Strong",
                entropy=80.0,
                crack_time_display="centuries",
                crack_time_seconds=1e20,
                feedback=[],
                warning=None,
                has_patterns=False
            )
            
            with patch('main.check_pwned') as mock_pwned:
                mock_pwned.return_value = 0
                
                with patch('main.display_strength_panel') as mock_display_strength:
                    with patch('main.display_breach_panel') as mock_display_breach:
                        with patch('main.display_final_status') as mock_display_final:
                            check_single_password("test", verbose=True)
                            
                            mock_display_strength.assert_called_once()
                            mock_display_breach.assert_called_once()
                            mock_display_final.assert_called_once()


class TestGeneratePasswordCli:
    """Tests for generate_password_cli function."""
    
    def test_generates_password(self):
        """Should generate and display password."""
        with patch('main.generate_secure_password') as mock_gen:
            mock_gen.return_value = "GeneratedP@ss123!"
            
            with patch('main.calculate_entropy') as mock_entropy:
                mock_entropy.return_value = 95.0
                
                with patch('main.get_password_strength_rating') as mock_rating:
                    mock_rating.return_value = "Very Strong"
                    
                    # Should not raise any exceptions
                    generate_password_cli(length=16, use_special=True, passphrase_mode=False)
    
    def test_generates_passphrase(self):
        """Should generate and display passphrase."""
        with patch('main.generate_passphrase') as mock_gen:
            mock_gen.return_value = "eagle-MOUNTAIN-umbrella-024"
            
            with patch('main.calculate_entropy') as mock_entropy:
                mock_entropy.return_value = 65.0
                
                # Should not raise any exceptions
                generate_password_cli(length=4, use_special=True, passphrase_mode=True)


class TestMain:
    """Tests for main function with argument parsing."""
    
    def test_interactive_mode_default(self):
        """Default should run interactive mode."""
        with patch('sys.argv', ['main.py']):
            with patch('main.interactive_mode') as mock_interactive:
                with patch('main.print_banner'):
                    main()
                    mock_interactive.assert_called_once()
    
    def test_password_check_mode(self):
        """-p flag should check specific password."""
        with patch('sys.argv', ['main.py', '-p', 'testpassword']):
            with patch('main.check_single_password') as mock_check:
                mock_check.return_value = True
                
                with pytest.raises(SystemExit) as exc_info:
                    main()
                
                mock_check.assert_called_once_with('testpassword', verbose=True)
                assert exc_info.value.code == 0
    
    def test_password_check_quiet_mode(self):
        """-q flag should use quiet mode."""
        with patch('sys.argv', ['main.py', '-p', 'testpassword', '-q']):
            with patch('main.check_single_password') as mock_check:
                mock_check.return_value = True
                
                with pytest.raises(SystemExit):
                    main()
                
                mock_check.assert_called_once_with('testpassword', verbose=False)
    
    def test_password_check_fails_exits_with_1(self):
        """Failed password check should exit with code 1."""
        with patch('sys.argv', ['main.py', '-p', 'weakpassword']):
            with patch('main.check_single_password') as mock_check:
                mock_check.return_value = False
                
                with pytest.raises(SystemExit) as exc_info:
                    main()
                
                assert exc_info.value.code == 1
    
    def test_generate_mode(self):
        """--generate flag should generate password."""
        with patch('sys.argv', ['main.py', '--generate']):
            with patch('main.generate_password_cli') as mock_gen:
                with patch('main.print_banner'):
                    main()
                    mock_gen.assert_called_once()
    
    def test_passphrase_mode(self):
        """--passphrase flag should generate passphrase."""
        with patch('sys.argv', ['main.py', '--passphrase']):
            with patch('main.generate_password_cli') as mock_gen:
                with patch('main.print_banner'):
                    main()
                    mock_gen.assert_called_once_with(
                        length=16,
                        use_special=True,
                        passphrase_mode=True
                    )
    
    def test_custom_length(self):
        """-l flag should set custom length."""
        with patch('sys.argv', ['main.py', '--generate', '-l', '20']):
            with patch('main.generate_password_cli') as mock_gen:
                with patch('main.print_banner'):
                    main()
                    mock_gen.assert_called_once_with(
                        length=20,
                        use_special=True,
                        passphrase_mode=False
                    )
    
    def test_no_special_flag(self):
        """--no-special flag should exclude special characters."""
        with patch('sys.argv', ['main.py', '--generate', '--no-special']):
            with patch('main.generate_password_cli') as mock_gen:
                with patch('main.print_banner'):
                    main()
                    mock_gen.assert_called_once_with(
                        length=16,
                        use_special=False,
                        passphrase_mode=False
                    )
    
    def test_keyboard_interrupt_handled(self):
        """KeyboardInterrupt should be handled gracefully."""
        with patch('sys.argv', ['main.py']):
            with patch('main.interactive_mode') as mock_interactive:
                mock_interactive.side_effect = KeyboardInterrupt()
                
                # Should not raise exception
                main()


class TestSecurityConsiderations:
    """Security-focused tests."""
    
    def test_password_not_in_error_messages(self):
        """Password should not appear in error messages."""
        # This is mostly ensured by design - we don't log passwords
        # But we verify the check_single_password doesn't leak it
        with patch('main.evaluate_password_strength') as mock_eval:
            mock_eval.side_effect = Exception("Error")
            
            with patch('main.console.print') as mock_print:
                try:
                    check_single_password("secretpassword123", verbose=False)
                except Exception:
                    pass
                
                # Check that print was not called with the password
                for call in mock_print.call_args_list:
                    args, _ = call
                    if args:
                        assert "secretpassword" not in str(args)