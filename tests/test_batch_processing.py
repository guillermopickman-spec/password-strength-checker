"""
Test suite for batch password processing functionality.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, mock_open, MagicMock, AsyncMock

from main import (
    batch_check_passwords,
    display_batch_results,
    export_results
)


class TestBatchCheckPasswords:
    """Tests for batch_check_passwords function."""

    @patch("main.check_pwned_batch")
    @patch("main.evaluate_password_strength")
    def test_batch_processes_all_passwords(
        self, mock_evaluate, mock_check_pwned_batch, tmp_path
    ):
        """Test that all passwords in file are processed."""
        # Create test file
        test_file = tmp_path / "passwords.txt"
        test_file.write_text("Password1!\nPassword2!\nPassword3!\n")

        # Mock strength results
        mock_evaluate.side_effect = [
            MagicMock(
                score=3,
                strength_label="Good",
                entropy=45.5,
                crack_time_display="2 years",
                warning=None,
                feedback=[]
            ),
            MagicMock(
                score=2,
                strength_label="Fair",
                entropy=30.0,
                crack_time_display="1 month",
                warning=None,
                feedback=[]
            ),
            MagicMock(
                score=4,
                strength_label="Strong",
                entropy=60.0,
                crack_time_display="100 years",
                warning=None,
                feedback=[]
            ),
        ]

        # Mock breach checks (none breached) - async batch function returns list of tuples
        mock_check_pwned_batch.return_value = [
            ("Password1!", 0),
            ("Password2!", 0),
            ("Password3!", 0)
        ]

        results = batch_check_passwords(test_file, verbose=False)

        assert len(results) == 3
        assert results[0]["password"] == "Password1!"
        assert results[1]["password"] == "Password2!"
        assert results[2]["password"] == "Password3!"

    @patch("main.check_pwned_batch")
    @patch("main.evaluate_password_strength")
    @patch("main.console")
    def test_file_not_found_prints_error(
        self, mock_console, mock_evaluate, mock_check_pwned_batch, tmp_path
    ):
        """Test that non-existent file exits with error."""
        non_existent = tmp_path / "does_not_exist.txt"

        with pytest.raises(SystemExit) as exc_info:
            batch_check_passwords(non_existent, verbose=False)

        assert exc_info.value.code == 1

    @patch("main.check_pwned_batch")
    @patch("main.evaluate_password_strength")
    def test_empty_file_returns_empty_list(
        self, mock_evaluate, mock_check_pwned_batch, tmp_path
    ):
        """Test that empty file returns empty results."""
        test_file = tmp_path / "empty.txt"
        test_file.write_text("\n\n\n")  # Only empty lines

        results = batch_check_passwords(test_file, verbose=False)

        assert results == []

    @patch("main.check_pwned_batch")
    @patch("main.evaluate_password_strength")
    def test_breached_passwords_detected(
        self, mock_evaluate, mock_check_pwned_batch, tmp_path
    ):
        """Test that breached passwords are correctly flagged."""
        test_file = tmp_path / "passwords.txt"
        test_file.write_text("breached_pass\n")

        mock_evaluate.return_value = MagicMock(
            score=3,
            strength_label="Good",
            entropy=45.5,
            crack_time_display="2 years",
            warning=None,
            feedback=[]
        )

        # This password is breached - async batch returns list of tuples
        mock_check_pwned_batch.return_value = [("breached_pass", 500)]

        results = batch_check_passwords(test_file, verbose=False)

        assert results[0]["breach_count"] == 500
        assert results[0]["is_safe"] is False
        assert results[0]["is_secure"] is False

    @patch("main.check_pwned_batch")
    @patch("main.evaluate_password_strength")
    def test_weak_passwords_flagged(
        self, mock_evaluate, mock_check_pwned_batch, tmp_path
    ):
        """Test that weak passwords are correctly flagged."""
        test_file = tmp_path / "passwords.txt"
        test_file.write_text("weak\n")

        mock_evaluate.return_value = MagicMock(
            score=1,
            strength_label="Weak",
            entropy=10.0,
            crack_time_display="instant",
            warning="Too short",
            feedback=["Add more characters"]
        )

        mock_check_pwned_batch.return_value = [("weak", 0)]

        results = batch_check_passwords(test_file, verbose=False)

        assert results[0]["is_strong"] is False
        assert results[0]["is_secure"] is False
        assert results[0]["strength_score"] == 1

    @patch("main.check_pwned_batch")
    @patch("main.evaluate_password_strength")
    @patch("main.export_results")
    def test_export_called_when_path_provided(
        self, mock_export, mock_evaluate, mock_check_pwned_batch, tmp_path
    ):
        """Test that export is called when export_path is provided."""
        test_file = tmp_path / "passwords.txt"
        test_file.write_text("Password1!\n")

        mock_evaluate.return_value = MagicMock(
            score=3,
            strength_label="Good",
            entropy=45.5,
            crack_time_display="2 years",
            warning=None,
            feedback=[]
        )
        mock_check_pwned_batch.return_value = [("Password1!", 0)]

        export_path = tmp_path / "results.json"
        batch_check_passwords(
            test_file,
            verbose=False,
            export_path=export_path,
            export_format="json"
        )

        mock_export.assert_called_once()


class TestExportResults:
    """Tests for export_results function."""

    def test_export_json_creates_file(self, tmp_path):
        """Test JSON export creates valid file."""
        export_path = tmp_path / "results.json"
        
        results = [
            {
                "password": "test123",
                "strength_score": 3,
                "strength_label": "Good",
                "entropy": 45.5,
                "crack_time": "2 years",
                "breach_count": 0,
                "is_strong": True,
                "is_safe": True,
                "is_secure": True,
                "feedback": []
            }
        ]

        export_results(results, export_path, "json")

        assert export_path.exists()
        
        with open(export_path) as f:
            data = json.load(f)
        
        assert data["summary"]["total_checked"] == 1
        assert data["summary"]["secure_count"] == 1
        assert data["results"][0]["password_length"] == 7
        # Password should NOT be in export (security)
        assert "password" not in data["results"][0]

    def test_export_csv_creates_file(self, tmp_path):
        """Test CSV export creates valid file."""
        export_path = tmp_path / "results.csv"
        
        results = [
            {
                "password": "test123",
                "strength_score": 3,
                "strength_label": "Good",
                "entropy": 45.5,
                "crack_time": "2 years",
                "breach_count": 0,
                "is_strong": True,
                "is_safe": True,
                "is_secure": True,
                "feedback": []
            }
        ]

        export_results(results, export_path, "csv")

        assert export_path.exists()
        
        content = export_path.read_text()
        assert "ID,Password Length,Strength Score" in content
        assert "3,Good,45.5" in content

    def test_export_unknown_format_shows_warning(self, capsys):
        """Test unknown format shows warning."""
        with patch("main.console") as mock_console:
            export_results([], Path("test.xyz"), "xml")
            mock_console.print.assert_any_call(
                "[yellow]⚠️  Unknown export format: xml[/]"
            )

    @patch("main.console")
    def test_export_handles_errors_gracefully(self, mock_console, tmp_path):
        """Test export handles file write errors."""
        # Create invalid export data that will cause KeyError
        invalid_result = {"invalid": "data"}  # Missing required keys
        
        export_path = tmp_path / "results.json"
        export_results([invalid_result], export_path, "json")
        
        # Verify error was printed
        assert mock_console.print.called
        error_call = str(mock_console.print.call_args)
        assert "Error exporting results" in error_call


class TestDisplayBatchResults:
    """Tests for display_batch_results function."""

    @patch("main.console")
    def test_summary_panel_created(self, mock_console):
        """Test that summary panel is displayed."""
        results = [
            {
                "password": "SecurePass123!",
                "is_secure": True,
                "is_strong": True,
                "is_safe": True,
                "breach_count": 0,
                "strength_score": 4,
                "strength_label": "Strong"
            },
            {
                "password": "weakpass",
                "is_secure": False,
                "is_strong": False,
                "is_safe": True,
                "breach_count": 0,
                "strength_score": 1,
                "strength_label": "Weak"
            },
            {
                "password": "breached",
                "is_secure": False,
                "is_strong": True,
                "is_safe": False,
                "breach_count": 100,
                "strength_score": 3,
                "strength_label": "Good"
            },
        ]
        
        display_batch_results(results)
        
        # Check that print was called (panels are printed)
        assert mock_console.print.call_count > 0

    @patch("main.console")
    def test_insecure_passwords_shown_in_recommendations(self, mock_console):
        """Test that insecure passwords are listed in recommendations."""
        results = [
            {
                "password": "weakpass",
                "is_secure": False,
                "is_strong": False,
                "is_safe": True,
                "strength_label": "Weak",
                "breach_count": 0,
                "strength_score": 1
            }
        ]
        
        display_batch_results(results)
        
        # Verify recommendations section is printed
        calls = [str(call) for call in mock_console.print.call_args_list]
        assert any("Recommendations" in str(call) for call in calls)


class TestBatchIntegration:
    """Integration tests for batch processing."""

    @patch("main.check_pwned_batch")
    @patch("main.evaluate_password_strength")
    def test_full_batch_workflow(
        self, mock_evaluate, mock_check_pwned_batch, tmp_path
    ):
        """Test complete batch workflow with mixed results."""
        # Create test file with various passwords
        test_file = tmp_path / "mixed_passwords.txt"
        test_file.write_text(
            "SecurePass123!\n"  # Strong, not breached
            "password123\n"      # Weak, not breached
            "breached_pass\n"    # Strong, breached
        )

        # Configure mocks for different passwords
        def mock_evaluate_side_effect(pwd):
            if pwd == "SecurePass123!":
                return MagicMock(
                    score=4, strength_label="Strong", entropy=60.0,
                    crack_time_display="centuries", warning=None, feedback=[]
                )
            elif pwd == "password123":
                return MagicMock(
                    score=1, strength_label="Weak", entropy=15.0,
                    crack_time_display="instant", warning="Too common", feedback=[]
                )
            else:
                return MagicMock(
                    score=3, strength_label="Good", entropy=45.0,
                    crack_time_display="2 years", warning=None, feedback=[]
                )

        # Async batch function returns list of tuples
        mock_check_pwned_batch.return_value = [
            ("SecurePass123!", 0),
            ("password123", 0),
            ("breached_pass", 1000)
        ]

        mock_evaluate.side_effect = mock_evaluate_side_effect

        # Run batch check
        results = batch_check_passwords(test_file, verbose=False)

        # Verify results
        assert len(results) == 3
        
        # First password: Secure
        assert results[0]["is_secure"] is True
        assert results[0]["strength_score"] == 4
        
        # Second password: Weak
        assert results[1]["is_secure"] is False
        assert results[1]["strength_score"] == 1
        
        # Third password: Breached
        assert results[2]["is_secure"] is False
        assert results[2]["breach_count"] == 1000
