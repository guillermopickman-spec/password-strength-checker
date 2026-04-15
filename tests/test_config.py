"""
Tests for configuration module with YAML/TOML support and policy profiles.

Tests cover:
- Configuration loading from multiple sources
- Policy profile application
- YAML/TOML file parsing
- Configuration hierarchy (defaults → file → env → CLI)
- Validation of configuration values
- Backward compatibility with legacy Config usage
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from config import (
    Config,
    PolicyProfileDefinition,
    POLICY_PROFILES,
    LegacyConfigWrapper,
)


class TestPolicyProfiles:
    """Tests for policy profile definitions."""

    def test_default_profile_exists(self):
        """Default profile should always exist."""
        assert "default" in POLICY_PROFILES
        profile = POLICY_PROFILES["default"]
        assert profile.min_password_length == 12
        assert profile.default_password_length == 16

    def test_all_profiles_have_required_fields(self):
        """All profiles should have required configuration fields."""
        required_attrs = [
            "name", "description", "min_password_length",
            "default_password_length", "entropy_very_weak",
            "entropy_weak", "entropy_moderate", "entropy_strong",
        ]
        for name, profile in POLICY_PROFILES.items():
            for attr in required_attrs:
                assert hasattr(profile, attr), f"Profile {name} missing {attr}"
                assert getattr(profile, attr) is not None

    def test_profile_thresholds_increasing(self):
        """Entropy thresholds should be strictly increasing in all profiles."""
        for name, profile in POLICY_PROFILES.items():
            thresholds = [
                profile.entropy_very_weak,
                profile.entropy_weak,
                profile.entropy_moderate,
                profile.entropy_strong,
            ]
            assert all(thresholds[i] < thresholds[i+1] for i in range(len(thresholds)-1)), \
                f"Profile {name} has non-increasing thresholds"

    def test_profile_password_lengths_valid(self):
        """Password lengths should be positive and sensible."""
        for name, profile in POLICY_PROFILES.items():
            assert profile.min_password_length >= 1
            assert profile.default_password_length >= profile.min_password_length
            assert profile.max_concurrent >= 1

    def test_list_profiles(self):
        """Should return dictionary of profile names and descriptions."""
        profiles = Config.list_profiles()
        assert isinstance(profiles, dict)
        assert "default" in profiles
        assert "soc2-strict" in profiles
        assert all(isinstance(desc, str) for desc in profiles.values())


class TestConfigLoading:
    """Tests for configuration loading."""

    def test_load_default_config(self):
        """Should load with default settings."""
        config = Config.load()
        assert config.profile == "default"
        assert config.min_password_length == 12
        assert config.hibp_api_timeout == 5

    def test_load_with_profile(self):
        """Should apply policy profile settings."""
        config = Config.load(profile="soc2-strict")
        assert config.profile == "soc2-strict"
        # SOC 2 should have stricter requirements
        assert config.min_password_length == 14
        assert config.default_password_length == 18

    def test_load_invalid_profile_uses_default(self):
        """Invalid profile name should use default."""
        config = Config.load(profile="nonexistent")
        assert config.profile == "nonexistent"  # Profile name stored
        # But default settings applied
        assert config.min_password_length == 12

    def test_profile_from_environment(self):
        """Should read POLICY_PROFILE from environment."""
        with patch.dict(os.environ, {"POLICY_PROFILE": "enterprise"}):
            config = Config.load()
            assert config.profile == "enterprise"
            assert config.min_password_length == 16  # Enterprise setting

    def test_environment_variable_override(self):
        """Environment variables should override defaults."""
        with patch.dict(os.environ, {
            "MIN_PASSWORD_LENGTH": "20",
            "DEFAULT_PASSWORD_LENGTH": "20",
            "HIBP_API_TIMEOUT": "10",
        }):
            config = Config.load()
            assert config.min_password_length == 20
            assert config.hibp_api_timeout == 10

    def test_cli_overrides_highest_priority(self):
        """CLI overrides should have highest priority."""
        with patch.dict(os.environ, {"MIN_PASSWORD_LENGTH": "15", "DEFAULT_PASSWORD_LENGTH": "15"}):
            config = Config.load(cli_overrides={
                "password_policy": {"min_password_length": 25, "default_password_length": 25}
            })
            assert config.min_password_length == 25


class TestYAMLConfigLoading:
    """Tests for YAML configuration file loading."""

    def test_load_yaml_config_file(self, tmp_path):
        """Should load configuration from YAML file."""
        config_file = tmp_path / ".password-auditor.yaml"
        config_data = {
            "profile": "soc2-strict",
            "password_policy": {
                "min_password_length": 16,
            },
            "hibp": {
                "max_concurrent": 5,
            },
        }
        config_file.write_text(yaml.dump(config_data))

        with patch("pathlib.Path.cwd", return_value=tmp_path):
            config = Config.load()
            assert config.profile == "soc2-strict"
            assert config.min_password_length == 16
            assert config.hibp.max_concurrent == 5

    def test_yaml_override_profile(self):
        """YAML settings should override profile defaults."""
        config_file = tmp_path = Path(tempfile.mkdtemp())
        yaml_file = tmp_path / ".password-auditor.yaml"
        
        config_data = {
            "profile": "default",
            "password_policy": {
                "min_password_length": 20,  # Override default's 12
                "default_password_length": 20,  # Must also be >= min
            },
        }
        yaml_file.write_text(yaml.dump(config_data))

        with patch("pathlib.Path.cwd", return_value=tmp_path):
            config = Config.load()
            assert config.profile == "default"
            assert config.min_password_length == 20

    def test_explicit_config_path(self, tmp_path):
        """Should load from explicitly provided config path."""
        config_file = tmp_path / "custom-config.yaml"
        config_data = {"profile": "enterprise"}
        config_file.write_text(yaml.dump(config_data))

        config = Config.load(config_path=config_file)
        assert config.profile == "enterprise"


class TestTOMLConfigLoading:
    """Tests for TOML configuration file loading."""

    def test_load_toml_config_file(self, tmp_path):
        """Should load configuration from TOML file."""
        config_file = tmp_path / ".password-auditor.toml"
        toml_content = """
profile = "pci-dss"

[password_policy]
min_password_length = 13

[hibp]
max_concurrent = 8
"""
        config_file.write_text(toml_content)

        with patch("pathlib.Path.cwd", return_value=tmp_path):
            config = Config.load()
            assert config.profile == "pci-dss"
            assert config.min_password_length == 13
            assert config.hibp.max_concurrent == 8

    def test_pyproject_toml_loading(self, tmp_path):
        """Should load from pyproject.toml [tool.password-auditor] section."""
        pyproject = tmp_path / "pyproject.toml"
        toml_content = """
[tool.password-auditor]
profile = "nist-moderate"

[tool.password-auditor.password_policy]
min_password_length = 15
"""
        pyproject.write_text(toml_content)

        with patch("pathlib.Path.cwd", return_value=tmp_path):
            config = Config.load()
            assert config.profile == "nist-moderate"
            assert config.min_password_length == 15


class TestConfigValidation:
    """Tests for configuration validation."""

    def test_valid_config_passes_validation(self):
        """Valid configuration should have no errors."""
        config = Config.load()
        errors = config.validate()
        assert errors == []

    def test_invalid_password_length_fails(self):
        """Default password length must be >= min length."""
        with pytest.raises(ValueError):
            Config.load(cli_overrides={
                "password_policy": {
                    "min_password_length": 20,
                    "default_password_length": 10,  # Invalid: less than min
                }
            })

    def test_invalid_entropy_thresholds(self):
        """Entropy thresholds must be strictly increasing."""
        with pytest.raises(ValueError):
            Config.load(cli_overrides={
                "entropy_thresholds": {
                    "very_weak": 28,
                    "weak": 36,
                    "moderate": 60,
                    "strong": 50,  # Invalid: less than moderate
                }
            })

    def test_negative_values_rejected(self):
        """Negative values should be rejected by pydantic."""
        with pytest.raises(ValueError):
            Config.load(cli_overrides={
                "password_policy": {
                    "min_password_length": -5,
                }
            })


class TestConfigConvenienceProperties:
    """Tests for convenience properties."""

    def test_min_password_length_property(self):
        """Should access password policy min length."""
        config = Config.load(profile="enterprise")
        assert config.min_password_length == 16

    def test_hibp_timeout_property(self):
        """Should access HIBP timeout."""
        config = Config.load()
        assert config.hibp_api_timeout == 5

    def test_log_level_property(self):
        """Should access log level."""
        config = Config.load()
        assert config.log_level == "INFO"


class TestConfigExport:
    """Tests for configuration export."""

    def test_to_dict(self):
        """Should convert to dictionary."""
        config = Config.load()
        data = config.to_dict()
        assert isinstance(data, dict)
        assert "profile" in data
        assert "password_policy" in data

    def test_to_yaml(self):
        """Should export to YAML string."""
        config = Config.load()
        yaml_str = config.to_yaml()
        assert isinstance(yaml_str, str)
        assert "profile:" in yaml_str
        # Should be valid YAML
        parsed = yaml.safe_load(yaml_str)
        assert parsed["profile"] == "default"


class TestConfigHierarchy:
    """Tests for configuration hierarchy."""

    def test_defaults_applied(self):
        """Should start with built-in defaults."""
        config = Config.load()
        assert config.hibp.api_timeout == 5
        assert config.password_policy.min_password_length == 12

    def test_profile_overrides_defaults(self):
        """Profile should override defaults."""
        config = Config.load(profile="enterprise")
        # Enterprise has min_length=16 vs default=12
        assert config.min_password_length == 16

    def test_file_overrides_profile(self, tmp_path):
        """Config file should override profile."""
        config_file = tmp_path / ".password-auditor.yaml"
        config_file.write_text(yaml.dump({
            "profile": "enterprise",
            "password_policy": {
                "min_password_length": 25,  # Override enterprise's 16
                "default_password_length": 25,  # Must also be >= min
            },
        }))

        with patch("pathlib.Path.cwd", return_value=tmp_path):
            config = Config.load()
            assert config.profile == "enterprise"
            assert config.min_password_length == 25

    def test_env_overrides_file(self, tmp_path):
        """Environment should override file."""
        config_file = tmp_path / ".password-auditor.yaml"
        config_file.write_text(yaml.dump({
            "password_policy": {
                "min_password_length": 20,
                "default_password_length": 20,
            },
        }))

        with patch("pathlib.Path.cwd", return_value=tmp_path):
            with patch.dict(os.environ, {"MIN_PASSWORD_LENGTH": "30", "DEFAULT_PASSWORD_LENGTH": "30"}):
                config = Config.load()
                assert config.min_password_length == 30

    def test_cli_overrides_all(self, tmp_path):
        """CLI overrides should take highest priority."""
        config_file = tmp_path / ".password-auditor.yaml"
        config_file.write_text(yaml.dump({
            "password_policy": {
                "min_password_length": 20,
                "default_password_length": 20,
            },
        }))

        with patch("pathlib.Path.cwd", return_value=tmp_path):
            with patch.dict(os.environ, {"MIN_PASSWORD_LENGTH": "25", "DEFAULT_PASSWORD_LENGTH": "25"}):
                config = Config.load(cli_overrides={
                    "password_policy": {"min_password_length": 30, "default_password_length": 30}
                })
                assert config.min_password_length == 30


class TestLegacyCompatibility:
    """Tests for backward compatibility with old Config usage."""

    def test_legacy_config_singleton_exists(self):
        """Legacy Config singleton should be importable."""
        from config import ConfigSingleton
        assert ConfigSingleton is not None

    def test_legacy_attribute_access(self):
        """Old Config.HIBP_API_TIMEOUT style access should work."""
        from config import ConfigSingleton
        timeout = ConfigSingleton.HIBP_API_TIMEOUT
        assert isinstance(timeout, int)
        assert timeout == 5

    def test_legacy_min_password_length(self):
        """Old Config.MIN_PASSWORD_LENGTH access should work."""
        from config import ConfigSingleton
        min_len = ConfigSingleton.MIN_PASSWORD_LENGTH
        assert isinstance(min_len, int)

    def test_legacy_get_entropy_thresholds(self):
        """Old Config.get_entropy_thresholds() should work."""
        from config import ConfigSingleton
        thresholds = ConfigSingleton.get_entropy_thresholds()
        assert isinstance(thresholds, list)
        assert len(thresholds) == 5

    def test_legacy_validate(self):
        """Old Config.validate() should work."""
        from config import ConfigSingleton
        errors = ConfigSingleton.validate()
        assert isinstance(errors, list)

    def test_direct_module_attribute_access(self):
        """Direct from config import HIBP_API_TIMEOUT should work."""
        # This uses __getattr__ at module level
        import config
        timeout = config.HIBP_API_TIMEOUT
        assert isinstance(timeout, int)


class TestConfigDeepMerge:
    """Tests for deep merge functionality."""

    def test_deep_merge_nested_dicts(self):
        """Should recursively merge nested dictionaries."""
        base = {
            "password_policy": {
                "min_password_length": 12,
                "require_uppercase": True,
            },
            "hibp": {
                "api_timeout": 5,
            },
        }
        override = {
            "password_policy": {
                "min_password_length": 20,  # Override
                "require_special": True,  # Add new
            },
        }
        result = Config._deep_merge(base, override)
        assert result["password_policy"]["min_password_length"] == 20
        assert result["password_policy"]["require_uppercase"] is True  # Preserved
        assert result["password_policy"]["require_special"] is True  # Added
        assert result["hibp"]["api_timeout"] == 5  # Preserved

    def test_deep_merge_non_dict_values(self):
        """Non-dict values should be replaced, not merged."""
        base = {"profile": "default", "timeout": 5}
        override = {"profile": "enterprise"}
        result = Config._deep_merge(base, override)
        assert result["profile"] == "enterprise"
        assert result["timeout"] == 5  # Preserved


class TestEntropyThresholds:
    """Tests for entropy threshold configuration."""

    def test_get_entropy_thresholds(self):
        """Should return ordered list of thresholds."""
        config = Config.load()
        thresholds = config.get_entropy_thresholds()
        assert len(thresholds) == 5
        # Check structure: (threshold_value, label)
        assert all(isinstance(t, tuple) and len(t) == 2 for t in thresholds)
        assert thresholds[0][1] == "Very Weak"
        assert thresholds[-1][1] == "Very Strong"
        assert thresholds[-1][0] == float('inf')

    def test_profile_affects_thresholds(self):
        """Different profiles should have different thresholds."""
        default_config = Config.load(profile="default")
        enterprise_config = Config.load(profile="enterprise")
        
        default_thresholds = default_config.get_entropy_thresholds()
        enterprise_thresholds = enterprise_config.get_entropy_thresholds()
        
        # Enterprise should have higher thresholds
        assert enterprise_thresholds[0][0] > default_thresholds[0][0]


class TestSecurityConfig:
    """Tests for security-related configuration."""

    def test_secure_memory_wipe_default(self):
        """Secure memory wipe should be enabled by default."""
        config = Config.load()
        assert config.security.secure_memory_wipe is True

    def test_secure_memory_wipe_from_env(self):
        """Should read SECURE_MEMORY_WIPE from environment."""
        with patch.dict(os.environ, {"SECURE_MEMORY_WIPE": "false"}):
            config = Config.load()
            assert config.security.secure_memory_wipe is False

    def test_password_history_default(self):
        """Password history should be enabled by default."""
        config = Config.load()
        assert config.security.disable_password_history is False


class TestLoggingConfig:
    """Tests for logging configuration."""

    def test_default_log_level(self):
        """Default log level should be INFO."""
        config = Config.load()
        assert config.logging.level == "INFO"

    def test_log_level_from_env(self):
        """Should read LOG_LEVEL from environment."""
        with patch.dict(os.environ, {"LOG_LEVEL": "DEBUG"}):
            config = Config.load()
            assert config.logging.level == "DEBUG"

    def test_log_format_validation(self):
        """Should validate log format."""
        # Valid formats should work
        config = Config.load(cli_overrides={"logging": {"format": "json"}})
        assert config.logging.format == "json"
        
        config = Config.load(cli_overrides={"logging": {"format": "simple"}})
        assert config.logging.format == "simple"
        
        # Invalid format should raise error
        with pytest.raises(ValueError):
            Config.load(cli_overrides={"logging": {"format": "invalid"}})


class TestHIBPConfig:
    """Tests for HIBP API configuration."""

    def test_default_timeout(self):
        """Default timeout should be 5 seconds."""
        config = Config.load()
        assert config.hibp.api_timeout == 5

    def test_default_concurrency(self):
        """Default max concurrent should be 10."""
        config = Config.load()
        assert config.hibp.max_concurrent == 10

    def test_profile_affects_concurrency(self):
        """Different profiles may have different concurrency limits."""
        default_config = Config.load(profile="default")
        soc2_config = Config.load(profile="soc2-strict")
        
        assert default_config.hibp.max_concurrent == 10
        assert soc2_config.hibp.max_concurrent == 5  # SOC 2 is more conservative

    def test_timeout_bounds(self):
        """Timeout should have reasonable bounds."""
        with pytest.raises(ValueError):
            Config.load(cli_overrides={"hibp": {"api_timeout": 0}})
        
        with pytest.raises(ValueError):
            Config.load(cli_overrides={"hibp": {"api_timeout": 100}})


class TestCharacterSetConfig:
    """Tests for character set configuration."""

    def test_default_special_chars(self):
        """Default special characters should be defined."""
        config = Config.load()
        assert config.character_sets.special_chars == "!@#$%^&*"

    def test_default_ambiguous_chars(self):
        """Default ambiguous characters should be defined."""
        config = Config.load()
        assert config.character_sets.ambiguous_chars == "0O1lI"

    def test_custom_special_chars_from_env(self):
        """Should accept custom special characters from environment."""
        with patch.dict(os.environ, {"SPECIAL_CHARS": "@#$%^&+="}):
            config = Config.load()
            assert config.character_sets.special_chars == "@#$%^&+="


class TestApplicationConfig:
    """Tests for application behavior configuration."""

    def test_quiet_mode_default(self):
        """Quiet mode should be disabled by default."""
        config = Config.load()
        assert config.application.quiet_mode is False

    def test_quiet_mode_from_env(self):
        """Should read QUIET_MODE from environment."""
        with patch.dict(os.environ, {"QUIET_MODE": "true"}):
            config = Config.load()
            assert config.application.quiet_mode is True

    def test_progress_bars_default(self):
        """Progress bars should be enabled by default."""
        config = Config.load()
        assert config.application.progress_bars is True

    def test_no_color_default(self):
        """Colors should be enabled by default."""
        config = Config.load()
        assert config.application.no_color is False


class TestConfigFileSearchPaths:
    """Tests for configuration file search order."""

    def test_explicit_path_takes_priority(self, tmp_path):
        """Explicitly provided path should be used first."""
        explicit_config = tmp_path / "explicit.yaml"
        cwd_config = tmp_path / ".password-auditor.yaml"
        
        explicit_config.write_text(yaml.dump({"profile": "from-explicit"}))
        cwd_config.write_text(yaml.dump({"profile": "from-cwd"}))
        
        config = Config.load(config_path=explicit_config)
        assert config.profile == "from-explicit"

    def test_cwd_yaml_preferred_over_toml(self, tmp_path):
        """YAML in cwd should be preferred over TOML."""
        yaml_config = tmp_path / ".password-auditor.yaml"
        toml_config = tmp_path / ".password-auditor.toml"
        
        yaml_config.write_text(yaml.dump({"profile": "from-yaml"}))
        toml_config.write_text('profile = "from-toml"')
        
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            config = Config.load()
            assert config.profile == "from-yaml"

    def test_toml_used_when_no_yaml(self, tmp_path):
        """TOML should be used when no YAML exists."""
        toml_config = tmp_path / ".password-auditor.toml"
        toml_config.write_text('profile = "from-toml"')
        
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            config = Config.load()
            assert config.profile == "from-toml"


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_config_file(self, tmp_path):
        """Empty config file should not cause errors."""
        config_file = tmp_path / ".password-auditor.yaml"
        config_file.write_text("")
        
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            config = Config.load()
            assert config.profile == "default"  # Uses defaults

    def test_invalid_yaml_handled_gracefully(self, tmp_path):
        """Invalid YAML should not crash, just use defaults."""
        config_file = tmp_path / ".password-auditor.yaml"
        config_file.write_text("invalid: yaml: content: [")
        
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            # Should not raise exception
            config = Config.load()
            # Should use defaults
            assert config.profile == "default"

    def test_missing_config_file_uses_defaults(self):
        """Missing config file should use defaults."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            with patch("pathlib.Path.cwd", return_value=tmp_path):
                config = Config.load()
                assert config.profile == "default"

    def test_boolean_env_var_variations(self):
        """Should handle various boolean string representations."""
        for value in ["true", "True", "1", "yes", "on"]:
            with patch.dict(os.environ, {"SECURE_MEMORY_WIPE": value}):
                config = Config.load()
                assert config.security.secure_memory_wipe is True, f"Failed for {value}"
        
        for value in ["false", "False", "0", "no", "off"]:
            with patch.dict(os.environ, {"SECURE_MEMORY_WIPE": value}):
                config = Config.load()
                assert config.security.secure_memory_wipe is False, f"Failed for {value}"