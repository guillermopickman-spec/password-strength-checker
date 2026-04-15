"""
Configuration Module for Password Strength Auditor

Supports multiple configuration sources with hierarchical loading:
1. Built-in defaults
2. YAML/TOML configuration files
3. Environment variables (.env file and system env)
4. CLI arguments (highest priority)

Includes policy profiles for compliance frameworks (SOC2, NIST, PCI-DSS).

Usage:
    from config import Config, PolicyProfile
    
    config = Config.load()
    timeout = config.hibp_api_timeout
    min_length = config.min_password_length
"""

import os
import sys
import warnings
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field

from dotenv import load_dotenv

# Handle TOML imports for different Python versions
if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib

import yaml
from pydantic import BaseModel, Field, field_validator


# =============================================================================
# Policy Profiles
# =============================================================================

@dataclass
class PolicyProfileDefinition:
    """Definition of a policy profile with security settings."""
    name: str
    description: str
    min_password_length: int
    default_password_length: int
    entropy_very_weak: int
    entropy_weak: int
    entropy_moderate: int
    entropy_strong: int
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special: bool = True
    max_concurrent: int = 10


# Predefined policy profiles for compliance frameworks
POLICY_PROFILES = {
    "default": PolicyProfileDefinition(
        name="default",
        description="General purpose password policy (balanced security/usability)",
        min_password_length=12,
        default_password_length=16,
        entropy_very_weak=28,
        entropy_weak=36,
        entropy_moderate=60,
        entropy_strong=80,
    ),
    "developer": PolicyProfileDefinition(
        name="developer",
        description="Relaxed policy for development environments",
        min_password_length=10,
        default_password_length=12,
        entropy_very_weak=24,
        entropy_weak=32,
        entropy_moderate=48,
        entropy_strong=64,
        require_special=False,
    ),
    "soc2-strict": PolicyProfileDefinition(
        name="soc2-strict",
        description="SOC 2 Type II compliance - strict security requirements",
        min_password_length=14,
        default_password_length=18,
        entropy_very_weak=40,
        entropy_weak=56,
        entropy_moderate=80,
        entropy_strong=100,
        max_concurrent=5,  # Conservative API usage
    ),
    "nist-moderate": PolicyProfileDefinition(
        name="nist-moderate",
        description="NIST SP 800-63B moderate assurance level",
        min_password_length=12,
        default_password_length=16,
        entropy_very_weak=30,
        entropy_weak=40,
        entropy_moderate=64,
        entropy_strong=80,
    ),
    "pci-dss": PolicyProfileDefinition(
        name="pci-dss",
        description="PCI DSS compliance for payment card industry",
        min_password_length=12,
        default_password_length=16,
        entropy_very_weak=32,
        entropy_weak=48,
        entropy_moderate=72,
        entropy_strong=96,
    ),
    "enterprise": PolicyProfileDefinition(
        name="enterprise",
        description="Maximum security for high-security organizations",
        min_password_length=16,
        default_password_length=20,
        entropy_very_weak=48,
        entropy_weak=64,
        entropy_moderate=96,
        entropy_strong=128,
        max_concurrent=8,
    ),
}


# =============================================================================
# Configuration Schema
# =============================================================================

class PasswordPolicyConfig(BaseModel):
    """Password policy configuration section."""
    min_password_length: int = Field(default=12, ge=1, le=128)
    default_password_length: int = Field(default=16, ge=1, le=128)
    default_passphrase_words: int = Field(default=4, ge=2, le=20)
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special: bool = True
    
    @field_validator('default_password_length')
    def default_ge_min(cls, v, info):
        values = info.data
        if 'min_password_length' in values and v < values['min_password_length']:
            raise ValueError(
                f"default_password_length ({v}) must be >= "
                f"min_password_length ({values['min_password_length']})"
            )
        return v


class EntropyThresholdsConfig(BaseModel):
    """Entropy threshold configuration."""
    very_weak: int = Field(default=28, ge=0)
    weak: int = Field(default=36, ge=0)
    moderate: int = Field(default=60, ge=0)
    strong: int = Field(default=80, ge=0)
    
    @field_validator('weak', 'moderate', 'strong')
    def thresholds_increasing(cls, v, info):
        field_order = ['very_weak', 'weak', 'moderate', 'strong']
        field_idx = field_order.index(info.field_name)
        values = info.data
        if field_idx > 0:
            prev_field = field_order[field_idx - 1]
            if prev_field in values and v <= values[prev_field]:
                raise ValueError(f'{info.field_name} must be greater than {prev_field}')
        return v


class HIBPConfig(BaseModel):
    """HaveIBeenPwned API configuration."""
    api_timeout: int = Field(default=5, ge=1, le=60)
    retry_attempts: int = Field(default=3, ge=0, le=10)
    user_agent: str = "PasswordStrengthChecker-Project"
    base_url: str = "https://api.pwnedpasswords.com"
    max_concurrent: int = Field(default=10, ge=1, le=100)
    call_delay: float = Field(default=0.1, ge=0.0, le=5.0)


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = Field(default="INFO", pattern="^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    format: str = Field(default="simple", pattern="^(simple|json)$")
    file: Optional[str] = None  # Log file path (None = stdout)
    rotation: Optional[str] = None  # Log rotation (daily, weekly, etc.)


class CharacterSetConfig(BaseModel):
    """Character set configuration."""
    special_chars: str = "!@#$%^&*"
    ambiguous_chars: str = "0O1lI"


class SecurityConfig(BaseModel):
    """Security-related configuration."""
    secure_memory_wipe: bool = True
    disable_password_history: bool = False  # For compliance in some environments


class ApplicationConfig(BaseModel):
    """Application behavior configuration."""
    quiet_mode: bool = False
    no_color: bool = False  # Disable colored output
    progress_bars: bool = True


class Config(BaseModel):
    """
    Main configuration class with support for hierarchical loading.
    
    Configuration hierarchy (lowest to highest priority):
    1. Built-in defaults
    2. Policy profile base settings
    3. YAML/TOML configuration file
    4. Environment variables
    5. CLI arguments (passed programmatically)
    """
    
    # Configuration metadata
    profile: str = Field(default="default", description="Policy profile name")
    config_file: Optional[str] = Field(default=None, description="Loaded config file path")
    
    # Configuration sections
    password_policy: PasswordPolicyConfig = Field(default_factory=PasswordPolicyConfig)
    entropy_thresholds: EntropyThresholdsConfig = Field(default_factory=EntropyThresholdsConfig)
    hibp: HIBPConfig = Field(default_factory=HIBPConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    character_sets: CharacterSetConfig = Field(default_factory=CharacterSetConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    application: ApplicationConfig = Field(default_factory=ApplicationConfig)
    
    # Additional custom settings
    custom: Dict[str, Any] = Field(default_factory=dict)
    
    def model_post_init(self, __context):
        """Validate configuration after initialization."""
        # Validate password lengths
        if (self.password_policy.default_password_length < 
            self.password_policy.min_password_length):
            raise ValueError(
                f"default_password_length ({self.password_policy.default_password_length}) "
                f"must be >= min_password_length ({self.password_policy.min_password_length})"
            )
    
    # =========================================================================
    # Class Methods for Loading Configuration
    # =========================================================================
    
    @classmethod
    def load(
        cls,
        profile: Optional[str] = None,
        config_path: Optional[Union[str, Path]] = None,
        env_file: Optional[str] = ".env",
        cli_overrides: Optional[Dict[str, Any]] = None
    ) -> "Config":
        """
        Load configuration from all sources with proper hierarchy.
        
        Args:
            profile: Policy profile name (default: "default")
            config_path: Explicit path to config file
            env_file: Path to .env file
            cli_overrides: Dictionary of CLI argument overrides
            
        Returns:
            Config instance with merged settings
        """
        # Start with defaults
        config_data: Dict[str, Any] = {}
        
        # 1. Apply policy profile if specified
        profile_name = profile or os.getenv("POLICY_PROFILE", "default")
        if profile_name in POLICY_PROFILES:
            profile_def = POLICY_PROFILES[profile_name]
            config_data = cls._apply_profile(config_data, profile_def)
        config_data["profile"] = profile_name
        
        # 2. Load from configuration file (YAML or TOML)
        file_config, loaded_path = cls._load_config_file(config_path)
        if file_config:
            config_data = cls._deep_merge(config_data, file_config)
            config_data["config_file"] = str(loaded_path) if loaded_path else None
        
        # 3. Load from environment variables
        env_config = cls._load_from_env()
        config_data = cls._deep_merge(config_data, env_config)
        
        # 4. Apply CLI overrides
        if cli_overrides:
            config_data = cls._deep_merge(config_data, cli_overrides)
        
        # Create and validate config
        try:
            return cls(**config_data)
        except Exception as e:
            raise ValueError(f"Configuration validation failed: {e}") from e
    
    @classmethod
    def _apply_profile(
        cls,
        config: Dict[str, Any],
        profile: PolicyProfileDefinition
    ) -> Dict[str, Any]:
        """Apply policy profile settings to configuration."""
        config["password_policy"] = {
            "min_password_length": profile.min_password_length,
            "default_password_length": profile.default_password_length,
            "default_passphrase_words": 4,
            "require_uppercase": profile.require_uppercase,
            "require_lowercase": profile.require_lowercase,
            "require_digits": profile.require_digits,
            "require_special": profile.require_special,
        }
        config["entropy_thresholds"] = {
            "very_weak": profile.entropy_very_weak,
            "weak": profile.entropy_weak,
            "moderate": profile.entropy_moderate,
            "strong": profile.entropy_strong,
        }
        config["hibp"] = {
            "max_concurrent": profile.max_concurrent,
        }
        return config
    
    @classmethod
    def _load_config_file(
        cls,
        explicit_path: Optional[Union[str, Path]] = None
    ) -> tuple[Optional[Dict[str, Any]], Optional[Path]]:
        """
        Load configuration from YAML or TOML file.
        
        Searches for config files in order:
        1. Explicitly provided path
        2. ./.password-auditor.yaml
        3. ./.password-auditor.toml
        4. ./pyproject.toml [tool.password-auditor]
        5. ~/.config/password-auditor/config.yaml
        6. ~/.config/password-auditor/config.toml
        
        Returns:
            Tuple of (config_dict, loaded_file_path)
        """
        search_paths = []
        
        if explicit_path:
            search_paths.append(Path(explicit_path))
        else:
            # Current directory - use Path.cwd() to allow test mocking
            cwd = Path.cwd()
            search_paths.extend([
                cwd / ".password-auditor.yaml",
                cwd / ".password-auditor.yml",
                cwd / ".password-auditor.toml",
            ])
            
            # pyproject.toml
            pyproject = cwd / "pyproject.toml"
            if pyproject.exists():
                search_paths.append(pyproject)
            
            # User config directory
            user_config_dir = Path.home() / ".config" / "password-auditor"
            search_paths.extend([
                user_config_dir / "config.yaml",
                user_config_dir / "config.yml",
                user_config_dir / "config.toml",
            ])
            
            # System-wide config (Unix-like)
            system_config = Path("/etc/password-auditor/config.yaml")
            if system_config.exists():
                search_paths.append(system_config)
        
        for config_path in search_paths:
            if not config_path.exists():
                continue
            
            try:
                with open(config_path, "rb" if config_path.suffix == ".toml" else "r") as f:
                    if config_path.suffix in [".yaml", ".yml"]:
                        content = yaml.safe_load(f)
                    elif config_path.suffix == ".toml" or config_path.name == "pyproject.toml":
                        if config_path.name == "pyproject.toml":
                            toml_content = tomllib.load(f)
                            content = toml_content.get("tool", {}).get("password-auditor", {})
                        else:
                            content = tomllib.load(f)
                    else:
                        continue
                    
                    if content:
                        return content, config_path
            
            except Exception as e:
                warnings.warn(f"Failed to load config from {config_path}: {e}", UserWarning)
                continue
        
        return None, None
    
    @classmethod
    def _load_from_env(cls) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        # Load .env file if present
        env_path = Path(__file__).parent / ".env"
        load_dotenv(dotenv_path=env_path, override=True)
        
        config: Dict[str, Any] = {}
        
        # Policy profile
        policy_profile = os.getenv("POLICY_PROFILE")
        if policy_profile:
            config["profile"] = policy_profile
        
        # Password policy
        password_policy = {}
        min_pwd_len = os.getenv("MIN_PASSWORD_LENGTH")
        if min_pwd_len:
            password_policy["min_password_length"] = int(min_pwd_len)
        default_pwd_len = os.getenv("DEFAULT_PASSWORD_LENGTH")
        if default_pwd_len:
            password_policy["default_password_length"] = int(default_pwd_len)
        passphrase_words = os.getenv("DEFAULT_PASSPHRASE_WORDS")
        if passphrase_words:
            password_policy["default_passphrase_words"] = int(passphrase_words)
        if password_policy:
            config["password_policy"] = password_policy
        
        # Entropy thresholds
        entropy = {}
        for key in ["VERY_WEAK", "WEAK", "MODERATE", "STRONG"]:
            env_key = f"ENTROPY_{key}"
            env_value = os.getenv(env_key)
            if env_value:
                entropy[key.lower()] = int(env_value)
        if entropy:
            config["entropy_thresholds"] = entropy
        
        # HIBP API
        hibp = {}
        api_timeout = os.getenv("HIBP_API_TIMEOUT")
        if api_timeout:
            hibp["api_timeout"] = int(api_timeout)
        retry_attempts = os.getenv("HIBP_RETRY_ATTEMPTS")
        if retry_attempts:
            hibp["retry_attempts"] = int(retry_attempts)
        user_agent = os.getenv("HIBP_USER_AGENT")
        if user_agent:
            hibp["user_agent"] = user_agent
        base_url = os.getenv("HIBP_API_BASE_URL")
        if base_url:
            hibp["base_url"] = base_url
        max_concurrent = os.getenv("DEFAULT_MAX_CONCURRENT")
        if max_concurrent:
            hibp["max_concurrent"] = int(max_concurrent)
        call_delay = os.getenv("API_CALL_DELAY")
        if call_delay:
            hibp["call_delay"] = float(call_delay)
        if hibp:
            config["hibp"] = hibp
        
        # Logging
        logging_config = {}
        log_level = os.getenv("LOG_LEVEL")
        if log_level:
            logging_config["level"] = log_level
        log_format = os.getenv("LOG_FORMAT")
        if log_format:
            logging_config["format"] = log_format
        if logging_config:
            config["logging"] = logging_config
        
        # Character sets
        char_sets = {}
        special_chars = os.getenv("SPECIAL_CHARS")
        if special_chars:
            char_sets["special_chars"] = special_chars
        ambiguous_chars = os.getenv("AMBIGUOUS_CHARS")
        if ambiguous_chars:
            char_sets["ambiguous_chars"] = ambiguous_chars
        if char_sets:
            config["character_sets"] = char_sets
        
        # Security
        security = {}
        secure_wipe = os.getenv("SECURE_MEMORY_WIPE")
        if secure_wipe:
            security["secure_memory_wipe"] = secure_wipe.lower() in ("true", "1", "yes", "on")
        if security:
            config["security"] = security
        
        # Application
        app = {}
        quiet_mode = os.getenv("QUIET_MODE")
        if quiet_mode:
            app["quiet_mode"] = quiet_mode.lower() in ("true", "1", "yes", "on")
        if app:
            config["application"] = app
        
        return config
    
    @classmethod
    def _deep_merge(cls, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge two dictionaries."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = cls._deep_merge(result[key], value)
            else:
                result[key] = value
        return result
    
    # =========================================================================
    # Convenience Properties
    # =========================================================================
    
    @property
    def min_password_length(self) -> int:
        """Shortcut to password policy min length."""
        return self.password_policy.min_password_length
    
    @property
    def default_password_length(self) -> int:
        """Shortcut to password policy default length."""
        return self.password_policy.default_password_length
    
    @property
    def hibp_api_timeout(self) -> int:
        """Shortcut to HIBP timeout."""
        return self.hibp.api_timeout
    
    @property
    def default_max_concurrent(self) -> int:
        """Shortcut to HIBP max concurrent."""
        return self.hibp.max_concurrent
    
    @property
    def api_call_delay(self) -> float:
        """Shortcut to API call delay."""
        return self.hibp.call_delay
    
    @property
    def log_level(self) -> str:
        """Shortcut to log level."""
        return self.logging.level
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def get_entropy_thresholds(self) -> List[tuple[float, str]]:
        """
        Get ordered list of entropy thresholds for strength rating.
        
        Returns:
            List of tuples: (threshold, rating)
        """
        return [
            (float(self.entropy_thresholds.very_weak), "Very Weak"),
            (float(self.entropy_thresholds.weak), "Weak"),
            (float(self.entropy_thresholds.moderate), "Moderate"),
            (float(self.entropy_thresholds.strong), "Strong"),
            (float('inf'), "Very Strong"),
        ]
    
    def validate(self) -> List[str]:
        """
        Validate configuration values.
        
        Returns:
            List of validation error messages (empty if all valid)
        """
        errors = []
        
        # Validate password lengths
        if self.password_policy.default_password_length < self.password_policy.min_password_length:
            errors.append("default_password_length must be >= min_password_length")
        
        # Validate entropy thresholds
        thresholds = [
            self.entropy_thresholds.very_weak,
            self.entropy_thresholds.weak,
            self.entropy_thresholds.moderate,
            self.entropy_thresholds.strong,
        ]
        if not all(thresholds[i] < thresholds[i+1] for i in range(len(thresholds)-1)):
            errors.append("Entropy thresholds must be strictly increasing")
        
        return errors
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return self.model_dump()
    
    def to_yaml(self) -> str:
        """Export configuration as YAML string."""
        return yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False)
    
    @classmethod
    def list_profiles(cls) -> Dict[str, str]:
        """List available policy profiles with descriptions."""
        return {
            name: profile.description 
            for name, profile in POLICY_PROFILES.items()
        }


# =============================================================================
# Legacy Compatibility
# =============================================================================

# Keep old Config class interface for backward compatibility
class LegacyConfigWrapper:
    """
    Wrapper to maintain backward compatibility with old Config class usage.
    
    Old usage: from config import Config; Config.HIBP_API_TIMEOUT
    New usage: from config import Config; config = Config.load(); config.hibp_api_timeout
    """
    
    _instance: Optional[Config] = None
    
    @classmethod
    def _get_instance(cls):
        if cls._instance is None:
            cls._instance = Config.load()
        return cls._instance
    
    @classmethod
    def reload(cls) -> None:
        """Reload configuration."""
        cls._instance = Config.load()
    
    # Map old attributes to new config
    @property
    def LOG_LEVEL(self) -> str:
        return self._get_instance().log_level
    
    @property
    def HIBP_API_TIMEOUT(self) -> int:
        return self._get_instance().hibp_api_timeout
    
    @property
    def HIBP_RETRY_ATTEMPTS(self) -> int:
        return self._get_instance().hibp.retry_attempts
    
    @property
    def HIBP_USER_AGENT(self) -> str:
        return self._get_instance().hibp.user_agent
    
    @property
    def HIBP_API_BASE_URL(self) -> str:
        return self._get_instance().hibp.base_url
    
    @property
    def DEFAULT_MAX_CONCURRENT(self) -> int:
        return self._get_instance().default_max_concurrent
    
    @property
    def API_CALL_DELAY(self) -> float:
        return self._get_instance().api_call_delay
    
    @property
    def MIN_PASSWORD_LENGTH(self) -> int:
        return self._get_instance().min_password_length
    
    @property
    def DEFAULT_PASSWORD_LENGTH(self) -> int:
        return self._get_instance().default_password_length
    
    @property
    def DEFAULT_PASSPHRASE_WORDS(self) -> int:
        return self._get_instance().password_policy.default_passphrase_words
    
    @property
    def SPECIAL_CHARS(self) -> str:
        return self._get_instance().character_sets.special_chars
    
    @property
    def AMBIGUOUS_CHARS(self) -> str:
        return self._get_instance().character_sets.ambiguous_chars
    
    @property
    def ENTROPY_VERY_WEAK(self) -> int:
        return self._get_instance().entropy_thresholds.very_weak
    
    @property
    def ENTROPY_WEAK(self) -> int:
        return self._get_instance().entropy_thresholds.weak
    
    @property
    def ENTROPY_MODERATE(self) -> int:
        return self._get_instance().entropy_thresholds.moderate
    
    @property
    def ENTROPY_STRONG(self) -> int:
        return self._get_instance().entropy_thresholds.strong
    
    @property
    def SECURE_MEMORY_WIPE(self) -> bool:
        return self._get_instance().security.secure_memory_wipe
    
    @property
    def QUIET_MODE(self) -> bool:
        return self._get_instance().application.quiet_mode
    
    def get_entropy_thresholds(self) -> List[tuple[float, str]]:
        return self._get_instance().get_entropy_thresholds()
    
    def validate(self) -> List[str]:
        return self._get_instance().validate()


# Create singleton instance for backward compatibility
ConfigSingleton = LegacyConfigWrapper()


# Maintain old import interface
def __getattr__(name: str) -> Any:
    """Support old Config attribute access pattern."""
    if hasattr(ConfigSingleton, name):
        return getattr(ConfigSingleton, name)
    raise AttributeError(f"module 'config' has no attribute '{name}'")


# Validate on module load (legacy behavior)
try:
    _validation_errors = ConfigSingleton.validate()
    if _validation_errors:
        for error in _validation_errors:
            warnings.warn(f"Configuration error: {error}", UserWarning)
except Exception as e:
    warnings.warn(f"Configuration validation failed: {e}", UserWarning)