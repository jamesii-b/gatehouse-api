"""SSH CA Configuration Manager.

Handles loading and managing SSH CA configuration from etc/ssh_ca.conf
and environment variables.
"""
import os
import configparser
from pathlib import Path
from typing import Optional, Union


class SSHCAConfig:
    """Configuration manager for SSH CA settings.
    
    Loads configuration from:
    1. etc/ssh_ca.conf file
    2. Environment variables (override config file)
    3. Application environment-specific defaults
    
    Example:
        config = SSHCAConfig()
        cert_hours = config.get_int('cert_validity_hours')
        kms_key = config.get_str('aws_kms_key_id')
    """

    # Configuration file location (relative to project root)
    DEFAULT_CONFIG_FILE = "etc/ssh_ca.conf"

    # Default values if config file is missing
    DEFAULTS = {
        'cert_validity_hours': '1',
        'max_cert_validity_hours': '24',
        'max_certs_per_user': '100',
        'crl_enabled': 'true',
        'crl_endpoint': 'https://ca.example.com/crl',
        'crl_refresh_hours': '24',
        'default_key_type': 'ed25519',
        'rsa_key_bits': '4096',
        'private_key_encryption': 'kms',
        'aws_kms_key_id': '',
        'extensions_enabled': 'true',
        'extensions': 'permit-X11-forwarding,permit-agent-forwarding,permit-pty,permit-port-forwarding,permit-user-rc',
        'critical_options_enabled': 'false',
        'max_principals_per_cert': '256',
        'max_key_id_length': '255',
        'log_level': 'INFO',
        'audit_enabled': 'true',
        'require_key_verification': 'true',
        'verification_challenge_max_age': '24',
        'rate_limit_certs_per_minute': '5',
        'request_timeout': '30',
        'auto_delete_unverified_days': '30',
        'archive_expired_days': '365',
        'oauth_token_endpoint': '/api/v1/oauth2/token',
        'oauth_userinfo_endpoint': '/api/v1/oauth2/userinfo',
        'ca_key_path': '',
    }

    def __init__(self, config_file: Optional[str] = None, environment: Optional[str] = None):
        """Initialize SSH CA configuration.
        
        Args:
            config_file: Path to config file (default: etc/ssh_ca.conf)
            environment: Environment name (development, production, testing)
                        Default: value of FLASK_ENV or 'development'
        """
        self.config = configparser.ConfigParser()
        
        # Determine environment
        if environment is None:
            environment = os.environ.get('FLASK_ENV', 'development')
        self.environment = environment
        
        # Load config file
        if config_file is None:
            # Try to find config file relative to this module
            module_dir = Path(__file__).parent.parent.parent
            config_file = module_dir / self.DEFAULT_CONFIG_FILE
        
        self.config_file = config_file
        self._load_config()

    def _load_config(self):
        """Load configuration from file and apply environment-specific overrides."""
        # Set defaults
        self.config['default'] = self.DEFAULTS.copy()
        
        # Load config file if it exists
        if Path(self.config_file).exists():
            self.config.read(self.config_file)
        
        # Apply environment-specific configuration
        if self.environment in self.config:
            for key, value in self.config[self.environment].items():
                self.config['default'][key] = value

    def get_str(self, key: str, default: Optional[str] = None) -> str:
        """Get a string configuration value.
        
        First checks environment variables (SSH_CA_<KEY>), then config file.
        
        Args:
            key: Configuration key
            default: Default value if not found
            
        Returns:
            Configuration value as string
        """
        env_key = f"SSH_CA_{key.upper()}"
        
        # Check environment variable first
        if env_key in os.environ:
            return os.environ[env_key]
        
        # Check config file
        if key in self.config['default']:
            value = self.config['default'][key]
            # Handle environment variable substitution
            return os.path.expandvars(value)
        
        # Return default
        if default is not None:
            return default
        
        return self.DEFAULTS.get(key, '')

    def get_int(self, key: str, default: Optional[int] = None) -> int:
        """Get an integer configuration value.
        
        Args:
            key: Configuration key
            default: Default value if not found
            
        Returns:
            Configuration value as integer
            
        Raises:
            ValueError: If value cannot be converted to integer
        """
        str_value = self.get_str(key)
        if not str_value:
            if default is not None:
                return default
            raise ValueError(f"No value found for {key}")
        
        try:
            return int(str_value)
        except ValueError:
            if default is not None:
                return default
            raise ValueError(f"Configuration {key}={str_value} is not a valid integer")

    def get_bool(self, key: str, default: Optional[bool] = None) -> bool:
        """Get a boolean configuration value.
        
        Args:
            key: Configuration key
            default: Default value if not found
            
        Returns:
            Configuration value as boolean
        """
        str_value = self.get_str(key)
        if not str_value:
            if default is not None:
                return default
            return False
        
        return str_value.lower() in ('true', '1', 'yes', 'on')

    def get_list(self, key: str, delimiter: str = ',', default: Optional[list] = None) -> list:
        """Get a comma-separated list configuration value.
        
        Args:
            key: Configuration key
            delimiter: Delimiter between items (default: comma)
            default: Default value if not found
            
        Returns:
            Configuration value as list of strings
        """
        str_value = self.get_str(key)
        if not str_value:
            if default is not None:
                return default
            return []
        
        return [item.strip() for item in str_value.split(delimiter) if item.strip()]

    def validate_config(self) -> list:
        """Validate SSH CA configuration.
        
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Check cert validity hours
        try:
            validity = self.get_int('cert_validity_hours')
            max_validity = self.get_int('max_cert_validity_hours')
            if validity > max_validity:
                errors.append(
                    f"cert_validity_hours ({validity}) > max_cert_validity_hours ({max_validity})"
                )
        except ValueError as e:
            errors.append(f"Invalid cert validity hours: {e}")
        
        # Check key type
        valid_key_types = ['ed25519', 'rsa', 'ecdsa']
        key_type = self.get_str('default_key_type', 'ed25519')
        if key_type not in valid_key_types:
            errors.append(f"Invalid key type: {key_type}. Must be one of {valid_key_types}")
        
        # Check encryption method
        valid_methods = ['kms', 'local']
        encryption = self.get_str('private_key_encryption', 'kms')
        if encryption not in valid_methods:
            errors.append(f"Invalid private_key_encryption: {encryption}. Must be one of {valid_methods}")
        
        # Warn if using local encryption in production
        if encryption == 'local' and self.environment == 'production':
            errors.append("WARNING: Using local key encryption in production! Use KMS instead.")
        
        # Check KMS key ID if using KMS
        if encryption == 'kms':
            kms_key = self.get_str('aws_kms_key_id', '').strip()
            if not kms_key:
                errors.append("aws_kms_key_id not set but private_key_encryption=kms")
        
        # Check principals limit
        max_principals = self.get_int('max_principals_per_cert')
        if max_principals > 256:
            errors.append(f"max_principals_per_cert ({max_principals}) exceeds SSH limit of 256")
        
        return errors

    def to_dict(self) -> dict:
        """Export current configuration as dictionary.
        """
        return dict(self.config['default'])

    def __repr__(self):
        """String representation of configuration."""
        return f"<SSHCAConfig environment={self.environment} file={self.config_file}>"


# Global configuration instance
_config_instance = None


def get_ssh_ca_config() -> SSHCAConfig:
    """Get the global SSH CA configuration instance.
    
    This function uses a singleton pattern to ensure only one
    configuration instance is created and reused.
    
    Returns:
        SSHCAConfig instance
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = SSHCAConfig()
    return _config_instance


def reset_config_instance():
    """Reset the global configuration instance.
    """
    global _config_instance
    _config_instance = None
