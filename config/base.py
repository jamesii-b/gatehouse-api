"""Base configuration for all environments."""
import os
from datetime import timedelta


class BaseConfig:
    """Base configuration class with common settings."""

    # Application
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    DEBUG = False
    TESTING = False

    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/authy2"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = os.getenv("SQLALCHEMY_ECHO", "False").lower() == "true"
    SQLALCHEMY_LOG_LEVEL = os.getenv("SQLALCHEMY_LOG_LEVEL", "WARNING")
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }

    # Security
    BCRYPT_LOG_ROUNDS = int(os.getenv("BCRYPT_LOG_ROUNDS", "12"))
    
    # Encryption key for sensitive data (client secrets, tokens, etc.)
    ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "dev-encryption-key-change-in-production")

    # Encryption key for CA private keys stored in the database.
    # Must be set to a strong random secret in production.
    # Any string is accepted — it is SHA-256 derived to a 32-byte Fernet key internally.
    CA_ENCRYPTION_KEY = os.getenv("CA_ENCRYPTION_KEY", "dev-ca-encryption-key-change-in-production")
    
    # Session configuration for WebAuthn cross-origin support
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "True").lower() == "true"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "None")
    
    # Set the cookie domain to allow sharing across subdomains (e.g., ui.webauthn.local and api.webauthn.local)
    # Extract base domain from WEBAUTHN_RP_ID or use default
    _rp_id = os.getenv("WEBAUTHN_RP_ID", "localhost")
    SESSION_COOKIE_DOMAIN = os.getenv("SESSION_COOKIE_DOMAIN", _rp_id if _rp_id != "localhost" else None)
    
    PERMANENT_SESSION_LIFETIME = timedelta(
        seconds=int(os.getenv("MAX_SESSION_DURATION", "86400"))
    )

    # CORS
    CORS_ORIGINS = os.getenv(
        "CORS_ORIGINS",
        "https://ui.webauthn.local,https://ui.webauthn.local:5173,http://localhost:3000,http://localhost:5173"
    ).split(",")
    CORS_SUPPORTS_CREDENTIALS = True

    # JWT (if using JWT)
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", SECRET_KEY)
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        seconds=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES", "3600"))
    )
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(
        seconds=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES", "2592000"))
    )

    # Redis
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    # Flask Session configuration - use Redis for better cross-instance support
    SESSION_TYPE = os.getenv("SESSION_TYPE", "redis")
    SESSION_REDIS_URL = os.getenv("SESSION_REDIS_URL", REDIS_URL)
    SESSION_REDIS = None  # Will be set at app initialization

    # Rate Limiting
    RATELIMIT_ENABLED = os.getenv("RATELIMIT_ENABLED", "True").lower() == "true"
    RATELIMIT_STORAGE_URL = os.getenv("RATELIMIT_STORAGE_URL", "redis://localhost:6379/1")
    RATELIMIT_DEFAULT = "100/hour"

    # Per-endpoint auth rate limits (override via env vars for each environment)
    RATELIMIT_AUTH_REGISTER = os.getenv("RATELIMIT_AUTH_REGISTER", "10 per minute; 50 per hour")
    RATELIMIT_AUTH_LOGIN = os.getenv("RATELIMIT_AUTH_LOGIN", "20 per minute; 100 per hour")
    RATELIMIT_AUTH_TOTP_VERIFY = os.getenv("RATELIMIT_AUTH_TOTP_VERIFY", "20 per minute; 100 per hour")
    RATELIMIT_AUTH_FORGOT_PASSWORD = os.getenv("RATELIMIT_AUTH_FORGOT_PASSWORD", "5 per minute; 20 per hour")
    RATELIMIT_AUTH_RESET_PASSWORD = os.getenv("RATELIMIT_AUTH_RESET_PASSWORD", "10 per minute; 30 per hour")

    # Logging
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_TO_STDOUT = os.getenv("LOG_TO_STDOUT", "False").lower() == "true"

    # OIDC Configuration
    OIDC_ISSUER_URL = os.getenv("OIDC_ISSUER_URL", "http://localhost:5000")
    OIDC_BASE_URL = os.getenv("OIDC_BASE_URL", OIDC_ISSUER_URL)
    
    # Token lifetimes
    OIDC_ACCESS_TOKEN_LIFETIME = int(os.getenv("OIDC_ACCESS_TOKEN_LIFETIME", "3600"))
    OIDC_REFRESH_TOKEN_LIFETIME = int(os.getenv("OIDC_REFRESH_TOKEN_LIFETIME", "2592000"))
    OIDC_ID_TOKEN_LIFETIME = int(os.getenv("OIDC_ID_TOKEN_LIFETIME", "3600"))
    OIDC_AUTHORIZATION_CODE_LIFETIME = int(os.getenv("OIDC_AUTHORIZATION_CODE_LIFETIME", "600"))
    
    # Security settings
    OIDC_REQUIRE_PKCE = os.getenv("OIDC_REQUIRE_PKCE", "True").lower() == "true"
    OIDC_ALLOW_IMPLICIT_FLOW = os.getenv("OIDC_ALLOW_IMPLICIT_FLOW", "False").lower() == "true"
    OIDC_SUPPORTED_SCOPES = ["openid", "profile", "email"]
    OIDC_DEFAULT_SCOPES = ["openid", "profile", "email"]
    
    # Key rotation
    OIDC_KEY_ROTATION_DAYS = int(os.getenv("OIDC_KEY_ROTATION_DAYS", "90"))
    OIDC_KEY_GRACE_PERIOD_DAYS = int(os.getenv("OIDC_KEY_GRACE_PERIOD_DAYS", "30"))
    
    # Rate limiting
    OIDC_RATE_LIMIT_AUTHORIZE = os.getenv("OIDC_RATE_LIMIT_AUTHORIZE", "10/minute")
    OIDC_RATE_LIMIT_TOKEN = os.getenv("OIDC_RATE_LIMIT_TOKEN", "20/minute")
    OIDC_RATE_LIMIT_USERINFO = os.getenv("OIDC_RATE_LIMIT_USERINFO", "60/minute")

    # API Versioning
    API_VERSION = "1.0.0"
    ENVELOPE_VERSION = "1.0"

    # Pagination
    DEFAULT_PAGE_SIZE = 20
    MAX_PAGE_SIZE = 100

    # WebAuthn Configuration
    WEBAUTHN_RP_ID = os.getenv("WEBAUTHN_RP_ID", "localhost")
    WEBAUTHN_RP_NAME = os.getenv("WEBAUTHN_RP_NAME", "Gatehouse")
    WEBAUTHN_ORIGIN = os.getenv("WEBAUTHN_ORIGIN", "https://ui.webauthn.local")

    # Frontend URL (for OAuth callback redirects)
    FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:8080")

    # Email / SMTP
    EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "False").lower() == "true"
    SMTP_HOST = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    FROM_ADDRESS = os.getenv("FROM_ADDRESS", "noreply@gatehouse.local")
