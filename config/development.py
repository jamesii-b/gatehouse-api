"""Development environment configuration."""
from config.base import BaseConfig
import os

class DevelopmentConfig(BaseConfig):
    """Development configuration."""

    DEBUG = True
    # Use environment variable like BaseConfig does
    SQLALCHEMY_ECHO = os.getenv("SQLALCHEMY_ECHO", "False").lower() == "true"
    SESSION_COOKIE_SECURE = False

    # More verbose logging in development
    LOG_LEVEL = "DEBUG"
    LOG_TO_STDOUT = True

    # Reduced bcrypt rounds for faster dev cycles
    BCRYPT_LOG_ROUNDS = 4

    # Gatehouse React UI URL — OIDC authorize redirects here instead of showing raw HTML
    OIDC_UI_URL = os.getenv("OIDC_UI_URL", "http://localhost:8080")

    # Add localhost:8080 (React UI) to CORS allowed origins for OIDC bridge endpoints
    CORS_ORIGINS = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:8080,http://localhost:3000,http://localhost:5173,https://ui.webauthn.local"
    ).split(",")

    # ── Email / SMTP ──────────────────────────────────────────────────────────
    # Read from .env so real SMTP credentials work in dev.
    # Set EMAIL_ENABLED=false in .env to disable; defaults to True if SMTP_HOST is set.
    EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "True").lower() == "true"
    SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "1025"))
    SMTP_USERNAME = os.getenv("SMTP_USERNAME") or None
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD") or None
    SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "").lower() == "true" if os.getenv("SMTP_USE_TLS") else int(os.getenv("SMTP_PORT", "1025")) not in (25, 1025)
    FROM_ADDRESS = os.getenv("FROM_ADDRESS", "noreply@gatehouse.local")
    EMAIL_FROM = FROM_ADDRESS  # alias
