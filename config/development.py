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
