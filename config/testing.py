"""Testing environment configuration."""
from config.base import BaseConfig
import os


class TestingConfig(BaseConfig):
    """Testing configuration."""

    TESTING = True
    DEBUG = True
    
    # Explicitly set SECRET_KEY for testing
    SECRET_KEY = os.getenv("SECRET_KEY", "test-secret-key-for-testing")

    # CA key encryption — use a fixed test key so tests are deterministic
    CA_ENCRYPTION_KEY = os.getenv("CA_ENCRYPTION_KEY", "test-ca-encryption-key-fixed-for-tests")

    # Use in-memory SQLite for testing
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_ECHO = False

    # Disable CSRF for testing
    WTF_CSRF_ENABLED = False

    # Fast password hashing for tests
    BCRYPT_LOG_ROUNDS = 4

    # Disable rate limiting in tests
    RATELIMIT_ENABLED = False

    # Use different Redis DB for testing
    REDIS_URL = "redis://localhost:6379/15"
    
    # Use filesystem for sessions in testing
    SESSION_TYPE = "filesystem"
    SESSION_FILE_DIR = "/tmp/flask_session_test"
