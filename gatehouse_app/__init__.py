"""Application factory."""
import os
import logging

from dotenv import load_dotenv
load_dotenv(dotenv_path=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env'))

# Test debug logging - this should appear when running `flask run --debug`
_root_logger = logging.getLogger(__name__)
_root_logger.debug("[TEST] Debug logging is working!")

from flask import Flask
from config import get_config
from gatehouse_app.extensions import db, migrate, bcrypt, ma, limiter
from gatehouse_app.extensions import session as flask_session
from gatehouse_app.middleware import RequestIDMiddleware, SecurityHeadersMiddleware, setup_cors
from gatehouse_app.exceptions.base import BaseAPIException
from gatehouse_app.utils.response import api_response
from gatehouse_app.services.oidc_jwks_service import OIDCJWKSService
import redis

# Configure SQLAlchemy logging BEFORE any database operations
# This must be done before db.init_app() to prevent verbose logging
_log_level_env = os.getenv("SQLALCHEMY_LOG_LEVEL", "WARNING").upper()
_sqlalchemy_log_level = getattr(logging, _log_level_env, logging.WARNING)
logging.getLogger('sqlalchemy').setLevel(_sqlalchemy_log_level)
logging.getLogger('sqlalchemy.engine').setLevel(_sqlalchemy_log_level)
logging.getLogger('sqlalchemy.dialects').setLevel(_sqlalchemy_log_level)
logging.getLogger('sqlalchemy.pool').setLevel(_sqlalchemy_log_level)


def create_app(config_name=None):
    """
    Create and configure the Flask application.

    Args:
        config_name: Configuration name (development, testing, production)

    Returns:
        Flask application instance
    """
    flask_app = Flask(__name__)

    # Load configuration
    config = get_config(config_name)
    flask_app.config.from_object(config)

    # Initialize extensions
    initialize_extensions(flask_app)

    # Setup middleware
    setup_middleware(flask_app)

    # Register blueprints
    register_blueprints(flask_app)

    # Register error handlers
    register_error_handlers(flask_app)

    # Setup logging
    setup_logging(flask_app)

    # Initialize OIDC JWKS service with a signing key
    initialize_oidc_jwks(flask_app)

    return flask_app


def initialize_extensions(app):
    """Initialize Flask extensions."""
    # Database
    db.init_app(app)
    migrate.init_app(app, db)

    # Security
    bcrypt.init_app(app)

    # CORS - using custom middleware only (see app/middleware/cors.py)
    # Flask-CORS disabled to avoid conflicts
    # cors.init_app(app)

    # Marshmallow
    ma.init_app(app)

    # Rate limiting
    if app.config.get("RATELIMIT_ENABLED"):
        limiter.init_app(app)

    # Redis for sessions and Flask-Session
    try:
        redis_url = app.config.get("REDIS_URL")
        if redis_url:
            import gatehouse_app.extensions
            gatehouse_app.extensions.redis_client = redis.from_url(redis_url)
            app.config["SESSION_REDIS"] = gatehouse_app.extensions.redis_client
            logging.info(f"Redis connected successfully for sessions")
    except Exception as e:
        logging.warning(f"Redis connection failed: {e}")

    # Flask-Session - configure with Redis if available, otherwise filesystem
    flask_session.init_app(app)


def setup_middleware(app):
    """Setup application middleware."""
    RequestIDMiddleware(app)
    SecurityHeadersMiddleware(app)
    setup_cors(app)


def register_blueprints(app):
    """Register application blueprints."""
    from gatehouse_app.api import register_api_blueprints
    from gatehouse_app.api.oidc import oidc_bp

    register_api_blueprints(app)

    # Register OIDC blueprint at root level
    app.register_blueprint(oidc_bp)


def register_error_handlers(app):
    """Register error handlers."""

    @app.errorhandler(BaseAPIException)
    def handle_api_exception(error):
        """Handle custom API exceptions."""
        return api_response(
            success=False,
            message=error.message,
            status=error.status_code,
            error_type=error.error_type,
            error_details=error.error_details,
        )

    @app.errorhandler(404)
    def handle_not_found(error):
        """Handle 404 errors."""
        return api_response(
            success=False,
            message="Resource not found",
            status=404,
            error_type="NOT_FOUND",
        )

    @app.errorhandler(405)
    def handle_method_not_allowed(error):
        """Handle 405 errors."""
        return api_response(
            success=False,
            message="Method not allowed",
            status=405,
            error_type="METHOD_NOT_ALLOWED",
        )

    @app.errorhandler(500)
    def handle_internal_error(error):
        """Handle 500 errors."""
        app.logger.error(f"Internal server error: {error}")
        return api_response(
            success=False,
            message="Internal server error",
            status=500,
            error_type="INTERNAL_ERROR",
        )

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        """Handle unexpected errors."""
        app.logger.error(f"Unexpected error: {error}", exc_info=True)
        return api_response(
            success=False,
            message="An unexpected error occurred",
            status=500,
            error_type="INTERNAL_ERROR",
        )


def setup_logging(app):
    """Setup application logging."""
    log_level = getattr(logging, app.config.get("LOG_LEVEL", "INFO"))

    # Create formatter
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(name)s: %(message)s"
    )

    # Configure root logger - this ensures all module loggers (like app.services.oidc_service)
    # will output DEBUG level logs when in development mode
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    if app.config.get("LOG_TO_STDOUT"):
        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(log_level)
        root_logger.addHandler(stream_handler)

    # Disable Werkzeug's default logger to avoid log duplication and interference
    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.setLevel(logging.INFO)

    # Ensure child loggers propagate to root logger
    # This is the key fix - explicitly enable propagation for common app loggers
    for logger_name in ['app', 'app.api', 'app.api.oidc', 'app.services', 'app.models']:
        child_logger = logging.getLogger(logger_name)
        child_logger.propagate = True
        child_logger.setLevel(log_level)

    # Configure Flask app logger
    app.logger.setLevel(log_level)

    # Configure SQLAlchemy logging level (also set at module level before DB init)
    sqlalchemy_log_level = getattr(logging, app.config.get("SQLALCHEMY_LOG_LEVEL", "WARNING"), logging.WARNING)
    logging.getLogger('sqlalchemy').setLevel(sqlalchemy_log_level)
    logging.getLogger('sqlalchemy.engine').setLevel(sqlalchemy_log_level)
    logging.getLogger('sqlalchemy.dialects').setLevel(sqlalchemy_log_level)
    logging.getLogger('sqlalchemy.pool').setLevel(sqlalchemy_log_level)

    app.logger.info("Application startup")
    
    # Test debug log after logging is configured
    app.logger.debug("[TEST] Debug logging is working!")


def initialize_oidc_jwks(app):
    """Initialize OIDC JWKS service with a signing key.
    
    This ensures that signing keys are available for token generation.
    Keys are loaded from the database if available, otherwise a new key
    is generated and persisted to the database.
    
    Args:
        app: Flask application instance
    """
    with app.app_context():
        try:
            jwks_service = OIDCJWKSService()
            # Use initialize_with_key which handles loading from DB
            # or generating a new key if none exists
            signing_key = jwks_service.initialize_with_key()
            app.logger.info(f"[OIDC] Signing key initialized: kid={signing_key.kid}")
        except Exception as e:
            app.logger.error(f"[OIDC] Failed to initialize JWKS: {e}")

# Create default app instance for gunicorn/wsgi
app = create_app()
