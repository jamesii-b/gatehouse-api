"""API v1 blueprint."""
from flask import Blueprint

# Create v1 API blueprint
api_v1_bp = Blueprint("api_v1", __name__)

# Import route modules to register them
from gatehouse_app.api.v1 import auth, users, organizations, policies, external_auth, departments, principals, ssh, sudo

api_v1_bp.register_blueprint(ssh.ssh_bp)

