"""Custom decorators for authentication and authorization."""
from functools import wraps
from flask import request, g
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.constants import OrganizationRole, UserStatus
from gatehouse_app.exceptions.auth_exceptions import UnauthorizedError, ForbiddenError


def login_required(f):
    """Decorator to require Bearer token authentication.
    
    Extracts token from Authorization: Bearer {token} header,
    validates the session, and sets g.current_user and g.current_session.
    """
    from gatehouse_app.services.session_service import SessionService
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Extract token from Authorization header
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return api_response(
                success=False,
                message="Authorization header is required",
                status=401,
                error_type="AUTH_REQUIRED"
            )
        
        # Expect format: "Bearer {token}"
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != 'bearer':
            return api_response(
                success=False,
                message="Invalid authorization format. Use: Bearer {token}",
                status=401,
                error_type="INVALID_AUTH_FORMAT"
            )
        
        token = parts[1]
        
        # Get active session by token
        session = SessionService.get_active_session_by_token(token)
        
        if not session:
            return api_response(
                success=False,
                message="Invalid or expired session",
                status=401,
                error_type="INVALID_TOKEN"
            )
        
        # Validate session is active
        if not session.is_active():
            return api_response(
                success=False,
                message="Session is no longer active",
                status=401,
                error_type="SESSION_INACTIVE"
            )
        
        # Update last_activity_at timestamp
        from datetime import datetime, timezone
        session.last_activity_at = datetime.now(timezone.utc)
        from gatehouse_app import db
        db.session.commit()

        # Set context variables
        g.current_user = session.user
        g.current_session = session

        user = session.user
        token_groups: list = []
        try:
            if session.device_info:
                # device_info may carry OIDC claims stored at login time
                claims = session.device_info
                # Normalise: Gatehouse stores roles as [{"organization_id":…,"role":…}]
                roles_claim = claims.get("roles", [])
                if isinstance(roles_claim, list):
                    for entry in roles_claim:
                        if isinstance(entry, dict):
                            role_val = entry.get("role")
                            if role_val:
                                token_groups.append(str(role_val))
                        elif isinstance(entry, str):
                            token_groups.append(entry)
                # Standard OIDC groups claim
                groups_claim = claims.get("groups", [])
                if isinstance(groups_claim, list):
                    token_groups.extend(str(g_) for g_ in groups_claim if g_)
        except Exception:
            pass  # Never block auth over token_groups enrichment failure
        user.token_groups = token_groups

        # Activation check: if the user has an `activated` attribute and it is
        # explicitly False, block access.  New accounts without the attribute are
        # treated as active to avoid breaking existing sessions.
        activated = getattr(user, "activated", None)
        if activated is False:
            return api_response(
                success=False,
                message="Account not yet activated. Please check your email for an activation link.",
                status=403,
                error_type="ACCOUNT_NOT_ACTIVATED",
            )

        return f(*args, **kwargs)
    
    return decorated_function


def require_role(*allowed_roles):
    """
    Decorator to require specific organization roles.

    Args:
        *allowed_roles: Variable number of OrganizationRole values

    Raises:
        ForbiddenError: If user doesn't have required role
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Ensure user is authenticated first
            if not hasattr(g, "current_user"):
                raise UnauthorizedError("Authentication required")

            # Get organization_id from kwargs or URL parameters
            org_id = kwargs.get("org_id") or kwargs.get("organization_id")
            if not org_id:
                raise ForbiddenError("Organization context required")

            # Check user's role in the organization
            from gatehouse_app.models.organization.organization_member import OrganizationMember

            membership = OrganizationMember.query.filter_by(
                user_id=g.current_user.id,
                organization_id=org_id,
                deleted_at=None,
            ).first()

            if not membership:
                raise ForbiddenError("Not a member of this organization")

            if membership.role not in allowed_roles:
                raise ForbiddenError(
                    f"Requires one of the following roles: {', '.join(allowed_roles)}"
                )

            g.current_membership = membership
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def require_owner(f):
    """Decorator to require organization owner role."""
    return require_role(OrganizationRole.OWNER)(f)


def require_admin(f):
    """Decorator to require organization admin or owner role."""
    return require_role(OrganizationRole.OWNER, OrganizationRole.ADMIN)(f)


def full_access_required(f):
    """Decorator to require full access session (not compliance-only).
    
    This decorator checks if the user has a compliance-only session or
    is in COMPLIANCE_SUSPENDED status. If so, it returns a 403 error
    with error_type "MFA_COMPLIANCE_REQUIRED".
    
    Use this decorator on endpoints that require full MFA compliance.
    Endpoints for MFA enrollment, status, and logout should NOT use this decorator.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = getattr(g, "current_user", None)
        session = getattr(g, "current_session", None)

        if not user or not session:
            return api_response(
                success=False,
                message="Authentication required",
                status=401,
                error_type="AUTH_REQUIRED",
            )

        # Check for compliance-only session or compliance suspended status
        if session.is_compliance_only or user.status == UserStatus.COMPLIANCE_SUSPENDED:
            return api_response(
                success=False,
                message="MFA compliance required to access this resource",
                status=403,
                error_type="MFA_COMPLIANCE_REQUIRED",
                error_details={"overall_status": "suspended"},
            )

        return f(*args, **kwargs)

    return decorated_function
