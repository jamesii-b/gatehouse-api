"""OAuth flow service for handling external authentication flows."""
import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from flask import current_app, request, g, redirect

from gatehouse_app.extensions import db
from gatehouse_app.models import User, AuthenticationMethod
from gatehouse_app.models.authentication_method import OAuthState
from gatehouse_app.models.base import BaseModel
from gatehouse_app.models.oidc_authorization_code import OIDCAuthCode
from gatehouse_app.utils.constants import AuthMethodType, AuditAction
from gatehouse_app.services.audit_service import AuditService
from gatehouse_app.services.external_auth_service import (
    ExternalAuthService,
    ExternalAuthError,
    ExternalProviderConfig,
)

logger = logging.getLogger(__name__)


class OAuthFlowError(Exception):
    """Exception for OAuth flow errors."""

    def __init__(self, message: str, error_type: str, status_code: int = 400):
        self.message = message
        self.error_type = error_type
        self.status_code = status_code
        super().__init__(message)


class OAuthFlowService:
    """Service for managing OAuth authentication flows."""

    @classmethod
    def initiate_login_flow(
        cls,
        provider_type: AuthMethodType,
        organization_id: str = None,
        redirect_uri: str = None,
        state_data: dict = None,
    ) -> Tuple[str, str]:
        """
        Initiate OAuth login flow without requiring organization_id upfront.
        
        This method initiates the OAuth flow using application-wide provider configuration.
        The organization context is determined after successful authentication.

        Args:
            provider_type: The authentication provider type
            organization_id: Optional organization hint for SSO discovery
            redirect_uri: Optional custom redirect URI
            state_data: Additional state data to include

        Returns:
            Tuple of (authorization_url, state)
        """
        # Get request context for audit logging
        try:
            ip_address = request.remote_addr if request else None
            user_agent = request.headers.get("User-Agent") if request else None
        except RuntimeError:
            ip_address = None
            user_agent = None

        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        try:
            # Get provider config (application-wide, no organization required)
            config = ExternalAuthService.get_provider_config(provider_type, organization_id)

            # Validate redirect URI
            if redirect_uri and not config.is_redirect_uri_allowed(redirect_uri):
                raise OAuthFlowError(
                    "Invalid redirect URI",
                    "INVALID_REDIRECT_URI",
                    400,
                )

            # Generate PKCE parameters (Google and Microsoft web applications don't use PKCE
            # when a client_secret is present — they are confidential clients)
            code_verifier = None
            code_challenge = None
            if provider_type_str not in ['google', 'microsoft']:
                code_verifier = secrets.token_urlsafe(32)
                code_challenge = ExternalAuthService._compute_s256_challenge(code_verifier)

            # DIAGNOSTIC LOGGING: Show PKCE decision
            logger.info(
                f"[PKCE DEBUG] Provider type check: provider_type_str='{provider_type_str}', "
                f"is_google={provider_type_str in ['google']}, "
                f"will_skip_pkce={provider_type_str in ['google', 'microsoft']}"
            )

            # Create OAuth state for login flow
            state = OAuthState.create_state(
                flow_type="login",
                provider_type=provider_type,
                organization_id=organization_id,
                redirect_uri=redirect_uri or (config.redirect_uris[0] if config.redirect_uris else None),
                code_verifier=code_verifier,
                code_challenge=code_challenge,
                extra_data=state_data,
                lifetime_seconds=600,
            )

            # DIAGNOSTIC LOGGING: Verify state object
            logger.info(
                f"[PKCE DEBUG] Created OAuthState object:\n"
                f"  state.id: {state.id}\n"
                f"  state.provider_type: {state.provider_type}\n"
                f"  state.code_challenge: {state.code_challenge}\n"
                f"  state.code_verifier: {state.code_verifier[:20] if state.code_verifier else None}..."
            )

            # Build authorization URL
            auth_url = ExternalAuthService._build_authorization_url(
                config=config,
                state=state,
            )

            logger.info(
                f"OAuth login flow initiated for provider={provider_type_str}, "
                f"org_id={organization_id}, state_token={state.state}, state_record_id={state.id}"
            )
            logger.info(
                f"[PKCE DEBUG] FINAL CHECK: code_challenge={code_challenge}, "
                f"code_verifier={code_verifier[:20] if code_verifier else None}..., "
                f"auth_url_has_challenge={'code_challenge=' in auth_url}, "
                f"returned_auth_url={auth_url}"
            )

            return auth_url, state.state

        except ExternalAuthError as e:
            # Log failed initiation
            AuditService.log_action(
                action=AuditAction.EXTERNAL_AUTH_LOGIN_FAILED,
                organization_id=organization_id,
                metadata={
                    "provider_type": provider_type_str,
                    "failure_reason": e.error_type,
                    "ip_address": ip_address,
                },
                description=f"OAuth login initiation failed: {e.message}",
                success=False,
                error_message=e.message,
            )
            raise

    @classmethod
    def initiate_register_flow(
        cls,
        provider_type: AuthMethodType,
        organization_id: str = None,
        redirect_uri: str = None,
    ) -> Tuple[str, str]:
        """
        Initiate OAuth registration flow without requiring organization_id upfront.

        Args:
            provider_type: The authentication provider type
            organization_id: Optional organization hint
            redirect_uri: Optional custom redirect URI

        Returns:
            Tuple of (authorization_url, state)
        """
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        try:
            # Get provider config (application-wide, no organization required)
            config = ExternalAuthService.get_provider_config(provider_type, organization_id)

            # Validate redirect URI
            if redirect_uri and not config.is_redirect_uri_allowed(redirect_uri):
                raise OAuthFlowError(
                    "Invalid redirect URI",
                    "INVALID_REDIRECT_URI",
                    400,
                )

            # Generate PKCE parameters (Google and Microsoft web applications don't use PKCE
            # when a client_secret is present — they are confidential clients)
            code_verifier = None
            code_challenge = None
            if provider_type_str not in ['google', 'microsoft']:
                code_verifier = secrets.token_urlsafe(32)
                code_challenge = ExternalAuthService._compute_s256_challenge(code_verifier)

            # DIAGNOSTIC LOGGING: Show PKCE decision for register flow
            logger.info(
                f"[PKCE DEBUG] Register flow - Provider type check: provider_type_str='{provider_type_str}', "
                f"is_google={provider_type_str in ['google']}, "
                f"will_skip_pkce={provider_type_str in ['google', 'microsoft']}"
            )

            # Create OAuth state for register flow
            state = OAuthState.create_state(
                flow_type="register",
                provider_type=provider_type,
                organization_id=organization_id,
                redirect_uri=redirect_uri or (config.redirect_uris[0] if config.redirect_uris else None),
                code_verifier=code_verifier,
                code_challenge=code_challenge,
                lifetime_seconds=600,
            )

            # DIAGNOSTIC LOGGING: Verify state object for register flow
            logger.info(
                f"[PKCE DEBUG] Register flow - Created OAuthState:\n"
                f"  state.id: {state.id}\n"
                f"  state.code_challenge: {state.code_challenge}\n"
                f"  state.code_verifier: {state.code_verifier[:20] if state.code_verifier else None}..."
            )

            # Build authorization URL
            auth_url = ExternalAuthService._build_authorization_url(
                config=config,
                state=state,
            )

            logger.info(
                f"OAuth register flow initiated for provider={provider_type_str}, "
                f"org_id={organization_id}, state_id={state.id}"
            )
            logger.info(
                f"[PKCE DEBUG] Register flow - FINAL: auth_url_has_challenge={'code_challenge=' in auth_url}"
            )

            return auth_url, state.state

        except ExternalAuthError as e:
            AuditService.log_action(
                action=AuditAction.EXTERNAL_AUTH_LOGIN_FAILED,
                organization_id=organization_id,
                metadata={
                    "provider_type": provider_type_str,
                    "failure_reason": e.error_type,
                },
                description=f"OAuth registration initiation failed: {e.message}",
                success=False,
                error_message=e.message,
            )
            raise

    @classmethod
    def handle_callback(
        cls,
        provider_type: AuthMethodType,
        authorization_code: str,
        state: str,
        redirect_uri: str = None,
        error: str = None,
        error_description: str = None,
    ) -> dict:
        """
        Handle OAuth callback from provider.

        Args:
            provider_type: The authentication provider type
            authorization_code: Authorization code from provider
            state: State parameter from provider
            redirect_uri: Redirect URI used in the flow
            error: Error code if auth failed
            error_description: Human-readable error description

        Returns:
            Dict with flow result
        """
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        # Get request context for audit logging
        try:
            ip_address = request.remote_addr if request else None
            user_agent = request.headers.get("User-Agent") if request else None
        except RuntimeError:
            ip_address = None
            user_agent = None

        # Handle error response from provider
        if error:
            AuditService.log_external_auth_login_failed(
                organization_id=None,
                provider_type=provider_type_str,
                failure_reason=error,
                error_message=error_description or error,
            )
            raise OAuthFlowError(
                error_description or f"OAuth error: {error}",
                error.upper() if error else "OAUTH_ERROR",
                400,
            )

        # Validate state
        state_record = OAuthState.query.filter_by(state=state).first()
        
        # Log validation details for debugging
        if state_record:
            logger.debug(
                f"State validation: found=True, used={state_record.used}, "
                f"expires_at={state_record.expires_at}, now={datetime.now(timezone.utc)}, "
                f"is_valid={state_record.is_valid()}"
            )
        else:
            logger.warning(f"State validation: state token not found in database: {state}")
        
        if not state_record or not state_record.is_valid():
            AuditService.log_external_auth_login_failed(
                organization_id=state_record.organization_id if state_record else None,
                provider_type=provider_type_str,
                failure_reason="invalid_state",
                error_message="Invalid or expired OAuth state",
            )
            raise OAuthFlowError(
                "Invalid or expired OAuth state",
                "INVALID_STATE",
                400,
            )

        # Route to appropriate handler based on flow type
        if state_record.flow_type == "login":
            return cls._handle_login_callback(
                provider_type=provider_type,
                state_record=state_record,
                authorization_code=authorization_code,
                redirect_uri=redirect_uri or state_record.redirect_uri,
                ip_address=ip_address,
                user_agent=user_agent,
            )
        elif state_record.flow_type == "link":
            return cls._handle_link_callback(
                provider_type=provider_type,
                state_record=state_record,
                authorization_code=authorization_code,
                redirect_uri=redirect_uri or state_record.redirect_uri,
            )
        elif state_record.flow_type == "register":
            return cls._handle_register_callback(
                provider_type=provider_type,
                state_record=state_record,
                authorization_code=authorization_code,
                redirect_uri=redirect_uri or state_record.redirect_uri,
            )
        else:
            raise OAuthFlowError(
                f"Unknown flow type: {state_record.flow_type}",
                "INVALID_FLOW_TYPE",
                400,
            )

    @classmethod
    def _handle_login_callback(
        cls,
        provider_type: AuthMethodType,
        state_record: OAuthState,
        authorization_code: str,
        redirect_uri: str,
        ip_address: str = None,
        user_agent: str = None,
    ) -> dict:
        """
        Handle login flow callback with organization discovery.
        
        This method:
        1. Exchanges the authorization code for tokens
        2. Gets user info from the OAuth provider
        3. Looks up the user by provider_user_id
        4. Determines which organization(s) the user belongs to
        5. Creates a session or returns org selection needed
        """
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        try:
            # Get provider config (application-wide)
            config = ExternalAuthService.get_provider_config(
                provider_type, state_record.organization_id
            )

            logger.debug(
                f"Exchanging code with PKCE: state_record.code_verifier={state_record.code_verifier[:20] if state_record.code_verifier else None}..."
            )

            # Exchange code for tokens
            tokens = ExternalAuthService._exchange_code(
                config=config,
                code=authorization_code,
                redirect_uri=redirect_uri,
                code_verifier=state_record.code_verifier,
            )

            # Get user info from provider
            user_info = ExternalAuthService._get_user_info(
                config=config,
                access_token=tokens["access_token"],
            )

            if not user_info.get("provider_user_id"):
                raise OAuthFlowError(
                    "Provider did not return a user identifier (sub claim). "
                    "Cannot complete authentication.",
                    "MISSING_PROVIDER_USER_ID",
                    400,
                )

            if not user_info.get("email"):
                raise OAuthFlowError(
                    "Provider did not return an email address. "
                    "Cannot complete authentication.",
                    "MISSING_EMAIL",
                    400,
                )

            logger.debug(
                f"Got user_info from provider: sub={user_info['provider_user_id']}, "
                f"email={user_info['email']}, email_verified={user_info.get('email_verified')}"
            )

            # Look up user by provider_user_id
            auth_method = AuthenticationMethod.query.filter_by(
                method_type=provider_type,
                provider_user_id=user_info["provider_user_id"],
            ).first()

            if not auth_method:
                # No linked account found — check if email matches an existing user
                existing_user = User.query.filter_by(
                    email=user_info["email"]
                ).first()

                if existing_user:
                    # Email exists but no OAuth link — auto-link and log in
                    logger.info(
                        f"OAuth login: email {user_info['email']} matches existing user "
                        f"{existing_user.id}, auto-linking {provider_type_str} account"
                    )
                    auth_method = AuthenticationMethod(
                        user_id=existing_user.id,
                        method_type=provider_type,
                        provider_user_id=user_info["provider_user_id"],
                        provider_data=ExternalAuthService._encrypt_provider_data(tokens, user_info),
                        verified=user_info.get("email_verified", False),
                        is_primary=False,
                        last_used_at=datetime.utcnow(),
                    )
                    auth_method.save()
                    user = existing_user
                else:
                    # Brand-new user — auto-register via OAuth (standard behaviour)
                    logger.info(
                        f"OAuth login: no account for {user_info['email']}, "
                        f"auto-creating user via {provider_type_str}"
                    )
                    user = User(
                        email=user_info["email"],
                        full_name=user_info.get("name", ""),
                        status="active",
                        email_verified=user_info.get("email_verified", False),
                    )
                    user.save()

                    auth_method = AuthenticationMethod(
                        user_id=user.id,
                        method_type=provider_type,
                        provider_user_id=user_info["provider_user_id"],
                        provider_data=ExternalAuthService._encrypt_provider_data(tokens, user_info),
                        verified=user_info.get("email_verified", False),
                        is_primary=True,
                        last_used_at=datetime.utcnow(),
                    )
                    auth_method.save()

                    AuditService.log_action(
                        action="user.register",
                        user_id=user.id,
                        organization_id=state_record.organization_id,
                        resource_type="user",
                        resource_id=user.id,
                        metadata={
                            "provider_type": provider_type_str,
                            "provider_user_id": user_info["provider_user_id"],
                            "auto_registered": True,
                        },
                        description=f"User auto-registered via {provider_type_str} OAuth",
                        success=True,
                    )
            else:
                # Existing linked account — update provider data
                auth_method.provider_data = ExternalAuthService._encrypt_provider_data(
                    tokens, user_info
                )
                auth_method.last_used_at = datetime.utcnow()
                auth_method.save()

            user = auth_method.user

            # Get user's organizations
            user_orgs = user.get_organizations()

            # Determine target organization
            target_org = None

            # Priority 1: Use organization_id from state if provided (org hint)
            if state_record.organization_id:
                target_org = next(
                    (org for org in user_orgs if org.id == state_record.organization_id),
                    None
                )

            # Priority 2: If user has exactly one organization, use it
            if not target_org and len(user_orgs) == 1:
                target_org = user_orgs[0]

            # Priority 3: No orgs at all — auto-create a personal org and log in
            if not target_org and len(user_orgs) == 0:
                import re
                import uuid
                from gatehouse_app.services.organization_service import OrganizationService
                org_name = f"{user_info.get('name') or user.email.split('@')[0]}'s Workspace"
                # Build a URL-safe slug and ensure uniqueness with a short suffix
                base_slug = re.sub(r"[^a-z0-9]+", "-", org_name.lower()).strip("-")[:40]
                slug = f"{base_slug}-{uuid.uuid4().hex[:6]}"
                org = OrganizationService.create_organization(
                    name=org_name,
                    slug=slug,
                    owner_user_id=user.id,
                )
                target_org = org
                logger.info(
                    f"OAuth login: auto-created org '{org.name}' (id={org.id}) "
                    f"for new user {user.id}"
                )

            # Priority 4: Multiple orgs — need user to pick one
            if not target_org:
                state_record.mark_used()
                logger.info(
                    f"OAuth login requires org selection for user={user.id}, "
                    f"provider={provider_type_str}, org_count={len(user_orgs)}"
                )
                return {
                    "success": True,
                    "flow_type": "login",
                    "requires_org_selection": True,
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "full_name": user.full_name,
                    },
                    "available_organizations": [
                        {
                            "id": org.id,
                            "name": org.name,
                            "slug": org.slug if hasattr(org, "slug") else None,
                        }
                        for org in user_orgs
                    ],
                    "state": state_record.state,
                }

            # Create session for the target org
            from gatehouse_app.services.auth_service import AuthService
            session = AuthService.create_session(
                user=user,
                is_compliance_only=False,
            )

            # Mark state as used
            state_record.mark_used()

            # Audit log - login success
            AuditService.log_external_auth_login(
                user_id=user.id,
                organization_id=target_org.id,
                provider_type=provider_type_str,
                provider_user_id=user_info["provider_user_id"],
                auth_method_id=auth_method.id,
                session_id=session.id,
            )

            logger.info(
                f"OAuth login successful for user={user.id}, "
                f"provider={provider_type_str}, org_id={target_org.id}"
            )

            # Build session dict with token (to_dict() excludes token for security)
            session_dict = session.to_dict()
            session_dict["token"] = session.token
            # Calculate expires_in handling naive datetime from database
            expires_at = session.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            session_dict["expires_in"] = int((expires_at - now).total_seconds())

            return {
                "success": True,
                "flow_type": "login",
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name,
                    "organization_id": target_org.id,
                },
                "session": session_dict,
            }

        except ExternalAuthError as e:
            logger.warning(
                f"OAuth login failed for state={state_record.id}, "
                f"provider={provider_type_str}, error={e.message}"
            )
            raise
        except OAuthFlowError:
            # Re-raise OAuthFlowError as-is
            raise
        except Exception as e:
            logger.error(
                f"Unexpected error in OAuth login callback: {str(e)}",
                exc_info=True
            )
            raise OAuthFlowError(
                "An unexpected error occurred during login",
                "INTERNAL_ERROR",
                500,
            )

    @classmethod
    def _handle_link_callback(
        cls,
        provider_type: AuthMethodType,
        state_record: OAuthState,
        authorization_code: str,
        redirect_uri: str,
    ) -> dict:
        """Handle account linking flow callback."""
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        try:
            # Complete link flow
            auth_method = ExternalAuthService.complete_link_flow(
                provider_type=provider_type,
                authorization_code=authorization_code,
                state=state_record.state,
                redirect_uri=redirect_uri,
            )

            logger.info(
                f"OAuth link successful for user={state_record.user_id}, "
                f"provider={provider_type_str}, auth_method_id={auth_method.id}"
            )

            return {
                "success": True,
                "flow_type": "link",
                "linked_account": {
                    "id": auth_method.id,
                    "provider_type": provider_type_str,
                    "provider_user_id": auth_method.provider_user_id,
                    "verified": auth_method.verified,
                },
            }

        except ExternalAuthError as e:
            logger.warning(
                f"OAuth link failed for state={state_record.id}, "
                f"provider={provider_type_str}, error={e.message}"
            )
            raise

    @classmethod
    def _handle_register_callback(
        cls,
        provider_type: AuthMethodType,
        state_record: OAuthState,
        authorization_code: str,
        redirect_uri: str,
    ) -> dict:
        """
        Handle registration flow callback.
        
        Creates a new user account and prompts for organization creation/selection.
        """
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        try:
            # Get provider config (application-wide)
            config = ExternalAuthService.get_provider_config(
                provider_type, state_record.organization_id
            )

            # Exchange code for tokens
            tokens = ExternalAuthService._exchange_code(
                config=config,
                code=authorization_code,
                redirect_uri=redirect_uri,
                code_verifier=state_record.code_verifier,
            )

            # Get user info
            user_info = ExternalAuthService._get_user_info(
                config=config,
                access_token=tokens["access_token"],
            )

            # Check if user already exists by email
            existing_user = User.query.filter_by(
                email=user_info["email"]
            ).first()

            if existing_user:
                # User exists - suggest linking
                raise OAuthFlowError(
                    f"An account with email {user_info['email']} already exists. "
                    "Please log in with your password and link your Google account from settings.",
                    "EMAIL_EXISTS",
                    400,
                )

            # Create new user
            user = User(
                email=user_info["email"],
                full_name=user_info.get("name", ""),
                status="active",
                email_verified=user_info.get("email_verified", False),
            )
            user.save()

            # Create authentication method
            auth_method = AuthenticationMethod(
                user_id=user.id,
                method_type=provider_type,
                provider_user_id=user_info["provider_user_id"],
                provider_data=ExternalAuthService._encrypt_provider_data(tokens, user_info),
                verified=user_info.get("email_verified", False),
                is_primary=True,
                last_used_at=datetime.utcnow(),
            )
            auth_method.save()

            # Mark state as used
            state_record.mark_used()

            # Audit log - registration success
            AuditService.log_action(
                action="user.register",
                user_id=user.id,
                organization_id=state_record.organization_id,
                resource_type="user",
                resource_id=user.id,
                metadata={
                    "provider_type": provider_type_str,
                    "provider_user_id": user_info["provider_user_id"],
                    "auth_method_id": auth_method.id,
                },
                description=f"User registered via {provider_type_str}",
                success=True,
            )

            AuditService.log_external_auth_link_completed(
                user_id=user.id,
                organization_id=state_record.organization_id,
                provider_type=provider_type_str,
                provider_user_id=user_info["provider_user_id"],
                auth_method_id=auth_method.id,
            )

            logger.info(
                f"OAuth registration successful for email={user_info['email']}, "
                f"provider={provider_type_str}, user_id={user.id}"
            )

            # If organization_id hint was provided and valid, create session for that org
            if state_record.organization_id:
                from gatehouse_app.models.organization import Organization
                org = Organization.query.get(state_record.organization_id)
                if org:
                    from gatehouse_app.services.auth_service import AuthService
                    session = AuthService.create_session(
                        user=user,
                        is_compliance_only=False,
                    )
                    # Build session dict with token (to_dict() excludes token for security)
                    session_dict = session.to_dict()
                    session_dict["token"] = session.token
                    # Calculate expires_in handling naive datetime from database
                    expires_at = session.expires_at
                    if expires_at.tzinfo is None:
                        expires_at = expires_at.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    session_dict["expires_in"] = int((expires_at - now).total_seconds())
                    return {
                        "success": True,
                        "flow_type": "register",
                        "user": {
                            "id": user.id,
                            "email": user.email,
                            "full_name": user.full_name,
                            "organization_id": org.id,
                        },
                        "session": session_dict,
                    }

            # No organization hint or invalid - need to create/select org
            return {
                "success": True,
                "flow_type": "register",
                "requires_org_creation": True,
                "user": {
                    "id": user.id,
                    "email": user.email,
                    "full_name": user.full_name,
                },
                "state": state_record.state,
            }

        except ExternalAuthError as e:
            logger.warning(
                f"OAuth registration failed for state={state_record.id}, "
                f"provider={provider_type_str}, error={e.message}"
            )
            raise
        except OAuthFlowError:
            # Re-raise OAuthFlowError as-is
            raise
        except Exception as e:
            logger.error(
                f"Unexpected error in OAuth registration callback: {str(e)}",
                exc_info=True
            )
            raise OAuthFlowError(
                "An unexpected error occurred during registration",
                "INTERNAL_ERROR",
                500,
            )

    @classmethod
    def validate_state(cls, state: str) -> Optional[OAuthState]:
        """
        Validate and return OAuth state.

        Args:
            state: The state parameter to validate

        Returns:
            OAuthState if valid, None otherwise
        """
        state_record = OAuthState.query.filter_by(state=state).first()
        if state_record and state_record.is_valid():
            return state_record
        return None

    @classmethod
    def cleanup_expired_states(cls):
        """Remove expired OAuth states."""
        OAuthState.cleanup_expired()
        logger.info("Expired OAuth states cleaned up")

    @classmethod
    def generate_authorization_code(
        cls,
        user_id: str,
        client_id: str,
        redirect_uri: str,
        scope: list = None,
        nonce: str = None,
        ip_address: str = None,
        user_agent: str = None,
        lifetime_seconds: int = 600,
    ) -> str:
        """
        Generate an authorization code for external OAuth applications.
        
        This method creates a short-lived, single-use authorization code that can be
        exchanged for a session token by external applications like oauth2-proxy.
        
        Args:
            user_id: The user ID
            client_id: The client ID (e.g., 'oauth2-proxy', 'bookstack')
            redirect_uri: The redirect URI
            scope: Requested scopes
            nonce: OIDC nonce for validation
            ip_address: Client IP address
            user_agent: Client user agent
            lifetime_seconds: Code lifetime in seconds (default 10 minutes)
        
        Returns:
            The authorization code (plain text, not hashed)
        """
        # Generate a secure random code
        code = secrets.token_urlsafe(32)
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        
        # Create the authorization code record
        OIDCAuthCode.create_code(
            client_id=client_id,
            user_id=user_id,
            code_hash=code_hash,
            redirect_uri=redirect_uri,
            scope=scope,
            nonce=nonce,
            ip_address=ip_address,
            user_agent=user_agent,
            lifetime_seconds=lifetime_seconds,
        )
        
        logger.info(
            f"Generated authorization code for user={user_id}, client={client_id}"
        )
        
        return code

    @classmethod
    def exchange_authorization_code(
        cls,
        code: str,
        client_id: str,
        redirect_uri: str,
        ip_address: str = None,
    ) -> dict:
        """
        Exchange an authorization code for a session token.
        
        This method validates and consumes the authorization code, then creates
        a session for the user.
        
        Args:
            code: The authorization code
            client_id: The client ID
            redirect_uri: The redirect URI (must match original request)
            ip_address: Client IP address
        
        Returns:
            Dict with session token and user info
        """
        # Hash the provided code for lookup
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        
        # Find the authorization code record
        auth_code = OIDCAuthCode.query.filter_by(
            client_id=client_id,
            code_hash=code_hash,
        ).first()
        
        if not auth_code:
            raise OAuthFlowError(
                "Invalid authorization code",
                "INVALID_CODE",
                400,
            )
        
        # Validate the code
        if not auth_code.is_valid():
            if auth_code.is_used:
                raise OAuthFlowError(
                    "Authorization code has already been used",
                    "CODE_USED",
                    400,
                )
            else:
                raise OAuthFlowError(
                    "Authorization code has expired",
                    "CODE_EXPIRED",
                    400,
                )
        
        # Validate redirect URI
        if auth_code.redirect_uri != redirect_uri:
            raise OAuthFlowError(
                "Redirect URI mismatch",
                "INVALID_REDIRECT_URI",
                400,
            )
        
        # Get the user
        from gatehouse_app.models import User
        user = User.query.get(auth_code.user_id)
        if not user:
            raise OAuthFlowError(
                "User not found",
                "USER_NOT_FOUND",
                404,
            )
        
        # Determine organization
        from gatehouse_app.models.organization import Organization
        from gatehouse_app.models.organization_member import OrganizationMember
        
        # Get user's organizations
        user_orgs = user.get_organizations()
        
        # Determine target organization
        target_org = None
        
        # Priority 1: Use organization_id from auth code if available
        # Priority 2: If user has exactly one organization, use it
        if not target_org and len(user_orgs) == 1:
            target_org = user_orgs[0]
        
        if not target_org:
            raise OAuthFlowError(
                "User does not have a default organization. Organization selection required.",
                "ORG_SELECTION_REQUIRED",
                400,
            )
        
        # Create session
        from gatehouse_app.services.auth_service import AuthService
        session = AuthService.create_session(
            user=user,
            is_compliance_only=False,
        )
        
        # Mark the code as used
        auth_code.mark_as_used()
        
        # Build session dict
        session_dict = session.to_dict()
        session_dict["token"] = session.token
        expires_at = session.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        session_dict["expires_in"] = int((expires_at - now).total_seconds())
        
        logger.info(
            f"Authorization code exchanged for session: user={user.id}, "
            f"org_id={target_org.id}, client={client_id}"
        )
        
        return {
            "success": True,
            "token": session_dict["token"],
            "expires_in": session_dict["expires_in"],
            "token_type": "Bearer",
            "user": {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "organization_id": target_org.id,
            },
        }

    @classmethod
    def create_redirect_response(
        cls,
        redirect_uri: str,
        authorization_code: str,
        state: str = None,
    ):
        """
        Create a redirect response with authorization code.
        
        Args:
            redirect_uri: The redirect URI
            authorization_code: The authorization code
            state: Optional state parameter
        
        Returns:
            Flask redirect response
        """
        from urllib.parse import urlencode, urlparse, urlunparse
        
        # Parse the redirect URI
        parsed = urlparse(redirect_uri)
        
        # Build query parameters
        params = {"code": authorization_code}
        if state:
            params["state"] = state
        
        # Reconstruct URL with query parameters
        redirect_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            urlencode(params),
            parsed.fragment,
        ))
        
        logger.info(
            f"Redirecting to {parsed.scheme}://{parsed.netloc} with authorization code"
        )
        
        return redirect(redirect_url)
