"""OIDC Service - Main OIDC service layer."""
import logging
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from flask import current_app, g

logger = logging.getLogger(__name__)

from gatehouse_app.extensions import db
from gatehouse_app.models import (
    User, OIDCClient, OIDCAuthCode, OIDCRefreshToken,
    OIDCSession, OIDCTokenMetadata
)
from gatehouse_app.models.organization_member import OrganizationMember
from gatehouse_app.exceptions.validation_exceptions import (
    ValidationError, NotFoundError, BadRequestError
)
from gatehouse_app.exceptions.auth_exceptions import UnauthorizedError, InvalidTokenError
from gatehouse_app.services.oidc_token_service import OIDCTokenService
from gatehouse_app.services.oidc_session_service import OIDCSessionService
from gatehouse_app.services.oidc_audit_service import OIDCAuditService
from gatehouse_app.services.oidc_jwks_service import OIDCJWKSService


class OIDCError(Exception):
    """Base exception for OIDC errors."""
    
    def __init__(self, error: str, error_description: str = None, status_code: int = 400):
        self.error = error
        self.error_description = error_description
        self.status_code = status_code


class InvalidClientError(OIDCError):
    """Raised when client authentication fails."""
    
    def __init__(self, error_description: str = "Invalid client"):
        super().__init__("invalid_client", error_description, 401)


class InvalidGrantError(OIDCError):
    """Raised when grant is invalid."""
    
    def __init__(self, error_description: str = "Invalid grant"):
        super().__init__("invalid_grant", error_description, 400)


class InvalidRequestError(OIDCError):
    """Raised when request is malformed."""
    
    def __init__(self, error_description: str = "Invalid request"):
        super().__init__("invalid_request", error_description, 400)


class OIDCService:
    """Main OIDC service handling all OpenID Connect operations.
    
    This service provides:
    - Authorization code generation and validation
    - Token generation (access, refresh, ID tokens)
    - Token refresh with rotation
    - Token validation and introspection
    - Token revocation
    """
    
    @staticmethod
    def _generate_code() -> str:
        """Generate a secure authorization code.
        
        Returns:
            URL-safe base64 encoded code
        """
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def _hash_value(value: str) -> str:
        """Hash a value for secure storage.
        
        Args:
            value: Value to hash
        
        Returns:
            SHA256 hash
        """
        return hashlib.sha256(value.encode()).hexdigest()
    
    @classmethod
    def generate_authorization_code(
        cls,
        client_id: str,
        user_id: str,
        redirect_uri: str,
        scope: list,
        state: str,
        nonce: str,
        code_challenge: str = None,
        code_challenge_method: str = None,
        ip_address: str = None,
        user_agent: str = None
    ) -> str:
        """Generate an authorization code for the auth code flow.
        
        Args:
            client_id: OIDC client ID
            user_id: User ID
            redirect_uri: Redirect URI
            scope: Requested scopes
            state: State parameter
            nonce: Nonce for ID token
            code_challenge: PKCE code challenge
            code_challenge_method: PKCE method ("S256" or "plain")
            ip_address: Client IP address
            user_agent: Client user agent
        
        Returns:
            Authorization code string
        
        Raises:
            ValidationError: If parameters are invalid
            NotFoundError: If client not found
        """
        logger.debug("[OIDC SERVICE] ===========================================")
        logger.debug("[OIDC SERVICE] generate_authorization_code called")
        logger.debug("[OIDC SERVICE] Current UTC time: %s", datetime.now(timezone.utc).isoformat() + "Z")
        logger.debug("[OIDC SERVICE] client_id=%s, user_id=%s", client_id, user_id)
        logger.debug("[OIDC SERVICE] redirect_uri=%s", redirect_uri)
        logger.debug("[OIDC SERVICE] scope=%s", scope)
        logger.debug("[OIDC SERVICE] state=%s, nonce=%s", state, nonce)
        
        # Validate client exists and is active
        client = OIDCClient.query.filter_by(client_id=client_id).first()
        
        # Development-only debug logging for client validation
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Generate auth code - Client validation: client_id={client_id}, exists={client is not None}")
        
        if not client:
            raise NotFoundError("Client not found")
        
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Generate auth code - Client active validation: client_id={client_id}, is_active={client.is_active}")
        
        if not client.is_active:
            raise ValidationError("Client is not active")
        
        # Validate redirect URI
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Generate auth code - Redirect URI validation: client_id={client_id}, redirect_uri={redirect_uri}")
        
        if not client.is_redirect_uri_allowed(redirect_uri):
            raise ValidationError("Invalid redirect_uri")
        
        # Validate scopes
        allowed_scopes = client.scopes or []
        valid_scopes = [s for s in scope if s in allowed_scopes]
        
        if not valid_scopes:
            raise ValidationError("Invalid scopes")
        
        # Generate authorization code
        logger.debug("[OIDC SERVICE] Generating authorization code...")
        logger.debug("[OIDC SERVICE] Current UTC time before code generation: %s", datetime.now(timezone.utc).isoformat() + "Z")
        code = cls._generate_code()
        code_hash = cls._hash_value(code)
        logger.debug("[OIDC SERVICE] Code generated: %s...", code[:20] if code else None)
        
        # Development-only debug logging for PKCE in code creation
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Generate auth code - PKCE: code_challenge={code_challenge is not None}, code_challenge_method={code_challenge_method}")
        
        # Create auth code record
        logger.debug("[OIDC SERVICE] Creating auth code record with lifetime_seconds=600 (10 minutes)")
        logger.debug("[OIDC SERVICE] Current UTC time before creating auth code: %s", datetime.now(timezone.utc).isoformat() + "Z")
        auth_code = OIDCAuthCode.create_code(
            client_id=client.id,
            user_id=user_id,
            code_hash=code_hash,
            redirect_uri=redirect_uri,
            scope=valid_scopes,
            nonce=nonce,
            code_verifier=code_challenge,  # Store for validation
            ip_address=ip_address,
            user_agent=user_agent,
            lifetime_seconds=600,  # 10 minutes
        )
        logger.debug("[OIDC SERVICE] Auth code created successfully")
        logger.debug("[OIDC SERVICE] Auth code expires_at (UTC): %s", auth_code.expires_at.isoformat() + "Z")
        logger.debug("[OIDC SERVICE] Current UTC time after creating auth code: %s", datetime.now(timezone.utc).isoformat() + "Z")
        
        # Log authorization event — use client.id (UUID) not client_id (string) for FK
        OIDCAuditService.log_authorization_event(
            client_id=client.id,
            user_id=user_id,
            success=True,
            redirect_uri=redirect_uri,
            scope=valid_scopes,
        )
        
        logger.debug("[OIDC SERVICE] generate_authorization_code completed successfully")
        logger.debug("[OIDC SERVICE] Final UTC time: %s", datetime.now(timezone.utc).isoformat() + "Z")
        logger.debug("[OIDC SERVICE] ===========================================")
        return code
    
    @classmethod
    def validate_authorization_code(
        cls,
        code: str,
        client_id: str,
        redirect_uri: str,
        code_verifier: str = None,
        ip_address: str = None,
        user_agent: str = None
    ) -> Tuple[Dict, User]:
        """Validate and consume an authorization code.
        
        Args:
            code: Authorization code
            client_id: OIDC client ID
            redirect_uri: Redirect URI
            code_verifier: PKCE code verifier (required if PKCE was used)
            ip_address: Client IP address
            user_agent: Client user agent
        
        Returns:
            Tuple of (claims dict, User instance)
        
        Raises:
            InvalidGrantError: If code is invalid
            ValidationError: If PKCE validation fails
        """
        logger.debug("[OIDC SERVICE] ===========================================")
        logger.debug("[OIDC SERVICE] validate_authorization_code called")
        logger.debug("[OIDC SERVICE] Current UTC time: %s", datetime.now(timezone.utc).isoformat() + "Z")
        logger.debug("[OIDC SERVICE] client_id=%s, redirect_uri=%s", client_id, redirect_uri)
        logger.debug("[OIDC SERVICE] code_verifier provided: %s", bool(code_verifier))
        
        # Get client
        client = OIDCClient.query.filter_by(client_id=client_id).first()
        
        # Development-only debug logging for client validation in code validation
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Validate auth code - Client validation: client_id={client_id}, exists={client is not None}")
        
        if not client:
            logger.error(f"[OIDC] Validate auth code - Client not found: client_id={client_id}")
            raise InvalidGrantError("Invalid client")
        
        # Hash the provided code and find matching auth code
        logger.debug("[OIDC SERVICE] Looking up authorization code...")
        logger.debug("[OIDC SERVICE] Current UTC time before code lookup: %s", datetime.now(timezone.utc).isoformat() + "Z")
        code_hash = cls._hash_value(code)
        auth_code = OIDCAuthCode.query.filter_by(
            code_hash=code_hash,
            client_id=client.id,
            deleted_at=None
        ).first()
        
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Validate auth code - Code lookup: code_hash={code_hash[:20]}..., found={auth_code is not None}")
        
        if not auth_code:
            logger.error(f"[OIDC] Validate auth code - Code not found or deleted: code_hash={code_hash[:20]}...")
            OIDCAuditService.log_authorization_event(
                client_id=client.id,
                success=False,
                error_code="invalid_grant",
                error_description="Invalid or expired authorization code",
            )
            raise InvalidGrantError("Invalid or expired authorization code")
        
        # Check if already used
        if auth_code.is_used:
            logger.error(f"[OIDC] Validate auth code - Code already used: code_hash={code_hash[:20]}..., user_id={auth_code.user_id}")
            OIDCAuditService.log_authorization_event(
                client_id=client.id,
                user_id=auth_code.user_id,
                success=False,
                error_code="invalid_grant",
                error_description="Authorization code already used",
            )
            raise InvalidGrantError("Authorization code already used")
        
        # Check expiration
        logger.debug("[OIDC SERVICE] Checking if authorization code is expired...")
        logger.debug("[OIDC SERVICE] Current UTC time: %s", datetime.now(timezone.utc).isoformat() + "Z")
        logger.debug("[OIDC SERVICE] Auth code expires_at (UTC): %s", auth_code.expires_at.isoformat() + "Z")
        # Handle timezone-naive expires_at from database
        expires_at = auth_code.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        logger.debug("[OIDC SERVICE] Time until expiration (seconds): %s", (expires_at - datetime.now(timezone.utc)).total_seconds())
        
        if auth_code.is_expired():
            logger.error("[OIDC] Validate auth code - Code expired: code_hash=%s..., expires_at (UTC)=%s, current UTC time=%s",
                        code_hash[:20], auth_code.expires_at.isoformat() + "Z", datetime.now(timezone.utc).isoformat() + "Z")
            OIDCAuditService.log_authorization_event(
                client_id=client.id,
                user_id=auth_code.user_id,
                success=False,
                error_code="invalid_grant",
                error_description="Authorization code expired",
            )
            raise InvalidGrantError("Authorization code expired")
        
        # Validate redirect URI
        if auth_code.redirect_uri != redirect_uri:
            logger.error(f"[OIDC] Validate auth code - Redirect URI mismatch: expected={auth_code.redirect_uri}, got={redirect_uri}")
            raise InvalidGrantError("Invalid redirect_uri")
        
        # Validate PKCE if required
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Validate auth code - PKCE: require_pkce={client.require_pkce}, has_verifier={bool(auth_code.code_verifier)}, provided_verifier={bool(code_verifier)}")
        
        if client.require_pkce and auth_code.code_verifier:
            if not code_verifier:
                logger.error(f"[OIDC] Validate auth code - PKCE required but no code_verifier provided")
                raise ValidationError("code_verifier is required")
            
            # Verify code verifier
            expected_challenge = cls._compute_code_challenge(code_verifier, "S256")
            if expected_challenge != auth_code.code_verifier:
                logger.error(f"[OIDC] Validate auth code - Invalid code_verifier: expected={expected_challenge[:20]}..., got={auth_code.code_verifier[:20]}...")
                OIDCAuditService.log_authorization_event(
                    client_id=client.id,
                    user_id=auth_code.user_id,
                    success=False,
                    error_code="invalid_grant",
                    error_description="Invalid code_verifier",
                )
                raise InvalidGrantError("Invalid code_verifier")
        
        # Mark code as used
        auth_code.mark_as_used()
        
        # Get user
        user = User.query.get(auth_code.user_id)
        
        # Development-only debug logging for user validation
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Validate auth code - User validation: user_id={auth_code.user_id}, exists={user is not None}")
        
        if not user:
            logger.error(f"[OIDC] Validate auth code - User not found: user_id={auth_code.user_id}")
            raise InvalidGrantError("User not found")
        
        claims = {
            "user_id": auth_code.user_id,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": auth_code.scope,
            "nonce": auth_code.nonce,
        }
        
        logger.debug("[OIDC SERVICE] validate_authorization_code completed successfully")
        logger.debug("[OIDC SERVICE] Final UTC time: %s", datetime.now(timezone.utc).isoformat() + "Z")
        logger.debug("[OIDC SERVICE] ===========================================")
        return claims, user
    
    @classmethod
    def _compute_code_challenge(cls, verifier: str, method: str = "S256") -> str:
        """Compute PKCE code challenge from verifier.
        
        Args:
            verifier: Code verifier
            method: Challenge method
        
        Returns:
            Code challenge
        """
        import hashlib
        import base64
        
        if method == "S256":
            digest = hashlib.sha256(verifier.encode()).digest()
            return base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return verifier
    
    @classmethod
    def generate_tokens(
        cls,
        client_id: str,
        user_id: str,
        scope: list,
        nonce: str = None,
        refresh_token: str = None,
        ip_address: str = None,
        user_agent: str = None,
        auth_time: int = None
    ) -> Dict:
        """Generate access token, ID token, and refresh token.
        
        Args:
            client_id: OIDC client ID
            user_id: User ID
            scope: Granted scopes
            nonce: Nonce for ID token
            refresh_token: Existing refresh token (for rotation)
            ip_address: Client IP address
            user_agent: Client user agent
            auth_time: Authentication time
        
        Returns:
            Dictionary with tokens
        """
        import hashlib
        
        logger.debug("[OIDC SERVICE] ===========================================")
        logger.debug("[OIDC SERVICE] generate_tokens called")
        logger.debug("[OIDC SERVICE] Current UTC time: %s", datetime.now(timezone.utc).isoformat() + "Z")
        logger.debug("[OIDC SERVICE] client_id=%s, user_id=%s, scope=%s", client_id, user_id, scope)
        logger.debug("[OIDC SERVICE] nonce=%s, auth_time=%s", nonce, auth_time)
        
        # Get client
        client = OIDCClient.query.filter_by(client_id=client_id).first()
        
        # Development-only debug logging for token generation client validation
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Generate tokens - Client validation: client_id={client_id}, exists={client is not None}")
        
        if not client:
            raise InvalidClientError()
        
        # Generate access token
        logger.debug("[OIDC SERVICE] Generating access token...")
        logger.debug("[OIDC SERVICE] Current UTC time before access token generation: %s", datetime.now(timezone.utc).isoformat() + "Z")
        logger.debug("[OIDC SERVICE] Access token lifetime (seconds): %s", client.access_token_lifetime or 3600)
        access_token_jti = OIDCTokenService._generate_jti()
        access_token = OIDCTokenService.create_access_token(
            client_id=client_id,
            user_id=user_id,
            scope=scope,
            jti=access_token_jti,
        )
        logger.debug("[OIDC SERVICE] Access token generated successfully")
        logger.debug("[OIDC SERVICE] Current UTC time after access token generation: %s", datetime.now(timezone.utc).isoformat() + "Z")
        
        # Generate ID token
        logger.debug("[OIDC SERVICE] Generating ID token...")
        logger.debug("[OIDC SERVICE] Current UTC time before ID token generation: %s", datetime.now(timezone.utc).isoformat() + "Z")
        logger.debug("[OIDC SERVICE] ID token lifetime (seconds): %s", client.id_token_lifetime or 3600)
        id_token = OIDCTokenService.create_id_token(
            client_id=client_id,
            user_id=user_id,
            nonce=nonce,
            scope=scope,
            access_token=access_token,
            auth_time=auth_time,
        )
        logger.debug("[OIDC SERVICE] ID token generated successfully")
        logger.debug("[OIDC SERVICE] Current UTC time after ID token generation: %s", datetime.now(timezone.utc).isoformat() + "Z")
        
        # Generate or rotate refresh token
        if "refresh_token" in (client.grant_types or []):
            if refresh_token:
                # Rotate existing refresh token
                refresh_token_obj = OIDCRefreshToken.query.filter_by(
                    token_hash=hashlib.sha256(refresh_token.encode()).hexdigest(),
                    deleted_at=None
                ).first()
                
                if refresh_token_obj and refresh_token_obj.is_valid():
                    # Create new refresh token
                    new_refresh, new_hash = OIDCTokenService.create_refresh_token(
                        client_id=client_id,
                        user_id=user_id,
                        scope=scope,
                        access_token_id=access_token_jti,
                    )
                    
                    # Rotate in database
                    refresh_token_obj.rotate(new_hash)
                    final_refresh_token = new_refresh
                else:
                    final_refresh_token = None
            else:
                # Create new refresh token
                final_refresh_token, refresh_hash = OIDCTokenService.create_refresh_token(
                    client_id=client_id,
                    user_id=user_id,
                    scope=scope,
                    access_token_id=access_token_jti,
                )
                
                # Store refresh token
                OIDCRefreshToken.create_token(
                    client_id=client.id,
                    user_id=user_id,
                    token_hash=refresh_hash,
                    scope=scope,
                    access_token_id=access_token_jti,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    lifetime_seconds=client.refresh_token_lifetime or 2592000,
                )
        else:
            final_refresh_token = None
        
        # Store token metadata
        client_db_id = client.id
        
        # Access token metadata
        logger.debug("[OIDC SERVICE] Creating access token metadata...")
        access_token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=client.access_token_lifetime or 3600)
        logger.debug("[OIDC SERVICE] Access token expires_at (UTC): %s", access_token_expires_at.isoformat() + "Z")
        OIDCTokenMetadata.create_metadata(
            client_id=client_db_id,
            user_id=user_id,
            token_type="access_token",
            token_jti=access_token_jti,
            expires_at=access_token_expires_at,
        )
        
        # ID token metadata (using access token JTI as reference)
        logger.debug("[OIDC SERVICE] Creating ID token metadata...")
        id_token_jti = OIDCTokenService._generate_jti()
        id_token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=client.id_token_lifetime or 3600)
        logger.debug("[OIDC SERVICE] ID token expires_at (UTC): %s", id_token_expires_at.isoformat() + "Z")
        OIDCTokenMetadata.create_metadata(
            client_id=client_db_id,
            user_id=user_id,
            token_type="id_token",
            token_jti=id_token_jti,
            expires_at=id_token_expires_at,
        )
        
        # Log token event — use client.id (UUID) not client_id (string) for FK
        OIDCAuditService.log_token_event(
            client_id=client.id,
            user_id=user_id,
            token_type="access_token",
            success=True,
            grant_type="authorization_code",
            scopes=scope,
        )
        
        result = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": client.access_token_lifetime or 3600,
            "id_token": id_token,
        }
        
        if final_refresh_token:
            result["refresh_token"] = final_refresh_token
        
        logger.debug("[OIDC SERVICE] generate_tokens completed successfully")
        logger.debug("[OIDC SERVICE] Final UTC time: %s", datetime.now(timezone.utc).isoformat() + "Z")
        logger.debug("[OIDC SERVICE] ===========================================")
        return result
    
    @classmethod
    def refresh_access_token(
        cls,
        refresh_token: str,
        client_id: str,
        scope: list = None,
        ip_address: str = None,
        user_agent: str = None
    ) -> Dict:
        """Refresh an access token with token rotation.
        
        Args:
            refresh_token: The refresh token
            client_id: OIDC client ID
            scope: Optional scope override
            ip_address: Client IP address
            user_agent: Client user agent
        
        Returns:
            Dictionary with new tokens
        
        Raises:
            InvalidGrantError: If refresh token is invalid
        """
        import hashlib
        
        logger.debug("[OIDC SERVICE] ===========================================")
        logger.debug("[OIDC SERVICE] refresh_access_token called")
        logger.debug("[OIDC SERVICE] Current UTC time: %s", datetime.now(timezone.utc).isoformat() + "Z")
        logger.debug("[OIDC SERVICE] client_id=%s, scope=%s", client_id, scope)
        
        # Get client
        client = OIDCClient.query.filter_by(client_id=client_id).first()
        
        # Development-only debug logging for refresh token client validation
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Refresh token - Client validation: client_id={client_id}, exists={client is not None}")
        
        if not client:
            raise InvalidClientError()
        
        # Find refresh token
        logger.debug("[OIDC SERVICE] Looking up refresh token...")
        logger.debug("[OIDC SERVICE] Current UTC time before refresh token lookup: %s", datetime.now(timezone.utc).isoformat() + "Z")
        token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
        refresh_token_obj = OIDCRefreshToken.query.filter_by(
            token_hash=token_hash,
            deleted_at=None
        ).first()
        
        # Development-only debug logging for refresh token validation
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Refresh token - Token validation: user_id={refresh_token_obj.user_id if refresh_token_obj else None}, found={refresh_token_obj is not None}")
        
        if not refresh_token_obj:
            OIDCAuditService.log_token_event(
                client_id=client.id,
                success=False,
                error_code="invalid_grant",
                error_description="Invalid refresh token",
            )
            raise InvalidGrantError("Invalid refresh token")
        
        # Check if valid
        logger.debug("[OIDC SERVICE] Checking if refresh token is valid...")
        logger.debug("[OIDC SERVICE] Current UTC time: %s", datetime.now(timezone.utc).isoformat() + "Z")
        if refresh_token_obj:
            logger.debug("[OIDC SERVICE] Refresh token expires_at (UTC): %s", refresh_token_obj.expires_at.isoformat() + "Z")
            # Handle timezone-naive expires_at from database
            rt_expires_at = refresh_token_obj.expires_at
            if rt_expires_at.tzinfo is None:
                rt_expires_at = rt_expires_at.replace(tzinfo=timezone.utc)
            logger.debug("[OIDC SERVICE] Time until expiration (seconds): %s", (rt_expires_at - datetime.now(timezone.utc)).total_seconds())
        
        if not refresh_token_obj.is_valid():
            OIDCAuditService.log_token_event(
                client_id=client.id,
                user_id=refresh_token_obj.user_id,
                success=False,
                error_code="invalid_grant",
                error_description="Refresh token expired or revoked",
            )
            raise InvalidGrantError("Refresh token expired or revoked")
        
        # Validate client matches
        if current_app.config.get('ENV') == 'development':
            logger.debug(f"[OIDC] Refresh token - Client match validation: expected={client.id}, actual={refresh_token_obj.client_id}, match={refresh_token_obj.client_id == client.id}")
        
        if refresh_token_obj.client_id != client.id:
            raise InvalidGrantError("Client mismatch")
        
        # Get original scope or use provided
        granted_scope = scope or (refresh_token_obj.scope or [])
        
        # Generate new access token
        logger.debug("[OIDC SERVICE] Generating new access token...")
        logger.debug("[OIDC SERVICE] Current UTC time before access token generation: %s", datetime.now(timezone.utc).isoformat() + "Z")
        logger.debug("[OIDC SERVICE] Access token lifetime (seconds): %s", client.access_token_lifetime or 3600)
        access_token_jti = OIDCTokenService._generate_jti()
        access_token = OIDCTokenService.create_access_token(
            client_id=client_id,
            user_id=refresh_token_obj.user_id,
            scope=granted_scope,
            jti=access_token_jti,
        )
        logger.debug("[OIDC SERVICE] Access token generated successfully")
        logger.debug("[OIDC SERVICE] Current UTC time after access token generation: %s", datetime.now(timezone.utc).isoformat() + "Z")
        
        # Generate new ID token
        logger.debug("[OIDC SERVICE] Generating new ID token...")
        logger.debug("[OIDC SERVICE] Current UTC time before ID token generation: %s", datetime.now(timezone.utc).isoformat() + "Z")
        logger.debug("[OIDC SERVICE] ID token lifetime (seconds): %s", client.id_token_lifetime or 3600)
        id_token = OIDCTokenService.create_id_token(
            client_id=client_id,
            user_id=refresh_token_obj.user_id,
            scope=granted_scope,
            access_token=access_token,
        )
        logger.debug("[OIDC SERVICE] ID token generated successfully")
        logger.debug("[OIDC SERVICE] Current UTC time after ID token generation: %s", datetime.now(timezone.utc).isoformat() + "Z")
        
        # Rotate refresh token
        new_refresh, new_hash = OIDCTokenService.create_refresh_token(
            client_id=client_id,
            user_id=refresh_token_obj.user_id,
            scope=granted_scope,
            access_token_id=access_token_jti,
        )
        
        refresh_token_obj.rotate(new_hash)
        
        # Store new token metadata
        logger.debug("[OIDC SERVICE] Creating access token metadata...")
        access_token_expires_at = datetime.now(timezone.utc) + timedelta(seconds=client.access_token_lifetime or 3600)
        logger.debug("[OIDC SERVICE] Access token expires_at (UTC): %s", access_token_expires_at.isoformat() + "Z")
        OIDCTokenMetadata.create_metadata(
            client_id=client.id,
            user_id=refresh_token_obj.user_id,
            token_type="access_token",
            token_jti=access_token_jti,
            expires_at=access_token_expires_at,
        )
        
        # Log refresh event — use client.id (UUID) not client_id (string) for FK
        OIDCAuditService.log_token_event(
            client_id=client.id,
            user_id=refresh_token_obj.user_id,
            token_type="access_token",
            success=True,
            grant_type="refresh_token",
            scopes=granted_scope,
        )
        
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": client.access_token_lifetime or 3600,
            "id_token": id_token,
            "refresh_token": new_refresh,
        }
        
        logger.debug("[OIDC SERVICE] refresh_access_token completed successfully")
        logger.debug("[OIDC SERVICE] Final UTC time: %s", datetime.now(timezone.utc).isoformat() + "Z")
        logger.debug("[OIDC SERVICE] ===========================================")
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": client.access_token_lifetime or 3600,
            "id_token": id_token,
            "refresh_token": new_refresh,
        }
    
    @classmethod
    def validate_access_token(cls, token: str, client_id: str = None) -> Dict:
        """Validate an access token and return its claims.
        
        Args:
            token: JWT access token
            client_id: Optional client ID to validate audience
        
        Returns:
            Token claims
        
        Raises:
            InvalidTokenError: If token is invalid
        """
        logger.debug("[OIDC SERVICE] ===========================================")
        logger.debug("[OIDC SERVICE] validate_access_token() called")
        logger.debug("[OIDC SERVICE] Token (first 50 chars): %s...", token[:50] if len(token) > 50 else token)
        logger.debug("[OIDC SERVICE] Token length: %d", len(token))
        logger.debug("[OIDC SERVICE] Client ID: %s", client_id)
        
        try:
            logger.debug("[OIDC SERVICE] Calling OIDCTokenService.validate_access_token()...")
            claims = OIDCTokenService.validate_access_token(token, client_id)
            logger.debug("[OIDC SERVICE] Token validation successful")
            logger.debug("[OIDC SERVICE] Token claims: %s", claims)
            logger.debug("[OIDC SERVICE] ===========================================")
            return claims
        except Exception as e:
            logger.error("[OIDC SERVICE] Token validation failed: %s: %s", type(e).__name__, str(e))
            import traceback
            logger.error("[OIDC SERVICE] Traceback: %s", traceback.format_exc())
            # Resolve internal client UUID for FK if possible
            _client_db_id = None
            if client_id:
                _c = OIDCClient.query.filter_by(client_id=client_id).first()
                _client_db_id = _c.id if _c else None
            OIDCAuditService.log_event(
                event_type="token_validation",
                client_id=_client_db_id,
                success=False,
                error_code="invalid_token",
                error_description=str(e),
            )
            raise InvalidTokenError(str(e))
    
    @classmethod
    def revoke_token(
        cls,
        token: str,
        client_id: str,
        token_type_hint: str = None,
        ip_address: str = None,
        user_agent: str = None
    ) -> bool:
        """Revoke a token.
        
        Args:
            token: Token to revoke
            client_id: OIDC client ID
            token_type_hint: Hint about token type
            ip_address: Client IP address
            user_agent: Client user agent
        
        Returns:
            True if token was revoked
        """
        import hashlib
        
        # Get client
        client = OIDCClient.query.filter_by(client_id=client_id).first()
        if not client:
            raise InvalidClientError()
        
        revoked = False
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        
        # Try to revoke as refresh token
        if token_type_hint in (None, "refresh_token"):
            refresh_token = OIDCRefreshToken.query.filter_by(
                token_hash=token_hash,
                deleted_at=None
            ).first()
            
            if refresh_token:
                refresh_token.revoke(reason="revoked_by_client")
                revoked = True
                
                OIDCAuditService.log_token_revocation_event(
                    client_id=client.id,
                    user_id=refresh_token.user_id,
                    token_type="refresh_token",
                    reason="revoked_by_client",
                )
        
        # Try to revoke as access token (JTI lookup)
        if not revoked or token_type_hint in (None, "access_token"):
            try:
                # Decode token to get JTI
                claims = OIDCTokenService.decode_token(token)
                jti = claims.get("jti")
                
                if jti:
                    revoked_at = OIDCTokenMetadata.revoke_by_jti(
                        jti,
                        reason="revoked_by_client"
                    )
                    if revoked_at:
                        revoked = True
                        
                        OIDCAuditService.log_token_revocation_event(
                            client_id=client.id,
                            user_id=claims.get("sub"),
                            token_type="access_token",
                            reason="revoked_by_client",
                        )
            except Exception:
                pass
        
        return revoked
    
    @classmethod
    def introspect_token(
        cls,
        token: str,
        client_id: str = None,
        ip_address: str = None,
        user_agent: str = None
    ) -> Dict:
        """Introspect a token and return its status and claims.
        
        Args:
            token: Token to introspect
            client_id: Client ID for validation
            ip_address: Client IP address
            user_agent: Client user agent
        
        Returns:
            Introspection response
        """
        result = OIDCTokenService.introspect_token(token, client_id)
        
        # Log introspection — resolve internal client UUID for FK
        _introspect_client_db_id = None
        if client_id:
            _ic = OIDCClient.query.filter_by(client_id=client_id).first()
            _introspect_client_db_id = _ic.id if _ic else None
        OIDCAuditService.log_event(
            event_type="token_introspection",
            client_id=_introspect_client_db_id,
            user_id=result.get("sub"),
            success=result.get("active", False),
            metadata={"active": result.get("active")},
        )
        
        return result
    
    @classmethod
    def get_jwks(cls) -> Dict:
        """Get the JWKS document.
        
        Returns:
            JWKS document
        """
        jwks_service = OIDCJWKSService()
        return jwks_service.get_jwks()
    
    @classmethod
    def get_userinfo(cls, access_token: str) -> Dict:
        """Get user information using access token.
        
        Args:
            access_token: Access token
        
        Returns:
            User information dictionary
        """
        logger.debug("[OIDC SERVICE] ===========================================")
        logger.debug("[OIDC SERVICE] get_userinfo() called")
        logger.debug("[OIDC SERVICE] Access token (first 50 chars): %s...", access_token[:50] if len(access_token) > 50 else access_token)
        logger.debug("[OIDC SERVICE] Access token length: %d", len(access_token))
        
        # Validate access token
        logger.debug("[OIDC SERVICE] Validating access token...")
        claims = cls.validate_access_token(access_token)
        logger.debug("[OIDC SERVICE] Access token validated successfully")
        logger.debug("[OIDC SERVICE] Token claims: %s", claims)
        
        user_id = claims.get("sub")
        logger.debug("[OIDC SERVICE] User ID from token: %s", user_id)
        
        logger.debug("[OIDC SERVICE] Querying user from database...")
        user = User.query.get(user_id)
        logger.debug("[OIDC SERVICE] User query result: %s", user)
        
        if not user:
            logger.error("[OIDC SERVICE] User not found in database: user_id=%s", user_id)
            raise NotFoundError("User not found")
        
        logger.debug("[OIDC SERVICE] User found: user_id=%s, email=%s, full_name=%s", user.id, user.email, user.full_name)
        
        # Get scopes from token
        scope_str = claims.get("scope", "")
        scopes = scope_str.split() if scope_str else []
        logger.debug("[OIDC SERVICE] Scope string from token: '%s'", scope_str)
        logger.debug("[OIDC SERVICE] Parsed scopes: %s", scopes)
        
        userinfo = {"sub": user_id}
        logger.debug("[OIDC SERVICE] Initial userinfo: %s", userinfo)
        
        # Add claims based on scope
        if "profile" in scopes and user.full_name:
            logger.debug("[OIDC SERVICE] Found 'profile' in scope, adding name claim")
            userinfo["name"] = user.full_name
            logger.debug("[OIDC SERVICE] Added name: %s", user.full_name)
        else:
            logger.debug("[OIDC SERVICE] 'profile' not in scope or user.full_name is None: profile_in_scope=%s, full_name=%s", "profile" in scopes, user.full_name)
        
        if "email" in scopes:
            logger.debug("[OIDC SERVICE] Found 'email' in scope, adding email claims")
            userinfo["email"] = user.email
            userinfo["email_verified"] = user.email_verified
            logger.debug("[OIDC SERVICE] Added email: %s, email_verified: %s", user.email, user.email_verified)
        else:
            logger.debug("[OIDC SERVICE] 'email' not in scope")
        
        if "roles" in scopes:
            logger.debug("[OIDC SERVICE] Found 'roles' in scope, adding roles claim")
            user_roles = cls._get_user_roles(user)
            userinfo["roles"] = user_roles
            logger.debug("[OIDC SERVICE] Added roles: %s", user_roles)
        else:
            logger.debug("[OIDC SERVICE] 'roles' not in scope")
        
        logger.debug("[OIDC SERVICE] Final userinfo: %s", userinfo)
        
        # Log userinfo access — resolve internal client UUID for FK
        logger.debug("[OIDC SERVICE] Logging userinfo access event...")
        _userinfo_client_id_str = claims.get("client_id")
        _userinfo_client_db_id = None
        if _userinfo_client_id_str:
            _uc = OIDCClient.query.filter_by(client_id=_userinfo_client_id_str).first()
            _userinfo_client_db_id = _uc.id if _uc else None
        OIDCAuditService.log_userinfo_event(
            access_token=access_token,
            user_id=user_id,
            client_id=_userinfo_client_db_id,
            success=True,
            scopes_claimed=scopes,
        )
        logger.debug("[OIDC SERVICE] Userinfo access event logged")
        
        logger.debug("[OIDC SERVICE] get_userinfo() completed successfully")
        logger.debug("[OIDC SERVICE] ===========================================")
        
        return userinfo
    
    @staticmethod
    def _get_user_roles(user: User) -> list:
        """Get user's organization roles.
        
        Args:
            user: User instance
        
        Returns:
            List of role objects with organization_id and role
        """
        logger.debug("[OIDC SERVICE] _get_user_roles() called")
        logger.debug("[OIDC SERVICE] User: %s", user)
        
        roles = []
        
        if not user:
            logger.debug("[OIDC SERVICE] User is None, returning empty roles list")
            return roles
        
        logger.debug("[OIDC SERVICE] User ID: %s", user.id)
        logger.debug("[OIDC SERVICE] User email: %s", user.email)
        logger.debug("[OIDC SERVICE] User organization_memberships: %s", user.organization_memberships)
        
        if user.organization_memberships:
            logger.debug("[OIDC SERVICE] User has %d organization memberships", len(user.organization_memberships))
            for idx, member in enumerate(user.organization_memberships):
                logger.debug("[OIDC SERVICE] Processing membership %d: member=%s", idx, member)
                logger.debug("[OIDC SERVICE]   organization_id: %s", member.organization_id)
                logger.debug("[OIDC SERVICE]   role: %s", member.role)
                logger.debug("[OIDC SERVICE]   role.value: %s", member.role.value)
                
                role_entry = {
                    "organization_id": str(member.organization_id),
                    "role": member.role.value
                }
                roles.append(role_entry)
                logger.debug("[OIDC SERVICE]   Added role entry: %s", role_entry)
        else:
            logger.debug("[OIDC SERVICE] User has no organization memberships")
        
        logger.debug("[OIDC SERVICE] Final roles list: %s", roles)
        logger.debug("[OIDC SERVICE] _get_user_roles() completed")
        
        return roles
