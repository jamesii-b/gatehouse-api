"""External authentication provider service."""
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple, Dict, Any

from flask import current_app

from gatehouse_app.extensions import db
from gatehouse_app.models import User, AuthenticationMethod
from gatehouse_app.models.auth.authentication_method import (
    OAuthState,
    ApplicationProviderConfig,
    OrganizationProviderOverride
)
from gatehouse_app.models.base import BaseModel
from gatehouse_app.utils.constants import AuthMethodType
from gatehouse_app.services.audit_service import AuditService

logger = logging.getLogger(__name__)


class ExternalAuthError(Exception):
    """Base exception for external auth errors."""

    def __init__(self, message: str, error_type: str, status_code: int = 400):
        self.message = message
        self.error_type = error_type
        self.status_code = status_code
        super().__init__(message)


class ExternalProviderConfig(BaseModel):
    """OAuth provider configuration per organization.
    
    DEPRECATED: This model is maintained for backward compatibility only.
    Use ApplicationProviderConfig and OrganizationProviderOverride instead.
    """

    __tablename__ = "external_provider_configs"

    # Organization reference
    organization_id = db.Column(
        db.String(36), db.ForeignKey("organizations.id"), nullable=False, index=True
    )

    # Provider type
    provider_type = db.Column(db.String(50), nullable=False, index=True)

    # OAuth credentials (client_secret is encrypted)
    client_id = db.Column(db.String(255), nullable=False)
    client_secret_encrypted = db.Column(db.String(512), nullable=True)

    # Provider endpoints
    auth_url = db.Column(db.String(2048), nullable=False)
    token_url = db.Column(db.String(2048), nullable=False)
    userinfo_url = db.Column(db.String(2048), nullable=True)
    jwks_url = db.Column(db.String(2048), nullable=True)

    # Configuration
    scopes = db.Column(db.JSON, nullable=False, default=list)
    redirect_uris = db.Column(db.JSON, nullable=False, default=list)

    # Provider-specific settings
    settings = db.Column(db.JSON, nullable=True)

    # Status
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    # Relationships
    organization = db.relationship(
        "Organization", back_populates="external_provider_configs"
    )

    # Indexes
    __table_args__ = (
        db.Index("idx_provider_config_org", "organization_id", "provider_type"),
        db.UniqueConstraint(
            "organization_id",
            "provider_type",
            name="uix_org_provider_type",
        ),
    )

    def get_client_secret(self) -> str:
        """Decrypt and return client secret."""
        from gatehouse_app.utils.encryption import decrypt
        if self.client_secret_encrypted:
            return decrypt(self.client_secret_encrypted)
        return None

    def set_client_secret(self, secret: str):
        """Encrypt and store client secret."""
        from gatehouse_app.utils.encryption import encrypt
        self.client_secret_encrypted = encrypt(secret)

    def is_redirect_uri_allowed(self, uri: str) -> bool:
        """Check if redirect URI is allowed."""
        return uri in (self.redirect_uris or [])

    def to_dict(self, include_secrets: bool = False) -> dict:
        """Convert to dictionary."""
        data = {
            "id": self.id,
            "organization_id": self.organization_id,
            "provider_type": self.provider_type,
            "client_id": self.client_id,
            "auth_url": self.auth_url,
            "token_url": self.token_url,
            "userinfo_url": self.userinfo_url,
            "scopes": self.scopes,
            "redirect_uris": self.redirect_uris,
            "is_active": self.is_active,
            "settings": self.settings,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
        if include_secrets and self.client_secret_encrypted:
            data["client_secret"] = self.get_client_secret()
        return data


class ProviderConfigAdapter:
    """
    Adapter to provide a unified interface for provider configuration.
    
    This merges application-level config with optional organization overrides,
    presenting a single config object that works with existing OAuth flow code.
    """
    
    def __init__(
        self,
        app_config: ApplicationProviderConfig,
        org_override: Optional[OrganizationProviderOverride] = None
    ):
        """
        Initialize adapter with app config and optional org override.
        
        Args:
            app_config: Application-level provider configuration
            org_override: Optional organization-specific override
        """
        self.app_config = app_config
        self.org_override = org_override
        self.provider_type = app_config.provider_type
    
    @property
    def client_id(self) -> str:
        """Get effective client ID (override takes precedence)."""
        if self.org_override and self.org_override.client_id:
            return self.org_override.client_id
        return self.app_config.client_id
    
    def get_client_secret(self) -> str:
        """Get effective client secret (override takes precedence)."""
        if self.org_override and self.org_override.client_secret_encrypted:
            return self.org_override.get_client_secret()
        return self.app_config.get_client_secret()
    
    @property
    def auth_url(self) -> str:
        """Get authorization URL from app config."""
        # Provider endpoints are not overridable
        return self._get_provider_endpoint('auth_url')
    
    @property
    def token_url(self) -> str:
        """Get token URL from app config."""
        return self._get_provider_endpoint('token_url')
    
    @property
    def userinfo_url(self) -> str:
        """Get userinfo URL from app config."""
        return self._get_provider_endpoint('userinfo_url')
    
    @property
    def jwks_url(self) -> str:
        """Get JWKS URL from app config."""
        return self._get_provider_endpoint('jwks_url')
    
    @property
    def scopes(self) -> list:
        """Get effective scopes (merged from app config and override)."""
        base_scopes = self.app_config.additional_config.get('scopes', []) if self.app_config.additional_config else []
        if self.org_override and self.org_override.additional_config:
            override_scopes = self.org_override.additional_config.get('scopes')
            if override_scopes is not None:
                return override_scopes
        return base_scopes or ['openid', 'profile', 'email']
    
    @property
    def redirect_uris(self) -> list:
        """Get effective redirect URIs."""
        # Use override redirect URL if present, otherwise app default
        if self.org_override and self.org_override.redirect_url_override:
            return [self.org_override.redirect_url_override]
        if self.app_config.default_redirect_url:
            return [self.app_config.default_redirect_url]
        return []
    
    @property
    def settings(self) -> dict:
        """Get merged settings (app config + org override)."""
        settings = {}
        if self.app_config.additional_config:
            settings.update(self.app_config.additional_config)
        if self.org_override and self.org_override.additional_config:
            settings.update(self.org_override.additional_config)
        return settings
    
    @property
    def is_active(self) -> bool:
        """Check if provider is active (both app and org must be enabled)."""
        app_enabled = self.app_config.is_enabled
        org_enabled = True if not self.org_override else self.org_override.is_enabled
        return app_enabled and org_enabled
    
    def is_redirect_uri_allowed(self, uri: str) -> bool:
        """Check if redirect URI is allowed."""
        return uri in self.redirect_uris
    
    def _get_provider_endpoint(self, endpoint_name: str) -> Optional[str]:
        """
        Get provider endpoint from app config additional_config.
        
        For application-wide configs, endpoints are stored in additional_config JSON.
        """
        if not self.app_config.additional_config:
            return None
        return self.app_config.additional_config.get(endpoint_name)


class ExternalAuthService:
    """Service for external authentication operations."""

    @classmethod
    def get_provider_config(
        cls,
        provider_type: AuthMethodType,
        organization_id: Optional[str] = None,
    ) -> ProviderConfigAdapter:
        """
        Get provider configuration for authentication.
        
        This method retrieves application-wide provider configuration and merges
        it with organization-specific overrides if present. Both the application
        config and organization override (if present) must be enabled for the
        provider to be considered active.
        
        Configuration Precedence:
        1. Application-level config provides the baseline configuration
        2. Organization override can override client_id and client_secret (for SSO)
        3. Both must be enabled for the provider to work
        
        Args:
            provider_type: The OAuth provider type (google, github, etc.)
            organization_id: Optional organization ID for override lookup
        
        Returns:
            ProviderConfigAdapter: Unified config object with merged settings
        
        Raises:
            ExternalAuthError: If provider is not configured or disabled
        """
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type
        
        # Get application-wide config
        app_config = ApplicationProviderConfig.query.filter_by(
            provider_type=provider_type_str
        ).first()
        
        if not app_config:
            raise ExternalAuthError(
                f"{provider_type_str.title()} OAuth is not configured for this application",
                "PROVIDER_NOT_CONFIGURED",
                400,
            )
        
        if not app_config.is_enabled:
            raise ExternalAuthError(
                f"{provider_type_str.title()} OAuth is currently disabled",
                "PROVIDER_DISABLED",
                400,
            )
        
        # Check for organization-specific override
        org_override = None
        if organization_id:
            org_override = OrganizationProviderOverride.query.filter_by(
                organization_id=organization_id,
                provider_type=provider_type_str
            ).first()
            
            # If override exists but is disabled, provider is not available for this org
            if org_override and not org_override.is_enabled:
                raise ExternalAuthError(
                    f"{provider_type_str.title()} OAuth is disabled for this organization",
                    "PROVIDER_DISABLED_FOR_ORG",
                    400,
                )
        
        # Return adapter with merged configuration
        return ProviderConfigAdapter(app_config, org_override)

    # ==================== Application-Wide Provider Management ====================
    
    @classmethod
    def create_app_provider_config(
        cls,
        provider_type: str,
        client_id: str,
        client_secret: str,
        **kwargs
    ) -> ApplicationProviderConfig:
        """
        Create application-wide provider configuration.
        
        Args:
            provider_type: Provider type (google, github, etc.)
            client_id: OAuth client ID
            client_secret: OAuth client secret
            **kwargs: Additional config (auth_url, token_url, userinfo_url, scopes, etc.)
        
        Returns:
            ApplicationProviderConfig: Created configuration
        
        Raises:
            ExternalAuthError: If provider already exists
        """
        # Check if provider already exists
        existing = ApplicationProviderConfig.query.filter_by(
            provider_type=provider_type
        ).first()
        
        if existing:
            raise ExternalAuthError(
                f"Provider {provider_type} already exists",
                "PROVIDER_EXISTS",
                400
            )
        
        # Build additional_config with endpoints and settings
        additional_config = {}
        for key in ['auth_url', 'token_url', 'userinfo_url', 'jwks_url', 'scopes']:
            if key in kwargs:
                additional_config[key] = kwargs.pop(key)
        
        # Add any extra settings
        if 'settings' in kwargs:
            additional_config.update(kwargs.pop('settings'))
        
        # Create new config
        config = ApplicationProviderConfig(
            provider_type=provider_type,
            client_id=client_id,
            is_enabled=kwargs.get('is_enabled', True),
            default_redirect_url=kwargs.get('default_redirect_url'),
            additional_config=additional_config
        )
        
        # Set encrypted secret
        config.set_client_secret(client_secret)
        config.save()
        
        logger.info(f"Created application provider config for {provider_type}")
        return config
    
    @classmethod
    def update_app_provider_config(
        cls,
        provider_type: str,
        **updates
    ) -> ApplicationProviderConfig:
        """
        Update application-wide provider configuration.
        
        Args:
            provider_type: Provider type to update
            **updates: Fields to update (client_id, client_secret, is_enabled, etc.)
        
        Returns:
            ApplicationProviderConfig: Updated configuration
        
        Raises:
            ExternalAuthError: If provider not found
        """
        config = ApplicationProviderConfig.query.filter_by(
            provider_type=provider_type
        ).first()
        
        if not config:
            raise ExternalAuthError(
                f"Provider {provider_type} not found",
                "PROVIDER_NOT_FOUND",
                404
            )
        
        # Update simple fields
        if 'client_id' in updates:
            config.client_id = updates['client_id']
        
        if 'client_secret' in updates:
            config.set_client_secret(updates['client_secret'])
        
        if 'is_enabled' in updates:
            config.is_enabled = updates['is_enabled']
        
        if 'default_redirect_url' in updates:
            config.default_redirect_url = updates['default_redirect_url']
        
        # Update additional_config JSON fields
        if config.additional_config is None:
            config.additional_config = {}
        
        for key in ['auth_url', 'token_url', 'userinfo_url', 'jwks_url', 'scopes']:
            if key in updates:
                config.additional_config[key] = updates[key]
        
        if 'settings' in updates:
            config.additional_config.update(updates['settings'])
        
        config.save()
        logger.info(f"Updated application provider config for {provider_type}")
        return config
    
    @classmethod
    def get_app_provider_config(cls, provider_type: str) -> ApplicationProviderConfig:
        """
        Get application-wide provider configuration.
        
        Args:
            provider_type: Provider type to retrieve
        
        Returns:
            ApplicationProviderConfig: Provider configuration
        
        Raises:
            ExternalAuthError: If provider not found
        """
        config = ApplicationProviderConfig.query.filter_by(
            provider_type=provider_type
        ).first()
        
        if not config:
            raise ExternalAuthError(
                f"Provider {provider_type} not found",
                "PROVIDER_NOT_FOUND",
                404
            )
        
        return config
    
    @classmethod
    def list_app_provider_configs(cls) -> list:
        """
        List all application-wide provider configurations.
        
        Returns:
            list: List of provider configuration dictionaries
        """
        configs = ApplicationProviderConfig.query.all()
        return [config.to_dict() for config in configs]
    
    @classmethod
    def delete_app_provider_config(cls, provider_type: str) -> bool:
        """
        Delete application-wide provider configuration.
        
        Args:
            provider_type: Provider type to delete
        
        Returns:
            bool: True if deleted successfully
        
        Raises:
            ExternalAuthError: If provider not found
        """
        config = ApplicationProviderConfig.query.filter_by(
            provider_type=provider_type
        ).first()
        
        if not config:
            raise ExternalAuthError(
                f"Provider {provider_type} not found",
                "PROVIDER_NOT_FOUND",
                404
            )
        
        config.delete()
        logger.info(f"Deleted application provider config for {provider_type}")
        return True
    
    # ==================== Organization Provider Override Management ====================
    
    @classmethod
    def create_org_provider_override(
        cls,
        organization_id: str,
        provider_type: str,
        **kwargs
    ) -> OrganizationProviderOverride:
        """
        Create organization-specific provider override (for SSO scenarios).
        
        Args:
            organization_id: Organization ID
            provider_type: Provider type to override
            **kwargs: Override fields (client_id, client_secret, redirect_url, etc.)
        
        Returns:
            OrganizationProviderOverride: Created override
        
        Raises:
            ExternalAuthError: If provider doesn't exist or override already exists
        """
        # Verify app-level provider exists
        app_config = ApplicationProviderConfig.query.filter_by(
            provider_type=provider_type
        ).first()
        
        if not app_config:
            raise ExternalAuthError(
                f"Application provider {provider_type} must be configured first",
                "PROVIDER_NOT_CONFIGURED",
                400
            )
        
        # Check if override already exists
        existing = OrganizationProviderOverride.query.filter_by(
            organization_id=organization_id,
            provider_type=provider_type
        ).first()
        
        if existing:
            raise ExternalAuthError(
                f"Override for {provider_type} already exists for this organization",
                "OVERRIDE_EXISTS",
                400
            )
        
        # Build additional_config from kwargs
        additional_config = {}
        if 'settings' in kwargs:
            additional_config.update(kwargs.pop('settings'))
        if 'scopes' in kwargs:
            additional_config['scopes'] = kwargs.pop('scopes')
        
        # Create override
        override = OrganizationProviderOverride(
            organization_id=organization_id,
            provider_type=provider_type,
            client_id=kwargs.get('client_id'),
            is_enabled=kwargs.get('is_enabled', True),
            redirect_url_override=kwargs.get('redirect_url_override'),
            additional_config=additional_config if additional_config else None
        )
        
        # Set encrypted secret if provided
        if 'client_secret' in kwargs:
            override.set_client_secret(kwargs['client_secret'])
        
        override.save()
        logger.info(f"Created org override for {provider_type} in org {organization_id}")
        return override
    
    @classmethod
    def update_org_provider_override(
        cls,
        organization_id: str,
        provider_type: str,
        **updates
    ) -> OrganizationProviderOverride:
        """
        Update organization-specific provider override.
        
        Args:
            organization_id: Organization ID
            provider_type: Provider type
            **updates: Fields to update
        
        Returns:
            OrganizationProviderOverride: Updated override
        
        Raises:
            ExternalAuthError: If override not found
        """
        override = OrganizationProviderOverride.query.filter_by(
            organization_id=organization_id,
            provider_type=provider_type
        ).first()
        
        if not override:
            raise ExternalAuthError(
                f"Override for {provider_type} not found for this organization",
                "OVERRIDE_NOT_FOUND",
                404
            )
        
        # Update simple fields
        if 'client_id' in updates:
            override.client_id = updates['client_id']
        
        if 'client_secret' in updates:
            override.set_client_secret(updates['client_secret'])
        
        if 'is_enabled' in updates:
            override.is_enabled = updates['is_enabled']
        
        if 'redirect_url_override' in updates:
            override.redirect_url_override = updates['redirect_url_override']
        
        # Update additional_config
        if 'settings' in updates or 'scopes' in updates:
            if override.additional_config is None:
                override.additional_config = {}
            
            if 'settings' in updates:
                override.additional_config.update(updates['settings'])
            if 'scopes' in updates:
                override.additional_config['scopes'] = updates['scopes']
        
        override.save()
        logger.info(f"Updated org override for {provider_type} in org {organization_id}")
        return override
    
    @classmethod
    def get_org_provider_override(
        cls,
        organization_id: str,
        provider_type: str
    ) -> OrganizationProviderOverride:
        """
        Get organization-specific provider override.
        
        Args:
            organization_id: Organization ID
            provider_type: Provider type
        
        Returns:
            OrganizationProviderOverride: Provider override
        
        Raises:
            ExternalAuthError: If override not found
        """
        override = OrganizationProviderOverride.query.filter_by(
            organization_id=organization_id,
            provider_type=provider_type
        ).first()
        
        if not override:
            raise ExternalAuthError(
                f"Override for {provider_type} not found for this organization",
                "OVERRIDE_NOT_FOUND",
                404
            )
        
        return override
    
    @classmethod
    def list_org_provider_overrides(cls, organization_id: str) -> list:
        """
        List all provider overrides for an organization.
        
        Args:
            organization_id: Organization ID
        
        Returns:
            list: List of override configuration dictionaries
        """
        overrides = OrganizationProviderOverride.query.filter_by(
            organization_id=organization_id
        ).all()
        return [override.to_dict() for override in overrides]
    
    @classmethod
    def delete_org_provider_override(
        cls,
        organization_id: str,
        provider_type: str
    ) -> bool:
        """
        Delete organization-specific provider override.
        
        Args:
            organization_id: Organization ID
            provider_type: Provider type
        
        Returns:
            bool: True if deleted successfully
        
        Raises:
            ExternalAuthError: If override not found
        """
        override = OrganizationProviderOverride.query.filter_by(
            organization_id=organization_id,
            provider_type=provider_type
        ).first()
        
        if not override:
            raise ExternalAuthError(
                f"Override for {provider_type} not found for this organization",
                "OVERRIDE_NOT_FOUND",
                404
            )
        
        override.delete()
        logger.info(f"Deleted org override for {provider_type} in org {organization_id}")
        return True

    # ==================== OAuth Flow Methods (Updated for New Architecture) ====================

    @classmethod
    def initiate_link_flow(
        cls,
        user_id: str,
        provider_type: AuthMethodType,
        organization_id: str,
        redirect_uri: str = None,
    ) -> Tuple[str, str]:
        """
        Initiate account linking flow.

        Returns:
            Tuple of (redirect_url, state)
        """
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        # Get provider config (with org override if applicable)
        config = cls.get_provider_config(provider_type, organization_id)

        # Validate redirect URI
        if redirect_uri and not config.is_redirect_uri_allowed(redirect_uri):
            raise ExternalAuthError(
                "Invalid redirect URI",
                "INVALID_REDIRECT_URI",
                400,
            )

        # Generate PKCE
        code_verifier = secrets.token_urlsafe(32)
        code_challenge = cls._compute_s256_challenge(code_verifier)

        # Create OAuth state
        state = OAuthState.create_state(
            flow_type="link",
            provider_type=provider_type,
            user_id=user_id,
            organization_id=organization_id,
            redirect_uri=redirect_uri or config.redirect_uris[0] if config.redirect_uris else None,
            code_verifier=code_verifier,
            code_challenge=code_challenge,
            lifetime_seconds=600,
        )

        # Build authorization URL
        auth_url = cls._build_authorization_url(
            config=config,
            state=state,
        )

        # Audit log - link initiated
        AuditService.log_external_auth_link_initiated(
            user_id=user_id,
            organization_id=organization_id,
            provider_type=provider_type_str,
            state_id=state.id,
        )

        return auth_url, state.state

    @classmethod
    def complete_link_flow(
        cls,
        provider_type: AuthMethodType,
        authorization_code: str,
        state: str,
        redirect_uri: str,
    ) -> AuthenticationMethod:
        """Complete account linking flow."""
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        # Validate state
        state_record = OAuthState.query.filter_by(state=state).first()
        if not state_record or not state_record.is_valid():
            AuditService.log_external_auth_link_failed(
                user_id=None,
                organization_id=None,
                provider_type=provider_type_str,
                error_message="Invalid or expired OAuth state",
                failure_reason="invalid_state",
            )
            raise ExternalAuthError(
                "Invalid or expired OAuth state",
                "INVALID_STATE",
                400,
            )

        if state_record.flow_type != "link":
            AuditService.log_external_auth_link_failed(
                user_id=state_record.user_id,
                organization_id=state_record.organization_id,
                provider_type=provider_type_str,
                error_message="Invalid flow type for this operation",
                failure_reason="invalid_flow_type",
            )
            raise ExternalAuthError(
                "Invalid flow type for this operation",
                "INVALID_FLOW_TYPE",
                400,
            )

        if state_record.provider_type != provider_type_str:
            AuditService.log_external_auth_link_failed(
                user_id=state_record.user_id,
                organization_id=state_record.organization_id,
                provider_type=provider_type_str,
                error_message="Provider mismatch",
                failure_reason="provider_mismatch",
            )
            raise ExternalAuthError(
                "Provider mismatch",
                "PROVIDER_MISMATCH",
                400,
            )

        # Get provider config (with org override if applicable)
        config = cls.get_provider_config(
            provider_type, state_record.organization_id
        )

        # Exchange code for tokens
        tokens = cls._exchange_code(
            config=config,
            code=authorization_code,
            redirect_uri=redirect_uri,
            code_verifier=state_record.code_verifier,
        )

        # Get user info
        user_info = cls._get_user_info(
            config=config,
            access_token=tokens["access_token"],
        )

        # Get user
        user = User.query.get(state_record.user_id)
        if not user:
            AuditService.log_external_auth_link_failed(
                user_id=None,
                organization_id=state_record.organization_id,
                provider_type=provider_type_str,
                error_message="User not found",
                failure_reason="user_not_found",
            )
            raise ExternalAuthError(
                "User not found",
                "USER_NOT_FOUND",
                400,
            )

        # Create or update authentication method
        auth_method = AuthenticationMethod.query.filter_by(
            user_id=user.id,
            method_type=provider_type,
            provider_user_id=user_info["provider_user_id"],
        ).first()

        if auth_method:
            # Update existing
            auth_method.provider_data = cls._encrypt_provider_data(tokens, user_info)
            auth_method.verified = user_info.get("email_verified", False)
            auth_method.last_used_at = datetime.utcnow()
            auth_method.save()
        else:
            # Create new
            auth_method = AuthenticationMethod(
                user_id=user.id,
                method_type=provider_type,
                provider_user_id=user_info["provider_user_id"],
                provider_data=cls._encrypt_provider_data(tokens, user_info),
                verified=user_info.get("email_verified", False),
                is_primary=False,
                last_used_at=datetime.utcnow(),
            )
            auth_method.save()

        # Mark state as used
        state_record.mark_used()

        # Audit log - link completed
        AuditService.log_external_auth_link_completed(
            user_id=user.id,
            organization_id=state_record.organization_id,
            provider_type=provider_type_str,
            provider_user_id=user_info["provider_user_id"],
            auth_method_id=auth_method.id,
        )

        return auth_method

    @classmethod
    def authenticate_with_provider(
        cls,
        provider_type: AuthMethodType,
        organization_id: str,
        authorization_code: str,
        state: str,
        redirect_uri: str,
    ) -> Tuple[User, dict]:
        """Authenticate user with external provider and return tokens."""
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        # Validate state
        state_record = OAuthState.query.filter_by(state=state).first()
        if not state_record or not state_record.is_valid():
            AuditService.log_external_auth_login_failed(
                organization_id=organization_id,
                provider_type=provider_type_str,
                failure_reason="invalid_state",
                error_message="Invalid or expired OAuth state",
            )
            raise ExternalAuthError(
                "Invalid or expired OAuth state",
                "INVALID_STATE",
                400,
            )

        # Get provider config (with org override if applicable)
        config = cls.get_provider_config(provider_type, organization_id)

        # Exchange code for tokens
        tokens = cls._exchange_code(
            config=config,
            code=authorization_code,
            redirect_uri=redirect_uri,
            code_verifier=state_record.code_verifier,
        )

        # Get user info
        user_info = cls._get_user_info(
            config=config,
            access_token=tokens["access_token"],
        )

        # Look up user by provider_user_id
        auth_method = AuthenticationMethod.query.filter_by(
            method_type=provider_type,
            provider_user_id=user_info["provider_user_id"],
        ).first()

        if not auth_method:
            # Check if email matches existing user
            existing_user = User.query.filter_by(
                email=user_info["email"]
            ).first()

            if existing_user:
                AuditService.log_external_auth_login_failed(
                    organization_id=organization_id,
                    provider_type=provider_type_str,
                    provider_user_id=user_info["provider_user_id"],
                    email=user_info["email"],
                    failure_reason="email_exists",
                    error_message=f"An account with email {user_info['email']} already exists",
                )
                raise ExternalAuthError(
                    f"An account with email {user_info['email']} already exists. "
                    "Please log in with your password and link your Google account from settings.",
                    "EMAIL_EXISTS",
                    400,
                )

            AuditService.log_external_auth_login_failed(
                organization_id=organization_id,
                provider_type=provider_type_str,
                provider_user_id=user_info["provider_user_id"],
                email=user_info["email"],
                failure_reason="account_not_found",
                error_message="No Gatehouse account matches this external account",
            )
            raise ExternalAuthError(
                "No Gatehouse account matches this external account. Please register first.",
                "ACCOUNT_NOT_FOUND",
                400,
            )

        user = auth_method.user

        # Update tokens
        auth_method.provider_data = cls._encrypt_provider_data(tokens, user_info)
        auth_method.last_used_at = datetime.utcnow()
        auth_method.save()

        # Mark state as used
        state_record.mark_used()

        # Create session
        from gatehouse_app.services.auth_service import AuthService
        session = AuthService.create_session(
            user=user,
            organization_id=organization_id,
        )

        # Audit log - login success
        AuditService.log_external_auth_login(
            user_id=user.id,
            organization_id=organization_id,
            provider_type=provider_type_str,
            provider_user_id=user_info["provider_user_id"],
            auth_method_id=auth_method.id,
            session_id=session.id,
        )

        return user, session.to_dict()

    @classmethod
    def unlink_provider(
        cls,
        user_id: str,
        provider_type: AuthMethodType,
        organization_id: str = None,
    ) -> bool:
        """Unlink external provider from user account."""
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

        auth_method = AuthenticationMethod.query.filter_by(
            user_id=user_id,
            method_type=provider_type,
        ).first()

        if not auth_method:
            raise ExternalAuthError(
                f"Provider not linked",
                "PROVIDER_NOT_LINKED",
                400,
            )

        # Check if this is the last auth method
        other_methods = AuthenticationMethod.query.filter_by(
            user_id=user_id,
        ).count()

        if other_methods <= 1:
            raise ExternalAuthError(
                "Cannot unlink the last authentication method",
                "CANNOT_UNLINK_LAST",
                400,
            )

        provider_user_id = auth_method.provider_user_id
        auth_method_id = auth_method.id
        auth_method.delete()

        # Audit log - unlink
        AuditService.log_external_auth_unlink(
            user_id=user_id,
            organization_id=organization_id,
            provider_type=provider_type_str,
            provider_user_id=provider_user_id,
            auth_method_id=auth_method_id,
        )

        return True

    @classmethod
    def get_linked_accounts(cls, user_id: str) -> list:
        """Get all linked external accounts for user."""
        methods = AuthenticationMethod.query.filter_by(
            user_id=user_id,
        ).all()

        external_providers = [
            AuthMethodType.GOOGLE,
            AuthMethodType.GITHUB,
            AuthMethodType.MICROSOFT,
        ]

        return [
            {
                "id": m.id,
                "provider_type": m.method_type.value if hasattr(m.method_type, 'value') else str(m.method_type),
                "provider_user_id": m.provider_user_id,
                "email": m.provider_data.get("email") if m.provider_data else None,
                "name": m.provider_data.get("name") if m.provider_data else None,
                "picture": m.provider_data.get("picture") if m.provider_data else None,
                "verified": m.verified,
                "linked_at": m.created_at.isoformat() if m.created_at else None,
                "last_used_at": m.last_used_at.isoformat() if m.last_used_at else None,
            }
            for m in methods
            if m.method_type in external_providers or str(m.method_type) in [p.value for p in external_providers]
        ]

    # ==================== Helper Methods ====================

    @staticmethod
    def _compute_s256_challenge(verifier: str) -> str:
        """Compute S256 code challenge from verifier."""
        import hashlib
        import base64

        digest = hashlib.sha256(verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).decode().rstrip("=")

    @staticmethod
    def _build_authorization_url(config: ProviderConfigAdapter, state: OAuthState) -> str:
        """Build authorization URL using the provider config adapter."""
        from urllib.parse import urlencode
        provider = (config.provider_type or "").lower()

        params = {
            "client_id": config.client_id,
            "redirect_uri": state.redirect_uri,
            "response_type": "code",
            "scope": " ".join(config.scopes or ["openid", "profile", "email"]),
            "state": state.state,
        }

        if provider == "google":
            params["access_type"] = (
                config.settings.get("access_type", "offline") if config.settings else "offline"
            )
            params["prompt"] = (
                config.settings.get("prompt", "consent") if config.settings else "consent"
            )
        elif provider == "microsoft":
            params["prompt"] = (
                config.settings.get("prompt", "select_account") if config.settings else "select_account"
            )
        else:
            if config.settings:
                if "prompt" in config.settings:
                    params["prompt"] = config.settings["prompt"]
                if "access_type" in config.settings:
                    params["access_type"] = config.settings["access_type"]

        if state.nonce:
            params["nonce"] = state.nonce

        if state.code_challenge:
            params["code_challenge"] = state.code_challenge
            params["code_challenge_method"] = "S256"

        full_url = f"{config.auth_url}?{urlencode(params)}"
        
        # DIAGNOSTIC LOGGING: Show exact URL being built
        logger.info(
            f"[PKCE DEBUG] Building authorization URL:\n"
            f"  provider_type: {config.provider_type}\n"
            f"  state.code_challenge: {state.code_challenge[:20] if state.code_challenge else 'None'}...\n"
            f"  params has code_challenge: {'code_challenge' in params}\n"
            f"  Full URL: {full_url}"
        )
        
        return full_url

    @staticmethod
    def _exchange_code(config: ProviderConfigAdapter, code: str, redirect_uri: str, code_verifier: str = None) -> dict:
        """Exchange authorization code for tokens using the provider config adapter."""
        import requests

        data = {
            "client_id": config.client_id,
            "client_secret": config.get_client_secret(),
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": redirect_uri,
        }

        if code_verifier:
            data["code_verifier"] = code_verifier

        # Log token exchange request (without secrets)
        logger.debug(
            f"Token exchange request: url={config.token_url}, "
            f"client_id={config.client_id}, redirect_uri={redirect_uri}, "
            f"has_code_verifier={bool(code_verifier)}"
        )

        response = requests.post(config.token_url, data=data)
        
        # Log response details for debugging
        if response.status_code != 200:
            logger.error(
                f"Token exchange failed: status={response.status_code}, "
                f"response={response.text}"
            )
        
        response.raise_for_status()

        return response.json()

    @staticmethod
    def _get_user_info(config: ProviderConfigAdapter, access_token: str) -> dict:
        """Get user info from provider using the provider config adapter."""
        import requests

        provider = (config.provider_type or "").lower()
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(config.userinfo_url, headers=headers)
        response.raise_for_status()

        data = response.json()

        # Microsoft's /oidc/userinfo endpoint returns verified email addresses
        # (all AAD accounts are verified) but may omit the email_verified claim.
        # Default to True for Microsoft so users aren't stuck with unverified state.
        if provider == "microsoft":
            email_verified = data.get("email_verified", True)
        else:
            email_verified = data.get("email_verified", False)

        sub = data.get("sub")

        # Derive email from sub when the provider omits the email claim.
        # This happens with some OIDC servers (including the nav-security mock)
        # that only return the minimal {sub, iss, iat, exp} set.
        # Rule: if sub looks like an email address, use it directly.
        #       Otherwise, construct a deterministic fallback so we never get NULL.
        raw_email = data.get("email")
        if not raw_email and sub:
            import re as _re
            if _re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", sub):
                raw_email = sub
                email_verified = True  # if sub IS the email it's already verified
            else:
                # e.g. "12345" → "12345@google.local" so we can store it
                raw_email = f"{sub}@{provider or 'oauth'}.local"
                email_verified = False

        # Derive display name when omitted
        raw_name = data.get("name") or data.get("display_name")
        if not raw_name and raw_email:
            raw_name = raw_email.split("@")[0]

        # Standardize user info
        return {
            "provider_user_id": sub,
            "email": raw_email,
            "email_verified": email_verified,
            "name": raw_name,
            "first_name": data.get("given_name"),
            "last_name": data.get("family_name"),
            "picture": data.get("picture"),
            "raw_data": data,
        }

    @staticmethod
    def _encrypt_provider_data(tokens: dict, user_info: dict) -> dict:
        """Encrypt and store provider tokens and user info."""
        from gatehouse_app.utils.encryption import encrypt

        result = {
            "access_token": encrypt(tokens.get("access_token")) if tokens.get("access_token") else None,
            "token_type": tokens.get("token_type", "Bearer"),
            "expires_in": tokens.get("expires_in"),
            "refresh_token": encrypt(tokens.get("refresh_token")) if tokens.get("refresh_token") else None,
            "scope": tokens.get("scope", []),
            "id_token": encrypt(tokens.get("id_token")) if tokens.get("id_token") else None,
            "email": user_info.get("email"),
            "name": user_info.get("name"),
            "picture": user_info.get("picture"),
            "raw_data": user_info.get("raw_data", {}),
        }

        return result

    @staticmethod
    def _decrypt_provider_data(provider_data: dict) -> dict:
        """
        Decrypt provider tokens from stored data.
        
        This method handles backward compatibility with existing data where
        access_token may be stored in plain text (unencrypted).
        """
        from gatehouse_app.utils.encryption import decrypt

        if not provider_data:
            return {}

        result = {
            "token_type": provider_data.get("token_type", "Bearer"),
            "expires_in": provider_data.get("expires_in"),
            "scope": provider_data.get("scope", []),
            "email": provider_data.get("email"),
            "name": provider_data.get("name"),
            "picture": provider_data.get("picture"),
            "raw_data": provider_data.get("raw_data", {}),
        }

        # Decrypt access_token with backward compatibility
        access_token = provider_data.get("access_token")
        if access_token:
            # Try to decrypt - if it fails, assume it's plain text (old data)
            try:
                result["access_token"] = decrypt(access_token)
            except Exception:
                # Access token is plain text (pre-encryption data)
                result["access_token"] = access_token
        else:
            result["access_token"] = None

        # Decrypt refresh_token
        refresh_token = provider_data.get("refresh_token")
        if refresh_token:
            try:
                result["refresh_token"] = decrypt(refresh_token)
            except Exception:
                result["refresh_token"] = refresh_token
        else:
            result["refresh_token"] = None

        # Decrypt id_token
        id_token = provider_data.get("id_token")
        if id_token:
            try:
                result["id_token"] = decrypt(id_token)
            except Exception:
                result["id_token"] = id_token
        else:
            result["id_token"] = None

        return result
