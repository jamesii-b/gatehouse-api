"""External auth models and adapter classes."""
from typing import Optional

from gatehouse_app.extensions import db
from gatehouse_app.models.base import BaseModel
from gatehouse_app.models.auth.authentication_method import (
    ApplicationProviderConfig,
    OrganizationProviderOverride,
)


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

    organization_id = db.Column(
        db.String(36), db.ForeignKey("organizations.id"), nullable=False, index=True
    )
    provider_type = db.Column(db.String(50), nullable=False, index=True)
    client_id = db.Column(db.String(255), nullable=False)
    client_secret_encrypted = db.Column(db.String(512), nullable=True)
    auth_url = db.Column(db.String(2048), nullable=False)
    token_url = db.Column(db.String(2048), nullable=False)
    userinfo_url = db.Column(db.String(2048), nullable=True)
    jwks_url = db.Column(db.String(2048), nullable=True)
    scopes = db.Column(db.JSON, nullable=False, default=list)
    redirect_uris = db.Column(db.JSON, nullable=False, default=list)
    settings = db.Column(db.JSON, nullable=True)
    is_active = db.Column(db.Boolean, default=True, nullable=False)

    organization = db.relationship(
        "Organization", back_populates="external_provider_configs"
    )

    __table_args__ = (
        db.Index("idx_provider_config_org", "organization_id", "provider_type"),
        db.UniqueConstraint(
            "organization_id",
            "provider_type",
            name="uix_org_provider_type",
        ),
    )

    def get_client_secret(self) -> str:
        from gatehouse_app.utils.encryption import decrypt
        if self.client_secret_encrypted:
            return decrypt(self.client_secret_encrypted)
        return None

    def set_client_secret(self, secret: str):
        from gatehouse_app.utils.encryption import encrypt
        self.client_secret_encrypted = encrypt(secret)

    def is_redirect_uri_allowed(self, uri: str) -> bool:
        return uri in (self.redirect_uris or [])

    def to_dict(self, include_secrets: bool = False) -> dict:
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
    """Unified interface for provider configuration.

    Merges application-level config with optional organization overrides.
    """

    def __init__(
        self,
        app_config: ApplicationProviderConfig,
        org_override: Optional[OrganizationProviderOverride] = None,
    ):
        self.app_config = app_config
        self.org_override = org_override
        self.provider_type = app_config.provider_type

    @property
    def client_id(self) -> str:
        if self.org_override and self.org_override.client_id:
            return self.org_override.client_id
        return self.app_config.client_id

    def get_client_secret(self) -> str:
        if self.org_override and self.org_override.client_secret_encrypted:
            return self.org_override.get_client_secret()
        return self.app_config.get_client_secret()

    @property
    def auth_url(self) -> str:
        return self._get_provider_endpoint('auth_url')

    @property
    def token_url(self) -> str:
        return self._get_provider_endpoint('token_url')

    @property
    def userinfo_url(self) -> str:
        return self._get_provider_endpoint('userinfo_url')

    @property
    def jwks_url(self) -> str:
        return self._get_provider_endpoint('jwks_url')

    @property
    def scopes(self) -> list:
        base_scopes = self.app_config.additional_config.get('scopes', []) if self.app_config.additional_config else []
        if self.org_override and self.org_override.additional_config:
            override_scopes = self.org_override.additional_config.get('scopes')
            if override_scopes is not None:
                return override_scopes
        return base_scopes or ['openid', 'profile', 'email']

    @property
    def redirect_uris(self) -> list:
        if self.org_override and self.org_override.redirect_url_override:
            return [self.org_override.redirect_url_override]
        if self.app_config.default_redirect_url:
            return [self.app_config.default_redirect_url]
        return []

    @property
    def settings(self) -> dict:
        settings = {}
        if self.app_config.additional_config:
            settings.update(self.app_config.additional_config)
        if self.org_override and self.org_override.additional_config:
            settings.update(self.org_override.additional_config)
        return settings

    @property
    def is_active(self) -> bool:
        app_enabled = self.app_config.is_enabled
        org_enabled = True if not self.org_override else self.org_override.is_enabled
        return app_enabled and org_enabled

    def is_redirect_uri_allowed(self, uri: str) -> bool:
        return uri in self.redirect_uris

    def _get_provider_endpoint(self, endpoint_name: str) -> Optional[str]:
        if not self.app_config.additional_config:
            return None
        return self.app_config.additional_config.get(endpoint_name)
