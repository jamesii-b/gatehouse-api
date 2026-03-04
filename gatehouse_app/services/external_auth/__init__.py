"""ExternalAuthService — public facade re-exporting the full API."""
import logging
from typing import Optional, Tuple

from gatehouse_app.models import AuthenticationMethod, User
from gatehouse_app.models.auth.authentication_method import (
    ApplicationProviderConfig,
    OrganizationProviderOverride,
    OAuthState,
)
from gatehouse_app.utils.constants import AuthMethodType

from gatehouse_app.services.external_auth.models import (
    ExternalAuthError,
    ExternalProviderConfig,
    ProviderConfigAdapter,
)
from gatehouse_app.services.external_auth import app_provider, org_override, linking
from gatehouse_app.services.external_auth._helpers import (
    _compute_s256_challenge,
    _build_authorization_url,
    _exchange_code,
    _get_user_info,
    _encrypt_provider_data,
    _decrypt_provider_data,
)

logger = logging.getLogger(__name__)


class ExternalAuthService:
    """Service for external authentication operations."""

    # ── Provider config lookup ──────────────────────────────────────────────

    @classmethod
    def get_provider_config(
        cls,
        provider_type: AuthMethodType,
        organization_id: Optional[str] = None,
    ) -> ProviderConfigAdapter:
        provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

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

        org_override_obj = None
        if organization_id:
            org_override_obj = OrganizationProviderOverride.query.filter_by(
                organization_id=organization_id,
                provider_type=provider_type_str,
            ).first()

            if org_override_obj and not org_override_obj.is_enabled:
                raise ExternalAuthError(
                    f"{provider_type_str.title()} OAuth is disabled for this organization",
                    "PROVIDER_DISABLED_FOR_ORG",
                    400,
                )

        return ProviderConfigAdapter(app_config, org_override_obj)

    # ── App-wide provider config ────────────────────────────────────────────

    @classmethod
    def create_app_provider_config(cls, provider_type, client_id, client_secret, **kwargs):
        return app_provider.create_app_provider_config(provider_type, client_id, client_secret, **kwargs)

    @classmethod
    def update_app_provider_config(cls, provider_type, **updates):
        return app_provider.update_app_provider_config(provider_type, **updates)

    @classmethod
    def get_app_provider_config(cls, provider_type):
        return app_provider.get_app_provider_config(provider_type)

    @classmethod
    def list_app_provider_configs(cls):
        return app_provider.list_app_provider_configs()

    @classmethod
    def delete_app_provider_config(cls, provider_type):
        return app_provider.delete_app_provider_config(provider_type)

    # ── Org override management ─────────────────────────────────────────────

    @classmethod
    def create_org_provider_override(cls, organization_id, provider_type, **kwargs):
        return org_override.create_org_provider_override(organization_id, provider_type, **kwargs)

    @classmethod
    def update_org_provider_override(cls, organization_id, provider_type, **updates):
        return org_override.update_org_provider_override(organization_id, provider_type, **updates)

    @classmethod
    def get_org_provider_override(cls, organization_id, provider_type):
        return org_override.get_org_provider_override(organization_id, provider_type)

    @classmethod
    def list_org_provider_overrides(cls, organization_id):
        return org_override.list_org_provider_overrides(organization_id)

    @classmethod
    def delete_org_provider_override(cls, organization_id, provider_type):
        return org_override.delete_org_provider_override(organization_id, provider_type)

    # ── OAuth link / auth flows ─────────────────────────────────────────────

    @classmethod
    def initiate_link_flow(cls, user_id, provider_type, organization_id, redirect_uri=None):
        return linking.initiate_link_flow(cls.get_provider_config, user_id, provider_type, organization_id, redirect_uri)

    @classmethod
    def complete_link_flow(cls, provider_type, authorization_code, state, redirect_uri):
        return linking.complete_link_flow(cls.get_provider_config, provider_type, authorization_code, state, redirect_uri)

    @classmethod
    def authenticate_with_provider(cls, provider_type, organization_id, authorization_code, state, redirect_uri):
        return linking.authenticate_with_provider(cls.get_provider_config, provider_type, organization_id, authorization_code, state, redirect_uri)

    @classmethod
    def unlink_provider(cls, user_id, provider_type, organization_id=None):
        return linking.unlink_provider(user_id, provider_type, organization_id)

    @classmethod
    def get_linked_accounts(cls, user_id):
        return linking.get_linked_accounts(user_id)

    # ── Static helpers (kept as class methods for backward compatibility) ───

    @staticmethod
    def _compute_s256_challenge(verifier: str) -> str:
        return _compute_s256_challenge(verifier)

    @staticmethod
    def _build_authorization_url(config, state) -> str:
        return _build_authorization_url(config, state)

    @staticmethod
    def _exchange_code(config, code, redirect_uri, code_verifier=None) -> dict:
        return _exchange_code(config, code, redirect_uri, code_verifier)

    @staticmethod
    def _get_user_info(config, access_token) -> dict:
        return _get_user_info(config, access_token)

    @staticmethod
    def _encrypt_provider_data(tokens, user_info) -> dict:
        return _encrypt_provider_data(tokens, user_info)

    @staticmethod
    def _decrypt_provider_data(provider_data) -> dict:
        return _decrypt_provider_data(provider_data)
