"""Application-wide provider configuration management."""
import logging

from gatehouse_app.models.auth.authentication_method import ApplicationProviderConfig
from gatehouse_app.services.external_auth.models import ExternalAuthError

logger = logging.getLogger(__name__)


def create_app_provider_config(
    provider_type: str,
    client_id: str,
    client_secret: str,
    **kwargs,
) -> ApplicationProviderConfig:
    existing = ApplicationProviderConfig.query.filter_by(
        provider_type=provider_type
    ).first()

    if existing:
        raise ExternalAuthError(
            f"Provider {provider_type} already exists",
            "PROVIDER_EXISTS",
            400,
        )

    additional_config = {}
    for key in ['auth_url', 'token_url', 'userinfo_url', 'jwks_url', 'scopes']:
        if key in kwargs:
            additional_config[key] = kwargs.pop(key)

    if 'settings' in kwargs:
        additional_config.update(kwargs.pop('settings'))

    config = ApplicationProviderConfig(
        provider_type=provider_type,
        client_id=client_id,
        is_enabled=kwargs.get('is_enabled', True),
        default_redirect_url=kwargs.get('default_redirect_url'),
        additional_config=additional_config,
    )
    config.set_client_secret(client_secret)
    config.save()

    logger.info(f"Created application provider config for {provider_type}")
    return config


def update_app_provider_config(
    provider_type: str,
    **updates,
) -> ApplicationProviderConfig:
    config = ApplicationProviderConfig.query.filter_by(
        provider_type=provider_type
    ).first()

    if not config:
        raise ExternalAuthError(
            f"Provider {provider_type} not found",
            "PROVIDER_NOT_FOUND",
            404,
        )

    if 'client_id' in updates:
        config.client_id = updates['client_id']

    if 'client_secret' in updates:
        config.set_client_secret(updates['client_secret'])

    if 'is_enabled' in updates:
        config.is_enabled = updates['is_enabled']

    if 'default_redirect_url' in updates:
        config.default_redirect_url = updates['default_redirect_url']

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


def get_app_provider_config(provider_type: str) -> ApplicationProviderConfig:
    config = ApplicationProviderConfig.query.filter_by(
        provider_type=provider_type
    ).first()

    if not config:
        raise ExternalAuthError(
            f"Provider {provider_type} not found",
            "PROVIDER_NOT_FOUND",
            404,
        )

    return config


def list_app_provider_configs() -> list:
    configs = ApplicationProviderConfig.query.all()
    return [config.to_dict() for config in configs]


def delete_app_provider_config(provider_type: str) -> bool:
    config = ApplicationProviderConfig.query.filter_by(
        provider_type=provider_type
    ).first()

    if not config:
        raise ExternalAuthError(
            f"Provider {provider_type} not found",
            "PROVIDER_NOT_FOUND",
            404,
        )

    config.delete()
    logger.info(f"Deleted application provider config for {provider_type}")
    return True
