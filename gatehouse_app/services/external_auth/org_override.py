"""Organization-specific provider override management."""
import logging

from gatehouse_app.models.auth.authentication_method import (
    ApplicationProviderConfig,
    OrganizationProviderOverride,
)
from gatehouse_app.services.external_auth.models import ExternalAuthError

logger = logging.getLogger(__name__)


def create_org_provider_override(
    organization_id: str,
    provider_type: str,
    **kwargs,
) -> OrganizationProviderOverride:
    app_config = ApplicationProviderConfig.query.filter_by(
        provider_type=provider_type
    ).first()

    if not app_config:
        raise ExternalAuthError(
            f"Application provider {provider_type} must be configured first",
            "PROVIDER_NOT_CONFIGURED",
            400,
        )

    existing = OrganizationProviderOverride.query.filter_by(
        organization_id=organization_id,
        provider_type=provider_type,
    ).first()

    if existing:
        raise ExternalAuthError(
            f"Override for {provider_type} already exists for this organization",
            "OVERRIDE_EXISTS",
            400,
        )

    additional_config = {}
    if 'settings' in kwargs:
        additional_config.update(kwargs.pop('settings'))
    if 'scopes' in kwargs:
        additional_config['scopes'] = kwargs.pop('scopes')

    override = OrganizationProviderOverride(
        organization_id=organization_id,
        provider_type=provider_type,
        client_id=kwargs.get('client_id'),
        is_enabled=kwargs.get('is_enabled', True),
        redirect_url_override=kwargs.get('redirect_url_override'),
        additional_config=additional_config if additional_config else None,
    )

    if 'client_secret' in kwargs:
        override.set_client_secret(kwargs['client_secret'])

    override.save()
    logger.info(f"Created org override for {provider_type} in org {organization_id}")
    return override


def update_org_provider_override(
    organization_id: str,
    provider_type: str,
    **updates,
) -> OrganizationProviderOverride:
    override = OrganizationProviderOverride.query.filter_by(
        organization_id=organization_id,
        provider_type=provider_type,
    ).first()

    if not override:
        raise ExternalAuthError(
            f"Override for {provider_type} not found for this organization",
            "OVERRIDE_NOT_FOUND",
            404,
        )

    if 'client_id' in updates:
        override.client_id = updates['client_id']

    if 'client_secret' in updates:
        override.set_client_secret(updates['client_secret'])

    if 'is_enabled' in updates:
        override.is_enabled = updates['is_enabled']

    if 'redirect_url_override' in updates:
        override.redirect_url_override = updates['redirect_url_override']

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


def get_org_provider_override(
    organization_id: str,
    provider_type: str,
) -> OrganizationProviderOverride:
    override = OrganizationProviderOverride.query.filter_by(
        organization_id=organization_id,
        provider_type=provider_type,
    ).first()

    if not override:
        raise ExternalAuthError(
            f"Override for {provider_type} not found for this organization",
            "OVERRIDE_NOT_FOUND",
            404,
        )

    return override


def list_org_provider_overrides(organization_id: str) -> list:
    overrides = OrganizationProviderOverride.query.filter_by(
        organization_id=organization_id
    ).all()
    return [override.to_dict() for override in overrides]


def delete_org_provider_override(organization_id: str, provider_type: str) -> bool:
    override = OrganizationProviderOverride.query.filter_by(
        organization_id=organization_id,
        provider_type=provider_type,
    ).first()

    if not override:
        raise ExternalAuthError(
            f"Override for {provider_type} not found for this organization",
            "OVERRIDE_NOT_FOUND",
            404,
        )

    override.delete()
    logger.info(f"Deleted org override for {provider_type} in org {organization_id}")
    return True
