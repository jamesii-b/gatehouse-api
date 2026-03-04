"""External auth provider config endpoints (admin and user)."""
from flask import g, request
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required
from gatehouse_app.services.external_auth import ExternalAuthService
from gatehouse_app.services.external_auth.models import ExternalAuthError, ExternalProviderConfig
from gatehouse_app.services.audit_service import AuditService
from gatehouse_app.api.v1.external_auth._helpers import get_provider_type, _get_provider_endpoints


@api_v1_bp.route("/auth/external/providers", methods=["GET"])
@login_required
def list_providers():
    from gatehouse_app.models.auth.authentication_method import ApplicationProviderConfig

    app_configs = {c.provider_type.lower(): c for c in ApplicationProviderConfig.query.filter_by(is_enabled=True).all()}

    user_orgs = g.current_user.get_organizations()
    org_configs = {}
    if user_orgs:
        organization_id = user_orgs[0].id
        org_level = ExternalProviderConfig.query.filter_by(organization_id=organization_id).all()
        org_configs = {c.provider_type.lower(): c for c in org_level}

    def provider_info(provider_id, name):
        app_cfg = app_configs.get(provider_id)
        org_cfg = org_configs.get(provider_id)
        is_configured = app_cfg is not None or org_cfg is not None
        is_active = bool(app_cfg.is_enabled) if app_cfg else False
        if org_cfg and hasattr(org_cfg, "is_active"):
            is_active = bool(org_cfg.is_active)
        return {"id": provider_id, "name": name, "type": provider_id, "is_configured": is_configured, "is_active": is_active,
                "settings": {"requires_domain": False, "supports_refresh_tokens": True}}

    providers = [provider_info("google", "Google"), provider_info("github", "GitHub"), provider_info("microsoft", "Microsoft")]
    return api_response(data={"providers": providers}, message="Providers retrieved successfully")


@api_v1_bp.route("/auth/external/providers/<provider>/config", methods=["GET"])
@login_required
def get_provider_config(provider: str):
    from gatehouse_app.models import OrganizationMember
    from gatehouse_app.utils.constants import OrganizationRole

    provider_type = get_provider_type(provider)

    user_orgs = g.current_user.get_organizations()
    if not user_orgs:
        return api_response(success=False, message="No organizations found for user", status=400, error_type="BAD_REQUEST")

    organization_id = user_orgs[0].id
    member = OrganizationMember.query.filter_by(user_id=g.current_user.id, organization_id=organization_id).first()
    if not member or member.role not in [OrganizationRole.OWNER, OrganizationRole.ADMIN]:
        return api_response(success=False, message="Admin access required", status=403, error_type="FORBIDDEN")

    config = ExternalProviderConfig.query.filter_by(organization_id=organization_id, provider_type=provider_type.value).first()
    if not config:
        return api_response(success=False, message=f"{provider.title()} OAuth is not configured", status=404, error_type="NOT_FOUND")

    return api_response(data=config.to_dict(include_secrets=False), message="Provider configuration retrieved successfully")


@api_v1_bp.route("/auth/external/providers/<provider>/config", methods=["POST"])
@login_required
def create_or_update_provider_config(provider: str):
    from gatehouse_app.models import OrganizationMember
    from gatehouse_app.utils.constants import OrganizationRole

    provider_type = get_provider_type(provider)

    user_orgs = g.current_user.get_organizations()
    if not user_orgs:
        return api_response(success=False, message="No organizations found for user", status=400, error_type="BAD_REQUEST")

    organization_id = user_orgs[0].id
    member = OrganizationMember.query.filter_by(user_id=g.current_user.id, organization_id=organization_id).first()
    if not member or member.role not in [OrganizationRole.OWNER, OrganizationRole.ADMIN]:
        return api_response(success=False, message="Admin access required", status=403, error_type="FORBIDDEN")

    data = request.json or {}
    client_id = data.get("client_id")
    client_secret = data.get("client_secret")

    if not client_id:
        return api_response(success=False, message="client_id is required", status=400, error_type="VALIDATION_ERROR")

    config = ExternalProviderConfig.query.filter_by(organization_id=organization_id, provider_type=provider_type.value).first()
    is_new = config is None

    if config:
        config.client_id = client_id
        if client_secret:
            config.set_client_secret(client_secret)
        config.scopes = data.get("scopes", ["openid", "profile", "email"])
        config.redirect_uris = data.get("redirect_uris", [])
        config.settings = data.get("settings", {})
        config.is_active = data.get("is_active", True)
        config.save()
        AuditService.log_external_auth_config_update(
            user_id=g.current_user.id, organization_id=organization_id, provider_type=provider_type.value,
            config_id=config.id,
            changes={"client_id": "updated", "client_secret": "updated" if client_secret else None,
                     "scopes": data.get("scopes"), "redirect_uris": data.get("redirect_uris"), "is_active": config.is_active},
        )
    else:
        auth_url, token_url, userinfo_url = _get_provider_endpoints(provider_type)
        config = ExternalProviderConfig(
            organization_id=organization_id, provider_type=provider_type.value,
            client_id=client_id, client_secret_encrypted=None,
            auth_url=auth_url, token_url=token_url, userinfo_url=userinfo_url,
            scopes=data.get("scopes", ["openid", "profile", "email"]),
            redirect_uris=data.get("redirect_uris", []), settings=data.get("settings", {}),
            is_active=data.get("is_active", True),
        )
        if client_secret:
            config.set_client_secret(client_secret)
        config.save()
        AuditService.log_external_auth_config_create(
            user_id=g.current_user.id, organization_id=organization_id,
            provider_type=provider_type.value, config_id=config.id,
        )

    return api_response(data=config.to_dict(include_secrets=False), message="Provider configuration saved successfully", status=201 if is_new else 200)


@api_v1_bp.route("/auth/external/providers/<provider>/config", methods=["DELETE"])
@login_required
def delete_provider_config(provider: str):
    from gatehouse_app.models import OrganizationMember
    from gatehouse_app.utils.constants import OrganizationRole

    provider_type = get_provider_type(provider)

    user_orgs = g.current_user.get_organizations()
    if not user_orgs:
        return api_response(success=False, message="No organizations found for user", status=400, error_type="BAD_REQUEST")

    organization_id = user_orgs[0].id
    member = OrganizationMember.query.filter_by(user_id=g.current_user.id, organization_id=organization_id).first()
    if not member or member.role not in [OrganizationRole.OWNER, OrganizationRole.ADMIN]:
        return api_response(success=False, message="Admin access required", status=403, error_type="FORBIDDEN")

    config = ExternalProviderConfig.query.filter_by(organization_id=organization_id, provider_type=provider_type.value).first()
    if not config:
        return api_response(success=False, message=f"{provider.title()} OAuth is not configured", status=404, error_type="NOT_FOUND")

    config_id = config.id
    config.delete()
    AuditService.log_external_auth_config_delete(
        user_id=g.current_user.id, organization_id=organization_id,
        provider_type=provider_type.value, config_id=config_id,
    )
    return api_response(message=f"{provider.title()} provider configuration deleted successfully")


@api_v1_bp.route("/auth/external/linked-accounts", methods=["GET"])
@login_required
def list_linked_accounts():
    from gatehouse_app.models import AuthenticationMethod

    linked_accounts = ExternalAuthService.get_linked_accounts(g.current_user.id)
    other_methods = AuthenticationMethod.query.filter_by(user_id=g.current_user.id, deleted_at=None).count()
    return api_response(data={"linked_accounts": linked_accounts, "unlink_available": other_methods > 1}, message="Linked accounts retrieved successfully")


@api_v1_bp.route("/auth/external/<provider>/link", methods=["POST"])
@login_required
def initiate_link_account(provider: str):
    provider_type = get_provider_type(provider)

    user_orgs = g.current_user.get_organizations()
    organization_id = user_orgs[0].id if user_orgs else None
    data = request.json or {}
    redirect_uri = data.get("redirect_uri")

    try:
        auth_url, state = ExternalAuthService.initiate_link_flow(
            user_id=g.current_user.id, provider_type=provider_type,
            organization_id=organization_id, redirect_uri=redirect_uri,
        )
        return api_response(data={"authorization_url": auth_url, "state": state}, message="Link flow initiated. Redirect to authorization URL.")
    except ExternalAuthError as e:
        return api_response(success=False, message=e.message, status=e.status_code, error_type=e.error_type)


@api_v1_bp.route("/auth/external/<provider>/unlink", methods=["DELETE"])
@login_required
def unlink_account(provider: str):
    provider_type = get_provider_type(provider)

    user_orgs = g.current_user.get_organizations()
    organization_id = user_orgs[0].id if user_orgs else None

    try:
        ExternalAuthService.unlink_provider(
            user_id=g.current_user.id, provider_type=provider_type, organization_id=organization_id,
        )
        return api_response(message=f"{provider.title()} account unlinked successfully")
    except ExternalAuthError as e:
        return api_response(success=False, message=e.message, status=e.status_code, error_type=e.error_type)
