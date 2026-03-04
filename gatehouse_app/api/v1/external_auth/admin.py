"""Admin application-level OAuth provider management."""
from flask import g, request
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required


@api_v1_bp.route("/admin/oauth/providers", methods=["GET"])
@login_required
def admin_list_app_providers():
    from gatehouse_app.models.auth.authentication_method import ApplicationProviderConfig
    from gatehouse_app.models import OrganizationMember
    from gatehouse_app.utils.constants import OrganizationRole

    admin_memberships = OrganizationMember.query.filter(
        OrganizationMember.user_id == g.current_user.id,
        OrganizationMember.role.in_([OrganizationRole.OWNER, OrganizationRole.ADMIN]),
    ).all()

    if not admin_memberships:
        return api_response(success=False, message="Admin access required", status=403, error_type="FORBIDDEN")

    PROVIDERS = [{"id": "google", "name": "Google"}, {"id": "github", "name": "GitHub"}, {"id": "microsoft", "name": "Microsoft"}]
    db_configs = {c.provider_type: c for c in ApplicationProviderConfig.query.all()}

    result = []
    for p in PROVIDERS:
        cfg = db_configs.get(p["id"])
        result.append({
            "id": p["id"], "name": p["name"],
            "is_configured": cfg is not None,
            "is_enabled": cfg.is_enabled if cfg else False,
            "client_id": cfg.client_id if cfg else None,
        })

    return api_response(data={"providers": result}, message="OAuth providers retrieved successfully")


@api_v1_bp.route("/admin/oauth/providers/<provider>", methods=["PUT"])
@login_required
def admin_configure_app_provider(provider: str):
    from gatehouse_app.models.auth.authentication_method import ApplicationProviderConfig
    from gatehouse_app.models import OrganizationMember
    from gatehouse_app.utils.constants import OrganizationRole
    from gatehouse_app.extensions import db

    SUPPORTED = ["google", "github", "microsoft"]
    if provider not in SUPPORTED:
        return api_response(success=False, message=f"Unsupported provider. Must be one of: {', '.join(SUPPORTED)}", status=400, error_type="VALIDATION_ERROR")

    admin_memberships = OrganizationMember.query.filter(
        OrganizationMember.user_id == g.current_user.id,
        OrganizationMember.role.in_([OrganizationRole.OWNER, OrganizationRole.ADMIN]),
    ).all()

    if not admin_memberships:
        return api_response(success=False, message="Admin access required", status=403, error_type="FORBIDDEN")

    data = request.json or {}
    client_id = (data.get("client_id") or "").strip()
    client_secret = (data.get("client_secret") or "").strip()
    is_enabled = data.get("is_enabled", True)

    if not client_id:
        return api_response(success=False, message="client_id is required", status=400, error_type="VALIDATION_ERROR")

    cfg = ApplicationProviderConfig.query.filter_by(provider_type=provider).first()
    if cfg:
        cfg.client_id = client_id
        if client_secret:
            cfg.set_client_secret(client_secret)
        cfg.is_enabled = bool(is_enabled)
        db.session.commit()
    else:
        cfg = ApplicationProviderConfig(provider_type=provider, client_id=client_id, is_enabled=bool(is_enabled))
        if client_secret:
            cfg.set_client_secret(client_secret)
        db.session.add(cfg)
        db.session.commit()

    return api_response(
        data={"provider": {"id": provider, "client_id": cfg.client_id, "is_enabled": cfg.is_enabled}},
        message=f"{provider.capitalize()} OAuth provider configured successfully",
    )


@api_v1_bp.route("/admin/oauth/providers/<provider>", methods=["DELETE"])
@login_required
def admin_delete_app_provider(provider: str):
    from gatehouse_app.models.auth.authentication_method import ApplicationProviderConfig
    from gatehouse_app.models import OrganizationMember
    from gatehouse_app.utils.constants import OrganizationRole
    from gatehouse_app.extensions import db

    admin_memberships = OrganizationMember.query.filter(
        OrganizationMember.user_id == g.current_user.id,
        OrganizationMember.role.in_([OrganizationRole.OWNER, OrganizationRole.ADMIN]),
    ).all()

    if not admin_memberships:
        return api_response(success=False, message="Admin access required", status=403, error_type="FORBIDDEN")

    cfg = ApplicationProviderConfig.query.filter_by(provider_type=provider).first()
    if not cfg:
        return api_response(success=False, message=f"Provider '{provider}' is not configured", status=404, error_type="NOT_FOUND")

    db.session.delete(cfg)
    db.session.commit()
    return api_response(message=f"{provider.capitalize()} OAuth provider configuration removed")
