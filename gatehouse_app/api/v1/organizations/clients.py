"""Organization OIDC client endpoints."""
import secrets as _secrets
from flask import g, request
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required, require_admin, full_access_required
from gatehouse_app.extensions import db, bcrypt


@api_v1_bp.route("/organizations/<org_id>/clients", methods=["GET"])
@login_required
@require_admin
@full_access_required
def list_org_clients(org_id):
    from gatehouse_app.models import OIDCClient, Organization

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404)

    clients = OIDCClient.query.filter_by(organization_id=org_id, is_active=True).all()

    def client_to_dict(c):
        return {
            "id": c.id,
            "name": c.name,
            "client_id": c.client_id,
            "redirect_uris": c.redirect_uris,
            "scopes": c.scopes,
            "grant_types": c.grant_types,
            "is_active": c.is_active,
            "created_at": c.created_at.isoformat() + "Z",
        }

    return api_response(data={"clients": [client_to_dict(c) for c in clients], "count": len(clients)}, message="Clients retrieved successfully")


@api_v1_bp.route("/organizations/<org_id>/clients", methods=["POST"])
@login_required
@require_admin
def create_org_client(org_id):
    from gatehouse_app.models import OIDCClient, Organization

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404)

    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    redirect_uris_raw = data.get("redirect_uris") or []

    if not name:
        return api_response(success=False, message="Client name is required", status=400, error_type="VALIDATION_ERROR")

    if isinstance(redirect_uris_raw, str):
        redirect_uris = [u.strip() for u in redirect_uris_raw.replace(",", "\n").splitlines() if u.strip()]
    else:
        redirect_uris = [u.strip() for u in redirect_uris_raw if isinstance(u, str) and u.strip()]

    if not redirect_uris:
        return api_response(success=False, message="At least one redirect URI is required", status=400, error_type="VALIDATION_ERROR")

    client_id = _secrets.token_hex(16)
    client_secret = _secrets.token_urlsafe(32)

    client = OIDCClient(
        organization_id=org_id,
        name=name,
        client_id=client_id,
        client_secret_hash=bcrypt.generate_password_hash(client_secret).decode("utf-8"),
        redirect_uris=redirect_uris,
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scopes=["openid", "profile", "email"],
        is_active=True,
        is_confidential=True,
    )
    db.session.add(client)
    db.session.commit()

    return api_response(
        data={
            "client": {
                "id": client.id,
                "name": client.name,
                "client_id": client.client_id,
                "client_secret": client_secret,
                "redirect_uris": client.redirect_uris,
                "scopes": client.scopes,
                "created_at": client.created_at.isoformat() + "Z",
            }
        },
        message="OIDC client created successfully",
        status=201,
    )


@api_v1_bp.route("/organizations/<org_id>/clients/<client_id>", methods=["DELETE"])
@login_required
@require_admin
def delete_org_client(org_id, client_id):
    from gatehouse_app.models import OIDCClient

    client = OIDCClient.query.filter_by(id=client_id, organization_id=org_id).first()
    if not client:
        return api_response(success=False, message="Client not found", status=404)

    client.is_active = False
    db.session.commit()
    return api_response(data={}, message="Client deactivated successfully")
