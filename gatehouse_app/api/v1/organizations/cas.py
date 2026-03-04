"""Organization Certificate Authority endpoints."""
from flask import g, request, current_app
from marshmallow import ValidationError
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.utils.response import api_response
from gatehouse_app.utils.decorators import login_required, require_admin
from gatehouse_app.extensions import db
from gatehouse_app.api.v1.organizations._helpers import _get_system_ca_dict


@api_v1_bp.route("/organizations/<org_id>/cas", methods=["GET"])
@login_required
@require_admin
def list_org_cas(org_id):
    from gatehouse_app.models.ssh_ca.ca import CA, CaType
    from gatehouse_app.models.organization.organization import Organization

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404, error_type="NOT_FOUND")

    cas = CA.query.filter_by(organization_id=org_id, deleted_at=None).all()
    ca_list = [ca.to_dict() for ca in cas]
    covered_types = {ca.ca_type for ca in cas}

    system_ca_dict = _get_system_ca_dict()
    if system_ca_dict and CaType.USER not in covered_types:
        ca_list.append({**system_ca_dict, "ca_type": "user"})

    return api_response(data={"cas": ca_list, "count": len(ca_list)}, message="CAs retrieved")


@api_v1_bp.route("/organizations/<org_id>/cas/<ca_id>", methods=["PATCH"])
@login_required
@require_admin
def update_org_ca(org_id, ca_id):
    from gatehouse_app.models.ssh_ca.ca import CA
    from gatehouse_app.models.organization.organization import Organization
    from marshmallow import Schema, fields, validate

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404, error_type="NOT_FOUND")

    ca = CA.query.filter_by(id=ca_id, organization_id=org_id, deleted_at=None).first()
    if not ca:
        return api_response(success=False, message="CA not found", status=404, error_type="NOT_FOUND")

    try:
        class CAUpdateSchema(Schema):
            default_cert_validity_hours = fields.Int(validate=validate.Range(min=1), required=False)
            max_cert_validity_hours = fields.Int(validate=validate.Range(min=1), required=False)

        schema = CAUpdateSchema()
        data = schema.load(request.json or {})

        default_hours = data.get("default_cert_validity_hours", ca.default_cert_validity_hours)
        max_hours = data.get("max_cert_validity_hours", ca.max_cert_validity_hours)

        if default_hours > max_hours:
            return api_response(success=False, message="Default validity must be less than or equal to maximum validity", status=400, error_type="VALIDATION_ERROR")

        if "default_cert_validity_hours" in data:
            ca.default_cert_validity_hours = data["default_cert_validity_hours"]
        if "max_cert_validity_hours" in data:
            ca.max_cert_validity_hours = data["max_cert_validity_hours"]

        db.session.commit()
        return api_response(data={"ca": ca.to_dict()}, message="CA updated successfully")
    except ValidationError as e:
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)
    except Exception:
        db.session.rollback()
        return api_response(success=False, message="Failed to update CA", status=500, error_type="SERVER_ERROR")


@api_v1_bp.route("/organizations/<org_id>/cas", methods=["POST"])
@login_required
@require_admin
def create_org_ca(org_id):
    from gatehouse_app.models.ssh_ca.ca import CA, KeyType, CaType
    from gatehouse_app.models.organization.organization import Organization
    from gatehouse_app.utils.crypto import compute_ssh_fingerprint
    from gatehouse_app.utils.ca_key_encryption import encrypt_ca_key
    from marshmallow import Schema, fields as ma_fields, validate, ValidationError as MaValidationError
    from sshkey_tools.keys import Ed25519PrivateKey, RsaPrivateKey, EcdsaPrivateKey

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404, error_type="NOT_FOUND")

    class CreateCASchema(Schema):
        name = ma_fields.Str(required=True, validate=validate.Length(min=1, max=255))
        description = ma_fields.Str(load_default=None, allow_none=True)
        ca_type = ma_fields.Str(load_default="user", validate=validate.OneOf(["user", "host"]))
        key_type = ma_fields.Str(load_default="ed25519", validate=validate.OneOf(["ed25519", "rsa", "ecdsa"]))
        default_cert_validity_hours = ma_fields.Int(load_default=8, validate=validate.Range(min=1))
        max_cert_validity_hours = ma_fields.Int(load_default=720, validate=validate.Range(min=1))

    try:
        schema = CreateCASchema()
        data = schema.load(request.get_json() or {})

        existing = CA.query.filter_by(organization_id=org_id, name=data["name"], deleted_at=None).first()
        if existing:
            return api_response(success=False, message="A CA with that name already exists in this organization", status=400, error_type="DUPLICATE_NAME")

        ca_type_val = data["ca_type"]
        existing_type = CA.query.filter_by(organization_id=org_id, deleted_at=None).filter(CA.ca_type == CaType(ca_type_val)).first()
        if existing_type:
            type_label = "User" if ca_type_val == "user" else "Host"
            return api_response(success=False, message=f"A {type_label} CA already exists for this organization. You can only have one {type_label} CA per organization.", status=400, error_type="DUPLICATE_CA_TYPE")

        if data["default_cert_validity_hours"] > data["max_cert_validity_hours"]:
            return api_response(success=False, message="Default validity must be less than or equal to maximum validity", status=400, error_type="VALIDATION_ERROR")

        key_type = data["key_type"]
        if key_type == "ed25519":
            private_key_obj = Ed25519PrivateKey.generate()
        elif key_type == "rsa":
            private_key_obj = RsaPrivateKey.generate(4096)
        else:
            private_key_obj = EcdsaPrivateKey.generate()

        private_key_pem = private_key_obj.to_string()
        public_key_str = private_key_obj.public_key.to_string()
        fingerprint = compute_ssh_fingerprint(public_key_str)
        encrypted_private_key = encrypt_ca_key(private_key_pem)

        ca = CA(
            organization_id=org_id,
            name=data["name"],
            description=data["description"],
            ca_type=CaType(ca_type_val),
            key_type=KeyType(key_type),
            private_key=encrypted_private_key,
            public_key=public_key_str,
            fingerprint=fingerprint,
            default_cert_validity_hours=data["default_cert_validity_hours"],
            max_cert_validity_hours=data["max_cert_validity_hours"],
            is_active=True,
        )
        db.session.add(ca)
        try:
            db.session.commit()
        except Exception as commit_exc:
            db.session.rollback()
            exc_str = str(commit_exc).lower()
            if "uix_org_ca_name" in exc_str or "unique" in exc_str:
                return api_response(success=False, message="A CA with that name already exists in this organization (it may have been recently deleted — choose a different name).", status=400, error_type="DUPLICATE_NAME")
            raise

        return api_response(data={"ca": ca.to_dict()}, message="CA created successfully", status=201)
    except MaValidationError as e:
        return api_response(success=False, message="Validation failed", status=400, error_type="VALIDATION_ERROR", error_details=e.messages)
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to create CA")
        return api_response(success=False, message="Failed to create CA", status=500, error_type="SERVER_ERROR")


@api_v1_bp.route("/organizations/<org_id>/cas/<ca_id>", methods=["DELETE"])
@login_required
@require_admin
def delete_org_ca(org_id, ca_id):
    from gatehouse_app.models.ssh_ca.ca import CA
    from gatehouse_app.models.organization.organization import Organization
    from gatehouse_app.utils.constants import AuditAction
    from gatehouse_app.models import AuditLog

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404, error_type="NOT_FOUND")

    ca = CA.query.filter_by(id=ca_id, organization_id=org_id, deleted_at=None).first()
    if not ca:
        return api_response(success=False, message="CA not found", status=404, error_type="NOT_FOUND")

    try:
        ca_name = ca.name
        ca_type = ca.ca_type.value if hasattr(ca.ca_type, "value") else str(ca.ca_type)
        ca.is_active = False
        ca.delete(soft=True)

        AuditLog.log(
            action=AuditAction.CA_DELETED,
            user_id=g.current_user.id,
            resource_type="CA",
            resource_id=ca_id,
            organization_id=org_id,
            ip_address=request.remote_addr,
            description=f"CA '{ca_name}' ({ca_type}) deleted",
        )
        return api_response(data={"ca_id": ca_id}, message="CA deleted successfully")
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to delete CA")
        return api_response(success=False, message="Failed to delete CA", status=500, error_type="SERVER_ERROR")


@api_v1_bp.route("/organizations/<org_id>/cas/<ca_id>/rotate", methods=["POST"])
@login_required
@require_admin
def rotate_org_ca(org_id, ca_id):
    from gatehouse_app.models.ssh_ca.ca import CA, KeyType
    from gatehouse_app.models.organization.organization import Organization
    from gatehouse_app.utils.crypto import compute_ssh_fingerprint
    from gatehouse_app.utils.ca_key_encryption import encrypt_ca_key
    from gatehouse_app.utils.constants import AuditAction
    from gatehouse_app.models import AuditLog
    from sshkey_tools.keys import Ed25519PrivateKey, RsaPrivateKey, EcdsaPrivateKey

    org = Organization.query.filter_by(id=org_id, deleted_at=None).first()
    if not org:
        return api_response(success=False, message="Organization not found", status=404, error_type="NOT_FOUND")

    ca = CA.query.filter_by(id=ca_id, organization_id=org_id, deleted_at=None).first()
    if not ca:
        return api_response(success=False, message="CA not found", status=404, error_type="NOT_FOUND")

    data = request.get_json() or {}
    new_key_type = data.get("key_type") or (ca.key_type.value if hasattr(ca.key_type, "value") else str(ca.key_type))
    reason = data.get("reason", "Admin-initiated key rotation")

    if new_key_type not in ("ed25519", "rsa", "ecdsa"):
        return api_response(success=False, message="Invalid key_type. Must be one of: ed25519, rsa, ecdsa", status=400, error_type="VALIDATION_ERROR")

    try:
        old_fingerprint = ca.fingerprint

        if new_key_type == "ed25519":
            private_key_obj = Ed25519PrivateKey.generate()
        elif new_key_type == "rsa":
            private_key_obj = RsaPrivateKey.generate(4096)
        else:
            private_key_obj = EcdsaPrivateKey.generate()

        new_private_key = private_key_obj.to_string()
        new_public_key = private_key_obj.public_key.to_string()
        new_fingerprint = compute_ssh_fingerprint(new_public_key)
        encrypted_new_private_key = encrypt_ca_key(new_private_key)

        ca.rotate_key(new_private_key=encrypted_new_private_key, new_public_key=new_public_key, new_fingerprint=new_fingerprint, reason=reason)
        ca.key_type = KeyType(new_key_type)
        db.session.commit()

        AuditLog.log(
            action=AuditAction.CA_KEY_ROTATED,
            user_id=g.current_user.id,
            resource_type="CA",
            resource_id=ca_id,
            organization_id=org_id,
            ip_address=request.remote_addr,
            description=(f"CA '{ca.name}' key rotated. Old fingerprint: {old_fingerprint}, New fingerprint: {new_fingerprint}. Reason: {reason}"),
        )

        return api_response(data={"ca": ca.to_dict(), "old_fingerprint": old_fingerprint}, message="CA key rotated successfully. Update TrustedUserCAKeys / known_hosts on your servers.")
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to rotate CA key")
        return api_response(success=False, message="Failed to rotate CA key", status=500, error_type="SERVER_ERROR")
