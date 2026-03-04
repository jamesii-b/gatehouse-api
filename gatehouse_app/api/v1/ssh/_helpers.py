"""Shared helpers for the SSH subpackage."""
import logging
from flask import Blueprint, request, g
from gatehouse_app.services.ssh_key_service import SSHKeyService
from gatehouse_app.services.ssh_ca_signing_service import SSHCASigningService

ssh_bp = Blueprint('ssh', __name__, url_prefix='/ssh')
ssh_key_service = SSHKeyService()
ssh_ca_service = SSHCASigningService()

_logger = logging.getLogger(__name__)


def _get_org_ca_for_user(user, ca_type: str = "user"):
    try:
        from gatehouse_app.models.ssh_ca.ca import CA, CaType
        org_ids = [m.organization_id for m in user.organization_memberships]
        if not org_ids:
            return None
        return CA.query.filter(
            CA.organization_id.in_(org_ids),
            CA.ca_type == CaType(ca_type),
            CA.is_active == True,  # noqa: E712
        ).first()
    except Exception:
        return None


def _get_or_create_system_ca():
    from gatehouse_app.extensions import db
    from gatehouse_app.models.ssh_ca.ca import CA, KeyType
    from gatehouse_app.config.ssh_ca_config import get_ssh_ca_config
    from gatehouse_app.utils.crypto import compute_ssh_fingerprint
    import os

    try:
        existing = CA.query.filter_by(name="system-config-ca").first()
        if existing:
            return existing

        cfg = get_ssh_ca_config()
        key_path = cfg.get_str("ca_key_path", "").strip()
        pub_key_path = key_path + ".pub"

        if not os.path.exists(pub_key_path):
            return None

        with open(pub_key_path) as f:
            pub_key = f.read().strip()

        priv_key = ""
        if os.path.exists(key_path):
            with open(key_path) as f:
                raw_priv_key = f.read()
            try:
                from gatehouse_app.utils.ca_key_encryption import encrypt_ca_key
                priv_key = encrypt_ca_key(raw_priv_key)
            except Exception:
                priv_key = raw_priv_key

        fingerprint = compute_ssh_fingerprint(pub_key)

        existing_by_fp = CA.query.filter_by(fingerprint=fingerprint).first()
        if existing_by_fp:
            return existing_by_fp

        system_ca = CA(
            name="system-config-ca",
            description="Global CA loaded from etc/ssh_ca.conf (ca_key_path)",
            key_type=KeyType.ED25519,
            private_key=priv_key,
            public_key=pub_key,
            fingerprint=fingerprint,
            is_active=True,
            default_cert_validity_hours=24,
            max_cert_validity_hours=720,
        )
        db.session.add(system_ca)
        db.session.commit()
        return system_ca
    except Exception as exc:
        _logger.warning(f"Could not upsert system-config-ca: {exc}")
        try:
            db.session.rollback()
        except Exception:
            pass
        return None


def _persist_certificate(user_id, ssh_key_id, ca, signing_response, request_ip=None, cert_type_str='user', cert_identity=None):
    if ca is None:
        return None

    try:
        from gatehouse_app.extensions import db
        from gatehouse_app.models.ssh_ca.ssh_certificate import SSHCertificate, CertificateStatus
        from gatehouse_app.models.ssh_ca.ca import CertType

        try:
            resolved_cert_type = CertType(cert_type_str)
        except ValueError:
            resolved_cert_type = CertType.USER

        cert_record = SSHCertificate(
            ca_id=ca.id,
            user_id=user_id,
            ssh_key_id=ssh_key_id,
            certificate=signing_response.certificate,
            serial=signing_response.serial,
            key_id=cert_identity or (str(ssh_key_id) if ssh_key_id else "host-cert"),
            cert_type=resolved_cert_type,
            principals=signing_response.principals,
            valid_after=signing_response.valid_after,
            valid_before=signing_response.valid_before,
            revoked=False,
            status=CertificateStatus.ISSUED,
            request_ip=request_ip,
        )
        db.session.add(cert_record)
        db.session.commit()
        return cert_record
    except Exception as exc:
        _logger.warning(f"Failed to persist certificate to DB: {exc}")
        try:
            from gatehouse_app.extensions import db as _db
            _db.session.rollback()
        except Exception:
            pass
        return None


def _get_merged_dept_cert_policy(user_id):
    from gatehouse_app.models.organization.department import DepartmentMembership
    from gatehouse_app.models.organization.department_cert_policy import DepartmentCertPolicy

    memberships = DepartmentMembership.query.filter_by(user_id=user_id, deleted_at=None).all()
    dept_ids = [m.department_id for m in memberships if m.department and m.department.deleted_at is None]
    if not dept_ids:
        return None

    policies = DepartmentCertPolicy.query.filter(
        DepartmentCertPolicy.department_id.in_(dept_ids),
        DepartmentCertPolicy.deleted_at.is_(None),
    ).all()
    if not policies:
        return None

    allow_user_expiry = all(p.allow_user_expiry for p in policies)
    default_expiry_hours = min(p.default_expiry_hours for p in policies)
    max_expiry_hours = min(p.max_expiry_hours for p in policies)
    ext_sets = [set(p.all_extensions()) for p in policies]
    extensions = list(ext_sets[0].intersection(*ext_sets[1:]))

    return {
        "allow_user_expiry": allow_user_expiry,
        "default_expiry_hours": default_expiry_hours,
        "max_expiry_hours": max_expiry_hours,
        "extensions": extensions,
    }


def _classify_ssh_key_material(raw: str) -> str:
    import re
    line = raw.strip().split()[0] if raw.strip() else ""
    if re.search(r"-cert-v01@openssh\.com$", line):
        return "certificate"
    if re.match(
        r"^(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com)$",
        line,
    ):
        return "public_key"
    if "BEGIN OPENSSH PRIVATE KEY" in raw or "BEGIN RSA PRIVATE KEY" in raw:
        return "private_key"
    return "unknown"
