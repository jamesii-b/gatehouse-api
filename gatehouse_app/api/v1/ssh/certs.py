"""SSH certificate signing and listing endpoints."""
from flask import request, g
from gatehouse_app.api.v1.ssh._helpers import (
    ssh_bp, ssh_key_service, ssh_ca_service,
    _get_org_ca_for_user, _persist_certificate,
    _get_merged_dept_cert_policy, _classify_ssh_key_material,
)
from gatehouse_app.services.ssh_ca_signing_service import SSHCertificateSigningRequest
from gatehouse_app.exceptions import SSHKeyNotFoundError, SSHCertificateError
from gatehouse_app.utils.constants import AuditAction, OrganizationRole
from gatehouse_app.models import AuditLog
from gatehouse_app.models.ssh_ca.certificate_audit_log import CertificateAuditLog
from gatehouse_app.utils.decorators import login_required
from gatehouse_app.utils.response import api_response


@ssh_bp.route('/dept-cert-policy', methods=['GET'])
@login_required
def get_my_dept_cert_policy():
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.organization.department_cert_policy import STANDARD_EXTENSIONS

    user = g.current_user
    user_id = user.id

    is_org_admin = OrganizationMember.query.filter(
        OrganizationMember.user_id == user_id,
        OrganizationMember.role.in_(["OWNER", "ADMIN"]),
        OrganizationMember.deleted_at == None,
    ).first() is not None

    policy = _get_merged_dept_cert_policy(user_id)
    if policy is None:
        policy = {"allow_user_expiry": is_org_admin, "default_expiry_hours": 1, "max_expiry_hours": 24, "extensions": list(STANDARD_EXTENSIONS)}
    elif is_org_admin:
        policy = {**policy, "allow_user_expiry": True}

    return api_response(data={"policy": policy}, message="Certificate policy retrieved")


@ssh_bp.route('/sign', methods=['POST'])
@login_required
def sign_certificate():
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.organization.principal import Principal, PrincipalMembership
    from gatehouse_app.models.organization.department import DepartmentMembership, DepartmentPrincipal
    from gatehouse_app.utils.constants import UserStatus

    user = g.current_user
    user_id = user.id

    if user.status in (UserStatus.SUSPENDED, UserStatus.COMPLIANCE_SUSPENDED):
        return api_response(success=False, message="Your account is suspended. Contact an administrator.", status=403, error_type="ACCOUNT_SUSPENDED")

    data = request.get_json()
    if not data:
        return api_response(success=False, message="No JSON data provided", status=400, error_type="BAD_REQUEST")

    requested_principals = data.get('principals') or []
    cert_type = data.get('cert_type', 'user')
    key_id = data.get('key_id') or data.get('cert_id')
    expiry_hours = data.get('expiry_hours')

    AuditLog.log(
        action=AuditAction.SSH_CERT_REQUESTED,
        user_id=user_id, resource_type='SSHCertificate', ip_address=request.remote_addr,
        description=(f'{user.email} requested a certificate' + (f' for principals: {", ".join(requested_principals)}' if requested_principals else '')),
    )

    allowed_principal_names = set()
    memberships = OrganizationMember.query.filter_by(user_id=user_id).all()
    for om in memberships:
        org = om.organization
        if not org or org.deleted_at is not None:
            continue
        role = om.role
        if role in (OrganizationRole.ADMIN, OrganizationRole.OWNER):
            for p in Principal.query.filter_by(organization_id=org.id, deleted_at=None).all():
                allowed_principal_names.add(p.name)
        else:
            for pm in PrincipalMembership.query.filter_by(user_id=user_id, deleted_at=None).all():
                if pm.principal and pm.principal.organization_id == org.id and pm.principal.deleted_at is None:
                    allowed_principal_names.add(pm.principal.name)
            for dm in DepartmentMembership.query.filter_by(user_id=user_id, deleted_at=None).all():
                if dm.department and dm.department.organization_id == org.id and dm.department.deleted_at is None:
                    for dp in DepartmentPrincipal.query.filter_by(department_id=dm.department_id, deleted_at=None).all():
                        if dp.principal and dp.principal.deleted_at is None:
                            allowed_principal_names.add(dp.principal.name)

    if not requested_principals:
        principals = list(allowed_principal_names)
        if not principals:
            return api_response(success=False, message="You have no principals assigned. Ask an admin to add you to a principal.", status=400, error_type="NO_PRINCIPALS")
    else:
        invalid = [p for p in requested_principals if p not in allowed_principal_names]
        if invalid:
            return api_response(success=False, message=f"You are not authorised to request principals: {', '.join(invalid)}", status=403, error_type="UNAUTHORIZED_PRINCIPALS")
        principals = requested_principals

    if not key_id:
        verified_keys = ssh_key_service.get_user_verified_ssh_keys(user_id)
        if not verified_keys:
            return api_response(success=False, message="No verified SSH keys found. Verify a key before requesting a certificate.", status=400, error_type="NO_VERIFIED_KEYS")
        key_id = verified_keys[0].id

    try:
        ssh_key = ssh_key_service.get_ssh_key(key_id)
    except SSHKeyNotFoundError:
        return api_response(success=False, message="SSH key not found", status=404, error_type="NOT_FOUND")

    if ssh_key.user_id != user_id:
        return api_response(success=False, message="Forbidden", status=403, error_type="FORBIDDEN")

    if not ssh_key.verified:
        return api_response(success=False, message="SSH key is not verified. Verify it before requesting a certificate.", status=400, error_type="KEY_NOT_VERIFIED")

    db_ca = _get_org_ca_for_user(user, ca_type=cert_type)
    if db_ca is None:
        return api_response(
            success=False,
            message="No active Certificate Authority is configured for your organization. An admin must generate a CA on the Certificate Authorities page before certificates can be issued.",
            status=503, error_type="CA_NOT_CONFIGURED",
        )

    is_org_admin = any(
        om.role in (OrganizationRole.ADMIN, OrganizationRole.OWNER)
        for om in memberships
        if om.organization and om.organization.deleted_at is None
    )

    dept_policy = _get_merged_dept_cert_policy(user_id)
    if dept_policy:
        if not dept_policy["allow_user_expiry"]:
            expiry_hours = dept_policy["default_expiry_hours"]
        elif is_org_admin:
            if expiry_hours is not None:
                expiry_hours = min(int(expiry_hours), dept_policy["max_expiry_hours"])
            else:
                expiry_hours = dept_policy["default_expiry_hours"]
        else:
            if expiry_hours is not None:
                expiry_hours = min(int(expiry_hours), dept_policy["max_expiry_hours"])
            else:
                expiry_hours = dept_policy["default_expiry_hours"]
        policy_extensions = dept_policy["extensions"]
    else:
        policy_extensions = None

    org_slugs = sorted({
        om.organization.slug for om in memberships
        if om.organization and om.organization.deleted_at is None and getattr(om.organization, 'slug', None)
    })
    org_slug = org_slugs[0] if org_slugs else "unknown"
    full_name = getattr(user, 'full_name', None) or getattr(user, 'name', None) or "unknown"
    cert_identity = f"{user.email} ({full_name}) [org:{org_slug}]"

    signing_request = SSHCertificateSigningRequest(
        ssh_public_key=ssh_key.payload, principals=principals, cert_type=cert_type,
        key_id=cert_identity, expiry_hours=int(expiry_hours) if expiry_hours else None,
        extensions=policy_extensions,
    )
    validation_errors = signing_request.validate()
    if validation_errors:
        return api_response(success=False, message="Invalid signing request", status=400, error_type="VALIDATION_ERROR", error_details={"errors": validation_errors})

    try:
        from gatehouse_app.utils.ca_key_encryption import decrypt_ca_key
        ca_private_key_pem = decrypt_ca_key(db_ca.private_key)
        response = ssh_ca_service.sign_certificate(signing_request, ca_private_key=ca_private_key_pem, ca_obj=db_ca)
    except SSHCertificateError as e:
        AuditLog.log(action=AuditAction.SSH_CERT_FAILED, user_id=user_id, resource_type='SSHCertificate', ip_address=request.remote_addr, success=False, error_message=str(e))
        return api_response(success=False, message=str(e), status=400, error_type="SIGNING_FAILED")
    except Exception as e:
        AuditLog.log(action=AuditAction.SSH_CERT_FAILED, user_id=user_id, resource_type='SSHCertificate', ip_address=request.remote_addr, success=False, error_message=str(e))
        return api_response(success=False, message="Certificate signing failed", status=500, error_type="SERVER_ERROR")

    cert_record = _persist_certificate(
        user_id=user_id, ssh_key_id=key_id, ca=db_ca,
        signing_response=response, request_ip=request.remote_addr,
        cert_type_str=cert_type, cert_identity=cert_identity,
    )

    AuditLog.log(
        action=AuditAction.SSH_CERT_ISSUED, user_id=user_id,
        resource_type='SSHCertificate', resource_id=cert_record.id if cert_record else key_id,
        ip_address=request.remote_addr,
        description=f'Certificate serial={response.serial} issued for {user.email}; principals: {", ".join(principals)}',
        extra_data={'serial': response.serial, 'key_id': cert_identity, 'principals': principals, 'ca_id': str(db_ca.id), 'ssh_key_id': str(key_id)},
    )

    if cert_record:
        CertificateAuditLog.log(
            certificate_id=cert_record.id, action='issued', user_id=user_id,
            ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent'),
            message=f'Certificate serial={response.serial} issued for {user.email}; principals: {", ".join(principals)}',
            extra_data={
                'serial': response.serial, 'key_id': cert_identity, 'principals': principals,
                'ca_id': str(db_ca.id), 'ssh_key_id': str(key_id),
                'valid_after': response.valid_after.isoformat() if response.valid_after else None,
                'valid_before': response.valid_before.isoformat() if response.valid_before else None,
            },
            success=True,
        )

    result = {
        'certificate': response.certificate, 'serial': response.serial,
        'principals': response.principals,
        'valid_after': response.valid_after.isoformat() if response.valid_after else None,
        'valid_before': response.valid_before.isoformat() if response.valid_before else None,
    }
    if cert_record:
        result['cert_id'] = str(cert_record.id)

    return api_response(data=result, message="Certificate signed successfully", status=201)


@ssh_bp.route('/sign/host', methods=['POST'])
@login_required
def sign_host_certificate():
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.ssh_ca.ca import CA, CaType
    from gatehouse_app.utils.ca_key_encryption import decrypt_ca_key

    user = g.current_user
    user_id = user.id

    is_admin = OrganizationMember.query.filter(
        OrganizationMember.user_id == user_id,
        OrganizationMember.role.in_([OrganizationRole.ADMIN, OrganizationRole.OWNER]),
        OrganizationMember.deleted_at.is_(None),
    ).first() is not None

    if not is_admin:
        return api_response(success=False, message="Issuing host certificates requires org admin or owner role.", status=403, error_type="FORBIDDEN")

    data = request.get_json()
    if not data:
        return api_response(success=False, message="No JSON data provided", status=400, error_type="BAD_REQUEST")

    host_public_key = (data.get("host_public_key") or "").strip()
    principals = data.get("principals") or []
    validity_hours = data.get("validity_hours", 720)
    ca_id = (data.get("ca_id") or "").strip()

    if not host_public_key:
        return api_response(success=False, message="host_public_key is required.", status=400, error_type="BAD_REQUEST")

    key_kind = _classify_ssh_key_material(host_public_key)
    if key_kind == "certificate":
        return api_response(success=False, message="You submitted a certificate (ssh-…-cert-v01@openssh.com), not a host public key. Retrieve the server's host public key with: cat /etc/ssh/ssh_host_ed25519_key.pub", status=400, error_type="WRONG_KEY_MATERIAL")
    if key_kind == "private_key":
        return api_response(success=False, message="Private keys must never be submitted here. Use the .pub file.", status=400, error_type="WRONG_KEY_MATERIAL")
    if key_kind == "unknown":
        return api_response(success=False, message="Unrecognised key format. Expected an OpenSSH public key starting with ssh-ed25519, ssh-rsa, or ecdsa-sha2-*.", status=400, error_type="WRONG_KEY_MATERIAL")

    if not principals or not isinstance(principals, list):
        return api_response(success=False, message="principals must be a non-empty list of hostnames.", status=422, error_type="VALIDATION_ERROR")
    principals = [str(p).strip() for p in principals if str(p).strip()]
    if not principals:
        return api_response(success=False, message="At least one principal (hostname/FQDN) is required.", status=422, error_type="VALIDATION_ERROR")

    try:
        validity_hours = int(validity_hours)
        if validity_hours < 1:
            raise ValueError
    except (TypeError, ValueError):
        return api_response(success=False, message="validity_hours must be a positive integer.", status=422, error_type="VALIDATION_ERROR")

    if not ca_id:
        return api_response(success=False, message="ca_id is required.", status=400, error_type="BAD_REQUEST")

    org_ids = [m.organization_id for m in OrganizationMember.query.filter_by(user_id=user_id, deleted_at=None).all()]

    any_ca = CA.query.filter(CA.id == ca_id, CA.is_active.is_(True), CA.organization_id.in_(org_ids), CA.deleted_at.is_(None)).first()

    if any_ca and any_ca.ca_type != CaType.HOST:
        return api_response(success=False, message=f"The CA '{any_ca.name}' is a {any_ca.ca_type.value} CA. Host certificates must be signed by a ca_type='host' CA.", status=400, error_type="WRONG_CA_TYPE")

    host_ca = any_ca
    if not host_ca:
        return api_response(success=False, message="Host CA not found, inactive, or you do not have permission to use it. Ensure the CA exists and ca_type is 'host'.", status=404, error_type="CA_NOT_FOUND")

    primary_principal = principals[0]
    cert_identity = f"host:{primary_principal} [signed-by:{user.email}]"

    signing_request = SSHCertificateSigningRequest(
        ssh_public_key=host_public_key, principals=principals, cert_type="host",
        key_id=cert_identity, expiry_hours=validity_hours, extensions=[], critical_options={},
    )
    validation_errors = signing_request.validate()
    if validation_errors:
        return api_response(success=False, message="Invalid signing request: " + "; ".join(validation_errors), status=422, error_type="VALIDATION_ERROR")

    try:
        ca_private_key_pem = decrypt_ca_key(host_ca.private_key)
        response = ssh_ca_service.sign_certificate(signing_request, ca_private_key=ca_private_key_pem, ca_obj=host_ca)
    except Exception as exc:
        AuditLog.log(action=AuditAction.SSH_CERT_FAILED, user_id=user_id, resource_type="SSHCertificate", ip_address=request.remote_addr, success=False, error_message=str(exc))
        return api_response(success=False, message=f"Host certificate signing failed: {exc}", status=500, error_type="SIGNING_FAILED")

    cert_record = _persist_certificate(
        user_id=user_id, ssh_key_id=None, ca=host_ca,
        signing_response=response, request_ip=request.remote_addr,
        cert_type_str="host", cert_identity=cert_identity,
    )

    AuditLog.log(
        action=AuditAction.SSH_CERT_ISSUED, user_id=user_id,
        resource_type="SSHCertificate", resource_id=cert_record.id if cert_record else None,
        ip_address=request.remote_addr,
        description=f"Host certificate serial={response.serial} issued for {primary_principal} by {user.email}",
        extra_data={"serial": response.serial, "principals": principals, "ca_id": str(host_ca.id), "cert_type": "host"},
    )

    result = {
        "certificate": response.certificate, "serial": response.serial, "principals": response.principals,
        "valid_after": response.valid_after.isoformat() if response.valid_after else None,
        "valid_before": response.valid_before.isoformat() if response.valid_before else None,
    }
    if cert_record:
        result["cert_id"] = str(cert_record.id)

    return api_response(data=result, message="Host certificate issued successfully", status=201)


@ssh_bp.route('/certificates', methods=['GET'])
@login_required
def list_certificates():
    user_id = g.current_user.id
    try:
        from gatehouse_app.models.ssh_ca.ssh_certificate import SSHCertificate
        certs = SSHCertificate.query.filter_by(user_id=user_id, deleted_at=None).order_by(SSHCertificate.created_at.desc()).all()
        return api_response(data={'certificates': [c.to_dict() for c in certs], 'count': len(certs)}, message="Certificates retrieved successfully")
    except Exception as e:
        return api_response(success=False, message=str(e), status=500, error_type='INTERNAL_ERROR')


@ssh_bp.route('/certificates/<cert_id>', methods=['GET'])
@login_required
def get_certificate(cert_id):
    user_id = g.current_user.id
    try:
        from gatehouse_app.models.ssh_ca.ssh_certificate import SSHCertificate
        cert = SSHCertificate.query.filter_by(id=cert_id, deleted_at=None).first()
        if not cert:
            return api_response(success=False, message='Certificate not found', status=404, error_type='NOT_FOUND')
        if cert.user_id != user_id:
            return api_response(success=False, message='Forbidden', status=403, error_type='FORBIDDEN')
        data = cert.to_dict()
        data['certificate'] = cert.certificate
        return api_response(success=True, message='Certificate retrieved', data=data, status=200)
    except Exception as e:
        return api_response(success=False, message=str(e), status=500, error_type='INTERNAL_ERROR')


@ssh_bp.route('/certificates/<cert_id>/revoke', methods=['POST'])
@login_required
def revoke_certificate(cert_id):
    user_id = g.current_user.id
    data = request.get_json() or {}
    reason = data.get('reason', 'User requested revocation')
    try:
        from gatehouse_app.models.ssh_ca.ssh_certificate import SSHCertificate
        cert = SSHCertificate.query.filter_by(id=cert_id, deleted_at=None).first()
        if not cert:
            return api_response(success=False, message='Certificate not found', status=404, error_type='NOT_FOUND')
        if cert.user_id != user_id:
            return api_response(success=False, message='Forbidden', status=403, error_type='FORBIDDEN')
        if cert.revoked:
            return api_response(success=False, message='Certificate is already revoked', status=409, error_type='ALREADY_REVOKED')

        cert.revoke(reason=reason)
        AuditLog.log(action=AuditAction.SSH_CERT_REVOKED, user_id=user_id, resource_type='SSHCertificate', resource_id=cert_id, ip_address=request.remote_addr, description=f'Revoked: {reason}')
        CertificateAuditLog.log(certificate_id=cert_id, action='revoked', user_id=user_id, ip_address=request.remote_addr, user_agent=request.headers.get('User-Agent'), message=f'Certificate revoked: {reason}', success=True)

        return api_response(success=True, message='Certificate revoked successfully', data={'status': 'revoked', 'cert_id': cert_id, 'reason': reason}, status=200)
    except Exception as e:
        return api_response(success=False, message=str(e), status=500, error_type='INTERNAL_ERROR')


@ssh_bp.route('/ca/public-key', methods=['GET'])
@login_required
def get_ca_public_key():
    user = g.current_user
    ca_type = request.args.get("ca_type", "user")
    if ca_type not in ("user", "host"):
        return api_response(success=False, message="ca_type must be 'user' or 'host'", status=400, error_type="BAD_REQUEST")

    db_ca = _get_org_ca_for_user(user, ca_type=ca_type)
    if db_ca:
        return api_response(
            data={'public_key': db_ca.public_key, 'fingerprint': db_ca.fingerprint, 'ca_name': db_ca.name, 'ca_type': ca_type, 'source': 'db'},
            message="CA public key retrieved successfully",
        )
    return api_response(success=False, message=f"No {ca_type} CA is configured for your organization. An admin must generate one on the Certificate Authorities page.", status=404, error_type="CA_NOT_CONFIGURED")
