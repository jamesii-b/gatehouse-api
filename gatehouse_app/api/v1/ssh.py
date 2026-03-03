"""SSH Key and Certificate API routes."""
from flask import Blueprint, request, jsonify, g
from sqlalchemy.exc import IntegrityError
from gatehouse_app.services.ssh_key_service import SSHKeyService
from gatehouse_app.services.ssh_ca_signing_service import (
    SSHCASigningService,
    SSHCertificateSigningRequest,
)
from gatehouse_app.exceptions import (
    SSHKeyError,
    SSHKeyNotFoundError,
    SSHCertificateError,
    ValidationError,
    SSHKeyAlreadyExistsError,
)
from gatehouse_app.utils.constants import AuditAction
from gatehouse_app.models import AuditLog
from gatehouse_app.models.ssh_ca.certificate_audit_log import CertificateAuditLog
from gatehouse_app.utils.decorators import login_required
from gatehouse_app.utils.response import api_response

ssh_bp = Blueprint('ssh', __name__, url_prefix='/ssh')
ssh_key_service = SSHKeyService()
ssh_ca_service = SSHCASigningService()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_org_ca_for_user(user, ca_type: str = "user"):
    """Return the active DB CA of the given type for the user's first org, or None.

    Args:
        user: The current user object.
        ca_type: ``"user"`` (default) or ``"host"`` — selects the CA that signs
                 the corresponding certificate type.
    """
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
    """
    Return a CA DB record representing the config-file CA.

    This is used as the ``ca_id`` FK when persisting certificates that were
    signed by the globally-configured CA key (not an org-specific DB CA).
    The record is created on first use and has no ``organization_id``.
    """
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

        # Load private key for the record (encrypt before storing in DB)
        priv_key = ""
        if os.path.exists(key_path):
            with open(key_path) as f:
                raw_priv_key = f.read()
            try:
                from gatehouse_app.utils.ca_key_encryption import encrypt_ca_key
                priv_key = encrypt_ca_key(raw_priv_key)
            except Exception:
                priv_key = raw_priv_key  # fallback: store as-is if encryption unavailable

        fingerprint = compute_ssh_fingerprint(pub_key)

        # Check by fingerprint in case it was created under a different name
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
        # organization_id is nullable=False in schema — we need a dummy org or
        # need to allow NULL.  Use None; the DB constraint will tell us quickly.
        # If the migration enforces NOT NULL we'll catch the error gracefully.
        db.session.add(system_ca)
        db.session.commit()
        return system_ca
    except Exception as exc:
        import logging
        logging.getLogger(__name__).warning(
            f"Could not upsert system-config-ca: {exc}"
        )
        try:
            db.session.rollback()
        except Exception:
            pass
        return None


def _persist_certificate(user_id, ssh_key_id, ca, signing_response, request_ip=None, cert_type_str='user', cert_identity=None):
    """Save a signed certificate to the ssh_certificates table.

    Args:
        user_id: UUID of the user
        ssh_key_id: UUID of the SSH key that was signed.  May be None for host
                    certificates issued against a raw public key (no pre-registered
                    SSHKey DB record).  When None the record is still persisted
                    but ``ssh_key_id`` is left NULL (requires nullable FK migration).
        ca: CA model instance (may be None — cert still returned but not persisted)
        signing_response: SSHCertificateSigningResponse
        request_ip: Client IP address
        cert_type_str: 'user' or 'host' (from the sign request)
        cert_identity: Rich OpenSSH key_id string (e.g. "user@host (Name) [org:slug]").
                       Falls back to str(ssh_key_id) when not provided.

    Returns:
        SSHCertificate instance or None if persistence failed
    """
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
            ssh_key_id=ssh_key_id,   # None is OK for host certs (nullable FK)
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
        import logging
        logging.getLogger(__name__).warning(
            f"Failed to persist certificate to DB: {exc}"
        )
        try:
            from gatehouse_app.extensions import db as _db
            _db.session.rollback()
        except Exception:
            pass
        return None



def _get_merged_dept_cert_policy(user_id):
    """Return a merged cert policy view for the given user across all their departments.

    Rules for merging when a user belongs to multiple departments:
    - ``allow_user_expiry``: True only if ALL departments allow it.
    - ``default_expiry_hours``: minimum across departments (most restrictive).
    - ``max_expiry_hours``: minimum across departments (most restrictive).
    - ``extensions``: intersection — only extensions allowed by ALL departments.

    Returns a plain dict with keys:
        allow_user_expiry, default_expiry_hours, max_expiry_hours, extensions
    Or None if the user has no department memberships or no policies are configured.
    """
    from gatehouse_app.models.organization.department import DepartmentMembership
    from gatehouse_app.models.organization.department_cert_policy import DepartmentCertPolicy, STANDARD_EXTENSIONS

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

    # Intersection of all_extensions() across policies
    ext_sets = [set(p.all_extensions()) for p in policies]
    extensions = list(ext_sets[0].intersection(*ext_sets[1:]))

    return {
        "allow_user_expiry": allow_user_expiry,
        "default_expiry_hours": default_expiry_hours,
        "max_expiry_hours": max_expiry_hours,
        "extensions": extensions,
    }


@ssh_bp.route('/dept-cert-policy', methods=['GET'])
@login_required
def get_my_dept_cert_policy():
    """Return the merged department certificate policy for the current user.

    Admins always get allow_user_expiry=True so the frontend shows the expiry
    picker for them regardless of the member-facing toggle setting.
    """
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.organization.department_cert_policy import STANDARD_EXTENSIONS
    from gatehouse_app.utils.constants import OrganizationRole

    user = g.current_user
    user_id = user.id

    # Check if caller is an org admin/owner
    is_org_admin = OrganizationMember.query.filter(
        OrganizationMember.user_id == user_id,
        OrganizationMember.role.in_(["OWNER", "ADMIN"]),
        OrganizationMember.deleted_at == None,
    ).first() is not None

    policy = _get_merged_dept_cert_policy(user_id)
    if policy is None:
        policy = {
            "allow_user_expiry": is_org_admin,  # admins default to True even without a dept policy
            "default_expiry_hours": 1,
            "max_expiry_hours": 24,
            "extensions": list(STANDARD_EXTENSIONS),
        }
    elif is_org_admin:
        # Override allow_user_expiry for admins — they can always pick
        policy = {**policy, "allow_user_expiry": True}

    return api_response(data={"policy": policy}, message="Certificate policy retrieved")


@ssh_bp.route('/keys', methods=['GET'])
@login_required
def list_ssh_keys():
    """Get all SSH keys for current user."""
    user_id = g.current_user.id
    
    keys = ssh_key_service.get_user_ssh_keys(user_id)
    return api_response(
        data={
            'keys': [k.to_dict() for k in keys],
            'count': len(keys),
        },
        message="SSH keys retrieved successfully"
    )


@ssh_bp.route('/keys', methods=['POST'])
@login_required
def add_ssh_key():
    """Add a new SSH public key for current user."""
    user_id = g.current_user.id

    data = request.get_json()
    if not data:
        return api_response(success=False, message='No JSON data provided', status=400, error_type='BAD_REQUEST')

    public_key = data.get('public_key') or data.get('key')
    description = data.get('description')

    if not public_key:
        return api_response(success=False, message='public_key is required', status=400, error_type='BAD_REQUEST')

    try:
        ssh_key = ssh_key_service.add_ssh_key(
            user_id=user_id,
            public_key=public_key,
            description=description,
        )

        AuditLog.log(
            action=AuditAction.SSH_KEY_ADDED,
            user_id=user_id,
            resource_type='SSHKey',
            resource_id=ssh_key.id,
            ip_address=request.remote_addr,
        )

        return api_response(success=True, message='SSH key added', data=ssh_key.to_dict(), status=201)

    except SSHKeyAlreadyExistsError as e:
        return api_response(success=False, message=e.message, status=409, error_type='SSH_KEY_ALREADY_EXISTS')
    except IntegrityError:
        return api_response(success=False, message='SSH key already exists', status=409, error_type='SSH_KEY_ALREADY_EXISTS')
    except SSHKeyError as e:
        return api_response(success=False, message=str(e), status=400, error_type='SSH_KEY_ERROR')
    except ValidationError as e:
        return api_response(success=False, message=str(e), status=400, error_type='VALIDATION_ERROR')


@ssh_bp.route('/keys/<key_id>', methods=['GET'])
@login_required
def get_ssh_key(key_id):
    """Get a specific SSH key."""
    user_id = g.current_user.id

    try:
        ssh_key = ssh_key_service.get_ssh_key(key_id)

        if ssh_key.user_id != user_id:
            return api_response(success=False, message='Forbidden', status=403, error_type='FORBIDDEN')

        return api_response(success=True, message='SSH key retrieved', data=ssh_key.to_dict(), status=200)

    except SSHKeyNotFoundError:
        return api_response(success=False, message='SSH key not found', status=404, error_type='NOT_FOUND')


@ssh_bp.route('/keys/<key_id>', methods=['DELETE'])
@login_required
def delete_ssh_key(key_id):
    """Delete an SSH key."""
    user_id = g.current_user.id

    try:
        ssh_key = ssh_key_service.get_ssh_key(key_id)

        if ssh_key.user_id != user_id:
            return api_response(success=False, message='Forbidden', status=403, error_type='FORBIDDEN')

        ssh_key_service.delete_ssh_key(key_id)

        AuditLog.log(
            action=AuditAction.SSH_KEY_DELETED,
            user_id=user_id,
            resource_type='SSHKey',
            resource_id=key_id,
            ip_address=request.remote_addr,
        )

        return api_response(success=True, message='SSH key deleted', data={'status': 'deleted'}, status=200)

    except SSHKeyNotFoundError:
        return api_response(success=False, message='SSH key not found', status=404, error_type='NOT_FOUND')


@ssh_bp.route('/keys/<key_id>/verify', methods=['GET', 'POST'])
@login_required
def verify_ssh_key(key_id):
    """Generate or verify SSH key ownership challenge."""
    user_id = g.current_user.id

    try:
        ssh_key = ssh_key_service.get_ssh_key(key_id)

        if ssh_key.user_id != user_id:
            return api_response(success=False, message='Forbidden', status=403, error_type='FORBIDDEN')

        # GET — return a fresh challenge
        if request.method == 'GET':
            challenge = ssh_key_service.generate_verification_challenge(key_id)
            return api_response(success=True, message='Challenge generated', data={
                'challenge_text': challenge,
                'validationText': challenge,
                'key_id': key_id,
            }, status=200)

        # POST — verify signature or generate challenge
        data = request.get_json() or {}
        action = data.get('action', 'verify_signature')

        if action == 'verify_signature':
            signature = data.get('signature')
            if not signature:
                return api_response(success=False, message='signature is required', status=400, error_type='BAD_REQUEST')

            try:
                verified = ssh_key_service.verify_ssh_key_ownership(key_id, signature)

                AuditLog.log(
                    action=AuditAction.SSH_KEY_VERIFIED,
                    user_id=user_id,
                    resource_type='SSHKey',
                    resource_id=key_id,
                    ip_address=request.remote_addr,
                    success=verified,
                )

                return api_response(success=True, message='Verification complete', data={'verified': verified}, status=200)

            except Exception as e:
                AuditLog.log(
                    action=AuditAction.SSH_KEY_VALIDATION_FAILED,
                    user_id=user_id,
                    resource_type='SSHKey',
                    resource_id=key_id,
                    ip_address=request.remote_addr,
                    success=False,
                    error_message=str(e),
                )
                return api_response(success=False, message=str(e), status=400, error_type='VERIFICATION_FAILED')

        else:  # generate_challenge
            challenge = ssh_key_service.generate_verification_challenge(key_id)
            return api_response(success=True, message='Challenge generated', data={
                'challenge_text': challenge,
                'challenge': challenge,
            }, status=200)

    except SSHKeyNotFoundError:
        return api_response(success=False, message='SSH key not found', status=404, error_type='NOT_FOUND')


@ssh_bp.route('/keys/<key_id>/update-description', methods=['PATCH'])
@login_required
def update_ssh_key_description(key_id):
    """Update SSH key description."""
    user_id = g.current_user.id

    data = request.get_json()
    if not data or 'description' not in data:
        return api_response(success=False, message='description is required', status=400, error_type='BAD_REQUEST')

    try:
        ssh_key = ssh_key_service.get_ssh_key(key_id)

        if ssh_key.user_id != user_id:
            return api_response(success=False, message='Forbidden', status=403, error_type='FORBIDDEN')

        updated_key = ssh_key_service.update_ssh_key_description(key_id, data['description'])

        return api_response(success=True, message='Description updated', data=updated_key.to_dict(), status=200)

    except SSHKeyNotFoundError:
        return api_response(success=False, message='SSH key not found', status=404, error_type='NOT_FOUND')


@ssh_bp.route('/sign', methods=['POST'])
@login_required
def sign_certificate():
    """Sign an SSH certificate for the current user."""
    user = g.current_user
    user_id = user.id

    # ── Check account suspension ──────────────────────────────────────────────
    from gatehouse_app.utils.constants import UserStatus
    if user.status in (UserStatus.SUSPENDED, UserStatus.COMPLIANCE_SUSPENDED):
        return api_response(
            success=False,
            message="Your account is suspended. Contact an administrator.",
            status=403,
            error_type="ACCOUNT_SUSPENDED",
        )

    data = request.get_json()
    if not data:
        return api_response(success=False, message="No JSON data provided", status=400, error_type="BAD_REQUEST")

    requested_principals = data.get('principals') or []
    cert_type = data.get('cert_type', 'user')
    key_id = data.get('key_id') or data.get('cert_id')
    expiry_hours = data.get('expiry_hours')

    # ── Log the request ───────────────────────────────────────────────────────
    AuditLog.log(
        action=AuditAction.SSH_CERT_REQUESTED,
        user_id=user_id,
        resource_type='SSHCertificate',
        ip_address=request.remote_addr,
        description=(
            f'{user.email} requested a certificate'
            + (f' for principals: {", ".join(requested_principals)}' if requested_principals else '')
        ),
    )

    # ── Resolve which principals the user is allowed to use ──────────────────
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.organization.principal import Principal, PrincipalMembership
    from gatehouse_app.models.organization.department import DepartmentMembership, DepartmentPrincipal
    from gatehouse_app.utils.constants import OrganizationRole

    allowed_principal_names = set()

    memberships = OrganizationMember.query.filter_by(user_id=user_id).all()
    for om in memberships:
        org = om.organization
        if not org or org.deleted_at is not None:
            continue
        role = om.role
        if role in (OrganizationRole.ADMIN, OrganizationRole.OWNER):
            # Admin/owner can use any principal in the org
            for p in Principal.query.filter_by(organization_id=org.id, deleted_at=None).all():
                allowed_principal_names.add(p.name)
        else:
            # Direct memberships
            for pm in PrincipalMembership.query.filter_by(user_id=user_id, deleted_at=None).all():
                if pm.principal and pm.principal.organization_id == org.id and pm.principal.deleted_at is None:
                    allowed_principal_names.add(pm.principal.name)
            # Via department
            for dm in DepartmentMembership.query.filter_by(user_id=user_id, deleted_at=None).all():
                if dm.department and dm.department.organization_id == org.id and dm.department.deleted_at is None:
                    for dp in DepartmentPrincipal.query.filter_by(department_id=dm.department_id, deleted_at=None).all():
                        if dp.principal and dp.principal.deleted_at is None:
                            allowed_principal_names.add(dp.principal.name)

    # ── Determine final principals list ─────────────────────────────────────
    if not requested_principals:
        # Auto-resolve: use all principals the user is assigned to
        principals = list(allowed_principal_names)
        if not principals:
            return api_response(
                success=False,
                message="You have no principals assigned. Ask an admin to add you to a principal.",
                status=400,
                error_type="NO_PRINCIPALS",
            )
    else:
        # Validate each requested principal is within the user's allowed set
        invalid = [p for p in requested_principals if p not in allowed_principal_names]
        if invalid:
            return api_response(
                success=False,
                message=f"You are not authorised to request principals: {', '.join(invalid)}",
                status=403,
                error_type="UNAUTHORIZED_PRINCIPALS",
            )
        principals = requested_principals

    # ── Key resolution ────────────────────────────────────────────────────────
    if not key_id:
        verified_keys = ssh_key_service.get_user_verified_ssh_keys(user_id)
        if not verified_keys:
            return api_response(
                success=False,
                message="No verified SSH keys found. Verify a key before requesting a certificate.",
                status=400,
                error_type="NO_VERIFIED_KEYS",
            )
        key_id = verified_keys[0].id

    try:
        ssh_key = ssh_key_service.get_ssh_key(key_id)
    except SSHKeyNotFoundError:
        return api_response(success=False, message="SSH key not found", status=404, error_type="NOT_FOUND")

    if ssh_key.user_id != user_id:
        return api_response(success=False, message="Forbidden", status=403, error_type="FORBIDDEN")

    if not ssh_key.verified:
        return api_response(
            success=False,
            message="SSH key is not verified. Verify it before requesting a certificate.",
            status=400,
            error_type="KEY_NOT_VERIFIED",
        )

    db_ca = _get_org_ca_for_user(user, ca_type=cert_type)
    if db_ca is None:
        return api_response(
            success=False,
            message=(
                "No active Certificate Authority is configured for your organization. "
                "An admin must generate a CA on the Certificate Authorities page before "
                "certificates can be issued."
            ),
            status=503,
            error_type="CA_NOT_CONFIGURED",
        )

    # Determine if the caller is an org admin/owner (admins can always choose expiry)
    is_org_admin = any(
        om.role in (OrganizationRole.ADMIN, OrganizationRole.OWNER)
        for om in memberships
        if om.organization and om.organization.deleted_at is None
    )

    # ── Apply department certificate policy ───────────────────────────────────
    dept_policy = _get_merged_dept_cert_policy(user_id)
    if dept_policy:
        if is_org_admin:
            # Admins can always choose their own expiry, but still capped at dept max
            if expiry_hours is not None:
                expiry_hours = min(int(expiry_hours), dept_policy["max_expiry_hours"])
        elif not dept_policy["allow_user_expiry"]:
            # Regular members: ignore user-requested expiry; use dept default
            expiry_hours = dept_policy["default_expiry_hours"]
        else:
            # Regular members allowed to pick, cap at dept maximum
            if expiry_hours is not None:
                expiry_hours = min(int(expiry_hours), dept_policy["max_expiry_hours"])
        policy_extensions = dept_policy["extensions"]
    else:
        policy_extensions = None  # let signing service use its own defaults

    # ── Build rich key_id identity for the OpenSSH cert ─────────────────────
    # This appears in `ssh-keygen -L -f cert.pub` as the Key ID field and
    # is stored in the DB cert record so it's auditable.
    org_slugs = sorted({
        om.organization.slug
        for om in memberships
        if om.organization and om.organization.deleted_at is None
        and getattr(om.organization, 'slug', None)
    })
    org_slug = org_slugs[0] if org_slugs else "unknown"
    full_name = getattr(user, 'full_name', None) or getattr(user, 'name', None) or "unknown"
    cert_identity = f"{user.email} ({full_name}) [org:{org_slug}]"

    signing_request = SSHCertificateSigningRequest(
        ssh_public_key=ssh_key.payload,
        principals=principals,
        cert_type=cert_type,
        key_id=cert_identity,
        expiry_hours=int(expiry_hours) if expiry_hours else None,
        extensions=policy_extensions,
    )
    validation_errors = signing_request.validate()
    if validation_errors:
        return api_response(
            success=False,
            message="Invalid signing request",
            status=400,
            error_type="VALIDATION_ERROR",
            error_details={"errors": validation_errors},
        )

    try:
        from gatehouse_app.utils.ca_key_encryption import decrypt_ca_key
        ca_private_key_pem = decrypt_ca_key(db_ca.private_key)
        response = ssh_ca_service.sign_certificate(
            signing_request, ca_private_key=ca_private_key_pem, ca_obj=db_ca
        )
    except SSHCertificateError as e:
        AuditLog.log(
            action=AuditAction.SSH_CERT_FAILED,
            user_id=user_id,
            resource_type='SSHCertificate',
            ip_address=request.remote_addr,
            success=False,
            error_message=str(e),
        )
        return api_response(success=False, message=str(e), status=400, error_type="SIGNING_FAILED")
    except Exception as e:
        AuditLog.log(
            action=AuditAction.SSH_CERT_FAILED,
            user_id=user_id,
            resource_type='SSHCertificate',
            ip_address=request.remote_addr,
            success=False,
            error_message=str(e),
        )
        return api_response(success=False, message="Certificate signing failed", status=500, error_type="SERVER_ERROR")

    cert_record = _persist_certificate(
        user_id=user_id,
        ssh_key_id=key_id,
        ca=db_ca,
        signing_response=response,
        request_ip=request.remote_addr,
        cert_type_str=cert_type,
        cert_identity=cert_identity,
    )

    AuditLog.log(
        action=AuditAction.SSH_CERT_ISSUED,
        user_id=user_id,
        resource_type='SSHCertificate',
        resource_id=cert_record.id if cert_record else key_id,
        ip_address=request.remote_addr,
        description=(
            f'Certificate serial={response.serial} issued for {user.email}; '
            f'principals: {", ".join(principals)}'
        ),
        extra_data={
            'serial': response.serial,
            'key_id': cert_identity,
            'principals': principals,
            'ca_id': str(db_ca.id),
            'ssh_key_id': str(key_id),
        },
    )

    if cert_record:
        CertificateAuditLog.log(
            certificate_id=cert_record.id,
            action='issued',
            user_id=user_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            message=(
                f'Certificate serial={response.serial} issued for {user.email}; '
                f'principals: {", ".join(principals)}'
            ),
            extra_data={
                'serial': response.serial,
                'key_id': cert_identity,
                'principals': principals,
                'ca_id': str(db_ca.id),
                'ssh_key_id': str(key_id),
                'valid_after': response.valid_after.isoformat() if response.valid_after else None,
                'valid_before': response.valid_before.isoformat() if response.valid_before else None,
            },
            success=True,
        )

    result = {
        'certificate': response.certificate,
        'serial': response.serial,
        'principals': response.principals,
        'valid_after': response.valid_after.isoformat() if response.valid_after else None,
        'valid_before': response.valid_before.isoformat() if response.valid_before else None,
    }
    if cert_record:
        result['cert_id'] = str(cert_record.id)

    return api_response(data=result, message="Certificate signed successfully", status=201)


# ---------------------------------------------------------------------------
# Host certificate issuance  (admin-only)
# ---------------------------------------------------------------------------

def _classify_ssh_key_material(raw: str) -> str:
    """Classify a raw SSH key string.

    Returns one of: 'certificate', 'public_key', 'private_key', 'unknown'.
    This mirrors the frontend ``classifySshKeyMaterial`` helper so that the
    API produces the same guardrails even when called directly (e.g. via CLI).
    """
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


@ssh_bp.route('/sign/host', methods=['POST'])
@login_required
def sign_host_certificate():
    """Issue a host certificate for a server's host public key.

    This endpoint is admin-only.  It accepts a raw OpenSSH host public key
    (the kind found in ``/etc/ssh/ssh_host_ed25519_key.pub``), signs it with
    the organisation's Host CA, and returns the signed host certificate.

    The certificate should be saved on the server as
    ``/etc/ssh/ssh_host_ed25519_key-cert.pub`` and referenced in
    ``sshd_config`` as ``HostCertificate``.

    Clients trust the host because they have the Host CA *public key* in their
    ``known_hosts`` (via ``@cert-authority``).  That key is different from —
    and must never be confused with — the certificate returned here.

    Request body (JSON):
        host_public_key  (str, required):
            Raw OpenSSH host public key, e.g.
            "ssh-ed25519 AAAA... root@server".
            Must NOT be a certificate (ssh-*-cert-v01@openssh.com) or a
            private key.
        principals       (list[str], required):
            Hostnames / FQDNs the server is known by, e.g.
            ["prod.example.com", "web01.internal"].
            These must match what SSH clients use in their connection target.
        validity_hours   (int, optional, default=720):
            Certificate validity in hours.  Host certs are typically
            30 days (720 h) to 1 year (8760 h).
        ca_id            (str, required):
            UUID of the Host CA to sign with.  Must be a ``ca_type=host`` CA
            belonging to the caller's organisation.

    Returns (201):
        certificate, serial, principals, valid_after, valid_before

    Errors:
        400  BAD_REQUEST      — pasted material is a cert / private key / unknown
        403  FORBIDDEN        — caller is not an org admin/owner
        404  CA_NOT_FOUND     — ca_id does not exist or is not a host CA
        422  VALIDATION_ERROR — invalid principals, validity, or public key
        503  CA_NOT_CONFIGURED
    """
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.ssh_ca.ca import CA, CaType
    from gatehouse_app.utils.constants import OrganizationRole
    from gatehouse_app.utils.ca_key_encryption import decrypt_ca_key

    user = g.current_user
    user_id = user.id

    # ── Admin-only gate ───────────────────────────────────────────────────────
    is_admin = OrganizationMember.query.filter(
        OrganizationMember.user_id == user_id,
        OrganizationMember.role.in_([OrganizationRole.ADMIN, OrganizationRole.OWNER]),
        OrganizationMember.deleted_at.is_(None),
    ).first() is not None

    if not is_admin:
        return api_response(
            success=False,
            message="Issuing host certificates requires org admin or owner role.",
            status=403,
            error_type="FORBIDDEN",
        )

    data = request.get_json()
    if not data:
        return api_response(success=False, message="No JSON data provided", status=400, error_type="BAD_REQUEST")

    host_public_key = (data.get("host_public_key") or "").strip()
    principals = data.get("principals") or []
    validity_hours = data.get("validity_hours", 720)
    ca_id = (data.get("ca_id") or "").strip()

    # ── Validate host public key material ─────────────────────────────────────
    if not host_public_key:
        return api_response(
            success=False,
            message="host_public_key is required.",
            status=400,
            error_type="BAD_REQUEST",
        )

    key_kind = _classify_ssh_key_material(host_public_key)
    if key_kind == "certificate":
        return api_response(
            success=False,
            message=(
                "You submitted a certificate (ssh-…-cert-v01@openssh.com), not a host public key. "
                "Retrieve the server's host public key with: "
                "cat /etc/ssh/ssh_host_ed25519_key.pub"
            ),
            status=400,
            error_type="WRONG_KEY_MATERIAL",
        )
    if key_kind == "private_key":
        return api_response(
            success=False,
            message="Private keys must never be submitted here. Use the .pub file.",
            status=400,
            error_type="WRONG_KEY_MATERIAL",
        )
    if key_kind == "unknown":
        return api_response(
            success=False,
            message=(
                "Unrecognised key format. "
                "Expected an OpenSSH public key starting with ssh-ed25519, ssh-rsa, or ecdsa-sha2-*."
            ),
            status=400,
            error_type="WRONG_KEY_MATERIAL",
        )

    # ── Validate principals ───────────────────────────────────────────────────
    if not principals or not isinstance(principals, list):
        return api_response(
            success=False,
            message="principals must be a non-empty list of hostnames.",
            status=422,
            error_type="VALIDATION_ERROR",
        )
    principals = [str(p).strip() for p in principals if str(p).strip()]
    if not principals:
        return api_response(
            success=False,
            message="At least one principal (hostname/FQDN) is required.",
            status=422,
            error_type="VALIDATION_ERROR",
        )

    # ── Validate validity ─────────────────────────────────────────────────────
    try:
        validity_hours = int(validity_hours)
        if validity_hours < 1:
            raise ValueError
    except (TypeError, ValueError):
        return api_response(
            success=False,
            message="validity_hours must be a positive integer.",
            status=422,
            error_type="VALIDATION_ERROR",
        )

    # ── Resolve CA ────────────────────────────────────────────────────────────
    if not ca_id:
        return api_response(
            success=False,
            message="ca_id is required.",
            status=400,
            error_type="BAD_REQUEST",
        )

    org_ids = [
        m.organization_id
        for m in OrganizationMember.query.filter_by(user_id=user_id, deleted_at=None).all()
    ]

    # First: find the CA by id (ignoring type) so we can give a specific error
    # if it exists but is the wrong type.
    any_ca = CA.query.filter(
        CA.id == ca_id,
        CA.is_active.is_(True),
        CA.organization_id.in_(org_ids),
        CA.deleted_at.is_(None),
    ).first()

    if any_ca and any_ca.ca_type != CaType.HOST:
        return api_response(
            success=False,
            message=(
                f"The CA '{any_ca.name}' is a {any_ca.ca_type.value} CA. "
                "Host certificates must be signed by a ca_type='host' CA."
            ),
            status=400,
            error_type="WRONG_CA_TYPE",
        )

    host_ca = any_ca  # already filtered for org + active + not-deleted above

    if not host_ca:
        return api_response(
            success=False,
            message=(
                "Host CA not found, inactive, or you do not have permission to use it. "
                "Ensure the CA exists and ca_type is 'host'."
            ),
            status=404,
            error_type="CA_NOT_FOUND",
        )

    # ── Build key_id for the OpenSSH cert Key ID field ────────────────────────
    # Format: "host:<principal> [signed-by:<user_email>]"
    primary_principal = principals[0]
    cert_identity = f"host:{primary_principal} [signed-by:{user.email}]"

    signing_request = SSHCertificateSigningRequest(
        ssh_public_key=host_public_key,
        principals=principals,
        cert_type="host",
        key_id=cert_identity,
        expiry_hours=validity_hours,
        extensions=[],       # Host certs carry no extensions (OpenSSH spec)
        critical_options={},
    )

    validation_errors = signing_request.validate()
    if validation_errors:
        return api_response(
            success=False,
            message="Invalid signing request: " + "; ".join(validation_errors),
            status=422,
            error_type="VALIDATION_ERROR",
        )

    try:
        ca_private_key_pem = decrypt_ca_key(host_ca.private_key)
        response = ssh_ca_service.sign_certificate(
            signing_request, ca_private_key=ca_private_key_pem, ca_obj=host_ca
        )
    except Exception as exc:
        AuditLog.log(
            action=AuditAction.SSH_CERT_FAILED,
            user_id=user_id,
            resource_type="SSHCertificate",
            ip_address=request.remote_addr,
            success=False,
            error_message=str(exc),
        )
        return api_response(
            success=False,
            message=f"Host certificate signing failed: {exc}",
            status=500,
            error_type="SIGNING_FAILED",
        )

    # Persist a cert record linked to the issuing admin (no ssh_key_id FK
    # because this was a raw key, not a registered user key).
    # We reuse _persist_certificate with ssh_key_id=ca_id as a stable sentinel.
    cert_record = _persist_certificate(
        user_id=user_id,
        ssh_key_id=None,     # host certs are not tied to a user SSH key record
        ca=host_ca,
        signing_response=response,
        request_ip=request.remote_addr,
        cert_type_str="host",
        cert_identity=cert_identity,
    )

    AuditLog.log(
        action=AuditAction.SSH_CERT_ISSUED,
        user_id=user_id,
        resource_type="SSHCertificate",
        resource_id=cert_record.id if cert_record else None,
        ip_address=request.remote_addr,
        description=(
            f"Host certificate serial={response.serial} issued for "
            f"{primary_principal} by {user.email}"
        ),
        extra_data={
            "serial": response.serial,
            "principals": principals,
            "ca_id": str(host_ca.id),
            "cert_type": "host",
        },
    )

    result = {
        "certificate": response.certificate,
        "serial": response.serial,
        "principals": response.principals,
        "valid_after": response.valid_after.isoformat() if response.valid_after else None,
        "valid_before": response.valid_before.isoformat() if response.valid_before else None,
    }
    if cert_record:
        result["cert_id"] = str(cert_record.id)

    return api_response(data=result, message="Host certificate issued successfully", status=201)


@ssh_bp.route('/certificates', methods=['GET'])
@login_required
def list_certificates():
    """List all SSH certificates issued for the current user."""
    user_id = g.current_user.id

    try:
        from gatehouse_app.models.ssh_ca.ssh_certificate import SSHCertificate
        certs = (
            SSHCertificate.query
            .filter_by(user_id=user_id, deleted_at=None)
            .order_by(SSHCertificate.created_at.desc())
            .all()
        )

        return api_response(
            data={
                'certificates': [c.to_dict() for c in certs],
                'count': len(certs),
            },
            message="Certificates retrieved successfully"
        )
    except Exception as e:
        return api_response(
            success=False,
            message=str(e),
            status=500,
            error_type='INTERNAL_ERROR'
        )


@ssh_bp.route('/certificates/<cert_id>', methods=['GET'])
@login_required
def get_certificate(cert_id):
    """Get a specific issued certificate (metadata only)."""
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
    """Revoke an issued certificate."""
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

        AuditLog.log(
            action=AuditAction.SSH_CERT_REVOKED,
            user_id=user_id,
            resource_type='SSHCertificate',
            resource_id=cert_id,
            ip_address=request.remote_addr,
            description=f'Revoked: {reason}',
        )

        CertificateAuditLog.log(
            certificate_id=cert_id,
            action='revoked',
            user_id=user_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent'),
            message=f'Certificate revoked: {reason}',
            success=True,
        )

        return api_response(
            success=True,
            message='Certificate revoked successfully',
            data={'status': 'revoked', 'cert_id': cert_id, 'reason': reason},
            status=200,
        )
    except Exception as e:
        return api_response(success=False, message=str(e), status=500, error_type='INTERNAL_ERROR')


@ssh_bp.route('/ca/public-key', methods=['GET'])
@login_required
def get_ca_public_key():
    """
    Return the CA public key for this user's organization.

    Server admins should add this key to their host's ``TrustedUserCAKeys``
    directive so that certificates issued by gatehouse are trusted.

    Query parameters:
        ca_type: 'user' (default) or 'host' — which CA's public key to return
        format:  'openssh' (default) or 'text' — affects Content-Type only

    Returns:
        { "public_key": "ssh-ed25519 AAAA...",
          "fingerprint": "SHA256:...",
          "ca_name": "..." }
    """
    user = g.current_user
    ca_type = request.args.get("ca_type", "user")
    if ca_type not in ("user", "host"):
        return api_response(
            success=False,
            message="ca_type must be 'user' or 'host'",
            status=400,
            error_type="BAD_REQUEST",
        )

    db_ca = _get_org_ca_for_user(user, ca_type=ca_type)
    if db_ca:
        return api_response(
            data={
                'public_key': db_ca.public_key,
                'fingerprint': db_ca.fingerprint,
                'ca_name': db_ca.name,
                'ca_type': ca_type,
                'source': 'db',
            },
            message="CA public key retrieved successfully"
        )

    return api_response(
        success=False,
        message=(
            f"No {ca_type} CA is configured for your organization. "
            "An admin must generate one on the Certificate Authorities page."
        ),
        status=404,
        error_type="CA_NOT_CONFIGURED",
    )


# ---------------------------------------------------------------------------
# CA Permissions
# ---------------------------------------------------------------------------

@ssh_bp.route('/ca/<ca_id>/permissions', methods=['GET'])
@login_required
def list_ca_permissions(ca_id):
    """List permissions for a Certificate Authority.

    Returns:
        200: { ca_id, permissions: [...], open_to_all: bool }
        403: Not admin/owner
        404: CA not found
    """
    from gatehouse_app.models.ssh_ca.ca import CA, CAPermission
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.utils.constants import OrganizationRole

    user = g.current_user

    ca = CA.query.filter_by(id=ca_id, deleted_at=None).first()
    if not ca:
        return api_response(success=False, message="CA not found", status=404, error_type="NOT_FOUND")

    # Verify user is admin/owner of the CA's org
    if ca.organization_id:
        membership = OrganizationMember.query.filter_by(
            organization_id=ca.organization_id,
            user_id=user.id,
            deleted_at=None,
        ).first()
        if not membership or membership.role not in (OrganizationRole.ADMIN, OrganizationRole.OWNER):
            return api_response(success=False, message="Admin access required", status=403, error_type="FORBIDDEN")

    perms = CAPermission.query.filter_by(ca_id=ca_id, deleted_at=None).all()
    perm_list = []
    for p in perms:
        d = p.to_dict()
        d["user_email"] = p.user.email if p.user else None
        perm_list.append(d)

    return api_response(
        data={
            "ca_id": ca_id,
            "permissions": perm_list,
            "open_to_all": len(perms) == 0,
        },
        message="CA permissions retrieved",
    )


@ssh_bp.route('/ca/<ca_id>/permissions', methods=['POST'])
@login_required
def add_ca_permission(ca_id):
    """Grant a user permission on a Certificate Authority.

    Request body:
        user_id: UUID of the user to grant access
        permission: "sign" or "admin" (default: "sign")

    Returns:
        201: Permission granted
        400: Validation error
        403: Not admin/owner
        404: CA or user not found
        409: Permission already exists
    """
    from gatehouse_app.models.ssh_ca.ca import CA, CAPermission
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.models.user import User
    from gatehouse_app.utils.constants import OrganizationRole, AuditAction
    from gatehouse_app.models import AuditLog
    from gatehouse_app.extensions import db

    user = g.current_user

    ca = CA.query.filter_by(id=ca_id, deleted_at=None).first()
    if not ca:
        return api_response(success=False, message="CA not found", status=404, error_type="NOT_FOUND")

    # Verify user is admin/owner of the CA's org
    if ca.organization_id:
        membership = OrganizationMember.query.filter_by(
            organization_id=ca.organization_id,
            user_id=user.id,
            deleted_at=None,
        ).first()
        if not membership or membership.role not in (OrganizationRole.ADMIN, OrganizationRole.OWNER):
            return api_response(success=False, message="Admin access required", status=403, error_type="FORBIDDEN")

    data = request.get_json() or {}
    target_user_id = (data.get("user_id") or "").strip()
    permission = data.get("permission", "sign")

    if not target_user_id:
        return api_response(success=False, message="user_id is required", status=400, error_type="VALIDATION_ERROR")
    if permission not in ("sign", "admin"):
        return api_response(
            success=False,
            message="permission must be 'sign' or 'admin'",
            status=400,
            error_type="VALIDATION_ERROR",
        )

    target_user = User.query.filter_by(id=target_user_id, deleted_at=None).first()
    if not target_user:
        return api_response(success=False, message="User not found", status=404, error_type="NOT_FOUND")

    # Check for duplicate
    existing = CAPermission.query.filter_by(
        ca_id=ca_id, user_id=target_user_id, deleted_at=None
    ).first()
    if existing:
        # Update permission level if different
        if existing.permission != permission:
            existing.permission = permission
            db.session.commit()
            d = existing.to_dict()
            d["user_email"] = target_user.email
            return api_response(
                data={"message": "Permission updated", "permission": d},
                message="Permission updated",
            )
        return api_response(
            success=False,
            message="User already has this permission on the CA",
            status=409,
            error_type="DUPLICATE",
        )

    perm = CAPermission(
        ca_id=ca_id,
        user_id=target_user_id,
        permission=permission,
    )
    db.session.add(perm)
    db.session.commit()

    AuditLog.log(
        action=AuditAction.CA_UPDATED,
        user_id=user.id,
        resource_type="CAPermission",
        resource_id=perm.id,
        ip_address=request.remote_addr,
        description=f"Granted '{permission}' on CA '{ca.name}' to user {target_user.email}",
    )

    d = perm.to_dict()
    d["user_email"] = target_user.email
    return api_response(
        data={"message": "Permission granted", "permission": d},
        message="Permission granted",
        status=201,
    )


@ssh_bp.route('/ca/<ca_id>/permissions/<target_user_id>', methods=['DELETE'])
@login_required
def remove_ca_permission(ca_id, target_user_id):
    """Revoke a user's permission on a Certificate Authority.

    Returns:
        200: Permission revoked
        403: Not admin/owner
        404: CA or permission not found
    """
    from gatehouse_app.models.ssh_ca.ca import CA, CAPermission
    from gatehouse_app.models.organization.organization_member import OrganizationMember
    from gatehouse_app.utils.constants import OrganizationRole, AuditAction
    from gatehouse_app.models import AuditLog
    from gatehouse_app.extensions import db

    user = g.current_user

    ca = CA.query.filter_by(id=ca_id, deleted_at=None).first()
    if not ca:
        return api_response(success=False, message="CA not found", status=404, error_type="NOT_FOUND")

    # Verify user is admin/owner of the CA's org
    if ca.organization_id:
        membership = OrganizationMember.query.filter_by(
            organization_id=ca.organization_id,
            user_id=user.id,
            deleted_at=None,
        ).first()
        if not membership or membership.role not in (OrganizationRole.ADMIN, OrganizationRole.OWNER):
            return api_response(success=False, message="Admin access required", status=403, error_type="FORBIDDEN")

    perm = CAPermission.query.filter_by(
        ca_id=ca_id, user_id=target_user_id, deleted_at=None
    ).first()
    if not perm:
        return api_response(success=False, message="Permission not found", status=404, error_type="NOT_FOUND")

    perm.delete(soft=True)

    AuditLog.log(
        action=AuditAction.CA_UPDATED,
        user_id=user.id,
        resource_type="CAPermission",
        resource_id=perm.id,
        ip_address=request.remote_addr,
        description=f"Revoked permission on CA '{ca.name}' from user {target_user_id}",
    )

    return api_response(
        data={},
        message="Permission revoked",
    )

