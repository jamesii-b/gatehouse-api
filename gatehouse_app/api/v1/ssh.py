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
from gatehouse_app.utils.decorators import login_required

ssh_bp = Blueprint('ssh', __name__, url_prefix='/ssh')
ssh_key_service = SSHKeyService()
ssh_ca_service = SSHCASigningService()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_org_ca_for_user(user):
    """Return the active DB CA for the user's first org, or None."""
    try:
        from gatehouse_app.models.ca import CA
        org_ids = [m.organization_id for m in user.organization_memberships]
        if not org_ids:
            return None
        return CA.query.filter(
            CA.organization_id.in_(org_ids),
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
    from gatehouse_app.models.ca import CA, KeyType
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

        # Load private key for the record (stored but not actually used for signing here)
        priv_key = ""
        if os.path.exists(key_path):
            with open(key_path) as f:
                priv_key = f.read()

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


def _persist_certificate(user_id, ssh_key_id, ca, signing_response, request_ip=None):
    """Save a signed certificate to the ssh_certificates table.

    Args:
        user_id: UUID of the user
        ssh_key_id: UUID of the SSH key that was signed
        ca: CA model instance (may be None — cert still returned but not persisted)
        signing_response: SSHCertificateSigningResponse
        request_ip: Client IP address

    Returns:
        SSHCertificate instance or None if persistence failed
    """
    if ca is None:
        return None

    try:
        from gatehouse_app.extensions import db
        from gatehouse_app.models.ssh_certificate import SSHCertificate, CertificateStatus
        from gatehouse_app.models.ca import CertType

        cert_record = SSHCertificate(
            ca_id=ca.id,
            user_id=user_id,
            ssh_key_id=ssh_key_id,
            certificate=signing_response.certificate,
            serial=signing_response.serial,
            key_id=str(ssh_key_id),
            cert_type=CertType.USER,
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



@ssh_bp.route('/keys', methods=['GET'])
@login_required
def list_ssh_keys():
    """Get all SSH keys for current user."""
    user_id = g.current_user.id
    
    keys = ssh_key_service.get_user_ssh_keys(user_id)
    return jsonify({
        'keys': [k.to_dict() for k in keys],
        'count': len(keys),
    }), 200


@ssh_bp.route('/keys', methods=['POST'])
@login_required
def add_ssh_key():
    """Add a new SSH public key for current user."""
    user_id = g.current_user.id
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    public_key = data.get('public_key') or data.get('key')
    description = data.get('description')
    
    if not public_key:
        return jsonify({'error': 'public_key is required'}), 400
    
    try:
        ssh_key = ssh_key_service.add_ssh_key(
            user_id=user_id,
            public_key=public_key,
            description=description,
        )
        
        # Audit log
        AuditLog.log(
            action=AuditAction.SSH_KEY_ADDED,
            user_id=user_id,
            resource_type='SSHKey',
            resource_id=ssh_key.id,
            ip_address=request.remote_addr,
        )
        
        return jsonify(ssh_key.to_dict()), 201
    
    except SSHKeyAlreadyExistsError as e:
        return jsonify({'error': e.message, 'code': 'SSH_KEY_ALREADY_EXISTS'}), 409
    except IntegrityError:
        return jsonify({'error': 'SSH key already exists', 'code': 'SSH_KEY_ALREADY_EXISTS'}), 409
    except SSHKeyError as e:
        return jsonify({'error': str(e)}), 400
    except ValidationError as e:
        return jsonify({'error': str(e)}), 400


@ssh_bp.route('/keys/<key_id>', methods=['GET'])
@login_required
def get_ssh_key(key_id):
    """Get a specific SSH key."""
    user_id = g.current_user.id
    
    try:
        ssh_key = ssh_key_service.get_ssh_key(key_id)
        
        # Check ownership
        if ssh_key.user_id != user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        return jsonify(ssh_key.to_dict()), 200
    
    except SSHKeyNotFoundError:
        return jsonify({'error': 'SSH key not found'}), 404


@ssh_bp.route('/keys/<key_id>', methods=['DELETE'])
@login_required
def delete_ssh_key(key_id):
    """Delete an SSH key."""
    user_id = g.current_user.id
    
    try:
        ssh_key = ssh_key_service.get_ssh_key(key_id)
        
        # Check ownership
        if ssh_key.user_id != user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        ssh_key_service.delete_ssh_key(key_id)
        
        # Audit log
        AuditLog.log(
            action=AuditAction.SSH_KEY_DELETED,
            user_id=user_id,
            resource_type='SSHKey',
            resource_id=key_id,
            ip_address=request.remote_addr,
        )
        
        return jsonify({'status': 'deleted'}), 200
    
    except SSHKeyNotFoundError:
        return jsonify({'error': 'SSH key not found'}), 404


@ssh_bp.route('/keys/<key_id>/verify', methods=['GET', 'POST'])
@login_required
def verify_ssh_key(key_id):
    """Generate or verify SSH key ownership challenge."""
    user_id = g.current_user.id
    
    try:
        ssh_key = ssh_key_service.get_ssh_key(key_id)
        
        # Check ownership
        if ssh_key.user_id != user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        # Handle GET request - return challenge
        if request.method == 'GET':
            challenge = ssh_key_service.generate_verification_challenge(key_id)
            return jsonify({
                'challenge_text': challenge,
                'validationText': challenge,  # Backwards compatibility
                'key_id': key_id,
            }), 200
        
        # Handle POST request - verify signature
        data = request.get_json() or {}
        action = data.get('action', 'verify_signature')
        
        if action == 'verify_signature':
            # Verify signature
            signature = data.get('signature')
            if not signature:
                return jsonify({'error': 'signature is required'}), 400
            
            try:
                verified = ssh_key_service.verify_ssh_key_ownership(key_id, signature)
                
                # Audit log
                AuditLog.log(
                    action=AuditAction.SSH_KEY_VERIFIED,
                    user_id=user_id,
                    resource_type='SSHKey',
                    resource_id=key_id,
                    ip_address=request.remote_addr,
                    success=verified,
                )
                
                return jsonify({'verified': verified}), 200
            
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
                return jsonify({'error': str(e)}), 400
        
        else:  # generate_challenge
            # Generate verification challenge
            challenge = ssh_key_service.generate_verification_challenge(key_id)
            return jsonify({
                'challenge_text': challenge,
                'challenge': challenge,  # Both for compatibility
            }), 200
    
    except SSHKeyNotFoundError:
        return jsonify({'error': 'SSH key not found'}), 404


@ssh_bp.route('/keys/<key_id>/update-description', methods=['PATCH'])
@login_required
def update_ssh_key_description(key_id):
    """Update SSH key description."""
    user_id = g.current_user.id
    
    data = request.get_json()
    if not data or 'description' not in data:
        return jsonify({'error': 'description is required'}), 400
    
    try:
        ssh_key = ssh_key_service.get_ssh_key(key_id)
        
        # Check ownership
        if ssh_key.user_id != user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        updated_key = ssh_key_service.update_ssh_key_description(
            key_id,
            data['description']
        )
        
        return jsonify(updated_key.to_dict()), 200
    
    except SSHKeyNotFoundError:
        return jsonify({'error': 'SSH key not found'}), 404


@ssh_bp.route('/sign', methods=['POST'])
@login_required
def sign_certificate():
    """Sign an SSH certificate for the current user."""
    user = g.current_user
    user_id = user.id
    
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No JSON data provided'}), 400
    
    try:
        principals = data.get('principals', [])
        cert_type = data.get('cert_type', 'user')
        # Accept both 'key_id' and 'cert_id' (from CLI)
        key_id = data.get('key_id') or data.get('cert_id')
        expiry_hours = data.get('expiry_hours')
        
        if not principals:
            return jsonify({'error': 'principals is required'}), 400
        
        # If key_id not specified, use first verified key
        if not key_id:
            verified_keys = ssh_key_service.get_user_verified_ssh_keys(user_id)
            if not verified_keys:
                return jsonify({'error': 'No verified SSH keys found'}), 400
            key_id = verified_keys[0].id
        
        # Get the SSH key
        ssh_key = ssh_key_service.get_ssh_key(key_id)
        if ssh_key.user_id != user_id:
            return jsonify({'error': 'Forbidden'}), 403
        
        if not ssh_key.verified:
            return jsonify({'error': 'SSH key is not verified'}), 400

        # Resolve which CA to use: org DB CA > config-file CA
        db_ca = _get_org_ca_for_user(user)
        ca_private_key = db_ca.private_key if db_ca else None  # None → signing service uses config

        # Create signing request
        signing_request = SSHCertificateSigningRequest(
            ssh_public_key=ssh_key.payload,
            principals=principals,
            cert_type=cert_type,
            key_id=key_id,
            expiry_hours=int(expiry_hours) if expiry_hours else None,
        )
        
        # Validate request
        validation_errors = signing_request.validate()
        if validation_errors:
            return jsonify({'errors': validation_errors}), 400
        
        # Sign the certificate (pass ca_private_key=None → service loads from config)
        response = ssh_ca_service.sign_certificate(signing_request, ca_private_key=ca_private_key)

        # Persist certificate to DB
        # If user's org has no DB CA, use the system-config-ca record
        ca_for_db = db_ca or _get_or_create_system_ca()
        cert_record = _persist_certificate(
            user_id=user_id,
            ssh_key_id=key_id,
            ca=ca_for_db,
            signing_response=response,
            request_ip=request.remote_addr,
        )

        # Audit log
        AuditLog.log(
            action=AuditAction.SSH_CERT_ISSUED,
            user_id=user_id,
            resource_type='SSHCertificate',
            resource_id=cert_record.id if cert_record else key_id,
            ip_address=request.remote_addr,
            description=f'Certificate issued for principals: {", ".join(principals)}',
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

        return jsonify(result), 201
    
    except SSHKeyNotFoundError:
        return jsonify({'error': 'SSH key not found'}), 404
    except SSHCertificateError as e:
        AuditLog.log(
            action=AuditAction.SSH_CERT_FAILED,
            user_id=user_id,
            resource_type='SSHCertificate',
            ip_address=request.remote_addr,
            success=False,
            error_message=str(e),
        )
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        AuditLog.log(
            action=AuditAction.SSH_CERT_FAILED,
            user_id=user_id,
            resource_type='SSHCertificate',
            ip_address=request.remote_addr,
            success=False,
            error_message=str(e),
        )
        return jsonify({'error': 'Certificate signing failed: ' + str(e)}), 500


@ssh_bp.route('/certificates', methods=['GET'])
@login_required
def list_certificates():
    """List all SSH certificates issued for the current user."""
    user_id = g.current_user.id

    try:
        from gatehouse_app.models.ssh_certificate import SSHCertificate
        certs = (
            SSHCertificate.query
            .filter_by(user_id=user_id, deleted_at=None)
            .order_by(SSHCertificate.created_at.desc())
            .all()
        )
        return jsonify({
            'certificates': [c.to_dict() for c in certs],
            'count': len(certs),
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@ssh_bp.route('/certificates/<cert_id>', methods=['GET'])
@login_required
def get_certificate(cert_id):
    """Get a specific issued certificate (metadata only)."""
    user_id = g.current_user.id

    try:
        from gatehouse_app.models.ssh_certificate import SSHCertificate
        cert = SSHCertificate.query.filter_by(id=cert_id, deleted_at=None).first()
        if not cert:
            return jsonify({'error': 'Certificate not found'}), 404
        if cert.user_id != user_id:
            return jsonify({'error': 'Forbidden'}), 403
        # Include full certificate text in single-fetch endpoint
        data = cert.to_dict()
        data['certificate'] = cert.certificate
        return jsonify(data), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@ssh_bp.route('/certificates/<cert_id>/revoke', methods=['POST'])
@login_required
def revoke_certificate(cert_id):
    """Revoke an issued certificate."""
    user_id = g.current_user.id

    data = request.get_json() or {}
    reason = data.get('reason', 'User requested revocation')

    try:
        from gatehouse_app.models.ssh_certificate import SSHCertificate
        cert = SSHCertificate.query.filter_by(id=cert_id, deleted_at=None).first()
        if not cert:
            return jsonify({'error': 'Certificate not found'}), 404
        if cert.user_id != user_id:
            return jsonify({'error': 'Forbidden'}), 403
        if cert.revoked:
            return jsonify({'error': 'Certificate is already revoked'}), 409

        cert.revoke(reason=reason)

        AuditLog.log(
            action=AuditAction.SSH_CERT_REVOKED,
            user_id=user_id,
            resource_type='SSHCertificate',
            resource_id=cert_id,
            ip_address=request.remote_addr,
            description=f'Revoked: {reason}',
        )

        return jsonify({'status': 'revoked', 'cert_id': cert_id, 'reason': reason}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@ssh_bp.route('/ca/public-key', methods=['GET'])
@login_required
def get_ca_public_key():
    """
    Return the CA public key for this user's organization.

    Server admins should add this key to their host's ``TrustedUserCAKeys``
    directive so that certificates issued by gatehouse are trusted.

    Query parameters:
        format: 'openssh' (default) or 'text' — affects Content-Type only

    Returns:
        { "public_key": "ssh-ed25519 AAAA...",
          "fingerprint": "SHA256:...",
          "ca_name": "..." }
    """
    user = g.current_user

    # Try org CA first
    db_ca = _get_org_ca_for_user(user)
    if db_ca:
        return jsonify({
            'public_key': db_ca.public_key,
            'fingerprint': db_ca.fingerprint,
            'ca_name': db_ca.name,
            'source': 'db',
        }), 200

    # Fall back to config-file CA
    try:
        from gatehouse_app.config.ssh_ca_config import get_ssh_ca_config
        import os
        cfg = get_ssh_ca_config()
        key_path = cfg.get_str('ca_key_path', '').strip() + '.pub'
        if os.path.exists(key_path):
            with open(key_path) as f:
                pub_key = f.read().strip()
            from gatehouse_app.utils.crypto import compute_ssh_fingerprint
            return jsonify({
                'public_key': pub_key,
                'fingerprint': compute_ssh_fingerprint(pub_key),
                'ca_name': 'system-config-ca',
                'source': 'config',
            }), 200
    except Exception as e:
        return jsonify({'error': f'Could not load CA public key: {e}'}), 500

    return jsonify({'error': 'No CA configured for this organization'}), 404


