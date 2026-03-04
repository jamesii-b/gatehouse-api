"""SSH key management endpoints."""
from sqlalchemy.exc import IntegrityError
from flask import request, g
from gatehouse_app.api.v1.ssh._helpers import ssh_bp, ssh_key_service
from gatehouse_app.exceptions import SSHKeyError, SSHKeyNotFoundError, ValidationError, SSHKeyAlreadyExistsError
from gatehouse_app.utils.constants import AuditAction
from gatehouse_app.models import AuditLog
from gatehouse_app.utils.decorators import login_required
from gatehouse_app.utils.response import api_response


@ssh_bp.route('/keys', methods=['GET'])
@login_required
def list_ssh_keys():
    user_id = g.current_user.id
    keys = ssh_key_service.get_user_ssh_keys(user_id)
    return api_response(data={'keys': [k.to_dict() for k in keys], 'count': len(keys)}, message="SSH keys retrieved successfully")


@ssh_bp.route('/keys', methods=['POST'])
@login_required
def add_ssh_key():
    user_id = g.current_user.id
    data = request.get_json()
    if not data:
        return api_response(success=False, message='No JSON data provided', status=400, error_type='BAD_REQUEST')

    public_key = data.get('public_key') or data.get('key')
    description = data.get('description')

    if not public_key:
        return api_response(success=False, message='public_key is required', status=400, error_type='BAD_REQUEST')

    try:
        ssh_key = ssh_key_service.add_ssh_key(user_id=user_id, public_key=public_key, description=description)
        AuditLog.log(action=AuditAction.SSH_KEY_ADDED, user_id=user_id, resource_type='SSHKey', resource_id=ssh_key.id, ip_address=request.remote_addr)
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
    user_id = g.current_user.id
    try:
        ssh_key = ssh_key_service.get_ssh_key(key_id)
        if ssh_key.user_id != user_id:
            return api_response(success=False, message='Forbidden', status=403, error_type='FORBIDDEN')
        ssh_key_service.delete_ssh_key(key_id)
        AuditLog.log(action=AuditAction.SSH_KEY_DELETED, user_id=user_id, resource_type='SSHKey', resource_id=key_id, ip_address=request.remote_addr)
        return api_response(success=True, message='SSH key deleted', data={'status': 'deleted'}, status=200)
    except SSHKeyNotFoundError:
        return api_response(success=False, message='SSH key not found', status=404, error_type='NOT_FOUND')


@ssh_bp.route('/keys/<key_id>/verify', methods=['GET', 'POST'])
@login_required
def verify_ssh_key(key_id):
    user_id = g.current_user.id
    try:
        ssh_key = ssh_key_service.get_ssh_key(key_id)
        if ssh_key.user_id != user_id:
            return api_response(success=False, message='Forbidden', status=403, error_type='FORBIDDEN')

        if request.method == 'GET':
            challenge = ssh_key_service.generate_verification_challenge(key_id)
            return api_response(success=True, message='Challenge generated', data={'challenge_text': challenge, 'validationText': challenge, 'key_id': key_id}, status=200)

        data = request.get_json() or {}
        action = data.get('action', 'verify_signature')

        if action == 'verify_signature':
            signature = data.get('signature')
            if not signature:
                return api_response(success=False, message='signature is required', status=400, error_type='BAD_REQUEST')
            try:
                verified = ssh_key_service.verify_ssh_key_ownership(key_id, signature)
                AuditLog.log(action=AuditAction.SSH_KEY_VERIFIED, user_id=user_id, resource_type='SSHKey', resource_id=key_id, ip_address=request.remote_addr, success=verified)
                return api_response(success=True, message='Verification complete', data={'verified': verified}, status=200)
            except Exception as e:
                AuditLog.log(action=AuditAction.SSH_KEY_VALIDATION_FAILED, user_id=user_id, resource_type='SSHKey', resource_id=key_id, ip_address=request.remote_addr, success=False, error_message=str(e))
                return api_response(success=False, message=str(e), status=400, error_type='VERIFICATION_FAILED')
        else:
            challenge = ssh_key_service.generate_verification_challenge(key_id)
            return api_response(success=True, message='Challenge generated', data={'challenge_text': challenge, 'challenge': challenge}, status=200)

    except SSHKeyNotFoundError:
        return api_response(success=False, message='SSH key not found', status=404, error_type='NOT_FOUND')


@ssh_bp.route('/keys/<key_id>/update-description', methods=['PATCH'])
@login_required
def update_ssh_key_description(key_id):
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
