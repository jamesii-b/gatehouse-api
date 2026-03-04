"""Account linking, authentication, and unlinking flows."""
import logging
import secrets
from datetime import datetime
from typing import Optional, Tuple

from gatehouse_app.models import User, AuthenticationMethod
from gatehouse_app.models.auth.authentication_method import OAuthState
from gatehouse_app.utils.constants import AuthMethodType
from gatehouse_app.services.audit_service import AuditService
from gatehouse_app.services.external_auth.models import ExternalAuthError

logger = logging.getLogger(__name__)


def initiate_link_flow(
    get_provider_config,
    user_id: str,
    provider_type: AuthMethodType,
    organization_id: str,
    redirect_uri: str = None,
) -> Tuple[str, str]:
    from gatehouse_app.services.external_auth._helpers import (
        _compute_s256_challenge,
        _build_authorization_url,
    )

    provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type
    config = get_provider_config(provider_type, organization_id)

    if redirect_uri and not config.is_redirect_uri_allowed(redirect_uri):
        raise ExternalAuthError("Invalid redirect URI", "INVALID_REDIRECT_URI", 400)

    code_verifier = None
    code_challenge = None
    if provider_type_str not in ('google', 'microsoft'):
        code_verifier = secrets.token_urlsafe(32)
        code_challenge = _compute_s256_challenge(code_verifier)

    state = OAuthState.create_state(
        flow_type="link",
        provider_type=provider_type,
        user_id=user_id,
        organization_id=organization_id,
        redirect_uri=redirect_uri or (config.redirect_uris[0] if config.redirect_uris else None),
        code_verifier=code_verifier,
        code_challenge=code_challenge,
        lifetime_seconds=600,
    )

    auth_url = _build_authorization_url(config=config, state=state)

    AuditService.log_external_auth_link_initiated(
        user_id=user_id,
        organization_id=organization_id,
        provider_type=provider_type_str,
        state_id=state.id,
    )

    return auth_url, state.state


def complete_link_flow(
    get_provider_config,
    provider_type: AuthMethodType,
    authorization_code: str,
    state: str,
    redirect_uri: str,
) -> AuthenticationMethod:
    from gatehouse_app.services.external_auth._helpers import (
        _exchange_code,
        _get_user_info,
        _encrypt_provider_data,
    )

    provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

    state_record = OAuthState.query.filter_by(state=state).first()
    if not state_record or not state_record.is_valid():
        AuditService.log_external_auth_link_failed(
            user_id=None,
            organization_id=None,
            provider_type=provider_type_str,
            error_message="Invalid or expired OAuth state",
            failure_reason="invalid_state",
        )
        raise ExternalAuthError("Invalid or expired OAuth state", "INVALID_STATE", 400)

    if state_record.flow_type != "link":
        AuditService.log_external_auth_link_failed(
            user_id=state_record.user_id,
            organization_id=state_record.organization_id,
            provider_type=provider_type_str,
            error_message="Invalid flow type for this operation",
            failure_reason="invalid_flow_type",
        )
        raise ExternalAuthError("Invalid flow type for this operation", "INVALID_FLOW_TYPE", 400)

    if state_record.provider_type != provider_type_str:
        AuditService.log_external_auth_link_failed(
            user_id=state_record.user_id,
            organization_id=state_record.organization_id,
            provider_type=provider_type_str,
            error_message="Provider mismatch",
            failure_reason="provider_mismatch",
        )
        raise ExternalAuthError("Provider mismatch", "PROVIDER_MISMATCH", 400)

    config = get_provider_config(provider_type, state_record.organization_id)

    tokens = _exchange_code(
        config=config,
        code=authorization_code,
        redirect_uri=redirect_uri,
        code_verifier=state_record.code_verifier,
    )

    user_info = _get_user_info(config=config, access_token=tokens["access_token"])

    user = User.query.get(state_record.user_id)
    if not user:
        AuditService.log_external_auth_link_failed(
            user_id=None,
            organization_id=state_record.organization_id,
            provider_type=provider_type_str,
            error_message="User not found",
            failure_reason="user_not_found",
        )
        raise ExternalAuthError("User not found", "USER_NOT_FOUND", 400)

    conflicting = AuthenticationMethod.query.filter(
        AuthenticationMethod.method_type == provider_type,
        AuthenticationMethod.provider_user_id == user_info["provider_user_id"],
        AuthenticationMethod.user_id != user.id,
        AuthenticationMethod.deleted_at == None,
    ).first()
    if conflicting:
        raise ExternalAuthError(
            f"This {provider_type_str} account is already linked to a different Gatehouse user.",
            "PROVIDER_ALREADY_LINKED",
            409,
        )

    auth_method = AuthenticationMethod.query.filter_by(
        user_id=user.id,
        method_type=provider_type,
        provider_user_id=user_info["provider_user_id"],
    ).first()

    if auth_method:
        # Restore the row if it was previously soft-deleted (re-linking after admin unlink)
        auth_method.deleted_at = None
        auth_method.provider_data = _encrypt_provider_data(tokens, user_info)
        auth_method.verified = user_info.get("email_verified", False)
        auth_method.last_used_at = datetime.utcnow()
        auth_method.save()
    else:
        auth_method = AuthenticationMethod(
            user_id=user.id,
            method_type=provider_type,
            provider_user_id=user_info["provider_user_id"],
            provider_data=_encrypt_provider_data(tokens, user_info),
            verified=user_info.get("email_verified", False),
            is_primary=False,
            last_used_at=datetime.utcnow(),
        )
        auth_method.save()

    state_record.mark_used()

    AuditService.log_external_auth_link_completed(
        user_id=user.id,
        organization_id=state_record.organization_id,
        provider_type=provider_type_str,
        provider_user_id=user_info["provider_user_id"],
        auth_method_id=auth_method.id,
    )

    return auth_method


def authenticate_with_provider(
    get_provider_config,
    provider_type: AuthMethodType,
    organization_id: str,
    authorization_code: str,
    state: str,
    redirect_uri: str,
) -> Tuple[User, dict]:
    from gatehouse_app.services.external_auth._helpers import (
        _exchange_code,
        _get_user_info,
        _encrypt_provider_data,
    )

    provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

    state_record = OAuthState.query.filter_by(state=state).first()
    if not state_record or not state_record.is_valid():
        AuditService.log_external_auth_login_failed(
            organization_id=organization_id,
            provider_type=provider_type_str,
            failure_reason="invalid_state",
            error_message="Invalid or expired OAuth state",
        )
        raise ExternalAuthError("Invalid or expired OAuth state", "INVALID_STATE", 400)

    config = get_provider_config(provider_type, organization_id)

    tokens = _exchange_code(
        config=config,
        code=authorization_code,
        redirect_uri=redirect_uri,
        code_verifier=state_record.code_verifier,
    )

    user_info = _get_user_info(config=config, access_token=tokens["access_token"])

    auth_method = AuthenticationMethod.query.filter_by(
        method_type=provider_type,
        provider_user_id=user_info["provider_user_id"],
    ).first()

    if not auth_method:
        existing_user = User.query.filter_by(email=user_info["email"]).first()

        if existing_user:
            AuditService.log_external_auth_login_failed(
                organization_id=organization_id,
                provider_type=provider_type_str,
                provider_user_id=user_info["provider_user_id"],
                email=user_info["email"],
                failure_reason="email_exists",
                error_message=f"An account with email {user_info['email']} already exists",
            )
            raise ExternalAuthError(
                f"An account with email {user_info['email']} already exists. "
                "Please log in with your password and link your Google account from settings.",
                "EMAIL_EXISTS",
                400,
            )

        AuditService.log_external_auth_login_failed(
            organization_id=organization_id,
            provider_type=provider_type_str,
            provider_user_id=user_info["provider_user_id"],
            email=user_info["email"],
            failure_reason="account_not_found",
            error_message="No Gatehouse account matches this external account",
        )
        raise ExternalAuthError(
            "No Gatehouse account matches this external account. Please register first.",
            "ACCOUNT_NOT_FOUND",
            400,
        )

    user = auth_method.user
    auth_method.provider_data = _encrypt_provider_data(tokens, user_info)
    auth_method.last_used_at = datetime.utcnow()
    auth_method.save()

    state_record.mark_used()

    from gatehouse_app.services.auth_service import AuthService
    session = AuthService.create_session(user=user, organization_id=organization_id)

    AuditService.log_external_auth_login(
        user_id=user.id,
        organization_id=organization_id,
        provider_type=provider_type_str,
        provider_user_id=user_info["provider_user_id"],
        auth_method_id=auth_method.id,
        session_id=session.id,
    )

    return user, session.to_dict()


def unlink_provider(
    user_id: str,
    provider_type: AuthMethodType,
    organization_id: str = None,
) -> bool:
    provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

    auth_method = AuthenticationMethod.query.filter_by(
        user_id=user_id,
        method_type=provider_type,
    ).first()

    if not auth_method:
        raise ExternalAuthError("Provider not linked", "PROVIDER_NOT_LINKED", 400)

    other_methods = AuthenticationMethod.query.filter_by(user_id=user_id).count()
    if other_methods <= 1:
        raise ExternalAuthError(
            "Cannot unlink the last authentication method",
            "CANNOT_UNLINK_LAST",
            400,
        )

    provider_user_id = auth_method.provider_user_id
    auth_method_id = auth_method.id
    auth_method.delete()

    AuditService.log_external_auth_unlink(
        user_id=user_id,
        organization_id=organization_id,
        provider_type=provider_type_str,
        provider_user_id=provider_user_id,
        auth_method_id=auth_method_id,
    )

    return True


def get_linked_accounts(user_id: str) -> list:
    from gatehouse_app.utils.constants import AuthMethodType as AMT

    methods = AuthenticationMethod.query.filter_by(user_id=user_id, deleted_at=None).all()

    external_providers = [AMT.GOOGLE, AMT.GITHUB, AMT.MICROSOFT]

    return [
        {
            "id": m.id,
            "provider_type": m.method_type.value if hasattr(m.method_type, 'value') else str(m.method_type),
            "provider_user_id": m.provider_user_id,
            "email": m.provider_data.get("email") if m.provider_data else None,
            "name": m.provider_data.get("name") if m.provider_data else None,
            "picture": m.provider_data.get("picture") if m.provider_data else None,
            "verified": m.verified,
            "linked_at": m.created_at.isoformat() if m.created_at else None,
            "last_used_at": m.last_used_at.isoformat() if m.last_used_at else None,
        }
        for m in methods
        if m.method_type in external_providers
        or str(m.method_type) in [p.value for p in external_providers]
    ]
