"""Registration flow: initiate and handle OAuth register callback."""
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional, Tuple

from gatehouse_app.models import User, AuthenticationMethod
from gatehouse_app.models.auth.authentication_method import OAuthState
from gatehouse_app.utils.constants import AuthMethodType, AuditAction
from gatehouse_app.services.audit_service import AuditService
from gatehouse_app.services.external_auth import ExternalAuthService
from gatehouse_app.services.external_auth.models import ExternalAuthError
from gatehouse_app.services.oauth_flow.login import OAuthFlowError

logger = logging.getLogger(__name__)


def initiate_register_flow(
    provider_type: AuthMethodType,
    organization_id: str = None,
    redirect_uri: str = None,
) -> Tuple[str, str]:
    provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

    try:
        config = ExternalAuthService.get_provider_config(provider_type, organization_id)

        if redirect_uri and not config.is_redirect_uri_allowed(redirect_uri):
            raise OAuthFlowError("Invalid redirect URI", "INVALID_REDIRECT_URI", 400)

        code_verifier = None
        code_challenge = None
        if provider_type_str not in ['google', 'microsoft']:
            code_verifier = secrets.token_urlsafe(32)
            code_challenge = ExternalAuthService._compute_s256_challenge(code_verifier)

        logger.info(
            f"[PKCE DEBUG] Register flow - Provider type check: provider_type_str='{provider_type_str}', "
            f"is_google={provider_type_str in ['google']}, "
            f"will_skip_pkce={provider_type_str in ['google', 'microsoft']}"
        )

        state = OAuthState.create_state(
            flow_type="register",
            provider_type=provider_type,
            organization_id=organization_id,
            redirect_uri=redirect_uri or (config.redirect_uris[0] if config.redirect_uris else None),
            code_verifier=code_verifier,
            code_challenge=code_challenge,
            lifetime_seconds=600,
        )

        logger.info(
            f"[PKCE DEBUG] Register flow - Created OAuthState:\n"
            f"  state.id: {state.id}\n"
            f"  state.code_challenge: {state.code_challenge}\n"
            f"  state.code_verifier: {state.code_verifier[:20] if state.code_verifier else None}..."
        )

        auth_url = ExternalAuthService._build_authorization_url(config=config, state=state)

        logger.info(
            f"OAuth register flow initiated for provider={provider_type_str}, "
            f"org_id={organization_id}, state_id={state.id}"
        )
        logger.info(
            f"[PKCE DEBUG] Register flow - FINAL: auth_url_has_challenge={'code_challenge=' in auth_url}"
        )

        return auth_url, state.state

    except ExternalAuthError as e:
        AuditService.log_action(
            action=AuditAction.EXTERNAL_AUTH_LOGIN_FAILED,
            organization_id=organization_id,
            metadata={
                "provider_type": provider_type_str,
                "failure_reason": e.error_type,
            },
            description=f"OAuth registration initiation failed: {e.message}",
            success=False,
            error_message=e.message,
        )
        raise


def handle_register_callback(
    provider_type: AuthMethodType,
    state_record: OAuthState,
    authorization_code: str,
    redirect_uri: str,
) -> dict:
    from gatehouse_app.services.external_auth._helpers import _encrypt_provider_data

    provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

    try:
        config = ExternalAuthService.get_provider_config(
            provider_type, state_record.organization_id
        )

        tokens = ExternalAuthService._exchange_code(
            config=config,
            code=authorization_code,
            redirect_uri=redirect_uri,
            code_verifier=state_record.code_verifier,
        )

        user_info = ExternalAuthService._get_user_info(
            config=config,
            access_token=tokens["access_token"],
        )

        existing_user = User.query.filter_by(email=user_info["email"]).first()
        if existing_user:
            raise OAuthFlowError(
                f"An account with email {user_info['email']} already exists. "
                "Please log in with your password and link your Google account from settings.",
                "EMAIL_EXISTS",
                400,
            )

        user = User(
            email=user_info["email"],
            full_name=user_info.get("name", ""),
            status="active",
            email_verified=user_info.get("email_verified", False),
        )
        user.save()

        auth_method = AuthenticationMethod(
            user_id=user.id,
            method_type=provider_type,
            provider_user_id=user_info["provider_user_id"],
            provider_data=_encrypt_provider_data(tokens, user_info),
            verified=user_info.get("email_verified", False),
            is_primary=True,
            last_used_at=datetime.utcnow(),
        )
        auth_method.save()

        state_record.mark_used()

        AuditService.log_action(
            action="user.register",
            user_id=user.id,
            organization_id=state_record.organization_id,
            resource_type="user",
            resource_id=user.id,
            metadata={
                "provider_type": provider_type_str,
                "provider_user_id": user_info["provider_user_id"],
                "auth_method_id": auth_method.id,
            },
            description=f"User registered via {provider_type_str}",
            success=True,
        )

        AuditService.log_external_auth_link_completed(
            user_id=user.id,
            organization_id=state_record.organization_id,
            provider_type=provider_type_str,
            provider_user_id=user_info["provider_user_id"],
            auth_method_id=auth_method.id,
        )

        logger.info(
            f"OAuth registration successful for email={user_info['email']}, "
            f"provider={provider_type_str}, user_id={user.id}"
        )

        if state_record.organization_id:
            from gatehouse_app.models.organization.organization import Organization
            org = Organization.query.get(state_record.organization_id)
            if org:
                from gatehouse_app.services.auth_service import AuthService
                session = AuthService.create_session(user=user, is_compliance_only=False)
                session_dict = session.to_dict()
                session_dict["token"] = session.token
                expires_at = session.expires_at
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                session_dict["expires_in"] = int((expires_at - now).total_seconds())
                return {
                    "success": True,
                    "flow_type": "register",
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "full_name": user.full_name,
                        "organization_id": org.id,
                    },
                    "session": session_dict,
                }

        from gatehouse_app.services.auth_service import AuthService as _AS
        from gatehouse_app.models.organization.org_invite_token import OrgInviteToken
        _session = _AS.create_session(user=user, is_compliance_only=False)
        _session_dict = _session.to_dict()
        _session_dict["token"] = _session.token
        _expires_at = _session.expires_at
        if _expires_at.tzinfo is None:
            _expires_at = _expires_at.replace(tzinfo=timezone.utc)
        _now = datetime.now(timezone.utc)
        _session_dict["expires_in"] = int((_expires_at - _now).total_seconds())

        _pending = OrgInviteToken.query.filter(
            OrgInviteToken.email == user.email,
            OrgInviteToken.accepted_at.is_(None),
            OrgInviteToken.expires_at > _now,
            OrgInviteToken.deleted_at.is_(None),
        ).all()
        _pending_list = [
            {
                "token": inv.token,
                "organization": {"id": str(inv.organization_id), "name": inv.organization.name},
                "role": inv.role,
                "expires_at": inv.expires_at.isoformat(),
            }
            for inv in _pending
        ]

        return {
            "success": True,
            "flow_type": "register",
            "requires_org_creation": True,
            "user": {"id": user.id, "email": user.email, "full_name": user.full_name},
            "session": _session_dict,
            "pending_invites": _pending_list,
            "state": state_record.state,
        }

    except ExternalAuthError as e:
        logger.warning(
            f"OAuth registration failed for state={state_record.id}, "
            f"provider={provider_type_str}, error={e.message}"
        )
        raise
    except OAuthFlowError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in OAuth registration callback: {str(e)}", exc_info=True)
        raise OAuthFlowError(
            "An unexpected error occurred during registration",
            "INTERNAL_ERROR",
            500,
        )
