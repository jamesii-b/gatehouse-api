"""Login flow: initiate and handle OAuth login callback."""
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

logger = logging.getLogger(__name__)


class OAuthFlowError(Exception):
    def __init__(self, message: str, error_type: str, status_code: int = 400):
        self.message = message
        self.error_type = error_type
        self.status_code = status_code
        super().__init__(message)


def initiate_login_flow(
    provider_type: AuthMethodType,
    organization_id: str = None,
    redirect_uri: str = None,
    state_data: dict = None,
) -> Tuple[str, str]:
    try:
        from flask import request
    except Exception:
        request = None

    try:
        ip_address = request.remote_addr if request else None
        user_agent = request.headers.get("User-Agent") if request else None
    except RuntimeError:
        ip_address = None
        user_agent = None

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
            f"[PKCE DEBUG] Provider type check: provider_type_str='{provider_type_str}', "
            f"is_google={provider_type_str in ['google']}, "
            f"will_skip_pkce={provider_type_str in ['google', 'microsoft']}"
        )

        state = OAuthState.create_state(
            flow_type="login",
            provider_type=provider_type,
            organization_id=organization_id,
            redirect_uri=redirect_uri or (config.redirect_uris[0] if config.redirect_uris else None),
            code_verifier=code_verifier,
            code_challenge=code_challenge,
            extra_data=state_data,
            lifetime_seconds=600,
        )

        logger.info(
            f"[PKCE DEBUG] Created OAuthState object:\n"
            f"  state.id: {state.id}\n"
            f"  state.provider_type: {state.provider_type}\n"
            f"  state.code_challenge: {state.code_challenge}\n"
            f"  state.code_verifier: {state.code_verifier[:20] if state.code_verifier else None}..."
        )

        auth_url = ExternalAuthService._build_authorization_url(config=config, state=state)

        logger.info(
            f"OAuth login flow initiated for provider={provider_type_str}, "
            f"org_id={organization_id}, state_token={state.state}, state_record_id={state.id}"
        )
        logger.info(
            f"[PKCE DEBUG] FINAL CHECK: code_challenge={code_challenge}, "
            f"code_verifier={code_verifier[:20] if code_verifier else None}..., "
            f"auth_url_has_challenge={'code_challenge=' in auth_url}, "
            f"returned_auth_url={auth_url}"
        )

        return auth_url, state.state

    except ExternalAuthError as e:
        AuditService.log_action(
            action=AuditAction.EXTERNAL_AUTH_LOGIN_FAILED,
            organization_id=organization_id,
            metadata={
                "provider_type": provider_type_str,
                "failure_reason": e.error_type,
                "ip_address": ip_address,
            },
            description=f"OAuth login initiation failed: {e.message}",
            success=False,
            error_message=e.message,
        )
        raise


def handle_login_callback(
    provider_type: AuthMethodType,
    state_record: OAuthState,
    authorization_code: str,
    redirect_uri: str,
    ip_address: str = None,
    user_agent: str = None,
) -> dict:
    from gatehouse_app.services.external_auth._helpers import _encrypt_provider_data

    provider_type_str = provider_type.value if isinstance(provider_type, AuthMethodType) else provider_type

    try:
        config = ExternalAuthService.get_provider_config(
            provider_type, state_record.organization_id
        )

        logger.debug(
            f"Exchanging code with PKCE: state_record.code_verifier="
            f"{state_record.code_verifier[:20] if state_record.code_verifier else None}..."
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

        if not user_info.get("provider_user_id"):
            raise OAuthFlowError(
                "Provider did not return a user identifier (sub claim). "
                "Cannot complete authentication.",
                "MISSING_PROVIDER_USER_ID",
                400,
            )

        if not user_info.get("email"):
            raise OAuthFlowError(
                "Provider did not return an email address. "
                "Cannot complete authentication.",
                "MISSING_EMAIL",
                400,
            )

        logger.debug(
            f"Got user_info from provider: sub={user_info['provider_user_id']}, "
            f"email={user_info['email']}, email_verified={user_info.get('email_verified')}"
        )

        # Find the active auth method for this provider identity.
        # Order by created_at DESC so that an explicitly linked (newer) row wins
        # over an older auto-created primary row when the same Google identity
        # was linked to a second profile.
        auth_method = (
            AuthenticationMethod.query
            .filter_by(
                method_type=provider_type,
                provider_user_id=user_info["provider_user_id"],
                deleted_at=None,
            )
            .order_by(AuthenticationMethod.created_at.desc())
            .first()
        )

        if not auth_method:
            deleted_method = (
                AuthenticationMethod.query
                .filter_by(
                    method_type=provider_type,
                    provider_user_id=user_info["provider_user_id"],
                )
                .order_by(AuthenticationMethod.created_at.desc())
                .first()
            )

            if deleted_method:
                logger.info(
                    f"OAuth login: restoring previously unlinked {provider_type_str} "
                    f"auth method for user {deleted_method.user_id}"
                )
                deleted_method.deleted_at = None
                deleted_method.provider_data = _encrypt_provider_data(tokens, user_info)
                deleted_method.last_used_at = datetime.utcnow()
                deleted_method.save()
                auth_method = deleted_method

            else:
                existing_user = User.query.filter_by(email=user_info["email"], deleted_at=None).first()

                if existing_user:
                    logger.info(
                        f"OAuth login: email {user_info['email']} matches existing user "
                        f"{existing_user.id}, auto-linking {provider_type_str} account"
                    )
                    auth_method = AuthenticationMethod(
                        user_id=existing_user.id,
                        method_type=provider_type,
                        provider_user_id=user_info["provider_user_id"],
                        provider_data=_encrypt_provider_data(tokens, user_info),
                        verified=user_info.get("email_verified", False),
                        is_primary=False,
                        last_used_at=datetime.utcnow(),
                    )
                    auth_method.save()
                    user = existing_user
                else:
                    logger.info(
                        f"OAuth login: no account for {user_info['email']}, "
                        f"auto-creating user via {provider_type_str}"
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

                    AuditService.log_action(
                        action="user.register",
                        user_id=user.id,
                        organization_id=state_record.organization_id,
                        resource_type="user",
                        resource_id=user.id,
                        metadata={
                            "provider_type": provider_type_str,
                            "provider_user_id": user_info["provider_user_id"],
                            "auto_registered": True,
                        },
                        description=f"User auto-registered via {provider_type_str} OAuth",
                        success=True,
                    )
        else:
            auth_method.provider_data = _encrypt_provider_data(tokens, user_info)
            auth_method.last_used_at = datetime.utcnow()
            auth_method.save()

        user = auth_method.user

        user_orgs = user.get_organizations()
        target_org = None

        if state_record.organization_id:
            target_org = next(
                (org for org in user_orgs if org.id == state_record.organization_id),
                None,
            )

        if not target_org and len(user_orgs) == 1:
            target_org = user_orgs[0]

        if not target_org and len(user_orgs) > 1:
            # Multiple orgs and none specified in the OAuth state — pick the one the
            # user joined most recently (highest created_at on their membership row).
            # Users can switch organisations inside the app after logging in.
            from gatehouse_app.models.organization.organization_member import OrganizationMember as _OM
            latest_membership = (
                _OM.query
                .filter_by(user_id=user.id, deleted_at=None)
                .order_by(_OM.created_at.desc())
                .first()
            )
            if latest_membership:
                target_org = latest_membership.organization
            else:
                target_org = user_orgs[0]

        if not target_org and len(user_orgs) == 0:
            from gatehouse_app.models.organization.org_invite_token import OrgInviteToken
            from gatehouse_app.services.auth_service import AuthService as _AS
            _now = datetime.now(timezone.utc)
            _session = _AS.create_session(user=user, is_compliance_only=False)
            _session_dict = _session.to_dict()
            _session_dict["token"] = _session.token
            _expires_at = _session.expires_at
            if _expires_at.tzinfo is None:
                _expires_at = _expires_at.replace(tzinfo=timezone.utc)
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

            state_record.mark_used()
            logger.info(
                f"OAuth login: user {user.id} has no org, redirecting to org-setup "
                f"(pending_invites={len(_pending_list)})"
            )
            return {
                "success": True,
                "flow_type": "login",
                "requires_org_creation": True,
                "user": {"id": user.id, "email": user.email, "full_name": user.full_name},
                "session": _session_dict,
                "pending_invites": _pending_list,
                "state": state_record.state,
            }

        if not target_org:
            state_record.mark_used()
            logger.info(
                f"OAuth login requires org selection for user={user.id}, "
                f"provider={provider_type_str}, org_count={len(user_orgs)}"
            )
            return {
                "success": True,
                "flow_type": "login",
                "requires_org_selection": True,
                "user": {"id": user.id, "email": user.email, "full_name": user.full_name},
                "available_organizations": [
                    {
                        "id": org.id,
                        "name": org.name,
                        "slug": org.slug if hasattr(org, "slug") else None,
                    }
                    for org in user_orgs
                ],
                "state": state_record.state,
            }

        from gatehouse_app.services.auth_service import AuthService
        session = AuthService.create_session(user=user, is_compliance_only=False)
        state_record.mark_used()

        AuditService.log_external_auth_login(
            user_id=user.id,
            organization_id=target_org.id,
            provider_type=provider_type_str,
            provider_user_id=user_info["provider_user_id"],
            auth_method_id=auth_method.id,
            session_id=session.id,
        )

        logger.info(
            f"OAuth login successful for user={user.id}, "
            f"provider={provider_type_str}, org_id={target_org.id}"
        )

        session_dict = session.to_dict()
        session_dict["token"] = session.token
        expires_at = session.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        session_dict["expires_in"] = int((expires_at - now).total_seconds())

        return {
            "success": True,
            "flow_type": "login",
            "user": {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "organization_id": target_org.id,
            },
            "session": session_dict,
        }

    except ExternalAuthError as e:
        logger.warning(
            f"OAuth login failed for state={state_record.id}, "
            f"provider={provider_type_str}, error={e.message}"
        )
        raise
    except OAuthFlowError:
        raise
    except Exception as e:
        logger.error(f"Unexpected error in OAuth login callback: {str(e)}", exc_info=True)
        raise OAuthFlowError("An unexpected error occurred during login", "INTERNAL_ERROR", 500)
