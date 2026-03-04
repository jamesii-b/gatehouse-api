"""Password reset, email verification, and account activation endpoints."""
import logging
from flask import request, current_app
from gatehouse_app.api.v1 import api_v1_bp
from gatehouse_app.extensions import limiter
from gatehouse_app.utils.response import api_response
from gatehouse_app.services.auth_service import AuthService
from gatehouse_app.services.notification_service import NotificationService

_logger = logging.getLogger(__name__)


@api_v1_bp.route("/auth/forgot-password", methods=["POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_AUTH_FORGOT_PASSWORD"])
def forgot_password():
    from gatehouse_app.models import User, PasswordResetToken

    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return api_response(success=False, message="Email is required", status=400, error_type="VALIDATION_ERROR")

    user = User.query.filter_by(email=email, deleted_at=None).first()
    if user:
        try:
            reset_token = PasswordResetToken.generate(user_id=user.id)
            app_url = current_app.config.get("APP_URL", "http://localhost:8080")
            reset_link = f"{app_url}/reset-password?token={reset_token.token}"
            NotificationService._send_email(
                to_address=user.email,
                subject="Reset your Gatehouse password",
                body=(
                    f"Hi {user.full_name or user.email},\n\n"
                    f"You requested a password reset for your Gatehouse account.\n\n"
                    f"Click the link below to reset your password (valid for 2 hours):\n"
                    f"{reset_link}\n\n"
                    f"If you did not request this, you can safely ignore this email.\n\n"
                    f"Gatehouse Security Team"
                ),
            )
            _logger.info(f"Password reset token generated for user {user.id}")
        except Exception as exc:
            _logger.exception(f"Error generating password reset token: {exc}")

    return api_response(data={}, message="If an account exists for this email, you will receive a password reset link shortly.")


@api_v1_bp.route("/auth/reset-password", methods=["POST"])
@limiter.limit(lambda: current_app.config["RATELIMIT_AUTH_RESET_PASSWORD"])
def reset_password():
    from gatehouse_app.extensions import bcrypt
    from gatehouse_app.models import PasswordResetToken, AuthenticationMethod
    from gatehouse_app.utils.constants import AuthMethodType
    from gatehouse_app.extensions import db

    data = request.get_json() or {}
    token_value = (data.get("token") or "").strip()
    new_password = data.get("password") or ""
    password_confirm = data.get("password_confirm") or ""

    if not token_value or not new_password:
        return api_response(success=False, message="Token and new password are required", status=400, error_type="VALIDATION_ERROR")

    if new_password != password_confirm:
        return api_response(success=False, message="Passwords do not match", status=400, error_type="VALIDATION_ERROR")

    if len(new_password) < 8:
        return api_response(success=False, message="Password must be at least 8 characters", status=400, error_type="VALIDATION_ERROR")

    reset_token = PasswordResetToken.query.filter_by(token=token_value).first()
    if not reset_token or not reset_token.is_valid:
        return api_response(success=False, message="This password reset link is invalid or has expired.", status=400, error_type="INVALID_TOKEN")

    try:
        user = reset_token.user
        auth_method = AuthenticationMethod.query.filter_by(user_id=user.id, method_type=AuthMethodType.PASSWORD, deleted_at=None).first()
        if auth_method:
            auth_method.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
            db.session.add(auth_method)
        reset_token.consume()
        _logger.info(f"Password reset for user {user.id}")
        return api_response(data={}, message="Your password has been reset. You can now sign in with your new password.")
    except Exception as exc:
        _logger.exception(f"Error resetting password: {exc}")
        return api_response(success=False, message="An error occurred while resetting your password.", status=500, error_type="INTERNAL_ERROR")


@api_v1_bp.route("/auth/verify-email", methods=["POST"])
def verify_email():
    from gatehouse_app.models import EmailVerificationToken
    from gatehouse_app.extensions import db

    data = request.get_json() or {}
    token_value = (data.get("token") or "").strip()

    if not token_value:
        return api_response(success=False, message="Verification token is required", status=400, error_type="VALIDATION_ERROR")

    verify_token = EmailVerificationToken.query.filter_by(token=token_value).first()
    if not verify_token or not verify_token.is_valid:
        return api_response(success=False, message="This verification link is invalid or has expired.", status=400, error_type="INVALID_TOKEN")

    try:
        user = verify_token.user
        user.email_verified = True
        db.session.add(user)
        verify_token.consume()
        _logger.info(f"Email verified for user {user.id}")
        return api_response(data={}, message="Your email has been verified. You can now sign in.")
    except Exception as exc:
        _logger.exception(f"Error verifying email: {exc}")
        return api_response(success=False, message="An error occurred while verifying your email.", status=500, error_type="INTERNAL_ERROR")


@api_v1_bp.route("/auth/resend-verification", methods=["POST"])
def resend_verification():
    from gatehouse_app.models import User, EmailVerificationToken

    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()

    if not email:
        return api_response(success=False, message="Email is required", status=400, error_type="VALIDATION_ERROR")

    user = User.query.filter_by(email=email, deleted_at=None).first()
    if user and not user.email_verified:
        try:
            verify_token = EmailVerificationToken.generate(user_id=user.id)
            app_url = current_app.config.get("APP_URL", "http://localhost:8080")
            verify_link = f"{app_url}/verify-email?token={verify_token.token}"
            NotificationService._send_email(
                to_address=user.email,
                subject="Verify your Gatehouse email address",
                body=(
                    f"Hi {user.full_name or user.email},\n\n"
                    f"Please verify your email address by clicking the link below (valid for 24 hours):\n"
                    f"{verify_link}\n\n"
                    f"Gatehouse Security Team"
                ),
            )
            _logger.info(f"Verification email sent for user {user.id}")
        except Exception as exc:
            _logger.exception(f"Error sending verification email: {exc}")

    return api_response(data={}, message="If an account exists for this email and is not yet verified, you will receive a verification link shortly.")


@api_v1_bp.route("/auth/activate", methods=["POST"])
def activate_account():
    import secrets
    from gatehouse_app.models.user.user import User
    from gatehouse_app.extensions import db

    data = request.get_json() or {}
    code = (data.get("code") or "").strip()
    if not code:
        return api_response(success=False, message="Activation code is required", status=400, error_type="VALIDATION_ERROR")

    user = User.query.filter_by(activation_key=code, deleted_at=None).first()
    if not user:
        return api_response(success=False, message="Invalid or expired activation code", status=404, error_type="NOT_FOUND")

    user.activated = True
    user.activation_key = None
    db.session.add(user)
    db.session.commit()

    user_session = AuthService.create_session(user)
    _logger.info(f"Account activated for user {user.id}")

    return api_response(
        data={
            "user": user.to_dict(),
            "token": user_session.token,
            "expires_at": user_session.expires_at.isoformat() + "Z" if user_session.expires_at.isoformat()[-1] != "Z" else user_session.expires_at.isoformat(),
        },
        message="Account activated successfully",
    )


@api_v1_bp.route("/auth/resend-activation", methods=["POST"])
def resend_activation():
    import secrets
    from gatehouse_app.models.user.user import User
    from gatehouse_app.extensions import db

    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    if not email:
        return api_response(success=False, message="Email is required", status=400, error_type="VALIDATION_ERROR")

    user = User.query.filter_by(email=email, deleted_at=None).first()
    if user and not user.activated:
        try:
            code = secrets.token_urlsafe(32)
            user.activation_key = code
            db.session.add(user)
            db.session.commit()

            app_url = current_app.config.get("APP_URL", current_app.config.get("FRONTEND_URL", "http://localhost:8080"))
            activate_link = f"{app_url}/activate?code={code}"
            NotificationService._send_email(
                to_address=user.email,
                subject="Activate your Gatehouse account",
                body=(
                    f"Hi {user.full_name or user.email},\n\n"
                    f"Please activate your Gatehouse account by clicking the link below:\n"
                    f"{activate_link}\n\n"
                    f"If you did not create an account, you can safely ignore this email.\n\n"
                    f"Gatehouse Security Team"
                ),
            )
            _logger.info(f"Activation email re-sent to {user.id}")
        except Exception as exc:
            _logger.exception(f"Error re-sending activation email: {exc}")

    return api_response(data={}, message="If an unactivated account exists for this email, you will receive a new activation link shortly.")
