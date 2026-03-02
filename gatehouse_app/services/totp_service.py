"""TOTP (Time-based One-Time Password) service."""
import base64
import io
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional, Tuple

import pyotp
from gatehouse_app.extensions import bcrypt

logger = logging.getLogger(__name__)

# TOTP codes are valid for at most (2*window + 1) * 30s steps.
# With window=1 that's 3 steps = 90 seconds.  We use a slightly
# generous TTL of 95 seconds to account for clock skew at boundaries.
_TOTP_USED_CODE_TTL = 95


class TOTPService:
    """Service for TOTP operations."""

    # ------------------------------------------------------------------
    # Replay-attack prevention helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _used_key(user_id: str, code: str) -> str:
        return f"totp:used:{user_id}:{code}"

    @staticmethod
    def is_code_already_used(user_id: str, code: str) -> bool:
        """Return True if *code* has already been accepted for *user_id*
        within the current validity window (prevents replay attacks)."""
        try:
            from gatehouse_app.extensions import redis_client
            if redis_client is None:
                return False
            return redis_client.exists(TOTPService._used_key(user_id, code)) == 1
        except Exception:
            logger.warning("Redis unavailable for TOTP replay check; allowing code")
            return False

    @staticmethod
    def mark_code_used(user_id: str, code: str) -> None:
        """Record *code* as consumed for *user_id* so it cannot be reused."""
        try:
            from gatehouse_app.extensions import redis_client
            if redis_client is None:
                return
            redis_client.setex(
                TOTPService._used_key(user_id, code),
                _TOTP_USED_CODE_TTL,
                "1",
            )
        except Exception:
            logger.warning("Redis unavailable; TOTP used-code not recorded")

    @staticmethod
    def generate_secret() -> str:
        """
        Generate a new TOTP secret.

        Returns:
            Base32 encoded secret (32 characters)

        Note:
            The secret is generated using cryptographically secure random bytes
            and encoded in base32 format for compatibility with authenticator apps.
        """
        # Generate 20 random bytes (160 bits) and encode as base32
        random_bytes = secrets.token_bytes(20)
        secret = base64.b32encode(random_bytes).decode("utf-8")
        logger.debug(f"Generated new TOTP secret: {secret[:8]}...")
        return secret

    @staticmethod
    def generate_provisioning_uri(user_email: str, secret: str, issuer: str = "Gatehouse") -> str:
        """
        Generate provisioning URI for QR code.

        Args:
            user_email: User's email address
            secret: TOTP secret (base32 encoded)
            issuer: Issuer name (default: "Gatehouse")

        Returns:
            otpauth:// URI for QR code generation

        Example:
            >>> uri = TOTPService.generate_provisioning_uri("user@example.com", "JBSWY3DPEHPK3PXP")
            >>> print(uri)
            otpauth://totp/Gatehouse:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Gatehouse
        """
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=user_email, issuer_name=issuer)
        logger.debug(f"Generated provisioning URI for user: {user_email}")
        return uri

    @staticmethod
    def verify_code(secret: str, code: str, window: int = 1, client_utc_timestamp: Optional[int] = None) -> bool:
        """
        Verify a TOTP code against the secret.

        Args:
            secret: TOTP secret (base32 encoded)
            code: 6-digit TOTP code to verify
            window: Time window for code validation (default: 1, allows codes from previous/next time steps)
            client_utc_timestamp: Optional client UTC timestamp in seconds since epoch.
                If provided, uses client's timestamp instead of server time to handle
                timezone mismatches between client and server.

        Returns:
            True if code is valid, False otherwise

        Note:
            The window parameter allows for clock skew between the server
            and the authenticator app. A window of 1 allows codes from
            the previous, current, and next 30-second intervals.
            
            IMPORTANT: Always uses UTC time for verification to ensure
            consistency across all timezones.
        """
        totp = pyotp.TOTP(secret)
        # Use timezone-aware UTC datetime for verification
        # IMPORTANT: We must pass a datetime object, NOT a Unix timestamp
        # pyotp's internal datetime.utcfromtimestamp() is deprecated and can be
        # affected by local timezone settings, causing the 10.5 hour skew issue
        if client_utc_timestamp:
            # Use client's UTC timestamp to handle timezone mismatches
            utc_now = datetime.fromtimestamp(client_utc_timestamp, tz=timezone.utc)
            logger.debug(f"[TOTP] Using client UTC timestamp: {client_utc_timestamp}")
        else:
            # Fallback to server time
            utc_now = datetime.now(timezone.utc)
        
        # DEBUG: Log detailed timezone information
        logger.debug(f"[TOTP DEBUG] UTC now: {utc_now}")
        logger.debug(f"[TOTP DEBUG] UTC now isoformat: {utc_now.isoformat()}")
        logger.debug(f"[TOTP DEBUG] UTC timestamp: {utc_now.timestamp()}")
        logger.debug(f"[TOTP DEBUG] UTC now tzinfo: {utc_now.tzinfo}")
        
        # Generate what the TOTP code should be at this moment using UTC datetime
        expected_code = totp.at(utc_now)
        logger.debug(f"[TOTP DEBUG] Expected TOTP code at UTC: {expected_code}")
        
        # Verify with the provided code using UTC datetime object
        # Passing a datetime object avoids pyotp's utcfromtimestamp() issues
        is_valid = totp.verify(code, valid_window=window, for_time=utc_now)
        
        logger.debug(f"[TOTP DEBUG] TOTP code verification: valid={is_valid}, window={window}")
        logger.debug(f"[TOTP DEBUG] Provided code: {code}, Expected code: {expected_code}")
        
        return is_valid

    @staticmethod
    def generate_backup_codes(count: int = 10) -> Tuple[list[str], list[str]]:
        """
        Generate backup codes for TOTP recovery.

        Args:
            count: Number of backup codes to generate (default: 10)

        Returns:
            Tuple of (plain_codes, hashed_codes)
            - plain_codes: List of plain text backup codes (for display to user)
            - hashed_codes: List of bcrypt hashed backup codes (for storage)

        Note:
            Backup codes are 16-character alphanumeric codes that can be used
            to recover access if the TOTP device is lost. Each code can only
            be used once.
        """
        plain_codes = []
        hashed_codes = []

        for _ in range(count):
            # Generate a 16-character alphanumeric code
            code = secrets.token_hex(8).upper()
            plain_codes.append(code)

            # Hash the code using bcrypt
            hashed_code = bcrypt.generate_password_hash(code).decode("utf-8")
            hashed_codes.append(hashed_code)

        logger.debug(f"Generated {count} backup codes")
        return plain_codes, hashed_codes

    @staticmethod
    def verify_backup_code(hashed_codes: list[str], code: str) -> Tuple[bool, list[str]]:
        """
        Verify and consume a backup code.

        Args:
            hashed_codes: List of bcrypt hashed backup codes
            code: Plain text backup code to verify

        Returns:
            Tuple of (is_valid, remaining_codes)
            - is_valid: True if code was valid and consumed, False otherwise
            - remaining_codes: List of remaining hashed codes (with consumed code removed)

        Note:
            Once a backup code is used, it is removed from the list and cannot
            be used again. This ensures each code is single-use.
        """
        remaining_codes = []
        matched = False

        for hashed_code in hashed_codes:
            if not matched and bcrypt.check_password_hash(hashed_code, code):
                # Code found and valid - mark as matched but don't add to remaining codes
                matched = True
            else:
                # Code doesn't match - keep it in remaining codes
                remaining_codes.append(hashed_code)

        if matched:
            return True, remaining_codes
        else:
            return False, hashed_codes

    @staticmethod
    def generate_qr_code_data_uri(provisioning_uri: str) -> str:
        """
        Generate QR code as data URI for frontend display.

        Args:
            provisioning_uri: otpauth:// URI to encode in QR code

        Returns:
            Base64 encoded PNG image as data URI (data:image/png;base64,...)

        Note:
            If the qrcode library is not installed, returns a placeholder message.
            Install with: pip install qrcode[pil]
        """
        try:
            import qrcode

            # Create QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(provisioning_uri)
            qr.make(fit=True)

            # Generate image
            img = qr.make_image(fill_color="black", back_color="white")

            # Convert to base64
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            img_base64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

            data_uri = f"data:image/png;base64,{img_base64}"
            logger.debug("Generated QR code data URI")
            return data_uri

        except ImportError:
            logger.warning("qrcode library not installed, returning placeholder")
            return "QR code generation requires the qrcode library. Install with: pip install qrcode[pil]"