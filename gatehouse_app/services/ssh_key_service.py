"""SSH Key management service."""
import base64
import logging
import os
import secrets
import subprocess
import tempfile
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

from gatehouse_app.extensions import db
from gatehouse_app.models import SSHKey, User
from gatehouse_app.exceptions import (
    SSHKeyError,
    SSHKeyNotFoundError,
    SSHKeyAlreadyExistsError,
    SSHKeyNotVerifiedError,
    ValidationError,
    UserNotFoundError,
)
from gatehouse_app.utils.crypto import (
    compute_ssh_fingerprint,
    verify_ssh_key_format,
    extract_ssh_key_type,
    extract_ssh_key_comment,
)
from gatehouse_app.config.ssh_ca_config import get_ssh_ca_config

logger = logging.getLogger(__name__)


class SSHKeyService:
    """Service for managing SSH keys."""

    def __init__(self):
        """Initialize SSH key service."""
        self.config = get_ssh_ca_config()

    def add_ssh_key(
        self,
        user_id: str,
        public_key: str,
        description: Optional[str] = None,
    ) -> SSHKey:
        """Add an SSH public key for a user.
        
        Args:
            user_id: ID of the user
            public_key: SSH public key in OpenSSH format
            description: Optional description of the key
            
        Returns:
            Created SSHKey instance
            
        Raises:
            UserNotFoundError: If user doesn't exist
            SSHKeyError: If key format is invalid
            SSHKeyAlreadyExistsError: If key already exists
        """
        # Verify user exists
        user = User.query.get(user_id)
        if not user:
            raise UserNotFoundError(f"User {user_id} not found")
        
        # Validate key format
        if not verify_ssh_key_format(public_key):
            raise SSHKeyError("Invalid SSH public key format")
        
        # Compute fingerprint
        try:
            fingerprint = compute_ssh_fingerprint(public_key)
        except Exception as e:
            logger.error(f"Failed to compute fingerprint: {str(e)}")
            raise SSHKeyError(f"Failed to compute key fingerprint: {str(e)}")
        
        # Check for duplicate (including soft-deleted records — fingerprint is unique in DB)
        existing = SSHKey.query.filter_by(fingerprint=fingerprint).first()
        if existing:
            if existing.deleted_at is not None:
                # Restore the soft-deleted key: clear deleted_at and update fields
                existing.deleted_at = None
                existing.user_id = user_id
                existing.description = description or existing.description
                existing.verified = False
                existing.verified_at = None
                existing.verify_text = None
                existing.verify_text_created_at = None
                db.session.commit()
                logger.info(
                    f"Restored soft-deleted SSH key for user {user_id}: "
                    f"fingerprint={fingerprint}"
                )
                return existing
            raise SSHKeyAlreadyExistsError(
                f"SSH key with fingerprint {fingerprint} already exists"
            )
        
        # Extract metadata
        key_type = extract_ssh_key_type(public_key)
        key_comment = extract_ssh_key_comment(public_key)
        
        # Create SSH key record
        ssh_key = SSHKey(
            user_id=user_id,
            payload=public_key,
            fingerprint=fingerprint,
            description=description,
            key_type=key_type,
            key_comment=key_comment,
            verified=False,
        )
        
        ssh_key.save()
        
        logger.info(
            f"SSH key added for user {user_id}: "
            f"fingerprint={fingerprint}, type={key_type}"
        )
        
        return ssh_key

    def get_ssh_key(self, key_id: str) -> SSHKey:
        """Get an SSH key by ID.
        
        Args:
            key_id: SSH key ID
            
        Returns:
            SSHKey instance
            
        Raises:
            SSHKeyNotFoundError: If key not found
        """
        key = SSHKey.query.filter_by(id=key_id, deleted_at=None).first()
        if not key:
            raise SSHKeyNotFoundError(f"SSH key {key_id} not found")
        return key

    def get_user_ssh_keys(self, user_id: str) -> List[SSHKey]:
        """Get all SSH keys for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of SSHKey instances
        """
        return SSHKey.query.filter_by(user_id=user_id, deleted_at=None).all()

    def get_user_verified_ssh_keys(self, user_id: str) -> List[SSHKey]:
        """Get all verified SSH keys for a user.
        
        Args:
            user_id: User ID
            
        Returns:
            List of verified SSHKey instances
        """
        return SSHKey.query.filter_by(
            user_id=user_id,
            verified=True,
            deleted_at=None,
        ).all()

    def delete_ssh_key(self, key_id: str) -> None:
        """Soft-delete an SSH key.
        
        Args:
            key_id: SSH key ID
            
        Raises:
            SSHKeyNotFoundError: If key not found
        """
        key = self.get_ssh_key(key_id)
        key.delete()
        
        logger.info(f"SSH key deleted: {key_id}")

    def generate_verification_challenge(self, key_id: str) -> str:
        """Generate a verification challenge for an SSH key.
        
        The user must sign this challenge text with their private key
        to prove key ownership.
        
        Args:
            key_id: SSH key ID
            
        Returns:
            Verification challenge text
            
        Raises:
            SSHKeyNotFoundError: If key not found
        """
        key = self.get_ssh_key(key_id)
        
        # Generate random challenge
        challenge = secrets.token_hex(32)
        challenge_text = f"Please sign this to verify SSH key ownership: {challenge}"
        
        # Store challenge
        key.verify_text = challenge_text
        key.verify_text_created_at = datetime.utcnow()
        key.save()
        
        logger.info(f"Generated verification challenge for SSH key {key_id}")
        
        return challenge_text

    def verify_ssh_key_ownership(
        self,
        key_id: str,
        signature: str,
    ) -> bool:
        """Verify SSH key ownership via signature.
        
        The user must sign the verification challenge with their private key.
        We verify the signature using the public key.
        
        Args:
            key_id: SSH key ID
            signature: Base64-encoded signature of the challenge
            
        Returns:
            True if signature is valid
            
        Raises:
            SSHKeyNotFoundError: If key not found
            SSHKeyNotVerifiedError: If challenge is stale or missing
            SSHKeyError: If verification fails
        """
        key = self.get_ssh_key(key_id)
        
        # Check if challenge exists and is not stale
        if not key.verify_text or not key.verify_text_created_at:
            raise SSHKeyNotVerifiedError("No verification challenge generated")
        
        max_age = self.config.get_int('verification_challenge_max_age')
        age = datetime.utcnow() - key.verify_text_created_at
        if age.total_seconds() > (max_age * 3600):
            raise SSHKeyNotVerifiedError("Verification challenge has expired")
        
        try:
            # Verify the SSH signature using ssh-keygen -Y verify.
            # The CLI signs the challenge with: ssh-keygen -Y sign -f <key> -n file <challenge>
            # We verify with:                  ssh-keygen -Y verify -f <allowed_signers> -I <identity> -n file -s <sig> < <message>
            #
            # allowed_signers format: "<identity> <keytype> <pubkey>"
            # We use the key fingerprint as the identity.

            sig_bytes = base64.b64decode(signature)
            challenge_text = key.verify_text + "\n"

            with tempfile.TemporaryDirectory() as tmpdir:
                allowed_signers_path = os.path.join(tmpdir, "allowed_signers")
                sig_path = os.path.join(tmpdir, "message.sig")
                message_path = os.path.join(tmpdir, "message.txt")

                identity = key.fingerprint

                # Write the allowed_signers file
                with open(allowed_signers_path, "w") as f:
                    f.write(f"{identity} {key.payload}\n")

                # Write the signature file
                with open(sig_path, "wb") as f:
                    f.write(sig_bytes)

                # Write the challenge message
                with open(message_path, "w") as f:
                    f.write(challenge_text)

                result = subprocess.run(
                    [
                        "ssh-keygen", "-Y", "verify",
                        "-f", allowed_signers_path,
                        "-I", identity,
                        "-n", "file",
                        "-s", sig_path,
                    ],
                    stdin=open(message_path, "rb"),
                    capture_output=True,
                    timeout=10,
                )

                if result.returncode != 0:
                    stderr = result.stderr.decode(errors="replace").strip()
                    logger.warning(f"SSH signature verification failed for key {key_id}: {stderr}")
                    raise SSHKeyError(f"Signature verification failed: {stderr}")

            key.mark_verified()
            logger.info(f"SSH key verified: {key_id}")
            return True
        
        except SSHKeyError:
            raise
        except Exception as e:
            logger.error(f"SSH key verification failed: {str(e)}")
            raise SSHKeyError(f"Signature verification failed: {str(e)}")

    def get_key_fingerprint(self, key_id: str) -> str:
        """Get the fingerprint of an SSH key.
        
        Args:
            key_id: SSH key ID
            
        Returns:
            Fingerprint string
            
        Raises:
            SSHKeyNotFoundError: If key not found
        """
        key = self.get_ssh_key(key_id)
        return key.fingerprint

    def update_ssh_key_description(self, key_id: str, description: str) -> SSHKey:
        """Update the description of an SSH key.
        
        Args:
            key_id: SSH key ID
            description: New description
            
        Returns:
            Updated SSHKey instance
            
        Raises:
            SSHKeyNotFoundError: If key not found
        """
        key = self.get_ssh_key(key_id)
        key.description = description
        key.save()
        
        return key

    def cleanup_expired_challenges(self) -> int:
        """Clean up expired verification challenges.
        
        Returns:
            Number of challenges cleaned
        """
        max_age = self.config.get_int('verification_challenge_max_age')
        threshold = datetime.utcnow() - timedelta(hours=max_age)
        
        expired = SSHKey.query.filter(
            SSHKey.verify_text_created_at < threshold,
            SSHKey.verify_text_created_at.isnot(None),
            SSHKey.deleted_at.is_(None),
        ).update({"verify_text": None, "verify_text_created_at": None})
        
        db.session.commit()
        
        logger.info(f"Cleaned up {expired} expired verification challenges")
        return expired

    def cleanup_unverified_keys(self) -> int:
        """Delete unverified SSH keys older than configured days.
        
        Returns:
            Number of keys deleted
        """
        days = self.config.get_int('auto_delete_unverified_days')
        threshold = datetime.utcnow() - timedelta(days=days)
        
        old_unverified = SSHKey.query.filter(
            SSHKey.verified == False,
            SSHKey.created_at < threshold,
            SSHKey.deleted_at.is_(None),
        ).all()
        
        count = 0
        for key in old_unverified:
            key.delete()
            count += 1
        
        logger.info(f"Deleted {count} unverified SSH keys older than {days} days")
        return count
