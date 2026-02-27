"""SSH Certificate Authority signing service.

Handles SSH certificate signing operations, leveraging sshkey-tools library.
This service is a Gatehouse-integrated version of the secuird/ssh_ca.py logic.
"""
import logging
import os
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from sshkey_tools.cert import SSHCertificate, CertificateFields
from sshkey_tools.keys import PublicKey, PrivateKey

from gatehouse_app.config.ssh_ca_config import get_ssh_ca_config
from gatehouse_app.exceptions import SSHCAError, ValidationError
from gatehouse_app.utils.crypto import compute_ssh_fingerprint

logger = logging.getLogger(__name__)


class SSHCASigningError(Exception):
    """SSH CA signing operation error."""
    pass


class SSHCertificateSigningRequest:
    """Represents an SSH certificate signing request."""
    
    def __init__(
        self,
        ssh_public_key: str,
        principals: List[str],
        key_id: str,
        cert_type: str = "user",
        expiry_hours: Optional[int] = None,
        critical_options: Optional[Dict[str, str]] = None,
        extensions: Optional[List[str]] = None,
    ):
        """Initialize signing request.
        
        Args:
            ssh_public_key: Public key in OpenSSH format (e.g., "ssh-ed25519 AAAA...")
            principals: List of principals (e.g., ["prod-servers", "staging"])
            key_id: Key identifier (usually user email)
            cert_type: Certificate type - "user" or "host" (default: user)
            expiry_hours: Certificate validity in hours
            critical_options: Critical options dict
            extensions: List of extensions (e.g., ["permit-pty", "permit-agent-forwarding"])
        """
        self.ssh_public_key = ssh_public_key
        self.principals = principals or []
        self.key_id = key_id
        self.cert_type = cert_type
        self.expiry_hours = expiry_hours
        self.critical_options = critical_options or {}
        self.extensions = extensions or []

    def validate(self) -> List[str]:
        """Validate the signing request.
        
        Returns:
            List of validation errors (empty if valid)
        """
        errors = []
        config = get_ssh_ca_config()
        
        # Validate cert type
        if self.cert_type not in ("user", "host"):
            errors.append(f"Invalid cert_type: {self.cert_type}. Must be 'user' or 'host'")
        
        # Validate SSH public key
        if not self.ssh_public_key or len(self.ssh_public_key) < 16:
            errors.append("SSH public key is missing or invalid")
        else:
            try:
                PublicKey.from_string(self.ssh_public_key)
            except Exception as e:
                errors.append(f"SSH public key is not valid: {str(e)}")
        
        # Validate principals
        if not self.principals or len(self.principals) == 0:
            errors.append("At least one principal is required")
        else:
            max_principals = config.get_int('max_principals_per_cert')
            if len(self.principals) > max_principals:
                errors.append(
                    f"Too many principals ({len(self.principals)}). "
                    f"Maximum is {max_principals}"
                )
        
        # Validate key_id
        if not self.key_id or len(self.key_id) < 5:
            errors.append("key_id is missing or too short (minimum 5 characters)")
        else:
            max_id_len = config.get_int('max_key_id_length')
            if len(self.key_id) > max_id_len:
                errors.append(f"key_id exceeds maximum length of {max_id_len}")
        
        # Validate expiry_hours
        if self.expiry_hours is not None:
            if not isinstance(self.expiry_hours, int) or self.expiry_hours <= 0:
                errors.append("expiry_hours must be a positive integer")
            else:
                max_validity = config.get_int('max_cert_validity_hours')
                if self.expiry_hours > max_validity:
                    errors.append(
                        f"Requested expiry ({self.expiry_hours}h) exceeds "
                        f"maximum allowed ({max_validity}h)"
                    )
        
        return errors


class SSHCertificateSigningResponse:
    """Represents a signed SSH certificate response."""
    
    def __init__(
        self,
        certificate: str,
        serial: str,
        valid_after: datetime,
        valid_before: datetime,
        principals: Optional[List[str]] = None,
    ):
        """Initialize signing response.
        
        Args:
            certificate: Full certificate in OpenSSH format
            serial: Certificate serial number
            valid_after: Validity start datetime
            valid_before: Validity end datetime
            principals: List of principals the cert was issued for
        """
        self.certificate = certificate
        self.serial = serial
        self.valid_after = valid_after
        self.valid_before = valid_before
        self.principals = principals or []

    def to_dict(self) -> Dict[str, Any]:
        """Convert response to dictionary."""
        return {
            'certificate': self.certificate,
            'serial': self.serial,
            'valid_after': self.valid_after.isoformat(),
            'valid_before': self.valid_before.isoformat(),
        }


class SSHCASigningService:
    """Service for signing SSH certificates.
    
    This service handles all SSH certificate signing operations.
    It uses configuration from ssh_ca_config to apply rules and limits.
    """

    def __init__(self):
        """Initialize the SSH CA signing service."""
        self.config = get_ssh_ca_config()
        self.logger = logger

    def _load_ca_key_from_config(self) -> str:
        """Load CA private key from config (local file or env var).
        
        Returns:
            CA private key in PEM/OpenSSH format as string
            
        Raises:
            SSHCASigningError: If key cannot be loaded
        """
        # Check env var first
        key_content = os.environ.get('SSH_CA_PRIVATE_KEY')
        if key_content:
            return key_content

        # Load from file path
        key_path = self.config.get_str('ca_key_path', '').strip()
        if not key_path:
            raise SSHCASigningError(
                "CA private key not configured. Set SSH_CA_PRIVATE_KEY env var "
                "or ca_key_path in etc/ssh_ca.conf"
            )
        
        key_path = os.path.expandvars(os.path.expanduser(key_path))
        if not os.path.exists(key_path):
            raise SSHCASigningError(f"CA private key file not found: {key_path}")
        
        with open(key_path, 'r') as f:
            return f.read()

    def sign_certificate(
        self,
        signing_request: SSHCertificateSigningRequest,
        ca_private_key: Optional[str] = None,
    ) -> SSHCertificateSigningResponse:
        """Sign an SSH certificate.
        
        Args:
            signing_request: SSHCertificateSigningRequest instance
            ca_private_key: CA private key in PEM format. If not provided,
                          loaded from config (ca_key_path or SSH_CA_PRIVATE_KEY env var)
            
        Returns:
            SSHCertificateSigningResponse with signed certificate
            
        Raises:
            SSHCASigningError: If signing fails
            ValidationError: If request is invalid
        """
        # Validate request
        errors = signing_request.validate()
        if errors:
            error_msg = "; ".join(errors)
            self.logger.error(f"Certificate signing validation failed: {error_msg}")
            raise ValidationError(f"Certificate signing validation failed: {error_msg}")
        
        # Load CA key if not provided
        if ca_private_key is None:
            ca_private_key = self._load_ca_key_from_config()
        
        try:
            # Parse CA private key
            try:
                ca_key = PrivateKey.from_string(ca_private_key)
            except Exception as e:
                self.logger.error(f"Failed to load CA private key: {str(e)}")
                raise SSHCASigningError(f"Invalid CA private key: {str(e)}")
            
            # Parse user's public key
            try:
                user_pub_key = PublicKey.from_string(signing_request.ssh_public_key)
            except Exception as e:
                self.logger.error(f"Failed to parse user public key: {str(e)}")
                raise SSHCASigningError(f"Invalid user public key: {str(e)}")
            
            # Create certificate
            certificate = SSHCertificate.create(
                subject_pubkey=user_pub_key,
                ca_privkey=ca_key,
            )
            
            # Set validity period
            now = datetime.utcnow()
            expiry_hours = signing_request.expiry_hours or self.config.get_int('cert_validity_hours')
            valid_before = now + timedelta(hours=expiry_hours)
            
            # Set certificate fields
            cert_type = 1 if signing_request.cert_type == "user" else 0
            
            certificate.fields.cert_type = cert_type
            certificate.fields.key_id = signing_request.key_id
            certificate.fields.principals = signing_request.principals
            certificate.fields.valid_after = now
            certificate.fields.valid_before = valid_before
            
            # Set extensions
            extensions = signing_request.extensions
            if not extensions and self.config.get_bool('extensions_enabled'):
                extensions = self.config.get_list('extensions')
            
            certificate.fields.extensions = extensions or []
            certificate.fields.critical_options = signing_request.critical_options or {}
            
            # Validate certificate before signing
            if not certificate.can_sign():
                raise SSHCASigningError("Certificate cannot be signed")
            
            # Sign the certificate
            certificate.sign()
            
            # Verify the certificate
            try:
                certificate.verify(ca_key.public_key, raise_on_error=True)
            except Exception as e:
                self.logger.error(f"Certificate verification failed: {str(e)}")
                raise SSHCASigningError(f"Certificate verification failed: {str(e)}")
            
            # Extract serial from certificate
            serial = str(certificate.fields.serial).split(":")[-1].strip() if hasattr(certificate.fields.serial, '__str__') else str(certificate.fields.serial)
            
            # Build response
            cert_string = certificate.to_string()
            
            self.logger.info(
                f"Successfully signed certificate: serial={serial}, "
                f"key_id={signing_request.key_id}, principals={signing_request.principals}"
            )
            
            return SSHCertificateSigningResponse(
                certificate=cert_string,
                serial=serial,
                valid_after=now,
                valid_before=valid_before,
                principals=signing_request.principals,
            )
        
        except (SSHCASigningError, ValidationError):
            raise
        except Exception as e:
            self.logger.error(f"Unexpected error during certificate signing: {str(e)}", exc_info=True)
            raise SSHCASigningError(f"Error signing certificate: {str(e)}")

    def verify_ca_key(self, ca_private_key: str) -> Dict[str, Any]:
        """Verify a CA private key is valid and extract metadata.
        
        Args:
            ca_private_key: CA private key in PEM format
            
        Returns:
            Dictionary with key metadata (fingerprint, key_type, etc.)
            
        Raises:
            SSHCASigningError: If key is invalid
        """
        try:
            ca_key = PrivateKey.from_string(ca_private_key)
            pub_key = ca_key.public_key
            
            # Compute fingerprint
            fingerprint = compute_ssh_fingerprint(pub_key.to_string())
            
            # Get key type
            key_type = pub_key.keytype if hasattr(pub_key, 'keytype') else 'unknown'
            
            return {
                'fingerprint': fingerprint,
                'key_type': key_type,
                'public_key': pub_key.to_string(),
                'valid': True,
            }
        except Exception as e:
            self.logger.error(f"CA key verification failed: {str(e)}")
            raise SSHCASigningError(f"Invalid CA key: {str(e)}")
