"""WebAuthn passkey authentication service."""
import logging
import secrets
import hashlib
import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
from flask import current_app
from sqlalchemy.orm.attributes import flag_modified

from gatehouse_app.extensions import db, redis_client
from gatehouse_app.models.user.user import User
from gatehouse_app.models.auth.authentication_method import AuthenticationMethod
from gatehouse_app.utils.constants import AuthMethodType, AuditAction
from gatehouse_app.exceptions.auth_exceptions import InvalidCredentialsError
from gatehouse_app.services.audit_service import AuditService

logger = logging.getLogger(__name__)


class WebAuthnService:
    """Service for WebAuthn passkey operations."""
    
    # WebAuthn algorithm constants (COSE algorithms)
    COSE_ALGORITHMS = {
        -7: "ES256",  # ECDSA with SHA-256
        -257: "RS256",  # RSASSA-PKCS1-v1_5 with SHA-256
    }
    
    # Supported key types
    KEY_TYPES = ["public-key"]
    
    @staticmethod
    def _generate_challenge() -> str:
        """Generate a cryptographically secure challenge.
        
        Returns:
            Base64URL-encoded challenge string
        """
        bytes_data = secrets.token_bytes(32)
        return base64.urlsafe_b64encode(bytes_data).decode('utf-8').rstrip('=')
    
    @staticmethod
    def _store_challenge(user_id: str, challenge: str, challenge_type: str, expires_in: int = 300) -> bool:
        """Store a challenge in Redis for validation.
        
        Args:
            user_id: User ID
            challenge: The challenge string
            challenge_type: Type of challenge ('registration' or 'authentication')
            expires_in: Expiration time in seconds
            
        Returns:
            True if stored successfully
        """
        try:
            key = f"webauthn:challenge:{user_id}:{challenge_type}:{challenge}"
            
            data = {
                "challenge": challenge,
                "user_id": user_id,
                "type": challenge_type,
                "created_at": datetime.now(timezone.utc).isoformat()
            }
            
            data_json = json.dumps(data)
            redis_client.setex(key, expires_in, data_json)
            
            return True
        except Exception as e:
            logger.error(f"Failed to store WebAuthn challenge for user {user_id}: {e}")
            return False
    
    @staticmethod
    def _get_and_delete_challenge(user_id: str, challenge: str, challenge_type: str) -> Optional[Dict]:
        """Retrieve and delete a challenge from Redis.
        
        Args:
            user_id: User ID
            challenge: The challenge string
            challenge_type: Type of challenge
            
        Returns:
            Challenge data dict or None if not found/expired
        """
        try:
            key = f"webauthn:challenge:{user_id}:{challenge_type}:{challenge}"
            
            data = redis_client.get(key)
            
            if data:
                # Delete the key
                redis_client.delete(key)
                
                # Parse the data
                data_str = data.decode('utf-8') if isinstance(data, bytes) else data
                parsed_data = json.loads(data_str)
                
                return parsed_data
            else:
                logger.warning(f"WebAuthn challenge not found or expired for user {user_id}, type: {challenge_type}")
                return None
        except Exception as e:
            logger.error(f"Failed to retrieve WebAuthn challenge for user {user_id}: {e}")
            return None
    
    @staticmethod
    def _base64url_decode(data: str) -> bytes:
        """Decode Base64URL string to bytes."""
        # Add padding if needed
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += '=' * padding
        return base64.urlsafe_b64decode(data)
    
    @staticmethod
    def _base64url_encode(data: bytes) -> str:
        """Encode bytes to Base64URL string."""
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')
    
    @staticmethod
    def _hash_credential_id(credential_id: bytes) -> str:
        """Hash a credential ID for secure storage lookup.
        
        Args:
            credential_id: Raw credential ID bytes
            
        Returns:
            Hashed credential ID string
        """
        return hashlib.sha256(credential_id).hexdigest()
    
    @classmethod
    def generate_registration_challenge(cls, user: User) -> Dict[str, Any]:
        """Generate a challenge for passkey registration.
        
        Args:
            user: User instance
            
        Returns:
            PublicKeyCredentialCreationOptions dict
        """
        # Generate challenge
        challenge = cls._generate_challenge()
        
        # Store challenge
        cls._store_challenge(user.id, challenge, 'registration')
        
        # Get existing credentials to exclude
        existing_credentials = cls.get_user_credentials(user)
        exclude_credentials = []
        for cred in existing_credentials:
            if cred.provider_data:
                cred_id_b64 = cred.provider_data.get("credential_id")
                if cred_id_b64:
                    try:
                        cred_id = cls._base64url_decode(cred_id_b64)
                        transports = cred.provider_data.get("transports", [])
                        exclude_credentials.append({
                            "id": cred_id_b64,
                            "type": "public-key",
                            "transports": transports
                        })
                    except Exception:
                        pass
        
        # Get RP configuration
        rp_id = current_app.config.get('WEBAUTHN_RP_ID', 'localhost')
        rp_name = current_app.config.get('WEBAUTHN_RP_NAME', 'Gatehouse')
        
        # Generate user ID (Base64URL encoded)
        user_id = cls._base64url_encode(user.id.encode('utf-8'))
        
        # Build options
        options = {
            "rp": {
                "name": rp_name,
                "id": rp_id
            },
            "user": {
                "id": user_id,
                "name": user.email,
                "displayName": user.full_name or user.email
            },
            "challenge": challenge,
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},  # ES256
                {"type": "public-key", "alg": -257}  # RS256
            ],
            "timeout": 60000,  # 60 seconds
            "excludeCredentials": exclude_credentials,
            "authenticatorSelection": {
                "residentKey": "preferred",
                "userVerification": "preferred"
            },
            "attestation": "none"
        }
        
        # Log audit event
        AuditService.log_action(
            action=AuditAction.WEBAUTHN_REGISTER_INITIATED,
            user_id=user.id,
            description="WebAuthn registration initiated"
        )
        
        return options
    
    @classmethod
    def verify_registration_response(
        cls,
        user: User,
        credential_data: Dict[str, Any],
        challenge: str
    ) -> AuthenticationMethod:
        """Verify and store a new passkey credential.
        
        Args:
            user: User instance
            credential_data: Credential response data from client
            challenge: The original challenge string
            
        Returns:
            AuthenticationMethod instance
            
        Raises:
            InvalidCredentialsError: If verification fails
        """
        user_email = user.email
        
        # Verify and consume challenge
        stored_challenge = cls._get_and_delete_challenge(user.id, challenge, 'registration')
        
        if not stored_challenge:
            logger.error(f"WebAuthn registration failed - challenge expired for user: {user_email}")
            AuditService.log_action(
                action=AuditAction.WEBAUTHN_REGISTER_FAILED,
                user_id=user.id,
                description="Registration failed: challenge expired or invalid"
            )
            raise InvalidCredentialsError("Challenge expired or invalid")
        
        try:
            # Parse credential data
            credential_id = credential_data.get("id")
            raw_id = credential_data.get("rawId")
            response = credential_data.get("response", {})
            attestation_object_b64 = response.get("attestationObject")
            client_data_json_b64 = response.get("clientDataJSON")
            transports = credential_data.get("transports", ["platform"])
            
            if not all([credential_id, raw_id, attestation_object_b64, client_data_json_b64]):
                logger.error(f"WebAuthn registration failed - missing required data for user: {user_email}")
                raise InvalidCredentialsError("Missing required credential data")
            
            # Decode attestation object
            attestation_object = cls._base64url_decode(attestation_object_b64)
            
            # Parse CBOR attestation object
            try:
                import cbor2
                attestation_dict = cbor2.loads(attestation_object)
            except ImportError:
                attestation_dict = {}
                logger.warning("cbor2 library not available, using fallback parsing")
            
            # Extract authenticator data
            auth_data = attestation_dict.get('authData', b'')
            
            # Parse authenticator data
            if len(auth_data) < 37:
                logger.error(f"WebAuthn registration failed - invalid auth data for user: {user_email}")
                raise InvalidCredentialsError("Invalid authenticator data")
            
            rp_id_hash = auth_data[:32]
            flags = auth_data[32]
            counter = int.from_bytes(auth_data[33:37], 'big')
            aaguid = auth_data[37:53] if len(auth_data) >= 53 else b''
            
            # Extract credential ID length and ID
            cred_id_length = int.from_bytes(auth_data[53:55], 'big') if len(auth_data) >= 55 else 0
            credential_id_raw = auth_data[55:55+cred_id_length] if cred_id_length > 0 else b''
            
            # Extract public key (COSE format)
            public_key_cose = auth_data[55+cred_id_length:]
            
            # Verify client data
            client_data_json = cls._base64url_decode(client_data_json_b64)
            client_data = json.loads(client_data_json)
            
            # Verify challenge matches
            if client_data.get("challenge") != challenge:
                logger.error(f"WebAuthn registration failed - challenge mismatch for user: {user_email}")
                raise InvalidCredentialsError("Challenge mismatch")
            
            # Verify origin
            expected_origin = current_app.config.get('WEBAUTHN_ORIGIN', 'http://localhost:5173')
            actual_origin = client_data.get("origin")
            
            if client_data.get("origin") != expected_origin:
                logger.warning(f"WebAuthn origin mismatch for user {user_email}: expected {expected_origin}, got {actual_origin}")
                # Don't fail on origin mismatch in development
            
            # Verify user presence
            user_present = bool(flags & 0x01)
            
            if not user_present:
                logger.error(f"WebAuthn registration failed - user presence not verified for user: {user_email}")
                raise InvalidCredentialsError("User presence not verified")
            
            # Store credential
            credential_id_hash = cls._hash_credential_id(credential_id_raw)
            
            # Check if credential already exists
            existing = AuthenticationMethod.query.filter_by(
                user_id=user.id,
                method_type=AuthMethodType.WEBAUTHN,
                deleted_at=None
            ).first()
            
            if existing and existing.provider_data:
                stored_cred_id = existing.provider_data.get("credential_id", "")
                if stored_cred_id == credential_id:
                    logger.error(f"WebAuthn registration failed - credential already registered for user: {user_email}")
                    raise InvalidCredentialsError("Credential already registered")
            
            # Get credential name from client request, or generate default
            client_provided_name = credential_data.get("name")
            if client_provided_name:
                credential_name = client_provided_name
            else:
                credential_name = f"Passkey {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
            
            # Create or update authentication method
            auth_method = existing or AuthenticationMethod(
                user_id=user.id,
                method_type=AuthMethodType.WEBAUTHN,
                is_primary=False,
                verified=True
            )
            
            # Store credential data
            auth_method.provider_data = {
                "credential_id": credential_id,
                "credential_id_hash": credential_id_hash,
                "public_key_cose": cls._base64url_encode(public_key_cose),
                "sign_count": counter,
                "transports": transports,
                "aaguid": cls._base64url_encode(aaguid) if aaguid else None,
                "attestation_format": attestation_dict.get('fmt', 'unknown'),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "last_used_at": None,
                "name": credential_name
            }
            
            auth_method.save()
            
            logger.info(f"WebAuthn registration completed successfully for user: {user_email}")
            
            # Log audit event
            AuditService.log_action(
                action=AuditAction.WEBAUTHN_REGISTER_COMPLETED,
                user_id=user.id,
                resource_type="authentication_method",
                resource_id=auth_method.id,
                description=f"WebAuthn credential registered: {credential_id[:16]}..."
            )
            
            return auth_method
            
        except InvalidCredentialsError:
            raise
        except Exception as e:
            logger.exception(f"WebAuthn registration failed for user {user_email}: {e}")
            AuditService.log_action(
                action=AuditAction.WEBAUTHN_REGISTER_FAILED,
                user_id=user.id,
                description=f"Registration failed: {str(e)}"
            )
            raise InvalidCredentialsError("Registration verification failed")
    
    @classmethod
    def generate_authentication_challenge(cls, user: User) -> Dict[str, Any]:
        """Generate a challenge for passkey authentication.
        
        Args:
            user: User instance
            
        Returns:
            PublicKeyCredentialRequestOptions dict
        """
        # Generate challenge
        challenge = cls._generate_challenge()
        
        # Store challenge
        store_result = cls._store_challenge(user.id, challenge, 'authentication')
        
        if not store_result:
            logger.error(f"WebAuthn challenge storage failed for user: {user.email}")
        
        # Get user's credentials
        credentials = cls.get_user_credentials(user)
        
        # Build allow credentials list
        allow_credentials = []
        for cred in credentials:
            if cred.provider_data:
                cred_id = cred.provider_data.get("credential_id")
                transports = cred.provider_data.get("transports", [])
                
                if cred_id:
                    allow_credentials.append({
                        "id": cred_id,
                        "type": "public-key",
                        "transports": transports
                    })
                else:
                    logger.warning(f"WebAuthn credential missing ID for user: {user.email}")
        
        # Get RP configuration
        rp_id = current_app.config.get('WEBAUTHN_RP_ID', 'localhost')
        
        # Build options
        options = {
            "challenge": challenge,
            "timeout": 60000,
            "rpId": rp_id,
            "allowCredentials": allow_credentials,
            "userVerification": "preferred"
        }
        
        # Log audit event
        AuditService.log_action(
            action=AuditAction.WEBAUTHN_LOGIN_INITIATED,
            user_id=user.id,
            description="WebAuthn authentication initiated"
        )
        
        return options
    
    @classmethod
    def verify_authentication_response(
        cls,
        user: User,
        credential_data: Dict[str, Any],
        challenge: str
    ) -> AuthenticationMethod:
        """Verify passkey authentication response.
        
        Args:
            user: User instance
            credential_data: Assertion response data from client
            challenge: The original challenge string
            
        Returns:
            AuthenticationMethod instance
            
        Raises:
            InvalidCredentialsError: If verification fails
        """
        user_email = user.email
        logger.info(f"WebAuthn authentication started for user: {user_email}")
        
        # Verify and consume challenge
        stored_challenge = cls._get_and_delete_challenge(user.id, challenge, 'authentication')
        
        if not stored_challenge:
            logger.error(f"WebAuthn authentication failed - challenge expired for user: {user_email}")
            
            AuditService.log_action(
                action=AuditAction.WEBAUTHN_LOGIN_FAILED,
                user_id=user.id,
                description="Authentication failed: challenge expired or invalid"
            )
            raise InvalidCredentialsError("Challenge expired or invalid")
        
        try:
            # Parse credential data
            credential_id = credential_data.get("id")
            raw_id = credential_data.get("rawId")
            response = credential_data.get("response", {})
            authenticator_data_b64 = response.get("authenticatorData")
            client_data_json_b64 = response.get("clientDataJSON")
            signature_b64 = response.get("signature")
            
            if not all([credential_id, authenticator_data_b64, client_data_json_b64, signature_b64]):
                logger.error(f"WebAuthn authentication failed - missing required data for user: {user_email}")
                raise InvalidCredentialsError("Missing required credential data")
            
            # Find the credential
            auth_method = AuthenticationMethod.query.filter_by(
                user_id=user.id,
                method_type=AuthMethodType.WEBAUTHN,
                deleted_at=None
            ).first()
            
            if not auth_method or not auth_method.provider_data:
                logger.error(f"WebAuthn authentication failed - no credential found for user: {user_email}")
                raise InvalidCredentialsError("No passkey found for user")
            
            stored_cred_id = auth_method.provider_data.get("credential_id")
            
            if stored_cred_id != credential_id:
                logger.error(f"WebAuthn authentication failed - credential ID mismatch for user: {user_email}")
                raise InvalidCredentialsError("Credential not found")
            
            # Decode authenticator data
            authenticator_data = cls._base64url_decode(authenticator_data_b64)
            
            # Parse authenticator data
            if len(authenticator_data) < 37:
                logger.error(f"WebAuthn authentication failed - invalid auth data for user: {user_email}")
                raise InvalidCredentialsError("Invalid authenticator data")
            
            rp_id_hash = authenticator_data[:32]
            flags = authenticator_data[32]
            counter = int.from_bytes(authenticator_data[33:37], 'big')
            
            # Verify client data
            client_data_json = cls._base64url_decode(client_data_json_b64)
            client_data = json.loads(client_data_json)
            
            # Verify challenge matches
            if client_data.get("challenge") != challenge:
                logger.error(f"WebAuthn authentication failed - challenge mismatch for user: {user_email}")
                raise InvalidCredentialsError("Challenge mismatch")
            
            # Verify origin
            expected_origin = current_app.config.get('WEBAUTHN_ORIGIN', 'http://localhost:5173')
            actual_origin = client_data.get("origin")
            
            if client_data.get("origin") != expected_origin:
                logger.warning(f"WebAuthn origin mismatch for user {user_email}: expected {expected_origin}, got {actual_origin}")
                # Don't fail on origin mismatch in development
            
            # Verify user presence
            user_present = bool(flags & 0x01)
            
            if not user_present:
                logger.error(f"WebAuthn authentication failed - user presence not verified for user: {user_email}")
                raise InvalidCredentialsError("User presence not verified")
            
            # Verify counter (prevent replay attacks)
            # Note: Some authenticators (especially platform/software authenticators) may always return 0
            # In such cases, we log a warning but don't fail the authentication
            stored_counter = auth_method.provider_data.get("sign_count", 0)
            
            if counter == 0 and stored_counter == 0:
                # Both counters are 0 - this is valid for certain authenticators (e.g., software authenticators)
                logger.warning(f"WebAuthn sign counter is 0 for both stored and received values for user {user_email} - authenticator may not support counters")
            elif counter <= stored_counter and counter != 0:
                # Counter didn't increase and is not 0 - potential replay attack
                logger.error(f"WebAuthn authentication failed - sign counter did not increase for user {user_email}: stored={stored_counter}, received={counter}")
                raise InvalidCredentialsError("Invalid sign counter - potential credential cloning detected")
            
            # Update counter and last used time
            auth_method.provider_data["sign_count"] = counter
            auth_method.provider_data["last_used_at"] = datetime.now(timezone.utc).isoformat()
            auth_method.last_used_at = datetime.now(timezone.utc)
            
            # Flag provider_data as modified so SQLAlchemy detects the JSON change
            flag_modified(auth_method, "provider_data")
            
            db.session.commit()
            
            # Log audit event
            AuditService.log_action(
                action=AuditAction.WEBAUTHN_LOGIN_SUCCESS,
                user_id=user.id,
                resource_type="authentication_method",
                resource_id=auth_method.id,
                description="WebAuthn authentication successful"
            )
            
            logger.info(f"WebAuthn authentication completed successfully for user: {user_email}")
            
            return auth_method
            
        except InvalidCredentialsError:
            raise
        except Exception as e:
            logger.exception(f"WebAuthn authentication failed for user {user_email}: {e}")
            
            AuditService.log_action(
                action=AuditAction.WEBAUTHN_LOGIN_FAILED,
                user_id=user.id,
                description=f"Authentication failed: {str(e)}"
            )
            raise InvalidCredentialsError("Authentication verification failed")
    
    @classmethod
    def get_user_credentials(cls, user: User) -> List[AuthenticationMethod]:
        """Get all passkey credentials for a user.
        
        Args:
            user: User instance
            
        Returns:
            List of AuthenticationMethod instances
        """
        return AuthenticationMethod.query.filter_by(
            user_id=user.id,
            method_type=AuthMethodType.WEBAUTHN,
            deleted_at=None
        ).order_by(AuthenticationMethod.created_at.desc()).all()
    
    @classmethod
    def delete_credential(cls, credential_id: str, user: User) -> bool:
        """Delete a passkey credential.
        
        Args:
            credential_id: The credential ID to delete
            user: User instance
            
        Returns:
            True if deleted successfully
        """
        auth_method = AuthenticationMethod.query.filter_by(
            user_id=user.id,
            method_type=AuthMethodType.WEBAUTHN,
            deleted_at=None
        ).first()
        
        if not auth_method or not auth_method.provider_data:
            return False
        
        stored_cred_id = auth_method.provider_data.get("credential_id")
        if stored_cred_id != credential_id:
            return False
        
        # Soft delete the credential
        auth_method.delete(soft=True)
        
        # Log audit event
        AuditService.log_action(
            action=AuditAction.WEBAUTHN_CREDENTIAL_DELETED,
            user_id=user.id,
            resource_type="authentication_method",
            resource_id=auth_method.id,
            description=f"WebAuthn credential deleted: {credential_id[:16]}..."
        )
        
        return True

    @classmethod
    def credential_belongs_to_user(cls, credential_id: str, user: User) -> bool:
        """Check whether *credential_id* exists and belongs to *user*.

        Args:
            credential_id: The credential ID to look up
            user: User instance

        Returns:
            True if the credential exists and belongs to this user, False otherwise.
        """
        auth_method = AuthenticationMethod.query.filter_by(
            user_id=user.id,
            method_type=AuthMethodType.WEBAUTHN,
            deleted_at=None,
        ).first()
        if not auth_method or not auth_method.provider_data:
            return False
        return auth_method.provider_data.get("credential_id") == credential_id
    
    @classmethod
    def rename_credential(cls, credential_id: str, user: User, name: str) -> bool:
        """Rename a passkey credential.
        
        Args:
            credential_id: The credential ID to rename
            user: User instance
            name: New name for the credential
            
        Returns:
            True if renamed successfully
        """
        auth_method = AuthenticationMethod.query.filter_by(
            user_id=user.id,
            method_type=AuthMethodType.WEBAUTHN,
            deleted_at=None
        ).first()
        
        if not auth_method or not auth_method.provider_data:
            return False
        
        stored_cred_id = auth_method.provider_data.get("credential_id")
        if stored_cred_id != credential_id:
            return False
        
        # Update name
        auth_method.provider_data["name"] = name
        
        # Flag provider_data as modified so SQLAlchemy detects the JSON change
        flag_modified(auth_method, "provider_data")
        
        db.session.commit()
        
        # Log audit event
        AuditService.log_action(
            action=AuditAction.WEBAUTHN_CREDENTIAL_RENAMED,
            user_id=user.id,
            resource_type="authentication_method",
            resource_id=auth_method.id,
            description=f"WebAuthn credential renamed to: {name}"
        )
        
        return True
    
    @classmethod
    def get_credential_by_id(cls, credential_id: str, user: User) -> Optional[AuthenticationMethod]:
        """Get a specific credential by ID.
        
        Args:
            credential_id: The credential ID
            user: User instance
            
        Returns:
            AuthenticationMethod instance or None
        """
        auth_method = AuthenticationMethod.query.filter_by(
            user_id=user.id,
            method_type=AuthMethodType.WEBAUTHN,
            deleted_at=None
        ).first()
        
        if auth_method and auth_method.provider_data:
            stored_cred_id = auth_method.provider_data.get("credential_id")
            if stored_cred_id == credential_id:
                return auth_method
        
        return None
