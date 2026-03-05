"""OIDC JWKS Service for key management and rotation."""
import uuid
import json
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from flask import current_app

from gatehouse_app.extensions import db
from gatehouse_app.models.oidc.oidc_jwks_key import OidcJwksKey


class JWKSKey:
    """Represents a JWKS key entry."""
    
    def __init__(self, kid: str, private_key: str, public_key: str, 
                 algorithm: str = "RS256", created_at: datetime = None,
                 expires_at: datetime = None, is_active: bool = True):
        self.kid = kid
        self.private_key = private_key
        self.public_key = public_key
        self.algorithm = algorithm
        self.created_at = created_at or datetime.now(timezone.utc)
        self.expires_at = expires_at or datetime.now(timezone.utc) + timedelta(days=365)
        self.is_active = is_active
    
    def to_jwk(self) -> Dict:
        """Convert to JWK format for JWKS endpoint."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.backends import default_backend
        
        # Import cryptography here to avoid issues if not installed
        try:
            # Get public key from PEM
            public_key = serialization.load_pem_public_key(
                self.public_key.encode(), backend=default_backend()
            )
            
            # Get RSA parameters
            public_numbers = public_key.public_numbers()
            
            return {
                "kty": "RSA",
                "kid": self.kid,
                "use": "sig",
                "alg": self.algorithm,
                "n": _base64url_encode(public_numbers.n),
                "e": _base64url_encode(public_numbers.e),
            }
        except ImportError:
            # Fallback for when cryptography is not installed
            return {
                "kty": "RSA",
                "kid": self.kid,
                "use": "sig",
                "alg": self.algorithm,
            }
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for storage."""
        return {
            "kid": self.kid,
            "private_key": self.private_key,
            "public_key": self.public_key,
            "algorithm": self.algorithm,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "is_active": self.is_active,
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> "JWKSKey":
        """Create from dictionary."""
        return cls(
            kid=data["kid"],
            private_key=data["private_key"],
            public_key=data["public_key"],
            algorithm=data.get("algorithm", "RS256"),
            created_at=datetime.fromisoformat(data["created_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            is_active=data.get("is_active", True),
        )


def _base64url_encode(value: int) -> str:
    """Encode an integer to base64url format."""
    import base64
    byte_length = (value.bit_length() + 7) // 8 or 1
    encoded = value.to_bytes(byte_length, byteorder="big")
    return base64.urlsafe_b64encode(encoded).decode().rstrip("=")


class OIDCJWKSService:
    """Service for managing OIDC signing keys (JWKS).
    
    This service handles RSA key pair generation, rotation, and JWKS document
    generation for the OIDC implementation.
    """
    
    _instance = None
    _keys: Dict[str, JWKSKey] = {}
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._keys = {}
        return cls._instance
    
    @classmethod
    def reset(cls):
        """Reset the singleton (for testing)."""
        cls._instance = None
        cls._keys = {}
    
    def _generate_kid(self, private_key: str) -> str:
        """Generate a key ID from the private key fingerprint."""
        kid_hash = hashlib.sha256(private_key.encode()).hexdigest()[:32]
        return kid_hash
    
    def _generate_rsa_key_pair(self) -> Tuple[str, str]:
        """Generate a new RSA key pair in PEM format.
        
        Returns:
            Tuple of (private_key_pem, public_key_pem)
        """
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            
            # Generate RSA private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize to PEM
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            
            return private_pem, public_pem
        except ImportError:
            # Fallback for testing without cryptography
            import secrets
            return f"private_key_{secrets.token_hex(32)}", f"public_key_{secrets.token_hex(32)}"
    
    def get_jwks(self, include_private_keys: bool = False) -> Dict:
        """Get the JWKS document containing public keys.
        
        Args:
            include_private_keys: Whether to include private keys (for internal use only)
        
        Returns:
            JWKS document dictionary
        """
        now = datetime.now(timezone.utc)
        
        keys = []
        for kid, key in self._keys.items():
            # Only include active, non-expired keys
            if key.is_active and key.expires_at > now:
                if include_private_keys:
                    keys.append(key.to_dict())
                else:
                    keys.append(key.to_jwk())
        
        return {
            "keys": keys
        }
    
    def load_keys_from_db(self) -> int:
        """Load existing keys from the database.
        
        Returns:
            Number of keys loaded
        """
        if not self._table_exists():
            return 0
        try:
            db_keys = OidcJwksKey.get_active_keys()
            now = datetime.now(timezone.utc)
            
            for db_key in db_keys:
                # Create JWKSKey from database model
                key = JWKSKey(
                    kid=db_key.kid,
                    private_key=db_key.private_key,
                    public_key=db_key.public_key,
                    algorithm=db_key.algorithm,
                    created_at=db_key.created_at,
                    expires_at=db_key.expires_at or now + timedelta(days=365),
                    is_active=db_key.is_active,
                )
                self._keys[db_key.kid] = key
            
            return len(self._keys)
        except Exception as e:
            current_app.logger.error(f"Error loading keys from database: {e}")
            db.session.rollback()
            return 0
    
    def save_key_to_db(self, key: JWKSKey, is_primary: bool = False) -> OidcJwksKey:
        """Save a key to the database.
        
        Args:
            key: JWKSKey instance to save
            is_primary: Whether this is the primary signing key
            
        Returns:
            OidcJwksKey database model instance
        """
        db_key = OidcJwksKey(
            kid=key.kid,
            key_type="RSA",
            algorithm=key.algorithm,
            private_key=key.private_key,
            public_key=key.public_key,
            is_active=key.is_active,
            is_primary=is_primary,
        )
        
        db.session.add(db_key)
        db.session.commit()
        
        return db_key
    
    def get_signing_key(self) -> Optional[JWKSKey]:
        """Get the current active signing key.
        
        Returns:
            JWKSKey instance or None if no active key
        """
        now = datetime.now(timezone.utc)
        
        # First try to get the primary key from database
        try:
            primary_db_key = OidcJwksKey.get_primary_key()
            if primary_db_key:
                # Check if we have it in memory, if not load it
                if primary_db_key.kid not in self._keys:
                    key = JWKSKey(
                        kid=primary_db_key.kid,
                        private_key=primary_db_key.private_key,
                        public_key=primary_db_key.public_key,
                        algorithm=primary_db_key.algorithm,
                        created_at=primary_db_key.created_at,
                        expires_at=primary_db_key.expires_at or now + timedelta(days=365),
                        is_active=primary_db_key.is_active,
                    )
                    self._keys[primary_db_key.kid] = key
                return self._keys[primary_db_key.kid]
        except Exception as e:
            current_app.logger.error(f"Error getting primary key from database: {e}")
        
        # Fall back to in-memory keys
        for kid, key in self._keys.items():
            if key.is_active and key.expires_at > now:
                return key
        
        return None
    
    def get_key_by_kid(self, kid: str) -> Optional[JWKSKey]:
        """Get a specific key by its ID.
        
        Args:
            kid: Key ID to look up
        
        Returns:
            JWKSKey instance or None if not found
        """
        return self._keys.get(kid)
    
    def generate_new_key_pair(self, expires_in_days: int = 365) -> JWKSKey:
        """Generate a new RSA key pair for signing.
        
        Args:
            expires_in_days: Days until key expiration
        
        Returns:
            JWKSKey instance
        """
        private_key, public_key = self._generate_rsa_key_pair()
        kid = self._generate_kid(private_key)
        
        now = datetime.now(timezone.utc)
        key = JWKSKey(
            kid=kid,
            private_key=private_key,
            public_key=public_key,
            algorithm="RS256",
            created_at=now,
            expires_at=now + timedelta(days=expires_in_days),
            is_active=True,
        )
        
        self._keys[kid] = key
        
        # Deactivate old keys (but keep them for grace period)
        for old_kid in self._keys:
            if old_kid != kid:
                self._keys[old_kid].is_active = False
        
        return key
    
    def rotate_keys(self, grace_period_hours: int = 24) -> Tuple[JWKSKey, List[str]]:
        """Rotate signing keys, keeping previous key active for grace period.
        
        Args:
            grace_period_hours: Hours to keep old keys active
        
        Returns:
            Tuple of (new_key, list_of_deprecated_kids)
        """
        now = datetime.now(timezone.utc)
        grace_end = now + timedelta(hours=grace_period_hours)
        
        # Mark current key as deprecated
        current_key = self.get_signing_key()
        deprecated_kids = []
        
        if current_key:
            deprecated_kids.append(current_key.kid)
            # Keep key active but mark as deprecated
            current_key.is_active = False
            current_key.expires_at = grace_end
        
        # Generate new key
        new_key = self.generate_new_key_pair()
        
        # Clean up expired keys
        expired_kids = [
            kid for kid, key in self._keys.items()
            if key.expires_at < now
        ]
        for kid in expired_kids:
            del self._keys[kid]
        
        return new_key, deprecated_kids
    
    def verify_key_exists(self, kid: str) -> bool:
        """Check if a key with the given ID exists and is valid.
        
        Args:
            kid: Key ID to check
        
        Returns:
            True if key exists and is valid
        """
        key = self.get_key_by_kid(kid)
        if not key:
            return False
        
        now = datetime.now(timezone.utc)
        return key.is_active and key.expires_at > now
    
    def _table_exists(self) -> bool:
        """Check if the oidc_jwks_keys table exists in the database."""
        try:
            from sqlalchemy import inspect
            inspector = inspect(db.engine)
            return "oidc_jwks_keys" in inspector.get_table_names()
        except Exception:
            return False

    def initialize_with_key(self) -> JWKSKey:
        """Initialize the service with a key, loading from database if available.
        
        This method first attempts to load existing keys from the database.
        If no active primary key exists, it generates a new key and saves it to the database.
        
        Returns:
            JWKSKey instance
        """
        # Check if the table exists before attempting any DB operations
        table_exists = self._table_exists()

        if table_exists:
            # First, try to load keys from database
            try:
                # Check if there's a primary key in the database
                primary_db_key = OidcJwksKey.get_primary_key()
                if primary_db_key:
                    # Load the primary key into memory
                    now = datetime.now(timezone.utc)
                    key = JWKSKey(
                        kid=primary_db_key.kid,
                        private_key=primary_db_key.private_key,
                        public_key=primary_db_key.public_key,
                        algorithm=primary_db_key.algorithm,
                        created_at=primary_db_key.created_at,
                        expires_at=primary_db_key.expires_at or now + timedelta(days=365),
                        is_active=primary_db_key.is_active,
                    )
                    self._keys[primary_db_key.kid] = key
                    current_app.logger.info(f"[OIDC] Loaded existing signing key from database: kid={primary_db_key.kid}")
                    return key
                
                # Try to load all active keys from database
                loaded_count = self.load_keys_from_db()
                if loaded_count > 0:
                    # Get the signing key from loaded keys
                    signing_key = self.get_signing_key()
                    if signing_key:
                        current_app.logger.info(f"[OIDC] Loaded {loaded_count} keys from database, using signing key: kid={signing_key.kid}")
                        return signing_key
            except Exception as e:
                current_app.logger.error(f"Error loading keys from database: {e}")
                db.session.rollback()
        else:
            current_app.logger.info("[OIDC] Table oidc_jwks_keys does not exist yet, skipping DB load")
        
        # No keys in database, generate a new key and save it
        current_app.logger.info("[OIDC] No existing keys found in database, generating new signing key")
        new_key = self.generate_new_key_pair()
        
        # Save the new key to database (only if table exists)
        if table_exists:
            try:
                self.save_key_to_db(new_key, is_primary=True)
                current_app.logger.info(f"[OIDC] Saved new signing key to database: kid={new_key.kid}")
            except Exception as e:
                current_app.logger.error(f"Error saving key to database: {e}")
                db.session.rollback()
        
        return new_key
