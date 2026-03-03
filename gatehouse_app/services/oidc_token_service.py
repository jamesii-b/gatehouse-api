"""OIDC Token Service for JWT token generation and validation."""
import hashlib
import base64
import secrets
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Any

import jwt
from flask import current_app, g

from gatehouse_app.models import User, OIDCClient
from gatehouse_app.models.organization.organization_member import OrganizationMember
from gatehouse_app.services.oidc_jwks_service import OIDCJWKSService

logger = logging.getLogger(__name__)


class OIDCTokenService:
    """Service for generating and validating OIDC tokens.
    
    This service handles:
    - Access token creation (JWT)
    - ID token creation (JWT)
    - Refresh token creation (opaque)
    - Token signature verification
    - Hash generation for PKCE claims (at_hash, c_hash)
    """
    
    @staticmethod
    def _generate_jti() -> str:
        """Generate a unique JWT ID."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def _generate_opaque_token(length: int = 43) -> str:
        """Generate an opaque token (for refresh tokens).
        
        Args:
            length: Length of the token
        
        Returns:
            URL-safe base64 encoded token
        """
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def _hash_token(token: str) -> str:
        """Hash a token for secure storage.
        
        Args:
            token: Token to hash
        
        Returns:
            SHA256 hash of the token
        """
        return hashlib.sha256(token.encode()).hexdigest()
    
    @staticmethod
    def _base64url_encode(data: bytes) -> str:
        """Encode bytes to base64url format without padding.
        
        Args:
            data: Bytes to encode
        
        Returns:
            Base64url encoded string
        """
        return base64.urlsafe_b64encode(data).decode().rstrip("=")
    
    @staticmethod
    def create_at_hash(access_token: str) -> str:
        """Create the at_hash claim for ID token.
        
        Implements OIDC spec for access token hash generation.
        Hash is the left-most half of the hash of the ASCII representation
        of the access token.
        
        Args:
            access_token: The access token string
        
        Returns:
            Base64url encoded hash
        """
        # Hash the access token using SHA256
        hash_digest = hashlib.sha256(access_token.encode()).digest()
        
        # Take left-most half of the hash
        half_length = len(hash_digest) // 2
        left_half = hash_digest[:half_length]
        
        # Base64url encode
        return OIDCTokenService._base64url_encode(left_half)
    
    @staticmethod
    def create_c_hash(code: str) -> str:
        """Create the c_hash claim for ID token.
        
        Implements OIDC spec for authorization code hash generation.
        
        Args:
            code: The authorization code string
        
        Returns:
            Base64url encoded hash
        """
        # Hash the code using SHA256
        hash_digest = hashlib.sha256(code.encode()).digest()
        
        # Take left-most half of the hash
        half_length = len(hash_digest) // 2
        left_half = hash_digest[:half_length]
        
        # Base64url encode
        return OIDCTokenService._base64url_encode(left_half)
    
    @staticmethod
    def _get_issuer() -> str:
        """Get the OIDC issuer URL."""
        return current_app.config.get("OIDC_ISSUER_URL", "http://localhost:5000")
    
    @staticmethod
    def _get_token_lifetime(client: OIDCClient, token_type: str) -> int:
        """Get the token lifetime in seconds for a client.
        
        Args:
            client: OIDCClient instance
            token_type: Type of token ("access_token", "refresh_token", "id_token")
        
        Returns:
            Lifetime in seconds
        """
        lifetimes = {
            "access_token": client.access_token_lifetime or 3600,
            "refresh_token": client.refresh_token_lifetime or 2592000,
            "id_token": client.id_token_lifetime or 3600,
        }
        return lifetimes.get(token_type, 3600)
    
    @classmethod
    def create_access_token(cls, client_id: str, user_id: str, scope: list,
                           jti: str = None) -> str:
        """Create a JWT access token.
        
        Args:
            client_id: The OIDC client ID
            user_id: The user ID (subject)
            scope: List of granted scopes
            jti: Optional JWT ID (generated if not provided)
        
        Returns:
            JWT access token string
        """
        logger.debug("[OIDC TOKEN SERVICE] ===========================================")
        logger.debug("[OIDC TOKEN SERVICE] create_access_token called")
        logger.debug("[OIDC TOKEN SERVICE] Current UTC time: %s", datetime.now(timezone.utc).isoformat())
        logger.debug("[OIDC TOKEN SERVICE] client_id=%s, user_id=%s", client_id, user_id)
        logger.debug("[OIDC TOKEN SERVICE] scope=%s", scope)
        
        jti = jti or cls._generate_jti()
        now_timestamp = int(time.time())
        now = datetime.now(timezone.utc)
        logger.debug("[OIDC TOKEN SERVICE] Token creation time (UTC): %s", now.isoformat())
        logger.debug("[OIDC TOKEN SERVICE] Token creation timestamp: %s", now_timestamp)
        
        # Get client for token lifetime
        client = OIDCClient.query.filter_by(client_id=client_id).first()
        lifetime = cls._get_token_lifetime(client, "access_token") if client else 3600
        logger.debug("[OIDC TOKEN SERVICE] Access token lifetime (seconds): %s", lifetime)
        
        exp_timestamp = now_timestamp + lifetime
        exp_time = now + timedelta(seconds=lifetime)
        logger.debug("[OIDC TOKEN SERVICE] Access token expiration time (UTC): %s", exp_time.isoformat())
        logger.debug("[OIDC TOKEN SERVICE] Access token expiration timestamp: %s", exp_timestamp)
        logger.debug("[OIDC TOKEN SERVICE] Time until expiration (seconds): %s", lifetime)
        
        claims = {
            "iss": cls._get_issuer(),
            "sub": user_id,
            "aud": client_id,
            "exp": exp_timestamp,
            "iat": now_timestamp,
            "nbf": now_timestamp,
            "jti": jti,
            "client_id": client_id,
            "scope": " ".join(scope) if isinstance(scope, list) else scope,
        }
        
        logger.debug("[OIDC TOKEN SERVICE] Token claims: exp=%s, iat=%s, nbf=%s",
                    claims["exp"], claims["iat"], claims["nbf"])
        
        # Get signing key
        jwks_service = OIDCJWKSService()
        signing_key = jwks_service.get_signing_key()
        
        if not signing_key:
            raise ValueError("No signing key available")
        
        # Sign with RS256
        logger.debug("[OIDC TOKEN SERVICE] Signing token with RS256...")
        token = jwt.encode(
            claims,
            signing_key.private_key,
            algorithm="RS256",
            headers={"kid": signing_key.kid}
        )
        
        logger.debug("[OIDC TOKEN SERVICE] Access token created successfully")
        logger.debug("[OIDC TOKEN SERVICE] Final UTC time: %s", datetime.now(timezone.utc).isoformat())
        logger.debug("[OIDC TOKEN SERVICE] ===========================================")
        return token
    
    @classmethod
    def create_id_token(cls, client_id: str, user_id: str, nonce: str = None,
                       scope: list = None, access_token: str = None,
                       auth_time: int = None) -> str:
        """Create a JWT ID token.
        
        Args:
            client_id: The OIDC client ID
            user_id: The user ID (subject)
            nonce: Nonce for replay protection
            scope: Requested/Granted scopes
            access_token: Associated access token (for at_hash)
            auth_time: Authentication time (Unix timestamp)
        
        Returns:
            JWT ID token string
        """
        logger.debug("[OIDC TOKEN SERVICE] ===========================================")
        logger.debug("[OIDC TOKEN SERVICE] create_id_token called")
        logger.debug("[OIDC TOKEN SERVICE] Current UTC time: %s", datetime.now(timezone.utc).isoformat())
        logger.debug("[OIDC TOKEN SERVICE] client_id=%s, user_id=%s", client_id, user_id)
        logger.debug("[OIDC TOKEN SERVICE] nonce=%s, auth_time=%s", nonce, auth_time)
        logger.debug("[OIDC TOKEN SERVICE] scope=%s", scope)
        
        now_timestamp = int(time.time())
        now = datetime.now(timezone.utc)
        logger.debug("[OIDC TOKEN SERVICE] Token creation time (UTC): %s", now.isoformat())
        logger.debug("[OIDC TOKEN SERVICE] Token creation timestamp: %s", now_timestamp)
        auth_time = auth_time or now_timestamp
        logger.debug("[OIDC TOKEN SERVICE] auth_time (Unix timestamp): %s", auth_time)
        
        # Get client for token lifetime
        client = OIDCClient.query.filter_by(client_id=client_id).first()
        lifetime = cls._get_token_lifetime(client, "id_token") if client else 3600
        logger.debug("[OIDC TOKEN SERVICE] ID token lifetime (seconds): %s", lifetime)
        
        exp_timestamp = now_timestamp + lifetime
        exp_time = now + timedelta(seconds=lifetime)
        logger.debug("[OIDC TOKEN SERVICE] ID token expiration time (UTC): %s", exp_time.isoformat())
        logger.debug("[OIDC TOKEN SERVICE] ID token expiration timestamp: %s", exp_timestamp)
        logger.debug("[OIDC TOKEN SERVICE] Time until expiration (seconds): %s", lifetime)
        
        # Get user for claims
        user = User.query.get(user_id)
        
        claims = {
            "iss": cls._get_issuer(),
            "sub": user_id,
            "aud": client_id,
            "exp": exp_timestamp,
            "iat": now_timestamp,
            "auth_time": auth_time,
        }
        
        logger.debug("[OIDC TOKEN SERVICE] Token claims: exp=%s, iat=%s, auth_time=%s",
                    claims["exp"], claims["iat"], claims["auth_time"])
        
        # Add nonce if provided
        if nonce:
            claims["nonce"] = nonce
        
        # Add at_hash if access token provided
        if access_token:
            claims["at_hash"] = cls.create_at_hash(access_token)
        
        # Add standard claims if user exists
        if user:
            if user.email:
                claims["email"] = user.email
            claims["email_verified"] = user.email_verified
            if user.full_name:
                claims["name"] = user.full_name
        
        # Add roles claim if scope is granted
        if scope and "roles" in scope:
            claims["roles"] = cls._get_user_roles(user)
        
        # Add scope if provided
        if scope:
            claims["scope"] = " ".join(scope) if isinstance(scope, list) else scope
        
        # Get signing key
        jwks_service = OIDCJWKSService()
        signing_key = jwks_service.get_signing_key()
        
        if not signing_key:
            raise ValueError("No signing key available")
        
        # Sign with RS256
        logger.debug("[OIDC TOKEN SERVICE] Signing token with RS256...")
        token = jwt.encode(
            claims,
            signing_key.private_key,
            algorithm="RS256",
            headers={"kid": signing_key.kid}
        )
        
        logger.debug("[OIDC TOKEN SERVICE] ID token created successfully")
        logger.debug("[OIDC TOKEN SERVICE] Final UTC time: %s", datetime.now(timezone.utc).isoformat())
        logger.debug("[OIDC TOKEN SERVICE] ===========================================")
        return token
    
    @staticmethod
    def _get_user_roles(user: User) -> list:
        """Get user's organization roles.
        
        Args:
            user: User instance
        
        Returns:
            List of role objects with organization_id and role
        """
        roles = []
        if user and user.organization_memberships:
            for member in user.organization_memberships:
                roles.append({
                    "organization_id": str(member.organization_id),
                    "role": member.role.value
                })
        return roles
    
    @classmethod
    def create_refresh_token(cls, client_id: str, user_id: str,
                            scope: list = None, access_token_id: str = None) -> str:
        """Create an opaque refresh token.
        
        Args:
            client_id: The OIDC client ID
            user_id: The user ID
            scope: List of granted scopes
            access_token_id: Associated access token ID
        
        Returns:
            Opaque refresh token string
        """
        logger.debug("[OIDC TOKEN SERVICE] ===========================================")
        logger.debug("[OIDC TOKEN SERVICE] create_refresh_token called")
        logger.debug("[OIDC TOKEN SERVICE] Current UTC time: %s", datetime.now(timezone.utc).isoformat())
        logger.debug("[OIDC TOKEN SERVICE] client_id=%s, user_id=%s", client_id, user_id)
        logger.debug("[OIDC TOKEN SERVICE] scope=%s, access_token_id=%s", scope, access_token_id)
        
        token = cls._generate_opaque_token()
        logger.debug("[OIDC TOKEN SERVICE] Refresh token generated: %s...", token[:20] if token else None)
        
        # Hash for storage
        token_hash = cls._hash_token(token)
        
        logger.debug("[OIDC TOKEN SERVICE] Refresh token created successfully")
        logger.debug("[OIDC TOKEN SERVICE] Final UTC time: %s", datetime.now(timezone.utc).isoformat())
        logger.debug("[OIDC TOKEN SERVICE] ===========================================")
        return token, token_hash
    
    @classmethod
    def verify_token_signature(cls, token: str) -> Dict:
        """Verify the signature of a JWT token.
        
        Args:
            token: JWT token string
        
        Returns:
            Decoded token claims
        
        Raises:
            jwt.InvalidSignatureError: If signature verification fails
            jwt.ExpiredSignatureError: If token is expired
            jwt.InvalidTokenError: If token is invalid
        """
        logger.debug("[OIDC TOKEN SERVICE] ===========================================")
        logger.debug("[OIDC TOKEN SERVICE] verify_token_signature() called")
        logger.debug("[OIDC TOKEN SERVICE] Token (first 50 chars): %s...", token[:50] if len(token) > 50 else token)
        logger.debug("[OIDC TOKEN SERVICE] Token length: %d", len(token))
        
        # Get the JWKS with public keys
        logger.debug("[OIDC TOKEN SERVICE] Getting JWKS...")
        jwks_service = OIDCJWKSService()
        jwks = jwks_service.get_jwks(include_private_keys=True)
        logger.debug("[OIDC TOKEN SERVICE] JWKS retrieved: %d keys", len(jwks.get("keys", [])))
        
        # Get the key ID from token header
        try:
            logger.debug("[OIDC TOKEN SERVICE] Getting unverified token header...")
            unverified_header = jwt.get_unverified_header(token)
            logger.debug("[OIDC TOKEN SERVICE] Unverified header: %s", unverified_header)
        except jwt.DecodeError as e:
            logger.error("[OIDC TOKEN SERVICE] Failed to decode token header: %s", str(e))
            raise jwt.InvalidTokenError("Invalid token header")
        
        kid = unverified_header.get("kid")
        logger.debug("[OIDC TOKEN SERVICE] Key ID (kid) from token header: %s", kid)
        
        # Find the matching public key
        logger.debug("[OIDC TOKEN SERVICE] Searching for matching public key...")
        public_key = None
        for idx, key in enumerate(jwks.get("keys", [])):
            logger.debug("[OIDC TOKEN SERVICE] Checking key %d: kid=%s", idx, key.get("kid"))
            if key.get("kid") == kid:
                logger.debug("[OIDC TOKEN SERVICE] Found matching key at index %d", idx)
                try:
                    from cryptography.hazmat.primitives import serialization
                    from cryptography.hazmat.backends import default_backend
                    
                    logger.debug("[OIDC TOKEN SERVICE] Loading PEM public key...")
                    public_key = serialization.load_pem_public_key(
                        key["public_key"].encode() if isinstance(key["public_key"], str)
                        else key["public_key"],
                        backend=default_backend()
                    )
                    logger.debug("[OIDC TOKEN SERVICE] Public key loaded successfully")
                    break
                except (ImportError, Exception) as e:
                    logger.error("[OIDC TOKEN SERVICE] Failed to load public key: %s: %s", type(e).__name__, str(e))
                    continue
        
        if not public_key:
            logger.error("[OIDC TOKEN SERVICE] No matching public key found for kid=%s", kid)
            raise jwt.InvalidSignatureError(f"Key with kid={kid} not found")
        
        logger.debug("[OIDC TOKEN SERVICE] Public key found, verifying signature...")
        
        # Verify the signature
        try:
            claims = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=None,  # We'll validate audience separately
                issuer=cls._get_issuer(),
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": False,  # Handle audience manually
                    "verify_iss": False,  # Handle issuer manually
                }
            )
            logger.debug("[OIDC TOKEN SERVICE] Signature verification successful")
            logger.debug("[OIDC TOKEN SERVICE] Decoded claims: %s", claims)
            logger.debug("[OIDC TOKEN SERVICE] ===========================================")
            return claims
        except jwt.ExpiredSignatureError as e:
            logger.error("[OIDC TOKEN SERVICE] Token has expired: %s", str(e))
            raise
        except jwt.InvalidSignatureError as e:
            logger.error("[OIDC TOKEN SERVICE] Invalid token signature: %s", str(e))
            raise
        except jwt.InvalidTokenError as e:
            logger.error("[OIDC TOKEN SERVICE] Invalid token: %s: %s", type(e).__name__, str(e))
            raise
        except Exception as e:
            logger.error("[OIDC TOKEN SERVICE] Unexpected error during token verification: %s: %s", type(e).__name__, str(e))
            import traceback
            logger.error("[OIDC TOKEN SERVICE] Traceback: %s", traceback.format_exc())
            raise
    
    @classmethod
    def decode_token(cls, token: str, verify: bool = False) -> Dict:
        """Decode a JWT token without verification (for debugging).
        
        Args:
            token: JWT token string
            verify: Whether to verify signature
        
        Returns:
            Decoded token claims
        """
        if verify:
            return cls.verify_token_signature(token)
        
        return jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
            }
        )
    
    @classmethod
    def validate_access_token(cls, token: str, client_id: str = None) -> Dict:
        """Validate an access token and return its claims.
        
        Args:
            token: JWT access token
            client_id: Optional client ID to validate audience
        
        Returns:
            Token claims dictionary
        
        Raises:
            jwt.InvalidTokenError: If token is invalid
            ValueError: If token is expired or audience mismatch
        """
        logger.debug("[OIDC TOKEN SERVICE] ===========================================")
        logger.debug("[OIDC TOKEN SERVICE] validate_access_token() called")
        logger.debug("[OIDC TOKEN SERVICE] Token (first 50 chars): %s...", token[:50] if len(token) > 50 else token)
        logger.debug("[OIDC TOKEN SERVICE] Token length: %d", len(token))
        logger.debug("[OIDC TOKEN SERVICE] Client ID: %s", client_id)
        
        # Verify token signature
        logger.debug("[OIDC TOKEN SERVICE] Verifying token signature...")
        claims = cls.verify_token_signature(token)
        logger.debug("[OIDC TOKEN SERVICE] Token signature verified")
        logger.debug("[OIDC TOKEN SERVICE] Claims: %s", claims)
        
        # Check expiration
        exp = claims.get("exp", 0)
        now_timestamp = int(time.time())
        
        if exp < now_timestamp:
            logger.error("[OIDC TOKEN SERVICE] Token has expired")
            raise ValueError("Token has expired")
        
        # Validate audience if client_id provided
        aud = claims.get("aud")
        logger.debug("[OIDC TOKEN SERVICE] Token audience (aud): %s", aud)
        logger.debug("[OIDC TOKEN SERVICE] Expected client_id: %s", client_id)
        
        if client_id:
            if aud != client_id:
                logger.error("[OIDC TOKEN SERVICE] Audience mismatch: expected=%s, got=%s", client_id, aud)
                raise ValueError("Invalid audience")
            logger.debug("[OIDC TOKEN SERVICE] Audience validation passed")
        else:
            logger.debug("[OIDC TOKEN SERVICE] No client_id provided, skipping audience validation")
        
        logger.debug("[OIDC TOKEN SERVICE] validate_access_token() completed successfully")
        logger.debug("[OIDC TOKEN SERVICE] ===========================================")
        
        return claims
    
    @classmethod
    def introspect_token(cls, token: str, client_id: str = None) -> Dict:
        """Introspect a token and return its status and claims.
        
        Args:
            token: JWT token to introspect
            client_id: Client ID for audience validation
        
        Returns:
            Dictionary with active status and claims
        """
        result = {
            "active": False,
        }
        
        try:
            claims = cls.validate_access_token(token, client_id)
            
            # Calculate remaining time
            now_timestamp = int(time.time())
            now = datetime.now(timezone.utc)
            exp = claims.get("exp", 0)
            iat = claims.get("iat", 0)
            
            logger.debug("[OIDC TOKEN SERVICE] Introspection - Current UTC time: %s", now.isoformat())
            logger.debug("[OIDC TOKEN SERVICE] Introspection - Token expiration timestamp: %s", exp)
            logger.debug("[OIDC TOKEN SERVICE] Introspection - Token expiration datetime (UTC): %s", datetime.fromtimestamp(exp, tz=timezone.utc).isoformat())
            logger.debug("[OIDC TOKEN SERVICE] Introspection - Time until expiration: %s seconds", exp - now_timestamp)
            
            result["active"] = exp > now_timestamp
            result.update({
                "iss": claims.get("iss"),
                "sub": claims.get("sub"),
                "aud": claims.get("aud"),
                "exp": exp,
                "iat": iat,
                "nbf": claims.get("nbf"),
                "jti": claims.get("jti"),
                "client_id": claims.get("client_id"),
                "scope": claims.get("scope"),
                "token_type": "Bearer",
            })
            
            # Add expiry in seconds
            if exp > now_timestamp:
                result["exp"] = int(exp - now_timestamp)
            
        except (jwt.InvalidTokenError, ValueError) as e:
            result["active"] = False
            result["error"] = str(e)
        
        return result
