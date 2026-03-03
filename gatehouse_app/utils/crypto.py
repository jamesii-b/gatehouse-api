"""Cryptographic utilities for SSH operations."""
import hashlib
import base64
from typing import Optional


def compute_ssh_fingerprint(public_key_str: str, hash_algorithm: str = "sha256") -> str:
    """Compute the fingerprint of an SSH public key.
    
    Args:
        public_key_str: SSH public key in OpenSSH format
        hash_algorithm: Hash algorithm to use (sha256, sha1, md5)
        
    Returns:
        Fingerprint string in the format "algorithm:hex_digest"
        
    Example:
        >>> key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKp2..."
        >>> fp = compute_ssh_fingerprint(key)
        >>> print(fp)
        sha256:Kb+...
    """
    if not public_key_str:
        raise ValueError("Public key string is empty")
    
    # Parse OpenSSH format: "ssh-ed25519 <base64> [comment]"
    parts = public_key_str.strip().split()
    if len(parts) < 2:
        raise ValueError("Invalid OpenSSH public key format")
    
    try:
        # The base64-encoded key is the second part
        key_bytes = base64.b64decode(parts[1])
    except Exception as e:
        raise ValueError(f"Failed to decode public key: {str(e)}")
    
    # Compute hash
    if hash_algorithm == "sha256":
        digest = hashlib.sha256(key_bytes).digest()
        # SSH format uses base64 encoding without padding
        fingerprint = base64.b64encode(digest).decode().rstrip('=')
    elif hash_algorithm == "sha1":
        digest = hashlib.sha1(key_bytes).hexdigest()
        fingerprint = digest
    elif hash_algorithm == "md5":
        digest = hashlib.md5(key_bytes).hexdigest()
        # Format as colons
        fingerprint = ':'.join(digest[i:i+2] for i in range(0, len(digest), 2))
    else:
        raise ValueError(f"Unsupported hash algorithm: {hash_algorithm}")
    
    return f"{hash_algorithm}:{fingerprint}"


def verify_ssh_key_format(public_key_str: str) -> bool:
    """Verify that a string is in valid OpenSSH public key format.
    
    Args:
        public_key_str: Potential SSH public key
        
    Returns:
        True if valid OpenSSH format, False otherwise
    """
    if not public_key_str or not isinstance(public_key_str, str):
        return False
    
    parts = public_key_str.strip().split()
    
    # Must have at least key type and key material
    if len(parts) < 2:
        return False
    
    key_type = parts[0]
    
    # Valid key types
    valid_types = [
        'ssh-rsa',
        'ssh-ed25519',
        'ecdsa-sha2-nistp256',
        'ecdsa-sha2-nistp384',
        'ecdsa-sha2-nistp521',
        'ssh-dss',
    ]
    
    if key_type not in valid_types:
        return False
    
    # Try to decode base64
    try:
        base64.b64decode(parts[1])
        return True
    except Exception:
        return False


def extract_ssh_key_type(public_key_str: str) -> Optional[str]:
    """Extract the key type from an OpenSSH public key.
    
    Args:
        public_key_str: SSH public key in OpenSSH format
        
    Returns:
        Key type (e.g., "ssh-ed25519") or None if invalid
    """
    if not verify_ssh_key_format(public_key_str):
        return None
    
    return public_key_str.strip().split()[0]


def extract_ssh_key_comment(public_key_str: str) -> Optional[str]:
    """Extract the comment from an OpenSSH public key.
    
    Args:
        public_key_str: SSH public key in OpenSSH format
        
    Returns:
        Comment string or None if not present
    """
    if not verify_ssh_key_format(public_key_str):
        return None
    
    parts = public_key_str.strip().split()
    if len(parts) >= 3:
        # Everything after the second part is the comment
        return ' '.join(parts[2:])
    
    return None
