"""SSH-specific exceptions."""
from gatehouse_app.exceptions.base import BaseAPIException


class SSHCAError(BaseAPIException):
    """Base exception for SSH CA operations."""
    
    status_code = 500
    error_type = "SSH_CA_ERROR"


class SSHKeyError(BaseAPIException):
    """Exception for SSH key operations."""
    
    status_code = 400
    error_type = "SSH_KEY_ERROR"


class SSHKeyNotFoundError(BaseAPIException):
    """SSH key not found."""
    
    status_code = 404
    error_type = "SSH_KEY_NOT_FOUND"


class SSHKeyAlreadyExistsError(BaseAPIException):
    """SSH key already exists (duplicate fingerprint)."""
    
    status_code = 409
    error_type = "SSH_KEY_ALREADY_EXISTS"


class SSHKeyNotVerifiedError(BaseAPIException):
    """SSH key has not been verified."""
    
    status_code = 400
    error_type = "SSH_KEY_NOT_VERIFIED"


class SSHCertificateError(BaseAPIException):
    """Exception for SSH certificate operations."""
    
    status_code = 400
    error_type = "SSH_CERT_ERROR"


class SSHCertificateNotFoundError(BaseAPIException):
    """SSH certificate not found."""
    
    status_code = 404
    error_type = "SSH_CERT_NOT_FOUND"


class CAError(BaseAPIException):
    """Exception for Certificate Authority operations."""
    
    status_code = 400
    error_type = "CA_ERROR"


class CANotFoundError(BaseAPIException):
    """Certificate Authority not found."""
    
    status_code = 404
    error_type = "CA_NOT_FOUND"


class PrincipalError(BaseAPIException):
    """Exception for principal operations."""
    
    status_code = 400
    error_type = "PRINCIPAL_ERROR"


class PrincipalNotFoundError(BaseAPIException):
    """Principal not found."""
    
    status_code = 404
    error_type = "PRINCIPAL_NOT_FOUND"


class DepartmentError(BaseAPIException):
    """Exception for department operations."""
    
    status_code = 400
    error_type = "DEPARTMENT_ERROR"


class DepartmentNotFoundError(BaseAPIException):
    """Department not found."""
    
    status_code = 404
    error_type = "DEPARTMENT_NOT_FOUND"
