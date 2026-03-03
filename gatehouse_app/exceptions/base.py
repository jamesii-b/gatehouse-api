"""Base exception classes."""


class BaseAPIException(Exception):
    """Base exception for all API errors."""

    status_code = 500
    error_type = "INTERNAL_ERROR"
    message = "An unexpected error occurred"

    def __init__(self, message=None, error_details=None):
        """
        Initialize exception.

        Args:
            message: Custom error message
            error_details: Additional error details dictionary
        """
        super().__init__(self.message)
        if message:
            self.message = message
            super().__init__(message)  # update args so str(e) works
        self.error_details = error_details or {}

    def to_dict(self):
        """Convert exception to dictionary for API response."""
        return {
            "error_type": self.error_type,
            "message": self.message,
            "details": self.error_details,
            "status_code": self.status_code,
        }
