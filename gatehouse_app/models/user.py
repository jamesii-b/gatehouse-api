"""Backward-compatibility shim — import from gatehouse_app.models.user.user instead."""
from gatehouse_app.models.user.user import User  # noqa: F401

__all__ = ["User"]
