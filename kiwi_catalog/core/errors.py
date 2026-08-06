"""Shared exception types for shopping-cli layers."""

from __future__ import annotations


class ShoppingCliError(Exception):
    """Base exception for expected shopping-cli failures."""


class ValidationError(ShoppingCliError):
    """Raised when caller input is invalid."""


class NotFoundError(ShoppingCliError):
    """Raised when requested durable state does not exist."""


class ConflictError(ShoppingCliError):
    """Raised when a request conflicts with existing state."""


class PermissionDenied(ShoppingCliError):
    """Raised when a caller is not allowed to perform an action."""


class AuthError(PermissionDenied):
    """Raised when an API token is missing, invalid, revoked, or expired."""


class IdempotencyConflict(ConflictError):
    """Raised when an idempotency key is reused unsafely."""


class RateLimitError(ShoppingCliError):
    """Raised when a caller exceeds an API rate limit."""


class PayloadTooLargeError(ShoppingCliError):
    """Raised when a request exceeds the configured byte limit."""


class MethodNotAllowedError(ShoppingCliError):
    """Raised when a path exists but does not support the request method."""
