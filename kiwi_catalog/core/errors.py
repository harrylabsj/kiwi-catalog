# Copyright 2026 harrylabsj
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
