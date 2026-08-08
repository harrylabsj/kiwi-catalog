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

"""Shared validation helpers for the discovery profile parsers (PRIVATE).

NOT part of the public discovery API.  This module implements the pipeline
stages that A2A Agent Card and UCP Profile parsing share (§17.2–§17.3):

    schema validate → semantic validate → identity/authority validate
    → secret quarantine (§17.3) → public-field projection (§3.4)

Profiles are untrusted input.  Every value read here is treated as opaque
data; natural-language fields are never interpreted as instructions.

Design: docs/shopping-cli-a2a-upgrade-design-v1.2.1.md §17.2, §17.3
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

from kiwi_catalog.core.errors import ShoppingCliError

# ── Error type ────────────────────────────────────────────────────────────


class ProfileValidationError(ShoppingCliError):
    """Raised when an untrusted discovery profile fails validation.

    Kept distinct from ``core.ValidationError`` so discovery callers can catch
    profile failures specifically, while remaining inside the shopping-cli
    exception hierarchy.
    """


# ── Bounds backstop (§17.2 "size limit") ───────────────────────────────────

_DEFAULT_MAX_DEPTH = 100
_DEFAULT_MAX_NODES = 50_000


def validate_json_bounds(
    value: Any,
    *,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    max_nodes: int = _DEFAULT_MAX_NODES,
) -> None:
    """Backstop guard against deep/huge untrusted JSON (defense in depth).

    ``ProfileFetcher`` already bounds response bytes/depth/nodes (§17.1);
    this re-check makes the parsers independently safe when called directly
    with an already-parsed object.
    """
    count = 0

    def _walk(o: Any, depth: int) -> None:
        nonlocal count
        if depth > max_depth:
            raise ProfileValidationError(f"profile exceeds max JSON depth of {max_depth}")
        count += 1
        if count > max_nodes:
            raise ProfileValidationError(f"profile exceeds max JSON node count of {max_nodes}")
        if isinstance(o, dict):
            for v in o.values():
                _walk(v, depth + 1)
        elif isinstance(o, list):
            for v in o:
                _walk(v, depth + 1)

    _walk(value, 0)


# ── Type-checked field accessors ───────────────────────────────────────────


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    """Return *value* if it is a JSON object, otherwise raise."""
    if not isinstance(value, dict):
        raise ProfileValidationError(f"{label}: expected a JSON object, got {_type_name(value)}")
    return value


def require_str(obj: dict[str, Any], key: str, label: str) -> str:
    """Return *obj[key]* requiring it to be a present, non-null string."""
    if key not in obj:
        raise ProfileValidationError(f"{label}.{key}: missing required field")
    value = obj[key]
    if not isinstance(value, str):
        raise ProfileValidationError(f"{label}.{key}: expected a string, got {_type_name(value)}")
    return value


def get_optional_str(obj: dict[str, Any], key: str, label: str) -> str | None:
    """Return an optional string field, or None when absent/null."""
    if key not in obj or obj[key] is None:
        return None
    value = obj[key]
    if not isinstance(value, str):
        raise ProfileValidationError(f"{label}.{key}: expected a string, got {_type_name(value)}")
    return value


def require_list_of_str(obj: dict[str, Any], key: str, label: str) -> list[str]:
    """Return *obj[key]* requiring a present list of strings."""
    if key not in obj:
        raise ProfileValidationError(f"{label}.{key}: missing required field")
    value = obj[key]
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ProfileValidationError(f"{label}.{key}: expected a list of strings")
    return value


def get_optional_list_of_str(obj: dict[str, Any], key: str, label: str) -> list[str] | None:
    """Return an optional list-of-strings field, or None when absent/null."""
    if key not in obj or obj[key] is None:
        return None
    value = obj[key]
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ProfileValidationError(f"{label}.{key}: expected a list of strings")
    return value


def _type_name(value: Any) -> str:
    return type(value).__name__


# ── URL / authority helpers ────────────────────────────────────────────────


def is_http_url(value: Any) -> bool:
    """True when *value* is a non-empty http(s) URL with a hostname."""
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = urllib.parse.urlparse(value)
    except ValueError:
        return False
    return parsed.scheme in ("http", "https") and bool(parsed.hostname)


def canonical_domain_of(url: str) -> str:
    """Extract the lowercase hostname of *url* (the fetch-source authority)."""
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError as exc:
        raise ProfileValidationError(f"invalid source URL '{url}': {exc}") from exc
    host = parsed.hostname
    if not host:
        raise ProfileValidationError(f"source URL '{url}' has no hostname")
    return host.lower()


def is_same_authority(host: str, canonical: str) -> bool:
    """True when *host* equals *canonical* or is a subdomain of it.

    A declared URL is considered owned by the fetch source when its host is
    the same domain or a subdomain (e.g. ``agent.merchant.example`` under
    ``merchant.example``).  This is the §17.2 profile-poisoning / endpoint
    hijack check: a card fetched from ``merchant.example`` must not point its
    endpoints at ``attacker.example``.
    """
    host = host.lower().rstrip(".")
    canonical = canonical.lower().rstrip(".")
    return host == canonical or host.endswith("." + canonical)


def assert_same_domain(url: str, canonical: str, label: str) -> None:
    """Require *url* to be http(s) and hosted on *canonical* (or a subdomain)."""
    if not is_http_url(url):
        raise ProfileValidationError(f"{label}: expected an http(s) URL, got {url!r}")
    host = canonical_domain_of(url)
    if not is_same_authority(host, canonical):
        raise ProfileValidationError(
            f"{label}: declared host '{host}' does not match fetch source domain '{canonical}'"
        )


# ── Secret quarantine (§17.3) ──────────────────────────────────────────────

# Field names that look like static secrets.  Each word must appear as a whole
# segment of the (dot/underscore/dash/hyphen separated) JSON field name so that
# e.g. "token", "access_token", "api-key" and "client_secret" are flagged while
# "passage" and "secretary" are not.
_SECRET_WORDS = (
    "token",
    "tokens",
    "api_key",
    "api-key",
    "apikey",
    "apikeys",
    "password",
    "passwords",
    "passwd",
    "pass",
    "secret",
    "secrets",
    "private_key",
    "private-key",
    "privatekey",
    "bearer",
    "bearers",
)
_SECRET_FIELD_RE = re.compile(
    r"(?:^|[._-])(?:" + "|".join(re.escape(w) for w in _SECRET_WORDS) + r")(?:[._-]|$)",
    re.IGNORECASE,
)

# String-value patterns that look like embedded credentials regardless of the
# field name that carries them (catches e.g. {"access": "Bearer abc..."}).
_SECRET_VALUE_PATTERNS = (
    re.compile(r"(?i)^bearer\s+(eyJ[A-Za-z0-9._~+/=-]{2,}|[A-Za-z0-9._~+/=-]{16,})"),
    re.compile(r"(?i)^basic\s+[A-Za-z0-9+/]{8,}={0,2}"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"^eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
)


def _is_secret_field(name: str) -> bool:
    return _SECRET_FIELD_RE.search(name) is not None


def _is_secret_value(value: str) -> bool:
    return any(p.search(value) is not None for p in _SECRET_VALUE_PATTERNS)


def scan_secrets(value: Any, *, max_secrets: int = 64) -> list[str]:
    """Recursively find secret-like fields and return their JSON paths.

    Paths use dot-separated keys with integer list indices, e.g.
    ``services.0.endpoints.0.access.token``.  The scan covers the entire raw
    profile, including regions that will not be projected, so audit code can
    see every quarantined field.  A value is flagged when either its field
    name matches a secret pattern or its string value matches a credential
    pattern.
    """
    paths: list[str] = []

    def _scan(o: Any, path: str) -> None:
        if isinstance(o, dict):
            for key, item in o.items():
                if len(paths) >= max_secrets:
                    # 审查 P1-1：early-return 会让第 65 个起的 secret 字段不被扫描，
                    # _skip 判「未隔离」→ 凭据进入 public 投影并落库。命中 cap 视为
                    # 敌意负载 fail-closed，而不是静默放行后半棵子树。
                    raise ProfileValidationError(
                        f"profile contains more than {max_secrets} secret-like fields; "
                        "refusing to scan past the cap"
                    )
                child = f"{path}.{key}" if path else str(key)
                if isinstance(item, str) and (_is_secret_field(key) or _is_secret_value(item)):
                    paths.append(child)
                elif not isinstance(item, str) and _is_secret_field(key):
                    # Secret-named field holding a container — quarantine the
                    # container itself and stop recursing into it.
                    paths.append(child)
                else:
                    _scan(item, child)
        elif isinstance(o, list):
            for i, item in enumerate(o):
                if len(paths) >= max_secrets:
                    # 同上：cap 命中即 fail-closed，不静默放行。
                    raise ProfileValidationError(
                        f"profile contains more than {max_secrets} secret-like fields; "
                        "refusing to scan past the cap"
                    )
                _scan(item, f"{path}.{i}")

    _scan(value, "")
    return paths
