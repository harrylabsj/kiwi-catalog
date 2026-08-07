"""HTTP cache helpers — conditional GET, freshness, and snapshot metadata.

Design: docs/shopping-cli-a2a-upgrade-design-v1.2.1.md §18

The module produces the fields that the catalog layer writes into
``agent_profile_snapshots`` (fetched_at, fresh_until, etag, content_hash)
and implements the three-state freshness model:

    fresh         —  now < fresh_until
    stale_usable  —  now >= fresh_until but the stale response is usable
    stale_unusable — cache must be refreshed before use
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from email.utils import mktime_tz, parsedate_to_datetime
from enum import Enum, auto
from typing import Any


class CacheState(Enum):
    """Three-state freshness model per §18."""

    FRESH = auto()
    """The cached response is still valid (now < fresh_until)."""

    STALE_USABLE = auto()
    """The cached response is past its freshness window but MAY still be used
    (e.g. when the origin is unreachable or a refresh is pending)."""

    STALE_UNUSABLE = auto()
    """The cached response MUST be refreshed before use (age exceeds the
    policy's hard limit or the cache entry has been invalidated)."""


# ── Header parsing ────────────────────────────────────────────────────────────


def _parse_http_date(value: str | None) -> float | None:
    """Parse an HTTP-date string into a Unix timestamp (float seconds).

    Returns None when *value* is empty, missing, or unparseable.
    """
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(str(value))
        if dt is None:
            return None
        # Build a time-tuple compatible with mktime_tz (10th elem is the UTC offset in seconds).
        tt = dt.timetuple()
        utcoff = dt.utcoffset()
        offset_seconds = int(utcoff.total_seconds()) if utcoff is not None else 0
        return mktime_tz(tt + (offset_seconds,))
    except (TypeError, ValueError, OverflowError):
        return None


def _parse_max_age(cache_control: str | None) -> int | None:
    """Extract ``max-age=<seconds>`` from a Cache-Control header value.

    Returns None when the directive is absent or unparseable.
    """
    if not cache_control:
        return None
    lower = str(cache_control).lower()
    for part in lower.split(","):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                return int(part.split("=", 1)[1].strip())
            except (ValueError, IndexError):
                return None
    return None


def _parse_etag(value: str | None) -> str | None:
    """Normalise an ETag header value for storage.

    Weak ETags (``W/\"...\"``) are stored as-is; the caller decides whether
    to use them for conditional requests.
    """
    if not value:
        return None
    return str(value).strip() or None


# ── Conditional request header builders ───────────────────────────────────────


def build_conditional_headers(
    etag: str | None = None,
    last_modified: str | None = None,
) -> dict[str, str]:
    """Build request headers for a conditional GET (§18).

    Pass the *etag* and *last_modified* values from a previous cached response
    (as stored in ``agent_profile_snapshots.etag`` / ``.last_modified``).

    Returns a dict that can be merged into the request headers.  An empty
    dict means no conditional headers are available.
    """
    headers: dict[str, str] = {}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    return headers


# ── Cache directives parsed from a response ───────────────────────────────────


@dataclass(frozen=True)
class CacheDirective:
    """Parsed caching metadata extracted from an HTTP response.

    All fields may be None when the corresponding header was absent or
    unparseable.
    """

    etag: str | None = None
    """Normalised ETag value (weak or strong)."""

    last_modified: str | None = None
    """Raw Last-Modified header value (for conditional requests)."""

    last_modified_ts: float | None = None
    """Parsed Last-Modified as a Unix timestamp, or None."""

    max_age: int | None = None
    """``max-age`` seconds from Cache-Control, or None."""

    cache_control_raw: str | None = None
    """Raw Cache-Control header value for diagnostics."""

    fetched_at_ts: float = field(default_factory=time.time)
    """Unix timestamp when the response was received."""

    @classmethod
    def from_response_headers(
        cls,
        headers: dict[str, str],
        *,
        fetched_at: float | None = None,
    ) -> "CacheDirective":
        """Parse a CacheDirective from a dict of response header values.

        Header names are matched case-insensitively.
        """
        lowered = {k.lower(): v for k, v in headers.items()}

        etag = _parse_etag(lowered.get("etag"))
        last_modified = lowered.get("last-modified") or None
        last_modified_ts = _parse_http_date(last_modified)
        cache_control = lowered.get("cache-control") or None
        max_age = _parse_max_age(cache_control)

        kwargs: dict[str, Any] = {
            "etag": etag,
            "last_modified": last_modified,
            "last_modified_ts": last_modified_ts,
            "max_age": max_age,
            "cache_control_raw": cache_control,
        }
        if fetched_at is not None:
            kwargs["fetched_at_ts"] = fetched_at

        return cls(**kwargs)

    # ── Computed fields ──────────────────────────────────────────────────

    def compute_fresh_until(self, policy_max_age_seconds: int) -> float:
        """Compute the ``fresh_until`` timestamp (Unix seconds).

        Precedence: ``Cache-Control: max-age`` > ``policy_max_age_seconds``.
        """
        age = self.max_age if self.max_age is not None else policy_max_age_seconds
        return self.fetched_at_ts + age


# ── Snapshot row helpers ──────────────────────────────────────────────────────


def compute_content_hash(content: str | bytes) -> str:
    """Compute a SHA-256 hex digest of the raw response body."""
    if isinstance(content, str):
        content = content.encode("utf-8")
    return hashlib.sha256(content).hexdigest()


def compute_etag(content: str | bytes) -> str:
    """Compute a strong ETag (quoted content hash) for an HTTP response body.

    §18 — server-side generated validator: the same content always yields the
    same ETag, and the value is opaque to clients (they only echo it back).
    """
    return f'"{compute_content_hash(content)}"'


def etag_matches(if_none_match: str, etag: str) -> bool:
    """True when an ``If-None-Match`` header value matches *etag*.

    Handles strong and weak ETags and the ``*`` wildcard.  The header is
    untrusted request data; every comparison is against the server's own
    computed *etag*, so a malformed header simply never matches.
    """
    expected = etag.strip('"')
    for raw in if_none_match.split(","):
        token = raw.strip()
        if token == "*":
            return True
        if token.startswith("W/"):
            token = token[2:].strip()
        token = token.strip('"')
        if token and token == expected:
            return True
    return False


def snapshot_meta(
    *,
    directive: CacheDirective,
    content: str | bytes,
    policy_max_age_seconds: int,
) -> dict[str, Any]:
    """Build the ``agent_profile_snapshots`` metadata fields from a fetch result.

    Returns a dict with keys matching the snapshot table columns:

    * ``etag``
    * ``last_modified``
    * ``content_hash``
    * ``fetched_at`` (ISO-8601)
    * ``fresh_until`` (ISO-8601)
    """
    from datetime import datetime, timezone

    content_hash = compute_content_hash(content)
    fresh_until_ts = directive.compute_fresh_until(policy_max_age_seconds)

    def _iso(ts: float) -> str:
        return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()

    return {
        "etag": directive.etag or "",
        "last_modified": directive.last_modified or "",
        "content_hash": content_hash,
        "fetched_at": _iso(directive.fetched_at_ts),
        "fresh_until": _iso(fresh_until_ts),
    }


def compute_cache_state(
    *,
    fresh_until: float,
    now: float | None = None,
    stale_usable_seconds: int | None = None,
) -> CacheState:
    """Determine the freshness state of a cached response.

    Args:
        fresh_until: Unix timestamp when the cached entry expires.
        now: Current time (defaults to ``time.time()``).
        stale_usable_seconds: Extra grace period beyond *fresh_until* during
            which a stale response is still ``STALE_USABLE``.  When None (the
            default), stale entries are immediately ``STALE_UNUSABLE`` — there
            is no grace period.

    Returns:
        ``CacheState.FRESH`` when *now* < *fresh_until*.
        ``CacheState.STALE_USABLE`` when *now* is within the grace period.
        ``CacheState.STALE_UNUSABLE`` when the grace period has also expired.
    """
    if now is None:
        now = time.time()

    if now < fresh_until:
        return CacheState.FRESH

    if stale_usable_seconds is not None and now < fresh_until + stale_usable_seconds:
        return CacheState.STALE_USABLE

    return CacheState.STALE_UNUSABLE
