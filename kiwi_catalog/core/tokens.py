"""Token storage helpers.

Raw API tokens are returned to callers once. SQLite stores deterministic
digests plus display hints so token list/audit views can stay useful without
persisting bearer secrets.
"""

from __future__ import annotations

import hashlib
import hmac
import string


def token_digest(token: str) -> str:
    return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()


def token_prefix(token: str) -> str:
    return str(token or "")[:24]


def token_suffix(token: str) -> str:
    return str(token or "")[-6:]


def is_sha256_digest(value: str) -> bool:
    text = str(value or "")
    return len(text) == 64 and all(char in string.hexdigits for char in text)


def token_matches(candidate: str, expected: str) -> bool:
    return hmac.compare_digest(str(candidate or ""), str(expected or ""))
