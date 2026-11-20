"""Shared wire contract for the HTTPS domain-control document."""

import hmac
from typing import Any

CHALLENGE_WELL_KNOWN_PATH = ".well-known/kiwi-catalog-agent.json"
CHALLENGE_DOCUMENT_KEYS = ("catalog_agent_id", "challenge")


def is_challenge_document(parsed: Any) -> bool:
    return isinstance(parsed, dict) and all(key in parsed for key in CHALLENGE_DOCUMENT_KEYS)


def challenge_matches(expected: str, actual: Any) -> bool:
    return bool(expected) and isinstance(actual, str) and hmac.compare_digest(
        expected.encode("utf-8"), actual.encode("utf-8")
    )
