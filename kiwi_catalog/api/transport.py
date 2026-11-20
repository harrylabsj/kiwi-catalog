"""Transport fields and response metadata shared by both HTTP stacks."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})
AUTH_TRANSPORT_FIELDS = frozenset({"_auth_token", "_binding_jws", "_origin", "_referer"})
COMMON_TRANSPORT_FIELDS = AUTH_TRANSPORT_FIELDS | frozenset({
    "_cookie", "_buyer_id", "_buyer_source", "_client_ip",
})
INQUIRY_ONLY_FIELDS = frozenset({"_raw_inquiry_body_b64", "_inquiry_headers"})
SERVER_PAYLOAD_FIELDS = COMMON_TRANSPORT_FIELDS | INQUIRY_ONLY_FIELDS
INQUIRY_TRANSPORT_KEYS = SERVER_PAYLOAD_FIELDS | {"idempotency_key"}
_REGISTER_PATHS = frozenset({"/v1/agent-catalog/agents/register", "/v1/agents/register"})

SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "content-security-policy": "frame-ancestors 'none'",
}
RESPONSE_META_FIELDS = frozenset({
    "__status__", "__no_store__", "__cookies__", "__html__", "__redirect__",
})


def strip_transport_fields(payload: dict[str, Any], *, path: str = "") -> dict[str, Any]:
    # Registration validates unexpected inquiry-only fields against its
    # closed contract. Common metadata is replaced by server values.
    fields = COMMON_TRANSPORT_FIELDS if path in _REGISTER_PATHS else SERVER_PAYLOAD_FIELDS
    return {key: value for key, value in payload.items() if key not in fields}


def redirect_location(value: Any) -> str:
    return quote(str(value), safe=":/%#?=@[]!$&'()*+,;~")
