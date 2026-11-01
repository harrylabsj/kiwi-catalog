"""Account-free A2A relay. Gate credentials never leave Catalog's server."""
from __future__ import annotations

import base64
import binascii
import json
import logging
from pathlib import Path
from typing import Any
from urllib.parse import quote

from kiwi_catalog.a2a.public_read_limit import enforce_public_read_limit
from kiwi_catalog.core.errors import NotFoundError, ValidationError
from kiwi_catalog.db.session import db_session
from kiwi_catalog.discovery.fetcher import ProfileFetcher
from kiwi_catalog.discovery.trust import TrustPolicy
from kiwi_catalog.services import public_inquiry_consent, runtime_access

_HEADERS = {"content-type", "content-digest", "signature", "signature-input",
            "a2a-version", "a2a-extensions"}
_METHODS = {"SendMessage", "GetTask", "ListTasks", "CancelTask", "message/send", "tasks/get"}
_LOG = logging.getLogger(__name__)
_SAFE_LOG_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-")
PUBLIC_INQUIRY_RELAY_FAILED = "PUBLIC_INQUIRY_RELAY_FAILED"
PUBLIC_INQUIRY_UPSTREAM_REJECTED = "PUBLIC_INQUIRY_UPSTREAM_REJECTED"
PUBLIC_INQUIRY_UPSTREAM_INVALID = "PUBLIC_INQUIRY_UPSTREAM_INVALID"


def _log_safe_id(value: str) -> str:
    """Bound a caller-supplied path id so it cannot inject log lines."""
    text = str(value)[:128]
    return "".join(ch if ch in _SAFE_LOG_ID_CHARS else f"\\x{ord(ch):02x}" for ch in text)


def _relay_failure(request_id: Any) -> dict[str, Any]:
    """Fixed 502 body: never carries upstream text or gate credentials."""
    return {"__status__": 502, "__no_store__": True, "jsonrpc": "2.0", "id": request_id,
            "error": {"code": -32000, "message": "商家服务暂不可用，请稍后重试"}}


def availability(db_path: str | Path, agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Public capability discovery contains no credential or merchant secret."""
    with db_session(db_path) as conn:
        enforce_public_read_limit(conn, payload, surface="open-inquiry-discovery")
    with db_session(db_path) as conn:
        if not public_inquiry_consent.enabled(conn, agent_id):
            raise NotFoundError("public inquiry is not available")
    return {"available": True, "catalog_agent_id": agent_id, "__no_store__": True}


def _contains_gate_secret(value: Any, secret: str) -> bool:
    if isinstance(value, str):
        return secret in value or quote(secret, safe="") in value
    if isinstance(value, dict):
        return any(_contains_gate_secret(k, secret) or _contains_gate_secret(v, secret) for k, v in value.items())
    if isinstance(value, list):
        return any(_contains_gate_secret(item, secret) for item in value)
    return False


def forward(db_path: str | Path, agent_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Forward the original signed bytes to the current explicitly opted-in binding."""
    encoded = payload.get("_raw_inquiry_body_b64")
    supplied_headers = payload.get("_inquiry_headers")
    if not isinstance(encoded, str) or len(encoded) > 87384 or not isinstance(supplied_headers, dict):
        raise ValidationError("invalid inquiry request")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise ValidationError("invalid inquiry request") from None
    if not raw or len(raw) > 65536:
        raise ValidationError("invalid inquiry request")
    try:
        message = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise ValidationError("invalid inquiry request") from None
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0" or message.get("method") not in _METHODS:
        raise ValidationError("unsupported inquiry method")
    request_id = message.get("id")
    if isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
        raise ValidationError("inquiry id is required")
    headers: dict[str, str] = {}
    for name, value in supplied_headers.items():
        if name not in _HEADERS or not isinstance(value, str) or not value or len(value) > 4096 or "\r" in value or "\n" in value:
            raise ValidationError("invalid inquiry header")
        headers[name] = value
    if not {"content-type", "content-digest", "signature", "signature-input"}.issubset(headers):
        raise ValidationError("signed inquiry headers are required")
    if headers["content-type"].split(";", 1)[0].strip().lower() != "application/json":
        raise ValidationError("inquiry content type must be application/json")
    # Commit IP budget independently so rejected attempts are also limited.
    with db_session(db_path) as conn:
        enforce_public_read_limit(conn, payload, surface="open-inquiry", limit=30)
    with db_session(db_path) as conn:
        if not public_inquiry_consent.enabled(conn, agent_id):
            raise NotFoundError("public inquiry is not available")
        binding = conn.execute("select runtime_origin,a2a_endpoint from runtime_bindings "
            "where catalog_agent_id=? and status='active' order by binding_version desc limit 1", (agent_id,)).fetchone()
        config = runtime_access.active_runtime_access(conn, agent_id)
        if binding is None or config is None:
            raise NotFoundError("public inquiry is not available")
        origin, endpoint = str(binding["runtime_origin"]), str(binding["a2a_endpoint"])
        if endpoint != origin.rstrip("/") + "/a2a":
            raise NotFoundError("public inquiry is not available")
        secret = runtime_access.row_secret(config, statuses=frozenset({"active"}))
        target = runtime_access.append_share_parameter(endpoint, secret)
    try:
        result = ProfileFetcher(TrustPolicy.defaults(), timeout=15).post_signed_a2a(target, raw, headers)
    except Exception as exc:
        # 传输异常可能带完整 URL（含分享码）：只记录自有固定码、净化后的
        # agent 标识与异常类型；绝不记录异常原文、URL 或响应体。
        _LOG.warning(
            "public inquiry relay failed: code=%s agent=%s error_type=%s",
            PUBLIC_INQUIRY_RELAY_FAILED, _log_safe_id(agent_id), type(exc).__name__,
        )
        return _relay_failure(request_id)
    if result.status_code != 200:
        _LOG.warning(
            "public inquiry relay failed: code=%s agent=%s upstream_status=%s",
            PUBLIC_INQUIRY_UPSTREAM_REJECTED, _log_safe_id(agent_id), result.status_code,
        )
        return _relay_failure(request_id)
    try:
        response = json.loads(result.body)
    except (TypeError, ValueError, RecursionError):
        response = None
    if not isinstance(response, dict) or response.get("jsonrpc") != "2.0" or response.get("id") != request_id \
            or set(response) - {"jsonrpc", "id", "result", "error"} \
            or (("result" in response) == ("error" in response)) or _contains_gate_secret(response, secret):
        _LOG.warning(
            "public inquiry relay failed: code=%s agent=%s",
            PUBLIC_INQUIRY_UPSTREAM_INVALID, _log_safe_id(agent_id),
        )
        return _relay_failure(request_id)
    response["__no_store__"] = True
    return response
