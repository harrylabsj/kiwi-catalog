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

"""一次业务确认的短期 Runtime enrollment 与 device authorization。"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from typing import Any

from kiwi_catalog.a2a.binding_claims import jwk_thumbprint
from kiwi_catalog.a2a.request_signature import verify_binding_possession
from kiwi_catalog.core.errors import ConflictError, NotFoundError, ValidationError
from kiwi_catalog.db.session import now_iso
from kiwi_catalog.a2a.request_signature import consume_request_nonce
from kiwi_catalog.agent_catalog.sqlite_repository import append_catalog_audit

SCOPES = ("runtime:bind", "card:publish", "heartbeat")

PAIRING_MODE_ENV = "KIWI_CATALOG_ENROLLMENT_PAIRING_MODE"
PAIRING_MODE_OPTIONAL = "optional"
PAIRING_MODE_REQUIRED = "required"
_OPTIONAL_MODE_VALUES = frozenset({"optional", "off", "0", "false", "no"})


def pairing_required() -> bool:
    """配对码是否**必须**提供（后端分阶段启用开关）。

    默认 ``required``（审查 P2）：缺少配对码的请求在所有栈上一律拒绝，不再
    依赖前端是否禁用了确认按钮。过渡期需要旧版授权页/旧浏览器兼容的部署必须
    **显式**设置 ``KIWI_CATALOG_ENROLLMENT_PAIRING_MODE=optional``。

    未知取值按 ``required`` 处理（fail-closed）：拼错开关不能意外放宽安全
    边界。
    """
    # 审查 P2：缺省翻转为 required——转发授权链接的钓鱼在无绑定商家上仍可
    # 成功。确需过渡期兼容的部署必须显式设置 optional（部署文档/CHANGELOG）。
    raw = str(os.environ.get(PAIRING_MODE_ENV) or "").strip().lower()
    if raw == PAIRING_MODE_OPTIONAL:
        return False
    return raw not in _OPTIONAL_MODE_VALUES


def validate_public_jwk(jwk: dict[str, Any]) -> str:
    """Accept only canonical public-key members; never persist private JWK material."""
    if not isinstance(jwk, dict):
        raise ValidationError("key_jwk must be a JSON object")
    kty = jwk.get("kty")
    if kty == "OKP":
        allowed = {"kty", "crv", "x"}
    elif kty == "EC":
        allowed = {"kty", "crv", "x", "y"}
    else:
        raise ValidationError("key_jwk must be a supported public OKP or EC JWK")
    if set(jwk) != allowed:
        raise ValidationError("key_jwk must contain only canonical public-key fields")
    return jwk_thumbprint(jwk)


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _stable_grant(enrollment_id: str, device_code_hash: str) -> str:
    # Deterministic under the server secret so a lost poll response is retryable;
    # only the digest is persisted. Database-only exposure cannot derive a grant.
    from kiwi_catalog.services.accounts import _owner_secret
    key = _owner_secret().encode("utf-8")
    return hmac.new(key, f"kiwi-catalog-enrollment-v1:{enrollment_id}:{device_code_hash}".encode(), hashlib.sha256).hexdigest()


def _body_digest(body: dict[str, Any]) -> str:
    from kiwi_catalog.a2a.enrollment_canonical import canonical_digest
    return canonical_digest(body)


def create_device(conn: sqlite3.Connection, body: dict[str, Any], signature: str) -> dict[str, Any]:
    raw_binding = body.get("binding")
    binding: dict[str, Any] = raw_binding if isinstance(raw_binding, dict) else body
    jwk = binding.get("key_jwk")
    if not isinstance(jwk, dict):
        raise ValidationError("key_jwk must be a JWK object")
    thumb = validate_public_jwk(jwk)
    if not isinstance(binding.get("key_id"), str) or not binding["key_id"].strip():
        raise ValidationError("key_id must be a non-empty string")
    for text_field in ("runtime_origin", "a2a_endpoint"):
        if not isinstance(binding.get(text_field), str) or not binding[text_field].strip():
            raise ValidationError(f"{text_field} must be a non-empty string")
    for number in ("generation", "service_epoch"):
        value = binding.get(number)
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValidationError(f"{number} must be a positive integer")
    preview = body.get("public_preview")
    if not isinstance(preview, dict):
        raise ValidationError("public_preview must be the complete public Agent Card object")
    from kiwi_catalog.a2a.card_store import scan_publication_leaks
    if scan_publication_leaks(preview):
        raise ValidationError("public_preview contains private data")
    from kiwi_catalog.discovery.agent_card import AgentCardParser
    try:
        AgentCardParser(reject_on_secret=True).parse(preview, source_url=str(preview.get("url", "")))
    except Exception as exc:
        raise ValidationError(f"public_preview is not a valid public Agent Card: {exc}") from exc
    from kiwi_catalog.a2a.endpoint_policy import assert_safe_binding_targets
    assert_safe_binding_targets({"runtime_origin": binding.get("runtime_origin", ""), "a2a_endpoint": binding.get("a2a_endpoint", "")})
    if str(binding["a2a_endpoint"]).rstrip("/") != str(binding["runtime_origin"]).rstrip("/") + "/a2a":
        raise ValidationError("a2a_endpoint must be the approved origin plus /a2a")
    interfaces = preview.get("supportedInterfaces")
    if not isinstance(interfaces, list) or not any(isinstance(item, dict) and item.get("url") == binding["a2a_endpoint"] for item in interfaces):
        raise ValidationError("public_preview must advertise the approved A2A endpoint")
    signed = verify_binding_possession(
        jws=signature, public_jwk=jwk,
        expected_fields={"method": "POST", "path": "/v1/enrollments/device", "audience": "kiwi-catalog",
                         "key_id": str(binding.get("key_id", "")), "key_thumbprint": thumb,
                         "generation": int(binding.get("generation", 0)),
                         "service_epoch": int(binding.get("service_epoch", 0))},
    )
    # body_digest also binds the public preview and endpoint to this possession proof.
    raw_digest = _body_digest(body)
    if str(signed.get("body_digest", "")) != raw_digest:
        raise ValidationError("device signature body_digest mismatch")
    _check_exp(signed)
    consume_request_nonce(conn, key_id=str(binding["key_id"]), nonce=str(signed.get("nonce", "")), issued_at=str(signed.get("issued_at", "")))
    now = now_iso()
    enrollment_id = "enr_" + secrets.token_urlsafe(18)
    device_code = secrets.token_urlsafe(32)
    user_code = secrets.token_hex(4).upper()
    expires = (datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=10)).isoformat()
    conn.execute(
        "insert into enrollments(enrollment_id,device_code_hash,user_code,status,key_id,key_thumbprint,key_jwk_json,"
        "runtime_origin,a2a_endpoint,generation,service_epoch,public_preview_json,public_profile_revision,expected_binding_version,created_at,expires_at)"
        " values(?,?,?,'ready_for_authorization',?,?,?,?,?,?,?,?,?,?,?,?)",
        (enrollment_id, _hash(device_code), user_code, str(binding.get("key_id", "")), thumb,
         json.dumps(jwk, separators=(",", ":")), str(binding["runtime_origin"]), str(binding["a2a_endpoint"]),
         int(binding["generation"]), int(binding["service_epoch"]),
         json.dumps(preview, ensure_ascii=False, separators=(",", ":")),
         str(body.get("public_profile_revision") or ""), 1, now, expires),
    )
    return {"enrollment_id": enrollment_id, "device_code": device_code, "user_code": user_code,
            "verification_uri": "/portal/connect/" + enrollment_id, "expires_at": expires, "interval": 5}


def public_enrollment(conn: sqlite3.Connection, enrollment_id: str) -> dict[str, Any]:
    row = conn.execute("select * from enrollments where enrollment_id=?", (enrollment_id,)).fetchone()
    if row is None:
        raise NotFoundError("enrollment not found")
    current = now_iso()
    is_expired = (
        row["status"] == "ready_for_authorization" and row["expires_at"] <= current
    ) or (
        row["status"] == "authorized" and row["grant_expires_at"] <= current
    )
    if is_expired:
        conn.execute("update enrollments set status='expired' where enrollment_id=?", (enrollment_id,))
        status = "expired"
    else:
        status = str(row["status"])
    # The device creation response is the sole user-code delivery. A session
    # preview must not disclose the secret used to claim an unowned enrollment.
    # ``pairing_required`` is a policy bit, not a credential: the portal may ask
    # the merchant for the code either way, and the backend still enforces it.
    return {"ok": True, "enrollment_id": enrollment_id,
            "public_preview": json.loads(row["public_preview_json"]), "runtime_origin": row["runtime_origin"],
            "a2a_endpoint": row["a2a_endpoint"], "status": status, "requested_at": row["created_at"],
            "pairing_required": pairing_required()}


def authorize(conn: sqlite3.Connection, row: sqlite3.Row, account: dict[str, Any], user_code: str,
              agent_id: str) -> dict[str, Any]:
    # review 3-61：grant 形参已删——service 内部始终以 _stable_grant 重算，
    # 传入的随机 grant 从未落库（死参数）；配对码校验收敛到本函数唯一一处。
    #
    # 配对码由商家从自己的商家应用工作台读出后手工输入，**只随 JSON 请求体**
    # 提交（页面不把码放进 URL/查询串，也不回显）。校验分两段：
    # - 提供之后必须匹配（恒定时间比较；错码一律拒，失败不改任何状态）；
    # - 是否允许缺省由 ``pairing_required()`` 决定：门户先行阶段默认兼容旧授权
    #   页，后端收紧后缺码即拒。两段都在服务端执行，前端按钮只是 UX。
    presented = user_code.strip().upper()
    if len(presented) > 64:
        raise ValidationError("user_code is malformed")
    expected = str(row["user_code"] or "").upper()
    if presented == "" and pairing_required():
        raise ConflictError("pairing code is required")
    if presented != "" and not hmac.compare_digest(presented, expected):
        raise ConflictError("user_code mismatch")
    if (row["status"] == "authorized" and row["grant_expires_at"] > now_iso()
            and row["merchant_id"] == account["merchant_id"]):
        return {"ok": True, "status": "authorized", "enrollment_id": row["enrollment_id"], "catalog_agent_id": agent_id}
    if row["status"] != "ready_for_authorization" or row["expires_at"] <= now_iso():
        raise ConflictError("enrollment is no longer authorizable")
    agent = conn.execute("select merchant_id, administrative_state from catalog_agents where catalog_agent_id=?", (agent_id,)).fetchone()
    if agent is None or agent["merchant_id"] != account["merchant_id"] or agent["administrative_state"] != "active":
        raise ConflictError("catalog agent is not eligible for enrollment authorization")
    preview = json.loads(row["public_preview_json"])
    from kiwi_catalog.a2a.enrollment_canonical import canonical_digest
    digest = canonical_digest(preview)
    now = now_iso()
    grant = _stable_grant(str(row["enrollment_id"]), str(row["device_code_hash"]))
    latest = conn.execute("select max(binding_version) from runtime_bindings where catalog_agent_id=?", (agent_id,)).fetchone()[0]
    expected_version = int(latest or 0) + 1
    grant_expires_at = (datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=10)).isoformat()
    conn.execute("update enrollments set status='authorized',merchant_id=?,catalog_agent_id=?,grant_hash=?,scopes_json=?,"
                 "approved_card_digest=?,authorized_at=?,grant_expires_at=?,expected_binding_version=? "
                 "where enrollment_id=? and status='ready_for_authorization'",
                 (str(account["merchant_id"]), agent_id, _hash(grant), json.dumps(SCOPES), digest, now, grant_expires_at,
                  expected_version, row["enrollment_id"]))
    if conn.execute("select changes()").fetchone()[0] != 1:
        raise ConflictError("enrollment authorization raced")
    append_catalog_audit(conn, agent_id, f"merchant:{account['merchant_id']}",
                         "runtime_enrollment_authorized", {"enrollment_id": row["enrollment_id"],
                         "approved_card_digest": digest, "scopes": list(SCOPES),
                         "authorization_epoch": int(row["authorization_epoch"])})
    return {"ok": True, "status": "authorized", "enrollment_id": row["enrollment_id"], "catalog_agent_id": agent_id}


def poll(conn: sqlite3.Connection, body: dict[str, Any], signature: str) -> dict[str, Any]:
    row = conn.execute("select * from enrollments where device_code_hash=?", (_hash(str(body.get("device_code", ""))),)).fetchone()
    if row is None:
        raise NotFoundError("enrollment not found")
    current = now_iso()
    if (row["status"] == "ready_for_authorization" and row["expires_at"] <= current) or (
        row["status"] == "authorized" and row["grant_expires_at"] <= current
    ):
        conn.execute("update enrollments set status='expired' where enrollment_id=?", (row["enrollment_id"],))
        raise ConflictError("enrollment expired")
    signed = verify_binding_possession(jws=signature, public_jwk=json.loads(row["key_jwk_json"]), expected_fields={
        "method": "POST", "path": "/v1/enrollments/device/token", "audience": "kiwi-catalog",
        "device_code_hash": _hash(str(body.get("device_code", ""))), "key_thumbprint": row["key_thumbprint"],
        "key_id": row["key_id"]})
    if _hash(str(body.get("device_code", ""))) != row["device_code_hash"]:
        raise ValidationError("invalid device code")
    _check_exp(signed)
    consume_request_nonce(conn, key_id=str(row["key_id"]), nonce=str(signed.get("nonce", "")), issued_at=str(signed.get("issued_at", "")))
    if row["status"] == "ready_for_authorization":
        return {"error": "authorization_pending", "interval": 5}
    if row["status"] != "authorized":
        raise ConflictError(f"enrollment {row['status']}")
    if row["grant_expires_at"] <= now_iso():
        conn.execute("update enrollments set status='expired' where enrollment_id=?", (row["enrollment_id"],))
        raise ConflictError("enrollment grant expired")
    grant = _stable_grant(str(row["enrollment_id"]), str(row["device_code_hash"]))
    if not hmac.compare_digest(_hash(grant), str(row["grant_hash"])):
        raise ConflictError("enrollment grant state is invalid")
    return {"enrollment_id": row["enrollment_id"], "grant": grant,
            "catalog_agent_id": row["catalog_agent_id"], "merchant_id": row["merchant_id"],
            "runtime_origin": row["runtime_origin"],
            "a2a_endpoint": row["a2a_endpoint"], "binding": {"runtime_origin": row["runtime_origin"],
            "a2a_endpoint": row["a2a_endpoint"], "key_jwk": json.loads(row["key_jwk_json"]), "key_id": row["key_id"],
            "generation": int(row["generation"]), "service_epoch": int(row["service_epoch"])},
            "scopes": json.loads(row["scopes_json"]), "approved_card_digest": row["approved_card_digest"],
            "authorization_epoch": int(row["authorization_epoch"]), "expires_at": row["grant_expires_at"]}


def _check_exp(signed: dict[str, Any]) -> None:
    try:
        expiry = datetime.fromisoformat(str(signed.get("exp", "")))
        if expiry.tzinfo is None or expiry <= datetime.now(UTC) or expiry > datetime.now(UTC) + timedelta(minutes=2):
            raise ValidationError("signature expired or has excessive lifetime")
    except ValueError as exc:
        raise ValidationError("signature exp is missing or malformed") from exc
