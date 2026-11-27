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

"""买家识别与交易回执 · C1：独立回执入口。

业务事实的产生方（商家 / 买方 agent）主动报告：意向、入口、订单三类事件。
与 public_inquiry 的纯转发边界相反——本入口在服务端验证报告方凭据后持久化。

鉴权与保障级别：
- 商家：Authorization Bearer 的 merchant token（token 即身份，绑定该店）；
  merchant_id 由服务端从凭据解析，不信任正文自报。
- 买方：自包含 EdDSA JWS（``buyer_signature``，compact，嵌入 JWK）——
  自签公钥单独标明保障级别 ``self_signed``；签名覆盖全部回执字段，
  服务端以签名载荷为准，外层同名字段必须一致（防未签名副本混淆）。
- 订单适配器（order_adapter）：需获授权代表商家与渠道；首版仅接受
  运营侧 admin token 协助登记，assurance 记 ``adapter_delegated``。

幂等：按（已验证报告方, 事件 ID）唯一；相同 ID 相同内容幂等返回原结果，
相同 ID 不同内容记 409 冲突。允许迟到与乱序——接收时间由服务端单独记录。

隐私：逐笔回执只对参与方（商家 token / 运营 admin）可见；公开页面与
公开查询不投影本表。
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kiwi_catalog.services import commerce_facts
from kiwi_catalog.api import auth as api_auth
from kiwi_catalog.core.tokens import token_digest
from kiwi_catalog.core.errors import AuthError, IdempotencyConflict, PermissionDenied, ValidationError
from kiwi_catalog.db.session import db_session, now_iso
from kiwi_catalog.services import merchant_tokens as tokens_service

PROTOCOL_VERSION = "1.0"

_INTENT_EVENT_TYPES = ("merchant_agreement_issued", "buyer_agreement_accepted")
_ENTRY_EVENT_TYPES = ("merchant_entry_offered", "buyer_handoff_generated")
_ORDER_EVENT_TYPES = ("merchant_order_created",)
_EVENT_TYPES = _INTENT_EVENT_TYPES + _ENTRY_EVENT_TYPES + _ORDER_EVENT_TYPES

# 事件类型 × 报告方白名单：入口、点击、交接授权、订单即使携带相同协议号，
# 也不能补任一侧的意向证据——来源由类型硬约束（设计 §3 意向判定）。
_EVENT_TYPE_BY_ROLE: dict[str, tuple[str, ...]] = {
    "merchant": ("merchant_agreement_issued", "merchant_entry_offered", "merchant_order_created"),
    "buyer": ("buyer_agreement_accepted", "buyer_handoff_generated"),
    "order_adapter": ("merchant_order_created",),
}

_ENTRY_TYPES = ("quote_handoff", "handoff_record")

# 严格字段白名单：逐事件类型定形，多余字段直接 400（不接受自由扩展）。
_COMMON_FIELDS = ("protocol_version", "event_id", "event_type", "merchant_id", "occurred_at")
_INTENT_FIELDS = _COMMON_FIELDS + ("negotiation_id", "merchant_agreement_id", "accepted_offer_id", "terms_digest")
_ENTRY_FIELDS = _COMMON_FIELDS + ("entry_type", "quote_ref", "handoff_ref")
_ORDER_FIELDS = _COMMON_FIELDS + ("order_channel", "order_ref", "order_evidence")

# 逐类型必填字段（意图六元组 + 入口引用 + 渠道订单引用）。
_REQUIRED_BY_TYPE: dict[str, tuple[str, ...]] = {
    "merchant_agreement_issued": _INTENT_FIELDS + ("buyer_binding",),
    "buyer_agreement_accepted": _INTENT_FIELDS,
    "merchant_entry_offered": _COMMON_FIELDS + ("entry_type", "quote_ref"),
    "buyer_handoff_generated": _COMMON_FIELDS + ("entry_type", "quote_ref", "handoff_ref"),
    "merchant_order_created": _COMMON_FIELDS + ("order_channel", "order_ref", "order_evidence"),
}

_QUOTE_REF_FIELDS = ("negotiation_id", "offer_id", "terms_digest")
_ORDER_EVIDENCE_FIELDS = ("merchant_agreement_ref", "checkout_session_ref", "channel_evidence")

_MAX_STRING = 256


def _require_str(value: Any, field: str, *, max_len: int = _MAX_STRING) -> str:
    if not isinstance(value, str) or value.strip() == "":
        raise ValidationError(f"{field} must be a non-empty string")
    if len(value) > max_len:
        raise ValidationError(f"{field} exceeds {max_len} characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValidationError(f"{field} contains control characters")
    return value.strip()


def _require_iso(value: Any, field: str) -> str:
    text = _require_str(value, field, max_len=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field} is not an ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{field} must carry a timezone")
    return text


def _require_small_object(value: Any, field: str, allowed_keys: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(value, dict) or not value:
        raise ValidationError(f"{field} must be a non-empty object")
    unknown = sorted(set(str(key) for key in value) - set(allowed_keys))
    if unknown:
        raise ValidationError(f"{field} has unsupported keys: {', '.join(unknown)}")
    return {str(key): value[key] for key in sorted(value)}


def _canonical_hash(fields: dict[str, Any]) -> str:
    canonical = json.dumps(fields, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _public_key_from_jwk(jwk: dict[str, Any]) -> Any:
    """仅支持 Ed25519 OKP（与 buyer 开放询价凭据一致）。"""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise PermissionDenied("buyer receipt JWK must be an Ed25519 OKP key")
    x = jwk.get("x")
    if not isinstance(x, str) or x == "":
        raise PermissionDenied("buyer receipt JWK missing x")
    try:
        raw = _b64url_decode(x)
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception as exc:  # noqa: BLE001 - 畸形 JWK 统一 403
        raise PermissionDenied("malformed buyer receipt JWK") from exc


def _verify_buyer_receipt_signature(
    jws: str,
    expected_fields: dict[str, Any],
) -> dict[str, Any]:
    """自包含买方回执签名：compact JWS，载荷即回执字段 + jwk + issued_at。

    kid 必须等于嵌入公钥的 RFC 7638 thumbprint（自证密钥）；时钟偏移 ±300s。
    返回签名载荷（服务端以此为准）。
    """
    from cryptography.exceptions import InvalidSignature

    from kiwi_catalog.a2a.binding_claims import jwk_thumbprint

    if not isinstance(jws, str) or jws.count(".") != 2:
        raise PermissionDenied("buyer receipt signature must be a compact JWS")
    header_segment, payload_segment, signature_segment = jws.split(".")
    try:
        header = json.loads(_b64url_decode(header_segment))
        payload = json.loads(_b64url_decode(payload_segment))
    except (ValueError, TypeError) as exc:
        raise PermissionDenied("malformed buyer receipt signature") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise PermissionDenied("malformed buyer receipt signature")
    if header.get("alg") != "EdDSA":
        raise PermissionDenied(f"unsupported buyer receipt alg: {header.get('alg')!r}")
    public_jwk = payload.get("jwk")
    if not isinstance(public_jwk, dict):
        raise PermissionDenied("buyer receipt signature payload missing jwk")
    public_key = _public_key_from_jwk(public_jwk)
    thumbprint = jwk_thumbprint(public_jwk)
    if str(header.get("kid", "")) != thumbprint:
        raise PermissionDenied("buyer receipt kid does not match the embedded key thumbprint")
    try:
        public_key.verify(
            _b64url_decode(signature_segment),
            f"{header_segment}.{payload_segment}".encode("ascii"),
        )
    except InvalidSignature as exc:
        raise PermissionDenied("buyer receipt signature verification failed") from exc
    for field, actual in expected_fields.items():
        if field not in payload:
            raise ValidationError(f"buyer receipt signature does not cover required field: {field}")
        if json.dumps(payload[field], sort_keys=True) != json.dumps(actual, sort_keys=True):
            raise PermissionDenied(f"buyer receipt signature field mismatch: {field}")
    issued_at = str(payload.get("issued_at", ""))
    try:
        issued = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("buyer receipt signature issued_at is malformed") from exc
    if issued.tzinfo is None:
        issued = issued.replace(tzinfo=timezone.utc)
    skew = abs((datetime.now(timezone.utc) - issued).total_seconds())
    if skew > 300:
        raise PermissionDenied("buyer receipt signature outside the clock skew window")
    return payload


def _scoped_order_adapter(bearer: str, payload: dict[str, Any]) -> str | None:
    """Only an explicitly delegated merchant/channel pair can attest checkout provenance."""
    try:
        bindings = json.loads(os.environ.get("KIWI_CATALOG_ORDER_ADAPTER_BINDINGS", "[]"))
    except (TypeError, ValueError):
        return None
    if not isinstance(bindings, list) or payload.get("event_type") != "merchant_order_created":
        return None
    digest = token_digest(bearer)
    for binding in bindings:
        if not isinstance(binding, dict):
            continue
        expected = binding.get("token_digest")
        adapter_id = binding.get("adapter_id")
        if (
            isinstance(expected, str) and expected.isascii()
            and isinstance(adapter_id, str) and bool(adapter_id.strip())
            and binding.get("merchant_id") == payload.get("merchant_id")
            and binding.get("order_channel") == payload.get("order_channel")
            and hmac.compare_digest(digest, expected)
        ):
            return adapter_id
    return None


def _resolve_reporter(
    conn: sqlite3.Connection, payload: dict[str, Any]
) -> tuple[str, str, str, dict[str, Any]]:
    """解析报告方凭据 → (reporter_role, reporter_identity, assurance, receipt_body)。

    买方路径：签名载荷即回执正文（外层同名字段必须一致，见 submit）。
    """
    from kiwi_catalog.a2a.binding_claims import jwk_thumbprint

    bearer = str(payload.get("_auth_token") or "").strip()
    buyer_signature = payload.get("buyer_signature")
    if isinstance(buyer_signature, str) and buyer_signature.strip() != "":
        if bearer:
            raise ValidationError("submit either a merchant token or a buyer signature, not both")
        signed_payload = _verify_buyer_receipt_signature(
            buyer_signature,
            {
                key: value
                for key, value in payload.items()
                if key != "buyer_signature"
                and key not in _TRANSPORT_RESERVED_KEYS
                and not str(key).startswith("_")
            },
        )
        thumbprint = jwk_thumbprint(signed_payload["jwk"])
        receipt_body = {
            key: value
            for key, value in signed_payload.items()
            if key not in ("jwk", "issued_at", "key_id")
        }
        return ("buyer", f"buyer:{thumbprint}", "self_signed", receipt_body)

    if bearer:
        token_row = tokens_service.resolve_merchant_by_token(conn, bearer)
        if token_row is not None:
            merchant_id = str(token_row["merchant_id"])
            return ("merchant", f"merchant_token:{merchant_id}", "verified", payload)
        adapter_id = _scoped_order_adapter(bearer, payload)
        if adapter_id is not None:
            return ("order_adapter", f"order_adapter:{adapter_id}", "adapter_delegated", payload)
    raise AuthError("invalid commerce receipt credential")


def _validate_receipt_fields(
    reporter_role: str,
    receipt: dict[str, Any],
) -> dict[str, Any]:
    """事件类型 × 报告方白名单 + 严格字段集 + 必填约束。返回规范化字段。"""
    event_type = _require_str(receipt.get("event_type"), "event_type", max_len=64)
    if event_type not in _EVENT_TYPES:
        raise ValidationError(f"unknown receipt event_type: {event_type}")
    allowed_for_role = _EVENT_TYPE_BY_ROLE.get(reporter_role, ())
    if event_type not in allowed_for_role:
        raise PermissionDenied(f"reporter role {reporter_role} may not report {event_type}")

    allowed = set(_REQUIRED_BY_TYPE[event_type])
    unknown = sorted(set(str(key) for key in receipt) - allowed)
    if unknown:
        raise ValidationError(f"receipt has unsupported fields: {', '.join(unknown)}")
    for field in _REQUIRED_BY_TYPE[event_type]:
        if field not in receipt:
            raise ValidationError(f"receipt missing required field: {field}")

    normalized: dict[str, Any] = {
        "protocol_version": PROTOCOL_VERSION,
        "event_id": _require_str(receipt.get("event_id"), "event_id", max_len=128),
        "event_type": event_type,
        "merchant_id": _require_str(receipt.get("merchant_id"), "merchant_id", max_len=128),
        "occurred_at": _require_iso(receipt.get("occurred_at"), "occurred_at"),
    }
    presented_protocol = receipt.get("protocol_version")
    if presented_protocol != PROTOCOL_VERSION:
        raise ValidationError(f"unsupported receipt protocol_version: {presented_protocol}")

    if event_type in _INTENT_EVENT_TYPES:
        normalized["negotiation_id"] = _require_str(receipt.get("negotiation_id"), "negotiation_id", max_len=128)
        normalized["merchant_agreement_id"] = _require_str(
            receipt.get("merchant_agreement_id"), "merchant_agreement_id", max_len=128
        )
        normalized["accepted_offer_id"] = _require_str(
            receipt.get("accepted_offer_id"), "accepted_offer_id", max_len=128
        )
        normalized["terms_digest"] = _require_str(receipt.get("terms_digest"), "terms_digest", max_len=128)
        # 买方回执的凭据绑定即其签名钥指纹（服务端从签名解析）；商家回执
        # 须显式携带该次已验签买方的公钥指纹（只用于本笔对账）。
        if event_type == "merchant_agreement_issued":
            normalized["buyer_binding"] = _require_str(
                receipt.get("buyer_binding"), "buyer_binding", max_len=256
            )
        else:
            normalized["buyer_binding"] = ""

    if event_type in _ENTRY_EVENT_TYPES:
        entry_type = _require_str(receipt.get("entry_type"), "entry_type", max_len=64)
        if entry_type not in _ENTRY_TYPES:
            raise ValidationError(f"unknown entry_type: {entry_type}")
        normalized["entry_type"] = entry_type
        quote_ref = _require_small_object(receipt.get("quote_ref"), "quote_ref", _QUOTE_REF_FIELDS)
        for ref_field in ("negotiation_id", "offer_id"):
            if ref_field not in quote_ref:
                raise ValidationError(f"quote_ref missing required field: {ref_field}")
            _require_str(quote_ref[ref_field], f"quote_ref/{ref_field}", max_len=128)
        if "terms_digest" in quote_ref:
            _require_str(quote_ref["terms_digest"], "quote_ref/terms_digest", max_len=128)
        normalized["quote_ref"] = quote_ref
        if event_type == "buyer_handoff_generated":
            normalized["handoff_ref"] = _require_str(receipt.get("handoff_ref"), "handoff_ref", max_len=128)
        else:
            handoff_ref = receipt.get("handoff_ref")
            normalized["handoff_ref"] = (
                _require_str(handoff_ref, "handoff_ref", max_len=128) if handoff_ref is not None else ""
            )

    if event_type in _ORDER_EVENT_TYPES:
        normalized["order_channel"] = _require_str(receipt.get("order_channel"), "order_channel", max_len=128)
        normalized["order_ref"] = _require_str(receipt.get("order_ref"), "order_ref", max_len=128)
        evidence = _require_small_object(receipt.get("order_evidence"), "order_evidence", _ORDER_EVIDENCE_FIELDS)
        if "merchant_agreement_ref" not in evidence and "checkout_session_ref" not in evidence:
            raise ValidationError(
                "order_evidence must carry a verifiable merchant_agreement_ref or checkout_session_ref"
            )
        normalized["order_evidence"] = {
            key: _require_str(value, f"order_evidence/{key}", max_len=256)
            for key, value in evidence.items()
        }
        if reporter_role == "order_adapter" and "channel_evidence" not in evidence:
            raise ValidationError("scoped adapter receipt requires channel_evidence")

    return normalized


def _receipt_projection(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "event_id": row["event_id"],
        "event_type": row["event_type"],
        "reporter_role": row["reporter_role"],
        "merchant_id": row["merchant_id"],
        "negotiation_id": row["negotiation_id"],
        "merchant_agreement_id": row["merchant_agreement_id"],
        "accepted_offer_id": row["accepted_offer_id"],
        "terms_digest": row["terms_digest"],
        "buyer_binding": row["buyer_binding"],
        "entry_type": row["entry_type"],
        "quote_ref": json.loads(row["quote_ref_json"]),
        "handoff_ref": row["handoff_ref"],
        "order_channel": row["order_channel"],
        "order_ref": row["order_ref"],
        "order_evidence": json.loads(row["order_evidence_json"]),
        "occurred_at": row["occurred_at"],
        "received_at": row["received_at"],
        "assurance": row["assurance"],
    }


# 传输层保留键：不参与回执字段校验（凭据/来源 IP/幂等键由传输注入）。
_TRANSPORT_RESERVED_KEYS = ("_auth_token", "_client_ip", "_cookie", "_buyer_id", "_buyer_source", "idempotency_key")


def _strip_transport_keys(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in payload.items()
        if key not in _TRANSPORT_RESERVED_KEYS and not str(key).startswith("_")
    }


def submit(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    """POST /v1/commerce/receipts：验报告方凭据 → 严格字段校验 → 幂等接收。"""
    if not isinstance(payload, dict):
        raise ValidationError("receipt payload must be an object")

    with db_session(db_path) as conn:
        reporter_role, reporter_identity, assurance, receipt_body = _resolve_reporter(conn, payload)

        receipt = _validate_receipt_fields(reporter_role, _strip_transport_keys(receipt_body))
        merchant_id = receipt["merchant_id"]
        if reporter_role == "merchant":
            # token 即身份：正文商家必须与凭据归属一致（不匹配按不存在处理）。
            token_merchant = reporter_identity.split(":", 1)[1]
            if merchant_id != token_merchant:
                raise AuthError("invalid merchant token")
        if reporter_role == "buyer" and receipt.get("event_type") in _INTENT_EVENT_TYPES:
            # 买方回执的凭据绑定 = 其签名钥指纹（服务端从签名解析，不可自报）。
            receipt["buyer_binding"] = reporter_identity.split(":", 1)[1]

        content_hash = _canonical_hash(receipt)
        received_at = now_iso()
        try:
            conn.execute(
                """insert into commerce_receipts(
                        protocol_version, event_id, event_type, reporter_role, merchant_id,
                        negotiation_id, merchant_agreement_id, accepted_offer_id, terms_digest,
                        buyer_binding, entry_type, quote_ref_json, handoff_ref,
                        order_channel, order_ref, order_evidence_json,
                        occurred_at, received_at, reporter_identity, assurance,
                        content_hash, payload_json, created_at)
                    values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    receipt["protocol_version"],
                    receipt["event_id"],
                    receipt["event_type"],
                    reporter_role,
                    merchant_id,
                    receipt.get("negotiation_id") or receipt.get("quote_ref", {}).get("negotiation_id", "").strip(),
                    receipt.get("merchant_agreement_id", ""),
                    receipt.get("accepted_offer_id", ""),
                    receipt.get("terms_digest", ""),
                    receipt.get("buyer_binding", ""),
                    receipt.get("entry_type", ""),
                    json.dumps(receipt.get("quote_ref", {}), ensure_ascii=False, sort_keys=True),
                    receipt.get("handoff_ref", ""),
                    receipt.get("order_channel", ""),
                    receipt.get("order_ref", ""),
                    json.dumps(receipt.get("order_evidence", {}), ensure_ascii=False, sort_keys=True),
                    receipt["occurred_at"],
                    received_at,
                    reporter_identity,
                    assurance,
                    content_hash,
                    json.dumps(receipt, ensure_ascii=False, sort_keys=True),
                    received_at,
                ),
            )
        except sqlite3.IntegrityError:
            # 并发同 ID：回读比对内容——同内容幂等，异内容冲突。
            row = conn.execute(
                """select * from commerce_receipts
                    where merchant_id = ? and reporter_role = ? and reporter_identity = ? and event_id = ?""",
                (merchant_id, reporter_role, reporter_identity, receipt["event_id"]),
            ).fetchone()
            if row is None:
                raise
            if str(row["content_hash"]) != content_hash:
                raise IdempotencyConflict(
                    "receipt event_id already reported with different content"
                ) from None
            return {**_receipt_projection(row), "idempotent": True}

        commerce_facts.refresh_receipt(conn, conn.execute("select last_insert_rowid()").fetchone()[0])
        return {
            "ok": True,
            "event_id": receipt["event_id"],
            "event_type": receipt["event_type"],
            "merchant_id": merchant_id,
            "reporter_role": reporter_role,
            "assurance": assurance,
            "received_at": received_at,
        }


def query_facts(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/commerce/facts：独立计算意向/入口/订单事实（C2，只读投影）。

    merchant token 只读本店事实；admin 全量（可按 merchant_id 过滤）。
    另一商家无法读取本店事实（B3 访问控制同逐笔回执）。
    ``cursor`` 只定位当前页面，不固定跨页快照；并发回执可能在已扫游标之前
    新增或替换事实。不要将跨页求和用于最终对账，须在写入静止时完整读取。
    """

    bearer = str(payload.get("_auth_token") or "").strip()
    with db_session(db_path) as conn:
        is_admin = False
        try:
            api_auth.require_admin_token(payload, db_path)
            is_admin = True
        except Exception:  # noqa: BLE001
            is_admin = False
        merchant_filter = str(query.get("merchant_id") or "").strip()
        if is_admin:
            scope = merchant_filter or None
        else:
            if not bearer:
                raise AuthError("invalid merchant token")
            token_row = tokens_service.resolve_merchant_by_token(conn, bearer)
            if token_row is None:
                raise AuthError("invalid merchant token")
            if merchant_filter and merchant_filter != str(token_row["merchant_id"]):
                # 越权读取另一商家事实按不存在处理（404 语义一致地拒绝）。
                raise AuthError("invalid merchant token")
            scope = str(token_row["merchant_id"])
        return commerce_facts.query_facts(conn, query, scope)


def list_receipts(
    db_path: str | Path, payload: dict[str, Any], query: dict[str, Any]
) -> dict[str, Any]:
    """GET /v1/commerce/receipts：逐笔回执只对参与方与运营可见。

    merchant token → 仅本店；admin token → 全量（可按 merchant_id 过滤）。
    买方（自签）不在首版查询面内——避免以自签凭据枚举他人交易。
    """
    bearer = str(payload.get("_auth_token") or "").strip()
    with db_session(db_path) as conn:
        is_admin = False
        try:
            api_auth.require_admin_token(payload, db_path)
            is_admin = True
        except Exception:  # noqa: BLE001
            is_admin = False

        filters: list[str] = []
        params: list[Any] = []
        if is_admin:
            merchant_filter = str(query.get("merchant_id") or "").strip()
            if merchant_filter:
                filters.append("merchant_id = ?")
                params.append(merchant_filter)
        else:
            if not bearer:
                raise AuthError("invalid merchant token")
            token_row = tokens_service.resolve_merchant_by_token(conn, bearer)
            if token_row is None:
                raise AuthError("invalid merchant token")
            filters.append("merchant_id = ?")
            params.append(str(token_row["merchant_id"]))

        negotiation_filter = str(query.get("negotiation_id") or "").strip()
        if negotiation_filter:
            filters.append("negotiation_id = ?")
            params.append(negotiation_filter)
        event_filter = str(query.get("event_type") or "").strip()
        if event_filter:
            if event_filter not in _EVENT_TYPES:
                raise ValidationError(f"unknown event_type filter: {event_filter}")
            filters.append("event_type = ?")
            params.append(event_filter)

        limit_raw = str(query.get("limit") or "200").strip()
        try:
            limit = max(1, min(int(limit_raw), 1000))
        except ValueError as exc:
            raise ValidationError("limit must be an integer") from exc

        where = f"where {' and '.join(filters)}" if filters else ""
        rows = conn.execute(
            f"select * from commerce_receipts {where} order by received_at desc, receipt_id desc limit ?",
            (*params, limit),
        ).fetchall()
        return {
            "ok": True,
            "receipts": [_receipt_projection(row) for row in rows],
            "total": len(rows),
        }
