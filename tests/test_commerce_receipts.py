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

"""买家识别与交易回执 · C1 独立回执入口测试。

覆盖：商家/买方/运营三类报告方凭据、事件类型×报告方白名单、字段限制、
幂等接收与同 ID 异内容冲突、乱序接收、双栈（FastAPI / fallback）一致性、
以及另一商家不可读取。
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import tempfile
import time
import unittest
from typing import Any
import unittest.mock

from kiwi_catalog.api import app as app_module
from kiwi_catalog.core.tokens import token_digest
from kiwi_catalog.db.session import open_connection


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _make_merchant_token(conn: sqlite3.Connection, merchant_id: str, token: str) -> None:
    conn.execute(
        "insert into merchant_tokens (merchant_id, token_hash, status, issued_at)"
        " values (?, ?, 'active', '2026-11-01T00:00:00+00:00')",
        (merchant_id, token_digest(token)),
    )
    conn.commit()


MERCHANT_TOKEN_A = "mka-test-token-0001"
MERCHANT_TOKEN_B = "mkb-test-token-0002"

INTENT_RECEIPT_MERCHANT = {
    "protocol_version": "1.0",
    "event_id": "evt-mrc-intent-1",
    "event_type": "merchant_agreement_issued",
    "merchant_id": "mkt-alpha",
    "negotiation_id": "neg-1",
    "merchant_agreement_id": "agr-1",
    "accepted_offer_id": "off-1",
    "terms_digest": "sha256:" + "a" * 64,
    "buyer_binding": "kiwi-inquiry-session-v1:buyerkey",
    "occurred_at": "2026-11-18T08:00:00+00:00",
}

INTENT_RECEIPT_BUYER = {
    "protocol_version": "1.0",
    "event_id": "evt-byr-intent-1",
    "event_type": "buyer_agreement_accepted",
    "merchant_id": "mkt-alpha",
    "negotiation_id": "neg-1",
    "merchant_agreement_id": "agr-1",
    "accepted_offer_id": "off-1",
    "terms_digest": "sha256:" + "a" * 64,
    "occurred_at": "2026-11-18T08:00:05+00:00",
}

ENTRY_RECEIPT_MERCHANT = {
    "protocol_version": "1.0",
    "event_id": "evt-mrc-entry-1",
    "event_type": "merchant_entry_offered",
    "merchant_id": "mkt-alpha",
    "entry_type": "quote_handoff",
    "quote_ref": {"negotiation_id": "neg-1", "offer_id": "off-1"},
    "occurred_at": "2026-11-18T07:00:00+00:00",
}

ORDER_RECEIPT = {
    "protocol_version": "1.0",
    "event_id": "evt-ord-1",
    "event_type": "merchant_order_created",
    "merchant_id": "mkt-alpha",
    "order_channel": "channel-x",
    "order_ref": "SO-100001",
    "order_evidence": {"merchant_agreement_ref": "agr-1"},
    "occurred_at": "2026-11-18T09:00:00+00:00",
}


class CommerceReceiptsTableTest(unittest.TestCase):
    def test_migration_registers_table_with_unique_idempotency_key(self) -> None:
        tmp = tempfile.mkdtemp()
        self.addCleanup(lambda: __import__("shutil").rmtree(tmp, ignore_errors=True))
        db = os.path.join(tmp, "catalog.sqlite")
        conn = open_connection(db)
        conn.close()
        conn = sqlite3.connect(db)
        columns = {
            str(row[1])
            for row in conn.execute("pragma table_info(commerce_receipts)")
        }
        indexes = {
            str(row[1])
            for row in conn.execute("pragma index_list(commerce_receipts)")
        }
        conn.close()
        self.assertIn("event_id", columns)
        self.assertIn("buyer_binding", columns)
        self.assertIn("content_hash", columns)
        self.assertIn("assurance", columns)
        unique_indexes = [
            name
            for name in indexes
            if name.startswith("sqlite_autoindex")
        ]
        self.assertTrue(unique_indexes)


class CommerceReceiptsSubmitTest(unittest.TestCase):
    """handler 级：凭据、类型白名单、字段限制、幂等与冲突、乱序。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        conn = open_connection(self.db_path)
        _make_merchant_token(conn, "mkt-alpha", MERCHANT_TOKEN_A)
        _make_merchant_token(conn, "mkt-beta", MERCHANT_TOKEN_B)
        conn.close()
        self.receipts = __import__(
            "kiwi_catalog.api.handlers.commerce_receipts",
            fromlist=["commerce_receipts"],
        )

    def _submit(self, payload: dict, token: str | None = None) -> dict:
        payload = dict(payload)
        if token is not None:
            payload["_auth_token"] = token
        return self.receipts.submit(self.db_path, payload)

    def test_merchant_intent_receipt_accepted_and_idempotent(self) -> None:
        first = self._submit(INTENT_RECEIPT_MERCHANT, token=MERCHANT_TOKEN_A)
        self.assertTrue(first["ok"])
        self.assertEqual(first["assurance"], "verified")
        self.assertEqual(first["reporter_role"], "merchant")
        replay = self._submit(INTENT_RECEIPT_MERCHANT, token=MERCHANT_TOKEN_A)
        self.assertTrue(replay.get("idempotent"))
        self.assertEqual(replay["event_id"], first["event_id"])

    def test_order_adapter_is_bound_to_merchant_and_channel(self) -> None:
        from kiwi_catalog.core.errors import AuthError

        token = "test-adapter-token"
        bindings = [{
            "adapter_id": "fixture", "token_digest": token_digest(token),
            "merchant_id": "mkt-alpha", "order_channel": "channel-x",
        }]
        receipt = {
            **ORDER_RECEIPT,
            "order_evidence": {"checkout_session_ref": "cs-1", "channel_evidence": "SO-100001"},
        }
        with unittest.mock.patch.dict(os.environ, {
            "KIWI_CATALOG_ORDER_ADAPTER_BINDINGS": json.dumps(bindings),
            "KIWI_CATALOG_ADMIN_TOKEN": "fixture-admin",
        }):
            self.assertEqual(self._submit(receipt, token=token)["assurance"], "adapter_delegated")
            with self.assertRaises(AuthError):
                self._submit({**receipt, "order_channel": "channel-y"}, token=token)
            with self.assertRaises(AuthError):
                self._submit({**receipt, "merchant_id": "mkt-beta"}, token=token)
            with self.assertRaises(AuthError):
                self._submit(receipt, token="fixture-admin")

    def test_same_event_id_with_different_content_conflicts(self) -> None:
        self._submit(INTENT_RECEIPT_MERCHANT, token=MERCHANT_TOKEN_A)
        mutated = dict(INTENT_RECEIPT_MERCHANT)
        mutated["terms_digest"] = "sha256:" + "b" * 64
        from kiwi_catalog.core.errors import IdempotencyConflict

        with self.assertRaises(IdempotencyConflict):
            self._submit(mutated, token=MERCHANT_TOKEN_A)

    def test_merchant_token_from_other_shop_is_rejected(self) -> None:
        from kiwi_catalog.core.errors import AuthError

        with self.assertRaises(AuthError):
            self._submit(INTENT_RECEIPT_MERCHANT, token=MERCHANT_TOKEN_B)

    def test_missing_credentials_rejected(self) -> None:
        from kiwi_catalog.core.errors import AuthError

        with self.assertRaises(AuthError):
            self._submit(INTENT_RECEIPT_MERCHANT)

    def test_buyer_cannot_report_merchant_event_types(self) -> None:
        from kiwi_catalog.core.errors import PermissionDenied

        receipt = dict(INTENT_RECEIPT_BUYER)
        receipt["event_type"] = "merchant_agreement_issued"
        receipt["buyer_binding"] = "kiwi-inquiry-session-v1:buyerkey"
        signed = self._sign_buyer_receipt(receipt)
        with self.assertRaises(PermissionDenied):
            self._submit(signed)

    def test_unknown_event_type_rejected(self) -> None:
        from kiwi_catalog.core.errors import ValidationError

        with self.assertRaises(ValidationError):
            self._submit(
                {**INTENT_RECEIPT_MERCHANT, "event_type": "click_event"},
                token=MERCHANT_TOKEN_A,
            )

    def test_unknown_fields_rejected(self) -> None:
        from kiwi_catalog.core.errors import ValidationError

        payload = {**INTENT_RECEIPT_MERCHANT, "chat_log": "应当留在交易双方"}
        with self.assertRaises(ValidationError):
            self._submit(payload, token=MERCHANT_TOKEN_A)

    def test_missing_required_intent_fields_rejected(self) -> None:
        from kiwi_catalog.core.errors import ValidationError

        payload = {
            key: value
            for key, value in INTENT_RECEIPT_MERCHANT.items()
            if key != "terms_digest"
        }
        with self.assertRaises(ValidationError):
            self._submit(payload, token=MERCHANT_TOKEN_A)

    def test_entry_receipt_without_agreement_number_accepted(self) -> None:
        result = self._submit(ENTRY_RECEIPT_MERCHANT, token=MERCHANT_TOKEN_A)
        self.assertTrue(result["ok"])
        self.assertEqual(result["event_type"], "merchant_entry_offered")

    def test_out_of_order_receipts_both_persisted(self) -> None:
        # 乱序：先收订单（时间晚），再收意向（时间早）——都保留，接收时间各自记录。
        order = self._submit(ORDER_RECEIPT, token=MERCHANT_TOKEN_A)
        intent = self._submit(INTENT_RECEIPT_MERCHANT, token=MERCHANT_TOKEN_A)
        self.assertTrue(order["ok"])
        self.assertTrue(intent["ok"])
        listed = self.receipts.list_receipts(
            self.db_path, {"_auth_token": MERCHANT_TOKEN_A}, {}
        )
        types = {item["event_type"] for item in listed["receipts"]}
        self.assertIn("merchant_order_created", types)
        self.assertIn("merchant_agreement_issued", types)

    def test_other_merchant_cannot_read(self) -> None:
        from kiwi_catalog.core.errors import AuthError

        self._submit(INTENT_RECEIPT_MERCHANT, token=MERCHANT_TOKEN_A)
        with self.assertRaises(AuthError):
            self.receipts.list_receipts(self.db_path, {"_auth_token": "no-such-token"}, {})
        other_shop = self.receipts.list_receipts(
            self.db_path, {"_auth_token": MERCHANT_TOKEN_B}, {}
        )
        self.assertEqual(other_shop["receipts"], [])

    def test_buyer_signed_receipt_accepted_with_self_signed_assurance(self) -> None:
        signed = self._sign_buyer_receipt(INTENT_RECEIPT_BUYER)
        result = self._submit(signed)
        self.assertTrue(result["ok"])
        self.assertEqual(result["reporter_role"], "buyer")
        self.assertEqual(result["assurance"], "self_signed")

    def test_buyer_signed_receipt_tampered_field_rejected(self) -> None:
        from kiwi_catalog.core.errors import PermissionDenied

        signed = self._sign_buyer_receipt(INTENT_RECEIPT_BUYER)
        tampered = dict(signed)
        tampered["terms_digest"] = "sha256:" + "c" * 64
        with self.assertRaises(PermissionDenied):
            self._submit(tampered)

    def test_buyer_receipt_outer_field_not_covered_by_signature_rejected(self) -> None:
        """外层出现签名未覆盖的字段 → 拒绝（防未签名副本混淆）。"""
        from kiwi_catalog.core.errors import ValidationError

        signed = self._sign_buyer_receipt(INTENT_RECEIPT_BUYER)
        payload = dict(signed)
        payload["extra_unsigned_field"] = "must not pass"
        with self.assertRaises(ValidationError):
            self._submit(payload)

    def _sign_buyer_receipt(self, receipt: dict, key_seed: bytes | None = None) -> dict:
        """构造自包含 EdDSA JWS（载荷=回执字段 + jwk + issued_at）。"""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from kiwi_catalog.a2a.binding_claims import jwk_thumbprint

        seed = key_seed or hashlib.sha256(b"k1-buyer-receipt-test").digest()
        key = Ed25519PrivateKey.from_private_bytes(seed)
        pub = key.public_key().public_bytes_raw()
        jwk = {"kty": "OKP", "crv": "Ed25519", "x": _b64url(pub)}
        kid = jwk_thumbprint(jwk)
        payload = {
            **receipt,
            "jwk": jwk,
            "key_id": kid,
            "issued_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
        }
        header = {"alg": "EdDSA", "kid": kid}
        header_segment = _b64url(
            json.dumps(header, separators=(",", ":")).encode()
        )
        payload_segment = _b64url(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        )
        signature = key.sign(f"{header_segment}.{payload_segment}".encode("ascii"))
        jws = f"{header_segment}.{payload_segment}.{_b64url(signature)}"
        return {**receipt, "buyer_signature": jws}


@unittest.skipIf(app_module.FastAPI is None, "fastapi not installed")
class CommerceReceiptsDualStackTest(unittest.TestCase):
    """B6 两套 HTTP 栈一致性：鉴权、类型限制、幂等与投影一致。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        conn = open_connection(self.db_path)
        _make_merchant_token(conn, "mkt-alpha", MERCHANT_TOKEN_A)
        conn.close()
        self.fastapi_app = app_module.create_catalog_app(self.db_path)
        with unittest.mock.patch.object(app_module, "FastAPI", None):
            self.fallback_app = app_module.create_catalog_app(self.db_path)

    def _call_asgi(self, app: Any, method: str, path: str, body: dict, token: str | None = None) -> tuple[int, dict]:
        """同一 ASGI 调用器驱动两栈（不依赖 httpx；FastAPI app 本身即 ASGI）。"""
        import asyncio

        received: list[dict] = []

        async def receive():
            return {"type": "http.request", "body": json.dumps(body).encode(), "more_body": False}

        async def send(msg: dict) -> None:
            received.append(msg)

        headers = [(b"content-type", b"application/json")]
        if token:
            headers.append((b"authorization", f"Bearer {token}".encode()))
        scope = {
            "type": "http",
            "method": method,
            "path": path,
            "headers": headers,
            "query_string": b"",
            "http_version": "1.1",
            "scheme": "http",
            "server": ("testserver", 80),
            "client": ("127.0.0.1", 12345),
        }

        async def invoke():
            await app(scope, receive, send)

        asyncio.run(invoke())
        start = next(m for m in received if m["type"] == "http.response.start")
        chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
        return start["status"], json.loads(chunks.decode() or "{}")

    def _call_fallback(self, method: str, path: str, body: dict, token: str | None = None) -> tuple[int, dict]:
        return self._call_asgi(self.fallback_app, method, path, body, token)

    def _call_fastapi(self, method: str, path: str, body: dict, token: str | None = None) -> tuple[int, dict]:
        return self._call_asgi(self.fastapi_app, method, path, body, token)

    def test_both_stacks_accept_and_replay_identically(self) -> None:
        for stack_call in (self._call_fastapi, self._call_fallback):
            status, body = stack_call(
                "POST", "/v1/commerce/receipts", INTENT_RECEIPT_MERCHANT, token=MERCHANT_TOKEN_A
            )
            self.assertEqual(status, 200, body)
            self.assertEqual(body["event_type"], "merchant_agreement_issued")
            status, body = stack_call(
                "POST", "/v1/commerce/receipts", INTENT_RECEIPT_MERCHANT, token=MERCHANT_TOKEN_A
            )
            self.assertEqual(status, 200, body)
            self.assertTrue(body.get("idempotent"))

    def test_both_stacks_reject_same_id_different_content(self) -> None:
        self._call_fallback("POST", "/v1/commerce/receipts", INTENT_RECEIPT_MERCHANT, token=MERCHANT_TOKEN_A)
        mutated = {**INTENT_RECEIPT_MERCHANT, "accepted_offer_id": "off-9"}
        for stack_call in (self._call_fastapi, self._call_fallback):
            status, body = stack_call("POST", "/v1/commerce/receipts", mutated, token=MERCHANT_TOKEN_A)
            self.assertEqual(status, 409, body)
            self.assertIn("error", body)

    def test_both_stacks_enforce_type_whitelist(self) -> None:
        # 商家 token 不能上报买方事件类型（类型 × 报告方白名单，403 先于字段校验）。
        for stack_call in (self._call_fastapi, self._call_fallback):
            status, _ = stack_call(
                "POST",
                "/v1/commerce/receipts",
                {**INTENT_RECEIPT_MERCHANT, "event_type": "buyer_agreement_accepted"},
                token=MERCHANT_TOKEN_A,
            )
            self.assertEqual(status, 403)

    def test_public_page_has_no_receipt_projection(self) -> None:
        # 公开路由表不暴露逐笔回执：匿名读取回执路径必须 403/404。
        status, _ = self._call_fallback("GET", "/v1/commerce/receipts", {})
        self.assertIn(status, (403, 404))
        status, _ = self._call_fallback("GET", "/v1/commerce/receipts?merchant_id=mkt-alpha", {})
        self.assertIn(status, (403, 404))


if __name__ == "__main__":
    unittest.main()
