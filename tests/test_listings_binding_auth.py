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

"""Binding-signed listing publish API tests with real Ed25519 JWS proofs."""

from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
import uuid
from datetime import UTC, datetime, timedelta
from unittest import mock

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from kiwi_catalog.a2a.binding_claims import jwk_thumbprint
from kiwi_catalog.a2a.enrollment_canonical import canonical_digest
from kiwi_catalog.agent_catalog.sqlite_repository import new_catalog_agent_id, upsert_catalog_agent
from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.core.tokens import token_digest
from kiwi_catalog.db.session import db_session, now_iso
from kiwi_catalog.listings.contracts import validate_publish_payload


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _call_route(
    app, method: str, path: str, body: dict | None = None, signature: str = "",
    idempotency_key: str = "", query_string: str = "",
):
    raw = json.dumps(body or {}, ensure_ascii=False).encode("utf-8") if method != "GET" else b""
    headers = [
        (b"content-type", b"application/json"),
    ]
    if signature:
        headers.append((b"x-kiwi-binding-jws", signature.encode("ascii")))
    if idempotency_key:
        headers.append((b"idempotency-key", idempotency_key.encode("ascii")))
    received: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": raw, "more_body": False}

    async def send(message: dict) -> None:
        received.append(message)

    import asyncio

    asyncio.run(app({
        "type": "http", "method": method, "path": path,
        "headers": headers, "query_string": query_string.encode("ascii"),
        "http_version": "1.1", "scheme": "https",
    }, receive, send))
    start = next(item for item in received if item["type"] == "http.response.start")
    raw_response = b"".join(item.get("body", b"") for item in received if item["type"] == "http.response.body")
    return int(start["status"]), json.loads(raw_response.decode("utf-8")) if raw_response else {}


def _call(app, body: dict, signature: str, idempotency_key: str):
    return _call_route(app, "POST", "/v1/listings/publish", body, signature, idempotency_key)


class ListingsBindingAuthTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        patcher = mock.patch.dict(os.environ, {"KIWI_CATALOG_OWNER_TOKEN_SECRET": "listing-binding-test-secret"})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.app = create_catalog_app(self.db_path)
        self.merchant_id = "mkt_listing_binding"
        self.agent_id = new_catalog_agent_id()
        private_key = Ed25519PrivateKey.generate()
        self.private_key = private_key
        self.key_id = "runtime-listing-key-1"
        self.key_jwk = {
            "kty": "OKP", "crv": "Ed25519",
            "x": _b64url(private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
        }
        self.binding_id = "binding_listing_1"
        self.enrollment_id = "enr_listing_1"
        self.owner_token = "mkt_random_owner_token_for_test"
        now = now_iso()
        with db_session(self.db_path) as conn:
            conn.execute(
                "insert into merchant_accounts (email,password_hash,email_verified,merchant_name,merchant_id,created_at,updated_at)"
                " values (?,'test',1,'Listing Binding Merchant',?,?,?)",
                ("owner@example.test", self.merchant_id, now, now),
            )
            conn.execute(
                "insert into merchant_listing_entitlements (merchant_id,plan_code,status,updated_at)"
                " values (?,'free','active',?)", (self.merchant_id, now),
            )
            upsert_catalog_agent(
                conn, self.agent_id, merchant_id=self.merchant_id,
                display_name="Listing Binding Merchant", canonical_domain="merchant.example",
            )
            conn.execute(
                "insert into runtime_bindings (binding_id,catalog_agent_id,merchant_id,runtime_origin,"
                "a2a_endpoint,key_id,key_thumbprint,key_jwk_json,binding_version,service_epoch,status,"
                "expires_at,created_at,updated_at) values(?,?,?,?,?,?,?,?,1,1,'active','','','')",
                (self.binding_id, self.agent_id, self.merchant_id, "https://merchant.example",
                 "https://merchant.example/a2a", self.key_id, jwk_thumbprint(self.key_jwk),
                 json.dumps(self.key_jwk, separators=(",", ":"))),
            )
            conn.execute(
                "insert into enrollments (enrollment_id,device_code_hash,user_code,status,key_id,key_thumbprint,"
                "key_jwk_json,runtime_origin,a2a_endpoint,public_preview_json,generation,service_epoch,"
                "merchant_id,catalog_agent_id,scopes_json,expected_binding_version,authorization_epoch,"
                "binding_id,created_at,expires_at,grant_expires_at,authorized_at,consumed_at)"
                " values(?,?,?,'published',?,?,?,?,?,?,?,?,?,?,?,1,1,?,?,?,'','','')",
                (self.enrollment_id, "test-device-hash", "AB12CD34", self.key_id,
                 jwk_thumbprint(self.key_jwk), json.dumps(self.key_jwk), "https://merchant.example",
                 "https://merchant.example/a2a", "{}", 1, 1, self.merchant_id, self.agent_id,
                 '["runtime:bind","card:publish","heartbeat"]', self.binding_id, now, now),
            )
            conn.execute(
                "insert into merchant_tokens (merchant_id,token_hash,token_encrypted,status,issued_at)"
                " values(?,?,?,'active',?)",
                (self.merchant_id, token_digest(self.owner_token), "", now),
            )
            conn.execute(
                "insert into merchant_applications (status,domain,agent_name,contact_email,merchant_id,created_at,reviewed_at)"
                " values('approved','merchant.example','Listing Binding Merchant','owner@example.test',?,?,?)",
                (self.merchant_id, now, now),
            )

    def _body(self, **overrides) -> dict:
        return {
            "listing_type": "product", "owner_agent_id": self.agent_id,
            "merchant_id": self.merchant_id, "source_product_ref": "SKU-APPROVED-1",
            "title": "Approved binding listing", "category": "industrial-display",
            "brand": "Example", "attributes": {"size": "21.5"},
            "regions": ["CN"], "tags": ["touch"],
            "commercial_hints": {"moq": 1},
            "handoff_destination_types": ["external_checkout_url"],
            **overrides,
        }

    def _signature(self, body: dict, idempotency_key: str, *, key=None, kid: str | None = None,
                   binding_id: str | None = None, merchant_id: str | None = None,
                   exp: str | None = None, nonce: str | None = None,
                   digest_body: dict | None = None) -> str:
        canonical = validate_publish_payload(digest_body if digest_body is not None else body)
        claims = {
            "method": "POST", "path": "/v1/listings/publish", "audience": "kiwi-catalog",
            "agent_id": self.agent_id, "merchant_id": merchant_id or self.merchant_id,
            "binding_id": binding_id or self.binding_id, "key_id": kid or self.key_id,
            "listing_digest": canonical_digest(canonical), "idempotency_key": idempotency_key,
            "issued_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
            "exp": exp or (datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=90)).isoformat(),
            "nonce": nonce or f"nonce-{uuid.uuid4().hex}",
        }
        return self._compact_jws(claims, key=key or self.private_key, kid=kid or self.key_id)

    def _compact_jws(self, claims: dict, *, key=None, kid: str | None = None) -> str:
        header = {"alg": "EdDSA", "kid": kid or self.key_id}
        header_part = _b64url(json.dumps(header, separators=(",", ":")).encode())
        payload_part = _b64url(json.dumps(claims, ensure_ascii=False, separators=(",", ":")).encode())
        signature = (key or self.private_key).sign(f"{header_part}.{payload_part}".encode("ascii"))
        return f"{header_part}.{payload_part}.{_b64url(signature)}"

    def _publish(self, body: dict | None = None, signature: str | None = None,
                 idempotency_key: str = "listing-idem-1"):
        actual = body or self._body()
        proof = signature or self._signature(actual, idempotency_key)
        return _call(self.app, actual, proof, idempotency_key)

    def test_registered_account_with_free_plan_grants_signed_publish(self) -> None:
        status, payload = self._publish()
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["listing"]["merchant_id"], self.merchant_id)
        self.assertEqual(payload["listing"]["owner_agent_id"], self.agent_id)

    def test_configurable_capacity_counts_active_rows_not_retries(self) -> None:
        with db_session(self.db_path) as conn:
            conn.execute("update merchant_listing_entitlements set limit_override=1 where merchant_id=?", (self.merchant_id,))
        self.assertEqual(self._publish(idempotency_key="capacity-first")[0], 200)
        self.assertEqual(self._publish(idempotency_key="capacity-update")[0], 200)
        other = self._body(source_product_ref="SKU-APPROVED-2")
        status, payload = self._publish(other, idempotency_key="capacity-second")
        self.assertEqual(status, 403, payload)
        self.assertIn("LISTINGS_CAPACITY_EXCEEDED", payload["error"])
        with db_session(self.db_path) as conn:
            conn.execute("update merchant_listing_entitlements set limit_override=2 where merchant_id=?", (self.merchant_id,))
        self.assertEqual(self._publish(other, idempotency_key="capacity-second-retry")[0], 200)
        with db_session(self.db_path) as conn:
            conn.execute("update merchant_listing_entitlements set limit_override=1 where merchant_id=?", (self.merchant_id,))
            from kiwi_catalog.services.listing_entitlements import capacity
            self.assertEqual(capacity(conn, self.merchant_id)["active_used"], 2)
        self.assertEqual(self._publish(other, idempotency_key="capacity-existing-after-downgrade")[0], 200)
        third = self._body(source_product_ref="SKU-APPROVED-3")
        self.assertEqual(self._publish(third, idempotency_key="capacity-third-after-downgrade")[0], 403)

    def test_email_verification_is_required_before_publication(self) -> None:
        with db_session(self.db_path) as conn:
            conn.execute("update merchant_accounts set email_verified=0 where merchant_id=?", (self.merchant_id,))
        status, payload = self._publish(idempotency_key="unverified-account")
        self.assertEqual(status, 403, payload)
        self.assertIn("LISTINGS_ACCOUNT_NOT_READY", payload["error"])

    def test_concurrent_distinct_products_cannot_exceed_one_slot(self) -> None:
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier

        with db_session(self.db_path) as conn:
            conn.execute("update merchant_listing_entitlements set limit_override=1 where merchant_id=?", (self.merchant_id,))
        barrier = Barrier(2)

        def submit(number: int) -> int:
            body = self._body(source_product_ref=f"SKU-CONCURRENT-{number}")
            barrier.wait()
            return self._publish(body, idempotency_key=f"concurrent-{number}")[0]

        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(submit, (1, 2)))
        self.assertEqual(sorted(statuses), [200, 403])
        with db_session(self.db_path) as conn:
            from kiwi_catalog.services.listing_entitlements import capacity
            self.assertEqual(capacity(conn, self.merchant_id)["active_used"], 1)

    def test_governance_hold_cannot_be_cleared_by_republish(self) -> None:
        status, published = self._publish(idempotency_key="governance-first")
        self.assertEqual(status, 200, published)
        listing_id = published["listing"]["listing_id"]
        with db_session(self.db_path) as conn:
            conn.execute("update commerce_listings set publication_state='SUSPENDED',governance_hold=1 where listing_id=?", (listing_id,))
        status, payload = self._publish(idempotency_key="governance-republish")
        self.assertEqual(status, 403, payload)
        self.assertIn("LISTINGS_GOVERNANCE_HOLD", payload["error"])

    def test_changed_body_or_cross_merchant_claim_is_rejected(self) -> None:
        body = self._body()
        status, payload = self._publish(
            {**body, "title": "tampered"}, self._signature(body, "listing-idem-tamper"),
            idempotency_key="listing-idem-tamper",
        )
        self.assertEqual(status, 403, payload)
        body = self._body()
        status, payload = self._publish(
            body, self._signature(body, "listing-idem-other-merchant", merchant_id="mkt_other"),
            idempotency_key="listing-idem-other-merchant",
        )
        self.assertEqual(status, 403, payload)

    def test_wrong_key_kid_and_binding_are_rejected(self) -> None:
        body = self._body()
        other_key = Ed25519PrivateKey.generate()
        for signature in (
            self._signature(body, "listing-idem-wrong-key", key=other_key),
            self._signature(body, "listing-idem-wrong-kid", kid="runtime-other-key"),
            self._signature(body, "listing-idem-wrong-binding", binding_id="binding-other"),
        ):
            status, payload = self._publish(body, signature)
            self.assertEqual(status, 403, payload)

    def test_invalid_binding_proof_never_falls_back_to_valid_owner_token(self) -> None:
        body = {**self._body(), "owner_token": self.owner_token}
        invalid = self._signature(body, "listing-idem-no-fallback", key=Ed25519PrivateKey.generate())
        status, payload = self._publish(body, invalid, idempotency_key="listing-idem-no-fallback")
        self.assertEqual(status, 403, payload)

    def test_revoked_current_binding_is_rejected(self) -> None:
        with db_session(self.db_path) as conn:
            conn.execute("update runtime_bindings set status='revoked' where binding_id=?", (self.binding_id,))
        status, payload = self._publish(idempotency_key="listing-idem-revoked-binding")
        self.assertEqual(status, 403, payload)

    def test_published_enrollment_is_required_for_this_binding(self) -> None:
        with db_session(self.db_path) as conn:
            conn.execute("update enrollments set status='bound' where enrollment_id=?", (self.enrollment_id,))
        status, payload = self._publish()
        self.assertEqual(status, 403, payload)
        self.assertIn("LISTINGS_ENTITLEMENT_REQUIRED", payload.get("error", ""))

    def test_owner_token_and_application_do_not_control_signed_publish(self) -> None:
        with db_session(self.db_path) as conn:
            conn.execute("update merchant_tokens set status='revoked' where merchant_id=?", (self.merchant_id,))
        status, payload = self._publish()
        self.assertEqual(status, 200, payload)

        # Re-activate token but make its current admin-reviewed application pending.
        with db_session(self.db_path) as conn:
            conn.execute("update merchant_tokens set status='active' where merchant_id=?", (self.merchant_id,))
            conn.execute("update merchant_applications set status='pending' where merchant_id=?", (self.merchant_id,))
        status, payload = self._publish(idempotency_key="listing-idem-pending")
        self.assertEqual(status, 200, payload)

        with db_session(self.db_path) as conn:
            conn.execute("update merchant_listing_entitlements set status='suspended' where merchant_id=?", (self.merchant_id,))
        status, payload = self._publish(idempotency_key="listing-idem-suspended")
        self.assertEqual(status, 403, payload)
        self.assertIn("LISTINGS_ENTITLEMENT_SUSPENDED", payload.get("error", ""))

    def test_invalid_exp_and_nonce_replay_are_rejected_but_fresh_retry_replays(self) -> None:
        body = self._body()
        old_exp = (datetime.now(UTC) - timedelta(seconds=2)).replace(microsecond=0).isoformat()
        status, payload = self._publish(
            body, self._signature(body, "listing-idem-expired", exp=old_exp),
            idempotency_key="listing-idem-expired",
        )
        self.assertEqual(status, 403, payload)

        idem = "listing-idem-retry"
        sig = self._signature(body, idem)
        status, first = self._publish(body, sig, idempotency_key=idem)
        self.assertEqual(status, 200, first)
        status, replay = self._publish(body, sig, idempotency_key=idem)
        self.assertEqual(status, 403, replay)
        status, replay = self._publish(body, self._signature(body, idem), idempotency_key=idem)
        self.assertEqual(status, 200, replay)
        self.assertTrue(replay["idempotent"])

    def test_pause_or_revocation_of_binding_stops_signed_publish(self) -> None:
        with db_session(self.db_path) as conn:
            conn.execute("update enrollments set status='canceled' where enrollment_id=?", (self.enrollment_id,))
        status, payload = self._publish(idempotency_key="listing-idem-paused")
        self.assertEqual(status, 403, payload)

    def test_binding_signed_self_list_uses_query_digest_and_does_not_need_owner_token(self) -> None:
        status, published = self._publish(idempotency_key="listing-idem-before-self-list")
        self.assertEqual(status, 200, published)
        query = {"limit": 20, "cursor": "", "freshness_state": ""}
        claims = {
            "method": "GET", "path": f"/v1/agents/{self.agent_id}/listings",
            "audience": "kiwi-catalog", "agent_id": self.agent_id,
            "merchant_id": self.merchant_id, "binding_id": self.binding_id, "key_id": self.key_id,
            "query_digest": canonical_digest(query),
            "issued_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
            "exp": (datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=90)).isoformat(),
            "nonce": f"nonce-{uuid.uuid4().hex}",
        }
        signature = self._compact_jws(claims)
        status, payload = _call_route(
            self.app, "GET", f"/v1/agents/{self.agent_id}/listings",
            signature=signature, query_string="limit=20",
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["results"]), 1)

        stale_claims = {**claims, "query_digest": canonical_digest({**query, "limit": 10})}
        status, payload = _call_route(
            self.app, "GET", f"/v1/agents/{self.agent_id}/listings",
            signature=self._compact_jws(stale_claims), query_string="limit=20",
        )
        self.assertEqual(status, 403, payload)

    def test_binding_signed_withdraw_is_idempotent_and_scope_limited(self) -> None:
        status, published = self._publish(idempotency_key="listing-idem-before-withdraw")
        self.assertEqual(status, 200, published)
        listing_id = published["listing"]["listing_id"]
        idem = "listing-idem-withdraw"
        with db_session(self.db_path) as conn:
            conn.execute("update merchant_listing_entitlements set status='suspended' where merchant_id=?", (self.merchant_id,))

        def withdraw_signature(*, signed_listing_id: str = listing_id) -> str:
            claims = {
                "method": "POST", "path": f"/v1/listings/{listing_id}/withdraw",
                "audience": "kiwi-catalog", "agent_id": self.agent_id,
                "merchant_id": self.merchant_id, "binding_id": self.binding_id,
                "key_id": self.key_id, "listing_id": signed_listing_id,
                "body_digest": canonical_digest({}), "idempotency_key": idem,
                "issued_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
                "exp": (datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=90)).isoformat(),
                "nonce": f"nonce-{uuid.uuid4().hex}",
            }
            return self._compact_jws(claims)

        status, payload = _call_route(
            self.app, "POST", f"/v1/listings/{listing_id}/withdraw", {},
            withdraw_signature(), idem,
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["listing"]["publication_state"], "WITHDRAWN")
        with db_session(self.db_path) as conn:
            from kiwi_catalog.services.listing_entitlements import capacity
            self.assertEqual(capacity(conn, self.merchant_id)["active_used"], 0)

        status, payload = _call_route(
            self.app, "POST", f"/v1/listings/{listing_id}/withdraw", {},
            withdraw_signature(signed_listing_id="lst_other_listing"), "listing-idem-wrong-listing",
        )
        self.assertEqual(status, 403, payload)

    def test_token_revocation_does_not_block_signed_self_list_or_withdraw(self) -> None:
        status, published = self._publish(idempotency_key="listing-idem-before-revocation")
        self.assertEqual(status, 200, published)
        listing_id = published["listing"]["listing_id"]
        with db_session(self.db_path) as conn:
            conn.execute("update merchant_tokens set status='revoked' where merchant_id=?", (self.merchant_id,))

        query = {"limit": 20, "cursor": "", "freshness_state": ""}
        read_claims = {
            "method": "GET", "path": f"/v1/agents/{self.agent_id}/listings",
            "audience": "kiwi-catalog", "agent_id": self.agent_id,
            "merchant_id": self.merchant_id, "binding_id": self.binding_id, "key_id": self.key_id,
            "query_digest": canonical_digest(query),
            "issued_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
            "exp": (datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=90)).isoformat(),
            "nonce": f"nonce-{uuid.uuid4().hex}",
        }
        status, payload = _call_route(
            self.app, "GET", f"/v1/agents/{self.agent_id}/listings",
            signature=self._compact_jws(read_claims), query_string="limit=20",
        )
        self.assertEqual(status, 200, payload)

        idem = "listing-idem-withdraw-revoked"
        withdraw_claims = {
            "method": "POST", "path": f"/v1/listings/{listing_id}/withdraw",
            "audience": "kiwi-catalog", "agent_id": self.agent_id,
            "merchant_id": self.merchant_id, "binding_id": self.binding_id, "key_id": self.key_id,
            "listing_id": listing_id, "body_digest": canonical_digest({}), "idempotency_key": idem,
            "issued_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
            "exp": (datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=90)).isoformat(),
            "nonce": f"nonce-{uuid.uuid4().hex}",
        }
        status, payload = _call_route(
            self.app, "POST", f"/v1/listings/{listing_id}/withdraw", {},
            self._compact_jws(withdraw_claims), idem,
        )
        self.assertEqual(status, 200, payload)
