# Copyright 2026 harrylabsj
# Licensed under the Apache License, Version 2.0
"""商家连接器服务状态只读投影测试。"""

from __future__ import annotations
import asyncio
import hashlib
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from unittest import mock
from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import connector_identity
from kiwi_catalog.services.listing_entitlements import ensure_free_entitlement


def _call(app, authorization=""):
    headers = [(b"content-type", b"application/json")]
    if authorization:
        headers.append((b"authorization", authorization.encode()))
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/v1/accounts/me/service-status",
        "headers": headers,
        "query_string": b"",
        "http_version": "1.1",
        "scheme": "http",
    }
    out = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        out.append(msg)

    asyncio.run(app(scope, receive, send))
    start = next(x for x in out if x["type"] == "http.response.start")
    body = b"".join(x.get("body", b"") for x in out if x["type"] == "http.response.body")
    return start["status"], json.loads(body) if body else {}


class ServiceStatusApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        p = mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
                "KIWI_CATALOG_PUBLIC_BASE_URL": "https://catalog.example",
            },
            clear=False,
        )
        p.start()
        self.addCleanup(p.stop)
        self.app = create_catalog_app(self.db_path)
        self.tokens = {
            "mkt_a": self._token("a@example.test", "A 商家", "mkt_a"),
            "mkt_b": self._token("b@example.test", "B 商家", "mkt_b"),
        }

    def _token(self, email, name, merchant_id):
        from tests.test_connector_identity import _register_and_login

        _register_and_login(self.app, email, name)
        with db_session(self.db_path) as conn:
            conn.execute("update merchant_accounts set merchant_id=? where email=?", (merchant_id, email))
            ensure_free_entitlement(conn, merchant_id)
            acct = conn.execute("select account_id from merchant_accounts where email=?", (email,)).fetchone()
            issued = connector_identity.issue_merchant_token(
                conn,
                account_id=int(acct["account_id"]),
                merchant_id=merchant_id,
                scope="catalog:read",
                now="2026-09-28T00:00:00+00:00",
            )
            conn.commit()
        return issued["access_token"]

    def test_authentication_and_unverified_email(self):
        self.assertEqual(_call(self.app)[0], 403)
        with db_session(self.db_path) as conn:
            conn.execute("update merchant_accounts set email_verified=0 where merchant_id='mkt_a'")
            conn.commit()
        status, data = _call(self.app, "Bearer " + self.tokens["mkt_a"])
        self.assertEqual(status, 200)
        self.assertFalse(data["account"]["email_verified"])
        self.assertEqual(data["onboarding"]["status"], "not_started")

    def test_waiting_confirmation_does_not_leak_pairing_or_grant_secrets(self):
        now = datetime.now(UTC)
        with db_session(self.db_path) as conn:
            conn.execute(
                "insert into enrollments(enrollment_id,device_code_hash,user_code,status,key_id,key_thumbprint,"
                "key_jwk_json,runtime_origin,a2a_endpoint,public_preview_json,merchant_id,created_at,expires_at) "
                "values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "enr_a",
                    hashlib.sha256(b"secret").hexdigest(),
                    "PRIVATE-CODE",
                    "ready_for_authorization",
                    "key",
                    "thumb",
                    "{}",
                    "https://runtime.example",
                    "https://runtime.example/a2a",
                    "{}",
                    "mkt_a",
                    now.isoformat(),
                    (now + timedelta(minutes=10)).isoformat(),
                ),
            )
            conn.commit()
        status, data = _call(self.app, "Bearer " + self.tokens["mkt_a"])
        self.assertEqual(status, 200)
        self.assertEqual(data["onboarding"]["status"], "awaiting_merchant_confirmation")
        self.assertEqual(data["onboarding"]["authorization_url"], "https://catalog.example/portal/connect/enr_a")
        rendered = json.dumps(data)
        for secret in ("PRIVATE-CODE", "user_code", "device_code", "grant"):
            self.assertNotIn(secret, rendered)

    def test_published_freshness_quota_and_cross_merchant_isolation(self):
        now = datetime.now(UTC).replace(microsecond=0).isoformat()
        with db_session(self.db_path) as conn:
            for merchant, last_seen in (("mkt_a", now), ("mkt_b", "2020-01-01T00:00:00+00:00")):
                agent = f"cagt_{merchant}"
                conn.execute(
                    "insert into catalog_agents(catalog_agent_id,merchant_id,display_name,source_type,"
                    "verification_status,verification_level,freshness_state,administrative_state,first_seen_at,last_seen_at,"
                    "created_at,updated_at) values(?,?,?,'hosted','commerce_verified','commerce_verified','fresh','active',?,?,?,?)",
                    (agent, merchant, "服务", now, last_seen, now, now),
                )
                conn.execute(
                    "insert into runtime_bindings(binding_id,catalog_agent_id,merchant_id,runtime_origin,"
                    "a2a_endpoint,key_id,key_thumbprint,key_jwk_json,binding_version,service_epoch,status,created_at,updated_at) "
                    "values(?,?,?,?,?,?,?,?,?,1,'active',?,?)",
                    (
                        f"b_{merchant}",
                        agent,
                        merchant,
                        "https://runtime.example/path",
                        "https://runtime.example/a2a",
                        "key",
                        "thumb",
                        "{}",
                        1,
                        now,
                        now,
                    ),
                )
                conn.execute("insert into card_publications values(?,?,?, ?,?)", (agent, 1, "ACTIVE", "etag", now))
                conn.execute(
                    "insert into enrollments(enrollment_id,device_code_hash,user_code,status,key_id,key_thumbprint,"
                    "key_jwk_json,runtime_origin,a2a_endpoint,public_preview_json,merchant_id,catalog_agent_id,created_at,expires_at) "
                    "values(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        f"e_{merchant}",
                        "hash",
                        f"SECRET-{merchant}",
                        "published",
                        "key",
                        "thumb",
                        "{}",
                        "https://runtime.example",
                        "https://runtime.example/a2a",
                        "{}",
                        merchant,
                        agent,
                        now,
                        now,
                    ),
                )
                conn.execute(
                    "insert into commerce_listings(listing_id,listing_type,owner_agent_id,merchant_id,title,category,"
                    "listing_digest,publication_state,published_at,updated_at,fresh_until,created_at) values(?, 'product', ?, ?, 'x','x',"
                    "'sha256:x','ACTIVE',?,?,?,?)",
                    (f"l_{merchant}", agent, merchant, now, now, now, now),
                )
            conn.commit()
        status, a = _call(self.app, "Bearer " + self.tokens["mkt_a"])
        status_b, b = _call(self.app, "Bearer " + self.tokens["mkt_b"])
        self.assertEqual(status, 200)
        self.assertEqual(status_b, 200)
        self.assertTrue(a["card"]["published"])
        self.assertEqual(a["card"]["origin"], "https://runtime.example")
        self.assertEqual(a["onboarding"]["status"], "published")
        self.assertEqual(a["presence"]["state"], "fresh")
        self.assertEqual(a["listings"], {"used": 1, "total": 20, "plan": "free"})
        self.assertEqual(b["presence"]["state"], "stale")
        self.assertNotIn("mkt_b", json.dumps(a))


if __name__ == "__main__":
    unittest.main()
