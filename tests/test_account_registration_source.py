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

"""账号注册来源（运营归因，schema v50）回归。

覆盖：
- migration 50 幂等增加 ``merchant_accounts.registration_source``，默认 unknown；
- ``/v1/accounts/register`` 携带白名单 ``source`` 时落库并回显；
- 缺省 / 空值 → unknown（老客户端不传不报错）；
- 白名单外取值 400（不把任意 referrer 字符串写进运营报表）；
- DB CHECK 兜底拒绝非法值（纵深防御）。
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.db.migrations import CURRENT_SCHEMA_VERSION
from kiwi_catalog.db.session import db_session, init_db, open_connection


def _call_http(app, method: str, path: str, body: bytes = b"") -> tuple[int, dict]:
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [(b"content-type", b"application/json")],
        "query_string": b"",
        "http_version": "1.1",
        "scheme": "http",
    }
    sent = {"body": body}
    received: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": sent["body"], "more_body": False}

    async def send(msg: dict) -> None:
        received.append(msg)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in received if m["type"] == "http.response.start")
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    payload: dict = {}
    if chunks:
        try:
            payload = json.loads(chunks.decode())
        except json.JSONDecodeError:
            payload = {"_raw": chunks.decode()}
    return start.get("status", 500), payload


class RegistrationSourceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        env_patch = mock.patch.dict(
            os.environ,
            {"KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console"},
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.app = create_catalog_app(self.db_path)

    def _register(self, email: str, source: str | None = None) -> tuple[int, dict]:
        status, payload = _call_http(
            self.app, "POST", "/v1/accounts/register/code", json.dumps({"email": email}).encode()
        )
        self.assertEqual(status, 200, payload)
        status, payload = _call_http(
            self.app,
            "POST",
            "/v1/accounts/register/verify",
            json.dumps({"email": email, "code": payload["verification_code"]}).encode(),
        )
        self.assertEqual(status, 200, payload)
        body = {
            "merchant_name": "Acme 商贸",
            "email": email,
            "password": "strong-pw-123",
            "phone": "+86 138 0000 0000",
            "verification_ticket": payload["verification_ticket"],
        }
        if source is not None:
            body["source"] = source
        return _call_http(self.app, "POST", "/v1/accounts/register", json.dumps(body).encode())

    def _stored_source(self, email: str) -> str:
        with db_session(self.db_path) as conn:
            row = conn.execute(
                "select registration_source from merchant_accounts where email = ?", (email,)
            ).fetchone()
        return str(row["registration_source"])

    def test_default_source_is_unknown_for_old_clients(self) -> None:
        status, payload = self._register("legacy@acme.example")
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["registration_source"], "unknown")
        self.assertEqual(self._stored_source("legacy@acme.example"), "unknown")

    def test_explicit_workbuddy_source_is_persisted(self) -> None:
        status, payload = self._register("wb@acme.example", "workbuddy")
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["registration_source"], "workbuddy")
        self.assertEqual(self._stored_source("wb@acme.example"), "workbuddy")

    def test_website_source_is_persisted(self) -> None:
        status, payload = self._register("web@acme.example", "website")
        self.assertEqual(status, 200, payload)
        self.assertEqual(self._stored_source("web@acme.example"), "website")

    def test_unknown_source_value_is_rejected(self) -> None:
        status, payload = self._register("spoof@acme.example", "some-referrer-host")
        self.assertEqual(status, 400, payload)
        self.assertFalse(payload.get("ok", False))
        with db_session(self.db_path) as conn:
            row = conn.execute(
                "select 1 from merchant_accounts where email = ?", ("spoof@acme.example",)
            ).fetchone()
        self.assertIsNone(row, "非法来源不得建号")

    def test_migration_is_idempotent_and_defaults_unknown(self) -> None:
        conn = open_connection(self.db_path)
        self.addCleanup(conn.close)
        # 第二次 init_db 必须幂等（migration 50 已存在时不得重复 ALTER）
        init_db(conn)
        columns = {str(row[1]) for row in conn.execute("pragma table_info(merchant_accounts)")}
        self.assertIn("registration_source", columns)
        self.assertEqual(CURRENT_SCHEMA_VERSION, 53)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute(
                "insert into merchant_accounts"
                " (email, password_hash, status, registration_source, created_at, updated_at)"
                " values ('bad@acme.example', 'x', 'active', 'referrer', 'now', 'now')"
            )
        conn.rollback()


if __name__ == "__main__":
    unittest.main()
