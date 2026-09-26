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

"""运营 admin token 轮换（2026-09-26，迁移 v37）。

覆盖：
- 轮换必须带**当前** token（fail-closed），缺/错 → 403；
- 轮换后旧值**立即失效**（含 env 引导值）、新值可用，且重启（重开 app）后仍生效；
- `new_token` 自选与自动生成两条路径；过短/含空白 → 400；
- 恢复路径：删掉轮换行 → env 引导值重新生效；
- 所有 admin 端点都用同一口径判定（矩阵），并有**静态检查**守住调用点；
- 通知邮件（旁路，失败不影响轮换）；
- FastAPI 栈路由已注册（回归 2026-09-26 的 buyer-day 500 那类"漏 import"错误）。
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import admin_credentials

ENV_TOKEN = "env-bootstrap-token-0123456789"
NEW_TOKEN = "operator-chosen-token-0123456789"
NOTIFY_EMAIL = "ops@example.com"


def _call_http(
    app, method: str, path: str, body: bytes = b"", headers: dict[str, str] | None = None
) -> tuple[int, dict]:
    path_only = path.split("?", 1)[0]
    query_bytes = path.split("?", 1)[1].encode() if "?" in path else b""
    scope_headers: list[tuple[bytes, bytes]] = [(b"content-type", b"application/json")]
    for key, value in (headers or {}).items():
        scope_headers.append((key.lower().encode("latin1"), value.encode("latin1")))
    scope = {
        "type": "http",
        "method": method,
        "path": path_only,
        "headers": scope_headers,
        "query_string": query_bytes,
        "http_version": "1.1",
        "scheme": "http",
    }
    sent = {"body": body}
    received: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": sent["body"], "more_body": False}

    async def send(msg: dict) -> None:
        received.append(msg)

    async def run():
        await app(scope, receive, send)

    asyncio.run(run())
    start = next(m for m in received if m["type"] == "http.response.start")
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    payload: dict = {}
    if chunks:
        try:
            payload = json.loads(chunks.decode())
        except json.JSONDecodeError:
            payload = {"_raw": chunks.decode()}
    return start.get("status", 500), payload


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": "Bearer " + token}


class AdminTokenRotateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "catalog.sqlite"
        env_patch = mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ADMIN_TOKEN": ENV_TOKEN,
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": "test-owner-secret",
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        os.environ.pop("KIWI_CATALOG_ADMIN_NOTIFY_EMAIL", None)
        self.app = create_catalog_app(self.db_path)

    def _rotate(self, body: dict | None = None, token: str | None = ENV_TOKEN):
        return _call_http(
            self.app,
            "POST",
            "/v1/admin/token/rotate",
            json.dumps(body or {}).encode(),
            _auth(token) if token is not None else {},
        )

    # ── 鉴权 ───────────────────────────────────────────────────────────────

    def test_rotate_requires_current_token(self) -> None:
        status, payload = self._rotate(token=None)
        self.assertEqual(status, 403, payload)
        status, payload = self._rotate(token="wrong-token-0123456789")
        self.assertEqual(status, 403, payload)
        self.assertIn("invalid admin token", payload.get("error", ""))

    def test_no_admin_token_configured_fails_closed(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("KIWI_CATALOG_ADMIN_TOKEN", None)
            status, payload = self._rotate(token=ENV_TOKEN)
        self.assertEqual(status, 403, payload)

    # ── 轮换语义 ───────────────────────────────────────────────────────────

    def test_rotate_generates_token_and_old_value_dies(self) -> None:
        status, payload = self._rotate()
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["generated"])
        new_token = payload["token"]
        self.assertGreaterEqual(len(new_token), admin_credentials.ADMIN_TOKEN_MIN_LENGTH)
        self.assertEqual(payload["rotation_count"], 1)
        # 新值可用、env 引导值立即失效
        self.assertEqual(_call_http(self.app, "GET", "/v1/admin/dashboard?days=1", headers=_auth(new_token))[0], 200)
        self.assertEqual(_call_http(self.app, "GET", "/v1/admin/dashboard?days=1", headers=_auth(ENV_TOKEN))[0], 403)

    def test_rotate_accepts_operator_chosen_token(self) -> None:
        status, payload = self._rotate({"new_token": NEW_TOKEN})
        self.assertEqual(status, 200, payload)
        self.assertFalse(payload["generated"])
        self.assertEqual(payload["token"], NEW_TOKEN)
        self.assertEqual(_call_http(self.app, "GET", "/v1/admin/merchants", headers=_auth(NEW_TOKEN))[0], 200)
        # 库里只有摘要：明文不得落库
        with db_session(self.db_path) as conn:
            row = admin_credentials.load(conn)
        self.assertIsNotNone(row)
        self.assertNotIn(NEW_TOKEN, json.dumps(row))
        self.assertGreaterEqual(row["rotation_count"], 1)

    def test_rotate_twice_counts_and_second_value_wins(self) -> None:
        self._rotate({"new_token": NEW_TOKEN})
        status, payload = self._rotate({"new_token": "third-token-0123456789abcd"}, token=NEW_TOKEN)
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["rotation_count"], 2)
        self.assertEqual(_call_http(self.app, "GET", "/v1/admin/merchants", headers=_auth(NEW_TOKEN))[0], 403)
        self.assertEqual(
            _call_http(self.app, "GET", "/v1/admin/merchants", headers=_auth("third-token-0123456789abcd"))[0], 200
        )

    def test_rotate_rejects_weak_or_whitespace_token(self) -> None:
        for bad in ("short", "with space 0123456789abcdef", " padded-token-0123456789 "):
            status, payload = self._rotate({"new_token": bad})
            self.assertEqual(status, 400, (bad, payload))
        # 被拒之后旧值仍然可用（失败不得改变现状）
        self.assertEqual(_call_http(self.app, "GET", "/v1/admin/merchants", headers=_auth(ENV_TOKEN))[0], 200)

    def test_rotation_survives_app_reopen(self) -> None:
        self._rotate({"new_token": NEW_TOKEN})
        reopened = create_catalog_app(self.db_path)
        self.assertEqual(_call_http(reopened, "GET", "/v1/admin/merchants", headers=_auth(NEW_TOKEN))[0], 200)
        self.assertEqual(_call_http(reopened, "GET", "/v1/admin/merchants", headers=_auth(ENV_TOKEN))[0], 403)

    def test_clear_restores_env_bootstrap(self) -> None:
        """恢复路径：删掉轮换行 → 控制权交回服务器配置。"""
        self._rotate({"new_token": NEW_TOKEN})
        with db_session(self.db_path) as conn:
            admin_credentials.clear(conn)
        reopened = create_catalog_app(self.db_path)
        self.assertEqual(_call_http(reopened, "GET", "/v1/admin/merchants", headers=_auth(ENV_TOKEN))[0], 200)
        self.assertEqual(_call_http(reopened, "GET", "/v1/admin/merchants", headers=_auth(NEW_TOKEN))[0], 403)

    def test_all_admin_endpoints_use_the_same_credential(self) -> None:
        """矩阵：轮换后旧值在每个 admin 端点都必须死（漏传 db 的调用点会在这里露出来）。"""
        self._rotate({"new_token": NEW_TOKEN})
        paths = (
            "/v1/admin/dashboard?days=1",
            "/v1/admin/merchants",
            "/v1/admin/searches",
            "/v1/admin/buyer-stats?days=1",
            "/v1/admin/buyer-day?day=2026-09-26",
            "/v1/admin/access-log?days=1",
            "/v1/admin/access-insights?days=1",
            "/v1/merchants/applications?status=pending",
        )
        for path in paths:
            old_status, _ = _call_http(self.app, "GET", path, headers=_auth(ENV_TOKEN))
            new_status, _ = _call_http(self.app, "GET", path, headers=_auth(NEW_TOKEN))
            self.assertEqual(old_status, 403, path)
            self.assertNotEqual(new_status, 403, path)

    # ── 通知邮件（旁路）─────────────────────────────────────────────────────

    _SMTP_ENV = {
        "KIWI_CATALOG_SMTP_HOST": "smtp.example",
        "KIWI_CATALOG_SMTP_USER": "ops@example",
        "KIWI_CATALOG_SMTP_PASSWORD": "pw",
    }

    def test_rotation_notifies_operator_by_email(self) -> None:
        with mock.patch.dict(
            os.environ, {**self._SMTP_ENV, "KIWI_CATALOG_ADMIN_NOTIFY_EMAIL": NOTIFY_EMAIL}, clear=False
        ):
            with mock.patch("smtplib.SMTP") as smtp:
                status, payload = self._rotate({"new_token": NEW_TOKEN})
        self.assertEqual(status, 200, payload)
        message = smtp.return_value.__enter__.return_value.send_message.call_args[0][0]
        self.assertEqual(message["To"], NOTIFY_EMAIL)
        self.assertIn("admin token", str(message["Subject"]))
        # 通知是"轮换发生过"的即时信号——写明旧值已失效与本次轮换次数
        self.assertIn("旧 token 已立即失效", message.get_content())
        self.assertIn("1", message.get_content())

    def test_smtp_failure_does_not_break_rotation(self) -> None:
        with mock.patch.dict(
            os.environ, {**self._SMTP_ENV, "KIWI_CATALOG_ADMIN_NOTIFY_EMAIL": NOTIFY_EMAIL}, clear=False
        ):
            with mock.patch("smtplib.SMTP", side_effect=OSError("smtp down")):
                status, payload = self._rotate({"new_token": NEW_TOKEN})
        self.assertEqual(status, 200, payload)
        self.assertEqual(_call_http(self.app, "GET", "/v1/admin/merchants", headers=_auth(NEW_TOKEN))[0], 200)

    def test_no_notify_email_configured_is_not_an_error(self) -> None:
        os.environ.pop("KIWI_CATALOG_ADMIN_NOTIFY_EMAIL", None)
        with mock.patch.dict(os.environ, self._SMTP_ENV, clear=False):
            with mock.patch("smtplib.SMTP") as smtp:
                status, _ = self._rotate({"new_token": NEW_TOKEN})
        self.assertEqual(status, 200)
        smtp.assert_not_called()

    # ── 静态完整性：轮换后"漏传 db 的调用点"= 旧值复活 ─────────────────────

    def test_every_require_admin_token_call_passes_db_context(self) -> None:
        """所有调用点都必须带第二个参数（db_path 或 conn）。

        漏传 = 该端点只认 env 引导值 → 轮换后旧值在那条路径上复活。这是**静态**
        检查（不依赖端点数得全），先例：仓库里的双栈路由 parity 断言。
        """
        root = Path(__file__).resolve().parent.parent / "kiwi_catalog"
        offenders: list[str] = []
        call = re.compile(r"require_admin_token\(([^)]*)\)")
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for match in call.finditer(text):
                args = match.group(1).strip()
                if args.endswith("payload") or args.endswith("auth_payload") or args.endswith("{}"):
                    offenders.append(f"{path.relative_to(root.parent)}: {match.group(0)}")
        self.assertEqual(offenders, [], "这些 require_admin_token 调用点漏传了 db 上下文")

    # ── FastAPI 栈 ─────────────────────────────────────────────────────────

    @unittest.skipUnless(
        __import__("kiwi_catalog.api.app", fromlist=["FastAPI"]).FastAPI is not None,
        "fastapi not installed",
    )
    def test_rotate_works_on_fastapi_stack(self) -> None:
        """真打 FastAPI 栈：漏进 import 列表时 NameError 只在请求时炸（2026-09-26
        buyer-day 500 的同族错误，本地 fallback 栈跑不出来）。"""
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            self.assertEqual(client.post("/v1/admin/token/rotate", json={}).status_code, 403)
            self.assertEqual(
                client.post(
                    "/v1/admin/token/rotate", json={}, headers=_auth("wrong-token-0123456789")
                ).status_code,
                403,
            )
            rotated = client.post(
                "/v1/admin/token/rotate", json={"new_token": NEW_TOKEN}, headers=_auth(ENV_TOKEN)
            )
            self.assertEqual(rotated.status_code, 200, rotated.text)
            self.assertEqual(rotated.json()["token"], NEW_TOKEN)
            self.assertEqual(
                client.get("/v1/admin/merchants", headers=_auth(ENV_TOKEN)).status_code, 403
            )
            self.assertEqual(
                client.get("/v1/admin/merchants", headers=_auth(NEW_TOKEN)).status_code, 200
            )


if __name__ == "__main__":
    unittest.main()
