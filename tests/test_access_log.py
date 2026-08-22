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

"""个体访问日志测试（v28 运营质量 + 安全审计数据源）。

覆盖：
- 服务层：surface 五分类、actor 派生、IP 截断、query 摘要凭据剔除、
  target_id 提取、record/list/prune 往返、记录失败不抛错；
- 中间件：fallback 栈（MarketplaceASGIApp 直挂）与 FastAPI 栈（TestClient）
  都落日志，/health 不记，result_count 从响应提取；
- admin 端点：鉴权 fail-closed、倒序返回、surface 过滤、limit/days 钳制、
  响应不含凭据。
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest import mock

from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.api import app as app_module
from kiwi_catalog.db.session import open_connection
from kiwi_catalog.services import access_log

ADMIN_TOKEN = "test-admin"
OWNER_SECRET = "test-owner-secret"


def _make_db() -> Path:
    tmp = tempfile.mkdtemp()
    db = Path(tmp) / "catalog.sqlite"
    conn = open_connection(db)
    conn.close()
    return db


def _call_http(
    app,
    method: str,
    path: str,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
    client: tuple[str, int] | None = None,
) -> tuple[int, dict]:
    """直挂 ASGI 调一次请求（fallback 与 FastAPI 都可用；参照 test_admin_api）。"""
    path_only = path.split("?", 1)[0]
    query_bytes = path.split("?", 1)[1].encode() if "?" in path else b""
    scope_headers: list[tuple[bytes, bytes]] = [(b"content-type", b"application/json")]
    for key, value in (headers or {}).items():
        scope_headers.append((key.lower().encode("latin1"), value.encode("latin1")))
    scope: dict = {
        "type": "http",
        "method": method,
        "path": path_only,
        "headers": scope_headers,
        "query_string": query_bytes,
        "http_version": "1.1",
        "scheme": "http",
    }
    if client is not None:
        scope["client"] = client
    sent = {"body": body}
    received: list[dict] = []

    async def receive() -> dict:
        return {"type": "http.request", "body": sent["body"], "more_body": False}

    async def send(msg: dict) -> None:
        received.append(msg)

    async def run() -> None:
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


def _has_fastapi() -> bool:
    return app_module.FastAPI is not None


# ── 服务层：纯函数分类 / 脱敏 / 截断 ─────────────────────────────────────────


class AccessLogClassificationTest(unittest.TestCase):
    def test_classify_surface(self) -> None:
        self.assertIsNone(access_log.classify_surface("GET", "/health"))
        # buyer_search：新 /v1 + legacy
        self.assertEqual(
            access_log.classify_surface("GET", "/v1/agents/search"),
            access_log.SURFACE_BUYER_SEARCH,
        )
        self.assertEqual(
            access_log.classify_surface("GET", "/v1/listings/search"),
            access_log.SURFACE_BUYER_SEARCH,
        )
        self.assertEqual(
            access_log.classify_surface("GET", "/v1/agent-catalog/agents/search"),
            access_log.SURFACE_BUYER_SEARCH,
        )
        # buyer_detail：/v1/agents/{id}、/v1/listings/{id}、hosted card/ucp
        self.assertEqual(
            access_log.classify_surface("GET", "/v1/agents/cagt_1"),
            access_log.SURFACE_BUYER_DETAIL,
        )
        self.assertEqual(
            access_log.classify_surface("GET", "/v1/listings/lst_1"),
            access_log.SURFACE_BUYER_DETAIL,
        )
        self.assertEqual(
            access_log.classify_surface("GET", "/v1/agent-catalog/agents/cagt_1"),
            access_log.SURFACE_BUYER_DETAIL,
        )
        self.assertEqual(
            access_log.classify_surface("GET", "/v1/hosted/agents/cagt_1/agent-card.json"),
            access_log.SURFACE_BUYER_DETAIL,
        )
        self.assertEqual(
            access_log.classify_surface("GET", "/v1/hosted/agents/cagt_1/ucp"),
            access_log.SURFACE_BUYER_DETAIL,
        )
        # merchant_write：POST /v1/* + 商家读端点自查
        self.assertEqual(
            access_log.classify_surface("POST", "/v1/agents/register"),
            access_log.SURFACE_MERCHANT_WRITE,
        )
        self.assertEqual(
            access_log.classify_surface("POST", "/v1/listings/publish"),
            access_log.SURFACE_MERCHANT_WRITE,
        )
        self.assertEqual(
            access_log.classify_surface("POST", "/v1/merchants/mkt_1/rotate"),
            access_log.SURFACE_MERCHANT_WRITE,
        )
        self.assertEqual(
            access_log.classify_surface("GET", "/v1/merchants/self"),
            access_log.SURFACE_MERCHANT_WRITE,
        )
        # account_portal：/v1/accounts/*、/portal/*（含首页 /portal）
        self.assertEqual(
            access_log.classify_surface("GET", "/v1/accounts/me"),
            access_log.SURFACE_ACCOUNT_PORTAL,
        )
        self.assertEqual(
            access_log.classify_surface("GET", "/portal/apply"),
            access_log.SURFACE_ACCOUNT_PORTAL,
        )
        self.assertEqual(
            access_log.classify_surface("GET", "/portal"),
            access_log.SURFACE_ACCOUNT_PORTAL,
        )
        # admin：/v1/admin/*、/portal/admin*、/portal/dashboard
        self.assertEqual(
            access_log.classify_surface("GET", "/v1/admin/dashboard"),
            access_log.SURFACE_ADMIN,
        )
        self.assertEqual(
            access_log.classify_surface("GET", "/portal/admin"),
            access_log.SURFACE_ADMIN,
        )
        self.assertEqual(
            access_log.classify_surface("GET", "/portal/admin/searches"),
            access_log.SURFACE_ADMIN,
        )
        self.assertEqual(
            access_log.classify_surface("GET", "/portal/dashboard"),
            access_log.SURFACE_ADMIN,
        )

    def test_derive_actor(self) -> None:
        self.assertEqual(
            access_log.derive_actor(access_log.SURFACE_ADMIN, True),
            access_log.ACTOR_ADMIN,
        )
        self.assertEqual(
            access_log.derive_actor(access_log.SURFACE_MERCHANT_WRITE, True),
            access_log.ACTOR_MERCHANT,
        )
        self.assertEqual(
            access_log.derive_actor(access_log.SURFACE_ACCOUNT_PORTAL, True),
            access_log.ACTOR_MERCHANT,
        )
        self.assertEqual(
            access_log.derive_actor(access_log.SURFACE_BUYER_SEARCH, True),
            access_log.ACTOR_BUYER,
        )
        self.assertEqual(
            access_log.derive_actor(access_log.SURFACE_BUYER_DETAIL, True),
            access_log.ACTOR_BUYER,
        )
        for surface in access_log.ALL_SURFACES:
            self.assertEqual(
                access_log.derive_actor(surface, False),
                access_log.ACTOR_ANONYMOUS,
            )

    def test_actor_key_is_sha256_truncated(self) -> None:
        headers = {"authorization": "Bearer tok-123"}
        expected = hashlib.sha256(b"tok-123").hexdigest()[:12]
        self.assertEqual(access_log._actor_key(headers), expected)
        self.assertEqual(access_log._actor_key({}), "")
        self.assertEqual(
            access_log._actor_key({"x-buyer-id": "buyer-1"}),
            hashlib.sha256(b"buyer-1").hexdigest()[:12],
        )

    def test_ip_prefix_truncation(self) -> None:
        self.assertEqual(access_log._ip_prefix("203.0.113.42"), "203.0.113.0")
        self.assertEqual(access_log._ip_prefix("8.8.8.8"), "8.8.8.0")
        # IPv6 截前 4 段（exploded 形式，段宽 4）
        self.assertEqual(
            access_log._ip_prefix("2001:db8:85a3:8d3:1319:8a2e:370:7348"),
            "2001:0db8:85a3:08d3",
        )
        # IPv4-mapped IPv6 先转回 IPv4 再截 /24
        self.assertEqual(access_log._ip_prefix("::ffff:192.168.1.1"), "192.168.1.0")
        # 非 IP → 空串（不记录不可信前缀）
        self.assertEqual(access_log._ip_prefix("not-an-ip"), "")
        self.assertEqual(access_log._ip_prefix(""), "")

    def test_query_summary_scrubs_credentials(self) -> None:
        summary = access_log.build_query_summary(
            access_log.SURFACE_BUYER_SEARCH,
            {
                "q": "tea",
                "category": "drink",
                "limit": "20",
                "owner_token": "sekrit",
                "key": "abc",
                "password": "pw",
                "code": "1234",
                "api_key": "k-1",
            },
        )
        data = json.loads(summary)
        self.assertEqual(data["q"], "tea")
        self.assertEqual(data["filters"]["category"], "drink")
        self.assertEqual(data["filters"]["limit"], "20")
        for cred in ("owner_token", "key", "password", "code", "api_key"):
            self.assertNotIn(cred, data["filters"])
            self.assertNotIn("sekrit", summary)
            self.assertNotIn("abc", summary)
        # 非搜索面 → 空串
        self.assertEqual(access_log.build_query_summary(access_log.SURFACE_ADMIN, {"q": "x"}), "")

    def test_query_summary_bounded_valid_json(self) -> None:
        """超长 q / 筛选值 → 落库仍是合法 JSON 且 ≤500 字符（P2-06 教训）。"""
        summary = access_log.build_query_summary(
            access_log.SURFACE_BUYER_SEARCH,
            {"q": "长" * 4000, "category": "x" * 4000, "region": "sh"},
        )
        self.assertLessEqual(len(summary), 500)
        data = json.loads(summary)  # 合法 JSON
        self.assertIn("q", data)

    def test_target_id_extraction(self) -> None:
        self.assertEqual(access_log.extract_target_id("/v1/agents/cagt_1"), "cagt_1")
        self.assertEqual(access_log.extract_target_id("/v1/agents/cagt_1/refresh"), "cagt_1")
        self.assertEqual(access_log.extract_target_id("/v1/agents/search"), "")
        self.assertEqual(access_log.extract_target_id("/v1/agents/register"), "")
        self.assertEqual(access_log.extract_target_id("/v1/listings/lst_1"), "lst_1")
        self.assertEqual(access_log.extract_target_id("/v1/listings/search"), "")
        self.assertEqual(access_log.extract_target_id("/v1/listings/publish"), "")
        self.assertEqual(access_log.extract_target_id("/v1/merchants/mkt_1/rotate"), "mkt_1")
        self.assertEqual(access_log.extract_target_id("/v1/merchants/self"), "")
        self.assertEqual(access_log.extract_target_id("/v1/hosted/agents/cagt_1/ucp"), "cagt_1")
        self.assertEqual(access_log.extract_target_id("/v1/admin/merchants/mkt_1/report"), "mkt_1")
        self.assertEqual(access_log.extract_target_id("/health"), "")


# ── 服务层：record / list / prune ───────────────────────────────────────────


class AccessLogServiceTest(unittest.TestCase):
    def test_record_and_list_roundtrip(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        access_log.record_access(
            conn,
            method="GET",
            path="/v1/agents/search?q=tea",
            surface=access_log.SURFACE_BUYER_SEARCH,
            actor_kind=access_log.ACTOR_BUYER,
            actor_key="abc123def456",
            ip_prefix="203.0.113.0",
            user_agent="agent/1.0",
            query_summary='{"q": "tea"}',
            status=200,
            result_count=3,
            latency_ms=12,
        )
        conn.commit()
        rows = access_log.list_access_log(conn, days=7, limit=10)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["surface"], access_log.SURFACE_BUYER_SEARCH)
        self.assertEqual(row["actor_kind"], access_log.ACTOR_BUYER)
        self.assertEqual(row["actor_key"], "abc123def456")
        self.assertEqual(row["ip_prefix"], "203.0.113.0")
        self.assertEqual(row["query_summary"], '{"q": "tea"}')
        self.assertEqual(row["status"], 200)
        self.assertEqual(row["result_count"], 3)
        self.assertEqual(row["latency_ms"], 12)
        self.assertEqual(row["target_id"], "")
        conn.close()

    def test_prune_removes_expired_rows(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        old = (datetime.now(UTC) - timedelta(days=100)).replace(microsecond=0).isoformat()
        now = datetime.now(UTC).replace(microsecond=0).isoformat()
        for occurred_at, path in ((old, "/old"), (now, "/new")):
            conn.execute(
                "insert into access_log"
                " (occurred_at, method, path, surface, actor_kind, actor_key, ip_prefix,"
                "  user_agent, query_summary, target_id)"
                " values (?, 'GET', ?, 'buyer_search', 'anonymous', '', '', '', '', '')",
                (occurred_at, path),
            )
        conn.commit()
        access_log.prune_access_log(conn, retention=90)
        conn.commit()
        paths = [r["path"] for r in conn.execute("select path from access_log").fetchall()]
        self.assertEqual(paths, ["/new"])
        conn.close()

    def test_retention_days_env(self) -> None:
        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_ACCESS_LOG_RETENTION_DAYS": "30"}, clear=False
        ):
            self.assertEqual(access_log.retention_days(), 30)
        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_ACCESS_LOG_RETENTION_DAYS": ""}, clear=False
        ):
            self.assertEqual(access_log.retention_days(), 90)  # 空串 → 默认
        with mock.patch.dict(
            os.environ, {"KIWI_CATALOG_ACCESS_LOG_RETENTION_DAYS": "abc"}, clear=False
        ):
            self.assertEqual(access_log.retention_days(), 90)  # 非数字 → 默认

    def test_record_access_never_raises_with_broken_conn(self) -> None:
        """记录失败绝不抛错（注入坏连接）：写入与清理都静默。"""
        db = _make_db()
        conn = open_connection(db)
        conn.close()  # 关闭后 execute 抛 ProgrammingError
        access_log.record_access(
            conn,
            method="GET",
            path="/v1/agents/search",
            surface=access_log.SURFACE_BUYER_SEARCH,
            actor_kind=access_log.ACTOR_ANONYMOUS,
        )
        access_log.prune_access_log(conn)
        access_log.record_http_access(
            db,
            method="GET",
            path="/v1/agents/search",
            query={"q": "tea"},
            headers={},
            client_ip="203.0.113.42",
            status=200,
            latency_ms=1,
        )

    def test_health_not_logged_by_record_http_access(self) -> None:
        db = _make_db()
        access_log.record_http_access(
            db,
            method="GET",
            path="/health",
            query={},
            headers={},
            client_ip="203.0.113.42",
            status=200,
            latency_ms=1,
        )
        conn = open_connection(db)
        count = conn.execute("select count(*) as n from access_log").fetchone()["n"]
        conn.close()
        self.assertEqual(count, 0)

    def test_record_http_access_derives_fields(self) -> None:
        """record_http_access 中间件入口：从原始请求/响应字段派生存取。"""
        db = _make_db()
        access_log.record_http_access(
            db,
            method="GET",
            path="/v1/agents/search?q=tea&owner_token=sekrit",
            query={"q": "tea", "owner_token": "sekrit", "category": "drink"},
            headers={"authorization": "Bearer tok-123", "user-agent": "test-agent"},
            client_ip="203.0.113.42",
            status=200,
            latency_ms=5,
            result_count=2,
        )
        conn = open_connection(db)
        row = conn.execute(
            "select * from access_log order by id desc limit 1"
        ).fetchone()
        conn.close()
        self.assertEqual(row["surface"], access_log.SURFACE_BUYER_SEARCH)
        self.assertEqual(row["actor_kind"], access_log.ACTOR_BUYER)
        self.assertEqual(
            row["actor_key"], hashlib.sha256(b"tok-123").hexdigest()[:12]
        )
        self.assertEqual(row["ip_prefix"], "203.0.113.0")
        self.assertEqual(row["target_id"], "")
        summary = json.loads(row["query_summary"])
        self.assertEqual(summary["q"], "tea")
        self.assertNotIn("owner_token", summary["filters"])
        self.assertNotIn("sekrit", json.dumps(dict(row)))
        self.assertEqual(row["result_count"], 2)


# ── 中间件：fallback 栈（MarketplaceASGIApp 直挂）───────────────────────────


class AccessLogMiddlewareFallbackTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        from kiwi_catalog.api.fallback_asgi import MarketplaceASGIApp
        from kiwi_catalog.api.route_table import _ROUTE_TABLE, resolve_route

        self.app = MarketplaceASGIApp(
            self.db_path,
            route_provider=lambda: list(_ROUTE_TABLE),
            route_resolver=lambda method, path: resolve_route(method, path),
        )
        env_patch = mock.patch.dict(
            os.environ,
            {"KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN, "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET},
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.addCleanup(self.tmp.cleanup)

    def _rows(self, surface: str = "") -> list[dict]:
        conn = open_connection(self.db_path)
        try:
            return access_log.list_access_log(conn, surface=surface, days=7, limit=100)
        finally:
            conn.close()

    def test_health_not_logged(self) -> None:
        status, _ = _call_http(self.app, "GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(self._rows(), [])

    def test_anonymous_search_logged_with_result_count(self) -> None:
        _call_http(self.app, "GET", "/v1/agents/search?q=tea")
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["surface"], access_log.SURFACE_BUYER_SEARCH)
        self.assertEqual(row["actor_kind"], access_log.ACTOR_ANONYMOUS)
        self.assertEqual(row["actor_key"], "")
        self.assertEqual(row["status"], 200)
        self.assertEqual(row["result_count"], 0)  # 空库
        summary = json.loads(row["query_summary"])
        self.assertEqual(summary["q"], "tea")

    def test_buyer_search_with_identity(self) -> None:
        _call_http(
            self.app, "GET", "/v1/agents/search",
            headers={"X-Buyer-Id": "buyer-abc"},
        )
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["actor_kind"], access_log.ACTOR_BUYER)
        self.assertEqual(row["actor_key"], hashlib.sha256(b"buyer-abc").hexdigest()[:12])
        self.assertNotIn("buyer-abc", json.dumps(row))  # 原始身份不落库

    def test_merchant_write_with_bearer_is_merchant(self) -> None:
        status, _ = _call_http(
            self.app,
            "POST",
            "/v1/merchants/mkt_1/rotate",
            body=b"{}",
            headers={"Authorization": "Bearer mkt-tok-1"},
        )
        # 非 admin 商家写端点 → fail-closed 403；访问日志仍记录（actor=merchant）
        self.assertEqual(status, 403)
        rows = self._rows(surface=access_log.SURFACE_MERCHANT_WRITE)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["actor_kind"], access_log.ACTOR_MERCHANT)
        self.assertEqual(rows[0]["actor_key"], hashlib.sha256(b"mkt-tok-1").hexdigest()[:12])

    def test_admin_endpoint_with_token_is_admin(self) -> None:
        _call_http(
            self.app, "GET", "/v1/admin/dashboard",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        rows = self._rows(surface=access_log.SURFACE_ADMIN)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["actor_kind"], access_log.ACTOR_ADMIN)

    def test_query_summary_scrubs_credentials_on_wire(self) -> None:
        _call_http(
            self.app,
            "GET",
            "/v1/agents/search?q=tea&category=drink&owner_token=sekrit&code=1234",
        )
        rows = self._rows()
        self.assertEqual(len(rows), 1)
        summary = json.loads(rows[0]["query_summary"])
        self.assertEqual(summary["q"], "tea")
        self.assertEqual(summary["filters"]["category"], "drink")
        self.assertNotIn("owner_token", summary["filters"])
        self.assertNotIn("code", summary["filters"])
        raw = json.dumps(rows[0])
        self.assertNotIn("sekrit", raw)
        self.assertNotIn("1234", raw)

    def test_ip_prefix_truncated_on_wire(self) -> None:
        _call_http(self.app, "GET", "/v1/agents/search", client=("203.0.113.42", 12345))
        rows = self._rows()
        self.assertEqual(rows[0]["ip_prefix"], "203.0.113.0")
        self.assertNotIn("203.0.113.42", json.dumps(rows[0]))  # 不存完整 IP

    def test_record_failure_does_not_break_request(self) -> None:
        """访问日志 DB 打不开（模拟坏连接）→ 请求仍 200（record_http_access 全兜底）。"""
        from kiwi_catalog.services import access_log as access_log_module

        with mock.patch.object(
            access_log_module, "db_session", side_effect=RuntimeError("db down")
        ):
            status, payload = _call_http(self.app, "GET", "/v1/agents/search")
        self.assertEqual(status, 200, payload)


# ── 中间件：FastAPI 栈（TestClient）────────────────────────────────────────


@unittest.skipUnless(_has_fastapi(), "fastapi not installed")
class AccessLogMiddlewareFastApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_file = Path(self.tmp.name) / "catalog.sqlite"
        env_patch = mock.patch.dict(
            os.environ,
            {"KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN, "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET},
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.addCleanup(self.tmp.cleanup)
        self.app = create_catalog_app(self.db_file)

    def _rows(self, surface: str = "") -> list[dict]:
        conn = open_connection(self.db_file)
        try:
            return access_log.list_access_log(conn, surface=surface, days=7, limit=100)
        finally:
            conn.close()

    def test_search_request_logged(self) -> None:
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            resp = client.get("/v1/agents/search", params={"q": "tea"})
            self.assertEqual(resp.status_code, 200, resp.text)
        rows = self._rows(surface=access_log.SURFACE_BUYER_SEARCH)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["actor_kind"], access_log.ACTOR_ANONYMOUS)
        self.assertEqual(json.loads(rows[0]["query_summary"])["q"], "tea")

    def test_search_result_count_extracted(self) -> None:
        """FastAPI 中间件从响应体提取 result_count（len(results)）。"""
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            resp = client.post(
                "/v1/agent-catalog/agents/register",
                json={"domain": "merchant.example", "idempotency_key": "r1"},
            )
            self.assertEqual(resp.status_code, 200, resp.text)
            resp = client.get("/v1/agents/search")
            self.assertEqual(resp.status_code, 200, resp.text)
        rows = self._rows(surface=access_log.SURFACE_BUYER_SEARCH)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["result_count"], 1)

    def test_health_not_logged(self) -> None:
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            resp = client.get("/health")
            self.assertEqual(resp.status_code, 200, resp.text)
        conn = open_connection(self.db_file)
        try:
            count = conn.execute("select count(*) as n from access_log").fetchone()["n"]
        finally:
            conn.close()
        self.assertEqual(count, 0)

    def test_record_failure_does_not_break_request(self) -> None:
        """访问日志 DB 打不开（模拟坏连接）→ 请求仍 200（record_http_access 全兜底）。"""
        from fastapi.testclient import TestClient

        from kiwi_catalog.services import access_log as access_log_module

        with mock.patch.object(
            access_log_module, "db_session", side_effect=RuntimeError("db down")
        ):
            with TestClient(self.app) as client:
                resp = client.get("/v1/agents/search")
        self.assertEqual(resp.status_code, 200, resp.text)

    def test_xff_honored_from_trusted_proxy(self) -> None:
        """FastAPI 栈与 fallback 同一 IP 语义：可信代理(回环)后采信 XFF 首跳。

        生产在 Caddy 同机反代后,直连对端恒为 127.0.0.1——不解析 XFF 会让
        ip_prefix 全部退化为 127.0.0.0(验收发现)。
        """
        from fastapi.testclient import TestClient

        with TestClient(self.app, client=("127.0.0.1", 50000)) as client:
            resp = client.get(
                "/v1/agents/search", headers={"x-forwarded-for": "203.0.113.7, 10.0.0.1"}
            )
            self.assertEqual(resp.status_code, 200, resp.text)
        rows = self._rows(surface=access_log.SURFACE_BUYER_SEARCH)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip_prefix"], "203.0.113.0")

    def test_failure_paths_logged_too(self) -> None:
        """FastAPI 中间件 early-return 分支(413/400)也落访问日志(与 fallback 对称)。

        审查发现:此前 413/400 直接 return JSONResponse 不记录,双栈不对称;
        统一到 finally 后失败路径也必须记录(验收守则:全覆盖、无旁路)。
        """
        from fastapi.testclient import TestClient

        with TestClient(self.app) as client:
            # 413: content-length 声明超限
            resp = client.post(
                "/v1/agents/register",
                content=b"x" * 2000000,
                headers={"content-type": "application/json"},
            )
            self.assertEqual(resp.status_code, 413, resp.text)
            # 400: 非法 JSON body
            resp = client.post(
                "/v1/agents/register",
                content=b"not-json",
                headers={"content-type": "application/json"},
            )
            self.assertEqual(resp.status_code, 400, resp.text)
            # 404: 未知路径
            resp = client.get("/v1/no-such-path")
            self.assertEqual(resp.status_code, 404, resp.text)
        # /v1/no-such-path 落在 merchant_write 面(classify_surface 兜底),
        # 404 未知 /v1/* 路径与 fallback 一样也记录(status=404)
        rows = self._rows(surface=access_log.SURFACE_MERCHANT_WRITE)
        statuses = sorted(r["status"] for r in rows)
        self.assertEqual(statuses, [400, 404, 413], rows)
        for row in rows:
            self.assertEqual(row["actor_key"], "", "失败路径同样不存身份原文")


# ── admin 端点 GET /v1/admin/access-log ────────────────────────────────────


class AccessLogAdminTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        env_patch = mock.patch.dict(
            os.environ,
            {"KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN, "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET},
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.addCleanup(self.tmp.cleanup)
        self.app = create_catalog_app(self.db_path)

    def _seed(self, rows: list[tuple[str, str]]) -> None:
        conn = open_connection(self.db_path)
        for surface, actor in rows:
            access_log.record_access(
                conn, method="GET", path="/seed", surface=surface, actor_kind=actor
            )
        conn.commit()
        conn.close()

    def test_requires_admin_token(self) -> None:
        status, payload = _call_http(self.app, "GET", "/v1/admin/access-log")
        self.assertEqual(status, 403, payload)
        self.assertIn("admin token", payload.get("error", ""))

    def test_returns_rows_time_desc_with_surface_filter(self) -> None:
        self._seed(
            [
                (access_log.SURFACE_BUYER_SEARCH, access_log.ACTOR_ANONYMOUS),
                (access_log.SURFACE_BUYER_DETAIL, access_log.ACTOR_ANONYMOUS),
                (access_log.SURFACE_MERCHANT_WRITE, access_log.ACTOR_MERCHANT),
            ]
        )
        status, payload = _call_http(
            self.app,
            "GET",
            "/v1/admin/access-log",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["results"]), 3)
        # 时间倒序：最近的在最前（同刻按 id 倒序保证稳定）
        surfaces = [r["surface"] for r in payload["results"]]
        self.assertEqual(
            surfaces,
            [
                access_log.SURFACE_MERCHANT_WRITE,
                access_log.SURFACE_BUYER_DETAIL,
                access_log.SURFACE_BUYER_SEARCH,
            ],
        )
        # surface 过滤
        status, payload = _call_http(
            self.app,
            "GET",
            "/v1/admin/access-log?surface=buyer_search",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(len(payload["results"]), 1)
        self.assertEqual(payload["results"][0]["surface"], access_log.SURFACE_BUYER_SEARCH)

    def test_limit_and_days_clamped(self) -> None:
        # surface 过滤隔离种子行——admin 访问日志请求自身也会落一行（surface=admin）
        self._seed([(access_log.SURFACE_BUYER_DETAIL, access_log.ACTOR_ANONYMOUS)] * 5)
        status, payload = _call_http(
            self.app,
            "GET",
            "/v1/admin/access-log?surface=buyer_detail&limit=2",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["results"]), 2)
        # limit 超上限钳制到 500（不报错）
        status, payload = _call_http(
            self.app,
            "GET",
            "/v1/admin/access-log?surface=buyer_detail&limit=9999",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["results"]), 5)
        # days=0 钳制到最小 1；全部 5 行都是今天 → 返回
        status, payload = _call_http(
            self.app,
            "GET",
            "/v1/admin/access-log?surface=buyer_detail&days=0",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["results"]), 5)

    def test_response_contains_no_credentials(self) -> None:
        # 带 Bearer token 的搜索请求 → access_log 记录 actor_key（哈希），无原文
        _call_http(
            self.app,
            "GET",
            "/v1/agents/search",
            headers={"Authorization": "Bearer super-secret-token"},
        )
        status, payload = _call_http(
            self.app,
            "GET",
            "/v1/admin/access-log",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(payload["results"]), 1)
        raw = json.dumps(payload)
        self.assertNotIn("super-secret-token", raw)
        self.assertEqual(
            payload["results"][0]["actor_key"],
            hashlib.sha256(b"super-secret-token").hexdigest()[:12],
        )

    def test_access_insights_requires_admin_token(self) -> None:
        status, payload = _call_http(self.app, "GET", "/v1/admin/access-insights")
        self.assertEqual(status, 403, payload)
        self.assertIn("admin token", payload.get("error", ""))

    def test_access_insights_returns_funnel_and_login_failure_signal(self) -> None:
        conn = open_connection(self.db_path)
        for _ in range(2):
            access_log.record_access(
                conn,
                method="GET",
                path="/v1/agents/search",
                surface=access_log.SURFACE_BUYER_SEARCH,
                actor_kind=access_log.ACTOR_ANONYMOUS,
                status=200,
            )
        access_log.record_access(
            conn,
            method="GET",
            path="/v1/agents/cagt_1",
            surface=access_log.SURFACE_BUYER_DETAIL,
            actor_kind=access_log.ACTOR_ANONYMOUS,
            target_id="cagt_1",
            status=200,
        )
        access_log.record_access(
            conn,
            method="POST",
            path="/v1/accounts/login",
            surface=access_log.SURFACE_ACCOUNT_PORTAL,
            actor_kind=access_log.ACTOR_ANONYMOUS,
            ip_prefix="203.0.113.0",
            status=401,
        )
        conn.commit()
        conn.close()

        status, payload = _call_http(
            self.app,
            "GET",
            "/v1/admin/access-insights?days=7",
            headers={"Authorization": "Bearer " + ADMIN_TOKEN},
        )

        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["days"], 7)
        self.assertEqual(payload["funnel"]["total_searches"], 2)
        self.assertEqual(payload["funnel"]["total_detail_views"], 1)
        self.assertEqual(payload["funnel"]["conversion"], 0.5)
        self.assertEqual(payload["top_viewed_agents"][0]["target_id"], "cagt_1")
        self.assertEqual(payload["login_failures"]["today"], 1)
        self.assertEqual(
            payload["login_failures"]["by_ip_prefix"][0],
            {"ip_prefix": "203.0.113.0", "failures": 1},
        )


if __name__ == "__main__":
    unittest.main()
