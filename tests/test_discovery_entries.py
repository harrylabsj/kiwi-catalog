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

"""发现条目（discovery entry）测试（v22：catalog 本地目录，替代代理通道）。

- 服务层：token 门槛（create/delete 强制 active，吊销即拒；list 只读放行）
  / agent 门槛 / 重名（大小写不敏感）/ 名称边界 / CRUD；
- handler：admin / owner token / portal 账号会话授权（越权 403、吊销后会话
  删除被拒）；
- 公开搜索：匿名可用、子串匹配、限流接线（per-IP 分桶 + global 总量兜底，
  X-Forwarded-For 首跳注入）；
- portal 页：三种状态（无令牌 / 无 Agent / 正常）与代理时代文案清除。
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kiwi_catalog.api.handlers import discovery_entries as handlers
from kiwi_catalog.api.handlers.portal import portal_account, portal_products
from kiwi_catalog.core.errors import (
    AuthError,
    NotFoundError,
    PermissionDenied,
    RateLimitError,
    ValidationError,
)
from kiwi_catalog.core.tokens import token_digest
from kiwi_catalog.db.session import now_iso, open_connection
from kiwi_catalog.services import accounts as accounts_service
from kiwi_catalog.services import discovery_entries as entries_service

_TS = "2026-08-11T00:00:00+00:00"


def _make_db() -> Path:
    tmp = tempfile.mkdtemp()
    db = Path(tmp) / "catalog.sqlite"
    conn = open_connection(db)
    conn.close()
    return db


def _grant_token(conn: sqlite3.Connection, merchant_id: str, plaintext: str = "tok-abc") -> None:
    """签发 active owner token（落库 SHA-256，与 approve_application 同机制）。"""
    conn.execute(
        "insert into merchant_tokens (merchant_id, token_hash, token_encrypted, status, issued_at)"
        " values (?, ?, '', 'active', ?)",
        (merchant_id, token_digest(plaintext), now_iso()),
    )


def _register_agent(conn: sqlite3.Connection, merchant_id: str, agent_id: str = "cagt_1") -> None:
    conn.execute(
        """insert into catalog_agents(
            catalog_agent_id, merchant_id, display_name, canonical_domain, agent_type,
            source_type, lifecycle_status, verification_status, hosting_mode,
            first_seen_at, last_seen_at, created_at, updated_at)
           values (?, ?, 'Agent', 'acme.example', 'commerce', 'self_registered',
            'active', 'discovered', 'direct', ?, ?, ?, ?)""",
        (agent_id, merchant_id, _TS, _TS, _TS, _TS),
    )


def _ready_merchant(conn: sqlite3.Connection, merchant_id: str = "mkt_test") -> str:
    """备好可上传的商家（active token + 注册 agent），返回 merchant_id。"""
    _grant_token(conn, merchant_id)
    _register_agent(conn, merchant_id, agent_id=f"cagt_{merchant_id}")
    return merchant_id


class DiscoveryEntryServiceTest(unittest.TestCase):
    def test_create_list_delete_roundtrip(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        _ready_merchant(conn)
        entry = entries_service.create_entry(conn, "mkt_test", "  有机猕猴桃 5kg  ")
        self.assertTrue(entry["entry_id"].startswith("dsc_"))
        self.assertEqual(entry["name"], "有机猕猴桃 5kg")
        entries = entries_service.list_entries(conn, "mkt_test")
        self.assertEqual([e["entry_id"] for e in entries], [entry["entry_id"]])
        entries_service.delete_entry(conn, "mkt_test", entry["entry_id"])
        self.assertEqual(entries_service.list_entries(conn, "mkt_test"), [])
        conn.close()

    def test_create_requires_active_token(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        conn.execute(
            "insert into merchant_tokens (merchant_id, token_hash, status, issued_at)"
            " values ('mkt_revoked', 'x', 'revoked', ?)",
            (now_iso(),),
        )
        _register_agent(conn, "mkt_revoked")
        with self.assertRaises(ValidationError) as ctx:
            entries_service.create_entry(conn, "mkt_revoked", "商品")
        self.assertIn("商家令牌", str(ctx.exception))
        with self.assertRaises(ValidationError):
            entries_service.create_entry(conn, "mkt_no_token", "商品")
        conn.close()

    def test_create_requires_registered_agent(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        _grant_token(conn, "mkt_test")
        with self.assertRaises(ValidationError) as ctx:
            entries_service.create_entry(conn, "mkt_test", "商品")
        self.assertIn("注册 Agent", str(ctx.exception))
        conn.close()

    def test_duplicate_name_rejected_case_insensitive(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        _ready_merchant(conn)
        entries_service.create_entry(conn, "mkt_test", "Kiwi Box")
        with self.assertRaises(ValidationError) as ctx:
            entries_service.create_entry(conn, "mkt_test", "kiwi box")
        self.assertIn("重复", str(ctx.exception))
        # 其他商家可用同名
        _ready_merchant(conn, "mkt_other")
        other = entries_service.create_entry(conn, "mkt_other", "kiwi box")
        self.assertTrue(other["entry_id"])
        conn.close()

    def test_name_bounds(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        _ready_merchant(conn)
        with self.assertRaises(ValidationError):
            entries_service.create_entry(conn, "mkt_test", "   ")
        with self.assertRaises(ValidationError):
            entries_service.create_entry(conn, "mkt_test", "x" * 201)
        entry = entries_service.create_entry(conn, "mkt_test", "x" * 200)
        self.assertTrue(entry["entry_id"])
        conn.close()

    def test_delete_foreign_or_missing_entry_404(self) -> None:
        db = _make_db()
        conn = open_connection(db)
        _ready_merchant(conn)
        entry = entries_service.create_entry(conn, "mkt_test", "商品")
        with self.assertRaises(NotFoundError):
            entries_service.delete_entry(conn, "mkt_other", entry["entry_id"])
        with self.assertRaises(NotFoundError):
            entries_service.delete_entry(conn, "mkt_test", "dsc_missing")
        conn.close()

    def test_revoked_token_blocks_create_and_delete_but_not_list(self) -> None:
        """审查 P3-04：吊销后 create/delete 被拒（写面一致）；list 是只读
        自身数据，放行（取舍见 list_entries docstring）。"""
        db = _make_db()
        conn = open_connection(db)
        _ready_merchant(conn)
        entry = entries_service.create_entry(conn, "mkt_test", "商品")
        conn.execute(
            "update merchant_tokens set status = 'revoked' where merchant_id = 'mkt_test'"
        )
        with self.assertRaises(ValidationError) as ctx:
            entries_service.create_entry(conn, "mkt_test", "商品B")
        self.assertIn("商家令牌", str(ctx.exception))
        with self.assertRaises(ValidationError) as ctx:
            entries_service.delete_entry(conn, "mkt_test", entry["entry_id"])
        self.assertIn("商家令牌", str(ctx.exception))
        # list 放行：吊销只切断写面，商家仍可只读自己的条目
        self.assertEqual(
            [e["entry_id"] for e in entries_service.list_entries(conn, "mkt_test")],
            [entry["entry_id"]],
        )
        conn.close()


class DiscoveryEntryHandlersTest(unittest.TestCase):
    def setUp(self) -> None:
        env_patch = mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ADMIN_TOKEN": "test-admin",
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": "test-secret",
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
            },
            clear=False,
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.db = _make_db()
        conn = open_connection(self.db)
        _ready_merchant(conn)
        conn.commit()
        conn.close()

    def test_create_list_delete_with_owner_token(self) -> None:
        res = handlers.create_entry(
            self.db, "mkt_test", {"owner_token": "tok-abc", "name": "商品A"}
        )
        self.assertTrue(res["ok"])
        entry_id = res["entry"]["entry_id"]
        res = handlers.list_entries(self.db, "mkt_test", {"owner_token": "tok-abc"})
        self.assertEqual([e["entry_id"] for e in res["results"]], [entry_id])
        res = handlers.delete_entry(
            self.db, "mkt_test", entry_id, {"owner_token": "tok-abc"}
        )
        self.assertTrue(res["ok"])

    def test_admin_token_allowed(self) -> None:
        res = handlers.create_entry(
            self.db, "mkt_test", {"_auth_token": "test-admin", "name": "商品B"}
        )
        self.assertTrue(res["ok"])

    def test_no_credential_rejected(self) -> None:
        with self.assertRaises(AuthError):
            handlers.list_entries(self.db, "mkt_test", {})

    def _make_account(self, email: str) -> tuple[str, str]:
        """注册账号并签发会话，返回 (merchant_id, session_token)。"""
        conn = open_connection(self.db)
        try:
            account = accounts_service.register_account(
                conn, email=email, password="password-123"
            )
            session = accounts_service.create_session(conn, int(account["account_id"]))
            conn.commit()
            return str(account["merchant_id"]), session
        finally:
            conn.close()

    def test_session_own_merchant_allowed(self) -> None:
        merchant_id, session = self._make_account("own@acme.example")
        conn = open_connection(self.db)
        _ready_merchant(conn, merchant_id)
        conn.commit()
        conn.close()
        res = handlers.create_entry(
            self.db, merchant_id, {"kiwi_session": session, "name": "商品C"}
        )
        self.assertTrue(res["ok"])
        # cookie 形式（fallback/FastAPI transport 透传 _cookie）等价
        res = handlers.list_entries(
            self.db, merchant_id, {"_cookie": f"kiwi_session={session}"}
        )
        self.assertEqual(len(res["results"]), 1)

    def test_session_wrong_merchant_403(self) -> None:
        _merchant_id, session = self._make_account("other@acme.example")
        with self.assertRaises(PermissionDenied):
            handlers.list_entries(self.db, "mkt_test", {"kiwi_session": session})

    def test_session_delete_after_revoke_rejected(self) -> None:
        """审查 P3-04：令牌吊销后，7 天会话 cookie 不得再删除发现条目
        （会话写面与 owner token 写面一致 fail-closed）；list 只读放行。"""
        merchant_id, session = self._make_account("revoked@acme.example")
        conn = open_connection(self.db)
        _ready_merchant(conn, merchant_id)
        conn.commit()
        conn.close()
        res = handlers.create_entry(
            self.db, merchant_id, {"kiwi_session": session, "name": "商品D"}
        )
        entry_id = res["entry"]["entry_id"]
        conn = open_connection(self.db)
        conn.execute(
            "update merchant_tokens set status = 'revoked' where merchant_id = ?",
            (merchant_id,),
        )
        conn.commit()
        conn.close()
        with self.assertRaises(ValidationError) as ctx:
            handlers.delete_entry(self.db, merchant_id, entry_id, {"kiwi_session": session})
        self.assertIn("商家令牌", str(ctx.exception))
        # list（只读自身数据）放行——吊销只切断写面
        res = handlers.list_entries(self.db, merchant_id, {"kiwi_session": session})
        self.assertEqual([e["entry_id"] for e in res["results"]], [entry_id])


class DiscoverySearchTest(unittest.TestCase):
    def setUp(self) -> None:
        self.db = _make_db()
        conn = open_connection(self.db)
        _ready_merchant(conn)
        conn.execute(
            "insert into merchants (id, name, created_at, updated_at)"
            " values ('mkt_test', 'Acme 商家', ?, ?)",
            (_TS, _TS),
        )
        entries_service.create_entry(conn, "mkt_test", "有机猕猴桃礼盒")
        entries_service.create_entry(conn, "mkt_test", "进口车厘子")
        conn.commit()
        conn.close()

    def test_anonymous_search_substring(self) -> None:
        res = handlers.search_discovery(self.db, {"q": "猕猴桃"})
        self.assertTrue(res["ok"])
        self.assertEqual(len(res["results"]), 1)
        hit = res["results"][0]
        self.assertEqual(hit["entry"]["name"], "有机猕猴桃礼盒")
        self.assertEqual(hit["entry"]["merchant_id"], "mkt_test")
        self.assertEqual(hit["merchant"], {"merchant_id": "mkt_test", "display_name": "Acme 商家"})
        self.assertEqual(hit["agent"]["catalog_agent_id"], "cagt_mkt_test")
        self.assertEqual(hit["agent"]["canonical_domain"], "acme.example")
        self.assertEqual(hit["agent"]["administrative_state"], "active")

    def test_search_empty_query_lists_all_with_limit(self) -> None:
        res = handlers.search_discovery(self.db, {"q": "", "limit": "1"})
        self.assertEqual(len(res["results"]), 1)
        res = handlers.search_discovery(self.db, {})
        self.assertEqual(len(res["results"]), 2)

    def test_search_case_insensitive_and_wildcard_literal(self) -> None:
        res = handlers.search_discovery(self.db, {"q": "KIWI"})
        self.assertEqual(len(res["results"]), 0)  # 无英文名条目
        # % 不当 LIKE 通配符（instr 子串匹配，q 原样）
        res = handlers.search_discovery(self.db, {"q": "%"})
        self.assertEqual(len(res["results"]), 0)

    def test_search_rate_limit_wired(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"KIWI_CATALOG_DISCOVERY_SEARCH_RATE_LIMIT_PER_MINUTE": "1"},
            clear=False,
        ):
            res = handlers.search_discovery(self.db, {"q": "猕猴桃"})
            self.assertTrue(res["ok"])
            with self.assertRaises(RateLimitError):
                handlers.search_discovery(self.db, {"q": "车厘子"})

    def test_search_rate_limit_per_client_ip_buckets(self) -> None:
        """审查 P3-06：按客户端 IP 分桶——单 IP 超限 429 不影响其他 IP。"""
        with mock.patch.dict(
            os.environ,
            {"KIWI_CATALOG_DISCOVERY_SEARCH_RATE_LIMIT_PER_MINUTE": "1"},
            clear=False,
        ):
            res = handlers.search_discovery(
                self.db, {"q": "猕猴桃", "_client_ip": "203.0.113.1"}
            )
            self.assertTrue(res["ok"])
            with self.assertRaises(RateLimitError):
                handlers.search_discovery(
                    self.db, {"q": "猕猴桃", "_client_ip": "203.0.113.1"}
                )
            # 不同 IP 独立桶：不受 203.0.113.1 超限影响
            res = handlers.search_discovery(
                self.db, {"q": "猕猴桃", "_client_ip": "203.0.113.2"}
            )
            self.assertTrue(res["ok"])

    def test_search_global_rate_limit_cap(self) -> None:
        """审查 P3-06：global 总量桶兜底——不同 IP 共享总量上限（防分布式滥用）。"""
        with mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_DISCOVERY_SEARCH_RATE_LIMIT_PER_MINUTE": "60",
                "KIWI_CATALOG_DISCOVERY_SEARCH_GLOBAL_RATE_LIMIT_PER_MINUTE": "2",
            },
            clear=False,
        ):
            handlers.search_discovery(self.db, {"_client_ip": "198.51.100.1"})
            handlers.search_discovery(self.db, {"_client_ip": "198.51.100.2"})
            with self.assertRaises(RateLimitError):
                handlers.search_discovery(self.db, {"_client_ip": "198.51.100.3"})


class DiscoverySearchTransportTest(unittest.TestCase):
    """_client_ip 双栈注入接线（fallback ASGI：X-Forwarded-For 首跳优先）。"""

    def setUp(self) -> None:
        self.db = _make_db()
        conn = open_connection(self.db)
        _ready_merchant(conn)
        entries_service.create_entry(conn, "mkt_test", "有机猕猴桃礼盒")
        conn.commit()
        conn.close()

    def _get(self, path: str, headers: dict[str, str] | None = None) -> tuple[int, dict]:
        from kiwi_catalog.api.app import create_catalog_app

        app = create_catalog_app(str(self.db))
        scope_headers = [(key.lower().encode("latin1"), value.encode("latin1")) for key, value in (headers or {}).items()]
        scope = {
            "type": "http",
            "method": "GET",
            "path": path.split("?", 1)[0],
            "headers": scope_headers,
            "query_string": (path.split("?", 1)[1].encode() if "?" in path else b""),
        }
        received: list[dict] = []

        async def receive() -> dict:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(msg: dict) -> None:
            received.append(msg)

        asyncio.run(app(scope, receive, send))
        start = next(m for m in received if m["type"] == "http.response.start")
        body = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
        return int(start.get("status", 500)), json.loads(body.decode())

    def test_forwarded_for_drives_per_ip_bucket(self) -> None:
        """审查 P3-06：X-Forwarded-For 首跳决定限流桶——同一首跳第二次 429，
        换首跳不受牵连。"""
        with mock.patch.dict(
            os.environ,
            {"KIWI_CATALOG_DISCOVERY_SEARCH_RATE_LIMIT_PER_MINUTE": "1"},
            clear=False,
        ):
            status, _ = self._get(
                "/v1/discovery/search?q=猕猴桃",
                {"X-Forwarded-For": "203.0.113.9, 10.0.0.1"},
            )
            self.assertEqual(status, 200)
            status, _ = self._get(
                "/v1/discovery/search?q=猕猴桃",
                {"X-Forwarded-For": "203.0.113.9, 10.0.0.2"},
            )
            self.assertEqual(status, 429)
            status, payload = self._get(
                "/v1/discovery/search?q=猕猴桃", {"X-Forwarded-For": "203.0.113.10"}
            )
            self.assertEqual(status, 200, payload)


class PortalProductsPageTest(unittest.TestCase):
    def test_page_renders_discovery_manager(self) -> None:
        page = portal_products()
        html = page["__html__"]
        self.assertIn("我的商品", html)
        # 三种状态：无令牌引导 / 无 Agent 引导 / 正常管理器
        self.assertIn("guide_token", html)
        self.assertIn("guide_agent", html)
        self.assertIn("/portal/account", html)  # 令牌信息页链接
        self.assertIn("manager", html)
        self.assertIn("discovery-entries", html)
        self.assertIn("商品名称", html)
        # 代理时代文案清除：免费档 / shopping-cli 写回 / SKU 表单
        self.assertNotIn("免费", html)
        self.assertNotIn("shopping-cli", html)
        self.assertNotIn("SKU", html)

    def test_account_page_token_copy_updated(self) -> None:
        html = portal_account()["__html__"]
        self.assertIn("上传商品名称到发现目录需要商家令牌", html)
        self.assertIn("令牌同时也是你的 Agent 接入 API 的凭据", html)
        self.assertNotIn("免费上架", html)
        # 令牌申请仍要求 Agent ID（表单必填）
        self.assertIn("Agent ID（必填", html)


if __name__ == "__main__":
    unittest.main()
