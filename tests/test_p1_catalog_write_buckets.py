"""审查 P1-1 回归：catalog 写限流的 actor 分桶不能由请求呈现的 token 决定。

此前的 catalog_write_actor_key 直接对 payload 里的 token（_auth_token /
owner_token）做 digest 分桶：公开 register 路由无认证，攻击者每请求换一个
随机 junk token 就得到全新桶，60/min 的 per-actor 预算形同虚设。修复后：

* 已验证身份（admin / merchant / verification worker）按 actor 分桶；
* 未认证调用按传输层解析的客户端 IP 分桶，轮换 junk token 换不到新桶；
* 两栈都先剥除客户端伪造的 _client_ip 再注入 server 侧解析值。
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

from kiwi_catalog.api import app as app_module
from kiwi_catalog.api.handlers import agent_catalog as handlers_mod
from kiwi_catalog.api.idempotency import catalog_write_actor_key

REGISTER_BODY = {
    "domain": "bucket.example",
    "display_name": "Bucket Merchant",
    "agent_card_url": "https://bucket.example/.well-known/agent-card.json",
    "hosting_mode": "direct_only",
}


def _stub_enqueue(db_path, catalog_agent_id, *, kind="verify", actor="verification_worker"):
    return type("_StubTask", (), {"task_id": ""})()


def _call_http(app, method, path, body, headers=None, client=("198.51.100.7", 1234)):
    """裸 ASGI 调用，允许指定请求头与直连对端（限流分桶输入）。"""
    scope_headers = [(b"content-type", b"application/json")]
    for name, value in (headers or {}).items():
        scope_headers.append((name.lower().encode(), value.encode()))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": scope_headers,
        "query_string": b"",
        "http_version": "1.1",
        "scheme": "http",
        "client": client,
    }
    received: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(msg: dict) -> None:
        received.append(msg)

    async def run() -> None:
        await app(scope, receive, send)

    asyncio.run(run())
    status = next((m.get("status") for m in received if m["type"] == "http.response.start"), None)
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    payload = json.loads(chunks.decode()) if chunks else {}
    return status or 500, payload


class ActorKeyTest(unittest.TestCase):
    def test_presented_tokens_never_choose_the_bucket(self) -> None:
        first = catalog_write_actor_key({"_auth_token": "junk-1", "_client_ip": "203.0.113.1"})
        second = catalog_write_actor_key({"_auth_token": "junk-2", "_client_ip": "203.0.113.1"})
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("ip:"))

    def test_verified_actor_bucket_ignores_presented_token_and_ip(self) -> None:
        first = catalog_write_actor_key(
            {"_auth_token": "junk-1", "_client_ip": "203.0.113.1"}, actor="merchant:m1"
        )
        second = catalog_write_actor_key(
            {"_auth_token": "junk-2", "_client_ip": "198.51.100.9"}, actor="merchant:m1"
        )
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("actor:"))
        self.assertNotEqual(first, catalog_write_actor_key({}, actor="merchant:m2"))

    def test_anonymous_register_actor_is_not_a_verified_identity(self) -> None:
        # 服务层把公开 register 的匿名 actor 记为 "cli"——它不是认证身份，
        # 不能因此得到 actor 桶（否则所有匿名注册仍共享同一个可预测桶）。
        key = catalog_write_actor_key({"_client_ip": "203.0.113.1"}, actor="cli")
        self.assertTrue(key.startswith("ip:"))
        # 无对端信息时退回全局常量桶（fail-closed）。
        self.assertEqual(catalog_write_actor_key({"cli": "x"}), catalog_write_actor_key({}))


class AnonymousRegisterBudgetTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = app_module.create_catalog_app(Path(self.tmp.name) / "catalog.sqlite")
        enqueue = mock.patch.object(handlers_mod, "_enqueue_verification", side_effect=_stub_enqueue)
        enqueue.start()
        self.addCleanup(enqueue.stop)
        limit = mock.patch.dict(os.environ, {"KIWI_CATALOG_WRITE_RATE_LIMIT_PER_MINUTE": "1"})
        limit.start()
        self.addCleanup(limit.stop)

    def _register(self, domain: str, *, headers=None, client=("198.51.100.7", 1234), extra=None):
        body = {**REGISTER_BODY, "domain": domain, "agent_card_url": f"https://{domain}/agent-card.json"}
        body.update(extra or {})
        return _call_http(
            self.app,
            "POST",
            "/v1/agents/register",
            json.dumps(body).encode(),
            headers=headers,
            client=client,
        )

    def test_rotating_junk_bearer_tokens_share_one_ip_bucket(self) -> None:
        status, payload = self._register("junk-one.example", headers={"authorization": "Bearer junk-one"})
        self.assertEqual(status, 200, payload)
        # 旧实现：token_digest("junk-two") 是全新桶 → 这里会 200。修复后同一
        # 客户端 IP 的第二个请求必须吃掉 per-actor 预算（429）。
        status, payload = self._register("junk-two.example", headers={"authorization": "Bearer junk-two"})
        self.assertEqual(status, 429, payload)

    def test_distinct_client_ips_get_separate_buckets(self) -> None:
        status, payload = self._register("ip-one.example", client=("198.51.100.7", 1234))
        self.assertEqual(status, 200, payload)
        status, payload = self._register("ip-two.example", client=("198.51.100.8", 1234))
        self.assertEqual(status, 200, payload)

    def test_body_supplied_client_ip_cannot_choose_the_bucket(self) -> None:
        # 直连对端不可信 → 忽略 XFF 与 body 里的 _client_ip，两请求同桶。
        status, payload = self._register(
            "forged-one.example",
            headers={"x-forwarded-for": "203.0.113.11"},
            extra={"_client_ip": "203.0.113.11"},
            client=("198.51.100.7", 1234),
        )
        self.assertEqual(status, 200, payload)
        status, payload = self._register(
            "forged-two.example",
            headers={"x-forwarded-for": "203.0.113.12"},
            extra={"_client_ip": "203.0.113.12"},
            client=("198.51.100.7", 1234),
        )
        self.assertEqual(status, 429, payload)


@unittest.skipUnless(app_module.FastAPI is not None, "fastapi not installed")
class FastApiRegisterIpInjectionTest(unittest.TestCase):
    def setUp(self) -> None:
        import httpx

        self.httpx = httpx
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.app = app_module.create_catalog_app(Path(self.tmp.name) / "catalog.sqlite")
        enqueue = mock.patch.object(handlers_mod, "_enqueue_verification", side_effect=_stub_enqueue)
        enqueue.start()
        self.addCleanup(enqueue.stop)
        limit = mock.patch.dict(os.environ, {"KIWI_CATALOG_WRITE_RATE_LIMIT_PER_MINUTE": "1"})
        limit.start()
        self.addCleanup(limit.stop)

    def _post(self, domain: str, forged_ip: str) -> Any:
        body = {**REGISTER_BODY, "domain": domain, "agent_card_url": f"https://{domain}/agent-card.json"}
        body["_client_ip"] = forged_ip

        async def run() -> Any:
            transport = self.httpx.ASGITransport(app=self.app, client=("198.51.100.7", 1234))
            async with self.httpx.AsyncClient(
                transport=transport, base_url="http://testserver"
            ) as client:
                return await client.post("/v1/agents/register", json=body)

        return asyncio.run(run())

    def test_forged_body_client_ip_does_not_open_a_new_bucket(self) -> None:
        first = self._post("fastapi-one.example", "203.0.113.21")
        self.assertEqual(first.status_code, 200, first.text)
        # 旧实现：FastAPI register 路由未注入 _client_ip → 客户端伪造值被采信；
        # 换一个伪造 IP 就能拿到新桶。修复后按直连对端分桶（同桶 → 429）。
        second = self._post("fastapi-two.example", "203.0.113.22")
        self.assertEqual(second.status_code, 429, second.text)
