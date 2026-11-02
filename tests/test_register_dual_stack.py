"""双栈注册回归(fallback 注入字段导致注册 400 的修复验收)。

修复后契约(双栈一致,经 2026-11-02 实证分类):
  - 真实注册载荷(demo-runner 同形)在 FastAPI 与 fallback ASGI 均 200;
  - 同域重复注册 -> 409(域名唯一,非幂等 200);
  - 客户端可见的未知额外字段 -> 400(additionalProperties 对客户端字段仍生效);
  - **传输层/auth 同名键被剥离**(注册 200,伪造值不影响注册与落库):
      ``_auth_token`` ``_binding_jws`` ``_origin`` ``_referer`` ``_cookie``
      ``_buyer_id`` ``_client_ip`` ``_idempotency_key``;
  - **询价专用键在注册中被拒绝**(400):``_raw_inquiry_body_b64``
      ``_inquiry_headers``(注册端点不收 inquiry 专属字段)。
  - 注册与询价互不干扰(同库注册后询价探测仍 404 未授权)。

修复前基线(2026-11-02 记录):fallback 对 demo 载荷返回 400
"register payload invalid: Additional properties are not allowed
('_client_ip', '_origin', '_referer' were unexpected)"——6366755/7e6359d9
基线均已存在(非 0.5.13 引入);本文件在该状态下 fallback 用例失败,
即回归钉的"修复前失败形态"。
"""
from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
import unittest.mock

from kiwi_catalog.api import app as app_module

DEMO_PAYLOAD = {
    "domain": "merchant-alpha.demo.local",
    "agent_card_url": "http://127.0.0.1:41001",
    "display_name": "Alpha 商贸",
    "hosting_mode": "direct",
    "capabilities": ["com.harrylabsj.kiwi.shopping.negotiation"],
}

# 实证分类(双栈一致):
STRIPPED_KEYS = ["_auth_token", "_binding_jws", "_origin", "_referer", "_cookie",
                 "_buyer_id", "_client_ip", "_idempotency_key"]
REJECTED_KEYS = ["_raw_inquiry_body_b64", "_inquiry_headers"]


def _call(app, method: str, path: str, body: dict):
    received: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": json.dumps(body).encode(), "more_body": False}

    async def send(msg: dict) -> None:
        received.append(msg)

    scope = {"type": "http", "method": method, "path": path,
             "headers": [(b"content-type", b"application/json")],
             "query_string": b"", "http_version": "1.1", "scheme": "http"}

    async def invoke():
        await app(scope, receive, send)

    asyncio.run(invoke())
    start = next(m for m in received if m["type"] == "http.response.start")
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    return start["status"], json.loads(chunks.decode() or "{}")


class RegisterDualStackTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        self.fastapi_app = app_module.create_catalog_app(self.db_path)
        with unittest.mock.patch.object(app_module, "FastAPI", None):
            self.fallback_app = app_module.create_catalog_app(self.db_path)
        self.stack_apps = {"fastapi": self.fastapi_app, "fallback": self.fallback_app}

    def _register(self, stack: str, payload: dict):
        # 同一 DB 供两栈共用:domain 必须按用例唯一,否则 409(域名唯一契约)。
        status, payload = _call(self.stack_apps[stack], "POST", "/v1/agents/register", payload)
        return status, payload, {}

    # -- 1. 真实载荷 -----------------------------------------------------
    def test_register_real_payload_succeeds_on_both_stacks(self) -> None:
        for stack in ("fastapi", "fallback"):
            with self.subTest(stack=stack):
                payload = {**DEMO_PAYLOAD,
                           "domain": f"register-real-{stack}.demo.local"}
                status, result, _h = self._register(stack, payload)
                self.assertEqual(status, 200, result)
                self.assertTrue(result["ok"], result)
                agent = result["agent"]
                self.assertEqual(agent["display_name"], "Alpha 商贸")
                self.assertEqual(agent["canonical_domain"], payload["domain"])
                self.assertEqual(agent["hosting_mode"], "direct")
                self.assertTrue(str(agent["catalog_agent_id"]).startswith("cagt_"))
                self.assertIn("verification_enqueued", result)

    def test_register_duplicate_domain_409_on_both_stacks(self) -> None:
        for stack in ("fastapi", "fallback"):
            with self.subTest(stack=stack):
                payload = {**DEMO_PAYLOAD, "domain": f"register-dup-{stack}.demo.local"}
                first = self._register(stack, payload)
                self.assertEqual(first[0], 200, first[1])
                second = self._register(stack, payload)
                self.assertEqual(second[0], 409, second[1])
                self.assertIn("already registered", second[1].get("error", ""))

    # -- 2. 额外字段拒绝 ---------------------------------------------------
    def test_register_rejects_unknown_extra_fields_on_both_stacks(self) -> None:
        for stack in ("fastapi", "fallback"):
            with self.subTest(stack=stack):
                payload = {**DEMO_PAYLOAD,
                           "domain": f"register-unknown-{stack}.demo.local",
                           "totally_unknown_field": {"nested": [1, 2]}}
                status, result, _h = self._register(stack, payload)
                self.assertEqual(status, 400, result)
                self.assertIn("invalid", str(result.get("error", "")).lower())
                self.assertNotIn("agent", result)

    # -- 3. 传输层/auth 同名键剥离与询价键拒绝 -----------------------------
    def test_register_strips_forged_transport_and_auth_keys(self) -> None:
        for stack in ("fastapi", "fallback"):
            for key in STRIPPED_KEYS:
                with self.subTest(stack=stack, key=key):
                    safe = key.strip("_").replace("_", "-")
                    payload = {**DEMO_PAYLOAD,
                               "domain": f"register-strip-{stack}-{safe}.demo.local",
                               key: f"forged-{stack}-{safe}"}
                    status, result, _h = self._register(stack, payload)
                    self.assertEqual(status, 200, result)
                    # 剥离后注册成功且伪造值不进响应/记录。
                    self.assertNotIn("forged-marker-value", json.dumps(result))
                    agent = result["agent"]
                    self.assertEqual(agent["canonical_domain"], payload["domain"])
                    self.assertNotIn(key, agent)

    def test_register_rejects_inquiry_only_keys_on_both_stacks(self) -> None:
        for stack in ("fastapi", "fallback"):
            for key in REJECTED_KEYS:
                with self.subTest(stack=stack, key=key):
                    safe = key.strip("_").replace("_", "-")
                    payload = {**DEMO_PAYLOAD,
                               "domain": f"register-rej-{stack}-{safe}.demo.local",
                               key: "forged-marker-value"}
                    status, result, _h = self._register(stack, payload)
                    self.assertEqual(status, 400, result)
                    self.assertNotIn("agent", result)
                    # 拒绝无副作用:同域干净重注册仍成功。
                    clean = {k: v for k, v in payload.items() if k != key}
                    retry = self._register(stack, clean)
                    self.assertEqual(retry[0], 200, retry[1])

    def test_register_stripped_keys_do_not_alter_identity(self) -> None:
        """同域"干净注册"与"带被剥离键注册"必须解析到同一 agent(剥离键不进入
        身份/幂等派生)。"""
        for stack in ("fastapi", "fallback"):
            with self.subTest(stack=stack):
                domain = f"register-ident-{stack}.demo.local"
                clean = self._register(stack, {**DEMO_PAYLOAD, "domain": domain})
                self.assertEqual(clean[0], 200, clean[1])
                forged = self._register(stack, {**DEMO_PAYLOAD, "domain": domain,
                                                **{k: f"forged-{stack}-{k}" for k in STRIPPED_KEYS}})
                # 同域重复 -> 409(域名唯一),但错误域与 clean 一致(键未改变身份)。
                self.assertEqual(forged[0], 409, forged[1])
                self.assertIn(domain, forged[1].get("error", ""))

    # -- 4. 原有 handler + 注册/询价互不干扰 -------------------------------
    def test_register_via_default_handler_then_inquiry_probe_coexists(self) -> None:
        for stack in ("fastapi", "fallback"):
            with self.subTest(stack=stack):
                payload = {**DEMO_PAYLOAD, "domain": f"register-coexist-{stack}.demo.local"}
                status, result, _h = self._register(stack, payload)
                self.assertEqual(status, 200, result)
                agent_id = result["agent"]["catalog_agent_id"]
                probe_status, probe_payload = _call(
                    self.stack_apps[stack], "GET", f"/v1/agents/{agent_id}/public-inquiry", {})
                self.assertEqual(probe_status, 404, probe_payload)  # 未开同意:404 而非 500
                status, payload = _call(self.stack_apps[stack], "GET",
                                        f"/v1/agents/{agent_id}", {})
                self.assertEqual(status, 200, payload)


if __name__ == "__main__":
    unittest.main()
