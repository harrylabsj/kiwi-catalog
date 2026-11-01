"""开放询价中继的加固专项(评审项 F-1/F-2/F-4/F-5/F-7/F-8)。

  F-1 双栈 raw body 边界(49153/65536/65537)与逐字节精确转发;客户端伪造
      传输层同名键不得绕过大小/深度限制;可信元数据只来自传输层;深层
      JSON 安全 400(不得 500)。
  F-2 fallback 502 严格无 ``__status__``/``__no_store__``/``__cookies__``
      元字段,no-store;cookie/HTML/重定向不回归。
  F-4 固定错误日志只含自有码、净化 agent 标识与异常类型名——绝无 URL、
      分享码或异常原文;路径内恶意字符被转义。
  F-5 从未授权与重复撤销的幂等(404);绑定签名必填;跨绑定撤权不可;
      撤权后有效签名也无法绕过 fail-closed。
  F-7 客户端 body 伪造 ``_client_ip`` 不能选择限流桶(先剥除再注入);
      可信代理 XFF 与自定义 handler(五参数、无 trusted keys)回归。
  F-8 固定脱敏分类(RELAY_FAILED / UPSTREAM_REJECTED / UPSTREAM_INVALID
      三分支)与恢复流程(失败不改授权状态,可直接重试)。
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import tempfile
import unittest
import unittest.mock

from tests.test_runtime_access_api import (
    ADMIN_TOKEN,
    CATALOG_ORIGIN,
    RUNTIME_ORIGIN,
    A2A_ENDPOINT,
    SHARE_SECRET_V1,
    _access_config,
    _call,
    _call_full,
    _jws,
    _runtime_key,
)
from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.api.fallback_asgi import MarketplaceASGIApp
from kiwi_catalog.api.route_table import all_routes, resolve_route
from kiwi_catalog.db.session import db_session
from kiwi_catalog.discovery.fetcher import FetchError, FetchResult, ProfileFetcher
from kiwi_catalog.services import public_inquiry_consent as policy

LOG_NAME = "kiwi_catalog.api.handlers.public_inquiry"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _body_with_pad(target_size: int, message_id: str) -> bytes:
    """构造**恰好 target_size 字节**的合法 JSON-RPC 请求(pad 字段精确填充)。"""
    base = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
            "params": {"message": {"role": "ROLE_USER", "messageId": message_id,
                                   "parts": [{"text": "quote"}]}, "pad": ""}}
    base_raw = json.dumps(base, ensure_ascii=False).encode("utf-8")
    pad_len = target_size - len(base_raw)
    assert pad_len >= 0, (target_size, len(base_raw))
    base["params"]["pad"] = "x" * pad_len
    raw = json.dumps(base, ensure_ascii=False).encode("utf-8")
    assert len(raw) == target_size, (len(raw), target_size)
    return raw


def _inquiry_body(message_id: str = "hardening-1") -> bytes:
    return _body_with_pad(len(_body_with_pad(0, message_id)), message_id) if False else \
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
                    "params": {"message": {"role": "ROLE_USER", "messageId": message_id,
                                           "parts": [{"text": "quote"}]}}},
                   ensure_ascii=False).encode("utf-8")


def _signed_headers() -> list[tuple[bytes, bytes]]:
    return [(b"content-digest", b"sha-256=:test:"),
            (b"signature", b"sig1=:test:"),
            (b"signature-input", b'sig1=("@method")')]


def _echo_fetch(status: int = 200):
    def _fetch(target: str, raw: bytes, headers: dict[str, str]) -> FetchResult:
        return FetchResult(url=target, status_code=status,
                           body=json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"echo": len(raw)}}),
                           fetched_at=0.0)
    return _fetch


class PublicInquiryRelayHardeningTest(unittest.TestCase):
    """独立夹具:owner→agent→admin 首绑(托管 SHARE_SECRET_V1)→ 开放询价同意。"""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = os.path.join(self.tmp.name, "catalog.sqlite")
        fernet_key = base64.urlsafe_b64encode(os.urandom(32)).decode()
        self.app = create_catalog_app(self.db_path)
        self.env = unittest.mock.patch.dict(os.environ, {
            "KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN,
            "KIWI_CATALOG_OWNER_TOKEN_SECRET": "test-owner-secret",
            "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
            "KIWI_CATALOG_PUBLIC_BASE_URL": CATALOG_ORIGIN,
            "KIWI_CATALOG_PUBLIC_ORIGIN": CATALOG_ORIGIN,
            "KIWI_CATALOG_ACCESS_CONFIG_KEYS_JSON": json.dumps({"ka-hardening-v1": fernet_key}),
            "KIWI_CATALOG_ACCESS_CONFIG_ACTIVE_KEY_ID": "ka-hardening-v1",
            "KIWI_CATALOG_ACCESS_CUSTODY_ENABLED": "1",
        }, clear=False)
        self.env.start()
        self.addCleanup(self.env.stop)
        self.runtime_pem, self.runtime_jwk = _runtime_key()
        self.owner_session = self._register("owner@hardening.example")
        self.merchant_id = self._merchant_id()
        self.cagt = self._create_agent()
        self.binding_id = self._admin_bind()
        self.grant_consent()
        self.calls: list[tuple[str, bytes]] = []

    # ── 夹具(与 test_runtime_access_api 同构的最小准备) ─────────────────
    def _register(self, email: str) -> str:
        password = "strong-pw-123"
        _s, p = _call(self.app, "POST", "/v1/accounts/register/code", {"email": email})
        _s, p = _call(self.app, "POST", "/v1/accounts/register/verify",
                      {"email": email, "code": p["verification_code"]})
        _s, p = _call(self.app, "POST", "/v1/accounts/register",
                      {"merchant_name": "Hardening 商贸", "email": email, "password": password,
                       "phone": "+86 138 0000 0000", "verification_ticket": p["verification_ticket"]})
        _s, _p, headers = _call_full(self.app, "POST", "/v1/accounts/login",
                                     {"email": email, "password": password})
        return headers["set-cookie"].split(";")[0].split("=", 1)[1]

    def _merchant_id(self) -> str:
        _s, p = _call(self.app, "GET", "/v1/accounts/me", cookie=f"kiwi_session={self.owner_session}")
        return p["merchant_id"]

    def _create_agent(self) -> str:
        _s, p = _call(self.app, "POST", "/v1/accounts/agents", {},
                      cookie=f"kiwi_session={self.owner_session}")
        return p["catalog_agent_id"]

    def _admin_bind(self) -> str:
        from kiwi_catalog.a2a.binding_claims import jwk_thumbprint
        body = {"admin_token": ADMIN_TOKEN,
                "binding": {"runtime_origin": RUNTIME_ORIGIN, "a2a_endpoint": A2A_ENDPOINT,
                            "key_jwk": self.runtime_jwk, "key_id": RUNTIME_ORIGIN,
                            "generation": 1, "service_epoch": 7},
                "access_config": _access_config(SHARE_SECRET_V1, 0)}
        sig = _jws(self.runtime_pem, RUNTIME_ORIGIN, {
            "agent_id": self.cagt, "key_id": RUNTIME_ORIGIN,
            "key_thumbprint": jwk_thumbprint(self.runtime_jwk),
            "runtime_origin": RUNTIME_ORIGIN, "a2a_endpoint": A2A_ENDPOINT,
            "generation": 1, "service_epoch": 7})
        status, payload = _call(self.app, "POST", f"/v1/agents/{self.cagt}/runtime-bindings",
                                body, signature=sig)
        self.assertEqual(status, 200, payload)
        return payload["binding_id"]

    def grant_consent(self) -> None:
        with db_session(self.db_path) as conn:
            policy.grant(conn, agent_id=self.cagt, merchant_id=self.merchant_id,
                         binding_id=self.binding_id, terms_version=policy.TERMS_VERSION)
            conn.execute("insert into card_publications(catalog_agent_id,active_revision,"
                         "publication_state,etag,updated_at) values(?,1,'ACTIVE','tag','t')"
                         " on conflict(catalog_agent_id) do update set publication_state='ACTIVE'",
                         (self.cagt,))

    def _app_on_stack(self, stack: str):
        from kiwi_catalog.api import app as app_module
        if stack == "fastapi":
            return app_module.create_catalog_app(self.db_path)
        with unittest.mock.patch.object(app_module, "FastAPI", None):
            app = app_module.create_catalog_app(self.db_path)
        self.assertEqual(type(app).__name__, "MarketplaceASGIApp")
        return app

    def _call_raw_full(self, app, method: str, path: str, raw: bytes = b"",
                       extra_headers: list[tuple[bytes, bytes]] | None = None,
                       client: tuple[str, int] | None = ("127.0.0.1", 40000),
                       xff: str | None = None):
        headers = [(b"content-type", b"application/json")] + (extra_headers or [])
        if xff:
            headers.append((b"x-forwarded-for", xff.encode()))
        received: list[dict] = []

        async def receive():
            return {"type": "http.request", "body": raw, "more_body": False}

        async def send(msg: dict) -> None:
            received.append(msg)

        scope: dict = {"type": "http", "method": method, "path": path, "headers": headers,
                       "query_string": b"", "http_version": "1.1", "scheme": "http"}
        if client is not None:
            scope["client"] = client

        async def invoke():
            await app(scope, receive, send)

        asyncio.run(invoke())
        start = next(m for m in received if m["type"] == "http.response.start")
        response_headers = {k.decode().lower(): v.decode() for k, v in start.get("headers", [])}
        chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
        try:
            payload = json.loads(chunks.decode("utf-8")) if chunks else {}
        except json.JSONDecodeError:
            payload = {}
        return start["status"], payload, response_headers

    def _inquiry_path(self) -> str:
        return f"/v1/agents/{self.cagt}/public-inquiry"

    def _relay(self, stack: str, raw: bytes, *, client=("127.0.0.1", 40000), xff=None,
               fetch=None):
        inner = fetch or _echo_fetch()

        def _recording_fetcher(target: str, raw_bytes: bytes, headers: dict[str, str]) -> FetchResult:
            self.calls.append((target, raw_bytes, dict(headers)))
            return inner(target, raw_bytes, headers)

        app = self._app_on_stack(stack)
        with unittest.mock.patch.object(ProfileFetcher, "post_signed_a2a", side_effect=_recording_fetcher):
            return self._call_raw_full(app, "POST", self._inquiry_path(), raw,
                                       extra_headers=_signed_headers(), client=client, xff=xff)

    def _consent_body(self, granted: bool, binding_id: str | None = None) -> dict:
        return {"binding": {"binding_id": binding_id or self.binding_id},
                "consent": {"granted": granted, "terms_version": policy.TERMS_VERSION}}

    def _consent_sig(self, body: dict, method: str = "PUT", *, pem: str | None = None) -> str:
        from kiwi_catalog.a2a.enrollment_canonical import canonical_digest
        # GET 无请求体:body_digest 对空对象签名(目录 read 端点同口径)。
        digest_source = {} if method == "GET" else body
        return _jws(pem or self.runtime_pem, RUNTIME_ORIGIN, {
            "method": method, "path": self._inquiry_path() + "-consent",
            "audience": "kiwi-catalog", "body_digest": canonical_digest(digest_source),
            "catalog_agent_id": self.cagt, "binding_id": body["binding"]["binding_id"],
            "key_id": RUNTIME_ORIGIN, "runtime_origin": RUNTIME_ORIGIN, "service_epoch": 7,
        }, with_exp=True)

    def _access_rows(self) -> int:
        with db_session(self.db_path) as conn:
            return conn.execute("select count(*) from public_inquiry_consents where catalog_agent_id=?",
                                (self.cagt,)).fetchone()[0]

    def _drop_consent(self) -> None:
        with db_session(self.db_path) as conn:
            conn.execute("delete from public_inquiry_consents where catalog_agent_id=?", (self.cagt,))

    # ── F-1 ─────────────────────────────────────────────────────────────
    def test_f1_dual_stack_raw_body_boundaries_and_exact_forwarding(self) -> None:
        """49153/65536 接受且逐字节转发;65537 拒绝且不外发;双栈一致。"""
        for stack in ("fastapi", "fallback"):
            for size in (49153, 65536, 65537):
                with self.subTest(stack=stack, size=size):
                    self.calls.clear()
                    raw = _body_with_pad(size, f"m-{size}")
                    status, payload, _h = self._relay(stack, raw)
                    if size <= 65536:
                        self.assertEqual(status, 200, payload)
                        self.assertEqual(self.calls[-1][1], raw)  # 逐字节精确转发
                        self.assertEqual(payload["result"]["echo"], len(raw))
                    else:
                        self.assertEqual(status, 400, payload)
                        self.assertEqual(self.calls, [])  # 超限请求绝不外发

    def test_f1_client_forged_transport_keys_cannot_bypass(self) -> None:
        """伪造传输层同名键:超长键被客户端 JSON 限制拒绝;合法大小的伪造键是
        客户端 JSON 的惰性内容(原样转发、不被当作元数据)——中继的转发头、
        限流桶与响应校验只使用传输层注入的真值。"""
        client_body = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {},
                       "_raw_inquiry_body_b64": _b64(b"A" * 70000),
                       "_inquiry_headers": {"content-type": "text/html"},
                       "_client_ip": "6.6.6.6"}
        status, payload, _h = self._relay("fallback", json.dumps(client_body).encode())
        self.assertEqual(status, 400, payload)  # 伪造超长键计入客户端 JSON 限制
        self.assertEqual(self.calls, [])
        inert = {**client_body, "_raw_inquiry_body_b64": _b64(b"B" * 64)}
        inert_raw = json.dumps(inert).encode()
        status, payload, _h = self._relay("fallback", inert_raw)
        self.assertEqual(status, 200, payload)
        _target, forwarded_raw, forwarded_headers = self.calls[-1]
        self.assertEqual(forwarded_raw, inert_raw)  # 客户端 body 原样转发(伪造键为惰性内容)
        # 转发头来自传输层 allowlist(真实 HTTP 头);客户端 JSON 里的伪造头不生效。
        self.assertEqual(forwarded_headers.get("content-type"), "application/json")
        self.assertNotIn("text/html", json.dumps(forwarded_headers))
        self.assertEqual(payload["result"]["echo"], len(inert_raw))
        self.assertNotIn("6.6.6.6", json.dumps(payload))

    def test_f1_deep_json_returns_400_never_500(self) -> None:
        for stack in ("fastapi", "fallback"):
            for depth in (100, 5000):
                with self.subTest(stack=stack, depth=depth):
                    raw = (b'{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"d":'
                           + b"[" * depth + b"1" + b"]" * depth + b"}}")
                    status, payload, _h = self._relay(stack, raw)
                    self.assertEqual(status, 400, payload)
                    self.assertIn("error", payload)

    # ── F-2 ─────────────────────────────────────────────────────────────
    def test_f2_relay_failure_body_is_strictly_fixed_with_no_store(self) -> None:
        for stack in ("fastapi", "fallback"):
            with self.subTest(stack=stack):
                def _boom(target, raw, headers):
                    raise FetchError(f"Fetch failed for '{target}': connection reset")
                status, payload, headers = self._relay(stack, _inquiry_body(), fetch=_boom)
                self.assertEqual(status, 502, payload)
                for meta in ("__status__", "__no_store__", "__cookies__"):
                    self.assertNotIn(meta, payload)
                self.assertEqual(payload["error"]["code"], -32000)
                self.assertEqual(headers.get("cache-control"), "no-store")
                self.assertIn("application/json", headers.get("content-type", ""))
                self.assertEqual(headers.get("x-content-type-options"), "nosniff")

    def test_f2_cookie_and_shape_regressions_on_fallback(self) -> None:
        """Set-Cookie 走响应头;404/错误为 JSON,不 HTML 不跳转;元字段不外泄。"""
        fallback = self._app_on_stack("fallback")
        status, payload, headers = self._call_raw_full(
            fallback, "POST", "/v1/accounts/login",
            json.dumps({"email": "owner@hardening.example", "password": "strong-pw-123"}).encode())
        self.assertEqual(status, 200, payload)
        self.assertIn("set-cookie", headers)
        for meta in ("__status__", "__no_store__", "__cookies__"):
            self.assertNotIn(meta, payload)
        status, payload, headers = self._call_raw_full(fallback, "GET", "/v1/definitely/unknown")
        self.assertEqual(status, 404)
        self.assertNotIn("location", headers)
        self.assertIn("application/json", headers.get("content-type", ""))

    # ── F-4 / F-8 ───────────────────────────────────────────────────────
    def test_f4_logs_are_fixed_codes_without_url_secret_or_exception_text(self) -> None:
        hostile_agent = f"{self.cagt}%0AEVIL-INJECTION"

        def _raise_with_secret(target, raw, headers):
            raise FetchError("Fetch failed for 'https://merchant.test:8443/a2a?sharecode=TOPSECRET': boom")

        with self.assertLogs(LOG_NAME, level="WARNING") as logs:
            status, _p, _h = self._relay("fallback", _inquiry_body("m-f4a"), fetch=_raise_with_secret)
            self.assertEqual(status, 502)
        joined = "\n".join(logs.output)
        self.assertIn("PUBLIC_INQUIRY_RELAY_FAILED", joined)
        self.assertIn("FetchError", joined)
        for forbidden in ("TOPSECRET", "https://", "boom", "sharecode="):
            self.assertNotIn(forbidden, joined)

        def _upstream_403(target, raw, headers):
            return FetchResult(url=target, status_code=403, body="upstream says TOPSECRET", fetched_at=0.0)

        with self.assertLogs(LOG_NAME, level="WARNING") as logs:
            status, _p, _h = self._relay("fallback", _inquiry_body("m-f4b"), fetch=_upstream_403)
            self.assertEqual(status, 502)
        joined = "\n".join(logs.output)
        self.assertIn("PUBLIC_INQUIRY_UPSTREAM_REJECTED", joined)
        self.assertIn("upstream_status=403", joined)
        self.assertNotIn("TOPSECRET", joined)

        def _upstream_leak(target, raw, headers):
            # 泄漏内容必须是**目录托管的真实分享码**:UPSTREAM_INVALID 分支的
            # 触发条件是响应命中 _contains_gate_secret。
            return FetchResult(url=target, status_code=200,
                               body=json.dumps({"jsonrpc": "2.0", "id": 1,
                                                "result": {"leak": SHARE_SECRET_V1}}), fetched_at=0.0)

        with self.assertLogs(LOG_NAME, level="WARNING") as logs:
            status, _p, _h = self._relay("fallback", _inquiry_body("m-f4c"), fetch=_upstream_leak)
            self.assertEqual(status, 502)
        joined = "\n".join(logs.output)
        self.assertIn("PUBLIC_INQUIRY_UPSTREAM_INVALID", joined)
        self.assertNotIn("TOPSECRET", joined)

        def _raise_boom(target, raw, headers):
            raise FetchError("boom")

        # 恶意路径 id 解析不到任何 agent → 404 早退,且零日志注入。
        app = self._app_on_stack("fallback")
        with self.assertNoLogs(LOG_NAME):
            with unittest.mock.patch.object(ProfileFetcher, "post_signed_a2a", side_effect=_raise_boom):
                status, _p, _h = self._call_raw_full(
                    app, "POST",
                    f"/v1/agents/{hostile_agent}/public-inquiry", _inquiry_body("m-f4d"),
                    extra_headers=_signed_headers())
                self.assertEqual(status, 404)
        # _log_safe_id 直测:换行/引号/控制字符被转义,长度有界(日志注入面收敛)。
        from kiwi_catalog.api.handlers.public_inquiry import _log_safe_id
        hostile = "cagt_x\nEVIL\u2028;DROP"
        safe = _log_safe_id(hostile)
        self.assertNotIn("\n", safe)
        self.assertNotIn("EVIL\u2028", safe.replace("\\u2028", ""))
        self.assertLessEqual(len(safe), 128 + 4 * 128)
        self.assertEqual(_log_safe_id("cagt-ok._:-9"), "cagt-ok._:-9")  # 安全字符原样

    def test_f8_recovery_flow_state_intact_after_failures(self) -> None:
        """失败序列后:固定 502 文案一致;授权状态未被破坏;重试直接成功。"""
        outcomes = []
        for fetch in (
            (lambda t, r, h: (_ for _ in ()).throw(FetchError("network down"))),
            (lambda t, r, h: FetchResult(url=t, status_code=502, body="bad gateway", fetched_at=0.0)),
            _echo_fetch(),
        ):
            outcomes.append(self._relay("fallback", _inquiry_body("m-f8"), fetch=fetch))
        for status, payload, _h in outcomes[:2]:
            self.assertEqual(status, 502)
            self.assertEqual(payload["error"]["message"], "商家服务暂不可用，请稍后重试")
        self.assertEqual(outcomes[2][0], 200)
        body = self._consent_body(True)
        status, payload, _h = _call_full(self.app, "GET", self._inquiry_path() + "-consent",
                                         signature=self._consent_sig(body, method="GET"))
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload["granted"])
        self.assertTrue(payload["policy_active"])

    # ── F-5 ─────────────────────────────────────────────────────────────
    def test_f5_consent_revoke_idempotent_and_signature_gated(self) -> None:
        path = self._inquiry_path() + "-consent"
        self._drop_consent()  # "从未授权"状态(setUp 默认已授权,需先清)
        self.assertEqual(self._access_rows(), 0)
        never = self._consent_body(False)
        for _ in range(2):  # 从未授权:撤销幂等 200(目标状态本就成立),不产生行
            status, payload, _h = _call_full(self.app, "PUT", path, never,
                                             signature=self._consent_sig(never))
            self.assertEqual(status, 200, payload)
            self.assertFalse(payload["granted"])
        self.assertEqual(self._access_rows(), 0)
        grant = self._consent_body(True)
        status, payload, _h = _call_full(self.app, "PUT", path, grant,
                                         signature=self._consent_sig(grant))
        self.assertEqual(status, 200, payload)
        self.assertEqual(self._access_rows(), 1)
        revoke = self._consent_body(False)
        status, payload, _h = _call_full(self.app, "PUT", path, revoke,
                                         signature=self._consent_sig(revoke))
        self.assertEqual(status, 200, payload)
        status, payload, _h = _call_full(self.app, "PUT", path, revoke,
                                         signature=self._consent_sig(revoke))
        self.assertEqual(status, 200, payload)  # 重复撤销:幂等 200,不 404 不 500
        status, payload, _h = _call_full(self.app, "GET", path,
                                         signature=self._consent_sig(self._consent_body(True), method="GET"))
        self.assertFalse(payload["granted"])
        self.assertFalse(payload["policy_active"])
        # 绑定签名必填:无签名 / 错误密钥 → 拒绝;错误绑定 → 404。
        status, payload, _h = _call_full(self.app, "PUT", path, grant)
        self.assertGreaterEqual(status, 400)
        wrong_pem, _jwk = _runtime_key()
        status, payload, _h = _call_full(self.app, "PUT", path, grant,
                                         signature=self._consent_sig(grant, pem=wrong_pem))
        self.assertGreaterEqual(status, 400)
        foreign = self._consent_body(True, binding_id="bnd_not_mine")
        status, payload, _h = _call_full(self.app, "PUT", path, foreign,
                                         signature=self._consent_sig(foreign))
        self.assertIn(status, (400, 404))
        # 撤权不可绕过:撤销后,即便携带有效绑定签名,买家路径 fail-closed。
        status, payload, _h = self._relay("fallback", _inquiry_body("m-f5"))
        self.assertEqual(status, 404, payload)
        status, _p, _h = self._call_raw_full(self._app_on_stack("fallback"), "GET", self._inquiry_path())
        self.assertEqual(status, 404)

    # ── F-7 ─────────────────────────────────────────────────────────────
    def test_f7_forged_client_ip_cannot_split_rate_limit_bucket(self) -> None:
        """未授权(每次 404 仍消耗预算):30 次轮换伪造 IP 消耗同一桶,第 31 次
        (又一个新伪造 IP)必须 429 —— body 冒充不了传输层分桶。"""
        self._drop_consent()
        last: tuple[int, dict, dict] | None = None
        for i in range(30):
            spoofed = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
                                  "params": {}, "_client_ip": f"10.0.0.{i}"}).encode()
            last = self._relay("fallback", spoofed, client=None)
        self.assertEqual(last[0], 404, last[1])  # 前 30 次:未授权 404(预算已耗尽)
        rotated = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
                              "params": {}, "_client_ip": "10.9.9.9"}).encode()
        status, payload, _h = self._relay("fallback", rotated, client=None)
        self.assertEqual(status, 429, payload)  # 伪造新 IP 不换桶

    def test_f7_trusted_proxy_xff_and_custom_handler_regression(self) -> None:
        self._drop_consent()
        for i in range(30):  # 耗尽直连(unknown)桶
            self._relay("fallback", _inquiry_body(f"m-f7x-{i}"), client=("127.0.0.1", 40001))
        status, payload, _h = self._relay("fallback", _inquiry_body("m-f7x-direct"),
                                          client=("127.0.0.1", 40001))
        self.assertEqual(status, 429, payload)
        status, payload, _h = self._relay("fallback", _inquiry_body("m-f7x-xff"),
                                          client=("127.0.0.1", 40002), xff="9.9.9.9")
        self.assertEqual(status, 404, payload)  # 可信代理 XFF=独立桶,未授权 404
        seen: dict = {}

        def custom_handler(db_path, method, path, payload, query):
            seen["payload"] = dict(payload)
            seen["kwargs"] = "none"
            return 200, {"ok": True, "custom": True}

        custom_app = MarketplaceASGIApp(
            self.db_path,
            handle_request_fn=custom_handler,
            route_provider=lambda: list(all_routes()),
            route_resolver=lambda method, path: resolve_route(method, path),
        )
        forged = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "SendMessage",
                             "params": {}, "_client_ip": "6.6.6.6"}).encode()
        status, payload, _h = self._call_raw_full(
            custom_app, "POST", self._inquiry_path(), forged,
            extra_headers=_signed_headers(), client=("127.0.0.1", 40003))
        self.assertEqual(status, 200, payload)
        self.assertTrue(payload.get("custom"))
        injected = seen["payload"]
        self.assertEqual(injected["_raw_inquiry_body_b64"], _b64(forged))
        self.assertEqual(injected["_client_ip"], "127.0.0.1")  # 传输层直连对端,非伪造值
        self.assertEqual(seen["kwargs"], "none")  # 自定义 handler 不接收 trusted keys


if __name__ == "__main__":
    unittest.main()
