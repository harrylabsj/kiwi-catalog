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

"""kiwi-catalog /v1/agents 新 API + 三正交状态域集成测试（v0.3 §7/§8/§9）。

覆盖：
- register 带 handoff_destination_types / capabilities / display_name 落库
  （public-only；非法 handoff 词表拒绝）；
- /v1/agents/search 三态域 + handoff 词表过滤（AND 语义）；
- /v1/agents/{id} record 形状（三域原样、legacy 折叠列同步）；
- 三域迁移：级别晋升/降级、freshness、行政处置、reinstate 保留级别；
- 折叠投影一致性：set_state_domains 后 verification_status 与 fold 一致。
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from unittest import mock

from kiwi_catalog.api.app import create_catalog_app
from kiwi_catalog.agent_catalog.state_domains import InvalidStateTransitionError
from kiwi_catalog.db.session import db_session
from kiwi_catalog.agent_catalog.sqlite_repository import require_catalog_agent

REGISTER_BODY = {
    "domain": "acme.example",
    "display_name": "Acme Merchant",
    "agent_card_url": "https://acme.example/.well-known/agent-card.json",
    "hosting_mode": "direct_only",
    "handoff_destination_types": ["external_checkout_url", "quote_document"],
    "capabilities": ["com.harrylabsj.shopping.capability:catalog"],
}


def _noop_enqueue(db_path, catalog_agent_id, *, kind="verify", actor="verification_worker"):
    """测试替身：注册不真的跑异步验证。

    审查 P3：REJECTED（证据失效）→ freshness=STALE 是异步可见状态——真实
    队列任务会让紧随注册的断言（fold/三域）竞态。确定性测试用替身。
    """
    return type("_StubTask", (), {"task_id": ""})()


def _call_http(app, method: str, path: str, body: bytes = b"") -> tuple[int, dict]:
    """裸 ASGI 调用（fallback 栈），返回 (status, parsed json)。

    query 参数经 scope["query_string"] 传递（fallback ASGI 从 scope 解析，
    不解析 path 中的 ?…）。
    """
    path_only = path.split("?", 1)[0]
    query_bytes = path.split("?", 1)[1].encode() if "?" in path else b""
    scope = {
        "type": "http",
        "method": method,
        "path": path_only,
        "headers": [(b"content-type", b"application/json")],
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
    status = next((m.get("status") for m in received if m["type"] == "http.response.start"), None)
    chunks = b"".join(m.get("body", b"") for m in received if m["type"] == "http.response.body")
    payload: dict = {}
    if chunks:
        payload = json.loads(chunks.decode())
    return status or 500, payload


class KiwiCatalogV1ApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        self.app = create_catalog_app(self.db_path)

    def _register(self, overrides: dict | None = None) -> dict:
        body = {**REGISTER_BODY, **(overrides or {})}
        status, payload = _call_http(
            self.app, "POST", "/v1/agents/register", json.dumps(body).encode()
        )
        self.assertEqual(status, 200, payload)
        return payload

    def test_register_stores_public_fields_and_three_domains(self) -> None:
        payload = self._register()
        agent = payload["agent"]
        self.assertEqual(agent["display_name"], "Acme Merchant")
        # canonical 输入（direct_only）在写边界归一化为 legacy 存储值（direct）——
        # wire schema 两种都收，消费方 normalize 无感知。
        self.assertEqual(agent["hosting_mode"], "direct")
        self.assertEqual(agent["handoff_destination_types"], ["external_checkout_url", "quote_document"])
        self.assertEqual(agent["capabilities"], ["com.harrylabsj.shopping.capability:catalog"])
        # 三正交域初始值
        self.assertEqual(agent["verification_level"], "discovered")
        self.assertEqual(agent["freshness_state"], "fresh")
        self.assertEqual(agent["administrative_state"], "active")
        self.assertTrue(payload["verification_enqueued"])

    def test_register_rejects_parallel_supports_vocabulary(self) -> None:
        status, payload = _call_http(
            self.app,
            "POST",
            "/v1/agents/register",
            json.dumps(
                {**REGISTER_BODY, "handoff_destination_types": ["supports_external_checkout"]}
            ).encode(),
        )
        self.assertEqual(status, 400)
        # schema 硬拒（register-input.schema.json 词表校验）——非法词表值被拒
        self.assertIn("supports_external_checkout", str(payload.get("error", "")))

    def test_search_filters_by_three_domains_and_handoff(self) -> None:
        from kiwi_catalog.api.handlers import agent_catalog as handlers_mod

        with mock.patch.object(
            handlers_mod, "_enqueue_verification", side_effect=_noop_enqueue
        ):
            self._register()
        # 全量命中
        _, payload = _call_http(
            self.app,
            "GET",
            "/v1/agents/search?handoff_destination_types=external_checkout_url",
        )
        self.assertEqual(len(payload["results"]), 1)
        # handoff 不匹配 → 空
        _, payload = _call_http(
            self.app,
            "GET",
            "/v1/agents/search?handoff_destination_types=platform_deep_link",
        )
        self.assertEqual(payload["results"], [])
        # 三态域过滤
        _, payload = _call_http(
            self.app,
            "GET",
            "/v1/agents/search?verification_level=discovered&freshness_state=fresh&administrative_state=active",
        )
        self.assertEqual(len(payload["results"]), 1)
        _, payload = _call_http(
            self.app,
            "GET",
            "/v1/agents/search?administrative_state=suspended",
        )
        self.assertEqual(payload["results"], [])

    def test_get_agent_record_shape(self) -> None:
        registered = self._register()
        cagt_id = registered["agent"]["catalog_agent_id"]
        status, payload = _call_http(self.app, "GET", f"/v1/agents/{cagt_id}")
        self.assertEqual(status, 200)
        self.assertEqual(payload["agent"]["catalog_agent_id"], cagt_id)
        self.assertNotIn("floor_price_minor", payload["agent"])  # #8 private-only

    def test_register_queue_full_is_graceful_not_500(self) -> None:
        """审查 P1-8：队列满 → 注册成功但显式标注未入队（此前 except 引用
        未定义名字抛 NameError → 500，调用方重试拿到「已入队」假象）。"""
        from kiwi_catalog.api.handlers import agent_catalog as handlers_mod
        from kiwi_catalog.services.agent_verification import VerificationQueueFullError

        with mock.patch.object(
            handlers_mod,
            "_enqueue_verification",
            side_effect=VerificationQueueFullError("queue full"),
        ):
            status, payload = _call_http(
                self.app,
                "POST",
                "/v1/agents/register",
                json.dumps(REGISTER_BODY).encode(),
            )
        self.assertEqual(status, 200, payload)
        self.assertFalse(payload.get("verification_enqueued", True))
        self.assertIn("queue full", payload.get("queue_reason", ""))

    def test_register_idempotency_hash_includes_public_fields(self) -> None:
        """审查 P2：同 key 改 display_name 等公开字段 → 409（此前 hash 不含
        这些字段，同 key 改字段被静默重放，调用方以为新字段已生效）。"""
        body = {**REGISTER_BODY, "domain": "hashcheck.example", "idempotency_key": "idem-reg-1"}
        status, first = _call_http(
            self.app, "POST", "/v1/agents/register", json.dumps(body).encode()
        )
        self.assertEqual(status, 200, first)
        body2 = {**body, "display_name": "Renamed"}
        status, payload = _call_http(
            self.app, "POST", "/v1/agents/register", json.dumps(body2).encode()
        )
        self.assertEqual(status, 409, payload)

    def test_legacy_route_consumes_v1_registered_agent(self) -> None:
        """#4 authority 转移消费端可用性：v1 register → legacy /v1/agent-catalog
        搜索命中，折叠 verification.status 与 v1 三态域一致（独立服务承载
        Agent Catalog 后，legacy 消费端照常工作）。"""
        from kiwi_catalog.api.handlers import agent_catalog as handlers_mod

        with mock.patch.object(
            handlers_mod, "_enqueue_verification", side_effect=_noop_enqueue
        ):
            registered = self._register()
        status, payload = _call_http(self.app, "GET", "/v1/agent-catalog/agents/search")
        self.assertEqual(status, 200)
        self.assertEqual(len(payload["results"]), 1)
        result = payload["results"][0]
        self.assertEqual(result["catalog_agent_id"], registered["agent"]["catalog_agent_id"])
        self.assertEqual(result["verification"]["status"], "discovered")  # 三态域折叠
        self.assertEqual(result["contract"], {"name": "candidate-agent", "version": "1.0"})

    def test_unknown_agent_404(self) -> None:
        status, _ = _call_http(self.app, "GET", "/v1/agents/does_not_exist")
        self.assertEqual(status, 404)


class ThreeDomainPersistenceTest(unittest.TestCase):
    """三域写入 → 折叠投影一致性 + 迁移约束（repository 层）。"""

    def setUp(self) -> None:
        # 治理重注册（P1-4b 修复后需 admin token）与 moderation 测试需要
        os.environ["KIWI_CATALOG_ADMIN_TOKEN"] = "test-admin"
        self.addCleanup(os.environ.pop, "KIWI_CATALOG_ADMIN_TOKEN", None)
        self.tmp = tempfile.mkdtemp()
        self.db_path = os.path.join(self.tmp, "catalog.sqlite")
        self.app = create_catalog_app(self.db_path)
        body = json.dumps(REGISTER_BODY).encode()
        # enqueue 替身：异步验证任务会让紧随的 fold/三域断言竞态（审查 P3）
        from kiwi_catalog.api.handlers import agent_catalog as handlers_mod

        with mock.patch.object(
            handlers_mod, "_enqueue_verification", side_effect=_noop_enqueue
        ):
            _, payload = _call_http(self.app, "POST", "/v1/agents/register", body)
        self.cagt_id = payload["agent"]["catalog_agent_id"]

    def _row(self) -> dict:
        with db_session(self.db_path) as conn:
            return require_catalog_agent(conn, self.cagt_id)

    def test_set_state_domains_syncs_fold_projection(self) -> None:
        from kiwi_catalog.agent_catalog.sqlite_repository import set_state_domains

        with db_session(self.db_path) as conn:
            set_state_domains(
                conn,
                self.cagt_id,
                verification_level="domain_verified",
                freshness_state="stale",
                administrative_state="active",
            )
        row = self._row()
        self.assertEqual(row["verification_level"], "domain_verified")
        self.assertEqual(row["freshness_state"], "stale")
        self.assertEqual(row["verification_status"], "stale")  # 折叠：stale > level

        with db_session(self.db_path) as conn:
            set_state_domains(conn, self.cagt_id, administrative_state="suspended")
        row = self._row()
        self.assertEqual(row["verification_status"], "suspended")  # 折叠：suspended 最重

    def test_reinstate_preserves_verification_level(self) -> None:
        from kiwi_catalog.services.agent_verification import VerificationService
        from kiwi_catalog.agent_catalog.sqlite_repository import set_state_domains

        with db_session(self.db_path) as conn:
            set_state_domains(conn, self.cagt_id, verification_level="commerce_verified")
            service = VerificationService(conn)
            service.suspend(self.cagt_id, actor="admin", reason="test")
            row = require_catalog_agent(conn, self.cagt_id)
            self.assertEqual(row["administrative_state"], "suspended")
            self.assertEqual(row["verification_level"], "commerce_verified")
            service.reinstate(self.cagt_id, actor="admin", reason="test")
            row = require_catalog_agent(conn, self.cagt_id)
        # v0.3 语义：恢复后级别保留（legacy 重置为 discovered 的行为已被取代）
        self.assertEqual(row["administrative_state"], "active")
        self.assertEqual(row["verification_level"], "commerce_verified")
        self.assertEqual(row["verification_status"], "commerce_verified")

    def test_mark_stale_keeps_level(self) -> None:
        from kiwi_catalog.services.agent_verification import VerificationService
        from kiwi_catalog.agent_catalog.sqlite_repository import set_state_domains

        with db_session(self.db_path) as conn:
            set_state_domains(conn, self.cagt_id, verification_level="agent_verified")
            service = VerificationService(conn)
            service.mark_stale(self.cagt_id)
            row = require_catalog_agent(conn, self.cagt_id)
        self.assertEqual(row["freshness_state"], "stale")
        self.assertEqual(row["verification_level"], "agent_verified")
        self.assertEqual(row["verification_status"], "stale")

    def test_rejected_admin_is_terminal_for_verify(self) -> None:
        from kiwi_catalog.services.agent_verification import VerificationService
        from kiwi_catalog.agent_catalog.sqlite_repository import set_state_domains

        with db_session(self.db_path) as conn:
            set_state_domains(conn, self.cagt_id, administrative_state="rejected")
            service = VerificationService(conn)
            with self.assertRaises(InvalidStateTransitionError):
                service.verify(self.cagt_id)

    def test_rejected_fold_and_registration_reopen(self) -> None:
        """行政 REJECTED 折叠为 rejected；同域可重新注册（v0.3 §7.3 可恢复终态）。

        审查 P1-4b：复活治理处置需 admin token（或既有绑定商户的 owner token）。
        """
        from kiwi_catalog.agent_catalog.sqlite_repository import set_state_domains

        with db_session(self.db_path) as conn:
            set_state_domains(conn, self.cagt_id, administrative_state="rejected")
            row = require_catalog_agent(conn, self.cagt_id)
        self.assertEqual(row["verification_status"], "rejected")

        status, payload = _call_http(
            self.app,
            "POST",
            "/v1/agents/register",
            json.dumps(
                {**REGISTER_BODY, "domain": "acme.example", "admin_token": "test-admin"}
            ).encode(),
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["agent"]["catalog_agent_id"], self.cagt_id)

    def test_rejected_profile_failure_marks_stale_for_reverify(self) -> None:
        """审查 P3：REJECTED（证据失效）后 freshness=STALE——/verify（不
        force）不再被 freshness 门短路成 no-op，可重试恢复。"""
        from kiwi_catalog.agent_catalog.sqlite_repository import require_catalog_agent
        from kiwi_catalog.services.agent_verification import (
            REJECTED,
            VerificationService,
            _ProfileFailure,
        )

        with db_session(self.db_path) as conn:
            service = VerificationService(conn)
            with mock.patch.object(
                service,
                "_load_profiles",
                side_effect=_ProfileFailure(REJECTED, "mock rejected"),
            ):
                result = service.verify(self.cagt_id, actor="test")
            self.assertIsNotNone(result)
            row = require_catalog_agent(conn, self.cagt_id)
            self.assertEqual(row["freshness_state"], "stale")
            # 下一次非 force verify：freshness=STALE → 门不短路，真正重跑
            #（用成功的 profiles 替身验证阶梯推进，而非返回 early no-op）
            class _FakeCard:
                canonical_domain = "acme.example"

            class _FakeProfiles:
                card = _FakeCard()
                ucp = None  # 参数求值需要属性存在；trust_evaluator 被 mock 忽略
                urls = {
                    "agent_card": "https://acme.example/a.json",
                    "ucp_profile": "https://acme.example/u.json",
                }
                snapshot_ids = (1, 2)

            from kiwi_catalog.discovery.verifier import VerificationEvidence

            def _passing_domain_control(_c: str, declared: dict | None = None) -> VerificationEvidence:
                return VerificationEvidence(
                    verification_type="domain_control",
                    result="passed",
                    details={},
                    reason="mock pass",
                    expires_in_seconds=3600,
                )

            service2 = VerificationService(conn)
            service2._load_profiles = lambda _cid: _FakeProfiles()  # type: ignore[method-assign]
            service2._identity_verifier.verify_domain_control = _passing_domain_control  # type: ignore[method-assign]
            service2._trust_evaluator.evaluate_agent_identity = (  # type: ignore[method-assign]
                lambda _card, _ucp, _domain: VerificationEvidence(
                    verification_type="agent_identity",
                    result="passed",
                    details={},
                    reason="mock pass",
                    expires_in_seconds=3600,
                )
            )
            service2._trust_evaluator.evaluate_commerce_capabilities = (  # type: ignore[method-assign]
                lambda _card, _ucp, _domain: VerificationEvidence(
                    verification_type="commerce_capability",
                    result="passed",
                    details={},
                    reason="mock pass",
                    expires_in_seconds=3600,
                )
            )
            retry = service2.verify(self.cagt_id, actor="test")
            self.assertEqual(retry.status, "commerce_verified", retry)

    def test_verify_reentry_domain_failure_keeps_evidence_level(self) -> None:
        """审查 P1-7：重验证中 domain 阶段瞬时失败 → 按最新 passed 证据降级到
        DOMAIN_VERIFIED，而非清级后恒 DISCOVERED（§7.1 证据重算主链路回归）。"""
        from datetime import datetime, timedelta, timezone

        from kiwi_catalog.agent_catalog.sqlite_repository import (
            insert_verification,
            set_state_domains,
        )
        from kiwi_catalog.discovery.verifier import VerificationEvidence
        from kiwi_catalog.services.agent_verification import (
            DISCOVERED,
            DOMAIN_VERIFIED,
            VerificationService,
        )

        class _FakeCard:
            canonical_domain = "acme.example"

        class _FakeProfiles:
            card = _FakeCard()
            urls = {
                "agent_card": "https://acme.example/.well-known/agent-card.json",
                "ucp_profile": "https://acme.example/ucp.json",
            }
            snapshot_ids = (1, 2)

        def _failing_domain_control(_canonical: str, declared: dict | None = None) -> VerificationEvidence:
            return VerificationEvidence(
                verification_type="domain_control",
                result="failed",
                details={},
                reason="mock domain control failure",
                expires_in_seconds=3600,
            )

        with db_session(self.db_path) as conn:
            set_state_domains(conn, self.cagt_id, verification_level="agent_verified")
            insert_verification(
                conn,
                catalog_agent_id=self.cagt_id,
                verification_type="domain_control",
                result="passed",
                evidence_json="{}",
                checked_at=(datetime.now(timezone.utc)).isoformat(),
                expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            )

        with db_session(self.db_path) as conn:
            service = VerificationService(conn)
            service._load_profiles = lambda _cid: _FakeProfiles()  # type: ignore[method-assign]
            service._identity_verifier.verify_domain_control = _failing_domain_control  # type: ignore[method-assign]
            result = service.verify(self.cagt_id, actor="test", force=True)
        self.assertEqual(result.status, "domain_verified", result)
        row = self._row()
        self.assertEqual(row["verification_level"], DOMAIN_VERIFIED)
        self.assertNotEqual(row["verification_level"], DISCOVERED)

        # 二次失败：最新一条证据已是 failed，passed 证据仍应支撑 DOMAIN_VERIFIED
        # （failed 行不得屏蔽历史 passed 证据）。
        with db_session(self.db_path) as conn:
            service = VerificationService(conn)
            service._load_profiles = lambda _cid: _FakeProfiles()  # type: ignore[method-assign]
            service._identity_verifier.verify_domain_control = _failing_domain_control  # type: ignore[method-assign]
            service.verify(self.cagt_id, actor="test", force=True)
        row = self._row()
        self.assertEqual(row["verification_level"], DOMAIN_VERIFIED)

    def test_v1_search_pagination_crosses_verification_ranks(self) -> None:
        """审查 P1-6：agent 搜索跨验证等级分页不丢行（游标与排序键同键）。

        历史 bug：游标只编码 catalog_agent_id，ORDER BY 首键是验证等级 rank
        组（同 rank 内按 last_verified_at/display_name）——rank 组的行跨页丢。
        """
        from kiwi_catalog.agent_catalog.sqlite_repository import set_state_domains

        ids: list[str] = []
        for domain in ("alpha.example", "beta.example", "gamma.example"):
            status, payload = _call_http(
                self.app,
                "POST",
                "/v1/agents/register",
                json.dumps({**REGISTER_BODY, "domain": domain}).encode(),
            )
            self.assertEqual(status, 200, payload)
            ids.append(payload["agent"]["catalog_agent_id"])
        with db_session(self.db_path) as conn:
            set_state_domains(conn, ids[0], verification_level="commerce_verified")
            set_state_domains(conn, ids[1], verification_level="domain_verified")
            # ids[2] 保持 discovered（rank 4）

        seen: list[str] = []
        cursor = ""
        for _ in range(10):
            path = (
                f"/v1/agents/search?limit=1&cursor={cursor}"
                if cursor
                else "/v1/agents/search?limit=1"
            )
            _, page = _call_http(self.app, "GET", path)
            seen += [r["catalog_agent_id"] for r in page["results"]]
            cursor = page["next_cursor"]
            if not cursor:
                break
        # setUp 已注册 acme.example（discovered，与 gamma 同 rank 组——顺带
        # 覆盖同 rank 内 display_name/id tie-break），合计 4 行
        self.assertEqual(len(seen), 4, "all 4 agents must be reachable across pages")
        self.assertEqual(len(set(seen)), 4, "no overlap / no skip across pages")

    def test_anonymous_register_cannot_revive_governed_agent(self) -> None:
        """审查 P1-4b：治理处置（suspended）的 agent 匿名重注册必须拒绝。

        复活 = 撤销 admin 处置，需 admin token 或既有绑定商户的 owner token。
        """
        from kiwi_catalog.agent_catalog.sqlite_repository import set_state_domains

        with db_session(self.db_path) as conn:
            set_state_domains(conn, self.cagt_id, administrative_state="suspended")

        status, payload = _call_http(
            self.app,
            "POST",
            "/v1/agents/register",
            json.dumps({**REGISTER_BODY, "domain": "acme.example"}).encode(),
        )
        self.assertEqual(status, 403, payload)
        self.assertEqual(self._row()["administrative_state"], "suspended")

    def _issue_merchant_token(self, email: str, domain: str) -> tuple[str, str]:
        """apply → approve 签发随机 merchant token，返回 (merchant_id, token)。"""
        status, applied = _call_http(
            self.app,
            "POST",
            "/v1/merchants/applications",
            json.dumps(
                {
                    "domain": domain,
                    "agent_name": "Merchant Agent",
                    "contact_email": email,
                    "purpose": "sell industrial displays",
                }
            ).encode(),
        )
        self.assertEqual(status, 200, applied)
        app_id = applied["application"]["application_id"]
        status, issued = _call_http(
            self.app,
            "POST",
            f"/v1/merchants/applications/{app_id}/approve",
            json.dumps({"admin_token": "test-admin"}).encode(),
        )
        self.assertEqual(status, 200, issued)
        self.assertTrue(issued["merchant_id"].startswith("mkt_"))
        return issued["merchant_id"], issued["token"]

    def test_foreign_merchant_token_cannot_revive_or_steal_governed_agent(self) -> None:
        """审查 P2（v17 一域多商家后）：外来商户 token 不得复活/抢绑他人被治理
        agent——它只会在共享域名上新建**自己的** agent，原 merchant 的治理行
        保持不变。

        历史 bug（P1-A）：旧 merchant 分支经域名级查询复用被治理行并改绑
        merchant_id；修复后 merchant 路径按商户主键只选自己的 agent，治理行的
        处置/绑定不可被他人 token 触碰。
        """
        from kiwi_catalog.agent_catalog.sqlite_repository import set_state_domains
        from kiwi_catalog.api.handlers import agent_catalog as handlers_mod

        # approve 签发明文 token 需 Fernet（owner secret）加密响应
        os.environ["KIWI_CATALOG_OWNER_TOKEN_SECRET"] = "test-owner-secret-for-p1a"
        self.addCleanup(os.environ.pop, "KIWI_CATALOG_OWNER_TOKEN_SECRET", None)

        merchant_a, token_a = self._issue_merchant_token("a@example.com", "a-merchant.example")
        with mock.patch.object(
            handlers_mod, "_enqueue_verification", side_effect=_noop_enqueue
        ):
            status, payload = _call_http(
                self.app,
                "POST",
                "/v1/agents/register",
                json.dumps(
                    {
                        **REGISTER_BODY,
                        "domain": "a-merchant.example",
                        "merchant_id": merchant_a,
                        "owner_token": token_a,
                    }
                ).encode(),
            )
        self.assertEqual(status, 200, payload)
        a_agent_id = payload["agent"]["catalog_agent_id"]
        with db_session(self.db_path) as conn:
            set_state_domains(conn, a_agent_id, administrative_state="suspended")

        # 外来商户 B 带自己 token 重注册同一 domain → 200（共享域名多商家规则）；
        # 但 B 得到的是自己的新 agent——A 的治理行不被复活、不被改绑。
        merchant_b, token_b = self._issue_merchant_token("b@example.com", "b-merchant.example")
        with mock.patch.object(
            handlers_mod, "_enqueue_verification", side_effect=_noop_enqueue
        ):
            status, payload = _call_http(
                self.app,
                "POST",
                "/v1/agents/register",
                json.dumps(
                    {
                        **REGISTER_BODY,
                        "domain": "a-merchant.example",
                        "merchant_id": merchant_b,
                        "owner_token": token_b,
                    }
                ).encode(),
            )
        self.assertEqual(status, 200, payload)
        b_agent_id = payload["agent"]["catalog_agent_id"]
        self.assertNotEqual(b_agent_id, a_agent_id)
        with db_session(self.db_path) as conn:
            a_row = conn.execute(
                "select administrative_state, merchant_id from catalog_agents"
                " where catalog_agent_id = ?",
                (a_agent_id,),
            ).fetchone()
            b_row = conn.execute(
                "select administrative_state, merchant_id from catalog_agents"
                " where catalog_agent_id = ?",
                (b_agent_id,),
            ).fetchone()
        self.assertEqual(a_row["administrative_state"], "suspended")
        self.assertEqual(a_row["merchant_id"], merchant_a)
        self.assertEqual(b_row["administrative_state"], "active")
        self.assertEqual(b_row["merchant_id"], merchant_b)

        # 绑定商户 A 带自己 token 重注册 → 复活自己的 agent（同 id），绑定保持 A
        with mock.patch.object(
            handlers_mod, "_enqueue_verification", side_effect=_noop_enqueue
        ):
            status, payload = _call_http(
                self.app,
                "POST",
                "/v1/agents/register",
                json.dumps(
                    {
                        **REGISTER_BODY,
                        "domain": "a-merchant.example",
                        "merchant_id": merchant_a,
                        "owner_token": token_a,
                    }
                ).encode(),
            )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["agent"]["catalog_agent_id"], a_agent_id)
        with db_session(self.db_path) as conn:
            a_row = conn.execute(
                "select administrative_state, merchant_id from catalog_agents"
                " where catalog_agent_id = ?",
                (a_agent_id,),
            ).fetchone()
        self.assertEqual(a_row["administrative_state"], "active")
        self.assertEqual(a_row["merchant_id"], merchant_a)

    def test_reopen_after_suspend_syncs_three_domains(self) -> None:
        """suspended → admin 重注册（可恢复终态 §7.3）→ 三域与折叠一致（P1 回归）。

        upsert 更新分支曾直写 legacy verification_status、漏走三域派生，留下
        admin=suspended + 折叠 discovered 的僵尸状态（公开列表可见但 verify
        永久 InvalidStateTransitionError）。审查 P1-4b 后：复活治理处置必须带
        admin token（匿名被拒，见 test_anonymous_register_cannot_revive_governed_agent）。
        """
        from kiwi_catalog.agent_catalog.sqlite_repository import set_state_domains
        from kiwi_catalog.services.agent_verification import (
            UNREACHABLE,
            VerificationService,
            _ProfileFailure,
        )

        with db_session(self.db_path) as conn:
            set_state_domains(conn, self.cagt_id, administrative_state="suspended")
        self.assertEqual(self._row()["verification_status"], "suspended")

        from kiwi_catalog.api.handlers import agent_catalog as handlers_mod

        with mock.patch.object(
            handlers_mod, "_enqueue_verification", side_effect=_noop_enqueue
        ):
            status, payload = _call_http(
                self.app,
                "POST",
                "/v1/agents/register",
                json.dumps(
                    {**REGISTER_BODY, "domain": "acme.example", "admin_token": "test-admin"}
                ).encode(),
            )
        self.assertEqual(status, 200, payload)
        row = self._row()
        # 重新打开：三域一致（discovered/fresh/active），折叠投影同值。
        self.assertEqual(row["verification_level"], "discovered")
        self.assertEqual(row["freshness_state"], "fresh")
        self.assertEqual(row["administrative_state"], "active")
        self.assertEqual(row["verification_status"], "discovered")
        # verify 不再被状态机拒绝（profile 抓取失败走正常 unreachable 阶梯）。
        with db_session(self.db_path) as conn:
            service = VerificationService(conn)
            with mock.patch.object(
                service, "_load_profiles", side_effect=_ProfileFailure(UNREACHABLE, "mock")
            ):
                result = service.verify(self.cagt_id)
        self.assertIsNotNone(result)
        self.assertEqual(result.status, "unreachable")

    def test_search_category_matches_merchant_tags_without_products_table(self) -> None:
        """category 过滤只走 merchants.tags_json（独立 schema 无 products 表，P1 回归）。

        修复前 products 子查询 → sqlite3.OperationalError: no such table → 500。
        """
        status, payload = _call_http(
            self.app, "GET", "/v1/agent-catalog/agents/search?category=食品"
        )
        self.assertEqual(status, 200, payload)
        self.assertIn("results", payload)

    def test_verify_response_three_domains_read_from_active_txn(self) -> None:
        """verify 响应三域从调用方事务连接读取（P1 回归）。

        修复前 _verification_response 开第二个连接读三域——WAL 模式下新连接
        读快照看不到未提交的验证写入，响应永远返回验证前的旧三域值。
        """
        from unittest import mock as _mock

        import kiwi_catalog.api.handlers.agent_catalog as handlers_mod
        from kiwi_catalog.agent_catalog.sqlite_repository import set_state_domains
        from kiwi_catalog.services.agent_verification import VerificationResult

        os.environ["KIWI_CATALOG_ADMIN_TOKEN"] = "test-admin"
        self.addCleanup(os.environ.pop, "KIWI_CATALOG_ADMIN_TOKEN", None)

        def fake_verify_service(db_path, conn):
            service = _mock.Mock()
            service.name = "fake"

            def _verify(catalog_agent_id, actor=None):
                # 在调用方事务（conn）内推进阶梯——未 commit 前跨连接读不到。
                set_state_domains(
                    conn, catalog_agent_id, verification_level="domain_verified"
                )
                return VerificationResult(catalog_agent_id, "discovered", "domain_verified", ())

            service.verify = _verify
            return service

        with _mock.patch.object(handlers_mod, "_verification_service", fake_verify_service):
            status, payload = _call_http(
                self.app,
                "POST",
                f"/v1/agent-catalog/agents/{self.cagt_id}/verify",
                json.dumps({"admin_token": "test-admin", "idempotency_key": "v1"}).encode(),
            )
        self.assertEqual(status, 200, payload)
        # 响应三域 = 验证推进后的新值（修复前是验证前的 discovered/active）。
        self.assertEqual(payload["verification_level"], "domain_verified")
        self.assertEqual(payload["administrative_state"], "active")

    def test_sync_verify_commits_preliminary_writes_before_fetch(self) -> None:
        """审查 P2-O：verify 抓取开始时外层事务必须无挂起写。

        限流计数 + 幂等 claim 的写事务必须在抓取前 commit——此前写锁跨
        2×30s 网络抓取（WAL 单写者 + busy_timeout 5s），并发 register/
        publish/withdraw 全部 database is locked → 500（攻击者可匿名放大）。
        """
        from unittest import mock as _mock

        import kiwi_catalog.api.handlers.agent_catalog as handlers_mod
        from kiwi_catalog.db.session import db_session as real_db_session
        from kiwi_catalog.services.agent_verification import VerificationResult

        os.environ["KIWI_CATALOG_ADMIN_TOKEN"] = "test-admin"
        self.addCleanup(os.environ.pop, "KIWI_CATALOG_ADMIN_TOKEN", None)

        captured: dict = {}

        class _RecordingSession:
            def __init__(self, path: str) -> None:
                self._inner = real_db_session(path)

            def __enter__(self):
                captured["conn"] = self._inner.__enter__()
                return captured["conn"]

            def __exit__(self, *args):
                return self._inner.__exit__(*args)

        def fake_verify_service(db_path, conn):
            service = _mock.Mock()
            service.name = "fake"

            def _verify(catalog_agent_id, actor=None):
                # 抓取开始时刻：外层事务必须已无挂起写（pre-writes 已 commit）
                captured["in_transaction_at_verify"] = captured["conn"].in_transaction
                return VerificationResult(catalog_agent_id, "discovered", "discovered", ())

            service.verify = _verify
            return service

        with _mock.patch("kiwi_catalog.api.handlers.agent_catalog.db_session", _RecordingSession):
            with _mock.patch.object(handlers_mod, "_verification_service", fake_verify_service):
                status, payload = _call_http(
                    self.app,
                    "POST",
                    f"/v1/agent-catalog/agents/{self.cagt_id}/verify",
                    json.dumps({"admin_token": "test-admin", "idempotency_key": "v2"}).encode(),
                )
        self.assertEqual(status, 200, payload)
        self.assertIs(captured["in_transaction_at_verify"], False)


if __name__ == "__main__":
    unittest.main()
