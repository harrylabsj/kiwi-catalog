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

"""审查 P1-01：换域名重注册的信任边界回归测试。

商家重注册换 normalized domain 时：
- 旧域名的 endpoints / capabilities / skills / profile snapshot /
  verification 证据必须清除，不得继续绑定新域名（registration 侧）；
- 验证管线必须以 agent **存储的** canonical_domain 为准（verification 侧）：
  *_load_profiles* 在抓取/索引前拒绝落在存储域名之外的 agent_card/ucp_profile
  端点；domain-control 阶段对存储域名验证，而非 profile 自称的域名。
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kiwi_catalog.agent_catalog.sqlite_repository import (
    list_capabilities,
    list_endpoints,
    list_skills,
    require_catalog_agent,
)
from kiwi_catalog.agent_catalog.verification_evidence import (
    insert_profile_snapshot,
    insert_verification,
    list_profile_snapshots,
    list_verifications,
)
from kiwi_catalog.db.session import now_iso, open_connection
from kiwi_catalog.discovery.fetcher import FetchError
from kiwi_catalog.services.agent_catalog_writes import register_catalog_agent


def _make_db() -> Path:
    tmp = tempfile.mkdtemp()
    db = Path(tmp) / "catalog.sqlite"
    conn = open_connection(db)
    conn.close()
    return db


def _seed_old_domain_evidence(conn, catalog_agent_id: str) -> None:
    """模拟 agent 在旧域名上已验证过：落一条 snapshot + passed domain 证据。"""
    ts = now_iso()
    insert_profile_snapshot(
        conn,
        catalog_agent_id=catalog_agent_id,
        profile_type="agent_card",
        source_url="https://old.example/.well-known/agent-card.json",
        etag='"old-etag"',
        last_modified="",
        content_hash="sha256:old",
        raw_json='{"name":"Old","url":"https://old.example/card.json","version":"1.0.0"}',
        fetched_at=ts,
        fresh_until="2099-01-01T00:00:00+00:00",
        validation_status="valid",
    )
    insert_verification(
        conn,
        catalog_agent_id=catalog_agent_id,
        verification_type="domain_control",
        result="passed",
        evidence_json='{"method":"https_domain_control","canonical_domain":"old.example"}',
        checked_at=ts,
        expires_at="2099-01-01T00:00:00+00:00",
    )
    conn.commit()


class DomainChangeTrustTest(unittest.TestCase):
    """Registration 侧：换域名清除旧域名绑定数据。"""

    def test_domain_change_purges_stale_bound_data(self) -> None:
        """换域名重注册：旧 endpoints/capabilities/skills/evidence 全部清除，
        级别回到 discovered，落 catalog_agent_domain_changed 审计。"""
        db = _make_db()
        conn = open_connection(db)
        first = register_catalog_agent(
            conn,
            domain="old.example",
            merchant_id="mrc-1",
            actor="test",
            agent_card_url="https://old.example/card.json",
            ucp_profile_url="https://old.example/ucp.json",
            capabilities=["com.example:old_cap"],
            skills=[{"skill_id": "old-skill", "name": "Old Skill"}],
        )
        cid = first["catalog_agent_id"]
        _seed_old_domain_evidence(conn, cid)

        second = register_catalog_agent(
            conn, domain="new.example", merchant_id="mrc-1", actor="test"
        )
        self.assertEqual(first["catalog_agent_id"], second["catalog_agent_id"])

        # agent_card/ucp_profile 旧端点全部清除。
        profile_eps = [
            e for e in list_endpoints(conn, cid) if e["kind"] in ("agent_card", "ucp_profile")
        ]
        self.assertEqual(profile_eps, [])
        # 旧 profile 派生声明与证据全部清除。
        self.assertEqual(list_capabilities(conn, cid), [])
        self.assertEqual(list_skills(conn, cid), [])
        self.assertEqual(list_profile_snapshots(conn, cid), [])
        self.assertEqual(list_verifications(conn, cid), [])
        # 级别回到 discovered（三域 active/fresh/discovered）。
        row = require_catalog_agent(conn, cid)
        self.assertEqual(row["canonical_domain"], "new.example")
        self.assertEqual(row["verification_level"], "discovered")
        self.assertEqual(row["freshness_state"], "fresh")
        self.assertEqual(row["administrative_state"], "active")
        # 审计事件记录换域名与清除事实（catalog_agent_id 存于 details_json）。
        audit = conn.execute(
            "select details_json from audit_events"
            " where event = 'catalog_agent_domain_changed'"
            " order by id desc limit 1"
        ).fetchone()
        self.assertIsNotNone(audit)
        self.assertIn("new.example", audit["details_json"])
        self.assertIn("old.example", audit["details_json"])
        conn.close()

    def test_domain_change_keeps_new_domain_declarations(self) -> None:
        """换域名 + 提供新 endpoints/capabilities/skills：旧值清除，新值保留。"""
        db = _make_db()
        conn = open_connection(db)
        first = register_catalog_agent(
            conn,
            domain="old.example",
            merchant_id="mrc-1",
            actor="test",
            agent_card_url="https://old.example/card.json",
            capabilities=["com.example:old_cap"],
        )
        cid = first["catalog_agent_id"]
        second = register_catalog_agent(
            conn,
            domain="new.example",
            merchant_id="mrc-1",
            actor="test",
            agent_card_url="https://agent.new.example/card.json",
            capabilities=["com.example:new_cap"],
            skills=[{"skill_id": "new-skill", "name": "New Skill"}],
        )
        self.assertEqual(first["catalog_agent_id"], second["catalog_agent_id"])

        # 新域名端点保留（子域同样通过 authority 检查），旧域名端点已清除。
        eps = {e["kind"]: e["url"] for e in list_endpoints(conn, cid) if e["kind"] in ("agent_card", "ucp_profile")}
        self.assertEqual(eps, {"agent_card": "https://agent.new.example/card.json"})
        caps = list_capabilities(conn, cid)
        self.assertEqual([c["capability_id"] for c in caps], ["new_cap"])
        self.assertEqual([s["skill_id"] for s in list_skills(conn, cid)], ["new-skill"])
        conn.close()

    def test_same_domain_reregister_keeps_data(self) -> None:
        """同域名重注册（仅换 card URL）不触发清除——非信任边界变更。"""
        db = _make_db()
        conn = open_connection(db)
        first = register_catalog_agent(
            conn,
            domain="one.example",
            merchant_id="mrc-1",
            actor="test",
            agent_card_url="https://one.example/old.json",
            capabilities=["com.example:cap"],
        )
        cid = first["catalog_agent_id"]
        _seed_old_domain_evidence(conn, cid)

        second = register_catalog_agent(
            conn,
            domain="one.example",
            merchant_id="mrc-1",
            actor="test",
            agent_card_url="https://one.example/new.json",
        )
        self.assertEqual(first["catalog_agent_id"], second["catalog_agent_id"])
        eps = {e["kind"]: e["url"] for e in list_endpoints(conn, cid)}
        self.assertEqual(eps["agent_card"], "https://one.example/new.json")
        # 能力与证据保留（同域名重注册不是信任边界变更）。
        self.assertEqual([c["capability_id"] for c in list_capabilities(conn, cid)], ["cap"])
        self.assertEqual(len(list_profile_snapshots(conn, cid)), 1)
        self.assertEqual(len(list_verifications(conn, cid)), 1)
        conn.close()


class VerificationAuthorityConsistencyTest(unittest.TestCase):
    """Verification 侧：必须以存储 canonical_domain 为准。"""

    def _register(self, conn, domain: str, **kw) -> dict:
        return register_catalog_agent(conn, domain=domain, merchant_id="mrc-1", actor="test", **kw)

    def test_domain_stage_verifies_stored_domain_not_profile_claimed(self) -> None:
        """domain-control 阶段验证 agent 存储的域名，而非 profile 自称的域名。"""
        from kiwi_catalog.discovery.verifier import VerificationEvidence
        from kiwi_catalog.services.agent_verification import VerificationService

        db = _make_db()
        conn = open_connection(db)
        cid = self._register(
            conn,
            domain="new.example",
            agent_card_url="https://new.example/card.json",
        )["catalog_agent_id"]

        class _FakeCard:
            canonical_domain = "old.example"  # 残留旧域名 profile 的自称域名
            name = "Old"
            public = {"url": "https://old.example/card.json"}
            version = "1.0.0"
            capabilities = ()
            skills = ()

        class _FakeUcp:
            specification_version = "2026-04-08"
            public = {}
            capabilities = ()
            skills = ()

        class _FakeProfiles:
            card = _FakeCard()
            ucp = _FakeUcp()
            urls = {
                "agent_card": "https://old.example/.well-known/agent-card.json",
                "ucp_profile": "https://old.example/ucp.json",
            }
            snapshot_ids = (1, 2)

        captured: dict[str, str] = {}

        def _recording_domain_control(canonical: str, declared: dict | None = None) -> VerificationEvidence:
            captured["domain"] = canonical
            return VerificationEvidence(
                verification_type="domain_control", result="passed", details={}, reason="mock"
            )

        def _pass(*args, **kwargs) -> VerificationEvidence:
            return VerificationEvidence(
                verification_type="agent_identity", result="passed", details={}, reason="mock"
            )

        service = VerificationService(conn)
        service._load_profiles = lambda _cid: _FakeProfiles()  # type: ignore[method-assign]
        service._identity_verifier.verify_domain_control = _recording_domain_control  # type: ignore[method-assign]
        service._trust_evaluator.evaluate_agent_identity = _pass  # type: ignore[method-assign]
        service._trust_evaluator.evaluate_commerce_capabilities = _pass  # type: ignore[method-assign]

        result = service.verify(cid, actor="test", force=True)
        # 修复前会传 profile 自称的 old.example；修复后必须传存储的 new.example。
        self.assertEqual(captured["domain"], "new.example")
        self.assertEqual(result.status, "commerce_verified", result)
        conn.close()

    def test_load_profiles_rejects_endpoints_outside_stored_domain(self) -> None:
        """profile 阶段在抓取/索引前拒绝落在存储域名之外的端点（fail-fast）。"""
        from kiwi_catalog.services.agent_verification import (
            REJECTED,
            VerificationService,
            _ProfileFailure,
        )

        db = _make_db()
        conn = open_connection(db)
        # 新注册（无 prior domain）接受端点声明；验证时 authority 检查拒绝。
        cid = self._register(
            conn,
            domain="new.example",
            agent_card_url="https://old.example/card.json",
            ucp_profile_url="https://old.example/ucp.json",
        )["catalog_agent_id"]
        service = VerificationService(conn)
        with self.assertRaises(_ProfileFailure) as ctx:
            service._load_profiles(cid)
        self.assertEqual(ctx.exception.target_status, REJECTED)
        self.assertIn("not under canonical domain 'new.example'", str(ctx.exception))
        conn.close()

    def test_load_profiles_accepts_endpoints_under_stored_domain(self) -> None:
        """存储域名下的端点通过 authority 检查（positive control：失败在后续抓取，
        而非 authority——证明 guard 不误伤合法端点）。"""
        from kiwi_catalog.services.agent_verification import (
            UNREACHABLE,
            VerificationService,
            _ProfileFailure,
        )

        db = _make_db()
        conn = open_connection(db)
        cid = self._register(
            conn,
            domain="new.example",
            agent_card_url="https://new.example/card.json",
            ucp_profile_url="https://new.example/ucp.json",
        )["catalog_agent_id"]

        class _OfflineFetcher:
            def fetch(self, url, etag=None, last_modified=None):
                raise FetchError("offline test fetcher")

        service = VerificationService(conn, fetcher=_OfflineFetcher())
        with self.assertRaises(_ProfileFailure) as ctx:
            service._load_profiles(cid)
        # 过了 authority 检查，在抓取阶段失败（无 prior snapshot → UNREACHABLE）。
        self.assertEqual(ctx.exception.target_status, UNREACHABLE)
        self.assertNotIn("not under canonical domain", str(ctx.exception))
        conn.close()

    def test_domain_change_purged_evidence_cannot_influence_level(self) -> None:
        """换域名清除证据后，profile 阶段失败按证据重算不会引用旧域名证据（级别
        停在下限 discovered）。"""
        from kiwi_catalog.services.agent_verification import (
            REJECTED,
            VerificationService,
            _ProfileFailure,
        )

        db = _make_db()
        conn = open_connection(db)
        first = register_catalog_agent(
            conn,
            domain="old.example",
            merchant_id="mrc-1",
            actor="test",
            agent_card_url="https://old.example/card.json",
        )
        cid = first["catalog_agent_id"]
        _seed_old_domain_evidence(conn, cid)
        # 换域名重注册 → 证据清除、级别回到 discovered。
        register_catalog_agent(conn, domain="new.example", merchant_id="mrc-1", actor="test")
        self.assertEqual(list_verifications(conn, cid), [])
        self.assertEqual(list_profile_snapshots(conn, cid), [])

        service = VerificationService(conn)
        with mock.patch.object(
            service, "_load_profiles", side_effect=_ProfileFailure(REJECTED, "mock rejected")
        ):
            result = service.verify(cid, actor="test")
        # 折叠 status = stale（REJECTED → freshness STALE）；关键是 verification_level
        # 停在 discovered——没有旧域名 passed 证据可被引用把级别拉回已验证档。
        self.assertEqual(result.status, "stale", result)
        row = require_catalog_agent(conn, cid)
        self.assertEqual(row["verification_level"], "discovered")
        self.assertEqual(row["freshness_state"], "stale")
        conn.close()


if __name__ == "__main__":
    unittest.main()
