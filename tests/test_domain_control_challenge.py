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

"""审查 P1-12：domain-control 挑战绑定 + 同域多商家克隆回归。

旧实现里 ``https://{domain}/.well-known/agent-card.json`` 返回 200 即通过
domain 阶段，不校验内容属于哪个 catalog_agent 行；一域多商家时攻击者可把
第二行的 profile URL 指向受害者的真实 card/ucp，整条阶梯通过并克隆信任徽章。

修复后：自注册/发现类 agent 必须在
``https://{domain}/.well-known/kiwi-catalog-agent.json`` 发布回指本行的
一次性 challenge（catalog_agent_id + token），每次验证重新读取比对。
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

from kiwi_catalog.agent_catalog.sqlite_repository import require_catalog_agent
from kiwi_catalog.api.handlers.agent_catalog import get_domain_challenge
from kiwi_catalog.core.errors import PermissionDenied
from kiwi_catalog.db.session import open_connection
from kiwi_catalog.discovery.fetcher import FetchResult
from kiwi_catalog.services.agent_catalog_writes import register_catalog_agent
from kiwi_catalog.services.agent_verification import VerificationService
from kiwi_catalog.services.domain_bindings import (
    STATE_LEGACY,
    STATE_PENDING,
    STATE_VERIFIED,
    challenge_document,
    get_domain_binding,
)

DOMAIN = "shop.example"
CHALLENGE_URL = f"https://{DOMAIN}/.well-known/kiwi-catalog-agent.json"

CARD = {
    "name": "Synthetic",
    "version": "1.0.0",
    "url": f"https://{DOMAIN}/a2a",
    "skills": [],
    "capabilities": {},
}
UCP = {
    "specificationVersion": "2026-04-08",
    "serviceIdentity": {"id": DOMAIN, "name": "Synthetic"},
    "services": [
        {
            "id": "commerce",
            "type": "commerce",
            "capabilities": [],
            "endpoints": [{"uri": f"https://{DOMAIN}/a2a", "protocol": "a2a"}],
        }
    ],
}


class ChallengeFetcher:
    """Serves profile + well-known paths; the challenge file is opt-in."""

    def __init__(self) -> None:
        self.documents: dict[str, object] = {}

    def fetch(self, url: str, etag: str | None = None, last_modified: str | None = None) -> FetchResult:
        if url == CHALLENGE_URL:
            if url not in self.documents:
                return FetchResult(url=url, status_code=404)
            return FetchResult(url=url, status_code=200, parsed=self.documents[url])
        if url.endswith("/card.json") or url.endswith("/.well-known/agent-card.json"):
            data = CARD
        elif url.endswith("/ucp.json") or url.endswith("/.well-known/ucp"):
            data = UCP
        else:
            return FetchResult(url=url, status_code=404)
        raw = json.dumps(data).encode()
        return FetchResult(
            url=url,
            status_code=200,
            parsed=data,
            raw_bytes=raw,
            body=raw.decode(),
            max_age=60,
        )


def _make_conn(tmpdir: str):
    path = Path(tmpdir) / "catalog.sqlite"
    return path, open_connection(path)


def _register(conn, domain: str = DOMAIN, merchant_id: str = "") -> str:
    result = register_catalog_agent(
        conn,
        domain=domain,
        agent_card_url=f"https://{domain}/card.json",
        ucp_profile_url=f"https://{domain}/ucp.json",
        merchant_id=merchant_id,
    )
    conn.commit()
    return str(result["catalog_agent_id"])


def _domain_stage(result):
    return next(stage for stage in result.stages if stage.stage == "domain_control")


def _verify(service, conn, catalog_agent_id):
    """Run one ladder pass and close its write transaction (next run needs idle)."""
    result = service.verify(catalog_agent_id, force=True)
    conn.commit()
    return result


class DomainControlChallengeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path, self.conn = _make_conn(self.tmp.name)
        self.addCleanup(self.conn.close)

    def test_registration_issues_pending_challenge(self) -> None:
        cid = _register(self.conn)
        binding = get_domain_binding(self.conn, cid)
        self.assertIsNotNone(binding)
        assert binding is not None
        self.assertEqual(binding["state"], STATE_PENDING)
        self.assertEqual(binding["canonical_domain"], DOMAIN)
        self.assertTrue(binding["challenge"].startswith("kc1_"))

    def test_domain_stage_fails_until_challenge_is_published(self) -> None:
        cid = _register(self.conn)
        fetcher = ChallengeFetcher()
        service = VerificationService(self.conn, fetcher=fetcher)

        failed = _verify(service, self.conn, cid)
        stage = _domain_stage(failed)
        self.assertEqual(stage.outcome, "rejected")
        self.assertIn("challenge", stage.reason)
        self.assertEqual(require_catalog_agent(self.conn, cid)["verification_level"], "discovered")

        binding = get_domain_binding(self.conn, cid)
        assert binding is not None
        fetcher.documents[CHALLENGE_URL] = challenge_document(
            cid, DOMAIN, str(binding["challenge"])
        )
        passed = _verify(service, self.conn, cid)
        self.assertEqual(_domain_stage(passed).outcome, "passed")
        self.assertEqual(get_domain_binding(self.conn, cid)["state"], STATE_VERIFIED)  # type: ignore[index]

    def test_second_merchant_on_same_domain_cannot_clone_the_first(self) -> None:
        """攻击场景：第二行指向受害者的真实 card/ucp，但没有 challenge 文件。"""
        victim = _register(self.conn, merchant_id="mrc-victim")
        attacker = _register(self.conn, merchant_id="mrc-attacker")
        self.assertNotEqual(victim, attacker)

        fetcher = ChallengeFetcher()
        service = VerificationService(self.conn, fetcher=fetcher)

        victim_binding = get_domain_binding(self.conn, victim)
        assert victim_binding is not None
        fetcher.documents[CHALLENGE_URL] = challenge_document(
            victim, DOMAIN, str(victim_binding["challenge"])
        )
        self.assertEqual(_domain_stage(_verify(service, self.conn, victim)).outcome, "passed")

        attacker_result = _verify(service, self.conn, attacker)
        self.assertEqual(_domain_stage(attacker_result).outcome, "rejected")
        # 发布的是受害者行的文档 → 攻击者行不得被提升到 domain_verified。
        self.assertEqual(
            require_catalog_agent(self.conn, attacker)["verification_level"], "discovered"
        )

    def test_wrong_agent_id_or_token_is_rejected(self) -> None:
        cid = _register(self.conn)
        binding = get_domain_binding(self.conn, cid)
        assert binding is not None
        fetcher = ChallengeFetcher()
        service = VerificationService(self.conn, fetcher=fetcher)

        fetcher.documents[CHALLENGE_URL] = {
            "catalog_agent_id": "cagt_someone_else",
            "challenge": str(binding["challenge"]),
        }
        self.assertEqual(_domain_stage(_verify(service, self.conn, cid)).outcome, "rejected")

        fetcher.documents[CHALLENGE_URL] = {
            "catalog_agent_id": cid,
            "challenge": "kc1_wrong",
        }
        self.assertEqual(_domain_stage(_verify(service, self.conn, cid)).outcome, "rejected")

    def test_legacy_binding_keeps_old_semantics(self) -> None:
        """升级前已验证的存量行不因新规则突然掉级（迁移标记 legacy）。"""
        cid = _register(self.conn)
        self.conn.execute(
            "update catalog_domain_bindings set state = ?, challenge = '', bound_at = 'now'"
            " where catalog_agent_id = ?",
            (STATE_LEGACY, cid),
        )
        self.conn.commit()
        service = VerificationService(self.conn, fetcher=ChallengeFetcher())
        result = _verify(service, self.conn, cid)
        self.assertEqual(_domain_stage(result).outcome, "passed")
        self.assertEqual(_domain_stage(result).evidence["details"]["domain_binding"], "legacy")

    def test_domain_change_rotates_challenge(self) -> None:
        cid = _register(self.conn, merchant_id="mrc-1")
        first = get_domain_binding(self.conn, cid)
        assert first is not None
        register_catalog_agent(
            self.conn,
            domain="new.example",
            agent_card_url="https://new.example/card.json",
            ucp_profile_url="https://new.example/ucp.json",
            merchant_id="mrc-1",
        )
        self.conn.commit()
        second = get_domain_binding(self.conn, cid)
        assert second is not None
        self.assertEqual(second["canonical_domain"], "new.example")
        self.assertEqual(second["state"], STATE_PENDING)
        self.assertNotEqual(second["challenge"], first["challenge"])

    def test_claim_requires_the_challenge_too(self) -> None:
        """未绑定 agent 的 claim 同样走 challenge，不能靠指向真实 card 得手。"""
        from kiwi_catalog.discovery.trust import TrustPolicy
        from kiwi_catalog.discovery.verifier import IdentityVerifier
        from kiwi_catalog.services.agent_catalog_writes import claim_catalog_agent

        cid = _register(self.conn)
        fetcher = ChallengeFetcher()
        verifier = IdentityVerifier(fetcher, TrustPolicy.defaults())

        with self.assertRaises(PermissionDenied):
            claim_catalog_agent(
                self.conn,
                catalog_agent_id=cid,
                merchant_id="mrc-claim",
                actor="test",
                identity_verifier=verifier,
            )
        self.conn.rollback()

        binding = get_domain_binding(self.conn, cid)
        assert binding is not None
        fetcher.documents[CHALLENGE_URL] = challenge_document(
            cid, DOMAIN, str(binding["challenge"])
        )
        result = claim_catalog_agent(
            self.conn,
            catalog_agent_id=cid,
            merchant_id="mrc-claim",
            actor="test",
            identity_verifier=verifier,
        )
        self.conn.commit()
        self.assertEqual(result["merchant"]["id"], "mrc-claim")
        self.assertEqual(get_domain_binding(self.conn, cid)["state"], STATE_VERIFIED)  # type: ignore[index]

    def test_handler_requires_authentication(self) -> None:
        cid = _register(self.conn)
        with self.assertRaises(PermissionDenied):
            get_domain_challenge(self.path, cid, {})

    def test_handler_returns_document_for_admin(self) -> None:
        cid = _register(self.conn)
        old = os.environ.get("KIWI_CATALOG_ADMIN_TOKEN")
        os.environ["KIWI_CATALOG_ADMIN_TOKEN"] = "test-admin"
        self.addCleanup(
            lambda: os.environ.pop("KIWI_CATALOG_ADMIN_TOKEN", None)
            if old is None
            else os.environ.__setitem__("KIWI_CATALOG_ADMIN_TOKEN", old)
        )
        payload = get_domain_challenge(self.path, cid, {"admin_token": "test-admin"})
        self.assertEqual(payload["publish_url"], CHALLENGE_URL)
        self.assertEqual(payload["document"]["catalog_agent_id"], cid)
        self.assertTrue(payload["document"]["challenge"].startswith("kc1_"))


if __name__ == "__main__":
    unittest.main()
