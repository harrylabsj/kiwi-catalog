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

"""2026-11-10 复核：legacy challenge 自助认领、治理态重注册、非 ASCII 挑战。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kiwi_catalog.agent_catalog.sqlite_repository import require_catalog_agent
from kiwi_catalog.core.errors import PermissionDenied
from kiwi_catalog.db.session import open_connection
from kiwi_catalog.discovery.trust import TrustPolicy
from kiwi_catalog.discovery.verifier import IdentityVerifier
from kiwi_catalog.services.agent_catalog_writes import (
    claim_catalog_agent,
    register_catalog_agent,
)
from kiwi_catalog.services.agent_verification import _has_active_binding
from kiwi_catalog.services.domain_bindings import (
    STATE_LEGACY,
    STATE_PENDING,
    challenge_document,
    get_domain_binding,
)
from tests.test_domain_control_challenge import CHALLENGE_URL, ChallengeFetcher, DOMAIN


class LegacyClaimTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.conn = open_connection(Path(self.tmp.name) / "catalog.sqlite")
        self.addCleanup(self.conn.close)

    def _register(self) -> str:
        result = register_catalog_agent(
            self.conn,
            domain=DOMAIN,
            agent_card_url=f"https://{DOMAIN}/card.json",
            ucp_profile_url=f"https://{DOMAIN}/ucp.json",
        )
        self.conn.commit()
        return str(result["catalog_agent_id"])

    def test_legacy_binding_is_rotated_before_claim(self) -> None:
        cid = self._register()
        self.conn.execute(
            "update catalog_domain_bindings set state = ?, challenge = ''"
            " where catalog_agent_id = ?",
            (STATE_LEGACY, cid),
        )
        self.conn.commit()
        fetcher = ChallengeFetcher()
        verifier = IdentityVerifier(fetcher, TrustPolicy.defaults())
        with self.assertRaises(PermissionDenied):
            claim_catalog_agent(
                self.conn,
                catalog_agent_id=cid,
                merchant_id="mrc-legacy",
                actor="test",
                identity_verifier=verifier,
            )
        self.conn.rollback()
        binding = get_domain_binding(self.conn, cid)
        assert binding is not None
        self.assertEqual(binding["state"], STATE_PENDING)
        self.assertTrue(binding["challenge"])
        fetcher.documents[CHALLENGE_URL] = challenge_document(
            cid, DOMAIN, str(binding["challenge"])
        )
        result = claim_catalog_agent(
            self.conn,
            catalog_agent_id=cid,
            merchant_id="mrc-legacy",
            actor="test",
            identity_verifier=verifier,
        )
        self.conn.commit()
        self.assertEqual(result["merchant"]["id"], "mrc-legacy")

    def test_non_ascii_challenge_document_fails_closed_without_500(self) -> None:
        cid = self._register()
        binding = get_domain_binding(self.conn, cid)
        assert binding is not None
        fetcher = ChallengeFetcher()
        verifier = IdentityVerifier(fetcher, TrustPolicy.defaults())
        fetcher.documents[CHALLENGE_URL] = {
            "catalog_agent_id": "代理中文",
            "challenge": str(binding["challenge"]),
        }
        evidence = verifier.verify_domain_control(
            DOMAIN,
            declared={
                "agent_card": f"https://{DOMAIN}/card.json",
                "ucp_profile": f"https://{DOMAIN}/ucp.json",
            },
            expected_catalog_agent_id=cid,
            challenge=str(binding["challenge"]),
        )
        self.assertFalse(evidence.passed)
        fetcher.documents[CHALLENGE_URL] = {
            "catalog_agent_id": cid,
            "challenge": "挑战中文",
        }
        evidence = verifier.verify_domain_control(
            DOMAIN,
            declared={
                "agent_card": f"https://{DOMAIN}/card.json",
                "ucp_profile": f"https://{DOMAIN}/ucp.json",
            },
            expected_catalog_agent_id=cid,
            challenge=str(binding["challenge"]),
        )
        self.assertFalse(evidence.passed)


class ReRegisterGovernanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.conn = open_connection(Path(self.tmp.name) / "catalog.sqlite")
        self.addCleanup(self.conn.close)

    def _register(self, merchant_id: str) -> str:
        result = register_catalog_agent(
            self.conn,
            domain=DOMAIN,
            merchant_id=merchant_id,
            agent_card_url=f"https://{DOMAIN}/card.json",
            ucp_profile_url=f"https://{DOMAIN}/ucp.json",
        )
        self.conn.commit()
        return str(result["catalog_agent_id"])

    def _set_state(self, cid: str, level: str, admin: str) -> None:
        self.conn.execute(
            "update catalog_agents set verification_level = ?,"
            " verification_status = ?, administrative_state = ?"
            " where catalog_agent_id = ?",
            (level, level if admin == "active" else admin, admin, cid),
        )
        self.conn.commit()

    def test_active_same_domain_keeps_level(self) -> None:
        cid = self._register("mrc-keep")
        self._set_state(cid, "commerce_verified", "active")
        self._register("mrc-keep")
        self.assertEqual(
            require_catalog_agent(self.conn, cid)["verification_level"], "commerce_verified"
        )

    def test_suspended_same_domain_reregistration_resets_level(self) -> None:
        cid = self._register("mrc-gov")
        self._set_state(cid, "commerce_verified", "suspended")
        with mock.patch(
            "kiwi_catalog.services.agent_catalog_writes.append_catalog_audit"
        ):
            self._register("mrc-gov")
        row = require_catalog_agent(self.conn, cid)
        self.assertEqual(row["verification_level"], "discovered")
        self.assertEqual(row["administrative_state"], "active")


class ActiveBindingExpiryTest(unittest.TestCase):
    def test_mixed_timezone_representations_do_not_raise(self) -> None:
        from kiwi_catalog.db.session import now_iso

        with tempfile.TemporaryDirectory() as tmp:
            conn = open_connection(Path(tmp) / "catalog.sqlite")
            try:
                conn.execute(
                    "insert into catalog_agents (catalog_agent_id, display_name, source_type,"
                    " canonical_domain, first_seen_at, last_seen_at, created_at, updated_at)"
                    " values ('cagt_tz', 'T', 'self_registered', 't.example', ?, ?, ?, ?)",
                    (now_iso(), now_iso(), now_iso(), now_iso()),
                )
                conn.execute(
                    "insert into runtime_bindings (binding_id, catalog_agent_id, merchant_id,"
                    " runtime_origin, a2a_endpoint, key_id, key_thumbprint, key_jwk_json,"
                    " binding_version, service_epoch, status, expires_at, created_at, updated_at)"
                    " values ('b1','cagt_tz','m','https://r.example','https://r.example/a2a',"
                    " 'k','tp','{}',1,1,'active','2099-01-01T00:00:00Z','now','now')",
                )
                self.assertTrue(_has_active_binding(conn, "cagt_tz", "2026-11-10T00:00:00+00:00"))
            finally:
                conn.close()


if __name__ == "__main__":
    unittest.main()
