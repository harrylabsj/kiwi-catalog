from __future__ import annotations

import sqlite3
import unittest
from unittest.mock import patch

from kiwi_catalog.core.errors import NotFoundError, ValidationError
from kiwi_catalog.db.migrations import run_migrations
from kiwi_catalog.services import public_inquiry_consent as policy


class PublicInquiryConsentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        run_migrations(self.conn)
        self.conn.execute(
            "insert into catalog_agents(catalog_agent_id,merchant_id,display_name,source_type,"
            "first_seen_at,last_seen_at,created_at,updated_at) values(?,?,?,?,?,?,?,?)",
            ("agent", "merchant", "Shop", "self_registered", "t", "t", "t", "t"),
        )
        self.conn.execute(
            "insert into runtime_bindings(binding_id,catalog_agent_id,merchant_id,runtime_origin,"
            "a2a_endpoint,key_id,key_thumbprint,key_jwk_json,binding_version,service_epoch,status,"
            "created_at,updated_at) values(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ("binding", "agent", "merchant", "https://shop.example", "https://shop.example/a2a",
             "key", "thumb", "{}", 1, 1, "active", "t", "t"),
        )
        self.conn.execute("insert into card_publications(catalog_agent_id,active_revision,publication_state,etag,updated_at) "
                          "values('agent',1,'ACTIVE','tag','t')")
        self.patches = [
            patch("kiwi_catalog.services.runtime_access.custody_enabled", return_value=True),
            patch("kiwi_catalog.services.runtime_access.active_consent", return_value=object()),
            patch("kiwi_catalog.services.runtime_access.active_runtime_access", return_value=object()),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self) -> None:
        for p in self.patches:
            p.stop()
        self.conn.close()

    def _grant(self, **overrides: str) -> None:
        args = {"agent_id": "agent", "merchant_id": "merchant", "binding_id": "binding",
                "terms_version": policy.TERMS_VERSION}
        args.update(overrides)
        policy.grant(self.conn, **args)

    def test_requires_new_explicit_consent_and_current_binding(self) -> None:
        self.assertFalse(policy.enabled(self.conn, "agent"))
        with self.assertRaises(ValidationError):
            self._grant(terms_version="workbuddy-share-v1-2026-10-27")
        with self.assertRaises(NotFoundError):
            self._grant(merchant_id="someone-else")
        with patch("kiwi_catalog.services.runtime_access.active_consent", return_value=None):
            with self.assertRaises(ValidationError):
                self._grant()
        self._grant()
        self.assertTrue(policy.enabled(self.conn, "agent"))
        self.conn.execute("update catalog_agents set lifecycle_status='inactive' where catalog_agent_id='agent'")
        self.assertFalse(policy.enabled(self.conn, "agent"))
        self.conn.execute("update catalog_agents set lifecycle_status='active' where catalog_agent_id='agent'")
        self.conn.execute("update runtime_bindings set status='paused' where binding_id='binding'")
        self.assertFalse(policy.enabled(self.conn, "agent"))
        self.conn.execute("update runtime_bindings set status='active', expires_at='2000-01-01T00:00:00Z' "
                          "where binding_id='binding'")
        self.assertFalse(policy.enabled(self.conn, "agent"))
        policy.revoke(self.conn, agent_id="agent", merchant_id="merchant", binding_id="binding")
        self.assertFalse(policy.enabled(self.conn, "agent"))

    def test_revocation_and_custody_or_publication_stop_access(self) -> None:
        self._grant()
        with patch("kiwi_catalog.services.runtime_access.custody_enabled", return_value=False):
            self.assertFalse(policy.enabled(self.conn, "agent"))
        self.conn.execute("update card_publications set publication_state='PAUSED' where catalog_agent_id='agent'")
        self.assertFalse(policy.enabled(self.conn, "agent"))
        self.conn.execute("update card_publications set publication_state='ACTIVE' where catalog_agent_id='agent'")
        policy.revoke(self.conn, agent_id="agent", merchant_id="merchant", binding_id="binding")
        self.assertFalse(policy.enabled(self.conn, "agent"))


if __name__ == "__main__":
    unittest.main()
