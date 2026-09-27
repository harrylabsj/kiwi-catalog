"""Capacity migration and configuration invariants."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from kiwi_catalog.db.session import db_session, now_iso
from kiwi_catalog.services.listing_entitlements import capacity, set_merchant_entitlement, set_plan_limit


class ListingEntitlementsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "catalog.sqlite"

    def test_plan_and_merchant_limit_are_separate(self) -> None:
        now = now_iso()
        with db_session(self.db) as conn:
            conn.execute("insert into merchants(id,name,created_at,updated_at) values ('mkt_quota','Shop',?,?)", (now, now))
            set_merchant_entitlement(conn, "mkt_quota", actor="test")
            set_plan_limit(conn, "free", 7, actor="test")
            self.assertEqual(capacity(conn, "mkt_quota")["active_limit"], 7)
            set_merchant_entitlement(conn, "mkt_quota", actor="test", limit_override=12)
            self.assertEqual(capacity(conn, "mkt_quota")["active_limit"], 12)
            set_merchant_entitlement(conn, "mkt_quota", actor="test", clear_override=True)
            self.assertEqual(capacity(conn, "mkt_quota")["active_limit"], 7)

    def test_migration_grandfathers_existing_public_inventory(self) -> None:
        now = now_iso()
        with db_session(self.db) as conn:
            conn.execute("""insert into merchant_accounts
                (email,password_hash,email_verified,merchant_name,merchant_id,created_at,updated_at)
                values ('shop@example.test','test',1,'Shop','mkt_existing',?,?)""", (now, now))
            for number in range(21):
                conn.execute("""insert into commerce_listings
                    (listing_id,listing_type,owner_agent_id,merchant_id,source_product_ref,
                     title,category,listing_digest,published_at,updated_at,fresh_until,created_at)
                    values (?, 'product','cagt_existing','mkt_existing',?,'Widget','widgets','digest',?,?,?,?)""",
                    (f"lst_existing_{number}", f"SKU-{number}", now, now, now, now))
            conn.execute("delete from merchant_listing_entitlements where merchant_id='mkt_existing'")
            conn.execute("pragma user_version=39")
        with db_session(self.db) as conn:
            current = capacity(conn, "mkt_existing")
            self.assertEqual((current["active_used"], current["active_limit"]), (21, 21))
            self.assertEqual(conn.execute("select count(*) from listing_entitlement_audit where action='grandfather_existing_listings'").fetchone()[0], 1)

    def test_v40_default_upgrades_but_admin_customization_is_preserved(self) -> None:
        with db_session(self.db) as conn:
            conn.execute("update listing_plans set active_limit=10 where plan_code='free'")
            conn.execute("pragma user_version=40")
        with db_session(self.db) as conn:
            self.assertEqual(conn.execute("select active_limit from listing_plans where plan_code='free'").fetchone()[0], 20)
            self.assertEqual(conn.execute("select count(*) from listing_entitlement_audit where action='free_default_increased'").fetchone()[0], 1)

        with db_session(self.db) as conn:
            set_plan_limit(conn, "free", 10, actor="admin")
            conn.execute("pragma user_version=40")
        with db_session(self.db) as conn:
            self.assertEqual(conn.execute("select active_limit from listing_plans where plan_code='free'").fetchone()[0], 10)


if __name__ == "__main__":
    unittest.main()
