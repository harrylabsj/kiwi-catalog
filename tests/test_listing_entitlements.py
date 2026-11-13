"""Capacity migration and configuration invariants."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from kiwi_catalog.core.errors import PermissionDenied
from kiwi_catalog.db.session import db_session, now_iso
from kiwi_catalog.services.listing_entitlements import (
    capacity,
    list_plans,
    require_publication_capacity,
    set_merchant_entitlement,
    set_merchant_plan,
    set_plan_limit,
)


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
            set_plan_limit(conn, "lite", 7, actor="test")
            self.assertEqual(capacity(conn, "mkt_quota")["active_limit"], 7)
            set_merchant_entitlement(conn, "mkt_quota", actor="test", limit_override=12)
            self.assertEqual(capacity(conn, "mkt_quota")["active_limit"], 12)
            set_merchant_entitlement(conn, "mkt_quota", actor="test", clear_override=True)
            self.assertEqual(capacity(conn, "mkt_quota")["active_limit"], 7)

    def test_migration_keeps_existing_public_inventory_but_lowers_lite_limit(self) -> None:
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
            # v40's grandfather override is cleared by v55; the new lite limit
            # applies, but the 21 already-ACTIVE rows are not unpublished.
            self.assertEqual((current["active_used"], current["active_limit"]), (21, 5))
            self.assertIsNone(current["limit_override"])
            self.assertEqual(conn.execute("select count(*) from listing_entitlement_audit where action='grandfather_existing_listings'").fetchone()[0], 1)
            self.assertEqual(conn.execute("select count(*) from listing_entitlement_audit where action='grandfather_override_cleared'").fetchone()[0], 1)
            self.assertEqual(conn.execute("select count(*) from listing_entitlement_audit where action='lite_capacity_reduced'").fetchone()[0], 1)

    def test_v40_default_upgrades_but_admin_customization_is_preserved(self) -> None:
        with db_session(self.db) as conn:
            # Simulate a v40 database: remove the v55 audit that a real v40 DB
            # would not have, then replay migrations from v40.
            conn.execute("delete from listing_entitlement_audit where actor='migration'")
            conn.execute("update listing_plans set plan_code='free', label='' where plan_code='lite'")
            conn.execute("update listing_plans set active_limit=10 where plan_code='free'")
            conn.execute("pragma user_version=40")
        with db_session(self.db) as conn:
            # v41 raises 10 -> 20; v55 lowers the untouched default to 5.
            self.assertEqual(conn.execute("select active_limit from listing_plans where plan_code='lite'").fetchone()[0], 5)
            self.assertEqual(conn.execute("select count(*) from listing_entitlement_audit where action='free_default_increased'").fetchone()[0], 1)

        with db_session(self.db) as conn:
            set_plan_limit(conn, "lite", 10, actor="admin")
            conn.execute("pragma user_version=40")
        with db_session(self.db) as conn:
            self.assertEqual(conn.execute("select active_limit from listing_plans where plan_code='lite'").fetchone()[0], 10)


    def test_v55_renames_existing_free_entitlements_to_lite(self) -> None:
        now = now_iso()
        with db_session(self.db) as conn:
            conn.execute(
                "insert into merchants(id,name,created_at,updated_at) values ('mkt_rename','Shop',?,?)",
                (now, now),
            )
            conn.execute(
                "insert into listing_plans"
                " (plan_code,label,active_limit,sort_order,updated_at)"
                " values ('free','Free',20,10,?)",
                (now,),
            )
            conn.execute(
                "insert into merchant_listing_entitlements"
                " (merchant_id,plan_code,status,limit_override,updated_at)"
                " values ('mkt_rename','free','active',null,?)",
                (now,),
            )
            conn.execute("delete from listing_plans where plan_code='lite'")
            conn.execute("pragma user_version=54")
        with db_session(self.db) as conn:
            current = capacity(conn, "mkt_rename")
            self.assertEqual(current["plan_code"], "lite")
            self.assertEqual(current["plan_label"], "Lite")
            self.assertEqual(current["active_limit"], 5)
            self.assertEqual(
                conn.execute(
                    "select count(*) from listing_plans where plan_code='free'"
                ).fetchone()[0],
                0,
            )

    def test_five_plan_tiers_are_seeded_and_ordered(self) -> None:
        with db_session(self.db) as conn:
            plans = list_plans(conn)
        self.assertEqual(
            [p["plan_code"] for p in plans],
            ["lite", "plus", "pro", "max", "ultra"],
        )
        self.assertEqual(
            [p["active_limit"] for p in plans],
            [5, 20, 50, 100, 500],
        )
        self.assertEqual([p["label"] for p in plans], ["Lite", "Plus", "Pro", "Max", "Ultra"])

    def test_capacity_exposes_plan_label_and_limit_source(self) -> None:
        now = now_iso()
        with db_session(self.db) as conn:
            conn.execute(
                "insert into merchants(id,name,created_at,updated_at) values ('mkt_label','Shop',?,?)",
                (now, now),
            )
            set_merchant_entitlement(conn, "mkt_label", actor="test", plan_code="plus")
            current = capacity(conn, "mkt_label")
            self.assertEqual(current["plan_code"], "plus")
            self.assertEqual(current["plan_label"], "Plus")
            self.assertEqual(current["active_limit"], 20)
            self.assertEqual(current["limit_source"], "plan")
            set_merchant_entitlement(conn, "mkt_label", actor="test", limit_override=12)
            current = capacity(conn, "mkt_label")
            self.assertEqual(current["active_limit"], 12)
            self.assertEqual(current["limit_source"], "override")

    def test_plan_downgrade_keeps_active_rows_and_blocks_new_publish(self) -> None:
        now = now_iso()
        with db_session(self.db) as conn:
            conn.execute(
                "insert into merchants(id,name,created_at,updated_at) values ('mkt_downgrade','Shop',?,?)",
                (now, now),
            )
            conn.execute(
                """insert into merchant_accounts
                (email,password_hash,email_verified,merchant_name,merchant_id,created_at,updated_at)
                values ('down@example.test','test',1,'Shop','mkt_downgrade',?,?)""",
                (now, now),
            )
            set_merchant_plan(conn, "mkt_downgrade", "plus", actor="admin")
            for number in range(6):
                conn.execute(
                    """insert into commerce_listings
                    (listing_id,listing_type,owner_agent_id,merchant_id,source_product_ref,
                     title,category,listing_digest,published_at,updated_at,fresh_until,created_at)
                    values (?, 'product','cagt_downgrade','mkt_downgrade',?,'Widget','widgets','digest',?,?,?,?)""",
                    (f"lst_downgrade_{number}", f"SKU-{number}", now, now, now, now),
                )
            current = capacity(conn, "mkt_downgrade")
            self.assertEqual((current["active_used"], current["active_limit"]), (6, 20))
            require_publication_capacity(conn, "mkt_downgrade", existing_state=None)
            set_merchant_plan(conn, "mkt_downgrade", "lite", actor="admin")
            current = capacity(conn, "mkt_downgrade")
            self.assertEqual((current["active_used"], current["active_limit"]), (6, 5))
            with self.assertRaises(PermissionDenied) as caught:
                require_publication_capacity(conn, "mkt_downgrade", existing_state=None)
            self.assertIn("LISTINGS_CAPACITY_EXCEEDED", str(caught.exception))
            # Updating an existing ACTIVE row does not consume another slot.
            require_publication_capacity(conn, "mkt_downgrade", existing_state="ACTIVE")
            self.assertEqual(
                conn.execute(
                    "select count(*) from listing_entitlement_audit"
                    " where action='merchant_plan_changed'"
                ).fetchone()[0],
                2,
            )


if __name__ == "__main__":
    unittest.main()
