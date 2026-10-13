from __future__ import annotations
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from kiwi_catalog.api.handlers import accounts as handlers
from kiwi_catalog.core.errors import ConflictError
from kiwi_catalog.db.session import db_session, now_iso, open_connection
from kiwi_catalog.services import connector_identity
from tests import test_accounts_api as setup_fixture


class AccountBoundariesTest(unittest.TestCase):
    def account_fixture(self):
        fixture = setup_fixture.AccountsApiTest()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.addCleanup(shutil.rmtree, fixture.tmp)
        session = fixture._register()
        return fixture, session

    def test_unclaimed_enrollment_preview_does_not_disclose_authorization_code(self):
        fixture, session = self.account_fixture()
        with db_session(fixture.db_path) as conn:
            conn.execute(
                "INSERT INTO enrollments(enrollment_id,device_code_hash,user_code,status,key_id,key_thumbprint,key_jwk_json,runtime_origin,a2a_endpoint,public_preview_json,created_at,expires_at) VALUES ('enr_test','digest','PRIVATE12','ready_for_authorization','k','t','{}','https://synthetic.example','https://synthetic.example/a2a','{}',?,'2099-01-01T00:00:00+00:00')",
                (now_iso(),),
            )
        preview = handlers.enrollment_detail(fixture.db_path, "enr_test", {"_cookie": f"kiwi_session={session}"})
        self.assertNotIn("user_code", preview)
        self.assertNotIn("PRIVATE12", json.dumps(preview))
        self.assertEqual(preview["status"], "ready_for_authorization")
        with mock.patch.dict(os.environ, {"KIWI_CATALOG_PUBLIC_BASE_URL": "https://catalog.example"}):
            with self.assertRaises(ConflictError):
                handlers.authorize_enrollment(
                    fixture.db_path,
                    "enr_test",
                    {"_cookie": f"kiwi_session={session}", "_origin": "https://catalog.example", "user_code": "WRONG"},
                )
        with db_session(fixture.db_path) as conn:
            row = conn.execute("SELECT status,merchant_id FROM enrollments WHERE enrollment_id='enr_test'").fetchone()
            self.assertEqual((row["status"], row["merchant_id"]), ("ready_for_authorization", ""))

    def test_profile_and_token_request_redact_but_me_remains_explicit_audited_reveal(self):
        fixture, session = self.account_fixture()
        fixture._request_token(session)
        issued = fixture._approve_first_application()
        cookie = f"kiwi_session={session}"
        for route, body in [
            ("/v1/accounts/profile", {"merchant_name": "Synthetic updated"}),
            ("/v1/accounts/token-request", {}),
        ]:
            status, view, _ = setup_fixture._call_http(
                fixture.app, "POST", route, json.dumps(body).encode(), cookie=cookie
            )
            self.assertEqual(status, 200, view)
            self.assertEqual(view["token"]["status"], "active")
            self.assertEqual(view["token"]["token"], "")
            self.assertNotIn(issued["token"], json.dumps(view))
        status, view, _ = setup_fixture._call_http(fixture.app, "GET", "/v1/accounts/me", cookie=cookie)
        self.assertEqual(status, 200, view)
        self.assertEqual(view["token"]["token"], issued["token"])
        with db_session(fixture.db_path) as conn:
            self.assertGreater(
                conn.execute("SELECT count(*) FROM audit_events WHERE event='merchant_token_viewed'").fetchone()[0], 0
            )

    def test_login_limit_invalid_nonpositive_cannot_disable_security_buckets(self):
        for raw in ("0", "-1", "garbage", ""):
            with self.subTest(raw=raw), mock.patch.dict(os.environ, {"KIWI_CATALOG_LOGIN_RATE_LIMIT_PER_15MIN": raw}):
                self.assertEqual(handlers._login_rate_limit_per_15min(), 10)
        with mock.patch.dict(os.environ, {"KIWI_CATALOG_LOGIN_RATE_LIMIT_PER_15MIN": "3"}):
            self.assertEqual(handlers._login_rate_limit_per_15min(), 3)

    def test_approve_stale_pending_read_cannot_return_unpersisted_code_for_other_account(self):
        with (
            tempfile.TemporaryDirectory() as root,
            mock.patch.dict(os.environ, {"KIWI_CATALOG_CONNECTOR_RETURN_URLS": "https://connector.example"}),
        ):
            path = Path(root) / "catalog.sqlite"
            a = open_connection(path)
            b = open_connection(path)
            try:
                created = connector_identity.create_request(a, return_url="https://connector.example/callback")
                a.commit()
                one = {"account_id": 101, "merchant_id": "first-owner", "merchant_name": "First", "email_verified": 1}
                two = {"account_id": 102, "merchant_id": "second-owner", "merchant_name": "Second", "email_verified": 1}
                load = connector_identity.load_request
                winner = {}

                def old_read_then_other_approve(conn, request_id):
                    row = load(conn, request_id)
                    if conn is a:
                        with mock.patch.object(connector_identity, "load_request", load):
                            winner.update(connector_identity.approve_request(b, request_id=request_id, account=one))
                            b.commit()
                    return row

                with mock.patch.object(connector_identity, "load_request", old_read_then_other_approve):
                    with self.assertRaises(ConflictError):
                        connector_identity.approve_request(a, request_id=created["request_id"], account=two)
                a.rollback()
                record = load(a, created["request_id"])
                self.assertEqual(record["merchant_id"], "first-owner")
                identity = connector_identity.exchange(a, request_id=created["request_id"], code=winner["code"])
                self.assertEqual(identity["merchant_id"], "first-owner")
            finally:
                a.rollback()
                a.close()
                b.close()

    def test_normal_approve_does_not_commit_or_rollback_outer_caller_transaction(self):
        with (
            tempfile.TemporaryDirectory() as root,
            mock.patch.dict(os.environ, {"KIWI_CATALOG_CONNECTOR_RETURN_URLS": "https://connector.example"}),
        ):
            path = Path(root) / "catalog.sqlite"
            a = open_connection(path)
            b = open_connection(path)
            try:
                created = connector_identity.create_request(a, return_url="https://connector.example/callback")
                a.execute("CREATE TABLE caller_scratch(v text)")
                a.commit()
                a.execute("INSERT INTO caller_scratch VALUES ('uncommitted')")
                result = connector_identity.approve_request(
                    a,
                    request_id=created["request_id"],
                    account={"account_id": 101, "merchant_id": "first-owner", "email_verified": 1},
                )
                self.assertTrue(result["code"])
                self.assertTrue(a.in_transaction)
                self.assertEqual(b.execute("SELECT count(*) FROM caller_scratch").fetchone()[0], 0)
                self.assertEqual(connector_identity.load_request(b, created["request_id"])["status"], "pending")
                a.rollback()
                self.assertEqual(a.execute("SELECT count(*) FROM caller_scratch").fetchone()[0], 0)
            finally:
                a.rollback()
                a.close()
                b.close()
