from __future__ import annotations
import asyncio
import os
import shutil
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock
import httpx
from kiwi_catalog.api import app as app_module
from kiwi_catalog.api.handlers import agent_catalog as agents
from kiwi_catalog.api.idempotency import catalog_write_actor_key, enforce_agent_catalog_rate_limit
from kiwi_catalog.db.session import db_session, open_connection
from kiwi_catalog.services import access_log, buyer_stats
from kiwi_catalog.services.rate_limit import SQLiteRateLimitBackend
from tests import test_heartbeat_binding_signature as heartbeat_fixture
from tests import test_merchant_publications as publication_fixture


class ResourceBoundariesTest(unittest.TestCase):
    def test_anonymous_keyword_retention_and_daily_cardinality_cap_keep_existing_counts(self):
        with tempfile.TemporaryDirectory() as root:
            c = open_connection(Path(root) / "catalog.sqlite")
            try:
                c.execute("INSERT INTO buyer_keyword_daily VALUES ('2020-01-01','listing','old',1,0,'2020-01-01')")
                with mock.patch.object(buyer_stats, "_KEYWORD_DAILY_MAX", 3, create=True):
                    for keyword in ("one", "two", "three", "four", "five"):
                        buyer_stats.record_buyer_keyword(c, "listing", keyword, 0)
                    buyer_stats.record_buyer_keyword(c, "listing", "one", 1)
                self.assertEqual(
                    c.execute("SELECT count(*) FROM buyer_keyword_daily WHERE day='2020-01-01'").fetchone()[0], 0
                )
                self.assertEqual(c.execute("SELECT count(*) FROM buyer_keyword_daily").fetchone()[0], 3)
                row = c.execute("SELECT searches,zero_results FROM buyer_keyword_daily WHERE keyword='one'").fetchone()
                self.assertEqual((row["searches"], row["zero_results"]), (2, 1))
            finally:
                c.rollback()
                c.close()

    def test_search_read_budget_is_peer_scoped_and_does_not_consume_catalog_write_budget(self):
        from kiwi_catalog.api.handlers import listings
        from kiwi_catalog.core.errors import RateLimitError

        with (
            tempfile.TemporaryDirectory() as root,
            mock.patch.dict(os.environ, {"KIWI_CATALOG_PUBLIC_READ_RATE_LIMIT_PER_MINUTE": "1"}),
        ):
            path = Path(root) / "catalog.sqlite"
            c = open_connection(path)
            c.close()
            agents.v1_search_agents(path, {"q": "one"}, auth_payload={"_client_ip": "198.51.100.1"})
            with self.assertRaises(RateLimitError):
                agents.v1_search_agents(path, {"q": "two"}, auth_payload={"_client_ip": "198.51.100.1"})
            agents.v1_search_agents(path, {"q": "two"}, auth_payload={"_client_ip": "198.51.100.2"})
            listings.v1_search_listings(path, {"q": "one"}, auth_payload={"_client_ip": "198.51.100.1"})
            with self.assertRaises(RateLimitError):
                listings.v1_search_listings(path, {"q": "two"}, auth_payload={"_client_ip": "198.51.100.1"})
            with db_session(path) as c:
                enforce_agent_catalog_rate_limit(c, catalog_write_actor_key({}), 1)

    def test_publication_detail_budget_preserves_visibility_and_other_surface_capacity(self):
        fixture = publication_fixture.MerchantPublicationsApiTest()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.addCleanup(shutil.rmtree, fixture.tmp)
        status, result = fixture._create(fixture.cookie_a, publication_fixture._publish_body("Synthetic observation"))
        self.assertEqual(status, 200, result)
        publication_id = result["publication"]["publication_id"]
        from kiwi_catalog.api.handlers import merchant_publications
        from kiwi_catalog.core.errors import RateLimitError

        with mock.patch.dict(os.environ, {"KIWI_CATALOG_PUBLIC_READ_RATE_LIMIT_PER_MINUTE": "1"}):
            self.assertTrue(
                merchant_publications.get_publication(fixture.db_path, publication_id, {"_client_ip": "198.51.100.1"})[
                    "ok"
                ]
            )
            with self.assertRaises(RateLimitError):
                merchant_publications.get_publication(fixture.db_path, publication_id, {"_client_ip": "198.51.100.1"})
            self.assertTrue(
                merchant_publications.get_publication(fixture.db_path, publication_id, {"_client_ip": "198.51.100.2"})[
                    "ok"
                ]
            )
            self.assertTrue(
                agents.v1_search_agents(fixture.db_path, {}, auth_payload={"_client_ip": "198.51.100.1"})["ok"]
            )

    def test_real_fastapi_search_uses_untrusted_direct_peer_not_spoofed_xff_or_query_ip(self):
        async def run():
            with tempfile.TemporaryDirectory() as root:
                path = Path(root) / "catalog.sqlite"
                c = open_connection(path)
                c.close()
                app = app_module.create_catalog_app(path)
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app, client=("198.51.100.1", 1234)),
                    base_url="http://synthetic.test",
                ) as one:
                    first = await one.get("/v1/listings/search?q=first")
                    spoofed = await one.get(
                        "/v1/listings/search?q=next&_client_ip=192.0.2.9", headers={"X-Forwarded-For": "192.0.2.8"}
                    )
                async with httpx.AsyncClient(
                    transport=httpx.ASGITransport(app=app, client=("198.51.100.2", 1234)),
                    base_url="http://synthetic.test",
                ) as two:
                    other = await two.get("/v1/listings/search?q=other")
                self.assertEqual([first.status_code, spoofed.status_code, other.status_code], [200, 429, 200])
                with db_session(path) as c:
                    keys = [row[0] for row in c.execute("SELECT actor_key FROM agent_catalog_write_rate_limits")]
                    self.assertIn("public-read:listing search:198.51.100.1", keys)
                    self.assertIn("public-read:listing search:198.51.100.2", keys)
                    self.assertFalse(any("192.0.2." in key for key in keys))

        with mock.patch.dict(os.environ, {"KIWI_CATALOG_PUBLIC_READ_RATE_LIMIT_PER_MINUTE": "1"}):
            asyncio.run(run())

    def test_new_backend_per_request_really_prunes_expired_rows_and_preserves_live_counts(self):
        with tempfile.TemporaryDirectory() as root:
            c = open_connection(Path(root) / "catalog.sqlite")
            try:
                c.execute(
                    "INSERT INTO merchant_application_limits VALUES ('expired','2020-01-01T00:00:00',1,'2020-01-01T00:00:00')"
                )
                for n in range(128):
                    backend = SQLiteRateLimitBackend(c, table="merchant_application_limits", key_column="actor_key")
                    self.assertTrue(backend.consume(key=f"live-{n}", window_start="2099-01-01T00:00:00", limit=2))
                self.assertEqual(
                    c.execute("SELECT count(*) FROM merchant_application_limits WHERE actor_key='expired'").fetchone()[
                        0
                    ],
                    0,
                )
                self.assertEqual(
                    c.execute(
                        "SELECT count(*) FROM merchant_application_limits WHERE actor_key LIKE 'live-%'"
                    ).fetchone()[0],
                    128,
                )
            finally:
                c.rollback()
                c.close()

    def test_signed_runtime_heartbeat_uses_independent_binding_budget_not_saturated_anonymous_bucket(self):
        fixture = heartbeat_fixture.HeartbeatBindingSignatureTest()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        with mock.patch.dict(os.environ, {"KIWI_CATALOG_WRITE_RATE_LIMIT_PER_MINUTE": "2"}):
            with db_session(fixture.db_path) as conn:
                for _ in range(2):
                    enforce_agent_catalog_rate_limit(conn, catalog_write_actor_key({}), 2)
            result = agents.heartbeat_catalog_agent(
                fixture.db_path, fixture.cagt, {"_binding_jws": fixture._heartbeat_sig()}
            )
            self.assertTrue(result["ok"])
            self.assertEqual(result["actor"], f"runtime:{fixture.binding_id}")
            with db_session(fixture.db_path) as conn:
                rows = conn.execute("SELECT actor_key, request_count FROM agent_catalog_write_rate_limits").fetchall()
                self.assertTrue(any(row["actor_key"].startswith("runtime:") for row in rows))

    def test_both_actual_asgi_stacks_do_not_block_event_loop_during_slow_access_log(self):
        async def one_stack(fallback):
            with tempfile.TemporaryDirectory() as root:
                with (
                    mock.patch.object(app_module, "FastAPI", None)
                    if fallback
                    else mock.patch.object(app_module, "FastAPI", app_module.FastAPI)
                ):
                    app = app_module.create_catalog_app(Path(root) / "catalog.sqlite")
                entered = threading.Event()
                done = threading.Event()
                record_threads = []
                loop_thread = threading.get_ident()

                def slow_record(*args, **kwargs):
                    record_threads.append(threading.get_ident())
                    entered.set()
                    time.sleep(0.15)
                    done.set()

                with mock.patch.object(access_log, "record_http_access", slow_record):
                    async with httpx.AsyncClient(
                        transport=httpx.ASGITransport(app=app), base_url="http://synthetic.test"
                    ) as client:
                        request = asyncio.create_task(client.get("/v1/no-such-route"))
                        self.assertTrue(await asyncio.to_thread(entered.wait, 1))
                        try:
                            self.assertFalse(done.is_set(), "log blocked the event loop until completion")
                            self.assertNotEqual(record_threads, [loop_thread])
                        finally:
                            response = await request
                        self.assertEqual(response.status_code, 404)
                self.assertTrue(done.is_set())

        for fallback in (True, False):
            with self.subTest(fallback=fallback):
                asyncio.run(one_stack(fallback))
