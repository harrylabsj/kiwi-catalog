# A323 返修自有控制：2-36 caller 全程 deadline / 3-55 外层事务归属。
import http.server
import socketserver
import threading
import time
import unittest
from unittest import mock

from kiwi_catalog.discovery import fetcher as fetcher_mod
from kiwi_catalog.discovery.fetcher import (
    FetchError,
    ProfileFetcher,
    TrustPolicy,
)


class _SlowBodyHandler(http.server.BaseHTTPRequestHandler):
    """发 8KiB 后滴漏停发（不关连接）——C3 同形。"""

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", "65536")
        self.end_headers()
        self.wfile.write(b"x" * 8192)
        self.wfile.flush()
        try:
            # 滴漏：每 0.2s 发 1 字节，永不发完
            while True:
                time.sleep(0.2)
                self.wfile.write(b".")
                self.wfile.flush()
        except Exception:
            pass

    def log_message(self, *args):  # 静默
        pass


class _RedirectSlowDnsHandler(http.server.BaseHTTPRequestHandler):
    """302 → 不可解析慢 DNS 目标——C5 同形。"""

    def do_GET(self):  # noqa: N802
        self.send_response(302)
        self.send_header("location", "https://slow-dns-a323.invalid/a2a")
        self.end_headers()

    def log_message(self, *args):
        pass


def _serve(handler):
    server = socketserver.TCPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


class BudgetBoundTest(unittest.TestCase):
    def setUp(self):
        # 探针同形：进程内预算 0.5s（不改产品默认 30s；仅本测试 patch）
        self._patch = mock.patch.object(fetcher_mod, "_MAX_FETCH_DURATION_SECONDS", 0.5)
        self._patch.start()
        self.addCleanup(self._patch.stop)

    def test_c3_body_drip_bounded(self):
        server, base = _serve(_SlowBodyHandler)
        try:
            fetcher = ProfileFetcher(TrustPolicy.defaults())
            started = time.monotonic()
            with self.assertRaises(FetchError):
                fetcher.fetch(f"{base}/profile.json")
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 1.0, f"body 滴漏未按预算收口：{elapsed:.3f}s")
        finally:
            server.shutdown()
            server.server_close()

    def test_c4_dns_stall_bounded(self):
        def slow_getaddrinfo(host, port, **kwargs):
            time.sleep(1.2)
            return [(2, 1, 6, "", ("127.0.0.1", port))]

        with mock.patch.object(fetcher_mod.socket, "getaddrinfo", side_effect=slow_getaddrinfo):
            fetcher = ProfileFetcher(TrustPolicy.defaults())
            started = time.monotonic()
            with self.assertRaises(FetchError):
                fetcher.fetch("https://dns-stall-a323.invalid/profile.json")
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 1.0, f"DNS 解析未按预算返回 caller：{elapsed:.3f}s")

    def test_c5_redirect_dns_shares_budget(self):
        server, base = _serve(_RedirectSlowDnsHandler)
        try:

            def slow_getaddrinfo(host, port, **kwargs):
                if host == "slow-dns-a323.invalid":
                    time.sleep(1.2)
                return [(2, 1, 6, "", ("127.0.0.1", port))]

            with mock.patch.object(fetcher_mod.socket, "getaddrinfo", side_effect=slow_getaddrinfo):
                fetcher = ProfileFetcher(TrustPolicy.defaults())
                started = time.monotonic()
                with self.assertRaises(FetchError):
                    fetcher.fetch(f"{base}/profile.json")
                elapsed = time.monotonic() - started
                self.assertLess(elapsed, 1.0, f"redirect DNS 未共享预算：{elapsed:.3f}s")
        finally:
            server.shutdown()
            server.server_close()

    def test_positive_fast_fetch_still_works(self):
        # loopback 在产品里被硬封（无 policy 杠杆）——正控 fixture 级放行
        # （与 C4 patch getaddrinfo 同口径；不改产品封禁语义）。
        blocked_patch = mock.patch.object(fetcher_mod, "_is_blocked_ip", return_value=None)
        blocked_patch.start()
        self.addCleanup(blocked_patch.stop)

        class OK(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                body = b'{"ok": true}'
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server, base = _serve(OK)
        try:
            # http 正控用 permissive_local（本地回环 http 允许形态）
            fetcher = ProfileFetcher(TrustPolicy.permissive_local())
            result = fetcher.fetch(f"{base}/profile.json")
            self.assertEqual(result.status_code, 200)
        finally:
            server.shutdown()
            server.server_close()


class MigrationOwnershipTest(unittest.TestCase):
    def _fresh(self):
        import sqlite3
        import tempfile

        from kiwi_catalog.db.migrations import run_migrations

        path = tempfile.mktemp(suffix="a323.sqlite")
        conn = sqlite3.connect(path)
        conn.execute("pragma busy_timeout = 5000")
        return conn, run_migrations

    def test_own_tx_path_commits_to_current_version(self):
        conn, run = self._fresh()
        run(conn)
        uv = conn.execute("pragma user_version").fetchone()[0]
        self.assertEqual(uv, 41)
        self.assertFalse(conn.in_transaction)

    def test_c4_outer_tx_stays_owned_by_caller(self):
        conn, run = self._fresh()
        # scratch 在 BEGIN **之前**独立提交（模拟 caller 此前已落库的状态）
        conn.execute("CREATE TABLE scratch_a323 (id integer)")
        conn.commit()
        conn.execute("BEGIN")
        run(conn)
        # review 3-55（A323）：迁移结束 caller 外层事务**仍开放**（不被代提交）
        self.assertTrue(conn.in_transaction)
        # caller 回滚撤销迁移效果；scratch 表仍在（外层自己的写入）
        conn.rollback()
        uv = conn.execute("pragma user_version").fetchone()[0]
        self.assertEqual(uv, 0)
        exists = conn.execute(
            "select count(*) from sqlite_master where type='table' and name='catalog_agents'"
        ).fetchone()[0]
        self.assertEqual(exists, 0)
        scratch = conn.execute(
            "select count(*) from sqlite_master where type='table' and name='scratch_a323'"
        ).fetchone()[0]
        self.assertEqual(scratch, 1)
        conn.close()

    def test_outer_tx_success_commit_left_to_caller(self):
        conn, run = self._fresh()
        conn.execute("BEGIN")
        run(conn)
        self.assertTrue(conn.in_transaction)
        conn.commit()  # caller 决定提交
        uv = conn.execute("pragma user_version").fetchone()[0]
        self.assertEqual(uv, 41)
        conn.close()


if __name__ == "__main__":
    unittest.main()
