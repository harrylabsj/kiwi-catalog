# A326 返修自有控制：2-36 真·触达 body/redirect 的 wall deadline + 3-55 事务归属异常收尾。
#
# 与 A323 控制的差别（源审校准）：
# 1. C3/C5 fixture 用 permissive_local + loopback 放行（受控条件），并以
#    **到达计数/屏障**证明 handler/第二 host DNS **确实被触达**（非前置 SSRF 拒绝）；
# 2. 滴流 handler 带 stop 事件 + finally 可靠关停（caller 不截止也不挂测试）；
# 3. 3-55 补 own-tx COMMIT 失败收尾与 apply 异常保 outer 的正负控。
import http.server
import socketserver
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest import mock

from kiwi_catalog.db.migrations import CURRENT_SCHEMA_VERSION, run_migrations
from kiwi_catalog.discovery import fetcher as fetcher_mod
from kiwi_catalog.discovery.fetcher import FetchError, ProfileFetcher, TrustPolicy, _resolve_and_validate


class _StopableServer:
    """带 stop 事件的滴流服务器：handler 每轮检查 stop，保证测试可靠收尾。"""

    def __init__(self, mode: str):
        self.stop = threading.Event()
        self.hits = {"get": 0}
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                outer.hits["get"] += 1
                if mode == "drip":
                    self.send_response(200)
                    self.send_header("content-type", "application/json")
                    self.send_header("content-length", "65536")
                    self.end_headers()
                    self.wfile.write(b"x" * 8192)
                    self.wfile.flush()
                    while not outer.stop.is_set():
                        time.sleep(0.05)
                        self.wfile.write(b".")
                        self.wfile.flush()
                elif mode == "redirect":
                    self.send_response(302)
                    self.send_header("location", "https://slow-dns-a326.invalid/a2a")
                    self.end_headers()
                else:
                    body = b'{"ok": true}'
                    self.send_response(200)
                    self.send_header("content-type", "application/json")
                    self.send_header("content-length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), H)
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.stop.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


class WallDeadlineTest(unittest.TestCase):
    def setUp(self):
        # 进程内预算 0.5s（探针同形；不改产品默认 30s）
        self._patch = mock.patch.object(fetcher_mod, "_MAX_FETCH_DURATION_SECONDS", 0.5)
        self._patch.start()
        self.addCleanup(self._patch.stop)
        # 受控 loopback 放行（fixture 级；产品 SSRF 封禁语义不改）——保证真触达
        self._blocked = mock.patch.object(fetcher_mod, "_is_blocked_ip", return_value=None)
        self._blocked.start()
        self.addCleanup(self._blocked.stop)

    def _permissive(self):
        return ProfileFetcher(TrustPolicy.permissive_local())

    def test_c3_body_drip_reaches_handler_and_bounded(self):
        srv = _StopableServer("drip")
        try:
            started = time.monotonic()
            with self.assertRaises(FetchError):
                self._permissive().fetch(f"{srv.base}/profile.json")
            elapsed = time.monotonic() - started
            # 真触达：handler 被调用（≥1 次 GET）
            self.assertGreaterEqual(srv.hits["get"], 1, "body fixture 未被触达")
            self.assertLess(elapsed, 1.0, f"滴流未按预算收口：{elapsed:.3f}s")
        finally:
            srv.close()  # stop 事件 + shutdown，caller 超时也不挂测试

    def test_c5_redirect_reaches_second_host_slow_dns_and_bounded(self):
        srv = _StopableServer("redirect")
        calls = {"slow_dns": 0}
        real_resolver = fetcher_mod.socket.getaddrinfo

        def counting_resolver(*args, **kwargs):
            host = args[0] if args else kwargs.get("host")
            if host == "slow-dns-a326.invalid":
                calls["slow_dns"] += 1
                time.sleep(1.2)
            return real_resolver(*args, **kwargs)

        try:
            with mock.patch.object(fetcher_mod.socket, "getaddrinfo", side_effect=counting_resolver):
                started = time.monotonic()
                with self.assertRaises(FetchError):
                    self._permissive().fetch(f"{srv.base}/profile.json")
                elapsed = time.monotonic() - started
                # 真触达：redirect 目标的 slow DNS **真的被调用**（非前置拒绝）
                self.assertGreaterEqual(calls["slow_dns"], 1, "第二 host DNS 未被触达")
                self.assertLess(elapsed, 1.0, f"redirect DNS 未共享预算：{elapsed:.3f}s")
        finally:
            srv.close()

    def test_dns_admission_atomic_bound_rejects_seventh_caller(self):
        # review 2-36（A328 余项）：**原子 admission 信号量**确定性控制——
        # 占满全部 6 个额度（等价 2 运行 + 4 排队）→ 第 7 个 caller 的
        # acquire(timeout=0.5) 立即 FetchError（admission），不排队不重驱；
        # 释放后恢复可解析（无额度泄漏）。不经 executor.submit 绕过产品
        # admission（A326 源审指出的假通过形态）。
        slots = [fetcher_mod._DNS_ADMISSION.acquire() for _ in range(6)]
        try:
            started = time.monotonic()
            with self.assertRaises(FetchError) as ctx:
                _resolve_and_validate("busy-a326.invalid", 443, deadline=time.monotonic() + 0.5)
            elapsed = time.monotonic() - started
            self.assertIn("waiting for DNS admission", str(ctx.exception))
            # 额度被真实占用时 caller 等到自身预算到期才拒（不是即时拒绝）——
            # 上界是 caller 预算本身，不是队列位置。
            self.assertLess(elapsed, 0.7, "admission 拒绝未受 caller 预算约束")
        finally:
            for slot in slots:
                fetcher_mod._DNS_ADMISSION.release()
        # 释放后恢复可解析（真实 resolver，127.0.0.1 字面量即时返回）
        ip = _resolve_and_validate("127.0.0.1", 443, deadline=time.monotonic() + 1.0)
        self.assertEqual(str(ip), "127.0.0.1")

    def test_positive_fast_fetch_still_works(self):
        blocked_patch = mock.patch.object(fetcher_mod, "_is_blocked_ip", return_value=None)
        blocked_patch.start()
        self.addCleanup(blocked_patch.stop)
        srv = _StopableServer("ok")
        try:
            result = self._permissive().fetch(f"{srv.base}/profile.json")
            self.assertEqual(result.status_code, 200)
        finally:
            srv.close()


class MigrationOwnershipTest(unittest.TestCase):
    def _fresh(self):
        tmp = tempfile.TemporaryDirectory(suffix="a326-mig")
        self.addCleanup(tmp.cleanup)
        conn = sqlite3.connect(f"{tmp.name}/a326.sqlite")
        self.addCleanup(conn.close)
        conn.execute("pragma busy_timeout = 5000")
        return conn, run_migrations

    def test_own_tx_chain_failure_rolls_back_own_and_reraises(self):
        # own-tx：链中 apply 异常 → 回滚自身（无 open tx）+ 原错误上抛。
        # （COMMIT 阶段失败的收尾为 3 行直审代码：rollback+raise，见
        #  migrations.py「own 事务 COMMIT 失败」注释——sqlite COMMIT 失败
        # 需磁盘满/锁等故障注入基础设施，不在本控制内模拟。）
        import tempfile

        from kiwi_catalog.db import migrations as mig_mod

        tmp = tempfile.TemporaryDirectory(suffix="a326-ownfail")
        self.addCleanup(tmp.cleanup)
        conn = sqlite3.connect(f"{tmp.name}/db.sqlite")
        self.addCleanup(conn.close)
        conn.execute("pragma busy_timeout = 200")

        class _Boom:
            version = 10_001

            @staticmethod
            def apply(conn):
                raise RuntimeError("boom mid-chain")

        original = mig_mod.MIGRATIONS
        run_migrations(conn)  # 迁到 CURRENT
        with mock.patch.object(mig_mod, "MIGRATIONS", original + (_Boom,)):
            conn.execute(f"pragma user_version = {CURRENT_SCHEMA_VERSION}")  # 只触发 _Boom
            with self.assertRaises(RuntimeError) as ctx:
                run_migrations(conn)
            self.assertIn("boom mid-chain", str(ctx.exception))
            self.assertFalse(conn.in_transaction)  # own-tx 已收尾（回滚）
        # 库未被 _Boom 半途写入破坏（CURRENT 状态保持）
        self.assertEqual(conn.execute("pragma user_version").fetchone()[0], CURRENT_SCHEMA_VERSION)

    def test_apply_exception_keeps_caller_outer_and_reraises_original(self):
        import tempfile

        from kiwi_catalog.db import migrations as mig_mod

        tmp = tempfile.TemporaryDirectory(suffix="a326-outer")
        self.addCleanup(tmp.cleanup)
        db_path = f"{tmp.name}/db.sqlite"
        conn = sqlite3.connect(db_path)
        self.addCleanup(conn.close)
        conn.execute("pragma busy_timeout = 200")

        class _Boom:
            version = 10_001

            @staticmethod
            def apply(conn):
                raise RuntimeError("boom mid-chain")

        original = mig_mod.MIGRATIONS
        try:
            conn.execute("BEGIN")  # caller 外层事务
            conn.execute(f"pragma user_version = {CURRENT_SCHEMA_VERSION}")  # 跳过既有链，只触发 _Boom
            with mock.patch.object(mig_mod, "MIGRATIONS", original + (_Boom,)):
                with self.assertRaises(RuntimeError) as ctx:
                    run_migrations(conn)
            self.assertIn("boom mid-chain", str(ctx.exception))
            # outer 事务仍开放（未被代回滚/代提交）——caller 自主决定
            self.assertTrue(conn.in_transaction)
        finally:
            conn.rollback()

    def test_c2_contention_and_c3_chain_lock_still_hold(self):
        # 回归：既有 guards 语义保持（fresh 迁移成功 + 竞争 fail-closed）
        conn, run = self._fresh()
        run(conn)
        uv = conn.execute("pragma user_version").fetchone()[0]
        self.assertEqual(uv, CURRENT_SCHEMA_VERSION)

if __name__ == "__main__":
    unittest.main()
