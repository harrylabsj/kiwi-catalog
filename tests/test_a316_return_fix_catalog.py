# Copyright 2026 harrylabsj
# A316 返修合成测试：仅覆盖本轮返修的原失败编号（catalog 侧）。
# 每 ID 一个聚焦控制；不弱化既有 guard/expected。
from __future__ import annotations

import base64
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock

from kiwi_catalog.a2a.binding_claims import read_runtime_binding
from kiwi_catalog.agent_catalog.pagination import (
    agent_cursor_predicate,
    decode_agent_cursor,
)
from kiwi_catalog.core.errors import PermissionDenied, ValidationError
from kiwi_catalog.api.handlers.agent_catalog import (
    _enqueue_verification,
    reinstate_catalog_agent,
)
from kiwi_catalog.services.agent_verification import VerificationQueueShutdownError

ADMIN_TOKEN = "a316-admin-token"
OWNER_SECRET = "a316-owner-secret"


def _raw_call(app, method: str, path: str, body: bytes = b"") -> tuple[int, dict]:
    """直调 ASGI（与本仓既有 _call 同口径），带 content-type JSON。"""
    import asyncio

    received: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(msg: dict) -> None:
        received.append(msg)

    async def call() -> None:
        await app(
            {
                "type": "http",
                "method": method,
                "path": path,
                "headers": [(b"content-type", b"application/json")],
                "query_string": b"",
                "http_version": "1.1",
                "scheme": "http",
                "client": ("127.0.0.1", 51000),
            },
            receive,
            send,
        )

    asyncio.run(call())
    status = received[0]["status"]
    payload = json.loads(received[-1]["body"].decode() or "{}")
    return status, payload


class CursorStrictnessTest(unittest.TestCase):
    """P1-5 + 2-33：cursor 分级 fail-closed。"""

    def test_v2_decode_failures_are_typed_not_legacy_fallback(self) -> None:
        bad = [
            "v2:!!!not-base64!!!",
            "v2:" + base64.urlsafe_b64encode(b"\xff\xfe-bin").decode(),
            "v2:" + base64.urlsafe_b64encode(json.dumps([{}, "x", "y", "z"]).encode()).decode(),
        ]
        for cursor in bad:
            with self.assertRaises(ValidationError):
                decode_agent_cursor(cursor)

    def test_legacy_id_cursor_is_rejected(self) -> None:
        with self.assertRaises(ValidationError):
            agent_cursor_predicate("cagt_bare_legacy_id")


class TrustedIpRateLimitTest(unittest.TestCase):
    """2-30：payload 伪造 _client_ip 不能跨桶打穿 per-IP 限流（FastAPI 栈）。"""

    def test_spoofed_payload_ip_does_not_cross_buckets(self) -> None:
        from kiwi_catalog.api.app import create_catalog_app

        tmp = tempfile.mkdtemp()
        db_path = os.path.join(tmp, "catalog.sqlite")
        with mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN,
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
                "KIWI_CATALOG_LOGIN_RATE_LIMIT_PER_15MIN": "4",
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
            },
            clear=False,
        ):
            app = create_catalog_app(db_path)
            codes = []
            for i in range(21):
                body = json.dumps(
                    {
                        "email": f"a316-{i}@example.test",
                        "password": "pw-123456",
                        "merchant_name": f"M{i}",
                        "phone": "13800000000",
                        # 伪造 payload IP：修复前每伪造一个新 IP 即换新桶，21 次全过
                        "_client_ip": f"10.{i}.0.{i}",
                    }
                ).encode()
                status, payload = _raw_call(app, "POST", "/v1/accounts/register", body)
                codes.append(status)
            # per-IP 桶 = max(1000*5,20)=20——同 peer 桶内第 21 次必须 429
            self.assertEqual(codes[-1], 429, f"spoofed-IP bucket not enforced: {codes}")


class ResendAntiEnumTest(unittest.TestCase):
    """3-64：未知邮箱 resend 响应与已知账号同形（SMTP 语义）。"""

    def test_unknown_email_response_shape_matches_known(self) -> None:
        from kiwi_catalog.api.app import create_catalog_app
        from kiwi_catalog.db.session import db_session
        from kiwi_catalog.services import accounts as accounts_service

        tmp = tempfile.mkdtemp()
        db_path = os.path.join(tmp, "catalog.sqlite")
        with mock.patch.dict(
            os.environ,
            {
                "KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN,
                "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET,
                "KIWI_CATALOG_EMAIL_VERIFICATION_MODE": "console",
            },
            clear=False,
        ):
            app = create_catalog_app(db_path)
            known_body = json.dumps(
                {"email": "known@example.test", "password": "pw-123456", "merchant_name": "K", "phone": "13800000000"}
            ).encode()
            _raw_call(app, "POST", "/v1/accounts/register", known_body)
            with db_session(db_path) as conn:
                account = accounts_service.account_by_email(conn, "known@example.test")
                accounts_service.verify_email(conn, int(account["account_id"]), "", bypass=True) if hasattr(
                    accounts_service, "verify_email"
                ) else None
            known_status, known = _raw_call(
                app, "POST", "/v1/accounts/resend-code", json.dumps({"email": "known@example.test"}).encode()
            )
            unknown_status, unknown = _raw_call(
                app, "POST", "/v1/accounts/resend-code", json.dumps({"email": "ghost@example.test"}).encode()
            )
            self.assertEqual(known_status, 200)
            self.assertEqual(unknown_status, 200)
            # 同形（键集合一致）——不再以 sent:false / 403 形状差异枚举
            self.assertEqual(sorted(unknown.keys()), sorted(known.keys()))
            self.assertNotIn("sent", unknown)


class ReinstateShutdownDegradeTest(unittest.TestCase):
    """3-58：队列 Shutdown 时已成功的治理动作不再 500，诚实标注未入队。"""

    def test_reinstate_survives_queue_shutdown(self) -> None:
        from kiwi_catalog.agent_catalog.sqlite_repository import (
            new_catalog_agent_id,
            upsert_catalog_agent,
        )
        from kiwi_catalog.api.handlers import agent_catalog as handlers
        from kiwi_catalog.db.session import db_session

        tmp = tempfile.mkdtemp()
        db_path = os.path.join(tmp, "catalog.sqlite")
        agent_id = new_catalog_agent_id()
        with db_session(db_path) as conn:
            upsert_catalog_agent(
                conn, catalog_agent_id=agent_id, merchant_id="",
                canonical_domain="a.example",
                source_type="admin_curated", lifecycle_status="active",
            )
            # reinstate 前置：administrative_state 必须是 suspended
            conn.execute(
                "update catalog_agents set administrative_state='suspended' where catalog_agent_id=?",
                (agent_id,),
            )
        with mock.patch.dict(
            os.environ,
            {"KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN, "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET},
            clear=False,
        ), mock.patch(
            "kiwi_catalog.api.handlers.agent_catalog._enqueue_verification",
            side_effect=VerificationQueueShutdownError("shutdown"),
        ):
            payload = handlers.reinstate_catalog_agent(
                db_path, agent_id, {"admin_token": ADMIN_TOKEN, "reason": "a316"}
            )
        # 治理动作已成功（ok），重排失败诚实降级标注（非 500、非静默）
        self.assertTrue(payload.get("ok"))
        self.assertEqual(payload.get("verification_status"), "discovered")
        self.assertFalse(payload.get("verify_enqueued", True))
        self.assertIn("queue_reason", payload)


class CliActorDeclarationTest(unittest.TestCase):
    """3-66：CLI actor 明示为本地未验证声明。"""

    def test_cli_actor_is_marked_declared(self) -> None:
        import argparse

        from kiwi_catalog.cli_agent_catalog_commands import _cli_actor

        args = argparse.Namespace(admin_token="anything")
        self.assertEqual(_cli_actor(args), "cli-declared:admin")
        args2 = argparse.Namespace(admin_token="", owner_token="t")
        self.assertEqual(_cli_actor(args2, merchant_id="m1"), "cli-declared:merchant:m1")


class BindingExpiryTypedTest(unittest.TestCase):
    """3-67：naive/aware expires_at 混比 → typed 403，不 500。"""

    def test_aware_expires_vs_naive_now_is_permission_denied(self) -> None:
        from kiwi_catalog.api.app import create_catalog_app
        from kiwi_catalog.agent_catalog.sqlite_repository import (
            new_catalog_agent_id,
            upsert_catalog_agent,
        )
        from kiwi_catalog.db.session import db_session

        tmp = tempfile.mkdtemp()
        db_path = os.path.join(tmp, "catalog.sqlite")
        with mock.patch.dict(
            os.environ,
            {"KIWI_CATALOG_ADMIN_TOKEN": ADMIN_TOKEN, "KIWI_CATALOG_OWNER_TOKEN_SECRET": OWNER_SECRET},
            clear=False,
        ):
            app = create_catalog_app(db_path)
            agent_id = new_catalog_agent_id()
            with db_session(db_path) as conn:
                upsert_catalog_agent(
                    conn, catalog_agent_id=agent_id, merchant_id="",
                    canonical_domain="b.example",
                    source_type="admin_curated", lifecycle_status="active",
                )
                conn.execute(
                    "insert into runtime_bindings (binding_id, catalog_agent_id, merchant_id,"
                    " runtime_origin, a2a_endpoint, key_id, key_thumbprint, key_jwk_json,"
                    " binding_version, service_epoch, status, expires_at, created_at, updated_at,"
                    " management_base_path, management_api_major, mcp_path)"
                    " values ('bind_a316', ?, 'm', 'https://p.example', 'https://p.example/a2a',"
                    " 'https://p.example', 'sha256:abc', '{}', 1, 1, 'active',"
                    " '2099-01-01T00:00:00+05:00', '', '', '', 1, '')",
                    (agent_id,),
                )
                conn.commit()
                naive_now = datetime(2098, 1, 1)  # naive；expires 带 +05:00 → 原实现 TypeError → 500
                with self.assertRaises(PermissionDenied):
                    read_runtime_binding(conn, agent_id, now=naive_now)


class MigrationLockTest(unittest.TestCase):
    """3-55：BEGIN IMMEDIATE 写锁保持到迁移完成（不再 BEGIN 后立刻 COMMIT）。"""

    def test_write_lock_held_until_migration_end(self) -> None:
        from kiwi_catalog.db.migrations import run_migrations

        conn = sqlite3.connect(":memory:")
        statements: list[str] = []
        conn.set_trace_callback(statements.append)
        run_migrations(conn)
        conn.set_trace_callback(None)
        try:
            begin_idx = statements.index("BEGIN IMMEDIATE")
        except ValueError:
            self.fail("run_migrations did not take BEGIN IMMEDIATE write lock")
        after_begin = statements[begin_idx + 1 :]
        # 写锁取得后，下一条语句不得是 COMMIT（原返修缺陷：立即释放）
        self.assertNotEqual(after_begin[0].upper(), "COMMIT")
        savepoint_idx = next(
            (i for i, st in enumerate(after_begin) if st.upper().startswith("SAVEPOINT")),
            None,
        )
        self.assertIsNotNone(savepoint_idx, "SAVEPOINT must be taken inside the write lock")
        commit_idx = next(
            (i for i, st in enumerate(after_begin) if st.upper() == "COMMIT"), None
        )
        self.assertIsNotNone(commit_idx)
        self.assertGreater(commit_idx, savepoint_idx, "write lock must outlive the migration chain")


if __name__ == "__main__":
    unittest.main()
