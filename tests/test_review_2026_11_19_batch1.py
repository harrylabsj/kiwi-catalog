"""审查 2026-11-19「第一批」修复回归：P2-1 封禁对存量会话 fail-closed、
P2-9 公开检索补匿名读限流。"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from kiwi_catalog.api.handlers import merchant_publications
from kiwi_catalog.core.errors import RateLimitError
from kiwi_catalog.db.session import now_iso, open_connection
from kiwi_catalog.services import accounts


def _create_account(conn, email: str, status: str = "active") -> int:
    now = now_iso()
    conn.execute(
        "insert into merchant_accounts(email, password_hash, status, created_at, updated_at)"
        " values (?, ?, ?, ?, ?)",
        (email, accounts.hash_password("correct horse battery staple"), status, now, now),
    )
    row = conn.execute("select account_id from merchant_accounts where email = ?", (email,)).fetchone()
    return int(row["account_id"])


class SuspendedSessionFailClosedTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.conn = open_connection(Path(self.tmp.name) / "catalog.sqlite")
        self.addCleanup(self.conn.close)

    def test_suspending_an_account_invalidates_existing_sessions(self) -> None:
        account_id = _create_account(self.conn, "blocked@acme.example")
        session_token = accounts.create_session(self.conn, account_id)
        self.conn.commit()
        self.assertIsNotNone(accounts.resolve_session(self.conn, session_token))

        self.conn.execute(
            "update merchant_accounts set status = ? where account_id = ?",
            ("suspended", account_id),
        )
        self.conn.commit()

        # 审查 P2-1：此前 resolve_session 不看 status，被封账号的现有 cookie 在
        # 7 天有效期内继续可用（仍能发布/撤回资料、建 agent、申 token）。
        self.assertIsNone(accounts.resolve_session(self.conn, session_token))
        remaining = self.conn.execute(
            "select count(*) from account_sessions where account_id = ?", (account_id,)
        ).fetchone()[0]
        self.assertEqual(remaining, 0, "封禁必须删除该账号的存量会话")

    def test_reactivated_account_requires_a_fresh_login(self) -> None:
        account_id = _create_account(self.conn, "back@acme.example")
        session_token = accounts.create_session(self.conn, account_id)
        self.conn.commit()
        self.conn.execute(
            "update merchant_accounts set status = ? where account_id = ?",
            ("suspended", account_id),
        )
        self.conn.commit()
        self.conn.execute(
            "update merchant_accounts set status = ? where account_id = ?",
            ("active", account_id),
        )
        self.conn.commit()
        # Suspended sessions are revoked even if unused during the suspension.
        self.assertIsNone(accounts.resolve_session(self.conn, session_token))
        self.assertIsNotNone(accounts.authenticate(self.conn, "back@acme.example", "correct horse battery staple"))


class PublicationSearchReadBudgetTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db_path = Path(self.tmp.name) / "catalog.sqlite"
        conn = open_connection(self.db_path)
        conn.close()

    def test_anonymous_search_is_rate_limited_per_client_ip(self) -> None:
        with mock.patch.dict(os.environ, {"KIWI_CATALOG_PUBLIC_READ_RATE_LIMIT_PER_MINUTE": "1"}):
            # 审查 P2-9：该端点匿名可达且写 3 张统计表，此前没有匿名读限流。
            self.assertTrue(
                merchant_publications.search_publications(
                    self.db_path, {"q": "one"}, {"_client_ip": "198.51.100.1"}
                )["ok"]
            )
            with self.assertRaises(RateLimitError):
                merchant_publications.search_publications(
                    self.db_path, {"q": "two"}, {"_client_ip": "198.51.100.1"}
                )
            # 不同 IP 仍有独立预算（per-IP 分桶，不是全站单桶）。
            self.assertTrue(
                merchant_publications.search_publications(
                    self.db_path, {"q": "two"}, {"_client_ip": "198.51.100.2"}
                )["ok"]
            )


if __name__ == "__main__":
    unittest.main()
