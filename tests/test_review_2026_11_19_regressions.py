"""Regression coverage for the remaining catalog review findings."""

import ipaddress
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

import pytest

from kiwi_catalog.api import auth
from kiwi_catalog.api.app import create_catalog_app, handle_request
from kiwi_catalog.api.handlers.agent_catalog import _catalog_write_rate_limit_per_minute
from kiwi_catalog.core.errors import AuthError, ConflictError, ValidationError
from kiwi_catalog.db.session import db_session, now_iso, open_connection
from kiwi_catalog.discovery.fetcher import _is_blocked_ip
from kiwi_catalog.services import accounts, merchant_tokens
from kiwi_catalog.services.agent_verification import VerificationQueue
from kiwi_catalog.services.buyer_bootstrap import rate_limit_per_minute
from kiwi_catalog.services.merchant_public_events import emit_public_event
from kiwi_catalog.services.merchant_publications import validate_shop_url
from kiwi_catalog.services.verification_queue import list_verification_fences, reconcile_verification_unknown
from kiwi_catalog.services.verification_queue_ledger import insert_pending_task, mark_task_running


def test_two_approvals_issue_only_one_credential(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KIWI_CATALOG_OWNER_TOKEN_SECRET", "fixture-only-merchant-keys-for-review")
    db = tmp_path / "catalog.sqlite"
    with db_session(db) as conn:
        application_id = conn.execute(
            "insert into merchant_applications(domain, agent_name, contact_email, created_at)"
            " values ('shop.example', 'Shop', 'billing@example.test', ?)",
            (now_iso(),),
        ).lastrowid
    assert application_id is not None
    start = threading.Barrier(2, timeout=5)

    def approve() -> str:
        try:
            with db_session(db) as conn:
                start.wait()
                return merchant_tokens.approve_application(conn, application_id)["merchant_id"]
        except ConflictError:
            return ""

    with ThreadPoolExecutor(2) as pool:
        outcomes = list(pool.map(lambda _index: approve(), range(2)))
    assert outcomes.count("") == 1
    with db_session(db) as conn:
        assert conn.execute("select count(*) from merchant_tokens where status='active'").fetchone()[0] == 1
        assert conn.execute("select count(*) from merchants").fetchone()[0] == 1


def test_concurrent_merchant_id_backfills_return_authoritative_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = tmp_path / "catalog.sqlite"
    with db_session(db) as conn:
        account_id = conn.execute(
            "insert into merchant_accounts(email, password_hash, created_at, updated_at)"
            " values ('legacy@example.test', 'unused', ?, ?)",
            (now_iso(), now_iso()),
        ).lastrowid
    assert account_id is not None
    start = threading.Barrier(2, timeout=5)
    generate = merchant_tokens.new_platform_merchant_id

    def allocate(name: str) -> str:
        start.wait()
        return generate(name)

    monkeypatch.setattr(merchant_tokens, "new_platform_merchant_id", allocate)

    def assign(_index: int) -> str:
        with db_session(db) as conn:
            return accounts.ensure_merchant_id(conn, account_id)

    with ThreadPoolExecutor(2) as pool:
        identities = list(pool.map(assign, range(2)))
    assert identities[0] == identities[1] != ""
    with db_session(db) as conn:
        assert conn.execute("select count(*) from merchants").fetchone()[0] == 1


def test_events_allocate_unique_versions_in_concurrent_transactions(tmp_path: Path) -> None:
    db = tmp_path / "catalog.sqlite"
    with closing(open_connection(db)):
        pass
    start = threading.Barrier(2, timeout=5)

    def publish(_index: int) -> dict:
        with db_session(db) as conn:
            start.wait()
            return emit_public_event(
                conn, merchant_id="example-merchant", publication_id="",
                event_type="service_notice", payload={},
            )

    with ThreadPoolExecutor(2) as pool:
        events = sorted(pool.map(publish, range(2)), key=lambda event: event["version"])
    assert [event["version"] for event in events] == [1, 2]
    assert events[0]["created_at"] < events[1]["created_at"]


def test_db_open_reports_incomplete_schema_at_the_current_version(tmp_path: Path) -> None:
    db = tmp_path / "catalog.sqlite"
    with db_session(db) as conn:
        conn.execute("drop table commerce_receipts")
    with pytest.raises(RuntimeError, match="incomplete.*commerce_receipts"):
        open_connection(db)


def test_queue_does_not_create_db_and_held_owner_blocks_a_second_scheduler(tmp_path: Path) -> None:
    db = tmp_path / "catalog.sqlite"
    with pytest.raises(RuntimeError, match="existing migrated"):
        VerificationQueue(service_factory=lambda: None, db_path=db)
    assert list(tmp_path.iterdir()) == []
    with closing(open_connection(db)):
        pass
    with VerificationQueue(service_factory=lambda: None, db_path=db) as worker:
        assert worker._db_conn.execute("pragma foreign_keys").fetchone()[0] == 1
        with pytest.raises(ConflictError, match="already owns"):
            VerificationQueue(service_factory=lambda: None, db_path=db)
    with VerificationQueue(service_factory=lambda: None, db_path=db):
        pass


def test_offline_queue_resolves_a_run_interrupted_before_marker_persistence(tmp_path: Path) -> None:
    db = tmp_path / "catalog.sqlite"
    with db_session(db) as conn:
        insert_pending_task(
            conn, task_id="task-1", catalog_agent_id="agent-1", kind="verify",
            actor="fixture", enqueued_at=1, created_at=now_iso(), updated_at=now_iso(),
        )
        assert mark_task_running(conn, task_id="task-1", started_at=2, updated_at=now_iso())
    with db_session(db) as conn:
        assert [row["task_id"] for row in list_verification_fences(conn, db)] == ["task-1"]
    assert reconcile_verification_unknown(db, "task-1", outcome="discarded")["status"] == "failed"


def test_admin_digest_read_failure_rejects_bootstrap_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KIWI_CATALOG_ADMIN_TOKEN", "fixture-admin-token")
    conn = sqlite3.connect(":memory:")
    conn.close()
    assert auth.effective_admin_digest(conn) == ""
    with pytest.raises(AuthError):
        auth.require_admin_token({"_auth_token": "fixture-admin-token"}, conn)


@pytest.mark.parametrize("setting", ["0", "-1", "invalid"])
def test_bad_rate_limit_configuration_uses_a_bounded_default(
    setting: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert rate_limit_per_minute(setting, default=60, maximum=100) == 60
    monkeypatch.setenv("KIWI_CATALOG_WRITE_RATE_LIMIT_PER_MINUTE", setting)
    assert _catalog_write_rate_limit_per_minute() == 60


def test_weak_owner_secret_prevents_service_start(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KIWI_CATALOG_OWNER_TOKEN_SECRET", "short")
    with pytest.raises(RuntimeError, match="at least 24 characters"):
        create_catalog_app(tmp_path / "catalog.sqlite")


def test_unknown_route_takes_precedence_over_facade_payload_size(tmp_path: Path) -> None:
    assert handle_request(
        tmp_path / "catalog.sqlite", "POST", "/unregistered", {"large": "x" * 1_048_577},
    )[0] == 404


def test_reserved_address_groups_and_noncanonical_shop_hosts_are_rejected() -> None:
    assert _is_blocked_ip(ipaddress.ip_address("224.0.0.1"))
    assert _is_blocked_ip(ipaddress.ip_address("192.0.0.9"))
    with pytest.raises(ValidationError, match="canonical IP"):
        validate_shop_url("https://134744072/")
    assert validate_shop_url("https://shop.example/listing") == "https://shop.example/listing"
