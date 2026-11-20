"""Regression coverage for the follow-up review of the local candidate."""

from contextlib import closing
from pathlib import Path
import errno
import socket
import threading

import pytest

from kiwi_catalog.api.extensions import ExtensionRegistry
from kiwi_catalog.core.errors import ConflictError
from kiwi_catalog.db import schema_integrity
from kiwi_catalog.db.session import open_connection
from kiwi_catalog.discovery import _bounded_dns as dns
from kiwi_catalog.services import accounts, merchant_tokens, verification_queue_ownership


def test_dns_reuses_only_unexpired_successful_results(monkeypatch):
    now = [10.0]
    calls = []

    def query(hostname, port):
        calls.append((hostname, port))
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.10", port))]

    monkeypatch.setattr(dns.time, "monotonic", lambda: now[0])
    monkeypatch.setattr(dns, "_query_system_resolver", query)
    with dns._CACHE_LOCK:
        dns._CACHE.clear()
    try:
        assert dns.lookup_address_infos("cached.example.test", 443)
        assert dns.lookup_address_infos("CACHED.example.test", 443)
        assert dns.lookup_address_infos("cached.example.test", 8443)
        assert len(calls) == 2
        now[0] += dns._CACHE_TTL_SECONDS
        assert dns.lookup_address_infos("cached.example.test", 443)
        assert len(calls) == 3
    finally:
        with dns._CACHE_LOCK:
            dns._CACHE.clear()


def test_dns_without_an_executable_produces_native_results(monkeypatch):
    record = dns.socket.getaddrinfo("127.0.0.1", 443, proto=socket.IPPROTO_TCP)
    monkeypatch.setattr(dns.sys, "executable", "")
    assert dns._query_system_resolver("127.0.0.1", 443) == record


def test_wedged_dns_fallback_does_not_admit_more_native_threads(monkeypatch):
    release = threading.Event()
    calls = []
    slot = threading.BoundedSemaphore(1)

    def native(hostname, *_args, **_kwargs):
        calls.append(hostname)
        release.wait(2)
        return []

    monkeypatch.setattr(dns, "_FALLBACK_SLOT", slot)
    monkeypatch.setattr(dns.socket, "getaddrinfo", native)
    monkeypatch.setattr(dns, "DNS_LOOKUP_TIMEOUT_SECONDS", .05)
    try:
        with pytest.raises(TimeoutError):
            dns._resolve_without_child("blocked.example.test", 443)
        with pytest.raises(TimeoutError, match="busy"):
            dns._resolve_without_child("next.example.test", 443)
        assert calls == ["blocked.example.test"]
    finally:
        release.set()
        assert slot.acquire(timeout=2)
        slot.release()


def test_shared_routes_reject_converters_at_declaration():
    registry = ExtensionRegistry()
    with pytest.raises(ValueError, match="converters require a FastAPI hook"):
        registry.add_route({"GET"}, "/example/{id:int}", lambda *_args: {})
    assert registry.routes == []


def test_current_schema_detects_missing_bootstrap_only_index(tmp_path, monkeypatch):
    with closing(open_connection(tmp_path / "schema.sqlite")) as conn:
        extra = "create index fixture_snapshot_only on account_sessions(account_id, expires_at)"
        monkeypatch.setattr(schema_integrity, "SCHEMA", [*schema_integrity.SCHEMA, extra])
        schema_integrity._expected_schema.cache_clear()
        try:
            with pytest.raises(RuntimeError, match="missing index fixture_snapshot_only"):
                schema_integrity.assert_catalog_schema(conn, 59)
        finally:
            schema_integrity._expected_schema.cache_clear()


def _pending_application(conn) -> int:
    value = conn.execute(
        "insert into merchant_applications(domain, agent_name, contact_email, created_at)"
        " values ('shop.example.test', 'Fixture', 'ops@example.test', '2026-11-20T00:00:00+00:00')"
    ).lastrowid
    assert value is not None
    return value


def test_unreserved_application_does_not_issue_a_token(tmp_path, monkeypatch):
    with closing(open_connection(tmp_path / "approval.sqlite")) as conn:
        app_id = _pending_application(conn)
        conn.execute(
            "create trigger fixture_reject_claim before update on merchant_applications "
            "begin select raise(ignore); end"
        )

        def unexpected_token():
            pytest.fail("reservation failed before issuance")

        monkeypatch.setattr(merchant_tokens, "generate_merchant_token", unexpected_token)
        with pytest.raises(ConflictError, match="no longer pending"):
            merchant_tokens.approve_application(conn, app_id)
        assert conn.execute("select count(*) from merchant_tokens").fetchone()[0] == 0
        assert conn.execute("select count(*) from merchants").fetchone()[0] == 0


def test_issuance_failure_restores_pending_and_preserves_outer_transaction(tmp_path, monkeypatch):
    with closing(open_connection(tmp_path / "approval.sqlite")) as conn:
        app_id = _pending_application(conn)

        def unavailable_encryption(_token):
            assert conn.execute("select status from merchant_applications").fetchone()[0] == "approved"
            raise ValueError("local encryption unavailable")

        monkeypatch.setattr(accounts, "encrypt_merchant_token", unavailable_encryption)
        with pytest.raises(ValueError, match="unavailable"):
            merchant_tokens.approve_application(conn, app_id)
        conn.commit()
        assert conn.execute("select status from merchant_applications").fetchone()[0] == "pending"
        assert conn.execute("select count(*) from merchant_tokens").fetchone()[0] == 0


def test_worker_lock_names_unwritable_sidecar(tmp_path, monkeypatch):
    def denied(*_args, **_kwargs):
        raise OSError(errno.EROFS, "fixture read-only file system")

    monkeypatch.setattr(verification_queue_ownership.os, "open", denied)
    with pytest.raises(RuntimeError, match=r"writable .*catalog\.sqlite\.verification-worker\.sqlite"):
        verification_queue_ownership.acquire_worker_lock(Path(tmp_path / "catalog.sqlite"))


def test_session_creation_reaps_at_most_500_expired_sessions(tmp_path):
    with closing(open_connection(tmp_path / "sessions.sqlite")) as conn:
        conn.executemany(
            "insert into account_sessions(session_token_hash, account_id, expires_at, created_at) values(?,1,?,?)",
            ((f"fixture-{index}", "2000-01-01T00:00:00+00:00", "1999-01-01T00:00:00+00:00")
             for index in range(502)),
        )
        assert accounts.create_session(conn, 1)
        assert conn.execute("select count(*) from account_sessions").fetchone()[0] == 3
