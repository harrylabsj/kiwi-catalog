# Copyright 2026 harrylabsj
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Characterization tests for the extracted verification profile-stage policy
(T8/T9 split of ``agent_verification.py``).

These tests lock the pure profile-stage shapes and the snapshot freshness /
304-reuse policy that previously lived in ``agent_verification.py`` — the
``ProfileFailure`` / ``Profiles`` / ``ReusedSnapshotFetch`` data shapes, the
ISO ``fresh_until`` parsing, and the §7.2 staleness gate — plus the re-export
surface that keeps the public facade unchanged.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from kiwi_catalog.agent_catalog.verification_evidence import insert_profile_snapshot
from kiwi_catalog.db.migrations import migration_001_agent_catalog
from kiwi_catalog.discovery.verifier import (
    AGENT_VERIFIED,
    COMMERCE_VERIFIED,
    DISCOVERED,
    DOMAIN_VERIFIED,
    PROFILE_VALID,
    REJECTED,
)
from kiwi_catalog.services import verification_profile_policy
from kiwi_catalog.services.verification_helpers import iso_from_epoch
from kiwi_catalog.services.verification_profile_policy import (
    LADDER_RUNGS,
    VERIFIED_RUNGS,
    ProfileFailure,
    Profiles,
    ReusedSnapshotFetch,
    parse_iso_ts,
    profile_is_stale,
)

# Fixed "now" used across the freshness tests: 2026-08-10T12:00:00Z.
NOW_TS = datetime(2026, 8, 10, 12, 0, 0, tzinfo=UTC).timestamp()


def _iso(timestamp: float) -> str:
    return iso_from_epoch(timestamp)


class _Fetch:
    """Minimal stand-in for the fetcher's FetchResult consumed by the 304
    reuse wrapper (the fields the wrapper copies and re-exposes)."""

    url = "https://acme.example/.well-known/agent-card.json"
    status_code = 200
    etag = '"abc"'
    last_modified = "2026-08-09T00:00:00+00:00"
    cache_control = "max-age=3600"
    max_age = 3600
    fetched_at = NOW_TS - 86400


@pytest.fixture
def conn() -> Iterator[sqlite3.Connection]:
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    migration_001_agent_catalog(c)
    c.commit()
    yield c
    c.close()


def _seed_snapshot(
    conn: sqlite3.Connection,
    *,
    profile_type: str = "agent_card",
    catalog_agent_id: str = "cagt_x",
    fresh_until: str = "2026-08-11T00:00:00+00:00",
) -> int:
    return insert_profile_snapshot(
        conn,
        catalog_agent_id=catalog_agent_id,
        profile_type=profile_type,
        source_url="https://acme.example/.well-known/agent-card.json",
        etag='"abc"',
        last_modified="2026-08-09T00:00:00+00:00",
        content_hash="sha256:deadbeef",
        raw_json='{"display_name":"Acme"}',
        fetched_at="2026-08-09T00:00:00+00:00",
        fresh_until=fresh_until,
        validation_status="valid",
    )


# ── parse_iso_ts ────────────────────────────────────────────────────────────


def test_parse_iso_ts_parses_aware_timestamp() -> None:
    assert parse_iso_ts("2026-08-09T04:05:06+00:00") == datetime(
        2026, 8, 9, 4, 5, 6, tzinfo=UTC
    ).timestamp()


def test_parse_iso_ts_treats_naive_timestamp_as_utc() -> None:
    assert parse_iso_ts("2026-08-09T04:05:06") == datetime(
        2026, 8, 9, 4, 5, 6, tzinfo=UTC
    ).timestamp()


def test_parse_iso_ts_returns_none_for_empty() -> None:
    assert parse_iso_ts("") is None


def test_parse_iso_ts_returns_none_for_invalid() -> None:
    assert parse_iso_ts("not-a-date") is None


def test_parse_iso_ts_round_trips_with_iso_from_epoch() -> None:
    """The staleness parser and the pipeline's formatter agree on the same
    second-precision UTC clock — cross-module lock with verification_helpers."""
    assert _iso(parse_iso_ts("2026-08-09T04:05:06+00:00")) == "2026-08-09T04:05:06+00:00"


# ── profile_is_stale (v0.3 §7.2 gate) ───────────────────────────────────────


def test_profile_is_stale_false_when_all_snapshots_fresh() -> None:
    future = _iso(NOW_TS + 3600)
    assert profile_is_stale([future, future], NOW_TS) is False


def test_profile_is_stale_true_when_any_snapshot_missing() -> None:
    future = _iso(NOW_TS + 3600)
    assert profile_is_stale(["", future], NOW_TS) is True
    assert profile_is_stale([future, ""], NOW_TS) is True


def test_profile_is_stale_true_when_any_snapshot_expired() -> None:
    future = _iso(NOW_TS + 3600)
    assert profile_is_stale([_iso(NOW_TS - 1), future], NOW_TS) is True


def test_profile_is_stale_true_at_expiry_boundary() -> None:
    """now == fresh_until counts as expired (now_ts >= parsed)."""
    assert profile_is_stale([_iso(NOW_TS), _iso(NOW_TS + 3600)], NOW_TS) is True


def test_profile_is_stale_true_for_unparseable_fresh_until() -> None:
    future = _iso(NOW_TS + 3600)
    assert profile_is_stale(["garbage", future], NOW_TS) is True


# ── ReusedSnapshotFetch (§18 304 reuse) ─────────────────────────────────────


def test_reused_snapshot_fetch_copies_fetch_fields_and_parses_json() -> None:
    reused = ReusedSnapshotFetch(_Fetch(), '{"display_name": "Acme"}')
    assert reused.url == _Fetch.url
    assert reused.status_code == _Fetch.status_code
    assert reused.etag == _Fetch.etag
    assert reused.last_modified == _Fetch.last_modified
    assert reused.cache_control == _Fetch.cache_control
    assert reused.max_age == _Fetch.max_age
    assert reused.fetched_at == _Fetch.fetched_at
    assert reused.parsed == {"display_name": "Acme"}


def test_reused_snapshot_fetch_is_not_modified_and_success() -> None:
    reused = ReusedSnapshotFetch(_Fetch(), "{}")
    assert reused.is_not_modified is True
    assert reused.is_success is True


def test_reused_snapshot_fetch_rejects_invalid_raw_json() -> None:
    with pytest.raises(ProfileFailure) as excinfo:
        ReusedSnapshotFetch(_Fetch(), "{not valid json")
    assert excinfo.value.target_status == REJECTED
    assert str(excinfo.value).startswith("stored snapshot raw_json is not valid JSON:")


# ── ProfileFailure / Profiles shapes ────────────────────────────────────────


def test_profile_failure_carries_target_status_and_reason() -> None:
    exc = ProfileFailure(REJECTED, "missing agent_card or ucp_profile endpoints")
    assert exc.target_status == REJECTED
    assert exc.reason == "missing agent_card or ucp_profile endpoints"
    assert str(exc) == "missing agent_card or ucp_profile endpoints"


class _Card:
    pass


class _Ucp:
    pass


def test_profiles_dataclass_holds_validated_pair() -> None:
    card, ucp = _Card(), _Ucp()
    profiles = Profiles(card=card, ucp=ucp, urls={"agent_card": "https://a", "ucp_profile": "https://u"}, snapshot_ids=(7, 8))
    assert profiles.card is card
    assert profiles.ucp is ucp
    assert profiles.urls == {"agent_card": "https://a", "ucp_profile": "https://u"}
    assert profiles.snapshot_ids == (7, 8)


# ── Rung classification constants ───────────────────────────────────────────


def test_ladder_rungs_are_the_persisted_rungs() -> None:
    assert LADDER_RUNGS == frozenset(
        {PROFILE_VALID, DOMAIN_VERIFIED, AGENT_VERIFIED, COMMERCE_VERIFIED}
    )
    assert DISCOVERED not in LADDER_RUNGS


def test_verified_rungs_are_the_funnel_rungs() -> None:
    assert VERIFIED_RUNGS == frozenset({DOMAIN_VERIFIED, AGENT_VERIFIED, COMMERCE_VERIFIED})
    assert PROFILE_VALID not in VERIFIED_RUNGS
    assert DISCOVERED not in VERIFIED_RUNGS


# ── Re-export / import surface preservation ─────────────────────────────────


def test_profile_policy_names_are_reexported_from_agent_verification() -> None:
    from kiwi_catalog.services import agent_verification

    assert agent_verification._ProfileFailure is ProfileFailure
    assert agent_verification._Profiles is Profiles
    assert agent_verification._ReusedSnapshotFetch is ReusedSnapshotFetch
    assert agent_verification._LADDER_RUNGS is LADDER_RUNGS
    assert agent_verification._VERIFIED_RUNGS is VERIFIED_RUNGS
    assert agent_verification._parse_iso_ts is parse_iso_ts
    assert agent_verification._profile_is_stale is profile_is_stale


def test_profile_policy_module_exports_only_policy_surface() -> None:
    assert set(verification_profile_policy.__all__) == {
        "LADDER_RUNGS",
        "VERIFIED_RUNGS",
        "ProfileFailure",
        "Profiles",
        "ReusedSnapshotFetch",
        "parse_iso_ts",
        "profile_is_stale",
    }


# ── Facade delegation: VerificationService._is_stale ────────────────────────


def test_facade_is_stale_delegates_to_profile_is_stale(conn) -> None:
    """The service keeps the DB read; the §7.2 decision is the leaf policy."""
    from kiwi_catalog.services.agent_verification import VerificationService

    service = VerificationService(conn, now=lambda: NOW_TS)

    # No snapshots → both kinds missing → stale.
    assert service._is_stale("cagt_x") is True

    # Future fresh_until on both required kinds → fresh.
    future = _iso(NOW_TS + 3600)
    _seed_snapshot(conn, profile_type="agent_card", fresh_until=future)
    _seed_snapshot(conn, profile_type="ucp", fresh_until=future)
    conn.commit()
    assert service._is_stale("cagt_x") is False

    # A newer expired agent_card snapshot (latest by snapshot_id) → stale again.
    _seed_snapshot(conn, profile_type="agent_card", fresh_until=_iso(NOW_TS - 1))
    conn.commit()
    assert service._is_stale("cagt_x") is True
