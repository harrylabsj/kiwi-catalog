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

"""Characterization tests for the extracted verification profile-index leaf
(T8/T9 split of ``agent_verification.py``).

These tests lock the pure §5.3 / §5.4 / §5.2 profile-index row shaping that
previously lived in ``VerificationService._index_profiles``: the merged
card-then-ucp capabilities/skills lists and the two profile-endpoint rows.
The leaf is side-effect free by construction; the facade delegation tests
prove ``_index_profiles`` still persists the identical rows through
``replace_capabilities`` / ``replace_skills`` / ``upsert_profile_endpoints``
in the original order with byte-for-byte equivalent arguments.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from dataclasses import FrozenInstanceError
from typing import Any

import pytest

from kiwi_catalog.agent_catalog.sqlite_repository import _insert_catalog_agent
from kiwi_catalog.db.migrations import (
    migration_001_agent_catalog,
    migration_008_three_state_domains,
    migration_009_shadow_tables,
)
from kiwi_catalog.discovery.agent_card import AgentCardResult
from kiwi_catalog.discovery.ucp import UcpProfileResult
from kiwi_catalog.services import verification_profile_index
from kiwi_catalog.services.verification_profile_index import (
    ProfileIndex,
    build_profile_index,
)


def _card(
    *,
    version: str = "1.0.0",
    capabilities: tuple[dict[str, Any], ...] = (),
    skills: tuple[dict[str, Any], ...] = (),
) -> AgentCardResult:
    return AgentCardResult(version=version, capabilities=capabilities, skills=skills)


def _ucp(
    *,
    specification_version: str = "2026-04-08",
    capabilities: tuple[dict[str, Any], ...] = (),
    skills: tuple[dict[str, Any], ...] = (),
) -> UcpProfileResult:
    return UcpProfileResult(
        specification_version=specification_version,
        capabilities=capabilities,
        skills=skills,
    )


def _urls() -> dict[str, str]:
    return {
        "agent_card": "https://acme.example/.well-known/agent-card.json",
        "ucp_profile": "https://acme.example/.well-known/ucp",
    }


# ── build_profile_index: field mapping ───────────────────────────────────────


def test_build_profile_index_merges_capabilities_and_skills_card_first() -> None:
    """Card rows come before ucp rows regardless of their natural sort order."""
    card = _card(
        capabilities=({"capability_id": "c1", "namespace": "beta"},),
        skills=({"skill_id": "s1", "name": "Card skill"},),
    )
    ucp = _ucp(
        capabilities=({"capability_id": "c2", "namespace": "alpha"},),
        skills=({"skill_id": "s2", "name": "UCP skill"},),
    )
    index = build_profile_index(card, ucp, _urls())
    assert index.capabilities == [
        {"capability_id": "c1", "namespace": "beta"},
        {"capability_id": "c2", "namespace": "alpha"},
    ]
    assert index.skills == [
        {"skill_id": "s1", "name": "Card skill"},
        {"skill_id": "s2", "name": "UCP skill"},
    ]


def test_build_profile_index_endpoint_rows_map_profiles_and_urls() -> None:
    """The two endpoint rows pin a2a/ucp protocols, the profiles' own version
    strings, the urls, and preference 1 — agent_card first."""
    index = build_profile_index(_card(version="1.1.0"), _ucp(specification_version="2026-06-01"), _urls())
    assert index.endpoints == [
        {
            "kind": "agent_card",
            "url": "https://acme.example/.well-known/agent-card.json",
            "protocol": "a2a",
            "protocol_version": "1.1.0",
            "preference": 1,
        },
        {
            "kind": "ucp_profile",
            "url": "https://acme.example/.well-known/ucp",
            "protocol": "ucp",
            "protocol_version": "2026-06-01",
            "preference": 1,
        },
    ]


# ── build_profile_index: empty lists ─────────────────────────────────────────


def test_build_profile_index_empty_profiles_yield_empty_merged_lists() -> None:
    """Empty capability/skill tuples produce empty merged lists, but the two
    profile-endpoint rows are still emitted (the endpoints always exist)."""
    index = build_profile_index(_card(), _ucp(), _urls())
    assert index.capabilities == []
    assert index.skills == []
    assert [ep["kind"] for ep in index.endpoints] == ["agent_card", "ucp_profile"]
    assert len(index.endpoints) == 2


def test_build_profile_index_empty_one_side_keeps_the_other_rows() -> None:
    index = build_profile_index(
        _card(capabilities=({"capability_id": "c1"},), skills=()),
        _ucp(capabilities=(), skills=({"skill_id": "s2", "name": "UCP skill"},)),
        _urls(),
    )
    assert index.capabilities == [{"capability_id": "c1"}]
    assert index.skills == [{"skill_id": "s2", "name": "UCP skill"}]


# ── build_profile_index: duplicates ──────────────────────────────────────────


def test_build_profile_index_preserves_duplicate_rows() -> None:
    """Duplicate rows are never deduplicated — the merged list keeps every
    occurrence, card and ucp contributions in order."""
    shared_cap = {"capability_id": "dup", "namespace": "shared"}
    shared_skill = {"skill_id": "dup", "name": "Dup"}
    card = _card(capabilities=(shared_cap, shared_cap), skills=(shared_skill,))
    ucp = _ucp(capabilities=(shared_cap,), skills=(shared_skill, shared_skill))
    index = build_profile_index(card, ucp, _urls())
    assert index.capabilities == [shared_cap, shared_cap, shared_cap]
    assert index.skills == [shared_skill, shared_skill, shared_skill]


# ── build_profile_index: input immutability ──────────────────────────────────


def test_build_profile_index_does_not_mutate_inputs() -> None:
    """The leaf never mutates the profile results or the urls mapping, and the
    returned lists are fresh containers (mutating them leaves inputs intact)."""
    card_caps = ({"capability_id": "c1", "namespace": "a2a"},)
    card_skills = ({"skill_id": "s1", "name": "Card skill"},)
    ucp_caps = ({"capability_id": "c2", "namespace": "ucp"},)
    ucp_skills = ({"skill_id": "s2", "name": "UCP skill"},)
    urls = _urls()
    card = _card(capabilities=card_caps, skills=card_skills)
    ucp = _ucp(capabilities=ucp_caps, skills=ucp_skills)

    index = build_profile_index(card, ucp, urls)

    assert card.capabilities == card_caps
    assert card.skills == card_skills
    assert card.version == "1.0.0"
    assert ucp.capabilities == ucp_caps
    assert ucp.skills == ucp_skills
    assert ucp.specification_version == "2026-04-08"
    assert urls == _urls()

    # The returned lists are fresh containers, not views into the inputs.
    index.capabilities.clear()
    index.skills.clear()
    index.endpoints.clear()
    assert card.capabilities == card_caps
    assert card.skills == card_skills
    assert ucp.capabilities == ucp_caps
    assert ucp.skills == ucp_skills
    assert urls == _urls()


# ── Data shapes / module surface ─────────────────────────────────────────────


def test_profile_index_type_is_frozen() -> None:
    index = ProfileIndex(capabilities=[], skills=[], endpoints=[])
    with pytest.raises(FrozenInstanceError):
        index.capabilities = ["x"]  # type: ignore[misc]


def test_profile_index_module_exports_only_policy_surface() -> None:
    assert set(verification_profile_index.__all__) == {
        "ProfileIndex",
        "build_profile_index",
    }


def test_profile_index_names_reexported_from_agent_verification() -> None:
    from kiwi_catalog.services import agent_verification

    assert agent_verification._build_profile_index is build_profile_index
    assert agent_verification._ProfileIndex is ProfileIndex


# ── Facade delegation: VerificationService._index_profiles ───────────────────


@pytest.fixture
def conn() -> Iterator[sqlite3.Connection]:
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    migration_001_agent_catalog(c)
    # _seed_agent writes the three-domain columns (migration_008) and the
    # facade flow touches no audit tables, but 009 keeps the fixture aligned
    # with the other verification facade tests.
    migration_008_three_state_domains(c)
    migration_009_shadow_tables(c)
    c.commit()
    yield c
    c.close()


def _seed_agent(conn: sqlite3.Connection) -> None:
    _insert_catalog_agent(
        conn,
        "cagt_x",
        merchant_id="",
        hosted_runtime_agent_id="",
        display_name="Acme",
        provider_name="Acme Inc",
        canonical_domain="acme.example",
        agent_type="merchant",
        source_type="self_registered",
        lifecycle_status="active",
        verification_status="discovered",
        hosting_mode="hosted",
    )
    conn.commit()


def test_facade_index_profiles_persists_merged_rows(conn) -> None:
    from kiwi_catalog.services.agent_verification import VerificationService

    _seed_agent(conn)
    card = _card(
        version="1.0.0",
        capabilities=({"capability_id": "c1", "namespace": "a2a"},),
        skills=({"skill_id": "s1", "name": "Card skill"},),
    )
    ucp = _ucp(
        specification_version="2026-04-08",
        capabilities=({"capability_id": "c2", "namespace": "ucp"},),
        skills=({"skill_id": "s2", "name": "UCP skill"},),
    )
    VerificationService(conn)._index_profiles("cagt_x", card, ucp, _urls())

    caps = conn.execute(
        """
        select namespace, capability_id
        from agent_capabilities where catalog_agent_id = 'cagt_x'
        order by namespace, capability_id
        """
    ).fetchall()
    assert [(r["namespace"], r["capability_id"]) for r in caps] == [
        ("a2a", "c1"),
        ("ucp", "c2"),
    ]

    skills = conn.execute(
        """
        select skill_id, name
        from agent_skills where catalog_agent_id = 'cagt_x'
        order by skill_id
        """
    ).fetchall()
    assert [(r["skill_id"], r["name"]) for r in skills] == [
        ("s1", "Card skill"),
        ("s2", "UCP skill"),
    ]

    endpoints = conn.execute(
        """
        select kind, url, protocol, protocol_version, preference
        from agent_endpoints where catalog_agent_id = 'cagt_x'
        order by kind
        """
    ).fetchall()
    assert [
        (r["kind"], r["url"], r["protocol"], r["protocol_version"], r["preference"])
        for r in endpoints
    ] == [
        (
            "agent_card",
            "https://acme.example/.well-known/agent-card.json",
            "a2a",
            "1.0.0",
            1,
        ),
        (
            "ucp_profile",
            "https://acme.example/.well-known/ucp",
            "ucp",
            "2026-04-08",
            1,
        ),
    ]


def test_facade_index_profiles_calls_persistence_in_original_order(
    conn, monkeypatch
) -> None:
    """The facade still drives replace_capabilities → replace_skills →
    upsert_profile_endpoints in order, passing the leaf rows straight through."""
    from kiwi_catalog.services import agent_verification
    from kiwi_catalog.services.agent_verification import VerificationService

    _seed_agent(conn)
    card = _card(
        version="1.0.0",
        capabilities=({"capability_id": "c1", "namespace": "a2a"},),
        skills=({"skill_id": "s1", "name": "Card skill"},),
    )
    ucp = _ucp(
        specification_version="2026-04-08",
        capabilities=({"capability_id": "c2", "namespace": "ucp"},),
        skills=({"skill_id": "s2", "name": "UCP skill"},),
    )

    calls: list[str] = []
    captured: dict[str, Any] = {}

    real_replace_capabilities = agent_verification.replace_capabilities
    real_replace_skills = agent_verification.replace_skills
    real_upsert_profile_endpoints = agent_verification.upsert_profile_endpoints

    def fake_replace_capabilities(conn_: sqlite3.Connection, agent_id: str, capabilities: list[dict[str, Any]]) -> None:
        calls.append("replace_capabilities")
        captured["capabilities"] = capabilities
        real_replace_capabilities(conn_, agent_id, capabilities)

    def fake_replace_skills(conn_: sqlite3.Connection, agent_id: str, skills: list[dict[str, Any]]) -> None:
        calls.append("replace_skills")
        captured["skills"] = skills
        real_replace_skills(conn_, agent_id, skills)

    def fake_upsert_profile_endpoints(conn_: sqlite3.Connection, agent_id: str, endpoints: list[dict[str, Any]]) -> None:
        calls.append("upsert_profile_endpoints")
        captured["endpoints"] = endpoints
        real_upsert_profile_endpoints(conn_, agent_id, endpoints)

    monkeypatch.setattr(agent_verification, "replace_capabilities", fake_replace_capabilities)
    monkeypatch.setattr(agent_verification, "replace_skills", fake_replace_skills)
    monkeypatch.setattr(agent_verification, "upsert_profile_endpoints", fake_upsert_profile_endpoints)

    VerificationService(conn)._index_profiles("cagt_x", card, ucp, _urls())

    assert calls == ["replace_capabilities", "replace_skills", "upsert_profile_endpoints"]
    # Byte-for-byte equivalent arguments, as the pre-extraction code produced.
    assert captured["capabilities"] == [
        {"capability_id": "c1", "namespace": "a2a"},
        {"capability_id": "c2", "namespace": "ucp"},
    ]
    assert captured["skills"] == [
        {"skill_id": "s1", "name": "Card skill"},
        {"skill_id": "s2", "name": "UCP skill"},
    ]
    assert captured["endpoints"] == [
        {
            "kind": "agent_card",
            "url": "https://acme.example/.well-known/agent-card.json",
            "protocol": "a2a",
            "protocol_version": "1.0.0",
            "preference": 1,
        },
        {
            "kind": "ucp_profile",
            "url": "https://acme.example/.well-known/ucp",
            "protocol": "ucp",
            "protocol_version": "2026-04-08",
            "preference": 1,
        },
    ]
