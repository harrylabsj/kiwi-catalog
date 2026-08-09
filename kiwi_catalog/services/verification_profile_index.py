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

"""Pure profile-index data shaping for the §6 verification ladder.

Extracted from ``agent_verification.py`` (T8/T9 hotspot convergence): the
§5.3 / §5.4 / §5.2 profile-index rows derived from the validated profile pair.
Given the validated ``AgentCardResult`` / ``UcpProfileResult`` and the
``urls`` mapping, the leaf computes the merged capabilities/skills lists and
the two profile-endpoint rows that ``VerificationService._index_profiles``
persists through ``replace_capabilities`` / ``replace_skills`` /
``upsert_profile_endpoints``.

The leaf is side-effect free by construction — it never opens a SQLite
connection, never commits a transaction, never takes a lock, never drives a
state machine, and never performs network I/O.  ``agent_verification.py``
(the facade) keeps the three persistence calls in their original order and
passes the returned rows straight through, so the merged content, ordering,
duplicate rows, protocol versions and preference values are byte-for-byte
identical to the pre-extraction code.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from kiwi_catalog.discovery.agent_card import AgentCardResult
from kiwi_catalog.discovery.ucp import UcpProfileResult


@dataclass(frozen=True)
class ProfileIndex:
    """§5.3 / §5.4 / §5.2 index rows derived from both validated profiles.

    ``capabilities`` / ``skills`` are the card-then-ucp merged lists: fresh
    lists referencing the same row dicts as the parser results, duplicates
    preserved (never deduplicated), card rows first then ucp rows.
    ``endpoints`` holds the two profile-endpoint rows, agent_card first then
    ucp_profile, with the pinned a2a/ucp protocols, the profiles' own
    declared version strings and ``preference`` 1.
    """

    capabilities: list[dict[str, Any]]
    skills: list[dict[str, Any]]
    endpoints: list[dict[str, Any]]


def build_profile_index(
    card: AgentCardResult,
    ucp: UcpProfileResult,
    urls: dict[str, str],
) -> ProfileIndex:
    """Shape the profile-index rows for ``VerificationService._index_profiles``.

    Mirrors the pre-extraction ``_index_profiles`` data construction exactly:
    card capabilities/skills come first, then ucp; the two endpoint rows carry
    the pinned ``protocol`` values (a2a / ucp), the profiles' own version
    strings and ``preference`` 1.
    """
    capabilities = list(card.capabilities) + list(ucp.capabilities)
    skills = list(card.skills) + list(ucp.skills)
    endpoints = [
        {
            "kind": "agent_card",
            "url": urls["agent_card"],
            "protocol": "a2a",
            "protocol_version": card.version,
            "preference": 1,
        },
        {
            "kind": "ucp_profile",
            "url": urls["ucp_profile"],
            "protocol": "ucp",
            "protocol_version": ucp.specification_version,
            "preference": 1,
        },
    ]
    return ProfileIndex(capabilities=capabilities, skills=skills, endpoints=endpoints)


__all__ = [
    "ProfileIndex",
    "build_profile_index",
]
