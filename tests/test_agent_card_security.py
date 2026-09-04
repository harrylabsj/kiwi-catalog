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

"""Agent Card ``security`` shape tests.

Covers the A2A Agent Card v1.0 array form (``security: [{scheme}]`` + a
``securitySchemes`` mapping) added for merchant runtime 0.8.0 cards, alongside
the legacy dict form (``security.authentication.schemes``).
"""

from __future__ import annotations

from typing import Any

import pytest

from kiwi_catalog.discovery.agent_card import AgentCardParser
from kiwi_catalog.discovery._validation import ProfileValidationError

SOURCE_URL = "https://veyquo.example/.well-known/agent-card.json"


def _card(**overrides: Any) -> dict[str, Any]:
    card: dict[str, Any] = {
        "name": "Test Merchant",
        "version": "1.0.0",
        "url": SOURCE_URL,
        "description": "merchant under test",
    }
    card.update(overrides)
    return card


def test_security_array_with_schemes_reference_passes() -> None:
    card = _card(
        security=[{"scheme": "kiwi-signature"}],
        securitySchemes={
            "kiwi-signature": {
                "type": "kiwi-http-message-signature",
                "keyid": "https://veyquo.example",
            }
        },
    )
    result = AgentCardParser().parse(card, source_url=SOURCE_URL)
    assert result.name == "Test Merchant"


def test_security_array_without_schemes_mapping_passes() -> None:
    # A2A v1.0 requires a securitySchemes entry, but the parser stays lenient
    # when the mapping is absent; only a dangling reference is rejected.
    card = _card(security=[{"scheme": "none"}])
    result = AgentCardParser().parse(card, source_url=SOURCE_URL)
    assert result.name == "Test Merchant"


def test_security_array_unknown_scheme_rejected() -> None:
    card = _card(
        security=[{"scheme": "no-such-scheme"}],
        securitySchemes={"kiwi-signature": {"type": "kiwi-http-message-signature"}},
    )
    with pytest.raises(ProfileValidationError, match="unknown scheme"):
        AgentCardParser().parse(card, source_url=SOURCE_URL)


def test_security_array_non_object_entry_rejected() -> None:
    card = _card(security=["kiwi-signature"])
    with pytest.raises(ProfileValidationError, match="security\\[0\\]"):
        AgentCardParser().parse(card, source_url=SOURCE_URL)


def test_legacy_security_object_still_passes() -> None:
    card = _card(
        security={
            "authentication": {
                "schemes": ["bearer"],
                "credentials": "https://veyquo.example/token",
            }
        }
    )
    result = AgentCardParser().parse(card, source_url=SOURCE_URL)
    assert result.name == "Test Merchant"
