"""Hosted A2A publication — Agent Card and UCP Profile generation (v2.4-W1).

A read-only projection layer that derives protocol documents from existing
catalog / merchant state without introducing any write semantics.

Design: docs/shopping-cli-a2a-upgrade-design-v1.2.1.md §14, §18
Binding: docs/a2a/shopping-cli-a2a-binding-1.0-rc1.md §5–§6
"""

from kiwi_catalog.a2a.agent_card import build_hosted_agent_card
from kiwi_catalog.a2a.ucp_profile import build_hosted_ucp_profile

__all__ = ["build_hosted_agent_card", "build_hosted_ucp_profile"]
