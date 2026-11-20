"""Pure helpers extracted from the verification pipeline."""

from __future__ import annotations

from kiwi_catalog.agent_catalog.state_domains import REJECTED, STALE, UNREACHABLE
from kiwi_catalog.db.session import iso_from_epoch as iso_from_epoch


def outcome_for(target_status: str) -> str:
    """Map a terminal verification state to its persisted stage outcome."""
    return {
        REJECTED: "rejected",
        UNREACHABLE: "unreachable",
        STALE: "stale",
    }.get(target_status, "failed")
