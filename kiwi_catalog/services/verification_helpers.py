"""Pure helpers extracted from the verification pipeline."""

from __future__ import annotations

from datetime import UTC, datetime

from kiwi_catalog.agent_catalog.state_domains import REJECTED, STALE, UNREACHABLE


def outcome_for(target_status: str) -> str:
    """Map a terminal verification state to its persisted stage outcome."""
    return {
        REJECTED: "rejected",
        UNREACHABLE: "unreachable",
        STALE: "stale",
    }.get(target_status, "failed")


def iso_from_epoch(timestamp: float) -> str:
    """Format epoch seconds as the pipeline's second-precision UTC timestamp."""
    return datetime.fromtimestamp(timestamp, tz=UTC).replace(microsecond=0).isoformat()
