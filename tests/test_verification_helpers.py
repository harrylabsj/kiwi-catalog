from datetime import UTC, datetime

from kiwi_catalog.agent_catalog.state_domains import REJECTED, STALE, UNREACHABLE
from kiwi_catalog.services.verification_helpers import iso_from_epoch, outcome_for


def test_outcome_for_preserves_verification_state_mapping() -> None:
    assert outcome_for(REJECTED) == "rejected"
    assert outcome_for(UNREACHABLE) == "unreachable"
    assert outcome_for(STALE) == "stale"
    assert outcome_for("unknown") == "failed"


def test_iso_from_epoch_uses_second_precision_utc() -> None:
    timestamp = datetime(2026, 8, 9, 4, 5, 6, 987654, tzinfo=UTC).timestamp()
    assert iso_from_epoch(timestamp) == "2026-08-09T04:05:06+00:00"
