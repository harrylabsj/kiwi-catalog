from kiwi_catalog.agent_catalog.pagination import (
    agent_cursor_predicate,
    agent_status_rank,
    decode_agent_cursor,
    encode_agent_cursor,
)


def test_agent_cursor_round_trip_preserves_v2_sort_keys() -> None:
    cursor = encode_agent_cursor(3, "2026-08-09T00:00:00+00:00", "Acme", "cagt_1")
    assert decode_agent_cursor(cursor) == ([3, "2026-08-09T00:00:00+00:00", "Acme", "cagt_1"], True)


def test_agent_cursor_keeps_legacy_cursor_compatibility() -> None:
    assert decode_agent_cursor("cagt_legacy") == (["cagt_legacy"], False)
    predicate, params = agent_cursor_predicate("cagt_legacy")
    assert predicate == "ca.catalog_agent_id > ?"
    assert params == ["cagt_legacy"]


def test_agent_status_rank_unknown_is_last() -> None:
    assert agent_status_rank("commerce_verified") == 0
    assert agent_status_rank("unknown") == 9
