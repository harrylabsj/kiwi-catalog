from kiwi_catalog.agent_catalog.pagination import (
    agent_cursor_predicate,
    agent_status_rank,
    decode_agent_cursor,
    encode_agent_cursor,
    paginate_agent_rows,
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


def test_paginate_agent_rows_projects_rows_and_encodes_cursor() -> None:
    rows = [
        {
            "verification_status": "commerce_verified",
            "last_verified_at": "2026-08-09T00:00:00+00:00",
            "display_name": "Acme",
            "catalog_agent_id": "cagt_1",
            "private_value": "hidden-by-caller",
        },
        {
            "verification_status": "agent_verified",
            "last_verified_at": "2026-08-08T00:00:00+00:00",
            "display_name": "Beta",
            "catalog_agent_id": "cagt_2",
        },
    ]

    projected, next_cursor = paginate_agent_rows(rows, 1)  # type: ignore[arg-type]

    assert projected == [rows[0]]
    assert next_cursor is not None
    assert decode_agent_cursor(next_cursor) == (
        [0, "2026-08-09T00:00:00+00:00", "Acme", "cagt_1"],
        True,
    )


def test_paginate_agent_rows_has_no_cursor_on_last_page() -> None:
    row = {
        "verification_status": "discovered",
        "last_verified_at": None,
        "display_name": "Acme",
        "catalog_agent_id": "cagt_1",
    }

    projected, next_cursor = paginate_agent_rows([row], 1)  # type: ignore[arg-type]

    assert projected == [row]
    assert next_cursor is None
