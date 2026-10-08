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


def test_agent_cursor_legacy_id_cursor_is_rejected_not_mispaged() -> None:
    """review P1-5 返修：裸 legacy id 无法还原 rank-first 排序四元组——明示
    拒绝（4xx），绝不静默退回单键谓词产生漏页/错页。"""
    import pytest

    from kiwi_catalog.core.errors import ValidationError

    assert decode_agent_cursor("cagt_legacy") == (["cagt_legacy"], False)
    with pytest.raises(ValidationError):
        agent_cursor_predicate("cagt_legacy")


def test_agent_cursor_v2_malformed_variants_are_typed_4xx() -> None:
    """review 2-33 返修：v2 前缀下解码/形状/类型失败一律 ValidationError。"""
    import base64
    import json as _json

    import pytest

    from kiwi_catalog.core.errors import ValidationError

    bad_payloads = [
        "!!!not-base64!!!",
        base64.urlsafe_b64encode(b"\xff\xfe non-utf8").decode(),
        base64.urlsafe_b64encode(_json.dumps([{}, "x", "y", "z"]).encode()).decode(),  # rank=dict
        base64.urlsafe_b64encode(_json.dumps([1, 2, 3]).encode()).decode(),  # 元素数错
        base64.urlsafe_b64encode(_json.dumps({"a": 1}).encode()).decode(),  # 非 list
    ]
    for payload in bad_payloads:
        with pytest.raises(ValidationError):
            decode_agent_cursor("v2:" + payload)


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
