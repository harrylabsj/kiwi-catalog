import sqlite3

from kiwi_catalog.agent_catalog.row_serialization import row_to_dict


def test_row_to_dict_applies_overrides_without_mutating_source() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    row = connection.execute("select 1 as id, 'old' as value").fetchone()
    assert row_to_dict(row, {"value": "new", "extra": True}) == {
        "id": 1,
        "value": "new",
        "extra": True,
    }
