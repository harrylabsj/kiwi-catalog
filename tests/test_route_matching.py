from kiwi_catalog.api.route_matching import match_path


def test_match_path_extracts_parameters_without_decoding_route_literals() -> None:
    assert match_path("/agents/{agent_id}", "/agents/a-1") == {"agent_id": "a-1"}
    assert match_path("/agents/{agent_id}", "/agents/a-1/extra") is None


def test_match_path_escapes_literal_regex_characters() -> None:
    assert match_path("/v1/items/{item_id}/detail.json", "/v1/items/x/detail.json") == {"item_id": "x"}
    assert match_path("/v1/items/{item_id}/detail.json", "/v1/items/x/detailXjson") is None
