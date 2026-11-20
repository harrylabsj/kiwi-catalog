from kiwi_catalog.api.route_matching import match_path


def test_match_path_extracts_parameters_without_decoding_route_literals() -> None:
    assert match_path("/agents/{agent_id}", "/agents/a-1") == {"agent_id": "a-1"}
    assert match_path("/agents/{agent_id}", "/agents/a-1/extra") is None


def test_match_path_escapes_literal_regex_characters() -> None:
    assert match_path("/v1/items/{item_id}/detail.json", "/v1/items/x/detail.json") == {"item_id": "x"}
    assert match_path("/v1/items/{item_id}/detail.json", "/v1/items/x/detailXjson") is None


def test_match_path_rejects_invalid_parameter_names_without_raising() -> None:
    # 审查 P1-4：非法参数名此前直接拼进命名分组，re.match 编译期抛 re.error；
    # 异常逃逸出 fallback __call__（只有 finally）后，进程内所有未知路径都变
    # 裸文本 500。现在 fail-closed 视为不匹配（该路由 404，其他路由不受影响）。
    assert match_path("/ext/{a-b}", "/ext/x") is None
    assert match_path("/ext/{a-b}", "/unknown") is None
    assert match_path("/ext/{1abc}", "/ext/x") is None
    assert match_path("/ext/{}", "/ext/x") is None
    # 重复参数名在编译期同样抛 re.error，按不匹配兜底。
    assert match_path("/ext/{a}/{a}", "/ext/x/y") is None


def test_match_path_keeps_matching_valid_templates() -> None:
    assert match_path("/ext/{agent_id}", "/ext/x") == {"agent_id": "x"}
    assert match_path("/ext/{agent_id}", "/ext/x/y") is None
