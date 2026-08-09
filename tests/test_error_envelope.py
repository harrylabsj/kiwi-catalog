from kiwi_catalog.api.error_envelope import error_body, error_result


def test_error_body_is_a_stable_non_reflective_envelope() -> None:
    assert error_body(ValueError("bad input")) == {"ok": False, "error": "bad input"}


def test_error_result_preserves_status_and_body_shape() -> None:
    assert error_result(413, "too large") == (413, {"ok": False, "error": "too large"})
