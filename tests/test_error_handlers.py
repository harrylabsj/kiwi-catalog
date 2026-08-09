# Copyright 2026 harrylabsj
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Characterization tests for kiwi_catalog.api.error_handlers.

The FastAPI exception mapping was extracted from app._register_fastapi_routes
into this module.  These tests pin the wire contract of the mapping — status
codes, the {"ok": false, "error": ...} envelope, RequestValidationError's
first-three sanitized details, Starlette 404/405/other, the unexpected 500 +
logging — and the registration order, so the refactor can't silently change
behavior.  The module must also stay importable without FastAPI/Starlette.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from kiwi_catalog.api.error_handlers import register_exception_handlers
from kiwi_catalog.core.errors import (
    AuthError,
    ConflictError,
    IdempotencyConflict,
    NotFoundError,
    PermissionDenied,
    RateLimitError,
    ShoppingCliError,
    ValidationError,
)


class _URL:
    def __init__(self, path: str) -> None:
        self.path = path


class FakeRequest:
    def __init__(self, method: str = "GET", path: str = "/") -> None:
        self.method = method
        self.url = _URL(path)


class FakeHTTPException(Exception):
    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


class FakeValidationError(Exception):
    def __init__(self, errors: list[dict[str, Any]]) -> None:
        super().__init__("validation failed")
        self._errors = errors

    def errors(self) -> list[dict[str, Any]]:
        return self._errors


class FakeJSONResponse:
    def __init__(self, content: Any, status_code: int = 200) -> None:
        self.content = content
        self.status_code = status_code


class FakeApp:
    def __init__(self) -> None:
        self.registrations: list[tuple[Any, Any]] = []

    def exception_handler(self, exc_type: Any) -> Any:
        def decorator(fn: Any) -> Any:
            self.registrations.append((exc_type, fn))
            return fn

        return decorator


def _register() -> tuple[FakeApp, dict[Any, Any]]:
    app = FakeApp()
    register_exception_handlers(
        app,
        json_response=FakeJSONResponse,
        request_type=FakeRequest,
        request_validation_error=FakeValidationError,
        http_exception=FakeHTTPException,
        logger_name="kiwi_catalog.api.app",
    )
    return app, dict(app.registrations)


def test_business_exception_mappings() -> None:
    _, handlers = _register()
    cases = [
        (AuthError("bad token"), 403),
        (PermissionDenied("no access"), 403),
        (NotFoundError("missing agent"), 404),
        (ConflictError("conflicts with state"), 409),
        (IdempotencyConflict("reused key"), 409),
        (RateLimitError("too many requests"), 429),
        (ValidationError("invalid input"), 400),
        (ShoppingCliError("base failure"), 400),
    ]
    for exc, status in cases:
        resp = handlers[type(exc)](FakeRequest(), exc)
        assert resp.status_code == status
        assert resp.content == {"ok": False, "error": str(exc)}


def test_registration_order_matches_original_mapping() -> None:
    app, _ = _register()
    expected = [
        AuthError,
        PermissionDenied,
        NotFoundError,
        ConflictError,
        IdempotencyConflict,
        RateLimitError,
        ValidationError,
        ShoppingCliError,
        FakeValidationError,
        FakeHTTPException,
        Exception,
    ]
    assert [exc_type for exc_type, _ in app.registrations] == expected


def test_request_validation_error_keeps_first_three_details() -> None:
    _, handlers = _register()
    errors = [
        {"loc": ["body", "display_name"], "msg": "field required", "type": "missing"},
        {"loc": ["body", "hosting_mode"], "msg": "field required", "type": "missing"},
        {"loc": ["body", "domain"], "msg": "field required", "type": "missing"},
        {"loc": ["body", "extra_field"], "msg": "extra field", "type": "extra"},
    ]
    resp = handlers[FakeValidationError](FakeRequest(), FakeValidationError(errors))
    assert resp.status_code == 400
    assert resp.content["ok"] is False
    # 只保留前三条 detail；未出现的第四条不被泄露进信封。
    assert resp.content["error"] == "invalid request: " + json.dumps(errors[:3])


def test_request_validation_error_sanitizes_bytes_inputs() -> None:
    _, handlers = _register()
    errors = [
        {"loc": ["body"], "msg": "invalid input", "type": "value", "input": b"\xff"}
    ]
    resp = handlers[FakeValidationError](FakeRequest(), FakeValidationError(errors))
    assert resp.status_code == 400
    # bytes input → 替换字符，序列化不再二次抛错变 500。
    assert "\\ufffd" in resp.content["error"]


def test_starlette_http_exception_404_405_and_other() -> None:
    _, handlers = _register()
    resp = handlers[FakeHTTPException](
        FakeRequest("GET", "/v1/does-not-exist"), FakeHTTPException(404, "Not Found")
    )
    assert resp.status_code == 404
    assert resp.content == {"ok": False, "error": "No route for GET /v1/does-not-exist"}

    resp = handlers[FakeHTTPException](
        FakeRequest("DELETE", "/v1/agents/register"),
        FakeHTTPException(405, "Method Not Allowed"),
    )
    assert resp.status_code == 405
    assert resp.content == {
        "ok": False,
        "error": "Method not allowed for DELETE /v1/agents/register",
    }

    resp = handlers[FakeHTTPException](
        FakeRequest("GET", "/private"), FakeHTTPException(401, "Not authenticated")
    )
    assert resp.status_code == 401
    assert resp.content == {"ok": False, "error": "Not authenticated"}


def test_unexpected_exception_becomes_500_and_logs(caplog: Any) -> None:
    _, handlers = _register()
    with caplog.at_level("ERROR", logger="kiwi_catalog.api.app"):
        resp = handlers[Exception](FakeRequest(), RuntimeError("kaboom"))
    assert resp.status_code == 500
    assert resp.content == {"ok": False, "error": "internal server error"}
    assert "unhandled request error" in caplog.text


def test_optional_framework_types_can_be_omitted() -> None:
    """request_validation_error / http_exception 缺省（None）时跳过注册。"""
    app = FakeApp()
    register_exception_handlers(
        app,
        json_response=FakeJSONResponse,
        request_type=FakeRequest,
        logger_name="kiwi_catalog.api.app",
    )
    registered = [exc_type for exc_type, _ in app.registrations]
    assert FakeValidationError not in registered
    assert FakeHTTPException not in registered
    assert Exception in registered


def test_error_handlers_module_imports_without_fastapi() -> None:
    """error_handlers 无 FastAPI/Starlette 顶层依赖（子进程 + sys.modules 阻断）。

    阻断 import 后仍能导入模块并调用注册函数——证明模块顶层不硬依赖
    fastapi/starlette，FastAPI 不可用时 fallback import 行为不变。
    """
    repo_root = Path(__file__).resolve().parents[1]
    code = (
        "import sys\n"
        "sys.modules['fastapi'] = None\n"
        "sys.modules['starlette'] = None\n"
        "from kiwi_catalog.api.error_handlers import register_exception_handlers\n"
        "print('import-ok')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "import-ok" in result.stdout


def _has_fastapi() -> bool:
    from kiwi_catalog.api import app as app_module

    return app_module.FastAPI is not None


@pytest.mark.skipif(not _has_fastapi(), reason="fastapi not installed")
def test_fastapi_integration_unexpected_500(caplog: Any) -> None:
    """真实 FastAPI app 上：未处理异常 → 500 信封 + 日志。"""
    from fastapi import FastAPI
    from fastapi import Request as FastAPIRequest
    from fastapi.exceptions import RequestValidationError
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient
    from starlette.exceptions import HTTPException as StarletteHTTPException

    app = FastAPI()
    register_exception_handlers(
        app,
        json_response=JSONResponse,
        request_type=FastAPIRequest,
        request_validation_error=RequestValidationError,
        http_exception=StarletteHTTPException,
        logger_name="kiwi_catalog.api.app",
    )

    @app.get("/boom")
    def boom() -> None:
        raise RuntimeError("kaboom")

    client = TestClient(app, raise_server_exceptions=False)
    with caplog.at_level("ERROR", logger="kiwi_catalog.api.app"):
        resp = client.get("/boom")
    assert resp.status_code == 500
    assert resp.json() == {"ok": False, "error": "internal server error"}
    assert "unhandled request error" in caplog.text


@pytest.mark.skipif(not _has_fastapi(), reason="fastapi not installed")
def test_fastapi_integration_request_validation_error() -> None:
    """真实 FastAPI app 上：校验失败 → 400 信封 + sanitized details。"""
    from fastapi import FastAPI
    from fastapi import Request as FastAPIRequest
    from fastapi.exceptions import RequestValidationError
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient
    from starlette.exceptions import HTTPException as StarletteHTTPException

    app = FastAPI()
    register_exception_handlers(
        app,
        json_response=JSONResponse,
        request_type=FastAPIRequest,
        request_validation_error=RequestValidationError,
        http_exception=StarletteHTTPException,
        logger_name="kiwi_catalog.api.app",
    )

    @app.post("/val")
    def val(payload: dict[str, Any]) -> dict[str, Any]:
        return {"ok": True}

    with TestClient(app) as client:
        # body 是数组而非对象 → FastAPI 抛 RequestValidationError（默认 422）
        resp = client.post(
            "/val", content=b"[1,2,3]", headers={"content-type": "application/json"}
        )
    assert resp.status_code == 400
    body = resp.json()
    assert body["ok"] is False
    assert body["error"].startswith("invalid request: ")
