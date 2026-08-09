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

"""Focused synthetic-route tests for the pure route-dispatch helper.

The dispatch loop is extracted from the app facade (app.handle_request).
These tests exercise it with synthetic route tables — no real catalog
handlers or DB — so the loop contract (allowed dispatch, wrong-method 405,
unknown-path 404, and path-parameter forwarding) is pinned independently of
the live route table.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

from kiwi_catalog.api.request_dispatch import dispatch_request
from kiwi_catalog.api.route_matching import match_path
from kiwi_catalog.core.errors import MethodNotAllowedError, NotFoundError


@dataclass(frozen=True)
class SyntheticRoute:
    methods: set[str]
    path_template: str
    handler: Callable[..., Any]


def _record(db_path, payload, query, **path_params):
    return {"db": db_path, "payload": payload, "query": query, "params": path_params}


ROUTES: tuple[SyntheticRoute, ...] = (
    SyntheticRoute(
        {"GET"},
        "/items",
        lambda db_path, payload, query, **kw: _record(db_path, payload, query),
    ),
    SyntheticRoute(
        {"POST"},
        "/items",
        lambda db_path, payload, query, **kw: _record(db_path, payload, query),
    ),
    SyntheticRoute(
        {"GET"},
        "/items/{item_id}",
        lambda db_path, payload, query, item_id: _record(
            db_path, payload, query, item_id=item_id
        ),
    ),
)


def test_dispatch_request_invokes_allowed_handler() -> None:
    result = dispatch_request(
        ROUTES, "GET", "/items", ":db:", {"a": 1}, {"b": "2"}, match_path
    )
    assert result == {
        "db": ":db:",
        "payload": {"a": 1},
        "query": {"b": "2"},
        "params": {},
    }


def test_dispatch_request_method_is_case_insensitive() -> None:
    result = dispatch_request(ROUTES, "post", "/items", ":db:", None, None, match_path)
    assert result["db"] == ":db:"
    assert result["payload"] == {}
    assert result["query"] == {}
    assert result["params"] == {}


def test_dispatch_request_raises_method_not_allowed_for_known_path() -> None:
    with pytest.raises(MethodNotAllowedError):
        dispatch_request(ROUTES, "DELETE", "/items", ":db:", {}, {}, match_path)


def test_dispatch_request_raises_not_found_for_unknown_path() -> None:
    with pytest.raises(NotFoundError):
        dispatch_request(ROUTES, "GET", "/unknown", ":db:", {}, {}, match_path)


def test_dispatch_request_forwards_path_parameters() -> None:
    result = dispatch_request(
        ROUTES, "GET", "/items/abc-123", ":db:", {"a": 1}, {"q": "x"}, match_path
    )
    assert result["db"] == ":db:"
    assert result["payload"] == {"a": 1}
    assert result["query"] == {"q": "x"}
    assert result["params"] == {"item_id": "abc-123"}


def test_dispatch_request_405_when_only_a_path_parameter_route_matches() -> None:
    """Path params participate in the known-path decision for wrong methods."""
    with pytest.raises(MethodNotAllowedError):
        dispatch_request(ROUTES, "DELETE", "/items/abc-123", ":db:", {}, {}, match_path)
