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

"""Pure route-dispatch loop extracted from the app facade.

This module owns no route table and no error-to-response mapping.  It walks
a caller-supplied route table, asks the injected path matcher for path
parameters, invokes the matched handler, and raises the same
MethodNotAllowedError/NotFoundError the app facade used to raise inline.
The app facade keeps payload validation and exception mapping intact.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from kiwi_catalog.core.errors import MethodNotAllowedError, NotFoundError

Matcher = Callable[[str, str], dict[str, str] | None]


def dispatch_request(
    routes: tuple[Any, ...] | list[Any],
    method: str,
    path: str,
    db_path: str | Path,
    payload: dict[str, Any] | None,
    query: dict[str, Any] | None,
    matcher: Matcher,
) -> Any:
    """Invoke the handler selected by *method*/*path* from *routes*.

    Each route entry must expose ``path_template``, ``methods``, and
    ``handler``.  Handlers are called as ``handler(db_path, payload, query,
    **path_params)`` and their result is returned unchanged.

    Raises:
        MethodNotAllowedError: when *path* matches a route but *method* is
            not among that route's supported methods.
        NotFoundError: when *path* matches no route.
    """
    payload = payload or {}
    query = query or {}
    path_matched = False
    for route in routes:
        path_params = matcher(route.path_template, path)
        if path_params is None:
            continue
        path_matched = True
        if method.upper() in route.methods:
            return route.handler(db_path, payload, query, **path_params)
    if path_matched:
        raise MethodNotAllowedError(f"Method not allowed for {method} {path}")
    raise NotFoundError(f"No route for {method} {path}")
