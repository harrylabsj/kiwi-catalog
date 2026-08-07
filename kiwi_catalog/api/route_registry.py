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

"""kiwi-catalog route view (阶段 2 裁剪).

The standalone service serves exactly the catalog route table in app.py —
no marketplace groups exist here, so the route view derives directly from
the executable table instead of a group registry.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RouteInfo:
    path: str
    methods: set[str]


def catalog_route_info() -> list[RouteInfo]:
    """Route view for the kiwi-catalog standalone service (from app.py)."""
    from kiwi_catalog.api.app import _ROUTE_TABLE

    return [RouteInfo(entry.path_template, set(entry.methods)) for entry in _ROUTE_TABLE]
