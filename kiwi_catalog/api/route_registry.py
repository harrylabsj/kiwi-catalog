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
