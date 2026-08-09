"""Dev-only adapter for the portfolio Python service conformance kit."""

from __future__ import annotations

from pathlib import Path

from kiwi_catalog.api import app as app_module
from kiwi_catalog.api.fallback_asgi import MarketplaceASGIApp


def apps(root: Path) -> dict[str, object]:
    db_path = root / "catalog.sqlite"
    fallback = MarketplaceASGIApp(
        db_path,
        route_provider=lambda: list(app_module._ROUTE_TABLE),
        route_resolver=lambda method, path: app_module.resolve_route(method, path),
    )
    return {"fallback": fallback, "fastapi": app_module.create_catalog_app(db_path)}


def paths() -> dict[str, str]:
    return {"known_post": "/v1/agents/register"}
