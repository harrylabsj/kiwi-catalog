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

"""Device enrollment HTTP adapters."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from kiwi_catalog.db.session import db_session
from kiwi_catalog.services import enrollments as service
from kiwi_catalog.services.rate_limit import SQLiteRateLimitBackend, enforce_rate_limit


def issuer_keys() -> dict[str, Any]:
    """Public issuer JWKS; callers must fetch only from their configured Catalog origin over TLS."""
    from kiwi_catalog.a2a.binding_claims import load_issuer_key_set, jwk_thumbprint
    import os
    keys = load_issuer_key_set().public_keys()
    return {"issuer": os.environ.get("KIWI_CATALOG_ISSUER_NAME", "catalog.kiwi"),
            "keys": [{"kid": kid, "state": value["state"], "jwk": value["jwk"],
                      "thumbprint": jwk_thumbprint(value["jwk"])}
                     for kid, value in sorted(keys.items())
                     if value["state"] in ("ACTIVE", "VERIFY_ONLY")]}


def create_device(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    signature = str(payload.get("_binding_jws") or "")
    body = {k: v for k, v in payload.items() if not k.startswith("_")}
    with db_session(db_path) as conn:
        backend = SQLiteRateLimitBackend(conn, table="merchant_application_limits", key_column="actor_key")
        enforce_rate_limit(backend, key=f"enrollment-device:{payload.get('_client_ip') or 'unknown'}",
                           limit=12, window_seconds=900, description="device enrollment creation")
        return service.create_device(conn, body, signature)


def device_token(db_path: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    signature = str(payload.get("_binding_jws") or "")
    body = {k: v for k, v in payload.items() if not k.startswith("_")}
    with db_session(db_path) as conn:
        from hashlib import sha256
        backend = SQLiteRateLimitBackend(conn, table="merchant_application_limits", key_column="actor_key")
        device_hash = sha256(str(body.get("device_code", "")).encode()).hexdigest()
        enforce_rate_limit(backend, key=f"enrollment-poll:{device_hash}",
                           limit=120, window_seconds=900, description="device enrollment polling")
        return service.poll(conn, body, signature)
