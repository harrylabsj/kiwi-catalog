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

"""UCP Profile 2026-04-08 parser and validator.

Design: docs/shopping-cli-a2a-upgrade-design-v1.2.1.md §0.3, §7, §17.2–17.3
Pinned external spec: UCP Profile 2026-04-08 (§0.3)

This parser implements the §17.2 pipeline stages that follow fetching:

    schema validate → semantic validate → identity/authority validate
    → secret quarantine (§17.3) → public-field projection (§3.4)

The input is the *already-parsed* JSON produced by ``ProfileFetcher`` and is
always treated as untrusted.  Every field is opaque data.  In particular the
natural-language ``description`` fields are DATA — they are never interpreted
as instructions, prompts, or policy (§17.2).

UCP is the commerce service & capability discovery document: it carries
commerce services, commerce capabilities, transport discovery, and
spec/schema references.  A2A interfaces/skills live in the Agent Card, not
here (binding rc1 D10).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kiwi_catalog.discovery._validation import (
    ProfileValidationError,
    assert_same_domain,
    canonical_domain_of,
    get_optional_str,
    is_http_url,
    require_list_of_str,
    require_mapping,
    require_str,
    scan_secrets,
    validate_json_bounds,
)
from kiwi_catalog.discovery.capabilities import (
    extract_ucp_capabilities,
    extract_ucp_skills,
)
from kiwi_catalog.discovery.trust import TrustPolicy

_DEFAULT_MAX_DEPTH = 100
_DEFAULT_MAX_NODES = 50_000


# ── Canonical Kiwi UCP model adapter ─────────────────────────────────────────
# Kiwi build 输出使用 canonical 模型：顶层 ``ucp`` 键 + ``version`` + **services
# map**（id → service）+ **capabilities map**（id → {version, spec, schema}）。
# Kiwi 的 canonical 类型是 ``Record<string, Declaration[]>``——map 值是**声明
# 数组**（validate.ts requireArray fail-closed）；其他发布者可能直接给 object。
# 两种形式都接受：数组形式取首个 object 声明。
# 标准解析器消费 ``specificationVersion`` + service 列表 + 每 capability 的
# version/spec/schema——适配器把 canonical 模型归一化为标准形状，使下游
# ``_knp_claims`` 对 Kiwi build 输出执行同样的 KNP 治理（缺 metadata → 拒）。


def _first_declaration(value: Any) -> Any:
    """Unwrap a canonical declaration map value.

    Object form（其他发布者）原样返回；Kiwi canonical 的数组形式取首个元素；
    空数组返回 ``None``。非 object 结果由调用方 fail-closed 处理（service →
    ProfileValidationError；capability metadata → 仅 id/label 条目，KNP 拒）。
    """
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _normalize_canonical_ucp(parsed: Any, *, canonical_domain: str = "") -> Any:
    """Detect and normalize the canonical Kiwi UCP model to the standard shape.

    Non-``ucp`` top-level input passes through unchanged.  The canonical model
    (exact Kiwi ``buildKiwiVendorProfile`` shape):
      - ``ucp.version`` → ``specificationVersion`` (pinned-version validation
        is done by the caller against ``allowed_ucp_versions``);
      - ``ucp.services`` **map** → the standard service **list**.  Each service
        declaration is ``{version, spec, transport, endpoint}`` (no
        capabilities/endpoints lists), so the adapter builds
        ``endpoints=[{uri: endpoint, protocol: transport, version: version}]``
        and defaults ``type`` to ``commerce``;
      - capability ids are derived from ``ucp.capabilities`` **map** keys whose
        prefix is ``service_id + "."`` (e.g. service
        ``com.harrylabsj.kiwi.shopping`` → capability
        ``com.harrylabsj.kiwi.shopping.negotiation``), or from an explicit
        service ``capabilities`` list;
      - per-capability ``{version, spec, schema}`` is injected into the owning
        service's ``specifications`` as ``{id, label, version, specUrl,
        schemaUrl}`` so ``_knp_claims`` sees per-capability metadata.  A
        capability with missing metadata still emits an id/label-only entry so
        KNP trust fails (never silently disappears).  ``spec``/``schema`` may be
        external spec-registry URLs — they are carried on ``specifications`` and
        are not domain-enforced (unlike ``documentationUri``/``openAPIDocument``);
      - a missing ``serviceIdentity`` is derived from *canonical_domain* (the
        standard parser requires a non-empty id/name).
    """
    if not isinstance(parsed, dict) or not isinstance(parsed.get("ucp"), dict):
        return parsed
    ucp = parsed["ucp"]
    version = ucp.get("version")
    if not isinstance(version, str) or not version.strip():
        raise ProfileValidationError("ucp.version is required (canonical Kiwi UCP model)")
    services_map = ucp.get("services")
    if not isinstance(services_map, dict) or not services_map:
        raise ProfileValidationError("ucp.services must be a non-empty map (canonical Kiwi UCP model)")
    capabilities_map = ucp.get("capabilities")
    capabilities_map = capabilities_map if isinstance(capabilities_map, dict) else {}

    standard_services: list[dict[str, Any]] = []
    for svc_id, svc in services_map.items():
        svc = _first_declaration(svc)
        if not isinstance(svc, dict):
            raise ProfileValidationError(
                f"ucp.services.{svc_id}: expected a JSON object or declaration array"
            )
        converted: dict[str, Any] = {
            "id": str(svc_id),
            "type": str(svc.get("type") or "commerce"),
        }
        # capabilities：显式声明（list / inline dict）+ 从 root capabilities map
        # 按 ``service_id + "."`` 前缀派生。Kiwi ``buildKiwiVendorProfile`` 的
        # 服务声明不含 capabilities 列表——capability 是 root map 里以 service
        # id 为前缀的完整 capability id（如 ``com.harrylabsj.kiwi.shopping`` →
        # ``com.harrylabsj.kiwi.shopping.negotiation``）。
        inline_caps: dict[str, Any] = {}
        caps = svc.get("capabilities")
        if isinstance(caps, dict):
            for k, v in caps.items():
                declaration = _first_declaration(v)
                if isinstance(declaration, dict):
                    inline_caps[str(k)] = declaration
            cap_ids = list(inline_caps)
        elif isinstance(caps, list):
            cap_ids = [str(c) for c in caps]
        else:
            cap_ids = []
        prefix = f"{svc_id}."
        for cap_key in capabilities_map:
            cap_key = str(cap_key)
            if cap_key.startswith(prefix) and cap_key not in cap_ids:
                cap_ids.append(cap_key)
        converted["capabilities"] = cap_ids
        # endpoints：显式 ``endpoints`` 列表，或 Kiwi 服务声明的
        # ``endpoint`` + ``transport`` + ``version`` → 单个 endpoint。
        if isinstance(svc.get("endpoints"), list):
            converted["endpoints"] = svc["endpoints"]
        else:
            endpoint_uri = svc.get("endpoint")
            if isinstance(endpoint_uri, str) and endpoint_uri.strip():
                ep: dict[str, Any] = {
                    "uri": endpoint_uri.strip(),
                    "protocol": str(svc.get("transport") or "a2a").strip() or "a2a",
                }
                if isinstance(svc.get("version"), str) and svc["version"].strip():
                    ep["version"] = svc["version"].strip()
                converted["endpoints"] = [ep]
            else:
                converted["endpoints"] = []  # 无 endpoint → _validate_services 拒
        for key in ("description", "documentationUri"):
            if isinstance(svc.get(key), str):
                converted[key] = svc[key]

        # Per-capability metadata → service specifications (version/spec/schema)。
        # 每个派生 capability 都生成条目（metadata 缺失时仅 id/label）——让
        # _knp_claims 以「缺声明版本」拒绝，而不是静默消失。
        specs: list[dict[str, Any]] = []
        for cap_id in cap_ids:
            meta = inline_caps.get(cap_id)
            if not isinstance(meta, dict):
                meta = _first_declaration(capabilities_map.get(cap_id))
            entry: dict[str, Any] = {"id": cap_id, "label": cap_id}
            if isinstance(meta, dict):
                if isinstance(meta.get("version"), str) and meta["version"].strip():
                    entry["version"] = meta["version"].strip()
                for src_key, spec_key in (("spec", "specUrl"), ("schema", "schemaUrl")):
                    if isinstance(meta.get(src_key), str) and meta[src_key].strip():
                        entry[spec_key] = meta[src_key].strip()
            specs.append(entry)
        if specs:
            converted["specifications"] = specs
        standard_services.append(converted)

    identity = ucp.get("serviceIdentity")
    identity = identity if isinstance(identity, dict) else {}
    if not str(identity.get("id") or "").strip():
        identity = {"id": canonical_domain or "kiwi-agent", "name": canonical_domain or "kiwi-agent"}

    standard: dict[str, Any] = {
        "specificationVersion": version.strip(),
        "serviceIdentity": identity,
        "services": standard_services,
    }
    if isinstance(ucp.get("specifications"), list):
        standard["specifications"] = ucp["specifications"]
    return standard


@dataclass(frozen=True)
class UcpProfileResult:
    """Validated UCP Profile with public projection and derived rows."""

    profile_type: str = "ucp"
    source_url: str = ""
    canonical_domain: str = ""
    specification_version: str = ""
    service_identity_id: str = ""
    public: dict[str, Any] = field(default_factory=dict)
    capabilities: tuple[dict[str, Any], ...] = ()
    skills: tuple[dict[str, Any], ...] = ()
    secrets_quarantined: tuple[str, ...] = ()


class UcpProfileParser:
    """Parse and validate a UCP Profile 2026-04-08.

    Usage::

        policy = TrustPolicy.defaults()
        parser = UcpProfileParser(policy)
        result = parser.parse(fetch_result.parsed, source_url="https://merchant.example/.well-known/ucp")
    """

    def __init__(
        self,
        policy: TrustPolicy | None = None,
        *,
        reject_on_secret: bool = False,
        max_depth: int = _DEFAULT_MAX_DEPTH,
        max_nodes: int = _DEFAULT_MAX_NODES,
    ) -> None:
        self._policy = policy or TrustPolicy.defaults()
        self._reject_on_secret = reject_on_secret
        self._max_depth = max_depth
        self._max_nodes = max_nodes

    # ── Pipeline ─────────────────────────────────────────────────────────

    def parse(self, parsed: Any, *, source_url: str) -> UcpProfileResult:
        """Validate an untrusted UCP Profile and return its public projection.

        Raises:
            ProfileValidationError: schema, semantic, authority, or (when
                ``reject_on_secret=True``) secret-policy failure.
        """
        # 0. Bounds backstop (independent of the fetcher's limits)
        validate_json_bounds(parsed, max_depth=self._max_depth, max_nodes=self._max_nodes)
        canonical = canonical_domain_of(source_url)
        # 审查 P2：Kiwi build 输出的 canonical 模型（顶层 ``ucp`` 键）先归一化
        # 为标准形状（services/capabilities map → 内部 service 列表，每 capability
        # 的 version/spec/schema 注入 specifications）。
        parsed = _normalize_canonical_ucp(parsed, canonical_domain=canonical)

        # 1. Schema validate
        profile = require_mapping(parsed, "ucp_profile")
        spec_version = require_str(profile, "specificationVersion", "ucp_profile")
        # The following calls exist for their validation side effect only.
        _implementation_version = get_optional_str(profile, "implementationVersion", "ucp_profile")
        identity = require_mapping(profile.get("serviceIdentity"), "ucp_profile.serviceIdentity")
        identity_id = require_str(identity, "id", "ucp_profile.serviceIdentity")
        identity_name = require_str(identity, "name", "ucp_profile.serviceIdentity")
        if "description" in identity and identity["description"] is not None:
            require_str(identity, "description", "ucp_profile.serviceIdentity")
        _services = self._validate_services(profile.get("services"))
        self._validate_specifications(profile.get("specifications"))

        # 2. Semantic validate
        if spec_version not in self._policy.allowed_ucp_versions:
            raise ProfileValidationError(
                f"ucp_profile.specificationVersion '{spec_version}' is not an allowed UCP version "
                f"(allowed: {', '.join(sorted(self._policy.allowed_ucp_versions)) or 'none'})"
            )
        if not identity_id.strip():
            raise ProfileValidationError("ucp_profile.serviceIdentity.id must be a non-empty string")
        if not identity_name.strip():
            raise ProfileValidationError("ucp_profile.serviceIdentity.name must be a non-empty string")

        # 3. Identity/authority validate (§17.2 — profile poisoning)
        self._validate_authority(profile, canonical)

        # 4. Secret quarantine (§17.3)
        secret_paths = scan_secrets(profile)
        if self._reject_on_secret and secret_paths:
            raise ProfileValidationError(
                f"ucp_profile contains secret-like fields: {', '.join(secret_paths[:8])}"
            )

        # 5. Public-field projection (§3.4)
        public = _project_public(profile, frozenset(secret_paths))

        # 6. Derived rows (capabilities)
        capabilities = extract_ucp_capabilities(
            public,
            default_namespace=canonical,
            specification_version=spec_version,
        )
        skill_rows = extract_ucp_skills(public)

        # NOTE: ``description`` and every other natural-language field are
        # carried through verbatim as DATA.  Nothing below may treat them as
        # instructions/prompts (§17.2).
        return UcpProfileResult(
            source_url=source_url,
            canonical_domain=canonical,
            specification_version=spec_version,
            service_identity_id=identity_id,
            public=public,
            capabilities=tuple(capabilities),
            skills=tuple(skill_rows),
            secrets_quarantined=tuple(secret_paths),
        )

    # ── Schema sub-validators ────────────────────────────────────────────

    def _validate_services(self, value: Any) -> list[dict[str, Any]]:
        if not isinstance(value, list) or not value:
            raise ProfileValidationError("ucp_profile.services: expected a non-empty list")
        result: list[dict[str, Any]] = []
        for i, service in enumerate(value):
            label = f"ucp_profile.services.{i}"
            if not isinstance(service, dict):
                raise ProfileValidationError(f"{label}: expected a JSON object")
            require_str(service, "id", label)
            require_str(service, "type", label)
            require_list_of_str(service, "capabilities", label)
            if "description" in service and service["description"] is not None:
                require_str(service, "description", label)
            self._validate_endpoints(service.get("endpoints"), label)
            if "documentationUri" in service and service["documentationUri"] is not None:
                require_str(service, "documentationUri", label)
            if "specifications" in service and service["specifications"] is not None:
                if not isinstance(service["specifications"], list):
                    raise ProfileValidationError(f"{label}.specifications: expected a list")
                for j, sp in enumerate(service["specifications"]):
                    if not isinstance(sp, dict):
                        raise ProfileValidationError(f"{label}.specifications.{j}: expected a JSON object")
                    require_str(sp, "id", f"{label}.specifications.{j}")
                    require_str(sp, "label", f"{label}.specifications.{j}")
            result.append(service)
        return result

    def _validate_endpoints(self, value: Any, label: str) -> None:
        if not isinstance(value, list) or not value:
            raise ProfileValidationError(f"{label}.endpoints: expected a non-empty list")
        for j, endpoint in enumerate(value):
            ep_label = f"{label}.endpoints.{j}"
            if not isinstance(endpoint, dict):
                raise ProfileValidationError(f"{ep_label}: expected a JSON object")
            require_str(endpoint, "uri", ep_label)
            require_str(endpoint, "protocol", ep_label)
            if "version" in endpoint and endpoint["version"] is not None:
                require_str(endpoint, "version", ep_label)
            if "access" in endpoint and endpoint["access"] is not None:
                # UCP allows ``access`` to be an object OR a string (URI
                # reference).  A string that carries a credential is caught by
                # the §17.3 value scan, so it must survive schema validation to
                # reach the secret quarantine stage.
                access = endpoint["access"]
                if not isinstance(access, (dict, str)):
                    raise ProfileValidationError(f"{ep_label}.access: expected a JSON object or string")

    def _validate_specifications(self, value: Any) -> None:
        if value is None:
            return
        if not isinstance(value, list):
            raise ProfileValidationError("ucp_profile.specifications: expected a list")
        for j, sp in enumerate(value):
            label = f"ucp_profile.specifications.{j}"
            if not isinstance(sp, dict):
                raise ProfileValidationError(f"{label}: expected a JSON object")
            require_str(sp, "id", label)
            require_str(sp, "label", label)
            if "openAPIDocument" in sp and sp["openAPIDocument"] is not None:
                require_str(sp, "openAPIDocument", label)

    # ── Authority sub-validator (§17.2) ──────────────────────────────────

    def _validate_authority(self, profile: dict[str, Any], canonical: str) -> None:
        """Require declared transport endpoints to live on *canonical*.

        ``serviceIdentity.id`` is enforced only when it is an http(s) URL
        (DID / URN identifiers are left to higher-level identity verification,
        out of scope for the MVP domain-control check).
        """
        identity = profile.get("serviceIdentity")
        if isinstance(identity, dict):
            identity_id = identity.get("id")
            if isinstance(identity_id, str) and is_http_url(identity_id):
                assert_same_domain(identity_id, canonical, "ucp_profile.serviceIdentity.id")

        services = profile.get("services")
        if isinstance(services, list):
            for i, service in enumerate(services):
                if not isinstance(service, dict):
                    continue
                base = f"ucp_profile.services.{i}"
                doc = service.get("documentationUri")
                if isinstance(doc, str) and is_http_url(doc):
                    assert_same_domain(doc, canonical, f"{base}.documentationUri")
                endpoints = service.get("endpoints")
                if isinstance(endpoints, list):
                    for j, endpoint in enumerate(endpoints):
                        if not isinstance(endpoint, dict):
                            continue
                        uri = endpoint.get("uri")
                        if isinstance(uri, str):
                            # Transport endpoints are routing targets — the
                            # domain check closes the endpoint-hijack vector.
                            assert_same_domain(uri, canonical, f"{base}.endpoints.{j}.uri")

        specifications = profile.get("specifications")
        if isinstance(specifications, list):
            for j, sp in enumerate(specifications):
                if not isinstance(sp, dict):
                    continue
                openapi = sp.get("openAPIDocument")
                if isinstance(openapi, str) and is_http_url(openapi):
                    assert_same_domain(openapi, canonical, f"ucp_profile.specifications.{j}.openAPIDocument")


# ── Public-field projection (§3.4) ──────────────────────────────────────────


def _project_public(profile: dict[str, Any], secret_paths: frozenset[str]) -> dict[str, Any]:
    """Project a validated UCP Profile down to §3.4 public fields.

    Secret-bearing regions (notably ``endpoints[].access``) are excluded;
    any field flagged by the §17.3 scan is dropped.
    """
    public: dict[str, Any] = {}

    def _skip(path: str) -> bool:
        """True when *path* itself or any descendant is a quarantined secret."""
        if path in secret_paths:
            return True
        return any(p.startswith(path + ".") for p in secret_paths)

    public["specificationVersion"] = profile["specificationVersion"]
    implementation_version = profile.get("implementationVersion")
    if isinstance(implementation_version, str) and implementation_version and not _skip("implementationVersion"):
        public["implementationVersion"] = implementation_version

    identity = profile.get("serviceIdentity")
    if isinstance(identity, dict):
        projected_identity: dict[str, Any] = {}
        for key in ("id", "name", "description"):
            if key in identity and identity[key] is not None and not _skip(f"serviceIdentity.{key}"):
                projected_identity[key] = identity[key]
        owner = identity.get("owner")
        if isinstance(owner, dict):
            projected_owner: dict[str, Any] = {}
            for key in ("name", "url"):
                if key in owner and owner[key] is not None and not _skip(f"serviceIdentity.owner.{key}"):
                    projected_owner[key] = owner[key]
            if projected_owner:
                projected_identity["owner"] = projected_owner
        service_area = identity.get("serviceArea")
        if isinstance(service_area, dict) and not _skip("serviceIdentity.serviceArea"):
            projected_identity["serviceArea"] = dict(service_area)
        if projected_identity:
            public["serviceIdentity"] = projected_identity

    services = profile.get("services")
    if isinstance(services, list):
        projected_services: list[dict[str, Any]] = []
        for i, service in enumerate(services):
            if not isinstance(service, dict):
                continue
            base = f"services.{i}"
            projected_service: dict[str, Any] = {}
            for key in ("id", "type", "description"):
                if key in service and service[key] is not None and not _skip(f"{base}.{key}"):
                    projected_service[key] = service[key]
            if isinstance(service.get("capabilities"), list) and not _skip(f"{base}.capabilities"):
                projected_service["capabilities"] = list(service["capabilities"])

            endpoints = service.get("endpoints")
            if isinstance(endpoints, list):
                projected_endpoints: list[dict[str, Any]] = []
                for j, endpoint in enumerate(endpoints):
                    if not isinstance(endpoint, dict):
                        continue
                    ebase = f"{base}.endpoints.{j}"
                    projected_endpoint: dict[str, Any] = {}
                    for key in ("uri", "protocol"):
                        if key in endpoint and endpoint[key] is not None and not _skip(f"{ebase}.{key}"):
                            projected_endpoint[key] = endpoint[key]
                    version = endpoint.get("version")
                    if isinstance(version, str) and not _skip(f"{ebase}.version"):
                        projected_endpoint["version"] = version
                    if projected_endpoint:
                        projected_endpoints.append(projected_endpoint)
                if projected_endpoints:
                    projected_service["endpoints"] = projected_endpoints

            documentation_uri = service.get("documentationUri")
            if isinstance(documentation_uri, str) and not _skip(f"{base}.documentationUri"):
                projected_service["documentationUri"] = documentation_uri

            service_specs = service.get("specifications")
            if isinstance(service_specs, list):
                projected_specs: list[dict[str, Any]] = []
                for j, sp in enumerate(service_specs):
                    if not isinstance(sp, dict):
                        continue
                    spbase = f"{base}.specifications.{j}"
                    projected_spec: dict[str, Any] = {}
                    # specUrl/schemaUrl：canonical Kiwi 模型每 capability 的
                    # spec/schema 引用（可指向外部 spec registry），供 _knp_claims
                    # 校验 KNP metadata；非 URL 也按原样投影。
                    for key in ("id", "label", "version", "specUrl", "schemaUrl"):
                        if key in sp and sp[key] is not None and not _skip(f"{spbase}.{key}"):
                            projected_spec[key] = sp[key]
                    if projected_spec:
                        projected_specs.append(projected_spec)
                if projected_specs:
                    projected_service["specifications"] = projected_specs

            if projected_service:
                projected_services.append(projected_service)
        if projected_services:
            public["services"] = projected_services

    specifications = profile.get("specifications")
    if isinstance(specifications, list):
        projected_top_specs: list[dict[str, Any]] = []
        for j, sp in enumerate(specifications):
            if not isinstance(sp, dict):
                continue
            base = f"specifications.{j}"
            projected_top_spec: dict[str, Any] = {}
            for key in ("id", "label", "version", "specUrl", "schemaUrl"):
                if key in sp and sp[key] is not None and not _skip(f"{base}.{key}"):
                    projected_top_spec[key] = sp[key]
            openapi = sp.get("openAPIDocument")
            if isinstance(openapi, str) and not _skip(f"{base}.openAPIDocument"):
                projected_top_spec["openAPIDocument"] = openapi
            if projected_top_spec:
                projected_top_specs.append(projected_top_spec)
        if projected_top_specs:
            public["specifications"] = projected_top_specs

    return public


def parse_ucp_profile(parsed: Any, *, source_url: str, policy: TrustPolicy | None = None) -> UcpProfileResult:
    """Convenience wrapper that constructs a default parser and runs it."""
    return UcpProfileParser(policy).parse(parsed, source_url=source_url)
