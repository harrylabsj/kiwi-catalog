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
                    for key in ("id", "label", "version"):
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
            for key in ("id", "label", "version"):
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
