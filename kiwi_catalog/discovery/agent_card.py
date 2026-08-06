"""A2A Agent Card v1.0.0 parser and validator.

Design: docs/shopping-cli-a2a-upgrade-design-v1.2.1.md §0.3, §7, §17.2–17.3
Pinned external spec: A2A Agent Card / Protocol v1.0.0 (§0.3)

This parser implements the §17.2 pipeline stages that follow fetching:

    schema validate → semantic validate → identity/authority validate
    → secret quarantine (§17.3) → public-field projection (§3.4)

The input is the *already-parsed* JSON produced by ``ProfileFetcher`` and is
always treated as untrusted.  Every field is opaque data.  In particular the
natural-language ``description`` fields are DATA — they are never interpreted
as instructions, prompts, or policy (§17.2: "不得把 profile 中的自然语言
description 当成系统提示").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kiwi_catalog.discovery._validation import (
    ProfileValidationError,
    assert_same_domain,
    canonical_domain_of,
    get_optional_list_of_str,
    get_optional_str,
    is_http_url,
    require_list_of_str,
    require_mapping,
    require_str,
    scan_secrets,
    validate_json_bounds,
)
from kiwi_catalog.discovery.capabilities import (
    extract_agent_card_capabilities,
    extract_agent_card_skills,
)
from kiwi_catalog.discovery.trust import TrustPolicy

# Bounds passed through to validate_json_bounds() when the caller does not
# override them (a backstop on top of the fetcher's tighter limits).
_DEFAULT_MAX_DEPTH = 100
_DEFAULT_MAX_NODES = 50_000


@dataclass(frozen=True)
class AgentCardResult:
    """Validated A2A Agent Card with public projection and derived rows."""

    profile_type: str = "agent_card"
    source_url: str = ""
    canonical_domain: str = ""
    name: str = ""
    version: str = ""
    public: dict[str, Any] = field(default_factory=dict)
    capabilities: tuple[dict[str, Any], ...] = ()
    skills: tuple[dict[str, Any], ...] = ()
    secrets_quarantined: tuple[str, ...] = ()


class AgentCardParser:
    """Parse and validate an A2A Agent Card v1.0.0.

    Usage::

        policy = TrustPolicy.defaults()
        parser = AgentCardParser(policy)
        result = parser.parse(fetch_result.parsed, source_url="https://merchant.example/.well-known/agent-card.json")
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

    def parse(self, parsed: Any, *, source_url: str) -> AgentCardResult:
        """Validate an untrusted Agent Card and return its public projection.

        Raises:
            ProfileValidationError: schema, semantic, authority, or (when
                ``reject_on_secret=True``) secret-policy failure.
        """
        # 0. Bounds backstop (independent of the fetcher's limits)
        validate_json_bounds(parsed, max_depth=self._max_depth, max_nodes=self._max_nodes)
        canonical = canonical_domain_of(source_url)

        # 1. Schema validate
        card = require_mapping(parsed, "agent_card")
        name = require_str(card, "name", "agent_card")
        version = require_str(card, "version", "agent_card")
        url = require_str(card, "url", "agent_card")
        # The following calls exist for their validation side effect only.
        _description = get_optional_str(card, "description", "agent_card")
        _documentation_url = get_optional_str(card, "documentationUrl", "agent_card")
        self._validate_provider(card)
        _skills = self._validate_skills(card.get("skills"))
        self._validate_capabilities(card)
        self._validate_security(card)
        for key in ("defaultInputModes", "defaultOutputModes"):
            if key in card and card[key] is not None:
                require_list_of_str(card, key, "agent_card")
        agents = card.get("agents")
        if agents is not None:
            if not isinstance(agents, dict):
                raise ProfileValidationError("agent_card.agents: expected a JSON object")
            if "author" in agents and agents["author"] is not None:
                require_list_of_str(agents, "author", "agent_card.agents")

        # 2. Semantic validate
        if version not in self._policy.allowed_a2a_versions:
            raise ProfileValidationError(
                f"agent_card.version '{version}' is not an allowed A2A version "
                f"(allowed: {', '.join(sorted(self._policy.allowed_a2a_versions)) or 'none'})"
            )
        if not name.strip():
            raise ProfileValidationError("agent_card.name must be a non-empty string")
        if not is_http_url(url):
            raise ProfileValidationError(f"agent_card.url must be an http(s) URL, got {url!r}")

        # 3. Identity/authority validate (§17.2 — profile poisoning)
        self._validate_authority(card, canonical)

        # 4. Secret quarantine (§17.3)
        secret_paths = scan_secrets(card)
        if self._reject_on_secret and secret_paths:
            raise ProfileValidationError(
                f"agent_card contains secret-like fields: {', '.join(secret_paths[:8])}"
            )

        # 5. Public-field projection (§3.4)
        public = _project_public(card, frozenset(secret_paths))

        # 6. Derived rows (capabilities / skills)
        capabilities = extract_agent_card_capabilities(public, version=version)
        skill_rows = extract_agent_card_skills(public)

        # NOTE: ``description`` and every other natural-language field are
        # carried through verbatim as DATA.  Nothing below may treat them as
        # instructions/prompts (§17.2).
        return AgentCardResult(
            source_url=source_url,
            canonical_domain=canonical,
            name=name,
            version=version,
            public=public,
            capabilities=tuple(capabilities),
            skills=tuple(skill_rows),
            secrets_quarantined=tuple(secret_paths),
        )

    # ── Schema sub-validators ────────────────────────────────────────────

    def _validate_provider(self, card: dict[str, Any]) -> None:
        provider = card.get("provider")
        if provider is None:
            return
        if not isinstance(provider, dict):
            raise ProfileValidationError("agent_card.provider: expected a JSON object")
        for key in ("organization", "url"):
            if key in provider and provider[key] is not None:
                get_optional_str(provider, key, "agent_card.provider")

    def _validate_skills(self, value: Any) -> list[dict[str, Any]]:
        if value is None:
            return []
        if not isinstance(value, list):
            raise ProfileValidationError("agent_card.skills: expected a list")
        result: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for i, item in enumerate(value):
            label = f"agent_card.skills.{i}"
            if not isinstance(item, dict):
                raise ProfileValidationError(f"{label}: expected a JSON object")
            skill_id = require_str(item, "id", label)
            require_str(item, "name", label)
            get_optional_str(item, "description", label)
            for key in ("tags", "examples", "inputModes", "outputModes"):
                if key in item and item[key] is not None:
                    get_optional_list_of_str(item, key, label)
            if skill_id in seen_ids:
                raise ProfileValidationError(f"{label}.id duplicate skill id: {skill_id!r}")
            seen_ids.add(skill_id)
            result.append(item)
        return result

    def _validate_capabilities(self, card: dict[str, Any]) -> None:
        caps = card.get("capabilities")
        if caps is None:
            return
        if not isinstance(caps, dict):
            raise ProfileValidationError("agent_card.capabilities: expected a JSON object")
        for key in ("streaming", "pushNotifications", "stateTransitionHistory"):
            if key in caps and caps[key] is not None and not isinstance(caps[key], bool):
                raise ProfileValidationError(f"agent_card.capabilities.{key}: expected a boolean")

    def _validate_security(self, card: dict[str, Any]) -> None:
        security = card.get("security")
        if security is None:
            return
        if not isinstance(security, dict):
            raise ProfileValidationError("agent_card.security: expected a JSON object")
        authn = security.get("authentication")
        if authn is not None:
            if not isinstance(authn, dict):
                raise ProfileValidationError("agent_card.security.authentication: expected a JSON object")
            if "schemes" in authn and authn["schemes"] is not None:
                require_list_of_str(authn, "schemes", "agent_card.security.authentication")
            get_optional_str(authn, "credentials", "agent_card.security.authentication")
        authz = security.get("authorization")
        if authz is not None and not isinstance(authz, dict):
            raise ProfileValidationError("agent_card.security.authorization: expected a JSON object")

    # ── Authority sub-validator (§17.2) ──────────────────────────────────

    def _validate_authority(self, card: dict[str, Any], canonical: str) -> None:
        """Require declared identity/endpoint URLs to live on *canonical*.

        ``security.authentication.credentials`` is deliberately NOT
        domain-enforced: it is an OAuth token endpoint that MAY be delegated
        to an external identity provider, it is never a routing target, and it
        is never projected.  It is still validated as an http(s) URL at the
        schema stage and is scanned for embedded secrets.
        """
        url = card.get("url")
        if isinstance(url, str):
            assert_same_domain(url, canonical, "agent_card.url")
        documentation_url = card.get("documentationUrl")
        if isinstance(documentation_url, str) and is_http_url(documentation_url):
            assert_same_domain(documentation_url, canonical, "agent_card.documentationUrl")
        provider = card.get("provider")
        if isinstance(provider, dict):
            provider_url = provider.get("url")
            if isinstance(provider_url, str) and is_http_url(provider_url):
                assert_same_domain(provider_url, canonical, "agent_card.provider.url")


# ── Public-field projection (§3.4) ──────────────────────────────────────────


def _project_public(card: dict[str, Any], secret_paths: frozenset[str]) -> dict[str, Any]:
    """Project a validated Agent Card down to §3.4 public fields.

    The ``security`` block is never projected (auth metadata is private), and
    any field that the §17.3 scan flagged is excluded.
    """
    public: dict[str, Any] = {}

    def _skip(path: str) -> bool:
        """True when *path* itself or any descendant is a quarantined secret."""
        if path in secret_paths:
            return True
        return any(p.startswith(path + ".") for p in secret_paths)

    for key in ("name", "url", "version", "description", "documentationUrl"):
        if key in card and card[key] is not None and not _skip(key):
            public[key] = card[key]

    provider = card.get("provider")
    if isinstance(provider, dict):
        projected_provider: dict[str, Any] = {}
        for key in ("organization", "url"):
            if key in provider and provider[key] is not None and not _skip(f"provider.{key}"):
                projected_provider[key] = provider[key]
        if projected_provider:
            public["provider"] = projected_provider

    skills = card.get("skills")
    if isinstance(skills, list):
        projected_skills: list[dict[str, Any]] = []
        for i, skill in enumerate(skills):
            if not isinstance(skill, dict):
                continue
            projected_skill: dict[str, Any] = {}
            base = f"skills.{i}"
            for key in ("id", "name", "description"):
                if key in skill and skill[key] is not None and not _skip(f"{base}.{key}"):
                    projected_skill[key] = skill[key]
            for key in ("tags", "examples", "inputModes", "outputModes"):
                if isinstance(skill.get(key), list) and not _skip(f"{base}.{key}"):
                    projected_skill[key] = list(skill[key])
            if projected_skill:
                projected_skills.append(projected_skill)
        if projected_skills:
            public["skills"] = projected_skills

    caps = card.get("capabilities")
    if isinstance(caps, dict):
        projected_caps: dict[str, Any] = {}
        for key in ("streaming", "pushNotifications", "stateTransitionHistory"):
            if key in caps and isinstance(caps[key], bool) and not _skip(f"capabilities.{key}"):
                projected_caps[key] = caps[key]
        if projected_caps:
            public["capabilities"] = projected_caps

    for key in ("defaultInputModes", "defaultOutputModes"):
        if isinstance(card.get(key), list) and not _skip(key):
            public[key] = list(card[key])

    agents = card.get("agents")
    if isinstance(agents, dict) and isinstance(agents.get("author"), list) and not _skip("agents.author"):
        public["agents"] = {"author": [str(a) for a in agents["author"]]}

    return public


def parse_agent_card(parsed: Any, *, source_url: str, policy: TrustPolicy | None = None) -> AgentCardResult:
    """Convenience wrapper that constructs a default parser and runs it."""
    return AgentCardParser(policy).parse(parsed, source_url=source_url)
