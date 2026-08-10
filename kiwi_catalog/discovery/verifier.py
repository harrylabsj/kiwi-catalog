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

"""Verification state machine, domain control, and trust evaluation.

Design: docs/shopping-cli-a2a-upgrade-design-v1.2.1.md §6, §6.1, §6.2, §7

This module is the PURE core of the verification pipeline.  It holds:

* the explicit verification state machine (§6) — every allowed transition
  is enumerated so an illegal jump (e.g. DISCOVERED straight to
  COMMERCE_VERIFIED) is rejected;
* the HTTPS domain-control verifier (§6 MVP identity mechanism);
* the trust evaluator that applies the later ladder stages
  (agent identity threshold + commerce capability intersection).

It performs NO persistence and NO audit writes — the service layer
(``services/agent_verification.py``) orchestrates those.  The only outbound
network dependency is the SSRF-safe ``ProfileFetcher`` (W1), injected here.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, ClassVar

from kiwi_catalog.agent_catalog.state_domains import InvalidStateTransitionError
from kiwi_catalog.discovery._validation import (
    canonical_domain_of,
    is_http_url,
    is_same_authority,
)
from kiwi_catalog.discovery.agent_card import AgentCardResult
from kiwi_catalog.discovery.fetcher import FetchError, ProfileFetcher, SSRFBlockError
from kiwi_catalog.discovery.trust import TrustPolicy
from kiwi_catalog.discovery.ucp import UcpProfileResult

# ── Verification status values (mirror catalog_agents.verification_status) ──

DISCOVERED = "discovered"
PROFILE_VALID = "profile_valid"
DOMAIN_VERIFIED = "domain_verified"
AGENT_VERIFIED = "agent_verified"
COMMERCE_VERIFIED = "commerce_verified"
STALE = "stale"
REJECTED = "rejected"
SUSPENDED = "suspended"
UNREACHABLE = "unreachable"

# The promotion ladder (§6).  Verification only ever advances one rung at a
# time; re-verification may re-enter the ladder from STALE/UNREACHABLE.
_LADDER: tuple[str, ...] = (
    DISCOVERED,
    PROFILE_VALID,
    DOMAIN_VERIFIED,
    AGENT_VERIFIED,
    COMMERCE_VERIFIED,
)
_LADDER_INDEX: dict[str, int] = {state: i for i, state in enumerate(_LADDER)}

# Terminal states — no automatic outgoing transitions.
TERMINAL_STATES: frozenset[str] = frozenset({REJECTED, SUSPENDED})


def ladder_index(state: str) -> int:
    """Return the position of *state* on the promotion ladder, or -1."""
    return _LADDER_INDEX.get(state, -1)


# ── Kiwi Negotiation Protocol (KNP) markers ─────────────────────────────────
# Single source for what counts as a KNP claim (审查 P1-04)：endpoint protocol
# 或 capability namespace 命中即 KNP claim——endpoint protocol 写成 ``a2a``
# 不能用来绕过 KNP 治理。
_KNP_PROTOCOLS = frozenset({"knp", "kiwi-negotiation", "kiwi_negotiation"})
_KNP_IDENTIFIER_SEP_RE = re.compile(r"[:./_-]+")


def _capability_declares_kiwi_negotiation(capability: str) -> bool:
    """True when a capability identifier denotes Kiwi negotiation (KNP).

    Matches normalized tokens of the fully-qualified id: ``knp`` alone, or
    the pair ``kiwi`` + ``negotiation`` (e.g. ``kiwi.negotiation``,
    ``com.kiwi:negotiation``, ``urn:kiwi:negotiation``).  A capability
    namespace declaration counts as a KNP claim regardless of the service
    endpoint protocol written in the profile (§P1-04).
    """
    tokens = set(_KNP_IDENTIFIER_SEP_RE.split(str(capability or "").lower()))
    return "knp" in tokens or ({"kiwi", "negotiation"} <= tokens)


# ── Explicit transition table (§6) ──────────────────────────────────────────
# Every (from, to) pair that the pipeline is permitted to persist.  Anything
# not listed raises InvalidStateTransitionError (fail-closed).
_ALL_TRANSITIONS: dict[str, frozenset[str]] = {
    DISCOVERED: frozenset({DISCOVERED, PROFILE_VALID, REJECTED, UNREACHABLE, STALE, SUSPENDED}),
    PROFILE_VALID: frozenset({PROFILE_VALID, DOMAIN_VERIFIED, REJECTED, UNREACHABLE, STALE, SUSPENDED}),
    DOMAIN_VERIFIED: frozenset({DOMAIN_VERIFIED, AGENT_VERIFIED, REJECTED, UNREACHABLE, STALE, SUSPENDED}),
    AGENT_VERIFIED: frozenset({AGENT_VERIFIED, COMMERCE_VERIFIED, REJECTED, UNREACHABLE, STALE, SUSPENDED}),
    COMMERCE_VERIFIED: frozenset({COMMERCE_VERIFIED, REJECTED, UNREACHABLE, STALE, SUSPENDED}),
    # Re-verification entry points: a stale or unreachable agent may recover
    # to any ladder rung, or fail again.
    STALE: frozenset(_LADDER) | {REJECTED, UNREACHABLE, STALE, SUSPENDED},
    UNREACHABLE: frozenset(_LADDER) | {REJECTED, UNREACHABLE, STALE, SUSPENDED},
    REJECTED: frozenset(),
    # The only exit from SUSPENDED is an explicit operator reinstate, which
    # resets the agent to the DISCOVERED entry point (v3.0 moderation / P2).
    # Automatic pipelines (refresh / verify / staleness) never leave SUSPENDED.
    SUSPENDED: frozenset({DISCOVERED}),
}





@dataclass(frozen=True)
class VerificationStateMachine:
    """Explicit, testable verification state machine (§6)."""

    transitions: Mapping[str, frozenset[str]] = field(default_factory=lambda: dict(_ALL_TRANSITIONS))

    def can_transition(self, current: str, target: str) -> bool:
        """True when *current* -> *target* is a permitted transition."""
        return target in self.transitions.get(current, frozenset())

    def transition(self, current: str, target: str) -> str:
        """Validate and return *target*, or raise InvalidStateTransitionError.

        Raises:
            InvalidStateTransitionError: the pair is not in the §6 table.
        """
        if not self.can_transition(current, target):
            raise InvalidStateTransitionError(
                f"illegal verification status transition {current!r} -> {target!r}"
            )
        return target

    def is_terminal(self, state: str) -> bool:
        """True when *state* has no automatic outgoing transitions."""
        return state in TERMINAL_STATES


# ── Evidence ────────────────────────────────────────────────────────────────


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).isoformat()


@dataclass(frozen=True)
class VerificationEvidence:
    """Result of one verification check, ready for ``agent_verifications``.

    The service layer writes ``checked_at``/``expires_at`` (ISO) from the
    *now* function and records ``trust_policy_version`` in the evidence JSON.
    """

    verification_type: str
    result: str  # "passed" | "failed"
    reason: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    expires_in_seconds: int = 86400  # default freshness window (24 h)

    @property
    def passed(self) -> bool:
        return self.result == "passed"


# ── HTTPS domain-control verification (§6) ──────────────────────────────────


class IdentityVerifier:
    """Prove HTTPS domain control over a catalog agent's canonical domain.

    MVP identity mechanism (design §6): the domain must serve the standard
    A2A/UCP well-known locations over HTTPS, and the declared profile URLs
    must live on that same domain.  redirect/DNS/certificate/SSRF policy are
    enforced by the injected ``ProfileFetcher`` (W1), so this verifier only
    needs to drive it and interpret the results.
    """

    # Standard discovery locations served from the domain root.
    WELL_KNOWN_PATHS: ClassVar[dict[str, str]] = {
        "agent_card": ".well-known/agent-card.json",
        "ucp": ".well-known/ucp",
    }

    def __init__(self, fetcher: ProfileFetcher, policy: TrustPolicy) -> None:
        self._fetcher = fetcher
        self._policy = policy

    def verify_domain_control(
        self,
        canonical_domain: str,
        *,
        declared: Mapping[str, str],
    ) -> VerificationEvidence:
        """Verify that *canonical_domain* controls its well-known locations.

        Args:
            canonical_domain: the agent's canonical domain (lowercase host).
            declared: mapping of profile kind -> declared URL (agent_card, ucp).

        Returns:
            ``VerificationEvidence`` with ``result == "passed"`` when HTTPS
            domain control is proven.
        """
        details: dict[str, Any] = {
            "method": "https_domain_control",
            "domain_control_method": self._policy.domain_control_method,
            "canonical_domain": canonical_domain,
        }

        # 1. Declared profile URLs must be HTTPS and hosted under the domain.
        for kind, url in declared.items():
            if not is_http_url(url):
                return _failed_evidence(
                    "domain_control", f"{kind} declared URL is not an http(s) URL: {url!r}", details
                )
            host = canonical_domain_of(url)
            if not is_same_authority(host, canonical_domain):
                return _failed_evidence(
                    "domain_control",
                    f"{kind} declared host '{host}' is not under canonical domain '{canonical_domain}'",
                    details,
                )
            if self._policy.require_https and urllib.parse.urlparse(url).scheme != "https":
                return _failed_evidence(
                    "domain_control", f"{kind} declared URL must be HTTPS: {url!r}", details
                )
        details["declared_urls"] = dict(declared)

        # 2. The domain must serve the standard well-known locations over HTTPS.
        well_known: dict[str, str] = {}
        statuses: dict[str, int] = {}
        for kind, path in self.WELL_KNOWN_PATHS.items():
            wk_url = f"https://{canonical_domain}/{path}"
            well_known[kind] = wk_url
            try:
                result = self._fetcher.fetch(wk_url)
            except (FetchError, SSRFBlockError) as exc:
                return _failed_evidence(
                    "domain_control",
                    f"well-known fetch failed for {kind} at {wk_url}: {exc}",
                    {**details, "well_known": well_known, "statuses": statuses},
                )
            statuses[kind] = result.status_code
            if not result.is_success:
                return _failed_evidence(
                    "domain_control",
                    f"well-known location {wk_url} returned HTTP {result.status_code}",
                    {**details, "well_known": well_known, "statuses": statuses},
                )
        details["well_known"] = well_known
        details["statuses"] = statuses

        return VerificationEvidence(verification_type="domain_control", result="passed", details=details)


# ── Trust evaluation (later ladder stages) ──────────────────────────────────


class TrustEvaluator:
    """Apply the AGENT_VERIFIED / COMMERCE_VERIFIED criteria (§6)."""

    def __init__(self, policy: TrustPolicy) -> None:
        self._policy = policy

    def evaluate_agent_identity(
        self,
        card: AgentCardResult,
        ucp: UcpProfileResult,
        canonical_domain: str,
    ) -> VerificationEvidence:
        """Agent identity threshold (MVP).

        With HTTPS domain control as the only identity mechanism, the agent
        is ``AGENT_VERIFIED`` when the validated profiles self-consistently
        bind their identity to the verified domain: the Agent Card's canonical
        ``url`` and (when present) the UCP ``serviceIdentity.id`` resolve to
        HTTPS endpoints on ``canonical_domain``.  A card that points its
        identity elsewhere is not bound to the controlled domain.
        """
        details: dict[str, Any] = {
            "method": "identity_binding",
            "canonical_domain": canonical_domain,
            "agent_card_name": card.name,
        }

        card_url = card.public.get("url") if isinstance(card.public, dict) else None
        if not isinstance(card_url, str) or not is_http_url(card_url):
            return _failed_evidence(
                "agent_identity", "agent card url is not an http(s) URL", details
            )
        if not is_same_authority(canonical_domain_of(card_url), canonical_domain):
            return _failed_evidence(
                "agent_identity",
                f"agent card identity url host '{canonical_domain_of(card_url)}' "
                f"is not under '{canonical_domain}'",
                details,
            )
        if self._policy.require_https and urllib.parse.urlparse(card_url).scheme != "https":
            return _failed_evidence(
                "agent_identity", f"agent card identity url must be HTTPS: {card_url!r}", details
            )

        # UCP service identity, when it is an http(s) URL, must bind to the same domain.
        service_identity = ucp.public.get("serviceIdentity")
        if isinstance(service_identity, dict):
            ucp_id = service_identity.get("id")
            if isinstance(ucp_id, str) and is_http_url(ucp_id):
                if not is_same_authority(canonical_domain_of(ucp_id), canonical_domain):
                    return _failed_evidence(
                        "agent_identity",
                        f"ucp serviceIdentity.id host '{canonical_domain_of(ucp_id)}' "
                        f"is not under '{canonical_domain}'",
                        details,
                    )
                if self._policy.require_https and urllib.parse.urlparse(ucp_id).scheme != "https":
                    return _failed_evidence(
                        "agent_identity",
                        f"ucp serviceIdentity.id must be HTTPS: {ucp_id!r}",
                        details,
                    )

        details["agent_card_url"] = card_url
        details["identity_binding"] = "canonical_domain"
        return VerificationEvidence(verification_type="agent_identity", result="passed", details=details)

    def evaluate_commerce_capabilities(
        self,
        card: AgentCardResult,
        ucp: UcpProfileResult,
        canonical_domain: str,
    ) -> VerificationEvidence:
        """Commerce capability intersection for COMMERCE_VERIFIED (§6).

        Requires both profiles validated, at least one commerce capability
        with a well-formed namespace, and — when KNP is claimed — that every
        claimed KNP version is accepted by the active TrustPolicy.
        """
        details: dict[str, Any] = {
            "method": "commerce_capability_intersection",
            "canonical_domain": canonical_domain,
            "a2a_version": card.version,
            "ucp_version": ucp.specification_version,
        }

        # Protocol/version intersection (parse already enforced these, re-asserted
        # so the evidence row is self-explanatory).
        if card.version not in self._policy.allowed_a2a_versions:
            return _failed_evidence(
                "commerce_capability",
                f"A2A version {card.version!r} is not allowed by TrustPolicy",
                details,
            )
        if ucp.specification_version not in self._policy.allowed_ucp_versions:
            return _failed_evidence(
                "commerce_capability",
                f"UCP version {ucp.specification_version!r} is not allowed by TrustPolicy",
                details,
            )

        # Capability namespace validation: at least one commerce capability and
        # every capability carries a well-formed (non-empty) namespace.
        capabilities = list(card.capabilities) + list(ucp.capabilities)
        commerce = [c for c in capabilities if c.get("namespace") not in ("a2a", "ucp")]
        if not commerce:
            return _failed_evidence(
                "commerce_capability", "no commerce capabilities declared in profiles", details
            )
        bad_namespace = [c for c in capabilities if not c.get("namespace")]
        if bad_namespace:
            return _failed_evidence(
                "commerce_capability", "capability without a namespace", details
            )
        details["capability_count"] = len(capabilities)
        details["commerce_capability_count"] = len(commerce)

        # Kiwi/KNP compatibility when claimed (§6 COMMERCE_VERIFIED bullet).
        # 审查 P1-04：capability namespace 声明的 Kiwi negotiation 也是 KNP
        # claim（endpoint protocol 写 a2a 不能绕过）；KNP claim 的
        # version / allowlist / spec / schema 缺任一项不得 COMMERCE_VERIFIED。
        knp_claims = self._knp_claims(ucp)
        if knp_claims:
            allowed = set(self._policy.allowed_knp_versions)
            for claim in knp_claims:
                source = str(claim.get("source") or "")
                if not claim.get("version"):
                    return _failed_evidence(
                        "commerce_capability",
                        "KNP claim is missing a declared version",
                        {**details, "knp_claim_source": source},
                    )
                if not allowed:
                    return _failed_evidence(
                        "commerce_capability",
                        "KNP is claimed but the TrustPolicy allows no KNP versions",
                        {**details, "knp_claim_source": source},
                    )
                if claim["version"] not in allowed:
                    return _failed_evidence(
                        "commerce_capability",
                        f"claimed KNP version {claim['version']} is not allowed "
                        f"(allowed: {sorted(allowed)})",
                        {**details, "knp_claim_source": source},
                    )
                if not claim.get("has_spec") or not claim.get("has_schema"):
                    return _failed_evidence(
                        "commerce_capability",
                        "KNP claim is missing a specification/schema reference",
                        {**details, "knp_claim_source": source},
                    )
            details["knp_versions"] = sorted({c["version"] for c in knp_claims})

        return VerificationEvidence(
            verification_type="commerce_capability", result="passed", details=details
        )

    def _knp_claims(self, ucp: UcpProfileResult) -> list[dict[str, Any]]:
        """KNP claims declared by the UCP profile (§P1-04).

        每个声明携带：claimed ``version``、是否带 spec（KNP spec 条目带非空
        ``specUrl``）、是否带 schema（service.documentationUri、顶层
        openAPIDocument 或 KNP spec 条目的 ``schemaUrl``）、以及
        ``source``（endpoint_protocol / capability_namespace）。capability
        namespace 的 Kiwi negotiation 声明即使 service endpoint protocol 写成
        ``a2a`` 也计入——协议写法不能用来绕过 KNP 治理。
        """
        services = ucp.public.get("services")
        if not isinstance(services, list):
            return []
        top_level_specs = ucp.public.get("specifications")
        has_top_schema = any(
            isinstance(sp, dict) and str(sp.get("openAPIDocument") or "").strip()
            for sp in (top_level_specs if isinstance(top_level_specs, list) else [])
        )
        claims: list[dict[str, Any]] = []
        for service in services:
            if not isinstance(service, dict):
                continue
            endpoints = service.get("endpoints")
            capabilities = service.get("capabilities")
            endpoints = endpoints if isinstance(endpoints, list) else []
            capabilities = capabilities if isinstance(capabilities, list) else []
            knp_endpoints = [
                e
                for e in endpoints
                if isinstance(e, dict) and str(e.get("protocol", "")).lower() in _KNP_PROTOCOLS
            ]
            kiwi_caps = [
                c
                for c in capabilities
                if isinstance(c, str) and _capability_declares_kiwi_negotiation(c)
            ]
            if not knp_endpoints and not kiwi_caps:
                continue
            versions: set[str] = set()
            for e in knp_endpoints:
                v = str(e.get("version", "")).strip()
                if v:
                    versions.add(v)
            specs = service.get("specifications")
            specs = specs if isinstance(specs, list) else []
            # KNP 相关的 spec 条目：id 本身声明 Kiwi negotiation（canonical 适配
            # 器把每 capability 的 version/spec/schema 注入其 id 为 capability id
            # 的 specifications 条目）——非 KNP capability 的 spec 版本不得计入
            # KNP 版本集合（否则 checkout 等能力的版本会污染 allowlist 校验）。
            knp_specs = [
                sp
                for sp in specs
                if isinstance(sp, dict)
                and _capability_declares_kiwi_negotiation(str(sp.get("id") or ""))
            ]
            for sp in knp_specs:
                v = str(sp.get("version", "")).strip()
                if v:
                    versions.add(v)
            # spec 引用必须是真实的 specification 指针（KNP spec 条目带非空
            # specUrl）——仅有 KNP 声明（endpoint/capability/id-only spec 条目）
            # 不算 spec 引用，否则无 specUrl 的声明可绕过治理（审查 P1-04）。
            has_spec = any(str(sp.get("specUrl") or "").strip() for sp in knp_specs)
            has_schema = (
                has_top_schema
                or bool(str(service.get("documentationUri") or "").strip())
                or any(str(sp.get("schemaUrl") or "").strip() for sp in knp_specs)
            )
            source = "+".join(
                filter(
                    None,
                    [
                        "endpoint_protocol" if knp_endpoints else "",
                        "capability_namespace" if kiwi_caps else "",
                    ],
                )
            )
            for version in versions or {""}:
                claims.append(
                    {
                        "version": version,
                        "has_spec": has_spec,
                        "has_schema": has_schema,
                        "source": source,
                    }
                )
        return claims


# ── Internal helper ─────────────────────────────────────────────────────────


def _failed_evidence(
    verification_type: str,
    reason: str,
    details: dict[str, Any],
) -> VerificationEvidence:
    return VerificationEvidence(
        verification_type=verification_type,
        result="failed",
        reason=reason,
        details=dict(details),
    )
