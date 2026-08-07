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

import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from kiwi_catalog.agent_catalog.state_domains import InvalidStateTransitionError  # noqa: F401 (re-export)
from kiwi_catalog.core.errors import ShoppingCliError
from kiwi_catalog.discovery._validation import canonical_domain_of, is_http_url, is_same_authority
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
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


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
    WELL_KNOWN_PATHS: dict[str, str] = {
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
        claimed = self._claimed_knp_versions(ucp)
        if claimed:
            allowed = set(self._policy.allowed_knp_versions)
            if not allowed:
                return _failed_evidence(
                    "commerce_capability",
                    "KNP is claimed but the TrustPolicy allows no KNP versions",
                    details,
                )
            if not claimed.keys() <= allowed:
                return _failed_evidence(
                    "commerce_capability",
                    f"claimed KNP versions {sorted(claimed)} exceed allowed {sorted(allowed)}",
                    details,
                )
            details["knp_versions"] = sorted(claimed)

        return VerificationEvidence(
            verification_type="commerce_capability", result="passed", details=details
        )

    @staticmethod
    def _claimed_knp_versions(ucp: UcpProfileResult) -> dict[str, str]:
        """Return {knp_version: endpoint_uri} for KNP-protocol endpoints."""
        claimed: dict[str, str] = {}
        services = ucp.public.get("services")
        if not isinstance(services, list):
            return claimed
        for service in services:
            if not isinstance(service, dict):
                continue
            endpoints = service.get("endpoints")
            if not isinstance(endpoints, list):
                continue
            for endpoint in endpoints:
                if not isinstance(endpoint, dict):
                    continue
                protocol = str(endpoint.get("protocol", "")).lower()
                if protocol in ("knp", "kiwi-negotiation", "kiwi_negotiation"):
                    version = str(endpoint.get("version", "")).strip() or "unspecified"
                    claimed.setdefault(version, str(endpoint.get("uri", "")))
        return claimed


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
