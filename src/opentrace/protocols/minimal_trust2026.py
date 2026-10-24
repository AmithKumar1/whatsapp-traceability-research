"""Policy-gate simulation for 2026 minimal-trust traceability research.

This module is a conceptual policy model, not the cryptographic protocol in
Wang et al. It evaluates the combination of multiple verified reports, a
regulator blocklist match, moderator approval, and a platform release gate.
It does not implement secret sharing, anonymous credentials, Signal protocols,
cryptographic report shares, or the paper's security proof.

Reference: Wang et al., "Abuse Resistant Traceability with Minimal Trust for
Encrypted Messaging Systems," NDSS 2026, DOI 10.14722/ndss.2026.240456.
https://www.ndss-symposium.org/ndss-paper/abuse-resistant-traceability-with-minimal-trust-for-encrypted-messaging-systems/
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

TrustedRole = Literal["platform", "regulator", "moderator", "recipient"]
VALID_ROLES: tuple[TrustedRole, ...] = ("platform", "regulator", "moderator", "recipient")


@dataclass(frozen=True)
class TraceDecision:
    protocol: str
    trace_allowed: bool
    source_account: str | None
    verified_distinct_reports: int
    required_reports: int
    regulator_blocklist_match: bool
    moderator_approved: bool
    platform_release_authorized: bool
    failed_gates: tuple[str, ...]
    disclosed_forwarders: int = 0
    interoperable_with_reference: bool = False

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class MinimalTrustTraceability2026Synthetic:
    """Four-gate policy simulator representing the paper's high-level workflow."""

    protocol_id = "minimal-trust-2026-synthetic"
    reference_status = "synthetic"

    def assess_trace(
        self,
        *,
        source_account: str,
        verified_distinct_reports: int,
        required_reports: int = 3,
        regulator_blocklist_match: bool,
        moderator_approved: bool,
        platform_release_authorized: bool = True,
    ) -> TraceDecision:
        if not source_account or not source_account.strip():
            raise ValueError("source_account must be a non-empty synthetic identifier")
        if required_reports < 1:
            raise ValueError("required_reports must be at least 1")
        if verified_distinct_reports < 0:
            raise ValueError("verified_distinct_reports must be non-negative")

        failed: list[str] = []
        if verified_distinct_reports < required_reports:
            failed.append("report_threshold_not_met")
        if not regulator_blocklist_match:
            failed.append("regulator_blocklist_match_missing")
        if not moderator_approved:
            failed.append("moderator_approval_missing")
        if not platform_release_authorized:
            failed.append("platform_release_not_authorized")
        allowed = not failed
        return TraceDecision(
            protocol=self.protocol_id,
            trace_allowed=allowed,
            source_account=source_account if allowed else None,
            verified_distinct_reports=verified_distinct_reports,
            required_reports=required_reports,
            regulator_blocklist_match=regulator_blocklist_match,
            moderator_approved=moderator_approved,
            platform_release_authorized=platform_release_authorized,
            failed_gates=tuple(failed),
        )

    def single_honest_role_scenarios(self, *, required_reports: int = 3) -> list[dict[str, Any]]:
        """Demonstrate gates that block an innocent-message trace in this model.

        The assumptions below are supplied by the simulation; they are not
        cryptographically enforced and do not constitute a security proof.
        """
        if required_reports < 2:
            raise ValueError("required_reports must be at least 2 for the recipient scenario")
        decisions: list[dict[str, Any]] = []
        for role in VALID_ROLES:
            gates: dict[str, Any] = {
                "source_account": "synthetic-innocent-origin",
                "verified_distinct_reports": required_reports,
                "required_reports": required_reports,
                "regulator_blocklist_match": True,
                "moderator_approved": True,
                "platform_release_authorized": True,
            }
            # For each row, model the one honest actor applying its own control.
            if role == "platform":
                gates["platform_release_authorized"] = False
            elif role == "regulator":
                gates["regulator_blocklist_match"] = False
            elif role == "moderator":
                gates["moderator_approved"] = False
            elif role == "recipient":
                # Honest recipients contribute one verified report each; the
                # simulated adversary cannot inflate the count with duplicates.
                gates["verified_distinct_reports"] = required_reports - 1
            decision = self.assess_trace(**gates)
            decisions.append({
                "sole_honest_role": role,
                "innocent_message_trace_blocked": not decision.trace_allowed,
                "failed_gates": list(decision.failed_gates),
                "model_caveat": "illustrative policy simulation; not a cryptographic or formal security guarantee",
            })
        return decisions
