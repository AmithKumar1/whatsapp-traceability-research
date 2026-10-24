from __future__ import annotations

from opentrace.protocols.minimal_trust2026 import MinimalTrustTraceability2026Synthetic


def test_trace_requires_all_four_policy_gates():
    model = MinimalTrustTraceability2026Synthetic()
    allowed = model.assess_trace(
        source_account="synthetic-origin",
        verified_distinct_reports=3,
        required_reports=3,
        regulator_blocklist_match=True,
        moderator_approved=True,
        platform_release_authorized=True,
    )
    assert allowed.trace_allowed is True
    assert allowed.source_account == "synthetic-origin"

    blocked = model.assess_trace(
        source_account="synthetic-origin",
        verified_distinct_reports=3,
        required_reports=3,
        regulator_blocklist_match=False,
        moderator_approved=True,
        platform_release_authorized=True,
    )
    assert blocked.trace_allowed is False
    assert blocked.source_account is None
    assert blocked.failed_gates == ("regulator_blocklist_match_missing",)


def test_each_single_honest_role_blocks_innocent_case_in_the_model():
    scenarios = MinimalTrustTraceability2026Synthetic().single_honest_role_scenarios()
    assert {row["sole_honest_role"] for row in scenarios} == {"platform", "regulator", "moderator", "recipient"}
    assert all(row["innocent_message_trace_blocked"] for row in scenarios)
    assert all("not a cryptographic" in row["model_caveat"] for row in scenarios)


def test_report_threshold_and_invalid_inputs():
    model = MinimalTrustTraceability2026Synthetic()
    result = model.assess_trace(
        source_account="synthetic-origin",
        verified_distinct_reports=2,
        required_reports=3,
        regulator_blocklist_match=True,
        moderator_approved=True,
        platform_release_authorized=True,
    )
    assert result.trace_allowed is False
    assert "report_threshold_not_met" in result.failed_gates
    try:
        model.single_honest_role_scenarios(required_reports=1)
    except ValueError:
        pass
    else:
        raise AssertionError("required report threshold should be bounded")
