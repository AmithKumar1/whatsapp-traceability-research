from opentrace.protocols.hts2025 import HopTrackingSignatures2025Synthetic


def test_hts_source_recovery_is_only_eligible_at_trace_threshold():
    model = HopTrackingSignatures2025Synthetic(anonymity_threshold_hops=2, trace_threshold_hops=4)
    before = model.evaluate(b"synthetic-message", 3)
    at_threshold = model.evaluate(b"synthetic-message", 4)
    assert before.source_recovered is False
    assert at_threshold.source_recovered is True
    assert before.disclosed_forwarders == at_threshold.disclosed_forwarders == 0
    assert before.interoperable_with_reference is False


def test_hts_threshold_gap_model_is_explicitly_didactic():
    gap_one = HopTrackingSignatures2025Synthetic(anonymity_threshold_hops=2, trace_threshold_hops=3)
    gap_two = HopTrackingSignatures2025Synthetic(anonymity_threshold_hops=2, trace_threshold_hops=4)
    assert "gap_one" in gap_one.evaluate(b"x", 5).succinctness_result_from_paper_model
    assert gap_one.evaluate(b"x", 8).didactic_payload_size_proxy_bytes > gap_one.evaluate(b"x", 4).didactic_payload_size_proxy_bytes
    assert "gap_at_least_two" in gap_two.evaluate(b"x", 8).succinctness_result_from_paper_model
    assert gap_two.evaluate(b"x", 8).didactic_payload_size_proxy_bytes == gap_two.evaluate(b"x", 4).didactic_payload_size_proxy_bytes


def test_hts_rejects_inconsistent_thresholds_and_bounds_hops():
    try:
        HopTrackingSignatures2025Synthetic(anonymity_threshold_hops=4, trace_threshold_hops=4)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid thresholds should fail")
    model = HopTrackingSignatures2025Synthetic()
    try:
        model.evaluate(b"x", -1)
    except ValueError:
        pass
    else:
        raise AssertionError("negative hop count should fail")
