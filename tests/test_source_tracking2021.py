from opentrace.protocols.source_tracking2021 import SourceTracking2021Synthetic


def test_source_tracking_discloses_source_only():
    p = SourceTracking2021Synthetic(authority_key=b"a" * 32)
    receipt = p.issue_receipt(b"same-message", "acct-origin")
    complaint = p.create_complaint(receipt)
    result = p.trace_source(complaint)
    assert result.source_account == "acct-origin"
    assert result.disclosed_forwarders == 0
    assert result.interoperable_with_reference is False


def test_source_tracking_rejects_tampering():
    p = SourceTracking2021Synthetic(authority_key=b"a" * 32)
    receipt = p.issue_receipt(b"same-message", "acct-origin")
    complaint = p.create_complaint(receipt)
    bad = type(complaint)(complaint.message_digest, b"x" * len(complaint.source_token))
    try:
        p.trace_source(bad)
    except ValueError as exc:
        assert "invalid" in str(exc)
    else:
        raise AssertionError("tampered complaint was accepted")
