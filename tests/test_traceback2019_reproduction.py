"""Automated test suite for the faithful cryptographic reproduction of Tyagi et al. (CCS 2019)."""
from __future__ import annotations

import json
from pathlib import Path
import jsonschema

from opentrace.protocols.traceback2019_crypto import (
    CryptographicTracebackServer,
    DeviceIdentity,
    _aes_ctr,
    _crprf,
    forward_message,
    originate_message,
)
from opentrace.traceback_experiment import run_experiment, experiment_markdown, SCHEMA_NAME


def test_crypto_primitives_invertible_and_deterministic() -> None:
    ptr1 = b"0123456789abcdef"
    ptr2 = b"fedcba9876543210"
    msg = b"Test message content"

    # CR-PRF determinism
    addr1 = _crprf(ptr1, msg)
    addr2 = _crprf(ptr1, msg)
    assert addr1 == addr2
    assert len(addr1) == 32
    assert _crprf(ptr1, b"different") != addr1

    # AES-CTR pointer encryption round-trip
    ct = _aes_ctr(ptr1, ptr2)
    assert ct != ptr2
    decrypted = _aes_ctr(ptr1, ct)
    assert decrypted == ptr2


def test_valid_path_traceback_reaches_origin_across_hops() -> None:
    for hops in (1, 2, 4, 7):
        report = run_experiment(hops=hops, scenario="valid_linear_path")
        result = report["traceback_result"]
        assert result["outcome"] == "SUCCESS"
        assert result["origin_reached"] is True
        assert result["recovered_origin_account"] == "acct:alice"
        assert result["recovered_origin_device"] == "dev:alice-primary"
        assert result["recovered_hops_count"] == hops
        assert result["termination_reason"] == "origin_reached_successfully"
        assert len(result["verified_hops"]) == hops


def test_framing_resistance_detects_forged_signature() -> None:
    report = run_experiment(hops=4, scenario="forged_signature", adversarial_hop=2)
    result = report["traceback_result"]
    assert result["outcome"] == "FAILED_VERIFICATION"
    assert result["origin_reached"] is False
    assert result["termination_reason"] == "forged_sender_signature_detected"
    assert any(h["status"] == "signature_verification_failed_framing_blocked" for h in result["verified_hops"])


def test_wrong_message_terminates_at_tampered_node() -> None:
    report = run_experiment(hops=4, scenario="tampered_content", adversarial_hop=2)
    result = report["traceback_result"]
    assert result["outcome"] == "TERMINATED_EARLY"
    assert result["origin_reached"] is False
    assert result["termination_reason"] == "missing_forwarding_record_in_server_state"


def test_broken_chain_reports_limitation_without_phantom_edges() -> None:
    report = run_experiment(hops=4, scenario="missing_hop", adversarial_hop=2)
    result = report["traceback_result"]
    assert result["outcome"] == "TERMINATED_EARLY"
    assert result["origin_reached"] is False
    # Traceback should only have traversed hops up to the missing link, not hallucinated
    assert result["recovered_hops_count"] < 4
    assert result["termination_reason"] == "missing_forwarding_record_in_server_state"


def test_epistemic_distinctions_and_schema_conformance() -> None:
    report = run_experiment(hops=3, scenario="valid_linear_path")
    epistemic = report["epistemic_notice"]
    assert "device cryptographic credentials" in epistemic["account_vs_device_distinction"]
    assert "does not establish the legal identity" in epistemic["real_world_identity_limitation"]
    assert "does not synthesize phantom hops" in epistemic["no_unrecorded_history_inference"]

    schema_path = Path(__file__).resolve().parents[1] / "schemas" / SCHEMA_NAME
    schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.validate(report, schema_data)

    md = experiment_markdown(report)
    assert "# Cryptographic Reproduction Report: Tyagi et al. (CCS 2019)" in md
    assert "Epistemic Limitations" in md
    assert "Verified Hop Sequence" in md


def test_deterministic_reproduction_test_vector() -> None:
    # Deterministic test using fixed keys
    alice = DeviceIdentity.generate("acct:test-alice", "dev:test-alice-01")
    bob = DeviceIdentity.generate("acct:test-bob", "dev:test-bob-01")
    server = CryptographicTracebackServer()

    msg = b"Deterministic RFC test message"
    ptr_origin = originate_message()

    next_ptr, tag = forward_message(
        server=server,
        sender=alice,
        receiver_account=bob.account_id,
        receiver_device=bob.device_id,
        incoming_pointer=ptr_origin,
        message=msg,
    )

    assert len(tag.addr) == 32
    assert len(tag.ct) == 16
    assert len(tag.signature) == 64

    # Bob reports the message
    trace_res = server.trace(
        message=msg,
        reporting_account=bob.account_id,
        reporting_device=bob.device_id,
        reporting_pointer=next_ptr,
    )

    assert trace_res.origin_reached is True
    assert trace_res.recovered_origin_account == "acct:test-alice"
    assert trace_res.recovered_origin_device == "dev:test-alice-01"
    assert len(trace_res.verified_hops) == 1
    assert trace_res.verified_hops[0].signature_valid is True
