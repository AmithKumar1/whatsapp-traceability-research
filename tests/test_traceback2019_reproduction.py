"""Automated test suite for the cryptographic reproduction of Tyagi et al. (CCS 2019)."""
from __future__ import annotations

from typing import Any

import json
from pathlib import Path
import jsonschema
import pytest

from opentrace.protocols.traceback2019_crypto import (
    CryptographicTracebackServer,
    DeviceIdentity,
    DeviceRegistry,
    DuplicateMessageIdentifierError,
    PathPointer,
    RecMsgVerificationError,
    _aes_ctr,
    _crprf,
    _kdf_enc,
    forward_message,
    originate_message,
    rec_msg,
)
from opentrace.traceback_experiment import run_experiment, experiment_markdown, SCHEMA_NAME


def test_crypto_primitives_invertible_and_deterministic() -> None:
    k1 = bytes.fromhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
    k2 = bytes.fromhex("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
    msg = b"Tyagi2019 primitive verification message"

    # CR-PRF determinism
    mid1 = _crprf(k1, msg)
    mid2 = _crprf(k1, msg)
    assert mid1 == mid2
    assert len(mid1) == 32
    assert _crprf(k1, b"different message") != mid1

    # KDF determinism
    enc_key = _kdf_enc(k1)
    assert len(enc_key) == 16
    assert _kdf_enc(k1) == enc_key

    # AES-CTR pointer encryption round-trip
    ct = _aes_ctr(enc_key, k2)
    assert ct != k2
    decrypted = _aes_ctr(enc_key, ct)
    assert decrypted == k2


def test_default_symmetric_mode_without_signatures() -> None:
    """Verifies that ordinary experiments use the paper's symmetric construction by default."""
    report = run_experiment(hops=4, enable_pki_extension=False)
    params = report["parameters"]
    assert "Canonical Symmetric" in params["signature_algorithm"]
    assert "Third-Party Deniable" in params["signature_algorithm"]

    result = report["traceback_result"]
    assert result["outcome"] == "SUCCESS"
    assert result["origin_reached"] is True
    assert result["candidate_origin_account"] == "acct:alice"
    assert result["candidate_origin_device"] == "dev:alice-primary"
    assert result["recovered_origin_account"] == "acct:alice"
    assert result["recovered_origin_device"] == "dev:alice-primary"
    assert result["recovered_hops_count"] == 4
    assert "predecessor_record_absent" in result["termination_reason"]
    for hop in result["verified_hops"]:
        assert hop["signature_valid"] is None
        assert hop["signature_status"] == "N/A"


def test_explicit_opt_in_to_pki_extension() -> None:
    """Verifies that enabling the PKI extension attaches Ed25519 signatures and verifies them."""
    report = run_experiment(hops=3, enable_pki_extension=True)
    params = report["parameters"]
    assert "Experimental PKI Extension" in params["signature_algorithm"]

    result = report["traceback_result"]
    assert result["outcome"] == "SUCCESS"
    assert result["origin_reached"] is True
    assert result["recovered_hops_count"] == 3
    for hop in result["verified_hops"]:
        assert hop["signature_valid"] is True
        assert hop["signature_status"] == "VALID"


def test_missing_registry_fails_closed() -> None:
    """When an extension signature is present, a missing DeviceRegistry MUST fail closed."""
    server = CryptographicTracebackServer()
    alice = DeviceIdentity.generate("acct:alice", "dev:alice-01")
    bob = DeviceIdentity.generate("acct:bob", "dev:bob-01")

    msg = b"Message requiring PKI verification"
    env, rec_state, tag = originate_message(
        server=server,
        sender=alice,
        receiver_account=bob.account_id,
        receiver_device=bob.device_id,
        message=msg,
        attach_extension_signature=True,
    )
    assert env.signature is not None

    # RecMsg fails closed without registry
    with pytest.raises(RecMsgVerificationError, match="failed closed: DeviceRegistry is required"):
        rec_msg(bob.account_id, bob.device_id, env, registry=None)

    # Server trace fails closed without registry
    trace_res = server.trace(
        message=msg,
        reporting_account=bob.account_id,
        reporting_device=bob.device_id,
        reporting_pointer=PathPointer(env.tracing_key),
        registry=None,
    )
    assert trace_res.outcome == "FAILED_VERIFICATION"
    assert trace_res.termination_reason == "missing_trusted_registry_fail_closed"
    assert trace_res.origin_reached is False


def test_unregistered_self_asserted_key_rejected() -> None:
    """Verifies that self-asserted public keys not in DeviceRegistry are rejected."""
    server = CryptographicTracebackServer()
    registry = DeviceRegistry()

    alice = DeviceIdentity.generate("acct:alice", "dev:alice-01")
    bob = DeviceIdentity.generate("acct:bob", "dev:bob-01")
    mallory = DeviceIdentity.generate("acct:mallory", "dev:mallory-01")

    # Only register Alice and Bob in registry
    registry.register(alice.account_id, alice.device_id, alice.public_key_bytes)
    registry.register(bob.account_id, bob.device_id, bob.public_key_bytes)

    msg = b"Spoofing attempt"
    env, rec_alice, tag = originate_message(
        server=server,
        sender=alice,
        receiver_account=bob.account_id,
        receiver_device=bob.device_id,
        message=msg,
        attach_extension_signature=True,
    )
    rec_bob = rec_msg(bob.account_id, bob.device_id, env, registry=registry)

    # Mallory attempts to forward claiming to be Bob, but signing with Mallory's key
    env_spoofed, rec_spoofed, tag_spoofed = forward_message(
        server=server,
        sender=bob,
        receiver_account="acct:charlie",
        receiver_device="dev:charlie-01",
        received_state=rec_bob,
        attach_extension_signature=True,
        adversarial_spoofed_sender=mallory,
    )

    # Recipient rec_msg rejects the unregistered key
    with pytest.raises(RecMsgVerificationError, match="not registered in DeviceRegistry"):
        rec_msg("acct:charlie", "dev:charlie-01", env_spoofed, registry=registry)

    # Server trace also rejects the unregistered key
    trace_res = server.trace(
        message=msg,
        reporting_account="acct:charlie",
        reporting_device="dev:charlie-01",
        reporting_pointer=PathPointer(rec_spoofed.tracing_key),
        registry=registry,
    )
    assert trace_res.outcome == "FAILED_VERIFICATION"
    assert trace_res.termination_reason == "unregistered_self_asserted_key_rejected"
    assert trace_res.origin_reached is False


def test_tampered_content_aborts_forwarding_before_downstream_hops() -> None:
    """Regression test: tampered message must be rejected by recipient and abort forwarding."""
    report = run_experiment(hops=5, scenario="tampered_content", adversarial_hop=2)
    result = report["traceback_result"]

    assert result["outcome"] == "FAILED_VERIFICATION"
    assert result["origin_reached"] is False
    assert result["recovered_hops_count"] == 1  # Only hop 1 succeeded; hops 2-5 never occurred
    assert result["candidate_origin_account"] is None
    assert result["candidate_origin_device"] is None
    assert "recipient_verification_failed_at_hop_2" in result["termination_reason"]
    assert "tampered_content" in result["termination_reason"]


def test_corrupt_signature_aborts_forwarding_before_downstream_hops() -> None:
    """Regression test: forged/corrupted signature must be rejected and abort forwarding."""
    report = run_experiment(hops=5, scenario="forged_signature", adversarial_hop=3)
    result = report["traceback_result"]

    assert result["outcome"] == "FAILED_VERIFICATION"
    assert result["origin_reached"] is False
    assert result["recovered_hops_count"] == 2  # Only hops 1-2 succeeded; hops 3-5 never occurred
    assert result["candidate_origin_account"] is None
    assert result["candidate_origin_device"] is None
    assert "recipient_verification_failed_at_hop_3" in result["termination_reason"]
    assert "forged_signature" in result["termination_reason"]


def test_cyclic_forwarding_actually_exercises_loop_and_terminates() -> None:
    """Verifies that a genuine forwarding cycle terminates safely without infinite loops."""
    report = run_experiment(hops=4, scenario="cyclic_forwarding", adversarial_hop=2)
    result = report["traceback_result"]
    assert result["origin_reached"] is False
    assert result["termination_reason"] == "cyclic_forwarding_detected"
    assert result["outcome"] == "TERMINATED_EARLY"
    assert result["candidate_origin_account"] is None
    assert result["candidate_origin_device"] is None


def test_fixed_deterministic_test_vector() -> None:
    """Documented, fixed deterministic test vector with hardcoded cryptographic keys and KAT outputs."""
    # Fixed 32-byte private key seeds (RFC-style test vectors)
    k_alice_sk = bytes.fromhex("1111111111111111111111111111111111111111111111111111111111111111")
    k_bob_sk = bytes.fromhex("2222222222222222222222222222222222222222222222222222222222222222")

    alice = DeviceIdentity.from_private_bytes("acct:test-alice", "dev:test-alice-01", k_alice_sk)
    bob = DeviceIdentity.from_private_bytes("acct:test-bob", "dev:test-bob-01", k_bob_sk)

    server = CryptographicTracebackServer()
    msg = b"Tyagi 2019 fixed test vector payload"
    fixed_k0 = bytes.fromhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")

    env, rec_state, tag = originate_message(
        server=server,
        sender=alice,
        receiver_account=bob.account_id,
        receiver_device=bob.device_id,
        message=msg,
        fixed_tracing_key=fixed_k0,
        fixed_predecessor_key=bytes(32),
        attach_extension_signature=False,  # Baseline symmetric
    )

    # Independently established Known-Answer Test (KAT) hexadecimal constants
    EXPECTED_MID_HEX = "9e35b1b5fb0a7dc8f56cb8eb622affc53f2f47e7cad89db802c1c16f727b3482"
    EXPECTED_ENC_KEY_HEX = "bc82b29e544be8de92d327c92a41d2dd"
    EXPECTED_CT_HEX = "ebdfe9c438a26a7dd6dfcea304e8785e8a68281862836df7d3ec34a8733dd205"

    assert tag.addr.hex() == EXPECTED_MID_HEX
    assert _kdf_enc(fixed_k0).hex() == EXPECTED_ENC_KEY_HEX
    assert tag.ct.hex() == EXPECTED_CT_HEX
    assert len(tag.addr) == 32
    assert len(tag.ct) == 32
    assert tag.signature is None

    # Bob verifies and reports
    rec_bob = rec_msg(bob.account_id, bob.device_id, env)
    trace_res = server.trace(
        message=msg,
        reporting_account=bob.account_id,
        reporting_device=bob.device_id,
        reporting_pointer=PathPointer(rec_bob.tracing_key),
    )

    # Protocol-level traceback: absence of predecessor record identifies candidate origin,
    # but does not claim origin_reached=True or return SUCCESS without external ground truth
    assert trace_res.origin_reached is False
    assert trace_res.outcome == "TERMINATED_EARLY"
    assert trace_res.candidate_origin_account == "acct:test-alice"
    assert trace_res.candidate_origin_device == "dev:test-alice-01"
    assert trace_res.recovered_origin_account is None
    assert trace_res.recovered_origin_device is None
    assert len(trace_res.verified_hops) == 1
    assert trace_res.termination_reason == "predecessor_record_absent_candidate_origin_unverified"


def test_recipient_view_confidentiality_no_predecessor_pointer_exposure() -> None:
    """Regression test (CCS 2019 Theorem 2 User Trace Confidentiality).

    Verifies that the recipient envelope and received state do NOT contain
    predecessor pointer ciphertexts `ct`. Predecessor pointers must remain exclusively
    on the platform. A recipient possessing tracing key k and ct could decrypt
    k_prev = Dec(H(k), ct), violating User Trace Confidentiality.
    """
    server = CryptographicTracebackServer()
    alice = DeviceIdentity.generate("acct:alice", "dev:alice-01")
    bob = DeviceIdentity.generate("acct:bob", "dev:bob-01")
    charlie = DeviceIdentity.generate("acct:charlie", "dev:charlie-01")

    msg = b"Confidentiality test message"

    # Alice originates to Bob
    env_ab, rec_bob, tag_ab = originate_message(
        server=server,
        sender=alice,
        receiver_account=bob.account_id,
        receiver_device=bob.device_id,
        message=msg,
    )
    rec_bob_verified = rec_msg(bob.account_id, bob.device_id, env_ab)

    # Bob forwards to Charlie
    env_bc, rec_charlie, tag_bc = forward_message(
        server=server,
        sender=bob,
        receiver_account=charlie.account_id,
        receiver_device=charlie.device_id,
        received_state=rec_bob_verified,
    )
    rec_charlie_verified = rec_msg(charlie.account_id, charlie.device_id, env_bc)

    # 1. Structural check: neither MessageEnvelope nor ReceivedMessageState expose ct
    assert not hasattr(env_bc, "ct")
    assert not hasattr(rec_charlie_verified, "ct")
    assert not hasattr(env_ab, "ct")
    assert not hasattr(rec_bob_verified, "ct")

    # 2. Server stores the predecessor ciphertext, not the recipient
    server_record = server.get_record(env_bc.mid)
    assert server_record is not None
    assert server_record.ct == tag_bc.ct

    # 3. Confidentiality invariant: Charlie possesses k_bc, but has no access to tag_bc.ct
    # If Charlie only inspects his local view, he cannot decrypt Bob's predecessor tracing key
    charlie_k = rec_charlie_verified.tracing_key
    charlie_derived_enc_key = _kdf_enc(charlie_k)
    recovered_alice_k = _aes_ctr(charlie_derived_enc_key, server_record.ct)
    assert recovered_alice_k == rec_bob_verified.tracing_key


def test_theorem_mapping_and_epistemic_validation() -> None:
    report = run_experiment(hops=3, scenario="valid_linear_path")
    epistemic = report["epistemic_notice"]
    assert "device cryptographic credentials" in epistemic["account_vs_device_distinction"]
    assert "does not establish the legal identity" in epistemic["real_world_identity_limitation"]
    assert "does not synthesize phantom hops" in epistemic["no_unrecorded_history_inference"]

    props = report["security_properties_evaluated"]
    # Check that hardcoded claims are absent and theorems are accurately mapped
    assert props["path_soundness"].startswith("OBSERVED_IN_EXPERIMENT:")
    assert "Theorem 1 establishes platform trace confidentiality" in props["confidentiality_unreported"]
    assert "Theorem 2 establishes user trace confidentiality" in props["confidentiality_unreported"]
    assert "Theorem 3 establishes trace unforgeability" in props["framing_resistance"]

    schema_path = Path(__file__).resolve().parents[1] / "schemas" / SCHEMA_NAME
    schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.validate(report, schema_data)

    md = experiment_markdown(report)
    assert "# Cryptographic Reproduction Report: Tyagi et al. (CCS 2019)" in md
    assert "Epistemic Limitations & Baseline Design" in md
    assert "Local Synthetic Microbenchmarks" in md
    assert "Theorem 1 & 2" in md
    assert "Theorem 3" in md


def test_normal_origin_termination_random_predecessor() -> None:
    """Verifies Figure 3 normal origin termination with a random predecessor key.

    In Tyagi et al. (CCS 2019) Figure 3, the originator generates a fresh random
    predecessor key k_prev (not a fixed zero sentinel). Traceback terminates
    because mid = F(k_prev, m) has no entry in the server table.
    """
    server = CryptographicTracebackServer()
    alice = DeviceIdentity.generate("acct:alice", "dev:alice-01")
    bob = DeviceIdentity.generate("acct:bob", "dev:bob-01")
    charlie = DeviceIdentity.generate("acct:charlie", "dev:charlie-01")

    msg = b"Testing normal origin termination with random predecessor key"

    # Alice originates with random k_0 and random k_prev_0 (default)
    env_ab, rec_bob, tag_ab = originate_message(
        server=server,
        sender=alice,
        receiver_account=bob.account_id,
        receiver_device=bob.device_id,
        message=msg,
    )
    rec_bob_verified = rec_msg(bob.account_id, bob.device_id, env_ab)

    # Bob forwards to Charlie
    env_bc, rec_charlie, tag_bc = forward_message(
        server=server,
        sender=bob,
        receiver_account=charlie.account_id,
        receiver_device=charlie.device_id,
        received_state=rec_bob_verified,
    )
    rec_charlie_verified = rec_msg(charlie.account_id, charlie.device_id, env_bc)

    # Charlie complains: pure protocol traceback traverses Charlie <- Bob <- Alice
    # Protocol level: identifies candidate origin without external ground truth oracle
    trace_res = server.trace(
        message=msg,
        reporting_account=charlie.account_id,
        reporting_device=charlie.device_id,
        reporting_pointer=PathPointer(rec_charlie_verified.tracing_key),
    )

    assert trace_res.candidate_origin_account == "acct:alice"
    assert trace_res.candidate_origin_device == "dev:alice-01"
    assert trace_res.recovered_origin_account is None
    assert trace_res.recovered_origin_device is None
    assert trace_res.recovered_hops_count == 2
    assert trace_res.termination_reason == "predecessor_record_absent_candidate_origin_unverified"
    assert trace_res.origin_reached is False
    assert trace_res.outcome == "TERMINATED_EARLY"
    assert len(trace_res.verified_hops) == 2

    # Controlled evaluation layer: verifies candidate origin against ground truth
    report = run_experiment(hops=3, scenario="valid_linear_path")
    exp_res = report["traceback_result"]
    assert exp_res["outcome"] == "SUCCESS"
    assert exp_res["origin_reached"] is True
    assert exp_res["candidate_origin_account"] == "acct:alice"
    assert exp_res["candidate_origin_device"] == "dev:alice-primary"
    assert exp_res["recovered_origin_account"] == "acct:alice"
    assert exp_res["recovered_origin_device"] == "dev:alice-primary"
    assert "predecessor_record_absent" in exp_res["termination_reason"]
    assert "verified_by_ground_truth" in exp_res["termination_reason"]


def test_missing_intermediate_record_terminates_at_intermediate_forwarder() -> None:
    """Verifies that missing intermediate server records halt traceback at an intermediate forwarder.

    CRITICAL EPISTEMIC INVARIANT:
    An absent predecessor record in server state (T[mid] is None) does NOT prove the
    true origin was reached. If intermediate records were pruned or dropped, traceback
    halts at the intermediate forwarder and reports an unverified candidate.
    """
    server = CryptographicTracebackServer()
    alice = DeviceIdentity.generate("acct:alice", "dev:alice-01")
    bob = DeviceIdentity.generate("acct:bob", "dev:bob-01")
    charlie = DeviceIdentity.generate("acct:charlie", "dev:charlie-01")
    dave = DeviceIdentity.generate("acct:dave", "dev:dave-01")

    msg = b"Testing missing intermediate record behavior"

    # Alice originates to Bob (stored in server)
    env_ab, rec_bob, tag_ab = originate_message(
        server=server,
        sender=alice,
        receiver_account=bob.account_id,
        receiver_device=bob.device_id,
        message=msg,
    )
    rec_bob_verified = rec_msg(bob.account_id, bob.device_id, env_ab)

    # Bob forwards to Charlie, but tag is omitted from server (simulating pruned/dropped hop)
    dummy_server = CryptographicTracebackServer()
    env_bc, rec_charlie, tag_bc = forward_message(
        server=dummy_server,  # NOT added to server._table!
        sender=bob,
        receiver_account=charlie.account_id,
        receiver_device=charlie.device_id,
        received_state=rec_bob_verified,
    )
    rec_charlie_verified = rec_msg(charlie.account_id, charlie.device_id, env_bc)

    # Charlie forwards to Dave (stored in server)
    env_cd, rec_dave, tag_cd = forward_message(
        server=server,
        sender=charlie,
        receiver_account=dave.account_id,
        receiver_device=dave.device_id,
        received_state=rec_charlie_verified,
    )
    rec_dave_verified = rec_msg(dave.account_id, dave.device_id, env_cd)

    # Dave reports to server.
    # Traceback can only recover Charlie -> Dave. The lookup for Bob's tag fails!
    trace_res = server.trace(
        message=msg,
        reporting_account=dave.account_id,
        reporting_device=dave.device_id,
        reporting_pointer=PathPointer(rec_dave_verified.tracing_key),
    )

    # Traversal stopped at Charlie; it NEVER reached Alice!
    assert trace_res.outcome == "TERMINATED_EARLY"
    assert trace_res.origin_reached is False
    assert trace_res.candidate_origin_account == "acct:charlie"
    assert trace_res.recovered_origin_account is None
    assert trace_res.recovered_hops_count == 1
    assert trace_res.termination_reason == "predecessor_record_absent_candidate_origin_unverified"
    assert trace_res.verified_hops[0].sender_account == "acct:charlie"


def test_server_trace_unverified_candidate_without_oracle() -> None:
    """Verifies that server.trace() reports an absent record as an unverified candidate.

    EPISTEMIC INVARIANT:
    Without ground truth, server.trace() cannot mathematically prove that an absent
    predecessor record represents the true origin. It must report outcome='TERMINATED_EARLY',
    origin_reached=False, and termination_reason='predecessor_record_absent_candidate_origin_unverified'.
    """
    server = CryptographicTracebackServer()
    alice = DeviceIdentity.generate("acct:alice", "dev:alice-01")
    bob = DeviceIdentity.generate("acct:bob", "dev:bob-01")

    msg = b"Testing pure protocol tracing behavior"
    env_ab, rec_bob, tag_ab = originate_message(
        server=server,
        sender=alice,
        receiver_account=bob.account_id,
        receiver_device=bob.device_id,
        message=msg,
    )
    rec_bob_verified = rec_msg(bob.account_id, bob.device_id, env_ab)

    trace_res = server.trace(
        message=msg,
        reporting_account=bob.account_id,
        reporting_device=bob.device_id,
        reporting_pointer=PathPointer(rec_bob_verified.tracing_key),
    )

    # Must NOT claim origin was proven or return SUCCESS
    assert trace_res.origin_reached is False
    assert trace_res.outcome == "TERMINATED_EARLY"
    assert trace_res.termination_reason == "predecessor_record_absent_candidate_origin_unverified"
    assert trace_res.candidate_origin_account == "acct:alice"
    assert trace_res.recovered_origin_account is None
    assert trace_res.recovered_hops_count == 1


def test_missing_hop_experiment_scenario() -> None:
    """Verifies that run_experiment correctly models missing intermediate records."""
    report = run_experiment(hops=4, scenario="missing_hop", adversarial_hop=2)
    result = report["traceback_result"]
    assert result["outcome"] == "TERMINATED_EARLY"
    assert result["origin_reached"] is False
    assert result["recovered_hops_count"] < 4
    assert result["candidate_origin_account"] == "acct:charlie"
    assert result["candidate_origin_device"] == "dev:charlie-primary"
    assert result["recovered_origin_account"] is None
    assert result["recovered_origin_device"] is None
    assert result["termination_reason"] == "predecessor_record_absent_missing_intermediate_evidence"


def test_signature_stripping_downgrade_rejected() -> None:
    """Regression test (Finding 1): Missing signatures in PKI mode MUST be rejected (no silent bypass)."""
    server = CryptographicTracebackServer()
    registry = DeviceRegistry()
    alice = DeviceIdentity.generate("acct:alice", "dev:alice-01")
    bob = DeviceIdentity.generate("acct:bob", "dev:bob-01")
    registry.register(alice.account_id, alice.device_id, alice.public_key_bytes)
    registry.register(bob.account_id, bob.device_id, bob.public_key_bytes)

    msg = b"Testing signature stripping protection"
    # Originate message without signature
    env, rec_alice, tag = originate_message(
        server=server,
        sender=alice,
        receiver_account=bob.account_id,
        receiver_device=bob.device_id,
        message=msg,
        attach_extension_signature=False,
    )

    # 1. Recipient rec_msg with require_signature=True must reject unsigned envelope
    with pytest.raises(RecMsgVerificationError, match="Missing required digital signature"):
        rec_msg(bob.account_id, bob.device_id, env, registry=registry, require_signature=True)

    # 2. Server traceback with require_signature=True must fail closed on unsigned hop
    trace_res = server.trace(
        message=msg,
        reporting_account=bob.account_id,
        reporting_device=bob.device_id,
        reporting_pointer=PathPointer(env.tracing_key),
        registry=registry,
        require_signature=True,
    )
    assert trace_res.outcome == "FAILED_VERIFICATION"
    assert trace_res.origin_reached is False
    assert trace_res.termination_reason == "missing_required_signature_in_pki_mode"
    assert trace_res.candidate_origin_account is None
    assert trace_res.candidate_origin_device is None
    assert len(trace_res.verified_hops) == 1
    assert trace_res.verified_hops[0].signature_status == "MISSING"


def test_tampered_predecessor_pointer_fails_signature_in_pki_mode() -> None:
    """Regression test (Finding 2): Modifying server-side ct breaks signature verification."""
    server = CryptographicTracebackServer()
    registry = DeviceRegistry()
    alice = DeviceIdentity.generate("acct:alice", "dev:alice-01")
    bob = DeviceIdentity.generate("acct:bob", "dev:bob-01")
    charlie = DeviceIdentity.generate("acct:charlie", "dev:charlie-01")
    registry.register(alice.account_id, alice.device_id, alice.public_key_bytes)
    registry.register(bob.account_id, bob.device_id, bob.public_key_bytes)
    registry.register(charlie.account_id, charlie.device_id, charlie.public_key_bytes)

    msg = b"Testing predecessor pointer integrity"
    env_ab, rec_bob, tag_ab = originate_message(
        server=server,
        sender=alice,
        receiver_account=bob.account_id,
        receiver_device=bob.device_id,
        message=msg,
        attach_extension_signature=True,
    )
    rec_bob_v = rec_msg(bob.account_id, bob.device_id, env_ab, registry=registry, require_signature=True)

    env_bc, rec_charlie, tag_bc = forward_message(
        server=server,
        sender=bob,
        receiver_account=charlie.account_id,
        receiver_device=charlie.device_id,
        received_state=rec_bob_v,
        attach_extension_signature=True,
    )
    rec_charlie_v = rec_msg(charlie.account_id, charlie.device_id, env_bc, registry=registry, require_signature=True)

    # Attacker tampers with predecessor pointer ciphertext on server
    orig_rec = server._table[tag_bc.addr]
    tampered_ct = bytes([b ^ 0x01 for b in orig_rec.ct])
    server._table[tag_bc.addr] = type(orig_rec)(
        ct=tampered_ct,
        sender_account=orig_rec.sender_account,
        sender_device=orig_rec.sender_device,
        sender_pubkey_raw=orig_rec.sender_pubkey_raw,
        receiver_account=orig_rec.receiver_account,
        receiver_device=orig_rec.receiver_device,
        signature=orig_rec.signature,
    )

    # Server traceback rejects the tampered predecessor pointer link
    trace_res = server.trace(
        message=msg,
        reporting_account=charlie.account_id,
        reporting_device=charlie.device_id,
        reporting_pointer=PathPointer(rec_charlie_v.tracing_key),
        registry=registry,
        require_signature=True,
    )
    assert trace_res.outcome == "FAILED_VERIFICATION"
    assert trace_res.termination_reason == "forged_sender_signature_detected"
    assert trace_res.candidate_origin_account is None
    assert trace_res.candidate_origin_device is None


def test_invalid_adversarial_hop_configurations_rejected() -> None:
    """Regression test (Finding 4): Invalid hops or adversarial_hop values are rejected at entry."""
    with pytest.raises(ValueError, match="requires at least 2 hops"):
        run_experiment(hops=1, scenario="tampered_content")

    with pytest.raises(ValueError, match="adversarial_hop must satisfy 2 <= adversarial_hop <= hops"):
        run_experiment(hops=4, scenario="tampered_content", adversarial_hop=1)

    with pytest.raises(ValueError, match="adversarial_hop must satisfy 2 <= adversarial_hop <= hops"):
        run_experiment(hops=4, scenario="tampered_content", adversarial_hop=5)


def test_duplicate_message_identifier_rejected() -> None:
    """Regression test (Finding 7): Reusing tracing keys raises DuplicateMessageIdentifierError."""
    server = CryptographicTracebackServer()
    alice = DeviceIdentity.generate("acct:alice", "dev:alice-01")
    bob = DeviceIdentity.generate("acct:bob", "dev:bob-01")
    fixed_k = b"\x42" * 32
    msg = b"Duplicate identifier test message"

    # First origination succeeds
    originate_message(
        server=server,
        sender=alice,
        receiver_account=bob.account_id,
        receiver_device=bob.device_id,
        message=msg,
        fixed_tracing_key=fixed_k,
    )

    # Second origination with identical (k, m) -> identical mid MUST be rejected per Figure 3 Svr-Process
    with pytest.raises(DuplicateMessageIdentifierError, match="already exists in server state"):
        originate_message(
            server=server,
            sender=alice,
            receiver_account=bob.account_id,
            receiver_device=bob.device_id,
            message=msg,
            fixed_tracing_key=fixed_k,
        )

def test_ground_truth_verifies_device_and_hop_sequence() -> None:
    """Regression test (Finding 6): Ground-truth certification strictly checks device ID."""
    report = run_experiment(hops=3, scenario="valid_linear_path")
    res = report["traceback_result"]
    assert res["outcome"] == "SUCCESS"
    assert res["origin_reached"] is True
    # The true origin device Dev:alice-primary is certified alongside the account
    assert res["candidate_origin_account"] == "acct:alice"
    assert res["candidate_origin_device"] == "dev:alice-primary"
    assert res["recovered_origin_account"] == "acct:alice"
    assert res["recovered_origin_device"] == "dev:alice-primary"
    # Ensure all hops in the sequence match forward chain
    assert len(res["verified_hops"]) == 3
    for hop in res["verified_hops"]:
        assert hop["status"] == "verified_hop_authenticated"


def test_missing_sender_public_key_produces_failed_verification() -> None:
    """Regression test: Missing public key in a signed record produces FAILED_VERIFICATION."""
    server = CryptographicTracebackServer()
    registry = DeviceRegistry()
    alice = DeviceIdentity.generate("acct:alice", "dev:alice-01")
    bob = DeviceIdentity.generate("acct:bob", "dev:bob-01")
    registry.register(alice.account_id, alice.device_id, alice.public_key_bytes)
    registry.register(bob.account_id, bob.device_id, bob.public_key_bytes)

    msg = b"Message for missing public key test"
    env_ab, rec_bob, tag_ab = originate_message(
        server=server,
        sender=alice,
        receiver_account=bob.account_id,
        receiver_device=bob.device_id,
        message=msg,
        attach_extension_signature=True,
    )
    rec_bob_v = rec_msg(bob.account_id, bob.device_id, env_ab, registry=registry, require_signature=True)

    # Manually remove the public key from the server record while keeping the signature intact
    orig_rec = server._table[tag_ab.addr]
    assert orig_rec.signature is not None
    server._table[tag_ab.addr] = type(orig_rec)(
        ct=orig_rec.ct,
        sender_account=orig_rec.sender_account,
        sender_device=orig_rec.sender_device,
        sender_pubkey_raw=None,  # stripped public key
        receiver_account=orig_rec.receiver_account,
        receiver_device=orig_rec.receiver_device,
        signature=orig_rec.signature,
    )

    trace_res = server.trace(
        message=msg,
        reporting_account=bob.account_id,
        reporting_device=bob.device_id,
        reporting_pointer=PathPointer(rec_bob_v.tracing_key),
        registry=registry,
        require_signature=True,
    )

    assert trace_res.outcome == "FAILED_VERIFICATION"
    assert trace_res.origin_reached is False
    assert trace_res.termination_reason == "missing_sender_public_key_in_record"
    assert trace_res.candidate_origin_account is None
    assert trace_res.candidate_origin_device is None
    assert len(trace_res.verified_hops) == 1
    hop = trace_res.verified_hops[0]
    assert hop.signature_valid is False
    assert hop.signature_status == "INVALID"
    assert hop.status == "missing_sender_public_key_in_record"


def test_ground_truth_rejects_candidate_device_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Negative test: Ground truth rejects certification if candidate device differs from ground truth."""
    import dataclasses

    orig_trace = CryptographicTracebackServer.trace

    def mock_trace(self: CryptographicTracebackServer, *args: Any, **kwargs: Any) -> Any:
        res = orig_trace(self, *args, **kwargs)
        # Account matches acct:alice, but device is altered to a secondary/wrong device
        return dataclasses.replace(res, candidate_origin_device="dev:alice-secondary")

    monkeypatch.setattr(CryptographicTracebackServer, "trace", mock_trace)

    report = run_experiment(hops=3, scenario="valid_linear_path")
    res = report["traceback_result"]
    assert res["outcome"] == "TERMINATED_EARLY"
    assert res["origin_reached"] is False
    assert res["candidate_origin_account"] == "acct:alice"
    assert res["candidate_origin_device"] == "dev:alice-secondary"
    assert res["recovered_origin_account"] is None
    assert res["recovered_origin_device"] is None
    assert res["termination_reason"] == "predecessor_record_absent_missing_intermediate_evidence"


def test_ground_truth_rejects_hop_sequence_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Negative test: Ground truth rejects certification if reverse hop sequence does not match chain."""
    import dataclasses

    orig_trace = CryptographicTracebackServer.trace

    def mock_trace(self: CryptographicTracebackServer, *args: Any, **kwargs: Any) -> Any:
        res = orig_trace(self, *args, **kwargs)
        tampered_hops = list(res.verified_hops)
        # Tamper with the sender identity of an intermediate hop
        tampered_hops[0] = dataclasses.replace(tampered_hops[0], sender_account="acct:eve")
        return dataclasses.replace(res, verified_hops=tuple(tampered_hops))

    monkeypatch.setattr(CryptographicTracebackServer, "trace", mock_trace)

    report = run_experiment(hops=3, scenario="valid_linear_path")
    res = report["traceback_result"]
    assert res["outcome"] == "TERMINATED_EARLY"
    assert res["origin_reached"] is False
    assert res["recovered_origin_account"] is None
    assert res["recovered_origin_device"] is None
    assert res["termination_reason"] == "predecessor_record_absent_missing_intermediate_evidence"


def test_cli_traceback_reproduction_includes_hops_signature_statuses(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verifies that CLI traceback-reproduction outputs hops_signature_statuses in summary JSON."""
    from opentrace.cli import main

    monkeypatch.setattr(
        "sys.argv",
        ["e2ee-traceability", "traceback-reproduction", "--hops", "2"],
    )
    main()
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert "hops_signature_statuses" in payload
    assert payload["hops_signature_statuses"] == ["N/A", "N/A"]


def test_cli_traceback_reproduction_pki_signature_statuses(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verifies CLI traceback-reproduction exposes VALID signature statuses under PKI mode."""
    from opentrace.cli import main

    monkeypatch.setattr(
        "sys.argv",
        ["e2ee-traceability", "traceback-reproduction", "--hops", "2", "--pki-extension"],
    )
    main()
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert "hops_signature_statuses" in payload
    assert payload["hops_signature_statuses"] == ["VALID", "VALID"]
