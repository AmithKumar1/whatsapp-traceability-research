"""Automated test suite for the cryptographic reproduction of Tyagi et al. (CCS 2019)."""
from __future__ import annotations

import json
from pathlib import Path
import jsonschema
import pytest

from opentrace.protocols.traceback2019_crypto import (
    CryptographicTracebackServer,
    DeviceIdentity,
    DeviceRegistry,
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


def test_canonical_symmetric_path_traceback_reaches_origin() -> None:
    """Verifies the canonical purely symmetric (third-party deniable) construction from Figure 3."""
    server = CryptographicTracebackServer()
    alice = DeviceIdentity.generate("acct:alice", "dev:alice-01")
    bob = DeviceIdentity.generate("acct:bob", "dev:bob-01")
    charlie = DeviceIdentity.generate("acct:charlie", "dev:charlie-01")

    msg = b"Symmetric path traceback test"
    # Alice originates (purely symmetric, sign_extension=False)
    env1, rec_alice, tag1 = originate_message(
        server=server,
        sender=alice,
        receiver_account=bob.account_id,
        receiver_device=bob.device_id,
        message=msg,
        attach_extension_signature=False,
    )
    assert tag1.signature is None

    # Bob runs RecMsg
    rec_bob = rec_msg(bob.account_id, bob.device_id, env1)
    assert rec_bob.tracing_key == env1.tracing_key

    # Bob forwards to Charlie
    env2, rec_fwd, tag2 = forward_message(
        server=server,
        sender=bob,
        receiver_account=charlie.account_id,
        receiver_device=charlie.device_id,
        received_state=rec_bob,
        attach_extension_signature=False,
    )
    assert tag2.signature is None

    # Charlie runs RecMsg
    rec_charlie = rec_msg(charlie.account_id, charlie.device_id, env2)

    # Charlie reports to server
    result = server.trace(
        message=msg,
        reporting_account=charlie.account_id,
        reporting_device=charlie.device_id,
        reporting_pointer=PathPointer(rec_charlie.tracing_key),
    )
    assert result.outcome == "SUCCESS"
    assert result.origin_reached is True
    assert result.recovered_origin_account == "acct:alice"
    assert result.recovered_origin_device == "dev:alice-01"
    assert result.recovered_hops_count == 2
    assert result.termination_reason == "origin_reached_successfully"


def test_recipient_rec_msg_lifecycle_and_tamper_rejection() -> None:
    """Tests that RecMsg explicitly binds message text, k, and mid before forwarding."""
    server = CryptographicTracebackServer()
    alice = DeviceIdentity.generate("acct:alice", "dev:alice-01")
    bob = DeviceIdentity.generate("acct:bob", "dev:bob-01")

    msg = b"Authentic message for RecMsg test"
    env, rec_state, tag = originate_message(
        server=server,
        sender=alice,
        receiver_account=bob.account_id,
        receiver_device=bob.device_id,
        message=msg,
    )

    # 1. Valid envelope succeeds
    valid_state = rec_msg(bob.account_id, bob.device_id, env)
    assert valid_state.message == msg

    # 2. Tampered message text rejected
    tampered_msg_env = type(env)(
        message=b"Modified message text",
        tracing_key=env.tracing_key,
        mid=env.mid,
        ct=env.ct,
        sender_account=env.sender_account,
        sender_device=env.sender_device,
        receiver_account=env.receiver_account,
        receiver_device=env.receiver_device,
    )
    with pytest.raises(RecMsgVerificationError, match="binding mismatch"):
        rec_msg(bob.account_id, bob.device_id, tampered_msg_env)

    # 3. Tampered mid rejected
    corrupt_mid_env = type(env)(
        message=env.message,
        tracing_key=env.tracing_key,
        mid=b"\xff" * 32,
        ct=env.ct,
        sender_account=env.sender_account,
        sender_device=env.sender_device,
        receiver_account=env.receiver_account,
        receiver_device=env.receiver_device,
    )
    with pytest.raises(RecMsgVerificationError, match="binding mismatch"):
        rec_msg(bob.account_id, bob.device_id, corrupt_mid_env)

    # 4. Tampered tracing key rejected
    corrupt_k_env = type(env)(
        message=env.message,
        tracing_key=b"\xee" * 32,
        mid=env.mid,
        ct=env.ct,
        sender_account=env.sender_account,
        sender_device=env.sender_device,
        receiver_account=env.receiver_account,
        receiver_device=env.receiver_device,
    )
    with pytest.raises(RecMsgVerificationError, match="binding mismatch"):
        rec_msg(bob.account_id, bob.device_id, corrupt_k_env)


def test_adversarial_self_asserted_identity_spoofing_rejected() -> None:
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
    )
    rec_bob = rec_msg(bob.account_id, bob.device_id, env, registry=registry)

    # Mallory attempts to forward claiming to be Bob, but signing with Mallory's key
    env_spoofed, rec_spoofed, tag_spoofed = forward_message(
        server=server,
        sender=bob,
        receiver_account="acct:charlie",
        receiver_device="dev:charlie-01",
        received_state=rec_bob,
        adversarial_spoofed_sender=mallory,
    )

    # Server trace with DeviceRegistry rejects the unregistered self-asserted key
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


def test_cyclic_forwarding_actually_exercises_loop_and_terminates() -> None:
    """Verifies that a genuine forwarding cycle terminates safely without infinite loops."""
    report = run_experiment(hops=4, scenario="cyclic_forwarding", adversarial_hop=3)
    result = report["traceback_result"]
    assert result["origin_reached"] is False
    assert result["termination_reason"] == "cyclic_forwarding_detected"
    assert result["outcome"] == "TERMINATED_EARLY"


def test_tampered_content_and_missing_hop_scenarios() -> None:
    # Tampered content terminates at modified node
    rep_tamper = run_experiment(hops=4, scenario="tampered_content", adversarial_hop=2)
    res_tamper = rep_tamper["traceback_result"]
    assert res_tamper["origin_reached"] is False
    assert res_tamper["termination_reason"] == "missing_forwarding_record_in_server_state"

    # Missing hop halts without phantom edges
    rep_missing = run_experiment(hops=4, scenario="missing_hop", adversarial_hop=2)
    res_missing = rep_missing["traceback_result"]
    assert res_missing["origin_reached"] is False
    assert res_missing["recovered_hops_count"] < 4
    assert res_missing["termination_reason"] == "missing_forwarding_record_in_server_state"


def test_fixed_deterministic_test_vector() -> None:
    """Documented, fixed deterministic test vector with hardcoded cryptographic keys."""
    # Fixed 32-byte private key seeds (RFC-style test vectors)
    k_alice_sk = bytes.fromhex("1111111111111111111111111111111111111111111111111111111111111111")
    k_bob_sk = bytes.fromhex("2222222222222222222222222222222222222222222222222222222222222222")

    alice = DeviceIdentity.from_private_bytes("acct:test-alice", "dev:test-alice-01", k_alice_sk)
    bob = DeviceIdentity.from_private_bytes("acct:test-bob", "dev:test-bob-01", k_bob_sk)

    registry = DeviceRegistry()
    registry.register(alice.account_id, alice.device_id, alice.public_key_bytes)
    registry.register(bob.account_id, bob.device_id, bob.public_key_bytes)

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
    )

    # Compute expected deterministic values
    expected_mid = _crprf(fixed_k0, msg)
    expected_enc_key = _kdf_enc(fixed_k0)
    expected_ct = _aes_ctr(expected_enc_key, bytes(32))

    assert tag.addr == expected_mid
    assert tag.ct == expected_ct
    assert len(tag.addr) == 32
    assert len(tag.ct) == 32

    # Bob verifies and reports
    rec_bob = rec_msg(bob.account_id, bob.device_id, env, registry=registry)
    trace_res = server.trace(
        message=msg,
        reporting_account=bob.account_id,
        reporting_device=bob.device_id,
        reporting_pointer=PathPointer(rec_bob.tracing_key),
        registry=registry,
    )

    assert trace_res.origin_reached is True
    assert trace_res.recovered_origin_account == "acct:test-alice"
    assert trace_res.recovered_origin_device == "dev:test-alice-01"
    assert len(trace_res.verified_hops) == 1
    assert trace_res.verified_hops[0].signature_valid is True


def test_epistemic_distinctions_and_schema_validation() -> None:
    report = run_experiment(hops=3, scenario="valid_linear_path")
    epistemic = report["epistemic_notice"]
    assert "device cryptographic credentials" in epistemic["account_vs_device_distinction"]
    assert "does not establish the legal identity" in epistemic["real_world_identity_limitation"]
    assert "does not synthesize phantom hops" in epistemic["no_unrecorded_history_inference"]

    props = report["security_properties_evaluated"]
    # Check that hardcoded claim strings are NOT present
    assert props["path_soundness"].startswith("DEMONSTRATED:")
    assert "FORMAL_THEORETICAL_CLAIM (Tyagi et al. 2019 Theorem 1)" in props["confidentiality_unreported"]

    schema_path = Path(__file__).resolve().parents[1] / "schemas" / SCHEMA_NAME
    schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.validate(report, schema_data)

    md = experiment_markdown(report)
    assert "# Cryptographic Reproduction Report: Tyagi et al. (CCS 2019)" in md
    assert "Epistemic Limitations" in md
    assert "Verified Hop Sequence" in md
    assert "Local Synthetic Microbenchmarks" in md
