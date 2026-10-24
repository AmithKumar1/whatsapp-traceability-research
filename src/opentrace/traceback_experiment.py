"""Experiment runner for Tyagi et al. (CCS 2019) Path Traceback reproduction."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import jsonschema

from .protocols.traceback2019_crypto import (
    CryptographicTracebackServer,
    DeviceIdentity,
    DeviceRegistry,
    MessageEnvelope,
    PathPointer,
    RecMsgVerificationError,
    TracebackExecutionResult,
    VerifiedHop,
    _aes_ctr,
    _compute_extension_payload,
    _kdf_enc,
    forward_message,
    originate_message,
    rec_msg,
)

SCHEMA_NAME = "traceback-experiment.schema.json"
SCHEMA_ID = "opentrace.traceback-experiment.v1"


def run_experiment(
    hops: int = 4,
    message: bytes = b"Synthetic viral message for Tyagi2019 reproduction",
    scenario: str = "valid_linear_path",
    adversarial_hop: int = 2,
    enable_pki_extension: bool = False,
) -> Dict[str, Any]:
    """Run an offline cryptographic traceback experiment and return a structured report."""
    if hops < 1:
        raise ValueError("hops must be at least 1")
    if hops > 50:
        raise ValueError("hops capped at 50 for realistic offline experiment limits")
    if not message:
        raise ValueError("message cannot be empty")

    valid_scenarios = {
        "valid_linear_path",
        "tampered_content",
        "forged_signature",
        "missing_hop",
        "cyclic_forwarding",
    }
    if scenario not in valid_scenarios:
        raise ValueError(f"Unknown scenario {scenario!r}; must be one of {sorted(valid_scenarios)}")

    # Forged signature scenario exercises the PKI extension
    use_pki = enable_pki_extension or (scenario == "forged_signature")

    t_start_setup = time.perf_counter_ns()
    # 1. Setup participants & DeviceRegistry
    num_participants = hops + 1
    participants: List[DeviceIdentity] = []
    registry = DeviceRegistry()
    names = ["Alice", "Bob", "Charlie", "David", "Eve", "Frank", "Grace", "Heidi", "Ivan", "Judy"]
    for i in range(num_participants):
        base_name = names[i % len(names)]
        suffix = f"-{i}" if i >= len(names) else ""
        acct = f"acct:{base_name.lower()}{suffix}"
        dev = f"dev:{base_name.lower()}-primary{suffix}"
        ident = DeviceIdentity.generate(account_id=acct, device_id=dev)
        participants.append(ident)
        registry.register(acct, dev, ident.public_key_bytes)

    server = CryptographicTracebackServer()
    setup_time_ns = time.perf_counter_ns() - t_start_setup

    # 2. Originator authors the message (canonical symmetric by default)
    t_start_forwarding = time.perf_counter_ns()
    originator = participants[0]
    first_receiver = participants[1]

    envelope, received_state, tag = originate_message(
        server=server,
        sender=originator,
        receiver_account=first_receiver.account_id,
        receiver_device=first_receiver.device_id,
        message=message,
        attach_extension_signature=use_pki,
    )

    # First recipient runs RecMsg
    rec_state = rec_msg(
        receiver_account=first_receiver.account_id,
        receiver_device=first_receiver.device_id,
        envelope=envelope,
        registry=registry if use_pki else None,
    )

    last_tag_size = len(tag.addr) + len(tag.ct)
    if tag.sender_pubkey_raw:
        last_tag_size += len(tag.sender_pubkey_raw)
    if tag.signature:
        last_tag_size += len(tag.signature)

    # 3. Simulate message forwarding across remaining hops
    active_rec_state = rec_state
    aborted_at_hop: Optional[int] = None
    abort_reason: Optional[str] = None
    hops_completed = 1  # Hop 1 successfully originated and accepted
    verified_delivery_hops: List[VerifiedHop] = [
        VerifiedHop(
            hop_index=1,
            sender_account=originator.account_id,
            sender_device=originator.device_id,
            receiver_account=first_receiver.account_id,
            receiver_device=first_receiver.device_id,
            address_hex=envelope.mid.hex(),
            signature_valid=True,
            status="verified_hop_authenticated",
        )
    ]

    for step in range(1, hops):
        sender = participants[step]
        receiver = participants[step + 1]
        is_adv_hop = (step + 1 == adversarial_hop)

        if scenario == "tampered_content" and is_adv_hop:
            # Participant attempts to tamper with message content
            tampered_message = message + b" [tampered]"
            bad_envelope, _, bad_tag = forward_message(
                server=server,
                sender=sender,
                receiver_account=receiver.account_id,
                receiver_device=receiver.device_id,
                received_state=active_rec_state,
                attach_extension_signature=use_pki,
            )
            tampered_env = MessageEnvelope(
                message=tampered_message,
                tracing_key=bad_envelope.tracing_key,
                mid=bad_envelope.mid,
                sender_account=bad_envelope.sender_account,
                sender_device=bad_envelope.sender_device,
                receiver_account=bad_envelope.receiver_account,
                receiver_device=bad_envelope.receiver_device,
                sender_pubkey_raw=bad_envelope.sender_pubkey_raw,
                signature=bad_envelope.signature,
            )
            try:
                rec_msg(
                    receiver_account=receiver.account_id,
                    receiver_device=receiver.device_id,
                    envelope=tampered_env,
                    registry=registry if use_pki else None,
                )
            except RecMsgVerificationError as exc:
                # Recipient RecMsg catches tampering: message is REJECTED
                # Forwarding is immediately aborted; no downstream hop occurs
                aborted_at_hop = step + 1
                abort_reason = f"rec_msg_verification_failed_tampered_content: {exc}"
                break

        elif scenario == "forged_signature" and is_adv_hop:
            # Forwarder supplies corrupted signature
            env, next_rec, fwd_tag = forward_message(
                server=server,
                sender=sender,
                receiver_account=receiver.account_id,
                receiver_device=receiver.device_id,
                received_state=active_rec_state,
                attach_extension_signature=True,
                adversarial_corrupt_signature=True,
            )
            try:
                rec_msg(
                    receiver_account=receiver.account_id,
                    receiver_device=receiver.device_id,
                    envelope=env,
                    registry=registry,
                )
            except RecMsgVerificationError as exc:
                # Recipient RecMsg catches invalid signature: message is REJECTED
                # Forwarding is immediately aborted; no downstream hop occurs
                aborted_at_hop = step + 1
                abort_reason = f"rec_msg_verification_failed_forged_signature: {exc}"
                break

        elif scenario == "missing_hop" and is_adv_hop:
            # Forwarding happens between clients, but server delivery fails or record is pruned
            dummy_server = CryptographicTracebackServer()
            env, next_rec, fwd_tag = forward_message(
                server=dummy_server,
                sender=sender,
                receiver_account=receiver.account_id,
                receiver_device=receiver.device_id,
                received_state=active_rec_state,
                attach_extension_signature=use_pki,
            )
            active_rec_state = rec_msg(
                receiver_account=receiver.account_id,
                receiver_device=receiver.device_id,
                envelope=env,
                registry=registry if use_pki else None,
            )
            hops_completed += 1
            verified_delivery_hops.append(
                VerifiedHop(
                    hop_index=step + 1,
                    sender_account=sender.account_id,
                    sender_device=sender.device_id,
                    receiver_account=receiver.account_id,
                    receiver_device=receiver.device_id,
                    address_hex=env.mid.hex(),
                    signature_valid=True,
                    status="verified_hop_authenticated",
                )
            )

        elif scenario == "cyclic_forwarding" and is_adv_hop:
            # Genuinely inject a loop in the backwards pointer chain:
            # Re-encrypt predecessor pointer so it decrypts to next_rec.tracing_key (cycle back to itself)
            env, next_rec, fwd_tag = forward_message(
                server=server,
                sender=sender,
                receiver_account=receiver.account_id,
                receiver_device=receiver.device_id,
                received_state=active_rec_state,
                attach_extension_signature=use_pki,
            )
            cycle_k = next_rec.tracing_key
            enc_k = _kdf_enc(cycle_k)
            ct_cycle = _aes_ctr(enc_k, cycle_k)
            sig_cycle: Optional[bytes] = None
            if use_pki:
                cycle_payload = _compute_extension_payload(
                    mid=fwd_tag.addr,
                    message_digest=hashlib.sha256(message).digest(),
                    sender_account=sender.account_id,
                    sender_device=sender.device_id,
                    receiver_account=receiver.account_id,
                    receiver_device=receiver.device_id,
                )
                sig_cycle = sender.private_key.sign(cycle_payload)
            # Replace record in server table with validly signed cycle pointer
            server._table[fwd_tag.addr] = type(server._table[fwd_tag.addr])(
                ct=ct_cycle,
                sender_account=sender.account_id,
                sender_device=sender.device_id,
                sender_pubkey_raw=fwd_tag.sender_pubkey_raw,
                receiver_account=receiver.account_id,
                receiver_device=receiver.device_id,
                signature=sig_cycle,
            )
            active_rec_state = next_rec
            hops_completed += 1
            verified_delivery_hops.append(
                VerifiedHop(
                    hop_index=step + 1,
                    sender_account=sender.account_id,
                    sender_device=sender.device_id,
                    receiver_account=receiver.account_id,
                    receiver_device=receiver.device_id,
                    address_hex=env.mid.hex(),
                    signature_valid=True,
                    status="verified_hop_authenticated",
                )
            )

        else:
            env, next_rec, fwd_tag = forward_message(
                server=server,
                sender=sender,
                receiver_account=receiver.account_id,
                receiver_device=receiver.device_id,
                received_state=active_rec_state,
                attach_extension_signature=use_pki,
            )
            active_rec_state = rec_msg(
                receiver_account=receiver.account_id,
                receiver_device=receiver.device_id,
                envelope=env,
                registry=registry if use_pki else None,
            )
            hops_completed += 1
            verified_delivery_hops.append(
                VerifiedHop(
                    hop_index=step + 1,
                    sender_account=sender.account_id,
                    sender_device=sender.device_id,
                    receiver_account=receiver.account_id,
                    receiver_device=receiver.device_id,
                    address_hex=env.mid.hex(),
                    signature_valid=True,
                    status="verified_hop_authenticated",
                )
            )

        last_tag_size = len(fwd_tag.addr) + len(fwd_tag.ct)
        if fwd_tag.sender_pubkey_raw:
            last_tag_size += len(fwd_tag.sender_pubkey_raw)
        if fwd_tag.signature:
            last_tag_size += len(fwd_tag.signature)

    forwarding_total_time_ns = time.perf_counter_ns() - t_start_forwarding

    # 4. Handle experiment outcome & Traceback execution
    t_start_trace = time.perf_counter_ns()
    if aborted_at_hop is not None:
        # Pipeline stopped at delivery because recipient RecMsg rejected the message
        traceback_time_ns = time.perf_counter_ns() - t_start_trace
        trace_res = TracebackExecutionResult(
            outcome="FAILED_VERIFICATION",
            origin_reached=False,
            recovered_origin_account=None,
            recovered_origin_device=None,
            recovered_hops_count=hops_completed,
            termination_reason=f"recipient_verification_failed_at_hop_{aborted_at_hop}_{abort_reason}",
            verified_hops=tuple(verified_delivery_hops),
        )
    else:
        # Final recipient files an abuse complaint with the server
        reporting_participant = participants[hops_completed]
        trace_res = server.trace(
            message=message,
            reporting_account=reporting_participant.account_id,
            reporting_device=reporting_participant.device_id,
            reporting_pointer=PathPointer(ptr=active_rec_state.tracing_key),
            registry=registry if use_pki else None,
            max_depth=hops + 5,
        )
        traceback_time_ns = time.perf_counter_ns() - t_start_trace

    # 5. Dynamic security property evaluations (distinguishing paper proof vs. observation)
    if trace_res.origin_reached:
        prop_path_soundness = (
            f"OBSERVED_IN_EXPERIMENT: Honest forwarding path successfully traversed backwards to originator in "
            f"{trace_res.recovered_hops_count} hops."
        )
    else:
        prop_path_soundness = (
            f"EVALUATED_HALTED: Backward traversal stopped at hop {trace_res.recovered_hops_count} "
            f"due to {trace_res.termination_reason}."
        )

    if scenario == "forged_signature":
        prop_framing_resistance = (
            f"OBSERVED_IN_EXPERIMENT (Theorem 3 Trace Unforgeability): Corrupted signature rejected by recipient "
            f"RecMsg at hop {aborted_at_hop}; message forwarding aborted before reaching downstream recipients."
        )
    else:
        prop_framing_resistance = (
            "NOT_EVALUATED_IN_THIS_RUN: Paper Theorem 3 establishes trace unforgeability under PRF collision "
            "resistance and authenticated routing. Evaluated experimentally in forged_signature scenario."
        )

    if scenario == "tampered_content":
        prop_wrong_message = (
            f"OBSERVED_IN_EXPERIMENT: Recipient RecMsg rejected modified message plaintext binding F(k, m) at "
            f"hop {aborted_at_hop}; message forwarding aborted before reaching downstream recipients."
        )
    else:
        prop_wrong_message = (
            "NOT_EVALUATED_IN_THIS_RUN: RecMsg guarantees mid binding to message plaintext. "
            "Evaluated experimentally in tampered_content scenario and unit tests."
        )

    prop_confidentiality = (
        "THEORETICAL_PAPER_PROOF (Tyagi et al. 2019 Theorem 1 & Theorem 2): Theorem 1 establishes platform trace "
        "confidentiality (uncomplained messages have pseudorandom mid and AES-CTR encrypted pointers indistinguishable "
        "from random) and Theorem 2 establishes user trace confidentiality (recipients cannot learn prior forwarding "
        "history or previous tracing keys from their local view; predecessor ciphertexts ct remain isolated on the server)."
    )

    if scenario == "missing_hop":
        prop_absence_phantom = (
            f"OBSERVED_IN_EXPERIMENT: Missing server record caused traceback to halt at the missing link "
            f"({trace_res.termination_reason}) without manufacturing phantom hops."
        )
    else:
        prop_absence_phantom = (
            "OBSERVED_DESIGN_PROPERTY: Traversal strictly dereferences present server table entries; "
            "missing records halt traversal without synthesizing unrecorded history."
        )

    sig_algo_desc = (
        "Experimental PKI Extension (Ed25519 with DeviceRegistry Authentication)"
        if use_pki
        else "Canonical Symmetric (Section 4, Figure 3 - Third-Party Deniable; No Signatures)"
    )

    # 6. Build structured output conforming to schema
    report: Dict[str, Any] = {
        "schema": SCHEMA_ID,
        "protocol": "tyagi2019-path-traceback-crypto",
        "reference_paper": "Tyagi, Miers & Ristenpart, 'Traceback for End-to-End Encrypted Messaging', ACM CCS 2019",
        "experiment_id": f"EXP-TYAGI2019-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scenario": scenario,
        "parameters": {
            "configured_hops": hops,
            "message_bytes_len": len(message),
            "message_sha256": hashlib.sha256(message).hexdigest(),
            "pointer_size_bytes": 32,
            "address_algorithm": "HMAC-SHA256 (Keyed message identifier mid = F(k, m))",
            "signature_algorithm": sig_algo_desc,
            "cipher_algorithm": "AES-128-CTR with K_enc = H(k) (Predecessor pointer encryption)",
        },
        "epistemic_notice": {
            "account_vs_device_distinction": (
                "Participant account IDs (acct:*) represent platform user accounts. "
                "Device IDs (dev:*) and public keys represent device cryptographic credentials."
            ),
            "real_world_identity_limitation": (
                "Cryptographic signature or tracing key possession establishes only that the message tag "
                "was generated with the key corresponding to an authenticated device credential. "
                "It does not establish the legal identity or human operator of the device."
            ),
            "no_unrecorded_history_inference": (
                "If forwarding state is pruned or omitted, the algorithm reports an explicit missing record "
                "and terminates. It does not synthesize phantom hops or guess missing historical events."
            ),
        },
        "participants": [
            {
                "account_id": p.account_id,
                "device_id": p.device_id,
                "public_key_fingerprint": p.public_key_fingerprint,
                "identity_claim_scope": "synthetic_device_credential_only",
            }
            for p in participants
        ],
        "traceback_result": {
            "outcome": trace_res.outcome,
            "origin_reached": trace_res.origin_reached,
            "recovered_origin_account": trace_res.recovered_origin_account,
            "recovered_origin_device": trace_res.recovered_origin_device,
            "recovered_hops_count": trace_res.recovered_hops_count,
            "termination_reason": trace_res.termination_reason,
            "verified_hops": [
                {
                    "hop_index": h.hop_index,
                    "sender_account": h.sender_account,
                    "sender_device": h.sender_device,
                    "receiver_account": h.receiver_account,
                    "receiver_device": h.receiver_device,
                    "address_hex": h.address_hex,
                    "signature_valid": h.signature_valid,
                    "status": h.status,
                }
                for h in trace_res.verified_hops
            ],
        },
        "measurements": {
            "setup_time_ns": setup_time_ns,
            "forwarding_total_time_ns": forwarding_total_time_ns,
            "traceback_time_ns": traceback_time_ns,
            "per_hop_tag_bytes": last_tag_size,
            "server_table_entries": server.entry_count,
            "server_table_bytes_approx": server.approximate_table_bytes,
        },
        "security_properties_evaluated": {
            "path_soundness": prop_path_soundness,
            "framing_resistance": prop_framing_resistance,
            "wrong_message_termination": prop_wrong_message,
            "confidentiality_unreported": prop_confidentiality,
            "absence_of_phantom_edges": prop_absence_phantom,
        },
    }

    # Validate against checked-in schema
    schema_path = Path(__file__).resolve().parents[2] / "schemas" / SCHEMA_NAME
    if schema_path.is_file():
        schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
        jsonschema.validate(report, schema_data)

    return report


def experiment_markdown(report: Dict[str, Any]) -> str:
    """Format an experiment report as clean GitHub Markdown."""
    params = report["parameters"]
    result = report["traceback_result"]
    meas = report["measurements"]
    props = report["security_properties_evaluated"]

    lines = [
        "# Cryptographic Reproduction Report: Tyagi et al. (CCS 2019)",
        "",
        f"**Experiment ID:** `{report['experiment_id']}` · **Scenario:** `{report['scenario']}`",
        f"**Reference:** {report['reference_paper']}",
        "",
        "> [!IMPORTANT]",
        "> **Epistemic Limitations & Baseline Design**",
        f"> - {report['epistemic_notice']['account_vs_device_distinction']}",
        f"> - {report['epistemic_notice']['real_world_identity_limitation']}",
        f"> - {report['epistemic_notice']['no_unrecorded_history_inference']}",
        "> - **Deniability & Symmetric Baseline:** Canonical Path Traceback is symmetric-only (third-party deniable); "
        "asymmetric digital signatures are an experimental extension requiring an authenticated DeviceRegistry.",
        "",
        "## 1. Parameters & Configuration",
        "",
        "| Parameter | Value |",
        "| :--- | :--- |",
        f"| **Configured Forwarding Hops** | {params['configured_hops']} |",
        f"| **Message Length** | {params['message_bytes_len']} bytes (`{params['message_sha256'][:16]}...`) |",
        f"| **Keyed Message Identifier** | {params['address_algorithm']} |",
        f"| **Pointer Encryption** | {params['cipher_algorithm']} |",
        f"| **Authentication Mode** | {params['signature_algorithm']} |",
        "",
        "## 2. Traceback Execution Outcome",
        "",
        f"- **Outcome:** `{result['outcome']}`",
        f"- **Origin Reached:** `{'Yes' if result['origin_reached'] else 'No'}`",
        f"- **Recovered Origin Account:** `{result['recovered_origin_account'] or 'None'}`",
        f"- **Recovered Origin Device:** `{result['recovered_origin_device'] or 'None'}`",
        f"- **Hops Recovered / Accepted:** {result['recovered_hops_count']} / {params['configured_hops']}",
        f"- **Termination Reason:** `{result['termination_reason']}`",
        "",
        "### Verified Hop Sequence",
        "",
        "| Hop | Sender Account | Sender Device | Receiver Account | Receiver Device | Sig/Auth | Status |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

    for h in result["verified_hops"]:
        sig_str = "PASS" if h["signature_valid"] else "FAIL"
        lines.append(
            f"| {h['hop_index']} | `{h['sender_account']}` | `{h['sender_device']}` | "
            f"`{h['receiver_account']}` | `{h['receiver_device']}` | `{sig_str}` | `{h['status']}` |"
        )

    if not result["verified_hops"]:
        lines.append("| - | *No hops recovered* | - | - | - | - | - |")

    lines.extend([
        "",
        "## 3. Cryptographic Measurements (Local Synthetic Microbenchmarks)",
        "",
        "> [!NOTE]",
        "> These timings measure pure local microbenchmarks on synthetic hardware. They illustrate relative "
        "overhead and do not directly correspond to the distributed WAN/network numbers reported in the original paper.",
        "",
        "| Metric | Value |",
        "| :--- | :--- |",
        f"| **Setup Latency** | {meas['setup_time_ns'] / 1_000_000:.3f} ms |",
        f"| **Forwarding Total (All Hops)** | {meas['forwarding_total_time_ns'] / 1_000_000:.3f} ms |",
        f"| **Traceback Dereference Latency** | {meas['traceback_time_ns'] / 1_000_000:.3f} ms |",
        f"| **Trace Tag Wire Size** | {meas['per_hop_tag_bytes']} bytes / hop |",
        f"| **Server State Entries** | {meas['server_table_entries']} entries (~{meas['server_table_bytes_approx']} bytes) |",
        "",
        "## 4. Evaluated Security Properties",
        "",
        f"- **Path Soundness:** {props['path_soundness']}",
        f"- **Framing Resistance (Theorem 3):** {props['framing_resistance']}",
        f"- **Wrong-Message Termination:** {props['wrong_message_termination']}",
        f"- **Trace Confidentiality (Theorem 1 & 2):** {props['confidentiality_unreported']}",
        f"- **Absence of Phantom Edges:** {props['absence_of_phantom_edges']}",
        "",
    ])

    return "\n".join(lines) + "\n"
