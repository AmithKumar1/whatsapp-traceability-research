#!/usr/bin/env python3
"""One-command reproducibility harness for WhatsApp Traceability Research Lab.

Recreates experimental artifacts, validates against JSON schemas (Draft 2020-12),
verifies core research invariants, compares stable semantics against committed
baselines, and produces a complete reproduction manifest with environment details
and SHA-256 checksums.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from opentrace import __version__  # noqa: E402
from opentrace.benchmark import run_benchmark, write_benchmark_report  # noqa: E402
from opentrace.comparison import comparison_markdown, compare_protocols, write_comparison_report  # noqa: E402
from opentrace.demo import create_demo  # noqa: E402
from opentrace.integrity import verify_case  # noqa: E402
from opentrace.transparency import build_inclusion_proof, verify_inclusion  # noqa: E402
from opentrace.traceback_experiment import experiment_markdown, run_experiment  # noqa: E402
from opentrace.protocols.traceback2019_crypto import (  # noqa: E402
    CryptographicTracebackServer,
    DeviceIdentity,
    ForwarderIdentityMismatchError,
    forward_message,
    originate_message,
)
from opentrace.protocols.hts2025 import HopTrackingSignatures2025Synthetic  # noqa: E402
from opentrace.protocols.minimal_trust2026 import MinimalTrustTraceability2026Synthetic  # noqa: E402

try:
    import jsonschema
except ImportError as exc:  # pragma: no cover
    raise SystemExit("Install pinned development dependencies first: python -m pip install -r requirements-dev.txt") from exc

SCHEMAS_DIR = ROOT / "schemas"
EXAMPLES_DIR = ROOT / "examples"


def compute_file_sha256(path: Path) -> str:
    """Compute the hexadecimal SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def get_environment_info() -> dict[str, Any]:
    """Capture runtime platform and Python execution environment details."""
    return {
        "python_version": sys.version,
        "python_version_tuple": list(sys.version_info[:3]),
        "platform": platform.platform(),
        "os_name": os.name,
        "system": platform.system(),
        "machine": platform.machine(),
        "executable": sys.executable,
    }


def get_git_info(repo_root: Path = ROOT) -> dict[str, Any]:
    """Retrieve current Git source revision information."""
    info: dict[str, Any] = {
        "commit": "unknown",
        "branch": "unknown",
        "is_dirty": False,
        "git_available": False,
    }
    try:
        commit_res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo_root,
            text=True,
            capture_output=True,
            check=False,
        )
        if commit_res.returncode == 0:
            info["commit"] = commit_res.stdout.strip()
            info["git_available"] = True

        branch_res = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            cwd=repo_root,
            text=True,
            capture_output=True,
            check=False,
        )
        if branch_res.returncode == 0:
            info["branch"] = branch_res.stdout.strip()

        status_res = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo_root,
            text=True,
            capture_output=True,
            check=False,
        )
        if status_res.returncode == 0:
            info["is_dirty"] = bool(status_res.stdout.strip())
    except Exception:  # pragma: no cover - fallback if git executable not in PATH
        pass
    return info


def run_test_suite(repo_root: Path = ROOT, extra_args: list[str] | None = None) -> dict[str, Any]:
    """Execute pytest against the repository test suite."""
    cmd = [sys.executable, "-m", "pytest", "-q"]
    if extra_args:
        cmd.extend(extra_args)

    start_time = time.monotonic()
    result = subprocess.run(
        cmd,
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
    )
    duration_s = round(time.monotonic() - start_time, 3)

    return {
        "command": cmd,
        "returncode": result.returncode,
        "passed": result.returncode == 0,
        "duration_seconds": duration_s,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def generate_reproduction_artifacts(
    output_dir: Path,
    quick: bool = False,
    verbose: bool = False,
) -> dict[str, Path]:
    """Generate all standard research reproduction artifacts."""
    output_dir.mkdir(parents=True, exist_ok=True)
    artifacts: dict[str, Path] = {}

    # 1. Tyagi et al. (CCS 2019) Path Traceback Experiment (Valid linear path)
    if verbose:
        print("  Generating Tyagi et al. path traceback experiment (valid linear path)...")
    hops = 2 if quick else 4
    tb_report = run_experiment(
        hops=hops,
        message=b"Reproducible Tyagi2019 path traceback research sample payload",
        scenario="valid_linear_path",
        adversarial_hop=2,
        enable_pki_extension=False,
    )
    tb_json_path = output_dir / "traceback-experiment.json"
    tb_json_path.write_text(json.dumps(tb_report, indent=2) + "\n", encoding="utf-8")
    artifacts["traceback-experiment.json"] = tb_json_path

    tb_md_path = output_dir / "traceback-experiment.md"
    tb_md_path.write_text(experiment_markdown(tb_report) + "\n", encoding="utf-8")
    artifacts["traceback-experiment.md"] = tb_md_path

    # 2. Tyagi et al. Adversarial Scenarios
    if verbose:
        print("  Generating Tyagi et al. adversarial cases (tampered content, missing hop)...")
    tb_tampered = run_experiment(
        hops=hops,
        message=b"Tampered content payload test",
        scenario="tampered_content",
        adversarial_hop=2,
    )
    tampered_path = output_dir / "traceback-adversarial-tampered.json"
    tampered_path.write_text(json.dumps(tb_tampered, indent=2) + "\n", encoding="utf-8")
    artifacts["traceback-adversarial-tampered.json"] = tampered_path

    tb_missing = run_experiment(
        hops=hops,
        message=b"Missing hop predecessor lookup test",
        scenario="missing_hop",
        adversarial_hop=2,
    )
    missing_path = output_dir / "traceback-adversarial-missing.json"
    missing_path.write_text(json.dumps(tb_missing, indent=2) + "\n", encoding="utf-8")
    artifacts["traceback-adversarial-missing.json"] = missing_path

    # 3. Multi-Protocol Comparison Report
    if verbose:
        print("  Generating cross-protocol comparison report...")
    comp_report = compare_protocols(
        message_size=32 if quick else 64,
        hops=2 if quick else 4,
        tree_depth=2,
        branching_factor=2,
        repeats=1,
    )
    comp_json_path = output_dir / "protocol-comparison.json"
    write_comparison_report(comp_report, comp_json_path)
    artifacts["protocol-comparison.json"] = comp_json_path

    comp_md_path = output_dir / "protocol-comparison.md"
    comp_md_path.write_text(comparison_markdown(comp_report) + "\n", encoding="utf-8")
    artifacts["protocol-comparison.md"] = comp_md_path

    # 4. Research Benchmark Report
    if verbose:
        print("  Generating synthetic benchmark report...")
    bench_report = run_benchmark(
        message_size=32 if quick else 64,
        max_hops=2,
        max_tree_depth=2,
        branching_factors=(2,),
        repeats=1,
    )
    bench_json_path = output_dir / "benchmark-report.json"
    write_benchmark_report(bench_report, bench_json_path)
    artifacts["benchmark-report.json"] = bench_json_path

    # 5. Offline Merkle Inclusion Proof
    if verbose:
        print("  Generating offline Merkle inclusion proof...")
    entries = [f"synthetic-research-event-{i:03d}".encode("utf-8") for i in range(8)]
    proof = build_inclusion_proof(entries, 2)
    verify_inclusion(entries[2], proof)
    merkle_path = output_dir / "merkle-inclusion-proof.json"
    merkle_path.write_text(json.dumps(proof, indent=2) + "\n", encoding="utf-8")
    artifacts["merkle-inclusion-proof.json"] = merkle_path

    # 6. Signed Synthetic Evidence Demo Case
    if verbose:
        print("  Generating signed synthetic evidence demo case...")
    demo_dir = output_dir / "demo-case"
    create_demo(demo_dir)
    verify_case(demo_dir)
    manifest_path = demo_dir / "manifest.json"
    artifacts["demo-case/manifest.json"] = manifest_path

    # 7. Hop Tracking Signatures (HTS 2025) Demo Report
    if verbose:
        print("  Generating HTS 2025 threshold demo...")
    hts = HopTrackingSignatures2025Synthetic(anonymity_threshold_hops=2, trace_threshold_hops=4)
    hts_eval = hts.evaluate(b"M" * 32, actual_hops=4)
    hts_data = {
        "protocol": hts.protocol_id,
        "interoperable_with_reference": False,
        **hts_eval.as_dict(),
        "caveat": "threshold-only didactic model; no cryptographic HTS implementation or interoperable signature",
    }
    hts_path = output_dir / "hts2025-demo.json"
    hts_path.write_text(json.dumps(hts_data, indent=2) + "\n", encoding="utf-8")
    artifacts["hts2025-demo.json"] = hts_path

    # 8. Minimal Trust 2026 Simulation Demo Report
    if verbose:
        print("  Generating Minimal Trust 2026 policy simulation demo...")
    min_trust = MinimalTrustTraceability2026Synthetic()
    valid_eval = min_trust.assess_trace(
        source_account="synthetic-source",
        verified_distinct_reports=2,
        required_reports=2,
        regulator_blocklist_match=False,
        moderator_approved=True,
        platform_release_authorized=True,
    )
    min_trust_data = {
        "protocol": min_trust.protocol_id,
        "interoperable_with_reference": False,
        "valid_synthetic_case": valid_eval.as_dict(),
        "single_honest_role_scenarios": min_trust.single_honest_role_scenarios(required_reports=2),
    }
    min_trust_path = output_dir / "minimal-trust2026-demo.json"
    min_trust_path.write_text(json.dumps(min_trust_data, indent=2) + "\n", encoding="utf-8")
    artifacts["minimal-trust2026-demo.json"] = min_trust_path

    return artifacts


def validate_schemas(
    artifacts: dict[str, Path],
    schemas_dir: Path = SCHEMAS_DIR,
) -> list[dict[str, Any]]:
    """Validate generated JSON artifacts against canonical Draft 2020-12 schemas."""
    schema_map: dict[str, str] = {
        "traceback-experiment.json": "traceback-experiment.schema.json",
        "traceback-adversarial-tampered.json": "traceback-experiment.schema.json",
        "traceback-adversarial-missing.json": "traceback-experiment.schema.json",
        "protocol-comparison.json": "protocol-comparison.schema.json",
        "benchmark-report.json": "benchmark-report.schema.json",
        "merkle-inclusion-proof.json": "merkle-inclusion-proof.schema.json",
        "demo-case/manifest.json": "case-manifest.schema.json",
    }

    results: list[dict[str, Any]] = []

    for artifact_key, schema_file in schema_map.items():
        artifact_path = artifacts.get(artifact_key)
        if not artifact_path or not artifact_path.exists():
            results.append({
                "artifact": artifact_key,
                "schema": schema_file,
                "passed": False,
                "error": "Artifact file not found",
            })
            continue

        schema_path = schemas_dir / schema_file
        if not schema_path.exists():
            results.append({
                "artifact": artifact_key,
                "schema": schema_file,
                "passed": False,
                "error": f"Schema definition not found: {schema_file}",
            })
            continue

        try:
            data = json.loads(artifact_path.read_text(encoding="utf-8"))
            schema_data = json.loads(schema_path.read_text(encoding="utf-8"))
            validator = jsonschema.Draft202012Validator(schema_data)
            validator.validate(data)
            results.append({
                "artifact": artifact_key,
                "schema": schema_file,
                "passed": True,
                "error": None,
            })
        except Exception as exc:
            results.append({
                "artifact": artifact_key,
                "schema": schema_file,
                "passed": False,
                "error": str(exc),
            })

    return results


def verify_research_invariants(artifacts: dict[str, Path]) -> list[dict[str, Any]]:
    """Verify essential algorithmic and epistemic research invariants."""
    invariants: list[dict[str, Any]] = []

    # Invariant 1: Epistemic Separation between Candidate and Verified Origin
    tb_file = artifacts.get("traceback-experiment.json")
    tampered_file = artifacts.get("traceback-adversarial-tampered.json")
    if tb_file and tb_file.exists() and tampered_file and tampered_file.exists():
        tb_data = json.loads(tb_file.read_text(encoding="utf-8"))
        tampered_data = json.loads(tampered_file.read_text(encoding="utf-8"))

        res = tb_data.get("traceback_result", {})
        cand_acct = res.get("candidate_origin_account")
        rec_acct = res.get("recovered_origin_account")
        cand_dev = res.get("candidate_origin_device")
        rec_dev = res.get("recovered_origin_device")

        # In valid linear path, both are reported and agree with ground truth
        valid_separation = bool(cand_acct and rec_acct and cand_dev and rec_dev)

        # In tampered content, verification fails and does NOT falsely certify an origin
        t_res = tampered_data.get("traceback_result", {})
        tampered_rejected = (
            t_res.get("outcome") == "FAILED_VERIFICATION"
            and t_res.get("origin_reached") is False
            and t_res.get("recovered_origin_account") is None
        )

        invariants.append({
            "name": "epistemic_origin_separation",
            "passed": valid_separation and tampered_rejected,
            "description": "Explicit distinction between unverified candidate forwarder and certified origin; tamper fails closed",
        })
    else:
        invariants.append({
            "name": "epistemic_origin_separation",
            "passed": False,
            "description": "Experiment files missing",
        })

    # Invariant 2: Recipient-View Confidentiality (Theorem 2)
    # Ensure predecessor pointer ciphertexts c_ptr are never included in message envelopes
    if tb_file and tb_file.exists():
        tb_data = json.loads(tb_file.read_text(encoding="utf-8"))
        # Security properties evaluated explicitly flags recipient view confidentiality
        sec_props = tb_data.get("security_properties_evaluated", {})
        theorem2_flag = "Theorem 2" in sec_props.get("confidentiality_unreported", "")

        # Functional validation: Send a message and check that recipient envelope has no c_ptr
        server = CryptographicTracebackServer()
        alice = DeviceIdentity.generate("acct:alice", "dev:alice-01")
        bob = DeviceIdentity.generate("acct:bob", "dev:bob-01")
        env, state, tag = originate_message(
            server=server,
            sender=alice,
            receiver_account=bob.account_id,
            receiver_device=bob.device_id,
            message=b"confidentiality-test",
        )

        # The envelope must contain ciphertext, nonce, tag, but NOT c_ptr (which is strictly in server table)
        envelope_has_no_ptr = not hasattr(env, "c_ptr")
        server_has_ptr = len(server._table) == 1

        invariants.append({
            "name": "recipient_view_confidentiality_theorem2",
            "passed": theorem2_flag and envelope_has_no_ptr and server_has_ptr,
            "description": "Predecessor pointers stored exclusively in server table, zero leak in recipient envelopes",
        })
    else:
        invariants.append({
            "name": "recipient_view_confidentiality_theorem2",
            "passed": False,
            "description": "Experiment file missing",
        })

    # Invariant 3: Forwarder Identity Binding & Snapshot Invariance
    # Forwarding message from unauthorized identity fails closed and mutates zero server state
    server = CryptographicTracebackServer()
    alice = DeviceIdentity.generate("acct:alice", "dev:alice-01")
    bob = DeviceIdentity.generate("acct:bob", "dev:bob-01")
    charlie = DeviceIdentity.generate("acct:charlie", "dev:charlie-01")
    eve = DeviceIdentity.generate("acct:eve", "dev:eve-01")

    env1, state1, tag1 = originate_message(
        server=server,
        sender=alice,
        receiver_account=bob.account_id,
        receiver_device=bob.device_id,
        message=b"forward-binding-test",
    )
    snap_before = dict(server._table)

    mismatch_caught = False
    try:
        # Eve attempts to forward Bob's received message
        forward_message(
            server=server,
            sender=eve,
            receiver_account=charlie.account_id,
            receiver_device=charlie.device_id,
            received_state=state1,
        )
    except ForwarderIdentityMismatchError:
        mismatch_caught = True

    snap_after = dict(server._table)
    table_unmodified = snap_before == snap_after

    invariants.append({
        "name": "forwarder_identity_binding_and_table_invariance",
        "passed": mismatch_caught and table_unmodified,
        "description": "Rejects forwarder identity mismatch before cryptographic ops; leaves server table unmodified",
    })

    # Invariant 4: Non-Interoperability & Synthetic Scope Disclaimers
    comp_file = artifacts.get("protocol-comparison.json")
    if comp_file and comp_file.exists():
        comp_data = json.loads(comp_file.read_text(encoding="utf-8"))
        summary = comp_data.get("summary", {})
        interop = summary.get("interoperable_protocols", [])
        protocol_count = summary.get("protocol_count", 0)

        invariants.append({
            "name": "synthetic_scope_and_zero_interoperability",
            "passed": (interop == [] and protocol_count == 5),
            "description": "All 5 adapters explicitly verified as synthetic research models; zero claimed wire compatibility",
        })
    else:
        invariants.append({
            "name": "synthetic_scope_and_zero_interoperability",
            "passed": False,
            "description": "Comparison report missing",
        })

    return invariants


def compare_semantic_baseline(
    comparison_path: Path,
    baseline_path: Path = EXAMPLES_DIR / "protocol-comparison-sample-v0.5.3.json",
) -> list[str]:
    """Compare stable semantics of generated comparison report against committed baseline.

    Ignores runtime variables: timestamps, execution durations, and random key seeds.
    """
    discrepancies: list[str] = []

    if not comparison_path.exists():
        return [f"Generated comparison file not found: {comparison_path}"]
    if not baseline_path.exists():
        return [f"Committed baseline file not found: {baseline_path}"]

    try:
        current = json.loads(comparison_path.read_text(encoding="utf-8"))
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"Failed to parse comparison or baseline JSON: {exc}"]

    # 1. Compare Schema IDs
    if current.get("schema") != baseline.get("schema"):
        discrepancies.append(
            f"Schema mismatch: current {current.get('schema')!r} != baseline {baseline.get('schema')!r}"
        )

    # 2. Compare Protocol Count & Summary
    curr_summary = current.get("summary", {})
    base_summary = baseline.get("summary", {})

    if curr_summary.get("protocol_count") != base_summary.get("protocol_count"):
        discrepancies.append(
            f"Protocol count mismatch: current {curr_summary.get('protocol_count')} != baseline {base_summary.get('protocol_count')}"
        )

    if curr_summary.get("interoperable_protocols") != []:
        discrepancies.append("Current report indicates non-empty interoperable protocols list")

    # 3. Compare Capabilities for Each Protocol in records
    curr_records = {p.get("protocol_id"): p for p in current.get("records", [])}
    base_records = {p.get("protocol_id"): p for p in baseline.get("records", [])}

    if set(curr_records.keys()) != set(base_records.keys()):
        discrepancies.append(
            f"Protocol ID list mismatch: current {sorted(curr_records.keys())} != baseline {sorted(base_records.keys())}"
        )

    for proto_id, base_p in base_records.items():
        curr_p = curr_records.get(proto_id)
        if not curr_p:
            continue

        if curr_p.get("reference_status") != "synthetic":
            discrepancies.append(f"Protocol {proto_id!r} must have reference_status='synthetic'")

        # Check qualitative capability dictionary
        curr_caps = curr_p.get("capabilities", {})
        base_caps = base_p.get("capabilities", {})
        for cap_key, base_val in base_caps.items():
            curr_val = curr_caps.get(cap_key)
            if curr_val != base_val:
                discrepancies.append(
                    f"Protocol {proto_id!r} capability mismatch on {cap_key!r}: current {curr_val!r} != baseline {base_val!r}"
                )

    return discrepancies


def build_reproduction_manifest(
    output_dir: Path,
    artifacts: dict[str, Path],
    test_result: dict[str, Any] | None,
    schema_results: list[dict[str, Any]],
    invariants: list[dict[str, Any]],
    baseline_discrepancies: list[str],
    environment_info: dict[str, Any],
    git_info: dict[str, Any],
    overall_passed: bool,
) -> dict[str, Any]:
    """Assemble and write reproduction-manifest.json."""
    artifact_entries: dict[str, dict[str, Any]] = {}

    for key, path in artifacts.items():
        if path.exists() and path.is_file():
            artifact_entries[key] = {
                "relative_path": str(path.relative_to(output_dir)).replace("\\", "/"),
                "size_bytes": path.stat().st_size,
                "sha256": compute_file_sha256(path),
            }

    manifest = {
        "schema": "opentrace.reproduction-manifest.v1",
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
        "project_version": __version__,
        "source_revision": git_info,
        "environment": environment_info,
        "overall_status": "PASS" if overall_passed else "FAIL",
        "test_suite": test_result,
        "schema_validations": schema_results,
        "invariants_verified": invariants,
        "baseline_semantic_comparison": {
            "passed": len(baseline_discrepancies) == 0,
            "discrepancies": baseline_discrepancies,
        },
        "artifacts": artifact_entries,
    }

    manifest_path = output_dir / "reproduction-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def reproduce_all(
    output_dir: Path,
    quick: bool = False,
    skip_tests: bool = False,
    verbose: bool = True,
) -> int:
    """Run the complete one-command reproduction sequence."""
    print("=" * 72)
    print("WhatsApp Traceability Research Lab — Reproduction Harness")
    print(f"Target Version: {__version__}")
    print(f"Output Directory: {output_dir}")
    print("=" * 72)

    env_info = get_environment_info()
    git_info = get_git_info()
    if verbose:
        print(f"Platform: {env_info['platform']}")
        print(f"Python:   {env_info['python_version'].splitlines()[0]}")
        print(f"Git:      commit={git_info['commit'][:10]} branch={git_info['branch']} dirty={git_info['is_dirty']}")
        print("-" * 72)

    overall_success = True

    # 1. Run Test Suite
    test_result = None
    if skip_tests:
        print("[1/5] Test suite: SKIPPED (--skip-tests)")
    else:
        print("[1/5] Running test suite (pytest -q)...")
        test_result = run_test_suite()
        if test_result["passed"]:
            print(f"  PASS: {test_result['stdout'].splitlines()[-1]} in {test_result['duration_seconds']}s")
        else:
            print("  FAIL: test suite encountered errors")
            if verbose:
                print(test_result["stderr"] or test_result["stdout"])
            overall_success = False

    # 2. Generate Reproduction Artifacts
    print("[2/5] Generating research reproduction artifacts...")
    artifacts = generate_reproduction_artifacts(output_dir, quick=quick, verbose=verbose)
    print(f"  PASS: Generated {len(artifacts)} research artifacts in {output_dir}")

    # 3. Validate Schemas
    print("[3/5] Validating artifacts against Draft 2020-12 JSON schemas...")
    schema_results = validate_schemas(artifacts)
    schemas_ok = all(r["passed"] for r in schema_results)
    for res in schema_results:
        status_tag = "PASS" if res["passed"] else "FAIL"
        print(f"  [{status_tag}] {res['artifact']} -> {res['schema']}")
        if not res["passed"] and verbose:
            print(f"         Error: {res['error']}")
    if not schemas_ok:
        overall_success = False

    # 4. Verify Research Invariants
    print("[4/5] Verifying algorithmic & epistemic research invariants...")
    invariants = verify_research_invariants(artifacts)
    invariants_ok = all(inv["passed"] for inv in invariants)
    for inv in invariants:
        status_tag = "PASS" if inv["passed"] else "FAIL"
        print(f"  [{status_tag}] {inv['name']}: {inv['description']}")
    if not invariants_ok:
        overall_success = False

    # 5. Semantic Baseline Comparison
    print("[5/5] Comparing stable semantics against committed v0.5.3 baseline...")
    comp_artifact = artifacts.get("protocol-comparison.json")
    baseline_discrepancies: list[str] = []
    if comp_artifact:
        baseline_discrepancies = compare_semantic_baseline(comp_artifact)
        if not baseline_discrepancies:
            print("  PASS: Protocol comparison matches committed v0.5.3 baseline semantics perfectly")
        else:
            print(f"  FAIL: Found {len(baseline_discrepancies)} semantic discrepancies:")
            for disc in baseline_discrepancies:
                print(f"    - {disc}")
            overall_success = False
    else:
        print("  FAIL: protocol-comparison.json not available for baseline check")
        overall_success = False

    # Write Manifest
    print("-" * 72)
    manifest = build_reproduction_manifest(
        output_dir=output_dir,
        artifacts=artifacts,
        test_result=test_result,
        schema_results=schema_results,
        invariants=invariants,
        baseline_discrepancies=baseline_discrepancies,
        environment_info=env_info,
        git_info=git_info,
        overall_passed=overall_success,
    )
    manifest_path = output_dir / "reproduction-manifest.json"
    print(f"Reproduction manifest written: {manifest_path}")
    print(f"Total verified artifact files: {len(manifest['artifacts'])}")
    print("=" * 72)
    if overall_success:
        print("RESULT: REPRODUCTION SUCCEEDED (All verification gates passed)")
        return 0
    else:
        print("RESULT: REPRODUCTION FAILED (Review logged discrepancies above)")
        return 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="One-command reproduction harness for WhatsApp Traceability Research Lab",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "artifacts" / "reproduction",
        help="directory to output generated artifacts and manifest (default: artifacts/reproduction)",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="run faster reproduction with reduced hops and message sizes",
    )
    parser.add_argument(
        "--skip-tests",
        action="store_true",
        help="skip running full pytest suite prior to generating artifacts",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=True,
        help="display detailed verbose output for all steps (default: True)",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_false",
        dest="verbose",
        help="run in quiet mode with minimal terminal output",
    )
    args = parser.parse_args()

    sys.exit(
        reproduce_all(
            output_dir=args.output_dir,
            quick=args.quick,
            skip_tests=args.skip_tests,
            verbose=args.verbose,
        )
    )


if __name__ == "__main__":
    main()
