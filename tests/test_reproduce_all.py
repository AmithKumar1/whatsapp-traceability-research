from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from scripts.reproduce_all import (  # noqa: E402
    build_reproduction_manifest,
    compare_semantic_baseline,
    compute_file_sha256,
    generate_reproduction_artifacts,
    get_environment_info,
    get_git_info,
    validate_schemas,
    verify_research_invariants,
)
from opentrace.protocols.traceback2019_crypto import (  # noqa: E402
    CryptographicTracebackServer,
    DeviceIdentity,
    ForwarderIdentityMismatchError,
    forward_message,
    originate_message,
)


def test_environment_and_git_info_structure() -> None:
    env = get_environment_info()
    assert "python_version" in env
    assert "platform" in env
    assert "executable" in env
    assert isinstance(env["python_version_tuple"], list)

    git = get_git_info(ROOT)
    assert "commit" in git
    assert "branch" in git
    assert "is_dirty" in git
    assert isinstance(git["is_dirty"], bool)


def test_reproduction_manifest_generation(tmp_path: Path) -> None:
    artifacts = generate_reproduction_artifacts(tmp_path, quick=True, verbose=False)
    assert len(artifacts) >= 8

    schema_results = validate_schemas(artifacts)
    assert all(r["passed"] for r in schema_results), [r for r in schema_results if not r["passed"]]

    invariants = verify_research_invariants(artifacts)
    assert all(inv["passed"] for inv in invariants), [inv for inv in invariants if not inv["passed"]]

    comp_artifact = artifacts["protocol-comparison.json"]
    discrepancies = compare_semantic_baseline(comp_artifact)
    assert discrepancies == []

    env_info = get_environment_info()
    git_info = get_git_info(ROOT)

    manifest = build_reproduction_manifest(
        output_dir=tmp_path,
        artifacts=artifacts,
        test_result={"passed": True, "duration_seconds": 1.2},
        schema_results=schema_results,
        invariants=invariants,
        baseline_discrepancies=discrepancies,
        environment_info=env_info,
        git_info=git_info,
        overall_passed=True,
    )
    assert manifest["overall_status"] == "PASS"

    manifest_path = tmp_path / "reproduction-manifest.json"
    assert manifest_path.exists()
    loaded_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    assert loaded_manifest["schema"] == "opentrace.reproduction-manifest.v1"
    assert loaded_manifest["overall_status"] == "PASS"
    assert len(loaded_manifest["artifacts"]) == len(artifacts)

    # Check each artifact entry has valid SHA-256 and size
    for key, info in loaded_manifest["artifacts"].items():
        assert info["size_bytes"] > 0
        assert len(info["sha256"]) == 64
        # Verify hash matches on disk
        actual_path = tmp_path / info["relative_path"]
        assert actual_path.exists()
        assert compute_file_sha256(actual_path) == info["sha256"]


def test_schema_validation_catches_invalid_payload(tmp_path: Path) -> None:
    artifacts = generate_reproduction_artifacts(tmp_path, quick=True, verbose=False)

    # Tamper with protocol-comparison.json by deleting a required field
    comp_file = artifacts["protocol-comparison.json"]
    data = json.loads(comp_file.read_text(encoding="utf-8"))
    del data["summary"]
    comp_file.write_text(json.dumps(data), encoding="utf-8")

    results = validate_schemas(artifacts)
    comp_result = next(r for r in results if r["artifact"] == "protocol-comparison.json")
    assert comp_result["passed"] is False
    assert "summary" in comp_result["error"]


def test_semantic_baseline_comparison_stability(tmp_path: Path) -> None:
    artifacts = generate_reproduction_artifacts(tmp_path, quick=True, verbose=False)
    comp_file = artifacts["protocol-comparison.json"]

    # 1. Clean report has 0 discrepancies
    discrepancies = compare_semantic_baseline(comp_file)
    assert discrepancies == []

    # 2. Mutate runtime timings — must still have 0 discrepancies (stable semantics)
    data = json.loads(comp_file.read_text(encoding="utf-8"))
    data["records"][0]["measurements"]["construction_ns_median"] = 999999999
    data["records"][0]["samples_ns"]["construction"] = [1, 2, 3]
    comp_file.write_text(json.dumps(data), encoding="utf-8")
    assert compare_semantic_baseline(comp_file) == []

    # 3. Mutate qualitative capability — must trigger a discrepancy
    data["records"][0]["capabilities"]["disclosure_mode"] = "INVALID_CAPABILITY"
    comp_file.write_text(json.dumps(data), encoding="utf-8")
    discrepancies = compare_semantic_baseline(comp_file)
    assert len(discrepancies) >= 1
    assert any("disclosure_mode" in d for d in discrepancies)


def test_candidate_versus_verified_origin_separation_invariant(tmp_path: Path) -> None:
    artifacts = generate_reproduction_artifacts(tmp_path, quick=True, verbose=False)
    invariants = verify_research_invariants(artifacts)

    epistemic_inv = next(i for i in invariants if i["name"] == "epistemic_origin_separation")
    assert epistemic_inv["passed"] is True

    # Check that tampered experiment has FAILED_VERIFICATION and no recovered origin
    tampered_data = json.loads(artifacts["traceback-adversarial-tampered.json"].read_text(encoding="utf-8"))
    res = tampered_data["traceback_result"]
    assert res["outcome"] == "FAILED_VERIFICATION"
    assert res["origin_reached"] is False
    assert res["recovered_origin_account"] is None


def test_recipient_view_confidentiality_theorem2_invariant(tmp_path: Path) -> None:
    artifacts = generate_reproduction_artifacts(tmp_path, quick=True, verbose=False)
    invariants = verify_research_invariants(artifacts)

    confidentiality_inv = next(i for i in invariants if i["name"] == "recipient_view_confidentiality_theorem2")
    assert confidentiality_inv["passed"] is True


def test_forwarder_identity_binding_and_table_snapshot_invariance() -> None:
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
        message=b"identity-binding-test",
    )
    table_before = dict(server._table)

    with pytest.raises(ForwarderIdentityMismatchError):
        forward_message(
            server=server,
            sender=eve,
            receiver_account=charlie.account_id,
            receiver_device=charlie.device_id,
            received_state=state1,
        )

    table_after = dict(server._table)
    assert table_before == table_after


def test_reproduce_all_cli_execution(tmp_path: Path) -> None:
    out_dir = tmp_path / "repro_cli_test"
    cmd = [
        sys.executable,
        str(ROOT / "scripts" / "reproduce_all.py"),
        "--quick",
        "--skip-tests",
        "--output-dir",
        str(out_dir),
    ]

    res = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, check=False)
    assert res.returncode == 0, res.stdout + res.stderr
    assert "RESULT: REPRODUCTION SUCCEEDED" in res.stdout
    assert (out_dir / "reproduction-manifest.json").exists()
