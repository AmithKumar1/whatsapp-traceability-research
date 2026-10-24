from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from opentrace.authorization import AuthorizationError, sign_approval, verify_authorization
from opentrace.authorization_demo import create_authorization_demo
from opentrace.canonical import canonical_bytes
from opentrace.demo import create_demo
from opentrace.integrity import IntegrityError, _safe_path, verify_case
from opentrace.strictjson import loads_strict
from opentrace.tracegraph import TraceGraphError, build_trace_report, validate_events
from opentrace.transparency import TransparencyError, build_inclusion_proof, merkle_root, verify_inclusion


def test_demo_bundle_verifies(tmp_path: Path) -> None:
    case_dir = create_demo(tmp_path / "demo")
    result = verify_case(case_dir)
    assert result["status"] == "VALID"
    assert result["manifest_version"] == "0.2"
    assert result["records_checked"] == 6
    assert result["manifest_signature"] == "valid"
    assert result["case_inventory"] == "complete"


def test_demo_exposes_only_synthetic_ids(tmp_path: Path) -> None:
    case_dir = create_demo(tmp_path / "demo")
    report = json.loads((case_dir / "trace.json").read_text(encoding="utf-8"))
    assert report["first_originator_candidate"]["actor_id"] == "acct:synthetic-A"
    assert "not an identity claim" in report["first_originator_candidate"]["status"]
    assert report["mode"] == "ORIGIN_ONLY"
    assert "forwarding_tree_in_supplied_dataset" not in report
    assert "reported_path_oldest_to_newest" not in report
    path_report = json.loads((case_dir / "trace-path-demo.json").read_text(encoding="utf-8"))
    tree_report = json.loads((case_dir / "trace-tree-demo.json").read_text(encoding="utf-8"))
    assert path_report["mode"] == "PATH"
    assert len(path_report["reported_path_oldest_to_newest"]) == 4
    assert tree_report["mode"] == "TREE"
    assert len(tree_report["forwarding_tree_in_supplied_dataset"]) == 6


def test_external_trusted_key_can_verify_without_bundled_key(tmp_path: Path) -> None:
    case_dir = create_demo(tmp_path / "demo")
    trusted_key = tmp_path / "trusted-public-key.pem"
    trusted_key.write_bytes((case_dir / "signing-public-key.pem").read_bytes())
    (case_dir / "signing-public-key.pem").unlink()
    result = verify_case(case_dir, trusted_key)
    assert result["status"] == "VALID"
    assert result["verification_key_source"] == "externally-supplied trusted public key"


def test_mismatched_external_trusted_key_fails(tmp_path: Path) -> None:
    case_dir = create_demo(tmp_path / "demo")
    wrong = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    trusted_key = tmp_path / "wrong.pem"
    trusted_key.write_bytes(wrong)
    with pytest.raises(IntegrityError, match="fingerprint does not match"):
        verify_case(case_dir, trusted_key)


def test_tampered_evidence_file_fails(tmp_path: Path) -> None:
    case_dir = create_demo(tmp_path / "demo")
    (case_dir / "events.json").write_text("[]\n", encoding="utf-8")
    with pytest.raises(IntegrityError, match="file size mismatch|file digest mismatch"):
        verify_case(case_dir)


def test_tampered_manifest_fails_signature(tmp_path: Path) -> None:
    case_dir = create_demo(tmp_path / "demo")
    manifest_path = case_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["case_id"] = "CHANGED"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(IntegrityError, match="signature verification failed"):
        verify_case(case_dir)


def test_duplicate_event_id_rejected(tmp_path: Path) -> None:
    case_dir = create_demo(tmp_path / "demo")
    events = json.loads((case_dir / "events.json").read_text(encoding="utf-8"))
    events.append(dict(events[0]))
    with pytest.raises(TraceGraphError, match="duplicate event_id"):
        validate_events(events)


def test_missing_parent_rejected(tmp_path: Path) -> None:
    case_dir = create_demo(tmp_path / "demo")
    events = json.loads((case_dir / "events.json").read_text(encoding="utf-8"))
    events[1]["parent_event_id"] = "does-not-exist"
    with pytest.raises(TraceGraphError, match="missing parent event"):
        validate_events(events)


def test_cycle_rejected() -> None:
    events: list[dict[str, Any]] = [
        {"event_id":"origin","event_type":"ORIGIN","actor_id":"acct:o","timestamp":"2026-10-23T08:00:00Z","time_source":"synthetic","parent_event_id":None,"content_ref":"c","evidence_class":"synthetic"},
        {"event_id":"b","event_type":"FORWARD","actor_id":"acct:b","timestamp":"2026-10-23T08:01:00Z","time_source":"synthetic","parent_event_id":"c","content_ref":"c","evidence_class":"synthetic"},
        {"event_id":"c","event_type":"FORWARD","actor_id":"acct:c","timestamp":"2026-10-23T08:02:00Z","time_source":"synthetic","parent_event_id":"b","content_ref":"c","evidence_class":"synthetic"},
    ]
    with pytest.raises(TraceGraphError, match="cycle detected"):
        validate_events(events)


def test_manifest_path_traversal_rejected(tmp_path: Path) -> None:
    case_dir = create_demo(tmp_path / "demo")
    with pytest.raises(IntegrityError, match="unsafe manifest path"):
        _safe_path(case_dir, "../outside")
    with pytest.raises(IntegrityError, match="unsafe manifest path"):
        _safe_path(case_dir, "/etc/passwd")
    with pytest.raises(IntegrityError, match="unsafe manifest path"):
        _safe_path(case_dir, r"..\outside")


def test_unlisted_payload_file_fails_inventory_check(tmp_path: Path) -> None:
    case_dir = create_demo(tmp_path / "demo")
    (case_dir / "unlisted.txt").write_text("secret extra data", encoding="utf-8")
    with pytest.raises(IntegrityError, match="inventory mismatch"):
        verify_case(case_dir)


def test_duplicate_json_keys_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        loads_strict('{"a":1,"a":2}')


def test_restricted_canonical_json_sorts_unicode_keys_by_utf16() -> None:
    # RFC 8785 sorts names by UTF-16 code units; U+1F600 starts with D83D,
    # which sorts before U+E000 even though its Unicode scalar value is larger.
    data = {"\ue000": 1, "😀": 2, "z": 3}
    canonical = canonical_bytes(data).decode("utf-8")
    assert canonical.index('"z"') < canonical.index('"😀"') < canonical.index('"\ue000"')
    with pytest.raises(ValueError, match="Floating-point"):
        canonical_bytes({"value": 1.25})


def test_authorization_demo_passes_policy(tmp_path: Path) -> None:
    result = create_authorization_demo(tmp_path / "auth-demo")
    assert result["status"] == "AUTHORIZED_BY_CONFIGURED_POLICY"
    assert result["approval_count"] == 2
    assert result["distinct_trust_domains"] == 2


def _build_auth_fixture(tmp_path: Path, *, same_domain: bool = False, allow_tree: bool = False):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    request = {
        "request_id": "REQ-1", "policy_id": "test-policy-v1", "case_id": "CASE-1", "protocol_id": "synthetic-v1",
        "target_ref": "msg:synthetic-1", "disclosure_mode": "ORIGIN_ONLY", "purpose": "unit test",
        "legal_basis_ref": "synthetic-only", "requested_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
        "request_version": "1",
        "scope": {"dataset_refs": ["synthetic-events.json"], "message_ref_only": True, "include_intermediate_recipients": False},
    }
    policy = {"policy_id": "test-policy-v1", "min_approvals": 2, "required_roles": ["case_reviewer", "privacy_reviewer"],
              "require_distinct_trust_domains": True, "allowed_modes": ["ORIGIN_ONLY", "TREE"] if allow_tree else ["ORIGIN_ONLY"], "max_validity_seconds": 3600}
    principals, approvals = {}, []
    approver_specs = (("case_reviewer", "domain-a"), ("privacy_reviewer", "domain-a" if same_domain else "domain-b"))
    for i, (role, domain) in enumerate(approver_specs, start=1):
        private = Ed25519PrivateKey.generate()
        public_path = tmp_path / f"approver{i}.pem"
        public_path.write_bytes(private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        pid = f"p{i}"
        from opentrace.authorization import public_key_fingerprint
        principals[pid] = {"role": role, "trust_domain": domain, "public_key_path": public_path.name, "public_key_fingerprint": public_key_fingerprint(private.public_key())}
        approvals.append(sign_approval(request, approver_id=pid, approval_id=f"a{i}", approved_at=now, private_key=private, policy=policy, role=role, trust_domain=domain))
    trust = {"registry_version": "1", "principals": principals}
    return now, request, policy, trust, approvals


def test_authorization_request_tampering_invalidates_approvals(tmp_path: Path) -> None:
    now, request, policy, trust, approvals = _build_auth_fixture(tmp_path, allow_tree=True)
    request["disclosure_mode"] = "TREE"
    request["scope"]["include_intermediate_recipients"] = True
    with pytest.raises(AuthorizationError, match="not bound to this request|insufficient valid approvals"):
        verify_authorization(request, approvals, trust, policy, now=now, trust_base_dir=tmp_path)


def test_authorization_requires_distinct_trust_domains(tmp_path: Path) -> None:
    now, request, policy, trust, approvals = _build_auth_fixture(tmp_path, same_domain=True)
    with pytest.raises(AuthorizationError, match="distinct trust domains"):
        verify_authorization(request, approvals, trust, policy, now=now, trust_base_dir=tmp_path)


def test_authorization_rejects_expired_request(tmp_path: Path) -> None:
    now, request, policy, trust, approvals = _build_auth_fixture(tmp_path)
    with pytest.raises(AuthorizationError, match="expired"):
        verify_authorization(request, approvals, trust, policy, now=now + timedelta(hours=1), trust_base_dir=tmp_path)


def test_authorization_rejects_unapproved_disclosure_mode(tmp_path: Path) -> None:
    now, request, policy, trust, approvals = _build_auth_fixture(tmp_path)
    request["disclosure_mode"] = "TREE"
    policy["allowed_modes"] = ["ORIGIN_ONLY"]
    with pytest.raises(AuthorizationError, match="not allowed by policy"):
        verify_authorization(request, approvals, trust, policy, now=now, trust_base_dir=tmp_path)


def test_authorization_rejects_policy_missing_policy_id(tmp_path: Path) -> None:
    now, request, policy, trust, approvals = _build_auth_fixture(tmp_path)
    del policy["policy_id"]
    with pytest.raises(AuthorizationError, match="invalid policy"):
        verify_authorization(request, approvals, trust, policy, now=now, trust_base_dir=tmp_path)


def test_authorization_rejects_key_path_escape(tmp_path: Path) -> None:
    now, request, policy, trust, approvals = _build_auth_fixture(tmp_path)
    trust["principals"]["p1"]["public_key_path"] = "../outside.pem"
    with pytest.raises(AuthorizationError, match="insufficient valid approvals"):
        verify_authorization(request, approvals, trust, policy, now=now, trust_base_dir=tmp_path)


def test_authorization_rejects_duplicate_dataset_refs(tmp_path: Path) -> None:
    now, request, policy, trust, approvals = _build_auth_fixture(tmp_path)
    request["scope"]["dataset_refs"].append("synthetic-events.json")
    with pytest.raises(AuthorizationError, match="may not contain duplicates"):
        verify_authorization(request, approvals, trust, policy, now=now, trust_base_dir=tmp_path)


def test_authorization_rejects_non_rfc3339_timestamp(tmp_path: Path) -> None:
    now, request, policy, trust, approvals = _build_auth_fixture(tmp_path)
    request["requested_at"] = "2026-10-23 08:00:00"
    with pytest.raises(AuthorizationError, match="RFC 3339"):
        verify_authorization(request, approvals, trust, policy, now=now, trust_base_dir=tmp_path)


def test_authorization_rejects_unknown_trust_registry_fields(tmp_path: Path) -> None:
    now, request, policy, trust, approvals = _build_auth_fixture(tmp_path)
    trust["allow_any_key"] = True
    with pytest.raises(AuthorizationError, match="missing or unknown fields"):
        verify_authorization(request, approvals, trust, policy, now=now, trust_base_dir=tmp_path)


@pytest.mark.parametrize("size", range(1, 20))
def test_merkle_inclusion_proofs_round_trip(size: int) -> None:
    entries = [f"event-{i}".encode() for i in range(size)]
    root = merkle_root(entries)
    for index, entry in enumerate(entries):
        proof = build_inclusion_proof(entries, index)
        assert proof["root_sha256"] == root
        assert verify_inclusion(entry, proof)
        assert not verify_inclusion(entry + b"-tampered", proof)


def test_merkle_proof_rejects_invalid_index() -> None:
    with pytest.raises(TransparencyError, match="outside the tree"):
        build_inclusion_proof([b"a"], 1)


def test_merkle_rejects_non_bytes_and_oversized_entries() -> None:
    with pytest.raises(TransparencyError, match="must be bytes"):
        merkle_root([b"ok", "not-bytes"])  # type: ignore[list-item]
    oversized = b"x" * (1_048_576 + 1)
    with pytest.raises(TransparencyError, match="exceed"):
        build_inclusion_proof([oversized], 0)
    valid_proof = build_inclusion_proof([b"normal-entry"], 0)
    assert not verify_inclusion(oversized, valid_proof)


def test_merkle_root_enforces_entry_count_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    import opentrace.transparency as transparency
    monkeypatch.setattr(transparency, "_MAX_ENTRIES", 2)
    with pytest.raises(TransparencyError, match="entry count exceeds"):
        merkle_root([b"a", b"b", b"c"])


def test_event_graph_handles_long_chains_without_recursion_error() -> None:
    size = 2500
    events = []
    for i in range(size):
        events.append({
            "event_id": f"evt-{i}", "event_type": "ORIGIN" if i == 0 else "FORWARD",
            "actor_id": f"acct:{i}", "timestamp": "2026-10-23T08:00:00Z", "time_source": "synthetic",
            "parent_event_id": None if i == 0 else f"evt-{i-1}", "content_ref": "content:one", "evidence_class": "synthetic",
        })
    assert len(validate_events(events)) == size


def test_request_scope_cannot_smuggle_intermediate_recipients(tmp_path: Path) -> None:
    now, request, policy, trust, approvals = _build_auth_fixture(tmp_path)
    request["scope"]["include_intermediate_recipients"] = True
    with pytest.raises(AuthorizationError, match="ORIGIN_ONLY mode may not include intermediate recipients"):
        verify_authorization(request, approvals, trust, policy, now=now, trust_base_dir=tmp_path)


def test_generated_files_match_json_schemas(tmp_path: Path) -> None:
    jsonschema = pytest.importorskip("jsonschema")
    case_dir = create_demo(tmp_path / "demo")
    schema_dir = Path(__file__).resolve().parents[1] / "schemas"
    manifest_schema = json.loads((schema_dir / "case-manifest.schema.json").read_text(encoding="utf-8"))
    event_schema = json.loads((schema_dir / "trace-event.schema.json").read_text(encoding="utf-8"))
    manifest = json.loads((case_dir / "manifest.json").read_text(encoding="utf-8"))
    events = json.loads((case_dir / "events.json").read_text(encoding="utf-8"))
    jsonschema.validate(manifest, manifest_schema)
    for event in events:
        jsonschema.validate(event, event_schema)
    from opentrace.transparency import build_inclusion_proof
    proof_schema = json.loads((schema_dir / "merkle-inclusion-proof.schema.json").read_text(encoding="utf-8"))
    proof = build_inclusion_proof([b"alpha", b"beta", b"gamma"], 1)
    jsonschema.validate(proof, proof_schema)
    auth_dir = tmp_path / "auth"
    create_authorization_demo(auth_dir)
    auth_schema = json.loads((schema_dir / "authorization-request.schema.json").read_text(encoding="utf-8"))
    approval_schema = json.loads((schema_dir / "authorization-approval.schema.json").read_text(encoding="utf-8"))
    approvals_schema = json.loads((schema_dir / "authorization-approvals.schema.json").read_text(encoding="utf-8"))
    policy_schema = json.loads((schema_dir / "authorization-policy.schema.json").read_text(encoding="utf-8"))
    trust_schema = json.loads((schema_dir / "trust-registry.schema.json").read_text(encoding="utf-8"))
    req = json.loads((auth_dir / "request.json").read_text(encoding="utf-8"))
    approvals = json.loads((auth_dir / "approvals.json").read_text(encoding="utf-8"))
    trust = json.loads((auth_dir / "trust-registry.json").read_text(encoding="utf-8"))
    policy = json.loads((auth_dir / "policy.json").read_text(encoding="utf-8"))
    jsonschema.validate(req, auth_schema)
    jsonschema.validate(approvals, approvals_schema)
    jsonschema.validate(policy, policy_schema)
    for approval in approvals:
        jsonschema.validate(approval, approval_schema)
    jsonschema.validate(trust, trust_schema)


def test_authorization_rejects_policy_substitution(tmp_path: Path) -> None:
    now, request, policy, trust, approvals = _build_auth_fixture(tmp_path)
    policy["min_approvals"] = 1  # Retain policy_id but change the signed policy bytes.
    with pytest.raises(AuthorizationError, match="policy version|insufficient valid approvals"):
        verify_authorization(request, approvals, trust, policy, now=now, trust_base_dir=tmp_path)


def test_build_trace_report_origin_only() -> None:
    events: list[dict[str, Any]] = [
        {"event_id": "origin", "event_type": "ORIGIN", "actor_id": "acct:origin", "timestamp": "2026-10-23T08:00:00Z", "time_source": "synthetic", "parent_event_id": None, "content_ref": "content:1", "evidence_class": "synthetic"},
        {"event_id": "fwd-1", "event_type": "FORWARD", "actor_id": "acct:fwd1", "timestamp": "2026-10-23T08:01:00Z", "time_source": "synthetic", "parent_event_id": "origin", "content_ref": "content:1", "evidence_class": "synthetic"},
        {"event_id": "rep-1", "event_type": "REPORT", "actor_id": "acct:reporter", "timestamp": "2026-10-23T08:02:00Z", "time_source": "synthetic", "parent_event_id": "fwd-1", "content_ref": "content:1", "evidence_class": "synthetic"},
    ]
    report = build_trace_report(events, "rep-1", "ORIGIN_ONLY")
    assert report["mode"] == "ORIGIN_ONLY"
    assert report["first_originator_candidate"]["actor_id"] == "acct:origin"
    assert "reported_path_oldest_to_newest" not in report
    assert "forwarding_tree_in_supplied_dataset" not in report


def test_build_trace_report_path_and_tree_modes() -> None:
    events: list[dict[str, Any]] = [
        {"event_id": "origin", "event_type": "ORIGIN", "actor_id": "acct:origin", "timestamp": "2026-10-23T08:00:00Z", "time_source": "synthetic", "parent_event_id": None, "content_ref": "content:1", "evidence_class": "synthetic"},
        {"event_id": "fwd-1", "event_type": "FORWARD", "actor_id": "acct:fwd1", "timestamp": "2026-10-23T08:01:00Z", "time_source": "synthetic", "parent_event_id": "origin", "content_ref": "content:1", "evidence_class": "synthetic"},
        {"event_id": "fwd-2", "event_type": "FORWARD", "actor_id": "acct:fwd2", "timestamp": "2026-10-23T08:01:30Z", "time_source": "synthetic", "parent_event_id": "origin", "content_ref": "content:1", "evidence_class": "synthetic"},
        {"event_id": "rep-1", "event_type": "REPORT", "actor_id": "acct:reporter", "timestamp": "2026-10-23T08:02:00Z", "time_source": "synthetic", "parent_event_id": "fwd-1", "content_ref": "content:1", "evidence_class": "synthetic"},
    ]
    path_report = build_trace_report(events, "rep-1", "PATH")
    assert "reported_path_oldest_to_newest" in path_report
    path_ids = [e["event_id"] for e in path_report["reported_path_oldest_to_newest"]]
    assert path_ids == ["origin", "fwd-1", "rep-1"]
    assert "forwarding_tree_in_supplied_dataset" not in path_report

    tree_report = build_trace_report(events, "rep-1", "TREE")
    assert "forwarding_tree_in_supplied_dataset" in tree_report
    tree_ids = [e["event_id"] for e in tree_report["forwarding_tree_in_supplied_dataset"]]
    assert set(tree_ids) == {"origin", "fwd-1", "fwd-2", "rep-1"}


def test_build_trace_report_rejects_invalid_inputs() -> None:
    events: list[dict[str, Any]] = [
        {"event_id": "origin", "event_type": "ORIGIN", "actor_id": "acct:origin", "timestamp": "2026-10-23T08:00:00Z", "time_source": "synthetic", "parent_event_id": None, "content_ref": "content:1", "evidence_class": "synthetic"},
        {"event_id": "fwd-1", "event_type": "FORWARD", "actor_id": "acct:fwd1", "timestamp": "2026-10-23T08:01:00Z", "time_source": "synthetic", "parent_event_id": "origin", "content_ref": "content:1", "evidence_class": "synthetic"},
        {"event_id": "rep-1", "event_type": "REPORT", "actor_id": "acct:reporter", "timestamp": "2026-10-23T08:02:00Z", "time_source": "synthetic", "parent_event_id": "fwd-1", "content_ref": "content:1", "evidence_class": "synthetic"},
    ]
    with pytest.raises(TraceGraphError, match="unsupported disclosure mode"):
        build_trace_report(events, "rep-1", "FULL_INTERCEPTION")
    with pytest.raises(TraceGraphError, match="reported_event_id not found"):
        build_trace_report(events, "non-existent-event")
    with pytest.raises(TraceGraphError, match="must refer to a REPORT event"):
        build_trace_report(events, "fwd-1")
