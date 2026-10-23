"""Generate a synthetic multi-approver policy fixture without real credentials."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .authorization import public_key_fingerprint, sign_approval, verify_authorization


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def create_authorization_demo(output_dir: Path) -> dict[str, object]:
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    keys_dir = output_dir / "public-keys"
    keys_dir.mkdir(exist_ok=True)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    request = {
        "request_id": "SYNTHETIC-REQUEST-001",
        "policy_id": "synthetic-demo-policy-v1",
        "case_id": "SYNTHETIC-CASE-001",
        "protocol_id": "synthetic-graph-v0",
        "target_ref": "content:synthetic-demo-001",
        "disclosure_mode": "ORIGIN_ONLY",
        "purpose": "Demonstrate scoped multi-party approval checks only",
        "legal_basis_ref": "SYNTHETIC_ONLY_NO_LEGAL_EFFECT",
        "requested_at": now.isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "request_version": "1",
        "scope": {
            "dataset_refs": ["synthetic-events.json"],
            "message_ref_only": True,
            "include_intermediate_recipients": False,
        },
        "synthetic_only": True,
    }
    policy = {
        "policy_id": "synthetic-demo-policy-v1",
        "min_approvals": 2,
        "required_roles": ["case_reviewer", "privacy_reviewer"],
        "require_distinct_trust_domains": True,
        "allowed_modes": ["ORIGIN_ONLY"],
        "max_validity_seconds": 7200,
    }
    trust_principals: dict[str, dict[str, str]] = {}
    approvals = []
    approvers = [
        ("approver-demo-01", "case_reviewer", "independent-review-domain-a"),
        ("approver-demo-02", "privacy_reviewer", "independent-review-domain-b"),
    ]
    for index, (approver_id, role, domain) in enumerate(approvers, start=1):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_path = keys_dir / f"{approver_id}.pem"
        public_path.write_bytes(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        trust_principals[approver_id] = {
            "role": role,
            "trust_domain": domain,
            "public_key_path": (Path("public-keys") / public_path.name).as_posix(),
            "public_key_fingerprint": public_key_fingerprint(public_key),
        }
        approvals.append(sign_approval(
            request,
            approver_id=approver_id,
            approval_id=f"SYNTHETIC-APPROVAL-{index:03d}",
            approved_at=now,
            private_key=private_key,
            policy=policy,
            role=role,
            trust_domain=domain,
        ))

    trust_registry = {"registry_version": "1", "notice": "Synthetic trust only; not a production trust store.", "principals": trust_principals}
    _write_json(output_dir / "request.json", request)
    _write_json(output_dir / "approvals.json", approvals)
    _write_json(output_dir / "policy.json", policy)
    _write_json(output_dir / "trust-registry.json", trust_registry)
    result = verify_authorization(request, approvals, trust_registry, policy, now=now, trust_base_dir=output_dir)
    _write_json(output_dir / "verification.json", result)
    (output_dir / "README.md").write_text(
        "# Synthetic authorization policy fixture\n\n"
        "> This fixture is synthetic. It is not a real legal order, legal authorization, or a production trust store.\n\n"
        "The signatures bind both approvals to the exact request digest. The policy requires two distinct approvers, "
        "two distinct trust domains, both configured roles, an unexpired request, and origin-only disclosure.\n\n"
        "Run `opentrace authorize-check --request request.json --approvals approvals.json "
        "--trust trust-registry.json --policy policy.json` from this directory. The trust registry must be protected "
        "and provisioned through a separate trusted channel in any real deployment.\n",
        encoding="utf-8",
    )
    return result
