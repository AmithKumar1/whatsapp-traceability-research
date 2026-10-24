"""Experimental multi-party authorization envelope for synthetic trace requests.

This module enforces a *configured technical policy*. It does not determine
whether an order is legally valid, whether a law applies, or whether an
investigator is entitled to conduct a real trace. Real deployment requires an
independently reviewed policy, trusted key provisioning, and legal governance.
"""
from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes

APPROVAL_DOMAIN = b"OpenTrace-TraceRequest-Approval-v1\x00"
REQUEST_MODES = {"ORIGIN_ONLY", "PATH", "TREE"}
_REQUEST_REQUIRED_FIELDS = {
    "request_id", "case_id", "protocol_id", "target_ref", "disclosure_mode",
    "purpose", "legal_basis_ref", "requested_at", "expires_at", "scope", "request_version", "policy_id",
}
_REQUEST_OPTIONAL_FIELDS = {"synthetic_only"}
_POLICY_REQUIRED_FIELDS = {
    "policy_id", "min_approvals", "required_roles", "require_distinct_trust_domains",
    "allowed_modes", "max_validity_seconds",
}
_TRUST_REQUIRED_FIELDS = {"registry_version", "principals"}
_TRUST_OPTIONAL_FIELDS = {"notice"}
_RFC3339 = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)


def public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    der = public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


class AuthorizationError(ValueError):
    """Raised when an authorization request fails the configured policy."""


def _instant(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not _RFC3339.fullmatch(value):
        raise AuthorizationError(f"{label} must be an RFC 3339 timestamp with timezone and seconds")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuthorizationError(f"{label} is not a valid RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AuthorizationError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def request_digest(request: Mapping[str, Any]) -> str:
    return hashlib.sha256(b"OpenTrace-TraceRequest-v1\x00" + canonical_bytes(dict(request))).hexdigest()


def policy_digest(policy: Mapping[str, Any]) -> str:
    return hashlib.sha256(b"OpenTrace-AuthorizationPolicy-v1\x00" + canonical_bytes(dict(policy))).hexdigest()


def _validate_policy(policy: Mapping[str, Any]) -> None:
    if not isinstance(policy, Mapping):
        raise AuthorizationError("policy must be a JSON object")
    fields = set(policy)
    missing = _POLICY_REQUIRED_FIELDS - fields
    unknown = fields - _POLICY_REQUIRED_FIELDS
    if missing or unknown:
        details = []
        if missing:
            details.append("missing fields: " + ", ".join(sorted(missing)))
        if unknown:
            details.append("unknown fields: " + ", ".join(sorted(unknown)))
        raise AuthorizationError("invalid policy (" + "; ".join(details) + ")")
    policy_id = policy.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id.strip() or len(policy_id) > 128:
        raise AuthorizationError("policy_id must be a non-empty string of at most 128 characters")
    min_approvals = policy.get("min_approvals")
    if isinstance(min_approvals, bool) or not isinstance(min_approvals, int) or not 1 <= min_approvals <= 20:
        raise AuthorizationError("policy min_approvals must be an integer from 1 to 20")
    roles = policy.get("required_roles")
    if not isinstance(roles, list) or any(not isinstance(role, str) or not role.strip() or len(role) > 128 for role in roles):
        raise AuthorizationError("policy required_roles must be an array of non-empty role strings")
    if len(roles) != len(set(roles)):
        raise AuthorizationError("policy required_roles may not contain duplicates")
    if not isinstance(policy.get("require_distinct_trust_domains"), bool):
        raise AuthorizationError("policy require_distinct_trust_domains must be boolean")
    modes = policy.get("allowed_modes")
    if not isinstance(modes, list) or not modes or any(not isinstance(item, str) or item not in REQUEST_MODES for item in modes):
        raise AuthorizationError("policy allowed_modes must be a non-empty list of supported disclosure modes")
    if len(modes) != len(set(modes)):
        raise AuthorizationError("policy allowed_modes may not contain duplicates")
    maximum = policy.get("max_validity_seconds")
    if isinstance(maximum, bool) or not isinstance(maximum, int) or not 1 <= maximum <= 604800:
        raise AuthorizationError("policy max_validity_seconds must be an integer from 1 to 604800")


def _validate_trust_registry(trust_registry: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(trust_registry, Mapping):
        raise AuthorizationError("trust registry must be a JSON object")
    fields = set(trust_registry)
    if fields - (_TRUST_REQUIRED_FIELDS | _TRUST_OPTIONAL_FIELDS) or _TRUST_REQUIRED_FIELDS - fields:
        raise AuthorizationError("trust registry has missing or unknown fields")
    if trust_registry.get("registry_version") != "1":
        raise AuthorizationError("unsupported trust registry version")
    notice = trust_registry.get("notice")
    if notice is not None and not isinstance(notice, str):
        raise AuthorizationError("trust registry notice must be a string")
    principals = trust_registry.get("principals")
    if not isinstance(principals, dict) or not 1 <= len(principals) <= 1000:
        raise AuthorizationError("trust registry principals must be an object with 1 to 1,000 entries")
    for principal_id, record in principals.items():
        if not isinstance(principal_id, str) or not principal_id.strip() or len(principal_id) > 128:
            raise AuthorizationError("trust registry principal IDs must be non-empty strings of at most 128 characters")
        if not isinstance(record, Mapping) or set(record) != {
            "role", "trust_domain", "public_key_path", "public_key_fingerprint"
        }:
            raise AuthorizationError(f"trust record for {principal_id} has missing or unknown fields")
        for field in ("role", "trust_domain", "public_key_path"):
            value = record.get(field)
            if not isinstance(value, str) or not value.strip() or len(value) > 512:
                raise AuthorizationError(f"trust record {principal_id}.{field} must be a non-empty string")
        fingerprint = record.get("public_key_fingerprint")
        if not isinstance(fingerprint, str) or not re.fullmatch(r"[a-f0-9]{64}", fingerprint):
            raise AuthorizationError(f"trust record {principal_id}.public_key_fingerprint is invalid")
    return principals


def validate_request(request: Mapping[str, Any], policy: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    if not isinstance(request, Mapping):
        raise AuthorizationError("request must be a JSON object")
    _validate_policy(policy)
    missing = _REQUEST_REQUIRED_FIELDS - set(request)
    unknown = set(request) - _REQUEST_REQUIRED_FIELDS - _REQUEST_OPTIONAL_FIELDS
    if missing:
        raise AuthorizationError(f"request missing required fields: {', '.join(sorted(missing))}")
    if unknown:
        raise AuthorizationError(f"request has unknown fields: {', '.join(sorted(unknown))}")
    if request.get("request_version", "1") != "1":
        raise AuthorizationError("unsupported request_version")
    if request.get("policy_id") != policy["policy_id"]:
        raise AuthorizationError("request policy_id does not match the configured policy")
    if "synthetic_only" in request and not isinstance(request["synthetic_only"], bool):
        raise AuthorizationError("synthetic_only must be boolean when present")
    for key in ("request_id", "case_id", "protocol_id", "target_ref", "purpose", "legal_basis_ref"):
        value = request.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > 2048:
            raise AuthorizationError(f"{key} must be a non-empty string of at most 2048 characters")
    mode = request.get("disclosure_mode")
    if not isinstance(mode, str) or mode not in REQUEST_MODES:
        raise AuthorizationError(f"unsupported disclosure_mode: {mode!r}")
    allowed_modes = policy.get("allowed_modes", ["ORIGIN_ONLY"])
    if mode not in allowed_modes:
        raise AuthorizationError(f"disclosure mode {mode} is not allowed by policy")
    scope = request.get("scope")
    if not isinstance(scope, dict) or not scope:
        raise AuthorizationError("scope must be a non-empty object")
    allowed_scope_fields = {"dataset_refs", "message_ref_only", "include_intermediate_recipients"}
    if set(scope) - allowed_scope_fields:
        raise AuthorizationError("scope contains unknown fields")
    dataset_refs = scope.get("dataset_refs")
    if not isinstance(dataset_refs, list) or not dataset_refs or len(dataset_refs) > 1000 or any(not isinstance(ref, str) or not ref.strip() or len(ref) > 512 for ref in dataset_refs):
        raise AuthorizationError("scope.dataset_refs must be an array of 1 to 1,000 non-empty strings of at most 512 characters")
    if len(dataset_refs) != len(set(dataset_refs)):
        raise AuthorizationError("scope.dataset_refs may not contain duplicates")
    if not isinstance(scope.get("message_ref_only"), bool):
        raise AuthorizationError("scope.message_ref_only must be boolean")
    include_intermediate = scope.get("include_intermediate_recipients")
    if not isinstance(include_intermediate, bool):
        raise AuthorizationError("scope.include_intermediate_recipients must be boolean")
    if mode == "ORIGIN_ONLY" and include_intermediate:
        raise AuthorizationError("ORIGIN_ONLY mode may not include intermediate recipients")
    if mode in {"PATH", "TREE"} and not include_intermediate:
        raise AuthorizationError(f"{mode} mode requires explicit intermediate-recipient scope")
    issued = _instant(request.get("requested_at"), "requested_at")
    expires = _instant(request.get("expires_at"), "expires_at")
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if expires <= issued:
        raise AuthorizationError("expires_at must be later than requested_at")
    if issued > current:
        raise AuthorizationError("request is not yet valid")
    if expires <= current:
        raise AuthorizationError("request has expired")
    max_validity = policy["max_validity_seconds"]
    validity_seconds = (expires - issued).total_seconds()
    if validity_seconds > max_validity:
        raise AuthorizationError("request validity window exceeds policy maximum")
    return {
        "request_id": request["request_id"],
        "case_id": request["case_id"],
        "disclosure_mode": mode,
        "request_sha256": request_digest(request),
        "validity_seconds": int(validity_seconds),
        "policy_checked_at": _timestamp(current),
    }


def sign_approval(
    request: Mapping[str, Any],
    *,
    approver_id: str,
    approval_id: str,
    approved_at: datetime,
    private_key: Ed25519PrivateKey,
    policy: Mapping[str, Any],
    role: str = "approver",
    trust_domain: str = "unspecified-domain",
) -> dict[str, Any]:
    """Create one approval signed by a trusted approver key (mostly for tests/demo)."""
    payload = {
        "approval_version": "1",
        "approval_id": approval_id,
        "request_sha256": request_digest(request),
        "policy_sha256": policy_digest(policy),
        "approver_id": approver_id,
        "role": role,
        "trust_domain": trust_domain,
        "decision": "APPROVE",
        "approved_at": _timestamp(approved_at),
        "signature_algorithm": "Ed25519",
    }
    signature = private_key.sign(APPROVAL_DOMAIN + canonical_bytes(payload))
    return {**payload, "signature": base64.b64encode(signature).decode("ascii")}


def verify_authorization(
    request: Mapping[str, Any],
    approvals: Sequence[Mapping[str, Any]],
    trust_registry: Mapping[str, Any],
    policy: Mapping[str, Any],
    *,
    now: datetime | None = None,
    trust_base_dir: Path | None = None,
) -> dict[str, Any]:
    """Verify signature-bound, distinct-domain approvals for a bounded request."""
    request_result = validate_request(request, policy, now=now)
    if not isinstance(approvals, list):
        raise AuthorizationError("approvals must be an array")
    if len(approvals) > 1000:
        raise AuthorizationError("approvals exceed the safety limit of 1,000 entries")
    min_approvals = policy["min_approvals"]
    registry = _validate_trust_registry(trust_registry)

    request_sha = request_result["request_sha256"]
    valid: list[dict[str, str]] = []
    seen_approvers: set[str] = set()
    seen_approval_ids: set[str] = set()
    seen_domains: set[str] = set()
    errors: list[str] = []
    now_utc = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

    for index, approval in enumerate(approvals):
        if not isinstance(approval, Mapping):
            errors.append(f"approval[{index}] is not an object")
            continue
        approver_id = approval.get("approver_id")
        approval_id = approval.get("approval_id")
        if not isinstance(approver_id, str) or approver_id not in registry:
            errors.append(f"approval[{index}] has an untrusted approver")
            continue
        if not isinstance(approval_id, str) or not approval_id:
            errors.append(f"approval[{index}] has no approval_id")
            continue
        if approver_id in seen_approvers:
            errors.append(f"duplicate approver: {approver_id}")
            continue
        if approval_id in seen_approval_ids:
            errors.append(f"duplicate approval_id: {approval_id}")
            continue
        principal = registry[approver_id]
        if not isinstance(principal, Mapping):
            errors.append(f"trust record for {approver_id} is malformed")
            continue
        if approval.get("decision") != "APPROVE" or approval.get("approval_version") != "1":
            errors.append(f"approval {approval_id} is not a supported affirmative decision")
            continue
        if approval.get("request_sha256") != request_sha:
            errors.append(f"approval {approval_id} is not bound to this request")
            continue
        if approval.get("policy_sha256") != policy_digest(policy):
            errors.append(f"approval {approval_id} is not bound to this policy version")
            continue
        if approval.get("signature_algorithm") != "Ed25519":
            errors.append(f"approval {approval_id} uses an unsupported signature algorithm")
            continue
        approved_at = _instant(approval.get("approved_at"), f"approval {approval_id}.approved_at")
        if approved_at > now_utc or approved_at < _instant(request["requested_at"], "requested_at"):
            errors.append(f"approval {approval_id} timestamp is outside the request window")
            continue
        try:
            signature = base64.b64decode(approval.get("signature", ""), validate=True)
            payload = {key: value for key, value in approval.items() if key != "signature"}
            if set(payload) != {
                "approval_version", "approval_id", "request_sha256", "policy_sha256", "approver_id", "role", "trust_domain",
                "decision", "approved_at", "signature_algorithm",
            }:
                errors.append(f"approval {approval_id} has missing or unknown fields")
                continue
            key_value = str(principal.get("public_key_path", ""))
            key_candidate = Path(key_value)
            if key_candidate.is_absolute() or ".." in key_candidate.parts:
                errors.append(f"trusted public key path for {approver_id} must be a safe relative path")
                continue
            if trust_base_dir is None:
                errors.append("trust_base_dir is required to constrain public-key paths")
                continue
            trust_root = Path(trust_base_dir).resolve()
            key_path = (trust_root / key_candidate).resolve()
            if not key_path.is_relative_to(trust_root):
                errors.append(f"trusted public key path for {approver_id} escapes trust directory")
                continue
            if not key_path.is_file():
                errors.append(f"trusted public key missing for {approver_id}")
                continue
            public_key = serialization.load_pem_public_key(key_path.read_bytes())
            if not isinstance(public_key, Ed25519PublicKey):
                errors.append(f"trusted public key for {approver_id} is not Ed25519")
                continue
            fingerprint = principal.get("public_key_fingerprint")
            if not isinstance(fingerprint, str) or public_key_fingerprint(public_key) != fingerprint:
                errors.append(f"trusted public key fingerprint mismatch for {approver_id}")
                continue
            if payload.get("role") != principal.get("role") or payload.get("trust_domain") != principal.get("trust_domain"):
                errors.append(f"signed role/trust domain does not match trust registry for {approver_id}")
                continue
            public_key.verify(signature, APPROVAL_DOMAIN + canonical_bytes(payload))
        except Exception:
            errors.append(f"signature invalid for {approval_id}")
            continue
        role = principal.get("role")
        domain = principal.get("trust_domain")
        if not isinstance(role, str) or not role or not isinstance(domain, str) or not domain:
            errors.append(f"trust record for {approver_id} lacks role/trust_domain")
            continue
        seen_approvers.add(approver_id)
        seen_approval_ids.add(approval_id)
        seen_domains.add(domain)
        valid.append({"approver_id": approver_id, "role": role, "trust_domain": domain, "approval_id": approval_id})

    if len(valid) < min_approvals:
        raise AuthorizationError(
            f"insufficient valid approvals: {len(valid)} verified, {min_approvals} required; "
            f"rejections={errors}"
        )
    if policy.get("require_distinct_trust_domains", True) and len(seen_domains) < min_approvals:
        raise AuthorizationError("approvals do not span the required number of distinct trust domains")
    required_roles = policy["required_roles"]
    approved_roles = {record["role"] for record in valid}
    missing_roles = sorted(set(required_roles) - approved_roles)
    if missing_roles:
        raise AuthorizationError(f"required approval roles missing: {', '.join(missing_roles)}")

    return {
        "status": "AUTHORIZED_BY_CONFIGURED_POLICY",
        "request": request_result,
        "policy_sha256": policy_digest(policy),
        "valid_approvals": valid,
        "approval_count": len(valid),
        "distinct_trust_domains": len(seen_domains),
        "rejected_approval_count": len(errors),
        "rejection_reasons": errors,
        "notice": (
            "Technical policy verification only. This result is not a legal opinion and does not "
            "establish that the underlying request is lawful or that a real trace should be run."
        ),
    }
