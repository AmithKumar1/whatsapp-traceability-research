"""Signed evidence-manifest builder and verifier for OpenTrace v0.2."""
from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes
from .strictjson import load_json

MANIFEST_NAME = "manifest.json"
SIGNATURE_NAME = "manifest.sig"
PUBLIC_KEY_NAME = "signing-public-key.pem"
DOMAIN = b"OpenTrace-EvidenceRecord-v2\x00"
SIGN_DOMAIN = b"OpenTrace-Manifest-v0.2\x00"
_MANIFEST_FIELDS = {
    "format", "manifest_version", "case_id", "created_at", "signing_algorithm",
    "signing_key_fingerprint", "digest_algorithm", "canonicalization", "record_count",
    "records", "head_record_hash", "trust_note",
}
_RECORD_FIELDS = {
    "path", "record_kind", "classification", "size_bytes", "sha256",
    "previous_record_hash", "record_hash",
}
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")


class IntegrityError(ValueError):
    """Raised when a case file fails a verification check."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_bytes(der)


def _safe_path(root: Path, relative: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative or "\x00" in relative or ":" in relative:
        raise IntegrityError(f"unsafe manifest path: {relative!r}")
    p = PurePosixPath(relative)
    if p.is_absolute() or ".." in p.parts or not p.parts or str(p) != relative or any(part in {"", "."} for part in p.parts):
        raise IntegrityError(f"unsafe manifest path: {relative!r}")
    resolved_root = root.resolve()
    current = resolved_root
    for part in p.parts:
        current = current / part
        # Symlink-free case bundles make path verification easier to reason about
        # and avoid a symlink being swapped between validation and hashing.
        if current.is_symlink():
            raise IntegrityError(f"symlinks are not permitted in evidence bundle paths: {relative!r}")
    target = current.resolve()
    if target != resolved_root and resolved_root not in target.parents:
        raise IntegrityError(f"manifest path escapes case directory: {relative!r}")
    return target


def _record_hash(record_without_hash: dict[str, Any]) -> str:
    return sha256_bytes(DOMAIN + canonical_bytes(record_without_hash))


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def seal_case(
    case_dir: Path,
    case_id: str,
    files: list[tuple[str, str, str]],
    private_key: Ed25519PrivateKey | None = None,
) -> dict[str, Any]:
    """Hash and sign all declared payload files; generated keys are demo-only.

    `files` contains (relative_path, record_kind, classification) tuples. The
    caller retains control over the private key; this routine never writes it.
    If no key is provided, a new ephemeral key suitable only for demonstrations
    is generated. It is not saved and cannot authenticate a person or authority.
    """
    if not isinstance(case_id, str) or not case_id.strip():
        raise IntegrityError("case_id must be a non-empty string")
    if not isinstance(files, list) or len(files) > 10_000:
        raise IntegrityError("files must be a list containing at most 10,000 entries")
    case_dir = case_dir.resolve()
    case_dir.mkdir(parents=True, exist_ok=True)
    if private_key is None:
        private_key = Ed25519PrivateKey.generate()
    records: list[dict[str, Any]] = []
    previous = "0" * 64
    seen_paths: set[str] = set()
    seen_casefolded: set[str] = set()
    normalized_files = sorted(files, key=lambda item: item[0] if isinstance(item, tuple) and item else "")
    for item in normalized_files:
        if not isinstance(item, tuple) or len(item) != 3:
            raise IntegrityError("each file descriptor must be a (path, record_kind, classification) tuple")
        relative, record_kind, classification = item
        if not isinstance(relative, str) or relative in {MANIFEST_NAME, SIGNATURE_NAME, PUBLIC_KEY_NAME}:
            raise IntegrityError(f"invalid or reserved manifest input path: {relative!r}")
        if not isinstance(record_kind, str) or not record_kind or not isinstance(classification, str) or not classification:
            raise IntegrityError(f"record_kind and classification must be non-empty strings for {relative!r}")
        if relative in seen_paths or relative.casefold() in seen_casefolded:
            raise IntegrityError(f"duplicate or case-colliding file record path: {relative}")
        seen_paths.add(relative)
        seen_casefolded.add(relative.casefold())
        target = _safe_path(case_dir, relative)
        if not target.is_file():
            raise IntegrityError(f"manifest input does not exist or is not a file: {relative}")
        record: dict[str, Any] = {
            "path": PurePosixPath(relative).as_posix(),
            "record_kind": record_kind,
            "classification": classification,
            "size_bytes": target.stat().st_size,
            "sha256": sha256_file(target),
            "previous_record_hash": previous,
        }
        record["record_hash"] = _record_hash(record)
        previous = record["record_hash"]
        records.append(record)

    public_key = private_key.public_key()
    manifest: dict[str, Any] = {
        "format": "opentrace-evidence-manifest",
        "manifest_version": "0.2",
        "case_id": case_id,
        "created_at": utc_now(),
        "signing_algorithm": "Ed25519",
        "signing_key_fingerprint": _public_key_fingerprint(public_key),
        "digest_algorithm": "SHA-256",
        "canonicalization": "OpenTrace restricted canonical JSON profile v0.2; see docs/CRYPTO_DECISIONS.md",
        "record_count": len(records),
        "records": records,
        "head_record_hash": previous,
        "trust_note": (
            "A bundled public key is not an independent trust anchor. Obtain the expected key fingerprint "
            "through a separate trusted channel. The canonical JSON profile rejects floating-point values "
            "and is not a complete RFC 8785 implementation."
        ),
    }
    signature = private_key.sign(SIGN_DOMAIN + canonical_bytes(manifest))
    _write_json(case_dir / MANIFEST_NAME, manifest)
    (case_dir / SIGNATURE_NAME).write_text(base64.b64encode(signature).decode("ascii") + "\n", encoding="ascii")
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (case_dir / PUBLIC_KEY_NAME).write_bytes(public_bytes)
    return manifest


def verify_case(case_dir: Path, trusted_public_key_path: Path | None = None) -> dict[str, Any]:
    case_dir = case_dir.resolve()
    manifest_path = case_dir / MANIFEST_NAME
    signature_path = case_dir / SIGNATURE_NAME
    bundled_key_path = case_dir / PUBLIC_KEY_NAME
    required_files = [manifest_path, signature_path]
    if trusted_public_key_path is None:
        required_files.append(bundled_key_path)
    for required in required_files:
        if not required.is_file() or required.is_symlink():
            raise IntegrityError(f"required case file missing or unsafe: {required.name}")
    try:
        manifest = load_json(manifest_path, max_bytes=16 * 1024 * 1024)
    except (ValueError, OSError) as exc:
        raise IntegrityError(f"manifest could not be safely parsed: {exc}") from exc
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_FIELDS:
        raise IntegrityError("manifest has missing or unknown fields")
    if manifest.get("format") != "opentrace-evidence-manifest":
        raise IntegrityError("unknown manifest format")
    if manifest.get("manifest_version") != "0.2":
        raise IntegrityError("unsupported manifest version")
    if manifest.get("signing_algorithm") != "Ed25519" or manifest.get("digest_algorithm") != "SHA-256":
        raise IntegrityError("unsupported signature or digest algorithm")
    if manifest.get("canonicalization") != "OpenTrace restricted canonical JSON profile v0.2; see docs/CRYPTO_DECISIONS.md":
        raise IntegrityError("unsupported canonicalization profile")
    if not isinstance(manifest.get("case_id"), str) or not manifest["case_id"]:
        raise IntegrityError("manifest case_id must be a non-empty string")
    try:
        created = datetime.fromisoformat(manifest["created_at"].replace("Z", "+00:00"))
        if created.tzinfo is None:
            raise ValueError("timezone is required")
    except (ValueError, AttributeError, TypeError) as exc:
        raise IntegrityError("manifest created_at is not a timezone-aware timestamp") from exc

    key_path = Path(trusted_public_key_path).resolve() if trusted_public_key_path else bundled_key_path
    try:
        loaded_key = serialization.load_pem_public_key(key_path.read_bytes())
        if not isinstance(loaded_key, Ed25519PublicKey):
            raise IntegrityError("public key is not Ed25519")
        if _public_key_fingerprint(loaded_key) != manifest.get("signing_key_fingerprint"):
            raise IntegrityError("trusted public key fingerprint does not match manifest signer")
        signature = base64.b64decode(signature_path.read_text(encoding="ascii").strip(), validate=True)
        if len(signature) != 64:
            raise IntegrityError("Ed25519 signature has invalid length")
        loaded_key.verify(signature, SIGN_DOMAIN + canonical_bytes(manifest))
    except IntegrityError:
        raise
    except Exception as exc:
        raise IntegrityError("manifest signature verification failed") from exc

    records = manifest.get("records")
    if not isinstance(records, list) or len(records) > 10_000:
        raise IntegrityError("manifest records must be an array of at most 10,000 records")
    if manifest.get("record_count") != len(records):
        raise IntegrityError("manifest record_count does not match records array")
    previous = "0" * 64
    checked_files = []
    seen_paths: set[str] = set()
    previous_path: str | None = None
    for index, record in enumerate(records):
        if not isinstance(record, dict) or set(record) != _RECORD_FIELDS:
            raise IntegrityError(f"record {index} has missing or unknown fields")
        relative = record.get("path")
        if not isinstance(relative, str):
            raise IntegrityError(f"record {index} path is not a string")
        if relative in {MANIFEST_NAME, SIGNATURE_NAME, PUBLIC_KEY_NAME}:
            raise IntegrityError(f"reserved manifest path listed as payload: {relative}")
        if relative in seen_paths or relative.casefold() in {p.casefold() for p in seen_paths}:
            raise IntegrityError(f"duplicate or case-colliding path: {relative}")
        if previous_path is not None and relative < previous_path:
            raise IntegrityError("manifest records are not sorted by path")
        previous_path = relative
        seen_paths.add(relative)
        if not isinstance(record.get("record_kind"), str) or not record["record_kind"]:
            raise IntegrityError(f"record {index} record_kind is invalid")
        if not isinstance(record.get("classification"), str) or not record["classification"]:
            raise IntegrityError(f"record {index} classification is invalid")
        if isinstance(record.get("size_bytes"), bool) or not isinstance(record.get("size_bytes"), int) or record["size_bytes"] < 0:
            raise IntegrityError(f"record {index} size_bytes is invalid")
        for digest_field in ("sha256", "previous_record_hash", "record_hash"):
            if not isinstance(record.get(digest_field), str) or not _HEX_256.fullmatch(record[digest_field]):
                raise IntegrityError(f"record {index} {digest_field} must be a lowercase SHA-256 hex digest")
        if record["previous_record_hash"] != previous:
            raise IntegrityError(f"record-chain predecessor mismatch at record {index}")
        payload = {k: v for k, v in record.items() if k != "record_hash"}
        calculated_record_hash = _record_hash(payload)
        if calculated_record_hash != record["record_hash"]:
            raise IntegrityError(f"record hash mismatch at record {index}")
        target = _safe_path(case_dir, relative)
        if not target.is_file():
            raise IntegrityError(f"manifest file missing: {relative}")
        stat_size = target.stat().st_size
        if stat_size != record["size_bytes"]:
            raise IntegrityError(f"file size mismatch: {relative}")
        actual_digest = sha256_file(target)
        if actual_digest != record["sha256"]:
            raise IntegrityError(f"file digest mismatch: {relative}")
        checked_files.append({"path": relative, "size_bytes": stat_size, "sha256": actual_digest, "status": "ok"})
        previous = record["record_hash"]
    if manifest.get("head_record_hash") != previous:
        raise IntegrityError("manifest head hash does not match record chain")

    # Inventory completeness matters: a hidden, unlisted payload file must not
    # silently sit beside a verified case bundle.
    allowed_controls = {MANIFEST_NAME, SIGNATURE_NAME, PUBLIC_KEY_NAME}
    actual_payloads: set[str] = set()
    for path in case_dir.rglob("*"):
        if path.is_symlink():
            raise IntegrityError(f"symlink found in case bundle: {path.relative_to(case_dir).as_posix()}")
        if path.is_file():
            rel = path.relative_to(case_dir).as_posix()
            if rel not in allowed_controls:
                actual_payloads.add(rel)
    if actual_payloads != seen_paths:
        missing_from_manifest = sorted(actual_payloads - seen_paths)
        missing_from_disk = sorted(seen_paths - actual_payloads)
        raise IntegrityError(
            f"case inventory mismatch; unlisted={missing_from_manifest}, missing={missing_from_disk}"
        )

    key_origin = "externally-supplied trusted public key" if trusted_public_key_path else "bundled public key (not an independent trust anchor)"
    return {
        "status": "VALID",
        "manifest_version": "0.2",
        "case_id": manifest.get("case_id"),
        "records_checked": len(records),
        "files_checked": checked_files,
        "manifest_signature": "valid",
        "signing_key_fingerprint": manifest["signing_key_fingerprint"],
        "record_chain": "valid",
        "file_digests_and_sizes": "valid",
        "case_inventory": "complete",
        "verification_key_source": key_origin,
        "limitations": [
            "A bundled public key is not an independent trust anchor; compare the fingerprint with a separately trusted value.",
            "No RFC 3161 trusted timestamp token or externally witnessed transparency proof is included.",
            "Integrity verification cannot establish that underlying statements are true or that evidence was lawfully acquired.",
            "The restricted canonical JSON profile rejects floating-point values and is not a complete RFC 8785 implementation.",
        ],
    }
