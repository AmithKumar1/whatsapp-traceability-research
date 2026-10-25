"""Tests for RFC 8785 (JSON Canonicalization Scheme / JCS) implementation."""
from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from opentrace.canonical import (
    canonical_bytes,
    canonical_bytes_restricted,
)
from opentrace.integrity import (
    CANONICALIZATION_JCS,
    CANONICALIZATION_LEGACY,
    seal_case,
    verify_case,
)

ROOT = Path(__file__).resolve().parent.parent


def test_rfc8785_appendix_b_numbers() -> None:
    """Verify normative ECMAScript number serialization per RFC 8785 Appendix B Table 1."""
    fixture_path = ROOT / "tests" / "data" / "jcs" / "appendix_b_numbers.json"
    with fixture_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    for sample in data["samples"]:
        raw_bytes = bytes.fromhex(sample["ieee754_hex"])
        val = struct.unpack(">d", raw_bytes)[0]
        canonical = canonical_bytes(val).decode("utf-8")
        assert canonical == sample["expected_json"], (
            f"Failed on {sample['comment']}: got {canonical!r}, expected {sample['expected_json']!r}"
        )


def test_rfc8785_golden_fixtures() -> None:
    """Verify cross-language golden test vectors and their SHA-256 digests."""
    fixture_path = ROOT / "tests" / "data" / "jcs" / "canonical_golden.json"
    with fixture_path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    for vec in data["test_vectors"]:
        result_bytes = canonical_bytes(vec["input"])
        result_str = result_bytes.decode("utf-8")
        result_digest = hashlib.sha256(result_bytes).hexdigest()

        assert result_str == vec["expected_canonical"], f"Golden vector {vec['name']} canonical string mismatch"
        assert result_digest == vec["sha256"], f"Golden vector {vec['name']} SHA-256 mismatch"


def test_rfc8785_utf16_sorting_edge_cases() -> None:
    """Verify property sorting strictly adheres to UTF-16 code unit ordering per RFC 8785."""
    # In UTF-16, surrogate pairs for astral characters (e.g. U+1F4A9 -> 0xD83D 0xDCA9)
    # sort before BMP private-use / high characters (e.g. U+E000 -> 0xE000).
    data = {
        "\ue000": "high_bmp",
        "\U0001f4a9": "astral_poo",
        "z": "ascii_last",
        "a": "ascii_first",
        "1": "digit",
        "\u00e9": "latin1_accent",
        "\u20ac": "euro",
    }
    encoded = canonical_bytes(data).decode("utf-8")
    expected_order = ['"1"', '"a"', '"z"', '"\u00e9"', '"\u20ac"', '"\U0001f4a9"', '"\ue000"']
    for prev_key, next_key in zip(expected_order, expected_order[1:]):
        assert encoded.index(prev_key) < encoded.index(next_key), (
            f"Key {prev_key} should precede {next_key} in {encoded}"
        )


def test_rfc8785_numeric_domain_rejections() -> None:
    """Verify out-of-domain numbers (specials and integers outside [-2^53+1, 2^53-1]) are rejected."""
    # Non-finite floats
    for special in [float("nan"), float("inf"), float("-inf")]:
        with pytest.raises(ValueError, match="Value cannot be represented in RFC 8785"):
            canonical_bytes(special)

    # Integer out-of-range (> 2^53 - 1 or < -2^53 + 1)
    max_safe = 9007199254740991
    min_safe = -9007199254740991
    # Boundaries pass
    assert canonical_bytes(max_safe) == b"9007199254740991"
    assert canonical_bytes(min_safe) == b"-9007199254740991"

    # Beyond safe integers
    with pytest.raises(ValueError):
        canonical_bytes(max_safe + 1)
    with pytest.raises(ValueError):
        canonical_bytes(min_safe - 1)


def test_rfc8785_nesting_depth_limit() -> None:
    """Verify deeply nested structures exceeding depth 64 are rejected."""
    cur: Any = "leaf"
    for _ in range(65):
        cur = [cur]
    with pytest.raises(ValueError, match="JSON nesting exceeds limit"):
        canonical_bytes(cur)


def test_rfc8785_non_string_keys_rejected() -> None:
    """Verify objects with non-string keys raise ValueError."""
    with pytest.raises(ValueError, match="Object key must be a string"):
        canonical_bytes({123: "number_key"})  # type: ignore[dict-item]


def test_legacy_manifest_compatibility() -> None:
    """Verify previously sealed v0.6.0 demo case verifies successfully without modification."""
    demo_dir = ROOT / "examples" / "demo-case"
    manifest_data = json.loads((demo_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest_data["canonicalization"] == CANONICALIZATION_LEGACY

    result = verify_case(demo_dir)
    assert result["status"] == "VALID"
    assert result["canonicalization"] == CANONICALIZATION_LEGACY
    assert result["case_id"] == "SYNTHETIC-CASE-001"
    assert result["records_checked"] == 6


def test_new_manifest_rfc8785(tmp_path: Path) -> None:
    """Verify new manifests generated with RFC 8785 canonicalization validate against schema and verify."""
    schema_path = ROOT / "schemas" / "case-manifest.schema.json"
    with schema_path.open("r", encoding="utf-8") as f:
        schema = json.load(f)

    # Create dummy files to seal
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    p1 = evidence_dir / "report.pdf"
    p1.write_bytes(b"%PDF-1.4 sample content")
    p2 = evidence_dir / "metadata.json"
    p2.write_text('{"event": "test", "hop": 1}\n', encoding="utf-8")

    files = [
        ("report.pdf", "report", "law-enforcement-sensitive"),
        ("metadata.json", "metadata", "unclassified"),
    ]

    manifest = seal_case(evidence_dir, "case-rfc8785-001", files, canonicalization=CANONICALIZATION_JCS)
    assert manifest["canonicalization"] == CANONICALIZATION_JCS
    assert "RFC 8785" in manifest["trust_note"]

    # Validate against JSON schema
    jsonschema.validate(instance=manifest, schema=schema)

    # Verify case using verify_case
    verification = verify_case(evidence_dir)
    assert verification["status"] == "VALID"
    assert verification["canonicalization"] == CANONICALIZATION_JCS
    assert verification["records_checked"] == 2
    assert verification["case_id"] == "case-rfc8785-001"


def test_byte_for_byte_identity_with_legacy_payloads() -> None:
    """Verify float-free data produces identical bytes to legacy canonicalization requirements."""
    payloads = [
        {"alpha": "first", "beta": "second", "active": True, "count": 42, "empty": None},
        ["item1", "item2", {"nested": [1, 2, 3]}],
        {"z": 26, "a": 1, "m": 13},
        {"path": "evidence/report.pdf", "sha256": "0" * 64, "size_bytes": 1024},
    ]

    for p in payloads:
        rfc_bytes = canonical_bytes(p)
        # Test restricted canonical_bytes_restricted returns the same
        restricted_bytes = canonical_bytes_restricted(p)
        assert rfc_bytes == restricted_bytes


def test_restricted_profile_rejects_floats() -> None:
    """Verify canonical_bytes(allow_floats=False) and canonical_bytes_restricted reject floats."""
    with pytest.raises(ValueError, match="Floating-point values are not allowed"):
        canonical_bytes({"val": 3.14}, allow_floats=False)

    with pytest.raises(ValueError, match="Floating-point values are not allowed"):
        canonical_bytes_restricted({"val": 3.14})
