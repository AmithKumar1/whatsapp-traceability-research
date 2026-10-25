"""Deterministic canonical JSON serialization per RFC 8785 (JSON Canonicalization Scheme / JCS).

This module provides RFC 8785 compliant canonicalization for cryptographic hashing,
manifest signing, and authorization requests within the WhatsApp Traceability Research Lab.

RFC 8785 defines canonical JSON serialization rules:
1. Object keys sorted by UTF-16 code units lexicographically.
2. Number formatting adhering to ECMAScript 6 / IEEE 754 64-bit double specifications:
   - Integers in range [-2^53 + 1, 2^53 - 1] serialized without exponents or fractions.
   - Floats serialized without redundant trailing zeroes; scientific notation used
     when |x| >= 10^21 or |x| < 10^-6.
   - -0.0 normalized to 0.
   - NaN, +Infinity, and -Infinity strictly rejected.
3. Whitespace stripped completely (separators: ',' and ':').
4. UTF-8 byte serialization without BOM.
5. Strict string escaping (only quotes, backslash, and control characters U+0000..U+001F escaped).

For backward compatibility with the legacy OpenTrace v0.2 restricted profile,
integer-only payloads produce byte-for-byte identical output to earlier versions.
An optional `allow_floats=False` mode is retained for legacy validation.
"""
from __future__ import annotations

from typing import Any

import rfc8785

_MAX_DEPTH = 64


def _check_depth_and_floats(value: Any, path: str = "$", depth: int = 0, *, allow_floats: bool = True) -> None:
    if depth > _MAX_DEPTH:
        raise ValueError(f"JSON nesting exceeds limit of {_MAX_DEPTH} at {path}")
    if isinstance(value, float) and not allow_floats:
        raise ValueError(f"Floating-point values are not allowed in restricted profile at {path}")
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _check_depth_and_floats(item, f"{path}[{i}]", depth + 1, allow_floats=allow_floats)
    elif isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError(f"Object key must be a string at {path}")
            _check_depth_and_floats(v, f"{path}.{k}", depth + 1, allow_floats=allow_floats)


def _sort_key_utf16(value: str) -> bytes:
    """Return big-endian UTF-16 bytes representing property sort order per RFC 8785."""
    return value.encode("utf-16-be", errors="strict")


def canonical_bytes(value: Any, *, allow_floats: bool = True) -> bytes:
    """Return stable UTF-8 JSON bytes for `value` according to RFC 8785 (JCS).

    Parameters:
        value: Any JSON-serializable Python data structure (dict, list, str, int, float, bool, None).
        allow_floats: If False, raises ValueError if any floating-point numbers are present,
                      preserving the legacy OpenTrace restricted profile behavior.

    Returns:
        Canonical UTF-8 bytes.

    Raises:
        ValueError: If `value` contains unsupported types, unrepresentable numbers (NaN, inf,
                    integers outside [-2^53 + 1, 2^53 - 1]), non-string keys, invalid Unicode,
                    or exceeds maximum nesting depth.
    """
    _check_depth_and_floats(value, allow_floats=allow_floats)
    try:
        return rfc8785.dumps(value)
    except rfc8785.CanonicalizationError as exc:
        raise ValueError(f"Value cannot be represented in RFC 8785 canonical JSON: {exc}") from exc


def canonical_bytes_restricted(value: Any) -> bytes:
    """Return canonical JSON bytes enforcing the legacy v0.2 no-floats profile."""
    return canonical_bytes(value, allow_floats=False)
