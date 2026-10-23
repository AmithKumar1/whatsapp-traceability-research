"""Deterministic canonical JSON for OpenTrace's restricted signed-data profile.

This is intentionally *not* advertised as a complete RFC 8785 implementation.
The profile allows null, booleans, strings, lists, mappings, and safe integers;
all floating-point values are rejected. Object keys are sorted by UTF-16 code
units as required by RFC 8785. Adopt a fully conformant JCS library before
accepting unconstrained third-party JSON or promising cross-language signatures.
"""
from __future__ import annotations

import json
from typing import Any

_SAFE_INTEGER = 2**53 - 1


def _validate(value: Any, path: str = "$", depth: int = 0) -> None:
    if depth > 64:
        raise ValueError(f"JSON nesting exceeds limit at {path}")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8", errors="strict")
        except UnicodeEncodeError as exc:
            raise ValueError(f"Invalid Unicode string at {path}") from exc
        return
    if isinstance(value, int):
        if abs(value) > _SAFE_INTEGER:
            raise ValueError(f"Integer outside interoperable safe range at {path}")
        return
    if isinstance(value, float):
        raise ValueError(f"Floating-point values are not allowed in OpenTrace canonical JSON at {path}")
    if isinstance(value, list):
        for i, item in enumerate(value):
            _validate(item, f"{path}[{i}]", depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError(f"Object key must be a string at {path}")
            try:
                key.encode("utf-8", errors="strict")
            except UnicodeEncodeError as exc:
                raise ValueError(f"Invalid Unicode object key at {path}") from exc
            _validate(item, f"{path}.{key}", depth + 1)
        return
    raise ValueError(f"Unsupported JSON value {type(value).__name__} at {path}")


def _sort_key_utf16(value: str) -> bytes:
    # RFC 8785 orders property names by unsigned UTF-16 code units, not Python
    # Unicode scalar-value order. Big-endian UTF-16 preserves that order.
    return value.encode("utf-16-be", errors="strict")


def _ordered(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _ordered(value[k]) for k in sorted(value, key=_sort_key_utf16)}
    if isinstance(value, list):
        return [_ordered(item) for item in value]
    return value


def canonical_bytes(value: Any) -> bytes:
    """Return stable UTF-8 JSON bytes for OpenTrace's no-floats profile."""
    _validate(value)
    try:
        encoded = json.dumps(
            _ordered(value),
            ensure_ascii=False,
            sort_keys=False,
            separators=(",", ":"),
            allow_nan=False,
        )
        return encoded.encode("utf-8", errors="strict")
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError("Value cannot be represented in OpenTrace canonical JSON") from exc
