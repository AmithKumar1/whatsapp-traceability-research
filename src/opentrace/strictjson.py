"""Strict JSON loading helpers for security-sensitive OpenTrace inputs."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DEFAULT_MAX_BYTES = 16 * 1024 * 1024


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON numeric constant is forbidden: {value}")


def loads_strict(text: str) -> Any:
    """Parse JSON while rejecting duplicate keys and NaN/Infinity extensions."""
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("invalid JSON") from exc


def load_json(path: Path, *, max_bytes: int = DEFAULT_MAX_BYTES) -> Any:
    """Read UTF-8 JSON under a bounded size limit and reject duplicate keys."""
    path = Path(path)
    try:
        # Bounded read avoids trusting a prior stat() size if the file changes
        # between metadata inspection and reading.
        with path.open("rb") as handle:
            raw = handle.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError(f"JSON file exceeds size limit ({len(raw)} > {max_bytes} bytes): {path.name}")
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"JSON file is not valid UTF-8: {path.name}") from exc
    return loads_strict(text)
