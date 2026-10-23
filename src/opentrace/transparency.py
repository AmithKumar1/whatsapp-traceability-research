"""Small, offline Merkle inclusion-proof laboratory using RFC 9162 hash domains.

This module creates/verifies inclusion proofs for local experiments. It is not
an online Certificate Transparency service, does not sign tree heads, and does
not prove append-only consistency across snapshots by itself.
"""
from __future__ import annotations

import hashlib
from typing import Iterable


class TransparencyError(ValueError):
    """Raised for malformed Merkle-tree inputs or proofs."""


_MAX_ENTRIES = 1_000_000
_MAX_ENTRY_BYTES = 1_048_576


def _sha256(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def leaf_hash(entry: bytes) -> bytes:
    if not isinstance(entry, bytes):
        raise TransparencyError("Merkle entries must be bytes")
    if len(entry) > _MAX_ENTRY_BYTES:
        raise TransparencyError(f"Merkle entries may not exceed {_MAX_ENTRY_BYTES} bytes")
    return _sha256(b"\x00" + entry)


def _node_hash(left: bytes, right: bytes) -> bytes:
    return _sha256(b"\x01" + left + right)


def _split(size: int) -> int:
    if size < 2:
        raise TransparencyError("cannot split a tree with fewer than two entries")
    return 1 << ((size - 1).bit_length() - 1)


def _mth_hashes(hashes: list[bytes], start: int = 0, size: int | None = None) -> bytes:
    """RFC 9162-style tree hash by index range, avoiding recursive list copies."""
    if size is None:
        size = len(hashes)
    if size == 0:
        return _sha256(b"")
    if size == 1:
        return hashes[start]
    k = _split(size)
    return _node_hash(
        _mth_hashes(hashes, start, k),
        _mth_hashes(hashes, start + k, size - k),
    )


def _collect_entries(entries: Iterable[bytes]) -> list[bytes]:
    collected: list[bytes] = []
    for index, entry in enumerate(entries):
        if index >= _MAX_ENTRIES:
            raise TransparencyError(f"entry count exceeds safety limit of {_MAX_ENTRIES}")
        if not isinstance(entry, bytes):
            raise TransparencyError("Merkle entries must be bytes")
        if len(entry) > _MAX_ENTRY_BYTES:
            raise TransparencyError(f"entry at index {index} exceeds {_MAX_ENTRY_BYTES} bytes")
        collected.append(entry)
    return collected


def merkle_root(entries: Iterable[bytes]) -> str:
    collected = _collect_entries(entries)
    hashes = [leaf_hash(item) for item in collected]
    return _mth_hashes(hashes).hex()


def build_inclusion_proof(entries: list[bytes], index: int) -> dict[str, object]:
    if not isinstance(entries, list) or not entries:
        raise TransparencyError("entries must be a non-empty list of bytes")
    if len(entries) > _MAX_ENTRIES:
        raise TransparencyError(f"entry count exceeds safety limit of {_MAX_ENTRIES}")
    if isinstance(index, bool) or not isinstance(index, int) or index < 0 or index >= len(entries):
        raise TransparencyError("leaf index is outside the tree")
    if any(not isinstance(entry, bytes) for entry in entries):
        raise TransparencyError("Merkle entries must be bytes")
    if any(len(entry) > _MAX_ENTRY_BYTES for entry in entries):
        raise TransparencyError(f"entries may not exceed {_MAX_ENTRY_BYTES} bytes")
    hashes = [leaf_hash(item) for item in entries]

    def walk(start: int, size: int, position: int) -> list[dict[str, str]]:
        if size == 1:
            return []
        k = _split(size)
        if position < k:
            return walk(start, k, position) + [
                {"side": "RIGHT", "hash": _mth_hashes(hashes, start + k, size - k).hex()}
            ]
        return walk(start + k, size - k, position - k) + [
            {"side": "LEFT", "hash": _mth_hashes(hashes, start, k).hex()}
        ]

    return {
        "proof_version": "1",
        "hash_algorithm": "SHA-256",
        "tree_size": len(entries),
        "leaf_index": index,
        "leaf_sha256": _sha256(entries[index]).hex(),
        "root_sha256": _mth_hashes(hashes).hex(),
        "audit_path": walk(0, len(hashes), index),
        "format_note": "Offline WhatsApp Traceability Research Lab proof using RFC 9162 leaf/node domain separation; no signed tree head is included.",
    }


def verify_inclusion(entry: bytes, proof: dict[str, object]) -> bool:
    if not isinstance(entry, bytes) or not isinstance(proof, dict):
        return False
    try:
        if proof.get("proof_version") != "1" or proof.get("hash_algorithm") != "SHA-256":
            return False
        tree_size, index = proof.get("tree_size"), proof.get("leaf_index")
        path, expected_leaf, expected_root = proof.get("audit_path"), proof.get("leaf_sha256"), proof.get("root_sha256")
        if isinstance(tree_size, bool) or not isinstance(tree_size, int) or tree_size < 1:
            return False
        if isinstance(index, bool) or not isinstance(index, int) or not (0 <= index < tree_size):
            return False
        if not isinstance(path, list) or not isinstance(expected_leaf, str) or not isinstance(expected_root, str):
            return False
        current = leaf_hash(entry)
        if _sha256(entry).hex() != expected_leaf:
            return False
        def expected_sides(size: int, leaf_index: int) -> list[str]:
            if size == 1:
                return []
            k = _split(size)
            if leaf_index < k:
                return expected_sides(k, leaf_index) + ["RIGHT"]
            return expected_sides(size - k, leaf_index - k) + ["LEFT"]
        if [step.get("side") if isinstance(step, dict) else None for step in path] != expected_sides(tree_size, index):
            return False
        for step in path:
            if not isinstance(step, dict) or set(step) != {"side", "hash"}:
                return False
            side, value = step["side"], step["hash"]
            if side not in {"LEFT", "RIGHT"} or not isinstance(value, str) or len(value) != 64:
                return False
            sibling = bytes.fromhex(value)
            current = _node_hash(sibling, current) if side == "LEFT" else _node_hash(current, sibling)
        return current.hex() == expected_root
    except (ValueError, TypeError):
        return False
