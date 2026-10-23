"""Research-only Python baseline inspired by Tyagi, Miers & Ristenpart (CCS 2019).

This module is a clean-room adapter for synthetic protocol experiments. It is
NOT wire-compatible with the original Rust implementation and does not claim
interoperability with any production messenger.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()


def _hash16(data: bytes) -> bytes:
    return _sha3_256(data)[:16]


def _prf(key: bytes, data: bytes) -> bytes:
    return _sha3_256(key + data)[:16]


def _crprf(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha3_256).digest()


def _aes_ecb(key: bytes, block: bytes, *, decrypt: bool = False) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    ctx = cipher.decryptor() if decrypt else cipher.encryptor()
    return ctx.update(block) + ctx.finalize()


def _encipher(key: bytes, block: bytes) -> bytes:
    return _aes_ecb(key, block)


def _decipher(key: bytes, block: bytes) -> bytes:
    return _aes_ecb(key, block, decrypt=True)


@dataclass(frozen=True)
class PathMetadata:
    ptr: bytes


@dataclass(frozen=True)
class SenderTraceTag:
    addr: bytes
    ct: bytes


@dataclass(frozen=True)
class ReceiverTraceTag:
    addr: bytes


class SyntheticPathServer:
    """In-memory synthetic server state used only for research/benchmarking."""

    def __init__(self) -> None:
        self._state: Dict[bytes, Tuple[bytes, int, int]] = {}

    def process(self, tag: SenderTraceTag, sender_id: int, receiver_id: int) -> ReceiverTraceTag | None:
        if tag.addr in self._state:
            return None
        self._state[tag.addr] = (tag.ct, sender_id, receiver_id)
        return ReceiverTraceTag(tag.addr)

    def trace(self, message: bytes, metadata: PathMetadata, recipient_id: int) -> List[int]:
        path = [recipient_id]
        ptr = metadata.ptr
        addr = _crprf(ptr, message)
        while addr in self._state:
            ct, sender_id, receiver_id = self._state[addr]
            if path[-1] != receiver_id:
                break
            path.append(sender_id)
            ptr = _decipher(ptr, ct)
            addr = _crprf(ptr, message)
        return path


def new_message() -> PathMetadata:
    """Create origin metadata for a synthetic message."""
    return PathMetadata(ptr=b"\x00" * 16)


def generate_tag(key: bytes, message: bytes, metadata: PathMetadata) -> SenderTraceTag:
    if len(key) != 16 or len(metadata.ptr) != 16:
        raise ValueError("baseline requires 16-byte synthetic keys/pointers")
    return SenderTraceTag(_crprf(key, message), _encipher(key, metadata.ptr))


def verify_tag(key: bytes, message: bytes, tag: ReceiverTraceTag) -> PathMetadata | None:
    if len(key) != 16:
        raise ValueError("baseline requires 16-byte synthetic keys")
    # The reference protocol exposes the key as the next pointer on successful verification.
    if _crprf(key, message) != tag.addr:
        return None
    return PathMetadata(ptr=key)


def synthetic_send(
    server: SyntheticPathServer,
    message: bytes,
    metadata: PathMetadata,
    sender_id: int,
    receiver_id: int,
) -> PathMetadata:
    key = os.urandom(16)
    sender_tag = generate_tag(key, message, metadata)
    receiver_tag = server.process(sender_tag, sender_id, receiver_id)
    if receiver_tag is None:
        raise ValueError("duplicate synthetic trace address")
    verified = verify_tag(key, message, receiver_tag)
    if verified is None:
        raise ValueError("synthetic tag verification failed")
    return verified


def build_path(message: bytes, hops: int) -> tuple[SyntheticPathServer, PathMetadata]:
    if hops < 0:
        raise ValueError("hops must be non-negative")
    server = SyntheticPathServer()
    metadata = new_message()
    for i in range(hops):
        metadata = synthetic_send(server, message, metadata, i, i + 1)
    return server, metadata


def benchmark_points(message_size: int = 256, max_hops: int = 32) -> list[dict]:
    """Return deterministic-shaped benchmark records; timings are measured locally."""
    import time
    message = b"M" * message_size
    records: list[dict] = []
    for hops in (1, 2, 4, 8, 16, 32):
        if hops > max_hops:
            continue
        t0 = time.perf_counter_ns()
        server, metadata = build_path(message, hops)
        build_ns = time.perf_counter_ns() - t0
        t1 = time.perf_counter_ns()
        path = server.trace(message, metadata, hops)
        trace_ns = time.perf_counter_ns() - t1
        records.append({"hops": hops, "build_ns": build_ns, "trace_ns": trace_ns, "path_length": len(path)})
    return records
