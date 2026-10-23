"""Synthetic 2019-style tree traceback adapter.

Clean-room research implementation derived from the public algorithmic structure
of Tyagi, Miers & Ristenpart (CCS 2019). It is deliberately isolated from any
production messenger and is not wire-compatible with WhatsApp or Signal.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple
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


def _aes(key: bytes, block: bytes, decrypt: bool = False) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    ctx = cipher.decryptor() if decrypt else cipher.encryptor()
    return ctx.update(block) + ctx.finalize()


def _enc(key: bytes, block: bytes) -> bytes:
    return _aes(key, block)


def _dec(key: bytes, block: bytes) -> bytes:
    return _aes(key, block, True)


@dataclass(frozen=True)
class TreeMetadata:
    bptr: bytes
    gk: bytes


@dataclass(frozen=True)
class SenderTraceTag:
    addr: bytes
    ct_ptr: bytes
    ct_bptr: bytes
    ct_gk: bytes
    ct_fgk: bytes


@dataclass(frozen=True)
class ReceiverTraceTag:
    addr: bytes
    ct_ptr: bytes
    ct_fgk: bytes
    ks_fgk: bytes


@dataclass(frozen=True)
class TraceTree:
    uid: int
    children: tuple["TraceTree", ...] = ()


class SyntheticTreeServer:
    def __init__(self) -> None:
        self._state: Dict[bytes, Tuple[bytes, bytes, bytes, bytes, int, int]] = {}

    def process(self, tag: SenderTraceTag, sender_id: int, receiver_id: int) -> ReceiverTraceTag | None:
        if tag.addr in self._state:
            return None
        ks_fgk = os.urandom(16)
        self._state[tag.addr] = (tag.ct_bptr, tag.ct_gk, tag.ct_fgk, ks_fgk, sender_id, receiver_id)
        return ReceiverTraceTag(tag.addr, tag.ct_ptr, tag.ct_fgk, ks_fgk)

    def _read(self, addr: bytes):
        return self._state[addr]

    def trace(self, message: bytes, metadata: TreeMetadata, recipient_id: int) -> TraceTree:
        root = recipient_id
        root_gk = metadata.gk
        gk = metadata.gk
        bptr = metadata.bptr
        addr = _prf(bptr, message)
        previous_recipient = recipient_id

        while addr in self._state:
            ct_bptr, ct_gk, ct_fgk, ks_platform, sender_id, receiver_id = self._read(addr)
            if previous_recipient != receiver_id:
                break
            ks_sender = _dec(bptr, ct_fgk)
            fgk = _hash16(ks_sender + ks_platform)
            if gk != fgk:
                return TraceTree(sender_id, (self._build_tree(message, fgk, receiver_id),))
            gk = _dec(bptr, ct_gk)
            root = sender_id
            root_gk = gk
            previous_recipient = sender_id

            ctr = 0
            ptr_valid = False
            while ctr < 1_000_000:
                ptr = _prf(gk, ctr.to_bytes(4, "big"))
                if ptr == bptr:
                    ptr_valid = True
                    break
                if _prf(ptr, message) not in self._state:
                    break
                ctr += 1
            if not ptr_valid:
                return TraceTree(sender_id, (self._build_tree(message, fgk, receiver_id),))
            bptr = _dec(bptr, ct_bptr)
            addr = _prf(bptr, message)

        return self._build_tree(message, root_gk, root)

    def _build_tree(self, message: bytes, gk: bytes, uid: int) -> TraceTree:
        children = []
        ctr = 0
        while ctr < 1_000_000:
            ptr = _prf(gk, ctr.to_bytes(4, "big"))
            addr = _prf(ptr, message)
            if addr not in self._state:
                break
            ct_bptr, ct_gk, ct_fgk, ks_platform, sender_id, receiver_id = self._read(addr)
            if sender_id != uid:
                break
            ks_sender = _dec(ptr, ct_fgk)
            child_gk = _hash16(ks_sender + ks_platform)
            children.append(self._build_tree(message, child_gk, receiver_id))
            ctr += 1
        return TraceTree(uid, tuple(children))


def new_message() -> TreeMetadata:
    return TreeMetadata(bptr=b"\x00" * 16, gk=os.urandom(16))


def generate_tag(key: bytes, message: bytes, metadata: TreeMetadata, counter: int) -> SenderTraceTag:
    if len(key) != 16 or len(metadata.bptr) != 16 or len(metadata.gk) != 16:
        raise ValueError("baseline requires 16-byte synthetic keys/pointers")
    ptr = _prf(metadata.gk, counter.to_bytes(4, "big"))
    addr = _prf(ptr, message)
    return SenderTraceTag(
        addr=addr,
        ct_ptr=_enc(key, ptr),
        ct_bptr=_enc(ptr, metadata.bptr),
        ct_gk=_enc(ptr, metadata.gk),
        ct_fgk=_enc(ptr, os.urandom(16)),
    )


def verify_tag(key: bytes, message: bytes, tag: ReceiverTraceTag) -> TreeMetadata | None:
    ptr = _dec(key, tag.ct_ptr)
    if _prf(ptr, message) != tag.addr:
        return None
    sender_key = _dec(ptr, tag.ct_fgk)
    gk = _hash16(sender_key + tag.ks_fgk)
    return TreeMetadata(bptr=ptr, gk=gk)


def synthetic_send(server: SyntheticTreeServer, message: bytes, metadata: TreeMetadata,
                   counter: int, sender_id: int, receiver_id: int) -> TreeMetadata:
    key = os.urandom(16)
    tag = generate_tag(key, message, metadata, counter)
    received = server.process(tag, sender_id, receiver_id)
    if received is None:
        raise ValueError("duplicate synthetic trace address")
    verified = verify_tag(key, message, received)
    if verified is None:
        raise ValueError("synthetic tag verification failed")
    return verified


def build_branch(server: SyntheticTreeServer, message: bytes, metadata: TreeMetadata,
                 sender_id: int, receivers: list[int]) -> None:
    for counter, receiver_id in enumerate(receivers):
        child = synthetic_send(server, message, metadata, counter, sender_id, receiver_id)
        # Recipients are leaves unless callers explicitly continue the branch.
        _ = child


def demo_tree() -> tuple[SyntheticTreeServer, TreeMetadata, TraceTree]:
    message = b"synthetic viral message"
    server = SyntheticTreeServer()
    root_md = new_message()
    md1 = synthetic_send(server, message, root_md, 0, 0, 1)
    md2 = synthetic_send(server, message, md1, 0, 1, 2)
    _ = synthetic_send(server, message, md1, 1, 1, 3)
    tree = server.trace(message, md2, 2)
    return server, md2, tree
