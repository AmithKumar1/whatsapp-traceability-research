"""Faithful clean-room cryptographic reproduction of Tyagi et al. (CCS 2019) Path Traceback.

Reference:
    Nirvan Tyagi, Ian Miers, and Thomas Ristenpart.
    "Traceback for End-to-End Encrypted Messaging."
    ACM CCS 2019 / IACR ePrint 2019/981.
    https://eprint.iacr.org/2019/981

Security properties reproduced:
    1. Path-Soundness (Traceability): Honest recipients along a forwarding chain
       can enable recovery of the authentic sender path back to originator.
    2. Framing Resistance (Sender Authentication): Senders sign message-bound tags,
       preventing a malicious forwarder or server from falsely framing an innocent sender.
    3. Wrong-Message Termination: Modifying message content alters the PRF address,
       causing traceback to stop immediately at the modification node.
    4. Epistemic Separation: Separates Account ID, Device ID, and cryptographic public key
       from unverified real-world human identity.
    5. Absence of Phantom Edges: If server records are absent or pruned, the tracer
       reports a missing record rather than manufacturing speculative hops.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DOMAIN_ADDRESS = b"Tyagi2019-Traceback-Address-v1\x00"
DOMAIN_TAG_SIGNATURE = b"Tyagi2019-SenderTag-Signature-v1\x00"
ORIGIN_POINTER = b"\x00" * 16
POINTER_SIZE = 16


def _crprf(key: bytes, message: bytes) -> bytes:
    """Collision-Resistant PRF mapping (pointer, message) -> 32-byte address."""
    return hmac.new(key, DOMAIN_ADDRESS + message, hashlib.sha256).digest()


def _aes_ctr(key: bytes, block: bytes) -> bytes:
    """Symmetric cipher for pointer encryption/decryption (AES-CTR with 0-IV)."""
    cipher = Cipher(algorithms.AES(key), modes.CTR(b"\x00" * 16))
    ctx = cipher.encryptor()
    return ctx.update(block) + ctx.finalize()


def _compute_tag_payload(
    addr: bytes,
    ct: bytes,
    message_digest: bytes,
    sender_account: str,
    sender_device: str,
    receiver_account: str,
    receiver_device: str,
) -> bytes:
    """Domain-separated payload committed and signed by the sender."""
    return (
        DOMAIN_TAG_SIGNATURE
        + addr
        + ct
        + message_digest
        + sender_account.encode("utf-8")
        + b"\x00"
        + sender_device.encode("utf-8")
        + b"\x00"
        + receiver_account.encode("utf-8")
        + b"\x00"
        + receiver_device.encode("utf-8")
    )


@dataclass(frozen=True)
class DeviceIdentity:
    """Participant device credential distinguishing device key from account or human."""
    account_id: str
    device_id: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @classmethod
    def generate(cls, account_id: str, device_id: str) -> "DeviceIdentity":
        sk = Ed25519PrivateKey.generate()
        return cls(account_id=account_id, device_id=device_id, private_key=sk, public_key=sk.public_key())

    @property
    def public_key_fingerprint(self) -> str:
        der = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der).hexdigest()

    @property
    def public_key_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


@dataclass(frozen=True)
class PathPointer:
    """Cryptographic tracking pointer transferred through the secure E2EE channel."""
    ptr: bytes

    @classmethod
    def origin(cls) -> "PathPointer":
        return cls(ptr=ORIGIN_POINTER)

    @classmethod
    def random(cls) -> "PathPointer":
        return cls(ptr=os.urandom(POINTER_SIZE))


@dataclass(frozen=True)
class CryptographicTraceTag:
    """Authenticated trace tag sent to server during message delivery."""
    addr: bytes
    ct: bytes
    sender_account: str
    sender_device: str
    sender_pubkey_raw: bytes
    receiver_account: str
    receiver_device: str
    signature: bytes


@dataclass(frozen=True)
class ServerStorageRecord:
    """Server-side routing entry stored in the address-indexed lookup table."""
    ct: bytes
    sender_account: str
    sender_device: str
    sender_pubkey_raw: bytes
    receiver_account: str
    receiver_device: str
    signature: bytes


@dataclass(frozen=True)
class VerifiedHop:
    """Cryptographically verified forwarding hop recovered during traceback."""
    hop_index: int
    sender_account: str
    sender_device: str
    receiver_account: str
    receiver_device: str
    address_hex: str
    signature_valid: bool
    status: str


@dataclass(frozen=True)
class TracebackExecutionResult:
    """Formal result of executing the traceback algorithm over server state."""
    outcome: str
    origin_reached: bool
    recovered_origin_account: Optional[str]
    recovered_origin_device: Optional[str]
    recovered_hops_count: int
    termination_reason: str
    verified_hops: Tuple[VerifiedHop, ...]


class CryptographicTracebackServer:
    """Server maintaining the address-indexed lookup table for Tyagi et al. traceback."""

    def __init__(self) -> None:
        self._table: Dict[bytes, ServerStorageRecord] = {}

    @property
    def entry_count(self) -> int:
        return len(self._table)

    @property
    def approximate_table_bytes(self) -> int:
        # 32 (addr) + 16 (ct) + accounts + devices + 32 (pubkey) + 64 (sig)
        total = 0
        for addr, rec in self._table.items():
            total += len(addr) + len(rec.ct) + len(rec.sender_account) + len(rec.sender_device)
            total += len(rec.receiver_account) + len(rec.receiver_device) + len(rec.sender_pubkey_raw) + len(rec.signature)
        return total

    def process_delivery(self, tag: CryptographicTraceTag) -> bool:
        """Store trace tag in server lookup table. Returns False if duplicate address exists."""
        if tag.addr in self._table:
            return False
        self._table[tag.addr] = ServerStorageRecord(
            ct=tag.ct,
            sender_account=tag.sender_account,
            sender_device=tag.sender_device,
            sender_pubkey_raw=tag.sender_pubkey_raw,
            receiver_account=tag.receiver_account,
            receiver_device=tag.receiver_device,
            signature=tag.signature,
        )
        return True

    def get_record(self, addr: bytes) -> Optional[ServerStorageRecord]:
        return self._table.get(addr)

    def trace(
        self,
        message: bytes,
        reporting_account: str,
        reporting_device: str,
        reporting_pointer: PathPointer,
        max_depth: int = 100,
    ) -> TracebackExecutionResult:
        """Execute the authenticated traceback algorithm from reporting user back to origin."""
        verified_hops: List[VerifiedHop] = []
        cursor_ptr = reporting_pointer.ptr
        current_receiver_account = reporting_account
        current_receiver_device = reporting_device
        visited_ptrs: set[bytes] = set()
        message_digest = hashlib.sha256(message).digest()

        origin_account: Optional[str] = None
        origin_device: Optional[str] = None
        origin_reached = False
        termination_reason = "in_progress"

        for hop_idx in range(max_depth):
            if cursor_ptr == ORIGIN_POINTER:
                origin_reached = True
                termination_reason = "origin_reached_successfully"
                break

            if cursor_ptr in visited_ptrs:
                termination_reason = "cyclic_forwarding_detected"
                break
            visited_ptrs.add(cursor_ptr)

            addr = _crprf(cursor_ptr, message)
            record = self._table.get(addr)
            if record is None:
                termination_reason = "missing_forwarding_record_in_server_state"
                break

            # 1. Identity binding check: the record's receiver must match current traversal node
            if (
                record.receiver_account != current_receiver_account
                or record.receiver_device != current_receiver_device
            ):
                termination_reason = "identity_binding_mismatch_at_hop"
                break

            # 2. Cryptographic signature check on tag commitment (Framing Resistance)
            expected_payload = _compute_tag_payload(
                addr=addr,
                ct=record.ct,
                message_digest=message_digest,
                sender_account=record.sender_account,
                sender_device=record.sender_device,
                receiver_account=record.receiver_account,
                receiver_device=record.receiver_device,
            )
            try:
                sender_pub = Ed25519PublicKey.from_public_bytes(record.sender_pubkey_raw)
                sender_pub.verify(record.signature, expected_payload)
            except (ValueError, InvalidSignature):
                verified_hops.append(
                    VerifiedHop(
                        hop_index=hop_idx + 1,
                        sender_account=record.sender_account,
                        sender_device=record.sender_device,
                        receiver_account=record.receiver_account,
                        receiver_device=record.receiver_device,
                        address_hex=addr.hex(),
                        signature_valid=False,
                        status="signature_verification_failed_framing_blocked",
                    )
                )
                termination_reason = "forged_sender_signature_detected"
                break

            # Decrypt predecessor pointer
            prev_ptr = _aes_ctr(cursor_ptr, record.ct)

            verified_hops.append(
                VerifiedHop(
                    hop_index=hop_idx + 1,
                    sender_account=record.sender_account,
                    sender_device=record.sender_device,
                    receiver_account=record.receiver_account,
                    receiver_device=record.receiver_device,
                    address_hex=addr.hex(),
                    signature_valid=True,
                    status="verified_hop_authenticated",
                )
            )

            origin_account = record.sender_account
            origin_device = record.sender_device
            cursor_ptr = prev_ptr
            current_receiver_account = record.sender_account
            current_receiver_device = record.sender_device

        if not origin_reached and termination_reason == "in_progress":
            termination_reason = "max_trace_depth_exceeded"

        outcome = "SUCCESS" if origin_reached else (
            "FAILED_VERIFICATION" if "signature" in termination_reason else "TERMINATED_EARLY"
        )

        return TracebackExecutionResult(
            outcome=outcome,
            origin_reached=origin_reached,
            recovered_origin_account=origin_account if origin_reached else None,
            recovered_origin_device=origin_device if origin_reached else None,
            recovered_hops_count=len(verified_hops),
            termination_reason=termination_reason,
            verified_hops=tuple(verified_hops),
        )


def originate_message() -> PathPointer:
    """Create initial origin pointer for a newly authored message."""
    return PathPointer.origin()


def forward_message(
    server: CryptographicTracebackServer,
    sender: DeviceIdentity,
    receiver_account: str,
    receiver_device: str,
    incoming_pointer: PathPointer,
    message: bytes,
    adversarial_corrupt_signature: bool = False,
    adversarial_different_message: Optional[bytes] = None,
) -> Tuple[PathPointer, CryptographicTraceTag]:
    """Execute sender's cryptographic operations to forward message to receiver.

    Returns:
        (receiver_incoming_pointer, trace_tag_sent_to_server)
    """
    next_pointer = PathPointer.random()
    addr_message = adversarial_different_message if adversarial_different_message is not None else message
    addr = _crprf(next_pointer.ptr, addr_message)
    ct = _aes_ctr(next_pointer.ptr, incoming_pointer.ptr)

    message_digest = hashlib.sha256(message).digest()
    tag_payload = _compute_tag_payload(
        addr=addr,
        ct=ct,
        message_digest=message_digest,
        sender_account=sender.account_id,
        sender_device=sender.device_id,
        receiver_account=receiver_account,
        receiver_device=receiver_device,
    )

    if adversarial_corrupt_signature:
        # Inject corrupted signature bytes (tampering / framing attempt)
        raw_sig = sender.private_key.sign(tag_payload)
        corrupted_sig = bytes([b ^ 0xFF for b in raw_sig[:8]]) + raw_sig[8:]
        signature = corrupted_sig
    else:
        signature = sender.private_key.sign(tag_payload)

    tag = CryptographicTraceTag(
        addr=addr,
        ct=ct,
        sender_account=sender.account_id,
        sender_device=sender.device_id,
        sender_pubkey_raw=sender.public_key_bytes,
        receiver_account=receiver_account,
        receiver_device=receiver_device,
        signature=signature,
    )

    stored = server.process_delivery(tag)
    if not stored:
        raise ValueError("Server rejected duplicate trace address")

    return next_pointer, tag
