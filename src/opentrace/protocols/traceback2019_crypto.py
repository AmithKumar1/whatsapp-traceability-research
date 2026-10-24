"""Cryptographic reproduction of Tyagi et al. (CCS 2019) Path Traceback.

Reference:
    Nirvan Tyagi, Ian Miers, and Thomas Ristenpart.
    "Traceback for End-to-End Encrypted Messaging."
    ACM CCS 2019 / IACR ePrint 2019/981.
    https://eprint.iacr.org/2019/981

Design & Cryptographic Architecture:
    1. Symmetric Foundation & Third-Party Deniability:
       The published Section 4 / Figure 3 construction is strictly symmetric.
       For each forwarding hop, participants generate a tracing key k in {0, 1}^256,
       compute a keyed message identifier mid = F(k, m) via HMAC-SHA256 (CR-PRF),
       derive an encryption key K_enc = H(k) via HMAC-SHA256, and encrypt the
       predecessor tracing key c_ptr = AES-CTR(K_enc, k_prev).
       Because all participants on a hop possess the symmetric key k and can compute
       mid and c_ptr, the core protocol achieves third-party deniability: no offline
       non-repudiable proof is produced that could convince an external third party.

    2. Recipient-Side Verification (RecMsg):
       Upon message receipt, the recipient executes RecMsg before accepting or
       forwarding: it recomputes expected_mid = F(k, m) and verifies expected_mid == mid.
       Any modification of the plaintext, tracing key, or mid causes immediate rejection,
       preventing downstream propagation of corrupt or manipulated tracing state.

    3. Experimental Non-Repudiation Extension (DeviceRegistry PKI):
       As an optional extension beyond the purely symmetric paper design, senders may
       affix an Ed25519 signature over the trace tag payload. To prevent identity spoofing,
       the verifier checks the sender's public key against a trusted DeviceRegistry.
       Self-asserted public keys not present in the registry are rejected.

    4. Formal Theorem Mapping:
       - Theorem 1 in Tyagi et al. 2019 establishes Platform Trace Confidentiality:
         unreported messages and intermediate hops remain computationally indistinguishable
         from random to the messaging platform under PRF and stream cipher security.
       - Trace Unforgeability: an adversary cannot frame an honest user as the originator
         of a message they never sent, protected by RecMsg binding and authenticated routing.
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

# Domain separation tags (RFC-style domain separation)
DOMAIN_PRF_MID = b"Tyagi2019-PRF-mid-v1\x00"
DOMAIN_KDF_ENC = b"Tyagi2019-KDF-enc-v1\x00"
DOMAIN_EXTENSION_SIG = b"Tyagi2019-Extension-Sig-v1\x00"

ORIGIN_KEY = b"\x00" * 32
TRACING_KEY_SIZE = 32
MID_SIZE = 32
AES_KEY_SIZE = 16


def _crprf(key: bytes, message: bytes) -> bytes:
    """Collision-Resistant PRF computing mid = F(k, m) via HMAC-SHA256."""
    return hmac.new(key, DOMAIN_PRF_MID + message, hashlib.sha256).digest()


def _kdf_enc(key: bytes) -> bytes:
    """Key derivation function computing K_enc = H(k) for pointer encryption."""
    digest = hmac.new(key, DOMAIN_KDF_ENC, hashlib.sha256).digest()
    return digest[:AES_KEY_SIZE]


def _aes_ctr(key: bytes, block: bytes) -> bytes:
    """Symmetric stream cipher for pointer encryption/decryption (AES-128-CTR with 0-IV)."""
    cipher = Cipher(algorithms.AES(key), modes.CTR(b"\x00" * 16))
    ctx = cipher.encryptor()
    return ctx.update(block) + ctx.finalize()


def _compute_extension_payload(
    mid: bytes,
    ct: bytes,
    message_digest: bytes,
    sender_account: str,
    sender_device: str,
    receiver_account: str,
    receiver_device: str,
) -> bytes:
    """Domain-separated payload for the optional PKI-backed non-repudiation extension."""
    return (
        DOMAIN_EXTENSION_SIG
        + mid
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


class RecMsgVerificationError(ValueError):
    """Raised when recipient-side verification (RecMsg) fails."""


class DeviceRegistry:
    """Trusted directory binding platform accounts and device IDs to public keys.

    Prevents identity spoofing: self-asserted keys provided without registry
    endorsement are rejected.
    """

    def __init__(self) -> None:
        self._keys: Dict[Tuple[str, str], bytes] = {}

    def register(self, account_id: str, device_id: str, public_key_raw: bytes) -> None:
        self._keys[(account_id, device_id)] = public_key_raw

    def is_registered(self, account_id: str, device_id: str, public_key_raw: bytes) -> bool:
        registered = self._keys.get((account_id, device_id))
        return registered is not None and registered == public_key_raw

    def get_public_key(self, account_id: str, device_id: str) -> Optional[bytes]:
        return self._keys.get((account_id, device_id))


@dataclass(frozen=True)
class DeviceIdentity:
    """Participant endpoint credential distinguishing device key from account or human."""
    account_id: str
    device_id: str
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    @classmethod
    def generate(cls, account_id: str, device_id: str) -> "DeviceIdentity":
        sk = Ed25519PrivateKey.generate()
        return cls(account_id=account_id, device_id=device_id, private_key=sk, public_key=sk.public_key())

    @classmethod
    def from_private_bytes(cls, account_id: str, device_id: str, raw_32_bytes: bytes) -> "DeviceIdentity":
        sk = Ed25519PrivateKey.from_private_bytes(raw_32_bytes)
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
    """Symmetric tracing key / pointer transferred through the secure E2EE channel."""
    ptr: bytes

    @classmethod
    def origin(cls) -> "PathPointer":
        return cls(ptr=ORIGIN_KEY)

    @classmethod
    def random(cls) -> "PathPointer":
        return cls(ptr=os.urandom(TRACING_KEY_SIZE))


@dataclass(frozen=True)
class CryptographicTraceTag:
    """Trace record stored in the server lookup table."""
    addr: bytes  # mid
    ct: bytes
    sender_account: str
    sender_device: str
    sender_pubkey_raw: Optional[bytes]
    receiver_account: str
    receiver_device: str
    signature: Optional[bytes]


@dataclass(frozen=True)
class MessageEnvelope:
    """Message payload and tracing metadata delivered over E2EE channel."""
    message: bytes
    tracing_key: bytes
    mid: bytes
    ct: bytes
    sender_account: str
    sender_device: str
    receiver_account: str
    receiver_device: str
    sender_pubkey_raw: Optional[bytes] = None
    signature: Optional[bytes] = None


@dataclass(frozen=True)
class ReceivedMessageState:
    """Validated recipient state produced by successful RecMsg verification."""
    message: bytes
    tracing_key: bytes
    mid: bytes
    ct: bytes
    sender_account: str
    sender_device: str
    receiver_account: str
    receiver_device: str


@dataclass(frozen=True)
class ServerStorageRecord:
    """Server-side table entry stored in the mid-indexed lookup table."""
    ct: bytes
    sender_account: str
    sender_device: str
    sender_pubkey_raw: Optional[bytes]
    receiver_account: str
    receiver_device: str
    signature: Optional[bytes]


@dataclass(frozen=True)
class VerifiedHop:
    """Cryptographically verified forwarding hop recovered during traceback."""
    hop_index: int
    sender_account: str
    sender_device: str
    receiver_account: str
    receiver_device: str
    address_hex: str  # mid in hex
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


def rec_msg(
    receiver_account: str,
    receiver_device: str,
    envelope: MessageEnvelope,
    registry: Optional[DeviceRegistry] = None,
) -> ReceivedMessageState:
    """Execute the recipient-side verification algorithm (RecMsg) from CCS 2019.

    Binds the message plaintext, tracing key k, and message identifier mid:
      expected_mid = F(k, m)
    Rejects modified content, wrong keys, or unauthenticated sender claims.
    """
    if envelope.receiver_account != receiver_account or envelope.receiver_device != receiver_device:
        raise RecMsgVerificationError(
            f"RecMsg recipient mismatch: expected ({receiver_account}, {receiver_device}), "
            f"got ({envelope.receiver_account}, {envelope.receiver_device})"
        )

    expected_mid = _crprf(envelope.tracing_key, envelope.message)
    if not hmac.compare_digest(expected_mid, envelope.mid):
        raise RecMsgVerificationError(
            f"RecMsg binding mismatch: mid does not match F(k, m). "
            f"expected={expected_mid.hex()[:16]}..., got={envelope.mid.hex()[:16]}..."
        )

    # If the optional non-repudiation extension is present, check sender signature
    if envelope.signature is not None:
        if envelope.sender_pubkey_raw is None:
            raise RecMsgVerificationError("RecMsg signature present but missing sender public key")
        if registry is not None:
            if not registry.is_registered(envelope.sender_account, envelope.sender_device, envelope.sender_pubkey_raw):
                raise RecMsgVerificationError(
                    f"RecMsg rejected self-asserted sender public key: not registered in DeviceRegistry for "
                    f"{envelope.sender_account}/{envelope.sender_device}"
                )
        message_digest = hashlib.sha256(envelope.message).digest()
        payload = _compute_extension_payload(
            mid=envelope.mid,
            ct=envelope.ct,
            message_digest=message_digest,
            sender_account=envelope.sender_account,
            sender_device=envelope.sender_device,
            receiver_account=envelope.receiver_account,
            receiver_device=envelope.receiver_device,
        )
        try:
            pub = Ed25519PublicKey.from_public_bytes(envelope.sender_pubkey_raw)
            pub.verify(envelope.signature, payload)
        except (ValueError, InvalidSignature) as exc:
            raise RecMsgVerificationError(f"RecMsg sender signature verification failed: {exc}") from exc

    return ReceivedMessageState(
        message=envelope.message,
        tracing_key=envelope.tracing_key,
        mid=envelope.mid,
        ct=envelope.ct,
        sender_account=envelope.sender_account,
        sender_device=envelope.sender_device,
        receiver_account=envelope.receiver_account,
        receiver_device=envelope.receiver_device,
    )


class CryptographicTracebackServer:
    """Server maintaining the mid-indexed lookup table for Tyagi et al. traceback."""

    def __init__(self) -> None:
        self._table: Dict[bytes, ServerStorageRecord] = {}

    @property
    def entry_count(self) -> int:
        return len(self._table)

    @property
    def approximate_table_bytes(self) -> int:
        total = 0
        for addr, rec in self._table.items():
            total += len(addr) + len(rec.ct) + len(rec.sender_account) + len(rec.sender_device)
            total += len(rec.receiver_account) + len(rec.receiver_device)
            if rec.sender_pubkey_raw:
                total += len(rec.sender_pubkey_raw)
            if rec.signature:
                total += len(rec.signature)
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
        registry: Optional[DeviceRegistry] = None,
        max_depth: int = 100,
    ) -> TracebackExecutionResult:
        """Execute the traceback algorithm from reporting user back to origin.

        Adheres to Figure 3: uses k and H(k) to decrypt predecessor tracing keys.
        Checks identity bindings, detects loops, and checks registry if extension active.
        """
        verified_hops: List[VerifiedHop] = []
        cursor_k = reporting_pointer.ptr
        current_receiver_account = reporting_account
        current_receiver_device = reporting_device
        visited_keys: set[bytes] = set()
        message_digest = hashlib.sha256(message).digest()

        origin_account: Optional[str] = None
        origin_device: Optional[str] = None
        origin_reached = False
        termination_reason = "in_progress"

        for hop_idx in range(max_depth):
            if cursor_k == ORIGIN_KEY:
                origin_reached = True
                termination_reason = "origin_reached_successfully"
                break

            if cursor_k in visited_keys:
                termination_reason = "cyclic_forwarding_detected"
                break
            visited_keys.add(cursor_k)

            # Compute message identifier mid = F(k, m)
            mid = _crprf(cursor_k, message)
            record = self._table.get(mid)
            if record is None:
                termination_reason = "missing_forwarding_record_in_server_state"
                break

            # 1. Identity binding check: record receiver must match current traversal node
            if (
                record.receiver_account != current_receiver_account
                or record.receiver_device != current_receiver_device
            ):
                termination_reason = "identity_binding_mismatch_at_hop"
                break

            # 2. Check extension signature if present
            sig_valid = True
            if record.signature is not None:
                if record.sender_pubkey_raw is None:
                    termination_reason = "missing_sender_public_key_in_record"
                    break
                if registry is not None:
                    # Enforce registry check: reject self-asserted keys
                    if not registry.is_registered(
                        record.sender_account, record.sender_device, record.sender_pubkey_raw
                    ):
                        verified_hops.append(
                            VerifiedHop(
                                hop_index=hop_idx + 1,
                                sender_account=record.sender_account,
                                sender_device=record.sender_device,
                                receiver_account=record.receiver_account,
                                receiver_device=record.receiver_device,
                                address_hex=mid.hex(),
                                signature_valid=False,
                                status="unregistered_self_asserted_key_rejected",
                            )
                        )
                        termination_reason = "unregistered_self_asserted_key_rejected"
                        break

                expected_payload = _compute_extension_payload(
                    mid=mid,
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
                            address_hex=mid.hex(),
                            signature_valid=False,
                            status="signature_verification_failed_framing_blocked",
                        )
                    )
                    termination_reason = "forged_sender_signature_detected"
                    break

            # 3. Decrypt predecessor pointer k_prev = Dec(H(k), c_ptr)
            enc_key = _kdf_enc(cursor_k)
            prev_k = _aes_ctr(enc_key, record.ct)

            verified_hops.append(
                VerifiedHop(
                    hop_index=hop_idx + 1,
                    sender_account=record.sender_account,
                    sender_device=record.sender_device,
                    receiver_account=record.receiver_account,
                    receiver_device=record.receiver_device,
                    address_hex=mid.hex(),
                    signature_valid=sig_valid,
                    status="verified_hop_authenticated",
                )
            )

            origin_account = record.sender_account
            origin_device = record.sender_device
            cursor_k = prev_k
            current_receiver_account = record.sender_account
            current_receiver_device = record.sender_device

        if not origin_reached and termination_reason == "in_progress":
            termination_reason = "max_trace_depth_exceeded"

        outcome = "SUCCESS" if origin_reached else (
            "FAILED_VERIFICATION" if "signature" in termination_reason or "unregistered" in termination_reason
            else "TERMINATED_EARLY"
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


def originate_message(
    server: CryptographicTracebackServer,
    sender: DeviceIdentity,
    receiver_account: str,
    receiver_device: str,
    message: bytes,
    fixed_tracing_key: Optional[bytes] = None,
    attach_extension_signature: bool = True,
) -> Tuple[MessageEnvelope, ReceivedMessageState, CryptographicTraceTag]:
    """Originate a fresh message.

    Generates initial tracing key k_0, encrypts ORIGIN_KEY pointer, and stores in server table.
    """
    k_0 = fixed_tracing_key if fixed_tracing_key is not None else os.urandom(TRACING_KEY_SIZE)
    mid_0 = _crprf(k_0, message)
    enc_key_0 = _kdf_enc(k_0)
    ct_0 = _aes_ctr(enc_key_0, ORIGIN_KEY)

    pubkey_bytes: Optional[bytes] = None
    sig: Optional[bytes] = None
    if attach_extension_signature:
        message_digest = hashlib.sha256(message).digest()
        payload = _compute_extension_payload(
            mid=mid_0,
            ct=ct_0,
            message_digest=message_digest,
            sender_account=sender.account_id,
            sender_device=sender.device_id,
            receiver_account=receiver_account,
            receiver_device=receiver_device,
        )
        sig = sender.private_key.sign(payload)
        pubkey_bytes = sender.public_key_bytes

    tag = CryptographicTraceTag(
        addr=mid_0,
        ct=ct_0,
        sender_account=sender.account_id,
        sender_device=sender.device_id,
        sender_pubkey_raw=pubkey_bytes,
        receiver_account=receiver_account,
        receiver_device=receiver_device,
        signature=sig,
    )
    server.process_delivery(tag)

    envelope = MessageEnvelope(
        message=message,
        tracing_key=k_0,
        mid=mid_0,
        ct=ct_0,
        sender_account=sender.account_id,
        sender_device=sender.device_id,
        receiver_account=receiver_account,
        receiver_device=receiver_device,
        sender_pubkey_raw=pubkey_bytes,
        signature=sig,
    )

    received_state = ReceivedMessageState(
        message=message,
        tracing_key=k_0,
        mid=mid_0,
        ct=ct_0,
        sender_account=sender.account_id,
        sender_device=sender.device_id,
        receiver_account=receiver_account,
        receiver_device=receiver_device,
    )
    return envelope, received_state, tag


def forward_message(
    server: CryptographicTracebackServer,
    sender: DeviceIdentity,
    receiver_account: str,
    receiver_device: str,
    received_state: ReceivedMessageState,
    fixed_next_tracing_key: Optional[bytes] = None,
    attach_extension_signature: bool = True,
    adversarial_corrupt_signature: bool = False,
    adversarial_spoofed_sender: Optional[DeviceIdentity] = None,
) -> Tuple[MessageEnvelope, ReceivedMessageState, CryptographicTraceTag]:
    """Forward a previously received and verified message.

    Generates next tracing key k_next, computes mid_next = F(k_next, m),
    encrypts previous tracing key c_ptr = AES-CTR(H(k_next), received_state.tracing_key),
    and stores record in server table.
    """
    message = received_state.message
    k_next = fixed_next_tracing_key if fixed_next_tracing_key is not None else os.urandom(TRACING_KEY_SIZE)
    mid_next = _crprf(k_next, message)
    enc_key = _kdf_enc(k_next)
    ct = _aes_ctr(enc_key, received_state.tracing_key)

    actual_signing_sender = adversarial_spoofed_sender if adversarial_spoofed_sender is not None else sender
    claimed_sender_account = sender.account_id
    claimed_sender_device = sender.device_id

    pubkey_bytes: Optional[bytes] = None
    sig: Optional[bytes] = None
    if attach_extension_signature:
        message_digest = hashlib.sha256(message).digest()
        payload = _compute_extension_payload(
            mid=mid_next,
            ct=ct,
            message_digest=message_digest,
            sender_account=claimed_sender_account,
            sender_device=claimed_sender_device,
            receiver_account=receiver_account,
            receiver_device=receiver_device,
        )
        if adversarial_corrupt_signature:
            raw = actual_signing_sender.private_key.sign(payload)
            sig = bytes([b ^ 0xFF for b in raw[:8]]) + raw[8:]
        else:
            sig = actual_signing_sender.private_key.sign(payload)
        pubkey_bytes = actual_signing_sender.public_key_bytes

    tag = CryptographicTraceTag(
        addr=mid_next,
        ct=ct,
        sender_account=claimed_sender_account,
        sender_device=claimed_sender_device,
        sender_pubkey_raw=pubkey_bytes,
        receiver_account=receiver_account,
        receiver_device=receiver_device,
        signature=sig,
    )
    server.process_delivery(tag)

    envelope = MessageEnvelope(
        message=message,
        tracing_key=k_next,
        mid=mid_next,
        ct=ct,
        sender_account=claimed_sender_account,
        sender_device=claimed_sender_device,
        receiver_account=receiver_account,
        receiver_device=receiver_device,
        sender_pubkey_raw=pubkey_bytes,
        signature=sig,
    )

    next_received_state = ReceivedMessageState(
        message=message,
        tracing_key=k_next,
        mid=mid_next,
        ct=ct,
        sender_account=claimed_sender_account,
        sender_device=claimed_sender_device,
        receiver_account=receiver_account,
        receiver_device=receiver_device,
    )
    return envelope, next_received_state, tag
