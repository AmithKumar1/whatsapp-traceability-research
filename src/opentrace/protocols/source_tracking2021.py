"""Synthetic research adapter for complaint-enabled source tracking (2021).

This module is deliberately NOT a cryptographic reimplementation of the CCS 2021
scheme. It models its key research property: an authorized complaint can recover
the source identity of a reported message without requiring disclosure of every
intermediate forwarder.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import hmac
import secrets


@dataclass(frozen=True)
class SourceReceipt:
    message_digest: str
    source_token: bytes


@dataclass(frozen=True)
class ComplaintProof:
    message_digest: str
    source_token: bytes


@dataclass(frozen=True)
class SourceDisclosure:
    protocol: str
    message_digest: str
    source_account: str
    disclosed_forwarders: int
    cryptographic_claim: str
    interoperable_with_reference: bool = False


class SourceTracking2021Synthetic:
    """Small deterministic model of source-only disclosure.

    The model intentionally exposes no forwarding graph. A real implementation
    would replace the token construction and verification with the paper's
    cryptographic algorithms after a formal specification/differential-test pass.
    """

    protocol_id = "source-tracking-2021-synthetic"

    def __init__(self, authority_key: bytes | None = None) -> None:
        self._authority_key = authority_key or secrets.token_bytes(32)
        self._receipts: dict[str, tuple[str, bytes]] = {}

    @staticmethod
    def digest(message: bytes) -> str:
        return sha256(message).hexdigest()

    def issue_receipt(self, message: bytes, source_account: str) -> SourceReceipt:
        digest = self.digest(message)
        token = hmac.new(
            self._authority_key,
            digest.encode("ascii") + b"\x00" + source_account.encode("utf-8"),
            "sha256",
        ).digest()
        self._receipts[digest] = (source_account, token)
        return SourceReceipt(digest, token)

    def create_complaint(self, receipt: SourceReceipt) -> ComplaintProof:
        if receipt.message_digest not in self._receipts:
            raise ValueError("unknown message receipt")
        return ComplaintProof(receipt.message_digest, receipt.source_token)

    def trace_source(self, complaint: ComplaintProof) -> SourceDisclosure:
        record = self._receipts.get(complaint.message_digest)
        if record is None:
            raise ValueError("unknown complaint")
        source, expected = record
        if not hmac.compare_digest(expected, complaint.source_token):
            raise ValueError("invalid complaint proof")
        return SourceDisclosure(
            protocol=self.protocol_id,
            message_digest=complaint.message_digest,
            source_account=source,
            disclosed_forwarders=0,
            cryptographic_claim="authorized complaint resolves source token only",
        )
