"""Didactic model of the 2025 Hop Tracking Signatures research line.

This is not an implementation of the paper's cryptographic construction. It
models only the threshold relationship described in the paper abstract: a gap
of exactly one hop does not admit the paper's succinct construction result,
whereas a gap larger than one supports a succinct construction under the
paper's assumptions. No real signatures, proofs, or message tags are created.

Reference: Branco et al., "How to Trace Viral Content in End-to-End Encrypted
Messaging," IACR ePrint 2025/1052, https://eprint.iacr.org/2025/1052
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256


@dataclass(frozen=True)
class HTSEvaluation:
    protocol: str
    message_digest_sha256: str
    actual_hops: int
    anonymity_threshold_hops: int
    trace_threshold_hops: int
    threshold_gap_hops: int
    source_recovered: bool
    disclosed_forwarders: int
    succinctness_result_from_paper_model: str
    didactic_payload_size_proxy_bytes: int
    interoperable_with_reference: bool = False

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


class HopTrackingSignatures2025Synthetic:
    """Threshold-only conceptual model; not a cryptographic HTS implementation."""

    protocol_id = "hts-2025-synthetic"
    reference_status = "synthetic"

    def __init__(self, *, anonymity_threshold_hops: int = 2, trace_threshold_hops: int = 4) -> None:
        if anonymity_threshold_hops < 0:
            raise ValueError("anonymity_threshold_hops must be non-negative")
        if trace_threshold_hops < 1:
            raise ValueError("trace_threshold_hops must be at least 1")
        if trace_threshold_hops <= anonymity_threshold_hops:
            raise ValueError("trace_threshold_hops must exceed anonymity_threshold_hops")
        self.anonymity_threshold_hops = anonymity_threshold_hops
        self.trace_threshold_hops = trace_threshold_hops

    @property
    def threshold_gap_hops(self) -> int:
        return self.trace_threshold_hops - self.anonymity_threshold_hops

    def evaluate(self, message: bytes, actual_hops: int) -> HTSEvaluation:
        if actual_hops < 0 or actual_hops > 100_000:
            raise ValueError("actual_hops must be between 0 and 100000")
        gap = self.threshold_gap_hops
        if gap == 1:
            succinctness = "paper_negative_result_gap_one_no_succinct_construction_claim"
            # An explicitly didactic proxy; it is not a signature length estimate.
            payload_proxy = 48 + (8 * actual_hops)
        else:
            succinctness = "paper_positive_result_gap_at_least_two_succinctness_possible_under_assumptions"
            # A constant proxy illustrates only the *shape* of a succinct result.
            payload_proxy = 48
        return HTSEvaluation(
            protocol=self.protocol_id,
            message_digest_sha256=sha256(message).hexdigest(),
            actual_hops=actual_hops,
            anonymity_threshold_hops=self.anonymity_threshold_hops,
            trace_threshold_hops=self.trace_threshold_hops,
            threshold_gap_hops=gap,
            source_recovered=actual_hops >= self.trace_threshold_hops,
            disclosed_forwarders=0,
            succinctness_result_from_paper_model=succinctness,
            didactic_payload_size_proxy_bytes=payload_proxy,
        )
