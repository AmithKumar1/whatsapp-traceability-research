#!/usr/bin/env python3
"""Reproducible microbenchmark for the offline Merkle proof laboratory.

This measures only WhatsApp Traceability Research Lab's local SHA-256/Merkle helper, not an E2EE source
tracing protocol, production transparency service, or end-to-end deployment.
"""
from __future__ import annotations

import argparse
import json
import platform
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from opentrace.transparency import build_inclusion_proof, merkle_root, verify_inclusion  # noqa: E402


def measure(size: int, repeats: int) -> dict[str, object]:
    entries = [f"E2EE-Traceability-Lab-synthetic-benchmark-event-{i:08d}".encode("utf-8") for i in range(size)]
    index = size // 2
    root_samples = []
    proof_samples = []
    verify_samples = []
    proof_bytes = 0
    result_root = ""
    for _ in range(repeats):
        start = time.perf_counter_ns()
        result_root = merkle_root(entries)
        root_samples.append((time.perf_counter_ns() - start) / 1_000_000)

        start = time.perf_counter_ns()
        proof = build_inclusion_proof(entries, index)
        proof_samples.append((time.perf_counter_ns() - start) / 1_000_000)
        proof_bytes = len(json.dumps(proof, separators=(",", ":")).encode("utf-8"))

        start = time.perf_counter_ns()
        valid = verify_inclusion(entries[index], proof)
        verify_samples.append((time.perf_counter_ns() - start) / 1_000_000)
        if not valid or proof["root_sha256"] != result_root:
            raise RuntimeError("Merkle proof benchmark self-check failed")

    return {
        "entry_count": size,
        "entry_bytes_each": len(entries[0]) if entries else 0,
        "root_median_ms": round(statistics.median(root_samples), 4),
        "proof_build_median_ms": round(statistics.median(proof_samples), 4),
        "proof_verify_median_ms": round(statistics.median(verify_samples), 4),
        "proof_json_bytes": proof_bytes,
        "root_sha256": result_root,
        "all_self_checks_passed": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", nargs="+", type=int, default=[10, 100, 1000, 10000])
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.repeats < 1 or any(size < 1 or size > 1_000_000 for size in args.sizes):
        parser.error("repeats must be >= 1 and each size must be between 1 and 1,000,000")
    payload = {
        "benchmark_name": "e2ee-traceability-lab-offline-merkle-microbenchmark",
        "benchmark_version": "1",
        "scope": "Local synthetic SHA-256/Merkle helper only; no tracing-protocol performance claim.",
        "environment": {"python": platform.python_version(), "platform": platform.platform()},
        "repeats": args.repeats,
        "results": [measure(size, args.repeats) for size in sorted(set(args.sizes))],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote benchmark results to {args.out.resolve()}")


if __name__ == "__main__":
    main()
