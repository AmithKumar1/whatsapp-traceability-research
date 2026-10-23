"""Unified synthetic benchmark harness for OpenTrace protocol adapters.

All identifiers and message bytes generated here are synthetic. The benchmark
measures these Python adapters only; it does not assert interoperability with
the cited Rust implementation or any deployed messaging platform.
"""
from __future__ import annotations

from collections import defaultdict
import json
import os
import platform
import statistics
import sys
import time
from typing import Any

from . import __version__
from .protocols.traceback2019 import build_path
from .protocols.traceback2019_tree import (
    SyntheticTreeServer,
    TraceTree,
    new_message as new_tree_message,
    synthetic_send as tree_send,
)


BENCHMARK_SCHEMA = "opentrace.benchmark.v1"
_PATH_HOP_SERIES = (1, 2, 4, 8, 16, 32, 64, 128, 256)


def _median(values: list[int]) -> int:
    return int(statistics.median(values))


def _tree_to_dict(tree: TraceTree) -> dict[str, Any]:
    return {"uid": tree.uid, "children": [_tree_to_dict(child) for child in tree.children]}


def _tree_size(tree: TraceTree) -> tuple[int, int, set[int]]:
    nodes = 1
    edges = 0
    ids = {tree.uid}
    for child in tree.children:
        child_nodes, child_edges, child_ids = _tree_size(child)
        nodes += child_nodes
        edges += child_edges + 1
        ids.update(child_ids)
    return nodes, edges, ids


def _expected_tree(parent_to_children: dict[int, list[int]], node_id: int = 0) -> TraceTree:
    return TraceTree(
        node_id,
        tuple(_expected_tree(parent_to_children, child_id) for child_id in parent_to_children.get(node_id, [])),
    )


def _build_tree_workload(
    message: bytes, depth: int, branching_factor: int
) -> tuple[SyntheticTreeServer, TraceTree, int, Any, int]:
    """Create a complete synthetic tree and return server, truth, leaf, metadata, node count."""
    server = SyntheticTreeServer()
    adjacency: dict[int, list[int]] = defaultdict(list)
    next_node_id = 1
    leaves: list[tuple[int, Any]] = []

    def expand(sender_id: int, metadata: Any, remaining_depth: int) -> None:
        nonlocal next_node_id
        if remaining_depth == 0:
            leaves.append((sender_id, metadata))
            return

        children: list[tuple[int, Any]] = []
        # A sender uses distinct counters for each sibling edge.
        for counter in range(branching_factor):
            receiver_id = next_node_id
            next_node_id += 1
            receiver_metadata = tree_send(
                server, message, metadata, counter, sender_id, receiver_id
            )
            adjacency[sender_id].append(receiver_id)
            children.append((receiver_id, receiver_metadata))
        for receiver_id, receiver_metadata in children:
            expand(receiver_id, receiver_metadata, remaining_depth - 1)

    expand(0, new_tree_message(), depth)
    truth = _expected_tree(adjacency)
    leaf_id, leaf_metadata = leaves[-1]
    return server, truth, leaf_id, leaf_metadata, next_node_id


def _benchmark_path(message: bytes, hops: int, repeats: int) -> dict[str, Any]:
    build_samples: list[int] = []
    trace_samples: list[int] = []
    final_path: list[int] = []
    state_entries = 0

    for _ in range(repeats):
        started = time.perf_counter_ns()
        server, metadata = build_path(message, hops)
        build_samples.append(time.perf_counter_ns() - started)
        state_entries = len(server._state)  # local adapter internals, not a network/storage estimate

        started = time.perf_counter_ns()
        final_path = server.trace(message, metadata, hops)
        trace_samples.append(time.perf_counter_ns() - started)

    expected = list(range(hops, -1, -1))
    correct = final_path == expected
    response = {"mode": "path", "recipient_to_origin_ids": final_path}
    response_bytes = len(json.dumps(response, separators=(",", ":")).encode("utf-8"))
    nodes = len(final_path)
    expected_nodes = hops + 1
    return {
        "protocol": "traceback2019-synthetic-path",
        "interoperable_with_reference": False,
        "workload": {"kind": "linear", "hops": hops, "message_bytes": len(message)},
        "measurements": {
            "repeats": repeats,
            "construction_ns_median": _median(build_samples),
            "construction_ns_min": min(build_samples),
            "construction_ns_max": max(build_samples),
            "trace_ns_median": _median(trace_samples),
            "trace_ns_min": min(trace_samples),
            "trace_ns_max": max(trace_samples),
            "state_entries": state_entries,
            "serialized_trace_bytes": response_bytes,
        },
        "outcome": {
            "correct": correct,
            "scenario_nodes": expected_nodes,
            "nodes_recovered": nodes,
            "edges_recovered": max(0, nodes - 1),
            "node_disclosure_fraction": round(nodes / expected_nodes, 6),
            "disclosure_mode": "path",
        },
        "samples_ns": {"construction": build_samples, "trace": trace_samples},
    }


def _benchmark_tree(
    message: bytes, depth: int, branching_factor: int, repeats: int
) -> dict[str, Any]:
    build_samples: list[int] = []
    trace_samples: list[int] = []
    final_tree = TraceTree(0)
    expected_tree = TraceTree(0)
    state_entries = 0
    expected_nodes = 0

    for _ in range(repeats):
        started = time.perf_counter_ns()
        server, expected_tree, leaf_id, leaf_metadata, expected_nodes = _build_tree_workload(
            message, depth, branching_factor
        )
        build_samples.append(time.perf_counter_ns() - started)
        state_entries = len(server._state)

        started = time.perf_counter_ns()
        final_tree = server.trace(message, leaf_metadata, leaf_id)
        trace_samples.append(time.perf_counter_ns() - started)

    final_nodes, final_edges, final_ids = _tree_size(final_tree)
    expected_count, expected_edges, expected_ids = _tree_size(expected_tree)
    correct = final_tree == expected_tree and final_ids == expected_ids
    response = {"mode": "tree", "tree": _tree_to_dict(final_tree)}
    response_bytes = len(json.dumps(response, separators=(",", ":")).encode("utf-8"))
    return {
        "protocol": "traceback2019-synthetic-tree",
        "interoperable_with_reference": False,
        "workload": {
            "kind": "complete_tree",
            "depth": depth,
            "branching_factor": branching_factor,
            "message_bytes": len(message),
        },
        "measurements": {
            "repeats": repeats,
            "construction_ns_median": _median(build_samples),
            "construction_ns_min": min(build_samples),
            "construction_ns_max": max(build_samples),
            "trace_ns_median": _median(trace_samples),
            "trace_ns_min": min(trace_samples),
            "trace_ns_max": max(trace_samples),
            "state_entries": state_entries,
            "serialized_trace_bytes": response_bytes,
        },
        "outcome": {
            "correct": correct,
            "scenario_nodes": expected_count,
            "nodes_recovered": final_nodes,
            "edges_recovered": final_edges,
            "expected_edges": expected_edges,
            "node_disclosure_fraction": round(final_nodes / expected_count, 6) if expected_count else 0.0,
            "disclosure_mode": "full_synthetic_forwarding_tree",
        },
        "samples_ns": {"construction": build_samples, "trace": trace_samples},
    }


def run_benchmark(
    *,
    message_size: int = 256,
    max_hops: int = 32,
    max_tree_depth: int = 3,
    branching_factors: tuple[int, ...] = (2,),
    repeats: int = 3,
) -> dict[str, Any]:
    """Run a common report schema over the implemented synthetic path/tree adapters."""
    if not isinstance(message_size, int) or not 1 <= message_size <= 1_000_000:
        raise ValueError("message_size must be an integer between 1 and 1000000")
    if not isinstance(max_hops, int) or not 1 <= max_hops <= 256:
        raise ValueError("max_hops must be an integer between 1 and 256")
    if not isinstance(max_tree_depth, int) or not 1 <= max_tree_depth <= 6:
        raise ValueError("max_tree_depth must be an integer between 1 and 6")
    if not isinstance(repeats, int) or not 1 <= repeats <= 100:
        raise ValueError("repeats must be an integer between 1 and 100")
    if not branching_factors or any(
        not isinstance(factor, int) or factor < 2 or factor > 5 for factor in branching_factors
    ):
        raise ValueError("branching_factors must contain integers from 2 through 5")
    if len(set(branching_factors)) != len(branching_factors):
        raise ValueError("branching_factors must not contain duplicates")
    # Bound aggregate work so a valid-looking depth/repeat combination cannot
    # accidentally request millions of public-key-independent crypto operations.
    estimated_tree_node_runs = repeats * sum(
        sum(factor ** level for level in range(depth + 1))
        for depth in range(1, max_tree_depth + 1)
        for factor in branching_factors
    )
    if estimated_tree_node_runs > 250_000:
        raise ValueError(
            "estimated tree workload exceeds 250000 node-runs; reduce repeats, depth, or branching factors"
        )

    message = b"M" * message_size
    records: list[dict[str, Any]] = []
    for hops in _PATH_HOP_SERIES:
        if hops <= max_hops:
            records.append(_benchmark_path(message, hops, repeats))
    for depth in range(1, max_tree_depth + 1):
        for factor in branching_factors:
            records.append(_benchmark_tree(message, depth, factor, repeats))

    return {
        "schema": BENCHMARK_SCHEMA,
        "opentrace_version": __version__,
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "platform": platform.platform(),
        },
        "method": {
            "timing_clock": "time.perf_counter_ns",
            "summary": "median/min/max over fresh synthetic workload runs",
            "message_content": "repeated synthetic byte M; message body not written to report",
            "identities": "synthetic sequential integer identifiers only",
            "protocol_status": "research adapter; not reference-interoperable; not production-certified",
        },
        "warnings": [
            "All workload data and identifiers are synthetic.",
            "Timings depend on this machine, runtime, load, and cryptographic library version.",
            "serialized_trace_bytes measures this report's compact JSON representation, not protocol wire bytes.",
            "state_entries is the in-memory adapter entry count, not an on-disk or provider storage estimate.",
            "Path and tree results have different workload shapes; do not interpret cross-topology timings as a controlled protocol contest.",
        ],
        "records": records,
        "summary": {
            "record_count": len(records),
            "correct_record_count": sum(1 for record in records if record["outcome"]["correct"]),
            "all_correct": all(record["outcome"]["correct"] for record in records),
        },
    }


def write_benchmark_report(report: dict[str, Any], output_path: str | os.PathLike[str]) -> None:
    """Write JSON report with stable indentation and a trailing newline."""
    from pathlib import Path

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
